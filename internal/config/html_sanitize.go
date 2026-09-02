package config

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

var blockPageAllowedTags = map[string]bool{
	"html": true, "head": true, "body": true, "title": true, "meta": true,
	"style": true, "main": true, "section": true, "header": true, "footer": true,
	"div": true, "span": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "p": true, "strong": true, "em": true, "b": true,
	"i": true, "small": true, "ul": true, "ol": true, "li": true, "a": true,
	"img": true, "br": true, "hr": true, "pre": true, "code": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true,
	"th": true, "td": true,
}

var blockPageGlobalAttrs = map[string]bool{
	"class": true, "id": true, "title": true, "role": true, "tabindex": true,
	"lang": true, "dir": true, "width": true, "height": true,
}

// SanitizeBlockPageHTML removes active browser capabilities before custom HTML
// is persisted or rendered. The policy intentionally keeps ordinary markup,
// inline styles, and Go template placeholders used by the block-page renderer.
func SanitizeBlockPageHTML(source string) (string, error) {
	if strings.TrimSpace(source) == "" {
		return "", nil
	}
	doc, err := html.Parse(strings.NewReader(source))
	if err != nil {
		return "", fmt.Errorf("parse custom block page HTML: %w", err)
	}
	if !sanitizeBlockPageNode(doc) {
		return source, nil
	}
	var out bytes.Buffer
	if err := html.Render(&out, doc); err != nil {
		return "", fmt.Errorf("render sanitized block page HTML: %w", err)
	}
	return out.String(), nil
}

func sanitizeBlockPageNode(node *html.Node) bool {
	changed := false
	for child := node.FirstChild; child != nil; {
		next := child.NextSibling
		if child.Type == html.ElementNode {
			tag := strings.ToLower(child.Data)
			if !blockPageAllowedTags[tag] {
				node.RemoveChild(child)
				changed = true
				child = next
				continue
			}
			if sanitizeBlockPageAttrs(child, tag) {
				changed = true
			}
			if tag == "style" && sanitizeBlockPageStyleText(child) {
				changed = true
			}
		} else if child.Type == html.CommentNode {
			node.RemoveChild(child)
			changed = true
			child = next
			continue
		}
		if sanitizeBlockPageNode(child) {
			changed = true
		}
		child = next
	}
	return changed
}

func sanitizeBlockPageStyleText(node *html.Node) bool {
	changed := false
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type != html.TextNode {
			continue
		}
		clean, textChanged := sanitizeBlockPageCSSRules(child.Data)
		if textChanged {
			child.Data = clean
			changed = true
		}
	}
	return changed
}

func sanitizeBlockPageCSSRules(value string) (string, bool) {
	changed := false
	for {
		start := strings.Index(strings.ToLower(value), "@import")
		if start < 0 {
			break
		}
		end := strings.Index(value[start:], ";")
		if end < 0 {
			return value[:start], true
		}
		value = value[:start] + value[start+end+1:]
		changed = true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"url(", "expression(", "javascript:", "vbscript:", "behavior:", "-moz-binding"} {
		if strings.Contains(lower, marker) {
			return "", true
		}
	}
	return value, changed
}

func sanitizeBlockPageAttrs(node *html.Node, tag string) bool {
	changed := false
	attrs := node.Attr[:0]
	for _, attr := range node.Attr {
		key := strings.ToLower(strings.TrimSpace(attr.Key))
		value := attr.Val
		if strings.HasPrefix(key, "on") || key == "srcset" || key == "formaction" || key == "action" || key == "method" {
			changed = true
			continue
		}
		if key == "style" {
			if unsafeBlockPageCSS(value) {
				changed = true
				continue
			}
			attrs = append(attrs, html.Attribute{Key: key, Val: value})
			continue
		}
		if key == "href" || key == "src" {
			if !safeBlockPageURL(value, tag == "img") {
				changed = true
				continue
			}
			attrs = append(attrs, html.Attribute{Key: key, Val: value})
			continue
		}
		if tag == "meta" {
			// Only charset metadata is harmless. In particular, remove refresh
			// and http-equiv attributes that can redirect or alter policy.
			if key != "charset" {
				changed = true
				continue
			}
		}
		if strings.HasPrefix(key, "aria-") || strings.HasPrefix(key, "data-") || blockPageGlobalAttrs[key] || (tag == "img" && key == "alt") || (tag == "a" && key == "target") {
			attrs = append(attrs, html.Attribute{Key: key, Val: value})
		} else {
			changed = true
		}
	}
	node.Attr = attrs
	return changed
}

func unsafeBlockPageCSS(value string) bool {
	lower := strings.ToLower(strings.ReplaceAll(value, " ", ""))
	for _, marker := range []string{"url(", "expression(", "javascript:", "vbscript:", "behavior:", "-moz-binding", "@import"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func safeBlockPageURL(value string, image bool) bool {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "#") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	case "mailto", "tel":
		return !image
	case "data":
		return image && strings.HasPrefix(strings.ToLower(value), "data:image/") && strings.Contains(strings.ToLower(value), ";base64,")
	default:
		return false
	}
}
