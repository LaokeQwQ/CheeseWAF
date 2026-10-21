package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
)

const (
	// DefaultMaxTextBytes caps normalized visible text per document.
	DefaultMaxTextBytes = 64 << 10
	// MaxDocumentTextBytes is the hard cap on normalized visible text.
	MaxDocumentTextBytes = 512 << 10
	// MaxCodeBlocks caps retained code blocks per document.
	MaxCodeBlocks = 32
	// MaxCodeBlockBytes caps each retained code block.
	MaxCodeBlockBytes = 8 << 10
	// MaxCodeBlockTotalBytes caps all retained code blocks together.
	MaxCodeBlockTotalBytes = 64 << 10
	// MaxDocumentTitleBytes caps the extracted title.
	MaxDocumentTitleBytes = 512
	// MaxHTMLInputBytes caps raw HTML accepted by the extractor.
	MaxHTMLInputBytes = 4 << 20
)

// Document is normalized HTML content. SHA256 covers the retained title, text,
// and code blocks so identical inputs hash identically.
type Document struct {
	Title      string
	Text       string
	CodeBlocks []string
	SHA256     string
	Truncated  bool
}

var skippedHTMLSubtrees = map[string]struct{}{
	"script":   {},
	"style":    {},
	"noscript": {},
	"template": {},
	"iframe":   {},
	"object":   {},
	"svg":      {},
	"math":     {},
}

// ExtractHTML strips script/style and other non-content subtrees, normalizes
// whitespace, extracts code blocks, caps output, and hashes the result. Page
// content remains untrusted data.
func ExtractHTML(content []byte, maxTextBytes int) (Document, error) {
	if len(content) == 0 {
		return Document{}, fmt.Errorf("%w: html content is empty", ErrInvalid)
	}
	if len(content) > MaxHTMLInputBytes {
		return Document{}, fmt.Errorf("%w: html content exceeds %d bytes", ErrInvalid, MaxHTMLInputBytes)
	}
	if maxTextBytes <= 0 {
		maxTextBytes = DefaultMaxTextBytes
	}
	if maxTextBytes > MaxDocumentTextBytes {
		maxTextBytes = MaxDocumentTextBytes
	}
	root, err := xhtml.Parse(bytes.NewReader(content))
	if err != nil {
		return Document{}, fmt.Errorf("%w: parse html: %v", ErrInvalid, err)
	}
	var (
		title      string
		text       strings.Builder
		codeBlocks []string
		codeBytes  int
		truncated  bool
	)
	appendCodeBlock := func(raw string) {
		block := strings.TrimSpace(raw)
		if block == "" || len(codeBlocks) >= MaxCodeBlocks {
			return
		}
		block, truncated = truncate(block, MaxCodeBlockBytes, truncated)
		remaining := MaxCodeBlockTotalBytes - codeBytes
		if remaining <= 0 {
			truncated = true
			return
		}
		block, truncated = truncate(block, remaining, truncated)
		codeBlocks = append(codeBlocks, block)
		codeBytes += len(block)
	}
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node == nil {
			return
		}
		if node.Type == xhtml.ElementNode {
			name := strings.ToLower(node.Data)
			if _, skip := skippedHTMLSubtrees[name]; skip {
				return
			}
			switch name {
			case "title":
				if title == "" {
					title = collapseWhitespace(nodeText(node))
					title, truncated = truncate(title, MaxDocumentTitleBytes, truncated)
				}
				return
			case "pre":
				appendCodeBlock(nodeText(node))
				return
			case "code":
				appendCodeBlock(nodeText(node))
			}
		}
		if node.Type == xhtml.TextNode {
			text.WriteString(node.Data)
			text.WriteByte(' ')
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	normalized := collapseWhitespace(text.String())
	normalized, truncated = truncate(normalized, maxTextBytes, truncated)
	document := Document{
		Title:      title,
		Text:       normalized,
		CodeBlocks: codeBlocks,
		Truncated:  truncated,
	}
	document.SHA256 = documentHash(document)
	return document, nil
}

// documentHash hashes the canonical retained document fields.
func documentHash(document Document) string {
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, document.Title)
	_, _ = hasher.Write([]byte{'\n'})
	_, _ = io.WriteString(hasher, document.Text)
	_, _ = hasher.Write([]byte{'\n'})
	if document.Truncated {
		_, _ = hasher.Write([]byte("truncated\n"))
	}
	for _, block := range document.CodeBlocks {
		_, _ = io.WriteString(hasher, block)
		_, _ = hasher.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func nodeText(node *xhtml.Node) string {
	var builder strings.Builder
	var walk func(*xhtml.Node)
	walk = func(current *xhtml.Node) {
		if current == nil {
			return
		}
		if current.Type == xhtml.ElementNode {
			if _, skip := skippedHTMLSubtrees[strings.ToLower(current.Data)]; skip {
				return
			}
			if strings.EqualFold(current.Data, "br") {
				builder.WriteByte('\n')
			}
		}
		if current.Type == xhtml.TextNode {
			builder.WriteString(current.Data)
		}
		for child := current.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(node)
	return builder.String()
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func truncate(value string, max int, truncated bool) (string, bool) {
	if max < 0 {
		max = 0
	}
	if len(value) <= max {
		return value, truncated
	}
	cut := max
	for cut > 0 && cut < len(value) && !utf8.RuneStart(value[cut]) {
		cut--
	}
	value = strings.TrimSpace(value[:cut])
	return value, true
}
