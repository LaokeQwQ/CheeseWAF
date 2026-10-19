package rules

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

type requestViews struct {
	decoded      map[string][]string
	err          error
	body         string
	bodyReady    bool
	headers      string
	headersReady bool
	cookies      string
	cookiesReady bool
}

func (v *requestViews) match(rule Rule, reqCtx *engine.RequestContext) string {
	if reqCtx == nil || reqCtx.Request == nil {
		return ""
	}
	r := reqCtx.Request
	switch rule.Location {
	case "request_uri":
		return r.URL.RequestURI()
	case "query":
		return r.URL.RawQuery
	case "body":
		if !v.bodyReady {
			body := reqCtx.DecodedBody
			v.body = string(body)
			v.bodyReady = true
		}
		return v.body
	case "header":
		if !v.headersReady {
			v.headers = headersText(r.Header)
			v.headersReady = true
		}
		return v.headers
	case "cookie":
		if !v.cookiesReady {
			var builder strings.Builder
			for _, cookie := range r.Cookies() {
				builder.WriteString(cookie.Name)
				builder.WriteByte('=')
				builder.WriteString(cookie.Value)
				builder.WriteByte(';')
			}
			v.cookies = builder.String()
			v.cookiesReady = true
		}
		return v.cookies
	case "method":
		return r.Method
	default:
		if reqCtx.NormalizedPath != "" {
			return reqCtx.NormalizedPath
		}
		return r.URL.Path
	}
}

func headersText(header http.Header) string {
	var builder strings.Builder
	for key, values := range header {
		builder.WriteString(key)
		builder.WriteByte(':')
		builder.WriteString(strings.Join(values, ","))
		builder.WriteByte('\n')
	}
	return builder.String()
}

// variants preserves the exact raw view and adds bounded application decoding.
// Keeping separate views preserves anchored rule semantics.
func (v *requestViews) variants(rule Rule, reqCtx *engine.RequestContext) []string {
	cacheKey := rule.Location
	if rule.Location == "uri" || rule.Location == "path" {
		if reqCtx != nil {
			cacheKey += ":" + reqCtx.NormalizedPath
		}
	}
	if cached, ok := v.decoded[cacheKey]; ok {
		return cached
	}
	rawValues := []string{v.match(rule, reqCtx)}
	if rule.Location == "args" {
		rawValues = v.argumentValues(reqCtx)
	}
	out := make([]string, 0, len(rawValues)*2)
	for _, raw := range rawValues {
		out = append(out, raw)
	}
	defer func() {
		if v.decoded == nil {
			v.decoded = make(map[string][]string)
		}
		v.decoded[cacheKey] = out
	}()
	if rule.Location == "method" {
		return out
	}
	for _, raw := range rawValues {
		decoded := decoder.DecodeWithDepthPreserveControls(raw, decoder.MaxDecodeDepth).Text
		if decoded != raw {
			out = append(out, decoded)
		}
	}
	if rule.Location == "args" {
		return out
	}
	raw := rawValues[0]
	if rule.Location == "body" && reqCtx != nil && reqCtx.Request != nil && strings.Contains(strings.ToLower(reqCtx.Request.Header.Get("Content-Type")), "json") {
		// JSON string escapes need their own application view. Decoder recursion is
		// capped by encoding/json; iterative tokenization avoids constructing a tree.
		if !json.Valid([]byte(raw)) {
			v.err = ruleInputIncompleteError{}
			return out
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		for tokens := 0; ; tokens++ {
			if tokens >= 4096 {
				v.err = ruleInputIncompleteError{}
				break
			}
			token, err := dec.Token()
			if err != nil {
				if err != io.EOF {
					v.err = ruleInputIncompleteError{}
				}
				break
			}
			if value, ok := token.(string); ok {
				out = append(out, value)
				text := decoder.DecodeWithDepthPreserveControls(value, decoder.MaxDecodeDepth).Text
				if text != value {
					out = append(out, text)
				}
			}
		}
	}
	return out
}

// argumentValues mirrors ModSecurity ARGS: each query or URL-encoded form
// argument value is inspected independently; argument names are not included.
func (v *requestViews) argumentValues(reqCtx *engine.RequestContext) []string {
	if reqCtx == nil || reqCtx.Request == nil {
		return nil
	}
	r := reqCtx.Request
	values := make([]string, 0)
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		v.err = ruleInputIncompleteError{}
	}
	queryKeys := make([]string, 0, len(query))
	for key := range query {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	for _, key := range queryKeys {
		values = append(values, query[key]...)
	}
	mediaType, _, mediaTypeErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaTypeErr == nil && strings.EqualFold(mediaType, "application/x-www-form-urlencoded") {
		form, err := url.ParseQuery(string(reqCtx.DecodedBody))
		if err != nil {
			v.err = ruleInputIncompleteError{}
		}
		formKeys := make([]string, 0, len(form))
		for key := range form {
			formKeys = append(formKeys, key)
		}
		sort.Strings(formKeys)
		for _, key := range formKeys {
			values = append(values, form[key]...)
		}
	}
	return values
}

type ruleInputIncompleteError struct{}

func (ruleInputIncompleteError) Error() string            { return "custom rule JSON field inspection incomplete" }
func (ruleInputIncompleteError) AnalysisIncomplete() bool { return true }
func (ruleInputIncompleteError) IncompleteReason() string { return "custom_rule_json_field_limit" }
