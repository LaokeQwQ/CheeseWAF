package rules

import (
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func MatchValue(rule Rule, reqCtx *engine.RequestContext) string {
	if reqCtx == nil || reqCtx.Request == nil {
		return ""
	}
	r := reqCtx.Request
	switch rule.Location {
	case "body":
		return string(reqCtx.DecodedBody)
	case "header":
		return headersText(r.Header)
	case "cookie":
		var builder strings.Builder
		for _, cookie := range r.Cookies() {
			builder.WriteString(cookie.Name)
			builder.WriteByte('=')
			builder.WriteString(cookie.Value)
			builder.WriteByte(';')
		}
		return builder.String()
	case "method":
		return r.Method
	default:
		return r.URL.RequestURI()
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
