package rules

import (
	"net/http"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type requestViews struct {
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
	case "query":
		return r.URL.RawQuery
	case "body":
		if !v.bodyReady {
			body := reqCtx.DecodedBody
			if len(body) > engine.MaxDecodedBytes {
				body = body[:engine.MaxDecodedBytes]
			}
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
