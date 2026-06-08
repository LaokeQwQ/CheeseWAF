package proxy

import (
	"net/http"
	"strings"
)

func IsWebSocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	return headerHasToken(r.Header, "Connection", "upgrade") &&
		strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func headerHasToken(header http.Header, key, token string) bool {
	for _, value := range header.Values(key) {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}
