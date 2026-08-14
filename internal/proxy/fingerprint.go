package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

func clientFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	ua := strings.TrimSpace(r.UserAgent())
	lang := strings.TrimSpace(r.Header.Get("Accept-Language"))
	if ua == "" && lang == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua + "\n" + lang))
	return hex.EncodeToString(sum[:8])
}

func allowlistSkipWorthLogging(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.URL != nil && r.URL.RawQuery != "" {
		return true
	}
	return r.ContentLength > 0
}

func fingerprintDenied(denylist []string, fingerprint string) bool {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return false
	}
	for _, item := range denylist {
		if strings.EqualFold(strings.TrimSpace(item), fingerprint) {
			return true
		}
	}
	return false
}
