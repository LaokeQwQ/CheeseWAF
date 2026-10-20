package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

func clientFingerprint(r *http.Request) string {
	if r == nil {
		return ""
	}
	ua := strings.ToLower(strings.Join(strings.Fields(r.UserAgent()), " "))
	lang := normalizeAcceptLanguage(r.Header.Get("Accept-Language"))
	if ua == "" && lang == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua + "\n" + lang))
	return hex.EncodeToString(sum[:8])
}

// normalizeAcceptLanguage makes the low-confidence UA/language auxiliary key
// stable across harmless whitespace, case, q-value and ordering changes. It is
// deliberately still only an auxiliary signal; it is not a browser identity.
func normalizeAcceptLanguage(raw string) string {
	type language struct {
		tag string
		q   int
		pos int
	}
	var values []language
	for pos, part := range strings.Split(raw, ",") {
		fields := strings.Split(part, ";")
		tag := strings.ToLower(strings.TrimSpace(fields[0]))
		if tag == "" {
			continue
		}
		q := 1000
		for _, param := range fields[1:] {
			name, value, ok := strings.Cut(strings.TrimSpace(param), "=")
			if ok && strings.EqualFold(strings.TrimSpace(name), "q") {
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil || parsed < 0 || parsed > 1 {
					q = 0
				} else {
					q = int(parsed*1000 + 0.5)
				}
			}
		}
		values = append(values, language{tag: tag, q: q, pos: pos})
	}
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].q != values[j].q {
			return values[i].q > values[j].q
		}
		if values[i].tag != values[j].tag {
			return values[i].tag < values[j].tag
		}
		return values[i].pos < values[j].pos
	})
	seen := make(map[string]struct{}, len(values))
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value.tag]; ok {
			continue
		}
		seen[value.tag] = struct{}{}
		parts = append(parts, value.tag+";q="+strconv.Itoa(value.q))
	}
	return strings.Join(parts, ",")
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
