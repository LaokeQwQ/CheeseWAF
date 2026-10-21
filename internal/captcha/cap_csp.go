package captcha

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// CapResourceOrigin returns one exact CSP source for a configured Cap resource.
// Paths never become policy text, and only HTTPS or loopback HTTP is accepted.
func CapResourceOrigin(raw string) string {
	if strings.ContainsRune(raw, '#') {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !validCapEndpoint(u) {
		return ""
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if strings.ContainsRune(host, ':') {
			// Retain the URL address family: IPv4-mapped IPv6 is an IPv6
			// origin in the browser, even though net.IP.String unmaps it.
			host = strings.ToLower(host)
			host = "[" + host + "]"
		} else {
			host = ip.String()
		}
	} else {
		host, err = idna.Lookup.ToASCII(strings.ToLower(host))
		if err != nil || host == "" || strings.ContainsAny(host, "*;'\"\\ \r\n\t") {
			return ""
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return ""
		}
		host += ":" + port
	} else if strings.HasSuffix(u.Host, ":") {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + host
}
