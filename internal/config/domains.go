package config

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
)

func normalizeSiteDomain(value string) (string, error) {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		if ip := net.ParseIP(value[1 : len(value)-1]); ip != nil {
			return ip.String(), nil
		}
		return "", fmt.Errorf("invalid bracketed IP address")
	}
	prefix := ""
	if strings.HasPrefix(value, "*.") {
		prefix = "*."
		value = value[2:]
	}
	host, err := idna.Lookup.ToASCII(value)
	if err != nil || host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid hostname label")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", fmt.Errorf("invalid hostname character")
			}
		}
	}
	return prefix + host, nil
}
