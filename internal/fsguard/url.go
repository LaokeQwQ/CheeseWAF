package fsguard

import "net/url"

func urlPathUnescape(s string) (string, error) {
	return url.PathUnescape(s)
}
