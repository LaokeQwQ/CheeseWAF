package decoder

import "net/url"

func URL(raw string) (string, error) {
	return url.QueryUnescape(raw)
}
