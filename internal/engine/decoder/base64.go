package decoder

import "encoding/base64"

// base64Encodings is the shared attempt order. Hoisted to package scope so the
// slice is static data instead of being rebuilt on every TryBase64/DecodeAll
// call, both of which run per candidate per request.
var base64Encodings = []*base64.Encoding{
	base64.StdEncoding,
	base64.RawStdEncoding,
	base64.URLEncoding,
	base64.RawURLEncoding,
}

func TryBase64(raw string) (string, bool) {
	for _, encoding := range base64Encodings {
		decoded, err := encoding.DecodeString(raw)
		if err == nil && len(decoded) > 0 {
			return string(decoded), true
		}
	}
	return "", false
}
