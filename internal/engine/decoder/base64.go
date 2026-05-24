package decoder

import "encoding/base64"

func TryBase64(raw string) (string, bool) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(raw)
		if err == nil && len(decoded) > 0 {
			return string(decoded), true
		}
	}
	return "", false
}
