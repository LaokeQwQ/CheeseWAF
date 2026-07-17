// Package captcha provides the Altcha-compatible proof-of-work challenge used
// by the admin login flow and other browser-verification surfaces.
package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const AlgorithmSHA256 = "SHA-256"

const (
	altchaMaxFieldBytes   = 4096
	altchaMaxPayloadBytes = 8192
)

type Challenge struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	MaxNumber int    `json:"max_number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type Payload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

type Options struct {
	Secret    string
	Purpose   string
	ClientKey string
	Path      string
	MaxNumber int
	TTL       time.Duration
	Now       func() time.Time
}

func NewChallenge(opts Options) (Challenge, error) {
	opts = normalizeOptions(opts)
	if strings.TrimSpace(opts.Secret) == "" {
		return Challenge{}, fmt.Errorf("captcha secret is required")
	}
	number, err := randomNumber(opts.MaxNumber)
	if err != nil {
		return Challenge{}, err
	}
	nonce, err := randomToken(18)
	if err != nil {
		return Challenge{}, err
	}
	expires := opts.now().Add(opts.TTL)
	salt := fmt.Sprintf("%s:%d", nonce, expires.Unix())
	out := Challenge{
		Algorithm: AlgorithmSHA256,
		Challenge: Hash(salt, number),
		MaxNumber: opts.MaxNumber,
		Salt:      salt,
		ExpiresAt: expires.UTC().Format(time.RFC3339),
	}
	out.Signature = sign(opts, out.Algorithm, out.Challenge, out.Salt)
	return out, nil
}

func Verify(opts Options, payload Payload) bool {
	opts = normalizeOptions(opts)
	if strings.TrimSpace(opts.Secret) == "" {
		return false
	}
	if len(payload.Algorithm) > 32 || len(payload.Challenge) > altchaMaxFieldBytes || len(payload.Salt) > altchaMaxFieldBytes || len(payload.Signature) > altchaMaxFieldBytes {
		return false
	}
	if !strings.EqualFold(payload.Algorithm, AlgorithmSHA256) || payload.Challenge == "" || payload.Salt == "" || payload.Signature == "" {
		return false
	}
	if payload.Number < 0 || payload.Number > opts.MaxNumber {
		return false
	}
	expires, ok := saltExpires(payload.Salt)
	if !ok || expires <= opts.now().Unix() {
		return false
	}
	want := sign(opts, payload.Algorithm, payload.Challenge, payload.Salt)
	if !hmac.Equal([]byte(want), []byte(payload.Signature)) {
		return false
	}
	return hmac.Equal([]byte(Hash(payload.Salt, payload.Number)), []byte(payload.Challenge))
}

func ParsePayload(raw string) (Payload, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > altchaMaxPayloadBytes {
		return Payload{}, false
	}
	raw = strings.TrimPrefix(raw, "challenge=")
	raw = strings.Trim(raw, `"`)
	if raw == "" {
		return Payload{}, false
	}
	var data []byte
	if strings.HasPrefix(raw, "{") {
		data = []byte(raw)
	} else {
		if base64.RawStdEncoding.DecodedLen(len(raw)) > altchaMaxPayloadBytes {
			return Payload{}, false
		}
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			decoded, err := encoding.DecodeString(raw)
			if err == nil {
				data = decoded
				break
			}
		}
	}
	if len(data) == 0 || len(data) > altchaMaxPayloadBytes {
		return Payload{}, false
	}
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		return Payload{}, false
	}
	return payload, true
}

func Hash(salt string, number int) string {
	sum := sha256.Sum256([]byte(salt + strconv.Itoa(number)))
	return hex.EncodeToString(sum[:])
}

func normalizeOptions(opts Options) Options {
	if opts.Purpose == "" {
		opts.Purpose = "captcha"
	}
	if opts.MaxNumber <= 0 {
		opts.MaxNumber = 75000
	}
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func (opts Options) now() time.Time {
	if opts.Now == nil {
		return time.Now()
	}
	return opts.Now()
}

func sign(opts Options, algorithm, challenge, salt string) string {
	mac := hmac.New(sha256.New, []byte(opts.Secret))
	for _, item := range []string{opts.Purpose, opts.ClientKey, opts.Path, algorithm, challenge, salt} {
		_, _ = mac.Write([]byte(item))
		_, _ = mac.Write([]byte{'\n'})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func saltExpires(salt string) (int64, bool) {
	_, rawExpires, ok := strings.Cut(salt, ":")
	if !ok {
		return 0, false
	}
	expires, err := strconv.ParseInt(rawExpires, 10, 64)
	return expires, err == nil
}

func randomNumber(max int) (int, error) {
	if max <= 0 {
		max = 75000
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max+1)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randomToken(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
