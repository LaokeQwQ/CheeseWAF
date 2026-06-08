package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpIssuer = "CheeseWAF"
	totpPeriod = int64(30)
	totpDigits = 6
)

func generateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func totpURL(username, secret string) string {
	label := url.PathEscape(fmt.Sprintf("%s:%s", totpIssuer, username))
	values := url.Values{}
	values.Set("secret", secret)
	values.Set("issuer", totpIssuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprint(totpDigits))
	values.Set("period", fmt.Sprint(totpPeriod))
	return fmt.Sprintf("otpauth://totp/%s?%s", label, values.Encode())
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, char := range code {
		if char < '0' || char > '9' {
			return false
		}
	}
	counter := now.Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		expected, err := hotp(secret, counter+offset)
		if err == nil && hmac.Equal([]byte(expected), []byte(code)) {
			return true
		}
	}
	return false
}

func hotp(secret string, counter int64) (string, error) {
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := decoder.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(msg[:]); err != nil {
		return "", err
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (int(sum[offset])&0x7f)<<24 |
		(int(sum[offset+1])&0xff)<<16 |
		(int(sum[offset+2])&0xff)<<8 |
		(int(sum[offset+3]) & 0xff)
	mod := 1
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod), nil
}
