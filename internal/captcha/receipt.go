package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type ReceiptOptions struct {
	Secret    string
	Purpose   string
	ClientKey string
	Path      string
	TTL       time.Duration
	Now       func() time.Time
}

type receiptPayload struct {
	Purpose   string `json:"purpose"`
	ClientKey string `json:"client_key"`
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	Expires   int64  `json:"expires"`
	Nonce     string `json:"nonce"`
}

func NewReceipt(opts ReceiptOptions, mode string) (string, time.Time, error) {
	opts = normalizeReceiptOptions(opts)
	expires := opts.now().Add(opts.TTL).UTC()
	nonce, err := randomToken(16)
	if err != nil {
		return "", time.Time{}, err
	}
	payload := receiptPayload{
		Purpose:   opts.Purpose,
		ClientKey: opts.ClientKey,
		Path:      opts.Path,
		Mode:      normalizeReceiptMode(mode),
		Expires:   expires.Unix(),
		Nonce:     nonce,
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(rawPayload)
	signature := signReceipt(opts, encoded)
	return encoded + "." + signature, expires, nil
}

func VerifyReceipt(opts ReceiptOptions, receipt string, mode string) bool {
	opts = normalizeReceiptOptions(opts)
	encoded, signature, ok := strings.Cut(strings.TrimSpace(receipt), ".")
	if !ok || encoded == "" || signature == "" {
		return false
	}
	want := signReceipt(opts, encoded)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return false
	}
	var payload receiptPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return false
	}
	if payload.Purpose != opts.Purpose || payload.ClientKey != opts.ClientKey || payload.Path != opts.Path {
		return false
	}
	if payload.Mode != normalizeReceiptMode(mode) {
		return false
	}
	return payload.Expires > opts.now().UTC().Unix()
}

func normalizeReceiptOptions(opts ReceiptOptions) ReceiptOptions {
	if opts.Purpose == "" {
		opts.Purpose = "captcha-receipt"
	}
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func (opts ReceiptOptions) now() time.Time {
	if opts.Now == nil {
		return time.Now()
	}
	return opts.Now()
}

func normalizeReceiptMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "captcha"
	}
	return mode
}

func signReceipt(opts ReceiptOptions, encodedPayload string) string {
	mac := hmac.New(sha256.New, []byte(opts.Secret))
	for _, item := range []string{opts.Purpose, opts.ClientKey, opts.Path, encodedPayload} {
		_, _ = mac.Write([]byte(item))
		_, _ = mac.Write([]byte{'\n'})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func ReceiptFingerprint(receipt string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(receipt)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
