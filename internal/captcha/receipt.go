package captcha

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	receiptMaxEncodedBytes = 4096
	receiptMaxPayloadBytes = 3072
)

type ReceiptOptions struct {
	Secret    string
	Purpose   string
	ClientKey string
	Path      string
	Subject   string
	TTL       time.Duration
	Now       func() time.Time
}

type receiptPayload struct {
	Purpose   string `json:"purpose"`
	ClientKey string `json:"client_key"`
	Path      string `json:"path"`
	Subject   string `json:"subject,omitempty"`
	Mode      string `json:"mode"`
	ExpiresMS int64  `json:"expires_ms"`
	Nonce     string `json:"nonce"`
}

func NewReceipt(opts ReceiptOptions, mode string) (string, time.Time, error) {
	opts = normalizeReceiptOptions(opts)
	if strings.TrimSpace(opts.Secret) == "" {
		return "", time.Time{}, fmt.Errorf("captcha receipt secret is required")
	}
	expires := opts.now().Add(opts.TTL).UTC()
	nonce, err := randomToken(16)
	if err != nil {
		return "", time.Time{}, err
	}
	payload := receiptPayload{
		Purpose:   opts.Purpose,
		ClientKey: opts.ClientKey,
		Path:      opts.Path,
		Subject:   normalizeReceiptSubject(opts.Subject),
		Mode:      normalizeReceiptMode(mode),
		ExpiresMS: expires.UnixMilli(),
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
	if strings.TrimSpace(opts.Secret) == "" {
		return false
	}
	receipt = strings.TrimSpace(receipt)
	if len(receipt) == 0 || len(receipt) > receiptMaxEncodedBytes {
		return false
	}
	encoded, signature, ok := strings.Cut(receipt, ".")
	if !ok || encoded == "" || signature == "" {
		return false
	}
	if base64.RawURLEncoding.DecodedLen(len(encoded)) > receiptMaxPayloadBytes {
		return false
	}
	want := signReceipt(opts, encoded)
	if !hmac.Equal([]byte(want), []byte(signature)) {
		return false
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(rawPayload) > receiptMaxPayloadBytes {
		return false
	}
	var payload receiptPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return false
	}
	if payload.Purpose != opts.Purpose || payload.ClientKey != opts.ClientKey || payload.Path != opts.Path || payload.Subject != normalizeReceiptSubject(opts.Subject) {
		return false
	}
	if payload.Mode != normalizeReceiptMode(mode) {
		return false
	}
	return payload.ExpiresMS > opts.now().UTC().UnixMilli()
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

func normalizeReceiptSubject(subject string) string {
	return strings.ToLower(strings.TrimSpace(subject))
}

func signReceipt(opts ReceiptOptions, encodedPayload string) string {
	mac := hmac.New(sha256.New, []byte(opts.Secret))
	for _, item := range []string{opts.Purpose, opts.ClientKey, opts.Path, normalizeReceiptSubject(opts.Subject), encodedPayload} {
		_, _ = mac.Write([]byte(item))
		_, _ = mac.Write([]byte{'\n'})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func ReceiptFingerprint(receipt string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(receipt)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
