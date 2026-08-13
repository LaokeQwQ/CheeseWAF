package assets

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"path/filepath"
	"strings"
)

const (
	DefaultMaxImageBytes = 8 << 20
	DefaultMaxFontBytes  = 16 << 20
	DefaultMaxPixels     = 16_000_000
	DefaultMaxAssets     = 512
	DefaultMaxTotalBytes = 512 << 20
)

type Limits struct {
	MaxImageBytes int64
	MaxFontBytes  int64
	MaxPixels     int64
	MaxAssets     int
	MaxTotalBytes int64
}

func (l Limits) normalized() Limits {
	if l.MaxImageBytes <= 0 {
		l.MaxImageBytes = DefaultMaxImageBytes
	}
	if l.MaxFontBytes <= 0 {
		l.MaxFontBytes = DefaultMaxFontBytes
	}
	if l.MaxPixels <= 0 {
		l.MaxPixels = DefaultMaxPixels
	}
	if l.MaxAssets <= 0 {
		l.MaxAssets = DefaultMaxAssets
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = DefaultMaxTotalBytes
	}
	return l
}

func (l Limits) maxBytesFor(kind Kind) int64 {
	l = l.normalized()
	if kind == KindFont {
		return l.MaxFontBytes
	}
	return l.MaxImageBytes
}

func (l Limits) allows(count int, totalBytes, addedBytes int64) bool {
	l = l.normalized()
	return count < l.MaxAssets && addedBytes > 0 && addedBytes <= l.MaxTotalBytes && totalBytes <= l.MaxTotalBytes-addedBytes
}

func validateStoredMetadata(asset Asset, expectedKind Kind, expectedID string, limits Limits) error {
	if !validID(asset.ID) || (expectedID != "" && asset.ID != expectedID) {
		return fmt.Errorf("%w: invalid asset id metadata", ErrInvalidAsset)
	}
	if !knownKind(asset.Kind) || (expectedKind != "" && asset.Kind != expectedKind) {
		return fmt.Errorf("%w: invalid asset kind metadata", ErrInvalidAsset)
	}
	if asset.Size <= 0 || asset.Size > limits.maxBytesFor(asset.Kind) {
		return fmt.Errorf("%w: invalid asset size metadata", ErrInvalidAsset)
	}
	if asset.CreatedAt.IsZero() {
		return fmt.Errorf("%w: invalid asset creation time metadata", ErrInvalidAsset)
	}
	if asset.Name == "" || len(asset.Name) > 255 || strings.ContainsAny(asset.Name, "\\/\x00\r\n") {
		return fmt.Errorf("%w: invalid asset name metadata", ErrInvalidAsset)
	}
	if asset.Kind == KindFont {
		switch asset.ContentType {
		case "font/otf", "font/ttf", "font/collection":
		default:
			return fmt.Errorf("%w: invalid font content type metadata", ErrInvalidAsset)
		}
	} else if asset.ContentType != "image/jpeg" && asset.ContentType != "image/png" {
		return fmt.Errorf("%w: invalid image content type metadata", ErrInvalidAsset)
	}
	digest, err := hex.DecodeString(asset.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("%w: invalid asset digest metadata", ErrInvalidAsset)
	}
	return nil
}

func validate(kind Kind, name, declared string, r io.Reader, limits Limits) ([]byte, string, error) {
	limits = limits.normalized()
	if r == nil {
		return nil, "", fmt.Errorf("%w: reader is required", ErrInvalidAsset)
	}
	if kind != KindBackground && kind != KindFont && kind != KindIcon && kind != KindLogo {
		return nil, "", fmt.Errorf("%w: unsupported kind", ErrInvalidAsset)
	}
	max := limits.MaxImageBytes
	if kind == KindFont {
		max = limits.MaxFontBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, "", fmt.Errorf("read asset: %w", err)
	}
	if int64(len(data)) > max {
		return nil, "", fmt.Errorf("%w: file exceeds %d bytes", ErrInvalidAsset, max)
	}
	if len(data) == 0 {
		return nil, "", fmt.Errorf("%w: empty file", ErrInvalidAsset)
	}
	if kind == KindFont {
		ct, err := validateFont(data)
		return data, ct, err
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, "", fmt.Errorf("%w: image decode failed", ErrInvalidAsset)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > limits.MaxPixels {
		return nil, "", fmt.Errorf("%w: invalid image dimensions", ErrInvalidAsset)
	}
	ct := map[string]string{"jpeg": "image/jpeg", "png": "image/png"}[format]
	if ct == "" {
		return nil, "", fmt.Errorf("%w: unsupported image format", ErrInvalidAsset)
	}
	declared = strings.ToLower(strings.TrimSpace(strings.Split(declared, ";")[0]))
	if declared != "" && declared != ct {
		return nil, "", fmt.Errorf("%w: content type does not match content", ErrInvalidAsset)
	}
	if ext := strings.ToLower(filepath.Ext(name)); ext != "" {
		if byExt := mime.TypeByExtension(ext); byExt != "" && strings.Split(byExt, ";")[0] != ct {
			return nil, "", fmt.Errorf("%w: filename extension does not match content", ErrInvalidAsset)
		}
	}
	return data, ct, nil
}

func readAndVerifyStoredAsset(r io.Reader, asset Asset, limits Limits) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: object body is missing", ErrInvalidAsset)
	}
	limits = limits.normalized()
	max := limits.MaxImageBytes
	if asset.Kind == KindFont {
		max = limits.MaxFontBytes
	}
	if asset.Size <= 0 || asset.Size > max {
		return nil, fmt.Errorf("%w: invalid object size metadata", ErrInvalidAsset)
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("read stored captcha asset: %w", err)
	}
	if int64(len(data)) > max || int64(len(data)) != asset.Size {
		return nil, fmt.Errorf("%w: object length mismatch", ErrInvalidAsset)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(data))
	if len(asset.SHA256) != sha256.Size*2 || !strings.EqualFold(sum, asset.SHA256) {
		return nil, fmt.Errorf("%w: object digest mismatch", ErrInvalidAsset)
	}
	validated, contentType, err := validate(asset.Kind, asset.Name, asset.ContentType, bytes.NewReader(data), limits)
	if err != nil {
		return nil, fmt.Errorf("%w: stored object validation failed", ErrInvalidAsset)
	}
	if len(validated) != len(data) || contentType != asset.ContentType {
		return nil, fmt.Errorf("%w: object content type mismatch", ErrInvalidAsset)
	}
	return data, nil
}
func validateFont(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("%w: truncated font", ErrInvalidAsset)
	}
	switch string(data[:4]) {
	case "OTTO":
		return "font/otf", nil
	case "ttcf":
		return "font/collection", nil
	case "wOFF", "wOF2":
		return "", fmt.Errorf("%w: web fonts are not accepted", ErrInvalidAsset)
	default:
		if binary.BigEndian.Uint32(data[:4]) == 0x00010000 {
			return "font/ttf", nil
		}
	}
	return "", fmt.Errorf("%w: unsupported font format", ErrInvalidAsset)
}
