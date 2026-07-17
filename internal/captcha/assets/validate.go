package assets

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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
)

type Limits struct {
	MaxImageBytes int64
	MaxFontBytes  int64
	MaxPixels     int64
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
	return l
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
