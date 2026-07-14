package imageengine

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
)

func PNGBytes(src image.Image, limits Limits) ([]byte, error) {
	if src == nil || src.Bounds().Empty() {
		return nil, ErrInvalidImage
	}
	limits = limits.normalized()
	if err := limits.validateDimensions(src.Bounds().Dx(), src.Bounds().Dy()); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	buffer.Grow(min(limits.MaxEncodedBytes, 64<<10))
	if err := png.Encode(&limitedBuffer{Buffer: &buffer, Remaining: limits.MaxEncodedBytes}, src); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func PNGDataURI(src image.Image, limits Limits) (string, error) {
	data, err := PNGBytes(src, limits)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(data), nil
}

type limitedBuffer struct {
	Buffer    *bytes.Buffer
	Remaining int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > w.Remaining {
		return 0, ErrResourceLimit
	}
	n, err := w.Buffer.Write(p)
	w.Remaining -= n
	return n, err
}
