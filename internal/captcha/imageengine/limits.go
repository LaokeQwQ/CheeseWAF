package imageengine

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidDimensions = errors.New("imageengine: invalid dimensions")
	ErrResourceLimit     = errors.New("imageengine: resource limit exceeded")
	ErrInvalidImage      = errors.New("imageengine: invalid image")
)

type Limits struct {
	MaxWidth        int
	MaxHeight       int
	MaxPixels       int64
	MaxLayers       int
	MaxEncodedBytes int
}

func DefaultLimits() Limits {
	return Limits{MaxWidth: 1024, MaxHeight: 1024, MaxPixels: 1_048_576, MaxLayers: 64, MaxEncodedBytes: 4 << 20}
}

func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxWidth <= 0 {
		l.MaxWidth = d.MaxWidth
	}
	if l.MaxHeight <= 0 {
		l.MaxHeight = d.MaxHeight
	}
	if l.MaxPixels <= 0 {
		l.MaxPixels = d.MaxPixels
	}
	if l.MaxLayers <= 0 {
		l.MaxLayers = d.MaxLayers
	}
	if l.MaxEncodedBytes <= 0 {
		l.MaxEncodedBytes = d.MaxEncodedBytes
	}
	return l
}

func (l Limits) validateDimensions(width, height int) error {
	l = l.normalized()
	if width <= 0 || height <= 0 {
		return ErrInvalidDimensions
	}
	if width > l.MaxWidth || height > l.MaxHeight || int64(width) > l.MaxPixels/int64(height) {
		return fmt.Errorf("%w: requested %dx%d", ErrResourceLimit, width, height)
	}
	return nil
}
