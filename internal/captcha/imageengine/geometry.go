package imageengine

import (
	"errors"
	"image"
)

func RectsOverlapWithPadding(a, b image.Rectangle, padding int) bool {
	if padding < 0 {
		padding = 0
	}
	expanded := image.Rect(b.Min.X-padding, b.Min.Y-padding, b.Max.X+padding, b.Max.Y+padding)
	return a.Overlaps(expanded)
}

func PlaceNonOverlapping(rng RandomSource, bounds image.Rectangle, sizes []image.Point, padding, maxAttempts int) ([]image.Rectangle, error) {
	if rng == nil || bounds.Empty() || maxAttempts <= 0 {
		return nil, errors.New("imageengine: invalid layout options")
	}
	if padding < 0 {
		return nil, errors.New("imageengine: negative layout padding")
	}
	placed := make([]image.Rectangle, 0, len(sizes))
	for _, size := range sizes {
		if size.X <= 0 || size.Y <= 0 || size.X > bounds.Dx() || size.Y > bounds.Dy() {
			return nil, ErrInvalidDimensions
		}
		found := false
		for attempt := 0; attempt < maxAttempts; attempt++ {
			x, err := RandomInt(rng, bounds.Min.X, bounds.Max.X-size.X+1)
			if err != nil {
				return nil, err
			}
			y, err := RandomInt(rng, bounds.Min.Y, bounds.Max.Y-size.Y+1)
			if err != nil {
				return nil, err
			}
			candidate := image.Rect(x, y, x+size.X, y+size.Y)
			valid := true
			for _, existing := range placed {
				if RectsOverlapWithPadding(candidate, existing, padding) {
					valid = false
					break
				}
			}
			if valid {
				placed = append(placed, candidate)
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("imageengine: unable to place items without overlap")
		}
	}
	return placed, nil
}
