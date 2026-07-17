package imageengine_test

import (
	"image"
	"image/color"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

func TestShapeMaskPoolKeepsSafeMargins(t *testing.T) {
	kinds := []imageengine.ShapeKind{
		imageengine.ShapePuzzle, imageengine.ShapeCircle, imageengine.ShapeTriangle,
		imageengine.ShapeSquare, imageengine.ShapeDiamond, imageengine.ShapeTrapezoid,
		imageengine.ShapeShield,
	}
	for _, kind := range kinds {
		t.Run(string(kind), func(t *testing.T) {
			mask, err := imageengine.NewShapeMask(kind, 72, 7, imageengine.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			bounds, ok := alphaBounds(mask.Alpha)
			if !ok {
				t.Fatal("mask is empty")
			}
			if bounds.Min.X < 7 || bounds.Min.Y < 7 || bounds.Max.X > 65 || bounds.Max.Y > 65 {
				t.Fatalf("mask violates safe margin: %v", bounds)
			}
		})
	}
}

func TestPieceAndSlotUseIdenticalMask(t *testing.T) {
	mask, err := imageengine.NewShapeMask(imageengine.ShapePuzzle, 72, 7, imageengine.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	src := image.NewRGBA(image.Rect(0, 0, 160, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 160; x++ {
			src.SetRGBA(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 180, A: 255})
		}
	}
	piece, err := imageengine.ExtractPiece(src, image.Pt(30, 12), mask)
	if err != nil {
		t.Fatal(err)
	}
	slot := image.NewRGBA(src.Bounds())
	if err := imageengine.DrawSlot(slot, image.Pt(30, 12), mask, color.RGBA{A: 100}, color.RGBA{R: 255, G: 255, B: 255, A: 255}, 3); err != nil {
		t.Fatal(err)
	}
	for y := 0; y < mask.Alpha.Bounds().Dy(); y++ {
		for x := 0; x < mask.Alpha.Bounds().Dx(); x++ {
			inside := mask.Alpha.AlphaAt(x, y).A > 0
			if (piece.RGBAAt(x, y).A > 0) != inside {
				t.Fatalf("piece alpha differs from mask at %d,%d", x, y)
			}
			if inside && slot.RGBAAt(x+30, y+12).A == 0 {
				t.Fatalf("slot missing mask pixel at %d,%d", x, y)
			}
		}
	}
}

func alphaBounds(mask *image.Alpha) (image.Rectangle, bool) {
	minX, minY, maxX, maxY := mask.Bounds().Max.X, mask.Bounds().Max.Y, mask.Bounds().Min.X, mask.Bounds().Min.Y
	found := false
	for y := mask.Bounds().Min.Y; y < mask.Bounds().Max.Y; y++ {
		for x := mask.Bounds().Min.X; x < mask.Bounds().Max.X; x++ {
			if mask.AlphaAt(x, y).A > 0 {
				found = true
				if x < minX {
					minX = x
				}
				if y < minY {
					minY = y
				}
				if x+1 > maxX {
					maxX = x + 1
				}
				if y+1 > maxY {
					maxY = y + 1
				}
			}
		}
	}
	return image.Rect(minX, minY, maxX, maxY), found
}
