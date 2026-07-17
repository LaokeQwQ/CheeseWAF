package captcha

import (
	"image"
	"image/color"
	"testing"
)

func TestDrawRotationLandmarksCrossesCenterCrop(t *testing.T) {
	base := color.RGBA{R: 20, G: 40, B: 60, A: 255}
	canvas := image.NewRGBA(image.Rect(0, 0, 320, 180))
	for y := canvas.Bounds().Min.Y; y < canvas.Bounds().Max.Y; y++ {
		for x := canvas.Bounds().Min.X; x < canvas.Bounds().Max.X; x++ {
			canvas.SetRGBA(x, y, base)
		}
	}

	drawRotationLandmarks(canvas, 112)
	cx, cy := canvas.Bounds().Dx()/2, canvas.Bounds().Dy()/2
	insideChanged := false
	outsideChanged := false
	for y := canvas.Bounds().Min.Y; y < canvas.Bounds().Max.Y; y++ {
		for x := canvas.Bounds().Min.X; x < canvas.Bounds().Max.X; x++ {
			if canvas.RGBAAt(x, y) == base {
				continue
			}
			distanceSquared := (x-cx)*(x-cx) + (y-cy)*(y-cy)
			if distanceSquared <= 56*56 {
				insideChanged = true
			} else {
				outsideChanged = true
			}
		}
	}
	if !insideChanged || !outsideChanged {
		t.Fatalf("rotation landmark must cross crop boundary: inside=%v outside=%v", insideChanged, outsideChanged)
	}
}
