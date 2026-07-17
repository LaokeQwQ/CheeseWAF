package imageengine_test

import (
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

type sequenceRandom struct{ next uint64 }

func (r *sequenceRandom) Uint64() (uint64, error) { value := r.next; r.next += 7919; return value, nil }
func (r *sequenceRandom) Read(dst []byte) (int, error) {
	for i := range dst {
		dst[i] = byte(i + 1)
	}
	return len(dst), nil
}

func TestEngineRejectsUnsafeCanvasDimensions(t *testing.T) {
	engine := imageengine.New(imageengine.Limits{MaxWidth: 320, MaxHeight: 180, MaxPixels: 57_600}, &sequenceRandom{})
	if _, err := engine.NewCanvas(321, 180, color.White); err == nil {
		t.Fatal("expected oversized canvas to be rejected")
	}
	if _, err := engine.NewCanvas(0, 180, color.White); err == nil {
		t.Fatal("expected zero width to be rejected")
	}
}

func TestCropCoverPreservesAspectRatioAndCenters(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 4, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 4; x++ {
			src.SetRGBA(x, y, color.RGBA{R: uint8(40 * x), G: uint8(100 * y), A: 255})
		}
	}
	got, err := imageengine.CropCover(src, 2, 2, imageengine.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds() != image.Rect(0, 0, 2, 2) {
		t.Fatalf("unexpected bounds: %v", got.Bounds())
	}
	if got.RGBAAt(0, 0).R == src.RGBAAt(0, 0).R {
		t.Fatal("expected centered horizontal crop")
	}
}

func TestPlaceNonOverlappingHonorsPaddingAndBounds(t *testing.T) {
	rng := &sequenceRandom{next: 10}
	items := []image.Point{{X: 24, Y: 20}, {X: 26, Y: 18}, {X: 20, Y: 20}, {X: 18, Y: 22}}
	placed, err := imageengine.PlaceNonOverlapping(rng, image.Rect(0, 0, 180, 100), items, 8, 128)
	if err != nil {
		t.Fatal(err)
	}
	for i, rect := range placed {
		if !rect.In(image.Rect(0, 0, 180, 100)) {
			t.Fatalf("item %d out of bounds: %v", i, rect)
		}
		for j := 0; j < i; j++ {
			if imageengine.RectsOverlapWithPadding(rect, placed[j], 8) {
				t.Fatalf("items %d and %d overlap", i, j)
			}
		}
	}
}

func TestTransformRotateAndScaleKeepsVisibleContent(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 20, 10))
	for y := 2; y < 8; y++ {
		for x := 3; x < 17; x++ {
			src.SetRGBA(x, y, color.RGBA{R: 220, A: 255})
		}
	}
	got, err := imageengine.RotateScale(src, 33, 1.4, imageengine.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Bounds().Dx() <= src.Bounds().Dx() || got.Bounds().Dy() <= src.Bounds().Dy() {
		t.Fatalf("rotation should expand bounds: %v", got.Bounds())
	}
	visible := 0
	for y := got.Bounds().Min.Y; y < got.Bounds().Max.Y; y++ {
		for x := got.Bounds().Min.X; x < got.Bounds().Max.X; x++ {
			if got.RGBAAt(x, y).A > 0 {
				visible++
			}
		}
	}
	if visible == 0 {
		t.Fatal("transformed image is blank")
	}
}

func TestNoiseAndPNGDataURIStayWithinBudget(t *testing.T) {
	engine := imageengine.New(imageengine.Limits{MaxEncodedBytes: 16 << 10}, &sequenceRandom{next: 3})
	canvas, err := engine.NewCanvas(120, 60, color.RGBA{R: 235, G: 240, B: 245, A: 255})
	if err != nil {
		t.Fatal(err)
	}
	if err := imageengine.AddNoise(canvas.Image(), engine.Random, imageengine.NoiseOptions{Dots: 120, Lines: 5, MaxAlpha: 90}); err != nil {
		t.Fatal(err)
	}
	uri, err := imageengine.PNGDataURI(canvas.Image(), engine.Limits)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("missing data URI prefix: %q", uri[:20])
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bounds() != image.Rect(0, 0, 120, 60) {
		t.Fatalf("unexpected decoded bounds: %v", decoded.Bounds())
	}
}

func TestCanvasEnforcesLayerLimit(t *testing.T) {
	engine := imageengine.New(imageengine.Limits{MaxLayers: 1}, &sequenceRandom{})
	canvas, err := engine.NewCanvas(20, 20, color.Transparent)
	if err != nil {
		t.Fatal(err)
	}
	layer := image.NewRGBA(image.Rect(0, 0, 4, 4))
	if err := canvas.DrawLayer(layer, image.Point{}, 255); err != nil {
		t.Fatal(err)
	}
	if err := canvas.DrawLayer(layer, image.Point{}, 255); err == nil {
		t.Fatal("expected layer limit error")
	}
}
