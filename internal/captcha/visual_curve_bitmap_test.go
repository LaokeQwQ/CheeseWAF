package captcha

import (
	"bytes"
	"image"
	"image/color"
	"strings"
	"testing"
	"time"
)

func TestVisualCurveChallengesRenderPNGAtContractDimensions(t *testing.T) {
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	for _, kind := range []BehaviorType{BehaviorCurveDraw, BehaviorCurveSlider} {
		t.Run(string(kind), func(t *testing.T) {
			challenge, err := IssueBehaviorChallenge(behaviorTestOptions(kind, now))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(challenge.Presentation.Image, "data:image/png;base64,") {
				t.Fatalf("image is not a PNG data URI: %q", challenge.Presentation.Image[:minBehavior(len(challenge.Presentation.Image), 32)])
			}
			decoded := decodeBehaviorPNG(t, challenge.Presentation.Image)
			if decoded.Bounds().Dx() != 320 || decoded.Bounds().Dy() != 180 {
				t.Fatalf("image dimensions = %v, want 320x180", decoded.Bounds())
			}
			if kind == BehaviorCurveSlider {
				if !strings.HasPrefix(challenge.Presentation.Piece, "data:image/png;base64,") {
					t.Fatal("curve slider piece is not a PNG data URI")
				}
				piece := decodeBehaviorPNG(t, challenge.Presentation.Piece)
				if piece.Bounds().Dx() != 320 || piece.Bounds().Dy() != 180 {
					t.Fatalf("piece dimensions = %v, want 320x180", piece.Bounds())
				}
				var opaque int
				for y := 0; y < 180; y++ {
					for x := 0; x < 320; x++ {
						_, _, _, a := piece.At(x, y).RGBA()
						if a > 0 {
							opaque++
						}
					}
				}
				if opaque < 200 {
					t.Fatalf("curve slider piece has too few opaque stroke pixels: %d", opaque)
				}
				return
			}
			var lightGuide, darkGuide, noise int
			background := color.RGBA{R: 238, G: 242, B: 245, A: 255}
			for y := 0; y < 180; y++ {
				for x := 0; x < 320; x++ {
					r, g, b, _ := decoded.At(x, y).RGBA()
					r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)
					if r8 > 245 && g8 > 245 && b8 > 245 {
						lightGuide++
					}
					if r8 >= 80 && r8 <= 150 && g8 >= 85 && g8 <= 155 && b8 >= 90 && b8 <= 165 {
						darkGuide++
					}
					if absBehavior(int(r8)-int(background.R))+absBehavior(int(g8)-int(background.G))+absBehavior(int(b8)-int(background.B)) > 18 {
						noise++
					}
				}
			}
			if lightGuide < 300 || darkGuide < 30 || noise < 500 {
				t.Fatalf("missing curve layers or noise: light=%d dark=%d varied=%d", lightGuide, darkGuide, noise)
			}
		})
	}
}

func TestVisualCurveDrawBitmapKeepsEndpointMarkers(t *testing.T) {
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	counts := map[BehaviorType]int{}
	for _, kind := range []BehaviorType{BehaviorCurveDraw, BehaviorCurveSlider} {
		challenge, err := IssueBehaviorChallenge(behaviorTestOptions(kind, now))
		if err != nil {
			t.Fatal(err)
		}
		decoded := decodeBehaviorPNG(t, challenge.Presentation.Image)
		for y := 0; y < decoded.Bounds().Dy(); y++ {
			for x := 0; x < decoded.Bounds().Dx(); x++ {
				r, g, b, _ := decoded.At(x, y).RGBA()
				if uint8(r>>8) > 220 && uint8(g>>8) >= 120 && uint8(g>>8) <= 190 && uint8(b>>8) < 70 {
					counts[kind]++
				}
			}
		}
	}
	if counts[BehaviorCurveDraw] < 80 {
		t.Fatalf("curve draw endpoint marker pixels = %d, want visible markers", counts[BehaviorCurveDraw])
	}
	if counts[BehaviorCurveSlider] != 0 {
		t.Fatalf("curve slider unexpectedly contains %d endpoint marker pixels", counts[BehaviorCurveSlider])
	}
}

func TestVisualCurveV3RandomizesHorizontalAnchors(t *testing.T) {
	curves := make([][]BehaviorPoint, 2)
	for index, value := range []byte{0, 1} {
		curve, err := randomVisualCurveV3(BehaviorOptions{Rand: bytes.NewReader(bytes.Repeat([]byte{value}, 128))})
		if err != nil {
			t.Fatal(err)
		}
		curves[index] = curve
	}
	if curves[0][0].X == curves[1][0].X || curves[0][len(curves[0])-1].X == curves[1][len(curves[1])-1].X {
		t.Fatalf("V3 horizontal endpoints remain fixed across random streams: first=%d last=%d", curves[0][0].X, curves[0][len(curves[0])-1].X)
	}
}

func TestVisualCurveSliderPieceAlphaBoundsDoNotRevealInitialOffset(t *testing.T) {
	curve := samplePolyline([]BehaviorPoint{
		{X: 1800, Y: 3000},
		{X: 3000, Y: 7000},
		{X: 4200, Y: 2500},
		{X: 5800, Y: 7500},
		{X: 7000, Y: 3200},
		{X: 8200, Y: 6800},
	}, visualCurveSamples)
	for _, offset := range []int{-visualCurveSliderMaxOffset, -10, 10, visualCurveSliderMaxOffset} {
		pieceURI, err := renderVisualCurvePiece(BehaviorOptions{}, curve, offset)
		if err != nil {
			t.Fatal(err)
		}
		piece := decodeBehaviorPNG(t, pieceURI)
		bounds, ok := visualCurveAlphaBounds(piece)
		if !ok || bounds != piece.Bounds() {
			t.Fatalf("offset %d alpha bounds = %v, want constant full canvas %v", offset, bounds, piece.Bounds())
		}
		for _, point := range []image.Point{
			piece.Bounds().Min,
			{X: piece.Bounds().Max.X - 1, Y: piece.Bounds().Min.Y},
			{X: piece.Bounds().Min.X, Y: piece.Bounds().Max.Y - 1},
			{X: piece.Bounds().Max.X - 1, Y: piece.Bounds().Max.Y - 1},
		} {
			_, _, _, alpha := piece.At(point.X, point.Y).RGBA()
			if alpha != 0x0101 {
				t.Fatalf("offset %d support alpha at %v = %#x, want imperceptible 1/255", offset, point, alpha)
			}
		}
	}
}

func visualCurveAlphaBounds(source image.Image) (image.Rectangle, bool) {
	bounds := source.Bounds()
	alphaBounds := image.Rectangle{Min: bounds.Max, Max: bounds.Min}
	visible := false
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			_, _, _, alpha := source.At(x, y).RGBA()
			if alpha == 0 {
				continue
			}
			visible = true
			alphaBounds.Min.X = minBehavior(alphaBounds.Min.X, x)
			alphaBounds.Min.Y = minBehavior(alphaBounds.Min.Y, y)
			alphaBounds.Max.X = maxBehavior(alphaBounds.Max.X, x+1)
			alphaBounds.Max.Y = maxBehavior(alphaBounds.Max.Y, y+1)
		}
	}
	return alphaBounds, visible
}
