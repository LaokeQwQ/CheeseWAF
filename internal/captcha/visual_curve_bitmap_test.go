package captcha

import (
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
