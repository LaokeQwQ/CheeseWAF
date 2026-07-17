package captcha

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
)

func TestSliderRejectsOversizedTokenAndTrack(t *testing.T) {
	opts := SliderOptions{Secret: "slider-test-secret", ClientKey: "client"}
	if VerifySlider(opts, SliderPayload{Token: strings.Repeat("x", sliderMaxTokenEncodedBytes+1), X: 1}) {
		t.Fatal("oversized slider token verified")
	}
	if VerifySlider(opts, SliderPayload{Token: "token", X: 1, Track: strings.Repeat("x", sliderMaxTrackBytes+1)}) {
		t.Fatal("oversized slider track verified")
	}
}

func TestSliderChallengeVerifiesUserDrag(t *testing.T) {
	now := time.Date(2026, 6, 9, 10, 0, 0, 0, time.UTC)
	opts := SliderOptions{
		Secret:    "slider-secret",
		Purpose:   "admin-login-slider",
		ClientKey: "203.0.113.10\nbrowser",
		Path:      "admin-login",
		TTL:       2 * time.Minute,
		Width:     320,
		Height:    150,
		PieceSize: 42,
		Tolerance: 6,
		MinDrag:   450 * time.Millisecond,
		Now:       func() time.Time { return now },
	}
	challenge, err := NewSliderChallenge(opts)
	if err != nil {
		t.Fatalf("new slider challenge: %v", err)
	}
	if !strings.HasPrefix(challenge.Image, "data:image/png;base64,") {
		t.Fatalf("expected png data url, got %q", challenge.Image[:min(32, len(challenge.Image))])
	}
	if !strings.HasPrefix(challenge.Piece, "data:image/png;base64,") {
		t.Fatalf("expected puzzle piece png data url, got %q", challenge.Piece[:min(32, len(challenge.Piece))])
	}
	token, ok := openSliderToken(opts, challenge.Token)
	if !ok {
		t.Fatal("expected token to decrypt with matching options")
	}
	dragMS := int(opts.MinDrag/time.Millisecond) + 80
	midX := token.TargetX / 2
	goodTrack := `[{"x":0,"y":20,"t":0,"type":"down"},{"x":` + strconv.Itoa(midX) + `,"y":21,"t":180,"type":"move"},{"x":` + strconv.Itoa(token.TargetX) + `,"y":22,"t":` + strconv.Itoa(dragMS) + `,"type":"up"}]`
	if VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX + opts.Tolerance, DragMS: dragMS}) {
		t.Fatal("expected empty track to fail")
	}
	if !VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX, DragMS: dragMS, Track: goodTrack}) {
		t.Fatal("expected solved slider payload with behavior track to verify")
	}
	badTrack := `[{"x":0,"y":20,"t":0,"type":"down"},{"x":` + strconv.Itoa(token.TargetX+120) + `,"y":22,"t":520,"type":"up"}]`
	if VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX, DragMS: int(opts.MinDrag/time.Millisecond) + 80, Track: badTrack}) {
		t.Fatal("expected malformed behavior track to fail")
	}
	if VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX + opts.Tolerance + 2, DragMS: int(opts.MinDrag/time.Millisecond) + 50}) {
		t.Fatal("expected position outside tolerance to fail")
	}
	if VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX, DragMS: int(opts.MinDrag/time.Millisecond) - 1}) {
		t.Fatal("expected too-fast drag to fail")
	}
	otherClient := opts
	otherClient.ClientKey = "203.0.113.11\nbrowser"
	if VerifySlider(otherClient, SliderPayload{Token: challenge.Token, X: token.TargetX, DragMS: int(opts.MinDrag/time.Millisecond) + 50}) {
		t.Fatal("expected client-bound token to fail for another client")
	}
	expired := opts
	expired.Now = func() time.Time { return now.Add(3 * time.Minute) }
	if VerifySlider(expired, SliderPayload{Token: challenge.Token, X: token.TargetX, DragMS: int(opts.MinDrag/time.Millisecond) + 50}) {
		t.Fatal("expected expired token to fail")
	}
}

func TestSliderShapePoolRendersEverySupportedOutline(t *testing.T) {
	const pieceSize = 84
	base := image.NewRGBA(image.Rect(0, 0, 640, 300))
	for y := 0; y < base.Bounds().Dy(); y++ {
		for x := 0; x < base.Bounds().Dx(); x++ {
			base.SetRGBA(x, y, color.RGBA{R: uint8(36 + x%170), G: uint8(58 + y%150), B: uint8(92 + (x+y)%130), A: 255})
		}
	}
	if len(sliderShapePool) != 7 {
		t.Fatalf("expected seven shared slider shapes, got %d", len(sliderShapePool))
	}
	seen := make(map[imageengine.ShapeKind]struct{}, len(sliderShapePool))
	for _, shape := range sliderShapePool {
		if _, duplicate := seen[shape]; duplicate {
			t.Fatalf("duplicate slider shape %q", shape)
		}
		seen[shape] = struct{}{}
		imageURL, pieceURL, err := renderSliderShapeAssets(base, pieceSize, 180, 92, shape)
		if err != nil {
			t.Fatalf("render shape %q: %v", shape, err)
		}
		background := decodePNGDataURI(t, imageURL)
		piece := decodePNGDataURI(t, pieceURL)
		if got := background.Bounds().Size(); got != base.Bounds().Size() {
			t.Fatalf("shape %q background size = %v, want %v", shape, got, base.Bounds().Size())
		}
		if got := piece.Bounds().Size(); got != image.Pt(pieceSize, pieceSize) {
			t.Fatalf("shape %q piece size = %v", shape, got)
		}
		assertTransparentSafeMargin(t, shape, piece)
		assertVisiblePieceStroke(t, shape, piece)
	}
}

func TestSliderChallengeAssetsAreRandomized(t *testing.T) {
	opts := SliderOptions{Secret: "randomness-secret", Purpose: "admin-login-slider", ClientKey: "client", Path: "admin-login"}
	images := make(map[string]struct{})
	pieces := make(map[string]struct{})
	tokens := make(map[string]struct{})
	for i := 0; i < 16; i++ {
		challenge, err := NewSliderChallenge(opts)
		if err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
		images[challenge.Image] = struct{}{}
		pieces[challenge.Piece] = struct{}{}
		tokens[challenge.Token] = struct{}{}
	}
	if len(images) < 12 || len(pieces) < 12 || len(tokens) != 16 {
		t.Fatalf("insufficient challenge randomness: images=%d pieces=%d tokens=%d", len(images), len(pieces), len(tokens))
	}
}

func decodePNGDataURI(t *testing.T, raw string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(raw, prefix) {
		t.Fatalf("not a PNG data URI: %.32q", raw)
	}
	encoded := strings.TrimPrefix(raw, prefix)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode PNG data URI: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode PNG: %v", err)
	}
	return img
}

func assertTransparentSafeMargin(t *testing.T, shape imageengine.ShapeKind, piece image.Image) {
	t.Helper()
	bounds := piece.Bounds()
	for x := bounds.Min.X; x < bounds.Max.X; x++ {
		if alphaAt(piece, x, bounds.Min.Y) != 0 || alphaAt(piece, x, bounds.Max.Y-1) != 0 {
			t.Fatalf("shape %q touches top or bottom bitmap edge at x=%d", shape, x)
		}
	}
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		if alphaAt(piece, bounds.Min.X, y) != 0 || alphaAt(piece, bounds.Max.X-1, y) != 0 {
			t.Fatalf("shape %q touches left or right bitmap edge at y=%d", shape, y)
		}
	}
}

func assertVisiblePieceStroke(t *testing.T, shape imageengine.ShapeKind, piece image.Image) {
	t.Helper()
	bright := 0
	opaque := 0
	for y := piece.Bounds().Min.Y; y < piece.Bounds().Max.Y; y++ {
		for x := piece.Bounds().Min.X; x < piece.Bounds().Max.X; x++ {
			r, g, b, a := piece.At(x, y).RGBA()
			if a >= 0xc000 {
				opaque++
				if r >= 0xd000 && g >= 0xd000 && b >= 0xd000 {
					bright++
				}
			}
		}
	}
	if opaque < 300 || bright < 80 {
		t.Fatalf("shape %q lacks a clear thick outline: opaque=%d bright=%d", shape, opaque, bright)
	}
}

func alphaAt(img image.Image, x, y int) uint32 {
	_, _, _, alpha := img.At(x, y).RGBA()
	return alpha
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
