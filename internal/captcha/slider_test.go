package captcha

import (
	"image"
	"image/color"
	"strconv"
	"strings"
	"testing"
	"time"
)

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
	if !VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX + opts.Tolerance, DragMS: int(opts.MinDrag/time.Millisecond) + 50}) {
		t.Fatal("expected solved slider payload to verify")
	}
	midX := token.TargetX / 2
	goodTrack := `[{"x":0,"y":20,"t":0,"type":"down"},{"x":` + strconv.Itoa(midX) + `,"y":21,"t":180,"type":"move"},{"x":` + strconv.Itoa(token.TargetX) + `,"y":22,"t":520,"type":"up"}]`
	if !VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX, DragMS: int(opts.MinDrag/time.Millisecond) + 80, Track: goodTrack}) {
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

func TestSliderPuzzlePieceHasVisibleOuterStroke(t *testing.T) {
	const pieceSize = 42
	base := image.NewRGBA(image.Rect(0, 0, 120, 90))
	for y := 0; y < 90; y++ {
		for x := 0; x < 120; x++ {
			base.SetRGBA(x, y, color.RGBA{R: uint8(58 + x/4), G: uint8(126 + y/8), B: 134, A: 255})
		}
	}
	piece := renderPuzzlePiece(base, 32, 24, pieceSize)
	strokePixels := 0
	transparentPixels := 0
	for y := 0; y < pieceSize; y++ {
		for x := 0; x < pieceSize; x++ {
			px := piece.NRGBAAt(x, y)
			if !puzzleMask(x, y, pieceSize) && puzzleNearMask(x, y, pieceSize, 2) && px.A >= 180 {
				strokePixels++
			}
			if !puzzleMask(x, y, pieceSize) && !puzzleNearMask(x, y, pieceSize, 2) && px.A == 0 {
				transparentPixels++
			}
		}
	}
	if strokePixels < 64 {
		t.Fatalf("expected a visible outer stroke around puzzle piece, got %d pixels", strokePixels)
	}
	if transparentPixels < 300 {
		t.Fatalf("expected piece PNG to remain shape-cut, got only %d transparent pixels", transparentPixels)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
