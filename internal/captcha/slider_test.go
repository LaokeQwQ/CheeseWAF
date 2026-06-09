package captcha

import (
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
	token, ok := openSliderToken(opts, challenge.Token)
	if !ok {
		t.Fatal("expected token to decrypt with matching options")
	}
	if !VerifySlider(opts, SliderPayload{Token: challenge.Token, X: token.TargetX + opts.Tolerance, DragMS: int(opts.MinDrag/time.Millisecond) + 50}) {
		t.Fatal("expected solved slider payload to verify")
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
