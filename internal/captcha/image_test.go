package captcha

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestImageChallengeVerifiesAnswerAndRendersAudio(t *testing.T) {
	now := time.Date(2026, 6, 10, 11, 0, 0, 0, time.UTC)
	opts := ImageOptions{
		Secret:    "image-secret",
		Purpose:   "waf-bot-image",
		ClientKey: "203.0.113.20\nbrowser",
		Path:      "/protected",
		TTL:       2 * time.Minute,
		Width:     220,
		Height:    86,
		Length:    6,
		Now:       func() time.Time { return now },
	}
	challenge, err := NewImageChallenge(opts)
	if err != nil {
		t.Fatalf("new image challenge: %v", err)
	}
	if !strings.HasPrefix(challenge.Image, "data:image/png;base64,") {
		t.Fatalf("expected png data url, got %q", challenge.Image[:min(32, len(challenge.Image))])
	}
	raw, err := json.Marshal(challenge)
	if err != nil {
		t.Fatalf("marshal challenge: %v", err)
	}
	if strings.Contains(string(raw), "audio") {
		t.Fatalf("image challenge must not inline audio data or answer-derived audio URLs: %s", raw)
	}
	token, ok := openImageToken(opts, challenge.Token)
	if !ok {
		t.Fatal("expected token to decrypt with matching options")
	}
	if !VerifyImage(opts, ImagePayload{Token: challenge.Token, Answer: token.Answer}) {
		t.Fatal("expected correct image answer to verify")
	}
	if VerifyImage(opts, ImagePayload{Token: challenge.Token, Answer: token.Answer + "1"}) {
		t.Fatal("expected wrong image answer to fail")
	}
	audio, ok, err := RenderImageAudio(opts, challenge.Token)
	if err != nil {
		t.Fatalf("render image audio: %v", err)
	}
	if !ok || len(audio) < 44 || string(audio[:4]) != "RIFF" || string(audio[8:12]) != "WAVE" {
		t.Fatalf("expected wav audio for valid token, ok=%v len=%d", ok, len(audio))
	}
	expired := opts
	expired.Now = func() time.Time { return now.Add(3 * time.Minute) }
	if VerifyImage(expired, ImagePayload{Token: challenge.Token, Answer: token.Answer}) {
		t.Fatal("expected expired image token to fail")
	}
	if _, ok, err := RenderImageAudio(expired, challenge.Token); err != nil || ok {
		t.Fatalf("expected expired audio token to fail, ok=%v err=%v", ok, err)
	}
}
