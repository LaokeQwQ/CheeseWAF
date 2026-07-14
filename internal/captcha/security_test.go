package captcha

import "testing"

func TestChallengeFamiliesRejectEmptySecrets(t *testing.T) {
	if _, err := NewChallenge(Options{}); err == nil {
		t.Fatal("PoW challenge accepted an empty secret")
	}
	if Verify(Options{}, Payload{Algorithm: AlgorithmSHA256, Challenge: "x", Salt: "n:1", Signature: "x"}) {
		t.Fatal("PoW proof verified with an empty secret")
	}
	if _, _, err := NewReceipt(ReceiptOptions{}, "slider"); err == nil {
		t.Fatal("receipt accepted an empty secret")
	}
	if VerifyReceipt(ReceiptOptions{}, "payload.signature", "slider") {
		t.Fatal("receipt verified with an empty secret")
	}
	if _, err := NewImageChallenge(ImageOptions{}); err == nil {
		t.Fatal("image challenge accepted an empty secret")
	}
	if VerifyImage(ImageOptions{}, ImagePayload{Token: "token", Answer: "1234"}) {
		t.Fatal("image challenge verified with an empty secret")
	}
	if _, err := NewSliderChallenge(SliderOptions{}); err == nil {
		t.Fatal("slider challenge accepted an empty secret")
	}
	if VerifySlider(SliderOptions{}, SliderPayload{Token: "token", X: 1}) {
		t.Fatal("slider challenge verified with an empty secret")
	}
	if _, err := IssueBehaviorChallenge(BehaviorOptions{}); err == nil {
		t.Fatal("behavior challenge accepted an empty secret")
	}
	if result := VerifyBehaviorChallenge(BehaviorOptions{}, BehaviorResponse{Token: "token"}); result.Valid {
		t.Fatal("behavior challenge verified with an empty secret")
	}
}
