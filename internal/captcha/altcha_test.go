package captcha

import (
	"strings"
	"testing"
	"time"
)

func TestAltchaRejectsOversizedInputs(t *testing.T) {
	if _, ok := ParsePayload(strings.Repeat("x", altchaMaxPayloadBytes+1)); ok {
		t.Fatal("oversized encoded payload parsed")
	}
	if Verify(Options{Secret: "secret"}, Payload{Algorithm: AlgorithmSHA256, Challenge: strings.Repeat("x", altchaMaxFieldBytes+1), Salt: "nonce:1", Signature: "sig"}) {
		t.Fatal("oversized proof verified")
	}
}

func TestChallengeVerifiesSolvedPayload(t *testing.T) {
	now := time.Date(2026, 6, 9, 9, 0, 0, 0, time.UTC)
	opts := Options{
		Secret:    "test-secret",
		Purpose:   "admin-login",
		ClientKey: "203.0.113.10\nbrowser",
		Path:      "admin-login",
		MaxNumber: 5000,
		TTL:       2 * time.Minute,
		Now:       func() time.Time { return now },
	}
	challenge, err := NewChallenge(opts)
	if err != nil {
		t.Fatalf("new challenge: %v", err)
	}
	payload := solveChallenge(t, challenge)
	if !Verify(opts, payload) {
		t.Fatal("expected solved payload to verify")
	}
	tampered := opts
	tampered.ClientKey = "203.0.113.11\nbrowser"
	if Verify(tampered, payload) {
		t.Fatal("expected client-bound payload to fail for another client")
	}
	expired := opts
	expired.Now = func() time.Time { return now.Add(3 * time.Minute) }
	if Verify(expired, payload) {
		t.Fatal("expected expired payload to fail")
	}
}

// Newline-joined HMAC fields collide when Purpose/ClientKey trade "\n" boundaries.
func TestSignLengthPrefixRejectsNewlineFieldCollision(t *testing.T) {
	const algorithm, challenge, salt = AlgorithmSHA256, "chal", "nonce:1"
	a := Options{Secret: "test-secret", Purpose: "A\nB", ClientKey: "C", Path: "p"}
	b := Options{Secret: "test-secret", Purpose: "A", ClientKey: "B\nC", Path: "p"}
	sigA := sign(a, algorithm, challenge, salt)
	sigB := sign(b, algorithm, challenge, salt)
	if sigA == "" || sigB == "" {
		t.Fatal("expected non-empty signatures")
	}
	if sigA == sigB {
		t.Fatal("Purpose=A\\nB ClientKey=C must not collide with Purpose=A ClientKey=B\\nC")
	}
}

func solveChallenge(t *testing.T, challenge Challenge) Payload {
	t.Helper()
	for i := 0; i <= challenge.MaxNumber; i++ {
		if Hash(challenge.Salt, i) == challenge.Challenge {
			return Payload{
				Algorithm: challenge.Algorithm,
				Challenge: challenge.Challenge,
				Number:    i,
				Salt:      challenge.Salt,
				Signature: challenge.Signature,
			}
		}
	}
	t.Fatalf("failed to solve challenge")
	return Payload{}
}
