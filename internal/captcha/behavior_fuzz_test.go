package captcha

import (
	"testing"
	"time"
)

func FuzzOpenBehaviorToken(f *testing.F) {
	opts := normalizeBehaviorOptions(behaviorTestOptions(BehaviorRandom, time.Unix(1_800_000_000, 0)))
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", "%%%", "A", "AAAA", challenge.Token} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > behaviorMaxTokenEncodedBytes+1024 {
			return
		}
		_, _ = openBehaviorToken(opts, raw)
	})
}

func FuzzVerifyBehaviorChallenge(f *testing.F) {
	opts := normalizeBehaviorOptions(behaviorTestOptions(BehaviorRandom, time.Unix(1_800_000_000, 0)))
	f.Add("%%%", "", 0, 0, 0, "")
	f.Add("AAAA", "proof", 1, 2, 3, "move")
	f.Fuzz(func(t *testing.T, token, proof string, x, y, duration int, pointType string) {
		if len(token) > behaviorMaxTokenEncodedBytes+1024 || len(proof) > behaviorMaxProofBytes+1024 || len(pointType) > behaviorMaxTrackPointTypeBytes+1024 {
			return
		}
		response := BehaviorResponse{
			Token: token, Proof: proof, DurationMS: duration,
			Point: &BehaviorPoint{X: x, Y: y},
			Track: []BehaviorTrackPoint{{X: x, Y: y, T: duration, Type: pointType}},
		}
		_ = VerifyBehaviorChallenge(opts, response)
	})
}
