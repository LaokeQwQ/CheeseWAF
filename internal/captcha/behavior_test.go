package captcha

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBehaviorChallenge_RejectsOversizedProtocolInputs(t *testing.T) {
	now := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	opts := normalizeBehaviorOptions(behaviorTestOptions(BehaviorShapeSlider, now))
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		response BehaviorResponse
	}{
		{name: "encoded token", response: BehaviorResponse{Token: strings.Repeat("A", behaviorMaxTokenEncodedBytes+1)}},
		{name: "proof", response: BehaviorResponse{Token: challenge.Token, Proof: strings.Repeat("x", behaviorMaxProofBytes+1)}},
		{name: "track", response: BehaviorResponse{Token: challenge.Token, Track: make([]BehaviorTrackPoint, behaviorMaxTrackPoints+1)}},
		{name: "track point type", response: BehaviorResponse{Token: challenge.Token, Track: []BehaviorTrackPoint{{Type: strings.Repeat("x", behaviorMaxTrackPointTypeBytes+1)}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyBehaviorChallenge(opts, tt.response)
			if result.Valid || result.Reason != "invalid_response" {
				t.Fatalf("oversized %s was not rejected at the protocol boundary: %+v", tt.name, result)
			}
		})
	}
}

func TestBehaviorToken_RejectsOversizedSealedFieldsAndPlaintext(t *testing.T) {
	now := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	opts := normalizeBehaviorOptions(behaviorTestOptions(BehaviorScratch, now))
	base := behaviorToken{Type: BehaviorScratch, Purpose: opts.Purpose, ClientKey: opts.ClientKey, Path: opts.Path, Site: opts.Site, Expires: now.Add(time.Minute).Unix(), Mode: "scratch", Nonce: "nonce"}

	tests := []struct {
		name   string
		mutate func(*behaviorToken)
	}{
		{name: "binding", mutate: func(tok *behaviorToken) { tok.ClientKey = strings.Repeat("x", behaviorMaxBindingBytes+1) }},
		{name: "curve", mutate: func(tok *behaviorToken) { tok.Curve = make([]BehaviorPoint, behaviorMaxCurvePoints+1) }},
		{name: "region", mutate: func(tok *behaviorToken) { tok.Region = make([]int, behaviorMaxRegionCoordinates+1) }},
		{name: "targets", mutate: func(tok *behaviorToken) { tok.Targets = make([][]int, behaviorMaxTargetRegions+1) }},
		{name: "target coordinates", mutate: func(tok *behaviorToken) { tok.Targets = [][]int{make([]int, behaviorMaxTargetCoordinates+1)} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := base
			tt.mutate(&tok)
			if _, err := sealBehaviorToken(opts, tok); err == nil {
				t.Fatalf("oversized %s was sealed", tt.name)
			}
			raw := sealBehaviorTokenUnchecked(t, opts, tok)
			if _, ok := openBehaviorToken(opts, raw); ok {
				t.Fatalf("authenticated token with oversized %s was opened", tt.name)
			}
		})
	}

	oversizedPlain := base
	oversizedPlain.Purpose = strings.Repeat("x", behaviorMaxTokenPlaintextBytes)
	raw := sealBehaviorTokenUnchecked(t, opts, oversizedPlain)
	if _, ok := openBehaviorToken(opts, raw); ok {
		t.Fatal("authenticated oversized plaintext was opened")
	}
}

func TestBehaviorToken_OversizedEncodingDoesNotScaleDecodeAllocations(t *testing.T) {
	opts := normalizeBehaviorOptions(behaviorTestOptions(BehaviorPOW, time.Now()))
	small := strings.Repeat("A", behaviorMaxTokenEncodedBytes+1)
	large := strings.Repeat("A", 8*1024*1024)
	smallAllocs := testing.AllocsPerRun(100, func() { _, _ = openBehaviorToken(opts, small) })
	largeAllocs := testing.AllocsPerRun(100, func() { _, _ = openBehaviorToken(opts, large) })
	if largeAllocs > smallAllocs+1 {
		t.Fatalf("oversized input caused length-dependent decode allocations: small=%v large=%v", smallAllocs, largeAllocs)
	}
}

func sealBehaviorTokenUnchecked(t *testing.T, opts BehaviorOptions, tok behaviorToken) string {
	t.Helper()
	plain, err := json.Marshal(tok)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(behaviorKey(opts.Secret))
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{0x5a}, gcm.NonceSize())
	sealed := gcm.Seal(nil, nonce, plain, []byte(behaviorAAD(opts)))
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...))
}

func TestBehaviorChallenge_BitmapTypesUseRealPNGAndSafeDisplayMetadata(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	for _, kind := range []BehaviorType{BehaviorShapeSlider, BehaviorRotate, BehaviorAngle, BehaviorRestoreSlider} {
		t.Run(string(kind), func(t *testing.T) {
			opts := behaviorTestOptions(kind, now)
			challenge, err := IssueBehaviorChallenge(opts)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(challenge.Presentation.Image, "data:image/png;base64,") {
				t.Fatalf("expected PNG presentation, got %q", challenge.Presentation.Image[:minBehavior(len(challenge.Presentation.Image), 32)])
			}
			decoded := decodeBehaviorPNG(t, challenge.Presentation.Image)
			if decoded.Bounds().Dx() != challenge.Presentation.Width || decoded.Bounds().Dy() != challenge.Presentation.Height {
				t.Fatalf("metadata dimensions do not match image: %v vs %dx%d", decoded.Bounds(), challenge.Presentation.Width, challenge.Presentation.Height)
			}
			assertPresentationDoesNotExposeTokenAnswer(t, opts, challenge)
			if !VerifyBehaviorChallenge(opts, correctBehaviorResponse(t, opts, challenge.Token)).Valid {
				t.Fatal("correct bitmap challenge response rejected")
			}
		})
	}
}

func TestBehaviorChallenge_ShapeSliderUsesMatchingPNGPieceAndRandomShapeMetadata(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	challenge, err := IssueBehaviorChallenge(behaviorTestOptions(BehaviorShapeSlider, now))
	if err != nil {
		t.Fatal(err)
	}
	piece := decodeBehaviorPNG(t, challenge.Presentation.Piece)
	if piece.Bounds().Dx() != challenge.Presentation.PieceSize || piece.Bounds().Dy() != challenge.Presentation.PieceSize {
		t.Fatalf("piece dimensions mismatch: %v", piece.Bounds())
	}
	if challenge.Presentation.Shape == "" || challenge.Presentation.PieceY < 0 || challenge.Presentation.PieceY+challenge.Presentation.PieceSize > challenge.Presentation.Height {
		t.Fatalf("invalid shape display metadata: %+v", challenge.Presentation)
	}
}

func TestBehaviorChallenge_RestorePublishesBoundedOffsetWithoutPublishingAnswer(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorRestoreSlider, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Presentation.MovingPart != "top" && challenge.Presentation.MovingPart != "bottom" {
		t.Fatalf("unexpected moving part %q", challenge.Presentation.MovingPart)
	}
	if challenge.Presentation.MaxOffset < 20 || absBehavior(challenge.Presentation.InitialOffset) > challenge.Presentation.MaxOffset {
		t.Fatalf("invalid offset metadata: %+v", challenge.Presentation)
	}
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok || tok.Point.X != 0 {
		t.Fatal("restore target must remain the sealed zero-alignment position")
	}
}

func TestBehaviorChallenge_RestoreOffsetContractIsReachableFromEitherDirection(t *testing.T) {
	now := time.Date(2026, 7, 12, 8, 0, 0, 0, time.UTC)
	seenNegative, seenPositive := false, false
	for i := 0; i < 128 && (!seenNegative || !seenPositive); i++ {
		opts := behaviorTestOptions(BehaviorRestoreSlider, now.Add(time.Duration(i)*time.Second))
		challenge, err := IssueBehaviorChallenge(opts)
		if err != nil {
			t.Fatal(err)
		}
		initial := float64(challenge.Presentation.InitialOffset)
		maxOffset := float64(challenge.Presentation.MaxOffset)
		if initial < 0 {
			seenNegative = true
		} else if initial > 0 {
			seenPositive = true
		}
		sliderValue := 5000 - initial*5000/maxOffset
		resolved := initial + (sliderValue-5000)*maxOffset/5000
		if sliderValue < 0 || sliderValue > behaviorCoordinateMax {
			t.FailNow()
		}
		if math.Abs(resolved) > 0.000001 {
			t.FailNow()
		}
	}
	if !seenNegative || !seenPositive {
		t.FailNow()
	}
}

func TestBehaviorChallenge_AllTypes(t *testing.T) {
	types := append(append([]BehaviorType{}, concreteBehaviorTypes...), BehaviorRandom)
	for _, kind := range types {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
			opts := behaviorTestOptions(kind, now)
			challenge, err := IssueBehaviorChallenge(opts)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if challenge.Token == "" || challenge.Type == BehaviorRandom {
				t.Fatalf("invalid challenge: %+v", challenge)
			}
			if challenge.Presentation.Kind != "pow" && !strings.HasPrefix(challenge.Presentation.Image, "data:image/") {
				t.Fatalf("missing renderable image: %+v", challenge.Presentation)
			}
			public, _ := json.Marshal(challenge.Presentation)
			for _, forbidden := range []string{`"point":`, `"points":`, `"angle":`, `"curve":`, `"coverage":`} {
				if strings.Contains(string(public), forbidden) {
					t.Fatalf("public challenge exposes answer field %s: %s", forbidden, public)
				}
			}
			if len(challenge.Presentation.Image) > 64*1024 {
				t.Fatalf("oversized data URI: %d", len(challenge.Presentation.Image))
			}
			assertPresentationDoesNotExposeTokenAnswer(t, opts, challenge)

			good := correctBehaviorResponse(t, opts, challenge.Token)
			if result := VerifyBehaviorChallenge(opts, good); !result.Valid {
				t.Fatalf("correct response rejected: %+v", result)
			}

			wrong := good
			wrong.Point = &BehaviorPoint{X: 10000, Y: 10000}
			wrong.Angle += 90
			wrong.Offset = 100
			wrong.Track = []BehaviorTrackPoint{{X: 0, Y: 0, T: 0}, {X: 1, Y: 1, T: 500}}
			wrong.Proof = "definitely-wrong"
			if result := VerifyBehaviorChallenge(opts, wrong); result.Valid {
				t.Fatal("wrong response accepted")
			}

			tampered := good
			raw := []byte(tampered.Token)
			mid := len(raw) / 2
			if raw[mid] == 'A' {
				raw[mid] = 'B'
			} else {
				raw[mid] = 'A'
			}
			tampered.Token = string(raw)
			if result := VerifyBehaviorChallenge(opts, tampered); result.Valid {
				t.Fatal("tampered token accepted")
			}

			cross := opts
			cross.ClientKey = "other-client"
			if result := VerifyBehaviorChallenge(cross, good); result.Valid {
				t.Fatal("cross-bound token accepted")
			}
		})
	}
}

func TestBehaviorChallenge_ExpiresAndBindsEveryContextField(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorTextClick, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	response := correctBehaviorResponse(t, opts, challenge.Token)
	expired := opts
	expired.Now = func() time.Time { return now.Add(3 * time.Minute) }
	if result := VerifyBehaviorChallenge(expired, response); result.Valid || result.Reason != "expired" {
		t.Fatalf("expired token result: %+v", result)
	}
	mutations := []func(*BehaviorOptions){func(o *BehaviorOptions) { o.Purpose = "other" }, func(o *BehaviorOptions) { o.Path = "/other" }, func(o *BehaviorOptions) { o.Site = "other.example" }}
	for _, mutate := range mutations {
		changed := opts
		mutate(&changed)
		if VerifyBehaviorChallenge(changed, response).Valid {
			t.Fatal("context mutation accepted")
		}
	}
}

func TestBehaviorChallenge_CurveSliderTrackLimits(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorCurveSlider, now)
	opts.Version = 2
	opts.Intensity = 5
	opts.MaxTrackPoints = 4
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Presentation.Version != 3 || challenge.Presentation.Intensity != 5 || challenge.Presentation.Track["max_points"] != 4 {
		t.Fatalf("missing V3 align parameters: %+v", challenge.Presentation)
	}
	if challenge.Presentation.Piece == "" || challenge.Presentation.MaxOffset != 0 || challenge.Presentation.InitialOffset != 0 {
		t.Fatalf("curve slider must publish only the pre-shifted piece: %+v", challenge.Presentation)
	}
	response := correctBehaviorResponse(t, opts, challenge.Token)
	response.Track = append(response.Track, BehaviorTrackPoint{X: 1, Y: 1, T: 200}, BehaviorTrackPoint{X: 2, Y: 2, T: 300}, BehaviorTrackPoint{X: 3, Y: 3, T: 500})
	if VerifyBehaviorChallenge(opts, response).Valid {
		t.Fatal("oversized track accepted")
	}
}

func TestBehaviorChallenge_ClickPromptsAndCandidates(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	for _, kind := range []BehaviorType{BehaviorTextClick, BehaviorIconClick} {
		challenge, err := IssueBehaviorChallenge(behaviorTestOptions(kind, now))
		if err != nil {
			t.Fatal(err)
		}
		if challenge.Presentation.Prompt == "" {
			t.Fatalf("%s has no target prompt", kind)
		}
		img := decodeBehaviorPNG(t, challenge.Presentation.Image)
		if img.Bounds().Dx() != selectionWidth || img.Bounds().Dy() != selectionHeight {
			t.Fatalf("%s has unexpected bitmap dimensions: %v", kind, img.Bounds())
		}
		public, err := json.Marshal(challenge.Presentation)
		if err != nil {
			t.Fatal(err)
		}
		tok, ok := openBehaviorToken(normalizeBehaviorOptions(behaviorTestOptions(kind, now)), challenge.Token)
		if !ok {
			t.Fatal("cannot open click token")
		}
		if strings.Contains(string(public), strconv.Itoa(tok.Point.X)) || strings.Contains(string(public), strconv.Itoa(tok.Point.Y)) {
			t.Fatalf("%s exposes answer coordinates", kind)
		}
	}
}

func TestBehaviorChallenge_ScratchRequiresTargetsWithoutWholePanelErasure(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorScratch, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	decodeBehaviorPNG(t, challenge.Presentation.Image)
	decodeBehaviorPNG(t, challenge.Presentation.Piece)
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok || len(tok.Targets) < 2 {
		t.Fatal("scratch targets were not sealed")
	}
	public, _ := json.Marshal(challenge.Presentation)
	if strings.Contains(string(public), "targets") || strings.Contains(string(public), "region") || strings.Contains(string(public), "coverage") {
		t.Fatal("scratch presentation exposes answer layout fields")
	}
	good := scratchTargetResponse(challenge.Token, tok.Targets)
	if result := VerifyBehaviorChallenge(opts, good); !result.Valid {
		t.Fatalf("targeted scratch rejected: %+v", result)
	}
	wholePanel := BehaviorResponse{Token: challenge.Token, DurationMS: 1200}
	for row := 0; row < 50; row++ {
		y := row * behaviorCoordinateMax / 49
		if row%2 == 0 {
			wholePanel.Track = append(wholePanel.Track, BehaviorTrackPoint{X: 0, Y: y, T: row * 24, Type: "move"}, BehaviorTrackPoint{X: behaviorCoordinateMax, Y: y, T: row*24 + 12, Type: "move"})
		} else {
			wholePanel.Track = append(wholePanel.Track, BehaviorTrackPoint{X: behaviorCoordinateMax, Y: y, T: row * 24, Type: "move"}, BehaviorTrackPoint{X: 0, Y: y, T: row*24 + 12, Type: "move"})
		}
	}
	wholePanel.Track[len(wholePanel.Track)-1].T = wholePanel.DurationMS
	if VerifyBehaviorChallenge(opts, wholePanel).Valid {
		t.Fatal("whole-panel scratch was accepted")
	}
	jump := good
	jump.Track = []BehaviorTrackPoint{{X: 100, Y: 100, T: 0}, {X: 9000, Y: 9000, T: 500}}
	if VerifyBehaviorChallenge(opts, jump).Valid {
		t.Fatal("discontinuous scratch was accepted")
	}
	incomplete := scratchTargetResponse(challenge.Token, tok.Targets[:len(tok.Targets)-1])
	if VerifyBehaviorChallenge(opts, incomplete).Valid {
		t.Fatal("scratch missing one sealed target was accepted")
	}
}

func TestBehaviorChallenge_VisualSelectionGenerationStaysBounded(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	for _, kind := range []BehaviorType{BehaviorTextClick, BehaviorIconClick, BehaviorScratch} {
		seen := map[string]struct{}{}
		for i := 0; i < 256; i++ {
			challenge, err := IssueBehaviorChallenge(behaviorTestOptions(kind, now.Add(time.Duration(i)*time.Second)))
			if err != nil {
				t.Fatalf("%s generation %d: %v", kind, i, err)
			}
			decodeBehaviorPNG(t, challenge.Presentation.Image)
			if len(challenge.Presentation.Image) > 64*1024 {
				t.Fatalf("%s image exceeds transport budget: %d", kind, len(challenge.Presentation.Image))
			}
			if kind == BehaviorScratch {
				decodeBehaviorPNG(t, challenge.Presentation.Piece)
				if len(challenge.Presentation.Piece) > 64*1024 {
					t.Fatalf("scratch mask exceeds transport budget: %d", len(challenge.Presentation.Piece))
				}
			}
			seen[challenge.Presentation.Image] = struct{}{}
		}
		if len(seen) < 12 {
			t.Fatalf("%s lacks sufficient visual diversity: %d unique images", kind, len(seen))
		}
	}
}

func TestBehaviorChallenge_SelectionImagesKeepVisualComplexity(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	for _, kind := range []BehaviorType{BehaviorTextClick, BehaviorIconClick} {
		challenge, err := IssueBehaviorChallenge(behaviorTestOptions(kind, now))
		if err != nil {
			t.Fatalf(`%s generation: %v`, kind, err)
		}
		img := decodeBehaviorPNG(t, challenge.Presentation.Image)
		edges := 0
		levels := map[uint32]struct{}{}
		for y := img.Bounds().Min.Y; y < img.Bounds().Max.Y; y += 2 {
			for x := img.Bounds().Min.X; x < img.Bounds().Max.X; x += 2 {
				r, g, b, _ := img.At(x, y).RGBA()
				levels[(r+g+b)/3/1024] = struct{}{}
				if x+2 < img.Bounds().Max.X {
					nr, ng, nb, _ := img.At(x+2, y).RGBA()
					if absBehavior(int(r)-int(nr))+absBehavior(int(g)-int(ng))+absBehavior(int(b)-int(nb)) > 42*257 {
						edges++
					}
				}
			}
		}
		if len(levels) < 30 || edges < 500 {
			t.Fatalf(`%s background is too easy to segment: levels=%d edges=%d`, kind, len(levels), edges)
		}
	}
}

func TestBehaviorChallenge_RotateUsesCorrectionAngle(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorRotate, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok {
		t.Fatal("cannot open rotate token")
	}
	if tok.Angle != 0 || challenge.Presentation.InitialAngle < 30 || challenge.Presentation.InitialAngle > 330 {
		t.Fatal("rotate challenge does not preserve a secret upright target and safe public initial angle")
	}
	targetX := angleTrackX(challenge.Presentation.InitialAngle, tok.Angle)
	good := BehaviorResponse{Token: challenge.Token, Angle: tok.Angle, DurationMS: 500, Track: []BehaviorTrackPoint{{X: 0, Y: 5000, T: 0, Type: "down"}, {X: targetX, Y: 5000, T: 500, Type: "up"}}}
	if !VerifyBehaviorChallenge(opts, good).Valid {
		t.Fatal("correction angle rejected")
	}
	good.Angle = challenge.Presentation.InitialAngle
	if VerifyBehaviorChallenge(opts, good).Valid {
		t.Fatal("initial display angle accepted as correction")
	}
	good.Angle = tok.Angle
	good.Track[1].X = (targetX + 5000) % behaviorCoordinateMax
	if VerifyBehaviorChallenge(opts, good).Valid {
		t.Fatal("correct angle with unrelated track accepted")
	}
	good.Track[1].X = targetX
	good.DurationMS = 1
	if VerifyBehaviorChallenge(opts, good).Valid {
		t.Fatal("instant rotation accepted")
	}
}

func TestBehaviorChallenge_AngleTrackUsesCircularTolerance(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorAngle, now)
	tok := behaviorToken{Type: BehaviorAngle, Purpose: opts.Purpose, ClientKey: opts.ClientKey, Path: opts.Path, Site: opts.Site, Expires: now.Add(time.Minute).Unix(), Tolerance: 300, MinMS: 100, MaxMS: 10000, MaxPoints: 128, Mode: "angle", Angle: 0, InitialAngle: 1, Nonce: "nonce"}
	response := BehaviorResponse{Token: sealBehaviorTokenUnchecked(t, normalizeBehaviorOptions(opts), tok), Angle: 359, DurationMS: 500, Track: []BehaviorTrackPoint{{X: 1000, Y: 5000, T: 0, Type: "down"}, {X: 9944, Y: 5000, T: 500, Type: "up"}}}
	if !VerifyBehaviorChallenge(opts, response).Valid {
		t.Fatal("angle track crossing 0/360 rejected within tolerance")
	}
}

func TestBehaviorChallenge_AngleTrackAllowsKeyboardStep(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorAngle, now)
	tok := behaviorToken{Type: BehaviorAngle, Purpose: opts.Purpose, ClientKey: opts.ClientKey, Path: opts.Path, Site: opts.Site, Expires: now.Add(time.Minute).Unix(), Tolerance: 300, MinMS: 100, MaxMS: 10000, MaxPoints: 128, Mode: "angle", Angle: 0, InitialAngle: 359, Nonce: "nonce"}
	response := BehaviorResponse{Token: sealBehaviorTokenUnchecked(t, normalizeBehaviorOptions(opts), tok), Angle: 0, DurationMS: 500, Track: []BehaviorTrackPoint{{X: 27, Y: 5000, T: 0, Type: "down"}, {X: 28, Y: 5000, T: 500, Type: "up"}}}
	if !VerifyBehaviorChallenge(opts, response).Valid {
		t.Fatal("single-step keyboard adjustment rejected")
	}
}

func TestBehaviorChallenge_AngleToleranceBoundary(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorAngle, now)
	tok := behaviorToken{Type: BehaviorAngle, Purpose: opts.Purpose, ClientKey: opts.ClientKey, Path: opts.Path, Site: opts.Site, Expires: now.Add(time.Minute).Unix(), Tolerance: 300, MinMS: 100, MaxMS: 10000, MaxPoints: 128, Mode: "angle", Angle: 0, InitialAngle: 0, Nonce: "nonce"}
	token := sealBehaviorTokenUnchecked(t, normalizeBehaviorOptions(opts), tok)
	response := BehaviorResponse{Token: token, Angle: 3, DurationMS: 500, Track: []BehaviorTrackPoint{{X: 82, Y: 5000, T: 0, Type: "down"}, {X: 83, Y: 5000, T: 500, Type: "up"}}}
	if !VerifyBehaviorChallenge(opts, response).Valid {
		t.Fatal("angle exactly at tolerance rejected")
	}
	response.Angle = 4
	if VerifyBehaviorChallenge(opts, response).Valid {
		t.Fatal("angle beyond tolerance accepted")
	}
}

func angleTrackX(initial, target int) int {
	delta := ((target-initial)%360 + 360) % 360
	return int(math.Round(float64(delta) * behaviorCoordinateMax / 360))
}

func TestBehaviorChallenge_CurveRejectsShortcut(t *testing.T) {
	now := time.Date(2026, 7, 11, 8, 0, 0, 0, time.UTC)
	opts := behaviorTestOptions(BehaviorCurveSlider, now)
	challenge, err := IssueBehaviorChallenge(opts)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	shortcut := BehaviorResponse{Token: challenge.Token, DurationMS: 500, Track: []BehaviorTrackPoint{{X: tok.Curve[0].X, Y: tok.Curve[0].Y, T: 0}, {X: tok.Curve[len(tok.Curve)-1].X, Y: tok.Curve[len(tok.Curve)-1].Y, T: 500}}}
	if VerifyBehaviorChallenge(opts, shortcut).Valid {
		t.Fatal("curve endpoint shortcut accepted")
	}
}

func behaviorTestOptions(kind BehaviorType, now time.Time) BehaviorOptions {
	return BehaviorOptions{Secret: "test-secret", Purpose: "login", ClientKey: "client-1", Path: "/login", Site: "example.test", TTL: 2 * time.Minute, Type: kind, Intensity: 1, Tolerance: 300, MinDuration: 100 * time.Millisecond, MaxDuration: 10 * time.Second, Now: func() time.Time { return now }}
}

func correctBehaviorResponse(t *testing.T, opts BehaviorOptions, token string) BehaviorResponse {
	t.Helper()
	normalized := normalizeBehaviorOptions(opts)
	tok, ok := openBehaviorToken(normalized, token)
	if !ok {
		t.Fatal("cannot open issued token")
	}
	response := BehaviorResponse{Token: token, DurationMS: 500}
	switch tok.Mode {
	case "pow":
		proof, ok := SolveBehaviorPOW(tok.POWSalt, tok.POWBits, 1<<22)
		if !ok {
			t.Fatal("could not solve pow")
		}
		response.Proof = proof
	case "angle":
		response.Angle = tok.Angle
		response.Track = []BehaviorTrackPoint{{X: 0, Y: 5000, T: 0, Type: "down"}, {X: angleTrackX(tok.InitialAngle, tok.Angle), Y: 5000, T: 500, Type: "up"}}
	case "point":
		response.Point = &BehaviorPoint{X: tok.Point.X, Y: tok.Point.Y}
	case "slider":
		response.Point = &BehaviorPoint{X: tok.Point.X, Y: tok.Point.Y}
		response.Track = []BehaviorTrackPoint{{X: 500, Y: tok.Point.Y, T: 0, Type: "down"}, {X: tok.Point.X, Y: tok.Point.Y, T: 500, Type: "up"}}
	case "restore_offset":
		response.Offset = float64(tok.Point.X) / 100
		response.Track = []BehaviorTrackPoint{{X: 5000, Y: 5000, T: 0, Type: "down"}, {X: 5000, Y: 5000, T: 500, Type: "up"}}
	case "curve":
		response = curveDrawResponse(token, tok.Curve)
	case "curve_slider":
		response = curveSliderResponse(token, tok.Point)
	case "scratch":
		return scratchTargetResponse(token, tok.Targets)
	}
	return response
}

func scratchTargetResponse(token string, targets [][]int) BehaviorResponse {
	response := BehaviorResponse{Token: token, DurationMS: 1600}
	for _, target := range targets {
		if len(target) != 4 {
			continue
		}
		for row := 0; row < 9; row++ {
			y := target[1] + (target[3]-target[1])*(2*row+1)/18
			x0, x1 := target[0]+40, target[2]-40
			startType := "move"
			if row == 0 {
				startType = "down"
			}
			endType := "move"
			if row == 8 {
				endType = "up"
			}
			if row%2 == 0 {
				response.Track = append(response.Track, BehaviorTrackPoint{X: x0, Y: y, T: len(response.Track) * 12, Type: startType}, BehaviorTrackPoint{X: x1, Y: y, T: len(response.Track)*12 + 6, Type: endType})
			} else {
				response.Track = append(response.Track, BehaviorTrackPoint{X: x1, Y: y, T: len(response.Track) * 12, Type: startType}, BehaviorTrackPoint{X: x0, Y: y, T: len(response.Track)*12 + 6, Type: endType})
			}
		}
	}
	if len(response.Track) > 0 {
		response.Track[len(response.Track)-1].T = response.DurationMS
	}
	return response
}

func assertPresentationDoesNotExposeTokenAnswer(t *testing.T, opts BehaviorOptions, challenge BehaviorChallenge) {
	t.Helper()
	tok, ok := openBehaviorToken(normalizeBehaviorOptions(opts), challenge.Token)
	if !ok {
		t.Fatal("cannot inspect token")
	}
	public, _ := json.Marshal(challenge.Presentation)
	s := string(public)
	if tok.Point != (BehaviorPoint{}) {
		exact := `"x":` + strconv.Itoa(tok.Point.X) + `,"y":` + strconv.Itoa(tok.Point.Y)
		if strings.Contains(s, exact) {
			t.Fatalf("presentation exposes exact point %s", exact)
		}
	}
}

func decodeBehaviorSVG(t *testing.T, uri string) string {
	t.Helper()
	const prefix = "data:image/svg+xml;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("not an SVG data URI: %q", uri)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func decodeBehaviorPNG(t *testing.T, uri string) image.Image {
	t.Helper()
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(uri, prefix) {
		t.Fatalf("not a PNG data URI: %q", uri)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, prefix))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
