package captcha

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

type BehaviorType string

const (
	BehaviorPOW                    BehaviorType = "pow"
	BehaviorCurveDraw              BehaviorType = "curve_draw"
	BehaviorCurveSlider            BehaviorType = "curve_slider"
	BehaviorShapeSlider            BehaviorType = "shape_slider"
	BehaviorRotate                 BehaviorType = "rotate"
	BehaviorRestoreSlider          BehaviorType = "restore_slider"
	BehaviorAngle                  BehaviorType = "angle"
	BehaviorScratch                BehaviorType = "scratch"
	BehaviorTextClick              BehaviorType = "text_click"
	BehaviorIconClick              BehaviorType = "icon_click"
	BehaviorRandom                 BehaviorType = "random"
	behaviorCoordinateMax                       = 10000
	behaviorMaxTrackPoints                      = 256
	behaviorMaxTokenEncodedBytes                = 16 * 1024
	behaviorMaxTokenDecodedBytes                = 12 * 1024
	behaviorMaxTokenPlaintextBytes              = 8 * 1024
	behaviorMaxBindingBytes                     = 2 * 1024
	behaviorMaxModeBytes                        = 32
	behaviorMaxNonceBytes                       = 128
	behaviorMaxProofBytes                       = 128
	behaviorMaxCurvePoints                      = 128
	behaviorMaxTargetRegions                    = 32
	behaviorMaxRegionCoordinates                = 8
	behaviorMaxTargetCoordinates                = 8
	behaviorMaxTrackPointTypeBytes              = 8
)

var concreteBehaviorTypes = []BehaviorType{BehaviorPOW, BehaviorCurveDraw, BehaviorCurveSlider, BehaviorShapeSlider, BehaviorRotate, BehaviorRestoreSlider, BehaviorAngle, BehaviorScratch, BehaviorTextClick, BehaviorIconClick}

type BehaviorPoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}
type BehaviorTrackPoint struct {
	X    int    `json:"x"`
	Y    int    `json:"y"`
	T    int    `json:"t"`
	Type string `json:"type,omitempty"`
}
type BehaviorPresentation struct {
	Kind          string         `json:"kind"`
	Image         string         `json:"image,omitempty"`
	Piece         string         `json:"piece,omitempty"`
	Prompt        string         `json:"prompt,omitempty"`
	Version       int            `json:"version,omitempty"`
	Intensity     int            `json:"intensity,omitempty"`
	Track         map[string]int `json:"track,omitempty"`
	Width         int            `json:"width,omitempty"`
	Height        int            `json:"height,omitempty"`
	PieceSize     int            `json:"piece_size,omitempty"`
	PieceY        int            `json:"piece_y,omitempty"`
	InitialAngle  int            `json:"initial_angle,omitempty"`
	MovingPart    string         `json:"moving_part,omitempty"`
	MaxOffset     int            `json:"max_offset,omitempty"`
	InitialOffset int            `json:"initial_offset,omitempty"`
	Shape         string         `json:"shape,omitempty"`
	POWAlgorithm  string         `json:"pow_algorithm,omitempty"`
	POWDifficulty int            `json:"pow_difficulty,omitempty"`
	POWSalt       string         `json:"pow_salt,omitempty"`
}
type BehaviorChallenge struct {
	Type         BehaviorType         `json:"type"`
	Token        string               `json:"token"`
	ExpiresAt    string               `json:"expires_at"`
	Presentation BehaviorPresentation `json:"presentation"`
}
type BehaviorResponse struct {
	Token      string               `json:"token"`
	Point      *BehaviorPoint       `json:"point,omitempty"`
	Angle      int                  `json:"angle,omitempty"`
	Offset     float64              `json:"offset,omitempty"`
	Track      []BehaviorTrackPoint `json:"track,omitempty"`
	DurationMS int                  `json:"duration_ms,omitempty"`
	Proof      string               `json:"proof,omitempty"`
}
type BehaviorResult struct {
	Valid  bool         `json:"valid"`
	Type   BehaviorType `json:"type,omitempty"`
	Reason string       `json:"reason,omitempty"`
}
type BehaviorOptions struct {
	Secret, Purpose, ClientKey, Path, Site string
	TTL                                    time.Duration
	Type                                   BehaviorType
	Version, Intensity, Tolerance          int
	MinDuration, MaxDuration               time.Duration
	MaxTrackPoints                         int
	Now                                    func() time.Time
	Rand                                   io.Reader
}
type behaviorToken struct {
	Type          BehaviorType    `json:"type"`
	Purpose       string          `json:"purpose"`
	ClientKey     string          `json:"client_key"`
	Path          string          `json:"path"`
	Site          string          `json:"site"`
	IssuedMS      int64           `json:"issued_ms,omitempty"`
	Expires       int64           `json:"expires"`
	Tolerance     int             `json:"tolerance"`
	MinMS         int             `json:"min_ms"`
	MaxMS         int             `json:"max_ms"`
	MaxPoints     int             `json:"max_points"`
	Version       int             `json:"version,omitempty"`
	Intensity     int             `json:"intensity,omitempty"`
	Mode          string          `json:"mode"`
	Point         BehaviorPoint   `json:"point,omitempty"`
	Angle         int             `json:"angle,omitempty"`
	InitialAngle  int             `json:"initial_angle,omitempty"`
	InitialOffset int             `json:"initial_offset,omitempty"`
	Curve         []BehaviorPoint `json:"curve,omitempty"`
	Region        []int           `json:"region,omitempty"`
	Targets       [][]int         `json:"targets,omitempty"`
	Coverage      int             `json:"coverage,omitempty"`
	POWSalt       string          `json:"pow_salt,omitempty"`
	POWBits       int             `json:"pow_bits,omitempty"`
	Nonce         string          `json:"nonce"`
}

func IssueBehaviorChallenge(opts BehaviorOptions) (BehaviorChallenge, error) {
	opts = normalizeBehaviorOptions(opts)
	if strings.TrimSpace(opts.Secret) == "" {
		return BehaviorChallenge{}, fmt.Errorf("captcha behavior secret is required")
	}
	kind := opts.Type
	if kind == "" {
		kind = BehaviorRandom
	}
	if kind == BehaviorRandom {
		n, err := behaviorRandomInt(opts.Rand, 0, len(concreteBehaviorTypes)-1)
		if err != nil {
			return BehaviorChallenge{}, err
		}
		kind = concreteBehaviorTypes[n]
	}
	if !isBehaviorType(kind) {
		return BehaviorChallenge{}, fmt.Errorf("unsupported behavior type %q", kind)
	}
	nonce, err := behaviorRandomToken(opts.Rand, 16)
	if err != nil {
		return BehaviorChallenge{}, err
	}
	issuedAt := opts.Now()
	tok := behaviorToken{Type: kind, Purpose: opts.Purpose, ClientKey: opts.ClientKey, Path: opts.Path, Site: opts.Site, IssuedMS: issuedAt.UnixMilli(), Expires: issuedAt.Add(opts.TTL).Unix(), Tolerance: opts.Tolerance, MinMS: int(opts.MinDuration / time.Millisecond), MaxMS: int(opts.MaxDuration / time.Millisecond), MaxPoints: opts.MaxTrackPoints, Version: opts.Version, Intensity: opts.Intensity, Nonce: nonce}
	presentation := BehaviorPresentation{Kind: "image", Version: opts.Version, Intensity: opts.Intensity}
	if err := populateBehavior(opts, &tok, &presentation); err != nil {
		return BehaviorChallenge{}, err
	}
	if tok.Mode == "angle" {
		tok.InitialAngle = presentation.InitialAngle
	}
	token, err := sealBehaviorToken(opts, tok)
	if err != nil {
		return BehaviorChallenge{}, err
	}
	return BehaviorChallenge{Type: kind, Token: token, ExpiresAt: time.Unix(tok.Expires, 0).UTC().Format(time.RFC3339), Presentation: presentation}, nil
}

func VerifyBehaviorChallenge(opts BehaviorOptions, response BehaviorResponse) BehaviorResult {
	opts = normalizeBehaviorOptions(opts)
	if strings.TrimSpace(opts.Secret) == "" {
		return BehaviorResult{Reason: "invalid_token"}
	}
	if response.Token == "" {
		return BehaviorResult{Reason: "missing_token"}
	}
	if !validBehaviorResponseShape(response) {
		return BehaviorResult{Reason: "invalid_response"}
	}
	tok, ok := openBehaviorToken(opts, response.Token)
	if !ok {
		return BehaviorResult{Reason: "invalid_token"}
	}
	result := BehaviorResult{Type: tok.Type}
	if tok.Purpose != opts.Purpose || tok.ClientKey != opts.ClientKey || tok.Path != opts.Path || tok.Site != opts.Site {
		result.Reason = "binding_mismatch"
		return result
	}
	if tok.Expires <= opts.Now().Unix() {
		result.Reason = "expired"
		return result
	}
	if opts.Type != "" && opts.Type != BehaviorRandom && opts.Type != tok.Type {
		result.Reason = "type_mismatch"
		return result
	}
	if !verifyBehaviorAnswer(opts, tok, response) {
		result.Reason = "incorrect"
		return result
	}
	result.Valid = true
	return result
}

func normalizeBehaviorOptions(opts BehaviorOptions) BehaviorOptions {
	if opts.Purpose == "" {
		opts.Purpose = "captcha-behavior"
	}
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Version < 1 || opts.Version > 3 {
		opts.Version = 3
	}
	if opts.Intensity < 1 || opts.Intensity > 5 {
		opts.Intensity = 3
	}
	if opts.Tolerance <= 0 {
		opts.Tolerance = 450
	}
	if opts.MinDuration <= 0 {
		opts.MinDuration = 120 * time.Millisecond
	}
	if opts.MaxDuration <= 0 {
		opts.MaxDuration = 2 * time.Minute
	}
	if opts.MaxTrackPoints <= 0 || opts.MaxTrackPoints > behaviorMaxTrackPoints {
		opts.MaxTrackPoints = 128
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	return opts
}

func populateBehavior(opts BehaviorOptions, tok *behaviorToken, p *BehaviorPresentation) error {
	switch tok.Type {
	case BehaviorPOW:
		tok.Mode, tok.POWBits, tok.POWSalt = "pow", 12+opts.Intensity, tok.Nonce
		p.Kind, p.POWAlgorithm, p.POWDifficulty, p.POWSalt = "pow", "sha256-leading-zero-bits", tok.POWBits, tok.POWSalt
		p.Prompt = "Complete the browser security check"
	case BehaviorRotate:
		return populateBitmapRotate(opts, tok, p)
	case BehaviorAngle:
		return populateBitmapAngle(opts, tok, p)
	case BehaviorTextClick:
		return populateVisualTextClick(opts, tok, p)
	case BehaviorIconClick:
		return populateVisualIconClick(opts, tok, p)
	case BehaviorCurveDraw:
		return populateVisualCurveDraw(opts, tok, p)
	case BehaviorCurveSlider:
		return populateVisualCurveSlider(opts, tok, p)
	case BehaviorShapeSlider:
		return populateBitmapShapeSlider(opts, tok, p)
	case BehaviorRestoreSlider:
		return populateBitmapRestore(opts, tok, p)
	case BehaviorScratch:
		return populateVisualScratch(opts, tok, p)
	}
	return nil
}

func verifyBehaviorAnswer(opts BehaviorOptions, tok behaviorToken, r BehaviorResponse) bool {
	switch tok.Mode {
	case "pow":
		return verifyBehaviorPOW(tok, r.Proof)
	case "angle":
		return verifyAngleTrack(tok, r, maxBehavior(2, tok.Tolerance/100))
	case "point":
		return r.Point != nil && behaviorDistance(*r.Point, tok.Point) <= float64(tok.Tolerance)
	case "slider":
		return r.Point != nil && behaviorDistance(*r.Point, tok.Point) <= float64(tok.Tolerance) && verifyBehaviorTrack(tok, r.Track, r.DurationMS, r.Point)
	case "restore_offset":
		return math.Abs(r.Offset-float64(tok.Point.X)/100) <= math.Max(0.8, float64(tok.Tolerance)/200) && validBehaviorTrack(tok, r.Track, r.DurationMS)
	case "curve":
		return verifyVisualCurveDraw(tok, r.Track, r.DurationMS)
	case "curve_slider":
		return verifyVisualCurveSlider(opts.Now().UnixMilli(), tok, r)
	case "scratch":
		return verifyVisualScratch(tok, r.Track, r.DurationMS)
	}
	return false
}

func verifyAngleTrack(tok behaviorToken, response BehaviorResponse, tolerance int) bool {
	track := response.Track
	if !validBehaviorTrack(tok, track, response.DurationMS) {
		return false
	}
	first, last := track[0], track[len(track)-1]
	if first.Type != "" && first.Type != "down" {
		return false
	}
	if last.Type != "" && last.Type != "up" {
		return false
	}
	if last.X < 0 || last.X > behaviorCoordinateMax {
		return false
	}
	trackAngle := normalizeBehaviorAngle(float64(tok.InitialAngle) + float64(last.X)*360/behaviorCoordinateMax)
	return angularDistance(tok.Angle, response.Angle) <= tolerance && angularDistance(trackAngle, response.Angle) <= tolerance && angularDistance(trackAngle, tok.Angle) <= tolerance
}

func normalizeBehaviorAngle(angle float64) int {
	normalized := math.Mod(angle, 360)
	if normalized < 0 {
		normalized += 360
	}
	return int(math.Round(normalized)) % 360
}
func verifyBehaviorTrack(tok behaviorToken, track []BehaviorTrackPoint, duration int, end *BehaviorPoint) bool {
	if !validBehaviorTrack(tok, track, duration) {
		return false
	}
	first, last := track[0], track[len(track)-1]
	return behaviorDistance(BehaviorPoint{X: last.X, Y: last.Y}, *end) <= float64(tok.Tolerance) && behaviorDistance(BehaviorPoint{X: first.X, Y: first.Y}, BehaviorPoint{X: last.X, Y: last.Y}) >= 500
}
func verifyCurve(tok behaviorToken, track []BehaviorTrackPoint, duration int) bool {
	if !validBehaviorTrack(tok, track, duration) || len(track) < len(tok.Curve) {
		return false
	}
	matched := 0
	for _, target := range tok.Curve {
		for _, q := range track {
			if behaviorDistance(BehaviorPoint{X: q.X, Y: q.Y}, target) <= float64(tok.Tolerance*2) {
				matched++
				break
			}
		}
	}
	return matched == len(tok.Curve)
}

func verifyCurveProgress(tok behaviorToken, track []BehaviorTrackPoint, duration int) bool {
	if !validBehaviorTrack(tok, track, duration) || len(tok.Curve) < 5 {
		return false
	}
	lastIndex := -1
	matched := 0
	for _, q := range track {
		bestIndex, bestDistance := -1, math.MaxFloat64
		for i, target := range tok.Curve {
			d := behaviorDistance(BehaviorPoint{X: q.X, Y: q.Y}, target)
			if d < bestDistance {
				bestIndex, bestDistance = i, d
			}
		}
		if bestDistance > float64(tok.Tolerance*2) || bestIndex+1 < lastIndex || (lastIndex >= 0 && bestIndex-lastIndex > 2) {
			return false
		}
		if bestIndex > lastIndex {
			matched += bestIndex - maxBehavior(lastIndex, 0)
			lastIndex = bestIndex
		}
	}
	return lastIndex >= len(tok.Curve)-2 && matched >= len(tok.Curve)/2
}
func validBehaviorTrack(tok behaviorToken, track []BehaviorTrackPoint, duration int) bool {
	if len(track) < 2 || len(track) > tok.MaxPoints || duration < tok.MinMS || duration > tok.MaxMS {
		return false
	}
	prev := track[0]
	if prev.T < 0 || prev.T > duration || !validBehaviorCoord(prev.X, prev.Y) {
		return false
	}
	for i := 1; i < len(track); i++ {
		q := track[i]
		if !validBehaviorCoord(q.X, q.Y) || q.T < prev.T || q.T > duration {
			return false
		}
		if q.Type != "" && q.Type != "move" && q.Type != "down" && q.Type != "up" {
			return false
		}
		prev = q
	}
	return track[len(track)-1].T >= duration-250
}
func verifyBehaviorPOW(tok behaviorToken, proof string) bool {
	if len(proof) == 0 || len(proof) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(tok.POWSalt + ":" + proof))
	bits := tok.POWBits
	for _, b := range sum {
		if bits <= 0 {
			return true
		}
		n := minBehavior(bits, 8)
		if b>>(8-n) != 0 {
			return false
		}
		bits -= n
	}
	return bits <= 0
}

func sealBehaviorToken(opts BehaviorOptions, tok behaviorToken) (string, error) {
	if !validBehaviorTokenShape(tok) {
		return "", fmt.Errorf("behavior token exceeds protocol limits")
	}
	plain, e := json.Marshal(tok)
	if e != nil {
		return "", e
	}
	if len(plain) > behaviorMaxTokenPlaintextBytes {
		return "", fmt.Errorf("behavior token plaintext exceeds protocol limit")
	}
	block, e := aes.NewCipher(behaviorKey(opts.Secret))
	if e != nil {
		return "", e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = io.ReadFull(opts.Rand, nonce); e != nil {
		return "", e
	}
	sealed := gcm.Seal(nil, nonce, plain, []byte(behaviorAAD(opts)))
	return base64.RawURLEncoding.EncodeToString(append(nonce, sealed...)), nil
}
func openBehaviorToken(opts BehaviorOptions, raw string) (behaviorToken, bool) {
	if len(raw) == 0 || len(raw) > behaviorMaxTokenEncodedBytes || base64.RawURLEncoding.DecodedLen(len(raw)) > behaviorMaxTokenDecodedBytes {
		return behaviorToken{}, false
	}
	data, e := base64.RawURLEncoding.DecodeString(raw)
	if e != nil {
		return behaviorToken{}, false
	}
	if len(data) > behaviorMaxTokenDecodedBytes {
		return behaviorToken{}, false
	}
	block, e := aes.NewCipher(behaviorKey(opts.Secret))
	if e != nil {
		return behaviorToken{}, false
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil || len(data) < gcm.NonceSize()+gcm.Overhead() || len(data)-gcm.NonceSize()-gcm.Overhead() > behaviorMaxTokenPlaintextBytes {
		return behaviorToken{}, false
	}
	plain, e := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(behaviorAAD(opts)))
	if e != nil {
		return behaviorToken{}, false
	}
	var tok behaviorToken
	if len(plain) > behaviorMaxTokenPlaintextBytes || json.Unmarshal(plain, &tok) != nil || !validBehaviorTokenShape(tok) {
		return behaviorToken{}, false
	}
	return tok, true
}

func validBehaviorResponseShape(response BehaviorResponse) bool {
	if len(response.Token) > behaviorMaxTokenEncodedBytes || len(response.Proof) > behaviorMaxProofBytes || len(response.Track) > behaviorMaxTrackPoints {
		return false
	}
	for _, point := range response.Track {
		if len(point.Type) > behaviorMaxTrackPointTypeBytes {
			return false
		}
	}
	return true
}

func validBehaviorTokenShape(tok behaviorToken) bool {
	if !isBehaviorType(tok.Type) || len(tok.Purpose) > behaviorMaxBindingBytes || len(tok.ClientKey) > behaviorMaxBindingBytes || len(tok.Path) > behaviorMaxBindingBytes || len(tok.Site) > behaviorMaxBindingBytes {
		return false
	}
	if len(tok.Mode) == 0 || len(tok.Mode) > behaviorMaxModeBytes || len(tok.Nonce) == 0 || len(tok.Nonce) > behaviorMaxNonceBytes || len(tok.POWSalt) > behaviorMaxNonceBytes {
		return false
	}
	if len(tok.Curve) > behaviorMaxCurvePoints || len(tok.Region) > behaviorMaxRegionCoordinates || len(tok.Targets) > behaviorMaxTargetRegions {
		return false
	}
	for _, target := range tok.Targets {
		if len(target) > behaviorMaxTargetCoordinates {
			return false
		}
	}
	if tok.Mode == "curve_slider" {
		expectedTarget := clampVisualCoord(5000 - tok.InitialOffset*5000/visualCurveSliderMaxOffset)
		if tok.IssuedMS <= 0 || tok.Version != 3 || absBehavior(tok.InitialOffset) < 10 ||
			absBehavior(tok.InitialOffset) > visualCurveSliderMaxOffset ||
			absBehavior(tok.Point.X-expectedTarget) > 1 || tok.Point.Y != behaviorCoordinateMax/2 {
			return false
		}
	}
	return true
}
func behaviorKey(secret string) []byte {
	sum := sha256.Sum256([]byte("cheesewaf:behavior:v1:" + secret))
	return sum[:]
}
func behaviorAAD(opts BehaviorOptions) string {
	return strings.Join([]string{"behavior-v1", opts.Purpose, opts.ClientKey, opts.Path, opts.Site}, "\x00")
}

func trackPresentation(tok *behaviorToken) map[string]int {
	return map[string]int{"min_points": 2, "max_points": tok.MaxPoints, "min_duration_ms": tok.MinMS}
}

func randomPermutation(r io.Reader, n int) ([]int, error) {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j, err := behaviorRandomInt(r, 0, i)
		if err != nil {
			return nil, err
		}
		p[i], p[j] = p[j], p[i]
	}
	return p, nil
}

func svgData(svg string) string {
	if len(svg) > 48*1024 {
		return ""
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(svg))
}

func behaviorRandomToken(r io.Reader, n int) (string, error) {
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func behaviorRandomInt(r io.Reader, min, max int) (int, error) {
	if max < min {
		return 0, fmt.Errorf("invalid random range")
	}
	span := uint64(max - min + 1)
	limit := uint64(math.MaxUint64) - (uint64(math.MaxUint64) % span)
	var b [8]byte
	for {
		if _, e := io.ReadFull(r, b[:]); e != nil {
			return 0, e
		}
		v := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
		if v < limit {
			return min + int(v%span), nil
		}
	}
}
func behaviorDistance(a, b BehaviorPoint) float64 {
	dx, dy := float64(a.X-b.X), float64(a.Y-b.Y)
	return math.Hypot(dx, dy)
}
func angularDistance(a, b int) int {
	d := absBehavior((a - b) % 360)
	if d > 180 {
		return 360 - d
	}
	return d
}
func validBehaviorCoord(x, y int) bool {
	return x >= 0 && x <= behaviorCoordinateMax && y >= 0 && y <= behaviorCoordinateMax
}
func isBehaviorType(t BehaviorType) bool {
	for _, v := range concreteBehaviorTypes {
		if t == v {
			return true
		}
	}
	return false
}
func maxBehavior(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func minBehavior(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func absBehavior(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// SolveBehaviorPOW is a bounded helper for trusted clients that need to solve a PoW presentation.
func SolveBehaviorPOW(salt string, difficulty int, maxAttempts uint64) (string, bool) {
	if difficulty < 1 || difficulty > 30 || maxAttempts == 0 {
		return "", false
	}
	for i := uint64(0); i < maxAttempts; i++ {
		proof := strconv.FormatUint(i, 10)
		if verifyBehaviorPOW(behaviorToken{POWSalt: salt, POWBits: difficulty}, proof) {
			return proof, true
		}
	}
	return "", false
}
