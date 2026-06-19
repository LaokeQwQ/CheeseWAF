package captcha

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	mrand "math/rand"
	"strings"
	"time"
)

type SliderChallenge struct {
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	PieceSize  int    `json:"piece_size"`
	TrackWidth int    `json:"track_width"`
	TargetY    int    `json:"target_y"`
	Tolerance  int    `json:"tolerance"`
	MinDragMS  int    `json:"min_drag_ms"`
	Image      string `json:"image"`
	Piece      string `json:"piece,omitempty"`
	Token      string `json:"token"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type SliderPayload struct {
	Token  string `json:"token"`
	X      int    `json:"x"`
	DragMS int    `json:"drag_ms"`
	Track  string `json:"track,omitempty"`
}

type SliderOptions struct {
	Secret    string
	Purpose   string
	ClientKey string
	Path      string
	TTL       time.Duration
	Width     int
	Height    int
	PieceSize int
	Tolerance int
	MinDrag   time.Duration
	Now       func() time.Time
}

type sliderTokenPayload struct {
	Purpose   string `json:"purpose"`
	ClientKey string `json:"client_key"`
	Path      string `json:"path"`
	TargetX   int    `json:"target_x"`
	TargetY   int    `json:"target_y"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	PieceSize int    `json:"piece_size"`
	Tolerance int    `json:"tolerance"`
	MinDragMS int    `json:"min_drag_ms"`
	Expires   int64  `json:"expires"`
	Nonce     string `json:"nonce"`
}

const (
	sliderPuzzleStrokeRadius = 4
	sliderPuzzleAASamples    = 4
	sliderCaptchaImageScale  = 2
	sliderPuzzleShapeVariants = 5
)

func NewSliderChallenge(opts SliderOptions) (SliderChallenge, error) {
	opts = normalizeSliderOptions(opts)
	minX := opts.PieceSize + 18
	maxX := opts.Width - opts.PieceSize - 18
	targetX, err := randomInt(minX, maxX)
	if err != nil {
		return SliderChallenge{}, err
	}
	minY := 18
	maxY := opts.Height - opts.PieceSize - 18
	targetY, err := randomInt(minY, maxY)
	if err != nil {
		return SliderChallenge{}, err
	}
	expires := opts.now().Add(opts.TTL)
	nonce, err := randomToken(16)
	if err != nil {
		return SliderChallenge{}, err
	}
	token, err := sealSliderToken(opts, sliderTokenPayload{
		Purpose:   opts.Purpose,
		ClientKey: opts.ClientKey,
		Path:      opts.Path,
		TargetX:   targetX,
		TargetY:   targetY,
		Width:     opts.Width,
		Height:    opts.Height,
		PieceSize: opts.PieceSize,
		Tolerance: opts.Tolerance,
		MinDragMS: int(opts.MinDrag / time.Millisecond),
		Expires:   expires.Unix(),
		Nonce:     nonce,
	})
	if err != nil {
		return SliderChallenge{}, err
	}
	imageURL, pieceURL, err := renderSliderAssets(opts.Width, opts.Height, opts.PieceSize, targetX, targetY, nonce)
	if err != nil {
		return SliderChallenge{}, err
	}
	return SliderChallenge{
		Width:      opts.Width,
		Height:     opts.Height,
		PieceSize:  opts.PieceSize,
		TrackWidth: opts.Width - opts.PieceSize,
		TargetY:    targetY,
		Tolerance:  opts.Tolerance,
		MinDragMS:  int(opts.MinDrag / time.Millisecond),
		Image:      imageURL,
		Piece:      pieceURL,
		Token:      token,
		ExpiresAt:  expires.UTC().Format(time.RFC3339),
	}, nil
}

func VerifySlider(opts SliderOptions, payload SliderPayload) bool {
	opts = normalizeSliderOptions(opts)
	if strings.TrimSpace(payload.Token) == "" || payload.X < 0 {
		return false
	}
	token, ok := openSliderToken(opts, payload.Token)
	if !ok {
		return false
	}
	if token.Purpose != opts.Purpose || token.ClientKey != opts.ClientKey || token.Path != opts.Path {
		return false
	}
	if token.Expires <= opts.now().Unix() {
		return false
	}
	if token.Width != opts.Width || token.Height != opts.Height || token.PieceSize != opts.PieceSize {
		return false
	}
	if payload.DragMS < token.MinDragMS {
		return false
	}
	delta := payload.X - token.TargetX
	if delta < 0 {
		delta = -delta
	}
	return delta <= token.Tolerance && verifySliderTrack(payload.Track, payload.X, payload.DragMS)
}

func normalizeSliderOptions(opts SliderOptions) SliderOptions {
	if opts.Purpose == "" {
		opts.Purpose = "captcha-slider"
	}
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Width <= 0 {
		opts.Width = 320
	}
	if opts.Height <= 0 {
		opts.Height = 150
	}
	if opts.PieceSize <= 0 {
		opts.PieceSize = 42
	}
	if opts.Tolerance <= 0 {
		opts.Tolerance = 6
	}
	if opts.MinDrag <= 0 {
		opts.MinDrag = 450 * time.Millisecond
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func (opts SliderOptions) now() time.Time {
	if opts.Now == nil {
		return time.Now()
	}
	return opts.Now()
}

func sealSliderToken(opts SliderOptions, payload sliderTokenPayload) (string, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(sliderKey(opts.Secret))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(sliderAAD(opts)))
	raw := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func openSliderToken(opts SliderOptions, raw string) (sliderTokenPayload, bool) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return sliderTokenPayload{}, false
	}
	block, err := aes.NewCipher(sliderKey(opts.Secret))
	if err != nil {
		return sliderTokenPayload{}, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(data) <= gcm.NonceSize() {
		return sliderTokenPayload{}, false
	}
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(sliderAAD(opts)))
	if err != nil {
		return sliderTokenPayload{}, false
	}
	var payload sliderTokenPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return sliderTokenPayload{}, false
	}
	return payload, true
}

func sliderKey(secret string) []byte {
	if secret == "" {
		secret = "cheesewaf-slider-captcha"
	}
	sum := sha256.Sum256([]byte("cheesewaf-slider-v1\n" + secret))
	return sum[:]
}

func sliderAAD(opts SliderOptions) string {
	return strings.Join([]string{opts.Purpose, opts.ClientKey, opts.Path}, "\n")
}

func renderSliderAssets(width, height, pieceSize, targetX, targetY int, nonce string) (string, string, error) {
	scale := sliderCaptchaImageScale
	if scale < 1 {
		scale = 1
	}
	physicalWidth := width * scale
	physicalHeight := height * scale
	physicalPieceSize := pieceSize * scale
	physicalTargetX := targetX * scale
	physicalTargetY := targetY * scale
	seed := int64(0)
	for _, b := range hmacHash("slider-image", nonce)[:8] {
		seed = (seed << 8) | int64(b)
	}
	rng := mrand.New(mrand.NewSource(seed))
	base := image.NewRGBA(image.Rect(0, 0, physicalWidth, physicalHeight))
	theme := rng.Intn(4)
	shapeVariant := rng.Intn(sliderPuzzleShapeVariants)
	renderSliderBackground(base, rng, theme)
	for i := 0; i < 10+rng.Intn(10); i++ {
		x0 := rng.Intn(physicalWidth)
		y0 := rng.Intn(physicalHeight)
		x1 := rng.Intn(physicalWidth)
		y1 := rng.Intn(physicalHeight)
		drawLine(base, x0, y0, x1, y1, color.RGBA{255, 255, 255, uint8(20 + rng.Intn(34))})
	}
	for i := 0; i < 14+rng.Intn(18); i++ {
		drawCircle(base, rng.Intn(physicalWidth), rng.Intn(physicalHeight), scale*(2+rng.Intn(8)), color.RGBA{255, 255, 255, uint8(12 + rng.Intn(22))})
	}
	for i := 0; i < 8+rng.Intn(8); i++ {
		drawRect(base, rng.Intn(physicalWidth), rng.Intn(physicalHeight), scale*(18+rng.Intn(42)), scale*(6+rng.Intn(18)), color.RGBA{255, 255, 255, uint8(10 + rng.Intn(20))})
	}
	img := cloneRGBA(base)
	piece := renderPuzzlePieceVariant(base, physicalTargetX, physicalTargetY, physicalPieceSize, shapeVariant)
	drawPuzzleSlotVariant(img, physicalTargetX, physicalTargetY, physicalPieceSize, shapeVariant)
	imageURL, err := encodePNGDataURL(img)
	if err != nil {
		return "", "", err
	}
	pieceURL, err := encodePNGDataURL(piece)
	if err != nil {
		return "", "", err
	}
	return imageURL, pieceURL, nil
}

func renderSliderBackground(img *image.RGBA, rng *mrand.Rand, theme int) {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	palettes := [][3]color.RGBA{
		{{R: 28, G: 99, B: 137, A: 255}, {R: 119, G: 171, B: 124, A: 255}, {R: 232, G: 202, B: 120, A: 255}},
		{{R: 50, G: 72, B: 135, A: 255}, {R: 101, G: 168, B: 188, A: 255}, {R: 238, G: 154, B: 111, A: 255}},
		{{R: 69, G: 96, B: 76, A: 255}, {R: 167, G: 155, B: 97, A: 255}, {R: 80, G: 154, B: 143, A: 255}},
		{{R: 86, G: 71, B: 129, A: 255}, {R: 51, G: 139, B: 156, A: 255}, {R: 213, G: 132, B: 117, A: 255}},
	}
	palette := palettes[theme%len(palettes)]
	phase := rng.Float64() * math.Pi * 2
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			nx := float64(x) / float64(maxInt(1, width-1))
			ny := float64(y) / float64(maxInt(1, height-1))
			var t float64
			switch theme % 4 {
			case 0:
				t = (nx + ny) / 2
			case 1:
				t = 0.5 + 0.32*math.Sin((nx*2.8+ny*1.6)*math.Pi+phase)
			case 2:
				dx := nx - 0.5
				dy := ny - 0.45
				t = math.Sqrt(dx*dx+dy*dy) * 1.45
			default:
				t = 0.58*nx + 0.28*math.Sin((ny*4.2+nx)*math.Pi+phase)
			}
			if t < 0 {
				t = 0
			}
			if t > 1 {
				t = 1
			}
			noise := rng.Intn(14) - 7
			c := blend(palette[0], palette[1], t, noise)
			if math.Sin((nx*7+ny*5)*math.Pi+phase) > 0.82 {
				c = blend(c, palette[2], 0.18, noise/2)
			}
			img.SetRGBA(x, y, c)
		}
	}
}

func verifySliderTrack(raw string, finalX, dragMS int) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	if len(raw) > 4096 {
		return false
	}
	var points []sliderTrackPoint
	if err := json.Unmarshal([]byte(raw), &points); err != nil {
		return false
	}
	if len(points) < 3 || len(points) > 128 {
		return false
	}
	first := points[0]
	last := points[len(points)-1]
	if first.Type != "down" || last.Type != "up" {
		return false
	}
	if first.T != 0 || last.T < 0 || last.T > dragMS+250 {
		return false
	}
	if dragMS > 0 && last.T < maxInt(0, dragMS-250) {
		return false
	}
	if abs(last.X-finalX) > 3 {
		return false
	}
	prev := first
	distinctX := map[int]struct{}{first.X: {}}
	moveCount := 0
	for i := 1; i < len(points); i++ {
		point := points[i]
		if point.Type != "move" && point.Type != "up" {
			return false
		}
		if point.T < prev.T || point.T-prev.T > maxInt(800, dragMS+250) {
			return false
		}
		if point.X < 0 || point.X > 4096 || point.Y < -2048 || point.Y > 4096 {
			return false
		}
		if abs(point.X-prev.X) > 220 || abs(point.Y-prev.Y) > 180 {
			return false
		}
		if point.Type == "move" {
			moveCount++
		}
		distinctX[point.X] = struct{}{}
		prev = point
	}
	if moveCount == 0 || len(distinctX) < 3 {
		return false
	}
	return true
}

type sliderTrackPoint struct {
	X    int    `json:"x"`
	Y    int    `json:"y"`
	T    int    `json:"t"`
	Type string `json:"type"`
}

func drawPuzzleSlot(img *image.RGBA, x, y, size int) {
	drawPuzzleSlotVariant(img, x, y, size, 0)
}

func drawPuzzleSlotVariant(img *image.RGBA, x, y, size, variant int) {
	shadow := color.RGBA{0, 0, 0, 150}
	edge := color.RGBA{255, 255, 255, 242}
	rim := color.RGBA{6, 18, 32, 158}
	outer := color.RGBA{0, 0, 0, 106}
	outerLight := color.RGBA{255, 255, 255, 128}
	radius := sliderPuzzleStrokeRadius
	for py := -radius; py < size+radius; py++ {
		for px := -radius; px < size+radius; px++ {
			gx := x + px
			gy := y + py
			if !inside(img, gx, gy) {
				continue
			}
			coverage := puzzleCoverageVariant(px, py, size, variant)
			if coverage <= 0 {
				near := puzzleNearCoverageVariant(px, py, size, radius, variant)
				if near <= 0 {
					continue
				}
				over(img, gx+1, gy+1, withAlpha(outer, uint8(62+near*84)))
				if px < size/2 || py < size/2 {
					over(img, gx, gy, withAlpha(outerLight, uint8(42+near*82)))
				}
				continue
			}
			if coverage < 0.98 || puzzleEdgeDepth(px, py, size, 1) > 0 {
				over(img, gx+1, gy+1, withAlpha(rim, uint8(82+coverage*78)))
				over(img, gx, gy, withAlpha(edge, uint8(102+coverage*140)))
				continue
			}
				over(img, gx, gy, shadow)
		}
	}
}

func puzzleMask(x, y, size int) bool {
	return puzzleMaskVariant(x, y, size, 0)
}

func puzzleMaskVariant(x, y, size, variant int) bool {
	return puzzleShapeContainsVariant(float64(x)+0.5, float64(y)+0.5, size, variant)
}

func puzzleShapeContains(fx, fy float64, size int) bool {
	return puzzleShapeContainsVariant(fx, fy, size, 0)
}

func puzzleShapeContainsVariant(fx, fy float64, size int, variant int) bool {
	if fx < 0 || fy < 0 || fx >= float64(size) || fy >= float64(size) {
		return false
	}
	r := float64(size) * 0.17
	left := float64(size) * 0.18
	right := float64(size) * 0.82
	top := float64(size) * 0.20
	bottom := float64(size) * 0.86
	inBody := fx >= left && fx <= right && fy >= top && fy <= bottom
	topMode, rightMode, bottomMode, leftMode := puzzleShapeModes(variant)
	if sideCut(topMode, fx, fy, float64(size)*0.50, top, r) ||
		sideCut(rightMode, fx, fy, right, float64(size)*0.58, r) ||
		sideCut(bottomMode, fx, fy, float64(size)*0.50, bottom, r) ||
		sideCut(leftMode, fx, fy, left, float64(size)*0.58, r) {
		return false
	}
	return inBody ||
		sideKnob(topMode, fx, fy, float64(size)*0.50, top, r) ||
		sideKnob(rightMode, fx, fy, right, float64(size)*0.58, r) ||
		sideKnob(bottomMode, fx, fy, float64(size)*0.50, bottom, r) ||
		sideKnob(leftMode, fx, fy, left, float64(size)*0.58, r)
}

func puzzleShapeModes(variant int) (top, right, bottom, left int) {
	switch ((variant % sliderPuzzleShapeVariants) + sliderPuzzleShapeVariants) % sliderPuzzleShapeVariants {
	case 1:
		return -1, 1, 1, 0
	case 2:
		return 1, -1, 1, -1
	case 3:
		return 0, -1, 1, 1
	case 4:
		return -1, 0, 1, 1
	default:
		return 1, 1, 0, -1
	}
}

func sideCut(mode int, fx, fy, cx, cy, r float64) bool {
	return mode < 0 && dist(fx, fy, cx, cy) <= r*r
}

func sideKnob(mode int, fx, fy, cx, cy, r float64) bool {
	return mode > 0 && dist(fx, fy, cx, cy) <= r*r
}

func puzzleCoverage(x, y, size int) float64 {
	return puzzleCoverageVariant(x, y, size, 0)
}

func puzzleCoverageVariant(x, y, size, variant int) float64 {
	if x < -sliderPuzzleStrokeRadius || y < -sliderPuzzleStrokeRadius || x >= size+sliderPuzzleStrokeRadius || y >= size+sliderPuzzleStrokeRadius {
		return 0
	}
	insideCount := 0
	total := sliderPuzzleAASamples * sliderPuzzleAASamples
	for sy := 0; sy < sliderPuzzleAASamples; sy++ {
		for sx := 0; sx < sliderPuzzleAASamples; sx++ {
			fx := float64(x) + (float64(sx)+0.5)/float64(sliderPuzzleAASamples)
			fy := float64(y) + (float64(sy)+0.5)/float64(sliderPuzzleAASamples)
			if puzzleShapeContainsVariant(fx, fy, size, variant) {
				insideCount++
			}
		}
	}
	return float64(insideCount) / float64(total)
}

func puzzleNearCoverage(x, y, size, radius int) float64 {
	return puzzleNearCoverageVariant(x, y, size, radius, 0)
}

func puzzleNearCoverageVariant(x, y, size, radius, variant int) float64 {
	maxCoverage := 0.0
	for dy := -radius; dy <= radius; dy++ {
		for dx := -radius; dx <= radius; dx++ {
			if dx == 0 && dy == 0 {
				continue
			}
			coverage := puzzleCoverageVariant(x+dx, y+dy, size, variant)
			if coverage > maxCoverage {
				maxCoverage = coverage
			}
		}
	}
	if maxCoverage <= 0 {
		return 0
	}
	distance := radius + 1
	for dist := 1; dist <= radius; dist++ {
		if puzzleCoverageVariant(x-dist, y, size, variant) > 0 ||
			puzzleCoverageVariant(x+dist, y, size, variant) > 0 ||
			puzzleCoverageVariant(x, y-dist, size, variant) > 0 ||
			puzzleCoverageVariant(x, y+dist, size, variant) > 0 {
			distance = dist
			break
		}
	}
	return maxCoverage * (1 - float64(distance-1)/float64(radius+1))
}

func puzzleEdgeDepth(x, y, size, radius int) int {
	return puzzleEdgeDepthVariant(x, y, size, radius, 0)
}

func puzzleEdgeDepthVariant(x, y, size, radius, variant int) int {
	if !puzzleMaskVariant(x, y, size, variant) {
		return 0
	}
	for dist := 1; dist <= radius; dist++ {
		if !puzzleMaskVariant(x-dist, y, size, variant) ||
			!puzzleMaskVariant(x+dist, y, size, variant) ||
			!puzzleMaskVariant(x, y-dist, size, variant) ||
			!puzzleMaskVariant(x, y+dist, size, variant) ||
			!puzzleMaskVariant(x-dist, y-dist, size, variant) ||
			!puzzleMaskVariant(x+dist, y-dist, size, variant) ||
			!puzzleMaskVariant(x-dist, y+dist, size, variant) ||
			!puzzleMaskVariant(x+dist, y+dist, size, variant) {
			return dist
		}
	}
	return 0
}

func puzzleNearMask(x, y, size, radius int) bool {
	return puzzleNearDepthVariant(x, y, size, radius, 0) > 0
}

func puzzleNearDepth(x, y, size, radius int) int {
	return puzzleNearDepthVariant(x, y, size, radius, 0)
}

func puzzleNearDepthVariant(x, y, size, radius, variant int) int {
	if puzzleMaskVariant(x, y, size, variant) {
		return 0
	}
	for dist := 1; dist <= radius; dist++ {
		if puzzleMaskVariant(x-dist, y, size, variant) ||
			puzzleMaskVariant(x+dist, y, size, variant) ||
			puzzleMaskVariant(x, y-dist, size, variant) ||
			puzzleMaskVariant(x, y+dist, size, variant) ||
			puzzleMaskVariant(x-dist, y-dist, size, variant) ||
			puzzleMaskVariant(x+dist, y-dist, size, variant) ||
			puzzleMaskVariant(x-dist, y+dist, size, variant) ||
			puzzleMaskVariant(x+dist, y+dist, size, variant) {
			return dist
		}
	}
	return 0
}

func cloneRGBA(src *image.RGBA) *image.RGBA {
	bounds := src.Bounds()
	dst := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			dst.SetRGBA(x, y, src.RGBAAt(x, y))
		}
	}
	return dst
}

func renderPuzzlePiece(base *image.RGBA, x, y, size int) *image.NRGBA {
	return renderPuzzlePieceVariant(base, x, y, size, 0)
}

func renderPuzzlePieceVariant(base *image.RGBA, x, y, size, variant int) *image.NRGBA {
	piece := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			coverage := puzzleCoverageVariant(px, py, size, variant)
			gx := x + px
			gy := y + py
			if coverage <= 0 || !inside(base, gx, gy) {
				continue
			}
			c := base.RGBAAt(gx, gy)
			piece.SetNRGBA(px, py, color.NRGBA{R: c.R, G: c.G, B: c.B, A: uint8(coverage * 255)})
		}
	}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			if puzzleCoverageVariant(px, py, size, variant) > 0 {
				continue
			}
			near := puzzleNearCoverageVariant(px, py, size, sliderPuzzleStrokeRadius, variant)
			if near <= 0 {
				continue
			}
			if px < size/2 || py < size/2 {
				piece.SetNRGBA(px, py, color.NRGBA{R: 255, G: 255, B: 255, A: uint8(near * 210)})
				continue
			}
			piece.SetNRGBA(px, py, color.NRGBA{R: 8, G: 22, B: 38, A: uint8(near * 226)})
		}
	}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			coverage := puzzleCoverageVariant(px, py, size, variant)
			if coverage <= 0 {
				continue
			}
			if coverage < 0.98 || puzzleEdgeDepthVariant(px, py, size, 1, variant) > 0 {
				if px < size/2 || py < size/2 {
					overNRGBA(piece, px, py, color.NRGBA{R: 255, G: 255, B: 255, A: uint8(166 + coverage*80)})
				} else {
					overNRGBA(piece, px, py, color.NRGBA{R: 5, G: 18, B: 32, A: uint8(116 + coverage*92)})
				}
			}
		}
	}
	return piece
}

func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx := abs(x1 - x0)
	dy := -abs(y1 - y0)
	sx := -1
	if x0 < x1 {
		sx = 1
	}
	sy := -1
	if y0 < y1 {
		sy = 1
	}
	err := dx + dy
	for {
		if inside(img, x0, y0) {
			over(img, x0, y0, c)
		}
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func drawCircle(img *image.RGBA, cx, cy, radius int, c color.RGBA) {
	rr := radius * radius
	for y := cy - radius; y <= cy+radius; y++ {
		for x := cx - radius; x <= cx+radius; x++ {
			if inside(img, x, y) && (x-cx)*(x-cx)+(y-cy)*(y-cy) <= rr {
				over(img, x, y, c)
			}
		}
	}
}

func drawRect(img *image.RGBA, x, y, width, height int, c color.RGBA) {
	for py := y; py < y+height; py++ {
		for px := x; px < x+width; px++ {
			if inside(img, px, py) {
				over(img, px, py, c)
			}
		}
	}
}

func blend(a, b color.RGBA, t float64, noise int) color.RGBA {
	mix := func(x, y uint8) uint8 {
		v := int(float64(x)*(1-t)+float64(y)*t) + noise
		if v < 0 {
			v = 0
		}
		if v > 255 {
			v = 255
		}
		return uint8(v)
	}
	return color.RGBA{R: mix(a.R, b.R), G: mix(a.G, b.G), B: mix(a.B, b.B), A: 255}
}

func over(img *image.RGBA, x, y int, fg color.RGBA) {
	if !inside(img, x, y) {
		return
	}
	bg := img.RGBAAt(x, y)
	alpha := float64(fg.A) / 255
	img.SetRGBA(x, y, color.RGBA{
		R: uint8(float64(fg.R)*alpha + float64(bg.R)*(1-alpha)),
		G: uint8(float64(fg.G)*alpha + float64(bg.G)*(1-alpha)),
		B: uint8(float64(fg.B)*alpha + float64(bg.B)*(1-alpha)),
		A: 255,
	})
}

func withAlpha(c color.RGBA, alpha uint8) color.RGBA {
	c.A = alpha
	return c
}

func overNRGBA(img *image.NRGBA, x, y int, fg color.NRGBA) {
	bounds := img.Bounds()
	if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
		return
	}
	bg := img.NRGBAAt(x, y)
	if bg.A == 0 {
		return
	}
	alpha := float64(fg.A) / 255
	img.SetNRGBA(x, y, color.NRGBA{
		R: uint8(float64(fg.R)*alpha + float64(bg.R)*(1-alpha)),
		G: uint8(float64(fg.G)*alpha + float64(bg.G)*(1-alpha)),
		B: uint8(float64(fg.B)*alpha + float64(bg.B)*(1-alpha)),
		A: bg.A,
	})
}

func encodePNGDataURL(img image.Image) (string, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func inside(img *image.RGBA, x, y int) bool {
	bounds := img.Bounds()
	return x >= bounds.Min.X && x < bounds.Max.X && y >= bounds.Min.Y && y < bounds.Max.Y
}

func dist(x0, y0, x1, y1 float64) float64 {
	dx := x0 - x1
	dy := y0 - y1
	return dx*dx + dy*dy
}

func hmacHash(key, value string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func randomInt(min, max int) (int, error) {
	if max < min {
		return 0, fmt.Errorf("invalid random range")
	}
	n, err := randomNumber(max - min)
	if err != nil {
		return 0, err
	}
	return min + n, nil
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}

func minUint8(a, b uint8) uint8 {
	if a < b {
		return a
	}
	return b
}
