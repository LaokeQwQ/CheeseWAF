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

	"github.com/LaokeQwQ/CheeseWAF/internal/captcha/imageengine"
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

const sliderCaptchaImageScale = 2

const (
	sliderMaxTokenEncodedBytes = 4096
	sliderMaxTokenDecodedBytes = 3072
	sliderMaxTrackBytes        = 4096
)

var sliderShapePool = [...]imageengine.ShapeKind{
	imageengine.ShapePuzzle,
	imageengine.ShapeCircle,
	imageengine.ShapeTriangle,
	imageengine.ShapeSquare,
	imageengine.ShapeDiamond,
	imageengine.ShapeTrapezoid,
	imageengine.ShapeShield,
}

func NewSliderChallenge(opts SliderOptions) (SliderChallenge, error) {
	opts = normalizeSliderOptions(opts)
	if strings.TrimSpace(opts.Secret) == "" {
		return SliderChallenge{}, fmt.Errorf("captcha slider secret is required")
	}
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
	if strings.TrimSpace(opts.Secret) == "" {
		return false
	}
	if len(payload.Token) > sliderMaxTokenEncodedBytes || len(payload.Track) > sliderMaxTrackBytes || strings.TrimSpace(payload.Token) == "" || payload.X < 0 {
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
	if len(raw) == 0 || len(raw) > sliderMaxTokenEncodedBytes || base64.RawURLEncoding.DecodedLen(len(raw)) > sliderMaxTokenDecodedBytes {
		return sliderTokenPayload{}, false
	}
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(data) > sliderMaxTokenDecodedBytes {
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
		// Never fall back to a hard-coded secret — callers must supply one.
		sum := sha256.Sum256([]byte("cheesewaf-slider-v1\ninvalid-empty-secret"))
		return sum[:]
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
	shape := sliderShapePool[rng.Intn(len(sliderShapePool))]
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
	return renderSliderShapeAssets(base, physicalPieceSize, physicalTargetX, physicalTargetY, shape)
}

func renderSliderShapeAssets(base *image.RGBA, pieceSize, targetX, targetY int, shape imageengine.ShapeKind) (string, string, error) {
	padding := maxInt(6, pieceSize/9)
	mask, err := imageengine.NewShapeMask(shape, pieceSize, padding, imageengine.Limits{})
	if err != nil {
		return "", "", err
	}
	piece, err := imageengine.ExtractPiece(base, image.Pt(targetX, targetY), mask)
	if err != nil {
		return "", "", err
	}
	strokeWidth := minInt(padding, maxInt(3, pieceSize/21))
	if err := imageengine.DrawSlot(piece, image.Point{}, mask, color.Transparent, color.RGBA{R: 255, G: 255, B: 255, A: 245}, strokeWidth); err != nil {
		return "", "", err
	}
	img := cloneRGBA(base)
	if err := imageengine.DrawSlot(img, image.Pt(targetX, targetY), mask,
		color.RGBA{R: 8, G: 18, B: 31, A: 142},
		color.RGBA{R: 255, G: 255, B: 255, A: 238}, strokeWidth); err != nil {
		return "", "", err
	}
	imageURL, err := imageengine.PNGDataURI(img, imageengine.Limits{})
	if err != nil {
		return "", "", err
	}
	pieceURL, err := imageengine.PNGDataURI(piece, imageengine.Limits{})
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
	// Empty track is never a successful human interaction signal.
	if raw == "" {
		return false
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
