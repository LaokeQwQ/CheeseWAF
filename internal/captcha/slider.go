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
	return delta <= token.Tolerance
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
	seed := int64(0)
	for _, b := range hmacHash("slider-image", nonce)[:8] {
		seed = (seed << 8) | int64(b)
	}
	rng := mrand.New(mrand.NewSource(seed))
	base := image.NewRGBA(image.Rect(0, 0, width, height))
	baseA := color.RGBA{R: uint8(26 + rng.Intn(32)), G: uint8(96 + rng.Intn(58)), B: uint8(126 + rng.Intn(48)), A: 255}
	baseB := color.RGBA{R: uint8(106 + rng.Intn(46)), G: uint8(157 + rng.Intn(42)), B: uint8(118 + rng.Intn(52)), A: 255}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			t := float64(x+y) / float64(width+height)
			noise := rng.Intn(10) - 5
			base.SetRGBA(x, y, blend(baseA, baseB, t, noise))
		}
	}
	for i := 0; i < 12; i++ {
		x0 := rng.Intn(width)
		y0 := rng.Intn(height)
		x1 := rng.Intn(width)
		y1 := rng.Intn(height)
		drawLine(base, x0, y0, x1, y1, color.RGBA{255, 255, 255, uint8(20 + rng.Intn(34))})
	}
	for i := 0; i < 18; i++ {
		drawCircle(base, rng.Intn(width), rng.Intn(height), 2+rng.Intn(8), color.RGBA{255, 255, 255, uint8(12 + rng.Intn(22))})
	}
	img := cloneRGBA(base)
	piece := renderPuzzlePiece(base, targetX, targetY, pieceSize)
	drawPuzzleSlot(img, targetX, targetY, pieceSize)
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

func drawPuzzleSlot(img *image.RGBA, x, y, size int) {
	shadow := color.RGBA{0, 0, 0, 132}
	edge := color.RGBA{255, 255, 255, 184}
	rim := color.RGBA{0, 0, 0, 58}
	for py := -2; py < size+2; py++ {
		for px := -2; px < size+2; px++ {
			gx := x + px
			gy := y + py
			if !inside(img, gx, gy) {
				continue
			}
			in := puzzleMask(px, py, size)
			if !in {
				continue
			}
			if px < 1 || py < 1 || px >= size-1 || py >= size-1 || !puzzleMask(px-1, py, size) || !puzzleMask(px+1, py, size) || !puzzleMask(px, py-1, size) || !puzzleMask(px, py+1, size) {
				over(img, gx+1, gy+1, rim)
				over(img, gx, gy, edge)
				continue
			}
			over(img, gx, gy, shadow)
		}
	}
}

func puzzleMask(x, y, size int) bool {
	if x < 0 || y < 0 || x >= size || y >= size {
		return false
	}
	fx := float64(x)
	fy := float64(y)
	r := float64(size) * 0.17
	left := float64(size) * 0.18
	right := float64(size) * 0.82
	top := float64(size) * 0.20
	bottom := float64(size) * 0.86
	inBody := fx >= left && fx <= right && fy >= top && fy <= bottom
	topKnob := dist(fx, fy, float64(size)*0.50, top) <= r*r
	rightKnob := dist(fx, fy, right, float64(size)*0.58) <= r*r
	leftCut := dist(fx, fy, left, float64(size)*0.58) <= r*r
	if leftCut {
		return false
	}
	return inBody || topKnob || rightKnob
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
	piece := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			if !puzzleMask(px, py, size) {
				continue
			}
			gx := x + px
			gy := y + py
			if !inside(base, gx, gy) {
				continue
			}
			c := base.RGBAAt(gx, gy)
			piece.SetNRGBA(px, py, color.NRGBA{R: c.R, G: c.G, B: c.B, A: 255})
		}
	}
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			if !puzzleMask(px, py, size) {
				continue
			}
			if px < 1 || py < 1 || px >= size-1 || py >= size-1 || !puzzleMask(px-1, py, size) || !puzzleMask(px+1, py, size) || !puzzleMask(px, py-1, size) || !puzzleMask(px, py+1, size) {
				if px < size/2 || py < size/2 {
					overNRGBA(piece, px, py, color.NRGBA{R: 255, G: 255, B: 255, A: 192})
				} else {
					overNRGBA(piece, px, py, color.NRGBA{R: 0, G: 0, B: 0, A: 74})
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
