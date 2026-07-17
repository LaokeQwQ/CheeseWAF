package captcha

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"image"
	"image/color"
	"math"
	mrand "math/rand"
	"strconv"
	"strings"
	"time"
)

type ImageChallenge struct {
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Length    int    `json:"length"`
	Image     string `json:"image"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type ImagePayload struct {
	Token  string `json:"token"`
	Answer string `json:"answer"`
}

type ImageOptions struct {
	Secret    string
	Purpose   string
	ClientKey string
	Path      string
	TTL       time.Duration
	Width     int
	Height    int
	Length    int
	Now       func() time.Time
}

type imageTokenPayload struct {
	Purpose   string `json:"purpose"`
	ClientKey string `json:"client_key"`
	Path      string `json:"path"`
	Answer    string `json:"answer"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Length    int    `json:"length"`
	Expires   int64  `json:"expires"`
	Nonce     string `json:"nonce"`
}

func NewImageChallenge(opts ImageOptions) (ImageChallenge, error) {
	opts = normalizeImageOptions(opts)
	answer, err := randomDigitCode(opts.Length)
	if err != nil {
		return ImageChallenge{}, err
	}
	nonce, err := randomToken(16)
	if err != nil {
		return ImageChallenge{}, err
	}
	expires := opts.now().Add(opts.TTL)
	token, err := sealImageToken(opts, imageTokenPayload{
		Purpose:   opts.Purpose,
		ClientKey: opts.ClientKey,
		Path:      opts.Path,
		Answer:    answer,
		Width:     opts.Width,
		Height:    opts.Height,
		Length:    opts.Length,
		Expires:   expires.Unix(),
		Nonce:     nonce,
	})
	if err != nil {
		return ImageChallenge{}, err
	}
	imageURL, err := renderImageCaptcha(opts.Width, opts.Height, answer, nonce)
	if err != nil {
		return ImageChallenge{}, err
	}
	return ImageChallenge{
		Width:     opts.Width,
		Height:    opts.Height,
		Length:    opts.Length,
		Image:     imageURL,
		Token:     token,
		ExpiresAt: expires.UTC().Format(time.RFC3339),
	}, nil
}

func RenderImageAudio(opts ImageOptions, token string) ([]byte, bool, error) {
	opts = normalizeImageOptions(opts)
	payload, ok := openImageToken(opts, token)
	if !ok {
		return nil, false, nil
	}
	if payload.Purpose != opts.Purpose || payload.ClientKey != opts.ClientKey || payload.Path != opts.Path {
		return nil, false, nil
	}
	if payload.Expires <= opts.now().Unix() {
		return nil, false, nil
	}
	if payload.Width != opts.Width || payload.Height != opts.Height || payload.Length != opts.Length {
		return nil, false, nil
	}
	data, err := renderDigitAudio(payload.Answer, payload.Nonce)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func VerifyImage(opts ImageOptions, payload ImagePayload) bool {
	opts = normalizeImageOptions(opts)
	if strings.TrimSpace(payload.Token) == "" {
		return false
	}
	token, ok := openImageToken(opts, payload.Token)
	if !ok {
		return false
	}
	if token.Purpose != opts.Purpose || token.ClientKey != opts.ClientKey || token.Path != opts.Path {
		return false
	}
	if token.Expires <= opts.now().Unix() {
		return false
	}
	if token.Width != opts.Width || token.Height != opts.Height || token.Length != opts.Length {
		return false
	}
	answer := normalizeImageAnswer(payload.Answer)
	return hmac.Equal([]byte(answer), []byte(token.Answer))
}

func normalizeImageOptions(opts ImageOptions) ImageOptions {
	if opts.Purpose == "" {
		opts.Purpose = "captcha-image"
	}
	if opts.TTL <= 0 {
		opts.TTL = 2 * time.Minute
	}
	if opts.Width <= 0 {
		opts.Width = 220
	}
	if opts.Height <= 0 {
		opts.Height = 86
	}
	if opts.Length <= 0 {
		opts.Length = 6
	}
	if opts.Length < 4 {
		opts.Length = 4
	}
	if opts.Length > 8 {
		opts.Length = 8
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func (opts ImageOptions) now() time.Time {
	if opts.Now == nil {
		return time.Now()
	}
	return opts.Now()
}

func sealImageToken(opts ImageOptions, payload imageTokenPayload) (string, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(imageKey(opts.Secret))
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
	ciphertext := gcm.Seal(nil, nonce, plain, []byte(imageAAD(opts)))
	raw := append(nonce, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func openImageToken(opts ImageOptions, raw string) (imageTokenPayload, bool) {
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return imageTokenPayload{}, false
	}
	block, err := aes.NewCipher(imageKey(opts.Secret))
	if err != nil {
		return imageTokenPayload{}, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(data) <= gcm.NonceSize() {
		return imageTokenPayload{}, false
	}
	plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(imageAAD(opts)))
	if err != nil {
		return imageTokenPayload{}, false
	}
	var payload imageTokenPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return imageTokenPayload{}, false
	}
	return payload, true
}

func imageKey(secret string) []byte {
	if secret == "" {
		secret = "cheesewaf-image-captcha"
	}
	sum := sha256.Sum256([]byte("cheesewaf-image-v1\n" + secret))
	return sum[:]
}

func imageAAD(opts ImageOptions) string {
	return strings.Join([]string{opts.Purpose, opts.ClientKey, opts.Path}, "\n")
}

func randomDigitCode(length int) (string, error) {
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		n, err := randomNumber(8)
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('1' + n))
	}
	return b.String(), nil
}

func normalizeImageAnswer(answer string) string {
	var b strings.Builder
	for _, r := range answer {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func renderImageCaptcha(width, height int, answer, nonce string) (string, error) {
	seed := int64(0)
	for _, b := range hmacHash("image-captcha", nonce)[:8] {
		seed = (seed << 8) | int64(b)
	}
	rng := mrand.New(mrand.NewSource(seed))
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	bgA := color.RGBA{R: uint8(232 + rng.Intn(12)), G: uint8(239 + rng.Intn(10)), B: uint8(244 + rng.Intn(10)), A: 255}
	bgB := color.RGBA{R: uint8(201 + rng.Intn(20)), G: uint8(229 + rng.Intn(18)), B: uint8(221 + rng.Intn(20)), A: 255}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			t := float64(x+y) / float64(width+height)
			img.SetRGBA(x, y, blend(bgA, bgB, t, rng.Intn(8)-4))
		}
	}
	for i := 0; i < 22; i++ {
		drawLine(img, rng.Intn(width), rng.Intn(height), rng.Intn(width), rng.Intn(height), color.RGBA{
			R: uint8(72 + rng.Intn(84)), G: uint8(102 + rng.Intn(84)), B: uint8(112 + rng.Intn(72)), A: uint8(34 + rng.Intn(52)),
		})
	}
	for i := 0; i < 90; i++ {
		drawCircle(img, rng.Intn(width), rng.Intn(height), 1+rng.Intn(2), color.RGBA{R: 45, G: 86, B: 100, A: uint8(30 + rng.Intn(54))})
	}
	slot := float64(width-28) / float64(len(answer))
	for i, r := range answer {
		x := 14 + int(float64(i)*slot) + rng.Intn(5)
		y := height/2 - 18 + rng.Intn(8) - 4
		scale := 3 + rng.Intn(2)
		drawDigit(img, int(r-'0'), x, y, scale, color.RGBA{R: uint8(23 + rng.Intn(42)), G: uint8(54 + rng.Intn(42)), B: uint8(74 + rng.Intn(42)), A: 230})
	}
	return encodePNGDataURL(img)
}

func drawDigit(img *image.RGBA, digit, x, y, scale int, c color.RGBA) {
	segments := [10][7]bool{
		{true, true, true, true, true, true, false},
		{false, true, true, false, false, false, false},
		{true, true, false, true, true, false, true},
		{true, true, true, true, false, false, true},
		{false, true, true, false, false, true, true},
		{true, false, true, true, false, true, true},
		{true, false, true, true, true, true, true},
		{true, true, true, false, false, false, false},
		{true, true, true, true, true, true, true},
		{true, true, true, true, false, true, true},
	}
	if digit < 0 || digit > 9 {
		return
	}
	w := 8 * scale
	h := 14 * scale
	thick := maxInt(2, scale)
	if segments[digit][0] {
		fillRect(img, x+thick, y, w-thick*2, thick, c)
	}
	if segments[digit][1] {
		fillRect(img, x+w-thick, y+thick, thick, h/2-thick, c)
	}
	if segments[digit][2] {
		fillRect(img, x+w-thick, y+h/2, thick, h/2-thick, c)
	}
	if segments[digit][3] {
		fillRect(img, x+thick, y+h-thick, w-thick*2, thick, c)
	}
	if segments[digit][4] {
		fillRect(img, x, y+h/2, thick, h/2-thick, c)
	}
	if segments[digit][5] {
		fillRect(img, x, y+thick, thick, h/2-thick, c)
	}
	if segments[digit][6] {
		fillRect(img, x+thick, y+h/2-thick/2, w-thick*2, thick, c)
	}
}

func fillRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	for py := y; py < y+h; py++ {
		for px := x; px < x+w; px++ {
			over(img, px, py, c)
		}
	}
}

func renderDigitAudio(answer, nonce string) ([]byte, error) {
	const sampleRate = 8000
	seed := int64(0)
	for _, b := range hmacHash("image-audio", nonce)[:8] {
		seed = (seed << 8) | int64(b)
	}
	rng := mrand.New(mrand.NewSource(seed))
	var samples []int16
	appendSilence := func(ms int) {
		count := sampleRate * ms / 1000
		for i := 0; i < count; i++ {
			samples = append(samples, 0)
		}
	}
	appendTone := func(freqA, freqB float64, ms int, amp float64) {
		count := sampleRate * ms / 1000
		phaseB := rng.Float64() * math.Pi
		for i := 0; i < count; i++ {
			t := float64(i) / sampleRate
			envelope := 1.0
			if i < 80 {
				envelope = float64(i) / 80
			} else if remain := count - i; remain < 80 {
				envelope = float64(remain) / 80
			}
			noise := (rng.Float64()*2 - 1) * 0.07
			wave := math.Sin(2*math.Pi*freqA*t)*0.62 + math.Sin(2*math.Pi*freqB*t+phaseB)*0.38 + noise
			samples = append(samples, int16(wave*amp*envelope))
		}
	}
	appendSilence(280)
	for pos, r := range answer {
		n, _ := strconv.Atoi(string(r))
		base := 430.0 + float64(n)*37 + rng.Float64()*16
		appendTone(base, base*1.53, 220+rng.Intn(80), 9200)
		appendSilence(70 + rng.Intn(60))
		appendTone(base*0.74, base*1.91, 180+rng.Intn(70), 8200)
		if pos < len(answer)-1 {
			appendSilence(260 + rng.Intn(140))
		}
	}
	appendSilence(320)
	var buf bytes.Buffer
	if err := writeWAV(&buf, sampleRate, samples); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeWAV(buf *bytes.Buffer, sampleRate int, samples []int16) error {
	dataLen := uint32(len(samples) * 2)
	if _, err := buf.WriteString("RIFF"); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, uint32(36)+dataLen); err != nil {
		return err
	}
	if _, err := buf.WriteString("WAVEfmt "); err != nil {
		return err
	}
	for _, v := range []any{
		uint32(16), uint16(1), uint16(1), uint32(sampleRate), uint32(sampleRate * 2), uint16(2), uint16(16),
	} {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			return err
		}
	}
	if _, err := buf.WriteString("data"); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, dataLen); err != nil {
		return err
	}
	return binary.Write(buf, binary.LittleEndian, samples)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
