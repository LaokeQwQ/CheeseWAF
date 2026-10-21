// Package php2shell detects the structural multipart shapes used against the
// PHP session upload progress bug tracked as CVE-2026-109618/109619.
//
// The detector reads the decoded request body and raw request headers without
// mutating the request. Parsing is bounded in parts, per-part bytes, and
// retained field names so a hostile multipart body cannot turn into unbounded
// work.
package php2shell

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

const (
	detectorID       = "rce.php2shell"
	detectorPriority = 240

	defaultMaxParts              = 512
	defaultMaxArrayDepth         = 6
	defaultMaxEmptyFilenameParts = 32
	defaultSessionFieldName      = "PHPSESSID"
	// uploadProgressFieldLower is PHP_SESSION_UPLOAD_PROGRESS, compared
	// case-insensitively against field names.
	uploadProgressFieldLower = "php_session_upload_progress"

	maxFieldValueBytes  = 4 << 10
	maxPartDrainBytes   = 1 << 20
	maxPayloadBytes     = 512
	maxSampleFields     = 3
	maxSampleFieldBytes = 64
)

// phpSerializedMarkers are matched case-insensitively. Serialized data uses
// the leading pipe form when it is embedded in a PHP upload field.
var phpSerializedMarkers = [...]string{
	"<?php",
	"<?=",
	"|o:",
	"|a:",
	"|s:",
	"|c:",
}

// Config bounds the detector. Zero values select conservative defaults.
type Config struct {
	Enabled               bool
	SessionFieldNames     []string
	MaxParts              int
	MaxArrayDepth         int
	MaxEmptyFilenameParts int
	BlockUploadProgress   bool
	// BlockAllMultipart is the explicit emergency stop. It only blocks
	// multipart/form-data requests; allowlisted paths still receive the normal
	// structural checks so a hard signature cannot bypass the emergency mode.
	BlockAllMultipart bool
	// AllowPaths contains exact path prefixes exempted from the emergency
	// all-multipart block. It never exempts a hard structural signature.
	AllowPaths []string
}

// Detector implements engine.Detector for the PHP2Shell multipart shape.
type Detector struct {
	cfg           Config
	sessionFields []string
}

// New builds a detector. Session names are normalized once so the per-part
// path does not repeat trimming, lowercasing, or duplicate checks.
func New(cfg Config) *Detector {
	if cfg.MaxParts <= 0 {
		cfg.MaxParts = defaultMaxParts
	}
	if cfg.MaxArrayDepth <= 0 {
		cfg.MaxArrayDepth = defaultMaxArrayDepth
	}
	if cfg.MaxEmptyFilenameParts <= 0 {
		cfg.MaxEmptyFilenameParts = defaultMaxEmptyFilenameParts
	}

	seen := make(map[string]struct{}, len(cfg.SessionFieldNames))
	fields := make([]string, 0, len(cfg.SessionFieldNames))
	for _, name := range cfg.SessionFieldNames {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		fields = append(fields, name)
	}
	if len(fields) == 0 {
		fields = append(fields, strings.ToLower(defaultSessionFieldName))
	}
	cfg.SessionFieldNames = append([]string(nil), fields...)
	return &Detector{cfg: cfg, sessionFields: fields}
}

func (d *Detector) ID() string    { return detectorID }
func (d *Detector) Name() string  { return "PHP2Shell Multipart Detector" }
func (d *Detector) Priority() int { return detectorPriority }

// Detect inspects multipart/form-data bodies for the CVE-2026-109618/109619
// structure. Benign multipart and malformed bodies without a hard signal
// return nil. A malformed body that already produced a blocking signal still
// blocks because the signal was observed before parsing stopped.
func (d *Detector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	if d == nil || !d.cfg.Enabled || reqCtx == nil || reqCtx.Request == nil {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	body := reqCtx.DecodedBody
	if len(body) == 0 {
		return nil, nil
	}
	contentType := reqCtx.Request.Header.Get("Content-Type")
	if d.cfg.BlockAllMultipart && isMultipartFormData(contentType) && !d.pathAllowed(reqCtx.NormalizedPath) {
		state := parseState{parts: 1}
		return d.result(&state, "emergency all-multipart block"), nil
	}
	if isURLEncodedForm(contentType) {
		return d.detectURLEncoded(body), nil
	}
	if !isMultipartFormData(contentType) {
		return nil, nil
	}
	boundary := multipartBoundary(contentType)
	if boundary == "" {
		return nil, nil
	}
	contentEncodingNonIdentity := hasNonIdentityContentEncoding(reqCtx.Request.Header.Get("Content-Encoding"))

	state := parseState{buf: make([]byte, maxFieldValueBytes)}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for state.parts < d.cfg.MaxParts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		part, err := reader.NextPart()
		if err != nil {
			if err != io.EOF {
				state.parseIncomplete = true
			}
			break
		}
		d.inspectPart(part, &state)
		_ = part.Close()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	reason, ok := d.decide(&state, contentEncodingNonIdentity)
	if !ok {
		return nil, nil
	}
	return d.result(&state, reason), nil
}

// inspectPart records only bounded metadata. File bodies are skipped without
// buffering; non-file values contribute at most the first 4 KiB.
func (d *Detector) inspectPart(part *multipart.Part, state *parseState) {
	state.parts++

	name, filename, hasFilename := contentDisposition(part.Header.Get("Content-Disposition"))
	if name != "" {
		state.observeField(name, d.sessionFields)
	}

	if hasFilename {
		if filename == "" {
			state.emptyFilenameParts++
		} else {
			state.fileParts++
			if hasPHPOrSerializedMarker(filename) {
				state.marker = true
			}
		}
		if err := drainPart(part); err != nil {
			state.parseIncomplete = true
		}
		return
	}

	n, err := io.ReadFull(part, state.buf)
	if n > 0 && hasPHPOrSerializedMarkerBytes(state.buf[:n]) {
		state.marker = true
	}
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		state.parseIncomplete = true
	}
	if err := drainPart(part); err != nil {
		state.parseIncomplete = true
	}
}

// decide applies the conservative rules. Reasons are stable enough for tests
// and audit output, and every branch is bounded by already-collected state.
func (d *Detector) decide(state *parseState, contentEncodingNonIdentity bool) (string, bool) {
	switch {
	case state.session && (state.uploadProgress || state.fileParts > 0 || state.maxArrayDepth >= 2 || state.marker):
		return "php session field combined with upload progress, file, array, or PHP marker", true
	case state.uploadProgress && (state.parts >= 16 ||
		state.arrayFields >= 16 ||
		state.maxArrayDepth >= 3 ||
		state.emptyFilenameParts >= 4 ||
		state.marker ||
		contentEncodingNonIdentity):
		return "upload progress combined with multipart spray or PHP marker", true
	case !state.uploadProgress && (state.maxArrayDepth >= d.cfg.MaxArrayDepth ||
		state.emptyFilenameParts >= d.cfg.MaxEmptyFilenameParts ||
		state.parts >= 256):
		return "multipart array depth, empty filenames, or part count exceeded", true
	case d.cfg.BlockUploadProgress && state.uploadProgress:
		return "upload progress blocked by configuration", true
	default:
		return "", false
	}
}

func (d *Detector) result(state *parseState, reason string) *engine.DetectionResult {
	message := "PHP2Shell multipart shape: " + reason
	if state.urlEncoded {
		message = "PHP2Shell URL-encoded form shape: " + reason
	}
	if state.parseIncomplete {
		message += " (truncated multipart)"
	}
	return &engine.DetectionResult{
		Detected:   true,
		DetectorID: d.ID(),
		Category:   "rce",
		Severity:   engine.SeverityCritical,
		Action:     engine.ActionBlock,
		Message:    message,
		Confidence: 0.97,
		Payload:    clip(state.payload(reason), maxPayloadBytes),
	}
}

// parseState is scratch state for a single Detect call.
type parseState struct {
	parts              int
	fileParts          int
	emptyFilenameParts int
	arrayFields        int
	maxArrayDepth      int
	session            bool
	uploadProgress     bool
	marker             bool
	parseIncomplete    bool
	urlEncoded         bool
	samples            []string
	buf                []byte
}

func (s *parseState) observeField(name string, sessionFields []string) {
	lower := strings.ToLower(strings.TrimSpace(name))
	for _, field := range sessionFields {
		if lower == field {
			s.session = true
			break
		}
	}
	if strings.Contains(lower, uploadProgressFieldLower) {
		s.uploadProgress = true
	}
	if depth := bracketDepth(name); depth > 0 {
		s.arrayFields++
		if depth > s.maxArrayDepth {
			s.maxArrayDepth = depth
		}
	}
	if len(s.samples) < maxSampleFields {
		s.samples = append(s.samples, clip(name, maxSampleFieldBytes))
	}
}

func (s *parseState) payload(reason string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "url_encoded=%t reason=%s parts=%d files=%d empty_filenames=%d array_fields=%d max_array_depth=%d session=%t progress=%t marker=%t",
		s.urlEncoded, reason, s.parts, s.fileParts, s.emptyFilenameParts, s.arrayFields, s.maxArrayDepth,
		s.session, s.uploadProgress, s.marker)
	if s.parseIncomplete {
		b.WriteString(" truncated=true")
	}
	if len(s.samples) > 0 {
		b.WriteString(" fields=")
		b.WriteString(strings.Join(s.samples, ","))
	}
	return b.String()
}

// bracketDepth reports PHP-style array dimensions such as files[a][b][c].
// Counting opening brackets matches what PHP sees as dimensions for the
// field name, including the empty form t[].
func (d *Detector) pathAllowed(path string) bool {
	for _, prefix := range d.cfg.AllowPaths {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			continue
		}
		if path == prefix || strings.HasPrefix(path, strings.TrimRight(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func isURLEncodedForm(header string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(header)), "application/x-www-form-urlencoded")
}

func (d *Detector) detectURLEncoded(body []byte) *engine.DetectionResult {
	// ParseQuery allocates per field; bound the input before parsing. A hard
	// signal in the inspected prefix still blocks, and full-body uploads are
	// handled by the multipart path.
	if len(body) > 1<<20 {
		body = body[:1<<20]
	}
	values, err := url.ParseQuery(string(body))
	if len(values) == 0 {
		return nil
	}
	state := parseState{urlEncoded: true, parseIncomplete: err != nil}
	for name, entries := range values {
		state.observeField(name, d.sessionFields)
		for _, value := range entries {
			if hasPHPOrSerializedMarker(value) {
				state.marker = true
			}
		}
	}
	switch {
	case state.session && (state.uploadProgress || state.marker || state.maxArrayDepth >= 2):
		return d.result(&state, "php session field in URL-encoded form")
	case state.uploadProgress && (state.arrayFields >= 16 || state.maxArrayDepth >= 3 || state.marker):
		return d.result(&state, "upload progress in URL-encoded spray")
	case state.maxArrayDepth >= 8 || len(values) >= 1000:
		return d.result(&state, "URL-encoded array depth or field count exceeded")
	case d.cfg.BlockUploadProgress && state.uploadProgress:
		return d.result(&state, "upload progress blocked by configuration")
	default:
		return nil
	}
}

func bracketDepth(name string) int {
	depth := 0
	for i := range name {
		if name[i] == '[' {
			depth++
		}
	}
	return depth
}

// isMultipartFormData accepts the media type prefix even when the remaining
// parameters are malformed, comma-separated, or truncated. The boundary is
// resolved separately so a bad parameter tail cannot hide the body type.
func isMultipartFormData(header string) bool {
	const prefix = "multipart/form-data"
	lower := strings.ToLower(strings.TrimSpace(header))
	if !strings.HasPrefix(lower, prefix) {
		return false
	}
	if len(lower) == len(prefix) {
		return true
	}
	switch lower[len(prefix)] {
	case ';', ',', ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

// multipartBoundary prefers the parsed media type and falls back to a raw
// parameter scan for headers that mime.ParseMediaType rejects.
func multipartBoundary(header string) string {
	if mediaType, params, err := mime.ParseMediaType(header); err == nil {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(mediaType)), "multipart/form-data") {
			if boundary := strings.TrimSpace(params["boundary"]); boundary != "" {
				return boundary
			}
		}
	}
	boundary, _ := rawHeaderParam(header, "boundary")
	return strings.TrimSpace(boundary)
}

// contentDisposition parses the name and filename parameters once. The raw
// fallback is what distinguishes filename="" (present but empty) from a field
// that has no filename parameter at all.
func contentDisposition(header string) (name, filename string, hasFilename bool) {
	if _, params, err := mime.ParseMediaType(header); err == nil {
		filename, hasFilename = params["filename"]
		return params["name"], filename, hasFilename
	}
	name, _ = rawHeaderParam(header, "name")
	filename, hasFilename = rawHeaderParam(header, "filename")
	return name, filename, hasFilename
}

// rawHeaderParam scans semicolon/comma/space separated parameters. It also
// tolerates unterminated quotes because truncated Content-Disposition headers
// are attacker-controlled and must not be dropped before counting.
func rawHeaderParam(header, key string) (string, bool) {
	key = strings.ToLower(key)
	if key == "" {
		return "", false
	}
	for i := 0; i < len(header); {
		if header[i] == '"' {
			// Skip quoted values so decoy text such as note="boundary=x"
			// cannot win over the real parameter.
			i++
			for i < len(header) {
				if header[i] == '\\' && i+1 < len(header) {
					i += 2
					continue
				}
				if header[i] == '"' {
					i++
					break
				}
				i++
			}
			continue
		}
		if (i == 0 || isParamSeparator(header[i-1])) && hasFoldASCIIAt(header, i, key) {
			position := i + len(key)
			for position < len(header) && isHorizontalSpace(header[position]) {
				position++
			}
			if position < len(header) && header[position] == '=' {
				position++
				for position < len(header) && isHorizontalSpace(header[position]) {
					position++
				}
				return headerParamValue(header, position)
			}
		}
		i++
	}
	return "", false
}

// hasFoldASCIIAt reports whether needle occurs at start. It folds one byte at
// a time, so the caller's offsets always stay valid even when the header
// contains non-ASCII bytes whose lowercase form would change the length.
func hasFoldASCIIAt(haystack string, start int, needle string) bool {
	if start < 0 || start+len(needle) > len(haystack) {
		return false
	}
	for j := range len(needle) {
		if lowerASCII(haystack[start+j]) != needle[j] {
			return false
		}
	}
	return true
}

func headerParamValue(header string, position int) (string, bool) {
	if position >= len(header) {
		// A truncated "name=" is still a present parameter with an empty value.
		return "", true
	}
	if header[position] != '"' {
		end := position
		for end < len(header) && !isParamTerminator(header[end]) {
			end++
		}
		return strings.TrimSpace(header[position:end]), true
	}
	var value strings.Builder
	for i := position + 1; i < len(header); i++ {
		switch header[i] {
		case '\\':
			if i+1 < len(header) {
				i++
				value.WriteByte(header[i])
			}
		case '"':
			return value.String(), true
		default:
			value.WriteByte(header[i])
		}
	}
	return value.String(), true
}

func isParamSeparator(c byte) bool {
	return c == ';' || c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func isParamTerminator(c byte) bool {
	return isParamSeparator(c) || c == '"'
}

func isHorizontalSpace(c byte) bool {
	return c == ' ' || c == '\t'
}

func hasNonIdentityContentEncoding(value string) bool {
	for _, encoding := range strings.Split(strings.ToLower(value), ",") {
		encoding = strings.TrimSpace(encoding)
		if encoding == "" || encoding == "identity" {
			continue
		}
		return true
	}
	return false
}

// drainPart consumes a bounded window from a part. multipart.Reader discards
// anything left when the next part is requested, so the detector never holds
// an entire part body in memory.
func drainPart(part *multipart.Part) error {
	_, err := io.CopyN(io.Discard, part, maxPartDrainBytes)
	if err == io.EOF {
		return nil
	}
	return err
}

func hasPHPOrSerializedMarker(value string) bool {
	for _, marker := range phpSerializedMarkers {
		if containsFoldBytesString(value, marker) {
			return true
		}
	}
	return false
}

func hasPHPOrSerializedMarkerBytes(value []byte) bool {
	for _, marker := range phpSerializedMarkers {
		if containsFoldBytes(value, marker) {
			return true
		}
	}
	return false
}

func containsFoldBytesString(value, marker string) bool {
	if marker == "" || len(value) < len(marker) {
		return false
	}
	for i := range len(value) - len(marker) + 1 {
		match := true
		for j := range len(marker) {
			if lowerASCII(value[i+j]) != marker[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func containsFoldBytes(value []byte, marker string) bool {
	if marker == "" || len(value) < len(marker) {
		return false
	}
	for i := range len(value) - len(marker) + 1 {
		match := true
		for j := range len(marker) {
			if lowerASCII(value[i+j]) != marker[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func clip(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

var _ engine.Detector = (*Detector)(nil)
