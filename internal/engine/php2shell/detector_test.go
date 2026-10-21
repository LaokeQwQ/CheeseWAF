package php2shell

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

const (
	testBoundary = "b12345678901"
	minimalBody  = "--b12345678901\r\n" +
		"Content-Disposition: form-data; name=\"PHPSESSID\"\r\n" +
		"\r\n" +
		"xxxx\r\n" +
		"--b12345678901\r\n" +
		"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n" +
		"\r\n" +
		"x\r\n" +
		"--b12345678901\r\n" +
		"Content-Disposition: form-data; name=\"f\"; filename=\"x\"\r\n" +
		"\r\n" +
		"x\r\n" +
		"--b12345678901--\r\n"
)

func TestDetectorIdentity(t *testing.T) {
	d := New(Config{Enabled: true})
	if d.ID() != "rce.php2shell" {
		t.Fatalf("ID() = %q", d.ID())
	}
	if d.Priority() != 240 {
		t.Fatalf("Priority() = %d", d.Priority())
	}
	if d.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
	var _ engine.Detector = d
}

func TestMinimalTriggerIs258Bytes(t *testing.T) {
	if len(minimalBody) != 258 {
		t.Fatalf("minimal trigger length = %d, want 258", len(minimalBody))
	}
}

func TestNewDefaults(t *testing.T) {
	d := New(Config{Enabled: true})
	if d.cfg.MaxParts != 512 {
		t.Fatalf("MaxParts = %d, want 512", d.cfg.MaxParts)
	}
	if d.cfg.MaxArrayDepth != 6 {
		t.Fatalf("MaxArrayDepth = %d, want 6", d.cfg.MaxArrayDepth)
	}
	if d.cfg.MaxEmptyFilenameParts != 32 {
		t.Fatalf("MaxEmptyFilenameParts = %d, want 32", d.cfg.MaxEmptyFilenameParts)
	}
	if len(d.sessionFields) != 1 || d.sessionFields[0] != "phpsessid" {
		t.Fatalf("sessionFields = %v, want [phpsessid]", d.sessionFields)
	}
}

func TestDetect(t *testing.T) {
	longNames := []formPart{
		{name: strings.Repeat("A", 2000) + "[]", value: "v"},
		{name: strings.Repeat("B", 2000) + "[]", value: "v"},
		{name: strings.Repeat("C", 2000) + "[]", value: "v"},
	}
	longNameBody := buildMultipart(t, testBoundary,
		formPart{name: "PHPSESSID", value: "abc"},
		formPart{name: "PHP_SESSION_UPLOAD_PROGRESS", value: "1"},
		longNames[0], longNames[1], longNames[2],
	)

	cases := []struct {
		name            string
		contentType     string
		contentEncoding string
		body            []byte
		cfg             *Config
		wantBlock       bool
		wantReason      string
	}{
		{
			name:        "minimal 258-byte session progress file trigger",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        []byte(minimalBody),
			wantBlock:   true,
			wantReason:  "php session field",
		},
		{
			name:        "149 t[] spray with upload progress",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        sprayBody(t, 149),
			wantBlock:   true,
			wantReason:  "upload progress",
		},
		{
			name:        "nested arrays with empty filenames",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: buildMultipart(t, testBoundary,
				formPart{name: "PHP_SESSION_UPLOAD_PROGRESS", value: "1"},
				formPart{name: "files[a][b][c]", filename: new("")},
				formPart{name: "files[0][1][2]", filename: new("")},
				formPart{name: "files[x][y][z]", filename: new("")},
				formPart{name: "files[][][]", filename: new("")},
			),
			wantBlock:  true,
			wantReason: "upload progress",
		},
		{
			name:        "benign single file upload",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: buildMultipart(t, testBoundary,
				formPart{name: "photo", filename: new("photo.jpg"), value: "jpeg-bytes"},
			),
		},
		{
			name:        "benign ten file upload",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        tenFileBody(t),
		},
		{
			name:        "malformed body without signal",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        []byte("--" + testBoundary + "\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\npartial"),
		},
		{
			name:        "malformed body with signal before failure",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: []byte("--" + testBoundary + "\r\nContent-Disposition: form-data; name=\"PHPSESSID\"\r\n\r\nx\r\n" +
				"--" + testBoundary + "\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n\r\nx"),
			wantBlock:  true,
			wantReason: "php session field",
		},
		{
			name:        "url encoded session progress is inspected",
			contentType: "application/x-www-form-urlencoded",
			body:        []byte("PHPSESSID=abc&PHP_SESSION_UPLOAD_PROGRESS=1&f=@shell.php"),
			wantBlock:   true,
			wantReason:  "URL-encoded",
		},
		{
			name:        "benign url encoded body is not blocked",
			contentType: "application/x-www-form-urlencoded",
			body:        []byte("q=hello&page=2&filter=active"),
		},
		{
			name:        "upload progress alone does not block by default",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        buildMultipart(t, testBoundary, formPart{name: "PHP_SESSION_UPLOAD_PROGRESS", value: "1"}),
		},
		{
			name:        "upload progress alone blocks when forced",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        buildMultipart(t, testBoundary, formPart{name: "PHP_SESSION_UPLOAD_PROGRESS", value: "1"}),
			cfg:         &Config{Enabled: true, BlockUploadProgress: true},
			wantBlock:   true,
			wantReason:  "configuration",
		},
		{
			name:            "upload progress with non-identity content encoding",
			contentType:     "multipart/form-data; boundary=" + testBoundary,
			contentEncoding: "gzip",
			body:            buildMultipart(t, testBoundary, formPart{name: "PHP_SESSION_UPLOAD_PROGRESS", value: "1"}),
			wantBlock:       true,
			wantReason:      "upload progress",
		},
		{
			name:        "session field with depth two array",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: buildMultipart(t, testBoundary,
				formPart{name: "PHPSESSID", value: "abc"},
				formPart{name: "a[b][c]", value: "v"},
			),
			wantBlock:  true,
			wantReason: "php session field",
		},
		{
			name:        "session field with serialized marker",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: buildMultipart(t, testBoundary,
				formPart{name: "PHPSESSID", value: "abc"},
				formPart{name: "data", value: `|a:1:{s:3:"cmd";s:2:"id";}`},
			),
			wantBlock:  true,
			wantReason: "php session field",
		},
		{
			name:        "session field alone does not block",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        buildMultipart(t, testBoundary, formPart{name: "PHPSESSID", value: "abc"}),
		},
		{
			name:        "depth six without upload progress",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        buildMultipart(t, testBoundary, formPart{name: "a[b][c][d][e][f][g]", value: "v"}),
			wantBlock:   true,
			wantReason:  "multipart array depth",
		},
		{
			name:        "32 empty filenames without upload progress",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        emptyFilenameBody(t, 32),
			wantBlock:   true,
			wantReason:  "empty filenames",
		},
		{
			name:        "256 parts without upload progress",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        manyFieldsBody(t, 256),
			wantBlock:   true,
			wantReason:  "part count",
		},
		{
			name:        "custom session field name",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: buildMultipart(t, testBoundary,
				formPart{name: "CUSTOMSESS", value: "abc"},
				formPart{name: "f", filename: new("x.php")},
			),
			cfg:        &Config{Enabled: true, SessionFieldNames: []string{"customsess"}},
			wantBlock:  true,
			wantReason: "php session field",
		},
		{
			name:        "tolerant comma separated content type",
			contentType: "Multipart/Form-Data, boundary=" + testBoundary,
			body:        []byte(minimalBody),
			wantBlock:   true,
			wantReason:  "php session field",
		},
		{
			name:        "tolerant quoted boundary with trailing semicolon",
			contentType: "multipart/form-data; boundary=\"" + testBoundary + "\";",
			body:        []byte(minimalBody),
			wantBlock:   true,
			wantReason:  "php session field",
		},
		{
			name:        "tolerant space separated content type",
			contentType: "multipart/form-data boundary=" + testBoundary,
			body:        []byte(minimalBody),
			wantBlock:   true,
			wantReason:  "php session field",
		},
		{
			name:        "raw fallback ignores quoted boundary decoy",
			contentType: "multipart/form-data; note=\"boundary=evil\"; boundary=" + testBoundary + "; broken",
			body:        []byte(minimalBody),
			wantBlock:   true,
			wantReason:  "php session field",
		},
		{
			name:        "part cap bounds parsing",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        tenFileBody(t),
			cfg:         &Config{Enabled: true, MaxParts: 4},
		},
		{
			name:        "session field with php marker in field value",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body: buildMultipart(t, testBoundary,
				formPart{name: "PHPSESSID", value: "abc"},
				formPart{name: "code", value: `<?php echo "pwn"; ?>`},
			),
			wantBlock:  true,
			wantReason: "php session field",
		},
		{
			name:        "payload is clipped for oversized field names",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        longNameBody,
			wantBlock:   true,
			wantReason:  "php session field",
		},
		{
			name:        "disabled detector ignores trigger",
			contentType: "multipart/form-data; boundary=" + testBoundary,
			body:        []byte(minimalBody),
			cfg:         &Config{Enabled: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Enabled: true}
			if tc.cfg != nil {
				cfg = *tc.cfg
			}
			ctx := newRequestContext(t, tc.contentType, tc.contentEncoding, tc.body)
			headerBefore := ctx.Request.Header.Clone()
			bodyBefore := append([]byte(nil), ctx.DecodedBody...)

			result, err := New(cfg).Detect(context.Background(), ctx)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if !reflect.DeepEqual(headerBefore, ctx.Request.Header) {
				t.Fatal("detector mutated request headers")
			}
			if !bytes.Equal(bodyBefore, ctx.DecodedBody) {
				t.Fatal("detector mutated decoded body")
			}

			if !tc.wantBlock {
				if result != nil {
					t.Fatalf("Detect() = %+v, want no detection", result)
				}
				return
			}
			if result == nil {
				t.Fatal("Detect() = nil, want block result")
			}
			if !result.Detected {
				t.Fatal("Detected = false")
			}
			if result.DetectorID != "rce.php2shell" {
				t.Fatalf("DetectorID = %q", result.DetectorID)
			}
			if result.Category != "rce" {
				t.Fatalf("Category = %q", result.Category)
			}
			if result.Severity != engine.SeverityCritical {
				t.Fatalf("Severity = %v", result.Severity)
			}
			if result.Action != engine.ActionBlock {
				t.Fatalf("Action = %v", result.Action)
			}
			if result.Confidence != 0.97 {
				t.Fatalf("Confidence = %v", result.Confidence)
			}
			if !strings.Contains(result.Message, tc.wantReason) {
				t.Fatalf("Message = %q, want reason %q", result.Message, tc.wantReason)
			}
			if len(result.Payload) > 512 {
				t.Fatalf("Payload length = %d, want <= 512", len(result.Payload))
			}
		})
	}
}

func TestMalformedMultipartDoesNotPanic(t *testing.T) {
	bodies := [][]byte{
		[]byte("--" + testBoundary),
		[]byte("--" + testBoundary + "\r\n"),
		[]byte("--" + testBoundary + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n"),
		[]byte("--" + testBoundary + "\r\nContent-Disposition: form-data; name=\"a\"; filename=\"\r\n\r\n"),
		[]byte("not multipart at all"),
	}
	for i, body := range bodies {
		ctx := newRequestContext(t, "multipart/form-data; boundary="+testBoundary, "", body)
		if _, err := New(Config{Enabled: true}).Detect(context.Background(), ctx); err != nil {
			t.Fatalf("case %d: Detect() error = %v", i, err)
		}
	}
}

func TestBracketDepth(t *testing.T) {
	cases := map[string]int{
		"field":           0,
		"t[]":             1,
		"files[a]":        1,
		"files[a][b][c]":  3,
		"files[][][]":     3,
		"weird[[nested]]": 2,
		"no closing [":    1,
		"close only ]":    0,
	}
	for name, want := range cases {
		if got := bracketDepth(name); got != want {
			t.Errorf("bracketDepth(%q) = %d, want %d", name, got, want)
		}
	}
}

func newRequestContext(t *testing.T, contentType, contentEncoding string, body []byte) *engine.RequestContext {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/upload.php", bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	return &engine.RequestContext{Request: req, DecodedBody: body}
}

type formPart struct {
	name     string
	value    string
	filename *string
}

func buildMultipart(t *testing.T, boundary string, parts ...formPart) []byte {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary(boundary); err != nil {
		t.Fatalf("SetBoundary(%q) error = %v", boundary, err)
	}
	for _, part := range parts {
		if part.filename != nil {
			dst, err := writer.CreateFormFile(part.name, *part.filename)
			if err != nil {
				t.Fatalf("CreateFormFile(%q) error = %v", part.name, err)
			}
			if _, err := dst.Write([]byte(part.value)); err != nil {
				t.Fatalf("write file part error = %v", err)
			}
			continue
		}
		if err := writer.WriteField(part.name, part.value); err != nil {
			t.Fatalf("WriteField(%q) error = %v", part.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("multipart Close() error = %v", err)
	}
	return body.Bytes()
}

func sprayBody(t *testing.T, count int) []byte {
	t.Helper()
	parts := make([]formPart, 0, count+1)
	for range count {
		parts = append(parts, formPart{name: "t[]", value: "x"})
	}
	parts = append(parts, formPart{name: "PHP_SESSION_UPLOAD_PROGRESS", value: "1"})
	return buildMultipart(t, testBoundary, parts...)
}

func tenFileBody(t *testing.T) []byte {
	t.Helper()
	parts := make([]formPart, 0, 10)
	for i := range 10 {
		parts = append(parts, formPart{name: "file" + string(rune('0'+i)), filename: new("photo.jpg"), value: "jpeg-bytes"})
	}
	return buildMultipart(t, testBoundary, parts...)
}

func emptyFilenameBody(t *testing.T, count int) []byte {
	t.Helper()
	parts := make([]formPart, 0, count)
	for i := range count {
		parts = append(parts, formPart{name: "files[" + string(rune('a'+i%26)) + "]", filename: new("")})
	}
	return buildMultipart(t, testBoundary, parts...)
}

func manyFieldsBody(t *testing.T, count int) []byte {
	t.Helper()
	parts := make([]formPart, 0, count)
	for i := range count {
		parts = append(parts, formPart{name: "field" + string(rune('a'+i%26)), value: "v"})
	}
	return buildMultipart(t, testBoundary, parts...)
}

func TestEmergencyBlockAllMultipart(t *testing.T) {
	body := buildMultipart(t, testBoundary, formPart{name: "file", value: "hello"})
	ctx := newRequestContext(t, "multipart/form-data; boundary="+testBoundary, "", body)
	result, err := New(Config{Enabled: true, BlockAllMultipart: true}).Detect(context.Background(), ctx)
	if err != nil || result == nil || !result.Detected {
		t.Fatalf("emergency block result=%+v err=%v", result, err)
	}
}

func TestEmergencyAllowPathStillBlocksHardSignal(t *testing.T) {
	cfg := Config{Enabled: true, BlockAllMultipart: true, AllowPaths: []string{"/upload"}}
	benign := buildMultipart(t, testBoundary, formPart{name: "file", value: "hello"})
	ctx := newRequestContext(t, "multipart/form-data; boundary="+testBoundary, "", benign)
	ctx.Request.URL.Path = "/upload/image"
	ctx.NormalizedPath = "/upload/image"
	if result, err := New(cfg).Detect(context.Background(), ctx); err != nil || result != nil {
		t.Fatalf("allowlisted benign upload result=%+v err=%v", result, err)
	}

	trigger := newRequestContext(t, "multipart/form-data; boundary="+testBoundary, "", []byte(minimalBody))
	trigger.Request.URL.Path = "/upload/image"
	trigger.NormalizedPath = "/upload/image"
	result, err := New(cfg).Detect(context.Background(), trigger)
	if err != nil || result == nil || !result.Detected {
		t.Fatalf("allowlisted hard signal result=%+v err=%v", result, err)
	}
}
