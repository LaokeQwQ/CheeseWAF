package response

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestPHP2ShellOversizedSessionCookie(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": {"PHPSESSID=" + strings.Repeat("a%41", 128) + "; Path=/; HttpOnly"},
		},
		Body: io.NopCloser(strings.NewReader("ok")),
	}
	finding, err := inspector.InspectHTTPForRequest(resp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if finding == nil || finding.DetectorID != "response.php2shell" {
		t.Fatalf("expected php2shell finding, got %+v", finding)
	}
}

func TestPHP2ShellNormalSessionCookiePasses(t *testing.T) {
	inspector, err := New(config.ResponseInspectionConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		Header: http.Header{
			"Set-Cookie": {"PHPSESSID=o7hdboj52ksh6ggf8g6c8uyd8m; Path=/; HttpOnly"},
		},
		Body: io.NopCloser(strings.NewReader("ok")),
	}
	finding, err := inspector.InspectHTTPForRequest(resp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if finding != nil {
		t.Fatalf("normal cookie must not match: %+v", finding)
	}
}
