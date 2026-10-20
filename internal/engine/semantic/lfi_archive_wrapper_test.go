package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestLFIArchiveWrapperMemberQuery(t *testing.T) {
	for _, value := range []string{
		`zip://archive.zip#index.php`,
		`zip://archive.zip%23index.php`,
		`zip://archive.zip\index.php`,
		`phar://archive.phar#index.php`,
		`phar://archive.phar%23index.php`,
		`phar://archive.phar\index.php`,
		`zip://archive.zip/index.php`,
		`phar://archive.phar/index.php`,
	} {
		t.Run(value, func(t *testing.T) {
			if !lfiWrapperPathShape(value) {
				t.Error("archive member separator was not recognized")
			}
			req := httptest.NewRequest(http.MethodGet, "http://x/view?page="+url.QueryEscape(value), nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "lfi").Detect(context.Background(), reqCtx)
			if err != nil || result == nil || !result.Detected || result.Category != "lfi" {
				t.Errorf("archive member query was missed: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestLFIArchiveWrapperDocumentationBoundary(t *testing.T) {
	for _, value := range []string{
		`zip://archive.zip is documented with #member`,
		`phar://archive.phar is documented with %23member`,
		"zip://archive.zip\u00a0is documented with \\member",
		`phar://archive.phar"#member`,
		`file://archive.zip#member`,
		`file://archive.zip%23member`,
		`php://filter#member`,
		`php://filter%23member`,
	} {
		t.Run(value, func(t *testing.T) {
			if lfiWrapperPathShape(value) {
				t.Error("wrapper borrowed archive syntax or crossed a token boundary")
			}
			req := httptest.NewRequest(http.MethodGet, "http://x/docs?q="+url.QueryEscape(value), nil)
			reqCtx, err := engine.NewRequestContext(req, "default")
			if err != nil {
				t.Fatal(err)
			}
			result, err := NewAnalyzer("block", 5, "lfi").Detect(context.Background(), reqCtx)
			if err != nil || result != nil && result.Detected {
				t.Errorf("benign wrapper documentation was detected: result=%+v err=%v", result, err)
			}
		})
	}
}
