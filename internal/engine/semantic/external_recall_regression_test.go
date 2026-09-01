package semantic

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestExternalRecallClustersRemainCovered replays only the two high-confidence
// shapes fixed from the research quarantine. It is a regression test, not a
// quality gate: the surrounding corpus remains untrusted and is not promoted
// into a formal or blind denominator by this check.
func TestExternalRecallClustersRemainCovered(t *testing.T) {
	f, err := os.Open("testdata/ai_waf_attack_clean.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	type row struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	}
	var unicodeLFI, dataURLXSS int
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for scanner.Scan() {
		var sample row
		if err := json.Unmarshal(scanner.Bytes(), &sample); err != nil {
			t.Fatal(err)
		}
		method := sample.Method
		if method == "" {
			method = http.MethodGet
		}
		switch {
		case strings.Contains(sample.URL, "%u2216"):
			unicodeLFI++
			if got := detectOnTarget(t, NewAnalyzer("block", 2, "lfi"), method, sample.URL, "", ""); got == nil || !got.Detected || got.Category != "lfi" {
				t.Fatalf("Unicode LFI regression missed %q: %+v", sample.URL, got)
			}
		case strings.Contains(sample.URL, "target=data:text/html;base64,"):
			dataURLXSS++
			if got := detectOnTarget(t, NewAnalyzer("block", 2, "xss"), method, sample.URL, "", ""); got == nil || !got.Detected || got.Category != "xss" {
				t.Fatalf("data-URI XSS regression missed %q: %+v", sample.URL, got)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if unicodeLFI != 5 {
		t.Fatalf("expected 5 Unicode LFI quarantine rows, found %d", unicodeLFI)
	}
	if dataURLXSS != 36 {
		t.Fatalf("expected 36 valid data-URI XSS quarantine rows, found %d", dataURLXSS)
	}
}
