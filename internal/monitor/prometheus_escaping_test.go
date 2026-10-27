package monitor

import (
	"strings"
	"testing"
	"time"
)

// TestRenderPrometheusEscapesLabelValues pins the text exposition format escape
// rules for label values: backslash, double quote, and line feed. A raw line
// feed would end the sample early (letting a value append samples of its own),
// and a trailing backslash would escape the closing quote.
func TestRenderPrometheusEscapesLabelValues(t *testing.T) {
	cases := []struct{ value, want string }{
		{`sqli`, `category="sqli"`},
		{"new\nline", `category="new\nline"`},
		{`b\`, `category="b\\"`},
		{`q"x`, `category="q\"x"`},
	}
	for _, tc := range cases {
		snapshot := Snapshot{
			GeneratedAt: time.Unix(1700000000, 0).UTC(),
			StatusCodes: map[int]int{},
			Categories:  map[string]int{tc.value: 1},
			DiskUsage:   map[string]int64{},
		}
		lines := strings.Split(strings.TrimSuffix(string(RenderPrometheus(snapshot)), "\n"), "\n")
		var sample string
		for _, line := range lines {
			if strings.HasPrefix(line, "cheesewaf_attack_category_total{") {
				if sample != "" {
					t.Fatalf("category %q produced more than one sample line", tc.value)
				}
				sample = line
			}
		}
		if !strings.Contains(sample, tc.want) {
			t.Fatalf("category %q rendered %q, want it to contain %q", tc.value, sample, tc.want)
		}
	}
}
