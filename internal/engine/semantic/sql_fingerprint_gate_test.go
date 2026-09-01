package semantic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

func TestSQLNaturalLanguageFingerprintGate(t *testing.T) {
	prose := "I just found a good way to UNION results FROM two tough queries without performance issues."
	cases := []struct {
		name      string
		source    string
		field     string
		text      string
		wantGate  bool
		wantBlock bool
	}{
		{
			name:      "human message with weak union window",
			source:    "body.form",
			field:     "message",
			text:      prose,
			wantGate:  true,
			wantBlock: false,
		},
		{
			name:      "same value in opaque field remains visible",
			source:    "body.form",
			field:     "id",
			text:      prose,
			wantGate:  false,
			wantBlock: true,
		},
		{
			name:      "same value in header remains visible",
			source:    "header",
			field:     "X-Note",
			text:      prose,
			wantGate:  false,
			wantBlock: true,
		},
		{
			name:      "short union fragment is not prose",
			source:    "body.form",
			field:     "message",
			text:      "union results from two queries",
			wantGate:  false,
			wantBlock: true,
		},
		{
			name:      "quoted breakout in human field stays visible",
			source:    "body.form",
			field:     "message",
			text:      "I saw x' UNION results FROM users--",
			wantGate:  false,
			wantBlock: true,
		},
		{
			name:      "strong union select structure stays visible",
			source:    "body.form",
			field:     "message",
			text:      "I used UNION SELECT password FROM users.",
			wantGate:  false,
			wantBlock: true,
		},
		{
			name:      "bare union select stays visible",
			source:    "query",
			field:     "q",
			text:      "UNION SELECT",
			wantGate:  false,
			wantBlock: true,
		},
		{
			name:      "comment fingerprint stays visible",
			source:    "query",
			field:     "q",
			text:      "SELECT/**/password",
			wantGate:  false,
			wantBlock: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: tc.source, Name: tc.field}, text: tc.text}
			fp, detected := engine.SQLLibinjectionFingerprint(tc.text)
			if tc.wantGate && (!detected || !containsReviewedSQLFingerprint(fp, tc.text)) {
				t.Fatalf("test value must exercise a reviewed fingerprint: fp=%q detected=%v", fp, detected)
			}
			if got := sqlNaturalLanguageFingerprintOnly(candidate, fp); got != tc.wantGate {
				t.Fatalf("gate=%v, want %v (fp=%q)", got, tc.wantGate, fp)
			}
			_, gotBlock := analyzeSQL(candidate)
			if gotBlock != tc.wantBlock {
				t.Fatalf("blocked=%v, want %v (fp=%q)", gotBlock, tc.wantBlock, fp)
			}
		})
	}

	// The helper is intentionally fingerprint-specific: a mixed window must not
	// be downgraded merely because the surrounding field reads like prose.
	candidate := semanticCandidate{
		input: InputPoint{Source: "body.form", Name: "message"},
		text:  prose,
	}
	if got := sqlNaturalLanguageFingerprintOnly(candidate, "Uwk kc"); got {
		t.Fatal("mixed fingerprint windows must remain visible")
	}
}

func TestSQLQuotedAndSelectSubqueryGate(t *testing.T) {
	attacks := []struct {
		name, field, text string
	}{
		{"scalar comparison", "password", "letmein' AnD (SeLeCt UsEr())='admin'"},
		{"aggregate from where", "profileDesc", "Admin panel access' AnD SeLeCt 1 FrOm users WhErE 'a'='a"},
		{"comment truncation", "query", "12' AND (SELECT count(*) FROM users) > 0 --"},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body.json", Name: tc.field}, text: tc.text}
			if !sqlQuotedAndSelectInjectionShape(tc.text) {
				t.Fatal("strong quoted AND SELECT shape was not recognized")
			}
			_, detected := analyzeSQL(candidate)
			if !detected {
				t.Fatalf("expected SQL detection for %q", tc.text)
			}
		})
	}

	benign := []struct {
		name, text string
	}{
		{"markdown example", strings.Repeat("This documentation explains safe query syntax. ", 4) + "```sql\nname=' AND (SELECT user() FROM users) > 0 --\n```\nThis is documentation only."},
		{"security prose", strings.Repeat("A security guide documents query examples for defenders. ", 4) + "The guide may show `id=' AND (SELECT 1 FROM users WHERE id=1)--` as an example without executing it."},
	}
	for _, tc := range benign {
		t.Run(tc.name, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body.json", Name: "text"}, text: tc.text}
			if !sqlQuotedAndSelectInjectionShape(tc.text) {
				t.Fatal("negative fixture must exercise the narrow shape")
			}
			_, detected := analyzeSQL(candidate)
			if detected {
				t.Fatalf("documentation fixture was detected as SQL injection: %q", tc.text)
			}
		})
	}

	for _, text := range []string{
		"select an option from the list",
		"the guide says ' and select a value from the menu",
		"ordinary SELECT users FROM the directory",
		"Please click ' and select (a menu) > options",
		"Use the quote ' and select (the item) -- then continue",
		"Please use ' and select menu(item) > options",
	} {
		if sqlQuotedAndSelectInjectionShape(text) {
			t.Fatalf("weak prose shape matched: %q", text)
		}
	}
}

func TestSQLDetectorQuotedAndSelectSubquery(t *testing.T) {
	reqCtx := sqlTestRequestContext("/login", []byte("password=letmein%27+AnD+%28SeLeCt+UsEr%28%29%29%3D%27admin%27"))
	got, err := NewSQLDetector("block").Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Category != "sqli" {
		t.Fatalf("expected SQL detector hit, got %#v", got)
	}
}

func TestSQLDetectorAdditionalSubqueryAndSideEffectShapes(t *testing.T) {
	cases := []struct {
		name, target string
	}{
		{"quoted concatenation", `/search?q=1%27%7C%7C%28select%20%27gbyh%27%20from%20dual%20where%205889%3D5889%20order%20by%201%23`},
		{"Oracle pipe receive", `/search?q=1%29%3Bselect%20dbms_pipe.receive_message%28chr%2866%29%2C5%29%20from%20dual`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := sqlTestRequestContext(tc.target, nil)
			got, err := NewSQLDetector("block").Detect(context.Background(), reqCtx)
			if err != nil {
				t.Fatal(err)
			}
			if got == nil || !got.Detected || got.Category != "sqli" {
				t.Fatalf("expected SQL detector hit, got %#v", got)
			}
		})
	}
}

func TestAnalyzerBlocksQuotedAndSelectSubqueryInJSONField(t *testing.T) {
	body := `{"username":"adminUser","password":"letmein' AnD (SeLeCt UsEr())='admin'"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.test/api/session/start", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Category != "sqli" {
		t.Fatalf("expected analyzer SQLi hit for JSON scalar subquery, got %#v", got)
	}
}

func TestAnalyzerDoesNotTreatShortSecurityResearchBioAsDocument(t *testing.T) {
	body := `{"email":"user@example.com","bio":"Security researcher' AnD (SeLeCt CoUnT(*) FroM usErs) > 10 -- "}`
	req := httptest.NewRequest(http.MethodPut, "http://example.test/api/v2/user/updateProfile", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	reqCtx, err := engine.NewRequestContext(req, "default")
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewAnalyzer("block", 2).Detect(context.Background(), reqCtx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !got.Detected || got.Category != "sqli" {
		t.Fatalf("expected analyzer SQLi hit for short profile bio, got %#v", got)
	}
}

func TestSQLAdditionalSubqueryAndSideEffectShapes(t *testing.T) {
	attacks := []struct {
		name, text string
	}{
		{"quoted concatenation predicate", `1'||(select 'gbyh' from dual where 5889=5889 order by 1#`},
		{"Oracle pipe receive side effect", `1);select dbms_pipe.receive_message(chr(66),5) from dual`},
		{"Firebird metadata table", `select 'qqpjq'||(case 5118 when 5118 then 1 else 0 end)||'qzvzq' from rdb$database`},
	}
	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "query", Name: "val"}, text: tc.text}
			if _, ok := analyzeSQL(candidate); !ok {
				t.Fatalf("expected SQL detection for %q", tc.text)
			}
		})
	}

	for _, text := range []string{
		"Please ' and select 'a' from the menu where color=red",
		"The guide quotes '|| (SELECT 1 WHERE 1=1) as an example.",
	} {
		t.Run("benign/"+text, func(t *testing.T) {
			candidate := semanticCandidate{input: InputPoint{Source: "body.json", Name: "message"}, text: text}
			if sqlQuotedConcatSelectPredicate.MatchString(text) {
				t.Fatalf("quoted concatenation gate matched prose: %q", text)
			}
			if sqlQuotedAndSelectInjectionShape(text) {
				t.Fatalf("quoted AND SELECT gate matched prose: %q", text)
			}
			if _, ok := analyzeSQL(candidate); ok {
				t.Fatalf("prose was detected as SQL injection: %q", text)
			}
		})
	}
}
