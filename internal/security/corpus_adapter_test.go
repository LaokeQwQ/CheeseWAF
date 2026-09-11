package security

import (
	"net/http"
	"strings"
	"testing"
)

func TestAdaptRawHTTPCaseMapsURLDataToTargetBody(t *testing.T) {
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "POST",
		URL:    "/api/report",
		Data:   "id=1%20union%20select%201",
		Label:  "sqli",
		Source: "HttpParamsDataset/payload_full.csv",
	}, "case-1", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Target != "/api/report" {
		t.Errorf("Target = %q, want /api/report", tc.Target)
	}
	if tc.Body != "id=1%20union%20select%201" {
		t.Errorf("Body = %q, want the data field verbatim", tc.Body)
	}
	if tc.Method != "POST" {
		t.Errorf("Method = %q, want POST", tc.Method)
	}
	if tc.Category != "sqli" {
		t.Errorf("Category = %q, want sqli", tc.Category)
	}
	if tc.Label != "attack" {
		t.Errorf("Label = %q, want attack", tc.Label)
	}
	if tc.SourceFamily != "HttpParamsDataset/payload_full.csv" {
		t.Errorf("SourceFamily = %q, want the raw source field", tc.SourceFamily)
	}
}

func TestAdaptRawHTTPCaseBenignIgnoresRecordLabel(t *testing.T) {
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "GET",
		URL:    "/blog/technology/ai-innovations-in-2024",
		Label:  "benign",
	}, "case-1", "benign")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Label != "benign" {
		t.Errorf("Label = %q, want benign", tc.Label)
	}
	// A benign record must not carry a category: the engine is not asked which
	// attack class it wrongly picked, only whether it fired at all.
	if tc.Category != "" {
		t.Errorf("Category = %q, want empty for benign", tc.Category)
	}
}

func TestAdaptRawHTTPCaseFallsBackToRecordLabel(t *testing.T) {
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "GET",
		URL:    "/?q=1",
		Label:  "benign",
	}, "case-1", "")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Label != "benign" {
		t.Errorf("Label = %q, want benign from the record label", tc.Label)
	}
}

func TestAdaptRawHTTPCaseRejectsUnknownGroundTruth(t *testing.T) {
	if _, err := AdaptRawHTTPCase(RawHTTPCase{Method: "GET", URL: "/"}, "c", "maybe"); err == nil {
		t.Fatal("expected an error for an unrecognised ground truth")
	}
}

func TestNormalizeCategoryMapsSourceLabels(t *testing.T) {
	tests := map[string]string{
		"sqli":           "sqli",
		"SQL":            "sqli",
		"sql_injection":  "sqli",
		"xss":            "xss",
		"rce":            "rce",
		"cmdi":           "rce",
		"path":           "lfi",
		"path-traversal": "lfi",
		"lfi":            "lfi",
		"ssrf":           "ssrf",
		"nosqli":         "nosqli",
		"ssti":           "ssti",
		"xxe":            "xxe",
		"log4shell":      "log4shell",
		"jndi":           "log4shell",
		// Unmodelled classes group together but stay inside the attack count.
		"smuggling":       CategoryGeneric,
		"protocol":        CategoryGeneric,
		"ldap":            CategoryGeneric,
		"deserialization": CategoryGeneric,
		"other":           CategoryGeneric,
		"":                CategoryGeneric,
		"totally-unknown": CategoryGeneric,
	}
	for label, want := range tests {
		if got := NormalizeCategory(label); got != want {
			t.Errorf("NormalizeCategory(%q) = %q, want %q", label, got, want)
		}
	}
}

func TestNormalizeCategoryOnlyEmitsKnownBuckets(t *testing.T) {
	known := map[string]bool{CategoryGeneric: true}
	for _, c := range DetectionCategories {
		known[c] = true
	}
	for _, label := range []string{"sqli", "xss", "path", "other", "smuggling", "weird-thing", "NOSQL"} {
		if got := NormalizeCategory(label); !known[got] {
			t.Errorf("NormalizeCategory(%q) = %q, which is not a known bucket", label, got)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := map[string]string{
		"":                                  "/",
		"/":                                 "/",
		"/param?val=1":                      "/param?val=1",
		"https://example.com/x?y=1":         "https://example.com/x?y=1",
		"uNiOn/**/SeLeCt/**/1,2,3--%0a":     "/uNiOn/**/SeLeCt/**/1,2,3--%0a",
		"%3Cscript%3Ealert(1)%3C/script%3E": "/%3Cscript%3Ealert(1)%3C/script%3E",
	}
	for in, want := range tests {
		if got := NormalizeTarget(in); got != want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAdaptRawHTTPCaseMovesCRLFTargetToBody(t *testing.T) {
	// A smuggling payload in the request line cannot be expressed as a URL.
	// It used to be rejected — and rejecting attack samples is precisely how a
	// corpus ends up looking cleaner than it is. It is now measured via the body.
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "POST",
		URL:    "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n",
		Data:   "separate data must not replace the target payload",
		Label:  "smuggling",
	}, "smuggling", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Body != "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Errorf("Body = %q, want the CRLF payload preserved byte for byte", tc.Body)
	}
	if tc.Rationale != RationaleRepairedToBody {
		t.Errorf("Rationale = %q, want the to-body repair marker", tc.Rationale)
	}
}

func TestParseHeaderBlock(t *testing.T) {
	headers := ParseHeaderBlock("Host: example.com\r\nContent-Length: 60\r\nTransfer-Encoding: chunked\r\n")
	if headers["Host"] != "example.com" {
		t.Errorf("Host = %q, want example.com", headers["Host"])
	}
	if headers["Content-Length"] != "60" {
		t.Errorf("Content-Length = %q, want 60", headers["Content-Length"])
	}
	if headers["Transfer-Encoding"] != "chunked" {
		t.Errorf("Transfer-Encoding = %q, want chunked", headers["Transfer-Encoding"])
	}
}

func TestParseHeaderBlockKeepsColonsInValues(t *testing.T) {
	headers := ParseHeaderBlock("Referer: https://example.com/a:b\nX-Empty: \n")
	if headers["Referer"] != "https://example.com/a:b" {
		t.Errorf("Referer = %q, want the value after the first colon only", headers["Referer"])
	}
	if v, ok := headers["X-Empty"]; !ok || v != "" {
		t.Errorf("X-Empty = %q (present=%v), want an empty but present value", v, ok)
	}
}

func TestParseHeaderBlockPreservesCaseInsensitiveDuplicates(t *testing.T) {
	headers := ParseHeaderBlock("X-Test: one\nx-test: two\n")
	if got := headers["X-Test"]; got != "one, two" {
		t.Fatalf("X-Test = %q, want both values joined deterministically", got)
	}
}

func TestHasDuplicateJSONKeys(t *testing.T) {
	if duplicate, err := hasDuplicateJSONKeys([]byte(`{"header":{"X-Test":"one","X-Test":"two"}}`)); err != nil || !duplicate {
		t.Fatalf("duplicate JSON key not detected: duplicate=%v err=%v", duplicate, err)
	}
	if duplicate, err := hasDuplicateJSONKeys([]byte(`{"header":{"X-Test":"one","x-test":"two"}}`)); err != nil || !duplicate {
		t.Fatalf("case-insensitive header JSON key not detected: duplicate=%v err=%v", duplicate, err)
	}
	if duplicate, err := hasDuplicateJSONKeys([]byte(`{"header":{"X-Test":"one","x-test":"two"},"body":{"X-Test":"one","x-test":"two"}}`)); err != nil || !duplicate {
		t.Fatalf("case-insensitive duplicate JSON keys should be detected: duplicate=%v err=%v", duplicate, err)
	}
}

func TestParseHeaderBlockSkipsMalformedLines(t *testing.T) {
	if headers := ParseHeaderBlock("not-a-header\n\n   \nAccept: */*\n"); headers["Accept"] != "*/*" {
		t.Errorf("headers = %v, want only the well-formed Accept line", headers)
	}
	if headers := ParseHeaderBlock(""); headers != nil {
		t.Errorf("headers = %v, want nil for an empty block", headers)
	}
	// A header name with a space cannot be encoded; it must not poison the map.
	if headers := ParseHeaderBlock("Bad Name: x\nAccept: */*\n"); headers["Accept"] != "*/*" || len(headers) != 1 {
		t.Errorf("headers = %v, want the invalid name dropped and Accept kept", headers)
	}
}

func TestForEachRawHTTPJSONLAdaptsAndShards(t *testing.T) {
	raw := strings.Join([]string{
		`{"method":"GET","url":"/a?id=1","data":"","label":"sqli","source":"unit/a"}`,
		`{"method":"POST","url":"/b","data":"x=1","headers":"Host: h\nContent-Type: application/x-www-form-urlencoded","label":"xss","source":"unit/b"}`,
		`{"method":"GET","url":"/c","data":"","label":"benign","source":"unit/c"}`,
	}, "\n")

	var all []Case
	stats, err := ForEachRawHTTPJSONL(strings.NewReader(raw), 1, 0, "attack", func(tc Case) error {
		all = append(all, tc)
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachRawHTTPJSONL: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("got %d cases, want 3", len(all))
	}
	if stats.TotalCases != 3 || stats.SelectedCases != 3 {
		t.Errorf("stats = %+v, want 3/3", stats)
	}
	if stats.SkippedUnadaptable != 0 {
		t.Errorf("SkippedUnadaptable = %d, want 0", stats.SkippedUnadaptable)
	}
	if all[1].Header["Content-Type"] != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want the parsed header block", all[1].Header["Content-Type"])
	}

	// Sharding must be disjoint and must cover every case.
	seen := map[string]int{}
	for shard := 0; shard < 3; shard++ {
		count := 0
		if _, err := ForEachRawHTTPJSONL(strings.NewReader(raw), 3, shard, "attack", func(tc Case) error {
			seen[tc.Name]++
			count++
			return nil
		}); err != nil {
			t.Fatalf("shard %d: %v", shard, err)
		}
	}
	if len(seen) != 3 {
		t.Errorf("shards covered %d distinct cases, want 3: %v", len(seen), seen)
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("case %s appeared in %d shards, want exactly 1", name, n)
		}
	}
}

func TestAdaptRawHTTPCaseRepairsSplitPayloadRows(t *testing.T) {
	// The aetherguard corpus splits a payload at its first space and stores the
	// head in `method`. `data` keeps the intact payload, so the row is
	// recoverable rather than unusable.
	raw := RawHTTPCase{
		Method: "X-Rewrite-URL:",
		URL:    "/admin",
		Data:   "X-Rewrite-URL: /admin",
		Label:  "other",
		Source: "aetherguard/17_oauth_bypass.json",
	}
	tc, err := AdaptRawHTTPCase(raw, "row", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Body != "X-Rewrite-URL: /admin" {
		t.Errorf("Body = %q, want the intact data payload", tc.Body)
	}
	if tc.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST for a repaired row", tc.Method)
	}
	if tc.Target != "/" {
		t.Errorf("Target = %q, want / for a repaired row", tc.Target)
	}
	if tc.Rationale != RationaleRepairedSplitPayload {
		t.Errorf("Rationale = %q, want the repair marker so callers can count it", tc.Rationale)
	}
}

func TestAdaptRawHTTPCaseRepairFallsBackToMethodPlusURL(t *testing.T) {
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "<SVG",
		URL:    "onload=alert(1)>",
		Data:   "",
		Label:  "xss",
	}, "row", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	// No intact payload available: rejoin the fragments rather than lose it.
	if tc.Body != "<SVG onload=alert(1)>" {
		t.Errorf("Body = %q, want the rejoined fragments", tc.Body)
	}
	if tc.Rationale != RationaleRepairedSplitPayload {
		t.Errorf("Rationale = %q, want the repair marker", tc.Rationale)
	}
}

func TestAdaptRawHTTPCaseLeavesRealMethodsAlone(t *testing.T) {
	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		tc, err := AdaptRawHTTPCase(RawHTTPCase{Method: method, URL: "/x", Data: "d"}, "row", "attack")
		if err != nil {
			t.Fatalf("AdaptRawHTTPCase(%s): %v", method, err)
		}
		if tc.Method != method {
			t.Errorf("Method = %q, want %q untouched", tc.Method, method)
		}
		if tc.Rationale != "" {
			t.Errorf("Rationale = %q, want empty for a well-formed row", tc.Rationale)
		}
	}
}

func TestAdaptRawHTTPCaseMovesUnroutableTargetToBody(t *testing.T) {
	// "javascript://%0d%0aalert(1)" is a CRLF-injection payload whose "host"
	// Go refuses to parse. The body accepts arbitrary bytes, so the payload is
	// measured there rather than dropped.
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "GET",
		URL:    "javascript://%0d%0aalert(1)",
		Label:  "xss",
	}, "row", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Body != "javascript://%0d%0aalert(1)" {
		t.Errorf("Body = %q, want the payload verbatim", tc.Body)
	}
	if tc.Target != "/" {
		t.Errorf("Target = %q, want / for a repaired row", tc.Target)
	}
	if tc.Rationale != RationaleRepairedToBody {
		t.Errorf("Rationale = %q, want the to-body repair marker", tc.Rationale)
	}
}

func TestAdaptRawHTTPCaseMovesBarePercentTargetToBody(t *testing.T) {
	// "%&(" is not a valid percent escape, so url.Parse rejects the whole line.
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "GET",
		URL:    `/param?val=<body onload!#$%&()=alert("xss")>`,
		Label:  "xss",
	}, "row", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Body != `/param?val=<body onload!#$%&()=alert("xss")>` {
		t.Errorf("Body = %q, want the payload verbatim", tc.Body)
	}
	if tc.Rationale != RationaleRepairedToBody {
		t.Errorf("Rationale = %q, want the to-body repair marker", tc.Rationale)
	}
}

func TestAdaptRawHTTPCaseLeavesParseableTargetsInPlace(t *testing.T) {
	// Bare payloads with no leading slash are still routed through the URL:
	// NormalizeTarget makes them a path, which is where they belong.
	tc, err := AdaptRawHTTPCase(RawHTTPCase{
		Method: "GET",
		URL:    "uNiOn/**/SeLeCt/**/1,2,3--%0a",
		Label:  "sqli",
	}, "row", "attack")
	if err != nil {
		t.Fatalf("AdaptRawHTTPCase: %v", err)
	}
	if tc.Target != "/uNiOn/**/SeLeCt/**/1,2,3--%0a" {
		t.Errorf("Target = %q, want the slash-prefixed payload", tc.Target)
	}
	if tc.Rationale != "" {
		t.Errorf("Rationale = %q, want empty for a row that needed no repair", tc.Rationale)
	}
}

func TestIsHTTPMethod(t *testing.T) {
	valid := []string{"GET", "POST", "PROPFIND", "M-SEARCH", "X-Banana"}
	invalid := []string{"", "X-Rewrite-URL:", "<SVG", "$(ls", "{\"query\":", "_.merge({},", "Bad Name"}
	for _, m := range valid {
		if !IsHTTPMethod(m) {
			t.Errorf("IsHTTPMethod(%q) = false, want true", m)
		}
	}
	for _, m := range invalid {
		if IsHTTPMethod(m) {
			t.Errorf("IsHTTPMethod(%q) = true, want false", m)
		}
	}
}

func TestForEachRawHTTPJSONLCountsUnadaptableRecords(t *testing.T) {
	// With an empty defaultTruth the record's own label supplies the ground
	// truth, so a label that is neither "attack" nor "benign" is genuinely
	// unusable — the one class of row no repair can rescue. Unparseable targets
	// and payload-fragment methods are repaired, not dropped.
	raw := strings.Join([]string{
		`{"method":"GET","url":"/ok","data":"","label":"benign","source":"unit/a"}`,
		`{"method":"GET","url":"/unusable","data":"","label":"sort-of-attack","source":"unit/b"}`,
		`{"method":"GET","url":"/also-ok","data":"","label":"attack","source":"unit/c"}`,
	}, "\n")

	got := 0
	stats, err := ForEachRawHTTPJSONL(strings.NewReader(raw), 1, 0, "", func(Case) error {
		got++
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachRawHTTPJSONL: %v", err)
	}
	if got != 2 {
		t.Errorf("got %d adapted cases, want 2", got)
	}
	// The dropped record must be visible, not hidden.
	if stats.SkippedUnadaptable != 1 {
		t.Errorf("SkippedUnadaptable = %d, want 1", stats.SkippedUnadaptable)
	}
}
