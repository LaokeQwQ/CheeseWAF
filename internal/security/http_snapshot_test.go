package security

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func snapshotBody(s string) ([]byte, string, int64) {
	b := []byte(s)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), int64(len(b))
}

func validSnapshot(t *testing.T) HTTPTransaction {
	t.Helper()
	body, digest, n := snapshotBody("id=7")
	empty, emptyDigest, emptyN := snapshotBody("")
	tx := HTTPTransaction{
		Version:             HTTPTransactionVersion,
		Request:             HTTPRequest{Method: "POST", Target: "/login", Protocol: "HTTP/1.1", Headers: []HTTPHeader{{Name: "Content-Type", Values: []string{"application/x-www-form-urlencoded"}}}, Body: body, BodySHA256: digest, BodyBytes: n},
		Response:            HTTPResponse{StatusCode: 200, Protocol: "HTTP/1.1", Body: empty, BodySHA256: emptyDigest, BodyBytes: emptyN},
		ExpectedOracleLabel: OracleLabel{Label: "benign", Category: "form", OracleType: "human-review", OracleVersion: "1", AssertionID: "assert-7"},
		Deployment:          "staging-eu", Provenance: "capture-sha256:abc", Source: "fixture", Site: "example.test", Session: "session-7", Timestamp: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC), Seed: "seed-7", Run: "run-7", Assertion: "assert-7",
	}
	h, err := CanonicalSHA256(tx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Hash = h
	return tx
}

func resealSnapshot(t *testing.T, tx *HTTPTransaction) {
	t.Helper()
	sealed, err := NewHTTPTransaction(*tx)
	if err != nil {
		t.Fatal(err)
	}
	*tx = sealed
}

func TestValidateHTTPTransactionAndProjection(t *testing.T) {
	tx := validSnapshot(t)
	if err := ValidateHTTPTransaction(tx); err != nil {
		t.Fatalf("valid transaction rejected: %v", err)
	}
	c, err := tx.ToCase()
	if err != nil {
		t.Fatal(err)
	}
	if c.Label != "benign" || c.Method != "POST" || c.Target != "/login" || c.Body != "id=7" {
		t.Fatalf("unexpected case projection: %+v", c)
	}
}

func TestHTTPTransactionProjectionNormalizesOracleLabels(t *testing.T) {
	tx := validSnapshot(t)
	tx.ExpectedOracleLabel.Label = "  BENIGN  "
	tx.ExpectedOracleLabel.Category = "  Form-Login  "
	resealSnapshot(t, &tx)
	if err := ValidateHTTPTransaction(tx); err != nil {
		t.Fatal(err)
	}
	c, err := tx.ToCase()
	if err != nil {
		t.Fatal(err)
	}
	if c.Label != "benign" || c.Category != "form-login" {
		t.Fatalf("oracle labels were not normalized: %+v", c)
	}
}

func TestHTTPTransactionRejectsOracleAndSensitiveData(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HTTPTransaction)
	}{
		{"missing oracle", func(tx *HTTPTransaction) { tx.ExpectedOracleLabel = OracleLabel{} }},
		{"waf derived label", func(tx *HTTPTransaction) { tx.ExpectedOracleLabel.Label = "waf_blocked" }},
		{"waf derived category", func(tx *HTTPTransaction) { tx.ExpectedOracleLabel.Category = "waf-score" }},
		{"detector derived oracle type", func(tx *HTTPTransaction) { tx.ExpectedOracleLabel.OracleType = "detector-result" }},
		{"decision in assertion id", func(tx *HTTPTransaction) {
			tx.ExpectedOracleLabel.AssertionID = "decision-7"
			tx.Assertion = "decision-7"
		}},
		{"sensitive header", func(tx *HTTPTransaction) {
			tx.Request.Headers = []HTTPHeader{{Name: "Authorization", Values: []string{"Bearer abc"}}}
		}},
		{"observed header name", func(tx *HTTPTransaction) {
			tx.Request.Headers = []HTTPHeader{{Name: "X-WAF-Decision", Values: []string{"blocked"}}}
		}},
		{"header name control", func(tx *HTTPTransaction) {
			tx.Request.Headers = []HTTPHeader{{Name: "X-Test\r\nInjected", Values: []string{"ok"}}}
		}},
		{"header value control", func(tx *HTTPTransaction) {
			tx.Request.Headers = []HTTPHeader{{Name: "X-Test", Values: []string{"ok\r\nInjected: yes"}}}
		}},
		{"email", func(tx *HTTPTransaction) { tx.Source = "analyst@example.com" }},
		{"ip", func(tx *HTTPTransaction) { tx.Site = "192.0.2.10" }},
		{"metadata control", func(tx *HTTPTransaction) { tx.Site = "site\nother" }},
		{"method control", func(tx *HTTPTransaction) { tx.Request.Method = "GET\r\n" }},
		{"invalid protocol", func(tx *HTTPTransaction) { tx.Request.Protocol = "not-http" }},
		{"userinfo", func(tx *HTTPTransaction) { tx.Request.Target = "https://user:pass@example.test/x" }},
		{"duplicate header", func(tx *HTTPTransaction) {
			tx.Request.Headers = append(tx.Request.Headers, HTTPHeader{Name: "content-type", Values: []string{"x"}})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := validSnapshot(t)
			tc.mutate(&tx)
			if err := ValidateHTTPTransaction(tx); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestHTTPTransactionRejectsBodyDigestSizeVersionAndHash(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*HTTPTransaction)
	}{
		{"body digest", func(tx *HTTPTransaction) { tx.Request.BodySHA256 = strings.Repeat("0", 64) }},
		{"body size", func(tx *HTTPTransaction) { tx.Request.BodyBytes++ }},
		{"body limit", func(tx *HTTPTransaction) {
			tx.Request.Body = make([]byte, MaxHTTPSnapshotBodyBytes+1)
			tx.Request.BodyBytes = int64(len(tx.Request.Body))
			h := sha256.Sum256(tx.Request.Body)
			tx.Request.BodySHA256 = hex.EncodeToString(h[:])
		}},
		{"version", func(tx *HTTPTransaction) { tx.Version = "http-transaction/v2" }},
		{"status code", func(tx *HTTPTransaction) { tx.Response.StatusCode = 600 }},
		{"hash", func(tx *HTTPTransaction) { tx.Hash = strings.Repeat("0", 64) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := validSnapshot(t)
			tc.mutate(&tx)
			if err := ValidateHTTPTransaction(tx); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestHTTPTransactionAllowsLargeNonSensitiveUTF8Body(t *testing.T) {
	body := strings.Repeat("payload=ok&", 500)
	tx := validSnapshot(t)
	tx.Request.Body, tx.Request.BodySHA256, tx.Request.BodyBytes = snapshotBody(body)
	resealSnapshot(t, &tx)
	if err := ValidateHTTPTransaction(tx); err != nil {
		t.Fatalf("body below 1 MiB should not use metadata field limit: %v", err)
	}
}

func TestHTTPTransactionRejectsQuotedSecrets(t *testing.T) {
	for _, body := range []string{
		`{"token":"s3cr3t"}`,
		`{'api-key':'s3cr3t'}`,
		`token = "s3cr3t"`,
	} {
		t.Run(body, func(t *testing.T) {
			tx := validSnapshot(t)
			tx.Request.Body = []byte(body)
			resealSnapshot(t, &tx)
			if err := ValidateHTTPTransaction(tx); err == nil {
				t.Fatal("quoted secret assignment unexpectedly accepted")
			}
		})
	}
}

func TestCanonicalSHA256DeterministicAndHeaderOrderIndependent(t *testing.T) {
	tx := validSnapshot(t)
	a, err := CanonicalSHA256(tx)
	if err != nil {
		t.Fatal(err)
	}
	tx.Request.Headers = []HTTPHeader{{Name: "X-Two", Values: []string{"b"}}, {Name: "X-One", Values: []string{"a"}}}
	tx.Request.Headers = append(tx.Request.Headers, HTTPHeader{Name: "Content-Type", Values: []string{"application/x-www-form-urlencoded"}})
	b, err := CanonicalSHA256(tx)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("changing headers should change canonical hash")
	}
	tx = validSnapshot(t)
	tx.Request.Headers = []HTTPHeader{{Name: "content-type", Values: []string{"application/x-www-form-urlencoded"}}}
	c, err := CanonicalSHA256(tx)
	if err != nil {
		t.Fatal(err)
	}
	if a != c {
		t.Fatalf("header case should not change canonical hash: %s != %s", a, c)
	}
	fpA, err := HTTPTransactionFingerprint(validSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	fpTx := validSnapshot(t)
	fpTx.Request.Headers = []HTTPHeader{{Name: "content-type", Values: []string{"application/x-www-form-urlencoded"}}}
	fpB, err := HTTPTransactionFingerprint(fpTx)
	if err != nil {
		t.Fatal(err)
	}
	if fpA != fpB {
		t.Logf("a=%+v b=%+v", validSnapshot(t).Request.Headers, fpTx.Request.Headers)
		t.Fatalf("fingerprint changed under header-name case normalization: %s != %s", fpA, fpB)
	}
}

func TestValidateHTTPTransactionSetGate(t *testing.T) {
	base := validSnapshot(t)
	other := base
	other.Deployment, other.Site, other.ExpectedOracleLabel.Label = "prod", "other.test", "attack"
	other.Request.Target = "/login?deployment=prod"
	other.Assertion = "assert-8"
	other.ExpectedOracleLabel.AssertionID = other.Assertion
	var err error
	other.Hash, err = CanonicalSHA256(other)
	if err != nil {
		t.Fatal(err)
	}
	third := base
	third.Deployment, third.ExpectedOracleLabel.Label, third.Assertion = "prod", "benign", "assert-9"
	third.Request.Target = "/login?deployment=prod&variant=benign"
	third.ExpectedOracleLabel.AssertionID = third.Assertion
	third.Hash, err = CanonicalSHA256(third)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHTTPTransactionSet([]HTTPTransaction{base, other, third}); err == nil {
		t.Fatal("expected deployment diversity gate to reject missing attack in staging")
	}
	fourth := base
	fourth.Deployment, fourth.ExpectedOracleLabel.Label, fourth.Assertion = "staging-eu", "attack", "assert-10"
	fourth.Request.Target = "/login?deployment=staging&variant=attack"
	fourth.ExpectedOracleLabel.AssertionID = fourth.Assertion
	fourth.Hash, err = CanonicalSHA256(fourth)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHTTPTransactionSet([]HTTPTransaction{base, other, third, fourth}); err != nil {
		t.Fatalf("valid diverse set rejected: %v", err)
	}
	if err := ValidateHTTPTransactionSet([]HTTPTransaction{base, base}); err == nil {
		t.Fatal("expected duplicate transaction rejection")
	}
	relabelled := base
	relabelled.Deployment, relabelled.Site, relabelled.Session = "other", "other.test", "other-session"
	relabelled.ExpectedOracleLabel.Label = "attack"
	relabelled.ExpectedOracleLabel.Category = "sqli"
	relabelled.Assertion, relabelled.ExpectedOracleLabel.AssertionID = "assert-relabeled", "assert-relabeled"
	resealSnapshot(t, &relabelled)
	baseFP, err := HTTPTransactionFingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	relabelledFP, err := HTTPTransactionFingerprint(relabelled)
	if err != nil {
		t.Fatal(err)
	}
	if baseFP != relabelledFP {
		t.Fatalf("request fingerprint changed after relabeling: %s != %s", baseFP, relabelledFP)
	}
	if err := ValidateHTTPTransactionSet([]HTTPTransaction{base, relabelled}); err == nil || !strings.Contains(err.Error(), "conflicting oracle labels") {
		t.Fatalf("relabeled duplicate was not rejected as a conflict: %v", err)
	}
	if err := ValidateHTTPTransactionSet(nil); err == nil {
		t.Fatal("expected empty set rejection")
	}
}

func TestNewHTTPTransactionComputesDigestsAndRejectsObservedEvidence(t *testing.T) {
	tx := validSnapshot(t)
	tx.Request.BodySHA256, tx.Request.BodyBytes, tx.Response.BodySHA256, tx.Response.BodyBytes, tx.Hash = "", 0, "", 0, ""
	sealed, err := NewHTTPTransaction(tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateHTTPTransaction(sealed); err != nil {
		t.Fatalf("sealed transaction rejected: %v", err)
	}
	tx = validSnapshot(t)
	tx.Provenance = "observed-waf-result"
	if err := ValidateHTTPTransaction(tx); err == nil {
		t.Fatal("observed WAF evidence should be rejected")
	}
	tx = validSnapshot(t)
	tx.Source = "repaired-capture"
	if err := ValidateHTTPTransaction(tx); err == nil {
		t.Fatal("repaired evidence should be rejected")
	}
}
