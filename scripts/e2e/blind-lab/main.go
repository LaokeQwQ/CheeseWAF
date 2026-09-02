// Command blind-lab generates a small, fully local blind-evaluation snapshot.
// It intentionally never inspects a WAF decision: labels come only from the
// fixed scenario oracle declared below.
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	security "github.com/LaokeQwQ/CheeseWAF/internal/security"
)

const (
	schemaVersion       = "blind-lab/v1"
	generatorVersion    = "1.0.0"
	maxBodyBytes        = 4096
	maxHeaderCount      = 16
	maxHeaderValueBytes = 256
	maxRecords          = 32
)

type Scenario struct {
	ID       string            `json:"scenario_id"`
	Group    string            `json:"group"`
	Class    string            `json:"class"`
	Category string            `json:"category,omitempty"`
	Method   string            `json:"method"`
	Target   string            `json:"target"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body,omitempty"`
	Oracle   Oracle            `json:"oracle"`
}

type Oracle struct {
	Label      string   `json:"label"`
	Assertions []string `json:"assertions"`
}

type snapshotRecord struct {
	security.HTTPTransaction
	Group string `json:"group"`
}

type Deployment struct {
	ID    string `json:"deployment_id"`
	Seed  string `json:"seed"`
	RunID string `json:"run_id"`
}

type Provenance struct {
	Generator string `json:"generator"`
	Source    string `json:"source"`
}

type Redaction struct {
	Policy              string `json:"policy"`
	Applied             bool   `json:"applied"`
	MaxBodyBytes        int    `json:"max_body_bytes"`
	MaxHeaderCount      int    `json:"max_header_count"`
	MaxHeaderValueBytes int    `json:"max_header_value_bytes"`
}

type Manifest struct {
	SchemaVersion    string          `json:"schema_version"`
	GeneratorVersion string          `json:"generator_version"`
	GeneratedAt      string          `json:"timestamp"`
	RunID            string          `json:"run_id"`
	SnapshotFile     string          `json:"snapshot_file"`
	EvaluationFile   string          `json:"evaluation_file"`
	CasesFile        string          `json:"cases_file"`
	GroupingFile     string          `json:"grouping_file"`
	SnapshotSHA256   string          `json:"snapshot_sha256"`
	EvaluationSHA256 string          `json:"evaluation_sha256"`
	CasesSHA256      string          `json:"cases_sha256"`
	GroupingSHA256   string          `json:"grouping_sha256"`
	RecordCount      int             `json:"record_count"`
	Groups           []string        `json:"groups"`
	Deployments      []Deployment    `json:"deployments"`
	Provenance       Provenance      `json:"provenance"`
	Redaction        Redaction       `json:"redaction"`
	Bounds           map[string]int  `json:"bounds"`
	Grouping         []GroupingEntry `json:"grouping"`
}

// GroupingEntry is sidecar-only metadata used to preserve deployment/site/
// session boundaries without adding grouping fields to detector Cases.
type GroupingEntry struct {
	ID          string `json:"id"`
	Deployment  string `json:"deployment"`
	Site        string `json:"site"`
	Session     string `json:"session"`
	Group       string `json:"group"`
	Fingerprint string `json:"fingerprint"`
	Timestamp   string `json:"timestamp"`
}

type stateServer struct {
	mu         sync.Mutex
	deployment Deployment
	counter    int
}

func (s *stateServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.counter++
	n := s.counter
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Deployment-ID", s.deployment.ID)
	w.Header().Set("X-State-Sequence", fmt.Sprintf("%d", n))
	if strings.Contains(r.URL.Query().Get("q"), "' OR 1=1") {
		w.WriteHeader(http.StatusForbidden)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	fmt.Fprintf(w, `{"deployment_id":%q,"seed":%q,"sequence":%d}`, s.deployment.ID, s.deployment.Seed, n)
}

var secretAssignmentPattern = regexp.MustCompile(`(?i)(["']?(?:authorization|cookie|api[_-]?key|access[_-]?token|secret|password|passwd|token|bearer|private[_-]?key)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}&\r\n]+)`)
var secretAssignmentPrefixPattern = regexp.MustCompile(`(?s)^(.+?[:=]\s*)(.*)$`)

func redactBody(v string) (string, bool, error) {
	if len(v) > maxBodyBytes {
		return "", false, fmt.Errorf("body exceeds %d bytes", maxBodyBytes)
	}
	out := secretAssignmentPattern.ReplaceAllStringFunc(v, func(match string) string {
		parts := secretAssignmentPrefixPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		value := parts[2]
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			return parts[1] + value[:1] + "[REDACTED]" + value[len(value)-1:]
		}
		return parts[1] + "[REDACTED]"
	})
	if len(out) > maxBodyBytes {
		return "", false, errors.New("redacted body exceeds bound")
	}
	return out, out != v, nil
}

func safeHeaders(h http.Header) (map[string]string, error) {
	allow := map[string]bool{"Accept": true, "Content-Type": true, "User-Agent": true, "X-Scenario-ID": true, "X-Deployment-Variant": true, "X-Deployment-ID": true, "X-State-Sequence": true}
	out := make(map[string]string)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		allowed := false
		for name := range allow {
			if strings.EqualFold(name, k) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		vals := h.Values(k)
		if len(vals) == 0 {
			continue
		}
		v := strings.Join(vals, ",")
		if len(v) > maxHeaderValueBytes {
			return nil, fmt.Errorf("header %s exceeds bound", k)
		}
		out[k] = v
	}
	if len(out) > maxHeaderCount {
		return nil, fmt.Errorf("header count exceeds bound")
	}
	return out, nil
}

func digest(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }

func toHTTPHeaders(in map[string]string) []security.HTTPHeader {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]security.HTTPHeader, 0, len(keys))
	for _, k := range keys {
		out = append(out, security.HTTPHeader{Name: k, Values: []string{in[k]}})
	}
	return out
}

func fixedScenarios() []Scenario {
	return []Scenario{
		{ID: "health-benign", Group: "baseline", Class: "benign", Method: "GET", Target: "/health", Headers: map[string]string{"Accept": "application/json"}, Oracle: Oracle{Label: "benign", Assertions: []string{"scenario.class == benign", "target == /health"}}},
		{ID: "search-sqli-attack", Group: "injection", Class: "attack", Category: "sqli", Method: "GET", Target: "/search?q=%27%20OR%201%3D1", Headers: map[string]string{"Accept": "application/json"}, Oracle: Oracle{Label: "attack", Assertions: []string{"scenario.class == attack", "query contains SQLi marker"}}},
	}
}

// Generate writes only to a newly-created temporary directory and returns its path.
func Generate(timestamp string) (string, error) {
	return generate(timestamp, "")
}

// GenerateAt writes a snapshot to an empty caller-owned directory. It is used
// by the CI integration path so the complete governance/split/replay chain can
// be exercised without leaving artifacts in the repository.
func GenerateAt(timestamp, outputDir string) (string, error) {
	return generate(timestamp, outputDir)
}

func generate(timestamp, outputDir string) (string, error) {
	if timestamp == "" {
		timestamp = "2025-01-01T00:00:00Z"
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		return "", fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	created := false
	var err error
	if strings.TrimSpace(outputDir) == "" {
		outputDir, err = os.MkdirTemp("", "cheesewaf-blind-lab-")
		if err != nil {
			return "", err
		}
		created = true
	} else {
		outputDir, err = filepath.Abs(outputDir)
		if err != nil {
			return "", fmt.Errorf("resolve output directory: %w", err)
		}
		info, statErr := os.Lstat(outputDir)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				return "", fmt.Errorf("inspect output directory: %w", statErr)
			}
			if err := os.MkdirAll(outputDir, 0o700); err != nil {
				return "", fmt.Errorf("create output directory: %w", err)
			}
			created = true
		} else {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", errors.New("output directory must be a local directory")
			}
			entries, readErr := os.ReadDir(outputDir)
			if readErr != nil {
				return "", fmt.Errorf("read output directory: %w", readErr)
			}
			if len(entries) != 0 {
				return "", errors.New("output directory must be empty")
			}
		}
	}
	dir := outputDir
	cleanup := func(e error) (string, error) {
		if e != nil && created {
			_ = os.RemoveAll(dir)
		}
		return dir, e
	}
	baseRun := "run-" + digest([]byte(timestamp))[:12]
	deployments := []Deployment{{ID: "local-a", Seed: "seed-a-42", RunID: baseRun + "-a"}, {ID: "local-b", Seed: "seed-b-84", RunID: baseRun + "-b"}}
	var records []snapshotRecord
	for _, dep := range deployments {
		ss := &stateServer{deployment: dep}
		srv := httptest.NewServer(http.HandlerFunc(ss.handler))
		for _, sc := range fixedScenarios() {
			body, _, err := redactBody(sc.Body)
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			req, err := http.NewRequest(sc.Method, srv.URL+sc.Target, strings.NewReader(body))
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			for k, v := range sc.Headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("X-Scenario-ID", sc.ID)
			// Keep the same scenario semantically distinct across independent
			// deployments so the global request fingerprint can detect accidental
			// duplicate capture while retaining a deployment-specific context.
			req.Header.Set("X-Deployment-Variant", dep.ID)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
			resp.Body.Close()
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			if len(respBody) > maxBodyBytes {
				srv.Close()
				return cleanup(errors.New("response body exceeds bound"))
			}
			respText, _, err := redactBody(string(respBody))
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			rh, err := safeHeaders(resp.Header)
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			reqHeaders, err := safeHeaders(req.Header)
			if err != nil {
				srv.Close()
				return cleanup(err)
			}
			reqHeadersList := toHTTPHeaders(reqHeaders)
			respHeadersList := toHTTPHeaders(rh)
			tm, _ := time.Parse(time.RFC3339, timestamp)
			caseID := dep.ID + "-" + sc.ID
			sessionID := dep.RunID + "-" + sc.ID
			siteID := dep.ID + "-" + sc.ID
			rec := snapshotRecord{HTTPTransaction: security.HTTPTransaction{Version: security.HTTPTransactionVersion, Request: security.HTTPRequest{Method: req.Method, Target: req.URL.RequestURI(), Protocol: req.Proto, Headers: reqHeadersList, Body: []byte(body)}, Response: security.HTTPResponse{StatusCode: resp.StatusCode, Protocol: resp.Proto, Headers: respHeadersList, Body: []byte(respText)}, ExpectedOracleLabel: security.OracleLabel{Label: sc.Class, Category: sc.Category, OracleType: "fixed-scenario", OracleVersion: "1", AssertionID: caseID}, Deployment: dep.ID, Provenance: "cheesewaf-blind-lab/" + generatorVersion + "; redaction=allowlist-headers", Source: "fixed-local-scenarios", Site: siteID, Session: sessionID, Timestamp: tm, Seed: dep.Seed, Run: dep.RunID, Assertion: caseID}, Group: sc.Group}
			rec.HTTPTransaction, err = security.NewHTTPTransaction(rec.HTTPTransaction)
			if err != nil {
				srv.Close()
				return cleanup(fmt.Errorf("seal transaction %s/%s: %w", dep.ID, sc.ID, err))
			}
			if err := security.ValidateHTTPTransaction(rec.HTTPTransaction); err != nil {
				srv.Close()
				return cleanup(fmt.Errorf("validate transaction %s/%s: %w", dep.ID, sc.ID, err))
			}
			records = append(records, rec)
		}
		srv.Close()
	}
	if len(records) == 0 || len(records) > maxRecords {
		return cleanup(errors.New("record bound violated"))
	}
	txs := make([]security.HTTPTransaction, 0, len(records))
	for _, rec := range records {
		txs = append(txs, rec.HTTPTransaction)
	}
	if err := security.ValidateHTTPTransactionSet(txs); err != nil {
		return cleanup(fmt.Errorf("validate transaction set: %w", err))
	}
	snapshotPath := filepath.Join(dir, "snapshot.jsonl")
	f, err := os.OpenFile(snapshotPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return cleanup(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			f.Close()
			return cleanup(err)
		}
	}
	if _, err = f.Write(buf.Bytes()); err != nil {
		f.Close()
		return cleanup(err)
	}
	if err = f.Close(); err != nil {
		return cleanup(err)
	}
	var evalBuf bytes.Buffer
	evalEnc := json.NewEncoder(&evalBuf)
	for _, rec := range records {
		c, err := rec.HTTPTransaction.ToCase()
		if err != nil {
			return cleanup(err)
		}
		eval := security.EvaluationRecord{ID: rec.Assertion, Case: c, Source: rec.Source, Site: rec.Site, Session: rec.Session, Timestamp: rec.Timestamp, Fingerprint: security.CaseFingerprint(c)}
		if err := evalEnc.Encode(eval); err != nil {
			return cleanup(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "evaluation.jsonl"), evalBuf.Bytes(), 0o600); err != nil {
		return cleanup(err)
	}
	var casesBuf bytes.Buffer
	casesEnc := json.NewEncoder(&casesBuf)
	grouping := make([]GroupingEntry, 0, len(records))
	for _, rec := range records {
		c, err := rec.HTTPTransaction.ToCase()
		if err != nil {
			return cleanup(err)
		}
		if err := casesEnc.Encode(c); err != nil {
			return cleanup(err)
		}
		grouping = append(grouping, GroupingEntry{ID: rec.Assertion, Deployment: rec.Deployment, Site: rec.Site, Session: rec.Session, Group: rec.Group, Fingerprint: security.CaseFingerprint(c), Timestamp: rec.Timestamp.UTC().Format(time.RFC3339)})
	}
	if err := os.WriteFile(filepath.Join(dir, "cases.jsonl"), casesBuf.Bytes(), 0o600); err != nil {
		return cleanup(err)
	}
	var groupingBuf bytes.Buffer
	groupingEnc := json.NewEncoder(&groupingBuf)
	for _, entry := range grouping {
		if err := groupingEnc.Encode(entry); err != nil {
			return cleanup(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "grouping.jsonl"), groupingBuf.Bytes(), 0o600); err != nil {
		return cleanup(err)
	}
	groups := []string{"baseline", "injection"}
	manifest := Manifest{SchemaVersion: schemaVersion, GeneratorVersion: generatorVersion, GeneratedAt: timestamp, RunID: baseRun, SnapshotFile: "snapshot.jsonl", EvaluationFile: "evaluation.jsonl", CasesFile: "cases.jsonl", GroupingFile: "grouping.jsonl", SnapshotSHA256: digest(buf.Bytes()), EvaluationSHA256: digest(evalBuf.Bytes()), CasesSHA256: digest(casesBuf.Bytes()), GroupingSHA256: digest(groupingBuf.Bytes()), RecordCount: len(records), Groups: groups, Deployments: deployments, Provenance: Provenance{Generator: "cheesewaf-blind-lab/" + generatorVersion, Source: "fixed-local-scenarios"}, Redaction: Redaction{Policy: "allowlist-headers; redact secret-like body parameters", Applied: true, MaxBodyBytes: maxBodyBytes, MaxHeaderCount: maxHeaderCount, MaxHeaderValueBytes: maxHeaderValueBytes}, Bounds: map[string]int{"max_records": maxRecords, "max_body_bytes": maxBodyBytes, "max_header_count": maxHeaderCount, "max_header_value_bytes": maxHeaderValueBytes}, Grouping: grouping}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	manifestBytes = append(manifestBytes, '\n')
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestBytes, 0o600); err != nil {
		return cleanup(err)
	}
	return dir, nil
}

func main() {
	ts := flag.String("timestamp", "2025-01-01T00:00:00Z", "RFC3339 timestamp (fixed by default for reproducibility)")
	outputDir := flag.String("output-dir", "", "empty local directory for output (default: a temporary directory)")
	flag.Parse()
	dir, err := GenerateAt(*ts, *outputDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f, _ := os.Open(filepath.Join(dir, "snapshot.jsonl"))
	defer f.Close()
	scanner := bufio.NewScanner(f)
	n := 0
	for scanner.Scan() {
		n++
	}
	fmt.Printf("blind-lab output: %s (%d records)\n", dir, n)
}
