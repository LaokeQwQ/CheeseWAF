package security

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeEvaluationRecord(name, source, site, session, target string, when time.Time) EvaluationRecord {
	c := Case{
		Name:         name,
		SourceFamily: source,
		Label:        "benign",
		Method:       "GET",
		Target:       target,
	}
	return EvaluationRecord{
		ID:          name,
		Case:        c,
		Source:      source,
		Site:        site,
		Session:     session,
		Timestamp:   when,
		Fingerprint: CaseFingerprint(c),
	}
}

func TestGroupAwareSplitKeepsConnectedComponentTogether(t *testing.T) {
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first := makeEvaluationRecord("a", "source-a", "site-a", "session-a", "/one", when)
	second := makeEvaluationRecord("b", "source-b", "site-a", "session-b", "/two", when)
	// The shared site connects these rows even though every other key differs.
	third := makeEvaluationRecord("c", "source-c", "site-c", "session-c", "/three", when)
	records := []EvaluationRecord{first, second, third}

	assigned, summary, err := GroupAwareSplit(records, SplitConfig{
		Seed:               "unit",
		ValidationFraction: 0.25,
		BlindFraction:      0.25,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Groups != 2 {
		t.Fatalf("summary groups=%d, want 2: %+v", summary.Groups, summary)
	}
	if assigned[0].Group != assigned[1].Group || assigned[0].Split != assigned[1].Split {
		t.Fatalf("connected records split apart: %+v", assigned)
	}
	if assigned[2].Group == assigned[0].Group {
		t.Fatalf("unconnected record reused component id: %+v", assigned)
	}
	if err := ValidateEvaluationSplit(assigned); err != nil {
		t.Fatalf("ValidateEvaluationSplit: %v", err)
	}

	// Hash assignment is deterministic and independent of map iteration.
	reversed := []EvaluationRecord{third, second, first}
	assignedReversed, _, err := GroupAwareSplit(reversed, SplitConfig{Seed: "unit", ValidationFraction: 0.25, BlindFraction: 0.25})
	if err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]AssignedEvaluationRecord, len(assignedReversed))
	for _, row := range assignedReversed {
		byID[row.ID] = row
	}
	for _, row := range assigned {
		if got := byID[row.ID]; got.Split != row.Split || got.Group != row.Group {
			t.Fatalf("assignment changed with input order for %s: got %+v want %+v", row.ID, got, row)
		}
	}
}

func TestGroupAwareSplitRepairsEmptyFractionalPartitions(t *testing.T) {
	when := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	records := []EvaluationRecord{
		makeEvaluationRecord("one", "source-one", "site-one", "session-one", "/one", when),
		makeEvaluationRecord("two", "source-two", "site-two", "session-two", "/two", when),
		makeEvaluationRecord("three", "source-three", "site-three", "session-three", "/three", when),
	}
	cfg := SplitConfig{Seed: "empty-repair", ValidationFraction: 0.2, BlindFraction: 0.2}
	assigned, summary, err := GroupAwareSplit(records, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Train == 0 || summary.Validation == 0 || summary.Blind == 0 {
		t.Fatalf("fractional repair left an empty partition: %+v", summary)
	}
	if summary.Groups != len(records) {
		t.Fatalf("unexpected component count: %+v", summary)
	}
	if err := ValidateEvaluationSplit(assigned); err != nil {
		t.Fatalf("repaired assignment failed leakage validation: %v", err)
	}

	// Assignment must remain stable when the input stream is reordered. This is
	// important because the split artifact is recomputed during replay.
	reordered := []EvaluationRecord{records[2], records[0], records[1]}
	assignedReordered, summaryReordered, err := GroupAwareSplit(reordered, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if summaryReordered != summary {
		t.Fatalf("summary changed after reorder: got %+v want %+v", summaryReordered, summary)
	}
	byID := make(map[string]AssignedEvaluationRecord, len(assignedReordered))
	for _, row := range assignedReordered {
		byID[row.ID] = row
	}
	for _, row := range assigned {
		got, ok := byID[row.ID]
		if !ok || got.Split != row.Split || got.Group != row.Group {
			t.Fatalf("repaired assignment changed for %s: got %+v want %+v", row.ID, got, row)
		}
	}
}

func TestGroupAwareSplitDoesNotInventPartitionsForOneComponent(t *testing.T) {
	when := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	record := makeEvaluationRecord("only", "source", "site", "session", "/only", when)
	assigned, summary, err := GroupAwareSplit([]EvaluationRecord{record}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Groups != 1 || summary.Train+summary.Validation+summary.Blind != 1 {
		t.Fatalf("unexpected one-component summary: %+v", summary)
	}
	if err := ValidateEvaluationSplit(assigned); err != nil {
		t.Fatalf("one-component assignment failed validation: %v", err)
	}
}

func TestNormalizeSplitConfigRejectsMixedStrategies(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _, err := GroupAwareSplit([]EvaluationRecord{makeEvaluationRecord("a", "s", "h", "x", "/", start)}, SplitConfig{
		ValidationFraction: 0.2,
		ValidationStart:    &start,
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("mixed strategy error=%v", err)
	}
	_, _, err = GroupAwareSplit([]EvaluationRecord{makeEvaluationRecord("a", "s", "h", "x", "/", start)}, SplitConfig{
		ValidationFraction: 0.7,
		BlindFraction:      0.4,
	})
	if err == nil {
		t.Fatal("expected fractions summing to >= 1 to fail")
	}
}

func TestGroupAwareSplitTimeBoundaryRejectsCrossingGroup(t *testing.T) {
	validation := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	blind := validation.Add(24 * time.Hour)
	a := makeEvaluationRecord("a", "same", "site", "session", "/a", validation.Add(-time.Hour))
	b := makeEvaluationRecord("b", "same", "site", "session", "/b", blind.Add(time.Hour))
	_, _, err := GroupAwareSplit([]EvaluationRecord{a, b}, SplitConfig{
		ValidationStart: &validation,
		BlindStart:      &blind,
	})
	if err == nil || !strings.Contains(err.Error(), "crosses a time boundary") {
		t.Fatalf("crossing group error=%v", err)
	}
}

func TestForEachEvaluationJSONLValidatesUnselectedShardAndHonorsLimit(t *testing.T) {
	when := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	row := makeEvaluationRecord("row", "source", "site", "session", "/", when)
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	// A malformed second line must fail even if the first line is selected by
	// another shard; shard filtering is never a way to hide bad input.
	input := string(encoded) + "\n{not-json}\n"
	_, err = ForEachEvaluationJSONL(strings.NewReader(input), EvaluationLoadOptions{Shards: 2, Shard: 0, MaxRecords: 10}, nil)
	if err == nil {
		t.Fatal("expected malformed unselected record to fail")
	}

	second := row
	second.ID = "row-2"
	second.Case.Name = "row-2"
	second.Case.Target = "/two"
	second.Fingerprint = CaseFingerprint(second.Case)
	line2, _ := json.Marshal(second)
	_, err = ForEachEvaluationJSONL(bytes.NewReader(append(append(encoded, '\n'), append(line2, '\n')...)), EvaluationLoadOptions{MaxRecords: 1}, nil)
	if err == nil || !errors.Is(err, ErrEvaluationRecordLimit) {
		t.Fatalf("limit error=%v, want ErrEvaluationRecordLimit", err)
	}
}

func TestEvaluationRecordUnmarshalFlatAndNested(t *testing.T) {
	flat := fmt.Sprintf(`{"name":"flat","source_family":"public","label":"benign","method":"GET","target":"https://Example.test/","session_id":"s1","host":"Example.test","timestamp":"%s"}`,
		time.Date(2026, 4, 1, 2, 3, 4, 0, time.FixedZone("CST", 8*60*60)).Format(time.RFC3339Nano))
	var record EvaluationRecord
	if err := json.Unmarshal([]byte(flat), &record); err != nil {
		t.Fatal(err)
	}
	if record.Source != "public" || record.Site != "Example.test" || record.Session != "s1" || record.Timestamp.Location() != time.UTC {
		t.Fatalf("unexpected flat record: %+v", record)
	}

	nested := `{"id":"nested","source":"public","site":"site","session":"s2","case":{"name":"nested","source_family":"public","label":"attack","category":"sqli","method":"POST","target":"/search","body":"x"}}`
	if err := json.Unmarshal([]byte(nested), &record); err != nil {
		t.Fatal(err)
	}
	if record.ID != "nested" || record.Case.Label != "attack" || record.Fingerprint == "" {
		t.Fatalf("unexpected nested record: %+v", record)
	}
}

func TestEvaluationRecordRejectsUnknownAndAmbiguousFields(t *testing.T) {
	validCase := `"case":{"name":"nested","source_family":"public","label":"benign","method":"GET","target":"/"}`
	base := `{"id":"nested","source":"public","site":"site","session":"session",` + validCase + `}`
	for name, input := range map[string]string{
		"unknown envelope field":  `{"id":"nested","source":"public","site":"site","session":"session","unexpected":true,"case":{"name":"nested","source_family":"public","label":"benign","method":"GET","target":"/"}}`,
		"unknown case field":      `{"id":"nested","source":"public","site":"site","session":"session","case":{"name":"nested","source_family":"public","label":"benign","method":"GET","target":"/","methode":"GET"}}`,
		"duplicate envelope key":  `{"id":"nested","source":"public","source":"other","site":"site","session":"session","case":{"name":"nested","source_family":"public","label":"benign","method":"GET","target":"/"}}`,
		"duplicate case alias":    `{"id":"nested","source":"public","site":"site","session":"session","case":{"name":"nested","source_family":"public","SourceFamily":"other","label":"benign","method":"GET","target":"/"}}`,
		"mixed envelope and flat": `{"id":"nested","source":"public","site":"site","session":"session","method":"GET",` + validCase + `}`,
		"alias envelope fields":   `{"id":"nested","source":"public","governance_source":"other","site":"site","session":"session","case":{"name":"nested","source_family":"public","label":"benign","method":"GET","target":"/"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var record EvaluationRecord
			if err := json.Unmarshal([]byte(input), &record); err == nil {
				t.Fatalf("ambiguous/unknown input unexpectedly accepted: %s", input)
			}
		})
	}
	var record EvaluationRecord
	if err := json.Unmarshal([]byte(base), &record); err != nil {
		t.Fatalf("valid nested input rejected: %v", err)
	}
}

func TestEvaluationRecordRejectsMismatchedFingerprint(t *testing.T) {
	record := makeEvaluationRecord("a", "source", "site", "session", "/", time.Now().UTC())
	record.Fingerprint = strings.Repeat("0", 64)
	if _, _, err := GroupAwareSplit([]EvaluationRecord{record}, SplitConfig{}); err == nil || !strings.Contains(err.Error(), "does not match case fingerprint") {
		t.Fatalf("mismatched fingerprint error=%v", err)
	}
}

func TestValidateEvaluationSplitRejectsInvalidGroupMetadata(t *testing.T) {
	when := time.Now().UTC()
	record := makeEvaluationRecord("a", "s", "site", "session", "/", when)
	assigned := []AssignedEvaluationRecord{{EvaluationRecord: record, Split: SplitTrain}}
	if err := ValidateEvaluationSplit(assigned); err == nil {
		t.Fatal("expected missing group id to fail")
	}
	assigned[0].Group = "group-a"
	if err := ValidateEvaluationSplit(assigned); err != nil {
		t.Fatalf("valid assignment rejected: %v", err)
	}
	other := record
	other.ID = "b"
	other.Case.Name = "b"
	other.Case.Target = "/other"
	other.Fingerprint = CaseFingerprint(other.Case)
	assigned = append(assigned, AssignedEvaluationRecord{EvaluationRecord: other, Split: SplitBlind, Group: "group-b"})
	if err := ValidateEvaluationSplit(assigned); err == nil {
		t.Fatal("expected shared source key across splits to fail")
	}
	// A key cannot be split across two component IDs even when both rows are
	// nominally in the same partition; otherwise the assignment metadata is no
	// longer a faithful connected-component description.
	sameSplit := []AssignedEvaluationRecord{
		{EvaluationRecord: record, Split: SplitTrain, Group: "group-a"},
		{EvaluationRecord: other, Split: SplitTrain, Group: "group-b"},
	}
	if err := ValidateEvaluationSplit(sameSplit); err == nil || !strings.Contains(err.Error(), "assigned to groups") {
		t.Fatalf("same-split group inconsistency error=%v", err)
	}
	duplicate := other
	duplicate.Case = record.Case
	duplicate.Fingerprint = record.Fingerprint
	if err := ValidateEvaluationSplit([]AssignedEvaluationRecord{
		{EvaluationRecord: record, Split: SplitTrain, Group: "group-a"},
		{EvaluationRecord: duplicate, Split: SplitTrain, Group: "group-a"},
	}); err == nil || !strings.Contains(err.Error(), "duplicate fingerprint") {
		t.Fatalf("duplicate fingerprint error=%v", err)
	}
}

func TestWilsonInterval99BoundsAndInvalidInputs(t *testing.T) {
	if lower, upper, ok := WilsonInterval99(0, 10); !ok || lower != 0 || upper <= 0 {
		t.Fatalf("zero-success interval=(%v,%v,%v)", lower, upper, ok)
	}
	if lower, upper, ok := WilsonInterval99(10, 10); !ok || lower <= 0 || upper != 1 {
		t.Fatalf("all-success interval=(%v,%v,%v)", lower, upper, ok)
	}
	for _, tc := range [][2]int{{-1, 10}, {11, 10}, {0, 0}} {
		if _, _, ok := WilsonInterval99(tc[0], tc[1]); ok {
			t.Errorf("WilsonInterval99(%d,%d) unexpectedly valid", tc[0], tc[1])
		}
	}
}

func TestValidateEvaluationSplitArtifactRecomputesAssignment(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	records := []EvaluationRecord{
		makeEvaluationRecord("a", "source-a", "site-a", "session-a", "/a", when),
		makeEvaluationRecord("b", "source-b", "site-b", "session-b", "/b", when),
	}
	artifact, err := BuildEvaluationSplit(records, SplitConfig{Seed: "artifact", ValidationFraction: 0.25, BlindFraction: 0.25})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvaluationSplitArtifact(artifact); err != nil {
		t.Fatalf("valid artifact rejected: %v", err)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := LoadEvaluationSplitArtifact(bytes.NewReader(encoded), 10)
	if err != nil {
		t.Fatalf("round-trip artifact rejected: %v", err)
	}
	if len(decoded.Records) != len(artifact.Records) || decoded.Records[0].Group != artifact.Records[0].Group {
		t.Fatalf("round-trip assignment changed: %+v", decoded.Records)
	}
	artifact.Records[0].Split = SplitBlind
	if err := ValidateEvaluationSplitArtifact(artifact); err == nil {
		t.Fatal("tampered assignment unexpectedly accepted")
	}
}

func TestEvaluationSplitRecordsSHA256BindsCompleteAssignedRecords(t *testing.T) {
	when := time.Date(2026, 5, 2, 3, 4, 5, 6, time.UTC)
	requestCase := Case{
		Name:         "complete-record",
		SourceFamily: "public-source",
		Label:        "attack",
		Category:     "sqli",
		Method:       "POST",
		Target:       "/search?q=one",
		ContentType:  "application/json",
		Body:         `{"query":"one"}`,
		Header:       map[string]string{"X-Second": "two", "X-First": "one"},
		Rationale:    "curated regression",
	}
	record := EvaluationRecord{
		ID:                "record-id",
		Case:              requestCase,
		Source:            "public-source",
		Site:              "site-a",
		Session:           "session-a",
		Timestamp:         when,
		Fingerprint:       CaseFingerprint(requestCase),
		GovernancePath:    "/governed/formal.jsonl",
		GovernanceLine:    7,
		RawHash:           strings.Repeat("a", 64),
		Decision:          "approve",
		ReviewRuleVersion: "review-v1",
		Reviewer:          "reviewer-a",
		ReviewReason:      "manually confirmed",
		ReviewedAt:        when.Format(time.RFC3339Nano),
	}
	artifact, err := BuildEvaluationSplit([]EvaluationRecord{record}, SplitConfig{Seed: "records-digest"})
	if err != nil {
		t.Fatal(err)
	}
	if !artifact.Governed {
		t.Fatal("governed input produced an ungoverned artifact")
	}
	if !isLowerHexSHA256(artifact.RecordsSHA256) {
		t.Fatalf("records_sha256=%q", artifact.RecordsSHA256)
	}
	recomputed, err := EvaluationSplitRecordsSHA256(artifact.Records)
	if err != nil {
		t.Fatal(err)
	}
	if recomputed != artifact.RecordsSHA256 {
		t.Fatalf("constructor records_sha256=%q, recomputed=%q", artifact.RecordsSHA256, recomputed)
	}
	encodedRecords, err := json.Marshal(artifact.Records)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.RecordsSHA256 == hashBytes(encodedRecords) {
		t.Fatal("records_sha256 is missing its version domain separator")
	}
	domainSeparated := append([]byte(evaluationSplitRecordsDigestDomain), encodedRecords...)
	if want := hashBytes(domainSeparated); artifact.RecordsSHA256 != want {
		t.Fatalf("domain-separated records_sha256=%q, want %q", artifact.RecordsSHA256, want)
	}

	// Header map insertion order must not change the digest.
	sameRecords := append([]AssignedEvaluationRecord(nil), artifact.Records...)
	sameRecords[0].Case.Header = map[string]string{"X-First": "one", "X-Second": "two"}
	sameDigest, err := EvaluationSplitRecordsSHA256(sameRecords)
	if err != nil {
		t.Fatal(err)
	}
	if sameDigest != artifact.RecordsSHA256 {
		t.Fatalf("header map order changed digest: got %q want %q", sameDigest, artifact.RecordsSHA256)
	}

	mutations := map[string]func(*AssignedEvaluationRecord){
		"label": func(row *AssignedEvaluationRecord) {
			row.Case.Label = "benign"
		},
		"category": func(row *AssignedEvaluationRecord) {
			row.Case.Category = "xss"
		},
		"request": func(row *AssignedEvaluationRecord) {
			row.Case.Body = `{"query":"tampered"}`
			row.Fingerprint = CaseFingerprint(row.Case)
		},
		"governance identity": func(row *AssignedEvaluationRecord) {
			row.RawHash = strings.Repeat("b", 64)
		},
		"group": func(row *AssignedEvaluationRecord) {
			row.Group += "-tampered"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			tampered := artifact
			tampered.Records = append([]AssignedEvaluationRecord(nil), artifact.Records...)
			mutate(&tampered.Records[0])
			if err := ValidateEvaluationSplitArtifact(tampered); err == nil || !strings.Contains(err.Error(), "records_sha256 mismatch") {
				t.Fatalf("tampered %s unexpectedly accepted: %v", name, err)
			}
		})
	}

	serializedTamper := artifact
	serializedTamper.Records = append([]AssignedEvaluationRecord(nil), artifact.Records...)
	serializedTamper.Records[0].Case.Label = "benign"
	encoded, err := json.Marshal(serializedTamper)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(encoded), 10); err == nil || !strings.Contains(err.Error(), "records_sha256 mismatch") {
		t.Fatalf("loader accepted a record with a stale digest: %v", err)
	}
}

func TestEvaluationSplitRecordsSHA256RequiredOnlyForGovernedArtifacts(t *testing.T) {
	when := time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC)
	record := makeEvaluationRecord("governed", "source", "site", "session", "/", when)
	record.GovernancePath = "/governed/formal.jsonl"
	record.GovernanceLine = 1
	record.RawHash = strings.Repeat("a", 64)
	record.Decision = "auto"
	governed, err := BuildEvaluationSplit([]EvaluationRecord{record}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEvaluationSplitArtifact(governed); err != nil {
		t.Fatalf("in-memory governed staging artifact rejected before binding attachment: %v", err)
	}
	stagingJSON, err := json.Marshal(governed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded EvaluationSplitArtifact
	if err := json.Unmarshal(stagingJSON, &decoded); err == nil || !strings.Contains(err.Error(), "requires a governance binding") {
		t.Fatalf("serialized governed staging artifact unexpectedly decoded: %v", err)
	}
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(stagingJSON), 10); err == nil || !strings.Contains(err.Error(), "requires a governance binding") {
		t.Fatalf("loader accepted governed artifact without binding: %v", err)
	}

	governed.Governance = &EvaluationGovernanceBinding{
		ManifestSHA256:      strings.Repeat("a", 64),
		ManifestPayloadHash: strings.Repeat("b", 64),
		FormalSHA256:        strings.Repeat("c", 64),
		InputSHA256:         strings.Repeat("d", 64),
		FormalRecords:       1,
		Pipeline:            "pipeline-v1",
		Version:             "v1",
		PolicyHash:          strings.Repeat("e", 64),
		ReviewHash:          strings.Repeat("f", 64),
	}
	boundJSON, err := json.Marshal(governed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(boundJSON), 10); err != nil {
		t.Fatalf("complete serialized governed artifact rejected: %v", err)
	}

	governed.Governance.ReviewHash = ""
	incompleteJSON, err := json.Marshal(governed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(incompleteJSON), 10); err == nil || !strings.Contains(err.Error(), "invalid governance binding") {
		t.Fatalf("serialized governed artifact with incomplete binding accepted: %v", err)
	}

	governed.Governance = nil
	governed.RecordsSHA256 = ""
	if err := ValidateEvaluationSplitArtifact(governed); err == nil || !strings.Contains(err.Error(), "requires records_sha256") {
		t.Fatalf("governed artifact without records_sha256 unexpectedly accepted: %v", err)
	}

	ungoverned, err := BuildEvaluationSplit([]EvaluationRecord{makeEvaluationRecord("smoke", "source", "site", "session", "/", when)}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ungoverned.RecordsSHA256 = ""
	encoded, err := json.Marshal(ungoverned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(encoded), 10); err != nil {
		t.Fatalf("historical ungoverned artifact without records_sha256 rejected: %v", err)
	}
}

func TestValidateEvaluationSplitArtifactRejectsSummaryAndStatsMismatch(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	record := makeEvaluationRecord("a", "source-a", "site-a", "session-a", "/a", when)
	artifact, err := BuildEvaluationSplit([]EvaluationRecord{record}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	artifact.Summary.Train++
	if err := ValidateEvaluationSplitArtifact(artifact); err == nil {
		t.Fatal("summary mismatch unexpectedly accepted")
	}
	artifact.Summary.Train--
	artifact.LoadStats = EvaluationLoadStats{NonEmptyLines: 1, TotalRecords: 1, SelectedRecords: 0}
	if err := ValidateEvaluationSplitArtifact(artifact); err == nil {
		t.Fatal("incomplete load stats unexpectedly accepted")
	}
}

func TestLoadEvaluationSplitArtifactRejectsUnknownDuplicateAndMissingStats(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	artifact, err := BuildEvaluationSplit([]EvaluationRecord{makeEvaluationRecord("a", "source", "site", "session", "/", when)}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	withoutStats := make(map[string]json.RawMessage)
	if err := json.Unmarshal(encoded, &withoutStats); err != nil {
		t.Fatal(err)
	}
	delete(withoutStats, "load_stats")
	missingStats, err := json.Marshal(withoutStats)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(missingStats), 10); err == nil || !strings.Contains(err.Error(), "load_stats") {
		t.Fatalf("missing load_stats unexpectedly accepted: %v", err)
	}

	unknown := bytes.TrimSpace(encoded)
	unknown = append(unknown[:len(unknown)-1], []byte(`,"unexpected":true}`)...)
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(unknown), 10); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown artifact field unexpectedly accepted: %v", err)
	}
	duplicate := bytes.TrimSpace(encoded)
	duplicate = append(duplicate[:len(duplicate)-1], []byte(`,"version":"tampered"}`)...)
	if _, err := LoadEvaluationSplitArtifact(bytes.NewReader(duplicate), 10); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate artifact field unexpectedly accepted: %v", err)
	}
}

func TestLoadEvaluationSplitArtifactBoundsRecordsBeforeDecode(t *testing.T) {
	// The records are intentionally not valid envelopes: the preflight counter
	// must reject the oversized array before attempting to decode any element.
	input := `{"version":"evaluation-split-v1","records":[{},{}]}`
	_, err := LoadEvaluationSplitArtifact(strings.NewReader(input), 1)
	if err == nil || !errors.Is(err, ErrEvaluationRecordLimit) {
		t.Fatalf("oversized records unexpectedly decoded: %v", err)
	}
}

func TestEvaluationJSONDocumentEnforcesDepthBudget(t *testing.T) {
	deep := strings.Repeat("[", DefaultEvaluationArtifactMaxDepth+2) + "0" + strings.Repeat("]", DefaultEvaluationArtifactMaxDepth+2)
	if err := validateJSONDocument([]byte(deep)); !errors.Is(err, ErrEvaluationArtifactDepthLimit) {
		t.Fatalf("deep JSON error=%v, want depth limit", err)
	}
}

func TestEvaluationJSONDocumentRejectsInvalidUTF8(t *testing.T) {
	input := append([]byte(`{"value":"`), 0xff)
	input = append(input, []byte(`"}`)...)
	if err := validateJSONDocument(input); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("invalid UTF-8 unexpectedly accepted: %v", err)
	}
}

func TestEvaluationSplitArtifactUnmarshalRunsSemanticValidation(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	artifact, err := BuildEvaluationSplit([]EvaluationRecord{makeEvaluationRecord("a", "source", "site", "session", "/", when)}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	artifact.Records[0].Group = "tampered"
	encoded, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	var decoded EvaluationSplitArtifact
	if err := json.Unmarshal(encoded, &decoded); err == nil || !strings.Contains(err.Error(), "records_sha256 mismatch") {
		t.Fatalf("tampered artifact unexpectedly accepted: %v", err)
	}
}

func TestForEachEvaluationJSONLUsesBoundedScannerBeforeRecordDecode(t *testing.T) {
	deep := strings.Repeat("[", DefaultEvaluationArtifactMaxDepth+2) + "0" + strings.Repeat("]", DefaultEvaluationArtifactMaxDepth+2)
	_, err := ForEachEvaluationJSONL(strings.NewReader(deep+"\n"), EvaluationLoadOptions{MaxRecords: 1, MaxBytes: int64(len(deep) + 1)}, nil)
	if !errors.Is(err, ErrEvaluationArtifactDepthLimit) {
		t.Fatalf("deep JSONL error=%v, want depth limit", err)
	}
}

func TestForEachEvaluationJSONLEnforcesAggregateByteBudget(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	encoded, err := json.Marshal(makeEvaluationRecord("bounded", "source", "site", "session", "/", when))
	if err != nil {
		t.Fatal(err)
	}
	_, err = ForEachEvaluationJSONL(bytes.NewReader(append(encoded, '\n')), EvaluationLoadOptions{
		MaxRecords: 1,
		MaxBytes:   int64(len(encoded)),
	}, nil)
	if !errors.Is(err, ErrEvaluationJSONLByteLimit) {
		t.Fatalf("aggregate byte error=%v, want ErrEvaluationJSONLByteLimit", err)
	}
}

func TestForEachEvaluationJSONLRequireGoverned(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	row := makeEvaluationRecord("governed", "source", "site", "session", "/", when)
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ForEachEvaluationJSONL(bytes.NewReader(append(encoded, '\n')), EvaluationLoadOptions{
		MaxRecords:      1,
		RequireGoverned: true,
	}, nil); err == nil || !strings.Contains(err.Error(), "governance_path") {
		t.Fatalf("ungoverned row unexpectedly accepted: %v", err)
	}

	// Provenance is checked against the referenced source line, so use a
	// real local normalized-case source rather than a made-up path. The
	// source line's hash is intentionally independent from the envelope row.
	formalPath := filepath.Join(t.TempDir(), "formal.jsonl")
	formalLine, err := json.Marshal(row.Case)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(formalPath, append(formalLine, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	row.GovernancePath = formalPath
	row.GovernanceLine = 1
	row.RawHash = hashBytes(formalLine)
	row.Decision = "auto"
	encoded, err = json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ForEachEvaluationJSONL(bytes.NewReader(append(encoded, '\n')), EvaluationLoadOptions{
		MaxRecords:      1,
		RequireGoverned: true,
	}, nil); err != nil {
		t.Fatalf("governed row rejected: %v", err)
	}

	row.Decision = "pending"
	encoded, err = json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ForEachEvaluationJSONL(bytes.NewReader(append(encoded, '\n')), EvaluationLoadOptions{
		MaxRecords:      1,
		RequireGoverned: true,
	}, nil); err == nil || !strings.Contains(err.Error(), "decision") {
		t.Fatalf("unsupported governed decision unexpectedly accepted: %v", err)
	}
}

func TestLoadEvaluationSplitArtifactEnforcesByteBudget(t *testing.T) {
	data := bytes.Repeat([]byte{' '}, DefaultEvaluationArtifactMaxBytes+1)
	_, err := LoadEvaluationSplitArtifact(bytes.NewReader(data), 1)
	if !errors.Is(err, ErrEvaluationArtifactByteLimit) {
		t.Fatalf("oversized artifact error=%v, want byte limit", err)
	}
}

func TestBuildEvaluationSplitProvidesCompleteLoadStats(t *testing.T) {
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	artifact, err := BuildEvaluationSplit([]EvaluationRecord{makeEvaluationRecord("a", "source", "site", "session", "/", when)}, SplitConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if artifact.LoadStats.TotalRecords != 1 || artifact.LoadStats.SelectedRecords != 1 || artifact.LoadStats.NonEmptyLines != 1 || artifact.LoadStats.SkippedOverlong != 0 {
		t.Fatalf("unexpected constructor stats: %+v", artifact.LoadStats)
	}
	if err := ValidateEvaluationSplitArtifact(artifact); err != nil {
		t.Fatalf("complete constructor artifact rejected: %v", err)
	}
}

func TestValidateEvaluationGovernanceBindingRequiresCompleteHashes(t *testing.T) {
	binding := EvaluationGovernanceBinding{
		ManifestSHA256:      strings.Repeat("a", 64),
		ManifestPayloadHash: strings.Repeat("b", 64),
		FormalSHA256:        strings.Repeat("c", 64),
		InputSHA256:         strings.Repeat("d", 64),
		FormalRecords:       1,
		Pipeline:            "pipeline-v1",
		Version:             "v1",
		PolicyHash:          strings.Repeat("e", 64),
		ReviewHash:          strings.Repeat("f", 64),
	}
	if err := ValidateEvaluationGovernanceBinding(&binding); err != nil {
		t.Fatalf("complete governance binding rejected: %v", err)
	}
	binding.InputSHA256 = ""
	if err := ValidateEvaluationGovernanceBinding(&binding); err == nil || !strings.Contains(err.Error(), "input_sha256") {
		t.Fatalf("binding without split input hash unexpectedly accepted: %v", err)
	}
}

func TestSplitConfigRejectsUnknownAndDuplicateFields(t *testing.T) {
	for name, input := range map[string]string{
		"unknown":   `{"seed":"a","unexpected":true}`,
		"duplicate": `{"seed":"a","seed":"b"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var cfg SplitConfig
			if err := json.Unmarshal([]byte(input), &cfg); err == nil {
				t.Fatalf("invalid split config unexpectedly accepted: %s", input)
			}
		})
	}
}

func TestEvaluationLoadStatsJSONUsesStableKeys(t *testing.T) {
	data, err := json.Marshal(EvaluationLoadStats{NonEmptyLines: 1, TotalRecords: 2, SelectedRecords: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != `{"non_empty_lines":1,"total_records":2,"selected_records":2,"skipped_overlong":0}` {
		t.Fatalf("stats JSON=%s", got)
	}
}
