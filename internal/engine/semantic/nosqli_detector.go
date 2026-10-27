package semantic

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
)

type NoSQLiDetector struct{ mode string }

func NewNoSQLiDetector(mode string) *NoSQLiDetector {
	if mode == "" {
		mode = "block"
	}
	return &NoSQLiDetector{mode: mode}
}
func (d *NoSQLiDetector) ID() string    { return "semantic.nosqli" }
func (d *NoSQLiDetector) Name() string  { return "NoSQL Injection Semantic Detector" }
func (d *NoSQLiDetector) Priority() int { return 340 }

func (d *NoSQLiDetector) Detect(ctx context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	result, err := NewAnalyzer(d.mode, 2, "nosqli").Detect(ctx, reqCtx)
	if result != nil {
		result.DetectorID = d.ID()
	}
	return result, err
}

// nosqlWholeValueOperatorDocument reports a value that is nothing but a MongoDB
// operator document: an object whose keys are query operators, either directly
// ("{"$ne":null}") or one level down through an ordinary field name
// ("{"username":{"$ne":null}}"). Both are the canonical authentication-bypass
// payloads, and both are complete attack values — no surrounding application
// logic is needed to make sense of them.
//
// This is structural evidence, not field-name evidence: an arbitrary parameter
// such as "q" carries the same meaning as "filter" once the value itself is an
// operator document. Everything else in the value must be ordinary, so a real
// filter object such as "{"page":2}" or a JSON Schema reference such as
// "{"$ref":"#/defs/x"}" stays clean.
func nosqlWholeValueOperatorDocument(text string) bool {
	t := strings.TrimSpace(text)
	if len(t) < 6 || len(t) > 256 || t[0] != '{' || t[len(t)-1] != '}' {
		return false
	}
	if !strings.Contains(t, "$") {
		return false
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(t), &doc); err != nil || len(doc) == 0 {
		return false
	}
	for key, raw := range doc {
		if nosqlQueryOperatorKey(key) {
			continue
		}
		// An ordinary top-level key is only acceptable when its value is itself an
		// operator document, which is the nested form of the same attack.
		if !nosqlNestedOperatorDocument(raw) {
			return false
		}
	}
	return true
}

// nosqlNestedOperatorDocument reports a JSON object whose every key is a query
// operator. Nested objects inside it are not inspected: one level of operator
// indirection is what the payloads use, and deeper parsing would only add cost.
func nosqlNestedOperatorDocument(raw json.RawMessage) bool {
	if len(raw) == 0 || raw[0] != '{' {
		return false
	}
	var nested map[string]json.RawMessage
	if err := json.Unmarshal(raw, &nested); err != nil || len(nested) == 0 {
		return false
	}
	for key := range nested {
		if !nosqlQueryOperatorKey(key) {
			return false
		}
	}
	return true
}

// nosqlQueryOperatorKey reports a MongoDB query/update operator name such as
// "$ne" or "$regex". The match is exact and comes from nosqlOperatorNames, so
// unrelated "$"-prefixed JSON Schema keywords ("$ref", "$comment") do not count.
func nosqlQueryOperatorKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if len(lower) < 3 || lower[0] != '$' {
		return false
	}
	for _, op := range nosqlOperatorNames {
		if lower == op {
			return true
		}
	}
	return false
}
