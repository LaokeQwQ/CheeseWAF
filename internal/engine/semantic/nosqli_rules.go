package semantic

import (
	"encoding/json"
	"strings"
)

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
