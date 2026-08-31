package decoder

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// maxJSONDepth caps how deep flatten descends into a decoded JSON value.
//
// It matches maxJSONDepth in internal/engine/semantic, which bounds the same
// walk over the same bodies inside the analyzer (jsonwalk.go, and
// flattenJSONValue in analyzer.go). That constant is unexported to package
// semantic and nothing outside it needs the number, so the value is mirrored
// rather than exported: keeping the two equal means FlattenJSON can never
// report a field the analyzer's own flatteners would have discarded, whichever
// of the two paths a caller ends up on.
//
// The recursion is additionally bounded by encoding/json's own 10000-level
// nesting limit, which rejects deeper documents before flatten ever runs. This
// cap keeps the walk's cost independent of that stdlib implementation detail.
const maxJSONDepth = 8

// errJSONTooDeep reports a document nested deeper than maxJSONDepth.
var errJSONTooDeep = errors.New("json nesting exceeds max depth")

// FlattenJSON renders raw's decoded JSON as a space-joined stream of keys and
// scalar values, for detectors that match against structure rather than syntax.
//
// Documents nested deeper than maxJSONDepth are rejected with errJSONTooDeep
// and returned verbatim rather than partially flattened: a truncated walk drops
// exactly the deeply nested fields a payload would hide itself in, so whatever
// survived above the cutoff would read to a detector as a clean request. The
// untouched bytes come back alongside the error so a caller that mishandles it
// still hands the whole payload on instead of a truncated prefix. Callers must
// treat the error as "flattening unavailable", never as "no fields found".
//
// Malformed input is returned unchanged with a nil error, matching the
// historical behaviour callers rely on.
func FlattenJSON(raw []byte) (string, error) {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw), nil
	}
	var parts []string
	if err := flatten(value, 0, &parts); err != nil {
		return string(raw), err
	}
	return strings.Join(parts, " "), nil
}

// flatten appends value's keys and scalars to parts. depth is value's nesting
// level, 0 at the document root, and mirrors flattenJSONValue's accounting in
// package semantic so both walks cut off at the same place.
func flatten(value any, depth int, parts *[]string) error {
	if depth > maxJSONDepth {
		return errJSONTooDeep
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			*parts = append(*parts, key)
			if err := flatten(item, depth+1, parts); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := flatten(item, depth+1, parts); err != nil {
				return err
			}
		}
	case string:
		*parts = append(*parts, v)
	case float64, bool:
		*parts = append(*parts, fmt.Sprint(v))
	}
	return nil
}
