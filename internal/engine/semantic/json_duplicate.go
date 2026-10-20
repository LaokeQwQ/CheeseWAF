package semantic

import (
	"bytes"
	"encoding/json"
	"io"
)

// jsonHasDuplicateKeys reports whether a syntactically valid JSON document
// repeats an object key. WAF and upstream commonly disagree on first-vs-last
// value selection; the caller emits a raw-body candidate so both values are
// inspected instead of silently trusting encoding/json's map collapse. Budget
// exhaustion is reported separately: map decoding may collapse the subtree that
// spent the budget, so extraction alone cannot establish complete coverage.
// Large documents use a streaming walk that retains duplicate occurrences.
func jsonHasDuplicateKeys(raw []byte) (bool, traversalStatus) {
	var status traversalStatus
	if len(raw) > maxJSONTreeDecodeBytes {
		return false, status
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	stack := make([]frame, 0, maxJSONDepth+1)
	keysSeen := 0
	valueDone := func() {
		if len(stack) == 0 {
			return
		}
		top := &stack[len(stack)-1]
		if top.object {
			top.expectKey = true
		}
	}
	for tokens := 0; tokens < maxJSONNodes*4; tokens++ {
		token, err := decoder.Token()
		if err == io.EOF {
			return false, status
		}
		if err != nil {
			return false, status
		}
		switch typed := token.(type) {
		case json.Delim:
			switch typed {
			case '{':
				if len(stack) > maxJSONDepth {
					status.mark(jsonDuplicateScanLimitReason)
					return false, status
				}
				stack = append(stack, frame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				if len(stack) > maxJSONDepth {
					status.mark(jsonDuplicateScanLimitReason)
					return false, status
				}
				stack = append(stack, frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				valueDone()
			}
		case string:
			if len(stack) > 0 {
				top := &stack[len(stack)-1]
				if top.object && top.expectKey {
					if _, ok := top.keys[typed]; ok {
						return true, status
					}
					if keysSeen >= maxJSONNodes {
						status.mark(jsonDuplicateScanLimitReason)
						return false, status
					}
					keysSeen++
					top.keys[typed] = struct{}{}
					top.expectKey = false
					continue
				}
			}
			valueDone()
		default:
			valueDone()
		}
	}
	status.mark(jsonDuplicateScanLimitReason)
	return false, status
}
