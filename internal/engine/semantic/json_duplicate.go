package semantic

import (
	"bytes"
	"encoding/json"
	"io"
)

// jsonHasDuplicateKeys reports whether a syntactically valid JSON document
// repeats an object key. WAF and upstream commonly disagree on first-vs-last
// value selection; the caller emits a raw-body candidate so both values are
// inspected instead of silently trusting encoding/json's map collapse.
func jsonHasDuplicateKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	var stack []*frame
	valueDone := func() {
		if len(stack) == 0 {
			return
		}
		top := stack[len(stack)-1]
		if top.object {
			top.expectKey = true
		}
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return false
		}
		if err != nil {
			return false
		}
		switch typed := token.(type) {
		case json.Delim:
			switch typed {
			case '{':
				stack = append(stack, &frame{object: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				valueDone()
			}
		case string:
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				if top.object && top.expectKey {
					if _, ok := top.keys[typed]; ok {
						return true
					}
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
}
