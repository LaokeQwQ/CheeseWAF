package semantic

// Fast-path JSON flattening.
//
// The decoder-based walk (flattenJSONInputsDecode) builds a complete
// map[string]any tree before extracting a single field: json.NewDecoder +
// bytes.NewReader + a scanner parse-state + per-value interface boxing measured
// as roughly nine of the analyzer's per-request allocations on JSON traffic.
// jsonWalker emits the same InputPoints straight from the body bytes.
//
// It is deliberately conservative. Anything it cannot guarantee it reproduces
// exactly — escape sequences and non-ASCII bytes (encoding/json applies \uXXXX
// surrogate pairing and U+FFFD substitution there), or any structural doubt —
// makes it bail, and the caller replays the original decoder walk. The set of
// bodies the fast path accepts is therefore a strict subset of what the decoder
// accepts, so a body can never be flattened differently, only more cheaply.
type jsonWalker struct {
	src    []byte
	pos    int
	source string
	inputs *[]InputPoint
	nodes  int
	status *traversalStatus

	// keyStack holds the source byte ranges of the object keys currently in
	// scope, one contiguous region per nesting level. encoding/json decodes an
	// object into a map, so a repeated key collapses to a single entry there
	// while a straight document walk would emit it twice. Detecting the repeat
	// and bailing keeps the two walks in exact agreement; the ranges point into
	// src, so the check costs no allocation.
	keyStack [maxWalkerKeys][2]int32
	keyTop   int
}

// maxWalkerKeys bounds the in-scope key ranges the fast path tracks across all
// nesting levels. Documents with more keys in scope than this bail to the
// decoder walk rather than skip the duplicate-key check.
const maxWalkerKeys = 256

// value parses one JSON value and emits its InputPoints. suppress mirrors the
// decoder walk's early return once a budget is spent: parsing continues (the
// decoder validated the whole document, so the fast path must too) while
// emission stops.
func (w *jsonWalker) value(prefix string, depth int, suppress bool) bool {
	if !suppress {
		if depth > maxJSONDepth {
			if w.status != nil {
				w.status.mark(jsonDepthLimitIncompleteReason)
			}
			suppress = true
		} else if w.nodes >= maxJSONNodes {
			if w.status != nil {
				w.status.mark(jsonNodeLimitIncompleteReason)
			}
			suppress = true
		} else if len(*w.inputs) >= maxCandidates {
			if w.status != nil {
				w.status.mark(jsonCollectorLimitReason)
			}
			suppress = true
		} else {
			w.nodes++
		}
	}
	w.skipWS()
	if w.pos >= len(w.src) {
		return false
	}
	switch c := w.src[w.pos]; {
	case c == '{':
		return w.object(prefix, depth, suppress)
	case c == '[':
		return w.array(prefix, depth, suppress)
	case c == '"':
		text, ok := w.stringToken()
		if !ok {
			return false
		}
		if clipped := clipRaw(text); clipped != text && w.status != nil {
			w.status.mark(jsonRawClippedReason)
		}
		w.emit(prefix, clipRaw(text), suppress)
		return true
	case c == 't':
		if !w.literal("true") {
			return false
		}
		w.emit(prefix, "true", suppress)
		return true
	case c == 'f':
		if !w.literal("false") {
			return false
		}
		w.emit(prefix, "false", suppress)
		return true
	case c == 'n':
		// null: the decoder walk increments the node count but emits nothing.
		return w.literal("null")
	default:
		lit, ok := w.numberToken()
		if !ok {
			return false
		}
		w.emit(prefix, lit, suppress)
		return true
	}
}

func (w *jsonWalker) emit(name, raw string, suppress bool) {
	if suppress {
		return
	}
	// The fast path receives already-clipped text; callers mark clipping at the
	// source boundary so exact-cap values remain complete.
	*w.inputs = append(*w.inputs, InputPoint{Source: w.source, Name: name, Raw: raw, Layers: rawLayersOnly})
}

func (w *jsonWalker) object(prefix string, depth int, suppress bool) bool {
	w.pos++ // consume '{'
	w.skipWS()
	if w.pos < len(w.src) && w.src[w.pos] == '}' {
		w.pos++
		return true
	}
	// Keys of this object only; sibling objects at the same depth must not see
	// each other's keys, so the region is popped on every exit path.
	keyBase := w.keyTop
	for {
		w.skipWS()
		key, keyStart, keyEnd, ok := w.stringTokenRange()
		if !ok {
			w.keyTop = keyBase
			return false
		}
		// A repeated key would collapse in the decoder's map: hand off.
		for i := keyBase; i < w.keyTop; i++ {
			prev := w.keyStack[i]
			if prev[1]-prev[0] != keyEnd-keyStart {
				continue
			}
			if string(w.src[prev[0]:prev[1]]) == key {
				w.keyTop = keyBase
				return false
			}
		}
		if w.keyTop >= maxWalkerKeys {
			w.keyTop = keyBase
			return false
		}
		w.keyStack[w.keyTop] = [2]int32{keyStart, keyEnd}
		w.keyTop++
		w.skipWS()
		if w.pos >= len(w.src) || w.src[w.pos] != ':' {
			return false
		}
		w.pos++

		// Budget is re-checked per key, exactly where the decoder walk checks it.
		childSuppress := suppress
		if !childSuppress && (w.nodes >= maxJSONNodes || len(*w.inputs) >= maxCandidates) {
			if w.status != nil {
				if w.nodes >= maxJSONNodes {
					w.status.mark(jsonNodeLimitIncompleteReason)
				} else {
					w.status.mark(jsonCollectorLimitReason)
				}
			}
			childSuppress = true
		}
		name := prefix
		if !childSuppress {
			if prefix == "" {
				// Name and Raw share one string, as they do via the decoder.
				name = key
			} else {
				name = prefix + "." + key
			}
			if clipped := clipRaw(key); clipped != key {
				if w.status != nil {
					w.status.mark(jsonRawClippedReason)
				}
			}
			w.emit(name, clipRaw(key), false)
		}
		if !w.value(name, depth+1, childSuppress) {
			return false
		}

		w.skipWS()
		if w.pos >= len(w.src) {
			return false
		}
		switch w.src[w.pos] {
		case ',':
			w.pos++
		case '}':
			w.pos++
			// Pop this object's keys: a sibling object may legitimately reuse them.
			w.keyTop = keyBase
			return true
		default:
			return false
		}
	}
}

func (w *jsonWalker) array(prefix string, depth int, suppress bool) bool {
	w.pos++ // consume '['
	w.skipWS()
	if w.pos < len(w.src) && w.src[w.pos] == ']' {
		w.pos++
		return true
	}
	// The decoder walk rebuilds prefix+"[]" per element; every element gets the
	// same string, so build it once.
	childPrefix := prefix
	if !suppress {
		childPrefix = prefix + "[]"
	}
	for {
		childSuppress := suppress
		if !childSuppress && w.nodes >= maxJSONNodes {
			if w.status != nil {
				w.status.mark(jsonNodeLimitIncompleteReason)
			}
			childSuppress = true
		}
		if !w.value(childPrefix, depth+1, childSuppress) {
			return false
		}
		w.skipWS()
		if w.pos >= len(w.src) {
			return false
		}
		switch w.src[w.pos] {
		case ',':
			w.pos++
		case ']':
			w.pos++
			return true
		default:
			return false
		}
	}
}

// stringTokenRange is stringToken plus the source byte range of the decoded
// text, which object() records for its duplicate-key check.
func (w *jsonWalker) stringTokenRange() (string, int32, int32, bool) {
	start := w.pos + 1
	out, ok := w.stringToken()
	if !ok {
		return "", 0, 0, false
	}
	// The token is escape-free by construction, so the decoded text is exactly
	// src[start:w.pos-1].
	return out, int32(start), int32(w.pos - 1), true
}

// stringToken reads a plain ASCII JSON string. Escapes and non-ASCII bytes bail
// so encoding/json keeps ownership of its exact unquote semantics.
func (w *jsonWalker) stringToken() (string, bool) {
	if w.pos >= len(w.src) || w.src[w.pos] != '"' {
		return "", false
	}
	for i := w.pos + 1; i < len(w.src); i++ {
		c := w.src[i]
		if c == '"' {
			out := string(w.src[w.pos+1 : i])
			w.pos = i + 1
			return out, true
		}
		// '\\' needs unquote; >=0x80 needs UTF-8 validation/replacement;
		// <0x20 is an unescaped control character (invalid JSON).
		if c == '\\' || c >= 0x80 || c < 0x20 {
			return "", false
		}
	}
	return "", false
}

// numberToken accepts exactly the JSON number grammar encoding/json accepts
// (no leading '+', no leading zeros, no bare '.'), and returns the literal text
// so the emitted value matches UseNumber's json.Number.String().
func (w *jsonWalker) numberToken() (string, bool) {
	start := w.pos
	i := w.pos
	if i < len(w.src) && w.src[i] == '-' {
		i++
	}
	if i >= len(w.src) {
		return "", false
	}
	switch c := w.src[i]; {
	case c == '0':
		i++
	case c >= '1' && c <= '9':
		for i < len(w.src) && isJSONDigit(w.src[i]) {
			i++
		}
	default:
		return "", false
	}
	if i < len(w.src) && w.src[i] == '.' {
		i++
		if i >= len(w.src) || !isJSONDigit(w.src[i]) {
			return "", false
		}
		for i < len(w.src) && isJSONDigit(w.src[i]) {
			i++
		}
	}
	if i < len(w.src) && (w.src[i] == 'e' || w.src[i] == 'E') {
		i++
		if i < len(w.src) && (w.src[i] == '+' || w.src[i] == '-') {
			i++
		}
		if i >= len(w.src) || !isJSONDigit(w.src[i]) {
			return "", false
		}
		for i < len(w.src) && isJSONDigit(w.src[i]) {
			i++
		}
	}
	w.pos = i
	return string(w.src[start:i]), true
}

func isJSONDigit(c byte) bool { return c >= '0' && c <= '9' }

func (w *jsonWalker) literal(lit string) bool {
	if w.pos+len(lit) > len(w.src) || string(w.src[w.pos:w.pos+len(lit)]) != lit {
		return false
	}
	w.pos += len(lit)
	return true
}

func (w *jsonWalker) skipWS() {
	for w.pos < len(w.src) {
		switch w.src[w.pos] {
		case ' ', '\t', '\n', '\r':
			w.pos++
		default:
			return
		}
	}
}
