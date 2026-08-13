package simd

// Portable SWAR (SIMD-Within-A-Register) reference implementations.
//
// These are compiled on every architecture and every build-tag combination.
// They are simultaneously:
//   - the fallback kernel where no vector unit is available, and
//   - the correctness ORACLE for every assembly kernel in this package.
//
// If an assembly kernel disagrees with the code in this file, the assembly is
// wrong. Never "fix" this file to match assembly.
//
// # SWAR primitives
//
// All lane predicates below produce a mask in the "high-bit domain": the
// result only ever has bits from hi8 set, and lane k's bit 7 is 1 iff the
// predicate holds for lane k. Masks in that domain compose with |, &, &^ and
// are complemented with ^hi8.
//
// The comparison primitives require the input word to have every lane's high
// bit already cleared (x = w &^ hi8), which keeps lane arithmetic from
// carrying into the neighbouring lane.

const (
	// hi8 is bit 7 of every byte lane.
	hi8 = uint64(0x8080808080808080)
	// lo8 is bit 0 of every byte lane; lo8*n broadcasts n to all lanes.
	lo8 = uint64(0x0101010101010101)
	// wordSize is the SWAR block size in bytes.
	wordSize = 8
)

// bcast replicates b into all eight lanes.
func bcast(b uint8) uint64 { return lo8 * uint64(b) }

// load64 assembles the eight bytes at s[i:i+8] into a little-endian word
// without allocating and without unsafe. The Go compiler recognises this
// shift-or pattern and folds it into a single 8-byte load on little-endian
// architectures.
func load64(s string, i int) uint64 {
	return uint64(s[i]) |
		uint64(s[i+1])<<8 |
		uint64(s[i+2])<<16 |
		uint64(s[i+3])<<24 |
		uint64(s[i+4])<<32 |
		uint64(s[i+5])<<40 |
		uint64(s[i+6])<<48 |
		uint64(s[i+7])<<56
}

// geLanes returns a high-bit-domain mask of lanes >= n.
//
// Requires x&hi8 == 0 and 1 <= n <= 0x80. Adding (0x80-n) to a lane in
// [0,0x7f] sets that lane's bit 7 exactly when the lane is >= n, and can
// never carry out of the lane because 0x7f + 0x7f = 0xfe.
func geLanes(x uint64, n uint8) uint64 { return (x + bcast(0x80-n)) & hi8 }

// ltLanes returns a high-bit-domain mask of lanes < n (complement of geLanes).
func ltLanes(x uint64, n uint8) uint64 { return geLanes(x, n) ^ hi8 }

// inLanes returns a high-bit-domain mask of lanes in [lo, hi].
// Requires x&hi8 == 0, 1 <= lo, hi < 0x80.
func inLanes(x uint64, lo, hi uint8) uint64 {
	return geLanes(x, lo) &^ geLanes(x, hi+1)
}

// eqLanes returns a high-bit-domain mask of lanes == n.
//
// Requires x&hi8 == 0 and n < 0x80. t's lanes are then all < 0x80, so
// t+0x7f sets bit 7 for every non-zero lane and leaves it clear for a zero
// lane; the complement flips that into "lane == n".
func eqLanes(x uint64, n uint8) uint64 { return ^(x ^ bcast(n) + bcast(0x7f)) & hi8 }

// sumLanes adds up eight 0-or-1 lane indicators. Callers pass a high-bit-
// domain mask shifted right by 7, or an accumulator of at most 31 such masks
// (31*8 = 248 < 256, so no lane can overflow before the flush).
func sumLanes(acc uint64) int { return int((acc * lo8) >> 56) }

// isSimpleASCIIGeneric is the SWAR oracle for IsSimpleASCII.
func isSimpleASCIIGeneric(s string) bool {
	i := 0
	for ; i+wordSize <= len(s); i += wordSize {
		w := load64(s, i)
		if w&hi8 != 0 {
			return false // some lane >= 0x80
		}
		// Every lane is now < 0x80, so w is already high-bit-clear.
		tabNL := inLanes(w, '\t', '\n') // 0x09, 0x0a
		cr := eqLanes(w, '\r')          // 0x0d
		bad := ltLanes(w, 0x20)&^(tabNL|cr) | eqLanes(w, '\\')
		if bad != 0 {
			return false
		}
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c >= 0x80 || c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
		if c == '\\' {
			return false
		}
	}
	return true
}

// isAlreadyLowerASCIIGeneric is the SWAR oracle for IsAlreadyLowerASCII.
func isAlreadyLowerASCIIGeneric(s string) bool {
	i := 0
	for ; i+wordSize <= len(s); i += wordSize {
		w := load64(s, i)
		// notHigh keeps only lanes that were < 0x80: a lane like 0xc1 must
		// not be mistaken for 'A' after its high bit is stripped.
		notHigh := ^w & hi8
		if inLanes(w&^hi8, 'A', 'Z')&notHigh != 0 {
			return false
		}
	}
	for ; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return false
		}
	}
	return true
}

// base64Alphabet reports whether c is in [A-Za-z0-9+/=-_], the combined
// standard and URL-safe base64 alphabet including padding.
func base64Alphabet(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '=', c == '-', c == '_':
		return true
	}
	return false
}

// countBase64Generic is the SWAR oracle for CountBase64Alphabet.
//
// Per 8-byte block it builds one high-bit-domain membership mask and folds the
// lane indicators into an accumulator; the accumulator is flushed with a
// single multiply every 31 blocks (31*8 = 248, so no lane overflows).
func countBase64Generic(s string) int {
	count := 0
	i := 0
	for i+wordSize <= len(s) {
		var acc uint64
		blocks := 0
		for ; blocks < 31 && i+wordSize <= len(s); blocks, i = blocks+1, i+wordSize {
			w := load64(s, i)
			x := w &^ hi8
			notHigh := ^w & hi8
			// Case-fold A-Z onto a-z so ONE range test covers both letter
			// ranges. Folding is only safe for the letter range: the folded
			// preimage of [0x61,0x7a] is exactly A-Z plus a-z ('_' 0x5f folds
			// to 0x7f, which is outside the range). It is NOT safe for the
			// '/'-'9' range, whose folded preimage would also include the
			// control bytes 0x0f and 0x10-0x19, so that range uses the
			// unfolded lanes.
			folded := x | bcast(0x20)
			member := inLanes(x, '/', '9') | // '/' 0x2f and '0'-'9' 0x30-0x39
				inLanes(folded, 'a', 'z') | // 'a'-'z' and folded 'A'-'Z'
				eqLanes(x, '+') |
				eqLanes(x, '-') |
				eqLanes(x, '=') |
				eqLanes(x, '_')
			acc += (member & notHigh) >> 7
		}
		count += sumLanes(acc)
	}
	for ; i < len(s); i++ {
		if base64Alphabet(s[i]) {
			count++
		}
	}
	return count
}

// isMostlyBase64Generic is the SWAR oracle for IsMostlyBase64.
func isMostlyBase64Generic(s string) bool {
	if len(s) == 0 {
		return false
	}
	return countBase64Generic(s)*10 >= len(s)*9
}
