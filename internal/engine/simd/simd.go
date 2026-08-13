// Package simd provides hardware-accelerated byte-predicate scanning for the
// WAF's hottest string inspection loops.
//
// The predicates mirror the guards in internal/engine/semantic/tokenizer.go
// (normalize's fast path) plus a base64-density heuristic used by the
// entropy/obfuscation checks. Each predicate has a portable SWAR
// (SIMD-Within-A-Register, uint64 word-at-a-time) implementation that doubles
// as the correctness oracle, plus hand-written vector kernels selected at
// runtime:
//
//	amd64: AVX2 (32 B/iter) > SSE2 (16 B/iter, part of the amd64 baseline)
//	arm64: NEON/ASIMD (16 B/iter)
//	other: SWAR (8 B/iter)
//
// Build with -tags purego to force the SWAR path everywhere.
//
// # Verification status (read before trusting this package)
//
// amd64 AVX2 and SSE2 kernels are runtime-verified on windows/amd64: the
// differential corpus, the all-256-byte-values sweep, and the native fuzzers
// all compare every backend against the SWAR oracle.
//
// The arm64 NEON kernels are COMPILE-VERIFIED AND LOGIC-REVIEWED ONLY. They
// have never been executed: the machine that authored them is windows/amd64
// and Go cannot run arm64 code there. Their algorithm is checked by a
// lane-by-lane Go model of the NEON instruction sequence (TestNEONModel*),
// which validates the algorithm but NOT the assembly encoding or operand
// order. The differential test suite in this package is the gate that will
// catch a broken arm64 kernel the first time it runs on real arm64 hardware;
// treat a failure there as "the asm is wrong", never as "the oracle is wrong".
//
// # Zero allocation
//
// Every exported predicate is allocation-free (no unsafe, no []byte
// conversions); the benchmarks assert 0 allocs/op.
package simd

// Backend names reported by Backend.
const (
	BackendAVX2 = "avx2"
	BackendSSE2 = "sse2"
	BackendNEON = "neon"
	BackendSWAR = "swar"
)

// backendName is set by the per-architecture init(); SWAR is the default so
// that a missing init can only ever cost speed, never correctness.
var backendName = BackendSWAR

// Dispatch vars. Tests swap these to exercise every kernel on one machine.
var (
	isSimpleASCIIImpl       func(string) bool = isSimpleASCIIGeneric
	isAlreadyLowerASCIIImpl func(string) bool = isAlreadyLowerASCIIGeneric
	isMostlyBase64Impl      func(string) bool = isMostlyBase64Generic
)

// IsSimpleASCII reports whether every byte of s is printable-or-whitespace
// 7-bit ASCII with no backslash escapes. Precisely, it returns true iff no
// byte b of s satisfies any of:
//
//	b >= 0x80
//	b < 0x20 && b != '\t' && b != '\n' && b != '\r'
//	b == '\\'
//
// The empty string returns true. Note 0x7F (DEL) is accepted, matching
// semantic.isSimpleASCII.
func IsSimpleASCII(s string) bool { return isSimpleASCIIImpl(s) }

// IsAlreadyLowerASCII reports whether s contains no byte in ['A'..'Z'].
// Bytes >= 0x80 are ignored (they are not ASCII uppercase). The empty string
// returns true. Matches semantic.isAlreadyLowerASCII.
func IsAlreadyLowerASCII(s string) bool { return isAlreadyLowerASCIIImpl(s) }

// IsMostlyBase64 reports whether s is non-empty and at least 90% of its bytes
// belong to the combined standard+URL-safe base64 alphabet
// [A-Za-z0-9+/=-_] (i.e. A-Z, a-z, 0-9, '+', '/', '=', '-', '_').
//
// Unlike semantic.isMostlyBase64Alphabet this predicate does not treat
// whitespace as neutral: whitespace simply fails to match, so a padded blob
// with more than 10% whitespace returns false.
func IsMostlyBase64(s string) bool { return isMostlyBase64Impl(s) }

// CountBase64Alphabet returns the number of bytes of s that belong to the
// base64 alphabet used by IsMostlyBase64. It is the counting kernel behind
// IsMostlyBase64, exported for entropy heuristics that need the raw ratio.
func CountBase64Alphabet(s string) int { return countBase64Impl(s) }

// countBase64Impl is the count dispatch behind both IsMostlyBase64 and
// CountBase64Alphabet.
var countBase64Impl func(string) int = countBase64Generic

// Backend reports the vector kernel selected for this process: "avx2",
// "sse2", "neon" or "swar".
func Backend() string { return backendName }
