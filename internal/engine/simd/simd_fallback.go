//go:build (!amd64 && !arm64) || purego

package simd

// No vector unit is available for this GOARCH (or purego was requested), so
// every dispatch var keeps its SWAR default. Restated explicitly here so the
// selected backend is obvious from the build configuration.
func init() {
	backendName = BackendSWAR
	isSimpleASCIIImpl = isSimpleASCIIGeneric
	isAlreadyLowerASCIIImpl = isAlreadyLowerASCIIGeneric
	isMostlyBase64Impl = isMostlyBase64Generic
	countBase64Impl = countBase64Generic
}
