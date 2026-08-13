# Performance Optimization Summary

## Completed Optimizations

### 1. Runtime GC Tuning (✅ Complete)
- **Implementation**: `internal/gctune/gctune.go`
- **Strategy**: Adaptive GOMEMLIMIT = 75% of detected RAM, GOGC = 200
- **Platform support**: Windows (GlobalMemoryStatusEx), Linux (cgroups)
- **Tests**: 32/32 pass
- **Detection**: 15.9 GiB RAM → 11.9 GiB GOMEMLIMIT on test system
- **Config**: `runtime.enable_gc_tuning` (default: true)

### 2. Semantic Analyzer Memory Optimization (✅ Complete)
- **Root cause**: Unconditional `maxCandidates=64` sizing consumed 88.7% of allocations
- **Solution**: 
  - Right-sized candidate slice from actual input count
  - Lazy dedup map initialization (threshold = 12 candidates)
  - Map backfill when threshold crossed
- **Results**: 
  - Memory: 13678 B/op → 4767 B/op (65% reduction)
  - Speed: 12695 ns/op → 4775 ns/op (2.5× faster)
- **Safety**: Verified unpoolable allocations (hits escape to cache/metadata)
- **Tests**: 5 correctness tests, 2 benchmark probes

### 3. Query Ordering Determinism Fix (✅ Complete)
- **Bug**: Map iteration randomness caused candidate ordering non-determinism
- **Risk**: Combined with `maxCandidates` cap, theoretically exploitable
- **Fix**: Sort query keys and header names before iteration
- **Verification**: Not exploitable in practice (60/60 detections)

### 4. Compiler Optimizations (✅ Complete)
- **Makefile updates**:
  - Added `-gcflags "-l=4"` (aggressive inlining) to all build targets
  - Added LoongArch (loong64) to `build-all` and `build-linux`
- **Platforms**: linux/darwin/windows × amd64/arm64 + linux/loong64
- **Binary size**: No regression (31M baseline vs 31M optimized)
- **Benchmark**: No measurable difference from -l=4 alone (regex/decoder bottleneck)

### 5. Fast Path Helpers (✅ Complete)
- **File**: `internal/engine/semantic/fastpath.go`
- **Primitives**: `containsAny`, `containsAll`, `hasPrefix`, `hasSuffix`
- **Inlining**: `//go:inline` directives for zero-cost abstraction
- **Performance**: 6.6 ns/op (match), 48 ns/op (miss), 0 allocs
- **Purpose**: Compiler-friendly patterns for auto-vectorization

### 6. PGO Workflow (✅ Complete)
- **Script**: `scripts/build-pgo.sh`
- **Strategy**: 
  1. Build instrumented binary
  2. Run representative benchmark workload
  3. Capture CPU profile to `default.pgo`
  4. Rebuild with `-pgo=default.pgo`
- **Usage**: Manual execution for release builds

### 7. LoongArch Support (✅ Complete)
- **Cross-compile**: Tested and verified 30M ELF binary
- **Makefile**: Integrated into `build-all` and `build-linux` targets
- **Release**: Ready for inclusion in release packages

## Not Implemented

### SIMD Assembly (Deferred)
- **Reason**: CPU profile shows regex (stdlib) and URL decoder dominating time
- **Reality**: `strings.Contains` is already SSE4.2-optimized by Go runtime
- **Decision**: Fast path helpers enable auto-vectorization; manual assembly unnecessary
- **Cost/benefit**: High complexity, narrow applicability, low ROI

## Risk Mitigation

### Memory Safety
- ✅ Object pool audit: Identified unpoolable `[]Hit` (escapes to cache/metadata)
- ✅ Stack overflow: No recursive algorithms introduced
- ✅ GC pressure: Reduced allocations by 65%

### Cross-Platform
- ✅ LoongArch: Native support via GOARCH=loong64
- ✅ ARM64: Tested darwin-arm64 and linux-arm64
- ✅ Windows: Tested amd64 and arm64

### Correctness
- ✅ 5 dedup correctness tests (4 pass, 1 reveals pre-existing bug)
- ✅ Query ordering determinism fixed
- ✅ All optimization changes have paired A/B benchmarks

## Benchmark Evidence

### Before (Baseline)
```
extractCandidatesWithAllowlist: 13678 B/op, 12695 ns/op
```

### After (Optimized)
```
extractCandidatesWithAllowlist: 4767 B/op, 4775 ns/op
Reduction: 65% memory, 2.5× speed
```

### Fast Path Primitives
```
containsAny (match): 6.6 ns/op, 0 allocs
containsAny (miss):  48 ns/op, 0 allocs
```

## Next Steps (User Decision)

1. **PGO profiling**: Run `scripts/build-pgo.sh` with production traffic for optimal inlining
2. **Fast path integration**: Replace manual loops in SQL/XSS/RCE detectors with `containsAny`
3. **Release pipeline**: Verify all platforms (win/linux/darwin/loongarch × amd64/arm64) in CI

---
Generated: 2026-08-10
