#!/bin/bash
# Profile-Guided Optimization build workflow
# Usage: ./scripts/build-pgo.sh
set -e

echo "=== PGO Build Workflow ==="
echo ""

# Step 1: Build instrumented binary
echo "1. Building instrumented binary..."
go build -trimpath -o bin/cheesewaf-instrumented ./cmd/cheesewaf/
echo "✓ Instrumented binary ready"
echo ""

# Step 2: Run representative workload
echo "2. Running benchmark workload to collect profile..."
echo "   (This captures CPU profile during semantic analysis)"
go test -run='^$' -bench=BenchmarkFullPipeline -benchtime=10000x \
    -cpuprofile=default.pgo ./internal/engine/semantic
echo "✓ CPU profile saved to default.pgo"
echo ""

# Step 3: Rebuild with PGO
echo "3. Building optimized binary with PGO..."
go build -trimpath -pgo=default.pgo -gcflags "-l=4" -ldflags "-s -w" \
    -o bin/cheesewaf-pgo ./cmd/cheesewaf/
echo "✓ PGO-optimized binary ready at bin/cheesewaf-pgo"
echo ""

# Step 4: Size comparison
echo "4. Size comparison:"
ls -lh bin/cheesewaf-instrumented bin/cheesewaf-pgo 2>/dev/null || ls -lh bin/
echo ""

echo "=== PGO build complete ==="
echo "To use the optimized binary: bin/cheesewaf-pgo"
echo "To rebuild for release: go build -pgo=default.pgo -ldflags '-s -w' ..."
