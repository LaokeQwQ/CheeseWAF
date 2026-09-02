# CheeseWAF Makefile
# ==================

BINARY_NAME  := cheesewaf
CLI_NAME     := waf-cli
MODULE       := github.com/LaokeQwQ/CheeseWAF
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT       := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
BUILD_TIME   := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
CHANNEL      := $(shell sh scripts/ci/channel-from-git.sh)
LDFLAGS      := -s -w -X '$(MODULE)/internal/version.Version=$(VERSION)' -X '$(MODULE)/internal/version.Commit=$(COMMIT)' -X '$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)' -X '$(MODULE)/internal/version.Channel=$(CHANNEL)'

GO           := go
GOFLAGS      := -trimpath
CGO_ENABLED  := 0

.PHONY: all build build-cli run test test-go semantic-bench semantic-bench-report web-test web-build security-corpus security-corpus-http security-gate corpus-governance evaluation-split evaluation-replay evaluation-lock blind-lab blind-lab-test lint clean dev help

## help: Show this help message
help:
	@echo "CheeseWAF Makefile Commands:"
	@echo ""
	@echo "  make build       Build cheesewaf binary"
	@echo "  make build-cli   Build and create waf-cli symlink"
	@echo "  make run         Run cheesewaf serve"
	@echo "  make dev         Run with hot-reload (requires air)"
	@echo "  make test        Run Go and frontend tests"
	@echo "  make semantic-bench       Run repeatable semantic mixed-workload benchmarks"
	@echo "  make semantic-bench-report Capture structured semantic benchmark statistics"
	@echo "  make web-build   Build the web dashboard"
	@echo "  make security-corpus      Run curated semantic corpus against analyzer"
	@echo "  make corpus-governance   Validate and classify all semantic JSONL corpora"
	@echo "  make evaluation-split    Build a manifest-bound train/validation/blind split (CORPUS=..., SPLIT_CONFIG=..., GOVERNANCE_MANIFEST=..., optional GOVERNANCE_FORMAL=..., OUTPUT=...)"
	@echo "  make evaluation-replay   Replay one governed split with an independently stored artifact hash (CORPUS=..., GOVERNANCE_MANIFEST=..., EVALUATION_SPLIT=..., EXPECTED_ARTIFACT_SHA256=..., optional OUTPUT=...)"
	@echo "  make evaluation-lock     Capture a first-use lock record for a governed split (CORPUS=..., GOVERNANCE_MANIFEST=..., EVALUATION_SPLIT=..., LOCK_OUTPUT=...)"
	@echo "  make blind-lab            Generate a bounded, repeatable local blind-lab snapshot in a temporary directory"
	@echo "  make blind-lab-test       Run focused blind-lab self-tests"
	@echo "  make security-corpus-http Run curated corpus against deployed WAF (BASE_URL=...)"
	@echo "  make security-gate        Run analyzer, HTTP replay, and optional external scanner gate (BASE_URL=..., ADMIN_URL=...)"
	@echo "  make lint        Run golangci-lint"
	@echo "  make clean       Remove build artifacts"
	@echo "  make deps        Download dependencies"
	@echo ""

## all: Build both binaries
all: build build-cli

## build: Build the cheesewaf binary
build:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME) ./cmd/cheesewaf/

## build-cli: Build and create waf-cli symlink/copy
build-cli: build
ifeq ($(OS),Windows_NT)
	@copy bin\$(BINARY_NAME).exe bin\$(CLI_NAME).exe 2>nul || copy bin\$(BINARY_NAME) bin\$(CLI_NAME) 2>nul || echo "Copy failed"
else
	@ln -sf $(BINARY_NAME) bin/$(CLI_NAME)
endif

## build-windows-gui: Build Windows local service controller (pure Go, no CGO)
build-windows-gui:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-gui-windows-amd64.exe ./cmd/cheesewaf-gui/
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-gui-windows-arm64.exe ./cmd/cheesewaf-gui/
ifeq ($(OS),Windows_NT)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-gui.exe ./cmd/cheesewaf-gui/
endif

## package-windows-cli: Stage a zip/bin-style Windows CLI payload directory
package-windows-cli: build-windows-gui
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME).exe ./cmd/cheesewaf/
	@mkdir -p dist/windows-cli/configs dist/windows-cli/data dist/windows-cli/logs dist/windows-cli/web
	@test -f bin/$(BINARY_NAME).exe
	@cp -f bin/$(BINARY_NAME).exe dist/windows-cli/
	@cp -f bin/$(BINARY_NAME).exe dist/windows-cli/waf-cli.exe
	@if [ -f bin/$(BINARY_NAME)-gui.exe ]; then cp -f bin/$(BINARY_NAME)-gui.exe dist/windows-cli/cheesewaf-gui.exe; \
	elif [ -f bin/$(BINARY_NAME)-gui-windows-amd64.exe ]; then cp -f bin/$(BINARY_NAME)-gui-windows-amd64.exe dist/windows-cli/cheesewaf-gui.exe; \
	else echo "missing cheesewaf-gui Windows binary" >&2; exit 1; fi
	@cp -f configs/cheesewaf.yaml dist/windows-cli/configs/
	@test -s web/dist/index.html || { echo "missing web/dist/index.html; run make web-build first" >&2; exit 1; }
	@cp -R web/dist dist/windows-cli/web/
	@test -s dist/windows-cli/web/dist/index.html
	@echo "Staged dist/windows-cli — zip manually; do not embed secrets"

## package-windows-nsis-payload: Stage SOURCE_DIR for makensis (no secrets)
package-windows-nsis-payload: package-windows-cli
	@mkdir -p dist/windows-payload/configs
	@test -f dist/windows-cli/cheesewaf.exe
	@cp -f dist/windows-cli/cheesewaf.exe dist/windows-payload/
	@cp -f dist/windows-cli/cheesewaf-gui.exe dist/windows-payload/
	@cp -f dist/windows-cli/waf-cli.exe dist/windows-payload/
	@cp -f dist/windows-cli/configs/cheesewaf.yaml dist/windows-payload/configs/
	@test -s dist/windows-cli/web/dist/index.html
	@cp -R dist/windows-cli/web dist/windows-payload/
	@test -s dist/windows-payload/web/dist/index.html
	@echo "Staged dist/windows-payload for: makensis /DVERSION=... /DSOURCE_DIR=dist/windows-payload deploy/windows/nsis/cheesewaf.nsi"

## build-linux: Cross-compile for Linux amd64
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/cheesewaf/
	@cp bin/$(BINARY_NAME)-linux-amd64 bin/$(CLI_NAME)-linux-amd64

## build-darwin: Cross-compile for macOS arm64 (Apple Silicon)
build-darwin:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/cheesewaf/
	@cp bin/$(BINARY_NAME)-darwin-arm64 bin/$(CLI_NAME)-darwin-arm64

## build-all: Build for all platforms (Linux amd64/arm64, macOS amd64/arm64, Windows amd64/arm64, LoongArch)
build-all:
	@echo "Building for all platforms..."
	@for goos in linux darwin windows; do \
		for goarch in amd64 arm64; do \
			ext=""; \
			if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
			echo "  → $$goos/$$goarch"; \
			GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
			-o bin/$(BINARY_NAME)-$$goarch-$$goos-$(subst +,-,$(VERSION))$$ext ./cmd/cheesewaf/; \
			cp bin/$(BINARY_NAME)-$$goarch-$$goos-$(subst +,-,$(VERSION))$$ext bin/$(CLI_NAME)-$$goarch-$$goos-$(subst +,-,$(VERSION))$$ext; \
		done; \
	done
	@echo "  → linux/loong64"
	@GOOS=linux GOARCH=loong64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
		-o bin/$(BINARY_NAME)-loong64-linux-$(subst +,-,$(VERSION)) ./cmd/cheesewaf/
	@cp bin/$(BINARY_NAME)-loong64-linux-$(subst +,-,$(VERSION)) bin/$(CLI_NAME)-loong64-linux-$(subst +,-,$(VERSION))
	@echo "Done! All binaries in bin/"

## run: Run cheesewaf serve
run: build
	./bin/$(BINARY_NAME) serve

## dev: Run with hot-reload (requires: go install github.com/air-verse/air@latest)
dev:
	air -c .air.toml

## test: Run all tests
test: test-go web-test

## test-go: Run Go tests
test-go:
	$(GO) test -v -race -count=1 ./cmd/... ./internal/...

SEMANTIC_BENCH_TIME ?= 1s
SEMANTIC_BENCH_COUNT ?= 5
SEMANTIC_BENCH_CPU ?= 1,4
SEMANTIC_BENCH_OUTPUT ?=

## semantic-bench: Run the fixed clean/attack semantic request workload with allocation metrics
semantic-bench:
	$(GO) test -run '^$$' -bench '^BenchmarkSemanticAnalyzerMixedRequestPath$$' -benchmem -benchtime=$(SEMANTIC_BENCH_TIME) -count=$(SEMANTIC_BENCH_COUNT) -cpu=$(SEMANTIC_BENCH_CPU) ./internal/engine/semantic

## semantic-bench-report: Emit a structured, no-threshold semantic benchmark report
semantic-bench-report:
	SEMANTIC_BENCH_TIME="$(SEMANTIC_BENCH_TIME)" \
	SEMANTIC_BENCH_COUNT="$(SEMANTIC_BENCH_COUNT)" \
	SEMANTIC_BENCH_CPU="$(SEMANTIC_BENCH_CPU)" \
	SEMANTIC_BENCH_OUTPUT="$(SEMANTIC_BENCH_OUTPUT)" \
	bash scripts/ci/run-semantic-benchmark.sh

## web-test: Run frontend unit tests
web-test:
	cd web && npm test

## web-build: Build the React dashboard
web-build:
	cd web && npm ci --no-audit --no-fund --ignore-scripts && npm run build

## security-corpus: Run curated attack/benign corpus against the semantic analyzer
security-corpus:
	bash scripts/ci/run-governed-semantic-gate.sh

## eval-shards: Run semantic evaluation corpus in parallel shards (env SEMANTIC_EVAL_SHARDS)
eval-shards:
	bash scripts/ci/run-semantic-eval-shards.sh

## corpus-governance: Run read-only corpus governance into a temporary directory
corpus-governance:
	bash scripts/ci/run-corpus-governance.sh

## evaluation-split: Build a complete, group-aware independent evaluation artifact
evaluation-split:
	@if [ -z "$(CORPUS)" ] || [ -z "$(SPLIT_CONFIG)" ] || [ -z "$(GOVERNANCE_MANIFEST)" ]; then echo "CORPUS, SPLIT_CONFIG, and GOVERNANCE_MANIFEST are required" >&2; exit 1; fi
	$(GO) run ./cmd/cheesewaf-corpus --mode split --corpus "$(CORPUS)" --split-config "$(SPLIT_CONFIG)" --governance-manifest "$(GOVERNANCE_MANIFEST)" $(if $(GOVERNANCE_FORMAL),--governance-formal "$(GOVERNANCE_FORMAL)") $(if $(OUTPUT),--output "$(OUTPUT)") $(if $(MAX_RECORDS),--max-records "$(MAX_RECORDS)") $(if $(MAX_BYTES),--max-bytes "$(MAX_BYTES)")

## evaluation-replay: Replay one governed partition against an independently stored artifact hash
evaluation-replay:
	@if [ -z "$(CORPUS)" ] || [ -z "$(GOVERNANCE_MANIFEST)" ] || [ -z "$(EVALUATION_SPLIT)" ] || [ -z "$(EXPECTED_ARTIFACT_SHA256)" ]; then echo "CORPUS, GOVERNANCE_MANIFEST, EVALUATION_SPLIT, and EXPECTED_ARTIFACT_SHA256 are required" >&2; exit 1; fi
	$(GO) run ./cmd/cheesewaf-corpus --mode evaluate-split --corpus "$(CORPUS)" --governance-manifest "$(GOVERNANCE_MANIFEST)" --evaluation-split "$(EVALUATION_SPLIT)" --expected-artifact-sha256 "$(EXPECTED_ARTIFACT_SHA256)" $(if $(OUTPUT),--output "$(OUTPUT)") $(if $(WORKERS),--workers "$(WORKERS)")

## evaluation-lock: Capture a first-use, non-sensitive lock record for one governed split
evaluation-lock:
	@if [ -z "$(CORPUS)" ] || [ -z "$(GOVERNANCE_MANIFEST)" ] || [ -z "$(EVALUATION_SPLIT)" ] || [ -z "$(LOCK_OUTPUT)" ]; then echo "CORPUS, GOVERNANCE_MANIFEST, EVALUATION_SPLIT, and LOCK_OUTPUT are required" >&2; exit 1; fi
	bash scripts/ci/lock-evaluation-artifact.sh "$(CORPUS)" "$(GOVERNANCE_MANIFEST)" "$(EVALUATION_SPLIT)" "$(LOCK_OUTPUT)"

## blind-lab-test: Run the local blind-lab generator self-tests
blind-lab-test:
	$(GO) test ./scripts/e2e/blind-lab

## blind-lab: Generate a temporary, bounded local blind-lab snapshot (no repository artifacts)
blind-lab: blind-lab-test
	$(GO) run ./scripts/e2e/blind-lab

## security-corpus-http: Run curated attack/benign corpus against a deployed WAF (BASE_URL=http://127.0.0.1:8080)
security-corpus-http:
	@if [ -z "$(BASE_URL)" ]; then echo "BASE_URL is required"; exit 1; fi
	$(GO) run ./cmd/cheesewaf-corpus --mode http --base-url "$(BASE_URL)" $(CORPUS_FLAGS)

## security-gate: Run release security gate against deployed data/admin planes
security-gate:
	@if [ -z "$(BASE_URL)" ]; then echo "BASE_URL is required"; exit 1; fi
	$(GO) run ./cmd/cheesewaf-corpus --mode gate --base-url "$(BASE_URL)" $(if $(ADMIN_URL),--admin-url "$(ADMIN_URL)") $(GATE_FLAGS)

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## deps: Download and tidy dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

## clean: Remove build artifacts
clean:
ifeq ($(OS),Windows_NT)
	@if exist bin rmdir /s /q bin
else
	@rm -rf bin/
endif
