# CheeseWAF Makefile
# ==================

BINARY_NAME  := cheesewaf
CLI_NAME     := waf-cli
MODULE       := github.com/LaokeQwQ/CheeseWAF
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT       := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo "unknown")
BUILD_TIME   := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
CHANNEL      := $(shell branch=$$(git branch --show-current 2>/dev/null || echo dev-local); case "$$branch" in master|main) echo stable ;; canary) echo canary ;; dev) echo dev ;; *) echo dev-local ;; esac)
LDFLAGS      := -s -w -X '$(MODULE)/internal/version.Version=$(VERSION)' -X '$(MODULE)/internal/version.Commit=$(COMMIT)' -X '$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)' -X '$(MODULE)/internal/version.Channel=$(CHANNEL)'

GO           := go
GOFLAGS      := -trimpath
CGO_ENABLED  := 0

.PHONY: all build build-cli run test test-go web-build security-corpus security-corpus-http security-gate lint clean dev help

## help: Show this help message
help:
	@echo "CheeseWAF Makefile Commands:"
	@echo ""
	@echo "  make build       Build cheesewaf binary"
	@echo "  make build-cli   Build and create waf-cli symlink"
	@echo "  make run         Run cheesewaf serve"
	@echo "  make dev         Run with hot-reload (requires air)"
	@echo "  make test        Run all tests"
	@echo "  make web-build   Build the web dashboard"
	@echo "  make security-corpus      Run curated semantic corpus against analyzer"
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
package-windows-cli: build build-windows-gui
	@mkdir -p dist/windows-cli/configs dist/windows-cli/data dist/windows-cli/logs
	@cp -f bin/$(BINARY_NAME).exe dist/windows-cli/ 2>/dev/null || cp -f bin/$(BINARY_NAME) dist/windows-cli/ || true
	@cp -f bin/$(BINARY_NAME)-gui.exe dist/windows-cli/cheesewaf-gui.exe 2>/dev/null || \
		cp -f bin/$(BINARY_NAME)-gui-windows-amd64.exe dist/windows-cli/cheesewaf-gui.exe 2>/dev/null || true
	@cp -f bin/$(BINARY_NAME).exe dist/windows-cli/waf-cli.exe 2>/dev/null || true
	@cp -f configs/cheesewaf.yaml dist/windows-cli/configs/ 2>/dev/null || true
	@echo "Staged dist/windows-cli — zip manually; do not embed secrets"

## package-windows-nsis-payload: Stage SOURCE_DIR for makensis (no secrets)
package-windows-nsis-payload: package-windows-cli
	@mkdir -p dist/windows-payload/configs
	@cp -f dist/windows-cli/cheesewaf.exe dist/windows-payload/ 2>/dev/null || true
	@cp -f dist/windows-cli/cheesewaf-gui.exe dist/windows-payload/ 2>/dev/null || true
	@cp -f dist/windows-cli/waf-cli.exe dist/windows-payload/ 2>/dev/null || true
	@cp -f dist/windows-cli/configs/cheesewaf.yaml dist/windows-payload/configs/ 2>/dev/null || true
	@echo "Staged dist/windows-payload for: makensis /DVERSION=... /DSOURCE_DIR=dist/windows-payload deploy/windows/nsis/cheesewaf.nsi"

## build-linux: Cross-compile for Linux amd64
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-amd64 ./cmd/cheesewaf/
	@cp bin/$(BINARY_NAME)-linux-amd64 bin/$(CLI_NAME)-linux-amd64

## build-darwin: Cross-compile for macOS arm64 (Apple Silicon)
build-darwin:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BINARY_NAME)-darwin-arm64 ./cmd/cheesewaf/
	@cp bin/$(BINARY_NAME)-darwin-arm64 bin/$(CLI_NAME)-darwin-arm64

## build-all: Build for all platforms (Linux amd64/arm64, macOS amd64/arm64, Windows amd64/arm64)
build-all:
	@echo "Building for all platforms..."
	@for goos in linux darwin windows; do \
		for goarch in amd64 arm64; do \
			ext=""; \
			if [ "$$goos" = "windows" ]; then ext=".exe"; fi; \
			echo "  → $$goos/$$goarch"; \
			GOOS=$$goos GOARCH=$$goarch CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" \
				-o bin/$(BINARY_NAME)-$$goos-$$goarch$$ext ./cmd/cheesewaf/; \
			cp bin/$(BINARY_NAME)-$$goos-$$goarch$$ext bin/$(CLI_NAME)-$$goos-$$goarch$$ext; \
		done; \
	done
	@echo "Done! All binaries in bin/"

## run: Run cheesewaf serve
run: build
	./bin/$(BINARY_NAME) serve

## dev: Run with hot-reload (requires: go install github.com/air-verse/air@latest)
dev:
	air -c .air.toml

## test: Run all tests
test: test-go web-build

## test-go: Run Go tests
test-go:
	$(GO) test -v -race -count=1 ./cmd/... ./internal/...

## web-build: Build the React dashboard
web-build:
	cd web && npm ci && npm run build

## security-corpus: Run curated attack/benign corpus against the semantic analyzer
security-corpus:
	$(GO) run ./cmd/cheesewaf-corpus --mode analyzer

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
