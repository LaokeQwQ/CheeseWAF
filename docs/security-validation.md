# Security Validation Gate

CheeseWAF uses repeatable validation gates before beta/stable releases. These
checks are evidence for the current build only; they do not prove parity with
SafeLine, ModSecurity, Coraza, or OWASP CRS by themselves.

## Curated Semantic Corpus

The curated corpus lives at:

```text
internal/engine/semantic/testdata/curated_external_shapes.jsonl
```

Each line is a reviewed case with:

- `label=attack` or `label=benign`
- `category` for attack cases
- HTTP method, target, optional content type, body, and headers
- `source_family` and `rationale`

Run against the in-process semantic analyzer:

```bash
go run ./cmd/cheesewaf-corpus --mode analyzer
```

Run against a deployed WAF data-plane listener:

```bash
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
```

For a self-signed HTTPS test listener:

```bash
go run ./cmd/cheesewaf-corpus --mode http --base-url https://127.0.0.1:9443 --insecure
```

The HTTP runner treats `403,406,429,451,503` as WAF block/challenge statuses by
default. A benign case passes when it is not blocked by the WAF, even if the
origin returns `404`.

When deployed replay misses body-based classes such as NoSQLi or SSTI, first
check the active site `semantic_engines` settings. CheeseWAF backfills newly
added engine switches for older YAML configs on load, but an operator can still
disable a class explicitly.

The runner emits JSON with detection rate, false-positive rate, total duration
in `duration_ms`, per-case `latency_ms`, and per-case evidence. A non-zero
failure count exits non-zero.

## Release Use

Before tagging V0.1 beta, run at least:

```bash
go test -race -count=1 ./cmd/... ./internal/...
cd web && npm ci && npm run build
go run ./cmd/cheesewaf-corpus --mode analyzer
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
```

Then add the heavier external tools where available:

- sqlmap against the deployed data plane
- XSStrike or equivalent XSS corpus replay
- nuclei against the admin and data planes
- OWASP ZAP against the admin plane after login
- CRS/FTW or Coraza/CRS comparison on the same payload families

Results should be stored as release artifacts, not committed if they contain
tokens, URLs, or private deployment details.
