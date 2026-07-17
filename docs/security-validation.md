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

## Release Gate Mode

`cheesewaf-corpus` also has a gate mode for release and acceptance runs:

```bash
go run ./cmd/cheesewaf-corpus --mode gate \
  --base-url http://127.0.0.1:8080 \
  --admin-url https://127.0.0.1:9443 \
  --insecure \
  --output security-gate.json
```

Gate mode runs:

- The in-process semantic analyzer against the curated JSONL corpus.
- The same corpus against the deployed WAF data-plane listener.
- External scanner wrappers when the tools or Docker are available:
  - `sqlmap` against a query-parameter target on the data plane.
  - `xsstrike` against an XSS query-parameter target on the data plane.
  - `nuclei` against repository-owned gate templates in
    `security-validation/nuclei/data` and, when `--admin-url` is supplied,
    `security-validation/nuclei/admin`.
  - OWASP ZAP baseline through `zap-baseline.py` when present, or the official
    ZAP Docker image when Docker is available.

For `sqlmap`, `xsstrike`, and `nuclei`, the runner prefers a local executable
from `PATH`. If it is missing and Docker is available, the runner falls back to
a containerized scanner and rewrites `127.0.0.1` / `localhost` targets to
`host.docker.internal` so containerized tools can reach a local acceptance
listener. ZAP follows the same local-script-first, Docker-second behavior.
Override the default images with:

```bash
CHEESEWAF_SQLMAP_DOCKER_IMAGE=parrotsec/sqlmap:latest
CHEESEWAF_XSSTRIKE_DOCKER_IMAGE=femtopixel/xsstrike:latest
CHEESEWAF_NUCLEI_DOCKER_IMAGE=projectdiscovery/nuclei:latest
CHEESEWAF_ZAP_DOCKER_IMAGE=ghcr.io/zaproxy/zaproxy:stable
```

Missing external tools and missing Docker are reported as `skipped` and counted
as warnings by default. Add `--require-external` to make any skipped or warning
scanner suite fail the gate. The generated JSON report includes
`external_suites`, each with the command, target, status, exit code, finding
count, duration, trimmed output, and any artifact path.

Scanner classification is conservative about positive findings:

- `sqlmap` fails only on strong injection evidence such as identified injection
  points, vulnerable parameters, or payload sections. WAF-protected runs that
  explicitly report all tested parameters as non-injectable are accepted even if
  the scanner logs WAF warnings.
- ZAP baseline keeps the raw exit code in the report. Exit code `2` is accepted
  only when the summary contains `FAIL-NEW: 0` and `FAIL-INPROG: 0`; any ZAP
  fail count still fails the gate.

Use `--skip-external` only for CI/unit-test environments where analyzer and
HTTP replay should be exercised without starting local scanner binaries or
Docker. Release acceptance should not use `--skip-external`.

The checked-in nuclei templates are intentionally negative release checks: they
report a finding only when a SQLi/XSS probe is not blocked/challenged or when a
protected admin entry does not return the expected `418` response. They do not
replace broad public template packs.

## Release Use

Before tagging V0.1 beta, run at least:

```bash
go test -race -count=1 ./cmd/... ./internal/...
cd web && npm ci && npm run build
go run ./cmd/cheesewaf-corpus --mode analyzer
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
go run ./cmd/cheesewaf-corpus --mode gate --base-url http://127.0.0.1:8080 --admin-url https://127.0.0.1:9443 --insecure
```

Then add the heavier external tools where available:

- sqlmap against the deployed data plane
- XSStrike or equivalent XSS corpus replay
- nuclei against the admin and data planes
- OWASP ZAP against the admin plane after login
- CRS/FTW or Coraza/CRS comparison on the same payload families

Results should be stored as release artifacts, not committed if they contain
tokens, URLs, or private deployment details.
