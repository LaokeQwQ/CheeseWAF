# CheeseWAF

CheeseWAF is a Go-based Web Application Firewall scaffold focused on a
single-binary deployment model, a shared management API, and unified Web,
mobile browser, and `waf-cli` TUI operations.

## Current Status

The repository currently includes:

- Reverse proxy WAF flow with staged semantic analysis (input extraction, deep decoding, lexical/syntax/behavior scoring), custom rules, IP/ACL/rate-limit/Bot protection, threat intel import/subscription, signed JS proof-of-work challenge, Altcha-style PoW CAPTCHA, waiting room, edge cache/header/compression policy, and response inspection.
- Shared Web/API/TUI management model with RBAC, audit logs, monitoring, API security, production deployment files, and a single-binary admin listener that serves both the REST API and built Web console. The Web site workspace covers domains, upstreams, TLS material, origin tuning, health checks, response inspection, access control, and rewrite rules.
- Web console hardening includes localized security/category/severity labels, dashboard chart axes and zoom/range controls, resilient event/resource card layouts, API security table layout isolation, route-level lazy loading, and Natural Earth/world-atlas based 2D/continent/interactive Three.js 3D attack-map views with zoom/pan controls, attack-intensity coloring, precise-location fallbacks, WebGL fallback handling, responsive tables, and real log data. The 3D globe renderer is split into an on-demand chunk so ordinary console pages and 2D maps do not load Three.js up front.
- GeoIP protection supports user-defined country CIDR overrides plus MaxMind-compatible `.mmdb` databases; proxy logs are enriched with `metadata.geo` country/city/region/lat/lon/accuracy/ASN fields so attack maps and reports can use real location data when a valid City database or threat-intel feed is configured.
- Safe admin defaults: the CLI bootstraps runtime config under `./data`, the admin listener defaults to localhost, public admin binding requires `server.admin_public: true` plus `server.admin_tls`, and first-run setup can choose local/tunnel/reverse-proxy access or public HTTPS with a generated local CA-signed admin certificate.
- Smart protection policy controls for global and site-level Web attack, API security, Bot/CC, and threat-intel levels (`off`, `low`, `smart`, `high`, `strict`); empty site levels inherit the global default. Web attack protection now applies runtime severity/confidence thresholds (`low`: critical/0.90, `smart`: high/0.85, `high`: medium/0.78, `strict`: low/0.65) while respecting monitor/log-only detector modes and preserving detector-requested JS challenges.
- AI operations surfaces for real attack/block/challenge event analysis, per-event recommendations, and a console assistant backed by recent WAF events and monitor snapshots.
- First-run setup wizard and REST setup API now share one completion service for validation, admin creation, SQLite migration, default config/certificate generation, and setup completion locking. The generated admin certificate bundle uses an ECDSA P-256 local CA (`CN=CheeseWAF Sign SSL CA`, `O=CheeseCloud Technology Ltc.`) and a server-auth leaf chain.
- Prometheus metrics, alert evaluation, remote write, and queryable multi-sink logs for local file, ClickHouse, VictoriaLogs, PostgreSQL, and Elasticsearch.
- Forgejo Actions CI as the primary build target, plus GitHub Actions as a secondary mirror check, covering PR flow validation, Go tests, web build, and cross-platform builds. Forgejo uses local/mirrored Go and Node toolchain bootstrap scripts to avoid self-hosted runner timeouts against GitHub tool-cache downloads.

Runtime Bot challenge secrets are generated per install. If an old config still
contains an empty value or `change-me-in-production`, CheeseWAF rotates it at
startup and saves the repaired runtime config.

## Development

```bash
go test ./cmd/... ./internal/...
go test -race -count=1 ./cmd/... ./internal/...
go build -trimpath -o bin/cheesewaf ./cmd/cheesewaf/
cd web && npm ci && npm run build
```

Private local planning files such as `task.md` and `implementation_plan.md` are
intentionally ignored by Git.

Semantic engine maturity is tracked in `docs/semantic-readiness.md`; the current
claim is "working and explainable", not "ModSecurity/OWASP CRS parity".

## Stage Snapshot

As of 2026-06-07, the active development line is `fix/admin-ui-dashboard-map`
with PR #8 targeting `dev`. Forgejo at `git.laoker.cc/Laoke/CheeseWAF` is the
primary forge/build target; GitHub remains a secondary mirror/check. `master`
and `canary` intentionally remain behind `dev` until the upward promotion flow
is completed. The Forgejo workflow is present under `.forgejo/workflows/ci.yml`
and uses `scripts/ci/setup-go-mirror.sh` plus `scripts/ci/setup-node-mirror.sh`
for self-hosted runner-friendly toolchain setup.

## Pre-Release Gaps

- The admin plane must be treated as a production security boundary: keep it
  behind TLS or a trusted reverse proxy, bind it to localhost/private networks by
  default, and avoid exposing browser tokens over plain HTTP.
- Before a public release, run repeatable sqlmap, XSStrike, nuclei, OWASP ZAP,
  CRS/Coraza or ModSecurity comparison, and admin-surface security tests.
- Web attack protection levels are wired into runtime severity/confidence
  thresholds. The default `smart` mode is tuned for lower false positives, but
  the exact thresholds still need corpus-backed iteration before GA.
- City/district-level map precision depends on a valid GeoIP City `.mmdb` or
  external threat-intel location feed. Without one, CheeseWAF intentionally
  degrades to country/CIDR-level attribution rather than inventing coordinates.
- The web console still has large shared vendor chunks, mainly from the UI stack
  and 3D globe dependency. Route-level lazy loading and map-data slimming are in
  place; a future pass should add stable vendor chunk grouping and measure cold
  start on low-end mobile browsers.
