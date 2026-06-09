# CheeseWAF

[English](README.md) | [简体中文](README_CN.md)

CheeseWAF is a Go-based Web Application Firewall scaffold focused on a
single-binary deployment model, a shared management API, and unified Web,
mobile browser, and `waf-cli` TUI operations.

## Current Status

The repository currently includes:

- Reverse proxy WAF flow with staged semantic analysis (input extraction, deep decoding, lexical/syntax/behavior scoring), custom rules, IP/ACL/rate-limit/Bot protection, threat intel import/subscription, signed JS proof-of-work challenge, Altcha-style PoW CAPTCHA, waiting room, edge cache/header/compression policy, and response inspection.
- Semantic regression coverage now includes function-based and error-based SQLi, MySQL executable version comments, PostgreSQL delay payloads, hex tautology, `ORDER BY`/`HAVING` inference, regex value probes, `PROCEDURE ANALYSE`, `xp_cmdshell`, and `into outfile` SQLi shapes; control-character/HTML-entity/data-URI/srcdoc/meta-refresh/CSS-expression/formaction/srcset XSS contexts; `${IFS}`/PowerShell/Pwsh/`cmd /c`/download-to-shell RCE variants; LFI Kubernetes-token, process-environment, and overlong-traversal cases; SSRF IPv6/IPv4-mapped IPv6/dotted-hex/dotted-octal/single-integer-hex/dynamic-DNS/file-scheme forms; Mongo/NoSQL operator, `$expr`, and `$function` injection for login/query contexts; SSTI object-graph/runtime/Twig/ERB execution chains; direct detector bypass samples; and paired benign cases that protect common documentation text from false positives. Maturity and benchmark details live in `docs/semantic-readiness.md`, and public corpus sourcing is tracked in `docs/semantic-corpus-sources.md`.
- Repeatable semantic validation now has a dedicated `cheesewaf-corpus` runner. It replays the curated JSONL corpus against either the in-process analyzer or a deployed WAF listener and emits a JSON report with detection rate, false-positive rate, per-case latency, and failure evidence. Older site YAML files that predate newly added semantic engines backfill missing engine switches to safe defaults unless the operator explicitly sets them to `false`. The release-gate workflow is documented in `docs/security-validation.md`.
- Shared Web/API/TUI management model with RBAC, audit logs, monitoring, API security, production deployment files, and a single-binary admin listener that serves both the REST API and built Web console. The Web site workspace covers domains, upstreams, TLS material, origin tuning, health checks, per-site semantic toggles including NoSQLi and SSTI, response inspection, access control, and rewrite rules.
- Management API authorization is now route-scoped: every non-public admin API requires a Bearer token, realtime streams are no longer public, read routes require `read:*`-style permissions, and all mutating routes are guarded by focused `write:*` permissions for system, users, sites, rules, protection, threat intel, edge, AI, storage, and ops. Router regression tests verify unauthorized access, cookie-only CSRF-style requests, and readonly write attempts.
- Admin tokens carry a unique token ID backed by a revocable server-side session. Login creates a session, `/api/auth/refresh` atomically revokes the old token ID and issues a new one, and `/api/auth/logout` revokes the current session before the Web console clears local state. Password/role and 2FA changes revoke existing sessions for the affected user, and expired/revoked sessions are pruned during login. The Web console refreshes valid near-expiry tokens before requests, while expired or invalid tokens still fall through to the normal 401 logout flow.
- Admin login now uses a configurable console login profile: `/api/auth/captcha` issues a server-generated graphical slider CAPTCHA by default, while browser PoW remains available as either a standalone mode or an optional slider hardening switch. The slider target is kept in an encrypted, client-bound token and login submissions must pass server-side slider-position, expiry, and drag-duration checks before password/2FA validation; when auxiliary PoW is enabled it is verified on the same backend path. System Settings can toggle CAPTCHA mode, tune slider tolerance/min-drag/optional PoW limits, and configure a security entry path that returns an Nginx-style `418 I'm a teapot` page for direct admin-port access or wrong entrances while the correct entrance sets an HttpOnly cookie with the same lifetime as the login session. The login page no longer hints default credentials, shows unobtrusive load timing below the login card, and supports operator-defined image or video background URLs through `console.login.background`.
- Web console hardening includes localized security/category/severity labels, dashboard total-vs-live posture separation, 1/3/5/10s live refresh controls, selectable total-stat windows, chart axes, legend, zoom buttons, range-slider scaling, resilient event/resource card layouts, URL-addressable IP-management tabs, API security table layout isolation, route-level lazy loading, and Natural Earth/world-atlas based 2D/China-mainland/interactive Three.js 3D attack-map views with zoom/pan controls, attack-intensity coloring, country-level GeoIP fallbacks, precise-location metadata support, WebGL fallback handling, responsive tables, and real log data. The China-mainland mode now uses its own mainland projection, real reference-city anchors, mainland-only filtering, and hover/zoom detail labels instead of a cropped world map. The 3D globe renderer is split into an on-demand chunk so ordinary console pages and 2D maps do not load Three.js up front.
- The Dashboard resource panel now reads real host metrics from the monitor snapshot: CPU usage, 1-minute system load with CPU-core context, host memory usage, swap usage, disk usage, and a separate process-runtime line for goroutines/heap. Live posture and resources auto-refresh at the selected 1/3/5/10s interval, support manual refresh, display disabled swap explicitly when the host has no swap device, and expose real memory/swap reclaim actions through the protected system API.
- Attack/block events now have a dedicated detail view under `/logs/:traceId`, reachable from the Dashboard, attack log table, and AI event table. The detail page shows request evidence, detector metadata, payload/user-agent context, and runs single-event AI analysis against the real log entry.
- Scheduled security reports can generate daily or weekly Markdown/JSON summaries from real WAF logs and deliver them to a local report directory or webhook. Reports include the time window, total and security-event counts, block/challenge/log-only totals, unique source IPs, action/severity/category/site/country breakdowns, top security source IPs, attacked URIs, detectors, and recent high-risk events while excluding ordinary pass traffic from risk rankings.
- Frontend build output uses stable Vite/Rolldown vendor chunks for React, Arco, Three.js, visualization, runtime, and UI utility dependencies. Production source maps are disabled unless `VITE_SOURCEMAP=true` is set, keeping the released Web console payload small, while the large Three.js dependency stays isolated to the attack-map path.
- The latest admin UI quality pass hardens Rules, IP Control, Protection Policy, Operations, Updates & Vulnerability Feeds, Block Pages, Dashboard, AI Operations, and System Settings against failed API calls, cramped search inputs, overflowing tags, blank controlled selects, action-button squeeze, false online states, and mixed settings layouts. The console now favors explicit loading/error/empty states, scoped action footers, responsive token/chip groups, grouped settings sections, mobile IP profile cards with real allow/block/reputation actions, AI assistant safe-area spacing, clickable health reconnect status, separated notification/account menus, and browser-verified layouts instead of placeholder or decorative-only UI.
- GeoIP protection supports user-defined country CIDR overrides plus MaxMind-compatible `.mmdb` databases; proxy logs are enriched with `metadata.geo` country/city/region/lat/lon/accuracy/ASN fields so attack maps and reports can use real location data when a valid City database or threat-intel feed is configured.
- Threat-intel indicators now carry action and confidence, are scored across severity/confidence/source count, and are enforced in the proxy hot path according to the global/site `threat_intel` level. Console imports, provider sync, lookups, and protection setting updates trigger runtime policy refresh without requiring a service restart.
- IP access control now supports global, site-level, and directory/path-level allow/block rules in addition to the legacy global whitelist/blacklist. Allow rules keep the existing allowlist bypass semantics for IP-based protections, block rules stop requests before upstream proxying, and IP profiles can apply manual 0-100 reputation overrides. Site access control can define trusted proxy/CDN CIDRs; only trusted remote proxies are allowed to supply real-client headers such as `CF-Connecting-IP`, `True-Client-IP`, `Fastly-Client-IP`, `Fly-Client-IP`, `DO-Connecting-IP`, `Ali-CDN-Real-IP`, `CDN-Src-IP`, `X-CDN-Src-IP`, `X-Azure-ClientIP`, `X-Vercel-Forwarded-For`, `X-Original-Forwarded-For`, `X-Real-IP`, `X-Forwarded-For`, and RFC `Forwarded`.
- Safe admin defaults: the CLI bootstraps runtime config under `./data`, the admin listener defaults to localhost, public admin binding requires `server.admin_public: true` plus `server.admin_tls`, and first-run setup can choose local/tunnel/reverse-proxy access or public HTTPS with a generated local CA-signed admin certificate.
- The single-binary admin handler applies baseline browser safety headers to API, SPA fallback, and static assets: an enforcing `Content-Security-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a locked-down `Permissions-Policy`, and HSTS on HTTPS admin responses. Static admin assets get immutable cache headers and gzip compression when the browser supports it, while SPA entry responses stay `no-cache`.
- Smart protection policy controls for global and site-level Web attack, API security, Bot/CC, and threat-intel levels (`off`, `low`, `smart`, `high`, `strict`); empty site levels inherit the global default. Web attack protection now applies runtime severity/confidence thresholds (`low`: critical/0.90, `smart`: high/0.85, `high`: medium/0.78, `strict`: low/0.65) while respecting monitor/log-only detector modes and preserving detector-requested JS challenges. API security schema validation, endpoint rate-limit findings, and JWT claims-profile anomalies now follow the same level model, so low mode can record and pass lower-confidence API findings while smart mode blocks validated schema/rate-limit/auth breaches; system APISec setting updates rebuild the proxy validator, endpoint limiter, and auth checker without restarting the service.
- Bot/CC protection levels are also enforced at runtime: suspicious bot detections and CC/rate-limit breaches are evaluated by severity/confidence thresholds, low-signal matches can be logged without blocking, and explicitly enabled waiting rooms remain active as traffic control.
- API authentication can now enforce WAF-side Bearer JWT signature validation with configured HMAC secrets, PEM public keys/certificates, local JWKS JSON/files, or remote JWKS subscriptions with cache files and background refresh, then apply issuer, audience, expiry, and scope checks through the same smart protection-policy model. Endpoint-level auth policies can override issuer/audience/scope requirements by method and path regex. Runtime APISec updates rebuild schema validation, endpoint rate limiting, and JWT auth without restarting the proxy, and disabled API auth skips JWT/JWKS initialization so optional cache paths cannot block service startup. The Web console exposes JWT signing, remote JWKS, and endpoint-policy settings under System Settings.
- AI operations surfaces for real attack/block/challenge event analysis, selectable time-window batch analysis, per-event recommendations, and a chat-style console assistant backed by recent WAF events and monitor snapshots. Single-event analysis and assistant replies expose provider/model metadata plus token usage when the provider returns it; assistant replies also include safe process summaries, live thinking-state timing, response timing, output-token speed, and timestamps without exposing hidden chain-of-thought. AI providers are configured as OpenAI-standard or Anthropic-standard endpoints with provider-specific authentication headers, and saved API keys are never returned to the Web console. AI prompts treat logs, payloads, runtime context, and operator questions as untrusted data, with explicit guardrails against prompt injection, secret disclosure, tool execution, and unapproved policy changes.
- First-run setup wizard and REST setup API now share one completion service for validation, admin creation, SQLite migration, default config/certificate generation, and setup completion locking. The generated admin certificate bundle uses an ECDSA P-256 local CA (`CN=CheeseWAF Sign SSL CA`, `O=CheeseCloud Technology Ltc.`) and a server-auth leaf chain.
- Prometheus metrics, alert evaluation, remote write, and queryable multi-sink logs for local file, ClickHouse, VictoriaLogs, PostgreSQL, and Elasticsearch. Metrics are available through authenticated `/api/metrics` by default; the bare scrape path such as `/metrics` is only exposed when `monitor.prometheus.public: true` is set explicitly.
- Forgejo Actions CI as the primary build target, plus GitHub Actions as a secondary mirror check, covering PR flow validation, Go tests, web build, cross-platform builds, and branch-channel release artifacts. Pushes to `dev`, `canary`, and `master` build distinct `dev`, `canary`, and `stable` packages on both platforms. Forgejo uses local/mirrored Go and Node toolchain bootstrap scripts to avoid self-hosted runner timeouts against GitHub tool-cache downloads.

Runtime Bot challenge secrets are generated per install. If an old config still
contains an empty value or `change-me-in-production`, CheeseWAF rotates it at
startup and saves the repaired runtime config.

## Development

```bash
go test ./cmd/... ./internal/...
# On restricted Windows shells, keep the Go build cache inside the workspace:
# PowerShell: $env:GOCACHE="$PWD\tmp\go-build-cache"; go test ./cmd/... ./internal/...
go test -race -count=1 ./cmd/... ./internal/...
go run ./cmd/cheesewaf-corpus --mode analyzer
# Against a deployed data-plane listener:
# go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
go build -trimpath -o bin/cheesewaf ./cmd/cheesewaf/
cd web && npm ci && npm run build
```

Private local planning files such as `task.md` and `implementation_plan.md` are
intentionally ignored by Git.

Semantic engine maturity is tracked in `docs/semantic-readiness.md`; the
repeatable security corpus gate is documented in `docs/security-validation.md`.
The current claim is "working and explainable", not "ModSecurity/OWASP CRS
parity".

## Branch Release Artifacts

GitHub Actions and Forgejo Actions both package branch-specific artifacts after
successful pushes to the protected branch chain:

| Branch | Channel | Version pattern |
| --- | --- | --- |
| `dev` | `dev` | `0.1.0-dev.<run>+<commit>` |
| `canary` | `canary` | `0.1.0-canary.<run>+<commit>` |
| `master` | `stable` | `0.1.0-beta.<run>+<commit>` |

Each artifact bundle includes the `cheesewaf` binary, a `waf-cli` alias/copy,
the built Web console, README files, `LICENSE`, `VERSION`, `release.json`, and a
top-level `SHA256SUMS` file. The shared packaging script lives at
`scripts/ci/package-release.sh` so GitHub and Forgejo build the same payloads.

## Stage Snapshot

As of 2026-06-09, the latest hardening release-flow batch has completed the
protected upward promotion flow on GitHub: PR #49 merged
`fix/login-slider-performance -> dev`, PR #50 promoted `dev -> canary`, and PR
#51 promoted `canary -> master`. Forgejo at `git.laoker.cc/Laoke/CheeseWAF` is the
primary forge/build target; GitHub remains a secondary mirror/check. A Forgejo
mirror-sync was triggered after the GitHub merges, and Forgejo matched the same
snapshot heads: `dev` (`9c1ba54`), `canary` (`4eda681`), and `master`
(`ebc62ae`). Those three protected branches had the same tree content while
retaining their required upward PR merge commits. The Forgejo workflow is
present under `.forgejo/workflows/ci.yml` and uses
`scripts/ci/setup-go-mirror.sh` plus `scripts/ci/setup-node-mirror.sh` for
self-hosted runner-friendly toolchain setup.

The current hardening pass covers curated public-corpus-inspired semantic
fixtures, real dashboard counters, live-vs-total posture separation, scoped
Dashboard chart sizing, real host CPU/load/memory/swap/disk resource metrics,
resource reclaim actions, single-event log detail/AI analysis, URL-addressable
IP threat-intel/access-list tabs with scoped allow/block rules, trusted
proxy/CDN real-client IP parsing, manual IP reputation overrides, honest
health/reconnect states, less abstract
2D/China-mainland/3D attack-map modes, APISec JWT
signing/audience/remote-JWKS/endpoint-policy controls, route-scoped management
API RBAC, and synchronized GitHub/Forgejo branch-channel artifacts for `dev`,
`canary`, and `stable`, plus richer scheduled security reports. The promoted
`master` snapshot `ebc62ae` has been
deployed to the remote acceptance host and smoke tested: admin health/index
return 200, the proxy home route returns 200, a SQLi probe is blocked with 403,
the deployed HTTP corpus replays 40/40 cases with 30/30 attacks blocked and
10/10 benign cases not blocked, and HTTPS admin responses include frame,
nosniff, referrer, permissions, and HSTS safety headers. The next release step
is to add repeatable external dynamic scanner evidence before tagging V0.1 beta.

## Pre-Release Gaps

- The admin plane must be treated as a production security boundary: keep it
  behind TLS or a trusted reverse proxy, bind it to localhost/private networks by
  default, and avoid exposing browser tokens over plain HTTP.
- Bare Prometheus scraping is private by default. Prefer authenticated
  `/api/metrics` or expose `monitor.prometheus.path` only on a trusted listener;
  set `monitor.prometheus.public: true` deliberately when an external scraper
  needs direct access.
- Before a public release, run repeatable sqlmap, XSStrike, nuclei, OWASP ZAP,
  CRS/Coraza or ModSecurity comparison, and `cheesewaf-corpus` analyzer plus
  deployed HTTP replay. Admin-surface route-level authentication/RBAC tests are
  now automated, but deployed dynamic scans should still be repeated before
  tagging V0.1 beta.
- Web attack, API security, Bot/CC, and threat-intel protection levels are wired
  into runtime severity/confidence or score thresholds. The default `smart` mode
  is tuned for lower false positives, but the exact thresholds still need
  corpus-backed iteration before GA.
- API auth checks now support configured JWT signature validation, audience
  validation, endpoint-level issuer/audience/scope policies, and remote JWKS
  refresh with SSRF-conscious HTTPS-only fetching plus cache-file fallback. They
  still do not replace source application authentication, and CheeseWAF
  intentionally does not fetch remote JWKS URLs in the proxy hot path.
- City/district-level map precision depends on a valid GeoIP City `.mmdb` or
  external threat-intel location feed. Without one, CheeseWAF intentionally
  degrades to country/CIDR-level attribution rather than inventing coordinates;
  the China-mainland view only shows mainland-scoped real positions or the safe
  country-level CN fallback.
- The web console now has route-level lazy loading, map-data slimming, and
  stable vendor chunk grouping. The remaining large chunk is primarily the
  on-demand Three.js 3D map dependency; measure cold start on low-end mobile
  browsers before GA.
- Browser-level visual regression now has a local Chrome Canary headless smoke
  path with desktop/mobile screenshots and DOM-overflow assertions. Before
  tagging V0.1 beta, repeat it against the deployed admin console and add a
  tablet viewport.
