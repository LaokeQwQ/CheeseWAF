<p align="center">
  <img src="web/public/cheesewaf-logo.png" alt="CheeseWAF logo" width="128">
</p>

<h1 align="center">CheeseWAF</h1>

<p align="center">
  Self-hosted Web Application Firewall in Go.<br>
  Reverse proxy in front of your origin, plus one admin API, web console, and terminal UI.
</p>

<p align="center">
  <a href="README.md">English</a> ·
  <a href="README_CN.md">简体中文</a> ·
  <a href="LICENSE">Apache-2.0</a>
</p>

> Pre-release. Config and APIs can still change. Try it in a controlled environment before you put production traffic through it.

## Contents

- [What it does](#what-it-does)
- [How it fits](#how-it-fits)
- [Protection levels](#protection-levels)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Development](#development)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [Before a public release](#before-a-public-release)
- [License](#license)

## What it does

CheeseWAF sits between clients and your origin. The data plane inspects HTTP requests and responses. The admin plane (localhost by default) configures sites, rules, users, logs, and runtime state.

- **Web attacks.** Staged semantic analysis for SQL injection, XSS, RCE, LFI, XXE, SSRF, NoSQL injection, SSTI, and related families. Custom rules and optional response inspection.
- **False-positive first blocking.** Isolated gadgets (almost only attack bytes in one decoded field) can block from level 2. Embedded gadgets inside prose pass at 2–4 and only block at level 5.
- **Review queue.** Suspicious requests that were not blocked (and level-5 blocks) go to `/review`. An operator can add a lasting payload, URL, IP, or client-fingerprint block, or allow and whitelist. The configured site model is asked in the background and does not stall the request.
- **Bot and traffic control.** Rate limits, JS proof-of-work, image CAPTCHA, slider CAPTCHA, and a waiting room.
- **API security.** Request schema checks, endpoint rate limits, and JWT checks (HMAC, PEM, or JWKS).
- **Access control.** Global, site, and path IP rules, reputation, GeoIP, and trusted-proxy bindings per vendor CIDR.
- **Operations.** One data model for the web console, REST API, and `waf-cli`. RBAC, revocable sessions, audit log, Prometheus metrics, and several log backends.
- **Deploy.** Docker Compose, systemd, and Windows packaging. Optional cluster join, certificate rotation, and rolling upgrade.

It does **not** replace origin authentication. It does **not** delete posts from a third-party CMS. It does **not** use a large language model as the primary detector.

## How it fits

```text
Client  --->  CheeseWAF data plane  --->  origin
                      |
                      +-- Admin API / web console / waf-cli
                      +-- Logs / metrics / reports
```

Default listeners after a local start:

| Plane | Address |
| --- | --- |
| Data plane | `http://127.0.0.1:8080` |
| Admin (setup) | `http://127.0.0.1:9443/setup` or `https://127.0.0.1:9443/setup` in Docker |

## Protection levels

Site field: `waf.paranoia_level`. New sites default to **3**. An omitted YAML value is 3. An explicit `0` stays record-only.

| Level | Isolated gadget | Embedded in prose |
| --- | --- | --- |
| 0–1 | record only | record only |
| 2–4 | block | pass, ask the model, enqueue review |
| 5 | block | block, still ask the model |

Level 4 can briefly promote the site to level 5 after an embedded hit (`promote_seconds`). That window is stored in SQLite and survives restart.

Client fingerprint for one-click deny is `SHA-256(User-Agent + "\n" + Accept-Language)`, first 8 bytes as 16 hex characters. It is not JA3.

Details: [docs/protection-policy-roadmap.md](docs/protection-policy-roadmap.md).

## Quick start

### Docker Compose

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF
docker compose -f deploy/docker/docker-compose.yml up -d --build
docker compose -f deploy/docker/docker-compose.yml logs -f cheesewaf
```

Then open `https://127.0.0.1:9443/setup`. The container uses a self-signed admin certificate. The first-run setup token is written only to the start log. After setup, change the sample site upstream to your real origin.

```bash
docker compose -f deploy/docker/docker-compose.yml down
```

Data lives in Compose named volumes. `down` does not delete those volumes.

### From source

Needs **Go 1.26.6** and **Node.js 24.18.0** (same major version is enough for the console).

```bash
git clone https://github.com/LaokeQwQ/CheeseWAF.git
cd CheeseWAF

cd web
npm ci
npm run build
cd ..

go run ./cmd/cheesewaf serve
```

First start creates runtime config, SQLite, and cert directories under `data/`. Open `http://127.0.0.1:9443/setup`.

## Configuration

Local start writes `data/cheesewaf.yaml`. The checked-in example is [configs/cheesewaf.yaml](configs/cheesewaf.yaml).

| Section | Role |
| --- | --- |
| `server` | Data-plane and admin listen addresses and TLS |
| `sites` | Domains, origins, detection policy, allowlists, rewrite |
| `protection` | Global levels, IP, rate limit, bot, API security |
| `storage` / `logging` / `monitor` | Database, log backends, metrics and alerts |
| `ai` | Optional site model used by the review queue and console |

The admin plane binds `127.0.0.1` by default. Public listen requires both `server.admin_public: true` and admin TLS.

## Development

```bash
go test ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...

cd web
npm ci
npm run typecheck
npm test
npm run build
```

Replay built-in semantic samples:

```bash
go run ./cmd/cheesewaf-corpus --mode analyzer
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
```

Integration path: `feature/*` → `dev` → `canary` → `master`. Merge only after required checks are green.

## Repository layout

| Path | Contents |
| --- | --- |
| `cmd/` | Server, corpus runner, Windows controller |
| `internal/` | Proxy, detection, admin API, storage, cluster |
| `web/` | React admin console |
| `configs/` | Example YAML |
| `deploy/` | Docker, systemd, Windows |
| `docs/` | Product and engine notes |
| `scripts/ci/` | Build, package, and CI helpers |

## Documentation

| Document | Topic |
| --- | --- |
| [docs/protection-policy-roadmap.md](docs/protection-policy-roadmap.md) | Levels 0–5, review queue, what we will not do |
| [docs/paranoia-level-implementation.md](docs/paranoia-level-implementation.md) | How those levels are wired |
| [docs/performance-optimization.md](docs/performance-optimization.md) | Runtime and analyzer notes |

## Before a public release

- Keep the admin plane on TLS or a trusted reverse proxy. Do not expose browser tokens on plain HTTP.
- Prometheus scrape is private by default. Use authenticated `/api/metrics`, or set `monitor.prometheus.public: true` on purpose.
- Run `cheesewaf-corpus --mode gate` against a deployed data plane and admin plane before you call a build a release. `--skip-external` is for CI replay, not release evidence.
- Default `smart` policy favors fewer false positives. Tune on real traffic and your own samples. Built-in corpora are regression tests, not a claim of ModSecurity / Coraza / OWASP CRS parity.
- City-level maps need a GeoIP City database or an external location source. Without that, CheeseWAF stays at country / CIDR attribution.

## License

[Apache License 2.0](LICENSE).
