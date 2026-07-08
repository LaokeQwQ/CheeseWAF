# Phase 4 Operations

## Monitoring

- Prometheus scrape path: `/metrics`.
- JSON monitor summary: `/api/monitor`.
- Alerts are configured under `monitor.alerts.rules`.
- Webhook style notifications are configured under `monitor.notifiers`.
- `monitor.remote_write` and `monitor.notifiers[*].endpoint` use SSRF-aware
  HTTP clients by default. They allow only `http` / `https`, reject URL
  credentials and fragments, block loopback/private/link-local/cloud metadata
  targets, and re-check DNS results before dialing. Set
  `allow_private_endpoint: true` only for trusted internal monitoring or
  notification services.
- `waf-cli` exposes a local monitoring summary for no-browser server sessions.

## Console Map Boundary Sources

- China-region map boundary rendering is configured under
  `console.map.china_boundary`.
- Local file sources should point to licensed GeoJSON/JSON FeatureCollection
  data and include either `license` or `review_id`.
- Remote URL sources use the same SSRF-aware outbound guard as other controlled
  background fetchers. HTTPS is required by default; URL credentials, fragments,
  loopback/private/link-local/cloud metadata targets, and DNS results resolving
  to non-public addresses are blocked.
- Set `allow_insecure: true` only when an operator knowingly trusts an HTTP
  source, and set `allow_private: true` only for a trusted internal map service.

## API Security

- Discovered endpoints are available at `/api/apisec/endpoints`.
- Request schema validation can be tested with `/api/apisec/validate`.
- Endpoint rate limits are configured under `apisec.rate_limits`.
- Scoped management API tokens are configured under
  `apisec.management_api` and documented in `docs/management-api.md`.
- Management API tokens are disabled by default, use
  `Authorization: Bearer cwapi_...`, store only a `sha256:` hash, and reuse
  the same RBAC permission strings as console users.
- Token secrets are returned only once at creation time. Revoked, disabled,
  expired, malformed, or globally disabled tokens fail closed with `401`.
- API tokens are intended for automation and integrations. They do not refresh
  browser sessions and do not bypass AI tool approval or RBAC boundaries.

## RBAC And Audit

- JWT roles are mapped through `apisec.permissions`.
- Mutating protection and site routes require write permissions.
- Audit logs are written to `apisec.audit.path` and exposed through `/api/audit`.
- Management API token requests enter the same protected route group as normal
  console requests, so route-level permissions and audit middleware continue to
  apply. Review audit records for the `api-token:<id>` subject when tracing
  automation actions.
- `waf-cli` shows local audit and access log counts from the same configured paths.
- Local password resets can be performed with `cheesewaf user password USERNAME`
  or `waf-cli user password USERNAME`; use `--password-stdin` for scripts or
  `--generate` for a one-time temporary password.
- Local usernames can be renamed with `cheesewaf user rename OLD_USERNAME NEW_USERNAME`
  or `waf-cli user rename OLD_USERNAME NEW_USERNAME`; the command revokes that
  user's existing admin sessions.
- Admin slider CAPTCHA verification is a two-step flow: `/api/auth/captcha/verify`
  validates the encrypted slider token and returns a short-lived one-time receipt,
  then `/api/auth/login` consumes that receipt. Raw slider coordinates are not a
  valid login payload.

## Transport

- HTTP/3 is enabled with `server.http3.enabled`.
- UDP listen address is `server.listen_http3`; when empty it falls back to `server.listen_tls`, then `:443`.
- HTTP/3 requires `tls.cert_file` and `tls.key_file`.
- TLS responses advertise HTTP/3 with `Alt-Svc` when HTTP/3 is enabled.

## External Logs

- Local file logging is always enabled as the first sink.
- ClickHouse uses JSONEachRow inserts.
- VictoriaLogs uses stream JSON ingestion.
- PostgreSQL uses the pgx driver, creates the configured table when needed, and stores tags/metadata as JSONB.
- ClickHouse, VictoriaLogs, and Elasticsearch HTTP endpoints use SSRF-aware
  clients by default. They allow only `http` / `https`, reject URL credentials
  and fragments, block loopback/private/link-local/cloud metadata targets,
  re-check DNS results before dialing, and ignore system proxy settings. Set
  `allow_private_endpoint: true` only for trusted internal storage services.

## ACME Certificates

- ACME issuance is executed through the configured local `acme.sh` binary, not
  through an embedded Go ACME client.
- The ACME server value accepts known `acme.sh` aliases such as `letsencrypt`
  and `zerossl`, or a public HTTPS directory URL. HTTP, private/link-local, URL
  credential, and fragment-bearing directory values are rejected before command
  execution.
- DNS API names must use the `dns_*` provider format, and DNS environment
  variable names must use uppercase shell-style names.
- `reload_command` is optional and is rejected if it contains newline, carriage
  return, or NUL characters. Keep it restricted to an operator-owned local
  service reload command.
- ACME notifications reuse the configured monitoring notifier path and inherit
  notifier endpoint SSRF protections.

## Deployment

- Docker: `deploy/docker/Dockerfile`
- Compose: `deploy/docker/docker-compose.yml`
- systemd: `deploy/systemd/cheesewaf.service`
- The systemd unit keeps `ProtectSystem=full`, but allows writes to
  `/etc/cheesewaf`, `/var/lib/cheesewaf`, and `/var/log/cheesewaf` so runtime
  secret repair, config persistence, certs, SQLite, and logs keep working.
