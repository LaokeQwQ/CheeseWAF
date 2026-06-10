# Phase 4 Operations

## Monitoring

- Prometheus scrape path: `/metrics`.
- JSON monitor summary: `/api/monitor`.
- Alerts are configured under `monitor.alerts.rules`.
- Webhook style notifications are configured under `monitor.notifiers`.
- `waf-cli` exposes a local monitoring summary for no-browser server sessions.

## API Security

- Discovered endpoints are available at `/api/apisec/endpoints`.
- Request schema validation can be tested with `/api/apisec/validate`.
- Endpoint rate limits are configured under `apisec.rate_limits`.

## RBAC And Audit

- JWT roles are mapped through `apisec.permissions`.
- Mutating protection and site routes require write permissions.
- Audit logs are written to `apisec.audit.path` and exposed through `/api/audit`.
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

## Deployment

- Docker: `deploy/docker/Dockerfile`
- Compose: `deploy/docker/docker-compose.yml`
- systemd: `deploy/systemd/cheesewaf.service`
- The systemd unit keeps `ProtectSystem=full`, but allows writes to
  `/etc/cheesewaf`, `/var/lib/cheesewaf`, and `/var/log/cheesewaf` so runtime
  secret repair, config persistence, certs, SQLite, and logs keep working.
