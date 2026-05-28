# Phase 4 Operations

## Monitoring

- Prometheus scrape path: `/metrics`.
- JSON monitor summary: `/api/monitor`.
- Alerts are configured under `monitor.alerts.rules`.
- Webhook style notifications are configured under `monitor.notifiers`.

## API Security

- Discovered endpoints are available at `/api/apisec/endpoints`.
- Request schema validation can be tested with `/api/apisec/validate`.
- Endpoint rate limits are configured under `apisec.rate_limits`.

## RBAC And Audit

- JWT roles are mapped through `apisec.permissions`.
- Mutating protection and site routes require write permissions.
- Audit logs are written to `apisec.audit.path` and exposed through `/api/audit`.

## Deployment

- Docker: `deploy/docker/Dockerfile`
- Compose: `deploy/docker/docker-compose.yml`
- systemd: `deploy/systemd/cheesewaf.service`
