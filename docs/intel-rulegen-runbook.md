# Intel, PHP2Shell, Notifications, and Passkey runbook

Operational defaults live in `docs/intel-rulegen.md`. This runbook covers
enablement, health checks, failure modes, and rollback.

## Health checks

```sh
# Core API and metrics (requires read:monitor)
curl -fsS -H "Authorization: Bearer $TOKEN" https://console.example/api/v1/monitor
curl -fsS -H "Authorization: Bearer $TOKEN" https://console.example/api/v1/monitor/notifiers

# Intel metrics
curl -fsS https://console.example/metrics | grep cheesewaf_intel_
```

Expected metrics:

- `cheesewaf_intel_imports_total{result="ok|error"}`
- `cheesewaf_intel_feed_items_stored_total`
- `cheesewaf_intel_candidates_reviewed_total{result="approved|rejected"}`

The feed scheduler only polls sources with `type: rss|atom|api`. `type: url`
sources are import allowlists and are deliberately not polled.

## Enable feed ingestion

```yaml
intel:
  enabled: true
  poll_interval: 15m
  sources:
    - id: vendor-feed
      type: rss
      url: https://vendor.example/security.rss
      trust: vendor
      enabled: true
```

Feed items are stored for review; they do not create rules automatically.
Candidate creation still requires a site scope through `POST /intel/import-url`
or the AI Ops import form. Scheduler failures are isolated to the intel
goroutine and cannot affect request inspection.

If a source is failing, logs contain `intel scheduler` or `store feed item`.
Disable that source and restart, or fix its URL/format. Dedupe retention is
bounded at 4096 IDs/hashes per source; expired entries fall out without
operator action.

## PHP2Shell

Check the per-site config after editing any site:

```yaml
sites:
  - id: site-a
    waf:
      php2shell:
        enabled: true
        block_all_multipart: false
```

`GET /api/v1/sites` must still show the expected `php2shell` block after a
site edit. If endpoint probes are blocked unexpectedly, verify that
`allow_paths` includes the probe path and that `block_all_multipart` is false.

Emergency containment:

1. Set `block_all_multipart: true` and add only required upload paths to
   `allow_paths`.
2. Apply the site update and verify probes fail closed.
3. Remove the emergency flag after the exploitation window; it is not a
   permanent setting.

## Notifications

Provider secrets stay in `monitor.notifiers`. The console lists provider
status and can send a test through the same native provider and SSRF policy:

- `GET /api/v1/monitor/notifiers` requires `read:monitor`.
- `POST /api/v1/monitor/notifiers/test` requires `write:monitor`.

A failed test returns `502 delivery_failed` and the sanitized network error.
No endpoint URL, token, or header is returned by the listing API.

To roll back a provider, set `enabled: false` and reload. If a provider loops
on failures, disable it first; retries are bounded but still consume workers.

## Passkey

- Disabling `console.login.passkey.enabled` hides the passkey button and
  rejects new assertions; existing credentials remain stored.
- To reset a user, delete their credentials and recovery codes from account
  management; password/TOTP login remains available.
- Clone warnings and non-monotonic sign counters are rejected. Multi-node
  deployments still use a process-local replay guard; use sticky sessions or a
  shared management database and treat replay protection as a residual risk.
- Recovery routes are intentionally absent; an operator reset is the supported
  recovery path.

## Rollback order

1. Disable notification providers that are failing.
2. Set `intel.enabled: false` to stop imports and polling; stored candidates
   remain reviewable.
3. Revert site `php2shell` settings if probes regress.
4. Roll back the release; migration 7 is forward-only, so restore the database
   from the pre-upgrade backup if schema rollback is required.
