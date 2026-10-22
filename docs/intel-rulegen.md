# Intel-to-rule, PHP2Shell, and Passkey operations

This page documents the operator-facing defaults added in 0.4.5. All three
features are opt-in at the management layer even where the detector defaults
to enabled.

## Intel-to-rule

```yaml
intel:
  enabled: true
  auto_apply: false          # always false in shipped configs
  url_import: true           # set false to remove POST /api/v1/intel/import-url
  poll_interval: 15m         # feed scheduler interval, 10s..24h
  max_fetch_bytes: 262144    # hard cap is 262144 (256 KiB)
  max_candidates_per_item: 5
  shadow_window: 1h
  trust_policy: balanced
  sources:
    - id: nvd
      type: url
      url: https://nvd.nist.gov/
      trust: official
      enabled: true
```

- Imports are review-first: every candidate is created `draft`, `log`, and
  `enabled: false`.
- URL imports must use a host covered by an enabled source. The fetcher blocks
  private, loopback, link-local, and non-public addresses and re-checks the
  final URL after redirects.
- `block` approval requires impact evidence and a completed shadow window.
  The shadow start is persisted in `updated_at`; draft age does not count.
- Concurrent approvals use a compare-and-set on candidate state and return
  `409 stale_candidate` instead of overwriting another reviewer.
- Response-only evidence (for example an oversized `Set-Cookie`) is not
  compiled into a request rule. It stays in review until response rule
  locations are supported.
- The API is mounted under `write:protection` or `write:rules`; read-only
  accounts cannot import or review.
- The background scheduler polls only `type: rss|atom|api` sources and stores
  normalized items for review. `type: url` sources are import allowlists and
  are not polled. Scheduler failures are isolated from the request path.
- Metrics: `cheesewaf_intel_imports_total`,
  `cheesewaf_intel_feed_items_stored_total`, and
  `cheesewaf_intel_candidates_reviewed_total`.

## PHP2Shell

```yaml
sites:
  - id: site-a
    waf:
      php2shell:
        enabled: true                  # default true
        block_upload_progress: true
        block_all_multipart: false     # emergency containment only
        max_parts: 256
        max_array_depth: 6
        max_empty_filename_parts: 32
        allow_paths: ["/health"]
```

Per-site values are persisted in the site record. Editing an unrelated site
field does not reset them. `block_all_multipart: true` blocks every multipart
request except `allow_paths`; use it only during active exploitation.

The adapter path (`/nginx/body-check` and the core
`/api/v1/adapter/inspect` endpoint) forwards bounded bodies for gateways that
buffer uploads. Bodies are base64 on the wire; the core cap accounts for that
expansion.

## Passkey

```yaml
console:
  login:
    passkey:
      enabled: true
      rp_id: console.example.com
      rp_name: CheeseWAF
      origins:
        - https://console.example.com
```

- Passkeys are stored in `passkey_credentials`; sign counters are updated with
  a monotonic compare-and-set. A non-increasing counter returns
  `passkey: authenticator clone warning`.
- `Authenticator.CloneWarning` from the WebAuthn library is rejected.
- Replay guards are currently process-local. Multi-node deployments must use a
  shared management database and sticky sessions, or accept this residual
  until a durable replay table is added.
- Password and TOTP login remain available. Passkey recovery routes are not
  exposed because there is no completed-factor state to authorize them.
- The Monitor page lists configured notification providers and can send a test
  through the native provider; provider secrets remain in configuration.
- Operators can rename or delete their own credentials from the console; admin
  reset revokes all credentials for the account.
