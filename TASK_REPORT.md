# R2-4 Protection Task Report

Status: `DONE_WITH_CONCERNS`

Implementation commit: `1832ecd`

## Finding Disposition

1. Webshell scanning is now wired into the production request pipeline. The
   detector bounds candidate bytes, concurrent scans, decode variants, and
   wall-clock time, and returns a bounded evidence payload.
2. Response tamper snapshots now use an HMAC bound to the canonical public URL,
   body length, and body bytes. Response inspection verifies the baseline inline,
   including cache hits, and fails closed when a configured snapshot cannot be
   fully inspected.
3. IP access decisions select the most specific matching rule regardless of
   action, IPv4-mapped prefixes cannot widen to `0.0.0.0/0`, and malformed
   blacklist entries are rejected.
4. ACL matching rejects empty/ambiguous rules and compares header values
   explicitly. API discovery normalizes variable paths and status families.
5. PoW AEAD keys are HKDF-derived per challenge and context is included in AAD.
   The obsolete reversible `protection/crypto` package was removed; the
   remaining presentation helpers are explicitly documented as non-security
   transforms.

## Verification

`env GOCACHE=/private/tmp/cw-r2-protection-gocache go test ./internal/protection/... ./internal/apisec/... ./internal/engine/response ./internal/proxy/... ./internal/proxytrust ./internal/storage ./internal/config ./internal/api/handler ./internal/cli -short -count=1`

Exit `0`; all affected Go packages passed.

`git diff --check` was clean before commit. No remaining Go imports reference
`internal/protection/crypto`.

## Concerns

- No external service is required for the focused checks; live deployment and
  response-cache integration remain CI/integration concerns.
- Tamper snapshots require operators to provision a strong key and valid
  authenticated baselines; invalid configuration is rejected rather than
  silently disabled.
