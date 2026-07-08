# CheeseWAF Management API Tokens

CheeseWAF supports scoped management API tokens for automation and integrations. This feature is disabled by default and must be enabled explicitly in System Settings before tokens can authenticate protected console APIs.

## Security Model

- API token authentication uses `Authorization: Bearer cwapi_...`.
- Token creation is rejected while the Management API token feature is disabled.
- A newly created token is shown once. CheeseWAF stores only a SHA-256 hash.
- Tokens reuse the same RBAC permission strings as console users.
- API tokens cannot refresh browser sessions or bypass AI tool approvals.
- Revoked, disabled, expired, or malformed tokens fail closed with `401`.
- Successful token use records `last_used_at` in memory for operator visibility.
- Audit records include the stable `subject` value `api-token:<id>` so token use can be traced even if the token display name changes.

## Endpoints

All endpoints below require a signed-in admin session with the listed RBAC permission.

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/system/api-tokens` | `read:system` | List token metadata without hashes or secrets. |
| `POST` | `/api/system/api-tokens` | `write:system` | Create a scoped token and return the raw token once. |
| `DELETE` | `/api/system/api-tokens/{id}` | `write:system` | Revoke a token immediately. |

Create payload example:

```json
{
  "name": "ci-release",
  "scopes": ["read:system", "write:sites"],
  "ttl": "720h",
  "notes": "Rotated monthly by release automation"
}
```

The response includes the raw `token` once and a redacted `item` view. Store the raw token in your secret manager immediately; it cannot be recovered later.

## Scope Format

Scopes use `action:resource` format. Supported actions are `read` and `write`; the `*` suffix is allowed for prefix-style groups such as `read:*`.

Common examples:

- `read:system`: read system and version information.
- `write:system`: update system settings, API tokens, block pages, backup and restore operations.
- `read:logs`: read WAF events and security logs.
- `write:sites`: create, update, or remove sites and site certificate actions.
- `write:ai`: update AI settings, execute approved AI tools, and run self-learning jobs.

Grant the smallest scope set required by the automation. Avoid `*` and `write:*` unless the token is stored in a hardened secret manager and rotated regularly.

## Console Workflow

1. Open System Settings, then API Security.
2. Enable Console API Tokens and save the API Security settings.
3. Enter a token name, scopes, lifetime, and notes.
4. Create the token and copy the one-time secret.
5. Clear the visible secret from the page after storing it securely.
6. Revoke stale tokens from the same panel.

API token access is intended for automation. Human operators should continue using normal console accounts with 2FA where possible.
