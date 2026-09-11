# Recovery and wrapping-key contract (stages 13–17, 93–119)

The internal/recovery package is a pure-Go boundary for portable recovery
credentials and wrapping-key selection. It has no network, KMS SDK, filesystem
persistence or background worker. Integrations provide those effects explicitly.

## Provider selection and key handling

SelectProvider checks an external KMS first. When it is unavailable, an embedded
provider is considered only when the caller explicitly approves the
single-node/temporary mode fallback. There is no implicit local bypass. The
embedded provider wraps values with AES-256-GCM and binds ciphertext to the
key-version string. Production adapters should source its 32-byte key from OS
Keychain, TPM or DPAPI; a password-protected encrypted key-ring is the offline
fallback. The provider owns KEK material and callers receive only wrapped DEKs,
matching the diagnostics envelope contract.

HMACDigest is the key-ring/pepper primitive for metadata. Recovery manager
state stores only an encrypted credential, a digest and delivery/recovery
markers. The portable secret is held in memory only while returned to the
caller, Web delivery, CLI file writing or revocation completes; it is never
logged or included in metadata.

## Recovery authorization

Each recovery request has an expiry and an exact scope. The manager is seeded
with three administrator identities and requires two distinct, non-replayed
confirmation IDs. Administrator identifiers use a strict no-whitespace form; the
server rejects leading, trailing, or embedded Unicode whitespace, control
characters (`Cc`), and format/invisible characters (`Cf`) instead of silently
normalizing them. It must not trim or case-fold identity fields. Duplicate
confirmations from one administrator do
not meet the threshold. Adapters should layer password/TOTP, local-session binding,
audit and approval-gate checks before calling this contract.

## Delivery semantics

Web delivery is one-time per request. CLI/Ansible delivery writes a local file
with mode 0600, creates it exclusively, and exposes an explicit removal
operation. Integrations must keep the file in a runtime temporary directory,
never under version-controlled templates; cleanup is their responsibility.

## Post-recovery revocation

Recover accepts a TemporaryRevoker callback. A successful thresholded recovery
invokes it so adapters can revoke temporary Session, recovery/setup, Join and
Break-glass credentials, leases and locks. Long-lived tokens are not silently
changed; they require an explicit administrator rotation policy.

The contract does not claim durable audit or revocation. PG append-only audit,
Redis short-lived blacklist, KMS rotation/revocation, offline signed
incremental snapshots and isolated restore validation belong to integration
layers. Recovery should be performed in an isolated environment before a
production cut-over.
