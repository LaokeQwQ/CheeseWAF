# Notification sidecar contract v1.1 (draft)

Status: contract draft. Native providers are implemented; this document defines
the future sidecar boundary. No runtime in this repository consumes it yet.

## Goals

- let a signed provider pack describe delivery without executing code;
- let an optional sidecar deliver through a host-brokered egress channel;
- keep secrets, endpoint allowlists, and activation under host control;
- preserve the CRP v1 archive and activation behavior.

## Non-goals

- third-party code inside the WAF request path;
- arbitrary network access from a sidecar;
- installing a provider pack that grants runtime capability by itself;
- changing the CRP v1 `manifest.json` / `artifact` / `signatures` layout.

## Descriptor

A notification sidecar manifest is a signed JSON document:

```json
{
  "api_version": "cheesewaf/notification-sidecar/v1alpha1",
  "id": "vendor.notify",
  "version": "1.0.0",
  "extension_class": "notification",
  "capabilities": ["notify.send", "health"],
  "provider_types": ["webhook"],
  "egress": {
    "mode": "brokered",
    "allowlist_ref": "notification-endpoints",
    "max_requests_per_minute": 60,
    "max_request_bytes": 65536,
    "timeout_seconds": 10
  },
  "limits": {
    "max_concurrent": 4,
    "max_queue": 256,
    "max_retained_failures": 1024
  },
  "publication": {
    "status": "planned",
    "installable": false,
    "crp_binding": "descriptor-only"
  },
  "integrity": {
    "algorithm": "ed25519",
    "issuer": "cheesewaf-host",
    "purpose": "notification-sidecar-descriptor",
    "domain": "cheesewaf-notification-sidecar-v1alpha1",
    "key_id": "store-key-1",
    "signed_at": "2026-10-22T00:00:00Z",
    "payload_sha256": "<sha256>",
    "value": "<base64 signature>"
  }
}
```

Validation rules:

- `api_version`, `id`, `version`, and `integrity` are required;
- `extension_class` must be `notification`;
- only `notify.send` and `health` capabilities are accepted;
- `egress.mode` must be `brokered`; `allowlist_ref` must name a host-owned
  allowlist, never an inline URL list;
- `publication.installable` must be `false` until the host advertises the
  v1alpha1 capability; a descriptor can never self-enable;
- `integrity` is verified over canonical JSON with the signature field removed;
- the host rejects unknown fields, duplicate capabilities, and oversized
  descriptors.

## Host boundary

The host owns:

- secret storage and resolution; the sidecar receives references, not values;
- endpoint allowlist and DNS/SSRF policy;
- rate limits, retries, queueing, and circuit breaking;
- audit records for activation and delivery attempts;
- activation and rollback.

The sidecar receives only:

```json
{
  "request_id": "01J...",
  "provider_id": "ops-webhook",
  "alert": { "rule_id": "...", "severity": "high", "message": "..." },
  "endpoint_ref": "allowlist:ops-webhook",
  "secret_ref": "secret:ops-webhook-token",
  "deadline_ms": 10000
}
```

It returns `{"delivered":true}` or a bounded error code. It cannot request an
arbitrary URL and cannot read files outside its artifact directory.

## Delivery semantics

- at-most-once from the sidecar's perspective; the host owns retries;
- idempotency key is `request_id`; duplicate keys are acknowledged without a
  second send;
- queue backpressure drops new deliveries with a metric rather than blocking
  the WAF request path;
- every failure is reported to the host audit stream with a sanitized code;
- a health probe is a separate capability and never triggers a delivery.

## Compatibility

CRP v1 remains unchanged: its sidecar descriptor still permits only `observe`,
`candidate_snapshot`, `hint`, and `health`, and keeps `metadata.egress=deny`.
The v1.1 notification contract is a separate manifest and activation path; it
must not be smuggled through the v1 descriptor.
