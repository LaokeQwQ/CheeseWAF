# Offline Egress and Temporary Socket Lease

`internal/netlease` has two deliberately separate layers. `OfflinePolicy` and
`Manager` are the no-I/O capability contract. `Broker` is the only runtime
component in the package that can resolve a hostname or open a socket. A
policy/lease unit test alone is therefore not evidence that external I/O is
enabled or correctly contained.

## Default-offline policy

An empty `OfflinePolicy` denies every external target. An ordinary plugin lease
is valid only for an exact registered internal resource: host, protocol, and
port must all match, and the policy epoch must match the current generation. A
known internal host with a different port or protocol is a scope error, not an
implicit external exception.

The policy applies to plugin/control-plane egress. WAF data-plane traffic to a
configured reverse-proxy origin is a separate path and is not sent through this
broker.

## Temporary confirmation and lease

Temporary external egress is default-deny and is not an ordinary resource
allowlist entry. The runtime flow is:

1. An authenticated administrator opens a short-lived temporary session.
2. The administrator enters their password again for the exact requested
   plugin ID/version, HTTPS target, TLS leaf SHA-256 pin, policy epoch, TTL,
   and byte cap.
3. The session manager creates an opaque, one-time confirmation bound to those
   fields. It never stores the password.
4. The secure lease manager consumes that confirmation atomically while issuing
   one socket lease. Replay, changed scope, expiry, revoked session, revoked
   lease, and policy-epoch changes are denied.
5. The broker consumes the lease immediately before the first resolver/dial
   action and holds an execution gate until the attempt has finished. A revoke
   or policy update therefore happens either before the connection begins or
   after the already-authorized attempt has been accounted for.

Leases have a platform maximum TTL of 10 minutes and are limited to one
request. Plugin code receives neither a `net.Conn` nor a reusable HTTP client.

## Runtime broker boundary

`NewBroker` is disabled unless its caller explicitly supplies all of the
following: `Enabled: true`, an epoch-bound policy, a temporary-session manager,
a real `NetworkTransport`, an address policy, and an audit sink. Production
wiring accepts only a fully initialized `StandardTransport` and requires a
durable audit sink; the in-memory sink and injected transports exist only for
tests.

The standard transport has no worker or background dial. Each authorized
operation resolves once, chooses one permitted result, and dials that literal
IP address rather than resolving the hostname again. `PublicAddressPolicy`
rejects loopback, unspecified, private, link-local, multicast, shared carrier,
benchmark, documentation, reserved, and other special-use ranges. This blocks
DNS rebinding and local-address SSRF through the temporary path.

The HTTPS and TLS APIs create one fresh connection with TLS 1.2 or newer and
verify the configured canonical `sha256:<lowercase-hex>` pin against the peer
leaf certificate. They do not use proxy settings, redirects, absolute request
URLs, caller-controlled Host headers, or connection reuse. HTTP requests are
bounded, accept only relative paths, and enforce their configured byte limits.
The connection deadline is the earliest applicable caller deadline, broker
operation timeout, or remaining lease TTL.

## Audit behavior

The local production adapter writes metadata-only JSONL records at
`<data-dir>/audit/netlease.jsonl`. The file and its directory are owner-only
(`0600` and `0700` respectively), every append is synced before the broker
continues, and symlink/non-regular audit paths are rejected. The records include
the lease and confirmation IDs, administrator ID, plugin/version, exact target,
TLS pin, policy epoch, byte counts, request count, timestamp, and result. They
do not contain passwords or HTTP/TLS payloads.

An unavailable audit sink prevents lease issuance and connection start. If the
audit write for a result fails after an already-authorized socket attempt, the
broker returns an error and preserves the in-memory final accounting; it cannot
retroactively undo an attempted network operation.

## Explicit local CLI

`cheesewaf temporary-online probe` is the currently mounted runtime entry
point. It is a local, one-shot HTTPS probe, not a daemon or download service.
It requires an exact administrator username, `--password-stdin`, plugin ID and
version, lowercase hostname, certificate pin, and bounded TTL/byte limits.
Only `HEAD` and `GET` requests to relative paths are permitted. Run
`cheesewaf temporary-online probe --help` to inspect the required flags.

The CLI verifies the local SQLite administrator record and performs a fresh
bcrypt password check. It explicitly uses the local-only authentication mode;
remote/control-plane integrations default to requiring a live, revocable
management-session ID as well as the password confirmation. Passwords are read
from standard input only and are never accepted as command-line flags.

The reusable runtime entry point is `Broker.ExecuteTemporaryHTTP`. It accepts
the already-authenticated administrator identity plus the fresh password and
the complete request scope, then owns the whole sequence in one synchronous
call: begin the temporary session, confirm the password, issue and consume one
lease, perform the pinned HTTPS request, record the result, and revoke both
the lease and session before returning. Cleanup errors are returned together
with the operation error; callers must not reconstruct this sequence around a
raw `DoHTTP` call.

`Broker.Revoke` also appends the terminal `revoked` metadata event to the
configured durable audit sink. Manager-only in-memory audit snapshots are not
production evidence of cleanup.

When the command returns, the CLI explicitly closes the temporary session and
revokes the one-shot lease, including after transport or audit failure. The
result and terminal lease event remain metadata-only audit records; cleanup
does not create a worker or extend the probe into a background service.

`cheesewaf serve` does not construct this broker, start a background network
worker, or expose a temporary-online HTTP endpoint. The standalone CWEDP HTTP
transport can be constructed with a broker-bound one-shot lease and uses this
TLS/pin boundary, but it is not mounted into `serve`, node registration, or a
complete plugin installation lifecycle. CRP activation is also not delegated
to this broker. No production control-plane adapter currently implements
`ExecuteTemporaryHTTP` with a revocable management session, nor does the main
`serve` dependency factory provide a plugin controller that can create the
broker and pass leases to CWEDP. These are explicit integration blockers, not
reasons to weaken the local lifecycle or mark the production gate passed.
