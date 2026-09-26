#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import signal
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]

GATES = [
    ("temporary_get_started", "temporary Get Started process/contract", True, "temporary runtime initialization and clean startup", [],
     "{get_started}", "temporary mode reports readiness and isolates runtime state below data-dir",
     "{get_started}", "template preservation, runtime isolation, and cleanup evidence are reported"),
    ("control_health_ready_status", "cheesewaf-control health/ready/status", True, "standalone control-plane HTTP read probes", [],
     "go test ./internal/controlplane/runtime -run '^TestHandlerFailsClosedUntilControlPlaneReady$' -count=1", "healthz and status are live while readyz and writes fail closed before readiness",
     "go test ./internal/controlplane/runtime -run '^TestHandlerRestrictsReadEndpointsToGET$' -count=1", "healthz, readyz, and status reject non-GET methods with 405"),
    ("control_postgres_dsn", "PostgreSQL DSN required and redacted", True, "control startup input validation and safe status output", [],
     "go test ./internal/controlplane/runtime -run '^TestStatusDoesNotExposePostgreSQLDSN$' -count=1", "status contains no host, password, or raw DSN material",
     "go test ./cmd/cheesewaf-control ./internal/controlplane/runtime -run 'Test(ValidateOptionsRejectsMissingProductionDependenciesBeforeIO|RunRejectsInvalidOptionsBeforeOpeningBackends)' -count=1", "missing DSN and malformed identity are rejected before backend I/O without credential leakage"),
    ("native_raft_single_node_restart", "native-raft single node and restart", True, "native-raft local bootstrap and persisted term/fence", [],
     "go test ./internal/controlplane/nativeraft -run '^TestSingleNodeBootstrapPersistsStateAndInvalidatesOldFenceAfterRestart$' -count=1", "single-node bootstrap persists state, advances term after restart, and invalidates the old fence",
     "go test ./internal/controlplane/nativeraft -run '^TestNewRejectsTemporaryProfileAndImplicitMode$' -count=1", "temporary profile and implicit raft mode are rejected before startup"),
    ("native_raft_join_only", "native-raft join-only membership", True, "explicit leader join and commit replication", [],
     "go test ./internal/controlplane/nativeraft -run '^TestJoinRequiresExplicitLeaderOperationAndReplicatesCommit$' -count=1", "join-only nodes join through an explicit leader operation and observe committed state",
     "go test ./internal/controlplane/nativeraft -run '^TestJoinNodeDoesNotSilentlyBootstrap$' -count=1", "join-only nodes never self-elect or fabricate state without explicit join"),
    ("production_serve_fail_closed", "production serve fails closed", True, "production management storage boundary", [],
     "go test ./internal/cli -run '^TestOpenConfiguredManagementStoreRefusesProductionSQLiteFallback$' -count=1", "production refuses SQLite fallback and returns ErrProductionStorageUnavailable",
     "go test ./internal/cli -run '^TestOpenConfiguredManagementStoreRejectsNilProductionStore$' -count=1", "nil production store is rejected without claiming readiness"),
    ("production_fail_closed", "production fail-closed smoke", True, "production profile startup rejection", [],
     "bash scripts/acceptance/get-started.sh --static-contract", "checked-in contract documents production fail-closed and runtime-copy boundaries",
     "go test ./internal/config ./internal/cli -run 'Test.*(ProductionStorage|RefusesProductionSQLiteFallback)' -count=1", "no production path creates or uses a cheesewaf.db fallback"),
    ("switch_migration_session_invalidation", "temporary to production migration and Session invalidation", False, "verified migration handoff and main serve production wiring versus deployment-level cutover", ["no deployment-level PostgreSQL cutover/recovery rehearsal is available in this repository", "temporary invalidation is enforced by handoff and ledger verification but is not exercised against a running production launcher"],
     "go test ./internal/storage -run '^TestSQLite.*(Migration|Session|Credential|Recovery)' -count=1 && go test ./internal/cli -run 'Test.*(Migration|Session|Credential|Recovery|Handoff)' -count=1 && go test ./internal/cli/migration -run 'Test.*(Migration|Session|Credential|Recovery|Handoff)' -count=1 && go test ./internal/recovery -run '^TestRecovery' -count=1", "migration, recovery, credential epochs, handoff evidence, and the main launcher handoff are covered by passing contract tests",
     "go test ./internal/cli -run 'Test(OpenProductionDependenciesRejectsUnwiredServeEvenWhenBackendsHealthy|OpenProductionServeDependenciesBindsMainLauncherHandoff)$' -count=1", "embedded callers remain fail-closed while the main serve composition root consumes only validated wiring"),
    ("crp_verify", "CRP CLI verify", True, "offline package verification", [],
     "go test ./internal/cli ./internal/crp -run 'Test(CRPVerifyPrintsSafeSummary|ManifestValidateAndVerify|ImportOfflineEnforcesAllBoundaries)' -count=1", "verify accepts valid offline packages and emits a safe summary",
     "go test ./internal/cli ./internal/crp -run 'Test(CRPVerifyRequiresExplicitInputs|ImportRequiresExplicitVerificationTime|ManifestRequiresAllDigests)' -count=1", "missing trust roots, sources, time, and digest fields are rejected"),
    ("crp_stage", "CRP CLI stage", True, "content-addressed staged runtime", [],
     "go test ./internal/cli -run '^TestCRPStagePersistsStagedOnly$' -count=1", "stage persists a verified package without activating it",
     "go test ./internal/cli -run 'TestCRPStage(RejectsConfirmationRequiredPackageByDefault|DoesNotExposeConfirmationBypass|RequiresExplicitInputs)' -count=1", "confirmation bypasses and missing explicit inputs fail closed"),
    ("crp_activation", "CRP activation CLI/runtime connection", False, "CLI and mTLS activation client versus deployed control-plane/sidecar services", ["deployed control-plane/sidecar services and durable production authorization/audit are outside this repository"],
     "go test ./internal/crp/activation -run 'Test(ActivateAuthorizedRunsObserveCanaryThenPromotes|ActivateAuthorizedFailureLeavesStagedAndStopsSidecar|ActivateAuthorizedVerifiesFreshRecordBeforeAuthorization|MTLSActivationTransportEndToEnd|ControlPlaneServerTLSConfigRequiresVerifiedClientCertificate)' -count=1", "service and mTLS transport prove observe, canary, atomic promotion, fresh verification, authenticated client/server exchange, and strict server-side TLS client verification",
     "go test ./internal/cli -run 'Test(CRPActivateFailsClosedWithoutControlPlaneOrSidecar|CRPActivationRejectsLegacyAuthorityFlags)' -count=1", "CLI activation rejects unavailable adapters and legacy authority bypasses without changing staged/current state"),
    ("crp_rollback", "CRP rollback CLI/runtime connection", False, "CLI and mTLS rollback client versus deployed control-plane/sidecar services", ["deployed control-plane/sidecar services and durable production authorization/audit are outside this repository"],
     "go test ./internal/crp/activation -run 'Test(RollbackAuthorizedUsesExactPreviousRecord|RollbackAuthorizedRejectsBlockedPreviousBeforeAuthorization|RollbackAllowedRejectsArbitraryTarget|MTLSRollbackTransportEndToEnd)' -count=1", "service and mTLS transport prove exact last-known-good, blocked/stale authorization, arbitrary target rejection, and authenticated rollback exchange",
     "go test ./internal/cli -run '^TestCRPActivationRejectsLegacyAuthorityFlags$' -count=1", "rollback CLI exposes no legacy authority or confirmation bypass flags"),
    ("approval_http", "approval HTTP", True, "approval request/confirm/replay HTTP boundary", [],
     "go test ./internal/api/handler -run '^TestApprovalHTTP' -count=1", "HTTP approval enforces server warning time, bindings, replay protection, and one commit under concurrency",
     "go test ./internal/api/handler -run 'TestApprovalHTTP(RejectsClientWarningTimeSessionAndLocalSpoofing|RejectsChangedScopeAndConfirmationReplay|ConfirmationFailsClosedWithoutCredentialVerifier|RejectsMalformedTrailingJSON)' -count=1", "spoofed timing/session/local data, changed scope, replay, missing verifier, and malformed JSON are rejected"),
    ("token_strict_identity", "Token strict identity", True, "token issuance and authorization identity boundaries", [],
     "go test ./internal/api/middleware ./internal/tokens/... -run 'Test.*(Canonical|Identity|Authorize|Epoch)' -count=1", "canonical identity, policy epoch, opaque secret handling, and authorization bindings pass",
     "go test ./internal/api/handler -run 'Test(CreateManagementAPITokenRejectsNonCanonicalScopes|CreateManagementAPITokenRejectsNonCanonicalConfirmationID|RevokeManagementAPITokenRejectsNonCanonicalID|PermissionMatchesRejectsNonCanonicalSelectors)' -count=1 && go test ./internal/api/middleware -run 'Test(TokenManagerRejectsNonCanonicalHumanUsernameAtSigning|TokenManagerRejectsAlreadySignedNonCanonicalHumanUsername|SessionMiddlewareRejectsNonCanonicalHumanUsernameBeforeStoreLookup)' -count=1 && go test ./internal/tokens ./internal/tokens/postgres -run 'Test.*(NonCanonical|Whitespace|Invisible)' -count=1", "Unicode whitespace, control, and invisible identity fields are rejected without trimming"),
    ("diagnostics_encryption", "diagnostics envelope encryption", True, "authenticated envelope and key lifecycle", [],
     "go test ./internal/diagnostics/envelope -run 'Test(SealOpenUsesIndependentDEKAndAuthenticatesAAD|RewrapRotatesKEKWithoutReencryptingPackage|LocalProviderIsExplicitAndErasesOnClose|KeyBuffersAreErasedAtApplicationBoundary)' -count=1", "independent DEKs, authenticated AAD, and erased key material are verified",
     "go test ./internal/diagnostics/envelope -run 'Test(OpenOnceRejectsReplayAtomically|DecodeStrictlyRejectsUnknownAndTrailingJSON|EnvelopeIdentityMustBeCanonicalHex|ReplayGuardFailsClosedWhenFull|RetiredKeyVersionCannotOpenOldEnvelopeAfterRewrap)' -count=1", "replay, malformed fields, noncanonical identity, full guards, and retired keys fail closed"),
    ("diagnostics_queue", "diagnostics encrypted queue", True, "durable encrypted queue and bounded retry", [],
     "go test ./internal/diagnostics/queue -run 'TestStore(PersistsEncryptedItemAcrossRestartAndDeletesObjectOnSuccess|SealingWipesInternalPlaintextAndPersistsNoPlaintext|ConcurrentSameIdempotencyKeyHasOneDurableEntry|WorkerIsSingleConcurrentWorker)' -count=1", "queue survives restart with ciphertext only, wipes plaintext, deduplicates idempotency, and has one worker",
     "go test ./internal/diagnostics/queue -run 'TestStore(EnforcesItemAndByteQuotaIncludingClaimedItems|RejectsUnsafeIdempotencyWhitespace|ExpiresItemsAndRejectsExpiredIdempotency|DropsCorruptObjectDuringRecovery|RequeuesProcessingItemAfterCrashLikeRestart)' -count=1", "capacity, unsafe identity, expiry, corruption, and crash recovery boundaries fail closed or requeue safely"),
    ("diagnostics_runtime_delivery", "diagnostics composed delivery runtime", True, "broker, canonical envelope, durable queue, replay lifecycle, and metadata-only audit composition", [],
     "go test ./internal/diagnostics/integration -run 'TestRuntime(RecoversQueuedEnvelopeAfterRestart|ReplayGuardReleasesAfterUploadFailure|AuditEventsAndOutboxContainMetadataOnly)' -count=1", "the composed runtime seals before persistence, survives restart, retries a failed upload, and emits metadata-only audit records",
     "go test ./internal/diagnostics/integration -run 'TestRuntime(DropsCorruptEnvelopeObjectOnRestart|TamperedEnvelopeDoesNotConsumeReplayReservation|AuditsReplayCommitFailureWithoutRepeatingSuccessfulUpload)' -count=1", "corrupt or tampered envelopes fail closed, and post-upload replay uncertainty is audited without duplicating the external side effect"),
    ("offline_no_egress", "offline mode and no egress", True, "offline source selection and egress denial", [],
     "go test ./internal/netlease ./internal/cwedp ./internal/cwedp/transport -run 'Test.*(Offline|Source|PullRejectsUnauthorizedEndpoint)' -count=1", "offline policy denies external egress while registered internal/offline sources remain usable",
     "go test ./internal/netlease ./internal/cwedp ./internal/cwedp/transport -run 'Test.*(RejectsOffline|UnauthorizedEndpoint|TargetValidation|Egress)' -count=1", "unregistered targets, unauthorized endpoints, ambiguous targets, and offline network use are rejected"),
    ("temporary_network_confirmation", "temporary network confirmation", False, "production temporary-network provider and CWEDP/plugin route versus deployment-level egress wiring", ["a deployment-level CWEDP/CRP peer with a public IP, high port, mTLS identity, and signed package is not currently available", "no complete deployment-level lease, HTTPS egress, and CWEDP download rehearsal has been run"],
     "go test ./internal/cli ./internal/netlease -run 'Test(ProductionTemporary|ProductionCWEDP|TemporaryOnlineProbeIsDiscoverableAndRequiresExplicitPasswordStdin|RunTemporaryOnlineProbeRejectsMethodAndLimitsBeforeReadingPassword|ReadTemporaryOnlinePasswordStripsOnlyOneTerminalLineEnding|ExecuteTemporaryHTTPOwnsConfirmationNetworkAndCleanupLifecycle)' -count=1", "the main production provider binds management sessions and policy epochs, mints one-shot leases, gates use-time access, and releases capabilities; local broker confirmation and cleanup remain covered",
     "go test ./internal/cli -run '^TestRunTemporaryOnlineProbeRejectsMethodAndLimitsBeforeReadingPassword$' -count=1", "invalid temporary-online requests are rejected before reading credentials or opening a backend"),
    ("digest_resume", "CWEDP digest and resumable transfer", True, "content-addressed pull and resume", [],
     "go test ./internal/cwedp ./internal/cwedp/transport -run 'Test.*(Resume|Digest|Chunk|Source|Pull)' -count=1", "HELLO/capabilities, Range resume, three digest algorithms, source switching, and quarantine pass",
     "go test ./internal/cwedp ./internal/cwedp/transport -run 'Test.*(DigestMismatch|Rejects.*Stale|InvalidChunk|FailureBudget|Quarantine)' -count=1", "digest mismatch, stale offsets, invalid chunks, source budgets, and quarantined sources are rejected"),
    ("audit_recovery_rollback", "audit/recovery rollback contracts", True, "append-only audit and threshold recovery", [],
     "go test ./internal/approval ./internal/recovery ./internal/audit -run 'Test.*(Audit|Recovery|Checkpoint|EncryptedSpool|Runtime)' -count=1", "audit chains, critical durability, threshold recovery, encrypted spool, and runtime contracts pass",
     "go test ./internal/approval ./internal/recovery ./internal/audit -run 'Test.*(Replay|Stale|Corrupt|Rejects|Regression|WithoutDurable)' -count=1", "replay, stale fences, corruption, regressions, and unavailable durable channels are rejected"),
    ("production_artifact_scan", "production artifact scan", True, "published static assets and build controls", [],
     "python3 scripts/acceptance/production_artifact_scan.py", "artifact trees and archives contain no dependency directories, source-only Web trees, links, or unsafe paths",
     "if find web/dist internal/webui/dist release -type l -o -path '*/node_modules/*' 2>/dev/null | grep -q .; then exit 1; else echo 'negative artifact boundary scan found no links or dependency trees'; fi", "links, dependency trees, source-only paths, unsafe archive members, or absent output fail closed"),
]

# These probes deliberately remain opt-in.  The normal matrix is dependency
# free and must continue to report the deployment evidence gap when it cannot
# reach a real PostgreSQL/Redis composition.  A full run promotes the first
# deployment-scoped gates only after the corresponding end-to-end test
# has actually been executed with all of its dependencies available.
REAL_INTEGRATION_GATES = {
    "switch_migration_session_invalidation": {
        "env": ("CHEESEWAF_POSTGRES_TEST_DSN", "CHEESEWAF_REDIS_RUNTIME_TEST_ADDR"),
        "command": "go test ./internal/cli/migration -run '^TestPostgres.*$' -count=1 && go test ./internal/cli -run '^TestRunServeProductionRealListenerAndSessionRoute$' -count=1",
        "evidence": "real PostgreSQL migration/recovery contracts and the production runServe listener prove migration handoff plus old-session invalidation",
    },
    "crp_activation": {
        "env": (
            "CHEESEWAF_POSTGRES_TEST_DSN",
            "CHEESEWAF_REDIS_RUNTIME_TEST_ADDR",
            "CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR",
        ),
        "command": "go test ./internal/cli -run '^TestRunServeProductionCRPActivationAndRollback$' -count=1",
        "evidence": "the real production runServe route exercises PostgreSQL approval, mTLS control-plane/sidecar activation, durable authorization, and audit",
        "cache_key": "crp_route",
    },
    "crp_rollback": {
        "env": (
            "CHEESEWAF_POSTGRES_TEST_DSN",
            "CHEESEWAF_REDIS_RUNTIME_TEST_ADDR",
            "CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR",
        ),
        "command": "go test ./internal/cli -run '^TestRunServeProductionCRPActivationAndRollback$' -count=1",
        "evidence": "the real production runServe route exercises exact previous-version rollback through PostgreSQL approval, mTLS, sidecar, durable authorization, and audit",
        "cache_key": "crp_route",
    },
    "temporary_network_confirmation": {
        "env": (
            "CHEESEWAF_POSTGRES_TEST_DSN",
            "CHEESEWAF_REDIS_RUNTIME_TEST_ADDR",
            "CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR",
            "CHEESEWAF_PUBLIC_NETLEASE_TEST_PIN",
            "CHEESEWAF_CWEDP_REAL_ROUTE_HOST",
            "CHEESEWAF_CWEDP_REAL_ROUTE_PORT",
        ),
        "command": "go test ./internal/cli -run '^(TestRunServeProductionTemporaryHTTPRoute|TestRunServeProductionCWEDPDownloadRoute)$' -count=1",
        "evidence": "the real production launcher exercises PostgreSQL/Redis session-bound temporary HTTPS egress and the runtime-owned CWEDP/CRP download route against a public mTLS peer with signed intent and resumable PostgreSQL state",
    },
}


def integration_plan(gate_id, mode, environment=None):
    """Return the real-evidence plan for a deployment-scoped gate.

    This is intentionally a pure decision helper so the contract tests can
    prove that static mode never silently upgrades a gate, and that a full run
    requires every declared dependency before setting ``implemented`` true.
    """
    spec = REAL_INTEGRATION_GATES.get(gate_id)
    if spec is None:
        return {"managed": False, "enabled": False, "implemented": None, "missing": [], "spec": None}
    if environment is None:
        environment = os.environ
    missing = [name for name in spec["env"] if not str(environment.get(name, "")).strip()]
    enabled = mode == "full" and not missing
    return {
        "managed": True,
        "enabled": enabled,
        "implemented": enabled,
        "missing": missing,
        "spec": spec,
    }

def sanitize(text):
    text = re.sub(r"(?i)(postgres(?:ql)?://[^\s/@:]+:)[^\s/@]+(@)", r"\1[REDACTED]\2", text)
    return re.sub(r"(?i)(password|secret|token)([=:])[^\s,}]+", r"\1\2[REDACTED]", text)


def _process_group_members(pgid):
    """Return live PIDs left in a probe's process group, or an error."""
    try:
        result = subprocess.run(
            ["ps", "-o", "pid=", "-g", str(pgid)],
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        # BSD ps exits 1 when a valid process group has no remaining members;
        # that is the successful empty-group result we need here.
        if error.returncode == 1 and not error.stdout.strip():
            return [], None
        return None, error
    except OSError as error:
        return None, error
    members = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            try:
                members.append(int(line))
            except ValueError:
                return None, ValueError(f"invalid ps PID output: {line!r}")
    return members, None


def _terminate_process_group(pgid):
    """Terminate leaked probe children and verify the process group is empty."""
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return [], None
    except OSError as error:
        return None, error
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        members, error = _process_group_members(pgid)
        if error is not None or not members:
            return members, error
        time.sleep(0.02)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        return None, error
    return _process_group_members(pgid)


def run_probe(work, gate_id, side, command):
    effective = command
    if command.startswith("go test "):
        effective = command.replace("go test ", "go test -v ", 1)
    environment = os.environ.copy()
    # Keep acceptance probes hermetic in the desktop sandbox and in clean CI
    # workers. The user's global Go cache may be outside the writable workspace
    # and would make an otherwise valid probe fail before package setup.
    acceptance_cache = os.environ.get("CHEESEWAF_ACCEPTANCE_GOCACHE", "/tmp/cheesewaf-acceptance-gocache")
    pathlib.Path(acceptance_cache).mkdir(parents=True, exist_ok=True)
    environment.update({"GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOCACHE": acceptance_cache})
    with tempfile.TemporaryFile(mode="w+t") as stdout_file, tempfile.TemporaryFile(mode="w+t") as stderr_file:
        process = subprocess.Popen(
            ["bash", "-o", "pipefail", "-c", effective],
            cwd=ROOT,
            text=True,
            stdout=stdout_file,
            stderr=stderr_file,
            env=environment,
            start_new_session=True,
        )
        process.wait()
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout, stderr = stdout_file.read(), stderr_file.read()
    returncode = process.returncode
    members, group_error = _process_group_members(process.pid)
    processes_stopped = group_error is None and not members
    cleanup_evidence = f"process_group={process.pid}; remaining_pids={members or []}"
    if group_error is not None:
        processes_stopped = False
        cleanup_evidence += f"; process_group_check_error={group_error}"
    elif not processes_stopped:
        members, terminate_error = _terminate_process_group(process.pid)
        cleanup_evidence += f"; after_termination_pids={members or []}"
        if terminate_error is not None:
            cleanup_evidence += f"; process_group_termination_error={terminate_error}"
        returncode = 1
    raw = stdout + stderr
    if returncode == 0 and command.startswith("go test "):
        if "--- PASS:" not in raw or ("[no tests to run]" in raw and "--- PASS:" not in raw) or "--- SKIP:" in raw:
            returncode = 1
            stderr += "\nacceptance probe did not produce an unsuppressed passing test (skip/no-test detected)"
    evidence = sanitize(stdout + stderr + f"\n[exit={returncode}]\n[{cleanup_evidence}]\n")
    log = work / f"{gate_id}.{side}.log"
    log.write_text(evidence, encoding="utf-8")
    return ("pass" if returncode == 0 else "failed", command, evidence, processes_stopped)


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--report", default="/tmp/acceptance_e2e_matrix_v2_report.json")
    parser.add_argument("--markdown", default="/tmp/acceptance_e2e_matrix_v2_report.md")
    args = parser.parse_args(argv)
    mode = "static" if args.static else "full"
    if args.list:
        for gate in GATES: print(gate[0])
        print("cleanup_no_tracked_pollution")
        return 0
    report_path = pathlib.Path(args.report).expanduser().resolve()
    markdown_path = pathlib.Path(args.markdown).expanduser().resolve()
    try:
        report_path.relative_to(ROOT)
        raise SystemExit("report path must be outside repository")
    except ValueError:
        pass
    try:
        markdown_path.relative_to(ROOT)
        raise SystemExit("markdown path must be outside repository")
    except ValueError:
        pass
    report_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    before = subprocess.run(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
    source = ROOT / "configs/cheesewaf.yaml"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    work = pathlib.Path(tempfile.mkdtemp(prefix="cheesewaf-acceptance-v2-", dir="/tmp"))
    runtime_removed = False
    processes_stopped = True
    records = []
    integration_results = {}
    get_started = "bash scripts/acceptance/get-started.sh --static-contract" if mode == "static" else "bash scripts/acceptance/get-started.sh --smoke"
    try:
        for gid, title, implemented, scope, blockers, pc, pa, nc, na in GATES:
            integration = integration_plan(gid, mode)
            blockers = list(blockers)
            if integration["managed"]:
                implemented = integration["implemented"]
                if integration["missing"]:
                    blockers.append(
                        "real integration requires: " + ", ".join(integration["missing"])
                    )
            pc = pc.format(get_started=get_started)
            nc = nc.format(get_started=get_started)
            ps, _, pe, positive_processes_stopped = run_probe(work, gid, "positive", pc)
            ns, _, ne, negative_processes_stopped = run_probe(work, gid, "negative", nc)
            processes_stopped = processes_stopped and positive_processes_stopped and negative_processes_stopped
            if integration["enabled"]:
                # The catalog blockers describe the evidence gap in static
                # mode. Once a full run has supplied every declared runtime
                # dependency, those historical blockers must not remain on a
                # passing record and imply that the gate is still blocked.
                blockers = []
                spec = integration["spec"]
                cache_key = spec.get("cache_key", gid)
                if cache_key not in integration_results:
                    integration_results[cache_key] = run_probe(
                        work, f"{gid}.real-integration", "positive", spec["command"]
                    )
                ips, _, ipe, integration_processes_stopped = integration_results[cache_key]
                processes_stopped = processes_stopped and integration_processes_stopped
                ps = "pass" if ps == "pass" and ips == "pass" else "failed"
                pc = f"{pc} && {spec['command']}"
                pe = pe + "\n[real integration]\n" + spec["evidence"] + "\n" + ipe
                if ips != "pass":
                    blockers.append("real integration probe failed")
            if ps != "pass":
                blockers.append("positive probe failed")
            if ns != "pass":
                blockers.append("negative probe failed")
            records.append({"id": gid, "title": title, "status": "pass" if implemented and ps == "pass" and ns == "pass" else "failed", "implemented": implemented, "scope": scope, "blockers": blockers, "positive": {"status": ps, "command": pc, "assertion": pa, "evidence": pe}, "negative": {"status": ns, "command": nc, "assertion": na, "evidence": ne}})
    finally:
        after = subprocess.run(["git", "status", "--porcelain=v1"], cwd=ROOT, text=True, capture_output=True, check=True).stdout
        tracked = before == after
        unchanged = hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
        shutil.rmtree(work, ignore_errors=True)
        runtime_removed = not work.exists()
    cleanup_ok = tracked and unchanged and processes_stopped and runtime_removed
    records.append({"id": "cleanup_no_tracked_pollution", "title": "runtime/process cleanup and tracked-file pollution", "status": "pass" if cleanup_ok else "failed", "implemented": True, "scope": "acceptance cleanup boundary", "blockers": [] if cleanup_ok else ["tracked worktree, source template, process group, or runtime root changed"], "positive": {"status": "pass" if tracked and unchanged else "failed", "command": "git status --porcelain=v1 before/after; sha256 configs/cheesewaf.yaml", "assertion": "tracked worktree and source config template are unchanged", "evidence": f"tracked_worktree_unchanged={tracked}; source_template_unchanged={unchanged}"}, "negative": {"status": "pass" if cleanup_ok else "failed", "command": "probe process groups are checked after every child exits; temporary root is removed", "assertion": "all probe process groups are empty and temporary runtime root is removed", "evidence": f"processes_stopped={processes_stopped}; runtime_removed={runtime_removed}"}})
    passed = sum(x["status"] == "pass" for x in records)
    failed = sum(x["status"] == "failed" for x in records)
    report = {"schema_version": 2, "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(), "repository": str(ROOT), "mode": mode, "summary": {"total": len(records), "passed": passed, "failed": failed, "skipped": 0}, "cleanup": {"runtime_removed": runtime_removed, "processes_stopped": processes_stopped, "source_template_unchanged": unchanged, "tracked_worktree_unchanged": tracked}, "gates": records}
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = ["# CheeseWAF acceptance matrix v2", "", f"Generated: {report['generated_at']}", f"Mode: {mode}; passed {passed} / failed {failed} / skipped 0", "", "Each gate has independently executed positive and negative evidence. Unconnected capabilities are failed with blockers; no gate is skipped.", "", "| Gate | Status | Implemented | Scope | Positive evidence | Negative evidence | Blockers |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for gate in records:
        clean = lambda value: str(value).replace("|", "\\\\|").replace("\\n", " ").strip()
        markdown.append(f"| {gate['id']} | {gate['status']} | {str(gate['implemented']).lower()} | {clean(gate['scope'])} | {clean(gate['positive']['assertion'])} ({gate['positive']['status']}) | {clean(gate['negative']['assertion'])} ({gate['negative']['status']}) | {clean('; '.join(gate['blockers']))} |")
    markdown.extend(["", "## Cleanup evidence", "", f"- Runtime root removed: {report['cleanup']['runtime_removed']}", f"- Child processes stopped: {report['cleanup']['processes_stopped']}", f"- Source template unchanged: {report['cleanup']['source_template_unchanged']}", f"- Tracked worktree unchanged: {report['cleanup']['tracked_worktree_unchanged']}"])
    markdown_path.write_text("\n".join(markdown) + "\n", encoding="utf-8")
    os.chmod(report_path, 0o600)
    os.chmod(markdown_path, 0o600)
    print(f"acceptance matrix v2: {passed} passed, {failed} failed, 0 skipped")
    for gate in records: print(f"{gate['status']:>6} {gate['id']}")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())
