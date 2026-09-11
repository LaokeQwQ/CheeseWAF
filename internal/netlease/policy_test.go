package netlease

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTLSFingerprint = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestOfflinePolicyDefaultsToDenyAndAllowsOnlyRegisteredInternalTargets(t *testing.T) {
	p := NewOfflinePolicy(nil)
	if err := p.Check(Target{Host: "example.com", Port: 443, Protocol: "https"}); !errors.Is(err, ErrExternalEgressDenied) {
		t.Fatalf("expected external deny, got %v", err)
	}
	p = NewOfflinePolicy([]Resource{{Host: "control.internal", Port: 8443, Protocol: "https"}})
	if err := p.Check(Target{Host: "control.internal", Port: 8443, Protocol: "https"}); err != nil {
		t.Fatalf("internal target denied: %v", err)
	}
	if err := p.Check(Target{Host: "control.internal", Port: 443, Protocol: "https"}); !errors.Is(err, ErrResourceNotAllowed) {
		t.Fatalf("expected scope deny, got %v", err)
	}
}

func TestSocketLeaseBindsScopeEpochAndConfirmationAndExpires(t *testing.T) {
	now := time.Unix(100, 0)
	m := NewManager(func() time.Time { return now })
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	lease, err := m.Issue(IssueRequest{PluginID: "p", PluginVersion: "1.2.3", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, ConfirmationID: "confirm-1", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize(lease, RequestScope{PluginID: "p", PluginVersion: "1.2.3", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7}); err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize(lease, RequestScope{PluginID: "other", PluginVersion: "1.2.3", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7}); !errors.Is(err, ErrLeaseScope) {
		t.Fatalf("expected plugin scope failure, got %v", err)
	}
	now = now.Add(time.Minute)
	if err := m.Authorize(lease, RequestScope{PluginID: "p", PluginVersion: "1.2.3", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7}); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestSocketLeaseCanBeRevokedAndCannotCrossPolicyEpoch(t *testing.T) {
	m := NewManager(func() time.Time { return time.Unix(100, 0) })
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	lease, err := m.Issue(IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 2, ConfirmationID: "c", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize(lease, RequestScope{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 3}); !errors.Is(err, ErrLeaseScope) {
		t.Fatalf("expected epoch failure, got %v", err)
	}
	if err := m.Revoke(lease.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.Authorize(lease, RequestScope{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 2}); !errors.Is(err, ErrLeaseRevoked) {
		t.Fatalf("expected revoke, got %v", err)
	}
}

func TestSocketLeaseRejectsTTLAbovePlatformLimit(t *testing.T) {
	m := NewManager(func() time.Time { return time.Unix(100, 0) })
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	_, err := m.Issue(IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 2, ConfirmationID: "c", TTL: MaxLeaseTTL + time.Second})
	if !errors.Is(err, ErrLeaseTTL) {
		t.Fatalf("overlong lease accepted: %v", err)
	}
}

func TestTLSFingerprintValidationIsCanonical(t *testing.T) {
	if err := ValidateTLSFingerprint(testTLSFingerprint); err != nil {
		t.Fatalf("valid fingerprint rejected: %v", err)
	}
	for _, value := range []string{"sha256:abc", "SHA256:" + strings.Repeat("a", 64), "sha1:" + strings.Repeat("a", 40), "sha256:" + strings.Repeat("g", 64), "sha256: " + strings.Repeat("a", 63)} {
		if err := ValidateTLSFingerprint(value); !errors.Is(err, ErrInvalidLease) {
			t.Fatalf("fingerprint %q accepted: %v", value, err)
		}
	}
}

func TestTargetValidationRejectsAmbiguousHostAndProtocol(t *testing.T) {
	valid := Target{Host: "updates.example.com", Port: 443, Protocol: "https"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	for _, target := range []Target{
		{Host: " updates.example.com", Port: 443, Protocol: "https"},
		{Host: "UPDATES.EXAMPLE.COM", Port: 443, Protocol: "https"},
		{Host: "updates.example.com", Port: 443, Protocol: "HTTPS"},
		{Host: "updates_example.com", Port: 443, Protocol: "https"},
		{Host: "updates.example.com/path", Port: 443, Protocol: "https"},
		{Host: "127.1", Port: 443, Protocol: "https"},
		{Host: "updates.example.com", Port: 0, Protocol: "https"},
	} {
		if err := target.Validate(); !errors.Is(err, ErrResourceNotAllowed) {
			t.Fatalf("ambiguous target %+v accepted: %v", target, err)
		}
	}
}

func TestOfflinePolicyBindsEpochAndLogicalResourceID(t *testing.T) {
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	p := NewOfflinePolicyFromBindings([]ResourceBinding{{ID: "control-plane", Target: target}}, 9)
	if err := p.CheckAt(target, 8); !errors.Is(err, ErrPolicyEpoch) {
		t.Fatalf("stale epoch accepted: %v", err)
	}
	if err := p.CheckResource("control-plane", target, 9); err != nil {
		t.Fatalf("registered resource denied: %v", err)
	}
	if err := p.CheckResource("control-plane", Target{Host: "control.internal", Port: 443, Protocol: "https"}, 9); !errors.Is(err, ErrResourceNotAllowed) {
		t.Fatalf("resource target substitution accepted: %v", err)
	}
	if err := p.CheckResource("other", target, 9); !errors.Is(err, ErrResourceNotAllowed) {
		t.Fatalf("unknown resource accepted: %v", err)
	}
	snapshot := p.Snapshot()
	if snapshot.Epoch != 9 || len(snapshot.Resources) != 1 || snapshot.Resources[0].ID != "control-plane" {
		t.Fatalf("unexpected policy snapshot: %+v", snapshot)
	}
}

func TestSecureManagerRequiresExplicitTemporaryConfirmationAndConsumesOnce(t *testing.T) {
	now := time.Unix(100, 0)
	policy := NewOfflinePolicyWithEpoch([]Resource{{Host: "control.internal", Port: 8443, Protocol: "https"}}, 7)
	var confirmation ConfirmationRequest
	verifierCalls := 0
	m := NewSecureManager(policy, func() time.Time { return now }, func(req ConfirmationRequest) error {
		confirmation = req
		verifierCalls++
		return nil
	})
	target := Target{Host: "updates.example.com", Port: 443, Protocol: "https"}
	r := IssueRequest{PluginID: "p", PluginVersion: "1.2.3", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, ConfirmationID: "confirm-temp", OperatorID: "admin", TTL: time.Minute, TemporaryEgress: true}
	if _, err := m.Issue(IssueRequest{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, ConfirmationID: "without-temp", OperatorID: "admin", TTL: time.Minute}); !errors.Is(err, ErrExternalEgressDenied) {
		t.Fatalf("unmarked external egress accepted: %v", err)
	}
	lease, err := m.IssueTemporary(r)
	if err != nil {
		t.Fatalf("explicit temporary egress rejected: %v", err)
	}
	if verifierCalls != 1 || confirmation.ID != r.ConfirmationID || confirmation.OperatorID != r.OperatorID || confirmation.Target != target {
		t.Fatalf("confirmation verifier received wrong scope: calls=%d request=%+v", verifierCalls, confirmation)
	}
	if confirmation.TTL != r.TTL || !confirmation.TemporaryEgress || confirmation.MaxBytes != r.MaxBytes {
		t.Fatalf("confirmation verifier missed lease bounds: %+v", confirmation)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, OperatorID: "admin", TemporaryEgress: true}
	if err := m.Consume(lease, scope); err != nil {
		t.Fatalf("first consume rejected: %v", err)
	}
	if err := m.Consume(lease, scope); !errors.Is(err, ErrLeaseConsumed) {
		t.Fatalf("lease was reusable: %v", err)
	}
	if err := m.Authorize(lease, scope); !errors.Is(err, ErrLeaseConsumed) {
		t.Fatalf("consumed lease authorized again: %v", err)
	}
	if err := m.RecordUsage(lease, scope, 128, "success"); err != nil {
		t.Fatalf("usage result rejected: %v", err)
	}
	if err := m.RecordUsage(lease, scope, 1, "success"); !errors.Is(err, ErrLeaseConsumed) {
		t.Fatalf("lease result was recorded twice: %v", err)
	}
	got, ok := m.Get(lease.ID)
	if !ok || !got.Consumed || !got.Completed || got.Bytes != 128 || got.Requests != 1 {
		t.Fatalf("unexpected lease usage state: ok=%v lease=%+v", ok, got)
	}
	events := m.Audit()
	if len(events) < 2 {
		t.Fatalf("expected issue and connection audit events, got %d", len(events))
	}
	var resultEvent AuditEvent
	for _, event := range events {
		if event.Action == "result" {
			resultEvent = event
		}
	}
	if resultEvent.Action != "result" || resultEvent.TargetHost != target.Host || resultEvent.TargetPort != target.Port || resultEvent.TargetProtocol != target.Protocol || resultEvent.TLSFingerprint != testTLSFingerprint || resultEvent.OperatorID != "admin" || resultEvent.PolicyEpoch != 7 || resultEvent.Bytes != 128 || resultEvent.Result != "success" {
		t.Fatalf("audit omitted required connection fields: %+v", resultEvent)
	}
}

func TestSecureManagerAllowsRegisteredInternalResourceWithoutHumanPrompt(t *testing.T) {
	now := time.Unix(150, 0)
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	verifierCalls := 0
	m := NewSecureManager(NewOfflinePolicyWithEpoch([]Resource{target}, 7), func() time.Time { return now }, func(ConfirmationRequest) error {
		verifierCalls++
		return nil
	})
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 7, ConfirmationID: "internal-policy-grant", TTL: time.Minute}
	lease, err := m.Issue(r)
	if err != nil {
		t.Fatalf("registered internal resource rejected: %v", err)
	}
	if verifierCalls != 0 {
		t.Fatalf("internal allowlist unexpectedly prompted administrator: %d", verifierCalls)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: r.PolicyEpoch}
	if err := m.Consume(lease, scope); err != nil {
		t.Fatal(err)
	}
}

func TestSecureManagerRejectsConfirmationReplayAndExpiry(t *testing.T) {
	now := time.Unix(200, 0)
	policy := NewOfflinePolicyWithEpoch(nil, 4)
	m := NewSecureManager(policy, func() time.Time { return now }, func(ConfirmationRequest) error { return nil })
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: Target{Host: "updates.example.com", Port: 443, Protocol: "https"}, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 4, ConfirmationID: "one", OperatorID: "admin", TTL: time.Minute, TemporaryEgress: true, ConfirmationExpiresAt: now.Add(20 * time.Second)}
	if _, err := m.IssueTemporary(r); err != nil {
		t.Fatalf("first confirmation rejected: %v", err)
	}
	r.ConfirmationID = "one"
	if _, err := m.IssueTemporary(r); !errors.Is(err, ErrConfirmationReplay) {
		t.Fatalf("confirmation replay accepted: %v", err)
	}
	now = now.Add(20 * time.Second)
	r.ConfirmationID = "two"
	if _, err := m.IssueTemporary(r); !errors.Is(err, ErrConfirmationExpired) {
		t.Fatalf("expired confirmation accepted: %v", err)
	}
}

func TestLeaseUsageCapsAndLegacyCompatibility(t *testing.T) {
	now := time.Unix(300, 0)
	m := NewManager(func() time.Time { return now })
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: "fp", PolicyEpoch: 2, ConfirmationID: "legacy", TTL: time.Minute, MaxBytes: 100}
	lease, err := m.Issue(r)
	if err != nil {
		t.Fatalf("legacy lease rejected: %v", err)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: r.PolicyEpoch}
	if err := m.Consume(lease, scope); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordUsage(lease, scope, 101, "failed"); !errors.Is(err, ErrUsageLimit) {
		t.Fatalf("byte cap bypassed: %v", err)
	}
	if err := m.RecordUsage(lease, scope, 100, "failed"); err != nil {
		t.Fatalf("usage at cap rejected: %v", err)
	}
}

func TestSecureManagerRejectsUnboundPolicyAndTemporaryWithoutApproval(t *testing.T) {
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	if _, err := NewSecureManager(NewOfflinePolicy([]Resource{target}), time.Now, func(ConfirmationRequest) error { return nil }).Issue(IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 1, ConfirmationID: "c", OperatorID: "admin", TTL: time.Minute}); !errors.Is(err, ErrPolicyEpoch) {
		t.Fatalf("secure manager accepted an unversioned policy: %v", err)
	}
	m := NewManagerWithOptions(ManagerOptions{Now: time.Now, AllowTemporaryEgress: true})
	_, err := m.IssueTemporary(IssueRequest{PluginID: "p", PluginVersion: "1", Target: Target{Host: "updates.example.com", Port: 443, Protocol: "https"}, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 1, ConfirmationID: "c", OperatorID: "admin", TTL: time.Minute})
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("temporary lease bypassed administrator verifier: %v", err)
	}
}

func TestRecordTransferAuditsDirectionalBytesWithoutPayload(t *testing.T) {
	now := time.Unix(400, 0)
	m := NewManager(func() time.Time { return now })
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c", TTL: time.Minute}
	lease, err := m.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: r.PolicyEpoch}
	if err := m.Consume(lease, scope); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordTransfer(lease, scope, Usage{BytesSent: 12, BytesReceived: 30, Result: "timeout"}); err != nil {
		t.Fatal(err)
	}
	events := m.Audit()
	last := events[len(events)-1]
	if last.Bytes != 42 || last.BytesSent != 12 || last.BytesReceived != 30 || last.Result != "timeout" {
		t.Fatalf("directional usage not audited: %+v", last)
	}
}

func TestLeaseScopeBindsResourceOperatorAndTemporaryMode(t *testing.T) {
	now := time.Unix(500, 0)
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	m := NewManager(func() time.Time { return now })
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 1, ConfirmationID: "c", ResourceID: "control", OperatorID: "admin", TTL: time.Minute, TemporaryEgress: true}
	lease, err := m.Issue(r)
	if err == nil {
		// Legacy manager correctly rejects the explicit temporary capability.
		t.Fatalf("legacy manager unexpectedly issued temporary lease: %+v", lease)
	}
	secure := NewSecureManager(NewOfflinePolicyFromBindings([]ResourceBinding{{ID: "control", Target: target}}, 1), func() time.Time { return now }, func(ConfirmationRequest) error { return nil })
	r.TemporaryEgress = false
	lease, err = secure.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: 1, ResourceID: r.ResourceID, OperatorID: r.OperatorID}
	if err := secure.Authorize(lease, scope); err != nil {
		t.Fatal(err)
	}
	scope.OperatorID = "other"
	if err := secure.Authorize(lease, scope); !errors.Is(err, ErrLeaseScope) {
		t.Fatalf("operator scope was not bound: %v", err)
	}
}

func TestConsumeIsAtomicUnderConcurrentAttempts(t *testing.T) {
	now := time.Unix(600, 0)
	m := NewManager(func() time.Time { return now })
	target := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: target, TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "atomic", TTL: time.Minute}
	lease, err := m.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: target, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: r.PolicyEpoch}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- m.Consume(lease, scope)
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	consumed := 0
	for err := range results {
		if err == nil {
			ok++
		}
		if errors.Is(err, ErrLeaseConsumed) {
			consumed++
		}
	}
	if ok != 1 || consumed != 1 {
		t.Fatalf("concurrent consume was not one-shot: success=%d consumed=%d", ok, consumed)
	}
}

func TestUpdatePolicyInvalidatesOlderLeasesByEpoch(t *testing.T) {
	now := time.Unix(700, 0)
	oldTarget := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	newTarget := Target{Host: "control.internal", Port: 9443, Protocol: "https"}
	manager := NewSecureManager(NewOfflinePolicyWithEpoch([]Resource{oldTarget}, 1), func() time.Time { return now }, func(ConfirmationRequest) error { return nil })
	r := IssueRequest{PluginID: "p", PluginVersion: "1", Target: oldTarget, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 1, ConfirmationID: "old", OperatorID: "admin", TTL: time.Minute}
	lease, err := manager.Issue(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdatePolicy(NewOfflinePolicyWithEpoch([]Resource{newTarget}, 2)); err != nil {
		t.Fatal(err)
	}
	scope := RequestScope{PluginID: r.PluginID, PluginVersion: r.PluginVersion, Target: oldTarget, TLSFingerprint: r.TLSFingerprint, PolicyEpoch: 1, OperatorID: r.OperatorID}
	if err := manager.Authorize(lease, scope); !errors.Is(err, ErrPolicyEpoch) {
		t.Fatalf("old-epoch lease remained usable: %v", err)
	}
	if err := manager.UpdatePolicy(NewOfflinePolicyWithEpoch([]Resource{newTarget}, 2)); !errors.Is(err, ErrPolicyEpoch) {
		t.Fatalf("non-monotonic policy update accepted: %v", err)
	}
}

func TestUpdatePolicyTurnsLegacyManagerIntoFailClosedPolicyBoundary(t *testing.T) {
	now := time.Unix(800, 0)
	manager := NewManager(func() time.Time { return now })
	allowed := Target{Host: "control.internal", Port: 8443, Protocol: "https"}
	if err := manager.UpdatePolicy(NewOfflinePolicyWithEpoch([]Resource{allowed}, 2)); err != nil {
		t.Fatal(err)
	}
	denied := IssueRequest{PluginID: "p", PluginVersion: "1", Target: Target{Host: "updates.example.com", Port: 443, Protocol: "https"}, TLSFingerprint: testTLSFingerprint, PolicyEpoch: 2, ConfirmationID: "legacy-now-denied", TTL: time.Minute}
	if _, err := manager.Issue(denied); !errors.Is(err, ErrExternalEgressDenied) {
		t.Fatalf("legacy manager bypassed newly published policy: %v", err)
	}
}
