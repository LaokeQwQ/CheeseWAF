package activation

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
)

func snapshotAuthorization(t *testing.T, now time.Time) Authorization {
	t.Helper()
	descriptor := SidecarDescriptor{
		PluginID: "rate-limit", Runtime: "sidecar", Version: "1.0.0",
		Namespace: "official/security", Source: "ota", SourceRoot: "root",
		ManifestIdentity: strings.Repeat("a", 64), ArtifactIdentity: strings.Repeat("b", 64),
		Capabilities: []string{"observe"}, Metadata: map[string]string{"channel": "stable"},
	}
	digest, err := descriptorIdentity(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Minute)
	request := AuthorizationRequest{
		SchemaVersion: TransportSchemaVersion, RequestID: "request-1",
		Identity: TransportIdentity{ClusterID: "cluster-a", NodeID: "node-a", Role: "waf", CertificateSHA256: strings.Repeat("c", 64)},
		Action:   crp.RuntimeActionPromote, Permission: PermissionActivate,
		Target: RuntimeTarget{Key: "rate-limit", PluginID: descriptor.PluginID, Namespace: descriptor.Namespace,
			Version: descriptor.Version, ReleaseSequence: 1, ManifestIdentity: descriptor.ManifestIdentity,
			ArtifactIdentity: descriptor.ArtifactIdentity, Revision: 1},
		ExpectedRevision: 1, Descriptor: descriptor, DescriptorIdentity: digest,
		Canary: CanaryPolicy{ObserveProbes: 1, CanaryProbes: 1}, RequestedAt: now,
	}
	request.ApprovalClaim = testApprovalClaim(request)
	return Authorization{
		SchemaVersion: TransportSchemaVersion, ID: "authorization-1", Request: request, ApprovalClaim: request.ApprovalClaim,
		Fence: Fence{ClusterID: "cluster-a", Token: "fence-1", Epoch: 1, Revision: 1, ExpiresAt: expires},
		Confirmation: &WireConfirmation{ID: request.ApprovalClaim.ConfirmationID, Actor: request.ApprovalClaim.Actor, Action: request.Action,
			PluginKey: request.Target.Key, ManifestIdentity: request.Target.ManifestIdentity,
			ExpectedRevision: 1, AuthorizedAt: now, ExpiresAt: expires},
		IssuedAt: now, ExpiresAt: expires,
	}
}

func mutateAuthorizationSnapshot(authorization *Authorization) {
	authorization.Confirmation.Actor = "different-operator"
	authorization.Request.Descriptor.Capabilities[0] = "active"
	authorization.Request.Descriptor.Metadata["channel"] = "different-channel"
}

func TestValidateAuthorizationRequestRequiresV2ApprovalClaim(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := snapshotAuthorization(t, now).Request
	tests := []struct {
		name   string
		mutate func(*AuthorizationRequest)
	}{
		{name: "old schema", mutate: func(request *AuthorizationRequest) { request.SchemaVersion = "crp-activation-transport.v1" }},
		{name: "missing claim", mutate: func(request *AuthorizationRequest) { request.ApprovalClaim = ApprovalClaim{} }},
		{name: "invalid approval id", mutate: func(request *AuthorizationRequest) { request.ApprovalClaim.ApprovalID = " approval" }},
		{name: "intent drift", mutate: func(request *AuthorizationRequest) { request.ApprovalClaim.IntentDigest = strings.Repeat("0", 64) }},
		{name: "scope drift", mutate: func(request *AuthorizationRequest) { request.ApprovalClaim.Scope = "crp:other:rate-limit" }},
		{name: "workflow digest drift", mutate: func(request *AuthorizationRequest) { request.ApprovalClaim.WorkflowDigest = "not-a-digest" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.mutate(&request)
			if err := validateAuthorizationRequest(request, request.Identity); !errors.Is(err, ErrAuthorizationBinding) {
				t.Fatalf("validateAuthorizationRequest() = %v, want ErrAuthorizationBinding", err)
			}
		})
	}
}

func TestValidateAuthorizationBindsClaimEchoAndConfirmation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := snapshotAuthorization(t, now)
	tests := []struct {
		name   string
		mutate func(*Authorization)
	}{
		{name: "missing top-level claim", mutate: func(authorization *Authorization) { authorization.ApprovalClaim = ApprovalClaim{} }},
		{name: "top-level claim drift", mutate: func(authorization *Authorization) { authorization.ApprovalClaim.Actor = "other-actor" }},
		{name: "request claim drift", mutate: func(authorization *Authorization) { authorization.Request.ApprovalClaim.Scope = "crp:other:rate-limit" }},
		{name: "confirmation id drift", mutate: func(authorization *Authorization) { authorization.Confirmation.ID = "other-confirmation" }},
		{name: "confirmation actor drift", mutate: func(authorization *Authorization) { authorization.Confirmation.Actor = "other-actor" }},
		{name: "authorization extends claim", mutate: func(authorization *Authorization) {
			authorization.ExpiresAt = authorization.Request.ApprovalClaim.ExpiresAt.Add(time.Minute)
		}},
		{name: "confirmation extends claim", mutate: func(authorization *Authorization) {
			authorization.Confirmation.ExpiresAt = authorization.Request.ApprovalClaim.ExpiresAt.Add(time.Minute)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := cloneAuthorization(base)
			test.mutate(&authorization)
			if err := validateAuthorization(authorization, base.Request, now); !errors.Is(err, ErrAuthorizationBinding) {
				t.Fatalf("validateAuthorization() = %v, want ErrAuthorizationBinding", err)
			}
		})
	}
}

func TestCloneDescriptorPreservesMetadataAndOwnsMutableFields(t *testing.T) {
	original := snapshotAuthorization(t, time.Now().UTC()).Request.Descriptor
	cloned := cloneDescriptor(original)
	if !reflect.DeepEqual(cloned, original) {
		t.Fatalf("descriptor changed during clone: got %+v, want %+v", cloned, original)
	}
	cloned.Metadata["channel"] = "changed"
	cloned.Capabilities[0] = "active"
	if original.Metadata["channel"] != "stable" || original.Capabilities[0] != "observe" {
		t.Fatalf("clone shares mutable fields with source: %+v", original)
	}
}

func TestMemoryAuthorizationStateSnapshotsPutAndGet(t *testing.T) {
	for _, source := range []string{"put", "get"} {
		t.Run(source, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			state, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			input := snapshotAuthorization(t, now)
			expected := snapshotAuthorization(t, now)
			if err := state.Put(context.Background(), input); err != nil {
				t.Fatal(err)
			}
			if source == "get" {
				input, err = state.Get(context.Background(), input.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			mutateAuthorizationSnapshot(&input)
			stored, err := state.Get(context.Background(), expected.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored, expected) {
				t.Fatalf("%s mutation changed pending authorization: got %+v, want %+v", source, stored, expected)
			}
			if err := state.Consume(context.Background(), input); !errors.Is(err, ErrAuthorizationBinding) {
				t.Fatalf("mutated authorization consume = %v, want ErrAuthorizationBinding", err)
			}
			if err := state.Consume(context.Background(), expected); err != nil {
				t.Fatalf("original authorization consume = %v", err)
			}
			if err := state.Consume(context.Background(), expected); !errors.Is(err, ErrAuthorizationReplay) {
				t.Fatalf("second consume = %v, want ErrAuthorizationReplay", err)
			}
		})
	}
}

func TestMemoryAuthorizationStateRejectsMutatedDuplicate(t *testing.T) {
	now := time.Now().UTC()
	state, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	input := snapshotAuthorization(t, now)
	if err := state.Put(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	mutateAuthorizationSnapshot(&input)
	if err := state.Put(context.Background(), input); !errors.Is(err, ErrAuthorizationBinding) {
		t.Fatalf("mutated duplicate put = %v, want ErrAuthorizationBinding", err)
	}
}

func TestMemoryAuthorizationStateConcurrentReadsAreIndependent(t *testing.T) {
	now := time.Now().UTC()
	state, err := NewMemoryAuthorizationState(1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	expected := snapshotAuthorization(t, now)
	if err := state.Put(context.Background(), expected); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, err := state.Get(context.Background(), expected.ID)
			if err != nil {
				t.Error(err)
				return
			}
			mutateAuthorizationSnapshot(&got)
		})
	}
	wg.Wait()
	got, err := state.Get(context.Background(), expected.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("concurrent reader mutation changed authorization: got %+v, want %+v", got, expected)
	}
}

func TestHTTPControlPlaneClientSnapshotsReturnedAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Authorization)
	}{
		{name: "confirmation", mutate: func(a *Authorization) { a.Confirmation.Actor = "different-operator" }},
		{name: "capability", mutate: func(a *Authorization) { a.Request.Descriptor.Capabilities[0] = "active" }},
		{name: "metadata", mutate: func(a *Authorization) { a.Request.Descriptor.Metadata["channel"] = "different-channel" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			harness := &transportHarness{now: now}
			pki := newMTLSPKIFixture(t)
			server := pki.newServer(t, "control-plane", http.HandlerFunc(harness.controlHandler))
			client, _ := newWireClients(t, server.server.URL, "control-plane", server.server.URL, "control-plane", pki.clientBundle)
			request := snapshotAuthorization(t, now).Request
			request.Identity = client.TransportIdentity()
			request.ApprovalClaim = testApprovalClaim(request)
			grant, err := client.Authorize(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			originalConfirmation := grant.Confirmation.RuntimeConfirmation()
			tc.mutate(&grant)
			if err := client.Validate(context.Background(), grant); !errors.Is(err, ErrConfirmationBinding) && !errors.Is(err, ErrAuthorizationBinding) {
				t.Fatalf("mutated returned authorization validate = %v, want a binding error", err)
			}
			harness.mu.Lock()
			validates := len(harness.validates)
			harness.mu.Unlock()
			if validates != 0 {
				t.Fatalf("mutated authorization reached remote provider: %d validates", validates)
			}
			if err := client.Consume(context.Background(), originalConfirmation); err != nil {
				t.Fatalf("mutating returned grant changed original pending confirmation: %v", err)
			}
			harness.mu.Lock()
			consumes := append([]crp.Confirmation(nil), harness.consumes...)
			harness.mu.Unlock()
			if len(consumes) != 1 || consumes[0] != originalConfirmation {
				t.Fatalf("remote consumes = %+v, want original confirmation %+v", consumes, originalConfirmation)
			}
		})
	}
}
