package cwedp

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type testLeaseVerifier struct{ got LeaseBinding }

func (v *testLeaseVerifier) VerifyLease(b LeaseBinding) error { v.got = b; return nil }

func TestBrokerNegotiatesPersistsResumeAndVerifiesAllDigests(t *testing.T) {
	data := []byte("cheese-waf-package")
	intent := intentForData(data)
	registry, err := NewSourceRegistry([]SourceRegistration{
		{ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"},
		{ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := &testLeaseVerifier{}
	store := NewMemoryResumeStore()
	broker := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: verifier, QueueSize: 4})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	broker.Start(ctx)
	req := TransferRequest{
		Intent:       intent,
		Hello:        Hello{NodeID: "node-1", Protocol: ProtocolVersion, Offline: true},
		Capabilities: Capabilities{NodeID: "node-1", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline}, MaxChunkSize: 8},
		Lease:        LeaseBinding{PluginID: "p", PluginVersion: "1.0.0", TargetHost: "127.0.0.1", TargetPort: 9443, TargetProtocol: "https", TLSFingerprint: "sha256:offline", PolicyEpoch: 3, ConfirmationID: "confirm-1"},
	}
	job, err := broker.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.got != req.Lease {
		t.Fatalf("lease not verified: got %+v", verifier.got)
	}
	if err := broker.Push(job.ID, 0, data[:8]); err != nil {
		t.Fatal(err)
	}
	if err := broker.Push(job.ID, 8, data[8:16]); err != nil {
		t.Fatal(err)
	}
	if err := broker.Push(job.ID, 16, data[16:]); err != nil {
		t.Fatal(err)
	}
	result, err := broker.Wait(job.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.NextOffset != int64(len(data)) || !result.Complete {
		t.Fatalf("result=%+v", result)
	}
	saved, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.NextOffset != int64(len(data)) || !saved.Complete {
		t.Fatalf("saved=%+v", saved)
	}
}

func TestBrokerRejectsOfflineWithoutOfflineSource(t *testing.T) {
	data := []byte("abc")
	intent := intentForData(data)
	intent.Sources = []Source{{Kind: SourcePeer, ID: "peer"}}
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}, {ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}})
	broker := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}})
	if _, err := broker.Submit(TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion, Offline: true}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", PolicyEpoch: 1, ConfirmationID: "c"}}); !errors.Is(err, ErrOfflineSource) {
		t.Fatalf("offline source accepted: %v", err)
	}
}

func TestBrokerPersistsResumeAcrossBrokerInstances(t *testing.T) {
	data := []byte("abcdefgh")
	intent := intentForData(data)
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}, {ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}})
	store := NewMemoryResumeStore()
	cfg := BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}}
	b1 := NewBroker(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b1.Start(ctx)
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "sha256:peer", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b1.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := b1.Push(job.ID, 0, data[:4]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	b2 := NewBroker(cfg)
	b2.Start(ctx)
	resumed, err := b2.Resume(job.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.NextOffset != 4 || resumed.Complete {
		t.Fatalf("resume=%+v", resumed)
	}
	if err := b2.Push(job.ID, 4, data[4:]); err != nil {
		t.Fatal(err)
	}
	result, err := b2.Wait(job.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete {
		t.Fatalf("not complete: %+v", result)
	}
}

func TestBrokerRejectsDigestMismatchAsTerminalFailure(t *testing.T) {
	data := []byte("abc")
	intent := intentForData(data)
	intent.Digests.SHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}, {ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}})
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	job, err := b.Submit(TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion, Offline: true}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "127.0.0.1", TargetPort: 9443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Push(job.ID, 0, data); err != nil {
		t.Fatal(err)
	}
	result, err := b.Wait(job.ID, time.Second)
	if !errors.Is(err, ErrInvalid) || !result.Failed || result.Complete {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestBrokerRejectsInvalidStructuredLeaseBinding(t *testing.T) {
	data := []byte("abc")
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}, {ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}})
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}})
	_, err := b.Submit(TransferRequest{Intent: intentForData(data), Hello: Hello{NodeID: "n", Protocol: ProtocolVersion, Offline: true}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "127.0.0.1", TargetPort: 0, TargetProtocol: "https", PolicyEpoch: 1, ConfirmationID: "c"}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid lease accepted: %v", err)
	}
}

func TestBrokerSubmitIsIdempotentAndPreservesResumeState(t *testing.T) {
	data := []byte("abcdefgh")
	intent := intentForData(data)
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}, {ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}})
	store := NewMemoryResumeStore()
	broker := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}})
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := broker.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	state.Data, state.NextOffset = append([]byte(nil), data[:4]...), 4
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Submit(req); err != nil {
		t.Fatalf("idempotent submit rejected: %v", err)
	}
	resumed, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resumed.NextOffset != 4 || string(resumed.Data) != string(data[:4]) {
		t.Fatalf("duplicate submit reset resume state: %+v", resumed)
	}
}

func TestBrokerRejectsChunkAboveByteBudgetBeforeQueueing(t *testing.T) {
	data := []byte("abcdefgh")
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}, {ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}})
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}, MaxChunkBytes: 4})
	intent := intentForData(data)
	intent.Sources = []Source{{Kind: SourcePeer, ID: "peer"}, {Kind: SourceOffline, ID: "offline"}}
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 8}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Push(job.ID, 0, data[:5]); !errors.Is(err, ErrChunkSize) {
		t.Fatalf("oversized chunk accepted: %v", err)
	}
}

func TestBrokerPersistsCorruptResumeStateAsTerminalFailure(t *testing.T) {
	data := []byte("abcdefgh")
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}, {ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}})
	store := NewMemoryResumeStore()
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}})
	intent := intentForData(data)
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	state.NextOffset = 1
	state.Data = nil
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	if err := b.Push(job.ID, 0, data[:1]); err != nil {
		t.Fatal(err)
	}
	result, err := b.Wait(job.ID, time.Second)
	if !errors.Is(err, ErrInvalid) || !result.Failed {
		t.Fatalf("corrupt state result=%+v err=%v", result, err)
	}
	saved, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Failed {
		t.Fatal("corrupt state was not persisted as terminal failure")
	}
}

func TestBrokerRejectsTransferAboveArtifactBudget(t *testing.T) {
	data := []byte("abcdefgh")
	registry, _ := NewSourceRegistry([]SourceRegistration{{ID: "peer", Kind: SourcePeer, Root: "enterprise", IndependenceGroup: "enterprise"}, {ID: "offline", Kind: SourceOffline, Root: "official", IndependenceGroup: "official"}})
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}, MaxArtifactBytes: 4})
	intent := intentForData(data)
	intent.Sources = []Source{{Kind: SourcePeer, ID: "peer"}, {Kind: SourceOffline, ID: "offline"}}
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	if _, err := b.Submit(req); !errors.Is(err, ErrTransferTooLarge) {
		t.Fatalf("oversized transfer accepted: %v", err)
	}
}

func TestMemoryResumeStoreSaveExpectedRejectsStaleOffset(t *testing.T) {
	store := NewMemoryResumeStore()
	state := ResumeState{JobID: "job", Intent: intentForData([]byte("abc")), MaxChunk: 3, MaxSourceSwitches: DefaultMaxSourceSwitches, Source: Source{Kind: SourceOffline, ID: "offline"}, UpdatedAt: time.Now().UTC()}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	next := state
	next.Data = []byte("a")
	next.NextOffset = 1
	if err := store.SaveExpected(context.Background(), 0, next); err != nil {
		t.Fatal(err)
	}
	next.Data = []byte("ab")
	next.NextOffset = 2
	if !errors.Is(store.SaveExpected(context.Background(), 0, next), ErrResumeOffsetConflict) {
		t.Fatal("stale expected offset was accepted")
	}
}

func TestBrokerQuarantinesBadSourceAndSwitchesAtomically(t *testing.T) {
	data := []byte("abcdefgh")
	intent := intentForData(data)
	registry, err := NewSourceRegistry([]SourceRegistration{
		{ID: "offline", Kind: SourceOffline, Root: "official-root", IndependenceGroup: "official"},
		{ID: "peer", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryResumeStore()
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}, MaxSourceSwitches: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	req := TransferRequest{
		Intent:       intent,
		Hello:        Hello{NodeID: "n", Protocol: ProtocolVersion},
		Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline, SourcePeer}, MaxChunkSize: 8},
		Lease:        LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"},
	}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if job.Source.ID != "offline" {
		t.Fatalf("initial source=%+v", job.Source)
	}
	if err := b.Push(job.ID, 0, []byte("XXXXXXXX")); err != nil {
		t.Fatal(err)
	}
	result, err := b.Wait(job.ID, time.Second)
	if err != nil {
		t.Fatalf("switch result err=%v result=%+v", err, result)
	}
	if !result.Retrying || result.Source.ID != "peer" || result.QuarantinedSource.ID != "offline" {
		t.Fatalf("unexpected switch result=%+v", result)
	}
	saved, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Source.ID != "peer" || saved.NextOffset != 0 || len(saved.Data) != 0 || saved.Failed || len(saved.QuarantinedSources) != 1 || saved.QuarantinedSources[0].Reason != QuarantineIntegrity {
		t.Fatalf("unsafe switch state=%+v", saved)
	}
	if _, err := b.Submit(req); err != nil {
		t.Fatalf("duplicate submit after source switch rejected: %v", err)
	}
	if err := b.Push(job.ID, 0, data); err != nil {
		t.Fatal(err)
	}
	result, err = b.Wait(job.ID, time.Second)
	if err != nil || !result.Complete {
		t.Fatalf("fallback completion result=%+v err=%v", result, err)
	}
}

func TestBrokerIntegrityFailureSkipsSameSupplyChainMirror(t *testing.T) {
	data := []byte("abcdefgh")
	intent := intentForData(data)
	intent.Sources = []Source{
		{Kind: SourceOffline, ID: "offline"},
		{Kind: SourceOTA, ID: "mirror"},
		{Kind: SourcePeer, ID: "peer"},
	}
	registry, _ := NewSourceRegistry([]SourceRegistration{
		{ID: "offline", Kind: SourceOffline, Root: "root-a", IndependenceGroup: "vendor-a"},
		{ID: "mirror", Kind: SourceOTA, Root: "root-a", IndependenceGroup: "vendor-a"},
		{ID: "peer", Kind: SourcePeer, Root: "root-b", IndependenceGroup: "enterprise-b"},
	})
	store := NewMemoryResumeStore()
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}, MaxSourceSwitches: 2})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline, SourceOTA, SourcePeer}, MaxChunkSize: 8}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Push(job.ID, 0, []byte("XXXXXXXX")); err != nil {
		t.Fatal(err)
	}
	result, err := b.Wait(job.ID, time.Second)
	if err != nil || !result.Retrying || result.Source.ID != "peer" {
		t.Fatalf("same-root mirror was selected: result=%+v err=%v", result, err)
	}
}

func TestBrokerQuarantineSourceRejectsStaleSourceAndExhaustsLimit(t *testing.T) {
	data := []byte("abcdefgh")
	intent := intentForData(data)
	registry, _ := NewSourceRegistry([]SourceRegistration{
		{ID: "offline", Kind: SourceOffline, Root: "official-root", IndependenceGroup: "official"},
		{ID: "peer", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"},
	})
	store := NewMemoryResumeStore()
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}, MaxSourceSwitches: 1})
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline, SourcePeer}, MaxChunkSize: 8}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.QuarantineSource(job.ID, req, Source{Kind: SourcePeer, ID: "peer"}, QuarantineTransport); !errors.Is(err, ErrResumeOffsetConflict) {
		t.Fatalf("stale source accepted: %v", err)
	}
	next, err := b.QuarantineSource(job.ID, req, job.Source, QuarantineTransport)
	if err != nil {
		t.Fatal(err)
	}
	if next.Source.ID != "peer" {
		t.Fatalf("fallback source=%+v", next)
	}
	if _, err := b.QuarantineSource(job.ID, req, next.Source, QuarantineTransport); !errors.Is(err, ErrSourceSwitchLimit) {
		t.Fatalf("source switch limit not enforced: %v", err)
	}
	saved, err := store.Load(context.Background(), job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Failed || saved.Failure == "" {
		t.Fatalf("exhausted source state not terminal: %+v", saved)
	}
}

func TestBrokerRetriesQuarantinedSourceAfterCapabilitiesRefresh(t *testing.T) {
	data := []byte("abcdefgh")
	intent := intentForData(data)
	registry, _ := NewSourceRegistry([]SourceRegistration{
		{ID: "offline", Kind: SourceOffline, Root: "official-root", IndependenceGroup: "official"},
		{ID: "peer", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"},
	})
	store := NewMemoryResumeStore()
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: store, LeaseVerifier: &testLeaseVerifier{}, MaxSourceSwitches: 2})
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOffline}, MaxChunkSize: 8}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.QuarantineSource(job.ID, req, job.Source, QuarantineTransport); !errors.Is(err, ErrNoSource) {
		t.Fatalf("missing fallback error=%v", err)
	}
	state, err := store.Load(context.Background(), job.ID)
	if err != nil || !state.Failed || !sourceKeyInQuarantines(state.QuarantinedSources, job.Source) {
		t.Fatalf("no-source quarantine state=%+v err=%v", state, err)
	}
	refreshed := req
	refreshed.Capabilities.Sources = []SourceKind{SourcePeer}
	next, err := b.QuarantineSource(job.ID, refreshed, job.Source, QuarantineTransport)
	if err != nil || next.Source.ID != "peer" {
		t.Fatalf("capability refresh did not recover source: next=%+v err=%v", next, err)
	}
	state, err = store.Load(context.Background(), job.ID)
	if err != nil || state.Failed || state.SourceSwitches != 1 || len(state.QuarantinedSources) != 1 {
		t.Fatalf("recovery state=%+v err=%v", state, err)
	}
}

func TestMemoryResumeStoreDeepCopiesSourceQuarantines(t *testing.T) {
	store := NewMemoryResumeStore()
	state := ResumeState{JobID: "job", Intent: intentForData(nil), MaxChunk: 1, UpdatedAt: time.Now().UTC(), QuarantinedSources: []SourceQuarantine{{Source: Source{Kind: SourceOffline, ID: "offline"}, Reason: QuarantineTransport}}}
	if err := store.Save(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(context.Background(), state.JobID)
	if err != nil {
		t.Fatal(err)
	}
	loaded.QuarantinedSources[0].Source.ID = "mutated"
	loaded.Intent.Sources[0].ID = "mutated"
	reloaded, err := store.Load(context.Background(), state.JobID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.QuarantinedSources[0].Source.ID != "offline" || reloaded.Intent.Sources[0].ID != "offline" {
		t.Fatalf("resume store leaked mutable slices: %+v", reloaded)
	}
}

type nonAtomicResumeStore struct{ state ResumeState }

func (s *nonAtomicResumeStore) Save(_ context.Context, state ResumeState) error {
	s.state = state
	return nil
}
func (s *nonAtomicResumeStore) Load(_ context.Context, _ string) (ResumeState, error) {
	if s.state.JobID == "" {
		return ResumeState{}, ErrJobNotFound
	}
	return s.state, nil
}

func TestBrokerRequiresAtomicResumeStore(t *testing.T) {
	data := []byte("abc")
	registry, _ := NewSourceRegistry([]SourceRegistration{
		{ID: "offline", Kind: SourceOffline, Root: "official-root", IndependenceGroup: "official"},
		{ID: "peer", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"},
	})
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: &nonAtomicResumeStore{}, LeaseVerifier: &testLeaseVerifier{}})
	req := TransferRequest{Intent: intentForData(data), Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	if _, err := b.Submit(req); !errors.Is(err, ErrAtomicResumeRequired) {
		t.Fatalf("non-atomic resume store accepted: %v", err)
	}
}

func TestBrokerAllowsExplicitSingleSourceLowRiskPolicy(t *testing.T) {
	data := []byte("abc")
	intent := intentForData(data)
	intent.Sources = []Source{{Kind: SourcePeer, ID: "peer"}}
	registry, err := NewSourceRegistry([]SourceRegistration{{ID: "peer", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"}})
	if err != nil {
		t.Fatal(err)
	}
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}, MinIndependentSources: 1})
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	if _, err := b.Submit(req); err != nil {
		t.Fatalf("explicit low-risk single source rejected: %v", err)
	}
}

func TestBrokerRetainsTerminalEventAfterManyChunks(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwxyz")
	intent := intentForData(data)
	registry, _ := NewSourceRegistry([]SourceRegistration{
		{ID: "peer", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"},
		{ID: "offline", Kind: SourceOffline, Root: "official-root", IndependenceGroup: "official"},
	})
	b := NewBroker(BrokerConfig{Registry: registry, ResumeStore: NewMemoryResumeStore(), LeaseVerifier: &testLeaseVerifier{}, QueueSize: 64})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)
	req := TransferRequest{Intent: intent, Hello: Hello{NodeID: "n", Protocol: ProtocolVersion}, Capabilities: Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 1}, Lease: LeaseBinding{PluginID: "p", PluginVersion: "1", TargetHost: "peer", TargetPort: 443, TargetProtocol: "https", TLSFingerprint: "fp", PolicyEpoch: 1, ConfirmationID: "c"}}
	job, err := b.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	for offset, byteValue := range data {
		if err := b.Push(job.ID, int64(offset), []byte{byteValue}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := b.Wait(job.ID, time.Second)
	if err != nil || !result.Complete {
		t.Fatalf("terminal event was dropped: result=%+v err=%v", result, err)
	}
}

func intentForData(data []byte) DistributionIntent {
	return DistributionIntent{ID: "intent", PackageID: "official/demo", Version: "1.0.0", Size: int64(len(data)), Digests: digestsFor(data), Sources: []Source{{Kind: SourceOffline, ID: "offline"}, {Kind: SourcePeer, ID: "peer"}}, Signature: "signed-intent"}
}
func digestsFor(data []byte) Digests {
	m, a, h := md5.Sum(data), sha1.Sum(data), sha256.Sum256(data)
	return Digests{MD5: hex.EncodeToString(m[:]), SHA1: hex.EncodeToString(a[:]), SHA256: hex.EncodeToString(h[:])}
}
