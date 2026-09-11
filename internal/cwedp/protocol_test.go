package cwedp

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestIntentAndNegotiation(t *testing.T) {
	intent := DistributionIntent{ID: "i-1", PackageID: "official/demo", Version: "1.2.3", Size: 10, Digests: Digests{MD5: strings.Repeat("a", 32), SHA1: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64)}, Sources: []Source{{Kind: SourceOTA, ID: "ota"}, {Kind: SourcePeer, ID: "peer-a"}}, Signature: "signed-intent"}
	if err := intent.Validate(); err != nil {
		t.Fatal(err)
	}
	hello := Hello{NodeID: "node-a", Protocol: ProtocolVersion, Offline: false}
	caps := Capabilities{NodeID: "node-a", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOTA, SourcePeer}, MaxChunkSize: 4}
	if err := hello.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := caps.Validate(); err != nil {
		t.Fatal(err)
	}
	source, err := Negotiate(intent, hello, caps)
	if err != nil || source.Kind != SourceOTA {
		t.Fatalf("source=%+v err=%v", source, err)
	}
}

func TestOfflineAndSourceIndependence(t *testing.T) {
	intent := validIntent()
	intent.Sources = []Source{{Kind: SourcePeer, ID: "peer"}, {Kind: SourceOffline, ID: "crp"}}
	caps := Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOTA, SourcePeer}, MaxChunkSize: 4}
	if _, err := Negotiate(intent, Hello{NodeID: "n", Protocol: ProtocolVersion, Offline: true}, caps); !errors.Is(err, ErrOfflineSource) {
		t.Fatalf("err=%v", err)
	}
	registry := mustSourceRegistry(t,
		SourceRegistration{ID: "peer", Kind: SourcePeer, Root: "vendor-root", IndependenceGroup: "vendor"},
		SourceRegistration{ID: "crp", Kind: SourceOffline, Root: "enterprise-root", IndependenceGroup: "enterprise"},
	)
	if err := ValidateSourceIndependence(intent, registry); err != nil {
		t.Fatal(err)
	}
}

func TestSourceIndependence(t *testing.T) {
	tests := []struct {
		name          string
		intentSources []Source
		registrations []SourceRegistration
		wantErr       error
	}{
		{
			name:          "rejects source without registered root",
			intentSources: []Source{{Kind: SourceOTA, ID: "ota-a"}, {Kind: SourcePeer, ID: "peer-b"}},
			registrations: []SourceRegistration{{ID: "peer-b", Kind: SourcePeer, Root: "enterprise-root", IndependenceGroup: "enterprise"}},
			wantErr:       ErrSourceIndependence,
		},
		{
			name:          "rejects OTA and peer from one root",
			intentSources: []Source{{Kind: SourceOTA, ID: "ota-a"}, {Kind: SourcePeer, ID: "peer-b"}},
			registrations: []SourceRegistration{{ID: "ota-a", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}, {ID: "peer-b", Kind: SourcePeer, Root: "vendor-root", IndependenceGroup: "vendor"}},
			wantErr:       ErrSourceIndependence,
		},
		{
			name:          "allows one kind from two independent roots",
			intentSources: []Source{{Kind: SourceOTA, ID: "ota-a"}, {Kind: SourceOTA, ID: "ota-b"}},
			registrations: []SourceRegistration{{ID: "ota-a", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}, {ID: "ota-b", Kind: SourceOTA, Root: "enterprise-root", IndependenceGroup: "enterprise"}},
		},
		{
			name:          "duplicate mirrors do not add an independent root",
			intentSources: []Source{{Kind: SourceOTA, ID: "mirror-a"}, {Kind: SourceOTA, ID: "mirror-b"}},
			registrations: []SourceRegistration{{ID: "mirror-a", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}, {ID: "mirror-b", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}},
			wantErr:       ErrSourceIndependence,
		},
		{
			name:          "rejects unknown source kind",
			intentSources: []Source{{Kind: SourceKind("unknown"), ID: "mystery"}, {Kind: SourceOTA, ID: "ota-a"}},
			registrations: []SourceRegistration{{ID: "ota-a", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}},
			wantErr:       ErrInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			intent := validIntent()
			intent.Sources = tt.intentSources
			registry := mustSourceRegistry(t, tt.registrations...)
			err := ValidateSourceIndependence(intent, registry)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestChunkResumeAndDigests(t *testing.T) {
	s := NewTransferState(10, 4)
	if err := s.Accept(0, 4); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(4, 4); err != nil {
		t.Fatal(err)
	}
	if s.NextOffset() != 8 {
		t.Fatalf("offset=%d", s.NextOffset())
	}
	if err := s.Accept(3, 1); !errors.Is(err, ErrChunkOverlap) {
		t.Fatalf("err=%v", err)
	}
	if err := s.Accept(8, 2); err != nil {
		t.Fatal(err)
	}
	if !s.Complete() {
		t.Fatal("not complete")
	}
	if err := VerifyDigests([]byte("abc"), Digests{MD5: "900150983cd24fb0d6963f7d28e17f72", SHA1: "a9993e364706816aba3e25717850c26c9cd0d89d", SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}); err != nil {
		t.Fatal(err)
	}
}

func TestTransferStateRejectsIntegerOverflow(t *testing.T) {
	s := NewTransferState(10, math.MaxInt64)
	if err := s.Accept(0, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept(1, math.MaxInt64); !errors.Is(err, ErrChunkOverlap) {
		t.Fatalf("overflowing chunk error=%v, want ErrChunkOverlap", err)
	}
	if got := s.NextOffset(); got != 1 {
		t.Fatalf("next offset=%d after rejected overflow chunk, want 1", got)
	}
}

func TestVerifyDigestsRejectsUppercaseValues(t *testing.T) {
	want := Digests{MD5: "900150983CD24FB0D6963F7D28E17F72", SHA1: "A9993E364706816ABA3E25717850C26C9CD0D89D", SHA256: "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"}
	if err := VerifyDigests([]byte("abc"), want); !errors.Is(err, ErrInvalid) {
		t.Fatalf("uppercase digests accepted: %v", err)
	}
}

func TestFailureBudget(t *testing.T) {
	b := NewFailureBudget(2)
	b.Failed()
	b.Failed()
	if !b.Exhausted() {
		t.Fatal("budget not exhausted")
	}
	if !errors.Is(b.Record(), ErrFailureLimit) {
		t.Fatal("limit not enforced")
	}
}

func validIntent() DistributionIntent {
	return DistributionIntent{ID: "i", PackageID: "p", Version: "1.0.0", Size: 1, Digests: Digests{MD5: strings.Repeat("a", 32), SHA1: strings.Repeat("b", 40), SHA256: strings.Repeat("c", 64)}, Sources: []Source{{Kind: SourceOTA, ID: "ota"}}, Signature: "signed-intent"}
}

func mustSourceRegistry(t *testing.T, registrations ...SourceRegistration) SourceRegistry {
	t.Helper()
	registry, err := NewSourceRegistry(registrations)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func TestNewSourceRegistryRejectsIncompleteOrUnnormalizedRegistration(t *testing.T) {
	if _, err := NewSourceRegistry([]SourceRegistration{{ID: "ota", Kind: SourceOTA, IndependenceGroup: "vendor"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing root error = %v", err)
	}
	registry, err := NewSourceRegistry([]SourceRegistration{{ID: " ota ", Kind: SourceOTA, Root: " vendor-root ", IndependenceGroup: " vendor "}})
	if err != nil || registry.entries["ota"].Root != "vendor-root" {
		t.Fatalf("registration normalization failed: registry=%+v err=%v", registry, err)
	}
	if _, err := NewSourceRegistry([]SourceRegistration{{ID: "ota\n", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("newline registration error = %v", err)
	}
	if _, err := NewSourceRegistry([]SourceRegistration{{ID: "ota\t", Kind: SourceOTA, Root: "vendor-root", IndependenceGroup: "vendor"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control-character registration error = %v", err)
	}
}

func TestIntentRejectsAmbiguousIdentifiersAndDuplicateSourceIdentity(t *testing.T) {
	base := validIntent()
	tests := []struct {
		name string
		edit func(*DistributionIntent)
	}{
		{name: "leading whitespace", edit: func(i *DistributionIntent) { i.ID = " i" }},
		{name: "trailing whitespace", edit: func(i *DistributionIntent) { i.PackageID = "pkg " }},
		{name: "control character", edit: func(i *DistributionIntent) { i.Version = "1.0.0\t" }},
		{name: "zero-width format character", edit: func(i *DistributionIntent) { i.ID = "i\u200b" }},
		{name: "signature control character", edit: func(i *DistributionIntent) { i.Signature = "sig\nref" }},
		{name: "duplicate source identity", edit: func(i *DistributionIntent) { i.Sources = append(i.Sources, i.Sources[0]) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			intent := base
			intent.Sources = append([]Source(nil), base.Sources...)
			tc.edit(&intent)
			if !errors.Is(intent.Validate(), ErrInvalid) {
				t.Fatalf("ambiguous intent accepted: %+v", intent)
			}
		})
	}
}

func TestCapabilitiesRejectsDuplicateKindsProtocolVersionsAndOversizedChunks(t *testing.T) {
	base := Capabilities{NodeID: "node", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4}
	tests := []Capabilities{
		{NodeID: "node", ProtocolVersions: []string{ProtocolVersion, ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: 4},
		{NodeID: "node", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer, SourcePeer}, MaxChunkSize: 4},
		{NodeID: "node", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceKind("rogue")}, MaxChunkSize: 4},
		{NodeID: "node", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourcePeer}, MaxChunkSize: DefaultMaxChunkBytes + 1},
	}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, caps := range tests {
		if !errors.Is(caps.Validate(), ErrInvalid) {
			t.Fatalf("invalid capabilities accepted: %+v", caps)
		}
	}
}

func TestSourceIndependenceRequiresDistinctRootAndGroup(t *testing.T) {
	intent := validIntent()
	intent.Sources = []Source{{Kind: SourceOTA, ID: "ota-a"}, {Kind: SourcePeer, ID: "peer-b"}}
	registry := mustSourceRegistry(t,
		SourceRegistration{ID: "ota-a", Kind: SourceOTA, Root: "same-root", IndependenceGroup: "vendor-a"},
		SourceRegistration{ID: "peer-b", Kind: SourcePeer, Root: "same-root", IndependenceGroup: "vendor-b"},
	)
	if !errors.Is(ValidateSourceIndependence(intent, registry), ErrSourceIndependence) {
		t.Fatal("sources sharing a supply-chain root were counted as independent")
	}
}

func TestIntentRejectsMissingSignature(t *testing.T) {
	intent := validIntent()
	intent.Signature = ""
	if !errors.Is(intent.Validate(), ErrIntentSignature) {
		t.Fatalf("unsigned intent accepted: %v", intent.Validate())
	}
}

func TestSelectSourceSkipsQuarantineAndHonorsOfflineBoundary(t *testing.T) {
	intent := validIntent()
	intent.Sources = []Source{{Kind: SourceOTA, ID: "ota"}, {Kind: SourcePeer, ID: "peer"}, {Kind: SourceOffline, ID: "crp"}}
	hello := Hello{NodeID: "n", Protocol: ProtocolVersion}
	caps := Capabilities{NodeID: "n", ProtocolVersions: []string{ProtocolVersion}, Sources: []SourceKind{SourceOTA, SourcePeer}, MaxChunkSize: 4}
	selected, err := SelectSource(intent, hello, caps, nil, []SourceQuarantine{{Source: intent.Sources[0], Reason: QuarantineTransport}})
	if err != nil || selected.ID != "peer" {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	offlineCaps := caps
	offlineCaps.Sources = []SourceKind{SourceOffline}
	offline, err := SelectSource(intent, Hello{NodeID: "n", Protocol: ProtocolVersion, Offline: true}, offlineCaps, nil, nil)
	if err != nil || offline.ID != "crp" {
		t.Fatalf("offline selected=%+v err=%v", offline, err)
	}
	if _, err := SelectSource(intent, Hello{NodeID: "n", Protocol: ProtocolVersion, Offline: true}, offlineCaps, nil, []SourceQuarantine{{Source: intent.Sources[2], Reason: QuarantineIntegrity}}); !errors.Is(err, ErrSourceQuarantined) {
		t.Fatalf("quarantined offline source error=%v", err)
	}
}

func TestAddSourceQuarantineIsIdempotentAndCanonical(t *testing.T) {
	intent := validIntent()
	intent.Sources = []Source{{Kind: SourcePeer, ID: "peer", TrustRoot: "root-a"}}
	reported := Source{Kind: SourcePeer, ID: "peer", TrustRoot: "attacker-root"}
	first, err := AddSourceQuarantine(intent, nil, reported, QuarantineIntegrity)
	if err != nil || len(first) != 1 || first[0].Source.TrustRoot != "root-a" {
		t.Fatalf("canonical quarantine=%+v err=%v", first, err)
	}
	second, err := AddSourceQuarantine(intent, first, reported, QuarantineTransport)
	if err != nil || len(second) != 1 || second[0].Reason != QuarantineIntegrity {
		t.Fatalf("quarantine replay changed evidence=%+v err=%v", second, err)
	}
}
