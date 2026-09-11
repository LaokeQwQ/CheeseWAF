package crp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestImportOfflineEnforcesAllBoundaries(t *testing.T) {
	artifact := []byte("offline-artifact")
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	private := make([]ed25519.PrivateKey, 3)
	var err error
	for i := range private {
		_, private[i], err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	manifest := testManifest(artifact)
	manifest.Source = "offline"
	manifest.SourceRoot = "vendor-root-v1"
	manifest.ReleaseSequence = 9
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignManifestWithKeyID(manifest, "official-a", private[0], now)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignManifestWithKeyID(manifest, "official-b", private[1], now)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewSourceRegistry([]SourceRootRegistration{{ID: "vendor-root-v1", NamespacePrefixes: []string{"official/"}, Sources: []string{"offline"}}})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore([]TrustRoot{{ID: "vendor-root-v1", Class: SignerOfficial, NamespacePrefixes: []string{"official/"}, Keys: []TrustKey{{ID: "official-a", PublicKey: private[0].Public().(ed25519.PublicKey), Class: SignerOfficial}, {ID: "official-b", PublicKey: private[1].Public().(ed25519.PublicKey), Class: SignerOfficial}, {ID: "official-c", PublicKey: private[2].Public().(ed25519.PublicKey), Class: SignerOfficial}}}})
	if err != nil {
		t.Fatal(err)
	}

	pkg := Package{Manifest: rawManifest, Artifact: artifact, Signatures: []Signature{sig, sig2}}
	if _, err := Import(pkg, ImportOptions{MaxManifestBytes: 4096, MaxArtifactBytes: 4096, SourceRegistry: registry, TrustStore: trust, Now: now, CurrentRelease: Release{Version: "1.0.0", Sequence: 8}}); err != nil {
		t.Fatalf("valid offline package rejected: %v", err)
	}
	oversized := pkg
	oversized.Manifest = append(append([]byte(nil), rawManifest...), make([]byte, 4096)...)
	if _, err := Import(oversized, ImportOptions{MaxManifestBytes: int64(len(rawManifest)), MaxArtifactBytes: 4096, SourceRegistry: registry, TrustStore: trust, Now: now}); !errors.Is(err, ErrManifestTooLarge) {
		t.Fatalf("oversized manifest err=%v, want ErrManifestTooLarge", err)
	}
	downgrade := manifest
	downgrade.Version = "0.9.0"
	downgrade.ReleaseSequence = 7
	downgradeRaw, _ := json.Marshal(downgrade)
	if _, err := Import(Package{Manifest: downgradeRaw, Artifact: artifact, Signatures: nil}, ImportOptions{MaxManifestBytes: 4096, MaxArtifactBytes: 4096, SourceRegistry: registry, TrustStore: trust, Now: now, CurrentRelease: Release{Version: "1.0.0", Sequence: 8}}); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("downgrade err=%v, want ErrDowngrade", err)
	}
	if _, err := Import(Package{Manifest: rawManifest, Artifact: append(append([]byte(nil), artifact...), 'x'), Signatures: []Signature{sig, sig2}}, ImportOptions{MaxManifestBytes: 4096, MaxArtifactBytes: int64(len(artifact)), SourceRegistry: registry, TrustStore: trust, Now: now}); !errors.Is(err, ErrArtifactTooLarge) {
		t.Fatalf("oversized artifact err=%v, want ErrArtifactTooLarge", err)
	}
	if _, err := Import(Package{Manifest: append(append([]byte(nil), rawManifest...), []byte(" {}")...), Artifact: artifact, Signatures: []Signature{sig, sig2}}, ImportOptions{MaxManifestBytes: 4096, MaxArtifactBytes: 4096, SourceRegistry: registry, TrustStore: trust, Now: now}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("trailing manifest err=%v, want ErrInvalidManifest", err)
	}
}

func TestImportRequiresExplicitVerificationTime(t *testing.T) {
	if _, err := Import(Package{}, ImportOptions{}); !errors.Is(err, ErrImporterConfig) {
		t.Fatalf("missing verification time error=%v, want ErrImporterConfig", err)
	}
}
