package consumer

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/md5" // #nosec G501 -- CWEDP compatibility digest test fixture.
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- CWEDP compatibility digest test fixture.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/transport"
	"github.com/LaokeQwQ/CheeseWAF/internal/netlease"
)

type durableMemoryStore struct{ *cwedp.MemoryResumeStore }

func (*durableMemoryStore) DurableCWEDPResumeStore() {}

func TestDownloadCWEDPStagesVerifiedPackageWithoutActivation(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	archive, importOptions := signedArchiveFixture(t, now)
	archivePath := filepath.Join(t.TempDir(), "package.crp")
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	source := cwedp.Source{Kind: cwedp.SourceOffline, ID: "offline"}
	registry, err := transport.NewRegistry([]transport.Endpoint{{Source: source, URL: "file://" + archivePath, Root: "root", IndependenceGroup: "offline"}})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := crp.NewRuntimeStore(filepath.Join(t.TempDir(), "runtime"), crp.RuntimeStoreOptions{
		Clock:       func() time.Time { return now },
		HealthCheck: crp.HealthCheckFunc(func(crp.RuntimeRecord) error { return nil }),
		Revalidate:  crp.RuntimeRevalidateFunc(func(crp.RuntimeRecord) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(Options{
		ResumeStore: &durableMemoryStore{MemoryResumeStore: cwedp.NewMemoryResumeStore()},
		Registry:    registry,
		IntentVerifier: cwedp.IntentSignatureVerifierFunc(func(intent cwedp.DistributionIntent) error {
			if intent.Signature != "trusted-intent" {
				return errors.New("bad signature")
			}
			return nil
		}),
		CRPImportOptions:      importOptions,
		Runtime:               runtime,
		PolicyEpoch:           7,
		MinIndependentSources: 1,
		Now:                   func() time.Time { return now },
		AdapterFactory: func(context.Context, Request, transport.Endpoint, cwedp.DistributionIntent, cwedp.Hello, cwedp.Capabilities, int64) (transport.LeaseBoundAdapter, error) {
			t.Fatal("offline transfer must not request an online lease adapter")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	intent := intentForArchive(archive, source)
	result, err := service.DownloadCWEDP(context.Background(), Request{
		Identity:     testIdentity(),
		Password:     "fresh-password",
		Intent:       intent,
		Hello:        cwedp.Hello{NodeID: "node-a", Protocol: cwedp.ProtocolVersion, Offline: true},
		Capabilities: cwedp.Capabilities{NodeID: "node-a", ProtocolVersions: []string{cwedp.ProtocolVersion}, Sources: []cwedp.SourceKind{cwedp.SourceOffline}, MaxChunkSize: 4096},
		PolicyEpoch:  7,
		TTL:          time.Minute,
		MaxBytes:     int64(len(archive)),
	})
	if err != nil {
		t.Fatalf("DownloadCWEDP() error = %v", err)
	}
	if result.JobID != intent.ID || result.Source != source || result.Staged.Slot != crp.RuntimeSlotStaged {
		t.Fatalf("unexpected result: %+v", result)
	}
	snapshot, err := runtime.Snapshot(result.Staged.Key)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Staged == nil || snapshot.Current != nil || snapshot.Staged.ManifestIdentity != result.Staged.ManifestIdentity {
		t.Fatalf("download did not leave an explicit staged-only record: %+v", snapshot)
	}
}

func testIdentity() netlease.AdministratorIdentity {
	return netlease.AdministratorIdentity{ID: "admin-a", ManagementSessionID: "session-a"}
}

func signedArchiveFixture(t *testing.T, now time.Time) ([]byte, crp.ImportOptions) {
	t.Helper()
	artifact := []byte("verified plugin payload")
	private := make([]ed25519.PrivateKey, 3)
	for index := range private {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private[index] = key
	}
	manifest := crp.Manifest{APIVersion: crp.APIVersion, Kind: crp.Kind, Name: "demo", PluginID: "demo", Version: "1.0.0", Namespace: "official/demo", Source: "offline", SourceRoot: "root", ReleaseSequence: 1, Artifact: crp.Artifact{Size: int64(len(artifact)), Digests: crp.Digests{MD5: md5Hex(artifact), SHA1: sha1Hex(artifact), SHA256: sha256Hex(artifact)}}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	first, err := crp.SignManifestWithKeyID(manifest, "a", private[0], now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := crp.SignManifestWithKeyID(manifest, "b", private[1], now)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := json.Marshal([]crp.Signature{first, second})
	if err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range map[string][]byte{"manifest.json": manifestBytes, "artifact/payload.bin": artifact, "signatures/manifest.json": signatures} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	trust, err := crp.NewTrustStore([]crp.TrustRoot{{ID: "root", Class: crp.SignerOfficial, NamespacePrefixes: []string{"official/"}, Keys: []crp.TrustKey{{ID: "a", PublicKey: private[0].Public().(ed25519.PublicKey), Class: crp.SignerOfficial}, {ID: "b", PublicKey: private[1].Public().(ed25519.PublicKey), Class: crp.SignerOfficial}, {ID: "c", PublicKey: private[2].Public().(ed25519.PublicKey), Class: crp.SignerOfficial}}}})
	if err != nil {
		t.Fatal(err)
	}
	sources, err := crp.NewSourceRegistry([]crp.SourceRootRegistration{{ID: "root", NamespacePrefixes: []string{"official/"}, Sources: []string{"offline"}}})
	if err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes(), crp.ImportOptions{MaxManifestBytes: 4096, MaxArtifactBytes: 4096, SourceRegistry: sources, TrustStore: trust}
}

func intentForArchive(data []byte, source cwedp.Source) cwedp.DistributionIntent {
	return cwedp.DistributionIntent{ID: "intent-a", PackageID: "demo", Version: "1.0.0", Size: int64(len(data)), Digests: cwedp.Digests{MD5: md5Hex(data), SHA1: sha1Hex(data), SHA256: sha256Hex(data)}, Sources: []cwedp.Source{source}, Signature: "trusted-intent"}
}

func md5Hex(data []byte) string    { sum := md5.Sum(data); return hex.EncodeToString(sum[:]) }
func sha1Hex(data []byte) string   { sum := sha1.Sum(data); return hex.EncodeToString(sum[:]) }
func sha256Hex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
