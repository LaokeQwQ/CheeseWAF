package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/crp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/consumer"
	"github.com/LaokeQwQ/CheeseWAF/internal/cwedp/postgres"
)

func TestDefaultProductionFactoryWiresCWEDPCompositionOpeners(t *testing.T) {
	factory := NewProductionDependencyFactory()
	if factory.OpenCWEDPDownload == nil || factory.OpenCWEDPAdmission == nil || factory.OpenCWEDPResumeStore == nil || factory.OpenCWEDPRuntime == nil || factory.OpenCRP == nil {
		t.Fatal("default production factory omitted a CWEDP composition opener")
	}
}

func TestOpenProductionCWEDPAdmissionRejectsMissingRuntimeOwnedFiles(t *testing.T) {
	root := t.TempDir()
	opts := ProductionCWEDPOptions{
		ResumeDSN:             "postgres://control.example.invalid/control",
		RegistryPath:          filepath.Join(root, "registry.json"),
		TrustRootsPath:        filepath.Join(root, "trust-roots.json"),
		SourcesPath:           filepath.Join(root, "sources.json"),
		IntentKeysPath:        filepath.Join(root, "intent-keys.json"),
		RuntimeDir:            filepath.Join(root, "runtime"),
		MinIndependentSources: 1,
	}
	if _, err := openProductionCWEDPAdmission(context.Background(), opts); !errors.Is(err, ErrProductionCWEDPConfig) {
		t.Fatalf("missing runtime-owned admission files error=%v, want ErrProductionCWEDPConfig", err)
	}
}

func TestProductionCWEDPIntentVerifierAuthenticatesCanonicalIntent(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "intent-keys.json")
	document, err := json.Marshal(productionCWEDPIntentKeysFile{Keys: []productionCWEDPIntentKey{{ID: "control-a", PublicKey: base64.StdEncoding.EncodeToString(publicKey)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	verifier, err := openProductionCWEDPIntentVerifier(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := cwedp.DistributionIntent{
		ID: "intent-a", PackageID: "official/demo", Version: "1.0.0", Size: 1,
		Digests:   cwedp.Digests{MD5: "00000000000000000000000000000000", SHA1: "0000000000000000000000000000000000000000", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		Sources:   []cwedp.Source{{Kind: cwedp.SourceOffline, ID: "offline"}},
		Signature: "placeholder",
	}
	payload, err := cwedp.SigningBytes(intent)
	if err != nil {
		t.Fatal(err)
	}
	intent.Signature = "control-a:" + base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if err := verifier.Verify(intent); err != nil {
		t.Fatalf("valid intent signature rejected: %v", err)
	}
	intent.Version = "1.0.1"
	if err := verifier.Verify(intent); err == nil {
		t.Fatal("mutated intent signature was accepted")
	}
}

func TestOpenProductionCWEDPDownloadFailsClosedBeforeResumeOpen(t *testing.T) {
	called := false
	_, err := openProductionCWEDPDownload(context.Background(), ProductionServeWiring{}, func(context.Context, ProductionCWEDPOptions) (ProductionCWEDPAdmission, error) {
		return ProductionCWEDPAdmission{}, ErrProductionCWEDPConfig
	}, func(context.Context, ProductionCWEDPOptions) (*postgres.ResumeStore, error) {
		called = true
		return nil, nil
	}, func(context.Context, ProductionCWEDPOptions, ProductionCWEDPAdmission) (*crp.RuntimeStore, error) {
		return nil, nil
	})
	if !errors.Is(err, ErrProductionCWEDPUnavailable) || called {
		t.Fatalf("incomplete CWEDP wiring error=%v resumeOpened=%t", err, called)
	}
}

type blockingProductionCWEDPExecutor struct {
	entered   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
}

func (e *blockingProductionCWEDPExecutor) DownloadCWEDP(ctx context.Context, _ consumer.Request) (consumer.Result, error) {
	close(e.entered)
	<-ctx.Done()
	close(e.cancelled)
	<-e.release
	return consumer.Result{}, ctx.Err()
}

func TestProductionCWEDPExecutorCloseCancelsAndWaitsForDownload(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	backend := &blockingProductionCWEDPExecutor{
		entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}),
	}
	defer func() {
		select {
		case <-backend.release:
		default:
			close(backend.release)
		}
	}()
	executor := &productionCWEDPExecutor{executor: backend, ctx: parent, cancel: cancel}
	downloadDone := make(chan error, 1)
	go func() {
		_, err := executor.DownloadCWEDP(t.Context(), consumer.Request{})
		downloadDone <- err
	}()
	select {
	case <-backend.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("CWEDP download did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- executor.Close() }()
	select {
	case <-backend.cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("CWEDP Close did not cancel the active download")
	}
	select {
	case err := <-closeDone:
		t.Fatalf("CWEDP Close returned before the download exited: %v", err)
	default:
	}
	close(backend.release)
	if err := <-downloadDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled CWEDP download error=%v, want context.Canceled", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("CWEDP Close error=%v", err)
	}
	if _, err := executor.DownloadCWEDP(t.Context(), consumer.Request{}); !errors.Is(err, ErrProductionCWEDPUnavailable) {
		t.Fatalf("download after Close error=%v, want production CWEDP unavailable", err)
	}
}
