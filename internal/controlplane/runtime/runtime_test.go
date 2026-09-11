package runtime

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
)

func TestValidateOptionsRejectsSameManagementAndRaftListener(t *testing.T) {
	opts := testOptions(t)
	opts.Listen = "127.0.0.1:9445"
	opts.RaftListen = opts.Listen
	if err := ValidateOptions(opts); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("ValidateOptions error=%v, want distinct listeners", err)
	}
}

func TestNativeRaftConstructsWithRuntimeTLSOptions(t *testing.T) {
	opts := testOptions(t)
	if err := os.Chmod(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	node, err := nativeraft.New(nativeRaftOptions(opts))
	if err != nil {
		t.Fatalf("native-raft construction with runtime TLS options failed: %v", err)
	}
	if err := node.Close(); err != nil {
		t.Fatalf("close native-raft test node: %v", err)
	}
}

func TestHandlerFailsClosedUntilControlPlaneReady(t *testing.T) {
	r := &Runtime{
		status: Status{
			Profile:   controlplane.StorageProfileProduction,
			ClusterID: "cluster-a", NodeID: "node-a", Phase: PhaseFrozen,
			Ready: false, WriteReady: false, Reason: "snapshot mismatch",
		},
	}
	for _, path := range []string{"/healthz", "/readyz", "/status"} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		r.Handler().ServeHTTP(recorder, req)
		if path == "/readyz" && recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status=%d, want 503", path, recorder.Code)
		}
		if path != "/readyz" && recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d, want 200 diagnostic response", path, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	r.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/proposals", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("frozen write status=%d, want 503", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
}

func TestStatusDoesNotExposePostgreSQLDSN(t *testing.T) {
	r := &Runtime{
		status: Status{
			Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a", NodeID: "node-a",
			Phase: PhaseFrozen, Reason: "postgres unavailable",
		},
		opts: Options{PostgreSQLDSN: "postgres://secret:password@db.example/control"},
	}
	recorder := httptest.NewRecorder()
	r.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/status", nil))
	if strings.Contains(recorder.Body.String(), "password") || strings.Contains(recorder.Body.String(), "db.example") {
		t.Fatalf("status leaked DSN: %s", recorder.Body.String())
	}
}

func TestInitialStateImportIsExplicitlyRejectedUntilMounted(t *testing.T) {
	opts := testOptions(t)
	opts.InitialVersion = "v1"
	opts.InitialState = []byte(`null`)
	if err := ValidateOptions(opts); err == nil {
		t.Fatal("null initial state unexpectedly accepted")
	}
	opts.InitialState = []byte(`{"mode":"observe"}`)
	if err := ValidateOptions(opts); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("valid initial state was silently accepted: %v", err)
	}
}

func TestHandlerRestrictsReadEndpointsToGET(t *testing.T) {
	r := &Runtime{status: Status{Phase: PhaseFrozen, Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a"}}
	for _, path := range []string{"/healthz", "/readyz", "/status"} {
		recorder := httptest.NewRecorder()
		r.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s POST status=%d, want 405", path, recorder.Code)
		}
	}
}
