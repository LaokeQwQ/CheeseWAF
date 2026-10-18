package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestClusterJoinReturnsPendingApproval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"approval_id": "cluster-operation-0123456789abcdef0123456789abcdef",
			"status":      "pending",
			"expires_at":  time.Now().Add(time.Minute),
		}})
	}))
	defer server.Close()

	_, err := requestClusterJoin(server.Client(), server.URL, map[string]string{"token": "token"})
	var pending *clusterJoinApprovalPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("error=%v, want pending approval", err)
	}
	if pending.ApprovalID != "cluster-operation-0123456789abcdef0123456789abcdef" {
		t.Fatalf("approval id=%q", pending.ApprovalID)
	}
}

func TestPendingClusterJoinIdentityRoundTripIsBoundToApproval(t *testing.T) {
	original := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = original })
	identity := clusterJoinLocalIdentity{KeyPEM: []byte("private"), CSRPEM: []byte("csr")}
	if err := saveClusterJoinPendingIdentity("waf-b", "cluster-operation-0123456789abcdef0123456789abcdef", identity); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("waf-b"))
	path := filepath.Join(dataDir, "cluster", "pending-join-"+fmt.Sprintf("%x", digest[:8])+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("pending identity mode=%#o, want 0600", info.Mode().Perm())
	}
	got, err := loadClusterJoinPendingIdentity(clusterJoinOptions{NodeID: "waf-b", ApprovalID: "cluster-operation-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.KeyPEM) != "private" || string(got.CSRPEM) != "csr" {
		t.Fatalf("pending identity=%q/%q", got.KeyPEM, got.CSRPEM)
	}
	if _, err := loadClusterJoinPendingIdentity(clusterJoinOptions{NodeID: "waf-b", ApprovalID: "cluster-operation-deadbeefdeadbeefdeadbeefdeadbeef"}); err == nil {
		t.Fatal("mismatched approval id was accepted")
	}
	if err := removeClusterJoinPendingIdentity("waf-b"); err != nil {
		t.Fatal(err)
	}
}
