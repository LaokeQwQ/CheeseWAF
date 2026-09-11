package nativeraft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
)

func testContext(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), timeout)
}

func waitForLeader(t *testing.T, node *Runtime) Status {
	t.Helper()
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	var status Status
	for {
		status = node.Status()
		if status.IsLeader && status.Term > 0 {
			return status
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("leader election did not complete: status=%+v err=%v", status, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForCurrent(t *testing.T, node *Runtime, want controlplane.Revision) controlplane.State {
	t.Helper()
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	for {
		state, err := node.Current(ctx, "cluster-a")
		if err == nil && state.Revision >= want {
			return state
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("current state did not converge: revision=%d err=%v", want, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func openTestNode(t *testing.T, dir, nodeID string, mode StartMode) *Runtime {
	t.Helper()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod test data dir: %v", err)
	}
	node, err := New(Options{
		Profile:          controlplane.StorageProfileProduction,
		ClusterID:        "cluster-a",
		NodeID:           nodeID,
		DataDir:          dir,
		BindAddress:      "127.0.0.1:0",
		Mode:             mode,
		InsecureTestMode: true,
	})
	if err != nil {
		t.Fatalf("New(%s): %v", mode, err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	if err := node.Prepare(ctx); err != nil {
		node.Close()
		t.Fatalf("Prepare(%s): %v", mode, err)
	}
	return node
}

func TestNewRejectsPlaintextTransportUnlessExplicitLoopbackTestMode(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := Options{
		Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a",
		DataDir: dataDir, BindAddress: "127.0.0.1:0", Mode: ModeBootstrap,
	}
	if _, err := New(base); err == nil || !strings.Contains(strings.ToLower(err.Error()), "tls") {
		t.Fatalf("plaintext production transport error=%v, want TLS rejection", err)
	}
	base.InsecureTestMode = true
	if node, err := New(base); err != nil {
		t.Fatalf("explicit loopback insecure test mode rejected: %v", err)
	} else {
		_ = node.Close()
	}
	base.BindAddress = "0.0.0.0:0"
	if _, err := New(base); err == nil || !strings.Contains(strings.ToLower(err.Error()), "loopback") {
		t.Fatalf("non-loopback insecure test mode error=%v, want loopback rejection", err)
	}
}

func TestNewRejectsIncompleteRaftTLSConfiguration(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Options{
		Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a",
		DataDir: dataDir, BindAddress: "127.0.0.1:0", Mode: ModeBootstrap,
		TLS: &TLSOptions{CAFile: "ca.pem", CertFile: "node.crt"},
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "ca") {
		t.Fatalf("incomplete TLS configuration error=%v, want material rejection", err)
	}
}

func TestDataDirRejectsSymlinkAndPermissiveDirectory(t *testing.T) {
	target := t.TempDir()
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	base := Options{Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a", DataDir: symlink, BindAddress: "127.0.0.1:0", Mode: ModeBootstrap, InsecureTestMode: true}
	if _, err := New(base); err == nil || !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Fatalf("symlink data dir error=%v, want symlink rejection", err)
	}
	permissive := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	base.DataDir = permissive
	if _, err := New(base); err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission") {
		t.Fatalf("permissive data dir error=%v, want permission rejection", err)
	}
}

func TestValidateSupportedPlatformFailsClosed(t *testing.T) {
	if err := validateSupportedPlatform("plan9"); err == nil {
		t.Fatal("unknown platform was accepted")
	}
	if err := validateSupportedPlatform("darwin"); err != nil {
		t.Fatalf("known platform rejected: %v", err)
	}
}

func TestIdentityAndAddressPersistenceUsesSecureModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	idPath := filepath.Join(dir, "node-id")
	if _, err := loadOrCreateIdentity(idPath, "node-a", "node"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(idPath)
	if err != nil {
		t.Fatalf("stat node-id: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("node-id mode=%04o, want 0600", info.Mode().Perm())
	}
	addressPath := filepath.Join(dir, "address")
	if err := atomicWriteSecure(addressPath, []byte("127.0.0.1:9444"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readAddress(addressPath); err != nil || got != "127.0.0.1:9444" {
		t.Fatalf("readAddress()=(%q,%v), want persisted address", got, err)
	}
}

func proposedCommit(t *testing.T, status Status, revision controlplane.Revision, nonce string) controlplane.Commit {
	t.Helper()
	machine, err := controlplane.NewStateMachine(status.ClusterID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := machine.InstallLeadership(status.Term, status.LeaderID); err != nil {
		t.Fatal(err)
	}
	if revision > 0 {
		// The helper is only used for a first commit in this file. Keeping this
		// assertion explicit prevents tests from silently manufacturing a CAS baseline.
		t.Fatalf("unexpected non-zero baseline revision %d", revision)
	}
	commit, err := machine.Propose(controlplane.Proposal{
		LeaderID:         status.LeaderID,
		ExpectedEpoch:    machine.Snapshot().Epoch,
		ExpectedRevision: 0,
		Version:          "v1",
		Payload:          []byte(`{"mode":"observe"}`),
		Nonce:            nonce,
	})
	if err != nil {
		t.Fatal(err)
	}
	return commit
}

func TestNewRejectsTemporaryProfileAndImplicitMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{name: "temporary", opts: Options{Profile: controlplane.StorageProfileTemporary, ClusterID: "cluster-a", DataDir: t.TempDir(), Mode: ModeBootstrap}, want: "production"},
		{name: "implicit mode", opts: Options{Profile: controlplane.StorageProfileProduction, ClusterID: "cluster-a", DataDir: t.TempDir()}, want: "mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.opts)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("New error=%v, want mention %q", err, tc.want)
			}
		})
	}
}

func TestSingleNodeBootstrapPersistsStateAndInvalidatesOldFenceAfterRestart(t *testing.T) {
	dir := t.TempDir()
	node := openTestNode(t, dir, "node-a", ModeBootstrap)
	status := waitForLeader(t, node)
	if status.NodeID != "node-a" || status.LeaderID != "node-a" {
		node.Close()
		t.Fatalf("unexpected leader status: %+v", status)
	}

	commit := proposedCommit(t, status, 0, "nonce-1")
	ctx, cancel := testContext(t, 8*time.Second)
	if err := node.Propose(ctx, commit); err != nil {
		cancel()
		node.Close()
		t.Fatalf("Propose: %v", err)
	}
	fence, err := node.Establish(ctx, commit.State)
	cancel()
	if err != nil {
		node.Close()
		t.Fatalf("Establish: %v", err)
	}
	if fence != commit.Fence {
		node.Close()
		t.Fatalf("fence=%+v, want %+v", fence, commit.Fence)
	}
	got := waitForCurrent(t, node, 1)
	if got.Desired.Digest != commit.State.Desired.Digest || got.Revision != 1 {
		node.Close()
		t.Fatalf("current=%+v, want committed state", got)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := openTestNode(t, dir, "", ModeBootstrap)
	defer restarted.Close()
	status2 := waitForLeader(t, restarted)
	if restarted.NodeID() != "node-a" {
		t.Fatalf("node id changed across restart: %q", restarted.NodeID())
	}
	current := waitForCurrent(t, restarted, 1)
	if current.Desired.Digest != commit.State.Desired.Digest {
		t.Fatalf("restarted state=%+v, want digest %s", current, commit.State.Desired.Digest)
	}
	ctx, cancel = testContext(t, 8*time.Second)
	_, err = restarted.Establish(ctx, commit.State)
	cancel()
	if err == nil {
		t.Fatal("old-term state unexpectedly fenced after restart")
	}
	if !errors.Is(err, ErrFenceStale) {
		t.Fatalf("restart fencing error=%v, want ErrFenceStale", err)
	}
	if status2.Term <= status.Term {
		t.Fatalf("raft term did not advance across restart: before=%d after=%d", status.Term, status2.Term)
	}
	ctx, cancel = testContext(t, 8*time.Second)
	if _, err := restarted.Establish(ctx, current); err != nil {
		cancel()
		t.Fatalf("re-establishing fence for current term failed: %v", err)
	}
	cancel()
}

func TestJoinRequiresExplicitLeaderOperationAndReplicatesCommit(t *testing.T) {
	leader := openTestNode(t, t.TempDir(), "leader-a", ModeBootstrap)
	defer leader.Close()
	status := waitForLeader(t, leader)

	follower := openTestNode(t, t.TempDir(), "follower-b", ModeJoin)
	defer follower.Close()
	ctx, cancel := testContext(t, time.Second)
	if err := follower.Health(ctx); err == nil {
		cancel()
		t.Fatal("unjoined node reported healthy")
	}
	cancel()

	ctx, cancel = testContext(t, 8*time.Second)
	if err := leader.Join(ctx, Member{ID: follower.NodeID(), Address: follower.Address()}); err != nil {
		cancel()
		t.Fatalf("Join: %v", err)
	}
	cancel()

	ctx, cancel = testContext(t, 8*time.Second)
	if err := follower.Health(ctx); err != nil {
		cancel()
		t.Fatalf("joined follower Health: %v", err)
	}
	if status := follower.Status(); !status.Ready || !status.ReadOnly || status.IsLeader {
		t.Fatalf("joined follower status=%+v, want ready/read-only", status)
	}
	if _, err := follower.Establish(ctx, controlplane.State{}); !errors.Is(err, controlplane.ErrNotLeader) {
		t.Fatalf("follower forged fence error=%v, want ErrNotLeader", err)
	}
	status = waitForLeader(t, leader)
	commit := proposedCommit(t, status, 0, "cluster-nonce-1")
	if err := leader.Propose(ctx, commit); err != nil {
		cancel()
		t.Fatalf("leader Propose: %v", err)
	}
	cancel()

	got := waitForCurrent(t, follower, 1)
	if got.Desired.Digest != commit.State.Desired.Digest || got.Revision != 1 {
		t.Fatalf("follower current=%+v, want replicated commit", got)
	}
}

func TestLeaderLossDropsReadyAndWriteAccess(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "node-loss", ModeBootstrap)
	defer node.Close()
	waitForLeader(t, node)
	node.notify <- false
	ctx, cancel := testContext(t, 3*time.Second)
	defer cancel()
	for {
		status := node.Status()
		if !status.Ready && status.ReadOnly && !status.IsLeader {
			return
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("leader loss did not become read-only: status=%+v err=%v", status, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProtectedInitialCommitCanReplicateWhileStartupFreezeIsHeld(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "node-initial", ModeBootstrap)
	defer node.Close()
	status := waitForLeader(t, node)
	node.Machine().FreezeWrites("control-plane startup incomplete")
	candidate, err := controlplane.NewStateMachine("cluster-a", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := candidate.InstallLeadership(status.Term, status.LeaderID); err != nil {
		t.Fatal(err)
	}
	commit, err := candidate.Propose(controlplane.Proposal{LeaderID: status.LeaderID, ExpectedEpoch: status.Epoch, Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-1"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	if err := node.Propose(ctx, commit); err != nil {
		t.Fatalf("protected initial commit was rejected while startup frozen: %v", err)
	}
	got := waitForCurrent(t, node, 1)
	if got.Revision != 1 || got.Desired.Digest != commit.State.Desired.Digest || !got.WriteFrozen {
		t.Fatalf("initial commit state=%+v, want committed but startup-frozen", got)
	}
}

func TestJoinNodeDoesNotSilentlyBootstrap(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "join-only", ModeJoin)
	defer node.Close()
	time.Sleep(300 * time.Millisecond)
	if node.Status().IsLeader {
		t.Fatalf("join-only node became leader without explicit bootstrap: %+v", node.Status())
	}
	ctx, cancel := testContext(t, time.Second)
	defer cancel()
	if _, err := node.Current(ctx, "cluster-a"); !errors.Is(err, controlplane.ErrStateNotFound) {
		t.Fatalf("join-only Current error=%v, want ErrStateNotFound", err)
	}
}
