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
	"github.com/hashicorp/raft"
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

func waitForTwoNodeLeader(t *testing.T, first, second *Runtime) (*Runtime, *Runtime, Status) {
	t.Helper()
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	var firstStatus, secondStatus Status
	for {
		firstStatus, secondStatus = first.Status(), second.Status()
		if firstStatus.Ready && secondStatus.Ready && firstStatus.LeaderID == secondStatus.LeaderID &&
			firstStatus.Term == secondStatus.Term && firstStatus.Epoch == secondStatus.Epoch &&
			firstStatus.IsLeader != secondStatus.IsLeader {
			leader, follower, leaderStatus, followerStatus := first, second, firstStatus, secondStatus
			if secondStatus.IsLeader {
				leader, follower, leaderStatus, followerStatus = second, first, secondStatus, firstStatus
			}
			if leaderStatus.LeaderID == leaderStatus.NodeID && leaderStatus.Term > 0 && leaderStatus.Epoch > 0 &&
				leaderStatus.WriteReady && !leaderStatus.ReadOnly && followerStatus.ReadOnly &&
				!followerStatus.IsLeader && !followerStatus.WriteReady {
				return leader, follower, leaderStatus
			}
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("two-node leader election did not converge: first=%+v second=%+v err=%v", firstStatus, secondStatus, err)
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

type coordinatorDurableStore struct {
	state   controlplane.State
	commits []controlplane.Commit
	err     error
}

func (s *coordinatorDurableStore) Backend() string               { return controlplane.DurableBackendPostgreSQL }
func (s *coordinatorDurableStore) Prepare(context.Context) error { return nil }
func (s *coordinatorDurableStore) Health(context.Context) error  { return nil }

func (s *coordinatorDurableStore) LoadState(context.Context, string) (controlplane.State, error) {
	if s.state.ClusterID == "" {
		return controlplane.State{}, controlplane.ErrStateNotFound
	}
	return s.state, nil
}

func (s *coordinatorDurableStore) AppendCommit(_ context.Context, commit controlplane.Commit) error {
	if s.err != nil {
		return s.err
	}
	s.state = commit.State
	s.commits = append(s.commits, commit)
	return nil
}

func (s *coordinatorDurableStore) CheckpointLeadership(_ context.Context, state controlplane.State) error {
	s.state = state
	return nil
}

type responseLostConsensus struct {
	runtime *Runtime
	lost    bool
}

func (c *responseLostConsensus) Current(ctx context.Context, clusterID string) (controlplane.State, error) {
	return c.runtime.Current(ctx, clusterID)
}

func (c *responseLostConsensus) Propose(ctx context.Context, commit controlplane.Commit) error {
	if err := c.runtime.Propose(ctx, commit); err != nil {
		return err
	}
	if !c.lost {
		c.lost = true
		return errors.New("raft response lost after apply")
	}
	return nil
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
	if revision > 0 {
		// The helper is only used for a first commit in this file. Keeping this
		// assertion explicit prevents tests from silently manufacturing a CAS baseline.
		t.Fatalf("unexpected non-zero baseline revision %d", revision)
	}
	if status.ClusterID == "" || status.LeaderID == "" || status.Term == 0 || status.Epoch == 0 {
		t.Fatalf("cannot construct proposal from incomplete leader status: %+v", status)
	}
	commit, err := controlplane.NewInitialCommit(status.ClusterID, controlplane.State{
		ClusterID: status.ClusterID,
		LeaderID:  status.LeaderID,
		Term:      status.Term,
		Epoch:     status.Epoch,
		Revision:  revision,
	}, controlplane.InitialStateRequest{
		Version: "v1",
		Payload: []byte(`{"mode":"observe"}`),
		Nonce:   nonce,
		Confirmation: controlplane.InitialStateConfirmation{
			ID:    "test-confirmation",
			Actor: "test",
		},
	})
	if err != nil {
		t.Fatalf("construct initial commit: %v", err)
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

func TestCoordinatorProposeAndApplyReplicatesExactNonInitialCommitWithRuntimeOwnedMachine(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "node-coordinator", ModeBootstrap)
	defer node.Close()
	status := waitForLeader(t, node)
	durable := &coordinatorDurableStore{}
	coordinator, err := controlplane.NewCoordinator(node.Machine(), node, durable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	initial, err := coordinator.Initialize(ctx, controlplane.InitialStateRequest{
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-1",
		Confirmation: controlplane.InitialStateConfirmation{ID: "confirmation-1", Actor: "test-operator"},
	})
	if err != nil {
		t.Fatalf("initialize coordinator: %v", err)
	}
	if err := coordinator.ResumeWrites(ctx, initial.Fence); err != nil {
		t.Fatalf("resume coordinator: %v", err)
	}
	second, err := coordinator.ProposeAndApply(ctx, controlplane.Proposal{
		LeaderID: status.LeaderID, ExpectedEpoch: initial.State.Epoch, ExpectedRevision: initial.State.Revision,
		Version: "v2", Payload: []byte(`{"mode":"enforce"}`), Nonce: "commit-2",
	})
	if err != nil {
		t.Fatalf("propose and apply exact second commit through native raft: %v", err)
	}
	if got := node.Machine().Snapshot(); got.Revision != 2 || got.Desired.Version != "v2" {
		t.Fatalf("runtime state=%+v, want committed revision 2", got)
	}
	if durable.state.Revision != 2 || len(durable.commits) != 2 {
		t.Fatalf("durable state revision=%d commits=%d, want 2/2", durable.state.Revision, len(durable.commits))
	}
	if err := node.Propose(ctx, second); err != nil {
		t.Fatalf("idempotent exact-commit retry failed: %v", err)
	}
}

func TestCoordinatorRetriesDurableFailureAfterNativeRaftAppliedExactCommit(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "node-retry", ModeBootstrap)
	defer node.Close()
	status := waitForLeader(t, node)
	durable := &coordinatorDurableStore{}
	coordinator, err := controlplane.NewCoordinator(node.Machine(), node, durable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	initial, err := coordinator.Initialize(ctx, controlplane.InitialStateRequest{
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-retry",
		Confirmation: controlplane.InitialStateConfirmation{ID: "confirmation-retry", Actor: "test-operator"},
	})
	if err != nil {
		t.Fatalf("initialize coordinator: %v", err)
	}
	if err := coordinator.ResumeWrites(ctx, initial.Fence); err != nil {
		t.Fatalf("resume coordinator: %v", err)
	}
	durable.err = errors.New("postgres temporarily unavailable")
	second, err := coordinator.ProposeAndApply(ctx, controlplane.Proposal{
		LeaderID: status.LeaderID, ExpectedEpoch: initial.State.Epoch, ExpectedRevision: initial.State.Revision,
		Version: "v2", Payload: []byte(`{"mode":"enforce"}`), Nonce: "commit-retry-2",
	})
	if err == nil || second.State.Revision != 2 {
		t.Fatalf("durable failure result commit=%+v err=%v", second, err)
	}
	if got := node.Machine().Snapshot(); got.Revision != 2 || !got.WriteFrozen {
		t.Fatalf("consensus commit was not retained fail-closed: %+v", got)
	}
	if durable.state.Revision != 1 || len(durable.commits) != 1 {
		t.Fatalf("durable store advanced despite failure: revision=%d commits=%d", durable.state.Revision, len(durable.commits))
	}
	durable.err = nil
	if err := coordinator.Apply(ctx, second); err != nil {
		t.Fatalf("exact durable retry failed: %v", err)
	}
	if err := coordinator.ResumeWrites(ctx, second.Fence); err != nil {
		t.Fatalf("resume after converged retry failed: %v", err)
	}
	if got := node.Machine().Snapshot(); got.Revision != 2 || got.WriteFrozen {
		t.Fatalf("runtime did not resume at revision 2: %+v", got)
	}
	if durable.state.Revision != 2 || len(durable.commits) != 2 {
		t.Fatalf("durable retry result revision=%d commits=%d, want 2/2", durable.state.Revision, len(durable.commits))
	}
}

func TestCoordinatorRetriesExactCommitAfterRaftResponseIsLost(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "node-response-lost", ModeBootstrap)
	defer node.Close()
	status := waitForLeader(t, node)
	durable := &coordinatorDurableStore{}
	bootstrapCoordinator, err := controlplane.NewCoordinator(node.Machine(), node, durable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	initial, err := bootstrapCoordinator.Initialize(ctx, controlplane.InitialStateRequest{
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-response-lost",
		Confirmation: controlplane.InitialStateConfirmation{ID: "confirmation-response-lost", Actor: "test-operator"},
	})
	if err != nil {
		t.Fatalf("initialize coordinator: %v", err)
	}
	if err := bootstrapCoordinator.ResumeWrites(ctx, initial.Fence); err != nil {
		t.Fatalf("resume coordinator: %v", err)
	}
	lossy := &responseLostConsensus{runtime: node}
	coordinator, err := controlplane.NewCoordinator(node.Machine(), lossy, durable)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := coordinator.ProposeAndApply(ctx, controlplane.Proposal{
		LeaderID: status.LeaderID, ExpectedEpoch: initial.State.Epoch, ExpectedRevision: initial.State.Revision,
		Version: "v2", Payload: []byte(`{"mode":"enforce"}`), Nonce: "response-lost-2",
	})
	if err == nil || commit.State.Revision != 2 {
		t.Fatalf("lost response result commit=%+v err=%v", commit, err)
	}
	if got := node.Machine().Snapshot(); got.Revision != 2 || !got.WriteFrozen {
		t.Fatalf("lost response did not retain committed raft state fail-closed: %+v", got)
	}
	lastIndex, err := node.logs.LastIndex()
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Apply(ctx, commit); err != nil {
		t.Fatalf("exact retry after lost raft response failed: %v", err)
	}
	afterRetry, err := node.logs.LastIndex()
	if err != nil {
		t.Fatal(err)
	}
	if afterRetry != lastIndex {
		t.Fatalf("exact retry appended raft log index %d after %d", afterRetry, lastIndex)
	}
	if durable.state.Revision != 2 || len(durable.commits) != 2 {
		t.Fatalf("durable retry revision=%d commits=%d, want 2/2", durable.state.Revision, len(durable.commits))
	}
}

func TestCoordinatorRetriesExactInitialCommitAfterRaftResponseIsLost(t *testing.T) {
	node := openTestNode(t, t.TempDir(), "node-initial-response-lost", ModeBootstrap)
	defer node.Close()
	waitForLeader(t, node)
	durable := &coordinatorDurableStore{}
	lossy := &responseLostConsensus{runtime: node}
	coordinator, err := controlplane.NewCoordinator(node.Machine(), lossy, durable)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	request := controlplane.InitialStateRequest{
		Version: "v1", Payload: []byte(`{"mode":"observe"}`), Nonce: "initial-lost-response",
		Confirmation: controlplane.InitialStateConfirmation{ID: "confirmation-initial-lost", Actor: "test-operator"},
	}
	commit, err := coordinator.Initialize(ctx, request)
	if err == nil || commit.State.Revision != 1 {
		t.Fatalf("lost initial response result commit=%+v err=%v", commit, err)
	}
	lastIndex, err := node.logs.LastIndex()
	if err != nil {
		t.Fatal(err)
	}
	retried, err := coordinator.Initialize(ctx, request)
	if err != nil {
		t.Fatalf("exact initial retry after lost response failed: %v", err)
	}
	if retried.Fence != commit.Fence || !retried.State.UpdatedAt.Equal(commit.State.UpdatedAt) {
		t.Fatalf("initial retry changed exact commit: first=%+v retry=%+v", commit, retried)
	}
	afterRetry, err := node.logs.LastIndex()
	if err != nil {
		t.Fatal(err)
	}
	if afterRetry != lastIndex {
		t.Fatalf("initial exact retry appended raft log index %d after %d", afterRetry, lastIndex)
	}
	if durable.state.Revision != 1 || len(durable.commits) != 1 {
		t.Fatalf("initial durable retry revision=%d commits=%d, want 1/1", durable.state.Revision, len(durable.commits))
	}
}

func TestJoinRequiresExplicitLeaderOperationAndReplicatesCommit(t *testing.T) {
	leader := openTestNode(t, t.TempDir(), "leader-a", ModeBootstrap)
	defer leader.Close()
	waitForLeader(t, leader)

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
	cancel()

	currentLeader, currentFollower, status := waitForTwoNodeLeader(t, leader, follower)
	configuration := currentLeader.raft.GetConfiguration()
	if err := configuration.Error(); err != nil {
		t.Fatalf("joined raft configuration: %v", err)
	}
	servers := configuration.Configuration().Servers
	if len(servers) != 2 {
		t.Fatalf("joined raft configuration has %d members, want exactly two voters", len(servers))
	}
	for _, member := range servers {
		if member.Suffrage != raft.Voter ||
			(member.ID != raft.ServerID(leader.NodeID()) || string(member.Address) != leader.Address()) &&
				(member.ID != raft.ServerID(follower.NodeID()) || string(member.Address) != follower.Address()) {
			t.Fatalf("unexpected joined raft member: %+v", member)
		}
	}
	ctx, cancel = testContext(t, 8*time.Second)
	defer cancel()
	if _, err := currentFollower.Establish(ctx, controlplane.State{}); !errors.Is(err, controlplane.ErrNotLeader) {
		t.Fatalf("follower forged fence error=%v, want ErrNotLeader", err)
	}
	commit := proposedCommit(t, status, 0, "cluster-nonce-1")
	if err := currentFollower.Propose(ctx, commit); !errors.Is(err, controlplane.ErrNotLeader) {
		t.Fatalf("follower forged proposal error=%v, want ErrNotLeader", err)
	}
	if err := currentLeader.Propose(ctx, commit); err != nil {
		t.Fatalf("leader Propose: %v", err)
	}
	for _, node := range []*Runtime{currentLeader, currentFollower} {
		got := waitForCurrent(t, node, 1)
		if !sameNativePayload(got, commit.State) || got.LeaderID != commit.State.LeaderID ||
			got.Term != commit.State.Term || got.Epoch != commit.State.Epoch ||
			got.WriteFrozen != commit.State.WriteFrozen || got.FreezeReason != commit.State.FreezeReason ||
			!got.UpdatedAt.Equal(commit.State.UpdatedAt) {
			t.Fatalf("node %s current=%+v, want exact replicated commit=%+v", node.NodeID(), got, commit.State)
		}
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
	commit, err := controlplane.NewInitialCommit(status.ClusterID, controlplane.State{
		ClusterID:   status.ClusterID,
		LeaderID:    status.LeaderID,
		Term:        status.Term,
		Epoch:       status.Epoch,
		Revision:    status.Revision,
		WriteFrozen: true,
	}, controlplane.InitialStateRequest{
		Version: "v1",
		Payload: []byte(`{"mode":"observe"}`),
		Nonce:   "initial-1",
		Confirmation: controlplane.InitialStateConfirmation{
			ID:    "test-confirmation",
			Actor: "test",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := testContext(t, 8*time.Second)
	defer cancel()
	if err := node.Propose(ctx, commit); err != nil {
		t.Fatalf("protected initial commit was rejected while startup frozen: %v", err)
	}
	got := waitForCurrent(t, node, 1)
	if got.Revision != 1 || got.Desired.Digest != commit.State.Desired.Digest || got.WriteFrozen {
		t.Fatalf("replicated initial commit state=%+v, want canonical non-frozen commit", got)
	}
	if local := node.Machine().Snapshot(); local.Revision != 1 || !local.WriteFrozen {
		t.Fatalf("local startup overlay=%+v, want committed but startup-frozen", local)
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
