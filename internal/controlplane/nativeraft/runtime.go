package nativeraft

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

var (
	ErrFenceStale = errors.New("native-raft fencing token is stale")
	ErrNotReady   = errors.New("native-raft node is not ready")
	ErrClosed     = errors.New("native-raft node is closed")
)

type StartMode string

const (
	ModeBootstrap StartMode = "bootstrap"
	ModeJoin      StartMode = "join"
)

type Options struct {
	Profile     string
	ClusterID   string
	NodeID      string
	DataDir     string
	BindAddress string
	Mode        StartMode
	TLS         *TLSOptions
	TLSConfig   *TLSOptions
	// InsecureTestMode is an explicit loopback-only escape hatch for tests.
	// Production callers must leave it false and provide mutual TLS material.
	InsecureTestMode bool
}

type Member struct {
	ID      string
	Address string
}

type Status struct {
	ClusterID  string
	NodeID     string
	Address    string
	LeaderID   string
	Leader     string
	Term       uint64
	Epoch      controlplane.Epoch
	Revision   controlplane.Revision
	IsLeader   bool
	Joined     bool
	Ready      bool
	ReadOnly   bool
	WriteReady bool
	State      raft.RaftState
}

type Runtime struct {
	mu        sync.RWMutex
	propose   sync.Mutex
	closeOnce sync.Once
	done      chan struct{}

	opts            Options
	machine         *controlplane.StateMachine
	logs            *raftboltdb.BoltStore
	transport       *raft.NetworkTransport
	snapshots       raft.SnapshotStore
	raft            *raft.Raft
	notify          chan bool
	existing        bool
	prepared        bool
	closed          bool
	leadershipReady bool
	bindings        *peerBindings
	consensusState  controlplane.State
	lastCommit      controlplane.Commit
	hasLastCommit   bool
}

type command struct {
	Kind      string              `json:"kind"`
	Term      uint64              `json:"term,omitempty"`
	LeaderID  string              `json:"leader_id,omitempty"`
	UpdatedAt time.Time           `json:"updated_at,omitempty"`
	Commit    controlplane.Commit `json:"commit,omitempty"`
}

func New(opts Options) (*Runtime, error) {
	if strings.ToLower(strings.TrimSpace(opts.Profile)) != controlplane.StorageProfileProduction {
		return nil, fmt.Errorf("native-raft requires production storage profile")
	}
	if !controlplane.ValidIdentity(opts.ClusterID) {
		return nil, fmt.Errorf("cluster id is required and must not contain whitespace")
	}
	if opts.Mode != ModeBootstrap && opts.Mode != ModeJoin {
		return nil, fmt.Errorf("mode must be explicitly set to %q or %q", ModeBootstrap, ModeJoin)
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, fmt.Errorf("data directory is required")
	}
	if opts.BindAddress == "" {
		opts.BindAddress = "127.0.0.1:0"
	}
	if _, _, err := net.SplitHostPort(opts.BindAddress); err != nil {
		return nil, fmt.Errorf("invalid bind address: %w", err)
	}
	dataDir, err := secureDataDir(opts.DataDir)
	if err != nil {
		return nil, err
	}
	opts.DataDir = dataDir
	host, _, _ := net.SplitHostPort(opts.BindAddress)
	loopback := host == "localhost"
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	}
	if opts.InsecureTestMode && !loopback {
		return nil, fmt.Errorf("insecure test mode requires a loopback bind address")
	}
	if opts.TLS == nil {
		opts.TLS = opts.TLSConfig
	}
	if !opts.InsecureTestMode && opts.TLS == nil {
		return nil, fmt.Errorf("native-raft production transport requires TLS/mTLS configuration")
	}

	identityPath := filepath.Join(opts.DataDir, "node-id")
	addressPath := filepath.Join(opts.DataDir, "address")
	if err := rejectExistingSecureFile(identityPath, 0o600); err != nil {
		return nil, err
	}
	if err := rejectExistingSecureFile(addressPath, 0o600); err != nil {
		return nil, err
	}

	nodeID, err := loadOrCreateIdentity(identityPath, opts.NodeID, "node")
	if err != nil {
		return nil, err
	}
	opts.NodeID = nodeID

	machine, err := controlplane.NewStateMachine(opts.ClusterID, nil)
	if err != nil {
		return nil, err
	}
	raftDBPath := filepath.Join(opts.DataDir, "raft.db")
	if err := rejectExistingSecureFile(raftDBPath, 0o600); err != nil {
		return nil, err
	}
	logs, err := raftboltdb.NewBoltStore(raftDBPath)
	if err != nil {
		return nil, fmt.Errorf("open raft store: %w", err)
	}
	if err := checkSecureRegularFile(raftDBPath, 0o600); err != nil {
		_ = logs.Close()
		return nil, fmt.Errorf("validate raft store permissions: %w", err)
	}
	snapshotDir := filepath.Join(opts.DataDir, "snapshots")
	if err := ensureSecureDirectoryPath(snapshotDir); err != nil {
		_ = logs.Close()
		return nil, fmt.Errorf("prepare raft snapshots directory: %w", err)
	}
	snapshots, err := raft.NewFileSnapshotStore(opts.DataDir, 2, io.Discard)
	if err != nil {
		_ = logs.Close()
		return nil, fmt.Errorf("open raft snapshots: %w", err)
	}
	if err := os.Chmod(snapshotDir, 0o700); err != nil {
		_ = logs.Close()
		return nil, fmt.Errorf("secure raft snapshots directory: %w", err)
	}
	existing, err := raft.HasExistingState(logs, logs, snapshots)
	if err != nil {
		_ = logs.Close()
		return nil, fmt.Errorf("inspect raft state: %w", err)
	}
	savedAddress, addressErr := readAddress(addressPath)
	if addressErr != nil && !errors.Is(addressErr, os.ErrNotExist) {
		_ = logs.Close()
		return nil, fmt.Errorf("read persisted raft address: %w", addressErr)
	}
	if addressErr == nil && savedAddress != "" {
		if _, port, splitErr := net.SplitHostPort(opts.BindAddress); splitErr == nil && port == "0" {
			opts.BindAddress = savedAddress
		}
	}
	bindings := newPeerBindings()
	var transport *raft.NetworkTransport
	if opts.InsecureTestMode {
		layer, layerErr := newPlainStreamLayer(opts.BindAddress)
		if layerErr != nil {
			_ = logs.Close()
			return nil, fmt.Errorf("open raft test transport: %w", layerErr)
		}
		transport = raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{Stream: layer, MaxPool: 3, Timeout: 10 * time.Second})
	} else {
		tlsConfig, configErr := loadTLSConfig(opts.TLS, opts.NodeID)
		if configErr != nil {
			_ = logs.Close()
			return nil, configErr
		}
		layer, layerErr := newTLSStreamLayer(opts.BindAddress, tlsConfig, bindings)
		if layerErr != nil {
			_ = logs.Close()
			return nil, fmt.Errorf("open raft TLS transport: %w", layerErr)
		}
		transport = raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{Stream: layer, MaxPool: 3, Timeout: 10 * time.Second})
	}
	if transport == nil {
		_ = logs.Close()
		return nil, fmt.Errorf("open raft transport")
	}
	address := string(transport.LocalAddr())
	if err := atomicWriteSecure(addressPath, []byte(address), 0600); err != nil {
		_ = transport.Close()
		_ = logs.Close()
		return nil, fmt.Errorf("persist raft address: %w", err)
	}

	notify := make(chan bool, 8)
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(opts.NodeID)
	config.NotifyCh = notify
	config.HeartbeatTimeout = 50 * time.Millisecond
	config.ElectionTimeout = 250 * time.Millisecond
	config.CommitTimeout = 25 * time.Millisecond
	config.LeaderLeaseTimeout = 25 * time.Millisecond
	config.SnapshotInterval = 20 * time.Minute
	config.SnapshotThreshold = 1024
	config.LogOutput = io.Discard
	r := &Runtime{opts: opts, machine: machine, logs: logs, transport: transport, snapshots: snapshots, notify: notify, existing: existing, done: make(chan struct{}), bindings: bindings, consensusState: cloneRuntimeState(machine.Snapshot())}
	r.raft, err = raft.NewRaft(config, r, logs, logs, snapshots, transport)
	if err != nil {
		_ = transport.Close()
		_ = logs.Close()
		return nil, fmt.Errorf("create raft: %w", err)
	}
	if configuration := r.raft.GetConfiguration(); configuration.Error() == nil {
		for _, server := range configuration.Configuration().Servers {
			bindings.bind(string(server.Address), string(server.ID))
		}
	}
	go r.observeLeadership()
	return r, nil
}

func (r *Runtime) Prepare(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	if r.prepared {
		r.mu.Unlock()
		return nil
	}
	r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.opts.Mode == ModeBootstrap && !r.existing {
		future := r.raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{{ID: raft.ServerID(r.opts.NodeID), Address: raft.ServerAddress(r.Address())}}})
		if err := future.Error(); err != nil && !errors.Is(err, raft.ErrCantBootstrap) {
			return fmt.Errorf("bootstrap raft cluster: %w", err)
		}
		r.existing = true
	}
	r.mu.Lock()
	r.prepared = true
	r.mu.Unlock()
	return nil
}

func (r *Runtime) Health(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.RLock()
	closed, prepared := r.closed, r.prepared
	r.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if !prepared {
		return ErrNotReady
	}
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %v", ErrNotReady, err)
		}
		if r.raft.State() == raft.Shutdown {
			return ErrClosed
		}
		if r.healthReady() {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%w: %v", ErrNotReady, ctx.Err())
		case <-timer.C:
		}
	}
}

func (r *Runtime) healthReady() bool {
	leaderAddr, leaderID := r.raft.LeaderWithID()
	if leaderAddr == "" || leaderID == "" {
		return false
	}
	conf := r.raft.GetConfiguration()
	if conf.Error() != nil {
		return false
	}
	found := false
	for _, server := range conf.Configuration().Servers {
		if server.ID == raft.ServerID(r.NodeID()) && string(server.Address) == r.Address() {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	state := r.machine.Snapshot()
	return state.LeaderID == string(leaderID) && state.Term == r.raft.CurrentTerm() && state.LeaderID != "" && state.Term != 0
}

func (r *Runtime) Current(ctx context.Context, clusterID string) (controlplane.State, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return controlplane.State{}, err
	}
	if clusterID != r.opts.ClusterID {
		return controlplane.State{}, controlplane.ErrStateNotFound
	}
	if r.raft == nil || r.raft.State() == raft.Shutdown {
		return controlplane.State{}, ErrClosed
	}
	state := r.consensusSnapshot()
	if state.ClusterID != clusterID || state.LeaderID == "" || state.Term == 0 {
		return controlplane.State{}, controlplane.ErrStateNotFound
	}
	return state, nil
}

// CurrentCommit returns the exact latest desired-state commit retained by the
// replicated FSM. Leadership checkpoints may advance term/epoch metadata
// without changing this commit, so callers must still compare Current before
// using it for one-step durable recovery.
func (r *Runtime) CurrentCommit(ctx context.Context, clusterID string) (controlplane.Commit, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return controlplane.Commit{}, err
	}
	if clusterID != r.opts.ClusterID || r.raft == nil || r.raft.State() == raft.Shutdown {
		return controlplane.Commit{}, controlplane.ErrStateNotFound
	}
	r.mu.RLock()
	commit, ok := cloneRuntimeCommit(r.lastCommit), r.hasLastCommit
	state := cloneRuntimeState(r.consensusState)
	r.mu.RUnlock()
	if !ok || !sameNativePayload(commit.State, state) {
		return controlplane.Commit{}, controlplane.ErrStateNotFound
	}
	return commit, nil
}

func (r *Runtime) Propose(ctx context.Context, commit controlplane.Commit) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.propose.Lock()
	defer r.propose.Unlock()
	current := r.machine.Snapshot()
	if r.commitAlreadyReplicated(current, commit) {
		return r.ensureLeaderForReplicatedRetry()
	}
	protectedInitial := isProtectedInitialCommit(current, commit)
	if protectedInitial {
		if err := r.ensureLeaderForInitial(); err != nil {
			return err
		}
	} else if err := r.ensureLeader(); err != nil {
		return err
	}
	initial := isInitialCommit(current, commit)
	if err := validateIncomingCommit(current, commit); err != nil {
		return err
	}
	if !initial {
		// The coordinator obtains this exact commit from the same state machine.
		// Re-proposing here would advance the tentative revision a second time
		// before Raft replicates it. Validate the proposal source instead, then
		// put the exact immutable commit in the log.
		if err := r.machine.ValidateCommit(commit); err != nil {
			return err
		}
	}
	data, err := json.Marshal(command{Kind: "commit", Commit: commit})
	if err != nil {
		return err
	}
	future := r.raft.Apply(data, remainingTimeout(ctx, 8*time.Second))
	if err := future.Error(); err != nil {
		r.machine.FreezeWrites("raft commit failed")
		return err
	}
	if responseErr, ok := future.Response().(error); ok && responseErr != nil {
		return responseErr
	}
	return nil
}

func (r *Runtime) commitAlreadyReplicated(current controlplane.State, commit controlplane.Commit) bool {
	r.mu.RLock()
	lastCommit, hasLastCommit := cloneRuntimeCommit(r.lastCommit), r.hasLastCommit
	r.mu.RUnlock()
	if !hasLastCommit || !runtimeCommitsEquivalent(lastCommit, commit) {
		return false
	}
	if current.ClusterID != commit.State.ClusterID || current.LeaderID != commit.State.LeaderID || current.Term != commit.State.Term || current.Epoch != commit.State.Epoch || current.Revision != commit.State.Revision ||
		current.Desired.Version != commit.State.Desired.Version || current.Desired.Digest != commit.State.Desired.Digest || string(current.Desired.Payload) != string(commit.State.Desired.Payload) ||
		commit.Fence.ClusterID != current.ClusterID || commit.Fence.LeaderID != current.LeaderID || commit.Fence.Epoch != current.Epoch || commit.Fence.Revision != current.Revision ||
		commit.Fence.Digest != current.Desired.Digest || commit.State.WriteFrozen || commit.State.FreezeReason != "" || commit.State.UpdatedAt.IsZero() ||
		commit.State.Desired.Digest != controlplane.Digest(commit.State.Desired.Payload) || !controlplane.ValidIdentity(commit.State.Desired.Version) || !controlplane.ValidIdentity(commit.Fence.Nonce) ||
		len(current.NonceLedger) != len(commit.State.NonceLedger) || commit.State.NonceLedger[commit.Fence.Nonce] != current.Revision {
		return false
	}
	for nonce, revision := range current.NonceLedger {
		if commit.State.NonceLedger[nonce] != revision {
			return false
		}
	}
	return r.machine.ValidateFence(commit.Fence) == nil
}

func (r *Runtime) ensureLeaderForReplicatedRetry() error {
	if r == nil || r.raft == nil || r.raft.State() != raft.Leader {
		return controlplane.ErrNotLeader
	}
	state := r.machine.Snapshot()
	if state.LeaderID != r.NodeID() || state.Term != r.raft.CurrentTerm() || !r.healthReady() {
		return controlplane.ErrNotLeader
	}
	return nil
}

func (r *Runtime) Establish(ctx context.Context, state controlplane.State) (controlplane.FenceToken, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return controlplane.FenceToken{}, err
	}
	if err := r.ensureLeaderForReplicatedRetry(); err != nil {
		return controlplane.FenceToken{}, err
	}
	current := r.consensusSnapshot()
	if state.ClusterID != current.ClusterID || state.LeaderID != current.LeaderID || state.Term != current.Term || state.Epoch != current.Epoch || state.Revision == 0 || state.Revision != current.Revision || state.Desired.Digest != current.Desired.Digest {
		return controlplane.FenceToken{}, ErrFenceStale
	}
	nonce := nonceForRevision(state.NonceLedger, state.Revision)
	if nonce == "" || current.NonceLedger[nonce] != state.Revision {
		return controlplane.FenceToken{}, ErrFenceStale
	}
	return controlplane.FenceToken{ClusterID: current.ClusterID, LeaderID: current.LeaderID, Epoch: current.Epoch, Revision: current.Revision, Digest: current.Desired.Digest, Nonce: nonce}, nil
}

func (r *Runtime) Join(ctx context.Context, member Member) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !controlplane.ValidIdentity(member.ID) || !validAddress(member.Address) {
		return fmt.Errorf("invalid raft member")
	}
	if err := r.ensureLeader(); err != nil {
		return err
	}
	r.bindings.bind(member.Address, member.ID)
	future := r.raft.AddVoter(raft.ServerID(member.ID), raft.ServerAddress(member.Address), 0, remainingTimeout(ctx, 8*time.Second))
	return future.Error()
}

func (r *Runtime) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		close(r.done)
		if r.raft != nil {
			err = r.raft.Shutdown().Error()
		}
		if r.transport != nil {
			if closeErr := r.transport.Close(); err == nil {
				err = closeErr
			}
		}
		if r.logs != nil {
			if closeErr := r.logs.Close(); err == nil {
				err = closeErr
			}
		}
	})
	return err
}

func (r *Runtime) NodeID() string {
	if r == nil {
		return ""
	}
	return r.opts.NodeID
}

func (r *Runtime) Address() string {
	if r == nil || r.transport == nil {
		return ""
	}
	return string(r.transport.LocalAddr())
}

func (r *Runtime) Backend() string {
	return controlplane.ConsensusBackendNativeRaft
}

// CheckpointLeadership validates the native-raft leadership metadata against
// a durable payload without changing the desired state. The durable adapter
// must persist the returned metadata through its own checkpoint capability;
// this method never overwrites PostgreSQL or fabricates a fence on followers.
func (r *Runtime) CheckpointLeadership(ctx context.Context, durable, consensus controlplane.State) (controlplane.State, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return controlplane.State{}, err
	}
	if r == nil || r.raft == nil || r.raft.State() == raft.Shutdown {
		return controlplane.State{}, ErrClosed
	}
	if !sameNativePayload(durable, consensus) {
		return controlplane.State{}, controlplane.ErrStaleRevision
	}
	leaderAddr, leaderID := r.raft.LeaderWithID()
	if leaderAddr == "" || leaderID == "" || consensus.LeaderID != string(leaderID) || consensus.Term != r.raft.CurrentTerm() || consensus.WriteFrozen {
		return controlplane.State{}, controlplane.ErrNotLeader
	}
	current := r.consensusSnapshot()
	if !sameNativePayload(current, consensus) || current.LeaderID != consensus.LeaderID || current.Term != consensus.Term || current.Epoch != consensus.Epoch || current.Revision != consensus.Revision {
		return controlplane.State{}, ErrFenceStale
	}
	return current, nil
}

// Machine exposes the runtime-owned state machine to the startup coordinator.
// Callers must treat the returned machine as a read/write boundary owned by
// Runtime; direct writes are only safe during the Bootstrap sequence.
func (r *Runtime) Machine() *controlplane.StateMachine {
	if r == nil {
		return nil
	}
	return r.machine
}

func (r *Runtime) Status() Status {
	if r == nil {
		return Status{}
	}
	state := r.machine.Snapshot()
	r.mu.RLock()
	leadershipReady := r.leadershipReady
	prepared := r.prepared
	r.mu.RUnlock()
	leaderAddr, leaderID := r.raft.LeaderWithID()
	raftState := r.raft.State()
	joined := false
	if future := r.raft.GetConfiguration(); future.Error() == nil {
		for _, server := range future.Configuration().Servers {
			if server.ID == raft.ServerID(r.NodeID()) {
				joined = true
				break
			}
		}
	}
	isLeader := raftState == raft.Leader && string(leaderID) == r.NodeID() && state.LeaderID == r.NodeID() && state.Term == r.raft.CurrentTerm() && leaderAddr != "" && leadershipReady
	ready := prepared && raftState != raft.Shutdown && joined && leaderAddr != "" && leaderID != "" && state.LeaderID != "" && state.Term == r.raft.CurrentTerm() && (raftState != raft.Leader || leadershipReady)
	return Status{ClusterID: r.opts.ClusterID, NodeID: r.NodeID(), Address: r.Address(), LeaderID: string(leaderID), Leader: string(leaderAddr), Term: r.raft.CurrentTerm(), Epoch: state.Epoch, Revision: state.Revision, IsLeader: isLeader, Joined: joined, Ready: ready, ReadOnly: joined && state.LeaderID != "" && !isLeader, WriteReady: isLeader && !state.WriteFrozen, State: raftState}
}

func (r *Runtime) ensureLeader() error {
	if r == nil || r.raft == nil {
		return ErrNotReady
	}
	if r.raft.State() != raft.Leader {
		return controlplane.ErrNotLeader
	}
	state := r.machine.Snapshot()
	if state.LeaderID != r.NodeID() || state.Term != r.raft.CurrentTerm() || state.WriteFrozen || !r.healthReady() {
		return controlplane.ErrNotLeader
	}
	return nil
}

func (r *Runtime) ensureLeaderForInitial() error {
	if r == nil || r.raft == nil {
		return ErrNotReady
	}
	if r.raft.State() != raft.Leader || !r.healthReady() {
		return controlplane.ErrNotLeader
	}
	state := r.machine.Snapshot()
	leaderAddr, leaderID := r.raft.LeaderWithID()
	if leaderAddr == "" || string(leaderID) != r.NodeID() || state.LeaderID != r.NodeID() || state.Term != r.raft.CurrentTerm() || state.Revision != 0 {
		return controlplane.ErrNotLeader
	}
	return nil
}

func (r *Runtime) observeLeadership() {
	for {
		select {
		case <-r.done:
			return
		case isLeader := <-r.notify:
			if !isLeader {
				r.machine.FreezeWrites("native-raft leadership unavailable")
				r.mu.Lock()
				r.leadershipReady = false
				r.mu.Unlock()
				continue
			}
			if err := r.persistLeadership(); err != nil {
				r.mu.Lock()
				r.leadershipReady = false
				r.mu.Unlock()
				continue
			}
			r.mu.Lock()
			r.leadershipReady = true
			r.mu.Unlock()
		}
	}
}

func (r *Runtime) persistLeadership() error {
	term := r.raft.CurrentTerm()
	leaderAddr, leaderID := r.raft.LeaderWithID()
	if leaderAddr == "" || string(leaderID) != r.NodeID() || term == 0 {
		return ErrNotReady
	}
	state := r.machine.Snapshot()
	if state.LeaderID == r.NodeID() && state.Term == term && !state.WriteFrozen {
		return nil
	}
	data, err := json.Marshal(command{Kind: "leadership", Term: term, LeaderID: r.NodeID(), UpdatedAt: time.Now().UTC()})
	if err != nil {
		return err
	}
	future := r.raft.Apply(data, 8*time.Second)
	return future.Error()
}

func (r *Runtime) Apply(log *raft.Log) interface{} {
	var cmd command
	if err := json.Unmarshal(log.Data, &cmd); err != nil {
		return err
	}
	switch cmd.Kind {
	case "leadership":
		machineState, err := r.machine.InstallLeadership(cmd.Term, cmd.LeaderID)
		if err != nil {
			return err
		}
		r.mu.Lock()
		next, err := advanceConsensusLeadership(r.consensusState, machineState, cmd)
		if err == nil {
			r.consensusState = next
		}
		r.mu.Unlock()
		return err
	case "commit":
		if err := r.machine.LoadSnapshot(cmd.Commit.State); err != nil {
			return err
		}
		r.mu.Lock()
		r.consensusState = cloneRuntimeState(cmd.Commit.State)
		r.lastCommit = cloneRuntimeCommit(cmd.Commit)
		r.hasLastCommit = true
		r.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("unknown native-raft command kind %q", cmd.Kind)
	}
}

func (r *Runtime) Snapshot() (raft.FSMSnapshot, error) {
	r.mu.RLock()
	snapshot := persistedSnapshot{Version: 1, State: cloneRuntimeState(r.consensusState)}
	if r.hasLastCommit {
		commit := cloneRuntimeCommit(r.lastCommit)
		snapshot.LastCommit = &commit
	}
	r.mu.RUnlock()
	return &fsmSnapshot{snapshot: snapshot}, nil
}

func (r *Runtime) Restore(reader io.ReadCloser) error {
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	var snapshot persistedSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil || snapshot.Version != 1 {
		var legacy controlplane.State
		if legacyErr := json.Unmarshal(data, &legacy); legacyErr != nil {
			if err != nil {
				return err
			}
			return legacyErr
		}
		snapshot = persistedSnapshot{State: legacy}
	}
	if snapshot.LastCommit != nil {
		if !validRuntimeSnapshotCommit(*snapshot.LastCommit, snapshot.State) {
			return controlplane.ErrInvalidCommit
		}
	}
	if err := r.machine.LoadSnapshot(snapshot.State); err != nil {
		return err
	}
	r.machine.FreezeWrites("native-raft leadership unavailable")
	r.mu.Lock()
	r.consensusState = cloneRuntimeState(snapshot.State)
	r.hasLastCommit = false
	r.lastCommit = controlplane.Commit{}
	if snapshot.LastCommit != nil {
		r.lastCommit = cloneRuntimeCommit(*snapshot.LastCommit)
		r.hasLastCommit = true
	}
	r.mu.Unlock()
	return nil
}

type persistedSnapshot struct {
	Version    int                  `json:"version"`
	State      controlplane.State   `json:"state"`
	LastCommit *controlplane.Commit `json:"last_commit,omitempty"`
}

type fsmSnapshot struct {
	snapshot persistedSnapshot
}

func (s *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.snapshot); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *fsmSnapshot) Release() {}

func validateIncomingCommit(current controlplane.State, commit controlplane.Commit) error {
	if commit.State.ClusterID != current.ClusterID || commit.Fence.ClusterID != current.ClusterID {
		return controlplane.ErrInvalidCommit
	}
	if commit.State.LeaderID != current.LeaderID || commit.Fence.LeaderID != current.LeaderID || commit.State.Term != current.Term || commit.State.Epoch != current.Epoch || commit.Fence.Epoch != current.Epoch {
		return controlplane.ErrStaleEpoch
	}
	if commit.State.Revision != current.Revision+1 || commit.Fence.Revision != commit.State.Revision {
		return controlplane.ErrStaleRevision
	}
	if commit.State.WriteFrozen || commit.State.FreezeReason != "" || commit.State.UpdatedAt.IsZero() || commit.State.Desired.Digest == "" || commit.State.Desired.Digest != controlplane.Digest(commit.State.Desired.Payload) || commit.Fence.Digest != commit.State.Desired.Digest || !controlplane.ValidIdentity(commit.State.Desired.Version) || !controlplane.ValidIdentity(commit.Fence.Nonce) || !nonceLedgerExtendsCurrent(current.NonceLedger, commit.State.NonceLedger, commit.Fence.Nonce, commit.State.Revision) {
		return controlplane.ErrInvalidCommit
	}
	return nil
}

func nonceLedgerExtendsCurrent(current, next map[string]controlplane.Revision, nonce string, revision controlplane.Revision) bool {
	if len(next) != len(current)+1 || next[nonce] != revision {
		return false
	}
	if _, reused := current[nonce]; reused {
		return false
	}
	for existing, existingRevision := range current {
		if next[existing] != existingRevision {
			return false
		}
	}
	return true
}

func cloneRuntimeCommit(commit controlplane.Commit) controlplane.Commit {
	clone := commit
	clone.State.Desired.Payload = append([]byte(nil), commit.State.Desired.Payload...)
	clone.State.NonceLedger = make(map[string]controlplane.Revision, len(commit.State.NonceLedger))
	for nonce, revision := range commit.State.NonceLedger {
		clone.State.NonceLedger[nonce] = revision
	}
	return clone
}

func cloneRuntimeState(state controlplane.State) controlplane.State {
	clone := state
	clone.Desired.Payload = append([]byte(nil), state.Desired.Payload...)
	clone.NonceLedger = make(map[string]controlplane.Revision, len(state.NonceLedger))
	for nonce, revision := range state.NonceLedger {
		clone.NonceLedger[nonce] = revision
	}
	return clone
}

func (r *Runtime) consensusSnapshot() controlplane.State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneRuntimeState(r.consensusState)
}

func advanceConsensusLeadership(current, machineState controlplane.State, cmd command) (controlplane.State, error) {
	if cmd.Term == 0 || !controlplane.ValidIdentity(cmd.LeaderID) || current.ClusterID == "" || machineState.ClusterID != current.ClusterID {
		return controlplane.State{}, controlplane.ErrInvalidCommit
	}
	if cmd.Term < current.Term || (cmd.Term == current.Term && cmd.LeaderID != current.LeaderID) {
		return controlplane.State{}, controlplane.ErrLeadershipConflict
	}
	if cmd.Term == current.Term && cmd.LeaderID == current.LeaderID {
		return cloneRuntimeState(current), nil
	}
	if current.Epoch == ^controlplane.Epoch(0) {
		return controlplane.State{}, controlplane.ErrInvalidCommit
	}
	updatedAt := cmd.UpdatedAt.UTC()
	if updatedAt.IsZero() {
		// Legacy logs did not carry a deterministic timestamp. Keep them
		// readable, but all newly written commands bind the leader timestamp.
		updatedAt = machineState.UpdatedAt.UTC()
	}
	if updatedAt.Before(current.UpdatedAt) {
		// A newly elected leader may have a slower wall clock than the previous
		// leader. Raft state timestamps are monotonic metadata, so clock skew
		// must not turn a valid leadership change into a PostgreSQL regression.
		updatedAt = current.UpdatedAt.UTC()
	}
	next := cloneRuntimeState(current)
	next.LeaderID = cmd.LeaderID
	next.Term = cmd.Term
	next.Epoch++
	next.WriteFrozen = false
	next.FreezeReason = ""
	next.UpdatedAt = updatedAt
	if machineState.LeaderID != next.LeaderID || machineState.Term != next.Term || machineState.Epoch != next.Epoch || !sameNativePayload(machineState, next) {
		return controlplane.State{}, controlplane.ErrInvalidCommit
	}
	return next, nil
}

func validRuntimeSnapshotCommit(commit controlplane.Commit, state controlplane.State) bool {
	return !commit.State.WriteFrozen && commit.State.FreezeReason == "" && !commit.State.UpdatedAt.IsZero() &&
		commit.Fence.ClusterID == commit.State.ClusterID && commit.Fence.LeaderID == commit.State.LeaderID && commit.Fence.Epoch == commit.State.Epoch &&
		commit.Fence.Revision == commit.State.Revision && commit.Fence.Digest == commit.State.Desired.Digest && commit.State.NonceLedger[commit.Fence.Nonce] == commit.State.Revision &&
		commit.State.Desired.Digest == controlplane.Digest(commit.State.Desired.Payload) && sameNativePayload(commit.State, state)
}

func runtimeCommitsEquivalent(a, b controlplane.Commit) bool {
	if a.Fence != b.Fence || a.State.ClusterID != b.State.ClusterID || a.State.LeaderID != b.State.LeaderID || a.State.Term != b.State.Term || a.State.Epoch != b.State.Epoch || a.State.Revision != b.State.Revision ||
		a.State.Desired.Version != b.State.Desired.Version || a.State.Desired.Digest != b.State.Desired.Digest || string(a.State.Desired.Payload) != string(b.State.Desired.Payload) ||
		a.State.WriteFrozen != b.State.WriteFrozen || a.State.FreezeReason != b.State.FreezeReason || !a.State.UpdatedAt.Equal(b.State.UpdatedAt) || len(a.State.NonceLedger) != len(b.State.NonceLedger) {
		return false
	}
	for nonce, revision := range a.State.NonceLedger {
		if b.State.NonceLedger[nonce] != revision {
			return false
		}
	}
	return true
}

func isProtectedInitialCommit(current controlplane.State, commit controlplane.Commit) bool {
	return current.WriteFrozen && isInitialCommit(current, commit)
}

func isInitialCommit(current controlplane.State, commit controlplane.Commit) bool {
	return current.Revision == 0 && current.LeaderID != "" && current.Term != 0 && current.Epoch != 0 && commit.State.Revision == 1 && commit.State.LeaderID == current.LeaderID && commit.State.Term == current.Term && commit.State.Epoch == current.Epoch
}

func nonceForRevision(ledger map[string]controlplane.Revision, revision controlplane.Revision) string {
	for nonce, entryRevision := range ledger {
		if entryRevision == revision {
			return nonce
		}
	}
	return ""
}

func validAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	return err == nil && host != "" && port != ""
}

func sameNativePayload(a, b controlplane.State) bool {
	if a.ClusterID != b.ClusterID || a.Revision != b.Revision || a.Desired.Version != b.Desired.Version || a.Desired.Digest != b.Desired.Digest || string(a.Desired.Payload) != string(b.Desired.Payload) || len(a.NonceLedger) != len(b.NonceLedger) {
		return false
	}
	for nonce, revision := range a.NonceLedger {
		if b.NonceLedger[nonce] != revision {
			return false
		}
	}
	return true
}

func remainingTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return time.Millisecond
		}
		return remaining
	}
	return fallback
}

func loadOrCreateIdentity(path, requested, prefix string) (string, error) {
	if saved, err := readIdentity(path); err == nil && saved != "" {
		if requested != "" && requested != saved {
			return "", fmt.Errorf("persisted node id %q conflicts with requested node id %q", saved, requested)
		}
		return saved, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if requested != "" {
		if !controlplane.ValidIdentity(requested) {
			return "", fmt.Errorf("invalid node id")
		}
		if err := atomicWriteSecure(path, []byte(requested), 0600); err != nil {
			return "", fmt.Errorf("persist node id: %w", err)
		}
		return requested, nil
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate node id: %w", err)
	}
	id := prefix + "-" + hex.EncodeToString(raw[:])
	if err := atomicWriteSecure(path, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("persist node id: %w", err)
	}
	return id, nil
}

func readIdentity(path string) (string, error) {
	if err := checkSecureRegularFile(path, 0600); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := string(data)
	if !controlplane.ValidIdentity(value) {
		return "", fmt.Errorf("invalid persisted identity")
	}
	return value, nil
}

func readAddress(path string) (string, error) {
	if err := checkSecureRegularFile(path, 0600); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := string(data)
	if !validAddress(value) {
		return "", fmt.Errorf("invalid persisted raft address")
	}
	return value, nil
}

func rejectExistingSecureFile(path string, perm os.FileMode) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect secure file %q: %w", path, err)
	}
	if err := checkSecureRegularFile(path, perm); err != nil {
		return err
	}
	return nil
}
