// Package controlplane contains the versioned control-plane contract.
//
// The package deliberately has no network or database dependencies. It is the
// deterministic core that a native-raft coordinator and a PostgreSQL durable
// store can embed later. Redis is intentionally represented by a separate
// lease interface; it must never become the source of durable configuration.
package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidProposal    = errors.New("invalid control-plane proposal")
	ErrNotLeader          = errors.New("control-plane node is not the leader")
	ErrWritesFrozen       = errors.New("control-plane writes are frozen")
	ErrStaleEpoch         = errors.New("control-plane epoch is stale")
	ErrStaleRevision      = errors.New("control-plane revision is stale")
	ErrStaleFence         = errors.New("control-plane fencing token is stale")
	ErrLeadershipConflict = errors.New("control-plane leadership conflicts with current term")
	ErrDuplicateNonce     = errors.New("control-plane proposal nonce was already used")
	ErrStateNotFound      = errors.New("control-plane state was not found")
)

// Epoch identifies a leadership/configuration generation. It must increase
// whenever leadership changes; consumers must reject an older epoch.
type Epoch uint64

// Revision identifies an ordered desired-state commit within an epoch.
type Revision uint64

// DesiredState is the immutable configuration snapshot committed by the
// control plane. Payload is opaque to this package and should contain a
// canonical JSON representation produced by the owning subsystem.
type DesiredState struct {
	Version string          `json:"version"`
	Digest  string          `json:"digest"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// FenceToken is attached to every downstream apply operation. A data-plane
// consumer must only apply a token that is at least as new as the one it has
// already accepted and must never apply a token from another leader.
type FenceToken struct {
	ClusterID string   `json:"cluster_id"`
	LeaderID  string   `json:"leader_id"`
	Epoch     Epoch    `json:"epoch"`
	Revision  Revision `json:"revision"`
	Digest    string   `json:"digest"`
	Nonce     string   `json:"nonce"`
}

// State is a read-only snapshot of control-plane metadata and desired state.
type State struct {
	ClusterID    string              `json:"cluster_id"`
	LeaderID     string              `json:"leader_id,omitempty"`
	Term         uint64              `json:"term"`
	Epoch        Epoch               `json:"epoch"`
	Revision     Revision            `json:"revision"`
	Desired      DesiredState        `json:"desired"`
	WriteFrozen  bool                `json:"write_frozen"`
	FreezeReason string              `json:"freeze_reason,omitempty"`
	UpdatedAt    time.Time           `json:"updated_at"`
	NonceLedger  map[string]Revision `json:"nonce_ledger,omitempty"`
}

// Proposal is a compare-and-swap request. ExpectedEpoch and ExpectedRevision
// prevent an operator or retrying client from overwriting a newer state.
type Proposal struct {
	LeaderID         string
	ExpectedEpoch    Epoch
	ExpectedRevision Revision
	Version          string
	Payload          json.RawMessage
	Digest           string
	Nonce            string
}

// Commit is the durable event written to the consensus log and PostgreSQL.
type Commit struct {
	State State      `json:"state"`
	Fence FenceToken `json:"fence"`
}

// DurableStore is the PostgreSQL-facing boundary. Implementations must make
// AppendCommit idempotent by (cluster_id, epoch, revision, nonce).
type DurableStore interface {
	LoadState(context.Context, string) (State, error)
	AppendCommit(context.Context, Commit) error
}

// ConsensusStore is the native-raft-facing boundary. It owns membership,
// leadership, epoch fencing and ordered commit replication.
type ConsensusStore interface {
	Current(context.Context, string) (State, error)
	Propose(context.Context, Commit) error
}

// LeaseStore is the Redis-facing boundary. It is for short-lived coordination
// only and must not be used to reconstruct State after a restart.
type LeaseStore interface {
	Acquire(context.Context, string, string, time.Duration) (Lease, error)
	Release(context.Context, Lease) error
}

type Lease struct {
	Key       string    `json:"key"`
	Owner     string    `json:"owner"`
	ExpiresAt time.Time `json:"expires_at"`
}

// StateMachine is a concurrency-safe deterministic state transition engine.
type StateMachine struct {
	mu              sync.RWMutex
	state           State
	committed       State
	now             func() time.Time
	fences          map[Revision]string
	committedFences map[Revision]string
	nonces          map[string]Revision
	proposals       map[Revision]Commit
}

func NewStateMachine(clusterID string, now func() time.Time) (*StateMachine, error) {
	if !ValidIdentity(clusterID) {
		return nil, fmt.Errorf("%w: cluster id is required", ErrInvalidProposal)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	initial := State{ClusterID: clusterID, WriteFrozen: true, FreezeReason: "leader not established", UpdatedAt: now().UTC()}
	return &StateMachine{state: initial, committed: initial, now: now, fences: make(map[Revision]string), committedFences: make(map[Revision]string), nonces: make(map[string]Revision), proposals: make(map[Revision]Commit)}, nil
}

// Snapshot returns a defensive copy suitable for API responses.
func (m *StateMachine) Snapshot() State {
	if m == nil {
		return State{WriteFrozen: true, FreezeReason: "state machine unavailable"}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := m.committed
	out.Desired.Payload = append([]byte(nil), m.committed.Desired.Payload...)
	if m.committed.NonceLedger != nil {
		out.NonceLedger = cloneNonceLedger(m.committed.NonceLedger)
	}
	return out
}

// InstallLeadership establishes or advances leadership. A new term or leader
// always increments Epoch, invalidating all previously issued fence tokens.
func (m *StateMachine) InstallLeadership(term uint64, leaderID string) (State, error) {
	if m == nil {
		return State{}, ErrInvalidProposal
	}
	if term == 0 || !ValidIdentity(leaderID) {
		return State{}, fmt.Errorf("%w: term and leader id are required", ErrInvalidProposal)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if term < m.state.Term || (term == m.state.Term && leaderID == m.state.LeaderID) {
		return m.snapshotLocked(), nil
	}
	if term == m.state.Term && leaderID != m.state.LeaderID {
		return State{}, fmt.Errorf("%w: term %d already belongs to leader %s", ErrLeadershipConflict, term, m.state.LeaderID)
	}
	if m.state.Epoch == ^Epoch(0) {
		m.state.WriteFrozen = true
		m.state.FreezeReason = "epoch overflow"
		m.committed.WriteFrozen = true
		m.committed.FreezeReason = "epoch overflow"
		return State{}, fmt.Errorf("%w: epoch overflow", ErrInvalidProposal)
	}
	base := m.state
	wasFrozen := m.state.WriteFrozen
	freezeReason := m.state.FreezeReason
	ledger := cloneNonceLedger(m.nonces)
	if m.state.WriteFrozen && m.committed.Revision != m.state.Revision {
		base = m.committed
		ledger = cloneNonceLedger(m.committed.NonceLedger)
	}
	base.Term = term
	base.LeaderID = leaderID
	base.Epoch++
	m.state = base
	m.fences = make(map[Revision]string)
	m.committedFences = make(map[Revision]string)
	m.nonces = ledger
	m.proposals = make(map[Revision]Commit)
	if !wasFrozen || m.committed.Revision == 0 || freezeReason == "native-raft leadership unavailable" {
		m.state.WriteFrozen = false
		m.state.FreezeReason = ""
	} else {
		m.state.WriteFrozen = true
		m.state.FreezeReason = freezeReason
	}
	m.state.UpdatedAt = m.now().UTC()
	m.state.NonceLedger = cloneNonceLedger(m.nonces)
	m.committed = m.state
	return m.snapshotLocked(), nil
}

// FreezeWrites makes the safety state explicit. Existing data-plane snapshots
// remain usable; only new desired-state commits are rejected.
func (m *StateMachine) FreezeWrites(reason string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state.WriteFrozen = true
	m.state.FreezeReason = reason
	if m.state.FreezeReason == "" {
		m.state.FreezeReason = "writes frozen"
	}
	m.state.UpdatedAt = m.now().UTC()
	m.committed.WriteFrozen = true
	m.committed.FreezeReason = m.state.FreezeReason
	m.committed.UpdatedAt = m.state.UpdatedAt
}

// ResumeWrites clears a freeze only for the currently installed leader and
// epoch. Recovery code must call this after it has validated a fresh durable
// snapshot and fencing token; callers cannot clear WriteFrozen arbitrarily.
func (m *StateMachine) ResumeWrites(token FenceToken) error {
	if m == nil {
		return ErrInvalidCommit
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateResumeFenceLocked(token); err != nil {
		return fmt.Errorf("%w: resume authority is invalid: %w", ErrWritesFrozen, err)
	}
	m.state.WriteFrozen = false
	m.state.FreezeReason = ""
	m.state.UpdatedAt = m.now().UTC()
	m.committed.WriteFrozen = false
	m.committed.FreezeReason = ""
	m.committed.UpdatedAt = m.state.UpdatedAt
	return nil
}

func (m *StateMachine) Propose(p Proposal) (Commit, error) {
	if m == nil {
		return Commit{}, ErrInvalidProposal
	}
	if !ValidIdentity(p.LeaderID) || !ValidIdentity(p.Version) || !ValidIdentity(p.Nonce) {
		return Commit{}, fmt.Errorf("%w: leader, version and nonce must be non-empty identity fields without whitespace", ErrInvalidProposal)
	}
	p.Payload = append([]byte(nil), p.Payload...)
	if len(p.Payload) == 0 {
		return Commit{}, fmt.Errorf("%w: leader, version, nonce and payload are required", ErrInvalidProposal)
	}
	digest := p.Digest
	if digest == "" {
		digest = Digest(p.Payload)
	}
	if !validDigest(digest) {
		return Commit{}, fmt.Errorf("%w: digest must be a lowercase sha256 hex value", ErrInvalidProposal)
	}
	if digest != Digest(p.Payload) {
		return Commit{}, fmt.Errorf("%w: digest does not match payload", ErrInvalidProposal)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state.WriteFrozen {
		return Commit{}, fmt.Errorf("%w: %s", ErrWritesFrozen, m.state.FreezeReason)
	}
	if p.LeaderID != m.state.LeaderID {
		return Commit{}, fmt.Errorf("%w: leader=%s", ErrNotLeader, m.state.LeaderID)
	}
	if p.ExpectedEpoch != m.state.Epoch {
		return Commit{}, fmt.Errorf("%w: got %d want %d", ErrStaleEpoch, p.ExpectedEpoch, m.state.Epoch)
	}
	if p.ExpectedRevision != m.state.Revision {
		return Commit{}, fmt.Errorf("%w: got %d want %d", ErrStaleRevision, p.ExpectedRevision, m.state.Revision)
	}
	if _, used := m.nonces[p.Nonce]; used {
		return Commit{}, ErrDuplicateNonce
	}
	m.state.Revision++
	m.state.Desired = DesiredState{Version: p.Version, Digest: digest, Payload: append([]byte(nil), p.Payload...)}
	m.state.UpdatedAt = m.now().UTC()
	m.fences[m.state.Revision] = digest
	m.nonces[p.Nonce] = m.state.Revision
	m.state.NonceLedger = cloneNonceLedger(m.nonces)
	commit := Commit{State: m.snapshotLocked(), Fence: FenceToken{ClusterID: m.state.ClusterID, LeaderID: m.state.LeaderID, Epoch: m.state.Epoch, Revision: m.state.Revision, Digest: digest, Nonce: p.Nonce}}
	m.proposals[m.state.Revision] = cloneCommit(commit)
	return commit, nil
}

// ValidateFence rejects tokens that belong to another cluster/leader or are
// older than the current state. It is intentionally side-effect free.
func (m *StateMachine) ValidateFence(token FenceToken) error {
	if m == nil {
		return ErrStaleFence
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Older revisions from the current epoch remain valid so the data plane can
	// continue serving its last-known-good snapshot while the control plane is
	// unavailable. A leadership change resets the fence history and invalidates
	// every token from the previous epoch.
	return m.validateFenceLocked(token)
}

func (m *StateMachine) validateFenceLocked(token FenceToken) error {
	digest, ok := m.committedFences[token.Revision]
	if token.ClusterID != m.committed.ClusterID || token.LeaderID != m.committed.LeaderID || token.Epoch != m.committed.Epoch || token.Revision == 0 || token.Revision > m.committed.Revision || !ok || token.Digest != digest || token.Nonce == "" || m.nonces[token.Nonce] != token.Revision {
		return ErrStaleFence
	}
	return nil
}

func (m *StateMachine) validateResumeFenceLocked(token FenceToken) error {
	if token.Revision != m.committed.Revision {
		return ErrStaleFence
	}
	return m.validateFenceLocked(token)
}

// ValidateCommit verifies that a commit was produced by this state machine
// and that every fencing field remains bound to the immutable desired-state
// payload. Historical commits from the current epoch remain valid for retry
// after a later revision has been proposed; a commit from an older epoch is
// always rejected.
func (m *StateMachine) ValidateCommit(commit Commit) error {
	if m == nil {
		return ErrInvalidCommit
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.validateCommitLocked(commit)
}

func (m *StateMachine) validateCommitLocked(commit Commit) error {
	if !ValidIdentity(commit.Fence.ClusterID) || !ValidIdentity(commit.Fence.LeaderID) || !ValidIdentity(commit.Fence.Nonce) || commit.Fence.Revision == 0 {
		return fmt.Errorf("%w: fencing fields are required", ErrInvalidCommit)
	}
	if !ValidIdentity(commit.State.ClusterID) || !ValidIdentity(commit.State.LeaderID) || !ValidIdentity(commit.State.Desired.Version) || len(commit.State.Desired.Payload) == 0 {
		return fmt.Errorf("%w: state fields are required", ErrInvalidCommit)
	}
	if commit.State.Desired.Digest != Digest(commit.State.Desired.Payload) || !validDigest(commit.State.Desired.Digest) {
		return fmt.Errorf("%w: desired digest does not match payload", ErrInvalidCommit)
	}
	if commit.Fence.Digest != commit.State.Desired.Digest || !validDigest(commit.Fence.Digest) || commit.State.Revision != commit.Fence.Revision {
		return fmt.Errorf("%w: fence digest does not match desired state", ErrInvalidCommit)
	}
	if commit.State.WriteFrozen {
		return fmt.Errorf("%w: frozen state cannot be committed", ErrInvalidCommit)
	}
	if !validNonceLedger(commit.State.NonceLedger, commit.State.Revision) {
		return fmt.Errorf("%w: nonce ledger is incomplete or invalid", ErrInvalidCommit)
	}
	if commit.State.ClusterID != m.state.ClusterID || commit.Fence.ClusterID != m.state.ClusterID {
		return fmt.Errorf("%w: cluster binding mismatch", ErrInvalidCommit)
	}
	if commit.State.LeaderID != commit.Fence.LeaderID || commit.State.Term != m.state.Term || commit.State.Epoch != commit.Fence.Epoch || commit.State.Revision > m.state.Revision {
		return fmt.Errorf("%w: leader, term, epoch or revision binding mismatch", ErrInvalidCommit)
	}
	if commit.Fence.LeaderID != m.state.LeaderID || commit.Fence.Epoch != m.state.Epoch || commit.Fence.Revision > m.state.Revision {
		return fmt.Errorf("%w: commit is stale or from another leader", ErrInvalidCommit)
	}
	digest, ok := m.fences[commit.Fence.Revision]
	if !ok || digest != commit.Fence.Digest {
		return fmt.Errorf("%w: unknown fencing digest", ErrInvalidCommit)
	}
	if revision, ok := m.nonces[commit.Fence.Nonce]; !ok || revision != commit.Fence.Revision {
		return fmt.Errorf("%w: nonce is not bound to commit revision", ErrInvalidCommit)
	}
	for nonce, revision := range commit.State.NonceLedger {
		if m.nonces[nonce] != revision {
			return fmt.Errorf("%w: nonce ledger does not match state machine", ErrInvalidCommit)
		}
	}
	if source, ok := m.proposals[commit.Fence.Revision]; ok {
		if !commitsEquivalent(source, commit) {
			return fmt.Errorf("%w: commit source is not bound to this state machine", ErrInvalidCommit)
		}
	} else if commit.State.Revision != m.committed.Revision || !statesEquivalentForCommit(m.committed, commit.State) {
		return fmt.Errorf("%w: commit source is not bound to this state machine", ErrInvalidCommit)
	}
	return nil
}

// LoadSnapshot installs a validated durable snapshot and resets transient
// proposal bookkeeping. The durable format does not retain historical nonce
// values, so only the snapshot's current digest is seeded as last-known-good;
// subsequent proposals continue with normal epoch/revision CAS checks.
func (m *StateMachine) LoadSnapshot(snapshot State) error {
	return m.loadSnapshot(snapshot, nil)
}

// LoadSnapshotIfCurrent installs a snapshot only if the committed state still
// equals expected. It closes the leadership-change window between a fencing
// check and snapshot installation.
func (m *StateMachine) LoadSnapshotIfCurrent(expected, snapshot State) error {
	return m.loadSnapshot(snapshot, &expected)
}

func (m *StateMachine) loadSnapshot(snapshot State, expected *State) error {
	if m == nil {
		return ErrInvalidCommit
	}
	if !ValidIdentity(snapshot.ClusterID) {
		return fmt.Errorf("%w: snapshot cluster id is required", ErrInvalidCommit)
	}
	if snapshot.Revision == 0 {
		if snapshot.Desired.Version != "" || len(snapshot.Desired.Payload) != 0 || snapshot.Desired.Digest != "" {
			return fmt.Errorf("%w: empty snapshot has desired state", ErrInvalidCommit)
		}
		if !validNonceLedger(snapshot.NonceLedger, 0) {
			return fmt.Errorf("%w: empty snapshot has nonce ledger", ErrInvalidCommit)
		}
	} else {
		if !ValidIdentity(snapshot.Desired.Version) || len(snapshot.Desired.Payload) == 0 || !validDigest(snapshot.Desired.Digest) || snapshot.Desired.Digest != Digest(snapshot.Desired.Payload) || !validNonceLedger(snapshot.NonceLedger, snapshot.Revision) {
			return fmt.Errorf("%w: snapshot desired digest is invalid", ErrInvalidCommit)
		}
	}
	if snapshot.LeaderID != "" && !ValidIdentity(snapshot.LeaderID) {
		return fmt.Errorf("%w: snapshot leader id is invalid", ErrInvalidCommit)
	}
	if snapshot.LeaderID == "" && (snapshot.Term != 0 || snapshot.Epoch != 0) {
		return fmt.Errorf("%w: leader-less snapshot has term or epoch", ErrInvalidCommit)
	}
	if snapshot.LeaderID == "" && !snapshot.WriteFrozen {
		return fmt.Errorf("%w: leader-less snapshot must freeze writes", ErrInvalidCommit)
	}
	if snapshot.LeaderID != "" && (snapshot.Term == 0 || snapshot.Epoch == 0) {
		return fmt.Errorf("%w: leader snapshot requires term and epoch", ErrInvalidCommit)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if snapshot.ClusterID != m.state.ClusterID {
		return fmt.Errorf("%w: snapshot cluster id mismatch", ErrInvalidCommit)
	}
	current := m.committed
	if expected != nil && !sameLeadershipState(current, *expected) {
		return fmt.Errorf("%w: state changed while installing snapshot", ErrStaleRevision)
	}
	if snapshot.Revision < current.Revision || snapshot.Epoch < current.Epoch || (snapshot.Epoch == current.Epoch && snapshot.Term < current.Term) {
		return fmt.Errorf("%w: snapshot regresses committed revision or epoch", ErrStaleRevision)
	}
	if snapshot.Epoch == current.Epoch && snapshot.Term != current.Term {
		return fmt.Errorf("%w: snapshot changes term within the same epoch", ErrInvalidCommit)
	}
	if snapshot.Epoch == current.Epoch && snapshot.LeaderID != current.LeaderID {
		return fmt.Errorf("%w: snapshot changes leader within the same epoch", ErrInvalidCommit)
	}
	if snapshot.Epoch > current.Epoch && snapshot.Term <= current.Term {
		return fmt.Errorf("%w: snapshot epoch advanced without a higher term", ErrInvalidCommit)
	}
	if snapshot.Revision == current.Revision && snapshot.Revision > 0 && (snapshot.Desired.Version != current.Desired.Version || snapshot.Desired.Digest != current.Desired.Digest || string(snapshot.Desired.Payload) != string(current.Desired.Payload) || !sameNonceLedger(snapshot.NonceLedger, current.NonceLedger)) {
		return fmt.Errorf("%w: snapshot conflicts with committed state at the same revision", ErrInvalidCommit)
	}
	wasFrozen := m.state.WriteFrozen
	freezeReason := m.state.FreezeReason
	if snapshot.UpdatedAt.IsZero() {
		snapshot.UpdatedAt = m.now().UTC()
	}
	snapshot.Desired.Payload = append([]byte(nil), snapshot.Desired.Payload...)
	m.committed = snapshot
	m.state = snapshot
	if wasFrozen {
		m.committed.WriteFrozen = true
		m.committed.FreezeReason = freezeReason
		m.state.WriteFrozen = true
		m.state.FreezeReason = freezeReason
	}
	m.fences = make(map[Revision]string)
	m.committedFences = make(map[Revision]string)
	m.nonces = cloneNonceLedger(snapshot.NonceLedger)
	m.proposals = make(map[Revision]Commit)
	if snapshot.Revision > 0 {
		m.fences[snapshot.Revision] = snapshot.Desired.Digest
		m.committedFences[snapshot.Revision] = snapshot.Desired.Digest
	}
	return nil
}

func (m *StateMachine) InstallCommit(commit Commit) error {
	if m == nil {
		return ErrInvalidCommit
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.validateCommitLocked(commit); err != nil {
		return err
	}
	state := commit.State
	state.Desired.Payload = append([]byte(nil), commit.State.Desired.Payload...)
	if m.state.WriteFrozen {
		state.WriteFrozen = true
		state.FreezeReason = m.state.FreezeReason
	} else {
		state.WriteFrozen = false
		state.FreezeReason = ""
	}
	state.NonceLedger = cloneNonceLedger(commit.State.NonceLedger)
	if commit.State.Revision >= m.committed.Revision {
		m.committed = state
		m.committedFences[commit.State.Revision] = commit.State.Desired.Digest
	}
	if m.state.WriteFrozen || commit.State.Revision >= m.state.Revision {
		m.state = state
	}
	return nil
}

func cloneCommit(commit Commit) Commit {
	clone := commit
	clone.State.Desired.Payload = append([]byte(nil), commit.State.Desired.Payload...)
	clone.State.NonceLedger = cloneNonceLedger(commit.State.NonceLedger)
	return clone
}

func commitsEquivalent(a, b Commit) bool {
	return a.Fence == b.Fence && statesEquivalentForCommit(a.State, b.State)
}

func statesEquivalentForCommit(a, b State) bool {
	if a.ClusterID != b.ClusterID || a.LeaderID != b.LeaderID || a.Term != b.Term || a.Epoch != b.Epoch || a.Revision != b.Revision || a.Desired.Version != b.Desired.Version || a.Desired.Digest != b.Desired.Digest || string(a.Desired.Payload) != string(b.Desired.Payload) || a.WriteFrozen != b.WriteFrozen || a.FreezeReason != b.FreezeReason || !a.UpdatedAt.Equal(b.UpdatedAt) || len(a.NonceLedger) != len(b.NonceLedger) {
		return false
	}
	for nonce, revision := range a.NonceLedger {
		if b.NonceLedger[nonce] != revision {
			return false
		}
	}
	return true
}

func sameNonceLedger(a, b map[string]Revision) bool {
	if len(a) != len(b) {
		return false
	}
	for nonce, revision := range a {
		if b[nonce] != revision {
			return false
		}
	}
	return true
}

func sameLeadershipState(a, b State) bool {
	return a.ClusterID == b.ClusterID && a.Term == b.Term && a.Epoch == b.Epoch && a.LeaderID == b.LeaderID
}

func cloneNonceLedger(in map[string]Revision) map[string]Revision {
	out := make(map[string]Revision, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (m *StateMachine) snapshotLocked() State {
	out := m.state
	out.Desired.Payload = append([]byte(nil), m.state.Desired.Payload...)
	out.NonceLedger = cloneNonceLedger(m.nonces)
	return out
}

func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

// ValidIdentity rejects empty values, leading/trailing whitespace, control
// characters and invisible format characters. Identity fields are validated
// without rewriting the supplied value.
func ValidIdentity(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func validNonceLedger(ledger map[string]Revision, revision Revision) bool {
	if revision == 0 {
		return len(ledger) == 0
	}
	if revision == ^Revision(0) {
		return false
	}
	if uint64(len(ledger)) != uint64(revision) {
		return false
	}
	seen := make(map[Revision]struct{}, len(ledger))
	for nonce, entryRevision := range ledger {
		if !ValidIdentity(nonce) || entryRevision == 0 || entryRevision > revision {
			return false
		}
		if _, ok := seen[entryRevision]; ok {
			return false
		}
		seen[entryRevision] = struct{}{}
	}
	for expected := Revision(1); expected <= revision; expected++ {
		if _, ok := seen[expected]; !ok {
			return false
		}
	}
	return true
}
