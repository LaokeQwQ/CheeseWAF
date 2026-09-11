package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	controlpostgres "github.com/LaokeQwQ/CheeseWAF/internal/controlplane/postgres"
)

type Phase string

const (
	PhaseStarting Phase = "starting"
	PhaseReady    Phase = "ready"
	PhaseFrozen   Phase = "frozen"
	PhaseClosed   Phase = "closed"
)

var (
	ErrNotReady = errors.New("control-plane runtime is not ready")
	ErrClosed   = errors.New("control-plane runtime is closed")
)

// Status is intentionally free of DSNs, credentials, paths, and raw backend
// errors. It is safe to expose through the local status endpoint.
type Status struct {
	Profile    string                `json:"profile"`
	ClusterID  string                `json:"cluster_id"`
	NodeID     string                `json:"node_id"`
	Phase      Phase                 `json:"phase"`
	Ready      bool                  `json:"ready"`
	WriteReady bool                  `json:"write_ready"`
	Reason     string                `json:"reason,omitempty"`
	LeaderID   string                `json:"leader_id,omitempty"`
	Term       uint64                `json:"term,omitempty"`
	Epoch      controlplane.Epoch    `json:"epoch,omitempty"`
	Revision   controlplane.Revision `json:"revision,omitempty"`
	UpdatedAt  time.Time             `json:"updated_at,omitempty"`
}

// Dependencies lets tests and embedding launchers provide already opened
// adapters. Production callers should use Open, which opens both PostgreSQL
// adapters and the native-raft runtime itself.
type Dependencies struct {
	Durable   controlplane.DurableBootstrap
	Consensus controlplane.ConsensusBootstrap
	Fencer    controlplane.FenceBootstrap
	Machine   *controlplane.StateMachine
	Close     func() error
}

type Runtime struct {
	mu          sync.RWMutex
	opts        Options
	status      Status
	machine     *controlplane.StateMachine
	consensus   controlplane.ConsensusBootstrap
	coordinator *controlplane.Coordinator
	closeDeps   func() error
	httpServer  *http.Server
	listener    net.Listener
	closed      bool
}

// Open opens adapters and attempts the complete fail-closed bootstrap. It
// returns an error for an unready production process; callers must not start
// the status server in that case unless they deliberately use OpenFrozen.
func Open(ctx context.Context, opts Options) (*Runtime, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	controlStore, err := controlpostgres.Open(ctx, opts.PostgreSQLDSN)
	if err != nil {
		return nil, fmt.Errorf("open control-plane durable store: %w", scrubError(err))
	}
	raftNode, err := nativeraft.New(nativeRaftOptions(opts))
	if err != nil {
		_ = controlStore.Close()
		return nil, fmt.Errorf("open native-raft: %w", scrubError(err))
	}
	if opts.NodeID == "" {
		opts.NodeID = raftNode.NodeID()
	}
	deps := Dependencies{Durable: controlStore, Consensus: raftNode, Fencer: raftNode, Machine: raftNode.Machine(), Close: func() error {
		var first error
		if err := raftNode.Close(); err != nil {
			first = err
		}
		if err := controlStore.Close(); first == nil {
			first = err
		}
		return first
	}}
	r, err := OpenWithDependencies(ctx, opts, deps)
	if err != nil {
		_ = deps.Close()
		return nil, err
	}
	return r, nil
}

func nativeRaftOptions(opts Options) nativeraft.Options {
	return nativeraft.Options{
		Profile:     controlplane.StorageProfileProduction,
		ClusterID:   opts.ClusterID,
		NodeID:      opts.NodeID,
		DataDir:     opts.DataDir,
		BindAddress: opts.RaftListen,
		Mode:        opts.Mode,
		TLS:         &nativeraft.TLSOptions{CAFile: opts.CAFile, CertFile: opts.CertFile, KeyFile: opts.KeyFile},
	}
}

// OpenFrozen creates a local status/liveness runtime without touching network
// or database adapters. It is used by supervisors to expose why a previous
// bootstrap failed; it never claims readiness or enables writes.
func OpenFrozen(opts Options, reason string) (*Runtime, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	return &Runtime{opts: opts, status: Status{Profile: opts.Profile, ClusterID: opts.ClusterID, NodeID: opts.NodeID, Phase: PhaseFrozen, Reason: safeReason(reason), UpdatedAt: time.Now().UTC()}}, nil
}

// OpenWithDependencies executes the shared production bootstrap sequence.
// A failed bootstrap is returned as an error and the dependency owner remains
// responsible for closing adapters; no partially ready Runtime is returned.
func OpenWithDependencies(ctx context.Context, opts Options, deps Dependencies) (*Runtime, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	if opts.InitialState != nil || opts.InitialVersion != "" {
		return nil, errors.New("initial state import is not supported by cheesewaf-control")
	}
	if deps.Machine == nil {
		if provider, ok := deps.Consensus.(interface {
			Machine() *controlplane.StateMachine
		}); ok {
			deps.Machine = provider.Machine()
		}
	}
	if deps.Machine == nil {
		var err error
		deps.Machine, err = controlplane.NewStateMachine(opts.ClusterID, nil)
		if err != nil {
			return nil, err
		}
	}
	r := &Runtime{opts: opts, machine: deps.Machine, consensus: deps.Consensus, closeDeps: deps.Close, status: Status{Profile: opts.Profile, ClusterID: opts.ClusterID, NodeID: opts.NodeID, Phase: PhaseStarting, UpdatedAt: time.Now().UTC()}}
	result, err := controlplane.Bootstrap(ctx, controlplane.StartupOptions{Profile: opts.Profile, ClusterID: opts.ClusterID, Machine: deps.Machine, Durable: deps.Durable, Consensus: deps.Consensus, Fencer: deps.Fencer})
	if err != nil {
		r.setStatusFromState(PhaseFrozen, false, "control-plane startup failed", deps.Machine.Snapshot())
		return nil, scrubError(err)
	}
	r.coordinator = result.Coordinator
	r.setStatusFromState(PhaseReady, result.Ready, "", result.State)
	return r, nil
}

// Serve starts the local status server. It is separate from Open so callers
// can inspect a ready runtime and bind a supervisor-owned listener.
func (r *Runtime) Serve(ctx context.Context) error {
	if r == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	if r.httpServer != nil || r.listener != nil {
		r.mu.Unlock()
		return errors.New("control-plane HTTP server already started")
	}
	// Bind while holding the lifecycle mutex. Close cannot race a successful
	// bind and leave a listener behind after the runtime has been closed.
	listener, err := net.Listen("tcp", r.opts.Listen)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("listen control-plane HTTP: %w", err)
	}
	server := &http.Server{Addr: r.opts.Listen, Handler: r.Handler(), ReadHeaderTimeout: time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 1 << 20}
	r.listener = listener
	r.httpServer = server
	r.mu.Unlock()
	go func() { <-ctx.Done(); _ = server.Shutdown(context.Background()) }()
	err = server.Serve(listener)
	r.mu.Lock()
	if r.httpServer == server {
		r.httpServer = nil
		r.listener = nil
	}
	r.mu.Unlock()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (r *Runtime) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", r.handleHealth)
	mux.HandleFunc("/readyz", r.handleReady)
	mux.HandleFunc("/status", r.handleStatus)
	mux.HandleFunc("/proposals", r.handleProposal)
	return mux
}

func (r *Runtime) handleHealth(w http.ResponseWriter, req *http.Request) {
	if req != nil && req.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, r.Status())
}

func (r *Runtime) handleReady(w http.ResponseWriter, req *http.Request) {
	if req != nil && req.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	status := r.Status()
	if !status.Ready || !status.WriteReady {
		writeJSON(w, http.StatusServiceUnavailable, status)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (r *Runtime) handleStatus(w http.ResponseWriter, req *http.Request) {
	if req != nil && req.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, r.Status())
}

func (r *Runtime) handleProposal(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	status := r.Status()
	if !status.WriteReady {
		writeJSON(w, http.StatusServiceUnavailable, status)
		return
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "proposal transport is not mounted in this binary"})
}

func (r *Runtime) Status() Status {
	if r == nil {
		return Status{Phase: PhaseClosed}
	}
	r.mu.RLock()
	status := r.status
	closed := r.closed
	consensus := r.consensus
	machine := r.machine
	r.mu.RUnlock()
	if closed {
		status.Phase, status.Ready, status.WriteReady = PhaseClosed, false, false
		return status
	}
	if machine != nil {
		state := machine.Snapshot()
		status.LeaderID, status.Term, status.Epoch, status.Revision = state.LeaderID, state.Term, state.Epoch, state.Revision
		status.WriteReady = status.Ready && !state.WriteFrozen
		if raftStatus, ok := consensus.(interface{ Status() nativeraft.Status }); ok {
			rs := raftStatus.Status()
			if status.NodeID == "" {
				status.NodeID = rs.NodeID
			}
			if rs.LeaderID != "" {
				status.LeaderID = rs.LeaderID
			}
			if rs.Term != 0 {
				status.Term = rs.Term
			}
			if !rs.Ready || status.Term == 0 || state.LeaderID != status.LeaderID || state.Term != status.Term {
				status.WriteReady = false
				if status.Phase == PhaseReady {
					status.Ready = false
					status.Phase = PhaseFrozen
					if status.Reason == "" {
						status.Reason = "native-raft is not ready"
					}
				}
			} else if !rs.IsLeader || state.WriteFrozen {
				status.WriteReady = false
			}
		}
	}
	return status
}

func (r *Runtime) setStatusFromState(phase Phase, ready bool, reason string, state controlplane.State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = Status{Profile: r.opts.Profile, ClusterID: r.opts.ClusterID, NodeID: r.opts.NodeID, Phase: phase, Ready: ready, WriteReady: ready && !state.WriteFrozen, Reason: safeReason(reason), LeaderID: state.LeaderID, Term: state.Term, Epoch: state.Epoch, Revision: state.Revision, UpdatedAt: time.Now().UTC()}
}

func (r *Runtime) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	server, listener, closeDeps := r.httpServer, r.listener, r.closeDeps
	r.httpServer = nil
	r.listener = nil
	r.status.Phase = PhaseClosed
	r.status.Ready = false
	r.status.WriteReady = false
	r.mu.Unlock()
	var first error
	if server != nil {
		if err := server.Shutdown(context.Background()); err != nil {
			first = err
		}
	}
	if listener != nil {
		_ = listener.Close()
	}
	if closeDeps != nil {
		if err := closeDeps(); first == nil {
			first = err
		}
	}
	return first
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func safeReason(reason string) string {
	lower := strings.ToLower(reason)
	for _, marker := range []string{"postgres://", "postgresql://", "password", "dsn=", "secret", "token="} {
		if strings.Contains(lower, marker) {
			return "backend initialization failed"
		}
	}
	if len(reason) > 512 {
		return reason[:512]
	}
	return reason
}

func scrubError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New("backend initialization failed")
}
