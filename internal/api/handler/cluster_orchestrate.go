package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/consensus"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/deploy"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/orchestrate"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/traffic"
	"github.com/go-chi/chi/v5"
)

// compile-time interface checks
var _ orchestrate.DeployStarter = (*handlerDeployStarter)(nil)

type clusterBootstrapRequest struct {
	orchestrate.BootstrapRequest
}

type clusterRollingUpgradeHTTPRequest struct {
	orchestrate.RollingUpgradeRequest
	// Authorization is required once when all targets share a pre-check handle;
	// otherwise each target must carry credentials for a fresh check is not enforced
	// for orchestrated multi-host upgrades started from an admin session.
	Authorization string `json:"authorization,omitempty"`
}

func (h *Handler) clusterRollingManager() *orchestrate.RollingManager {
	h.clusterDeployTasksMu.Lock()
	defer h.clusterDeployTasksMu.Unlock()
	if h.clusterRolling == nil {
		h.clusterRolling = orchestrate.NewRollingManager(h.clusterDeployStarter(), nil, h.nowUTC)
	}
	return h.clusterRolling
}

func (h *Handler) clusterDeployStarter() orchestrate.DeployStarter {
	return &handlerDeployStarter{h: h}
}

type handlerDeployStarter struct {
	h *Handler
}

func (s *handlerDeployStarter) StartInstall(ctx context.Context, target orchestrate.RollingTarget) (string, error) {
	return s.start(ctx, target, "install")
}

func (s *handlerDeployStarter) StartRollbackInstall(ctx context.Context, target orchestrate.RollingTarget) (string, error) {
	return s.start(ctx, target, "rollback-install")
}

func (s *handlerDeployStarter) StartRestart(ctx context.Context, target orchestrate.RollingTarget) (string, error) {
	return s.start(ctx, target, "restart-service")
}

func (s *handlerDeployStarter) start(_ context.Context, target orchestrate.RollingTarget, action string) (string, error) {
	if s == nil || s.h == nil {
		return "", fmt.Errorf("handler unavailable")
	}
	req := deploy.SSHDeploymentRequest{
		Host:          target.Host,
		User:          target.User,
		Port:          target.Port,
		Password:      target.Password,
		PrivateKey:    target.PrivateKey,
		HostKeySHA256: target.HostKeySHA256,
		Action:        action,
	}
	task, err := s.h.clusterDeployTaskManager().Start(context.Background(), req)
	if err != nil {
		return "", err
	}
	return task.ID, nil
}

func (s *handlerDeployStarter) WaitTask(ctx context.Context, taskID string) (bool, string, error) {
	if s == nil || s.h == nil {
		return false, "", fmt.Errorf("handler unavailable")
	}
	deadline := time.Now().Add(15 * time.Minute)
	for {
		if ctx.Err() != nil {
			return false, "", ctx.Err()
		}
		task, ok := s.h.clusterDeployTaskManager().Get(taskID)
		if !ok {
			return false, "deploy task not found", fmt.Errorf("deploy task not found")
		}
		switch task.Status {
		case deploy.TaskStatusSucceeded:
			return true, task.Message, nil
		case deploy.TaskStatusFailed, deploy.TaskStatusCancelled:
			msg := task.Error
			if msg == "" {
				msg = task.Message
			}
			if msg == "" {
				msg = task.Status
			}
			return false, msg, nil
		}
		if time.Now().After(deadline) {
			return false, "deploy task wait timed out", fmt.Errorf("deploy task wait timed out")
		}
		select {
		case <-ctx.Done():
			return false, "", ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ClusterBootstrapPlan mints a join token and returns install/join operator steps (M2 close-out).
func (h *Handler) ClusterBootstrapPlan(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req clusterBootstrapRequest
	if !decode(w, r, &req) {
		return
	}
	ttl := h.defaultJoinTokenTTL()
	if strings.TrimSpace(req.TokenTTL) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(req.TokenTTL))
		if err != nil {
			writeError(w, http.StatusBadRequest, "CLUSTER_BOOTSTRAP_INVALID", "token_ttl must be a duration such as 15m")
			return
		}
		ttl = parsed
	}
	maxUses := req.TokenMaxUses
	if maxUses == 0 {
		maxUses = 1
	}
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	token, err := svc.CreateJoinToken(req.Role, ttl, maxUses)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_BOOTSTRAP_INVALID", err.Error())
		return
	}
	plan, err := orchestrate.BuildBootstrapPlan(req.BootstrapRequest, token.ID, token.Value, token.ExpiresAt)
	if err != nil {
		_ = svc.RevokeJoinToken(token.ID)
		writeError(w, http.StatusBadRequest, "CLUSTER_BOOTSTRAP_INVALID", err.Error())
		return
	}
	writeData(w, plan)
}

// ClusterStartRollingUpgrade starts sequential multi-node binary upgrades (M2 close-out).
func (h *Handler) ClusterStartRollingUpgrade(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req clusterRollingUpgradeHTTPRequest
	if !decode(w, r, &req) {
		return
	}
	job, err := h.clusterRollingManager().Start(r.Context(), req.RollingUpgradeRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_ROLLING_INVALID", err.Error())
		return
	}
	// Never echo SSH secrets in the response.
	sanitized := *job
	writeData(w, sanitized)
}

func (h *Handler) ClusterGetRollingUpgrade(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	job, err := h.clusterRollingManager().Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "CLUSTER_ROLLING_NOT_FOUND", err.Error())
		return
	}
	writeData(w, job)
}

func (h *Handler) ClusterListRollingUpgrades(w http.ResponseWriter, r *http.Request) {
	items := h.clusterRollingManager().List()
	writeData(w, map[string]any{"items": items, "total": len(items)})
}

// ClusterTrafficPeers returns mesh peers eligible for M4 traffic scheduling.
func (h *Handler) ClusterTrafficPeers(w http.ResponseWriter, r *http.Request) {
	nodes := cluster.RuntimeNodes(h.Config, h.clusterHeartbeatRegistry(), requestLanguage(r))
	peers := traffic.EligiblePeers(nodes)
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))
	if mode == "" {
		mode = traffic.ModeRoundRobin
	}
	clientIP := remoteIPFromRequest(r)
	prefer := strings.TrimSpace(r.URL.Query().Get("region"))
	stickyKey := strings.TrimSpace(r.URL.Query().Get("sticky_key"))
	if stickyKey == "" {
		stickyKey = strings.TrimSpace(r.URL.Query().Get("session"))
	}
	selected, ok := h.clusterTrafficScheduler().PickAdvanced(mode, peers, clientIP, prefer, stickyKey)
	healthy := h.clusterTrafficScheduler().FilterHealthy(peers)
	writeData(w, map[string]any{
		"mode":     mode,
		"peers":    peers,
		"healthy":  healthy,
		"selected": selected,
		"ok":       ok,
		"status":   cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), requestLanguage(r)),
	})
}

type clusterTrafficReportRequest struct {
	NodeID string `json:"node_id"`
	Report string `json:"report"` // failure | success
}

// ClusterTrafficPeerReport records circuit success/failure for a peer (write path).
func (h *Handler) ClusterTrafficPeerReport(w http.ResponseWriter, r *http.Request) {
	var req clusterTrafficReportRequest
	if !decode(w, r, &req) {
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_TRAFFIC_INVALID", "node_id is required")
		return
	}
	sched := h.clusterTrafficScheduler()
	switch strings.TrimSpace(strings.ToLower(req.Report)) {
	case "failure", "fail":
		sched.ReportFailure(nodeID)
	case "success", "ok":
		sched.ReportSuccess(nodeID)
	default:
		writeError(w, http.StatusBadRequest, "CLUSTER_TRAFFIC_INVALID", "report must be failure or success")
		return
	}
	writeData(w, map[string]any{"ok": true, "node_id": nodeID, "report": strings.TrimSpace(strings.ToLower(req.Report))})
}

// ClusterConsensusStatus returns the built-in coordinator view (leader, role, freeze).
func (h *Handler) ClusterConsensusStatus(w http.ResponseWriter, r *http.Request) {
	lang := requestLanguage(r)
	status := cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), lang)
	nodes := cluster.RuntimeNodes(h.Config, h.clusterHeartbeatRegistry(), lang)
	snap := h.clusterConsensusCoordinator().Evaluate(status, nodes)
	writeData(w, snap)
}

type clusterConfigVersionRequest struct {
	Version string `json:"version"`
	Message string `json:"message"`
}

// ClusterProposeConfigVersion records a config version on the writable leader.
func (h *Handler) ClusterProposeConfigVersion(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	var req clusterConfigVersionRequest
	if !decode(w, r, &req) {
		return
	}
	lang := requestLanguage(r)
	status := cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), lang)
	nodes := cluster.RuntimeNodes(h.Config, h.clusterHeartbeatRegistry(), lang)
	rec, err := h.clusterConsensusCoordinator().ProposeConfigVersion(req.Version, req.Message, status, nodes)
	if err != nil {
		writeError(w, http.StatusConflict, "CLUSTER_CONSENSUS_REJECTED", err.Error())
		return
	}
	writeData(w, rec)
}

// ClusterStartRollingRollback starts reverse-order reinstall for a finished rolling job.
func (h *Handler) ClusterStartRollingRollback(w http.ResponseWriter, r *http.Request) {
	if h.rejectClusterConfigWriteIfFrozen(w, r) {
		return
	}
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	job, err := h.clusterRollingManager().StartRollback(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "CLUSTER_ROLLING_NOT_FOUND", err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, "CLUSTER_ROLLING_INVALID", err.Error())
		return
	}
	writeData(w, job)
}

func (h *Handler) clusterTrafficScheduler() *traffic.Scheduler {
	h.clusterTrafficMu.Lock()
	defer h.clusterTrafficMu.Unlock()
	if h.clusterTraffic == nil {
		h.clusterTraffic = traffic.NewScheduler()
	}
	return h.clusterTraffic
}

func (h *Handler) clusterConsensusCoordinator() *consensus.Coordinator {
	h.clusterConsensusMu.Lock()
	defer h.clusterConsensusMu.Unlock()
	if h.clusterConsensus == nil {
		provider := "builtin"
		var etcd []string
		localID := ""
		if h.Config != nil {
			provider = strings.TrimSpace(h.Config.Cluster.Consensus.Provider)
			etcd = append([]string(nil), h.Config.Cluster.Consensus.EtcdEndpoints...)
			localID = strings.TrimSpace(h.Config.Cluster.NodeID)
		}
		h.clusterConsensus = consensus.NewCoordinator(consensus.Options{
			Provider:      provider,
			LocalNodeID:   localID,
			EtcdEndpoints: etcd,
			Now:           h.nowUTC,
		})
	}
	return h.clusterConsensus
}
