package handler

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/deploy"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/go-chi/chi/v5"
)

func (h *Handler) ClusterStatus(w http.ResponseWriter, r *http.Request) {
	writeData(w, cluster.FromConfig(h.Config, requestLanguage(r)))
}

func (h *Handler) ClusterHealth(w http.ResponseWriter, r *http.Request) {
	status := cluster.FromConfig(h.Config, requestLanguage(r))
	code := http.StatusOK
	if status.Enabled && !status.CanReceiveTraffic {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(dto.Response{Data: status})
}

func (h *Handler) ClusterAnsiblePackage(w http.ResponseWriter, r *http.Request) {
	var plan deploy.Plan
	if !decode(w, r, &plan) {
		return
	}
	pkg, err := deploy.GenerateAnsiblePackage(plan)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_DEPLOY_PLAN_INVALID", err.Error())
		return
	}
	files := map[string]string{}
	for name, data := range pkg.Files() {
		files[name] = string(data)
	}
	writeData(w, map[string]any{"files": files})
}

func (h *Handler) ClusterDeployCheck(w http.ResponseWriter, r *http.Request) {
	var req deploy.SSHDeploymentRequest
	if !decode(w, r, &req) {
		return
	}
	runner := deploy.NewSSHRunner(deploy.SSHRunnerOptions{})
	result, err := runner.Check(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_SSH_INVALID", err.Error())
		return
	}
	writeData(w, result)
}

func (h *Handler) ClusterDeployRun(w http.ResponseWriter, r *http.Request) {
	var req deploy.SSHDeploymentRequest
	if !decode(w, r, &req) {
		return
	}
	runner := deploy.NewSSHRunner(deploy.SSHRunnerOptions{})
	result, err := runner.Deploy(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "CLUSTER_SSH_FAILED", err.Error())
		return
	}
	writeData(w, result)
}

type clusterJoinTokenRequest struct {
	Role    string `json:"role"`
	TTL     string `json:"ttl"`
	MaxUses int    `json:"max_uses"`
}

func (h *Handler) ClusterCreateJoinToken(w http.ResponseWriter, r *http.Request) {
	var req clusterJoinTokenRequest
	if !decode(w, r, &req) {
		return
	}
	ttl := h.defaultJoinTokenTTL()
	if strings.TrimSpace(req.TTL) != "" {
		parsed, err := time.ParseDuration(strings.TrimSpace(req.TTL))
		if err != nil {
			writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_TOKEN_INVALID", "ttl must be a duration such as 15m")
			return
		}
		ttl = parsed
	}
	maxUses := req.MaxUses
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
		writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_TOKEN_INVALID", err.Error())
		return
	}
	token.Hash = ""
	writeData(w, token)
}

func (h *Handler) ClusterListJoinTokens(w http.ResponseWriter, r *http.Request) {
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	tokens := svc.ListJoinTokens()
	items := make([]clusterJoinTokenView, 0, len(tokens))
	for _, token := range tokens {
		items = append(items, clusterJoinTokenViewFromToken(token))
	}
	writeData(w, map[string]any{"items": items, "total": len(items)})
}

func (h *Handler) ClusterRevokeJoinToken(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_TOKEN_INVALID", "join token id is required")
		return
	}
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	if err := svc.RevokeJoinToken(id); err != nil {
		writeError(w, http.StatusNotFound, "CLUSTER_JOIN_TOKEN_NOT_FOUND", err.Error())
		return
	}
	writeData(w, map[string]any{"revoked": true, "id": id})
}

type clusterRevokeNodeRequest struct {
	Reason string `json:"reason"`
}

type clusterJoinTokenView struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

func clusterJoinTokenViewFromToken(token identity.JoinToken) clusterJoinTokenView {
	return clusterJoinTokenView{
		ID:        token.ID,
		Role:      token.Role,
		ExpiresAt: token.ExpiresAt,
		MaxUses:   token.MaxUses,
		UsedCount: token.UsedCount,
		CreatedAt: token.CreatedAt,
		Revoked:   token.Revoked,
	}
}

func (h *Handler) ClusterRevokeNode(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_NODE_INVALID", "node id is required")
		return
	}
	var req clusterRevokeNodeRequest
	if r.Body != nil && !decodeOptional(w, r, &req, defaultJSONBodyLimit, "invalid revoke node request") {
		return
	}
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	if err := svc.RevokeNode(id, req.Reason); err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_NODE_INVALID", err.Error())
		return
	}
	writeData(w, map[string]any{"revoked": true, "id": id})
}

func (h *Handler) clusterIdentityService() (*identity.MemoryIdentityService, error) {
	h.clusterIdentityMu.Lock()
	defer h.clusterIdentityMu.Unlock()
	if h.ClusterIdentity != nil {
		return h.ClusterIdentity, nil
	}
	clusterID := "cheesewaf-local"
	statePath := ""
	if h.Config != nil && strings.TrimSpace(h.Config.Cluster.ClusterID) != "" {
		clusterID = h.Config.Cluster.ClusterID
	}
	if h.Config != nil && strings.TrimSpace(h.Config.Setup.DataDir) != "" {
		statePath = filepath.Join(h.Config.Setup.DataDir, "cluster", "identity.json")
	}
	svc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: clusterID, StatePath: statePath})
	if err != nil {
		return nil, err
	}
	h.ClusterIdentity = svc
	return svc, nil
}

func (h *Handler) defaultJoinTokenTTL() time.Duration {
	if h != nil && h.Config != nil && h.Config.Cluster.Join.TokenTTL > 0 {
		return h.Config.Cluster.Join.TokenTTL
	}
	return 15 * time.Minute
}

func requestLanguage(r *http.Request) string {
	if r == nil {
		return "zh-CN"
	}
	raw := r.Header.Get("Accept-Language")
	if strings.TrimSpace(raw) == "" {
		return "zh-CN"
	}
	first := strings.Split(raw, ",")[0]
	first = strings.TrimSpace(strings.Split(first, ";")[0])
	if first == "" {
		return "zh-CN"
	}
	return first
}
