package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/deploy"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
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

type clusterJoinRequest struct {
	Token         string `json:"token"`
	NodeID        string `json:"node_id"`
	Role          string `json:"role"`
	AdvertiseAddr string `json:"advertise_addr"`
	Listen        string `json:"listen"`
	CSR           string `json:"csr"`
}

type clusterJoinResponse struct {
	ClusterID     string                      `json:"cluster_id"`
	NodeID        string                      `json:"node_id"`
	Role          string                      `json:"role"`
	AdvertiseAddr string                      `json:"advertise_addr"`
	Listen        string                      `json:"listen"`
	Interconnect  configInterconnectBootstrap `json:"interconnect"`
	Certificates  clusterJoinCertificates     `json:"certificates"`
	Node          identity.NodeRegistration   `json:"node"`
}

type configInterconnectBootstrap struct {
	Listen        string `json:"listen"`
	AdvertiseAddr string `json:"advertise_addr"`
	MTLSRequired  bool   `json:"mtls_required"`
	CAFile        string `json:"ca_file,omitempty"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
}

type clusterJoinCertificates struct {
	CA   string `json:"ca"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (h *Handler) ClusterJoin(w http.ResponseWriter, r *http.Request) {
	var req clusterJoinRequest
	if !decode(w, r, &req) {
		return
	}
	req.Token = strings.TrimSpace(req.Token)
	req.NodeID = strings.TrimSpace(req.NodeID)
	req.Role = strings.TrimSpace(req.Role)
	req.AdvertiseAddr = strings.TrimSpace(req.AdvertiseAddr)
	req.Listen = strings.TrimSpace(req.Listen)
	req.CSR = strings.TrimSpace(req.CSR)
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_INVALID", "join token is required")
		return
	}
	if req.CSR == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_INVALID", "node csr is required")
		return
	}
	if req.Listen == "" {
		req.Listen = req.AdvertiseAddr
	}
	clusterID := "cheesewaf-local"
	if h.Config != nil && strings.TrimSpace(h.Config.Cluster.ClusterID) != "" {
		clusterID = h.Config.Cluster.ClusterID
	}
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	if err := svc.ValidateJoinToken(req.Token, req.Role); err != nil {
		writeClusterJoinRejected(w)
		return
	}
	pendingNode := identity.NodeRegistration{
		NodeID:        req.NodeID,
		Role:          req.Role,
		ClusterID:     clusterID,
		AdvertiseAddr: req.AdvertiseAddr,
	}
	if err := h.validateJoinedClusterNodeConfig(pendingNode); err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_INVALID", err.Error())
		return
	}
	enrollment, err := svc.EnrollNodeWithCSR(req.Token, identity.NodeIdentity{
		NodeID:        req.NodeID,
		Role:          req.Role,
		ClusterID:     clusterID,
		AdvertiseAddr: req.AdvertiseAddr,
	}, []byte(req.CSR))
	if err != nil {
		writeClusterJoinRejected(w)
		return
	}
	if err := h.recordJoinedClusterNode(enrollment.Node); err != nil {
		if rollbackErr := enrollment.Rollback(); rollbackErr != nil {
			err = fmt.Errorf("%w; enrollment rollback failed: %v", err, rollbackErr)
		}
		writeError(w, http.StatusInternalServerError, "CLUSTER_JOIN_CONFIG_SAVE_FAILED", err.Error())
		return
	}
	resp := clusterJoinResponse{
		ClusterID:     clusterID,
		NodeID:        enrollment.Node.NodeID,
		Role:          enrollment.Node.Role,
		AdvertiseAddr: enrollment.Node.AdvertiseAddr,
		Listen:        req.Listen,
		Interconnect: configInterconnectBootstrap{
			Listen:        req.Listen,
			AdvertiseAddr: enrollment.Node.AdvertiseAddr,
			MTLSRequired:  true,
		},
		Certificates: clusterJoinCertificates{
			CA:   string(enrollment.Bundle.CAPEM),
			Cert: string(enrollment.Bundle.CertPEM),
		},
		Node: enrollment.Node,
	}
	writeData(w, resp)
}

func writeClusterJoinRejected(w http.ResponseWriter) {
	writeError(w, http.StatusUnauthorized, "CLUSTER_JOIN_REJECTED", "invalid join token or join request")
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

func (h *Handler) ClusterListNodes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	nodes := svc.ListNodes()
	writeData(w, map[string]any{"items": nodes, "total": len(nodes)})
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

func (h *Handler) recordJoinedClusterNode(node identity.NodeRegistration) error {
	if h == nil || h.Config == nil {
		return nil
	}
	h.configMutationMu.Lock()
	defer h.configMutationMu.Unlock()
	next, err := h.joinedClusterNodeConfig(node)
	if err != nil {
		return err
	}
	previous := h.Config
	h.Config = next
	if err := h.persistConfigLocked(); err != nil {
		h.Config = previous
		return err
	}
	return nil
}

func (h *Handler) validateJoinedClusterNodeConfig(node identity.NodeRegistration) error {
	if h == nil || h.Config == nil {
		return nil
	}
	_, err := h.joinedClusterNodeConfig(node)
	return err
}

func (h *Handler) joinedClusterNodeConfig(node identity.NodeRegistration) (*config.Config, error) {
	if h == nil || h.Config == nil {
		return nil, nil
	}
	next := *h.Config
	next.Deployment.Mode = "cluster"
	next.Cluster.Enabled = true
	if strings.TrimSpace(next.Cluster.ClusterID) == "" {
		next.Cluster.ClusterID = node.ClusterID
	}
	if strings.TrimSpace(next.Cluster.HAMode) == "" {
		next.Cluster.HAMode = "single-node"
	}
	next.Cluster.Interconnect.MTLSRequired = true
	for idx := range next.Cluster.Nodes {
		if next.Cluster.Nodes[idx].ID != node.NodeID {
			continue
		}
		return nil, fmt.Errorf("cluster node %q already exists; revoke or rotate it before rejoining", node.NodeID)
	}
	next.Cluster.Nodes = append(next.Cluster.Nodes, config.ClusterNodeConfig{
		ID:            node.NodeID,
		Role:          node.Role,
		AdvertiseAddr: node.AdvertiseAddr,
	})
	if err := config.Validate(&next); err != nil {
		return nil, err
	}
	return &next, nil
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
