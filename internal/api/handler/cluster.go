package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/dto"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
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

func (h *Handler) ClusterStartDeployTask(w http.ResponseWriter, r *http.Request) {
	var req deploy.SSHDeploymentRequest
	if !decode(w, r, &req) {
		return
	}
	task, err := h.clusterDeployTaskManager().Start(context.Background(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_DEPLOY_TASK_INVALID", err.Error())
		return
	}
	writeData(w, task)
}

func (h *Handler) ClusterGetDeployTask(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_DEPLOY_TASK_INVALID", "deploy task id is required")
		return
	}
	task, ok := h.clusterDeployTaskManager().Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "CLUSTER_DEPLOY_TASK_NOT_FOUND", "deploy task not found")
		return
	}
	writeData(w, task)
}

func (h *Handler) ClusterListDeployTasks(w http.ResponseWriter, _ *http.Request) {
	items := h.clusterDeployTaskManager().List(50)
	writeData(w, map[string]any{"items": items, "total": len(items)})
}

type clusterAuditEntry struct {
	ID         string    `json:"id"`
	Source     string    `json:"source"`
	EventType  string    `json:"event_type"`
	Action     string    `json:"action,omitempty"`
	Status     string    `json:"status,omitempty"`
	StatusCode int       `json:"status_code,omitempty"`
	Actor      string    `json:"actor,omitempty"`
	Role       string    `json:"role,omitempty"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	RemoteIP   string    `json:"remote_ip,omitempty"`
	Target     string    `json:"target,omitempty"`
	Message    string    `json:"message,omitempty"`
	TaskID     string    `json:"task_id,omitempty"`
	NodeID     string    `json:"node_id,omitempty"`
	LatencyMS  int64     `json:"latency_ms,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

func (h *Handler) ClusterAudit(w http.ResponseWriter, _ *http.Request) {
	items, err := h.clusterAuditEntries(250)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CLUSTER_AUDIT_ERROR", err.Error())
		return
	}
	writeData(w, map[string]any{"items": items, "total": len(items)})
}

func (h *Handler) clusterAuditEntries(limit int) ([]clusterAuditEntry, error) {
	if limit <= 0 {
		limit = 250
	}
	entries := make([]clusterAuditEntry, 0, limit)
	if h != nil && h.Auditor != nil {
		auditEntries, err := h.Auditor.Query(limit * 4)
		if err != nil {
			return nil, err
		}
		for _, entry := range auditEntries {
			item, ok := clusterAuditFromHTTP(entry)
			if ok {
				entries = append(entries, item)
			}
		}
	}
	if h != nil && h.ClusterDeployTasks != nil {
		for _, task := range h.clusterDeployTaskManager().List(50) {
			entries = append(entries, clusterAuditFromTask(task)...)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].Timestamp.After(entries[j].Timestamp)
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func clusterAuditFromHTTP(entry middleware.AuditEntry) (clusterAuditEntry, bool) {
	path := strings.TrimSpace(entry.Path)
	if path == "/api/cluster/audit" {
		return clusterAuditEntry{}, false
	}
	if !strings.HasPrefix(path, "/api/cluster/") {
		return clusterAuditEntry{}, false
	}
	action := clusterAuditPathAction(entry.Method, path)
	source := "management_api"
	eventType := "management_api"
	if action == "join_cluster" {
		source = "cluster_join"
		eventType = "cluster_join"
	}
	item := clusterAuditEntry{
		ID:         clusterAuditID("http", entry.Timestamp, entry.Method, path, entry.Subject),
		Source:     source,
		EventType:  eventType,
		Action:     action,
		Status:     clusterAuditHTTPStatus(entry.Status),
		StatusCode: entry.Status,
		Actor:      firstNonEmpty(entry.User, entry.Subject, "unknown"),
		Role:       entry.Role,
		Method:     entry.Method,
		Path:       path,
		RemoteIP:   entry.RemoteIP,
		Target:     firstNonEmpty(entry.Target, clusterAuditTargetFromPath(path)),
		Message:    entry.Message,
		LatencyMS:  entry.LatencyMS,
		Timestamp:  entry.Timestamp,
	}
	return item, true
}

func clusterAuditFromTask(task deploy.Task) []clusterAuditEntry {
	items := make([]clusterAuditEntry, 0, len(task.Events)+1)
	target := strings.TrimSpace(task.Host)
	if target == "" {
		target = task.ID
	}
	if len(task.Events) == 0 {
		at := task.UpdatedAt
		if at.IsZero() {
			at = task.StartedAt
		}
		items = append(items, clusterAuditEntry{
			ID:        clusterAuditID("task", at, task.ID, task.Stage, ""),
			Source:    "deploy_task",
			EventType: "deploy_task",
			Action:    task.Action,
			Status:    task.Status,
			Actor:     "system",
			Target:    target,
			Message:   firstNonEmpty(task.Message, task.Error, task.Stage),
			TaskID:    task.ID,
			Timestamp: at,
		})
		return items
	}
	for index, event := range task.Events {
		at := event.Timestamp
		if at.IsZero() {
			at = task.UpdatedAt
		}
		message := strings.TrimSpace(event.Message)
		if message == "" {
			message = event.Stage
		}
		items = append(items, clusterAuditEntry{
			ID:        clusterAuditID("task", at, task.ID, event.Event, fmt.Sprint(index)),
			Source:    "deploy_task",
			EventType: "deploy_task",
			Action:    firstNonEmpty(event.Event, task.Action),
			Status:    firstNonEmpty(event.Status, task.Status),
			Actor:     "system",
			Target:    target,
			Message:   message,
			TaskID:    task.ID,
			Timestamp: at,
		})
	}
	return items
}

func clusterAuditPathAction(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	path = strings.TrimSpace(path)
	switch {
	case method == http.MethodGet && strings.HasSuffix(path, "/cluster/status"):
		return "view_status"
	case method == http.MethodGet && strings.HasSuffix(path, "/cluster/nodes"):
		return "list_nodes"
	case method == http.MethodPost && strings.Contains(path, "/cluster/deploy/ansible"):
		return "generate_ansible_package"
	case method == http.MethodPost && strings.Contains(path, "/cluster/deploy/check"):
		return "ssh_precheck"
	case method == http.MethodPost && strings.Contains(path, "/cluster/deploy/run"):
		return "ssh_run"
	case method == http.MethodPost && strings.Contains(path, "/cluster/deploy/tasks"):
		return "start_deploy_task"
	case method == http.MethodGet && strings.Contains(path, "/cluster/deploy/tasks"):
		return "view_deploy_task"
	case method == http.MethodPost && strings.Contains(path, "/cluster/join-tokens"):
		return "create_join_token"
	case method == http.MethodDelete && strings.Contains(path, "/cluster/join-tokens"):
		return "revoke_join_token"
	case method == http.MethodPost && strings.Contains(path, "/rotate-certificate"):
		return "rotate_node_certificate"
	case method == http.MethodPost && strings.Contains(path, "/revoke"):
		return "revoke_node"
	case method == http.MethodPost && strings.HasSuffix(path, "/cluster/join"):
		return "join_cluster"
	default:
		return strings.ToLower(method) + "_cluster"
	}
}

func clusterAuditTargetFromPath(path string) string {
	path = strings.TrimSpace(path)
	parts := strings.Split(path, "/")
	for index, part := range parts {
		if part == "join-tokens" && index+1 < len(parts) {
			return "join-token:" + parts[index+1]
		}
		if part == "nodes" && index+1 < len(parts) {
			return "node:" + parts[index+1]
		}
		if part == "tasks" && index+1 < len(parts) {
			return "task:" + parts[index+1]
		}
	}
	switch {
	case strings.Contains(path, "/deploy/"):
		return "deployment"
	case strings.Contains(path, "/join-tokens"):
		return "join-token"
	case strings.Contains(path, "/nodes"):
		return "node"
	default:
		return "cluster"
	}
}

func clusterAuditHTTPStatus(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "succeeded"
	case status >= 400:
		return "failed"
	default:
		return "unknown"
	}
}

func (h *Handler) recordClusterJoinAudit(r *http.Request, req clusterJoinRequest, status int, message string, latency time.Duration) {
	if h == nil || h.Auditor == nil {
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	target := "cluster"
	if nodeID != "" {
		target = "node:" + nodeID
	}
	if strings.TrimSpace(message) == "" {
		message = "join request processed"
	}
	_ = h.Auditor.Write(context.Background(), middleware.AuditEntry{
		Timestamp: time.Now().UTC(),
		Subject:   nodeID,
		User:      "join-token",
		Role:      strings.TrimSpace(req.Role),
		Method:    http.MethodPost,
		Path:      "/api/cluster/join",
		Status:    status,
		RemoteIP:  remoteIPFromRequest(r),
		LatencyMS: latency.Milliseconds(),
		Target:    target,
		Message:   strings.TrimSpace(message),
	})
}

func clusterAuditID(parts ...any) string {
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		switch value := part.(type) {
		case time.Time:
			values = append(values, value.UTC().Format(time.RFC3339Nano))
		default:
			values = append(values, strings.TrimSpace(fmt.Sprint(value)))
		}
	}
	return strings.Join(values, ":")
}

func remoteIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return host
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
	started := time.Now()
	var req clusterJoinRequest
	auditStatus := http.StatusBadRequest
	auditMessage := "invalid join request"
	defer func() {
		h.recordClusterJoinAudit(r, req, auditStatus, auditMessage, time.Since(started))
	}()
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
		auditMessage = "join token is required"
		writeError(w, http.StatusBadRequest, "CLUSTER_JOIN_INVALID", "join token is required")
		return
	}
	if req.CSR == "" {
		auditMessage = "node csr is required"
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
		auditStatus = http.StatusServiceUnavailable
		auditMessage = "cluster identity is unavailable"
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	if err := svc.ValidateJoinToken(req.Token, req.Role); err != nil {
		auditStatus = http.StatusUnauthorized
		auditMessage = "invalid join token or join request"
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
		auditMessage = "join request failed local config validation"
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
		auditStatus = http.StatusUnauthorized
		auditMessage = "invalid join token or join request"
		writeClusterJoinRejected(w)
		return
	}
	if err := h.recordJoinedClusterNode(enrollment.Node); err != nil {
		if rollbackErr := enrollment.Rollback(); rollbackErr != nil {
			err = fmt.Errorf("%w; enrollment rollback failed: %v", err, rollbackErr)
		}
		auditStatus = http.StatusInternalServerError
		auditMessage = "joined node could not be persisted"
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
	auditStatus = http.StatusOK
	auditMessage = "node enrolled"
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

type clusterRotateNodeCertificateRequest struct {
	CSR string `json:"csr"`
}

type clusterRotateNodeCertificateResponse struct {
	Certificates clusterJoinCertificates   `json:"certificates"`
	Node         identity.NodeRegistration `json:"node"`
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

func (h *Handler) ClusterRotateNodeCertificate(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_NODE_CERTIFICATE_INVALID", "node id is required")
		return
	}
	var req clusterRotateNodeCertificateRequest
	if !decode(w, r, &req) {
		return
	}
	req.CSR = strings.TrimSpace(req.CSR)
	if req.CSR == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_NODE_CERTIFICATE_INVALID", "node csr is required")
		return
	}
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	rotation, err := svc.RotateNodeCertificateWithCSR(id, []byte(req.CSR))
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_NODE_CERTIFICATE_INVALID", err.Error())
		return
	}
	writeData(w, clusterRotateNodeCertificateResponse{
		Certificates: clusterJoinCertificates{
			CA:   string(rotation.Bundle.CAPEM),
			Cert: string(rotation.Bundle.CertPEM),
		},
		Node: rotation.Node,
	})
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

func (h *Handler) clusterDeployTaskManager() *deploy.TaskManager {
	h.clusterDeployTasksMu.Lock()
	defer h.clusterDeployTasksMu.Unlock()
	if h.ClusterDeployTasks == nil {
		h.ClusterDeployTasks = deploy.NewTaskManager(deploy.TaskManagerOptions{})
	}
	return h.ClusterDeployTasks
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
