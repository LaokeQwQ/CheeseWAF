package handler

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
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
	writeData(w, cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), requestLanguage(r)))
}

func (h *Handler) ClusterHealth(w http.ResponseWriter, r *http.Request) {
	status := cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), requestLanguage(r))
	code := http.StatusOK
	if status.Enabled && !status.CanReceiveTraffic {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(dto.Response{Data: status})
}

type clusterHeartbeatRequest struct {
	Role              string `json:"role"`
	AdvertiseAddr     string `json:"advertise_addr"`
	ConfigVersion     string `json:"config_version"`
	CanReceiveTraffic *bool  `json:"can_receive_traffic"`
	CanWriteConfig    *bool  `json:"can_write_config"`
}

func (h *Handler) ClusterNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(chi.URLParam(r, "id"))
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, "CLUSTER_HEARTBEAT_INVALID", "node id is required")
		return
	}
	if !h.clusterNodeConfigured(nodeID) {
		writeError(w, http.StatusNotFound, "CLUSTER_NODE_NOT_FOUND", "cluster node is not configured")
		return
	}
	svc, err := h.clusterIdentityService()
	if err == nil && svc.IsRevoked(nodeID) {
		writeError(w, http.StatusForbidden, "CLUSTER_NODE_REVOKED", "cluster node is revoked")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	if ok, code, message := h.authorizeClusterHeartbeatCertificate(r, svc, nodeID); !ok {
		writeError(w, code, "CLUSTER_NODE_CERT_INVALID", message)
		return
	}
	var req clusterHeartbeatRequest
	if r.Body != nil && !decodeOptional(w, r, &req, defaultJSONBodyLimit, "invalid heartbeat request") {
		return
	}
	heartbeat := cluster.Heartbeat{
		NodeID:        nodeID,
		Role:          req.Role,
		AdvertiseAddr: req.AdvertiseAddr,
		ConfigVersion: req.ConfigVersion,
	}
	if heartbeat.Role == "" || heartbeat.AdvertiseAddr == "" {
		if node, ok := h.clusterNodeConfig(nodeID); ok {
			if heartbeat.Role == "" {
				heartbeat.Role = node.Role
			}
			if heartbeat.AdvertiseAddr == "" {
				heartbeat.AdvertiseAddr = node.AdvertiseAddr
			}
		}
	}
	if req.CanReceiveTraffic != nil {
		heartbeat.CanReceiveTraffic = *req.CanReceiveTraffic
		heartbeat.CanReceiveTrafficSet = true
	}
	if req.CanWriteConfig != nil {
		heartbeat.CanWriteConfig = *req.CanWriteConfig
		heartbeat.CanWriteConfigSet = true
	}
	record, err := h.clusterHeartbeatRegistry().Record(heartbeat)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_HEARTBEAT_INVALID", err.Error())
		return
	}
	writeData(w, map[string]any{
		"ok":        true,
		"heartbeat": record,
		"status":    cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), requestLanguage(r)),
	})
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

type clusterDeployRequest struct {
	deploy.SSHDeploymentRequest
	Authorization string `json:"authorization,omitempty"`
}

type clusterDeployTaskView struct {
	deploy.Task
	Authorization *deploy.Authorization `json:"authorization,omitempty"`
}

func (h *Handler) ClusterDeployCheck(w http.ResponseWriter, r *http.Request) {
	var req clusterDeployRequest
	if !decode(w, r, &req) {
		return
	}
	result, err := deploy.NewSSHRunner(deploy.SSHRunnerOptions{}).Check(r.Context(), req.SSHDeploymentRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_SSH_INVALID", err.Error())
		return
	}
	auth, err := h.clusterDeployAuthorizationStore().Issue("", authorizationTarget(req.SSHDeploymentRequest))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CLUSTER_SSH_AUTHORIZATION_FAILED", err.Error())
		return
	}
	writeData(w, map[string]any{"result": result, "authorization": auth})
}

func (h *Handler) ClusterDeployRun(w http.ResponseWriter, r *http.Request) {
	var req clusterDeployRequest
	if !decode(w, r, &req) {
		return
	}
	if err := h.consumeClusterDeployAuthorization(req); err != nil {
		writeError(w, http.StatusForbidden, "CLUSTER_SSH_PRECHECK_REQUIRED", err.Error())
		return
	}
	result, err := deploy.NewSSHRunner(deploy.SSHRunnerOptions{}).Deploy(r.Context(), req.SSHDeploymentRequest)
	if err != nil {
		writeError(w, http.StatusBadGateway, "CLUSTER_SSH_FAILED", err.Error())
		return
	}
	writeData(w, result)
}

func (h *Handler) ClusterStartDeployTask(w http.ResponseWriter, r *http.Request) {
	var req clusterDeployRequest
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Action) != "check" {
		if err := h.consumeClusterDeployAuthorization(req); err != nil {
			writeError(w, http.StatusForbidden, "CLUSTER_SSH_PRECHECK_REQUIRED", err.Error())
			return
		}
	}
	task, err := h.clusterDeployTaskManager().Start(context.Background(), req.SSHDeploymentRequest)
	if err != nil {
		writeError(w, http.StatusBadRequest, "CLUSTER_DEPLOY_TASK_INVALID", err.Error())
		return
	}
	if task.Action == "check" {
		h.clusterDeployAuthMu.Lock()
		h.clusterDeployPending[task.ID] = authorizationTarget(req.SSHDeploymentRequest)
		h.clusterDeployAuthMu.Unlock()
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
	view := clusterDeployTaskView{Task: task}
	if task.Action == "check" && task.Status == deploy.TaskStatusSucceeded {
		if auth, ok := h.clusterDeployAuthorizationStore().GetByTask(id); ok {
			view.Authorization = &auth
			writeData(w, view)
			return
		}
		h.clusterDeployAuthMu.Lock()
		target, ok := h.clusterDeployPending[id]
		h.clusterDeployAuthMu.Unlock()
		if ok {
			auth, err := h.clusterDeployAuthorizationStore().Issue(id, target)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "CLUSTER_SSH_AUTHORIZATION_FAILED", err.Error())
				return
			}
			h.clusterDeployAuthMu.Lock()
			delete(h.clusterDeployPending, id)
			h.clusterDeployAuthMu.Unlock()
			view.Authorization = &auth
		}
	}
	writeData(w, view)
}

func (h *Handler) ClusterListDeployTasks(w http.ResponseWriter, r *http.Request) {
	page := clusterPositiveQueryInt(r, "page", 1, 1000000)
	pageSize := clusterPositiveQueryInt(r, "page_size", 50, 100)
	items, total := h.clusterDeployTaskManager().ListPage((page-1)*pageSize, pageSize)
	writeData(w, map[string]any{"items": items, "total": total, "page": page, "page_size": pageSize})
}

func authorizationTarget(req deploy.SSHDeploymentRequest) deploy.AuthorizationTarget {
	return deploy.AuthorizationTarget{Host: req.Host, User: req.User, Port: req.Port, HostKeySHA256: req.HostKeySHA256}
}
func (h *Handler) consumeClusterDeployAuthorization(req clusterDeployRequest) error {
	return h.clusterDeployAuthorizationStore().Consume(req.Authorization, authorizationTarget(req.SSHDeploymentRequest))
}
func (h *Handler) clusterDeployAuthorizationStore() *deploy.AuthorizationStore {
	h.clusterDeployAuthMu.Lock()
	defer h.clusterDeployAuthMu.Unlock()
	if h.ClusterDeployAuth == nil {
		h.ClusterDeployAuth = deploy.NewAuthorizationStore(deploy.AuthorizationStoreOptions{})
	}
	if h.clusterDeployPending == nil {
		h.clusterDeployPending = map[string]deploy.AuthorizationTarget{}
	}
	return h.ClusterDeployAuth
}
func clusterPositiveQueryInt(r *http.Request, name string, fallback, maximum int) int {
	if r == nil {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get(name)))
	if err != nil || value <= 0 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
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

func (h *Handler) authorizeClusterHeartbeatCertificate(r *http.Request, svc *identity.MemoryIdentityService, nodeID string) (bool, int, string) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return false, http.StatusUnauthorized, "node heartbeat requires a verified mTLS client certificate"
	}
	if len(r.TLS.VerifiedChains) == 0 {
		return false, http.StatusUnauthorized, "node client certificate was not verified by the cluster CA"
	}
	cert := r.TLS.PeerCertificates[0]
	if cert == nil {
		return false, http.StatusUnauthorized, "node client certificate is empty"
	}
	registration, ok := clusterRegistrationByID(svc, nodeID)
	if !ok {
		return false, http.StatusForbidden, "cluster node is not enrolled"
	}
	if registration.Revoked {
		return false, http.StatusForbidden, "cluster node is revoked"
	}
	now := h.nowUTC()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false, http.StatusForbidden, "node client certificate is expired or not yet valid"
	}
	if strings.TrimSpace(registration.CertificateSerial) == "" || cert.SerialNumber == nil || cert.SerialNumber.String() != registration.CertificateSerial {
		return false, http.StatusForbidden, "node client certificate serial does not match the enrolled node"
	}
	if !clusterCertificateIdentifiesNode(cert, registration) {
		return false, http.StatusForbidden, "node client certificate identity does not match the heartbeat node"
	}
	return true, http.StatusOK, ""
}

func clusterRegistrationByID(svc *identity.MemoryIdentityService, nodeID string) (identity.NodeRegistration, bool) {
	if svc == nil {
		return identity.NodeRegistration{}, false
	}
	for _, node := range svc.ListNodes() {
		if node.NodeID == nodeID {
			return node, true
		}
	}
	return identity.NodeRegistration{}, false
}

func clusterCertificateIdentifiesNode(cert *x509.Certificate, node identity.NodeRegistration) bool {
	if cert == nil {
		return false
	}
	expectedCN := strings.TrimSpace(node.ClusterID) + "/" + strings.TrimSpace(node.Role) + "/" + strings.TrimSpace(node.NodeID)
	if cert.Subject.CommonName != expectedCN {
		return false
	}
	hasNodeDNSName := false
	for _, name := range cert.DNSNames {
		if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(node.NodeID)) {
			hasNodeDNSName = true
			break
		}
	}
	return hasNodeDNSName
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
		Timestamp: h.nowUTC(),
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

type clusterNodeView struct {
	identity.NodeRegistration
	Runtime cluster.RuntimeNodeStatus `json:"runtime"`
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

func (h *Handler) clusterNodeViews(registrations []identity.NodeRegistration, lang string) []clusterNodeView {
	runtimeNodes := cluster.RuntimeNodes(h.Config, h.clusterHeartbeatRegistry(), lang)
	runtimeByID := make(map[string]cluster.RuntimeNodeStatus, len(runtimeNodes))
	for _, node := range runtimeNodes {
		runtimeByID[node.NodeID] = node
	}
	registrationByID := make(map[string]identity.NodeRegistration, len(registrations))
	for _, node := range registrations {
		registrationByID[node.NodeID] = node
	}
	for _, node := range runtimeNodes {
		if _, ok := registrationByID[node.NodeID]; ok {
			continue
		}
		registrationByID[node.NodeID] = identity.NodeRegistration{
			NodeID:        node.NodeID,
			Role:          node.Role,
			ClusterID:     clusterIDFromConfig(h.Config),
			AdvertiseAddr: node.AdvertiseAddr,
		}
	}
	ids := make([]string, 0, len(registrationByID))
	for id := range registrationByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]clusterNodeView, 0, len(ids))
	for _, id := range ids {
		view := clusterNodeView{NodeRegistration: registrationByID[id]}
		if runtimeNode, ok := runtimeByID[id]; ok {
			view.Runtime = runtimeNode
		}
		out = append(out, view)
	}
	return out
}

func (h *Handler) ClusterListNodes(w http.ResponseWriter, r *http.Request) {
	svc, err := h.clusterIdentityService()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "CLUSTER_IDENTITY_UNAVAILABLE", err.Error())
		return
	}
	nodes := svc.ListNodes()
	items := h.clusterNodeViews(nodes, requestLanguage(r))
	writeData(w, map[string]any{"items": items, "total": len(items)})
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
	// Preserve process-wide pointer identity: other subsystems hold *h.Config.
	previous, err := config.Clone(h.Config)
	if err != nil {
		return err
	}
	*h.Config = *next
	if err := h.persistConfigLocked(); err != nil {
		*h.Config = *previous
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
	// Full clone so validation/join never mutates the live config graph
	// (shallow struct copy + append can write into the live Nodes backing array).
	cloned, err := config.Clone(h.Config)
	if err != nil {
		return nil, err
	}
	next := cloned
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
	next.Cluster.Nodes = append(append([]config.ClusterNodeConfig(nil), next.Cluster.Nodes...), config.ClusterNodeConfig{
		ID:            node.NodeID,
		Role:          node.Role,
		AdvertiseAddr: node.AdvertiseAddr,
	})
	if err := config.Validate(next); err != nil {
		return nil, err
	}
	return next, nil
}

type clusterIdentityClock func() time.Time

func (clock clusterIdentityClock) Now() time.Time {
	return clock()
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
	svc, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: clusterID, StatePath: statePath, Clock: clusterIdentityClock(h.nowUTC)})
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

func (h *Handler) clusterHeartbeatRegistry() *cluster.HeartbeatRegistry {
	h.clusterHeartbeatsMu.Lock()
	defer h.clusterHeartbeatsMu.Unlock()
	if h.ClusterHeartbeats == nil {
		h.ClusterHeartbeats = cluster.NewHeartbeatRegistry(cluster.HeartbeatRegistryOptions{})
	}
	return h.ClusterHeartbeats
}

func (h *Handler) clusterNodeConfigured(nodeID string) bool {
	_, ok := h.clusterNodeConfig(nodeID)
	return ok
}

func (h *Handler) clusterNodeConfig(nodeID string) (config.ClusterNodeConfig, bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || h == nil || h.Config == nil {
		return config.ClusterNodeConfig{}, false
	}
	for _, node := range h.Config.Cluster.Nodes {
		if strings.TrimSpace(node.ID) == nodeID {
			return node, true
		}
	}
	if strings.TrimSpace(h.Config.Cluster.NodeID) == nodeID {
		return config.ClusterNodeConfig{
			ID:            nodeID,
			Role:          "waf",
			AdvertiseAddr: h.Config.Cluster.Interconnect.AdvertiseAddr,
		}, true
	}
	return config.ClusterNodeConfig{}, false
}

func (h *Handler) defaultJoinTokenTTL() time.Duration {
	if h != nil && h.Config != nil && h.Config.Cluster.Join.TokenTTL > 0 {
		return h.Config.Cluster.Join.TokenTTL
	}
	return 15 * time.Minute
}

func clusterIDFromConfig(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.Cluster.ClusterID) != "" {
		return strings.TrimSpace(cfg.Cluster.ClusterID)
	}
	return "cheesewaf-local"
}

func (h *Handler) clusterConfigWritable(lang string) (bool, string) {
	if h == nil || h.Config == nil {
		return true, ""
	}
	status := cluster.FromConfigWithRuntime(h.Config, h.clusterHeartbeatRegistry(), lang)
	if !status.Enabled || status.CanWriteConfig {
		return true, ""
	}
	reason := status.ProtectionModeReason
	if strings.TrimSpace(reason) == "" {
		reason = clusterProtectionModeFallback(lang)
	}
	return false, reason
}

func (h *Handler) rejectClusterConfigWriteIfFrozen(w http.ResponseWriter, r *http.Request) bool {
	h.configMutationMu.RLock()
	frozen, freezeReason := h.configWriteFrozen, h.configFreezeReason
	h.configMutationMu.RUnlock()
	if frozen {
		if strings.TrimSpace(freezeReason) == "" {
			freezeReason = "configuration state could not be restored"
		}
		writeError(w, http.StatusLocked, "CONFIG_WRITES_FROZEN", freezeReason)
		return true
	}
	ok, reason := h.clusterConfigWritable(requestLanguage(r))
	if ok {
		return false
	}
	writeError(w, http.StatusLocked, "CLUSTER_PROTECTION_MODE", reason)
	return true
}

func clusterProtectionModeFallback(lang string) string {
	if strings.HasPrefix(lang, "zh") {
		return "集群处于保护模式，暂不允许配置变更"
	}
	return "Cluster is in protection mode and configuration writes are paused"
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
