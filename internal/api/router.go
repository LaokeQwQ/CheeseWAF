package api

import (
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	captchaassets "github.com/LaokeQwQ/CheeseWAF/internal/captcha/assets"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/realtime"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

type Options struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Hub                 *realtime.Hub
	Secret              string
	OnSitesChanged      func([]config.SiteConfig) error
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
	OnBlockPageChanged  func(config.BlockPageConfig) error
	ACMEIssuer          acme.Issuer
	AuthState           *handler.AuthState
	AssistantApprovals  *ai.ApprovalStore
	CAPTCHAAssets       captchaassets.Store
}

var newAuditor = middleware.NewAuditor
var newRouterAssistantApprovalStore = func() *ai.ApprovalStore { return nil }

func NewRouter(opts Options) http.Handler {
	r := chi.NewRouter()
	tokens := middleware.NewTokenManager(opts.Secret, config.AdminSessionTTL)
	auditor := newAuditor(opts.Config.APISec.Audit.Path)
	approvals := opts.AssistantApprovals
	if approvals == nil {
		approvals = newRouterAssistantApprovalStore()
	}
	require := func(permission string) func(http.Handler) http.Handler {
		return middleware.RBAC(opts.Config.APISec.Permissions, permission)
	}
	h := handler.New(handler.Options{
		Config:              opts.Config,
		ConfigPath:          opts.ConfigPath,
		Store:               opts.Store,
		Sink:                opts.Sink,
		Tokens:              tokens,
		Secret:              opts.Secret,
		Auditor:             auditor,
		AssistantApprovals:  approvals,
		ACMEIssuer:          opts.ACMEIssuer,
		OnSitesChanged:      opts.OnSitesChanged,
		OnProtectionChanged: opts.OnProtectionChanged,
		OnAPISecChanged:     opts.OnAPISecChanged,
		OnBlockPageChanged:  opts.OnBlockPageChanged,
		CAPTCHAAssets:       opts.CAPTCHAAssets,
	})
	if opts.AuthState != nil {
		handler.ApplyAuthState(h, opts.AuthState)
	}
	managementAuth := middleware.ManagementAPIOrSessionMiddleware(tokens, opts.Store, h.AuthenticateManagementAPIToken)
	hub := opts.Hub
	if hub == nil {
		hub = realtime.NewHub()
	}

	r.Get("/health", h.Health)
	r.Get("/health/live", h.Health)
	r.Get("/health/ready", h.Health)
	r.Get("/health/cluster", h.ClusterHealth)
	if opts.Config.Monitor.Prometheus.Enabled && opts.Config.Monitor.Prometheus.Public {
		r.Get(opts.Config.Monitor.Prometheus.Path, h.Metrics)
	}
	r.Route("/api", func(r chi.Router) {
		r.Get("/auth/login-options", h.LoginOptions)
		r.Post("/auth/captcha", h.LoginCAPTCHA)
		r.Post("/auth/captcha/verify", h.VerifyLoginCAPTCHA)
		r.Post("/auth/login", h.Login)
		r.Post("/setup", h.Setup)
		r.Post("/cluster/join", h.ClusterJoin)
		r.Post("/cluster/nodes/{id}/heartbeat", h.ClusterNodeHeartbeat)

		r.Group(func(r chi.Router) {
			r.Use(tokens.Middleware)
			r.Use(middleware.SessionMiddleware(opts.Store))
			r.Post("/auth/refresh", h.RefreshToken)
			r.Post("/auth/logout", h.Logout)
			r.Post("/ui/errors", h.ReportUIError)
		})

		r.Group(func(r chi.Router) {
			r.Use(managementAuth)
			if opts.Config.APISec.Audit.Enabled {
				r.Use(auditor.Middleware)
			}
			r.With(require("read:realtime")).Get("/realtime/events", hub.SSEHandler)
			r.With(require("read:realtime")).Get("/realtime/ws", hub.WSHandler)
			r.With(require("read:monitor")).Get("/stats", h.Stats)
			r.With(require("read:monitor")).Get("/metrics", h.Metrics)
			r.With(require("read:monitor")).Get("/monitor", h.MonitorSummary)
			r.With(require("read:apisec")).Get("/apisec/endpoints", h.APIEndpoints)
			r.With(require("read:apisec")).Post("/apisec/validate", h.ValidateAPIRequest)
			r.With(require("read:audit")).Get("/audit", h.AuditEntries)
			r.With(require("read:monitor")).Get("/notifications", h.ListNotifications)
			r.With(require("read:monitor")).Patch("/notifications/{id}", h.UpdateNotification)
			r.With(require("read:monitor")).Post("/notifications/read-all", h.MarkAllNotificationsRead)
			r.With(require("read:monitor")).Delete("/notifications", h.ClearNotifications)
			r.With(require("read:system")).Get("/version", h.Version)
			r.With(require("read:system")).Get("/system", h.System)
			r.With(require("read:system")).Get("/system/api-tokens", h.ListManagementAPITokens)
			r.With(require("manage:api_tokens")).Post("/system/api-tokens", h.CreateManagementAPIToken)
			r.With(require("manage:api_tokens")).Delete("/system/api-tokens/{id}", h.RevokeManagementAPIToken)
			r.With(require("read:cluster")).Get("/cluster/status", h.ClusterStatus)
			r.With(require("read:cluster")).Get("/cluster/audit", h.ClusterAudit)
			r.With(require("read:cluster")).Get("/cluster/nodes", h.ClusterListNodes)
			r.With(require("write:cluster")).Post("/cluster/deploy/ansible", h.ClusterAnsiblePackage)
			r.With(require("write:cluster")).Post("/cluster/deploy/check", h.ClusterDeployCheck)
			r.With(require("read:cluster")).Get("/cluster/deploy/tasks", h.ClusterListDeployTasks)
			r.With(require("read:cluster")).Get("/cluster/deploy/tasks/{id}", h.ClusterGetDeployTask)
			r.With(require("write:cluster")).Post("/cluster/deploy/tasks", h.ClusterStartDeployTask)
			r.With(require("read:cluster")).Get("/cluster/join-tokens", h.ClusterListJoinTokens)
			r.With(require("write:cluster")).Post("/cluster/join-tokens", h.ClusterCreateJoinToken)
			r.With(require("write:cluster")).Delete("/cluster/join-tokens/{id}", h.ClusterRevokeJoinToken)
			r.With(require("write:cluster")).Post("/cluster/nodes/{id}/rotate-certificate", h.ClusterRotateNodeCertificate)
			r.With(require("write:cluster")).Post("/cluster/nodes/{id}/revoke", h.ClusterRevokeNode)
			r.With(require("read:system")).Get("/system/map/china-boundary", h.ChinaMapBoundary)
			r.With(require("read:system")).Get("/system/map/china-boundary/{adcode}", h.ChinaMapBoundaryByCode)
			r.With(require("write:system")).Put("/system", h.UpdateSystem)
			r.With(require("write:system")).Post("/system/storage/test", h.TestStorageBackend)
			r.With(require("read:users")).Get("/users", h.ListUsers)
			r.With(require("write:users")).Post("/users", h.CreateUser)
			r.With(require("write:users")).Put("/users/{id}", h.UpdateUser)
			r.Post("/users/{id}/2fa/setup", h.SetupUser2FA)
			r.Post("/users/{id}/2fa/enable", h.EnableUser2FA)
			r.Post("/users/{id}/2fa/disable", h.DisableUser2FA)
			r.With(require("write:config")).Post("/captcha/lab/challenges", h.IssueCaptchaLabChallenge)
			r.With(require("write:config")).Post("/captcha/lab/verify", h.VerifyCaptchaLabChallenge)
			r.Post("/users/{id}/2fa/recover", h.RecoverUser2FA)
			r.With(require("read:logs")).Get("/logs", h.ListLogs)
			r.With(require("read:protection")).Get("/ip", h.ListIPRules)
			r.With(require("write:protection")).Put("/ip/access-rules", h.UpdateIPAccessRules)
			r.With(require("write:protection")).Put("/ip/reputation-overrides", h.UpdateIPReputationOverrides)
			r.With(require("write:protection")).Put("/ip/tags", h.UpdateIPTags)
			r.With(require("read:threat_intel")).Get("/ip/threat-intel/export", h.ExportThreatIntel)
			r.With(require("write:threat_intel")).Put("/ip/threat-intel/providers", h.UpdateThreatIntelProviders)
			r.With(require("write:threat_intel")).Post("/ip/threat-intel/import", h.ImportThreatIntel)
			r.With(require("write:threat_intel")).Post("/ip/threat-intel/sync", h.SyncThreatIntel)
			r.With(require("write:threat_intel")).Post("/ip/threat-intel/test", h.TestThreatIntelProvider)
			r.With(require("read:threat_intel")).Post("/ip/threat-intel/lookup", h.LookupThreatIntel)
			r.With(require("read:protection")).Get("/protection", h.Protection)
			r.With(require("read:protection")).Get("/protection/bot/metrics", h.BotChallengeMetrics)
			r.With(require("read:protection")).Get("/captcha/assets", h.ListCAPTCHAAssets)
			r.With(require("write:protection")).Post("/captcha/assets", h.UploadCAPTCHAAsset)
			r.With(require("write:protection")).Delete("/captcha/assets/{id}", h.DeleteCAPTCHAAsset)
			r.With(require("read:protection")).Post("/captcha/assets/{id}/preview", h.IssueCAPTCHAAssetPreview)
			r.With(require("read:protection")).Get("/captcha/assets/preview/{reference}", h.PreviewCAPTCHAAsset)
			r.With(require("read:protection")).Get("/captcha/assets/config", h.GetCAPTCHAAssetConfig)
			r.With(require("write:protection")).Put("/captcha/assets/config", h.UpdateCAPTCHAAssetConfig)
			r.With(require("write:protection")).Post("/captcha/assets/config/test", h.TestCAPTCHAAssetConfig)
			r.With(require("write:protection")).Put("/protection/policy", h.UpdateProtectionPolicy)
			r.With(require("write:protection")).Put("/protection/ip", h.UpdateIPRules)
			r.With(require("write:protection")).Put("/protection/acl", h.UpdateACLRules)
			r.With(require("write:protection")).Put("/protection/ratelimit", h.UpdateRateLimit)
			r.With(require("write:protection")).Put("/protection/bot", h.UpdateBotProtection)
			r.With(require("read:sites")).Get("/sites", h.ListSites)
			r.With(require("read:sites")).Get("/sites/{id}", h.GetSite)
			r.With(require("write:sites")).Post("/sites", h.CreateSite)
			r.With(require("write:sites")).Put("/sites/{id}", h.UpdateSite)
			r.With(require("write:sites")).Delete("/sites/{id}", h.DeleteSite)
			r.With(require("read:sites")).Get("/acme/providers", h.ACMEDNSProviders)
			r.With(require("write:sites")).Post("/sites/{id}/acme/issue", h.IssueSiteACME)
			r.With(require("read:rules")).Get("/rules", h.ListRules)
			r.With(require("write:rules")).Post("/rules", h.CreateRule)
			r.With(require("write:rules")).Put("/rules/{id}", h.UpdateRule)
			r.With(require("write:rules")).Delete("/rules/{id}", h.DeleteRule)
			r.With(require("read:ops")).Get("/scheduler/tasks", h.ListTasks)
			r.With(require("write:ops")).Put("/scheduler/tasks", h.UpdateTasks)
			r.With(require("read:ops")).Get("/scheduler/history", h.TaskHistory)
			r.With(require("read:edge")).Get("/edge", h.EdgePolicy)
			r.With(require("write:edge")).Put("/edge", h.UpdateEdgePolicy)
			r.With(require("read:ai")).Get("/ai/config", h.AIConfig)
			r.With(require("write:ai")).Put("/ai/config", h.UpdateAIConfig)
			r.With(require("read:ai")).Get("/ai/models", h.AIModels)
			r.With(require("write:ai")).Post("/ai/models", h.AIModels)
			r.With(require("write:ai")).Post("/ai/test", h.TestAIConnection)
			r.With(require("read:ai")).Post("/ai/analyze", h.AnalyzeLog)
			r.With(require("read:ai")).Post("/ai/analyze/stream", h.AnalyzeLogStream)
			r.With(require("read:ai")).Post("/ai/events/analyze", h.AnalyzeEvents)
			r.With(require("read:ai")).Post("/ai/events/analyze/stream", h.AnalyzeEventsStream)
			r.With(require("write:ai")).Post("/ai/self-learning/run", h.RunAISelfLearning)
			r.With(require("read:ai")).Post("/ai/assistant", h.AIAssistant)
			r.With(require("read:ai")).Post("/ai/assistant/stream", h.AIAssistantStream)
			r.With(require("read:ai")).Get("/ai/tools", h.AITools)
			r.With(require("write:ai")).Post("/ai/tools/execute", h.ExecuteAITool)
			r.With(middleware.RBACAny(opts.Config.APISec.Permissions, "read:ai", "write:ai", "approve:ai")).Get("/ai/tools/approvals", h.ListAIApprovals)
			r.With(middleware.RBACAny(opts.Config.APISec.Permissions, "read:ai", "write:ai", "approve:ai")).Get("/ai/tools/approvals/{id}", h.GetAIApproval)
			r.With(middleware.RBACAny(opts.Config.APISec.Permissions, "write:ai", "approve:ai")).Post("/ai/tools/approvals/{id}/approve", h.ApproveAIApproval)
			r.With(require("write:ai")).Post("/ai/tools/approvals/{id}/continue/stream", h.ContinueAIApprovalStream)
			r.With(middleware.RBACAny(opts.Config.APISec.Permissions, "write:ai", "approve:ai")).Post("/ai/tools/approvals/{id}/reject", h.RejectAIApproval)
			r.With(require("read:storage")).Get("/storage", h.StorageStats)
			r.With(require("write:storage")).Post("/storage/cleanup", h.CleanupStorage)
			r.With(require("write:system")).Post("/system/reclaim", h.ReclaimSystemResources)
			r.With(require("read:system")).Post("/backup/export", h.ExportBackup)
			r.With(require("write:system")).Post("/backup/restore", h.RestoreBackup)
			r.With(require("read:system")).Get("/block-pages/templates", h.BlockPageTemplates)
			r.With(require("read:system")).Get("/block-pages/config", h.BlockPageConfig)
			r.With(require("read:system")).Post("/block-pages/preview", h.PreviewBlockPageConfig)
			r.With(require("write:system")).Put("/block-pages/config", h.UpdateBlockPageConfig)
			r.With(require("write:system")).Post("/block-pages/upload", h.UploadBlockPageHTML)
			r.With(require("write:system")).Delete("/block-pages/custom", h.DeleteCustomBlockPage)
			r.With(require("write:sites")).Post("/nginx/import", h.ImportNginx)
		})
	})
	return r
}
