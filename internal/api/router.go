package api

import (
	"fmt"
	"net/http"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/ai"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	captchaassets "github.com/LaokeQwQ/CheeseWAF/internal/captcha/assets"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/realtime"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
	"github.com/go-chi/chi/v5"
)

type Options struct {
	Config              *config.Config
	ConfigPath          string
	Store               storage.Store
	Sink                storage.LogSink
	Hub                 *realtime.Hub
	Secret              string
	SetupToken          string
	OnSitesChanged      func([]config.SiteConfig) error
	OnEdgeChanged       func(config.EdgeConfig) error
	OnProtectionChanged func(config.ProtectionConfig) error
	OnAPISecChanged     func(config.APISecConfig) error
	OnBlockPageChanged  func(config.BlockPageConfig) error
	OnTimeSyncChanged   func(config.TimeSyncConfig) error
	ACMEIssuer          acme.Issuer
	AuthState           *handler.AuthState
	AssistantApprovals  *ai.ApprovalStore
	ClusterIdentity     *identity.MemoryIdentityService
	ClusterHeartbeats   *cluster.HeartbeatRegistry
	CAPTCHAAssets       captchaassets.Store
	Clock               timekeeper.Clock
	TimeSync            handler.TimeSyncService
	// IsolateConfig makes the router own a deep-cloned configuration graph.
	// The serve command enables it so background readers never alias API writes.
	IsolateConfig bool
}

var newAuditor = middleware.NewAuditorWithClock
var newRouterAssistantApprovalStore = func() *ai.ApprovalStore { return nil }

func NewRouter(opts Options) http.Handler {
	r := chi.NewRouter()
	routerConfig := opts.Config
	if opts.IsolateConfig && opts.Config != nil {
		cloned, err := config.Clone(opts.Config)
		if err != nil {
			panic(fmt.Sprintf("clone API configuration: %v", err))
		}
		routerConfig = cloned
	}
	requestConfig, err := config.Clone(routerConfig)
	if err != nil {
		panic(fmt.Sprintf("clone API request configuration: %v", err))
	}
	clock := opts.Clock
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	tokens := middleware.NewTokenManagerWithClock(opts.Secret, config.AdminSessionTTL, clock)
	auditor := newAuditor(routerConfig.APISec.Audit.Path, clock)
	var panicAuditor *middleware.Auditor
	if routerConfig.APISec.Audit.Enabled {
		panicAuditor = auditor
	}
	r.Use(middleware.Recovery(panicAuditor))
	approvals := opts.AssistantApprovals
	if approvals == nil {
		approvals = newRouterAssistantApprovalStore()
	}
	aiUseLimit := middleware.NewAIRequestLimiter(middleware.AIRequestLimitOptions{}).Middleware
	hub := opts.Hub
	if hub == nil {
		hub = realtime.NewHub()
	}
	h := handler.New(handler.Options{
		Config:              routerConfig,
		ConfigSnapshot:      requestConfig,
		ConfigPath:          opts.ConfigPath,
		Store:               opts.Store,
		Sink:                opts.Sink,
		Tokens:              tokens,
		Secret:              opts.Secret,
		SetupToken:          opts.SetupToken,
		Auditor:             auditor,
		AssistantApprovals:  approvals,
		Realtime:            hub,
		ClusterIdentity:     opts.ClusterIdentity,
		ClusterHeartbeats:   opts.ClusterHeartbeats,
		ACMEIssuer:          opts.ACMEIssuer,
		OnSitesChanged:      opts.OnSitesChanged,
		OnEdgeChanged:       opts.OnEdgeChanged,
		OnProtectionChanged: opts.OnProtectionChanged,
		OnAPISecChanged:     opts.OnAPISecChanged,
		OnBlockPageChanged:  opts.OnBlockPageChanged,
		OnTimeSyncChanged:   opts.OnTimeSyncChanged,
		CAPTCHAAssets:       opts.CAPTCHAAssets,
		Clock:               clock,
		TimeSync:            opts.TimeSync,
	})
	if opts.AuthState != nil {
		handler.ApplyAuthState(h, opts.AuthState)
	}
	require := func(permission string) func(http.Handler) http.Handler {
		return middleware.RBACProvider(h.CurrentPermissions, permission)
	}
	requireAny := func(permissions ...string) func(http.Handler) http.Handler {
		return middleware.RBACAnyProvider(h.CurrentPermissions, permissions...)
	}
	managementAuth := middleware.ManagementAPIOrSessionMiddlewareWithClock(tokens, opts.Store, h.AuthenticateManagementAPIToken, clock)

	r.With(h.ConfigReadMiddleware).Get("/health", h.Health)
	r.With(h.ConfigReadMiddleware).Get("/health/live", h.Health)
	r.With(h.ConfigReadMiddleware).Get("/health/ready", h.Health)
	r.With(h.ConfigReadMiddleware).Get("/health/cluster", h.ClusterHealth)
	if routerConfig.Monitor.Prometheus.Enabled && routerConfig.Monitor.Prometheus.Public {
		r.Get(routerConfig.Monitor.Prometheus.Path, h.Metrics)
	}
	r.Route("/api", func(r chi.Router) {
		r.With(h.ConfigReadMiddleware).Get("/auth/login-options", h.LoginOptions)
		r.Post("/auth/captcha", h.LoginCAPTCHA)
		r.Post("/auth/captcha/verify", h.VerifyLoginCAPTCHA)
		r.Post("/auth/login", h.Login)
		r.With(h.ConfigReadMiddleware).Get("/setup/status", h.SetupStatus)
		r.Post("/setup", h.Setup)
		r.Post("/setup/probe", h.SetupProbe)
		r.Get("/setup/draft", h.SetupDraftGet)
		r.Patch("/setup/draft", h.SetupDraftPatch)
		r.Post("/cluster/join", h.ClusterJoin)
		r.Post("/cluster/nodes/{id}/heartbeat", h.ClusterNodeHeartbeat)

		r.Group(func(r chi.Router) {
			r.Use(tokens.Middleware)
			r.Use(middleware.SessionMiddlewareWithClock(opts.Store, clock))
			r.Use(middleware.CSRFMiddleware)
			r.Use(h.ConfigReadMiddleware)
			r.Get("/auth/session", h.SessionInfo)
			r.Post("/auth/session/bootstrap", h.BootstrapSession)
			r.Post("/auth/refresh", h.RefreshToken)
			r.Post("/auth/logout", h.Logout)
			r.Post("/ui/errors", h.ReportUIError)
		})

		r.Group(func(r chi.Router) {
			if routerConfig.APISec.Audit.Enabled {
				r.Use(auditor.Middleware)
			}
			r.Use(managementAuth)
			r.Use(middleware.CSRFMiddleware)
			r.Use(h.ConfigReadMiddleware)
			r.With(require("read:realtime"), h.ConfigReadMiddleware).Get("/realtime/events", hub.SSEHandler)
			r.With(require("read:realtime"), h.ConfigReadMiddleware).Get("/realtime/ws", hub.WSHandler)
			r.With(require("read:monitor"), h.ConfigReadMiddleware).Get("/stats", h.Stats)
			r.With(require("read:monitor"), h.ConfigReadMiddleware).Get("/metrics", h.Metrics)
			r.With(require("read:monitor"), h.ConfigReadMiddleware).Get("/monitor", h.MonitorSummary)
			r.With(require("read:apisec"), h.ConfigReadMiddleware).Get("/apisec/endpoints", h.APIEndpoints)
			r.With(require("read:apisec")).Post("/apisec/validate", h.ValidateAPIRequest)
			r.With(require("read:audit"), h.ConfigReadMiddleware).Get("/audit", h.AuditEntries)
			r.With(require("read:monitor"), h.ConfigReadMiddleware).Get("/notifications", h.ListNotifications)
			r.With(require("write:monitor")).Patch("/notifications/{id}", h.UpdateNotification)
			r.With(require("write:monitor")).Post("/notifications/read-all", h.MarkAllNotificationsRead)
			r.With(require("write:monitor")).Delete("/notifications", h.ClearNotifications)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/version", h.Version)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/system", h.System)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/system/time-sync", h.TimeSyncStatus)
			r.With(require("write:system")).Post("/system/time-sync/reselect", h.ReselectTimeSync)
			r.With(require("write:system")).Post("/system/time-sync/sync", h.SyncTimeNow)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/system/api-tokens", h.ListManagementAPITokens)
			r.With(require("manage:api_tokens")).Post("/system/api-tokens", h.CreateManagementAPIToken)
			r.With(require("manage:api_tokens")).Delete("/system/api-tokens/{id}", h.RevokeManagementAPIToken)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/status", h.ClusterStatus)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/audit", h.ClusterAudit)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/nodes", h.ClusterListNodes)
			r.With(require("write:cluster")).Post("/cluster/deploy/ansible", h.ClusterAnsiblePackage)
			r.With(require("write:cluster")).Post("/cluster/deploy/check", h.ClusterDeployCheck)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/deploy/tasks", h.ClusterListDeployTasks)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/deploy/tasks/{id}", h.ClusterGetDeployTask)
			r.With(require("write:cluster")).Post("/cluster/deploy/tasks", h.ClusterStartDeployTask)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/join-tokens", h.ClusterListJoinTokens)
			r.With(require("write:cluster")).Post("/cluster/join-tokens", h.ClusterCreateJoinToken)
			r.With(require("write:cluster")).Delete("/cluster/join-tokens/{id}", h.ClusterRevokeJoinToken)
			r.With(require("write:cluster")).Post("/cluster/nodes/{id}/rotate-certificate", h.ClusterRotateNodeCertificate)
			r.With(require("write:cluster")).Post("/cluster/nodes/{id}/revoke", h.ClusterRevokeNode)
			r.With(require("write:cluster")).Post("/cluster/orchestrate/bootstrap", h.ClusterBootstrapPlan)
			r.With(require("write:cluster")).Post("/cluster/orchestrate/rolling-upgrade", h.ClusterStartRollingUpgrade)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/orchestrate/rolling-upgrade", h.ClusterListRollingUpgrades)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/orchestrate/rolling-upgrade/{id}", h.ClusterGetRollingUpgrade)
			r.With(require("write:cluster")).Post("/cluster/orchestrate/rolling-upgrade/{id}/rollback", h.ClusterStartRollingRollback)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/traffic/peers", h.ClusterTrafficPeers)
			r.With(require("write:cluster")).Post("/cluster/traffic/peers/report", h.ClusterTrafficPeerReport)
			r.With(require("read:cluster"), h.ConfigReadMiddleware).Get("/cluster/consensus", h.ClusterConsensusStatus)
			r.With(require("write:cluster")).Post("/cluster/consensus/config-version", h.ClusterProposeConfigVersion)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/system/map/china-boundary", h.ChinaMapBoundary)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/system/map/china-boundary/{adcode}", h.ChinaMapBoundaryByCode)
			r.With(require("write:system")).Put("/system", h.UpdateSystem)
			r.With(require("write:system")).Post("/system/storage/test", h.TestStorageBackend)
			r.With(require("read:users"), h.ConfigReadMiddleware).Get("/users", h.ListUsers)
			r.With(require("write:users")).Post("/users", h.CreateUser)
			r.With(require("write:users")).Put("/users/{id}", h.UpdateUser)
			// 2FA enrollment/enable/disable stay behind the handler account-owner
			// check (authorizeUser2FA). Do NOT add require("write:users") here or a
			// write:users operator could act on arbitrary user ids.
			r.Post("/users/{id}/2fa/setup", h.SetupUser2FA)
			r.Post("/users/{id}/2fa/enable", h.EnableUser2FA)
			r.Post("/users/{id}/2fa/disable", h.DisableUser2FA)
			r.With(require("write:config")).Post("/captcha/lab/challenges", h.IssueCaptchaLabChallenge)
			r.With(require("write:config")).Post("/captcha/lab/verify", h.VerifyCaptchaLabChallenge)
			// Recover is a security-sensitive admin operation; require write:users
			// at the route as defence-in-depth. The handler still enforces that the
			// caller is an admin session and never the account owner.
			r.With(require("write:users")).Post("/users/{id}/2fa/recover", h.RecoverUser2FA)
			r.With(require("read:logs"), h.ConfigReadMiddleware).Get("/logs", h.ListLogs)
			r.With(require("read:logs"), h.ConfigReadMiddleware).Get("/attack-map/aggregate", h.AttackMapAggregate)
			r.With(require("read:logs"), h.ConfigReadMiddleware).Get("/review", h.ListReviewItems)
			r.With(require("read:logs"), h.ConfigReadMiddleware).Get("/review/{id}", h.GetReviewItem)
			r.With(require("write:protection")).Post("/review/{id}/decide", h.DecideReviewItem)
			r.With(require("read:protection"), h.ConfigReadMiddleware).Get("/ip", h.ListIPRules)
			r.With(require("write:protection")).Put("/ip/access-rules", h.UpdateIPAccessRules)
			r.With(require("write:protection")).Put("/ip/reputation-overrides", h.UpdateIPReputationOverrides)
			r.With(require("write:protection")).Put("/ip/tags", h.UpdateIPTags)
			r.With(require("read:threat_intel"), h.ConfigReadMiddleware).Get("/ip/threat-intel/export", h.ExportThreatIntel)
			r.With(require("write:threat_intel")).Put("/ip/threat-intel/providers", h.UpdateThreatIntelProviders)
			r.With(require("write:threat_intel")).Post("/ip/threat-intel/import", h.ImportThreatIntel)
			r.With(require("write:threat_intel")).Post("/ip/threat-intel/sync", h.SyncThreatIntel)
			r.With(require("write:threat_intel")).Post("/ip/threat-intel/test", h.TestThreatIntelProvider)
			r.With(require("read:threat_intel")).Post("/ip/threat-intel/lookup", h.LookupThreatIntel)
			r.With(require("read:protection"), h.ConfigReadMiddleware).Get("/protection", h.Protection)
			r.With(require("read:protection"), h.ConfigReadMiddleware).Get("/protection/bot/metrics", h.BotChallengeMetrics)
			r.With(require("read:protection"), h.ConfigReadMiddleware).Get("/captcha/assets", h.ListCAPTCHAAssets)
			r.With(require("write:protection")).Post("/captcha/assets", h.UploadCAPTCHAAsset)
			r.With(require("write:protection")).Delete("/captcha/assets/{id}", h.DeleteCAPTCHAAsset)
			r.With(require("read:protection")).Post("/captcha/assets/{id}/preview", h.IssueCAPTCHAAssetPreview)
			r.With(require("read:protection"), h.ConfigReadMiddleware).Get("/captcha/assets/preview/{reference}", h.PreviewCAPTCHAAsset)
			r.With(require("read:protection"), h.ConfigReadMiddleware).Get("/captcha/assets/config", h.GetCAPTCHAAssetConfig)
			r.With(require("write:protection")).Put("/captcha/assets/config", h.UpdateCAPTCHAAssetConfig)
			r.With(require("write:protection")).Post("/captcha/assets/config/test", h.TestCAPTCHAAssetConfig)
			r.With(require("write:protection")).Put("/protection/policy", h.UpdateProtectionPolicy)
			r.With(require("write:protection")).Put("/protection/ip", h.UpdateIPRules)
			r.With(require("write:protection")).Put("/protection/acl", h.UpdateACLRules)
			r.With(require("write:protection")).Put("/protection/ratelimit", h.UpdateRateLimit)
			r.With(require("write:protection")).Put("/protection/bot", h.UpdateBotProtection)
			r.With(require("read:sites"), h.ConfigReadMiddleware).Get("/sites", h.ListSites)
			r.With(require("read:sites"), h.ConfigReadMiddleware).Get("/sites/{id}", h.GetSite)
			r.With(require("write:sites")).Post("/sites", h.CreateSite)
			r.With(require("write:sites")).Put("/sites/{id}", h.UpdateSite)
			r.With(require("write:sites")).Delete("/sites/{id}", h.DeleteSite)
			r.With(require("read:sites"), h.ConfigReadMiddleware).Get("/acme/providers", h.ACMEDNSProviders)
			r.With(require("write:sites")).Post("/sites/{id}/acme/issue", h.IssueSiteACME)
			r.With(require("read:rules"), h.ConfigReadMiddleware).Get("/rules", h.ListRules)
			r.With(require("write:rules")).Post("/rules", h.CreateRule)
			r.With(require("write:rules")).Put("/rules/{id}", h.UpdateRule)
			r.With(require("write:rules")).Delete("/rules/{id}", h.DeleteRule)
			r.With(require("read:ops"), h.ConfigReadMiddleware).Get("/scheduler/tasks", h.ListTasks)
			r.With(require("write:ops")).Put("/scheduler/tasks", h.UpdateTasks)
			r.With(require("read:ops"), h.ConfigReadMiddleware).Get("/scheduler/history", h.TaskHistory)
			r.With(require("read:edge"), h.ConfigReadMiddleware).Get("/edge", h.EdgePolicy)
			r.With(require("write:edge")).Put("/edge", h.UpdateEdgePolicy)
			r.With(require("read:ai"), h.ConfigReadMiddleware).Get("/ai/config", h.AIConfig)
			r.With(require("write:ai")).Put("/ai/config", h.UpdateAIConfig)
			r.With(require("read:ai"), h.ConfigReadMiddleware).Get("/ai/models", h.AIModels)
			r.With(require("write:ai"), aiUseLimit).Post("/ai/models", h.AIModels)
			r.With(require("write:ai"), aiUseLimit).Post("/ai/test", h.TestAIConnection)
			r.With(require("use:ai"), aiUseLimit).Post("/ai/analyze", h.AnalyzeLog)
			r.With(require("use:ai"), aiUseLimit).Post("/ai/analyze/stream", h.AnalyzeLogStream)
			r.With(require("use:ai"), aiUseLimit).Post("/ai/events/analyze", h.AnalyzeEvents)
			r.With(require("use:ai"), aiUseLimit).Post("/ai/events/analyze/stream", h.AnalyzeEventsStream)
			r.With(require("write:ai"), aiUseLimit).Post("/ai/self-learning/run", h.RunAISelfLearning)
			r.With(require("write:ai"), aiUseLimit).Post("/ai/assistant", h.AIAssistant)
			r.With(require("write:ai"), aiUseLimit).Post("/ai/assistant/stream", h.AIAssistantStream)
			r.With(require("read:ai"), h.ConfigReadMiddleware).Get("/ai/tools", h.AITools)
			r.With(require("use:ai"), aiUseLimit).Post("/ai/tools/execute", h.ExecuteAITool)
			r.With(requireAny("read:ai", "use:ai", "write:ai", "approve:ai"), h.ConfigReadMiddleware).Get("/ai/tools/approvals", h.ListAIApprovals)
			r.With(requireAny("read:ai", "use:ai", "write:ai", "approve:ai"), h.ConfigReadMiddleware).Get("/ai/tools/approvals/{id}", h.GetAIApproval)
			r.With(requireAny("use:ai", "write:ai", "approve:ai")).Post("/ai/tools/approvals/{id}/approve", h.ApproveAIApproval)
			r.With(require("use:ai"), aiUseLimit).Post("/ai/tools/approvals/{id}/continue/stream", h.ContinueAIApprovalStream)
			r.With(requireAny("use:ai", "write:ai", "approve:ai")).Post("/ai/tools/approvals/{id}/reject", h.RejectAIApproval)
			r.With(require("read:storage"), h.ConfigReadMiddleware).Get("/storage", h.StorageStats)
			r.With(require("write:storage")).Post("/storage/cleanup", h.CleanupStorage)
			r.With(require("write:system")).Post("/system/reclaim", h.ReclaimSystemResources)
			r.With(require("read:system")).Post("/backup/export", h.ExportBackup)
			r.With(require("write:system")).Post("/backup/restore", h.RestoreBackup)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/block-pages/templates", h.BlockPageTemplates)
			r.With(require("read:system"), h.ConfigReadMiddleware).Get("/block-pages/config", h.BlockPageConfig)
			r.With(require("read:system")).Post("/block-pages/preview", h.PreviewBlockPageConfig)
			r.With(require("write:system")).Put("/block-pages/config", h.UpdateBlockPageConfig)
			r.With(require("write:system")).Post("/block-pages/upload", h.UploadBlockPageHTML)
			r.With(require("write:system")).Delete("/block-pages/custom", h.DeleteCustomBlockPage)
			r.With(require("write:sites")).Post("/nginx/import", h.ImportNginx)
		})
	})
	return r
}
