package api

import (
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/api/handler"
	"github.com/LaokeQwQ/CheeseWAF/internal/api/middleware"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/realtime"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
	"github.com/go-chi/chi/v5"
)

type Options struct {
	Config         *config.Config
	ConfigPath     string
	Store          storage.Store
	Sink           storage.LogSink
	Hub            *realtime.Hub
	Secret         string
	OnSitesChanged func([]config.SiteConfig)
}

func NewRouter(opts Options) http.Handler {
	r := chi.NewRouter()
	tokens := middleware.NewTokenManager(opts.Secret, 24*time.Hour)
	auditor := middleware.NewAuditor(opts.Config.APISec.Audit.Path)
	h := handler.New(handler.Options{
		Config:         opts.Config,
		ConfigPath:     opts.ConfigPath,
		Store:          opts.Store,
		Sink:           opts.Sink,
		Tokens:         tokens,
		Auditor:        auditor,
		OnSitesChanged: opts.OnSitesChanged,
	})
	hub := opts.Hub
	if hub == nil {
		hub = realtime.NewHub()
	}

	r.Get("/health", h.Health)
	if opts.Config.Monitor.Prometheus.Enabled {
		r.Get(opts.Config.Monitor.Prometheus.Path, h.Metrics)
	}
	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", h.Login)
		r.Post("/setup", h.Setup)
		r.Get("/realtime/events", hub.SSEHandler)
		r.Get("/realtime/ws", hub.WSHandler)

		r.Group(func(r chi.Router) {
			r.Use(tokens.Middleware)
			if opts.Config.APISec.Audit.Enabled {
				r.Use(auditor.Middleware)
			}
			r.Get("/stats", h.Stats)
			r.Get("/metrics", h.Metrics)
			r.Get("/monitor", h.MonitorSummary)
			r.Get("/apisec/endpoints", h.APIEndpoints)
			r.Post("/apisec/validate", h.ValidateAPIRequest)
			r.Get("/audit", h.AuditEntries)
			r.Get("/system", h.System)
			r.Put("/system", h.UpdateSystem)
			r.Post("/system/storage/test", h.TestStorageBackend)
			r.Get("/users", h.ListUsers)
			r.Post("/users", h.CreateUser)
			r.Put("/users/{id}", h.UpdateUser)
			r.Post("/users/{id}/2fa/setup", h.SetupUser2FA)
			r.Post("/users/{id}/2fa/enable", h.EnableUser2FA)
			r.Post("/users/{id}/2fa/disable", h.DisableUser2FA)
			r.Get("/logs", h.ListLogs)
			r.Get("/ip", h.ListIPRules)
			r.Put("/ip/tags", h.UpdateIPTags)
			r.Get("/ip/threat-intel/export", h.ExportThreatIntel)
			r.Put("/ip/threat-intel/providers", h.UpdateThreatIntelProviders)
			r.Post("/ip/threat-intel/import", h.ImportThreatIntel)
			r.Post("/ip/threat-intel/sync", h.SyncThreatIntel)
			r.Post("/ip/threat-intel/test", h.TestThreatIntelProvider)
			r.Post("/ip/threat-intel/lookup", h.LookupThreatIntel)
			r.Get("/protection", h.Protection)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:protection")).Put("/protection/ip", h.UpdateIPRules)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:protection")).Put("/protection/acl", h.UpdateACLRules)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:protection")).Put("/protection/ratelimit", h.UpdateRateLimit)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:protection")).Put("/protection/bot", h.UpdateBotProtection)
			r.Get("/sites", h.ListSites)
			r.Get("/sites/{id}", h.GetSite)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:sites")).Post("/sites", h.CreateSite)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:sites")).Put("/sites/{id}", h.UpdateSite)
			r.With(middleware.RBAC(opts.Config.APISec.Permissions, "write:sites")).Delete("/sites/{id}", h.DeleteSite)
			r.Get("/rules", h.ListRules)
			r.Post("/rules", h.CreateRule)
			r.Put("/rules/{id}", h.UpdateRule)
			r.Delete("/rules/{id}", h.DeleteRule)
			r.Get("/scheduler/tasks", h.ListTasks)
			r.Put("/scheduler/tasks", h.UpdateTasks)
			r.Get("/scheduler/history", h.TaskHistory)
			r.Get("/edge", h.EdgePolicy)
			r.Put("/edge", h.UpdateEdgePolicy)
			r.Get("/ai/config", h.AIConfig)
			r.Put("/ai/config", h.UpdateAIConfig)
			r.Post("/ai/test", h.TestAIConnection)
			r.Post("/ai/analyze", h.AnalyzeLog)
			r.Get("/storage", h.StorageStats)
			r.Post("/storage/cleanup", h.CleanupStorage)
			r.Post("/backup/export", h.ExportBackup)
			r.Post("/backup/restore", h.RestoreBackup)
			r.Get("/block-pages/templates", h.BlockPageTemplates)
			r.Post("/nginx/import", h.ImportNginx)
		})
	})
	return r
}
