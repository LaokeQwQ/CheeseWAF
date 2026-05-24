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
	Config *config.Config
	Store  storage.Store
	Sink   storage.LogSink
	Hub    *realtime.Hub
	Secret string
}

func NewRouter(opts Options) http.Handler {
	r := chi.NewRouter()
	tokens := middleware.NewTokenManager(opts.Secret, 24*time.Hour)
	h := handler.New(opts.Config, opts.Store, opts.Sink, tokens)
	hub := opts.Hub
	if hub == nil {
		hub = realtime.NewHub()
	}

	r.Get("/health", h.Health)
	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/login", h.Login)
		r.Post("/setup", h.Setup)
		r.Get("/realtime/events", hub.SSEHandler)
		r.Get("/realtime/ws", hub.WSHandler)

		r.Group(func(r chi.Router) {
			r.Use(tokens.Middleware)
			r.Get("/stats", h.Stats)
			r.Get("/system", h.System)
			r.Get("/users", h.ListUsers)
			r.Get("/logs", h.ListLogs)
			r.Get("/ip", h.ListIPRules)
			r.Get("/sites", h.ListSites)
			r.Post("/sites", h.CreateSite)
			r.Put("/sites/{id}", h.UpdateSite)
			r.Delete("/sites/{id}", h.DeleteSite)
			r.Get("/rules", h.ListRules)
			r.Post("/rules", h.CreateRule)
			r.Put("/rules/{id}", h.UpdateRule)
			r.Delete("/rules/{id}", h.DeleteRule)
		})
	})
	return r
}
