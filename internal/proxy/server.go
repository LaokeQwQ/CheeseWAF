package proxy

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/blockpage"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/protection/ip"
	"github.com/LaokeQwQ/CheeseWAF/internal/storage"
)

type Server struct {
	config    *config.Config
	pipeline  *engine.Pipeline
	logSink   storage.LogSink
	renderer  *blockpage.Renderer
	lb        *LoadBalancer
	blacklist *ip.Blacklist
	whitelist *ip.Whitelist
}

func NewServer(cfg *config.Config, pipeline *engine.Pipeline, sink storage.LogSink) (*Server, error) {
	blacklist, err := ip.NewBlacklist(cfg.Protection.IP.Blacklist)
	if err != nil {
		return nil, err
	}
	whitelist, err := ip.NewWhitelist(cfg.Protection.IP.Whitelist)
	if err != nil {
		return nil, err
	}
	return &Server{
		config:    cfg,
		pipeline:  pipeline,
		logSink:   sink,
		renderer:  blockpage.NewRenderer(),
		lb:        NewLoadBalancer(cfg.Sites),
		blacklist: blacklist,
		whitelist: whitelist,
	}, nil
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(http.HandlerFunc(s.handle))
}

func (s *Server) HTTPServer() *http.Server {
	return &http.Server{
		Addr:         s.config.Server.Listen,
		Handler:      s.Handler(),
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	site := s.lb.SiteForHost(r.Host)
	reqCtx, err := engine.NewRequestContext(r, site.ID)
	if err != nil {
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	start := time.Now()
	if s.blacklist.Blocked(reqCtx.ClientIP) && !s.whitelist.Allowed(reqCtx.ClientIP) {
		s.block(w, reqCtx, "ip", "IP is blocked", http.StatusForbidden, start)
		return
	}
	if site.WAF.Enabled && site.WAF.Mode != "off" && s.pipeline != nil {
		result, err := s.pipeline.Detect(r.Context(), reqCtx)
		if err != nil {
			http.Error(w, "waf pipeline error", http.StatusInternalServerError)
			return
		}
		if result != nil && result.Detected && result.Action == engine.ActionBlock {
			s.block(w, reqCtx, result.Category, result.Message, http.StatusForbidden, start)
			return
		}
	}
	target, err := s.lb.Next(site, reqCtx.ClientIP)
	if err != nil {
		http.Error(w, "no upstream", http.StatusBadGateway)
		return
	}
	NewReverseProxy(target, site.WAF.Performance.ProxyTimeout).ServeHTTP(w, r)
	s.writeLog(r.Context(), reqCtx, "pass", http.StatusOK, start, nil)
}

func (s *Server) block(w http.ResponseWriter, reqCtx *engine.RequestContext, category, message string, status int, start time.Time) {
	s.renderer.Render(w, status, blockpage.Data{
		TraceID:    reqCtx.TraceID,
		AttackType: category,
		ClientIP:   reqCtx.ClientIP,
		Message:    message,
		Timestamp:  time.Now().UTC(),
	})
	s.writeLog(reqCtx.Request.Context(), reqCtx, "block", status, start, &storage.LogEntry{
		Category: category,
		Message:  message,
	})
}

func (s *Server) writeLog(ctx context.Context, reqCtx *engine.RequestContext, action string, status int, start time.Time, extra *storage.LogEntry) {
	if s.logSink == nil || reqCtx == nil || reqCtx.Request == nil {
		return
	}
	entry := &storage.LogEntry{
		ID:         reqCtx.TraceID,
		Timestamp:  time.Now().UTC(),
		TraceID:    reqCtx.TraceID,
		SiteID:     reqCtx.SiteID,
		ClientIP:   reqCtx.ClientIP,
		Method:     reqCtx.Request.Method,
		URI:        reqCtx.Request.URL.RequestURI(),
		StatusCode: status,
		Action:     action,
		UserAgent:  reqCtx.Request.UserAgent(),
		Latency:    time.Since(start),
	}
	if extra != nil {
		entry.Category = extra.Category
		entry.Message = extra.Message
	}
	_ = s.logSink.Write(ctx, entry)
}

func ListenAndServe(ctx context.Context, srv *http.Server) error {
	errCh := make(chan error, 1)
	go func() {
		if srv.TLSConfig != nil {
			errCh <- srv.ListenAndServeTLS("", "")
			return
		}
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
