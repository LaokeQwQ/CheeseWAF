package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func (s *Server) TLSServer(altSvc string) (*http.Server, error) {
	if s.config.Server.ListenTLS == "" {
		return nil, nil
	}
	if s.certs == nil || !s.certs.HasCertificate() {
		return nil, fmt.Errorf("tls.cert_file and tls.key_file are required when server.listen_tls is set")
	}
	tlsConfig := s.certs.TLSConfig(s.config.TLS)
	handler := s.Handler()
	if altSvc != "" {
		handler = withAltSvc(handler, altSvc)
	}
	return &http.Server{
		Addr:              s.config.Server.ListenTLS,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: s.config.Server.ReadTimeout,
		ReadTimeout:       s.config.Server.ReadTimeout,
		WriteTimeout:      s.config.Server.WriteTimeout,
		IdleTimeout:       s.config.Server.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes(s.config),
	}, nil
}

func (s *Server) HTTP3Server() (*http3.Server, string, error) {
	if !s.config.Server.HTTP3.Enabled {
		return nil, "", nil
	}
	if s.certs == nil || !s.certs.HasCertificate() {
		return nil, "", fmt.Errorf("tls.cert_file and tls.key_file are required when HTTP/3 is enabled")
	}
	tlsConfig := s.certs.TLSConfig(s.config.TLS)
	addr := HTTP3ListenAddr(s.config.Server)
	altSvc, err := HTTP3AltSvcValue(addr)
	if err != nil {
		return nil, "", err
	}
	return &http3.Server{
		Addr:      addr,
		Handler:   s.Handler(),
		TLSConfig: http3.ConfigureTLSConfig(tlsConfig),
		QUICConfig: &quic.Config{
			Allow0RTT:      s.config.Server.HTTP3.ZeroRTT,
			MaxIdleTimeout: s.config.Server.IdleTimeout,
		},
		IdleTimeout:    s.config.Server.IdleTimeout,
		MaxHeaderBytes: maxHeaderBytes(s.config),
	}, altSvc, nil
}

func HTTP3ListenAddr(cfg config.ServerConfig) string {
	if cfg.ListenHTTP3 != "" {
		return cfg.ListenHTTP3
	}
	if cfg.ListenTLS != "" {
		return cfg.ListenTLS
	}
	return ":443"
}

func HTTP3AltSvcValue(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid HTTP/3 listen address %q: %w", addr, err)
	}
	portNum, err := net.LookupPort("udp", port)
	if err != nil {
		return "", fmt.Errorf("invalid HTTP/3 port %q: %w", port, err)
	}
	return fmt.Sprintf(`h3=":%d"; ma=2592000`, portNum), nil
}

func ListenAndServeHTTP3(ctx context.Context, srv *http3.Server) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func withAltSvc(next http.Handler, value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", value)
		next.ServeHTTP(w, r)
	})
}

func maxHeaderBytes(cfg *config.Config) int {
	maxHeaderBytes := 0
	for _, site := range cfg.Sites {
		if site.WAF.Performance.MaxHeaderBytes > maxHeaderBytes {
			maxHeaderBytes = site.WAF.Performance.MaxHeaderBytes
		}
	}
	if maxHeaderBytes <= 0 {
		return 1 << 20
	}
	return maxHeaderBytes
}
