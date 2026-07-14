package proxy

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	minVersion := uint16(tls.VersionTLS13)
	if cfg.MinVersion == "1.2" {
		minVersion = tls.VersionTLS12
	}
	tlsConfig := &tls.Config{
		MinVersion: minVersion,
	}
	if HasCertificate(cfg) {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

func HasCertificate(cfg config.TLSConfig) bool {
	return cfg.CertFile != "" && cfg.KeyFile != ""
}

type SiteCertificateStore struct {
	mu          sync.RWMutex
	defaultCert *tls.Certificate
	byDomain    map[string]*tls.Certificate
}

func NewSiteCertificateStore(cfg *config.Config) (*SiteCertificateStore, error) {
	store := &SiteCertificateStore{byDomain: map[string]*tls.Certificate{}}
	if err := store.Update(cfg); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *SiteCertificateStore) Update(cfg *config.Config) error {
	next := map[string]*tls.Certificate{}
	var defaultCert *tls.Certificate
	if requiresDefaultTLSCertificate(cfg) && HasCertificate(cfg.TLS) {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load default tls certificate: %w", err)
		}
		defaultCert = &cert
	}
	if cfg != nil {
		for _, site := range cfg.Sites {
			if !site.Enabled || !site.EnableSSL {
				continue
			}
			cert, err := siteTLSCertificate(site)
			if err != nil {
				return fmt.Errorf("load site %q tls certificate: %w", site.Name, err)
			}
			if cert == nil {
				continue
			}
			for _, domain := range site.Domains {
				normalized := normalizeSNI(domain)
				if normalized == "" {
					continue
				}
				copyCert := *cert
				next[normalized] = &copyCert
				if strings.HasPrefix(normalized, "*.") {
					next[strings.TrimPrefix(normalized, "*.")] = &copyCert
				}
			}
			if defaultCert == nil {
				copyCert := *cert
				defaultCert = &copyCert
			}
		}
	}
	s.mu.Lock()
	s.defaultCert = defaultCert
	s.byDomain = next
	s.mu.Unlock()
	return nil
}

func requiresDefaultTLSCertificate(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if strings.TrimSpace(cfg.Server.ListenTLS) != "" {
		return true
	}
	return cfg.Server.HTTP3.Enabled && strings.TrimSpace(cfg.Server.ListenHTTP3) != ""
}

func (s *SiteCertificateStore) TLSConfig(cfg config.TLSConfig) *tls.Config {
	minVersion := uint16(tls.VersionTLS13)
	if cfg.MinVersion == "1.2" {
		minVersion = tls.VersionTLS12
	}
	return &tls.Config{
		MinVersion:     minVersion,
		GetCertificate: s.GetCertificate,
	}
}

func (s *SiteCertificateStore) HasCertificate() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.defaultCert != nil || len(s.byDomain) > 0
}

func (s *SiteCertificateStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s == nil {
		return nil, fmt.Errorf("certificate store is nil")
	}
	name := ""
	if hello != nil {
		name = normalizeSNI(hello.ServerName)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if name != "" {
		if cert := s.byDomain[name]; cert != nil {
			return cert, nil
		}
		for domain, cert := range s.byDomain {
			if strings.HasPrefix(domain, "*.") && strings.HasSuffix(name, strings.TrimPrefix(domain, "*")) {
				return cert, nil
			}
		}
	}
	if s.defaultCert != nil {
		return s.defaultCert, nil
	}
	return nil, fmt.Errorf("no certificate available")
}

func siteTLSCertificate(site config.SiteConfig) (*tls.Certificate, error) {
	if site.Certificate.Mode == "inline" {
		if site.Certificate.CertPEM == "" || site.Certificate.KeyPEM == "" {
			return nil, nil
		}
		cert, err := tls.X509KeyPair([]byte(site.Certificate.CertPEM), []byte(site.Certificate.KeyPEM))
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
	if site.CertFile == "" || site.KeyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(site.CertFile, site.KeyFile)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func normalizeSNI(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	return strings.Split(value, ":")[0]
}
