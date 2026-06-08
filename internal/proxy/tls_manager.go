package proxy

import (
	"crypto/tls"
	"fmt"

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
