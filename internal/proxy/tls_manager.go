package proxy

import (
	"crypto/tls"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	minVersion := uint16(tls.VersionTLS13)
	if cfg.MinVersion == "1.2" {
		minVersion = tls.VersionTLS12
	}
	return &tls.Config{
		MinVersion: minVersion,
	}, nil
}

func HasCertificate(cfg config.TLSConfig) bool {
	return cfg.CertFile != "" && cfg.KeyFile != ""
}
