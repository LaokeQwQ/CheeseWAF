package activation

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// ServerTLSOptions describes the certificate material for a control-plane
// activation listener. The listener must use this config with an
// http.Server; ControlPlaneHandler still performs the cluster/role/SAN
// binding checks for every request.
type ServerTLSOptions struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// NewControlPlaneServerTLSConfig builds the only supported TLS configuration
// for a production CRP authorization endpoint. It requires a verified client
// certificate, TLS 1.3 or newer, and a server certificate whose chain is
// anchored by the explicit CA file. No caller can accidentally replace this
// with plaintext, a proxy, or InsecureSkipVerify through this helper.
func NewControlPlaneServerTLSConfig(opts ServerTLSOptions) (*tls.Config, error) {
	if err := validateTLSFile(opts.CAFile, false); err != nil {
		return nil, fmt.Errorf("%w: server CA: %v", ErrTransportTLS, err)
	}
	if err := validateTLSFile(opts.CertFile, false); err != nil {
		return nil, fmt.Errorf("%w: server certificate: %v", ErrTransportTLS, err)
	}
	if err := validateTLSFile(opts.KeyFile, true); err != nil {
		return nil, fmt.Errorf("%w: server private key: %v", ErrTransportTLS, err)
	}

	certificate, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("%w: server certificate is invalid", ErrTransportTLS)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("%w: parse server certificate", ErrTransportTLS)
	}
	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return nil, fmt.Errorf("%w: read server CA", ErrTransportTLS)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%w: server CA contains no certificates", ErrTransportTLS)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		intermediate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: server certificate chain", ErrTransportTLS)
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return nil, fmt.Errorf("%w: server certificate chain", ErrTransportTLS)
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}, nil
}
