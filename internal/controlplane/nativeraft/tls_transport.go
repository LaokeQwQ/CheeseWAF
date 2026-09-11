package nativeraft

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// TLSOptions contains the node certificate and CA used by native-raft. The
// certificate SAN must contain the configured NodeID. Every peer connection
// uses mutual TLS; plaintext is available only through InsecureTestMode.
type TLSOptions struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// TLSConfig is the public spelling used by transport callers.
type TLSConfig = TLSOptions

// TransportTLSConfig is kept as a descriptive alias for callers that build
// transport options outside the native-raft package.
type TransportTLSConfig = TLSOptions

type peerBindings struct {
	mu     sync.RWMutex
	byAddr map[string]string
}

func newPeerBindings() *peerBindings {
	return &peerBindings{byAddr: make(map[string]string)}
}

func (p *peerBindings) bind(address, nodeID string) {
	if p == nil || address == "" || nodeID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byAddr[address] = nodeID
}

func (p *peerBindings) lookup(address string) string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if nodeID := p.byAddr[address]; nodeID != "" {
		return nodeID
	}
	return ""
}

type raftStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
	tlsConfig *tls.Config
	bindings  *peerBindings
}

func newPlainStreamLayer(bindAddr string) (*raftStreamLayer, error) {
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	return &raftStreamLayer{listener: listener, advertise: listener.Addr()}, nil
}

func newTLSStreamLayer(bindAddr string, tlsConfig *tls.Config, bindings *peerBindings) (*raftStreamLayer, error) {
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	return &raftStreamLayer{listener: tls.NewListener(listener, tlsConfig), advertise: listener.Addr(), tlsConfig: tlsConfig, bindings: bindings}, nil
}

func (s *raftStreamLayer) Accept() (net.Conn, error) {
	conn, err := s.listener.Accept()
	if err != nil || s.tlsConfig == nil {
		return conn, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("native-raft TLS listener returned unexpected connection type")
	}
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("native-raft TLS handshake: %w", err)
	}
	if expected := s.bindings.lookup(conn.RemoteAddr().String()); expected != "" {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 || !certificateIdentifiesNode(state.PeerCertificates[0], expected) {
			_ = conn.Close()
			return nil, fmt.Errorf("native-raft peer certificate is not bound to node %q", expected)
		}
	}
	return tlsConn, nil
}

func (s *raftStreamLayer) Close() error   { return s.listener.Close() }
func (s *raftStreamLayer) Addr() net.Addr { return s.advertise }

func (s *raftStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", string(address), timeout)
	if err != nil || s.tlsConfig == nil {
		return raw, err
	}
	expected := s.bindings.lookup(string(address))
	host, _, splitErr := net.SplitHostPort(string(address))
	if splitErr != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("native-raft peer address is invalid: %w", splitErr)
	}
	config := s.tlsConfig.Clone()
	config.ServerName = expected
	if config.ServerName == "" {
		config.ServerName = host
	}
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		return verifyPeerCertificate(rawCerts, config.RootCAs, expected)
	}
	tlsConn := tls.Client(raw, config)
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("native-raft TLS handshake with %s: %w", host, err)
	}
	return tlsConn, nil
}

func loadTLSConfig(options *TLSOptions, nodeID string) (*tls.Config, error) {
	if options == nil {
		return nil, fmt.Errorf("native-raft TLS configuration is required")
	}
	if strings.TrimSpace(options.CAFile) == "" || strings.TrimSpace(options.CertFile) == "" || strings.TrimSpace(options.KeyFile) == "" {
		return nil, fmt.Errorf("native-raft CA, certificate and key files must be configured together")
	}
	if err := validateTLSMaterialFile(options.CAFile, 0o644); err != nil {
		return nil, fmt.Errorf("validate native-raft CA file: %w", err)
	}
	if err := validateTLSMaterialFile(options.CertFile, 0o644); err != nil {
		return nil, fmt.Errorf("validate native-raft certificate file: %w", err)
	}
	if err := validateTLSMaterialFile(options.KeyFile, 0o600); err != nil {
		return nil, fmt.Errorf("validate native-raft private key file: %w", err)
	}
	certificate, err := tls.LoadX509KeyPair(options.CertFile, options.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load native-raft certificate: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, fmt.Errorf("native-raft certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse native-raft certificate: %w", err)
	}
	if !certificateIdentifiesNode(leaf, nodeID) {
		return nil, fmt.Errorf("native-raft certificate SAN is not bound to node id %q", nodeID)
	}
	caPEM, err := os.ReadFile(options.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read native-raft CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("native-raft CA contains no certificates")
	}
	return &tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificate(rawCerts, roots, "")
		},
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

func validateTLSMaterialFile(path string, wantPerm os.FileMode) error {
	if wantPerm == 0o600 {
		return checkSecureRegularFile(path, 0o600)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("secure TLS material %q is not a regular file", path)
	}
	if err := checkOwned(path, info); err != nil {
		return err
	}
	if info.Mode().Perm() != 0o600 && info.Mode().Perm() != wantPerm {
		return fmt.Errorf("secure TLS material %q has mode %04o; want 0600 or %04o", path, info.Mode().Perm(), wantPerm)
	}
	return nil
}

func verifyPeerCertificate(rawCerts [][]byte, roots *x509.CertPool, expectedNodeID string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("peer certificate is missing")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		cert, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return fmt.Errorf("parse peer intermediate certificate: %w", parseErr)
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify peer certificate chain: %w", err)
	}
	if expectedNodeID != "" && !certificateIdentifiesNode(leaf, expectedNodeID) {
		return fmt.Errorf("peer certificate is not bound to node id %q", expectedNodeID)
	}
	if expectedNodeID == "" && len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return fmt.Errorf("peer certificate has no node identity SAN")
	}
	return nil
}

func certificateIdentifiesNode(cert *x509.Certificate, nodeID string) bool {
	if cert == nil || nodeID == "" {
		return false
	}
	for _, name := range cert.DNSNames {
		if name == nodeID {
			return true
		}
	}
	if ip := net.ParseIP(nodeID); ip != nil {
		for _, candidate := range cert.IPAddresses {
			if candidate.Equal(ip) {
				return true
			}
		}
	}
	return false
}

func parseCertificatePEM(raw []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}
