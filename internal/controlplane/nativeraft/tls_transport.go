package nativeraft

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/hashicorp/raft"
)

const tlsHandshakeTimeout = 5 * time.Second

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

func (p *peerBindings) replaceVoters(voters []raft.Server) {
	if p == nil {
		return
	}
	next := make(map[string]string, len(voters))
	for _, voter := range voters {
		if voter.Suffrage == raft.Voter && voter.Address != "" && voter.ID != "" {
			next[string(voter.Address)] = string(voter.ID)
		}
	}
	p.mu.Lock()
	p.byAddr = next
	p.mu.Unlock()
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

func (p *peerBindings) authorize(nodeID, address string) bool {
	if p == nil || nodeID == "" || address == "" {
		return false
	}
	return p.lookup(address) == nodeID
}

func (p *peerBindings) identifyCertificate(cert *x509.Certificate) string {
	if p == nil || cert == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	matched := ""
	for _, nodeID := range p.byAddr {
		if certificateIdentifiesNode(cert, nodeID) {
			if matched != "" && matched != nodeID {
				return ""
			}
			matched = nodeID
		}
	}
	return matched
}

type raftStreamLayer struct {
	listener  net.Listener
	advertise net.Addr
	tlsConfig *tls.Config
	bindings  *peerBindings
	ready     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newPlainStreamLayer(bindAddr string) (*raftStreamLayer, error) {
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	return &raftStreamLayer{listener: listener, advertise: listener.Addr(), done: make(chan struct{})}, nil
}

func newTLSStreamLayer(bindAddr string, tlsConfig *tls.Config, bindings *peerBindings) (*raftStreamLayer, error) {
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	layer := &raftStreamLayer{listener: listener, advertise: listener.Addr(), tlsConfig: tlsConfig, bindings: bindings, ready: make(chan net.Conn), done: make(chan struct{})}
	go layer.acceptTLSLoop()
	return layer, nil
}

func (s *raftStreamLayer) Accept() (net.Conn, error) {
	if s.tlsConfig == nil {
		return s.listener.Accept()
	}
	select {
	case conn := <-s.ready:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-s.done:
		return nil, net.ErrClosed
	}
}

func (s *raftStreamLayer) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.listener.Close()
	})
	return nil
}
func (s *raftStreamLayer) Addr() net.Addr { return s.advertise }

func (s *raftStreamLayer) acceptTLSLoop() {
	sem := make(chan struct{}, 64)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-s.done:
			_ = conn.Close()
			return
		}
		go func(raw net.Conn) {
			defer func() { <-sem }()
			tlsConn := tls.Server(raw, s.tlsConfig)
			_ = tlsConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
			if err := tlsConn.Handshake(); err != nil {
				_ = raw.Close()
				return
			}
			_ = tlsConn.SetDeadline(time.Time{})
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				_ = tlsConn.Close()
				return
			}
			peerID := s.bindings.identifyCertificate(state.PeerCertificates[0])
			if peerID == "" {
				_ = tlsConn.Close()
				return
			}
			authorized := &rpcIdentityConn{Conn: tlsConn, reader: bufio.NewReader(tlsConn), peerID: peerID, bindings: s.bindings}
			select {
			case s.ready <- authorized:
			case <-s.done:
				_ = authorized.Close()
			}
		}(conn)
	}
}

// rpcIdentityConn re-frames each inbound request after checking the sender's
// certificate identity against the Raft RPC header. It also preserves the
// InstallSnapshot byte stream following its framed request.
type rpcIdentityConn struct {
	net.Conn
	reader   *bufio.Reader
	pending  bytes.Buffer
	peerID   string
	bindings *peerBindings
	rawLeft  int64
}

func (c *rpcIdentityConn) Read(p []byte) (int, error) {
	if c.pending.Len() > 0 {
		return c.pending.Read(p)
	}
	if c.rawLeft > 0 {
		want := int64(len(p))
		if want > c.rawLeft {
			want = c.rawLeft
		}
		n, err := c.reader.Read(p[:want])
		c.rawLeft -= int64(n)
		return n, err
	}
	rpcType, err := c.reader.ReadByte()
	if err != nil {
		return 0, err
	}
	var request any
	switch rpcType {
	case 0:
		request = &raft.AppendEntriesRequest{}
	case 1:
		request = &raft.RequestVoteRequest{}
	case 2:
		request = &raft.InstallSnapshotRequest{}
	case 3:
		request = &raft.TimeoutNowRequest{}
	case 4:
		request = &raft.RequestPreVoteRequest{}
	default:
		return 0, fmt.Errorf("native-raft unknown RPC type %d", rpcType)
	}
	if err := codec.NewDecoder(c.reader, &codec.MsgpackHandle{}).Decode(request); err != nil {
		return 0, err
	}
	header, ok := request.(raft.WithRPCHeader)
	if !ok {
		return 0, fmt.Errorf("native-raft RPC has no identity header")
	}
	h := header.GetRPCHeader()
	if !c.bindings.authorize(string(h.ID), string(h.Addr)) || string(h.ID) != c.peerID {
		return 0, fmt.Errorf("native-raft RPC identity is not authorized")
	}
	if snapshot, ok := request.(*raft.InstallSnapshotRequest); ok {
		c.rawLeft = snapshot.Size
	}
	c.pending.WriteByte(rpcType)
	if err := codec.NewEncoder(&c.pending, &codec.MsgpackHandle{}).Encode(request); err != nil {
		return 0, err
	}
	return c.pending.Read(p)
}

func (s *raftStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = tlsHandshakeTimeout
	}
	deadline := time.Now().Add(timeout)
	raw, err := (&net.Dialer{Deadline: deadline}).Dial("tcp", string(address))
	if err != nil || s.tlsConfig == nil {
		return raw, err
	}
	expected := s.bindings.lookup(string(address))
	if expected == "" {
		_ = raw.Close()
		return nil, fmt.Errorf("native-raft peer address is not an authorized voter")
	}
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
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("native-raft TLS handshake with %s: %w", host, err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
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
