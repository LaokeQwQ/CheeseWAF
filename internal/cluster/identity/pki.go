package identity

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type FakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func NewFakeClock(now time.Time) *FakeClock {
	return &FakeClock{now: now}
}

func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type ServiceOptions struct {
	Clock     Clock
	ClusterID string
	StatePath string
}

type JoinToken struct {
	ID        string    `json:"id"`
	Value     string    `json:"value,omitempty"`
	Hash      string    `json:"hash,omitempty"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	MaxUses   int       `json:"max_uses"`
	UsedCount int       `json:"used_count"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
}

type NodeIdentity struct {
	NodeID        string
	Role          string
	ClusterID     string
	AdvertiseAddr string
}

type NodeRegistration struct {
	NodeID            string    `json:"node_id"`
	Role              string    `json:"role"`
	ClusterID         string    `json:"cluster_id"`
	AdvertiseAddr     string    `json:"advertise_addr"`
	JoinedAt          time.Time `json:"joined_at"`
	CertificateSerial string    `json:"certificate_serial"`
	CertificateExpiry time.Time `json:"certificate_expiry"`
	Revoked           bool      `json:"revoked"`
	RevokedReason     string    `json:"revoked_reason,omitempty"`
}

type NodeCertificateBundle struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
	CAPEM       []byte
}

type NodeEnrollment struct {
	Node     NodeRegistration
	Bundle   NodeCertificateBundle
	Token    JoinToken
	rollback func() error
}

type NodeCertificateRotation struct {
	Node   NodeRegistration
	Bundle NodeCertificateBundle
}

type MemoryIdentityService struct {
	mu        sync.Mutex
	clock     Clock
	clusterID string
	statePath string
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caDER     []byte
	tokens    map[string]*JoinToken
	nodes     map[string]*NodeRegistration
	revoked   map[string]string
}

func NewMemoryIdentityService(opts ServiceOptions) (*MemoryIdentityService, error) {
	clock := opts.Clock
	if clock == nil {
		clock = realClock{}
	}
	clusterID := strings.TrimSpace(opts.ClusterID)
	if clusterID == "" {
		clusterID = "cheesewaf-local"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	cert := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   "CheeseWAF Cluster CA " + clusterID,
			Organization: []string{"CheeseCloud Technology Ltc."},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	svc := &MemoryIdentityService{
		clock:     clock,
		clusterID: clusterID,
		statePath: strings.TrimSpace(opts.StatePath),
		caKey:     key,
		caCert:    cert,
		caDER:     caDER,
		tokens:    map[string]*JoinToken{},
		nodes:     map[string]*NodeRegistration{},
		revoked:   map[string]string{},
	}
	if err := svc.loadState(); err != nil {
		return nil, err
	}
	if svc.statePath != "" {
		svc.mu.Lock()
		err := svc.saveStateLocked()
		svc.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return svc, nil
}

func (s *MemoryIdentityService) CreateJoinToken(role string, ttl time.Duration, maxUses int) (JoinToken, error) {
	role = strings.TrimSpace(role)
	if role != "waf" && role != "monitor" {
		return JoinToken{}, fmt.Errorf("role must be waf or monitor")
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return JoinToken{}, fmt.Errorf("ttl must be between 1s and 24h")
	}
	if maxUses <= 0 || maxUses > 100 {
		return JoinToken{}, fmt.Errorf("max uses must be between 1 and 100")
	}
	value, err := randomTokenValue()
	if err != nil {
		return JoinToken{}, err
	}
	now := s.clock.Now()
	token := &JoinToken{
		ID:        "jt-" + tokenHash(value)[:16],
		Value:     value,
		Hash:      tokenHash(value),
		Role:      role,
		ExpiresAt: now.Add(ttl),
		MaxUses:   maxUses,
		CreatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := *token
	stored.Value = ""
	s.tokens[token.ID] = &stored
	if err := s.saveStateLocked(); err != nil {
		delete(s.tokens, token.ID)
		return JoinToken{}, err
	}
	return *token, nil
}

func (s *MemoryIdentityService) ConsumeJoinToken(value string) error {
	hash := tokenHash(strings.TrimSpace(value))
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.consumeJoinTokenLocked(hash, "")
	if err != nil {
		return err
	}
	if err := s.saveStateLocked(); err != nil {
		token.UsedCount--
		return err
	}
	return nil
}

func (s *MemoryIdentityService) ValidateJoinToken(value string, expectedRole string) error {
	hash := tokenHash(strings.TrimSpace(value))
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.validateJoinTokenLocked(hash, strings.TrimSpace(expectedRole))
	return err
}

func (s *MemoryIdentityService) ListJoinTokens() []JoinToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens := make([]JoinToken, 0, len(s.tokens))
	for _, token := range s.tokens {
		next := *token
		next.Value = ""
		tokens = append(tokens, next)
	}
	sortJoinTokens(tokens)
	return tokens
}

func (s *MemoryIdentityService) EnrollNode(value string, node NodeIdentity) (NodeEnrollment, error) {
	if err := validateNodeIdentity(node, s.clusterID); err != nil {
		return NodeEnrollment{}, err
	}
	hash := tokenHash(strings.TrimSpace(value))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validateJoinTokenLocked(hash, node.Role); err != nil {
		return NodeEnrollment{}, err
	}
	if _, revoked := s.revoked[node.NodeID]; revoked {
		return NodeEnrollment{}, fmt.Errorf("node %q is revoked", node.NodeID)
	}
	if _, exists := s.nodes[node.NodeID]; exists {
		return NodeEnrollment{}, fmt.Errorf("node %q is already enrolled; revoke or rotate it before rejoining", node.NodeID)
	}
	token, err := s.consumeJoinTokenLocked(hash, node.Role)
	if err != nil {
		return NodeEnrollment{}, err
	}
	bundle, err := s.issueNodeCertificateBundleLocked(node)
	if err != nil {
		token.UsedCount--
		return NodeEnrollment{}, err
	}
	now := s.clock.Now()
	registration := NodeRegistration{
		NodeID:            node.NodeID,
		Role:              node.Role,
		ClusterID:         node.ClusterID,
		AdvertiseAddr:     node.AdvertiseAddr,
		JoinedAt:          now,
		CertificateSerial: bundle.Certificate.SerialNumber.String(),
		CertificateExpiry: bundle.Certificate.NotAfter,
	}
	stored := registration
	s.nodes[node.NodeID] = &stored
	if err := s.saveStateLocked(); err != nil {
		token.UsedCount--
		delete(s.nodes, node.NodeID)
		return NodeEnrollment{}, err
	}
	tokenView := *token
	tokenView.Value = ""
	tokenView.Hash = ""
	return NodeEnrollment{
		Node:   registration,
		Bundle: bundle,
		Token:  tokenView,
		rollback: func() error {
			return s.rollbackNodeEnrollment(node.NodeID, token.ID)
		},
	}, nil
}

func (s *MemoryIdentityService) EnrollNodeWithCSR(value string, node NodeIdentity, csrPEM []byte) (NodeEnrollment, error) {
	if err := validateNodeIdentity(node, s.clusterID); err != nil {
		return NodeEnrollment{}, err
	}
	csr, err := parseCertificateRequestPEM(csrPEM)
	if err != nil {
		return NodeEnrollment{}, err
	}
	if err := validateCSRMatchesNodeIdentity(csr, node); err != nil {
		return NodeEnrollment{}, err
	}
	hash := tokenHash(strings.TrimSpace(value))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validateJoinTokenLocked(hash, node.Role); err != nil {
		return NodeEnrollment{}, err
	}
	if _, revoked := s.revoked[node.NodeID]; revoked {
		return NodeEnrollment{}, fmt.Errorf("node %q is revoked", node.NodeID)
	}
	if _, exists := s.nodes[node.NodeID]; exists {
		return NodeEnrollment{}, fmt.Errorf("node %q is already enrolled; revoke or rotate it before rejoining", node.NodeID)
	}
	token, err := s.consumeJoinTokenLocked(hash, node.Role)
	if err != nil {
		return NodeEnrollment{}, err
	}
	bundle, err := s.issueNodeCertificateBundleForPublicKeyLocked(node, csr.PublicKey)
	if err != nil {
		token.UsedCount--
		return NodeEnrollment{}, err
	}
	now := s.clock.Now()
	registration := NodeRegistration{
		NodeID:            node.NodeID,
		Role:              node.Role,
		ClusterID:         node.ClusterID,
		AdvertiseAddr:     node.AdvertiseAddr,
		JoinedAt:          now,
		CertificateSerial: bundle.Certificate.SerialNumber.String(),
		CertificateExpiry: bundle.Certificate.NotAfter,
	}
	stored := registration
	s.nodes[node.NodeID] = &stored
	if err := s.saveStateLocked(); err != nil {
		token.UsedCount--
		delete(s.nodes, node.NodeID)
		return NodeEnrollment{}, err
	}
	tokenView := *token
	tokenView.Value = ""
	tokenView.Hash = ""
	return NodeEnrollment{
		Node:   registration,
		Bundle: bundle,
		Token:  tokenView,
		rollback: func() error {
			return s.rollbackNodeEnrollment(node.NodeID, token.ID)
		},
	}, nil
}

func (s *MemoryIdentityService) ListNodes() []NodeRegistration {
	s.mu.Lock()
	defer s.mu.Unlock()
	nodes := make([]NodeRegistration, 0, len(s.nodes))
	for _, node := range s.nodes {
		next := *node
		if reason, ok := s.revoked[next.NodeID]; ok {
			next.Revoked = true
			next.RevokedReason = reason
		}
		nodes = append(nodes, next)
	}
	sortNodeRegistrations(nodes)
	return nodes
}

func (s *MemoryIdentityService) RotateNodeCertificateWithCSR(nodeID string, csrPEM []byte) (NodeCertificateRotation, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return NodeCertificateRotation{}, fmt.Errorf("node id is required")
	}
	csr, err := parseCertificateRequestPEM(csrPEM)
	if err != nil {
		return NodeCertificateRotation{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[nodeID]
	if !ok {
		return NodeCertificateRotation{}, fmt.Errorf("node %q is not enrolled", nodeID)
	}
	if node.Revoked {
		return NodeCertificateRotation{}, fmt.Errorf("node %q is revoked", nodeID)
	}
	if _, revoked := s.revoked[nodeID]; revoked {
		return NodeCertificateRotation{}, fmt.Errorf("node %q is revoked", nodeID)
	}
	identity := NodeIdentity{
		NodeID:        node.NodeID,
		Role:          node.Role,
		ClusterID:     node.ClusterID,
		AdvertiseAddr: node.AdvertiseAddr,
	}
	if err := validateNodeIdentity(identity, s.clusterID); err != nil {
		return NodeCertificateRotation{}, err
	}
	if err := validateCSRMatchesNodeIdentity(csr, identity); err != nil {
		return NodeCertificateRotation{}, err
	}
	bundle, err := s.issueNodeCertificateBundleForPublicKeyLocked(identity, csr.PublicKey)
	if err != nil {
		return NodeCertificateRotation{}, err
	}
	previous := *node
	node.CertificateSerial = bundle.Certificate.SerialNumber.String()
	node.CertificateExpiry = bundle.Certificate.NotAfter
	if err := s.saveStateLocked(); err != nil {
		*node = previous
		return NodeCertificateRotation{}, err
	}
	updated := *node
	return NodeCertificateRotation{Node: updated, Bundle: bundle}, nil
}

func (e NodeEnrollment) Rollback() error {
	if e.rollback != nil {
		return e.rollback()
	}
	return nil
}

func (s *MemoryIdentityService) rollbackNodeEnrollment(nodeID string, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, nodeID)
	if tokenID != "" {
		if token, ok := s.tokens[tokenID]; ok && token.UsedCount > 0 {
			token.UsedCount--
		}
	}
	return s.saveStateLocked()
}

func (s *MemoryIdentityService) RevokeJoinToken(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("join token id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[id]
	if !ok {
		return fmt.Errorf("join token not found")
	}
	token.Revoked = true
	return s.saveStateLocked()
}

func (s *MemoryIdentityService) IssueNodeCertificate(identity NodeIdentity) (*x509.Certificate, error) {
	bundle, err := s.IssueNodeCertificateBundle(identity)
	if err != nil {
		return nil, err
	}
	return bundle.Certificate, nil
}

func (s *MemoryIdentityService) IssueNodeCertificateBundle(identity NodeIdentity) (NodeCertificateBundle, error) {
	if err := validateNodeIdentity(identity, s.clusterID); err != nil {
		return NodeCertificateBundle{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	bundle, err := s.issueNodeCertificateBundleForPublicKeyLocked(identity, &key.PublicKey)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	bundle.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return bundle, nil
}

func (s *MemoryIdentityService) issueNodeCertificateBundleLocked(identity NodeIdentity) (NodeCertificateBundle, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	bundle, err := s.issueNodeCertificateBundleForPublicKeyLocked(identity, &key.PublicKey)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	bundle.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return bundle, nil
}

func (s *MemoryIdentityService) issueNodeCertificateBundleForPublicKeyLocked(identity NodeIdentity, publicKey any) (NodeCertificateBundle, error) {
	if err := validateNodeCertificatePublicKey(publicKey); err != nil {
		return NodeCertificateBundle{}, err
	}
	now := s.clock.Now()
	cert := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   identity.ClusterID + "/" + identity.Role + "/" + identity.NodeID,
			Organization: []string{"CheeseCloud Technology Ltc."},
		},
		DNSNames:    []string{identity.NodeID},
		NotBefore:   now.Add(-time.Minute),
		NotAfter:    now.Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	host, _, err := net.SplitHostPort(identity.AdvertiseAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = []net.IP{ip}
		} else if host != "" {
			cert.DNSNames = append(cert.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, s.caCert, publicKey, s.caKey)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	return NodeCertificateBundle{
		Certificate: parsed,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		CAPEM:       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caDER}),
	}, nil
}

func (s *MemoryIdentityService) RevokeNode(nodeID string, reason string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return fmt.Errorf("node id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[nodeID] = strings.TrimSpace(reason)
	if node, ok := s.nodes[nodeID]; ok {
		node.Revoked = true
		node.RevokedReason = strings.TrimSpace(reason)
	}
	return s.saveStateLocked()
}

func (s *MemoryIdentityService) IsRevoked(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revoked[nodeID]
	return ok
}

type persistedState struct {
	CA      persistedCA        `json:"ca"`
	Tokens  []JoinToken        `json:"tokens"`
	Nodes   []NodeRegistration `json:"nodes"`
	Revoked map[string]string  `json:"revoked"`
}

type persistedCA struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func (s *MemoryIdentityService) loadState() error {
	if s == nil || s.statePath == "" {
		return nil
	}
	info, err := os.Lstat(s.statePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat cluster identity state: %w", err)
	}
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cluster identity state must not be a symlink")
		}
		if enforcePOSIXPrivateMode() && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("cluster identity state permissions must not allow group or world access")
		}
	}
	raw, err := os.ReadFile(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read cluster identity state: %w", err)
	}
	var state persistedState
	if err := json.Unmarshal(raw, &state); err != nil {
		return fmt.Errorf("parse cluster identity state: %w", err)
	}
	if err := s.loadCAFromState(state.CA); err != nil {
		return err
	}
	s.tokens = map[string]*JoinToken{}
	for i := range state.Tokens {
		token := state.Tokens[i]
		token.Value = ""
		if strings.TrimSpace(token.ID) == "" || strings.TrimSpace(token.Hash) == "" {
			continue
		}
		s.tokens[token.ID] = &token
	}
	s.nodes = map[string]*NodeRegistration{}
	for i := range state.Nodes {
		node := state.Nodes[i]
		if strings.TrimSpace(node.NodeID) == "" {
			continue
		}
		s.nodes[node.NodeID] = &node
	}
	if state.Revoked == nil {
		state.Revoked = map[string]string{}
	}
	s.revoked = state.Revoked
	return nil
}

func (s *MemoryIdentityService) saveStateLocked() error {
	if s == nil || s.statePath == "" {
		return nil
	}
	state := persistedState{
		CA:      s.persistedCA(),
		Tokens:  make([]JoinToken, 0, len(s.tokens)),
		Nodes:   make([]NodeRegistration, 0, len(s.nodes)),
		Revoked: map[string]string{},
	}
	for _, token := range s.tokens {
		next := *token
		next.Value = ""
		state.Tokens = append(state.Tokens, next)
	}
	sortJoinTokens(state.Tokens)
	for _, node := range s.nodes {
		next := *node
		if reason, ok := s.revoked[next.NodeID]; ok {
			next.Revoked = true
			next.RevokedReason = reason
		}
		state.Nodes = append(state.Nodes, next)
	}
	sortNodeRegistrations(state.Nodes)
	for nodeID, reason := range s.revoked {
		state.Revoked[nodeID] = reason
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cluster identity state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o750); err != nil {
		return fmt.Errorf("create cluster identity state dir: %w", err)
	}
	if info, err := os.Lstat(s.statePath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("cluster identity state must not be a symlink")
		}
		if err := os.Chmod(s.statePath, 0o600); err != nil {
			return fmt.Errorf("secure cluster identity state permissions: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat cluster identity state: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.statePath), ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("create cluster identity state temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("secure cluster identity state temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write cluster identity state temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync cluster identity state temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cluster identity state temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.statePath); err != nil {
		return fmt.Errorf("replace cluster identity state: %w", err)
	}
	if err := os.Chmod(s.statePath, 0o600); err != nil {
		return err
	}
	if dirHandle, err := os.Open(filepath.Dir(s.statePath)); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func (s *MemoryIdentityService) loadCAFromState(state persistedCA) error {
	if strings.TrimSpace(state.CertPEM) == "" || strings.TrimSpace(state.KeyPEM) == "" {
		return nil
	}
	certBlock, _ := pem.Decode([]byte(state.CertPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("parse cluster identity state: invalid CA certificate")
	}
	keyBlock, _ := pem.Decode([]byte(state.KeyPEM))
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("parse cluster identity state: invalid CA private key")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse cluster identity state CA certificate: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse cluster identity state CA key: %w", err)
	}
	if !cert.IsCA {
		return fmt.Errorf("parse cluster identity state: certificate is not a CA")
	}
	s.caCert = cert
	s.caDER = certBlock.Bytes
	s.caKey = key
	return nil
}

func (s *MemoryIdentityService) persistedCA() persistedCA {
	if s == nil || s.caKey == nil || len(s.caDER) == 0 {
		return persistedCA{}
	}
	keyDER, err := x509.MarshalECPrivateKey(s.caKey)
	if err != nil {
		return persistedCA{}
	}
	return persistedCA{
		CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caDER})),
		KeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
}

func sortJoinTokens(tokens []JoinToken) {
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].CreatedAt.Equal(tokens[j].CreatedAt) {
			return tokens[i].ID < tokens[j].ID
		}
		return tokens[i].CreatedAt.Before(tokens[j].CreatedAt)
	})
}

func sortNodeRegistrations(nodes []NodeRegistration) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].JoinedAt.Equal(nodes[j].JoinedAt) {
			return nodes[i].NodeID < nodes[j].NodeID
		}
		return nodes[i].JoinedAt.Before(nodes[j].JoinedAt)
	})
}

func (s *MemoryIdentityService) consumeJoinTokenLocked(hash string, expectedRole string) (*JoinToken, error) {
	token, err := s.validateJoinTokenLocked(hash, expectedRole)
	if err != nil {
		return nil, err
	}
	token.UsedCount++
	return token, nil
}

func (s *MemoryIdentityService) validateJoinTokenLocked(hash string, expectedRole string) (*JoinToken, error) {
	for _, token := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(token.Hash), []byte(hash)) != 1 {
			continue
		}
		if token.Revoked {
			return nil, fmt.Errorf("join token revoked")
		}
		if !s.clock.Now().Before(token.ExpiresAt) {
			return nil, fmt.Errorf("join token expired")
		}
		if token.UsedCount >= token.MaxUses {
			return nil, fmt.Errorf("join token already used")
		}
		if expectedRole != "" && token.Role != expectedRole {
			return nil, fmt.Errorf("join token role %q cannot enroll %q node", token.Role, expectedRole)
		}
		return token, nil
	}
	return nil, fmt.Errorf("join token not found")
}

func enforcePOSIXPrivateMode() bool {
	return runtime.GOOS != "windows"
}

func validateNodeIdentity(identity NodeIdentity, expectedClusterID string) error {
	if strings.TrimSpace(identity.NodeID) == "" {
		return fmt.Errorf("node id is required")
	}
	if !isSafeNodeID(identity.NodeID) {
		return fmt.Errorf("node id may only contain letters, numbers, dot, underscore, and dash")
	}
	if identity.Role != "waf" && identity.Role != "monitor" {
		return fmt.Errorf("role must be waf or monitor")
	}
	if strings.TrimSpace(identity.ClusterID) == "" || identity.ClusterID != expectedClusterID {
		return fmt.Errorf("cluster id mismatch")
	}
	if strings.TrimSpace(identity.AdvertiseAddr) == "" {
		return fmt.Errorf("advertise addr is required")
	}
	if _, err := net.ResolveTCPAddr("tcp", identity.AdvertiseAddr); err != nil {
		return fmt.Errorf("advertise addr invalid: %w", err)
	}
	return nil
}

func isSafeNodeID(value string) bool {
	if len(value) > 64 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func parseCertificateRequestPEM(raw []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("csr must be PEM encoded CERTIFICATE REQUEST")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("csr must contain exactly one PEM encoded CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature invalid: %w", err)
	}
	if csr.PublicKey == nil {
		return nil, fmt.Errorf("csr public key is required")
	}
	if err := validateNodeCertificatePublicKey(csr.PublicKey); err != nil {
		return nil, fmt.Errorf("csr public key invalid: %w", err)
	}
	return csr, nil
}

func validateNodeCertificatePublicKey(publicKey any) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil || key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
			return fmt.Errorf("ECDSA public key is invalid")
		}
		switch key.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			return fmt.Errorf("ECDSA public key curve is not allowed")
		}
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.E < 3 || key.N.BitLen() < 2048 {
			return fmt.Errorf("RSA public key must be at least 2048 bits")
		}
		return nil
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("Ed25519 public key is invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", publicKey)
	}
}

func validateCSRMatchesNodeIdentity(csr *x509.CertificateRequest, identity NodeIdentity) error {
	if csr == nil {
		return fmt.Errorf("csr is required")
	}
	nodeID := strings.TrimSpace(identity.NodeID)
	if nodeID == "" {
		return fmt.Errorf("node id is required")
	}
	for _, dnsName := range csr.DNSNames {
		if strings.EqualFold(strings.TrimSpace(dnsName), nodeID) {
			return nil
		}
	}
	if ip := net.ParseIP(nodeID); ip != nil {
		for _, csrIP := range csr.IPAddresses {
			if csrIP.Equal(ip) {
				return nil
			}
		}
	}
	commonName := strings.TrimSpace(csr.Subject.CommonName)
	if commonName != "" {
		allowedCommonNames := []string{
			nodeID,
			strings.TrimSpace(identity.Role) + "/" + nodeID,
			strings.TrimSpace(identity.ClusterID) + "/" + strings.TrimSpace(identity.Role) + "/" + nodeID,
		}
		for _, allowed := range allowedCommonNames {
			if allowed != "" && commonName == allowed {
				return nil
			}
		}
	}
	return fmt.Errorf("csr subject must identify node %q", nodeID)
}

func randomTokenValue() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func tokenHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil || serial.Sign() == 0 {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}
