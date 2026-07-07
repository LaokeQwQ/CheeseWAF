package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

type NodeCertificateBundle struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
	CAPEM       []byte
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
	for _, token := range s.tokens {
		if token.Hash != hash {
			continue
		}
		if token.Revoked {
			return fmt.Errorf("join token revoked")
		}
		if !s.clock.Now().Before(token.ExpiresAt) {
			return fmt.Errorf("join token expired")
		}
		if token.UsedCount >= token.MaxUses {
			return fmt.Errorf("join token already used")
		}
		token.UsedCount++
		if err := s.saveStateLocked(); err != nil {
			token.UsedCount--
			return err
		}
		return nil
	}
	return fmt.Errorf("join token not found")
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
	der, err := x509.CreateCertificate(rand.Reader, cert, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return NodeCertificateBundle{}, err
	}
	return NodeCertificateBundle{
		Certificate: parsed,
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
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
	return s.saveStateLocked()
}

func (s *MemoryIdentityService) IsRevoked(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.revoked[nodeID]
	return ok
}

type persistedState struct {
	CA      persistedCA       `json:"ca"`
	Tokens  []JoinToken       `json:"tokens"`
	Revoked map[string]string `json:"revoked"`
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
		Revoked: map[string]string{},
	}
	for _, token := range s.tokens {
		next := *token
		next.Value = ""
		state.Tokens = append(state.Tokens, next)
	}
	sortJoinTokens(state.Tokens)
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
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close cluster identity state temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.statePath); err != nil {
		return fmt.Errorf("replace cluster identity state: %w", err)
	}
	return os.Chmod(s.statePath, 0o600)
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

func enforcePOSIXPrivateMode() bool {
	return runtime.GOOS != "windows"
}

func validateNodeIdentity(identity NodeIdentity, expectedClusterID string) error {
	if strings.TrimSpace(identity.NodeID) == "" {
		return fmt.Errorf("node id is required")
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
