// Package runtime owns the standalone cheesewaf-control process.
package runtime

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane"
	"github.com/LaokeQwQ/CheeseWAF/internal/controlplane/nativeraft"
	"github.com/jackc/pgx/v5"
)

// Options is the intentionally small process boundary. PostgreSQL DSNs are
// accepted here but are never copied into status responses or error strings.
type Options struct {
	Profile        string
	ClusterID      string
	NodeID         string
	DataDir        string
	Listen         string
	RaftListen     string
	Mode           nativeraft.StartMode
	CAFile         string
	CertFile       string
	KeyFile        string
	PostgreSQLDSN  string
	Timeout        time.Duration
	InitialVersion string
	InitialState   []byte
}

func ValidateOptions(opts Options) error {
	if strings.ToLower(opts.Profile) != controlplane.StorageProfileProduction {
		return fmt.Errorf("control process requires production storage profile")
	}
	if !controlplane.ValidIdentity(opts.ClusterID) {
		return fmt.Errorf("cluster id is required and must not contain whitespace")
	}
	if opts.NodeID != "" && !controlplane.ValidIdentity(opts.NodeID) {
		return fmt.Errorf("node id is invalid")
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("control data directory is required")
	}
	if err := validateLoopbackAddress(opts.Listen, "management HTTP"); err != nil {
		return err
	}
	if err := validateLoopbackAddress(opts.RaftListen, "native-raft"); err != nil {
		return err
	}
	if sameConcreteAddress(opts.Listen, opts.RaftListen) {
		return fmt.Errorf("management HTTP and native-raft listen addresses must be different")
	}
	if opts.Mode != nativeraft.ModeBootstrap && opts.Mode != nativeraft.ModeJoin {
		return fmt.Errorf("raft mode must be explicitly set to bootstrap or join")
	}
	if strings.TrimSpace(opts.PostgreSQLDSN) == "" {
		return fmt.Errorf("PostgreSQL DSN is required")
	}
	if err := validatePostgreSQLDSN(opts.PostgreSQLDSN); err != nil {
		return err
	}
	if err := validateNativeRaftTLS(opts); err != nil {
		return err
	}
	if opts.Timeout <= 0 {
		return fmt.Errorf("startup timeout must be positive")
	}
	if opts.InitialState != nil || opts.InitialVersion != "" {
		return fmt.Errorf("initial state import is not supported by cheesewaf-control; use the protected migration workflow")
	}
	return nil
}

func validateNativeRaftTLS(opts Options) error {
	if strings.TrimSpace(opts.CAFile) == "" || strings.TrimSpace(opts.CertFile) == "" || strings.TrimSpace(opts.KeyFile) == "" {
		return fmt.Errorf("native-raft TLS CA, certificate and key files are required")
	}
	if err := validateTLSMaterialPath(opts.CAFile, false, "CA"); err != nil {
		return err
	}
	if err := validateTLSMaterialPath(opts.CertFile, false, "certificate"); err != nil {
		return err
	}
	if err := validateTLSMaterialPath(opts.KeyFile, true, "private key"); err != nil {
		return err
	}

	certificate, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return fmt.Errorf("native-raft certificate is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("native-raft certificate is invalid")
	}
	caPEM, err := os.ReadFile(opts.CAFile)
	if err != nil {
		return fmt.Errorf("native-raft CA is unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("native-raft CA is invalid")
	}
	intermediates := x509.NewCertPool()
	for _, raw := range certificate.Certificate[1:] {
		intermediate, parseErr := x509.ParseCertificate(raw)
		if parseErr != nil {
			return fmt.Errorf("native-raft certificate chain is invalid")
		}
		intermediates.AddCert(intermediate)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("native-raft certificate chain is invalid")
	}
	if opts.NodeID != "" && !certificateHasNodeSAN(leaf, opts.NodeID) {
		return fmt.Errorf("native-raft certificate SAN is not bound to node id")
	}
	return nil
}

func validateTLSMaterialPath(path string, private bool, label string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("native-raft TLS %s file is invalid", label)
	}
	perm := info.Mode().Perm()
	if private {
		if perm != 0o600 {
			return fmt.Errorf("native-raft TLS %s file has insecure permissions", label)
		}
		return nil
	}
	if perm != 0o600 && perm != 0o644 {
		return fmt.Errorf("native-raft TLS %s file has insecure permissions", label)
	}
	return nil
}

func certificateHasNodeSAN(cert *x509.Certificate, nodeID string) bool {
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

func validateLoopbackAddress(raw, name string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("%s listen address is required", name)
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || port == "" {
		return fmt.Errorf("%s listen address must be host:port", name)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%s listen address must be loopback; remote exposure requires TLS, mTLS and ACL", name)
	}
	return nil
}

func sameConcreteAddress(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil || leftPort == "0" || rightPort == "0" {
		return false
	}
	return leftHost == rightHost && leftPort == rightPort
}

func validatePostgreSQLDSN(raw string) error {
	parsed, err := pgx.ParseConfig(raw)
	if err != nil || parsed == nil || parsed.Host == "" || parsed.Database == "" || !controlplane.ValidIdentity(parsed.User) {
		return fmt.Errorf("PostgreSQL DSN is invalid")
	}
	// Unix sockets and loopback are safe for local development. Any network
	// endpoint must verify the server certificate; sslmode=disable/prefer is
	// rejected so a production process cannot silently downgrade transport.
	if ip := net.ParseIP(parsed.Host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if strings.EqualFold(parsed.Host, "localhost") || strings.HasPrefix(parsed.Host, "/") {
		return nil
	}
	if parsed.TLSConfig == nil || parsed.TLSConfig.InsecureSkipVerify {
		return fmt.Errorf("remote PostgreSQL DSN requires TLS certificate verification")
	}
	return nil
}
