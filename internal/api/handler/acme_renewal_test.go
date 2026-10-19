package handler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/acme"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
)

func TestValidateACMECertificateFilesRestrictsKeyAndChecksSAN(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeRenewalTestCertificate(t, dir, []string{"example.test"}, time.Now().Add(24*time.Hour))
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	expires, err := validateACMECertificateFiles(certPath, keyPath, []string{"example.test"}, time.Now(), true)
	if err != nil {
		t.Fatalf("validate certificate: %v", err)
	}
	if expires.IsZero() {
		t.Fatal("expected certificate expiry")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("private key mode = %o, want 600", got)
		}
	}
	if _, err := validateACMECertificateFiles(certPath, keyPath, []string{"other.test"}, time.Now(), true); err == nil {
		t.Fatal("certificate with an unrelated SAN was accepted")
	}
}

func TestValidateACMECertificateFilesRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeRenewalTestCertificate(t, dir, []string{"example.test"}, time.Now().Add(time.Hour))
	link := filepath.Join(dir, "linked.key")
	if err := os.Symlink(keyPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := validateACMECertificateFiles(certPath, link, []string{"example.test"}, time.Now(), true); err == nil {
		t.Fatal("symlinked private key was accepted")
	}
}

func TestRenewACMEOnceRenewsDueSiteAndPersistsStatus(t *testing.T) {
	h, store, site := newSiteTestHandler(t)
	h.Config.ACME.Enabled = false
	h.Config.ACME.CertDir = t.TempDir()
	certDir := filepath.Join(h.Config.ACME.CertDir, "example.test")
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeRenewalTestCertificate(t, certDir, []string{"example.test"}, time.Now().Add(24*time.Hour))
	site.Enabled = true
	site.EnableSSL = true
	site.CertFile = certPath
	site.KeyFile = keyPath
	site.Advanced.Certificate.Mode = "acme"
	site.Advanced.Certificate.AutoRenew = true
	site.Advanced.Certificate.ACME.DNSAPI = "dns_cf"
	site.Advanced.Certificate.ACME.ExpiresAt = time.Now().Add(-time.Hour)
	if err := store.UpdateSite(context.Background(), &site); err != nil {
		t.Fatal(err)
	}
	issuer := &renewingACMEIssuer{}
	h.ACMEIssuer = issuer
	if err := h.RenewACMEOnce(context.Background()); err != nil {
		t.Fatalf("disabled renewal scan failed: %v", err)
	}
	if issuer.calls != 0 {
		t.Fatal("disabled ACME must not issue certificates")
	}
	next, err := config.Clone(h.currentConfig())
	if err != nil {
		t.Fatal(err)
	}
	next.ACME.Enabled = true
	if err := h.publishConfig(next); err != nil {
		t.Fatal(err)
	}
	if err := h.RenewACMEOnce(context.Background()); err != nil {
		t.Fatalf("renewal failed: %v", err)
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls = %d, want 1", issuer.calls)
	}
	got, err := store.GetSite(context.Background(), site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Advanced.Certificate.ACME.LastStatus != "renewed" {
		t.Fatalf("last status = %q, want renewed", got.Advanced.Certificate.ACME.LastStatus)
	}
}

func TestRecoverACMEDeploymentRestoresSiteAfterSuccessfulUpdate(t *testing.T) {
	h, store, previous := newSiteTestHandler(t)
	ctx := context.Background()
	current, err := store.GetSite(ctx, previous.ID)
	if err != nil {
		t.Fatal(err)
	}
	current.EnableSSL = true
	current.CertFile = "/tmp/new-fullchain.cer"
	current.KeyFile = "/tmp/new-site.key"
	current.Advanced.Certificate.Mode = "acme"
	if err := store.UpdateSite(ctx, current); err != nil {
		t.Fatalf("persist candidate site: %v", err)
	}
	if current.UpdatedAt.Equal(previous.UpdatedAt) {
		t.Fatal("candidate update did not advance UpdatedAt, test cannot exercise stale CAS rollback")
	}

	if err := h.recoverACMEDeployment(newACMERequest(ctx), &previous, acmeCertificateSnapshot{}, true); err != nil {
		t.Fatalf("recover deployment: %v", err)
	}

	got, err := store.GetSite(ctx, previous.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EnableSSL != previous.EnableSSL || got.CertFile != previous.CertFile || got.KeyFile != previous.KeyFile || got.Advanced.Certificate.Mode != previous.Advanced.Certificate.Mode {
		t.Fatalf("site was not restored to its previous state: got=%+v want=%+v", got, previous)
	}
	if !got.UpdatedAt.Equal(previous.UpdatedAt) {
		t.Fatalf("restored UpdatedAt=%s, want previous timestamp %s", got.UpdatedAt, previous.UpdatedAt)
	}
}

type renewingACMEIssuer struct{ calls int }

func (i *renewingACMEIssuer) Providers() []acme.DNSProvider { return nil }

func (i *renewingACMEIssuer) Issue(_ context.Context, req acme.IssueRequest) (acme.IssueResult, error) {
	i.calls++
	if err := os.MkdirAll(req.CertDir, 0o750); err != nil {
		return acme.IssueResult{}, err
	}
	certPath, keyPath := writeRenewalTestCertificateForIssuer(req.CertDir, req.Domains)
	now := time.Now().UTC()
	return acme.IssueResult{SiteID: req.SiteID, RunID: "renew-test", Domains: req.Domains, CertFile: certPath, Fullchain: certPath, KeyFile: keyPath, IssuedAt: now, RenewAfter: now.Add(60 * 24 * time.Hour), AutoRenew: true}, nil
}

func writeRenewalTestCertificateForIssuer(dir string, domains []string) (string, string) {
	// This helper is only used by the injected issuer in the worker test.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: domains, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, "site.key")
	_ = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certPath, keyPath
}

func writeRenewalTestCertificate(t *testing.T, dir string, names []string, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          newSerialNumber(t),
		Subject:               pkix.Name{CommonName: names[0]},
		DNSNames:              names,
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "fullchain.cer")
	keyPath := filepath.Join(dir, "site.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func newSerialNumber(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return serial
}
