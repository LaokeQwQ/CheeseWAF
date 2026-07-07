package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/spf13/cobra"
)

type clusterJoinOptions struct {
	ControllerURL      string
	Token              string
	TokenFile          string
	TokenEnv           string
	NodeID             string
	Role               string
	AdvertiseAddr      string
	Listen             string
	CAFile             string
	InsecureSkipVerify bool
	AllowInsecureHTTP  bool
	DryRun             bool
	Force              bool
}

type clusterJoinLocalIdentity struct {
	KeyPEM []byte
	CSRPEM []byte
}

type clusterJoinAPIResponse struct {
	ClusterID     string `json:"cluster_id"`
	NodeID        string `json:"node_id"`
	Role          string `json:"role"`
	AdvertiseAddr string `json:"advertise_addr"`
	Listen        string `json:"listen"`
	Interconnect  struct {
		Listen        string `json:"listen"`
		AdvertiseAddr string `json:"advertise_addr"`
		MTLSRequired  bool   `json:"mtls_required"`
		CAFile        string `json:"ca_file"`
		CertFile      string `json:"cert_file"`
		KeyFile       string `json:"key_file"`
	} `json:"interconnect"`
	Certificates struct {
		CA   string `json:"ca"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"certificates"`
	Node struct {
		NodeID            string    `json:"node_id"`
		Role              string    `json:"role"`
		ClusterID         string    `json:"cluster_id"`
		AdvertiseAddr     string    `json:"advertise_addr"`
		JoinedAt          time.Time `json:"joined_at"`
		CertificateSerial string    `json:"certificate_serial"`
		CertificateExpiry time.Time `json:"certificate_expiry"`
	} `json:"node"`
}

type apiEnvelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		TraceID string `json:"trace_id"`
		EventID string `json:"event_id"`
	} `json:"error"`
}

func newClusterJoinCommand() *cobra.Command {
	var opts clusterJoinOptions
	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join this node to an existing CheeseWAF cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterJoin(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.ControllerURL, "controller", "", "Controller admin URL, for example https://10.0.0.10:9443")
	cmd.Flags().StringVar(&opts.Token, "token", "", "One-time join token. Prefer --token-file or --token-env in production")
	cmd.Flags().StringVar(&opts.TokenFile, "token-file", "", "Read one-time join token from file")
	cmd.Flags().StringVar(&opts.TokenEnv, "token-env", "", "Read one-time join token from environment variable")
	cmd.Flags().StringVar(&opts.NodeID, "node-id", "", "Node identifier")
	cmd.Flags().StringVar(&opts.Role, "role", "waf", "Node role: waf or monitor")
	cmd.Flags().StringVar(&opts.AdvertiseAddr, "advertise-addr", "", "Node interconnect advertise address, for example 10.0.0.11:9444")
	cmd.Flags().StringVar(&opts.Listen, "listen", "", "Node interconnect listen address; defaults to advertise address")
	cmd.Flags().StringVar(&opts.CAFile, "ca-file", "", "Controller CA certificate file")
	cmd.Flags().BoolVar(&opts.InsecureSkipVerify, "insecure-skip-verify", false, "Skip controller TLS certificate verification")
	cmd.Flags().BoolVar(&opts.AllowInsecureHTTP, "allow-insecure-http", false, "Allow cleartext HTTP for isolated lab bootstrap only. Join tokens are exposed on the network")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "Validate local join inputs and CSR generation without contacting the controller or consuming the token")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "Overwrite existing local cluster certificate files")
	_ = cmd.MarkFlagRequired("controller")
	_ = cmd.MarkFlagRequired("node-id")
	_ = cmd.MarkFlagRequired("advertise-addr")
	return cmd
}

func runClusterJoin(cmd *cobra.Command, opts clusterJoinOptions) error {
	token, err := resolveJoinToken(opts)
	if err != nil {
		return err
	}
	localIdentity, err := generateClusterJoinLocalIdentity(opts)
	if err != nil {
		return err
	}
	reqPayload := map[string]string{
		"token":          token,
		"node_id":        strings.TrimSpace(opts.NodeID),
		"role":           strings.TrimSpace(opts.Role),
		"advertise_addr": strings.TrimSpace(opts.AdvertiseAddr),
		"listen":         strings.TrimSpace(opts.Listen),
		"csr":            string(localIdentity.CSRPEM),
	}
	if reqPayload["listen"] == "" {
		reqPayload["listen"] = reqPayload["advertise_addr"]
	}
	controllerURL, err := validateClusterJoinControllerURL(opts.ControllerURL, opts.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	if opts.DryRun {
		fmt.Fprintf(cmd.OutOrStdout(), "Join request is valid for node %s. Dry run did not contact the controller or consume the token.\n", reqPayload["node_id"])
		return nil
	}
	client, err := clusterJoinHTTPClient(opts)
	if err != nil {
		return err
	}
	result, err := requestClusterJoin(client, controllerURL, reqPayload)
	if err != nil {
		return err
	}
	paths, err := writeClusterJoinFiles(result, opts, localIdentity)
	if err != nil {
		return err
	}
	if err := applyClusterJoinConfig(result, paths); err != nil {
		cleanupClusterJoinFiles(paths)
		return clusterJoinConfigApplyError(result, paths, err)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Node joined cluster: %s / %s\n", result.ClusterID, result.NodeID)
	fmt.Fprintf(out, "Certificate files written under: %s\n", filepath.Dir(paths.CertFile))
	fmt.Fprintln(out, "Restart CheeseWAF for the cluster interconnect settings to take effect.")
	return nil
}

func clusterJoinConfigApplyError(result clusterJoinAPIResponse, _ clusterJoinPaths, err error) error {
	return fmt.Errorf("controller accepted the join and consumed the token, but local cluster config was not saved: %w. Revoke or rotate node %q on the controller before retrying with a new join token", err, result.NodeID)
}

func generateClusterJoinLocalIdentity(opts clusterJoinOptions) (clusterJoinLocalIdentity, error) {
	nodeID := strings.TrimSpace(opts.NodeID)
	if nodeID == "" {
		return clusterJoinLocalIdentity{}, fmt.Errorf("node id is required")
	}
	role := strings.TrimSpace(opts.Role)
	if role == "" {
		role = "waf"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return clusterJoinLocalIdentity{}, fmt.Errorf("generate node private key: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return clusterJoinLocalIdentity{}, fmt.Errorf("marshal node private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   role + "/" + nodeID,
			Organization: []string{"CheeseCloud Technology Ltc."},
		},
		DNSNames: []string{nodeID},
	}, key)
	if err != nil {
		return clusterJoinLocalIdentity{}, fmt.Errorf("create node csr: %w", err)
	}
	return clusterJoinLocalIdentity{
		KeyPEM: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}

func resolveJoinToken(opts clusterJoinOptions) (string, error) {
	sources := 0
	token := strings.TrimSpace(opts.Token)
	if token != "" {
		sources++
	}
	if strings.TrimSpace(opts.TokenFile) != "" {
		sources++
		raw, err := os.ReadFile(opts.TokenFile)
		if err != nil {
			return "", fmt.Errorf("read join token file: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if strings.TrimSpace(opts.TokenEnv) != "" {
		sources++
		token = strings.TrimSpace(os.Getenv(opts.TokenEnv))
	}
	if sources != 1 {
		return "", fmt.Errorf("provide exactly one of --token, --token-file, or --token-env")
	}
	if token == "" {
		return "", fmt.Errorf("join token is empty")
	}
	return token, nil
}

func clusterJoinHTTPClient(opts clusterJoinOptions) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}
	if strings.TrimSpace(opts.CAFile) != "" {
		raw, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read controller CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("controller CA file does not contain PEM certificates")
		}
		tlsConfig.RootCAs = pool
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func validateClusterJoinControllerURL(controllerURL string, allowInsecureHTTP bool) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(controllerURL), "/")
	if base == "" {
		return "", fmt.Errorf("controller URL is required")
	}
	lower := strings.ToLower(base)
	if strings.HasPrefix(lower, "http://") && !allowInsecureHTTP {
		return "", fmt.Errorf("cluster join requires HTTPS because the request contains a join token; use --allow-insecure-http only for isolated local lab bootstrap")
	}
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
		return "", fmt.Errorf("controller URL must start with https://")
	}
	return base, nil
}

func requestClusterJoin(client *http.Client, controllerURL string, payload map[string]string) (clusterJoinAPIResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return clusterJoinAPIResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, controllerURL+"/api/cluster/join", bytes.NewReader(body))
	if err != nil {
		return clusterJoinAPIResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return clusterJoinAPIResponse{}, fmt.Errorf("cluster join request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return clusterJoinAPIResponse{}, fmt.Errorf("read cluster join response: %w", err)
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return clusterJoinAPIResponse{}, fmt.Errorf("parse cluster join response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Error != nil && envelope.Error.Message != "" {
			return clusterJoinAPIResponse{}, fmt.Errorf("cluster join rejected: %s", envelope.Error.Message)
		}
		return clusterJoinAPIResponse{}, fmt.Errorf("cluster join rejected with status %d", resp.StatusCode)
	}
	var result clusterJoinAPIResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return clusterJoinAPIResponse{}, fmt.Errorf("parse cluster join data: %w", err)
	}
	if strings.TrimSpace(result.Certificates.CA) == "" || strings.TrimSpace(result.Certificates.Cert) == "" {
		return clusterJoinAPIResponse{}, fmt.Errorf("cluster join response is missing certificate material")
	}
	return result, nil
}

type clusterJoinPaths struct {
	CAFile   string
	CertFile string
	KeyFile  string
	backups  []clusterJoinFileBackup
}

type clusterJoinFileBackup struct {
	path   string
	exists bool
	data   []byte
	mode   os.FileMode
}

func writeClusterJoinFiles(result clusterJoinAPIResponse, opts clusterJoinOptions, localIdentity clusterJoinLocalIdentity) (clusterJoinPaths, error) {
	nodeID := strings.TrimSpace(result.NodeID)
	if nodeID == "" {
		return clusterJoinPaths{}, fmt.Errorf("join response missing node id")
	}
	dir := filepath.Join(dataDir, "cluster", "certs", safePathName(nodeID))
	paths := clusterJoinPaths{
		CAFile:   filepath.Join(dir, "ca.pem"),
		CertFile: filepath.Join(dir, "node.crt"),
		KeyFile:  filepath.Join(dir, "node.key"),
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return clusterJoinPaths{}, fmt.Errorf("create cluster cert directory: %w", err)
	}
	backups := make([]clusterJoinFileBackup, 0, 3)
	for _, path := range []string{paths.CAFile, paths.CertFile, paths.KeyFile} {
		backup, err := backupClusterJoinFile(path)
		if err != nil {
			return clusterJoinPaths{}, err
		}
		backups = append(backups, backup)
		if !opts.Force {
			if _, err := os.Stat(path); err == nil {
				return clusterJoinPaths{}, fmt.Errorf("%s already exists; use --force to overwrite", path)
			} else if !os.IsNotExist(err) {
				return clusterJoinPaths{}, err
			}
		}
	}
	wrote := false
	defer func() {
		if !wrote {
			restoreClusterJoinFiles(backups)
		}
	}()
	if err := os.WriteFile(paths.CAFile, []byte(result.Certificates.CA), 0o644); err != nil {
		return clusterJoinPaths{}, fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.WriteFile(paths.CertFile, []byte(result.Certificates.Cert), 0o644); err != nil {
		return clusterJoinPaths{}, fmt.Errorf("write node certificate: %w", err)
	}
	if len(localIdentity.KeyPEM) == 0 {
		return clusterJoinPaths{}, fmt.Errorf("local node private key is missing")
	}
	if err := os.WriteFile(paths.KeyFile, localIdentity.KeyPEM, 0o600); err != nil {
		return clusterJoinPaths{}, fmt.Errorf("write node private key: %w", err)
	}
	paths.backups = backups
	wrote = true
	return paths, nil
}

func backupClusterJoinFile(path string) (clusterJoinFileBackup, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return clusterJoinFileBackup{path: path}, nil
		}
		return clusterJoinFileBackup{}, err
	}
	if info.IsDir() {
		return clusterJoinFileBackup{}, fmt.Errorf("%s is a directory", path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return clusterJoinFileBackup{}, err
	}
	return clusterJoinFileBackup{path: path, exists: true, data: raw, mode: info.Mode().Perm()}, nil
}

func cleanupClusterJoinFiles(paths clusterJoinPaths) {
	if len(paths.backups) > 0 {
		restoreClusterJoinFiles(paths.backups)
		if strings.TrimSpace(paths.KeyFile) != "" {
			_ = os.Remove(filepath.Dir(paths.KeyFile))
		}
		return
	}
	restoreClusterJoinFiles([]clusterJoinFileBackup{
		{path: paths.KeyFile},
		{path: paths.CertFile},
		{path: paths.CAFile},
	})
	if strings.TrimSpace(paths.KeyFile) != "" {
		_ = os.Remove(filepath.Dir(paths.KeyFile))
	}
}

func restoreClusterJoinFiles(backups []clusterJoinFileBackup) {
	for i := len(backups) - 1; i >= 0; i-- {
		backup := backups[i]
		if strings.TrimSpace(backup.path) == "" {
			continue
		}
		if backup.exists {
			mode := backup.mode
			if mode == 0 {
				mode = 0o600
			}
			_ = os.WriteFile(backup.path, backup.data, mode)
			continue
		}
		_ = os.Remove(backup.path)
	}
}

func applyClusterJoinConfig(result clusterJoinAPIResponse, paths clusterJoinPaths) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	cfg.Deployment.Mode = "cluster"
	cfg.Cluster.Enabled = true
	cfg.Cluster.ClusterID = result.ClusterID
	cfg.Cluster.NodeID = result.NodeID
	if cfg.Cluster.HAMode == "" {
		cfg.Cluster.HAMode = "single-node"
	}
	listen := result.Listen
	if listen == "" {
		listen = result.Interconnect.Listen
	}
	if listen == "" {
		listen = result.AdvertiseAddr
	}
	cfg.Cluster.Interconnect.Listen = listen
	cfg.Cluster.Interconnect.AdvertiseAddr = result.AdvertiseAddr
	cfg.Cluster.Interconnect.MTLSRequired = true
	cfg.Cluster.Interconnect.CAFile = filepath.ToSlash(paths.CAFile)
	cfg.Cluster.Interconnect.CertFile = filepath.ToSlash(paths.CertFile)
	cfg.Cluster.Interconnect.KeyFile = filepath.ToSlash(paths.KeyFile)
	if cfg.Cluster.Consensus.Provider == "" {
		cfg.Cluster.Consensus.Provider = "builtin"
	}
	if cfg.Cluster.Join.TokenTTL == 0 {
		cfg.Cluster.Join.TokenTTL = config.Default().Cluster.Join.TokenTTL
	}
	found := false
	for idx := range cfg.Cluster.Nodes {
		if cfg.Cluster.Nodes[idx].ID != result.NodeID {
			continue
		}
		cfg.Cluster.Nodes[idx].Role = result.Role
		cfg.Cluster.Nodes[idx].AdvertiseAddr = result.AdvertiseAddr
		found = true
		break
	}
	if !found {
		cfg.Cluster.Nodes = append(cfg.Cluster.Nodes, config.ClusterNodeConfig{
			ID:            result.NodeID,
			Role:          result.Role,
			AdvertiseAddr: result.AdvertiseAddr,
		})
	}
	if err := config.Validate(cfg); err != nil {
		return err
	}
	return config.Save(configPath, cfg)
}

func safePathName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "node"
	}
	var b strings.Builder
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}
	return b.String()
}
