package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/spf13/cobra"
)

type clusterCertRotateOptions struct {
	ControllerURL      string
	APIToken           string
	APITokenFile       string
	APITokenEnv        string
	CAFile             string
	InsecureSkipVerify bool
	AllowInsecureHTTP  bool
}

type clusterCertRotateResponse struct {
	Certificates struct {
		CA   string `json:"ca"`
		Cert string `json:"cert"`
		Key  string `json:"key"`
	} `json:"certificates"`
	Node identity.NodeRegistration `json:"node"`
}

func newClusterCertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage local cluster certificates",
	}
	cmd.AddCommand(newClusterCertRotateCommand())
	return cmd
}

func newClusterCertRotateCommand() *cobra.Command {
	var opts clusterCertRotateOptions
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate this node's cluster certificate with a local private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClusterCertRotate(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.ControllerURL, "controller", "", "Controller admin URL, for example https://10.0.0.10:9443")
	cmd.Flags().StringVar(&opts.APIToken, "api-token", "", "Management API token with write:cluster permission. Prefer --api-token-file or --api-token-env in production")
	cmd.Flags().StringVar(&opts.APITokenFile, "api-token-file", "", "Read management API token from file")
	cmd.Flags().StringVar(&opts.APITokenEnv, "api-token-env", "", "Read management API token from environment variable")
	cmd.Flags().StringVar(&opts.CAFile, "ca-file", "", "Controller CA certificate file")
	cmd.Flags().BoolVar(&opts.InsecureSkipVerify, "insecure-skip-verify", false, "Skip controller TLS certificate verification")
	cmd.Flags().BoolVar(&opts.AllowInsecureHTTP, "allow-insecure-http", false, "Allow cleartext HTTP for isolated lab bootstrap only. API tokens are exposed on the network")
	_ = cmd.MarkFlagRequired("controller")
	return cmd
}

func runClusterCertRotate(cmd *cobra.Command, opts clusterCertRotateOptions) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if err := validateClusterCertRotateConfig(cfg); err != nil {
		return err
	}
	apiToken, err := resolveClusterAPIToken(opts)
	if err != nil {
		return err
	}
	controllerURL, err := validateClusterJoinControllerURL(opts.ControllerURL, opts.AllowInsecureHTTP)
	if err != nil {
		return err
	}
	localIdentity, err := generateClusterJoinLocalIdentity(clusterJoinOptions{
		NodeID: strings.TrimSpace(cfg.Cluster.NodeID),
		Role:   localClusterNodeRole(cfg),
	})
	if err != nil {
		return err
	}
	client, err := clusterJoinHTTPClient(clusterJoinOptions{
		CAFile:             opts.CAFile,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	})
	if err != nil {
		return err
	}
	result, err := requestClusterCertRotate(client, controllerURL, apiToken, cfg.Cluster.NodeID, string(localIdentity.CSRPEM))
	if err != nil {
		return err
	}
	nodeID := strings.TrimSpace(result.Node.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(cfg.Cluster.NodeID)
	}
	if err := validateClusterCertificateMaterial(result.Certificates.CA, result.Certificates.Cert, localIdentity.KeyPEM, nodeID); err != nil {
		return err
	}
	paths := clusterJoinPaths{
		CAFile:   filepath.Clean(cfg.Cluster.Interconnect.CAFile),
		CertFile: filepath.Clean(cfg.Cluster.Interconnect.CertFile),
		KeyFile:  filepath.Clean(cfg.Cluster.Interconnect.KeyFile),
	}
	backups, err := backupClusterCertFiles(paths)
	if err != nil {
		return err
	}
	paths.backups = backups
	wrote := false
	defer func() {
		if !wrote {
			restoreClusterJoinFiles(backups)
		}
	}()
	if err := writeClusterCertFiles(paths, result, localIdentity); err != nil {
		return err
	}
	wrote = true
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "已轮换节点证书: %s\n", result.Node.NodeID)
	fmt.Fprintf(out, "新证书序列号: %s\n", result.Node.CertificateSerial)
	fmt.Fprintf(out, "证书文件目录: %s\n", filepath.Dir(paths.CertFile))
	fmt.Fprintln(out, "请重启或重新加载 CheeseWAF，使新的集群互联证书生效。")
	return nil
}

func validateClusterCertRotateConfig(cfg *config.Config) error {
	if cfg == nil || !cfg.Cluster.Enabled {
		return fmt.Errorf("cluster mode is not enabled on this node")
	}
	if strings.TrimSpace(cfg.Cluster.NodeID) == "" {
		return fmt.Errorf("cluster node id is required")
	}
	if strings.TrimSpace(cfg.Cluster.Interconnect.CAFile) == "" ||
		strings.TrimSpace(cfg.Cluster.Interconnect.CertFile) == "" ||
		strings.TrimSpace(cfg.Cluster.Interconnect.KeyFile) == "" {
		return fmt.Errorf("cluster interconnect certificate paths are incomplete")
	}
	return nil
}

func localClusterNodeRole(cfg *config.Config) string {
	nodeID := strings.TrimSpace(cfg.Cluster.NodeID)
	for _, node := range cfg.Cluster.Nodes {
		if node.ID == nodeID && strings.TrimSpace(node.Role) != "" {
			return strings.TrimSpace(node.Role)
		}
	}
	return "waf"
}

func resolveClusterAPIToken(opts clusterCertRotateOptions) (string, error) {
	sources := 0
	token := strings.TrimSpace(opts.APIToken)
	if token != "" {
		sources++
	}
	if strings.TrimSpace(opts.APITokenFile) != "" {
		sources++
		raw, err := readTokenFile(opts.APITokenFile)
		if err != nil {
			return "", err
		}
		token = raw
	}
	if strings.TrimSpace(opts.APITokenEnv) != "" {
		sources++
		token = strings.TrimSpace(os.Getenv(opts.APITokenEnv))
	}
	if sources != 1 {
		return "", fmt.Errorf("provide exactly one of --api-token, --api-token-file, or --api-token-env")
	}
	if token == "" {
		return "", fmt.Errorf("management API token is empty")
	}
	return token, nil
}

func readTokenFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read management API token file: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func requestClusterCertRotate(client *http.Client, controllerURL string, apiToken string, nodeID string, csr string) (clusterCertRotateResponse, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return clusterCertRotateResponse{}, fmt.Errorf("cluster node id is required")
	}
	body, err := json.Marshal(map[string]string{"csr": csr})
	if err != nil {
		return clusterCertRotateResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, controllerURL+"/api/cluster/nodes/"+url.PathEscape(nodeID)+"/rotate-certificate", bytes.NewReader(body))
	if err != nil {
		return clusterCertRotateResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiToken)
	resp, err := client.Do(req)
	if err != nil {
		return clusterCertRotateResponse{}, fmt.Errorf("cluster certificate rotation request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return clusterCertRotateResponse{}, fmt.Errorf("read cluster certificate rotation response: %w", err)
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return clusterCertRotateResponse{}, fmt.Errorf("parse cluster certificate rotation response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if envelope.Error != nil && envelope.Error.Message != "" {
			return clusterCertRotateResponse{}, fmt.Errorf("cluster certificate rotation rejected: %s", envelope.Error.Message)
		}
		return clusterCertRotateResponse{}, fmt.Errorf("cluster certificate rotation rejected with status %d", resp.StatusCode)
	}
	var result clusterCertRotateResponse
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return clusterCertRotateResponse{}, fmt.Errorf("parse cluster certificate rotation data: %w", err)
	}
	if strings.TrimSpace(result.Certificates.CA) == "" || strings.TrimSpace(result.Certificates.Cert) == "" {
		return clusterCertRotateResponse{}, fmt.Errorf("cluster certificate rotation response is missing certificate material")
	}
	if strings.TrimSpace(result.Certificates.Key) != "" {
		return clusterCertRotateResponse{}, fmt.Errorf("cluster certificate rotation response unexpectedly included private key material")
	}
	return result, nil
}

func backupClusterCertFiles(paths clusterJoinPaths) ([]clusterJoinFileBackup, error) {
	if strings.TrimSpace(paths.CAFile) == "" || strings.TrimSpace(paths.CertFile) == "" || strings.TrimSpace(paths.KeyFile) == "" {
		return nil, fmt.Errorf("cluster certificate paths are incomplete")
	}
	backups := make([]clusterJoinFileBackup, 0, 3)
	for _, path := range []string{paths.CAFile, paths.CertFile, paths.KeyFile} {
		backup, err := backupClusterJoinFile(path)
		if err != nil {
			return nil, err
		}
		backups = append(backups, backup)
	}
	return backups, nil
}

func writeClusterCertFiles(paths clusterJoinPaths, result clusterCertRotateResponse, localIdentity clusterJoinLocalIdentity) error {
	if len(localIdentity.KeyPEM) == 0 {
		return fmt.Errorf("local node private key is missing")
	}
	for _, path := range []string{paths.CAFile, paths.CertFile, paths.KeyFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("create cluster certificate directory: %w", err)
		}
	}
	if err := os.WriteFile(paths.CAFile, []byte(result.Certificates.CA), 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	if err := os.WriteFile(paths.CertFile, []byte(result.Certificates.Cert), 0o644); err != nil {
		return fmt.Errorf("write node certificate: %w", err)
	}
	if err := os.WriteFile(paths.KeyFile, localIdentity.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write node private key: %w", err)
	}
	return nil
}
