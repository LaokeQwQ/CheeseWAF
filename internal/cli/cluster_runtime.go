package cli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster"
	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/timekeeper"
)

func initializeClusterRuntime(cfg *config.Config, clock timekeeper.Clock) (*identity.MemoryIdentityService, *cluster.HeartbeatRegistry, error) {
	if cfg == nil || !cfg.Cluster.Enabled {
		return nil, nil, nil
	}
	if err := config.ValidateClusterConsensus(cfg); err != nil {
		return nil, nil, fmt.Errorf("initialize cluster consensus: %w", err)
	}
	if clock == nil {
		clock = timekeeper.SystemClock{}
	}
	clusterID := strings.TrimSpace(cfg.Cluster.ClusterID)
	if clusterID == "" {
		clusterID = "cheesewaf-local"
	}
	baseDir := strings.TrimSpace(cfg.Setup.DataDir)
	if baseDir == "" {
		baseDir = dataDir
	}
	identityService, err := identity.NewMemoryIdentityService(identity.ServiceOptions{
		ClusterID: clusterID,
		StatePath: filepath.Join(baseDir, "cluster", "identity.json"),
		Clock:     clock,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("initialize cluster identity: %w", err)
	}
	heartbeats := cluster.NewHeartbeatRegistry(cluster.HeartbeatRegistryOptions{Now: clock.Now})
	return identityService, heartbeats, nil
}

func newClusterInterconnectServer(cfg *config.Config, next http.Handler, identityService *identity.MemoryIdentityService) (*http.Server, error) {
	if cfg == nil || !cfg.Cluster.Enabled || strings.TrimSpace(cfg.Cluster.Interconnect.Listen) == "" {
		return nil, nil
	}
	if next == nil {
		return nil, fmt.Errorf("cluster interconnect handler is unavailable")
	}
	tlsConfig, err := clusterInterconnectTLSConfig(cfg, identityService)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              strings.TrimSpace(cfg.Cluster.Interconnect.Listen),
		Handler:           clusterInterconnectRoutes(next),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: cfg.Server.ReadTimeout,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}, nil
}

func clusterInterconnectTLSConfig(cfg *config.Config, identityService *identity.MemoryIdentityService) (*tls.Config, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cluster configuration is unavailable")
	}
	if !cfg.Cluster.Interconnect.MTLSRequired {
		return nil, fmt.Errorf("cluster interconnect must require mTLS")
	}

	interconnect := cfg.Cluster.Interconnect
	caFile := strings.TrimSpace(interconnect.CAFile)
	certFile := strings.TrimSpace(interconnect.CertFile)
	keyFile := strings.TrimSpace(interconnect.KeyFile)
	hasMaterial := caFile != "" || certFile != "" || keyFile != ""
	var (
		certificate tls.Certificate
		caPEM       []byte
		err         error
	)
	if hasMaterial {
		if caFile == "" || certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("cluster interconnect ca_file, cert_file and key_file must be set together")
		}
		certificate, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load cluster interconnect certificate: %w", err)
		}
		caPEM, err = os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("load cluster interconnect CA: %w", err)
		}
	} else {
		if identityService == nil {
			return nil, fmt.Errorf("cluster identity is unavailable")
		}
		localIdentity, err := localClusterInterconnectIdentity(cfg)
		if err != nil {
			return nil, err
		}
		bundle, err := identityService.IssueNodeCertificateBundle(localIdentity)
		if err != nil {
			return nil, fmt.Errorf("issue local cluster interconnect certificate: %w", err)
		}
		certificate, err = tls.X509KeyPair(bundle.CertPEM, bundle.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("load generated cluster interconnect certificate: %w", err)
		}
		caPEM = bundle.CAPEM
	}

	clientCAs := x509.NewCertPool()
	if len(caPEM) == 0 || !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("cluster interconnect CA contains no valid certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}, nil
}

func localClusterInterconnectIdentity(cfg *config.Config) (identity.NodeIdentity, error) {
	nodeID := strings.TrimSpace(cfg.Cluster.NodeID)
	advertiseAddr := strings.TrimSpace(cfg.Cluster.Interconnect.AdvertiseAddr)
	clusterID := strings.TrimSpace(cfg.Cluster.ClusterID)
	if clusterID == "" {
		clusterID = "cheesewaf-local"
	}
	if nodeID == "" {
		return identity.NodeIdentity{}, fmt.Errorf("cluster node_id is required for the interconnect server")
	}
	if advertiseAddr == "" {
		return identity.NodeIdentity{}, fmt.Errorf("cluster interconnect advertise_addr is required")
	}
	role := "waf"
	for _, node := range cfg.Cluster.Nodes {
		if strings.TrimSpace(node.ID) == nodeID && strings.TrimSpace(node.Role) != "" {
			role = strings.TrimSpace(node.Role)
			break
		}
	}
	return identity.NodeIdentity{
		NodeID:        nodeID,
		Role:          role,
		ClusterID:     clusterID,
		AdvertiseAddr: advertiseAddr,
	}, nil
}

func clusterInterconnectRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		path := r.URL.Path
		allowed := r.Method == http.MethodGet && path == "/health/cluster"
		if r.Method == http.MethodPost && strings.HasPrefix(path, "/api/cluster/nodes/") && strings.HasSuffix(path, "/heartbeat") {
			nodeID := strings.TrimSuffix(strings.TrimPrefix(path, "/api/cluster/nodes/"), "/heartbeat")
			allowed = nodeID != "" && !strings.Contains(nodeID, "/")
		}
		if !allowed {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
