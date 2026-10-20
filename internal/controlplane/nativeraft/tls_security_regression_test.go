package nativeraft

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/cluster/identity"
	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/hashicorp/raft"
)

func securityTLSConfig(t *testing.T, service *identity.MemoryIdentityService, nodeID string) (*tls.Config, TLSOptions) {
	t.Helper()
	bundle, err := service.IssueNodeCertificateBundle(identity.NodeIdentity{NodeID: nodeID, Role: "waf", ClusterID: "cluster-a", AdvertiseAddr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	paths := TLSOptions{CAFile: filepath.Join(dir, "ca.pem"), CertFile: filepath.Join(dir, "cert.pem"), KeyFile: filepath.Join(dir, "key.pem")}
	for path, contents := range map[string][]byte{paths.CAFile: bundle.CAPEM, paths.CertFile: bundle.CertPEM, paths.KeyFile: bundle.KeyPEM} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := loadTLSConfig(&paths, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	return config, paths
}

func securityIdentityService(t *testing.T) *identity.MemoryIdentityService {
	t.Helper()
	service, err := identity.NewMemoryIdentityService(identity.ServiceOptions{ClusterID: "cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func securityTransport(t *testing.T, config *tls.Config, bindings *peerBindings) (*raft.NetworkTransport, *raftStreamLayer) {
	t.Helper()
	layer, err := newTLSStreamLayer("127.0.0.1:0", config, bindings)
	if err != nil {
		t.Fatal(err)
	}
	transport := raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{Stream: layer, Timeout: time.Second})
	t.Cleanup(func() { _ = transport.Close() })
	return transport, layer
}

func securityClient(t *testing.T, config *tls.Config, address string) *tls.Conn {
	t.Helper()
	config = config.Clone()
	config.ServerName = "node-a"
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	return conn
}

func writeSecurityRPC(t *testing.T, conn net.Conn, kind byte, request any) {
	t.Helper()
	if _, err := conn.Write([]byte{kind}); err != nil {
		t.Fatal(err)
	}
	if err := codec.NewEncoder(conn, &codec.MsgpackHandle{}).Encode(request); err != nil {
		t.Fatal(err)
	}
}

func TestTLSRejectsNonVoterRPCBeforeDispatch(t *testing.T) {
	service := securityIdentityService(t)
	serverConfig, _ := securityTLSConfig(t, service, "node-a")
	clientConfig, _ := securityTLSConfig(t, service, "monitor")
	bindings := newPeerBindings()
	bindings.bind("127.0.0.1:9001", "node-b")
	transport, layer := securityTransport(t, serverConfig, bindings)
	conn := securityClient(t, clientConfig, layer.Addr().String())
	request := &raft.AppendEntriesRequest{RPCHeader: raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte("node-b"), Addr: []byte("127.0.0.1:9001")}, Term: 100, PrevLogEntry: 1}
	// A rejected TLS handshake can report its alert on the first application write.
	_, _ = conn.Write([]byte{0})
	_ = codec.NewEncoder(conn, &codec.MsgpackHandle{}).Encode(request)
	select {
	case rpc := <-transport.Consumer():
		rpc.Respond(nil, nil)
		t.Fatal("non-voter certificate dispatched a forged voter RPC")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTLSChecksEveryRPCIdentityOnPooledConnection(t *testing.T) {
	service := securityIdentityService(t)
	serverConfig, _ := securityTLSConfig(t, service, "node-a")
	clientConfig, _ := securityTLSConfig(t, service, "node-b")
	bindings := newPeerBindings()
	bindings.bind("127.0.0.1:9001", "node-b")
	bindings.bind("127.0.0.1:9002", "node-c")
	transport, layer := securityTransport(t, serverConfig, bindings)
	conn := securityClient(t, clientConfig, layer.Addr().String())
	header := raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte("node-b"), Addr: []byte("127.0.0.1:9001")}
	writeSecurityRPC(t, conn, 0, &raft.AppendEntriesRequest{RPCHeader: header, Term: 1, PrevLogEntry: 1})
	select {
	case rpc := <-transport.Consumer():
		rpc.Respond(&raft.AppendEntriesResponse{Success: true}, nil)
	case <-time.After(time.Second):
		t.Fatal("legitimate voter RPC was not dispatched")
	}
	decoder := codec.NewDecoder(bufio.NewReader(conn), &codec.MsgpackHandle{})
	var rpcErr string
	var response raft.AppendEntriesResponse
	if err := decoder.Decode(&rpcErr); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	header.ID, header.Addr = []byte("node-c"), []byte("127.0.0.1:9002")
	writeSecurityRPC(t, conn, 3, &raft.TimeoutNowRequest{RPCHeader: header})
	select {
	case rpc := <-transport.Consumer():
		rpc.Respond(nil, nil)
		t.Fatal("pooled TLS connection dispatched an RPC impersonating another voter")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestTLSSlowHandshakeDoesNotBlockLegitimatePeer(t *testing.T) {
	service := securityIdentityService(t)
	serverConfig, _ := securityTLSConfig(t, service, "node-a")
	clientConfig, _ := securityTLSConfig(t, service, "node-b")
	bindings := newPeerBindings()
	bindings.bind("127.0.0.1:9001", "node-b")
	transport, layer := securityTransport(t, serverConfig, bindings)
	slow, err := net.Dial("tcp", layer.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	clientConfig = clientConfig.Clone()
	clientConfig.ServerName = "node-a"
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 300 * time.Millisecond}, "tcp", layer.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("legitimate peer blocked behind half-open TLS handshake: %v", err)
	}
	defer conn.Close()
	writeSecurityRPC(t, conn, 3, &raft.TimeoutNowRequest{RPCHeader: raft.RPCHeader{ID: []byte("node-b"), Addr: []byte("127.0.0.1:9001")}})
	select {
	case rpc := <-transport.Consumer():
		rpc.Respond(&raft.TimeoutNowResponse{}, nil)
	case <-time.After(time.Second):
		t.Fatal("legitimate peer RPC blocked")
	}
}

func TestTLSDialTimeoutIncludesHandshake(t *testing.T) {
	service := securityIdentityService(t)
	config, _ := securityTLSConfig(t, service, "node-a")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	bindings := newPeerBindings()
	bindings.bind(listener.Addr().String(), "node-b")
	layer := &raftStreamLayer{tlsConfig: config, bindings: bindings}
	finished := make(chan error, 1)
	go func() {
		conn, err := layer.Dial(raft.ServerAddress(listener.Addr().String()), 50*time.Millisecond)
		if conn != nil {
			_ = conn.Close()
		}
		finished <- err
	}()
	conn := <-accepted
	defer conn.Close()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("blackhole TLS server accepted")
		}
	case <-time.After(250 * time.Millisecond):
		_ = conn.Close()
		<-finished
		t.Fatal("TLS handshake exceeded Dial timeout")
	}
}

func TestTLSJoinRequiresTrustedInitialVoter(t *testing.T) {
	service := securityIdentityService(t)
	_, paths := securityTLSConfig(t, service, "node-b")
	node, err := New(Options{Profile: "production", ClusterID: "cluster-a", NodeID: "node-b", DataDir: t.TempDir(), BindAddress: "127.0.0.1:0", Mode: ModeJoin, TLS: &paths})
	if node != nil {
		_ = node.Close()
	}
	if err == nil {
		t.Fatal("fresh TLS join trusted any certificate from the shared CA without a configured voter")
	}
}

// Keep the imports used by the snapshot stream regression added with framing.
var _ = context.Background
var _ = io.EOF
