package deploy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type staticTargetResolver struct {
	answers map[string][]netip.Addr
	calls   []string
}

type rebindingTargetResolver struct {
	answers [][]netip.Addr
	calls   int
}

func (r *rebindingTargetResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	index := r.calls
	r.calls++
	if index >= len(r.answers) {
		index = len(r.answers) - 1
	}
	return append([]netip.Addr(nil), r.answers[index]...), nil
}

func (r *staticTargetResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.calls = append(r.calls, network+":"+host)
	addresses, ok := r.answers[host]
	if !ok {
		return nil, fmt.Errorf("host not found")
	}
	return append([]netip.Addr(nil), addresses...), nil
}

func TestSSHRunnerRejectsUnsafeLiteralTargetsByDefault(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{name: "unspecified IPv4", host: "0.0.0.0"},
		{name: "loopback IPv4", host: "127.0.0.1"},
		{name: "RFC1918 10/8", host: "10.10.0.4"},
		{name: "RFC1918 172.16/12", host: "172.20.0.4"},
		{name: "RFC1918 192.168/16", host: "192.168.1.4"},
		{name: "carrier grade NAT", host: "100.64.0.1"},
		{name: "link local metadata", host: "169.254.169.254"},
		{name: "multicast IPv4", host: "224.0.0.1"},
		{name: "reserved IPv4", host: "240.0.0.1"},
		{name: "documentation IPv4", host: "192.0.2.1"},
		{name: "AS112 protocol assignment", host: "192.31.196.1"},
		{name: "AMT protocol assignment", host: "192.52.193.1"},
		{name: "unspecified IPv6", host: "::"},
		{name: "loopback IPv6", host: "::1"},
		{name: "IPv6 unique local", host: "fd00::1"},
		{name: "IPv6 link local", host: "fe80::1"},
		{name: "IPv6 multicast", host: "ff02::1"},
		{name: "documentation IPv6", host: "2001:db8::1"},
		{name: "IPv6 local translation", host: "64:ff9b:1::1"},
		{name: "IPv6 6to4", host: "2002::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewSSHRunner(SSHRunnerOptions{})
			if _, err := runner.resolveTarget(context.Background(), tt.host); err == nil {
				t.Fatalf("unsafe target %s was accepted", tt.host)
			}
		})
	}
}

func TestSSHRunnerRejectsHostnameWhenAnyResolvedAddressIsUnsafe(t *testing.T) {
	resolver := &staticTargetResolver{answers: map[string][]netip.Addr{
		"localhost":                {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
		"metadata.google.internal": {netip.MustParseAddr("169.254.169.254")},
		"mixed.example.com":        {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.7")},
	}}
	runner := NewSSHRunner(SSHRunnerOptions{Resolver: resolver})

	for _, host := range []string{"localhost", "metadata.google.internal", "mixed.example.com"} {
		t.Run(host, func(t *testing.T) {
			if _, err := runner.resolveTarget(context.Background(), host); err == nil {
				t.Fatalf("hostname %s with unsafe DNS answer was accepted", host)
			}
		})
	}
}

func TestSSHRunnerAllowsPublicTargetsAndNormalizesResolvedSet(t *testing.T) {
	resolver := &staticTargetResolver{answers: map[string][]netip.Addr{
		"public.example.com": {
			netip.MustParseAddr("2001:4860:4860::8888"),
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.8.8"),
		},
	}}
	runner := NewSSHRunner(SSHRunnerOptions{Resolver: resolver})

	got, err := runner.resolveTarget(context.Background(), " Public.Example.com. ")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8", "2001:4860:4860::8888"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolved addresses = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(resolver.calls, []string{"ip:public.example.com"}) {
		t.Fatalf("resolver calls = %v", resolver.calls)
	}

	literal, err := runner.resolveTarget(context.Background(), "8.8.4.4")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(literal, []string{"8.8.4.4"}) {
		t.Fatalf("literal addresses = %v", literal)
	}
}

func TestSSHRunnerPrivateTargetOptInIsNarrow(t *testing.T) {
	runner := NewSSHRunner(SSHRunnerOptions{AllowPrivateTargets: true})
	for _, host := range []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1"} {
		if got, err := runner.resolveTarget(context.Background(), host); err != nil || len(got) != 1 {
			t.Fatalf("private target %s rejected with opt-in: %v, %v", host, got, err)
		}
	}
	for _, host := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.1", "::1", "fe80::1", "ff02::1"} {
		if _, err := runner.resolveTarget(context.Background(), host); err == nil || !strings.Contains(err.Error(), "not permitted") {
			t.Fatalf("non-private unsafe target %s accepted with opt-in: %v", host, err)
		}
	}
}

func TestSSHDeployDialsPrecheckedNumericAddressWithoutDNSReresolution(t *testing.T) {
	server := startTestSSHServer(t, testSSHServerOptions{Password: "secret", Output: "ok\n"})
	resolver := &rebindingTargetResolver{answers: [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8")},
		{netip.MustParseAddr("10.0.0.9")},
	}}
	var dialed []string
	runner := NewSSHRunner(SSHRunnerOptions{
		Resolver: resolver,
		Timeout:  5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(server.host, fmt.Sprint(server.port)))
		},
	})
	req := SSHDeploymentRequest{
		Host:          "node.example.com",
		User:          "root",
		Port:          server.port,
		Password:      "secret",
		HostKeySHA256: ssh.FingerprintSHA256(server.hostKey.PublicKey()),
	}
	checked, err := runner.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(checked.ResolvedIPs, []string{"8.8.8.8"}) {
		t.Fatalf("precheck binding = %v", checked.ResolvedIPs)
	}
	req.Action = actionRestartService
	req.ResolvedIPs = checked.ResolvedIPs
	if _, err := runner.Deploy(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver called %d times, want exactly one precheck lookup", resolver.calls)
	}
	wantDial := net.JoinHostPort("8.8.8.8", fmt.Sprint(server.port))
	if !reflect.DeepEqual(dialed, []string{wantDial, wantDial}) {
		t.Fatalf("dialed addresses = %v, want prechecked numeric address for both connections", dialed)
	}
}

func TestSSHDeployRejectsMissingOrForgedAddressBinding(t *testing.T) {
	var dialed bool
	runner := NewSSHRunner(SSHRunnerOptions{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, fmt.Errorf("unexpected dial")
		},
	})
	req := SSHDeploymentRequest{Host: "node.example.com", User: "root", Port: 22, HostKeySHA256: "SHA256:abc", Action: actionRestartService}
	if _, err := runner.Deploy(context.Background(), req); err == nil || !strings.Contains(err.Error(), "precheck address binding") {
		t.Fatalf("missing binding error = %v", err)
	}
	req.ResolvedIPs = []string{"10.0.0.9"}
	if _, err := runner.Deploy(context.Background(), req); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("forged private binding error = %v", err)
	}
	if dialed {
		t.Fatal("invalid binding reached the network dialer")
	}
}
