package netguard

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Resolver func(ctx context.Context, network, host string) ([]net.IP, error)

type URLPolicy struct {
	Purpose        string
	HostPurpose    string
	AllowedSchemes []string
	AllowPrivate   bool
	AllowUserInfo  bool
	AllowFragment  bool
}

type HTTPClientOptions struct {
	Timeout  time.Duration
	Resolver Resolver
	Policy   URLPolicy
}

var restrictedCIDRs = mustParseCIDRs(
	"100.64.0.0/10",
	"169.254.169.254/32",
	"169.254.170.2/32",
	"100.100.100.200/32",
	"fd00:ec2::254/128",
)

func ValidateURL(raw string, policy URLPolicy) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	schemes := policy.schemes()
	if _, ok := schemes[strings.ToLower(parsed.Scheme)]; !ok {
		return nil, fmt.Errorf("only %s %s URLs are allowed", schemeList(policy.schemesSlice()), policy.urlPurpose())
	}
	if parsed.User != nil && !policy.AllowUserInfo {
		return nil, fmt.Errorf("credentials in %s URL are not allowed", policy.urlPurpose())
	}
	if parsed.Fragment != "" && !policy.AllowFragment {
		return nil, fmt.Errorf("fragments in %s URL are not allowed", policy.urlPurpose())
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if !policy.AllowPrivate {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && !IsPublicIP(ip) {
			return nil, fmt.Errorf("%s host IP must be public", policy.hostPurpose())
		}
	}
	return parsed, nil
}

func NewRequest(ctx context.Context, method, rawURL string, body io.Reader, policy URLPolicy) (*http.Request, error) {
	parsed, err := ValidateURL(rawURL, policy)
	if err != nil {
		return nil, err
	}
	return http.NewRequestWithContext(ctx, method, parsed.String(), body)
}

func NewHTTPClient(opts HTTPClientOptions) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver.LookupIP
	}
	policy := opts.Policy
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSHandshakeTimeout = timeout
	transport.ResponseHeaderTimeout = timeout
	dialer := &net.Dialer{Timeout: timeout}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := resolveHost(ctx, resolver, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("%s host resolved to no IP addresses", policy.hostPurpose())
		}
		if !policy.AllowPrivate {
			for _, ip := range ips {
				if !IsPublicIP(ip) {
					return nil, fmt.Errorf("%s host resolved to non-public IP %s", policy.hostPurpose(), ip)
				}
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: validatingTransport{policy: policy, next: transport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if _, err := ValidateURL(req.URL.String(), policy); err != nil {
				return fmt.Errorf("blocked %s redirect: %w", policy.urlPurpose(), err)
			}
			return nil
		},
	}
}

type validatingTransport struct {
	policy URLPolicy
	next   http.RoundTripper
}

func (t validatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request URL is required")
	}
	if _, err := ValidateURL(req.URL.String(), t.policy); err != nil {
		return nil, err
	}
	return t.next.RoundTrip(req)
}

func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified() &&
		!inRestrictedCIDR(ip)
}

func resolveHost(ctx context.Context, resolver Resolver, host string) ([]net.IP, error) {
	trimmed := strings.Trim(host, "[]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return []net.IP{ip}, nil
	}
	return resolver(ctx, "ip", trimmed)
}

func (p URLPolicy) urlPurpose() string {
	if strings.TrimSpace(p.Purpose) == "" {
		return "remote"
	}
	return strings.TrimSpace(p.Purpose)
}

func (p URLPolicy) hostPurpose() string {
	if strings.TrimSpace(p.HostPurpose) != "" {
		return strings.TrimSpace(p.HostPurpose)
	}
	return p.urlPurpose()
}

func (p URLPolicy) schemes() map[string]struct{} {
	out := map[string]struct{}{}
	for _, scheme := range p.schemesSlice() {
		out[strings.ToLower(scheme)] = struct{}{}
	}
	return out
}

func (p URLPolicy) schemesSlice() []string {
	if len(p.AllowedSchemes) == 0 {
		return []string{"http", "https"}
	}
	out := make([]string, 0, len(p.AllowedSchemes))
	for _, scheme := range p.AllowedSchemes {
		trimmed := strings.ToLower(strings.TrimSpace(scheme))
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return []string{"http", "https"}
	}
	return out
}

func schemeList(schemes []string) string {
	if len(schemes) == 1 {
		return schemes[0]
	}
	if len(schemes) == 2 {
		return schemes[0] + " and " + schemes[1]
	}
	return strings.Join(schemes[:len(schemes)-1], ", ") + ", and " + schemes[len(schemes)-1]
}

func inRestrictedCIDR(ip net.IP) bool {
	for _, cidr := range restrictedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(values ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, cidr, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		out = append(out, cidr)
	}
	return out
}
