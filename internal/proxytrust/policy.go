package proxytrust

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

// Provider-specific client-IP headers are never trusted through the generic
// proxy CIDR list. Each provider must have its own CIDR binding in config.
type providerPolicy struct {
	name    string
	headers []string
}

var providerPolicies = []providerPolicy{
	{name: "cloudflare", headers: []string{"CF-Connecting-IP", "True-Client-IP"}},
	{name: "akamai", headers: []string{"True-Client-IP"}},
	{name: "fastly", headers: []string{"Fastly-Client-IP"}},
	{name: "fly", headers: []string{"Fly-Client-IP"}},
	{name: "digitalocean", headers: []string{"DO-Connecting-IP"}},
	{name: "aliyun", headers: []string{"Ali-CDN-Real-IP"}},
	{name: "generic-cdn", headers: []string{"CDN-Src-IP", "X-CDN-Src-IP"}},
	{name: "azure", headers: []string{"X-Azure-ClientIP"}},
	{name: "vercel", headers: []string{"X-Vercel-Forwarded-For"}},
	{name: "original-forwarded", headers: []string{"X-Original-Forwarded-For"}},
	{name: "nginx", headers: []string{"X-Real-IP"}},
	{name: "client-ip", headers: []string{"X-Client-IP"}},
	{name: "cluster", headers: []string{"X-Cluster-Client-IP"}},
	{name: "google-app-engine", headers: []string{"X-Appengine-User-IP"}},
}

// Policy is an immutable, request-safe trusted proxy policy. It contains
// parsed CIDRs so request processing does not repeatedly parse configuration.
type Policy struct {
	providers map[string][]netip.Prefix
	all       []netip.Prefix
	allCIDRs  []string
}

// Compile validates and compiles generic and provider-specific CIDRs.
func Compile(genericCIDRs []string, providerCIDRs map[string][]string) (*Policy, error) {
	p := &Policy{providers: make(map[string][]netip.Prefix)}
	for _, raw := range genericCIDRs {
		prefix, ok := parsePrefix(raw)
		if !ok {
			return nil, invalidCIDRError("trusted_cidrs", raw)
		}
		p.all = append(p.all, prefix)
		p.allCIDRs = append(p.allCIDRs, strings.TrimSpace(raw))
	}
	canonicalSeen := make(map[string]struct{}, len(providerCIDRs))
	for rawName, cidrs := range providerCIDRs {
		name, ok := CanonicalProvider(rawName)
		if !ok {
			return nil, errors.New("unknown trusted proxy provider: " + strings.TrimSpace(rawName))
		}
		if _, exists := canonicalSeen[name]; exists {
			return nil, errors.New("duplicate trusted proxy provider: " + name)
		}
		canonicalSeen[name] = struct{}{}
		compiled := make([]netip.Prefix, 0, len(cidrs))
		for _, raw := range cidrs {
			prefix, valid := parsePrefix(raw)
			if !valid {
				return nil, invalidCIDRError("trusted_proxy_providers."+name, raw)
			}
			compiled = append(compiled, prefix)
			p.all = append(p.all, prefix)
			p.allCIDRs = append(p.allCIDRs, strings.TrimSpace(raw))
		}
		p.providers[name] = compiled
	}
	return p, nil
}

func invalidCIDRError(scope, raw string) error {
	return errors.New(scope + " contains invalid IP or CIDR: " + strings.TrimSpace(raw))
}

// SupportedProviders returns canonical provider names in deterministic order.
func SupportedProviders() []string {
	out := make([]string, 0, len(providerPolicies))
	for _, policy := range providerPolicies {
		out = append(out, policy.name)
	}
	return out
}

// ProviderIdentityHeaders returns every provider-specific identity header.
// Callers that proxy requests onward use this list to prevent identity headers
// from being reinterpreted by an upstream trust boundary.
func ProviderIdentityHeaders() []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(providerPolicies))
	for _, policy := range providerPolicies {
		for _, header := range policy.headers {
			canonical := http.CanonicalHeaderKey(header)
			if _, exists := seen[canonical]; exists {
				continue
			}
			seen[canonical] = struct{}{}
			out = append(out, canonical)
		}
	}
	return out
}

// CanonicalProvider normalizes a provider name and reports whether it is
// supported. Names are intentionally explicit; generic CIDRs cannot enable
// any provider implicitly.
func CanonicalProvider(raw string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(raw))
	for _, policy := range providerPolicies {
		if name == policy.name {
			return policy.name, true
		}
	}
	return "", false
}

// AllTrustedCIDRs returns a defensive copy of generic and provider-bound CIDRs.
// It is used by other trusted-proxy decisions such as X-Forwarded-Proto.
func (p *Policy) AllTrustedCIDRs() []string {
	if p == nil || len(p.allCIDRs) == 0 {
		return []string{}
	}
	return append([]string(nil), p.allCIDRs...)
}

// IsTrustedRemoteAddr reports whether a socket peer is covered by any generic
// or explicitly bound provider CIDR.
func (p *Policy) IsTrustedRemoteAddr(remoteAddr string) bool {
	if p == nil {
		return false
	}
	addr, ok := parseRemoteAddr(remoteAddr)
	if !ok {
		return false
	}
	return p.isTrusted(addr)
}

// ClientIP resolves the client address while keeping provider-specific headers
// scoped to the provider whose CIDRs match the socket peer.
func (p *Policy) ClientIP(r *http.Request) string {
	remote := remoteAddrIP(r)
	if p == nil || r == nil {
		return remote
	}
	remoteAddr, ok := parseRemoteAddr(remote)
	if !ok || !p.isTrusted(remoteAddr) {
		return remote
	}
	if ip := p.forwardedFor(strings.Join(r.Header.Values("X-Forwarded-For"), ",")); ip != "" {
		return ip
	}
	if ip := p.forwardedFor(strings.Join(forwardedHeaderValues(strings.Join(r.Header.Values("Forwarded"), ",")), ",")); ip != "" {
		return ip
	}
	for _, provider := range providerPolicies {
		cidrs, configured := p.providers[provider.name]
		if !configured || !containsAny(cidrs, remoteAddr) {
			continue
		}
		for _, header := range provider.headers {
			if ip := firstHeaderIP(strings.Join(r.Header.Values(header), ",")); ip != "" {
				return ip
			}
		}
	}
	return remote
}

func (p *Policy) isTrusted(addr netip.Addr) bool {
	return containsAny(p.all, addr)
}

func (p *Policy) forwardedFor(value string) string {
	parts := splitHeaderList(value, ',')
	var first string
	for i := len(parts) - 1; i >= 0; i-- {
		ip := parseHeaderIP(parts[i])
		if ip == "" {
			continue
		}
		first = ip
		addr, err := netip.ParseAddr(ip)
		if err != nil || !p.isTrusted(addr) {
			return ip
		}
	}
	return first
}

func containsAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePrefix(raw string) (netip.Prefix, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), true
	}
	return netip.PrefixFrom(addr, 128), true
}

func parseRemoteAddr(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	} else {
		raw = strings.Trim(raw, "[]")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func remoteAddrIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if addr, ok := parseRemoteAddr(r.RemoteAddr); ok {
		return addr.String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func firstHeaderIP(value string) string {
	for _, part := range splitHeaderList(value, ',') {
		if ip := parseHeaderIP(part); ip != "" {
			return ip
		}
	}
	return ""
}

func parseHeaderIP(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if raw == "" || strings.EqualFold(raw, "unknown") {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	} else {
		raw = strings.Trim(raw, "[]")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return addr.Unmap().String()
}

func forwardedHeaderValues(raw string) []string {
	values := make([]string, 0)
	for _, item := range splitHeaderList(raw, ',') {
		for _, part := range splitHeaderList(item, ';') {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			values = append(values, strings.TrimSpace(value))
		}
	}
	return values
}

// splitHeaderList splits a comma/semicolon separated header while preserving
// separators inside quoted values and handling escaped quotes.
func splitHeaderList(raw string, separator byte) []string {
	parts := make([]string, 0, 4)
	start := 0
	inQuote := false
	escaped := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && c == separator {
			parts = append(parts, raw[start:i])
			start = i + 1
		}
	}
	parts = append(parts, raw[start:])
	return parts
}

// ProviderNamesSorted is useful for deterministic validation errors and docs.
func ProviderNamesSorted() []string {
	names := SupportedProviders()
	sort.Strings(names)
	return names
}
