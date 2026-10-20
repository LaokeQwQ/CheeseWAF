package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/LaokeQwQ/CheeseWAF/internal/protection/bot"
	"github.com/LaokeQwQ/CheeseWAF/internal/proxytrust"
)

var ErrNoUpstream = errors.New("no upstream available")

const maxSharedTransports = 16

var sharedTransports = struct {
	sync.Mutex
	items map[time.Duration]*http.Transport
	order []time.Duration
}{items: make(map[time.Duration]*http.Transport)}

// Client-forged forwarding identity headers are stripped before rebuild.
var stripClientForwardHeaders = append([]string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Forwarded-Port",
	"X-Forwarded-Scheme",
	"X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override",
}, proxytrust.ProviderIdentityHeaders()...)

func NewReverseProxy(target *url.URL, timeout time.Duration) *httputil.ReverseProxy {
	return newReverseProxyWithOptions(target, timeout, "", reverseProxyOptions{})
}

// NewReverseProxyForClient rebuilds upstream forwarding headers from the
// client identity already validated by the proxy trust policy.
func NewReverseProxyForClient(target *url.URL, timeout time.Duration, clientIP string) *httputil.ReverseProxy {
	return newReverseProxyWithOptions(target, timeout, normalizedClientIP(clientIP), reverseProxyOptions{})
}

// NewReverseProxyForSite applies the site's origin transport and Host policy.
// Site configuration is kept separate from the request-facing forwarding
// identity so a saved per-site origin setting cannot be silently ignored.
func NewReverseProxyForSite(target *url.URL, timeout time.Duration, clientIP string, originScheme string, passHost bool, hostHeader string) *httputil.ReverseProxy {
	if target == nil {
		return newReverseProxyWithOptions(target, timeout, normalizedClientIP(clientIP), reverseProxyOptions{})
	}
	clone := *target
	if scheme := strings.ToLower(strings.TrimSpace(originScheme)); scheme == "http" || scheme == "https" {
		clone.Scheme = scheme
	}
	return newReverseProxyWithOptions(&clone, timeout, normalizedClientIP(clientIP), reverseProxyOptions{
		passHost:   passHost,
		hostHeader: strings.TrimSpace(hostHeader),
	})
}

type reverseProxyOptions struct {
	passHost   bool
	hostHeader string
}

func newReverseProxyWithOptions(target *url.URL, timeout time.Duration, trustedClientIP string, options reverseProxyOptions) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	proxy.Transport = transportForTimeout(timeout)
	proxy.Director = nil
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		r := pr.Out
		originalHost := pr.In.Host
		clientAddr := pr.In.RemoteAddr
		for _, h := range stripClientForwardHeaders {
			deleteHeaderAliases(r.Header, h)
		}
		pr.SetURL(target)
		switch {
		case options.hostHeader != "":
			r.Host = options.hostHeader
		case options.passHost:
			r.Host = originalHost
		default:
			r.Host = target.Host
		}
		if originalHost != "" {
			r.Header.Set("X-Forwarded-Host", originalHost)
		}
		ip := trustedClientIP
		if ip == "" {
			ip = peerIP(clientAddr)
		}
		if ip != "" {
			r.Header.Set("X-Forwarded-For", ip)
			r.Header.Set("X-Real-IP", ip)
		}
		if requestIsHTTPS(pr.In, bot.TrustedCIDRsFromContext(pr.In.Context())) {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Port", "443")
		} else {
			r.Header.Set("X-Forwarded-Proto", "http")
			r.Header.Set("X-Forwarded-Port", "80")
		}
	}
	return proxy
}

func deleteHeaderAliases(header http.Header, name string) {
	for key := range header {
		if strings.EqualFold(strings.ReplaceAll(key, "_", "-"), name) {
			delete(header, key)
		}
	}
}

func stripRoutingOverrideHeaders(header http.Header) {
	for _, name := range []string{"X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"} {
		deleteHeaderAliases(header, name)
	}
}

func normalizedClientIP(raw string) string {
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(raw), "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func peerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	if host == "" {
		return ""
	}
	// Forward only a parsed IP; reject hostnames or unparsed RemoteAddr values.
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.String()
	}
	return ""
}

func transportForTimeout(timeout time.Duration) *http.Transport {
	sharedTransports.Lock()
	defer sharedTransports.Unlock()
	if transport := sharedTransports.items[timeout]; transport != nil {
		return transport
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = timeout
	transport.DialContext = (&net.Dialer{Timeout: min(timeout, 10*time.Second), KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = min(timeout, 10*time.Second)
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(1024)}
	transport.IdleConnTimeout = 90 * time.Second
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = 64
	transport.MaxConnsPerHost = 128
	if len(sharedTransports.order) >= maxSharedTransports {
		oldest := sharedTransports.order[0]
		sharedTransports.order = sharedTransports.order[1:]
		if old := sharedTransports.items[oldest]; old != nil {
			old.CloseIdleConnections()
		}
		delete(sharedTransports.items, oldest)
	}
	sharedTransports.items[timeout] = transport
	sharedTransports.order = append(sharedTransports.order, timeout)
	return transport
}
