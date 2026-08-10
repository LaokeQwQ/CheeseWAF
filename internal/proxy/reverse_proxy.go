package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

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
}, proxytrust.ProviderIdentityHeaders()...)

func NewReverseProxy(target *url.URL, timeout time.Duration) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	proxy.Transport = transportForTimeout(timeout)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalHost := r.Host
		clientAddr := r.RemoteAddr
		for _, h := range stripClientForwardHeaders {
			r.Header.Del(h)
		}
		originalDirector(r)
		r.Host = target.Host
		if originalHost != "" {
			r.Header.Set("X-Forwarded-Host", originalHost)
		}
		if ip := peerIP(clientAddr); ip != "" {
			r.Header.Set("X-Forwarded-For", ip)
			r.Header.Set("X-Real-IP", ip)
		}
		if r.TLS != nil {
			r.Header.Set("X-Forwarded-Proto", "https")
		} else {
			r.Header.Set("X-Forwarded-Proto", "http")
		}
	}
	return proxy
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
