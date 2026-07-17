package proxy

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

var ErrNoUpstream = errors.New("no upstream available")

const maxSharedTransports = 16

var sharedTransports = struct {
	sync.Mutex
	items map[time.Duration]*http.Transport
	order []time.Duration
}{items: make(map[time.Duration]*http.Transport)}

func NewReverseProxy(target *url.URL, timeout time.Duration) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	proxy.Transport = transportForTimeout(timeout)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalHost := r.Host
		originalDirector(r)
		r.Host = target.Host
		if originalHost != "" {
			r.Header.Set("X-Forwarded-Host", originalHost)
		}
	}
	return proxy
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
