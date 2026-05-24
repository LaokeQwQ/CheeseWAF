package proxy

import (
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

var ErrNoUpstream = errors.New("no upstream available")

func NewReverseProxy(target *url.URL, timeout time.Duration) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	proxy.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
	}
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		originalDirector(r)
		r.Host = target.Host
		r.Header.Set("X-Forwarded-Host", r.Host)
	}
	return proxy
}
