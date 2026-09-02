package proxy

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

func shouldRetryUpstream(err error, retrySafe bool) bool {
	if err == nil {
		return false
	}
	if isConnectionRefused(err) {
		return true
	}
	return retrySafe && isUpstreamConnectError(err)
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

func isUpstreamConnectError(err error) bool {
	if err == nil {
		return false
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"connection refused",
		"connection reset",
		"no such host",
		"i/o timeout",
		"network is unreachable",
		"broken pipe",
		"tls handshake timeout",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

func (s *Server) markUpstream(target *url.URL, healthy bool) {
	if s == nil || s.health == nil || target == nil {
		return
	}
	s.health.Set(upstreamKeyFromURL(target), healthy)
}
