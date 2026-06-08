package config

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var (
	serverNameRE = regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRE     = regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	proxyPassRE  = regexp.MustCompile(`^\s*proxy_pass\s+([^;]+);`)
	rewriteRE    = regexp.MustCompile(`^\s*rewrite\s+(\S+)\s+(\S+)(?:\s+\S+)?;`)
)

// ParseNginxServerBlock imports a practical subset of nginx server blocks:
// listen, server_name, proxy_pass, and rewrite directives.
func ParseNginxServerBlock(contents []byte) ([]SiteConfig, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	var sites []SiteConfig
	var current *SiteConfig
	var rewrites []RewriteRuleConfig
	locationDepth := 0
	for scanner.Scan() {
		line := stripNginxComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "server") && strings.Contains(line, "{") {
			current = &SiteConfig{Enabled: true, WAF: WAFConfig{Enabled: true, Mode: "block"}}
			rewrites = nil
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, "location") && strings.Contains(line, "{") {
			locationDepth++
			continue
		}
		if line == "}" {
			if locationDepth > 0 {
				locationDepth--
				continue
			}
			if current.Name == "" && len(current.Domains) > 0 {
				current.Name = current.Domains[0]
			}
			if current.ID == "" {
				current.ID = strings.ReplaceAll(current.Name, ".", "-")
			}
			if current.LoadBalance == "" {
				current.LoadBalance = "round_robin"
			}
			current.WAF.Rewrite = rewrites
			if len(current.Domains) > 0 || len(current.Upstreams) > 0 {
				sites = append(sites, *current)
			}
			current = nil
			continue
		}
		if match := serverNameRE.FindStringSubmatch(line); len(match) == 2 {
			current.Domains = strings.Fields(match[1])
			if len(current.Domains) > 0 {
				current.Name = current.Domains[0]
			}
			continue
		}
		if match := listenRE.FindStringSubmatch(line); len(match) == 2 {
			current.ListenPort = parseListenPort(match[1])
			continue
		}
		if match := proxyPassRE.FindStringSubmatch(line); len(match) == 2 {
			current.Upstreams = append(current.Upstreams, UpstreamConfig{Address: match[1], Weight: 1})
			continue
		}
		if match := rewriteRE.FindStringSubmatch(line); len(match) >= 3 {
			rewrites = append(rewrites, RewriteRuleConfig{
				ID:          fmt.Sprintf("nginx-rewrite-%d", len(rewrites)+1),
				Pattern:     match[1],
				Replacement: match[2],
				Enabled:     true,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

func stripNginxComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func parseListenPort(value string) int {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 80
	}
	item := fields[0]
	if strings.Contains(item, ":") {
		parts := strings.Split(item, ":")
		item = parts[len(parts)-1]
	}
	var port int
	_, _ = fmt.Sscanf(item, "%d", &port)
	if port == 0 {
		port = 80
	}
	return port
}
