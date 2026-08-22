package config

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	serverNameRE = regexp.MustCompile(`^\s*server_name\s+([^;]+);`)
	listenRE     = regexp.MustCompile(`^\s*listen\s+([^;]+);`)
	proxyPassRE  = regexp.MustCompile(`^\s*proxy_pass\s+([^;]+);`)
	rewriteRE    = regexp.MustCompile(`^\s*rewrite\s+(\S+)\s+(\S+)(?:\s+(last|break|redirect|permanent))?\s*;`)
)

const maxNginxScannerLineBytes = 4 << 20

// ParseNginxServerBlock imports a practical subset of nginx server blocks:
// listen, server_name, proxy_pass, and rewrite directives.
func ParseNginxServerBlock(contents []byte) ([]SiteConfig, error) {
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 64<<10), maxNginxScannerLineBytes)
	var sites []SiteConfig
	var current *SiteConfig
	var rewrites []RewriteRuleConfig
	blockDepth := 0
	finishServer := func() {
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
		blockDepth = 0
	}
	for scanner.Scan() {
		line := stripNginxComment(strings.TrimSpace(scanner.Text()))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "server") && strings.Contains(line, "{") {
			current = &SiteConfig{Enabled: true, WAF: WAFConfig{Enabled: true, Mode: "block"}}
			rewrites = nil
			blockDepth = nginxBlockDelta(line)
			continue
		}
		if current == nil {
			continue
		}
		blockDepth += nginxBlockDelta(line)
		if blockDepth <= 0 {
			finishServer()
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
			redirectCode := 0
			if len(match) >= 4 {
				switch match[3] {
				case "permanent":
					redirectCode = http.StatusMovedPermanently
				case "redirect":
					redirectCode = http.StatusFound
				}
			}
			rewrites = append(rewrites, RewriteRuleConfig{
				ID:          fmt.Sprintf("nginx-rewrite-%d", len(rewrites)+1),
				Pattern:     match[1],
				Replacement: match[2],
				RedirectCode: redirectCode,
				Enabled:     true,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sites, nil
}

func nginxBlockDelta(line string) int {
	delta := 0
	inQuote := byte(0)
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote != 0 && c == '\\' {
			escaped = true
			continue
		}
		if c == '\'' || c == '"' {
			if inQuote == 0 {
				inQuote = c
			} else if inQuote == c {
				inQuote = 0
			}
			continue
		}
		if inQuote != 0 || (c != '{' && c != '}') || !nginxStructuralBrace(line, i) {
			continue
		}
		if c == '{' {
			delta++
		} else {
			delta--
		}
	}
	return delta
}

func nginxStructuralBrace(line string, index int) bool {
	before := index == 0 || line[index-1] == ' ' || line[index-1] == '\t' || line[index-1] == ';'
	after := index+1 == len(line) || line[index+1] == ' ' || line[index+1] == '\t' || line[index+1] == ';'
	return before && after
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
