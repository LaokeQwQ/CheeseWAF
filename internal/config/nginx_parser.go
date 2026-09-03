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
		if current == nil && strings.HasPrefix(line, "server") {
			if blocks := nginxInlineServerBlocks(line); len(blocks) > 0 {
				for _, block := range blocks {
					current = &SiteConfig{Enabled: true, WAF: WAFConfig{Enabled: true, Mode: "block"}}
					rewrites = nil
					parseNginxInlineServer(block, current, &rewrites)
					finishServer()
				}
				continue
			}
		}
		if strings.HasPrefix(line, "server") && strings.Contains(line, "{") {
			current = &SiteConfig{Enabled: true, WAF: WAFConfig{Enabled: true, Mode: "block"}}
			rewrites = nil
			blockDepth = nginxBlockDelta(line)
			if blockDepth <= 0 {
				parseNginxInlineServer(line, current, &rewrites)
				finishServer()
			}
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
				ID:           fmt.Sprintf("nginx-rewrite-%d", len(rewrites)+1),
				Pattern:      match[1],
				Replacement:  match[2],
				RedirectCode: redirectCode,
				Enabled:      true,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if current != nil {
		finishServer()
	}
	return sites, nil
}

// parseNginxInlineServer handles compact server blocks such as
// `server { listen 8080; server_name example.test; proxy_pass http://up; }`.
// The normal directive regexes are intentionally line-anchored, so use
// boundary-aware searches here rather than dropping the whole one-line block.
func parseNginxInlineServer(line string, current *SiteConfig, rewrites *[]RewriteRuleConfig) {
	if current == nil {
		return
	}
	inner := line
	if start := strings.IndexByte(inner, '{'); start >= 0 {
		inner = inner[start+1:]
	}
	if end := strings.LastIndexByte(inner, '}'); end >= 0 {
		inner = inner[:end]
	}
	for _, statement := range nginxInlineDirectiveStatements(inner) {
		statement = strings.TrimSpace(statement)
		for len(statement) > 0 && (statement[0] == '}' || statement[0] == '{') {
			statement = strings.TrimSpace(statement[1:])
		}
		if idx := nginxLastStructuralBrace(statement); idx >= 0 {
			statement = strings.TrimSpace(statement[idx+1:])
		}
		statement += ";"
		if match := serverNameRE.FindStringSubmatch(statement); len(match) == 2 {
			current.Domains = strings.Fields(match[1])
			if len(current.Domains) > 0 {
				current.Name = current.Domains[0]
			}
			continue
		}
		if match := listenRE.FindStringSubmatch(statement); len(match) == 2 {
			current.ListenPort = parseListenPort(match[1])
			continue
		}
		if match := proxyPassRE.FindStringSubmatch(statement); len(match) == 2 {
			current.Upstreams = append(current.Upstreams, UpstreamConfig{Address: strings.TrimSpace(match[1]), Weight: 1})
			continue
		}
		if match := rewriteRE.FindStringSubmatch(statement); len(match) >= 3 {
			redirectCode := 0
			if len(match) >= 4 {
				switch match[3] {
				case "permanent":
					redirectCode = http.StatusMovedPermanently
				case "redirect":
					redirectCode = http.StatusFound
				}
			}
			*rewrites = append(*rewrites, RewriteRuleConfig{ID: fmt.Sprintf("nginx-rewrite-%d", len(*rewrites)+1), Pattern: match[1], Replacement: match[2], RedirectCode: redirectCode, Enabled: true})
		}
	}
}

func nginxInlineDirectiveStatements(inner string) []string {
	var out []string
	start := 0
	inQuote := byte(0)
	escaped := false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote != 0 {
			if c == '\\' {
				escaped = true
			} else if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == ';' {
			out = append(out, inner[start:i])
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(inner[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

func nginxLastStructuralBrace(statement string) int {
	last := -1
	inQuote := byte(0)
	escaped := false
	for i := 0; i < len(statement); i++ {
		c := statement[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote != 0 {
			if c == '\\' {
				escaped = true
			} else if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == '{' && nginxStructuralBrace(statement, i) {
			last = i
		}
	}
	return last
}

func nginxInlineServerBlocks(line string) []string {
	var blocks []string
	for offset := 0; offset < len(line); {
		start, ok := nginxNextServerToken(line, offset)
		if !ok {
			break
		}
		open, ok := nginxNextStructuralBrace(line, start+len("server"))
		if !ok {
			break
		}
		depth := 0
		inQuote := byte(0)
		escaped := false
		closed := false
		for i := open; i < len(line); i++ {
			c := line[i]
			if escaped {
				escaped = false
				continue
			}
			if inQuote != 0 {
				if c == '\\' {
					escaped = true
				} else if c == inQuote {
					inQuote = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				inQuote = c
				continue
			}
			if (c != '{' && c != '}') || !nginxStructuralBrace(line, i) {
				continue
			}
			if c == '{' {
				depth++
			} else {
				depth--
				if depth == 0 {
					blocks = append(blocks, line[start:i+1])
					offset = i + 1
					closed = true
					break
				}
			}
		}
		if !closed {
			break
		}
	}
	return blocks
}

func nginxNextServerToken(line string, offset int) (int, bool) {
	inQuote := byte(0)
	escaped := false
	for i := offset; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote != 0 {
			if c == '\\' {
				escaped = true
			} else if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if !strings.HasPrefix(line[i:], "server") {
			continue
		}
		if i > 0 {
			prev := line[i-1]
			if prev == '_' || prev == '-' || prev >= 'a' && prev <= 'z' || prev >= 'A' && prev <= 'Z' {
				continue
			}
		}
		if end := i + len("server"); end < len(line) && line[end] != ' ' && line[end] != '\t' && line[end] != '{' {
			continue
		}
		return i, true
	}
	return 0, false
}

func nginxNextStructuralBrace(line string, offset int) (int, bool) {
	inQuote := byte(0)
	escaped := false
	for i := offset; i < len(line); i++ {
		c := line[i]
		if escaped {
			escaped = false
			continue
		}
		if inQuote != 0 {
			if c == '\\' {
				escaped = true
			} else if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			inQuote = c
			continue
		}
		if c == '{' && nginxStructuralBrace(line, i) {
			return i, true
		}
	}
	return 0, false
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
