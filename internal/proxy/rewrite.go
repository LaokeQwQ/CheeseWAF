package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/config"
	"github.com/LaokeQwQ/CheeseWAF/internal/fsguard"
)

type RewriteRule struct {
	ID           string
	Pattern      *regexp.Regexp
	Replacement  string
	RedirectCode int
}

type Rewriter struct {
	rules []RewriteRule
}

func NewRewriter(items []config.RewriteRuleConfig) (*Rewriter, error) {
	rewriter := &Rewriter{}
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		pattern, err := regexp.Compile(item.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile rewrite %q: %w", item.ID, err)
		}
		rewriter.rules = append(rewriter.rules, RewriteRule{
			ID:           item.ID,
			Pattern:      pattern,
			Replacement:  item.Replacement,
			RedirectCode: item.RedirectCode,
		})
	}
	return rewriter, nil
}

func (r *Rewriter) Apply(req *http.Request) (redirect bool, code int) {
	if r == nil || req == nil {
		return false, 0
	}
	original := req.URL.Path
	for _, rule := range r.rules {
		if !rule.Pattern.MatchString(original) {
			continue
		}
		next := rule.Pattern.ReplaceAllString(original, rule.Replacement)
		// Rewrite/redirect targets must stay same-origin relative paths (no open redirects).
		safe := fsguard.SafeRelativeRedirect(next)
		pathPart := safe
		if q := strings.IndexByte(safe, '?'); q >= 0 {
			pathPart = safe[:q]
			// Only adopt query from replacement when the rule itself introduced one.
			if strings.Contains(next, "?") {
				req.URL.RawQuery = safe[q+1:]
			}
		}
		req.URL.Path = pathPart
		req.URL.RawPath = ""
		if rule.RedirectCode >= 300 && rule.RedirectCode < 400 {
			return true, rule.RedirectCode
		}
		return false, 0
	}
	return false, 0
}
