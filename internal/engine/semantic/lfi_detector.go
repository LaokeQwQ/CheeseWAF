package semantic

import (
	"context"
	"regexp"
	"strings"

	"github.com/LaokeQwQ/CheeseWAF/internal/engine"
	"github.com/LaokeQwQ/CheeseWAF/internal/engine/decoder"
)

var lfiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:\.\.[/\\])+`),
	regexp.MustCompile(`(?i)(?:\.\.\.\.[/\\]{2,})+`),
	// Encoded traversal only — bare %2f/%5c are normal URL encoding and must not match.
	regexp.MustCompile(`(?i)(?:%25)*(?:%2e){2,}(?:%25)*(?:%2f|%5c)|(?:\.\.(?:%25)*(?:%2f|%5c))|(?:%25)*%2e(?:%25)*%2e[/\\]|%c0%af|%25c0%25af`),
	regexp.MustCompile(`(?i)(?:/etc/(?:passwd|shadow|group|hosts|hostname|fstab|sudoers|crontab|nginx/nginx\.conf|apache2/apache2\.conf|redis/redis\.conf|mysql/my\.cnf|php/php\.ini|ssh/sshd_config)|/proc/(?:self/(?:environ|cmdline|maps|fd/\d+)|version|cpuinfo)|boot\.ini|win\.ini|windows[/\\]win\.ini|winnt[/\\]system32[/\\]cmd\.exe)`),
	regexp.MustCompile(`(?i)(?:php|zip|data|file)://`),
	regexp.MustCompile(`(?i)(?:WEB-INF/web\.xml|META-INF/MANIFEST\.MF)`),
	regexp.MustCompile(`(?i)(?:^|/|\b)(?:\.aws/credentials|\.git/config|\.env|\.htaccess|\.ssh/(?:id_rsa|id_dsa|authorized_keys)|wp-config(?:\.php)?|_config\.php|dump\.sql|database\.sql|config/(?:database|parameters|settings)\.(?:php|ya?ml|json)|WEB-INF/web\.xml|var/log/(?:syslog|auth\.log|nginx/access\.log|nginx/error\.log|apache2/access\.log|apache2/error\.log|httpd-access\.log)|var/run/secrets/kubernetes\.io/serviceaccount/(?:token|ca\.crt|namespace))(?:$|\b|%00|%23|\.)`),
}

type LFIDetector struct {
	mode string
}

func NewLFIDetector(mode string) *LFIDetector {
	if mode == "" {
		mode = "block"
	}
	return &LFIDetector{mode: mode}
}

func (d *LFIDetector) ID() string    { return "semantic.lfi" }
func (d *LFIDetector) Name() string  { return "Local File Inclusion Semantic Detector" }
func (d *LFIDetector) Priority() int { return 330 }

func (d *LFIDetector) Detect(_ context.Context, reqCtx *engine.RequestContext) (*engine.DetectionResult, error) {
	payload := requestText(reqCtx)
	// Keep control boundaries in the decoded view. The historical decoder
	// strips NULs, which turns documentation such as c%00at /etc/passwd into a
	// real-looking `cat` command before the path matcher runs.
	candidates := []string{payload, decoder.DecodeWithDepthPreserveControls(payload, decoder.DefaultDecodeDepth).Text}
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		views := []string{trimmed}
		if lfiUnicodeSeparatorCandidate(trimmed, "", "") && !standaloneLFIUnicodeDocumentationContext(trimmed) {
			if folded, ok := foldLFIUnicodeSeparators(trimmed); ok && folded != trimmed {
				views = append(views, folded)
			}
		}
		// Standalone detection has no parsed field name. The raw-only gate still
		// permits the high-confidence NUL+sensitive-target shape while refusing
		// ordinary SQL hexadecimal constants.
		if lfiHexPathEscapeCandidate(trimmed, "", "") {
			// Evaluate each qualifying cluster locally. A documentation example at
			// the beginning of a long body must not suppress a later executable
			// cluster in the same candidate.
			for _, escapeRange := range lfiHexPathEscapeClusters(trimmed) {
				if standaloneLFIHexDocumentationContextAt(trimmed, escapeRange) {
					continue
				}
				if folded, ok := foldLFIHexPathEscapeRange(trimmed, escapeRange); ok && folded != trimmed {
					views = append(views, folded)
				}
			}
		}
		for _, view := range views {
			// A Server Side Includes directive is already an executable file/
			// command sink.  The standalone detector cannot rely on a parsed
			// field name, so keep the signature local and apply the same
			// documentation suppression used by the folded LFI paths below.
			lowerView := strings.ToLower(view)
			if matches := lfiSSIDirective.FindAllStringIndex(lowerView, -1); len(matches) > 0 {
				for _, match := range matches {
					if standaloneLFISSIDocumentationContextAt(view, match[0], match[1]) {
						continue
					}
					return &engine.DetectionResult{
						Detected:   true,
						DetectorID: d.ID(),
						Category:   "lfi",
						Severity:   engine.SeverityHigh,
						Action:     actionForMode(d.mode),
						Message:    "server-side include directive matched",
						Confidence: 0.86,
						Payload:    trimmed,
					}, nil
				}
			}
			controlBoundary := lfiNullByteInternalBoundary(view)
			pathSuffix := lfiNullBytePathSuffixShape(view)
			for index, pattern := range lfiPatterns {
				if controlBoundary && !pathSuffix && (index == 3 || index == 6) {
					continue
				}
				if pattern.MatchString(view) {
					return &engine.DetectionResult{
						Detected:   true,
						DetectorID: d.ID(),
						Category:   "lfi",
						Severity:   engine.SeverityHigh,
						Action:     actionForMode(d.mode),
						Message:    "local file inclusion pattern matched",
						Confidence: 0.86,
						Payload:    trimmed,
					}, nil
				}
			}
			if pathSuffix {
				return &engine.DetectionResult{
					Detected:   true,
					DetectorID: d.ID(),
					Category:   "lfi",
					Severity:   engine.SeverityHigh,
					Action:     actionForMode(d.mode),
					Message:    "local file inclusion null-byte suffix matched",
					Confidence: 0.86,
					Payload:    trimmed,
				}, nil
			}
		}
	}
	return nil, nil
}

func standaloneLFIHexDocumentationContextAt(full string, escapeRange lfiHexEscapeRange) bool {
	lo := escapeRange.start - evidenceNeighbourhoodRadius
	if lo < 0 {
		lo = 0
	}
	hi := escapeRange.end + evidenceNeighbourhoodRadius
	if hi > len(full) {
		hi = len(full)
	}
	win := full[lo:hi]
	return securityDocumentContextWindowed(win, win) || technicalDocumentationContext(win)
}

func standaloneLFISSIDocumentationContextAt(full string, start, end int) bool {
	lo := start - evidenceNeighbourhoodRadius
	if lo < 0 {
		lo = 0
	}
	hi := end + evidenceNeighbourhoodRadius
	if hi > len(full) {
		hi = len(full)
	}
	win := full[lo:hi]
	return securityDocumentContextWindowed(win, win) || technicalDocumentationContext(win)
}

func standaloneLFIUnicodeDocumentationContext(full string) bool {
	index := strings.Index(full, "%u2216")
	if index < 0 {
		index = strings.Index(full, "%U2216")
	}
	if index < 0 {
		return false
	}
	lo := index - evidenceNeighbourhoodRadius
	if lo < 0 {
		lo = 0
	}
	hi := index + len("%u2216") + evidenceNeighbourhoodRadius
	if hi > len(full) {
		hi = len(full)
	}
	win := full[lo:hi]
	return securityDocumentContextWindowed(win, win) || technicalDocumentationContext(win)
}
