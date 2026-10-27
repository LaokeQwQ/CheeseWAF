package semantic

import (
	"regexp"
	"strings"
)

var (
	lfiTraversalPattern         = regexp.MustCompile(`(?i)(?:\.\.[/\\])+`)
	lfiOverlongTraversalPattern = regexp.MustCompile(`(?i)(?:\.\.\.\.[/\\]{2,})+`)
	// lfiMatrixTraversalPattern matches Tomcat-style matrix segments. Servlet
	// containers strip path parameters (";jsessionid=…") before resolving a path,
	// so "..;/" reaches the filesystem as "../" without ever containing the
	// literal "../" sequence this file used to look for.
	//
	// The leading (?:^|[^.]) excludes prose ellipses: "...;/" contains the "..;"
	// substring, but what survives the container's strip is "...", not a parent
	// reference. Real payloads keep their leading boundary — "..;/etc/passwd" is
	// anchored by ^, and "/a/..;/b" by the "/" (a [^.] byte).
	lfiMatrixTraversalPattern   = regexp.MustCompile(`(?i)(?:^|[^.])(?:\.\.;[/\\])+`)
	lfiEncodedTraversalPattern  = regexp.MustCompile(`(?i)(?:%25)*(?:%2e){2,}(?:%25)*(?:%2f|%5c)|(?:\.\.(?:%25)*(?:%2f|%5c))|(?:%25)*%2e(?:%25)*%2e[/\\]|%c0%af|%25c0%25af`)
	lfiSensitiveAbsolutePattern = regexp.MustCompile(`(?i)(?:/etc/(?:passwd|shadow|group|hosts|hostname|fstab|sudoers|crontab|nginx/nginx\.conf|apache2/apache2\.conf|redis/redis\.conf|mysql/my\.cnf|php/php\.ini|ssh/sshd_config)|/proc/(?:self/(?:environ|cmdline|maps|fd/\d+)|version|cpuinfo)|boot\.ini|win\.ini|windows[/\\]win\.ini|winnt[/\\]system32[/\\]cmd\.exe)`)
	lfiWrapperPattern           = regexp.MustCompile(`(?i)(?:php|zip|data|file)://`)
	lfiWebMetadataPattern       = regexp.MustCompile(`(?i)(?:WEB-INF/web\.xml|META-INF/MANIFEST\.MF)`)
	lfiSensitiveRelativePattern = regexp.MustCompile(`(?i)(?:^|/|\b)(?:\.aws/credentials|\.git/config|\.env|\.htaccess|\.ssh/(?:id_rsa|id_dsa|authorized_keys)|wp-config(?:\.php)?|_config\.php|dump\.sql|database\.sql|config/(?:database|parameters|settings)\.(?:php|ya?ml|json)|WEB-INF/web\.xml|var/log/(?:syslog|auth\.log|nginx/access\.log|nginx/error\.log|apache2/access\.log|apache2/error\.log|httpd-access\.log)|var/run/secrets/kubernetes\.io/serviceaccount/(?:token|ca\.crt|namespace))(?:$|\b|%00|%23|\.)`)
	lfiPatterns                 = []*regexp.Regexp{
		lfiTraversalPattern,
		lfiOverlongTraversalPattern,
		lfiMatrixTraversalPattern,
		lfiEncodedTraversalPattern,
		lfiSensitiveAbsolutePattern,
		lfiWrapperPattern,
		lfiWebMetadataPattern,
		lfiSensitiveRelativePattern,
	}
)

const maxLFIFoldedViews = 64

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
	return securityDocumentContextWindowed(full, win) || technicalDocumentationContext(win)
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
	return securityDocumentContextWindowed(full, win) || technicalDocumentationContext(win)
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
	return securityDocumentContextWindowed(full, win) || technicalDocumentationContext(win)
}
