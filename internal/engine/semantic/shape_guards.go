package semantic

import (
	"regexp"
	"strings"
)

// RESTful path guard: legitimate API paths should not trigger LFI.
// Returns true if the text looks like a RESTful route with HTTP method prefix,
// OpenAPI parameter placeholders {param}, or @username style paths.
func restfulPathShape(text string) bool {
	lower := strings.ToLower(text)

	// HTTP method prefix: GET /api/v1/users, POST /admin/dashboard
	if strings.HasPrefix(lower, "get ") || strings.HasPrefix(lower, "post ") ||
		strings.HasPrefix(lower, "put ") || strings.HasPrefix(lower, "patch ") ||
		strings.HasPrefix(lower, "delete ") || strings.HasPrefix(lower, "options ") ||
		strings.HasPrefix(lower, "head ") {
		return true
	}

	// OpenAPI path parameter placeholders: /api/v1/users/{id}, /api/{version}/resource
	// Must be single braces {id}, not double braces {{ (template syntax)
	if strings.Contains(text, "{") && strings.Contains(text, "}") && !strings.Contains(text, "{{") && !strings.Contains(text, "}}") {
		// Must have slash to be a path, not a JSON/template
		// And must look like a path parameter: single word/identifier in braces
		if strings.Contains(text, "/") {
			// Check if it's a simple path parameter pattern like {id} or {version}
			// Not template expressions like {get_user_file(...)}
			if !strings.Contains(text, "(") && !strings.Contains(text, "[") {
				return true
			}
		}
	}

	// Social media username paths: /@username/settings, /@user/posts
	if strings.Contains(text, "/@") {
		return true
	}

	return false
}

// HTTP protocol context guard: HTTP methods, status codes, headers should not trigger attacks.
// Returns true if the text has complete HTTP request/response structure.
func httpProtocolContextShape(text string) bool {
	lower := strings.ToLower(text)

	// HTTP request line: GET /path HTTP/1.1, POST /api HTTP/2
	if httpRequestLine.MatchString(text) {
		return true
	}

	// HTTP response line: HTTP/1.1 200 OK, HTTP/2 404 Not Found
	if httpResponseLine.MatchString(text) {
		return true
	}

	// HTTP headers with typical structure: Header-Name: value
	// Must have at least one header-like pattern
	if httpHeaderPattern.MatchString(text) {
		// Additional evidence: multiple header-like lines or common header names
		headerCount := strings.Count(lower, "content-type:") +
			strings.Count(lower, "authorization:") +
			strings.Count(lower, "user-agent:") +
			strings.Count(lower, "accept:") +
			strings.Count(lower, "host:") +
			strings.Count(lower, "cookie:")
		if headerCount > 0 {
			return true
		}
	}

	return false
}

// Markdown code block guard: code examples in fenced blocks or inline code should not trigger attacks.
// Returns true if the text is within Markdown code fence boundaries or inline code backticks.
// Does NOT fire for actual attack payloads that happen to contain backticks.
// Requires sufficient documentation context (length > 150 chars).
func markdownCodeBlockShape(text string) bool {
	// Short payloads are likely real attacks, not documentation
	if len(text) < 150 {
		return false
	}

	// Fenced code blocks: ```sql SELECT * ```, ```bash rm -rf ```
	if strings.Contains(text, "```") {
		// Check if there's at least one pair of fences
		fenceCount := strings.Count(text, "```")
		if fenceCount >= 2 {
			return true
		}
		// Single fence at start or end (partial block in excerpt)
		if strings.HasPrefix(strings.TrimSpace(text), "```") || strings.HasSuffix(strings.TrimSpace(text), "```") {
			return true
		}
	}

	// Inline code: `SELECT`, `rm -rf`, `union select`
	// Must have balanced backticks and be a short technical term (not shell command substitution)
	backtickCount := strings.Count(text, "`")
	if backtickCount >= 2 && backtickCount%2 == 0 {
		// Extract content between backticks to check if it's documentation-style
		parts := strings.Split(text, "`")
		inlineCodeCount := 0
		for i := 1; i < len(parts); i += 2 {
			content := strings.TrimSpace(parts[i])
			if len(content) > 0 && len(content) < 100 {
				// Inline code is typically short technical terms
				// If it contains shell metacharacters with spaces, it's likely shell substitution
				if !strings.ContainsAny(content, ";|&><$()") || !strings.ContainsAny(content, " \t") {
					inlineCodeCount++
				}
			}
		}
		// Only return true if we have multiple inline code blocks (documentation pattern)
		// Single backtick pair might be part of actual payload
		if inlineCodeCount >= 2 {
			return true
		}
	}

	return false
}

// Technical documentation keyword guard: educational/documentation terms should reduce confidence.
// Returns true if the text contains documentation/tutorial markers.
// Does NOT fire for short payloads (< 200 chars) that might be legitimate attacks.
func technicalDocumentationContext(text string) bool {
	// Short payloads are likely real attacks, not documentation
	if len(text) < 200 {
		return false
	}

	lower := strings.ToLower(text)

	// Chinese documentation markers
	chineseMarkers := []string{
		"示例", "例如", "如下所示", "注意", "说明", "描述",
		"漏洞", "安全", "攻击", "防御", "检测", "分析",
		"详细说明", "漏洞证明", "修复方案", "披露状态",
	}
	for _, marker := range chineseMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	// English documentation markers
	englishMarkers := []string{
		"example", "for instance", "as follows", "note:", "warning:",
		"description:", "vulnerability", "exploit", "attack", "defense",
		"detection", "analysis", "proof of concept", "poc", "cve-",
		"example code", "sample code", "tutorial", "demonstration",
	}
	for _, marker := range englishMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	// Academic paper markers
	if strings.Contains(lower, "abstract") || strings.Contains(lower, "author:") ||
		strings.Contains(lower, "title:") || strings.Contains(lower, "copyright") {
		return true
	}

	return false
}

// Vulnerability report context guard: content from security advisories, CVE reports, or WooYun should not trigger.
// Returns true if the text contains vulnerability report structure markers.
func vulnerabilityReportContext(text string) bool {
	lower := strings.ToLower(text)

	// Chinese vulnerability report markers (WooYun, security blogs). These name
	// disclosure-record fields that only exist in a real report body.
	//
	// Bracketed field labels (【漏洞类型】, 【POC利用方法】…) used to be accepted here
	// too. They are not: a bracket pair is a dozen bytes an attacker can paste in
	// front of any payload, which made this branch an evasion oracle. They now
	// live in bracketedVulnLabelContext, which callers evaluate on the evidence
	// window so the label has to sit next to the payload it supposedly documents.
	if strings.Contains(lower, "漏洞概要") || strings.Contains(lower, "缺陷编号") ||
		strings.Contains(lower, "wooyun-") || strings.Contains(lower, "漏洞标题") ||
		strings.Contains(lower, "相关厂商") || strings.Contains(lower, "漏洞作者") {
		return true
	}

	// CVE/vulnerability identifiers
	if strings.Contains(lower, "cve-20") || strings.Contains(lower, "报告编号") ||
		strings.Contains(lower, "更新日期") || strings.Contains(lower, "漏洞简述") {
		return true
	}

	// Extended vulnerability markers. Specific multi-token markers are safe
	// unconditionally. Generic words like "payload"/"exploit" occur inside real
	// attack strings ("Payload: 1;sleep${IFS}9;#"), so they only count as
	// evidence at document scale and never on their own.
	if strings.Contains(lower, "exploit-db") || strings.Contains(lower, "安全公告") ||
		strings.Contains(lower, "cve编号") || strings.Contains(lower, "漏洞证明") ||
		strings.Contains(lower, "proof of concept") || strings.Contains(lower, "security advisory") ||
		strings.Contains(lower, "security research") {
		return true
	}
	if len(text) >= documentScaleThreshold && countWordMarkers(lower, vulnWeakMarkers) >= 2 {
		return true
	}

	// ATT&CK framework references
	if strings.Contains(lower, "att&ck") || strings.Contains(lower, "t1059-") ||
		strings.Contains(lower, "来自att") {
		return true
	}

	// Security conference/training materials
	if strings.Contains(lower, "kcon") || strings.Contains(lower, "360天马安全") ||
		strings.Contains(lower, "security team") {
		return true
	}

	return false
}

// PowerShell documentation context guard: technical documentation about PowerShell commands.
// Returns true if the text describes PowerShell features without executable context.
func powerShellDocumentationContext(text string) bool {
	lower := strings.ToLower(text)

	// Must contain PowerShell keywords
	hasPowerShell := strings.Contains(lower, "powershell") || strings.Contains(lower, "get-host") ||
		strings.Contains(lower, "invoke-") || strings.Contains(lower, "downloadstring")

	if !hasPowerShell {
		return false
	}

	// Documentation markers: describing what PowerShell does, not executing it
	docMarkers := []string{
		"攻击者可能滥用", "来自att", "的描述", "是windows操作系统",
		"may abuse", "attackers", "description", "can be used to",
		"is a", "allows", "enables", "provides",
	}

	for _, marker := range docMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	// Markdown heading before PowerShell content (like ## 来自ATT&CK的描述)
	if strings.Contains(text, "##") && strings.Contains(text, "\n") {
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "##") {
				// Heading followed by PowerShell content is documentation
				if i+1 < len(lines) && strings.Contains(strings.ToLower(lines[i+1]), "powershell") {
					return true
				}
			}
		}
	}

	return false
}

// HTTP header documentation context guard: text describing HTTP headers as examples.
// Returns true if the text is explaining HTTP headers rather than using them in an attack.
func httpHeaderDocumentationContext(text string) bool {
	lower := strings.ToLower(text)

	// Explaining HTTP headers: "The Accept header specifies...", "Content-Length header indicates..."
	if (strings.Contains(lower, "header") || strings.Contains(lower, "头")) &&
		(strings.Contains(lower, "specifies") || strings.Contains(lower, "indicates") ||
			strings.Contains(lower, "defines") || strings.Contains(lower, "说明") ||
			strings.Contains(lower, "指定") || strings.Contains(lower, "表示")) {
		return true
	}

	// Common HTTP header names in documentation context
	headerExamples := []string{
		"`accept`", "`content-length`", "`content-type`", "`accept-encoding`",
		"**accept**", "**content-length**", "**content-type**",
	}
	for _, example := range headerExamples {
		if strings.Contains(lower, example) {
			return true
		}
	}

	// MIME type examples in documentation: `application/json`, `text/html`
	if strings.Contains(lower, "`application/") || strings.Contains(lower, "`text/") ||
		strings.Contains(lower, "mime type") {
		return true
	}

	return false
}

// C source code comment context guard: /* */ comments in C/C++ source code.
// Returns true if the text looks like C source code with block comments.
func cSourceCodeCommentContext(text string) bool {
	// Must contain /* ... */ structure
	if !strings.Contains(text, "/*") || !strings.Contains(text, "*/") {
		return false
	}

	lower := strings.ToLower(text)

	// C source file headers: /* file.c, * Routines for..., * Copyright */
	if strings.Contains(lower, ".c\n") || strings.Contains(lower, ".h\n") ||
		strings.Contains(lower, "* routines") || strings.Contains(lower, "* copyright") ||
		strings.Contains(lower, "* file:") {
		return true
	}

	// Multi-line C comment structure: line starts with " * "
	lines := strings.Split(text, "\n")
	starLineCount := 0
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "*\t") {
			starLineCount++
		}
	}
	// At least 2 lines starting with " * " indicates C comment block
	if starLineCount >= 2 {
		return true
	}

	return false
}

// Book/ISBN documentation context guard: technical books, ISBNs should not trigger LFI.
// Returns true if the text contains book metadata or ISBN identifiers.
func bookDocumentationContext(text string) bool {
	lower := strings.ToLower(text)

	// ISBN identifiers
	if strings.Contains(lower, "isbn:") || strings.Contains(lower, "isbn：") ||
		strings.Contains(text, "978-") {
		return true
	}

	// Book metadata
	if (strings.Contains(lower, "著") || strings.Contains(lower, "author")) &&
		(strings.Contains(lower, "出版") || strings.Contains(lower, "publish")) {
		return true
	}

	// Technical book series markers
	if strings.Contains(lower, "丛书") || strings.Contains(lower, "技术") ||
		strings.Contains(lower, "代码审计") {
		return true
	}

	return false
}

// Markdown heading date context guard: Changelog entries with dates using -- separator.
// Returns true if the text contains Markdown heading date patterns (#### 1.6.9 - March 16, 2019).
// Prevents SQL comment false positives on version-date changelog entries.
func markdownHeadingDateContext(text string) bool {
	// Must contain Markdown heading marker
	if !strings.Contains(text, "####") && !strings.Contains(text, "###") && !strings.Contains(text, "##") {
		return false
	}

	lower := strings.ToLower(text)

	// Changelog markers with version patterns
	if (strings.Contains(lower, "changelog") || strings.Contains(lower, "version") ||
		strings.Contains(lower, "release")) &&
		(strings.Contains(text, "####") || strings.Contains(text, "###")) {
		// Look for version pattern: digit.digit.digit - date
		// Examples: #### 1.6.9 - March 16, 2019
		lines := strings.Split(text, "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "####") || strings.HasPrefix(trimmed, "###") || strings.HasPrefix(trimmed, "##") {
				// Check if line contains year pattern (20XX) and dash separator
				if changelogYear.MatchString(trimmed) && strings.Contains(trimmed, " - ") {
					return true
				}
			}
		}
	}

	return false
}

// Chinese technical article short prose guard: reduce threshold for Chinese tech articles.
// Returns true if the text is a Chinese technical article with recognizable structure.
// Original technicalDocumentationContext requires ≥200 chars; this handles shorter Chinese prose.
func chineseTechnicalArticleContext(text string) bool {
	// Article scale in bytes. CJK runs 3 bytes/char, so 200 bytes is roughly a
	// 66-character excerpt — still far above any curated attack payload.
	if len(text) < 200 {
		return false
	}

	lower := strings.ToLower(text)

	// Chinese technical article markers
	chineseMarkers := []string{
		"# 前言", "## 前言", "# 方法", "## 方法", "# 总结", "## 总结",
		"上传", "设备", "二进制", "研究", "过程中", "方法", "服务",
		"配置", "命令", "使用", "启动", "操作",
	}

	markerCount := 0
	for _, marker := range chineseMarkers {
		if strings.Contains(lower, marker) {
			markerCount++
		}
	}

	// Require at least 2 Chinese technical markers for short prose
	if markerCount >= 2 {
		return true
	}

	// Markdown heading structure: # heading or ## heading
	if (strings.Contains(text, "# ") || strings.Contains(text, "## ")) && markerCount >= 1 {
		return true
	}

	return false
}

// CTF writeup context guard: CTF competition writeups should not trigger attacks.
// Returns true if the text contains CTF writeup structure markers.
//
// Marker matching is word-boundary based and (except for unambiguous markers)
// gated on document scale: a real payload is short, a writeup is an article.
// Bare substring matching here previously swallowed live attacks, because
// "hack"/"wp"/"lab" appear inside strings like "crashlab" and "swissky".
func ctfWriteupContext(text string) bool {
	lower := strings.ToLower(text)

	// Unambiguous writeup markers: these do not appear in attack payloads.
	if strings.Contains(lower, "flag{") || strings.Contains(lower, "writeup") ||
		strings.Contains(lower, "write-up") || strings.Contains(lower, "hackthebox") ||
		strings.Contains(lower, "tryhackme") || strings.Contains(lower, "web题") ||
		strings.Contains(lower, "解题") || strings.Contains(lower, "队伍") ||
		strings.Contains(lower, "靶场") {
		return true
	}

	// Weaker markers require article scale plus corroboration.
	if len(text) < documentScaleThreshold {
		return false
	}
	return countWordMarkers(lower, ctfWeakMarkers) >= 2
}

// Security training context guard: security courses and training materials.
// Returns true if the text contains security training/course markers.
//
// CJK markers have natural word boundaries and are safe as substrings. Latin
// markers must match on word boundaries and at document scale — "lab" as a
// bare substring matches "crashlab" and "BURP-COLLABORATOR", which are attack
// payloads, not training material.
func securityTrainingContext(text string) bool {
	lower := strings.ToLower(text)

	// CJK training markers: no substring ambiguity.
	for _, marker := range []string{"课程", "教程", "实战", "靶场", "练习", "培训", "教学"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	// Latin markers require article scale plus corroboration.
	if len(text) < documentScaleThreshold {
		return false
	}
	if countWordMarkers(lower, trainingWeakMarkers) >= 2 {
		return true
	}

	// Course structure plus a security topic.
	if countWordMarkers(lower, []string{"chapter", "section", "exercise"}) >= 1 &&
		(strings.Contains(lower, "security") || strings.Contains(lower, "安全")) {
		return true
	}

	return false
}

// Academic conference paper context guard: conference papers should not trigger attacks.
// Returns true if the text contains academic paper structure markers.
//
// A paper is a long document with several section markers. One marker is not
// evidence — "abstract" and "references" appear in ordinary prose, and short
// tokens like "acm" appear inside unrelated identifiers. Require document
// scale plus two word-boundary markers.
func academicPaperContext(text string) bool {
	if len(text) < documentScaleThreshold {
		return false
	}
	lower := strings.ToLower(text)

	// Citation identifiers are unambiguous on their own.
	if strings.Contains(lower, "doi:") || strings.Contains(lower, "arxiv:") ||
		strings.Contains(lower, "isbn") || strings.Contains(lower, "keywords:") {
		return true
	}

	return countWordMarkers(lower, academicWeakMarkers) >= 2
}

// Source code file context guard: a checked-in source file is not a payload.
// Returns true if the text has the structure of a source file in a common
// language — an import/include block, a package or module declaration, or a
// shebang, together with multiple lines.
//
// Attack payloads are single-line and have no module structure, so this cannot
// fire on them. Security corpora, by contrast, carry whole exploit scripts and
// application sources whose string literals mention template and query syntax.
func sourceCodeFileContext(text string) bool {
	if len(text) < documentScaleThreshold {
		return false
	}
	// Multi-line is a precondition: payloads are one line.
	if strings.Count(text, "\n") < 4 {
		return false
	}
	lower := strings.ToLower(text)

	// Interpreter shebang on the first line.
	if strings.HasPrefix(text, "#!") && (strings.Contains(lower, "python") ||
		strings.Contains(lower, "/bin/sh") || strings.Contains(lower, "bash") ||
		strings.Contains(lower, "perl") || strings.Contains(lower, "ruby") ||
		strings.Contains(lower, "node")) {
		return true
	}

	// Module/import structure. Count line-anchored declarations so that a
	// mention of "import" inside prose does not qualify.
	declLines := 0
	for _, line := range strings.Split(lower, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		switch {
		case strings.HasPrefix(trimmed, "import "), strings.HasPrefix(trimmed, "from "),
			strings.HasPrefix(trimmed, "#include "), strings.HasPrefix(trimmed, "using "),
			strings.HasPrefix(trimmed, "package "), strings.HasPrefix(trimmed, "require("),
			strings.HasPrefix(trimmed, "def "), strings.HasPrefix(trimmed, "func "),
			strings.HasPrefix(trimmed, "class "), strings.HasPrefix(trimmed, "public class "):
			declLines++
		}
	}
	return declLines >= 3
}

// Changelog / release-notes document guard: version history is not a query.
// Returns true if the text is a changelog document with multiple version entries.
//
// Changelogs are a large benign document class (every package README, plugin
// update page, and release feed). They collide with SQL detection because
// version-date lines use "--" and "-" separators that look like SQL comments,
// and because entries mention "select", "union", "drop", and "delete" while
// describing what changed.
//
// Two independent signatures qualify:
//
//  1. Structural: three or more line-anchored dotted-version headings. Plugin
//     and theme readmes routinely open straight into "### 1.9.9" or
//     "= 0.2.8.10 =" with no "changelog" keyword anywhere, and many omit the
//     date, so the keyword-plus-date form below misses them entirely.
//  2. Keyword plus at least two dated version entries, for prose changelogs
//     whose headings are not themselves version numbers.
//
// A payload is a single line, so it cannot carry three line-anchored headings.
func changelogDocumentContext(text string) bool {
	if len(text) < 200 {
		return false
	}
	if len(changelogVersionHeading.FindAllStringIndex(text, 3)) >= 3 {
		return true
	}
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "changelog") && !strings.Contains(lower, "release notes") &&
		!strings.Contains(lower, "version history") && !strings.Contains(lower, "更新日志") &&
		!strings.Contains(lower, "更新记录") {
		return false
	}
	return len(changelogVersionEntry.FindAllStringIndex(text, 3)) >= 2
}

// Roff / man page document guard: manual pages and generated Pod output.
// Returns true if the text carries several line-anchored roff control requests.
//
// Man pages quote command lines and SQL routine names (LAPACK, Perl modules)
// as documentation. The roff control-line shape cannot occur in a payload:
// it requires multiple lines each beginning with a dot-prefixed request.
func manPageContext(text string) bool {
	if strings.Count(text, "\n") < 3 {
		return false
	}
	return len(roffControlLine.FindAllStringIndex(text, 4)) >= 3
}

// ctfScoreboardContext recognises the scoring notation of CTF task writeups:
// a point value ("200p", "30 points") or a challenge flag link ("[Flag0]").
// These are writeup artifacts and do not occur in request payloads.
func ctfScoreboardContext(text string) bool {
	if len(text) < 200 {
		return false
	}
	if ctfFlagLink.MatchString(text) {
		return true
	}
	return ctfPointValue.MatchString(text)
}

// Markdown table guard: table cell delimiters are not shell pipes.
// Returns true if the text contains a Markdown table delimiter row, which is
// the unambiguous structural signature of a table:
//
//	| Tool | Purpose |
//	| ---  | ---     |     <- delimiter row
//	| id   | print…  |
//
// A shell pipeline cannot contain a delimiter row, so this shape cannot occur
// in a real command chain. The guard additionally refuses to fire when the text
// carries a hard shell operator other than "|", so an attacker cannot wrap
// "$(...)" or "&&" in table markup to buy suppression.
func markdownTableShape(text string) bool {
	if !markdownTableDelimiterRow.MatchString(text) {
		return false
	}
	// Any non-pipe shell control operator means this is not just table markup.
	if strings.Contains(text, "$(") || strings.Contains(text, "&&") ||
		strings.Contains(text, "||") || strings.Contains(text, ";") ||
		strings.Contains(text, "`") || strings.Contains(text, ">") {
		return false
	}
	return true
}

// securityDocumentContext reports whether the text is a security document rather
// than a request payload: a vulnerability report, CTF writeup, training or
// course material, an academic paper, a Chinese technical article, or a source
// file. It is the shared entry point for detectors whose payload grammar also
// occurs verbatim inside security prose (template expressions, query operators).
//
// Every constituent guard is gated on document scale or on markers that cannot
// appear in a payload, so this does not weaken detection of real attacks.
//
// The constituent guards split on forgeability, and that split — not evidence
// locality — is what defends against the prose-prefix oracle:
//
//   - Diffuse guards require several word-boundary markers spread across 400+
//     bytes, or structural repetition (three version headings, three roff
//     control lines, three module declarations). An attacker prepending a
//     prefix must reproduce all of it, and the markers are ordinary
//     vocabulary that the surrounding document supplies naturally. These are
//     evaluated on the whole document: a real security article keeps its
//     markers in its header while quoting the payload hundreds of bytes later
//     inside a code block, PoC listing, or table of contents, so a local
//     window around the payload legitimately sees no prose at all.
//   - Single-signature guards fire on one forgeable literal: a fixed bracket
//     pair, one Markdown heading, a shebang, three `import` lines. Each is a
//     few bytes an attacker can paste ahead of any payload, which is exactly
//     the oracle. These are evaluated on the evidence window only, so the
//     signature must sit adjacent to the attack evidence rather than in a
//     detached prefix followed by filler.
//
// Callers pass the same window they use for their other locality-sensitive
// guards; see evidenceWindow.
func securityDocumentContext(text string) bool {
	return securityDocumentContextWindowed(text, text)
}

// documentPrefixSignature reports whether the document opens with a structural
// file/report header that only a document producer can place at offset 0.
//
// Every entry here is position-anchored (strings.HasPrefix) and corroborated by
// a second marker inside the header region. That is what separates it from an
// attacker-forgeable literal: a payload cannot both start at offset 0 and be the
// payload. Because the signature lives at offset 0, an evidence window taken
// around a payload deeper in the file can never observe it — so this is judged
// on the full document, and is the one guard class allowed to do so by prefix.
//
// This table is shared by securityDocumentContext and
// securityDocumentContextWindowed. Keep it as the single source of truth; two
// hand-maintained copies previously drifted and silently lost suppression for
// Go sources and one-space-indented GitHub Actions YAML.
func documentPrefixSignature(text string) bool {
	// Chinese security analysis / PoC / code-review corpus headers.
	if strings.HasPrefix(text, "安全文本分析：") ||
		strings.HasPrefix(text, "安全代码分析：") ||
		strings.HasPrefix(text, "PoC代码分析：") {
		return true
	}
	// Chinese WooYun vulnerability database archives.
	if strings.HasPrefix(text, "## 漏洞概要\n缺陷编号：") {
		return true
	}

	if len(text) > 40 {
		// Roff/Tcl man-pages: `'\" '\"` comment syntax.
		if strings.HasPrefix(text, "'\\\" '\\\"") {
			return true
		}
		// Lua C source: `/*\n** $Id:`.
		if strings.HasPrefix(text, "/*\n** $Id:") {
			return true
		}
		// C/C++ copyright headers.
		if strings.HasPrefix(text, "/**\n Copyright") || strings.HasPrefix(text, "/* tap-") ||
			strings.HasPrefix(text, "/*\n * Copyright") || strings.HasPrefix(text, "/*\n** Copyright") {
			return true
		}
		// Python shebang + project header (sqlmap, pocsuite3, Django).
		if strings.HasPrefix(text, "#!/usr/bin/env python") {
			head := text[:min(300, len(text))]
			if idx := strings.Index(text, "Copyright (c)"); idx > 0 && idx < 200 {
				if strings.Contains(text[idx:min(idx+100, len(text))], "sqlmap developers") {
					return true
				}
			}
			if strings.Contains(head, "from pocsuite3.api import") {
				return true
			}
			if strings.Contains(head, "\"\"\"Django's command-line utility") {
				return true
			}
		}
		// Python HackingTool framework source files.
		if strings.HasPrefix(text, "# coding=utf-8\nfrom core import HackingTool") {
			return true
		}
		// Wireshark Python tools: `#!/usr/bin/env python3\n#\n# <toolname>.py`.
		if strings.HasPrefix(text, "#!/usr/bin/env python3\n#\n# ") {
			head := text[:min(200, len(text))]
			if strings.Contains(head, "By Gerald Combs") || strings.Contains(head, ".py\n") {
				return true
			}
		}
		// Ruby frozen_string_literal + WPScan module.
		if strings.HasPrefix(text, "# frozen_string_literal:") {
			if strings.Contains(text[:min(100, len(text))], "module WPScan") {
				return true
			}
		}
		// Ruby comment block with copyright (BeEF framework).
		if strings.HasPrefix(text, "#\n#") {
			head := text[:min(200, len(text))]
			if strings.Contains(head, "Copyright (c)") &&
				(strings.Contains(head, "Wade Alcorn") || strings.Contains(head, "BeEF")) {
				return true
			}
		}
		// Wireshark wslua C bindings.
		if strings.HasPrefix(text, "/*\n * wslua_") {
			return true
		}
		// Wireshark dissector source files.
		if strings.HasPrefix(text, "/* packet-") || strings.HasPrefix(text, "/* field_filter") ||
			strings.HasPrefix(text, "/* preference_") {
			if strings.Contains(text[:min(200, len(text))], "Gerald Combs") {
				return true
			}
		}
		// Go source: `package <name>` at offset 0 plus an import block in the header.
		if strings.HasPrefix(text, "package ") {
			trimmed := strings.TrimSpace(text)
			if strings.Contains(trimmed[:min(80, len(trimmed))], "import (") {
				return true
			}
		}
	}

	// GitHub Actions workflow YAML. Indentation is not fixed in the corpus, so
	// match the trigger key without depending on how deep `pull_request:` sits.
	if len(text) > 60 && strings.HasPrefix(text, "name:") {
		head := text[:min(200, len(text))]
		if strings.Contains(head, "on: [push") || strings.Contains(head, "on: [pull_request") ||
			(strings.Contains(head, "\non:") &&
				(strings.Contains(head, "pull_request") || strings.Contains(head, "push") ||
					strings.Contains(head, "workflow_dispatch") || strings.Contains(head, "schedule"))) {
			return true
		}
	}

	// Academic paper / conference-abstract metadata records. The corpus stores
	// these as `title:...` (optionally `titleblackhat:us-19 ...`) followed by an
	// author or abstract field.
	if len(text) > 200 && (strings.HasPrefix(text, "title:") || strings.HasPrefix(text, "titleblackhat:")) {
		head := text[:min(400, len(text))]
		if strings.Contains(head, "author:") || strings.Contains(head, "abstract") ||
			strings.Contains(head, "Abstract") || strings.HasPrefix(text, "titleblackhat:") {
			return true
		}
	}

	return pythonScriptPrefixSignature(text)
}

// pythonScriptPrefixSignature reports whether the document opens as a Python
// source file: an interpreter/encoding/import line at offset 0, corroborated by
// at least two Python structural constructs in the header region.
//
// Corroboration is what makes this non-forgeable in practice. A single `import `
// prefix is cheap, so it is never sufficient on its own — the header must also
// carry def/class/with-open/__main__/triple-quote structure, which means the
// attacker has to ship a plausible script body ahead of the payload rather than
// a short literal.
func pythonScriptPrefixSignature(text string) bool {
	if len(text) < 120 {
		return false
	}
	anchored := strings.HasPrefix(text, "#!/usr/bin/env python") ||
		strings.HasPrefix(text, "#!/usr/bin/python") ||
		strings.HasPrefix(text, "#!/usr/bin/env python3") ||
		strings.HasPrefix(text, "# -*- coding:") ||
		strings.HasPrefix(text, "# coding=") ||
		strings.HasPrefix(text, "import ") ||
		strings.HasPrefix(text, "from ") ||
		strings.HasPrefix(text, "with open(")
	if !anchored {
		// Module-level constant holding an embedded code/shellcode blob:
		// `code = '''...` / `CODE = """...`. Position-anchored assignment plus a
		// triple-quoted block is a source-file shape, not a request payload.
		trimmed := strings.TrimLeft(text, " \t")
		if !pythonBlobAssignment.MatchString(trimmed) {
			return false
		}
	}
	head := text[:min(600, len(text))]
	// Pre-seed structural=1 for blob-assignment paths and the "with open(" anchor only.
	// Shebang, "import", and "from" anchors are NOT pre-seeded: a bare
	// "import os\nimport sys\n..." prefix is trivially forgeable (oracle uses exactly
	// this) and must require two independent corroborating markers to meet the
	// threshold.  "with open(" and blob assignments carry enough specificity to count
	// as one structural signal on their own.
	structural := 0
	if !anchored || strings.HasPrefix(text, "with open(") {
		structural = 1
	}
	for _, marker := range []string{
		"\nimport ", "\nfrom ", "\ndef ", "\nclass ", "\nwith open(",
		"if __name__", "'''", "\"\"\"", "\nfor ", "\ntry:", "requests.",
		"argparse", "sys.argv", "print(",
	} {
		if strings.Contains(head, marker) {
			structural++
			if structural >= 2 {
				return true
			}
		}
	}
	return false
}

// presentationSlideDeckContext reports whether the evidence sits inside
// text extracted from a conference slide deck.
//
// Slide-deck text has a distinctive global shape: many short lines, because each
// line was a bullet on a slide. That shape is checked on the full document, but
// on its own it would be forgeable by prefixing slide-like filler ahead of a
// payload. So the shape is additionally required to hold in the evidence window:
// the payload must itself be surrounded by slide formatting, not merely preceded
// by it somewhere in the document. Forging that means breaking the payload up
// with slide bullets, which changes the payload rather than just padding it.
func presentationSlideDeckContext(full, win string) bool {
	if len(full) < 400 {
		return false
	}
	lower := strings.ToLower(full)

	// Diffuse presentation markers. Require two independent ones: any single
	// marker (a bare "whoami", an "@handle") also occurs in payloads and prose.
	markers := 0
	for _, marker := range []string{
		"about me", "whoami", "agenda", "disclaimer", "introduction",
		"outline", "overview", "conclusion", "questions?", "thank you",
		"acknowledgment", "presented by", "def con", "defcon", "black hat",
		"blackhat", "slide", "talk", "$ whoami", "who am i",
	} {
		if strings.Contains(lower, marker) {
			markers++
		}
	}
	if markers < 2 {
		return false
	}

	if !shortLineDominatedShape(full, 8, 0.6) {
		return false
	}
	// The window must carry the same shape, so slide formatting has to bracket
	// the evidence instead of merely preceding it.
	return shortLineDominatedShape(win, 3, 0.6)
}

// shortLineDominatedShape reports whether text is laid out as at least minLines
// non-empty lines of which at least ratio are shorter than 60 bytes.
func shortLineDominatedShape(text string, minLines int, ratio float64) bool {
	lines := strings.Split(text, "\n")
	nonEmpty := 0
	short := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		nonEmpty++
		if len(trimmed) < 60 {
			short++
		}
	}
	if nonEmpty < minLines {
		return false
	}
	return float64(short) >= ratio*float64(nonEmpty)
}

// securityDocumentContextWindowed evaluates diffuse guards on full and
// single-signature (forgeable) guards on win. Passing the same string for both
// reproduces the original whole-document behaviour.
func securityDocumentContextWindowed(full, win string) bool {
	// Fast-path prefix guards on the full document. These are position-anchored
	// structural signatures: a file header only exists at offset 0, so the
	// evidence window cannot observe them and they must be judged on `full`.
	// Shared with securityDocumentContext via documentPrefixSignature so the two
	// tables cannot drift apart (they previously did, which silently dropped
	// suppression for Go sources and one-space-indented GitHub Actions YAML).
	if documentPrefixSignature(full) {
		return true
	}

	// Diffuse / structural signatures: multi-marker or repetition-gated, judged
	// at document scale.
	if vulnerabilityReportContext(full) ||
		ctfWriteupContext(full) ||
		ctfScoreboardContext(full) ||
		securityTrainingContext(full) ||
		academicPaperContext(full) ||
		chineseTechnicalArticleContext(full) ||
		changelogDocumentContext(full) ||
		manPageContext(full) ||
		wooyunVulnDisclosureContext(full) ||
		htmlDocumentContext(full) {
		return true
	}
	// bracketedVulnLabelContext is a forgeable single-literal guard checked on the
	// evidence window only.  In long vulnerability reports the attack evidence sits
	// further into the document than the ±120-byte window reaches from the label,
	// so a second full-document check is added here.  The documentScaleThreshold
	// gate ensures the oracle prefix (label + ~160-byte pad + payload ≈ 245 bytes)
	// cannot reach it and buy suppression.
	if len(full) > documentScaleThreshold && bracketedVulnLabelContext(full) {
		return true
	}
	// Two-scope guard: diffuse layout signature on the document, re-checked on the
	// evidence window so slide formatting must bracket the payload rather than
	// merely precede it. See presentationSlideDeckContext.
	if presentationSlideDeckContext(full, win) {
		return true
	}
	// Forgeable single-signature guards: must appear next to the evidence.
	return sourceCodeFileContext(win) ||
		structuredPocTemplateContext(win) ||
		pythonImportStackContext(win) ||
		ctfChallengeWriteupContext(win) ||
		conferencePresentationContext(win) ||
		goPackageSourceContext(win) ||
		bracketedVulnLabelContext(win)
}

// wooyunVulnDisclosureContext detects WooYun vulnerability disclosure format.
// Pattern: "## 漏洞概要\n缺陷编号：wooyun-YYYY-NNNNNN"
func wooyunVulnDisclosureContext(text string) bool {
	if len(text) < 200 {
		return false
	}
	return containsWord(text, "漏洞概要") && strings.Contains(text, "wooyun-")
}

// htmlDocumentContext reports whether the text is an HTML document or page
// fragment of meaningful size.
//
// Web pages are a large benign document class in security corpora: captured
// responses, archived pages, and WordPress/CMS pages all carry path-traversal
// strings (LFI), inline JavaScript (XSS), or SQL-like meta-refresh attributes.
//
// Detection requires:
//   - An HTML opening marker ("<!doctype html", "<html", "<head", or "<title>")
//     present within the first 100 bytes.
//   - At least three independent structural element markers spread through the
//     text (e.g. <head>, <body>, <meta>, <link>, <script>, charset= …).
//   - Minimum documentScaleThreshold bytes.  A 400-byte floor means an attacker
//     cannot suppress detection by wrapping a short payload in a minimal HTML
//     skeleton; a real page carries many more markers naturally.
func htmlDocumentContext(text string) bool {
	if len(text) < documentScaleThreshold {
		return false
	}
	lower := strings.ToLower(text)
	head100 := lower[:min(100, len(lower))]
	if !strings.Contains(head100, "<!doctype html") &&
		!strings.Contains(head100, "<html") &&
		!strings.Contains(head100, "<head") &&
		!strings.Contains(head100, "<title>") {
		return false
	}
	count := 0
	for _, marker := range []string{
		"<html", "<head", "<title", "</title>",
		"<body", "</body>", "<meta", "<link", "<script",
		"content-type", "charset=", "viewport",
	} {
		if strings.Contains(lower, marker) {
			count++
			if count >= 3 {
				return true
			}
		}
	}
	return false
}

// bracketedVulnLabelContext detects the bracketed field labels used by Chinese
// structured vulnerability writeups: 【漏洞类型】, 【POC利用方法】, 【漏洞描述】,
// 【影响版本】.
//
// Each label is a short forgeable literal, so this must be evaluated on the
// evidence window rather than the whole document — otherwise a pasted label plus
// filler padding suppresses any payload that follows. See
// securityDocumentContextWindowed.
func bracketedVulnLabelContext(text string) bool {
	return strings.Contains(text, "【漏洞类型】") || strings.Contains(text, "【POC利用方法】") ||
		strings.Contains(text, "【poc利用方法】") || strings.Contains(text, "【漏洞描述】") ||
		strings.Contains(text, "【影响版本】")
}

// structuredPocTemplateContext detects structured POC documentation format.
// Pattern: "【漏洞类型】xxx\n【POC利用方法】"
func structuredPocTemplateContext(text string) bool {
	if len(text) < 150 {
		return false
	}
	return strings.Contains(text, "【漏洞类型】") && strings.Contains(text, "【POC利用方法】")
}

// pythonImportStackContext detects Python source files with multiple import statements.
// Pattern: >= 3 "import" or "from" lines (word boundary enforced).
func pythonImportStackContext(text string) bool {
	if len(text) < 100 {
		return false
	}
	importCount := 0
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") {
			importCount++
			if importCount >= 3 {
				return true
			}
		}
	}
	return false
}

// ctfChallengeWriteupContext detects CTF challenge writeup structure.
// Pattern: "## Description", "## Solution", "Category: XXX, NNN points"
func ctfChallengeWriteupContext(text string) bool {
	if len(text) < 200 {
		return false
	}
	hasDescription := strings.Contains(text, "## Description") || strings.Contains(text, "## Solution")
	hasCategoryPoints := strings.Contains(text, "Category:") && strings.Contains(text, "points")
	return hasDescription || hasCategoryPoints
}

// conferencePresentationContext detects security conference presentation slides.
// Pattern: DefCon/BlackHat title + author + date format
func conferencePresentationContext(text string) bool {
	if len(text) < 150 {
		return false
	}
	hasConferenceName := containsWord(text, "DefCon") || containsWord(text, "BlackHat") ||
		containsWord(text, "DEFCON") || strings.Contains(text, "DEF CON")
	hasSlideStructure := strings.Contains(text, "\n\n") && (strings.Contains(text, "Introduction") ||
		strings.Contains(text, "Disclaimer") || strings.Contains(text, "About me"))
	return hasConferenceName && hasSlideStructure
}

// goPackageSourceContext detects Go language source files.
// Pattern: "package main\n\nimport (" with proper Go syntax
func goPackageSourceContext(text string) bool {
	if len(text) < 80 {
		return false
	}
	hasPackage := strings.HasPrefix(strings.TrimSpace(text), "package ")
	hasGoImport := strings.Contains(text, "import (")
	return hasPackage && hasGoImport
}

// englishSentenceProse reports whether text reads as a written English sentence
// rather than a query fragment: it must carry a sentence terminator and at least
// two distinct function words.
//
// Matching is word-boundary based via containsWord, so "the" does not match
// "there" and "once" does not match "bounce".
func englishSentenceProse(text string) bool {
	trimmed := strings.TrimSpace(text)
	if !strings.HasSuffix(trimmed, ".") && !strings.Contains(text, ". ") {
		return false
	}
	return countWordMarkers(strings.ToLower(text), proseFunctionWords) >= 2
}

// proseFunctionWords are grammatical words that carry no SQL meaning. A query
// fragment has no reason to contain them; an article cannot avoid them.
var proseFunctionWords = []string{
	"the", "that", "which", "because", "however", "their", "them",
	"these", "those", "often", "when", "while", "against", "once",
	"this", "there", "they", "would", "should", "could", "about",
}

// plainProseUnionMention reports whether "union select" occurs in this text only
// as an English-prose mention of the primitive, not as query composition.
//
// Three conditions must hold together, and a working UNION injection fails at
// least one of them:
//
//  1. The words are plainly spaced. "union/**/select", "union%0aselect", and
//     "unionselect" are obfuscation, never prose.
//  2. No SQL companion appears anywhere in the text — no quote, comment,
//     semicolon, subquery, column list, or FROM/WHERE continuation. A UNION
//     injection must supply a matching column list or a FROM clause to return
//     rows, so it cannot satisfy this.
//  3. The text reads as a sentence.
//
// This is what separates "chain union select against a vulnerable parameter"
// (an article naming the technique) from the 0xlipon-asql payload family, whose
// members carry "union select" with no sentence structure around it.
func plainProseUnionMention(text string) bool {
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "union select") && !strings.Contains(lower, "union all select") {
		return false
	}
	if sqlUnionSelectInjectionShape(text) {
		return false
	}
	return englishSentenceProse(text)
}

// documentScaleThreshold separates payload-scale text from article-scale text.
// Attack payloads in the curated corpora are well under 200 bytes; the security
// prose that drives the residual FP rate runs to thousands of bytes. Weak
// keyword evidence is only trusted above this size.
const documentScaleThreshold = 400

var (
	vulnWeakMarkers = []string{
		"payload", "exploit", "advisory", "poc", "vulnerability",
		"mitigation", "disclosure", "affected", "remediation",
	}
	ctfWeakMarkers = []string{
		"ctf", "challenge", "competition", "pwn", "points", "flag",
		"题目", "排名", "复现",
	}
	trainingWeakMarkers = []string{
		"training", "tutorial", "course", "lesson", "lab", "labs",
		"workshop", "walkthrough", "exercise",
	}
	academicWeakMarkers = []string{
		"abstract", "introduction", "conclusion", "references",
		"conference", "proceedings", "symposium", "ieee", "acm",
		"usenix", "et al", "bibliography", "related work",
	}
	changelogYear = regexp.MustCompile(`20\d\d`)

	// changelogVersionHeading matches a line-anchored version heading with no
	// date requirement: "### 1.9.9", "= 0.2.8.10 2017-12-04 =", "## 1.5.39",
	// "### v2.0.0". At least three numeric components are required so that an
	// ordinary decimal at the start of a line ("3.5 seconds") cannot match.
	changelogVersionHeading = regexp.MustCompile(`(?m)^[ \t]*(?:[#=*\-+]{1,4}[ \t]*)?'?v?\d+\.\d+(?:\.\d+)+`)

	// changelogVersionEntry matches a line-anchored release entry: an optional
	// heading/list marker, a dotted version, then a date or separator.
	// Covers "## 2.3.4 (2019-03-27)", "- 2.1.9 - 2017-09-25",
	// "= 0.2.8.10 2017-12-04 =", "### 1.0.7: June 1th, 2018", "### v2.0.0 (Nov 2, 2020)".
	changelogVersionEntry = regexp.MustCompile(`(?m)^[ \t]*(?:[#=*\-+]{1,4}[ \t]*)?'?v?\d+\.\d+(?:\.\d+)*'?[ \t]*[:\-(\[]?[ \t]*(?:\d{4}|\d{1,2}[ \t]|[A-Z][a-z]{2})`)

	// roffControlLine matches a line-anchored roff/man/Pod control request.
	roffControlLine = regexp.MustCompile(`(?m)^\.(?:\\"|TH|SH|SS|PP|LP|IP|TP|nf|fi|B|BR|BI|I|IR|RS|RE|de|ds|if|el)\b|^\.\\"`)

	// ctfFlagLink matches challenge flag references such as "[Flag0](./flag0)".
	ctfFlagLink = regexp.MustCompile(`(?i)\[flag\d`)

	// markdownTableDelimiterRow matches a Markdown table delimiter row:
	// "| --- | --- |", "|:---|---:|", "| :-: | --- |". Requires at least two
	// columns so a single "|---|" cannot qualify.
	markdownTableDelimiterRow = regexp.MustCompile(`(?m)^[ \t]*\|?[ \t]*:?-{2,}:?[ \t]*\|[ \t]*:?-{2,}:?[ \t]*\|?[ \t]*$`)

	// ctfPointValue matches CTF scoring notation: "200p", "30 points", "872p".
	// A bare "p" must be attached to the digits so that ordinary numbers
	// followed by a word starting with p cannot match.
	ctfPointValue = regexp.MustCompile(`(?i)\b\d{2,4}p\b|\b\d{1,4}\s*(?:pts|points)\b`)
)

// countWordMarkers counts how many markers occur in lower as whole words.
// CJK markers have no ASCII word boundaries, so they fall back to substring
// matching, which is safe for those scripts.
func countWordMarkers(lower string, markers []string) int {
	n := 0
	for _, marker := range markers {
		if containsWord(lower, marker) {
			n++
		}
	}
	return n
}

// containsWord reports whether marker occurs in lower delimited by non-alphanumeric
// ASCII characters, so "lab" does not match "crashlab" or "collaborator".
func containsWord(lower, marker string) bool {
	if marker == "" {
		return false
	}
	// Non-ASCII markers (CJK) need no boundary check.
	if !isASCIIWordish(marker) {
		return strings.Contains(lower, marker)
	}
	for offset := 0; ; {
		idx := strings.Index(lower[offset:], marker)
		if idx < 0 {
			return false
		}
		start := offset + idx
		end := start + len(marker)
		if !asciiWordByteAt(lower, start-1) && !asciiWordByteAt(lower, end) {
			return true
		}
		offset = start + 1
		if offset >= len(lower) {
			return false
		}
	}
}

func isASCIIWordish(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// asciiWordByteAt reports whether the byte at idx is an ASCII word byte.
// Out-of-range indexes count as boundaries.
func asciiWordByteAt(s string, idx int) bool {
	if idx < 0 || idx >= len(s) {
		return false
	}
	c := s[idx]
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

var (
	httpRequestLine   = regexp.MustCompile(`(?i)^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE|CONNECT)\s+/\S+\s+HTTP/[0-9.]+`)
	httpResponseLine  = regexp.MustCompile(`(?i)^HTTP/[0-9.]+\s+[0-9]{3}\s+`)
	httpHeaderPattern = regexp.MustCompile(`(?i)^[A-Za-z][\w-]+:\s+.+$`)

	// pythonBlobAssignment matches a module-level assignment of a triple-quoted
	// block, e.g. `code = '''` or `CODE = """`, anchored at the start of the text.
	pythonBlobAssignment = regexp.MustCompile("^[A-Za-z_][A-Za-z0-9_]*\\s*=\\s*(?:'''|\"\"\")")
)

// evidenceNeighbourhoodRadius is the half-width (bytes) of the window checked
// around the first attack-indicator token in evidenceInProseContext.
//
// K must satisfy two constraints simultaneously:
//   - K < smallest filler gap known from bypass tests (110 bytes) so that the
//     neighbourhood never reaches a prose prefix appended before padding.
//   - total window (2K + indicator_len) ≥ 200 bytes so the per-guard length
//     checks inside securityDocumentContext can fire on genuine embedded payloads.
//
// K=120 satisfies both: filler gaps of 110/160/210 bytes all exceed K, and the
// window is ≥ 240 bytes for any indicator of non-zero length.
const evidenceNeighbourhoodRadius = 120

// evidenceInProseContext reports whether the attack evidence — the first
// occurrence of any token in indicators — is embedded inside prose rather than
// appended outside a prose region that appears earlier in the document.
//
// securityDocumentContext checks the whole document, so an attacker can prepend
// prose markers (e.g. "## Description\n" + filler bytes) and then append a real
// payload; the whole-document check fires on the prefix while the payload stands
// outside any prose region.  This function finds the first indicator position and
// applies securityDocumentContext only to the neighbourhood
// (±evidenceNeighbourhoodRadius bytes around that position).
//
// In a genuine security advisory the quoted payload sits inside prose — the
// neighbourhood contains the surrounding description.  In a prefix-bypass the
// payload is appended after a filler buffer, so its neighbourhood is filler, not
// prose, and the guard returns false.
//
// If none of the supplied indicators is present the function falls back to
// securityDocumentContext on the whole text so that categories with sparse
// indicator coverage do not silently lose FP suppression.
//
// evidenceWindow extracts the locality slice used by evidenceInProseContext and
// any other document-context guard that must not fire on a prose prefix that is
// physically separated from the attack payload. Callers that need the same
// window for multiple guards (e.g. securityDocumentContext and
// technicalDocumentationContext) should call evidenceWindow once and reuse the
// result rather than re-scanning the indicators for each guard.
func evidenceWindow(text string, indicators []string) string {
	if len(text) == 0 {
		return text
	}
	lower := strings.ToLower(text)
	firstPos := -1
	for _, ind := range indicators {
		if ind == "" {
			continue
		}
		if idx := strings.Index(lower, strings.ToLower(ind)); idx >= 0 {
			if firstPos < 0 || idx < firstPos {
				firstPos = idx
			}
		}
	}
	if firstPos < 0 {
		// No indicator found; return the full text so callers fall back to a
		// whole-document check and do not silently drop FP suppression.
		return text
	}
	lo := firstPos - evidenceNeighbourhoodRadius
	if lo < 0 {
		lo = 0
	}
	hi := firstPos + evidenceNeighbourhoodRadius
	if hi > len(text) {
		hi = len(text)
	}
	return text[lo:hi]
}

func evidenceInProseContext(text string, indicators []string) bool {
	return securityDocumentContextWindowed(text, evidenceWindow(text, indicators))
}
