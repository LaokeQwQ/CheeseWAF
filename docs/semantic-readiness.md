# Semantic Analyzer Readiness

This document is intentionally conservative. CheeseWAF's staged semantic analyzer is usable for the current product path, but it is not yet equivalent to ModSecurity with OWASP CRS.

## Current Coverage

Implemented in `internal/engine/semantic/analyzer.go`:

- HTTP input extraction from URI, query, headers, cookies, form bodies, JSON bodies, multipart fields, XML/raw bodies.
- Recursive decoding for URL encoding, HTML entities, printable Base64, and JavaScript `\uXXXX` / `\xXX` escapes.
- Category guessing for SQLi, XSS, RCE, LFI, XXE, SSRF, NoSQLi, and SSTI.
- Obfuscation handling for SQL comment keyword splitting, MySQL executable version comments, Windows path traversal, numeric IPv4 SSRF hosts, and common cloud metadata addresses.
- Additional SQLi handling for error-based XML functions (`extractvalue`/`updatexml`-style patterns), database time-delay functions including `pg_sleep`, boolean predicates that use SQL string functions such as `char()`, hex tautologies, `ORDER BY` / `HAVING` inference, regex/`LIKE` value probes, MySQL `PROCEDURE ANALYSE`, SQL Server `xp_cmdshell`, and database file read/write primitives such as `load_file` / `into outfile`, without flagging standalone documentation text or SQL comment tutorials.
- Initial SQL dialect hardening for Oracle PL/SQL and T-SQL high-risk primitives, including `DBMS_LOCK.SLEEP` / `DBMS_SESSION.SLEEP`, `sp_OA*`, `OPENROWSET`, `OPENDATASOURCE`, and `UTL_HTTP.REQUEST`. These rules require executable SQL context so database-hardening documentation does not become a standalone block reason.
- XSS handling for NUL/control-character obfuscation in executable `javascript:` URL contexts, URL-bearing attributes including `href`, `src`, `srcset`, and `formaction`, executable `data:text/html` / SVG data URI attributes, `iframe srcdoc`, meta refresh JavaScript redirects, and legacy CSS expression contexts, while keeping standalone `javascript:` / data URI documentation and ordinary iframe markup examples clean.
- RCE handling for shell control operators, command substitution, `${IFS}` whitespace evasion, download-to-shell chains, `bash`/`sh -c`, `cmd /c`, PowerShell/Pwsh dynamic execution and encoded-command payloads, with command-parameter context used as supporting evidence rather than a standalone trigger.
- LFI handling for Windows/Linux traversal, overlong dot-slash traversal, process environment disclosure paths, and Kubernetes service-account token paths.
- SSRF handling for loopback/cloud metadata hosts, dotted-decimal, dotted-hex, dotted-octal, single-integer hex IPv4, IPv6 loopback, IPv4-mapped IPv6 loopback, dynamic DNS hostnames that encode internal IPs (`nip.io` / `sslip.io` / `xip.io`), scheme-relative URLs, bare host / host:port targets in fetch-sink fields, userinfo-like bare targets, and local `file://` URL schemes in fetch-sink contexts.
- NoSQLi handling for MongoDB-style operators in structured JSON/form/query/cookie inputs, including `$ne` credential bypasses, bracket-notation form operators, `$regex` wildcard query changes, logical query branch operators, `$expr` aggregation predicates, `$where`, and `$function` server-side JavaScript predicates. Standalone MongoDB operator documentation text remains clean.
- JSON schema query operator injection (`$jsonSchema`) is treated as a query-constraint replacement signal when it appears in structured query input; standalone MongoDB schema documentation remains clean.
- NoSQLi and SSTI are exposed through the same global/site configuration path as the other semantic engines (`semantic_engines.nosql`, `semantic_engines.ssti`, `advanced.protection.semantic_nosql`, and `advanced.protection.semantic_ssti`) so the runtime pipeline, saved site settings, and Web console stay aligned.
- SSTI handling for Jinja-style object graph traversal, Spring EL runtime execution, Freemarker `Execute` utility calls, Twig filter-callback abuse, ERB command helpers, and context-bound arithmetic probes. Documentation and CMS content examples with ordinary template placeholders remain clean unless they contain execution primitives.
- Syntax plus behavior evidence in `semantic_analysis`, including payload, source field, severity, confidence, and reason text.
- Blocking integration before the individual semantic detectors in the runtime pipeline.
- Protocol-level enforcement covers CL.TE / TE.CL request smuggling, chunked encoding abuse, header injection, HTTP/1.0 downgrade signals, HTTP/2 forbidden hop-by-hop / downgrade-smuggling headers, invalid HTTP/2 `TE` values, and malformed WebSocket upgrade requests while allowing valid WebSocket upgrade shape.

Regression coverage:

- `TestAnalyzerReadinessMatrix` covers common SQLi/XSS/RCE/LFI/XXE/SSRF/NoSQLi/SSTI payloads, cookie and multipart inputs, SQL comment keyword splitting, MySQL versioned comments, database file-read/write and error-based function side effects, PostgreSQL time delay functions, Oracle `DBMS_LOCK.SLEEP`, T-SQL `OPENROWSET` / `sp_OA*` shapes, SQL Server command-execution primitives, function-based boolean SQLi, HAVING/regex/procedure-enumeration inference, Unicode/control-character/entity/data-URI/srcdoc/formaction/srcset XSS, `${IFS}` command injection, PowerShell/Pwsh encoded or dynamic execution, inline interpreter execution, Windows traversal, sensitive local file targets, internal-network SSRF including decimal/hex/octal/single-integer-hex/IPv6/IP-mapped IPv6/dynamic-DNS/file-scheme/scheme-relative/bare-host forms, MongoDB operator injection including `$jsonSchema` in JSON/form login or query structures, and template-injection execution chains.
- `TestAnalyzerReadinessBenignMatrix` protects a small benign corpus from obvious false positives, including SQL function/comment documentation, standalone `javascript:` / `data:text/html` URL safety text, non-executable iframe markup examples, defensive PowerShell/cmd documentation without runnable payloads, ordinary JSON filters, MongoDB operator documentation text, MongoDB `$expr` / `$function` documentation, and safe template documentation/CMS content.
- `TestAnalyzerAgainstOpenWAFRegressionPayloads` keeps CRS-inspired payload shapes in the suite.
- `TestAnalyzerCuratedExternalCorpus` loads reviewed JSONL fixtures from `internal/engine/semantic/testdata/curated_external_shapes.jsonl` so public-corpus-inspired shapes stay visible without importing large raw payload lists into the repository.
- Direct `SQLDetector`, `XSSDetector`, and `RCEDetector` tests cover the same newly added function-based SQLi, executable-context XSS, and obfuscated command-injection samples because those detectors are still usable independently in the proxy pipeline.
- `internal/engine/protocol_enforcement_test.go` covers HTTP/2 forbidden hop-by-hop headers, invalid HTTP/2 `TE`, forbidden HTTP/2 `Transfer-Encoding`, and valid versus malformed WebSocket upgrade handling.

Corpus sourcing:

- `docs/semantic-corpus-sources.md` tracks public source families and import rules.
- OWASP CRS / FTW, FuzzDB, SecLists, and BCCC-SFU-SQLInj-2023 are used as source families for reviewed regression shapes only.
- Raw public corpora stay outside the repository by default. Checked-in samples must be minimal, labeled, and paired with benign neighbors when a pattern can affect normal traffic.

Run:

```bash
go test ./internal/engine/semantic -run 'Readiness|OpenWAF'
go test ./internal/engine -run TestDetectProtocolViolations
go test ./internal/engine/semantic -bench BenchmarkAnalyzerReadinessCorpus -benchmem
go run ./cmd/cheesewaf-corpus --mode analyzer
```

The same curated corpus can be replayed against a deployed WAF data-plane
listener:

```bash
go run ./cmd/cheesewaf-corpus --mode http --base-url http://127.0.0.1:8080
```

The runner emits a JSON report with detection rate, false-positive rate,
per-case latency, and per-case pass/fail evidence. See
`docs/security-validation.md` for the release gate.

Latest local baseline on Windows amd64 / Ryzen 5 5500:

```text
BenchmarkAnalyzerReadinessCorpus-12  36810  32326 ns/op  6145 B/op  108 allocs/op
```

## Not Yet ModSecurity/CRS Parity

CheeseWAF currently lacks several things that make ModSecurity plus CRS a mature baseline:

- Full SecLang compatibility and rule ecosystem reuse.
- CRS paranoia levels, anomaly scoring, rule exclusions, reporting model, and plugin model.
- CRS-scale regression coverage across protocol enforcement, request smuggling, scanner detection, language-specific rules, and response leakage rules.
- Large real-traffic false-positive baseline.
- Full libinjection/CRS-level SQLi/XSS tokenization depth beyond the current lightweight token fingerprints and semantic heuristics.
- A continuous public benchmark that compares CheeseWAF, ModSecurity/CRS, and Coraza/CRS on identical payloads.

## Gate Before Claiming "Can Beat ModSecurity"

Do not claim parity until all gates are green:

- Import and run the OWASP CRS regression corpus by category.
- Compare CheeseWAF against a local ModSecurity/CRS container and a Coraza/CRS container.
- Track detection rate, false-positive rate, bypass samples, latency, allocations, and log explainability.
- Keep a checked-in corpus of misses and false positives; every engine change must move the numbers in the right direction.
- Publish the benchmark command and raw results in release artifacts.

The current truthful claim is:

> CheeseWAF has a working staged semantic analyzer with explainable evidence and growing CRS-inspired regressions. It is suitable for MVP/product hardening, but it is not yet a replacement for ModSecurity plus OWASP CRS in high-assurance deployments.
