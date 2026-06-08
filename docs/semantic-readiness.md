# Semantic Analyzer Readiness

This document is intentionally conservative. CheeseWAF's staged semantic analyzer is usable for the current product path, but it is not yet equivalent to ModSecurity with OWASP CRS.

## Current Coverage

Implemented in `internal/engine/semantic/analyzer.go`:

- HTTP input extraction from URI, query, headers, cookies, form bodies, JSON bodies, multipart fields, XML/raw bodies.
- Recursive decoding for URL encoding, HTML entities, printable Base64, and JavaScript `\uXXXX` / `\xXX` escapes.
- Category guessing for SQLi, XSS, RCE, LFI, XXE, SSRF, and NoSQLi.
- Obfuscation handling for SQL comment keyword splitting, MySQL executable version comments, Windows path traversal, numeric IPv4 SSRF hosts, and common cloud metadata addresses.
- Additional SQLi handling for error-based XML functions (`extractvalue`/`updatexml`-style patterns), database time-delay functions including `pg_sleep`, boolean predicates that use SQL string functions such as `char()`, hex tautologies, and `ORDER BY` enumeration without flagging standalone documentation text or SQL comment tutorials.
- XSS handling for NUL/control-character obfuscation in executable `javascript:` URL contexts, executable `data:text/html` / SVG data URI attributes, `iframe srcdoc`, meta refresh JavaScript redirects, and legacy CSS expression contexts, while keeping standalone `javascript:` / data URI documentation and ordinary iframe markup examples clean.
- RCE handling for shell control operators, command substitution, `${IFS}` whitespace evasion, download-to-shell chains, `bash`/`sh -c`, `cmd /c`, PowerShell/Pwsh dynamic execution and encoded-command payloads, with command-parameter context used as supporting evidence rather than a standalone trigger.
- LFI handling for Windows/Linux traversal, overlong dot-slash traversal, and Kubernetes service-account token paths.
- SSRF handling for loopback/cloud metadata hosts, dotted-decimal, dotted-hex, dotted-octal, and IPv6 loopback forms.
- NoSQLi handling for MongoDB-style operators in structured JSON/form/query/cookie inputs, including `$ne` credential bypasses, bracket-notation form operators, `$regex` wildcard query changes, logical query branch operators, and `$where` server-side JavaScript predicates. Standalone MongoDB operator documentation text remains clean.
- NoSQLi is exposed through the same global/site configuration path as the other semantic engines (`semantic_engines.nosql` and `advanced.protection.semantic_nosql`) so the runtime pipeline, saved site settings, and Web console stay aligned.
- Syntax plus behavior evidence in `semantic_analysis`, including payload, source field, severity, confidence, and reason text.
- Blocking integration before the individual semantic detectors in the runtime pipeline.

Regression coverage:

- `TestAnalyzerReadinessMatrix` covers common SQLi/XSS/RCE/LFI/XXE/SSRF/NoSQLi payloads, cookie and multipart inputs, SQL comment keyword splitting, MySQL versioned comments, database file-read and error-based function side effects, PostgreSQL time delay functions, function-based boolean SQLi, Unicode/control-character/entity/data-URI/srcdoc XSS, `${IFS}` command injection, PowerShell/Pwsh encoded or dynamic execution, inline interpreter execution, Windows traversal, internal-network SSRF including decimal IPv4 notation, and MongoDB operator injection in JSON/form login or query structures.
- `TestAnalyzerReadinessBenignMatrix` protects a small benign corpus from obvious false positives, including SQL function/comment documentation, standalone `javascript:` / `data:text/html` URL safety text, non-executable iframe markup examples, defensive PowerShell/cmd documentation without runnable payloads, ordinary JSON filters, and MongoDB operator documentation text.
- `TestAnalyzerAgainstOpenWAFRegressionPayloads` keeps CRS-inspired payload shapes in the suite.
- `TestCuratedExternalCorpusShapes` loads reviewed JSONL fixtures from `internal/engine/semantic/testdata/curated_external_shapes.jsonl` so public-corpus-inspired shapes stay visible without importing large raw payload lists into the repository.
- Direct `SQLDetector`, `XSSDetector`, and `RCEDetector` tests cover the same newly added function-based SQLi, executable-context XSS, and obfuscated command-injection samples because those detectors are still usable independently in the proxy pipeline.

Corpus sourcing:

- `docs/semantic-corpus-sources.md` tracks public source families and import rules.
- OWASP CRS / FTW, FuzzDB, SecLists, and BCCC-SFU-SQLInj-2023 are used as source families for reviewed regression shapes only.
- Raw public corpora stay outside the repository by default. Checked-in samples must be minimal, labeled, and paired with benign neighbors when a pattern can affect normal traffic.

Run:

```bash
go test ./internal/engine/semantic -run 'Readiness|OpenWAF'
go test ./internal/engine/semantic -bench BenchmarkAnalyzerReadinessCorpus -benchmem
```

Latest local baseline on Windows amd64 / Ryzen 5 5500:

```text
BenchmarkAnalyzerReadinessCorpus-12  34459  33902 ns/op  6157 B/op  108 allocs/op
```

## Not Yet ModSecurity/CRS Parity

CheeseWAF currently lacks several things that make ModSecurity plus CRS a mature baseline:

- Full SecLang compatibility and rule ecosystem reuse.
- CRS paranoia levels, anomaly scoring, rule exclusions, reporting model, and plugin model.
- CRS-scale regression coverage across protocol enforcement, request smuggling, scanner detection, language-specific rules, and response leakage rules.
- Large real-traffic false-positive baseline.
- libinjection-style SQLi/XSS tokenization depth.
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
