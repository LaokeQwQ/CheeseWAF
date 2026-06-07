# Semantic Analyzer Readiness

This document is intentionally conservative. CheeseWAF's staged semantic analyzer is usable for the current product path, but it is not yet equivalent to ModSecurity with OWASP CRS.

## Current Coverage

Implemented in `internal/engine/semantic/analyzer.go`:

- HTTP input extraction from URI, query, headers, cookies, form bodies, JSON bodies, multipart fields, XML/raw bodies.
- Recursive decoding for URL encoding, HTML entities, printable Base64, and JavaScript `\uXXXX` / `\xXX` escapes.
- Category guessing for SQLi, XSS, RCE, LFI, XXE, and SSRF.
- Obfuscation handling for SQL comment keyword splitting, Windows path traversal, numeric IPv4 SSRF hosts, and common cloud metadata addresses.
- Additional SQLi handling for error-based XML functions (`extractvalue`/`updatexml`-style patterns), database time-delay functions including `pg_sleep`, and boolean predicates that use SQL string functions such as `char()` without flagging standalone documentation text.
- XSS handling for NUL/control-character obfuscation in executable `javascript:` URL contexts, while keeping standalone `javascript:` documentation clean.
- Syntax plus behavior evidence in `semantic_analysis`, including payload, source field, severity, confidence, and reason text.
- Blocking integration before the individual semantic detectors in the runtime pipeline.

Regression coverage:

- `TestAnalyzerReadinessMatrix` covers common SQLi/XSS/RCE/LFI/XXE/SSRF payloads, cookie and multipart inputs, SQL comment keyword splitting, database file-read and error-based function side effects, PostgreSQL time delay functions, function-based boolean SQLi, Unicode/control-character/entity XSS, inline interpreter execution, Windows traversal, and internal-network SSRF including decimal IPv4 notation.
- `TestAnalyzerReadinessBenignMatrix` protects a small benign corpus from obvious false positives, including SQL function documentation and standalone `javascript:` URL safety text.
- `TestAnalyzerAgainstOpenWAFRegressionPayloads` keeps CRS-inspired payload shapes in the suite.
- Direct `SQLDetector` and `XSSDetector` tests cover the same newly added function-based SQLi and executable-context XSS bypass samples because those detectors are still usable independently in the proxy pipeline.

Run:

```bash
go test ./internal/engine/semantic -run 'Readiness|OpenWAF'
go test ./internal/engine/semantic -bench BenchmarkAnalyzerReadinessCorpus -benchmem
```

Latest local baseline on Windows amd64 / Ryzen 5 5500:

```text
BenchmarkAnalyzerReadinessCorpus-12  47311  25143 ns/op  5726 B/op  94 allocs/op
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
