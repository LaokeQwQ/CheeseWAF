# Semantic Corpus Source Plan

CheeseWAF should use public security datasets as regression inputs, not as
blind rule imports. Every imported sample must be tagged, reviewed, and paired
with benign counterexamples when a pattern is likely to affect normal traffic.

## Candidate Sources

| Source | Use | Notes |
| --- | --- | --- |
| OWASP Core Rule Set / FTW | WAF-positive and WAF-negative request shapes | Best baseline for parity-style regression because FTW is designed to issue repeatable HTTP requests and validate WAF behavior. See <https://github.com/coreruleset/coreruleset>, <https://github.com/coreruleset/ftw>, and <https://github.com/coreruleset/go-ftw>. |
| FuzzDB | Attack payload primitives for SQLi, XSS, RCE, LFI, SSRF, XXE, NoSQLi, SSTI, and discovery | Use as a source of payload shapes only. Do not bulk-import every line as a block rule. See <https://github.com/fuzzdb-project/fuzzdb>. |
| SecLists | Broad fuzzing and payload lists | Use selected web payloads and pair them with benign examples. Repository is large and includes material that can trigger local security tooling. See <https://github.com/danielmiessler/SecLists>. |
| BCCC-SFU-SQLInj-2023 | Evasive and sophisticated SQL injection queries | Good candidate for SQLi adversarial regression and benchmark scoring after license and download handling are reviewed. See <https://www.yorku.ca/research/bccc/ucs-technical/cybersecurity-datasets-cds/sql-injection-attack-bccc-sfu-sqlinj-2023/>. |
| Internal production/user reports | False positives and false negatives seen by CheeseWAF users | Highest priority for threshold tuning because it reflects real deployments. Must redact secrets and personal data. |

## Import Rules

- Keep external raw corpora outside the repository by default.
- Store only curated, minimal regression samples in `internal/engine/semantic/testdata/`.
- Each sample needs `source_family`, `label`, `category`, and `rationale`.
- Every new high-risk attack family should add at least one benign neighbor.
- Treat LLM-generated payloads as untrusted proposals; they must fail red tests
  first and be reviewed before becoming regression fixtures.
- Track detection rate, false-positive rate, latency, allocations, and evidence
  quality before claiming parity with ModSecurity/CRS or SafeLine.
- Prefer semantic families and bypass mechanisms over copy-pasted raw payloads.
  A sample should explain what behavior it exercises and why the expected
  action is block, challenge, log, or pass.

## Current Curated Corpus

`internal/engine/semantic/testdata/curated_external_shapes.jsonl` contains
small, reviewed samples inspired by public dataset families. It currently
focuses on:

- SQLi hex tautology and ORDER BY enumeration.
- XSS meta refresh and CSS execution contexts.
- LFI Kubernetes service account token and overlong dot-slash traversal.
- SSRF IPv6, dotted-hex, and dotted-octal internal hosts.
- NoSQLi MongoDB operator injection shapes for credential and `$where` query behavior.
- SSTI Jinja/Freemarker execution-chain shapes.
- Benign documentation neighbors for localhost URLs, browser security terms, MongoDB operator references, and harmless template examples.

This is not a replacement for full CRS/FTW, SecLists, FuzzDB, or BCCC runs. It
is a checked-in safety net for the engine behavior CheeseWAF already claims.
