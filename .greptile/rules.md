# CheeseWAF Review Rules

## Scope and evidence

- Review the changed behavior in the context of the architecture and contract files listed in `.greptile/files.json`.
- Prefer concrete, reproducible findings with an impact, affected path, and suggested correction.
- Do not treat formatting preferences, generated assets, or test fixtures as production defects unless they alter runtime behavior.

## Security boundaries

- Keep management-plane endpoints loopback by default unless the relevant contract explicitly changes.
- Reject empty, whitespace-only, and control-character identity inputs at validation boundaries.
- Preserve redaction, least privilege, expiry, replay protection, and fail-closed behavior for security decisions.
- Never replay untrusted traffic against a real origin as part of a review or test suggestion; use the repository's isolated test or sandbox paths.

## Go services

- Propagate cancellation and deadlines through I/O and background work.
- Bound request bodies, caches, retries, queues, and goroutine lifetimes.
- Close response bodies and release locks/resources on every path.
- Keep configuration validation, runtime defaults, and operator-facing documentation consistent.

## Management console

- Put user-facing text through the existing i18n layer and keep locale keys synchronized.
- Preserve focus order, keyboard access, contrast in every theme, responsive layout, and reduced-motion behavior.
- Keep loading, retry, empty, error, and success states explicit and testable.

## Verification

- Prefer focused regression tests for changed behavior and run the smallest relevant repository checks before declaring a change complete.
- Treat CI workflow changes, dependency updates, and release metadata as production-impacting changes that require explicit verification.
