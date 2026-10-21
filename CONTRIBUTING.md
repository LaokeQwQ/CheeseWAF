# Contributing to CheeseWAF

## Before you start

For bugs, use the bug report template. For ideas, use the feature request
template. Security vulnerabilities must follow [SECURITY.md](SECURITY.md),
not a public issue.

## Changes

- Keep changes focused and explain the user-visible or security impact.
- Do not commit credentials, tokens, private server data, or internal handoff
  material.
- Add or update tests for behavioural changes.
- Preserve the branch promotion flow: changes target `dev`; releases move
  through `canary` and then `master`.
- Keep public documentation and configuration examples free of local paths
  and personal data.

## Validation

Run the smallest relevant checks while iterating, then run the repository CI
checks before requesting review. At minimum, Go changes should pass the
affected package tests and `git diff --check`; web changes should pass
`npm run typecheck` and `npm run build` from `web`.

Pull requests should describe what changed, how it was tested, and any known
limitations. Maintainers may request a threat model or regression test for
security-sensitive changes.
