# R2-3 Web Core Task Report

Status: DONE_WITH_CONCERNS

## Scope

- R2 number: `R2-3`
- Worktree: `/private/tmp/cw-r2-web`
- Branch: `fix/r2-web`
- Audit source: `/Users/laoke/Dev/CheeseWAF-audit-reports/06-Web前端.md`
- Assigned findings: `1` and `5-10`
- Explicitly out of scope: findings `2-4` (R2-9 ownership)
- Backend scope: no Go files edited

## Changed Files

- `web/src/api/client.ts`
- `web/src/api/client.test.ts`
- `web/src/api/realtime.ts`
- `web/src/api/realtime.test.ts`
- `web/src/authProfile.ts`
- `web/src/authProfile.test.ts`
- `web/src/layouts/MainLayout.tsx`
- `web/src/layouts/MainLayout.test.tsx`
- `web/src/pages/AttackMap/GlobeMap.tsx`
- `web/src/pages/Users/UsersPage.tsx`
- `web/src/pages/Users/UsersPage.test.tsx`
- `TASK_REPORT.md`

## Finding Disposition

### Finding 1: authenticated subject and 2FA controls

Complete. Login, session refresh, session fetch, and legacy-session bootstrap cache the account `id` as `subject`, together with username, role, and optional scopes. Logout and unauthorized-session handling clear the profile. Desktop and mobile 2FA predicates now allow setup/disable only for the account owner and allow administrator recovery only for a different account. Focused tests cover the subject cache and self/administrator cases.

### Finding 5: shell polling and navigation permissions

Complete. Navigation is filtered by the cached role/scope profile. Version, recent-log, audit, user, notification, and realtime shell surfaces are independently gated before their queries or subscriptions start. Realtime invalidation is mapped to the consuming query-key prefixes, with slower safety polling while a live channel is connected and faster polling when both live channels are unavailable.

### Finding 6: malformed SSE frames

Complete. `parseSSEBlock` catches invalid JSON and returns no event, allowing subsequent frames to continue. Tests cover both the parser and a later valid assistant-stream completion after a malformed frame.

### Finding 7: setup token storage

Complete. Setup tokens are held only in a module-local memory value, removed from the URL fragment, and cleared after successful setup. The legacy session-storage key is removed defensively but is never written. Tests cover fragment/status acquisition, successful clearing, failed-setup retry, and non-setup requests.

### Finding 8: exact setup/auth path checks

Complete. Request handling normalizes the URL pathname and compares exact paths for CSRF and refresh exemptions. Lookalike paths such as `/setup-notes` and `/auth/login-audit` remain subject to normal handling and are covered by tests.

### Finding 9: path parameter encoding

Complete. Site, user/2FA, and rule identifiers are consistently wrapped with `encodeURIComponent`; existing review, cluster, notification, system, and AI identifier paths remain encoded. Focused tests use an ID containing slash, query, and fragment characters across every changed endpoint.

### Finding 10: GlobeMap explicit `any`

Complete. GlobeMap now uses constructor-derived native Three.js instance types, typed marker data, and typed geometry/material disposal. No explicit `any` remains in `web/src/pages/AttackMap/GlobeMap.tsx`; lifecycle disposal and event cleanup remain intact.

### Findings 2-4

Not implemented, as required by the brief. They remain assigned to R2-9.

## Verification Evidence

All commands below were run from `/private/tmp/cw-r2-web` or its `web` subdirectory as shown.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `cd /private/tmp/cw-r2-web/web && npm test -- src/api/client.test.ts src/api/realtime.test.ts src/authProfile.test.ts src/layouts/MainLayout.test.tsx src/pages/Users/UsersPage.test.tsx` | `0` | 5 test files passed; 52 tests passed. |
| `cd /private/tmp/cw-r2-web/web && npm test` | `0` | 62 test files passed; 326 tests passed; duration 75.05s. |
| `cd /private/tmp/cw-r2-web/web && npm run typecheck` | `0` | `tsc -b` completed without diagnostics. |
| `cd /private/tmp/cw-r2-web/web && npm run build` | `0` | Vite production build completed; 2,568 modules transformed; `Build budgets OK` (1 initial preload, 0.42 KiB gzip; 32.61 KiB initial CSS gzip; 6 lazy theme stylesheets). |
| `cd /private/tmp/cw-r2-web && git diff --cached --check` | `0` | Staged diff has no whitespace errors. |
| `cd /private/tmp/cw-r2-web && git status --short --branch` before implementation commit | `0` | Only the 11 listed web source/test files were staged; no other worktree was touched. |

The full test run emits the repository's existing Node `localStorage` experimental warnings and the intentional `AppErrorBoundary` test stack trace. The build emits the existing Vite native-config warning and large-chunk advisory; neither changes the exit result or budget check.

## Commits

- Implementation commit: `3705743` (`fix(web): complete R2-3 audit findings`)
- The documentation commit containing this report is made immediately after this report is written; its hash is included in the final handoff.

## Concerns

- The repository contains the realtime SSE/WebSocket endpoints and message contract, but a source scan found no `Hub.Broadcast` producer call site beyond the hub itself. Until producers are wired by the backend owner, the client will correctly remain on its polling fallback even though the transport implementation is ready.
- The current auth user payload does not expose custom-role scope lists in the checked-in backend DTO. The web profile supports scopes when supplied and conservatively exposes only built-in role defaults otherwise; custom roles without returned scopes may see fewer navigation items until the profile contract supplies them.
- Findings 2-4 were intentionally deferred to R2-9 and are not represented as regressions in this task.
