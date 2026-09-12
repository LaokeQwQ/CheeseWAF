# Server Release Signing Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the stable CheeseWAF release server-oriented so Windows Authenticode and macOS Developer ID credentials are optional instead of blocking the release.

**Architecture:** Stable `vMAJOR.MINOR.PATCH` tags use a `server` release profile that packages Linux targets only and skips the macOS disk-image job. Branch and canary workflows keep the existing full cross-platform packaging path. Release notes are generated from the artifacts that actually exist, while Sigstore checksums and SBOM signing remain required for published releases.

**Tech Stack:** Bash, GitHub Actions YAML, Go build scripts, shell regression tests, Sigstore Cosign.

## Global Constraints

- Keep `@agent-eyes/agent-eyes`, code-inspector, and `codex-acp` out of production artifacts.
- Keep runtime data outside tracked templates and source files.
- Preserve the existing promotion path and stable tag format `vMAJOR.MINOR.PATCH`.
- Do not expose or add signing secrets.
- Run `actionlint`, shell syntax checks, release-script tests, and the repository CI static gate before claiming completion.

### Task 1: Define the server release profile in packaging

**Files:**
- Modify: `scripts/ci/package-release.sh:157-158`
- Create: `scripts/ci/release-targets.sh`
- Test: `scripts/ci/package-release_profile_test.sh`

**Interfaces:**
- Consumes `CHEESEWAF_RELEASE_PROFILE` and optional `CHEESEWAF_TARGETS`.
- Produces the existing release archive layout, with `server` selecting Linux targets by default.

- [x] **Step 1: Write the failing test**

  Add a test that checks `CHEESEWAF_RELEASE_PROFILE=server` prints only `linux/amd64 linux/arm64 linux/loong64` through a test-only target listing mode, while `full` preserves the current seven-target default.

- [x] **Step 2: Run the test to verify it fails**

  Run: `bash scripts/ci/package-release_profile_test.sh`

  Expected: FAIL because the profile selector does not exist.

- [x] **Step 3: Write the minimal implementation**

  Add a `CHEESEWAF_RELEASE_PROFILE` selector with `full` and `server` values, reject unknown values, and expose the selected targets through `scripts/ci/release-targets.sh` so the test can inspect selection without building artifacts. Keep explicit `CHEESEWAF_TARGETS` overrides for existing smoke tests.

- [x] **Step 4: Run the test to verify it passes**

  Run: `bash scripts/ci/package-release_profile_test.sh`

  Expected: PASS for both profiles and an unknown-profile failure.

### Task 2: Stop requiring desktop signing for stable tags

**Files:**
- Modify: `.github/workflows/ci.yml:424-523`
- Modify: `scripts/ci/verify-release.sh:223-230`
- Test: `scripts/ci/verify-release_test.sh`
- Test: `scripts/ci/verify-ci-static.sh`

**Interfaces:**
- Stable tag jobs set `CHEESEWAF_RELEASE_PROFILE=server` and `CHEESEWAF_SIGNING_SCOPE=server`.
- `verify-release.sh` accepts `server` and skips platform-specific Authenticode/Developer ID checks while retaining archive, checksum, metadata, and content checks.

- [x] **Step 1: Write the failing regression test**

  Add a Linux-only fixture invocation with `CHEESEWAF_REQUIRE_SIGNING=1 CHEESEWAF_SIGNING_SCOPE=server` and assert it passes without `osslsigncode`, `codesign`, or a `.dmg`.

- [x] **Step 2: Run the test to verify it fails**

  Run: `bash scripts/ci/verify-release_test.sh`

  Expected: FAIL because `server` is currently rejected as an invalid signing scope.

- [x] **Step 3: Write the minimal implementation**

  Accept `server` in the signing-scope case statement. Guard both platform-signing blocks so they run only for `all`, `windows`, or `macos`. Set the stable-tag profile in `release-artifacts`, skip `package-macos-dmg` for `v*` tags, remove the macOS dependency/download from `publish-release`, and keep branch/canary behavior unchanged.

- [x] **Step 4: Run the test to verify it passes**

  Run: `bash scripts/ci/verify-release_test.sh`

  Expected: PASS, including the existing strict Windows and macOS regression cases.

- [x] **Step 5: Update the static workflow assertions**

  Require the server profile and server signing scope in GitHub CI, while retaining checks that branch packaging can still build Windows and macOS artifacts.

### Task 3: Generate release notes from actual artifacts

**Files:**
- Modify: `scripts/ci/publish-prerelease.sh:173-220`
- Test: `scripts/ci/publish-prerelease_test.sh`

**Interfaces:**
- The release-note table lists only platform patterns present in `release/`.
- Existing stable and pre-release publishing behavior remains unchanged apart from accurate platform rows.

- [x] **Step 1: Write the failing regression test**

  Extend the fake `gh` command to capture `--notes-file`, then assert that a Linux-only stable fixture contains a Linux row and no Windows/macOS rows.

- [x] **Step 2: Run the test to verify it fails**

  Run: `bash scripts/ci/publish-prerelease_test.sh`

  Expected: FAIL because the current notes always list every platform.

- [x] **Step 3: Write the minimal implementation**

  Add a bounded artifact-presence helper and append platform rows only when matching files exist. Keep the existing Sigstore verification instructions and stable/pre-release wording.

- [x] **Step 4: Run the test to verify it passes**

  Run: `bash scripts/ci/publish-prerelease_test.sh`

  Expected: PASS for Linux-only and full-matrix fixtures.

### Task 4: Document the server-first release contract

**Files:**
- Modify: `README.md:160-210`
- Modify: `README_CN.md:175-215`
- Modify: `docs/acceptance-matrix.md`

**Interfaces:**
- Documentation states that stable releases guarantee Linux archives and Sigstore-verifiable checksums/SBOMs; container deployment remains documented as a source build path.
- Windows/macOS artifacts, when present on branch or manual builds, are optional and may be unsigned.

- [x] **Step 1: Update the English and Chinese release sections**

  Remove the claim that every stable release includes every desktop platform, explain the server profile, and keep commands runnable from a clean workspace.

- [x] **Step 2: Update acceptance evidence**

  Separate required server release checks from optional desktop packaging checks.

- [x] **Step 3: Run documentation and static checks**

  Run: `bash scripts/ci/verify-ci-static.sh`

  Expected: PASS with no stale release-policy assertions.

### Task 5: Full verification and handoff

**Files:**
- Create: `scripts/ci/run-actionlint.sh`
- Modify: `.github/workflows/ci.yml`
- Modify: `.forgejo/workflows/ci.yml`

- [x] **Step 1: Run shell syntax checks**

  Run: `bash -n scripts/ci/package-release.sh scripts/ci/verify-release.sh scripts/ci/publish-prerelease.sh scripts/ci/package-release_profile_test.sh`

- [x] **Step 2: Run release regression tests**

  Run: `bash scripts/ci/package-release_profile_test.sh && bash scripts/ci/verify-release_test.sh && bash scripts/ci/publish-prerelease_test.sh`

- [x] **Step 3: Run workflow validation**

  Run: `bash scripts/ci/run-actionlint.sh -shellcheck= -pyflakes= -color .github/workflows/*.yml`

- [x] **Step 4: Run the repository static gate**

  Run: `bash scripts/ci/verify-ci-static.sh`

- [x] **Step 5: Inspect the diff and report exact remaining gaps**

  Run: `git diff --check && git status --short && git diff --stat`

### Task 6: Close stable-release provenance and asset invariants

**Files:**
- Create: `scripts/ci/stable-release-policy.sh`
- Create: `scripts/ci/verify-stable-tag.sh`
- Create: `scripts/ci/verify-stable-tag_test.sh`
- Modify: `scripts/ci/verify-release.sh`
- Modify: `scripts/ci/publish-prerelease.sh`
- Modify: `.github/workflows/ci.yml`

- [x] **Step 1: Make the server release directory fail closed**

  Require exactly the Linux x86_64, ARM64, and LoongArch64 archives for the stable version. Reject every other top-level file except the checksum, SBOM, and Sigstore bundle allowlist.

- [x] **Step 2: Bind the tag to the protected source state**

  Require the stable tag to match `scripts/ci/product-version` and the tag commit to equal the fetched `master` head before packaging begins.

- [x] **Step 3: Harden stable release reruns**

  Verify an existing release is non-draft, non-prerelease, targets the expected commit, and has no extra remote assets. Download and verify the existing immutable files without regenerating SBOMs, replacing assets, or editing release notes.

- [x] **Step 4: Narrow Sigstore verification identity**

  Bind stable verification to `.github/workflows/ci.yml` and the exact current stable tag. Keep pre-release verification limited to its branch/tag namespace.

- [x] **Step 5: Add and run negative regressions**

  Cover missing Linux architectures, unknown extensions, mismatched product versions, non-master commits, archive metadata mismatches, missing or moved remote tags, extra remote assets, incorrect release targets, unsafe ref names, and the executable Sigstore command in release notes.
