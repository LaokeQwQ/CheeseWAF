# R2-8 Release, CI, and Docs Task Report

Status: `DONE_WITH_CONCERNS`

Implementation commits: `6fa8369`, `8027308`, `59f84d7`

## Finding Disposition

1. **Signing verification exit codes and anchors:** fixed. Authenticode, codesign, and spctl must return success; Authenticode and spctl output checks are line-anchored. CI selects explicit `windows` or `macos` verification scopes so the macOS runner does not require `osslsigncode`. Negative and positive fixtures cover false-success text, non-zero exits, invalid scope, and missing scoped artifacts.
2. **Unsigned artifacts:** fixed to the locked policy. Release jobs use strict mode when the matching credentials exist and explicit `warn` mode otherwise. Windows and macOS packaging emit visible warnings when credentials are absent. Forgejo now passes Windows certificate secrets to the packaging step as well as verification.
3. **NSIS and Makefile silent omissions:** fixed. Required NSIS payloads no longer use `/nonfatal`; Makefile packaging asserts the built UI and staged payload before succeeding.
4. **README configuration drift:** fixed in both languages. The example has one `sites` key, loopback defaults, real `protection.ratelimit`/`protection.ip` fields, and valid WAF settings. Both examples were parsed as YAML in verification.
5. **PGO disabling inlining:** fixed. `-l=4` was removed from Makefile, `build-all.sh`, and `build-pgo.sh`; performance documents now describe the compiler behavior accurately.
6. **Mutable published assets:** fixed. Existing release assets are retained and only missing names are uploaded; `--clobber` is forbidden by the static gate.
7. **Stale checksums before SBOM:** fixed. Checksums are rebuilt before artifact scanning and rebuilt again after generated SBOM files exist.
8. **Signing passwords in argv:** fixed. Windows uses `osslsigncode -readpass` with a mode-0600 file. macOS converts the PKCS#12 using an OpenSSL password file, imports from protected temporary PEM material, restores the user's keychain list, and deletes the temporary keychain.
9. **Stock macOS Bash/tools:** fixed in the release paths. `mapfile`, associative arrays, GNU-only checksums, and `seq` were removed or given portable replacements. Tests ran under Bash 3.2.57 on macOS.
10. **Duplicate macOS checksums:** fixed. DMG packaging atomically rewrites the complete checksum manifest instead of appending entries.
11. **Silent sed coupling:** fixed. Docker image construction and release smoke configuration assert every critical replacement.
12. **Ports, timeouts, and cleanup:** fixed. Release smoke chooses randomized available ports and bounds curl calls; DMG attach/detach, conversion, notarization, and stapling are bounded, with exit cleanup for mounted volumes.
13. **Canary channel drift:** fixed. `channel-from-git.sh` now emits `PreTest`, matching package metadata.
14. **Unsafe recursive cleanup:** fixed. Release/work output paths must be repository children, cannot contain dot segments, and cannot traverse existing symbolic links. A dynamic symlink escape fixture was rejected before cleanup.
15. **Hard-coded Docker smoke credentials:** fixed. One-run token/password values are generated, stored in mode-0600 files, and passed with Docker env-file/curl file arguments rather than literal argv values.
16. **Release verifier negative coverage:** fixed. Tests cover checksum tampering, an unlisted artifact, missing config, archive path traversal, failed/ambiguous Authenticode output, strict scope without artifacts, and the valid signature path.
17. **README channel-specific filenames:** fixed. Download tables and commands use channel-independent artifact globs and explain the channel suffixes.
18. **Duplicate dependency automation:** fixed. Dependabot owns Go, npm, and GitHub Actions; Renovate is restricted to Dockerfiles and moved to Tuesday.
19. **Stale performance artifact list:** fixed. The document now labels build outputs as generated and lists current OS/architecture naming patterns.

## Changed Files

- `.forgejo/workflows/ci.yml`
- `.github/workflows/ci.yml`
- `Makefile`
- `PERFORMANCE_DELIVERY.md`
- `README.md`
- `README_CN.md`
- `deploy/docker/Dockerfile`
- `deploy/windows/nsis/cheesewaf.nsi`
- `docs/performance-optimization.md`
- `renovate.json`
- `scripts/build-all.sh`
- `scripts/build-pgo.sh`
- `scripts/ci/channel-from-git.sh`
- `scripts/ci/docker-build.sh`
- `scripts/ci/package-macos-dmg.sh`
- `scripts/ci/package-release.sh`
- `scripts/ci/publish-prerelease.sh`
- `scripts/ci/sign-windows.sh`
- `scripts/ci/verify-ci-static.sh`
- `scripts/ci/verify-release.sh`
- `scripts/ci/verify-release_test.sh`

The final commit adds the shared atomic checksum rewrite integration, release/work
directory nesting guards, Forgejo packaging tool assertions, Docker replacement
assertions, and macOS signing fixtures.

## Verification Evidence

All successful commands below were run after the final source changes.

```text
bash -n scripts/ci/*.sh scripts/build-all.sh scripts/build-pgo.sh && sh -n scripts/ci/channel-from-git.sh
```

Exit `0` under GNU Bash 3.2.57 on arm64 macOS.

```text
bash scripts/ci/verify-release_test.sh
```

Exit `0`. The expected negative fixtures failed at their intended gates; the anchored Authenticode success fixture passed.

```text
bash scripts/ci/verify-ci-static.sh
```

Exit `0`, including metadata tests and the complete release-verifier regression suite.

```text
ruby -e "require 'yaml'; YAML.load_file('.github/workflows/ci.yml'); YAML.load_file('.forgejo/workflows/ci.yml')"
node -e "JSON.parse(require('fs').readFileSync('renovate.json','utf8'))"
```

Both exited `0`.

```text
ruby -ryaml -e '<extract and parse the README.md and README_CN.md ratelimit examples>'
```

Exit `0`; each document had exactly one site and `protection.ratelimit.default.requests == 100`.

```text
CHEESEWAF_RELEASE_DIR="$PWD/.r2-release-link-<pid>/out" \
  CHEESEWAF_RELEASE_WORK_DIR=tmp/r2-release-guard-work \
  bash scripts/ci/package-release.sh
```

Exited non-zero as expected with `must not traverse a symbolic link`; the harness itself exited `0` after asserting the rejection and cleaning its fixture.

```text
CHEESEWAF_TARGETS=darwin/arm64 \
  CHEESEWAF_RELEASE_DIR=release-r2-smoke \
  CHEESEWAF_RELEASE_WORK_DIR=tmp/release-r2-smoke \
  CHEESEWAF_REF_NAME=dev CHEESEWAF_RUN_NUMBER=822 \
  CHEESEWAF_COMMIT=9ccb5eeaa450fefad792dadeebff653b95de8827 \
  bash scripts/ci/package-release.sh
```

Exit `0`; built the Web UI, arm64 macOS CLI, GUI, archive, metadata, and checksums.

```text
CHEESEWAF_REQUIRE_SIGNING=warn bash scripts/ci/verify-release.sh release-r2-smoke
```

Exit `0`; full startup and JavaScript/CSS MIME smoke passed for one 52,687,302-byte archive. Generated smoke directories and the build-created `.keep` change were removed/restored afterward.

```text
make -n package-windows-nsis-payload
git diff --check
```

Both exited `0` before the implementation commit.

## Concerns

- No real Windows certificate, Apple Developer ID/notarization credentials, `makensis`, `shellcheck`, or `actionlint` were available locally. Signature behavior is covered with deterministic verifier fixtures, workflow/static assertions, and the unsigned macOS package smoke; credential-backed signing remains a CI-only gate.
- Docker CLI was present, but `docker info` exited `1` because the configured Colima daemon socket did not exist. The credential injection path is statically pinned here; the full container build/smoke must be exercised by the repository CI.
- No publish command was run, by contract.
