#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
work_root="$(mktemp -d)"
work_web="${work_root}/web"
trap 'rm -rf "$work_root"' EXIT

mkdir -p "$work_web"
cp \
  "${repo_root}/web/package.json" \
  "${repo_root}/web/package-lock.json" \
  "${repo_root}/web/index.html" \
  "${repo_root}/web/tsconfig.json" \
  "${repo_root}/web/tsconfig.app.json" \
  "${repo_root}/web/tsconfig.node.json" \
  "${repo_root}/web/vite.config.ts" \
  "${repo_root}/web/vite.proxy.ts" \
  "$work_web/"
cp -R "${repo_root}/web/public" "${work_web}/public"
cp -R "${repo_root}/web/scripts" "${work_web}/scripts"
cp -R "${repo_root}/web/src" "${work_web}/src"

pushd "$work_web" >/dev/null
# agent-eyes postinstall runs `pnpm build` and fails without a monorepo layout;
# the published package ships usable dist, so skip lifecycle scripts on CI install.
npm ci --no-audit --no-fund --ignore-scripts
npm run build
popd >/dev/null

rm -rf "${repo_root}/web/dist"
cp -R "${work_web}/dist" "${repo_root}/web/dist"
