#!/usr/bin/env bash
# Run the P0 fuzz targets with a bounded wall time. Intended for PR CI and
# local smoke; nightly jobs should set FUZZ_TIME to 10m or more.
set -euo pipefail

cd "$(dirname "$0")/.."

FUZZ_TIME="${FUZZ_TIME:-10s}"
TARGETS=(
  "./internal/crp:FuzzParseArchive"
  "./internal/crp:FuzzParseManifest"
  "./internal/crp:FuzzParseArchiveSignatures"
  "./internal/crp:FuzzRuntimeStateJSON"
  "./internal/crp/activation:FuzzProcessAcknowledgementShape"
  "./internal/engine:FuzzNormalizeRequestPath"
  "./internal/engine:FuzzRequestContext"
  "./internal/engine:FuzzRuleCompile"
  "./internal/engine/semantic:FuzzMultipartInputs"
  "./internal/netguard:FuzzValidateURL"
  "./internal/audit:FuzzDecodeEvent"
  "./internal/diagnostics:FuzzDecodePackage"
  "./internal/config:FuzzConfigYAML"
  "./internal/monitor/notifier:FuzzWebhookEndpoint"
  "./internal/plugin/hostapi:FuzzDecodeFrame"
)

for item in "${TARGETS[@]}"; do
  pkg="${item%%:*}"
  target="${item##*:}"
  echo "==> ${pkg} ${target} (${FUZZ_TIME})"
  go test -run='^$' -fuzz="^${target}$" -fuzztime="${FUZZ_TIME}" "${pkg}"
done

echo "fuzz smoke passed: ${#TARGETS[@]} targets"
