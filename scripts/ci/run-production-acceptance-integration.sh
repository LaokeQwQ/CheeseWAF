#!/usr/bin/env bash
set -euo pipefail

required_env=(
  CHEESEWAF_POSTGRES_TEST_DSN
  CHEESEWAF_REDIS_RUNTIME_TEST_ADDR
  CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR
)
for variable in "${required_env[@]}"; do
  if [[ -z "${!variable:-}" ]]; then
    echo "::error::${variable} is required for production acceptance integration"
    exit 2
  fi
done

registry_dir="${CHEESEWAF_CRP_SIDECAR_TEST_REGISTRY_DIR}"
if [[ ! -d "${registry_dir}" || -L "${registry_dir}" ]]; then
  echo "::error::CRP sidecar test registry must be an existing, non-symlink directory"
  exit 2
fi
if stat -c '%a' "${registry_dir}" >/dev/null 2>&1; then
  registry_mode="$(stat -c '%a' "${registry_dir}")"
else
  registry_mode="$(stat -f '%Lp' "${registry_dir}")"
fi
if [[ "${registry_mode}" != "700" ]]; then
  echo "::error::CRP sidecar test registry must have mode 700"
  exit 2
fi

bash scripts/ci/go-env.sh go test -race -count=1 -timeout=15m ./internal/cli/migration -run '^TestPostgres.*$'
bash scripts/ci/go-env.sh go test -race -count=1 -timeout=15m ./internal/cli -run '^(TestRunServeProductionRealListenerAndSessionRoute|TestRunServeProductionCRPActivationAndRollback)$'
