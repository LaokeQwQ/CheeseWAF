#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
image_tag="${CHEESEWAF_DOCKER_TAG:-cheesewaf:ci}"
pull_args=()
build_args=()

if [[ "${DOCKER_PULL:-1}" == "1" ]]; then
  pull_args+=(--pull)
fi

for entry in \
  "GO_IMAGE:${CHEESEWAF_GO_IMAGE:-}" \
  "NODE_IMAGE:${CHEESEWAF_NODE_IMAGE:-}" \
  "RUNTIME_IMAGE:${CHEESEWAF_RUNTIME_IMAGE:-}"; do
  name="${entry%%:*}"
  value="${entry#*:}"
  if [[ -n "$value" ]]; then
    build_args+=(--build-arg "${name}=${value}")
  fi
done

docker build \
  "${pull_args[@]}" \
  "${build_args[@]}" \
  --file "${repo_root}/deploy/docker/Dockerfile" \
  --tag "$image_tag" \
  "$repo_root"

container_name="cheesewaf-ci-smoke-$$"
log_file="$(mktemp)"
setup_response="$(mktemp)"
trap 'docker rm -f "$container_name" >/dev/null 2>&1 || true; rm -f "$log_file" "$setup_response"' EXIT

runtime_user="$(docker image inspect --format '{{.Config.User}}' "$image_tag")"
[[ -n "$runtime_user" && "$runtime_user" != "0" && "$runtime_user" != "root" ]] || {
  echo "::error::container image must declare a non-root runtime user" >&2
  exit 1
}

docker run --detach \
  --name "$container_name" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
  --tmpfs /var/lib/cheesewaf:rw,nosuid,nodev,size=64m \
  --tmpfs /var/log/cheesewaf:rw,noexec,nosuid,nodev,size=32m \
  --publish 127.0.0.1::9443 \
  "$image_tag" >/dev/null

host_port="$(docker port "$container_name" 9443/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -n 1)"
[[ "$host_port" =~ ^[0-9]+$ ]] || {
  docker logs "$container_name" >&2 || true
  echo "::error::unable to discover mapped admin port" >&2
  exit 1
}

ready=""
for _ in $(seq 1 45); do
  if ! docker inspect --format '{{.State.Running}}' "$container_name" | grep -qx true; then
    docker logs "$container_name" >&2 || true
    echo "::error::container exited during startup smoke" >&2
    exit 1
  fi
  if curl --fail --silent --show-error --insecure "https://127.0.0.1:${host_port}/" >/dev/null 2>&1; then
    ready="yes"
    break
  fi
  sleep 1
done
[[ -n "$ready" ]] || {
  docker logs "$container_name" >&2 || true
  echo "::error::container admin endpoint did not become ready" >&2
  exit 1
}

curl --fail --silent --show-error --insecure \
  --header 'Content-Type: application/json' \
  --data '{"username":"smoke-admin","password":"CheeseWAF-CI-Smoke-Only-2026!","admin_listen":"0.0.0.0:9443","admin_strategy":"public_tls"}' \
  "https://127.0.0.1:${host_port}/api/setup" >"$setup_response"
grep -q '"setup_complete":true' "$setup_response" || {
  cat "$setup_response" >&2
  echo "::error::fresh container setup did not complete" >&2
  exit 1
}

docker exec "$container_name" /usr/local/bin/cheesewaf-entrypoint healthcheck >/dev/null || {
  docker logs "$container_name" >&2 || true
  echo "::error::container readiness command failed after setup" >&2
  exit 1
}

asset_path="$(curl --fail --silent --show-error --insecure "https://127.0.0.1:${host_port}/" | sed -nE 's#.*(\/assets\/[^"'"'"' ]+\.js).*#\1#p' | head -n 1)"
[[ -n "$asset_path" ]] || {
  echo "::error::container UI entrypoint did not reference a JavaScript asset" >&2
  exit 1
}
content_type="$(curl --fail --silent --show-error --insecure --head "https://127.0.0.1:${host_port}${asset_path}" | awk 'BEGIN { IGNORECASE=1 } /^content-type:/ { sub(/^[^:]+:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }')"
[[ "$content_type" == *javascript* ]] || {
  echo "::error::container JavaScript asset returned unexpected MIME type: ${content_type}" >&2
  exit 1
}

echo "Container smoke passed as ${runtime_user}; fresh setup, admin readiness, HTTPS, and JavaScript MIME are healthy."
