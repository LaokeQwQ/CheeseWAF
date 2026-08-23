#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
image_tag="${CHEESEWAF_DOCKER_TAG:-cheesewaf:ci}"
platforms="${CHEESEWAF_DOCKER_PLATFORMS:-linux/amd64,linux/arm64}"
# Build the argv in one array. Bash 3.2 + set -u rejects "${empty[@]}".
if docker buildx version >/dev/null 2>&1; then
  docker_build=(docker buildx build)
  use_buildx=1
else
  docker_build=(docker build)
  use_buildx=0
fi

if [[ "${DOCKER_PULL:-1}" == "1" ]]; then
  docker_build+=(--pull)
fi

for entry in \
  "GO_IMAGE:${CHEESEWAF_GO_IMAGE:-}" \
  "NODE_IMAGE:${CHEESEWAF_NODE_IMAGE:-}" \
  "RUNTIME_IMAGE:${CHEESEWAF_RUNTIME_IMAGE:-}"; do
  name="${entry%%:*}"
  value="${entry#*:}"
  if [[ -n "$value" ]]; then
    docker_build+=(--build-arg "${name}=${value}")
  fi
done

docker_build+=(
  --file "${repo_root}/deploy/docker/Dockerfile"
  --tag "$image_tag"
)

if [[ "$use_buildx" -eq 1 ]]; then
  if ! docker buildx inspect cheesewaf >/dev/null 2>&1; then
    docker buildx create --name cheesewaf --driver docker-container --use >/dev/null
  else
    docker buildx use cheesewaf >/dev/null
  fi
  docker buildx inspect --bootstrap >/dev/null

  host_os="$(docker version -f '{{.Server.Os}}')"
  host_arch="$(docker version -f '{{.Server.Arch}}')"
  host_platform="${host_os}/${host_arch}"

  if [[ -n "$platforms" ]]; then
    echo "building container platforms ${platforms}"
    "${docker_build[@]}" --platform "$platforms" --output type=cacheonly "$repo_root"
  fi

  echo "loading host platform ${host_platform} as ${image_tag}"
  "${docker_build[@]}" --platform "$host_platform" --load "$repo_root"
else
  "${docker_build[@]}" "$repo_root"
fi

container_name="cheesewaf-ci-smoke-$$"
log_file="$(mktemp)"
setup_response="$(mktemp)"
setup_payload="$(mktemp)"
setup_header="$(mktemp)"
secret_env_file="$(mktemp)"
trap 'docker rm -f "$container_name" >/dev/null 2>&1 || true; rm -f "$log_file" "$setup_response" "$setup_payload" "$setup_header" "$secret_env_file"' EXIT

runtime_user="$(docker image inspect --format '{{.Config.User}}' "$image_tag")"
[[ -n "$runtime_user" && "$runtime_user" != "0" && "$runtime_user" != "root" ]] || {
  echo "::error::container image must declare a non-root runtime user" >&2
  exit 1
}

command -v python3 >/dev/null 2>&1 || {
  echo "::error::python3 is required to reserve a loopback port for the container smoke" >&2
  exit 1
}
host_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
[[ "$host_port" =~ ^[0-9]+$ ]] || {
  echo "::error::unable to reserve a loopback port for the container smoke" >&2
  exit 1
}

# Match Dockerfile CHEESEWAF_UID/GID (10001). Empty root-owned tmpfs made
# entrypoint "mkdir .../config: Permission denied", container exited, and
# HostPort was empty (surfaced as a misleading port-mapping error).
cheesewaf_uid=10001
cheesewaf_gid=10001

# Generate one-run credentials and pass them through files so neither value is
# committed nor exposed in the docker/curl argument list.
smoke_setup_token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
smoke_admin_password="Cw1!$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')Aa"
printf 'CHEESEWAF_SETUP_TOKEN=%s\n' "$smoke_setup_token" >"$secret_env_file"
printf 'X-CheeseWAF-Setup-Token: %s\n' "$smoke_setup_token" >"$setup_header"
printf '{"username":"smoke-admin","password":"%s","admin_listen":"0.0.0.0:9443","admin_strategy":"public_tls"}\n' \
  "$smoke_admin_password" >"$setup_payload"
chmod 0600 "$secret_env_file" "$setup_header" "$setup_payload"

docker run --detach \
  --name "$container_name" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --env-file "$secret_env_file" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
  --tmpfs "/var/lib/cheesewaf:rw,nosuid,nodev,size=64m,uid=${cheesewaf_uid},gid=${cheesewaf_gid},mode=0755" \
  --tmpfs "/var/log/cheesewaf:rw,noexec,nosuid,nodev,size=32m,uid=${cheesewaf_uid},gid=${cheesewaf_gid},mode=0755" \
  --publish "127.0.0.1:${host_port}:9443/tcp" \
  "$image_tag" >/dev/null

# Give the entrypoint a moment; fail fast if it dies on startup (permissions etc.).
sleep 1
if ! docker inspect --format '{{.State.Running}}' "$container_name" | grep -qx true; then
  docker logs "$container_name" >&2 || true
  echo "::error::container exited immediately during smoke start" >&2
  exit 1
fi

mapped_port="$(docker inspect --format '{{with index .NetworkSettings.Ports "9443/tcp"}}{{(index . 0).HostPort}}{{end}}' "$container_name")"
[[ -n "$mapped_port" ]] || {
  docker logs "$container_name" >&2 || true
  echo "::error::container did not publish admin port 9443/tcp (empty HostPort)" >&2
  exit 1
}
[[ "$mapped_port" == "$host_port" ]] || {
  docker logs "$container_name" >&2 || true
  echo "::error::container admin port mapping does not match the reserved loopback port (want ${host_port}, got ${mapped_port})" >&2
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
  --header "@${setup_header}" \
  --data-binary "@${setup_payload}" \
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

docker exec "$container_name" sh -c 'test -r /etc/ssl/certs/ca-certificates.crt && test -s /etc/ssl/certs/ca-certificates.crt' || {
  docker logs "$container_name" >&2 || true
  echo "::error::runtime image is missing a readable CA bundle at /etc/ssl/certs/ca-certificates.crt" >&2
  exit 1
}

if [[ "${CHEESEWAF_SKIP_OUTBOUND_TLS:-0}" != "1" ]]; then
  outbound_url="${CHEESEWAF_OUTBOUND_TLS_URL:-https://example.com}"
  docker exec "$container_name" /usr/local/bin/cheesewaf-entrypoint healthcheck --outbound-tls "$outbound_url" >/dev/null || {
    docker logs "$container_name" >&2 || true
    echo "::error::container outbound HTTPS probe failed for ${outbound_url}" >&2
    exit 1
  }
fi

echo "Container smoke passed as ${runtime_user}; fresh setup, admin readiness, HTTPS, JavaScript MIME, and outbound TLS are healthy."
