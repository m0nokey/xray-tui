#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/controller/compose.yml"
IMAGE="local/xray-tui:latest"
BASE_IMAGE="alpine:3.23"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"

# Match the container process to the host user so the 0700 Vault directory
# remains writable without granting the controller root privileges.
export XRAY_TUI_UID="${XRAY_TUI_UID:-$(id -u)}"

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

docker_hub_manifest_digest() {
    local image_ref="$1" repo tag token
    repo="${image_ref%:*}"
    tag="${image_ref##*:}"
    [[ "$repo" == */* ]] || repo="library/$repo"
    token="$(curl -fsSL --connect-timeout 10 --max-time 30 \
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" \
        | sed -nE 's/.*"token"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' || true)"
    [[ -n "$token" ]] || return 0
    curl -fsSI --connect-timeout 10 --max-time 30 \
        -H "Authorization: Bearer $token" \
        -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json' \
        "https://registry-1.docker.io/v2/${repo}/manifests/${tag}" \
        | tr -d '\r' \
        | awk 'tolower($1)=="docker-content-digest:" {print $2; exit}' || true
}

resolve_digest() {
    local digest
    digest="$(docker buildx imagetools inspect "$BASE_IMAGE" 2>/dev/null | awk '/^Digest:/ {print $2; exit}' || true)"
    if [[ -z "$digest" ]]; then
        digest="$(docker manifest inspect "$BASE_IMAGE" 2>/dev/null | sed -nE 's/.*"digest"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1 || true)"
    fi
    [[ -n "$digest" ]] || digest="$(docker_hub_manifest_digest "$BASE_IMAGE")"
    printf '%s' "$digest"
}

image_label() {
    docker image inspect "$IMAGE" --format "{{ index .Config.Labels \"$1\" }}" 2>/dev/null || true
}

build_if_needed() {
    local digest dockerfile_hash current_digest current_hash current_uid
    digest="$(resolve_digest)"
    dockerfile_hash="$(file_sha256 "$ROOT_DIR/controller/Dockerfile")"
    current_digest="$(image_label xray.tui.base-image)"
    current_hash="$(image_label xray.tui.dockerfile-sha256)"
    current_uid="$(image_label xray.tui.runtime-uid)"

    if [[ -n "$digest" && "$current_digest" == "$BASE_IMAGE@$digest" && "$current_hash" == "$dockerfile_hash" && "$current_uid" == "$XRAY_TUI_UID" ]]; then
        return 0
    fi
    if [[ -z "$digest" && -n "$(docker image inspect "$IMAGE" 2>/dev/null)" ]]; then
        printf 'Warning: base image digest unavailable; using existing local image.\n' >&2
        return 0
    fi

    local base_arg="$BASE_IMAGE"
    [[ -n "$digest" ]] && base_arg="${BASE_IMAGE}@${digest}"
    docker compose -f "$COMPOSE_FILE" build \
        --build-arg "XRAY_TUI_BASE_IMAGE=$base_arg" \
        --build-arg "XRAY_TUI_DOCKERFILE_SHA256=$dockerfile_hash" \
        xray-tui
}

build_if_needed
printf '\033[H\033[2J\033[3J'
exec docker compose -f "$COMPOSE_FILE" run --rm --pull never xray-tui "$@"
