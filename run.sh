#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/controller/compose.yml"
IMAGE="local/xray-tui:latest"
BASE_IMAGE="alpine:3.24"
REGISTRY_IMAGE="ghcr.io/m0nokey/xray-tui-controller"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/xray"

# Match the container process to the host user so the 0700 Vault directory
# remains writable without granting the controller root privileges.
export XRAY_TUI_UID="${XRAY_TUI_UID:-$(id -u)}"

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

# The container runs as the host UID (no root, no image changes). It only
# needs a passwd entry for that UID (ssh requires one); mount it read-only.
PASSWD_DIR="$(dirname "$STATE_DIR")/xray-controller"
mkdir -p "$PASSWD_DIR"
chmod 700 "$PASSWD_DIR"
printf 'root:x:0:0:root:/root:/sbin/nologin\nuser:x:%s:%s:user:/tmp:/sbin/nologin\n' \
    "$XRAY_TUI_UID" "$XRAY_TUI_UID" > "$PASSWD_DIR/passwd"
chmod 644 "$PASSWD_DIR/passwd"
export XRAY_TUI_PASSWD_FILE="$PASSWD_DIR/passwd"

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

# Release archives contain a VERSION file. For those, pull the prebuilt
# multi-arch controller image from GitHub Container Registry instead of
# building it. A git checkout (no VERSION) builds the image locally.
use_release_image() {
    local tag platform ref arch
    [[ -f "$ROOT_DIR/VERSION" ]] || return 1
    tag="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1

    case "$(uname -m)" in
        arm64|aarch64) platform="linux/arm64" ;;   # Apple Silicon, ARM Linux
        x86_64|amd64)  platform="linux/amd64" ;;   # Intel/AMD, Linux
        *) return 1 ;;
    esac

    ref="${REGISTRY_IMAGE}:${tag}"
    arch="${platform#linux/}"
    if [[ "$(docker image inspect "$ref" --format '{{.Architecture}}' 2>/dev/null || true)" != "$arch" ]]; then
        printf 'Pulling controller image %s (%s)...\n' "$ref" "$platform" >&2
        if ! docker pull --platform "$platform" "$ref" >&2; then
            printf 'Warning: could not pull %s; building locally.\n' "$ref" >&2
            return 1
        fi
    fi
    IMAGE="$ref"
}

build_if_needed() {
    local digest dockerfile_hash current_digest current_hash current_uid
    if use_release_image; then
        return 0
    fi
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
export XRAY_TUI_IMAGE="$IMAGE"
printf '\033[H\033[2J\033[3J'
exec docker compose -f "$COMPOSE_FILE" run --rm --pull never xray-tui "$@"
