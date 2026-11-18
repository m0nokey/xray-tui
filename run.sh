#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/controller/compose.yml"
IMAGE="local/xray-tui:latest"
BASE_IMAGE="alpine:3.24"
RELEASE_REPO="m0nokey/xray-tui"
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

# Use the prebuilt controller image attached to the GitHub release that
# matches ./VERSION. VERSION exists only in release archives, so a git
# checkout (no VERSION) keeps building the image locally.
use_release_image() {
    local tag asset base tmp expected actual rimage
    [[ -f "$ROOT_DIR/VERSION" ]] || return 1
    tag="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1

    if [[ "$(image_label xray.tui.release)" == "$tag" \
        && "$(image_label xray.tui.runtime-uid)" == "$XRAY_TUI_UID" ]]; then
        return 0
    fi

    asset="xray-tui-${tag}-controller-image.tar.gz"
    base="https://github.com/${RELEASE_REPO}/releases/download/${tag}"
    rimage="local/xray-tui-release:${tag}"
    tmp="$(mktemp -d)"

    printf 'Downloading controller image %s...\n' "$tag" >&2
    if ! curl -fSL --proto '=https' --connect-timeout 15 --retry 3 \
            -o "$tmp/$asset" "$base/$asset" \
        || ! curl -fsSL --proto '=https' --connect-timeout 15 --retry 3 \
            -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"; then
        rm -rf "$tmp"
        printf 'Warning: could not download release image; building locally.\n' >&2
        return 1
    fi

    expected="$(awk -v f="$asset" '$2 == f {print $1; exit}' "$tmp/SHA256SUMS")"
    actual="$(file_sha256 "$tmp/$asset")"
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        rm -rf "$tmp"
        printf 'Warning: release image checksum mismatch; building locally.\n' >&2
        return 1
    fi

    if ! gzip -dc "$tmp/$asset" | docker load >/dev/null; then
        rm -rf "$tmp"
        printf 'Warning: docker load failed; building locally.\n' >&2
        return 1
    fi
    rm -rf "$tmp"

    # Re-create the runtime user with the host UID (offline, takes ~1s).
    if ! docker build --quiet --tag "$IMAGE" - >/dev/null <<DOCKERFILE_EOF
FROM ${rimage}
USER root
RUN deluser user 2>/dev/null || true; delgroup user 2>/dev/null || true; \\
    addgroup -S user && adduser -S -D -H -u "${XRAY_TUI_UID}" -G user -s /sbin/nologin user
USER user
LABEL xray.tui.release="${tag}" xray.tui.runtime-uid="${XRAY_TUI_UID}"
DOCKERFILE_EOF
    then
        printf 'Warning: could not prepare release image; building locally.\n' >&2
        return 1
    fi
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
printf '\033[H\033[2J\033[3J'
exec docker compose -f "$COMPOSE_FILE" run --rm --pull never xray-tui "$@"
