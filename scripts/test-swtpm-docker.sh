#!/bin/sh
set -eu

src="${SRC_DIR:-/repo}"
workspace="${WORKSPACE_DIR:-$HOME/workspace}"
image_id="${SWTPM_DOCKER_IMAGE_ID:?}"
marker="$CARGO_TARGET_DIR/.swtpm-docker-image-id"

if [ ! -f "$marker" ] || [ "$(cat "$marker")" != "$image_id" ]; then
    rm -rf "$CARGO_TARGET_DIR/debug/swtpm" "$CARGO_TARGET_DIR/release/swtpm"
    printf '%s\n' "$image_id" > "$marker"
fi

mkdir -p "$workspace"
find "$src" -mindepth 1 -maxdepth 1 \
    ! -name .git \
    ! -name target \
    ! -name build \
    ! -name .pytest_cache \
    ! -name __pycache__ \
    -exec cp -a --no-preserve=ownership -t "$workspace" -- {} +

cd "$workspace"
exec make test-swtpm PROFILE="${PROFILE:-debug}"
