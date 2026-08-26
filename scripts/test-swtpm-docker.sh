#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "test-swtpm-docker: the container test runner must run as root (uid 0), got uid $(id -u);" \
        "the upstream root-only tests exit 77 otherwise" >&2
    exit 1
fi

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
    ! -name target \
    ! -name build \
    ! -name .pytest_cache \
    ! -name __pycache__ \
    -exec cp -a --no-preserve=ownership -t "$workspace" -- {} +

for patch_file in "$src/scripts/swtpm-patches"/*.patch; do
    echo "test-swtpm-docker: applying ${patch_file##*/}"
    patch --directory="$workspace/swtpm" --strip=1 --batch --forward < "$patch_file"
done

for tool in tssstartup tssnvdefinespace tsscreateprimary; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "test-swtpm-docker: required IBM TSS command '$tool' not found in PATH" >&2
        exit 1
    fi
done

cd "$workspace"
exec env SWTPM_TEST_IBMTSS2=1 SWTPM_TEST_EXPENSIVE=1 \
    make test-swtpm PROFILE="${PROFILE:-debug}"
