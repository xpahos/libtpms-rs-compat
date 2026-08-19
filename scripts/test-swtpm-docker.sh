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

# TODO: remove this after tests fix
ctrl3="$workspace/swtpm/tests/test_tpm2_ctrlchannel3"
old_guard='skip_test_no_tpm12 "${SWTPM_EXE}"'
new_guard='skip_test_no_tpm20 "${SWTPM_EXE}"'
if [ "$(grep -cxF -- "$old_guard" "$ctrl3" || true)" != 1 ]; then
    echo "test-swtpm-docker: expected exactly one exact '$old_guard' line in $ctrl3" >&2
    exit 1
fi
awk -v old="$old_guard" -v new="$new_guard" '$0 == old { print new; next } { print }' "$ctrl3" > "$ctrl3.tmp"
cat "$ctrl3.tmp" > "$ctrl3"
rm "$ctrl3.tmp"
if [ "$(grep -cxF -- "$new_guard" "$ctrl3" || true)" != 1 ]; then
    echo "test-swtpm-docker: corrected guard '$new_guard' does not occur exactly once in $ctrl3" >&2
    exit 1
fi
if grep -qF skip_test_no_tpm12 "$ctrl3"; then
    echo "test-swtpm-docker: incorrect guard still present in $ctrl3" >&2
    exit 1
fi

cd "$workspace"
exec make test-swtpm PROFILE="${PROFILE:-debug}"
