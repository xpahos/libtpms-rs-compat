#!/bin/sh
set -eu
repo=/repo
out=/repo/target/timing-tests/linux-amd64
jobs=$(nproc)

mkdir -p "$out"
rust_target="$out/rust-lib-target"
CARGO_TARGET_DIR="$rust_target" cargo build --release --locked --manifest-path "$repo/Cargo.toml"
rust_lib="$rust_target/release/libtpms.so"
rust_rev=$(git -c safe.directory='*' -C "$repo" rev-parse HEAD)
rust_dirty=$(git -c safe.directory='*' -C "$repo" status --porcelain -- src Cargo.toml build.rs | wc -l)
cat > "$rust_lib.build-info.json" <<JSON
{
  "implementation": "rust (libtpms-rs-compat)",
  "revision": "$rust_rev",
  "dirty_paths_in_src_cargo_toml_build_rs": $rust_dirty,
  "profile": "release",
  "command": "cargo build --release --locked --manifest-path $repo/Cargo.toml",
  "rustc": "$(rustc -V)",
  "cargo": "$(cargo -V)",
  "rustflags": "${RUSTFLAGS:-}",
  "openssl_pkg_config": "$(pkg-config --modversion libcrypto)",
  "root_cargo_lock_sha256": "$(sha256sum "$repo/Cargo.lock" | cut -d' ' -f1)"
}
JSON

ref_src="$out/reference-src"
ref_build="$out/reference-build"
rm -rf "$ref_src" "$ref_build"
mkdir -p "$ref_src" "$ref_build"
git -c safe.directory='*' -C "$repo/libtpms" archive --format=tar HEAD | tar -x -C "$ref_src"
(cd "$ref_src" && NOCONFIGURE=1 ./autogen.sh)
(cd "$ref_build" && "$ref_src/configure" --with-tpm2 --with-openssl --enable-shared --disable-static >/dev/null)
make -C "$ref_build" -j"$jobs" >/dev/null
ref_lib="$ref_build/src/.libs/libtpms.so"
ref_rev=$(git -c safe.directory='*' -C "$repo/libtpms" rev-parse HEAD)
ref_desc=$(git -c safe.directory='*' -C "$repo/libtpms" describe --tags --always)
ref_dirty=$(git -c safe.directory='*' -C "$repo/libtpms" status --porcelain | wc -l)
cat > "$ref_lib.build-info.json" <<JSON
{
  "implementation": "reference C libtpms (pinned submodule, unpatched)",
  "revision": "$ref_rev",
  "describe": "$ref_desc",
  "built_from": "git archive HEAD (uncommitted submodule changes are not compiled; dirty entries: $ref_dirty)",
  "configure": "--with-tpm2 --with-openssl --enable-shared --disable-static",
  "cflags": "autoconf default (-g -O2)",
  "cc": "$(cc --version | head -n1)",
  "openssl_pkg_config": "$(pkg-config --modversion libcrypto)"
}
JSON

echo "rust library:      $rust_lib"
echo "reference library: $ref_lib"
ldd "$rust_lib" | grep -E 'libcrypto|libssl' || true
ldd "$ref_lib" | grep -E 'libcrypto|libssl' || true
