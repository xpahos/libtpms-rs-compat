#!/bin/sh
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
image=tpms-timing-tests:amd64
work="$repo/target/timing-tests"
mkdir -p "$work/linux-amd64"
docker build --quiet --platform linux/amd64 -t "$image" "$repo/timing-tests/docker" >/dev/null
tty_flag=""
if [ -t 0 ] && [ -t 1 ]; then
    tty_flag="-it"
fi
exec docker run --rm $tty_flag --platform linux/amd64 \
    -v "$repo:/repo:ro" \
    -v "$work:/repo/target/timing-tests" \
    -w /repo/timing-tests \
    -e CARGO_HOME=/repo/target/timing-tests/linux-amd64/cargo-home \
    -e CARGO_TARGET_DIR=/repo/target/timing-tests/linux-amd64/cargo \
    -e PATH=/repo/target/timing-tests/linux-amd64/cargo/release:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$image" "$@"
