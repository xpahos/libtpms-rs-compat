#!/usr/bin/env python3
"""Regenerate the TPMLIB_DecodeBlob oracle fixture from the vendored libtpms.

Produces ``src/library/testdata/decode_blob_oracle.txt``: for every scenario in
``scripts/decode_blob_oracle.c``, the input the harness feeds the *real*
vendored ``TPMLIB_DecodeBlob``, the ``TPM_RESULT`` it returns and the exact
bytes it decodes.  The Rust unit tests replay every record against the safe
decoder, so any upstream change to tag scanning, Base64 filtering or padding
handling shows up as a fixture diff.

Each record carries its own input in hex, so the corpus lives in the C harness
only; the Rust side never restates it.  The harness exercises
``TPMLIB_BLOB_TYPE_INITSTATE`` alone -- upstream indexes its tag table with the
raw blob type, so every other value reads out of bounds and has no behaviour
worth pinning.

The vendored library is built (and cached) by
``generate_validate_state_oracle.py``: this generator reuses its OpenSSL
detection, build settings, fingerprinting and build directory verbatim, so both
oracles share one autotools build of the pinned submodule.

Like that generator, this one is not part of ``make check``: it needs a full
build of the vendored library, not a handful of translation units.

Usage:
    python3 scripts/generate_decode_blob_oracle.py
    python3 scripts/generate_decode_blob_oracle.py --check
    python3 scripts/generate_decode_blob_oracle.py --libtpms-build DIR
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_validate_state_oracle import (  # noqa: E402
    BUILD_ROOT,
    CommandError,
    build_inputs,
    build_libtpms,
    build_settings,
    fingerprint,
    library_path,
    openssl_flags,
    run,
    vendored_fingerprint,
)

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "scripts" / "decode_blob_oracle.c"
FIXTURE = ROOT / "src" / "library" / "testdata" / "decode_blob_oracle.txt"

HEADER = """\
# TPMLIB_DecodeBlob oracle: inputs, results and decoded bytes of the vendored
# C libtpms (libtpms/src/tpm_library.c, TPMLIB_DecodeBlob) for
# TPMLIB_BLOB_TYPE_INITSTATE.
# Regenerate with scripts/generate_decode_blob_oracle.py.
# scenario<TAB>input hex<TAB>result<TAB>decoded hex ('-' when the call fails)
"""


def build_harness(settings, build_dir, workdir):
    binary = workdir / "decode_blob_oracle"
    run(
        [
            *settings.compiler,
            "-O1",
            *settings.cppflags,
            *settings.cflags,
            "-I",
            str(Path(build_dir) / "include"),
            *settings.openssl_cflags,
            "-o",
            str(binary),
            str(HARNESS),
            str(library_path(build_dir)),
            *settings.ldflags,
            *settings.openssl_libs,
        ]
    )
    return binary


def collect(binary):
    command = [str(binary)]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise CommandError(command, result)
    records = [line for line in result.stdout.splitlines() if line.strip()]
    if not records:
        sys.exit("error: the harness produced no records")
    names = []
    for record in records:
        fields = record.split("\t")
        if len(fields) != 4:
            sys.exit(f"error: malformed record {record!r}")
        names.append(fields[0])
    if len(set(names)) != len(names):
        sys.exit("error: the harness repeats a scenario name")
    return HEADER + "\n".join(records) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--libtpms-build", type=Path, default=None)
    args = parser.parse_args()

    settings = build_settings(*openssl_flags())
    build_dir = args.libtpms_build
    if build_dir is None:
        digest = fingerprint(build_inputs(settings), vendored_fingerprint())
        build_dir = BUILD_ROOT / f"libtpms-{digest}"
    build_libtpms(build_dir, settings)
    with tempfile.TemporaryDirectory() as tmp:
        content = collect(build_harness(settings, build_dir, Path(tmp)))

    if args.check:
        if not FIXTURE.exists():
            sys.exit(f"error: {FIXTURE} is missing")
        if FIXTURE.read_text() != content:
            sys.exit(f"error: {FIXTURE} is stale; rerun {Path(__file__).name}")
        print(f"{Path(__file__).name}: OK")
        return

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(content)
    print(f"wrote {FIXTURE}")


if __name__ == "__main__":
    main()
