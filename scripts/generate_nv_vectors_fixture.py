#!/usr/bin/env python3
"""Pack the TPM2_NV_* C-oracle vectors into the binary test fixtures.

The vectors were captured from the vendored C libtpms with
``target/c-oracle/oracle25.c`` (the NV command suite) and
``target/c-oracle/oracle26.c`` (TPM2_NV_Certify).  This script converts a
``name = "<hex>"`` listing into the deterministic record format read by
``src/library/tpm2/nv_vectors.rs``.

Usage::

    generate_nv_vectors_fixture.py <listing.txt> <output.bin>

Each non-empty input line is ``NAME <hex>``.  ``--from-rust`` instead reads a
legacy ``pub(in ...) const ORACLE_NAME: &str = "<hex>";`` Rust source file.

Only the NV fixtures are generated here; the other oracle vector families keep
their own generators.
"""

import argparse
import re
import struct
import sys

MAGIC = b"NVORACLE"
VERSION = 1

RUST_CONST = re.compile(
    r'const\s+ORACLE_([A-Z0-9_]+)\s*:\s*&str\s*=\s*((?:\s*"[0-9a-fA-F\\\s]*")+)\s*;',
    re.MULTILINE,
)
STRING_PIECE = re.compile(r'"([0-9a-fA-F\\\s]*)"')
CONTINUATION = re.compile(r"\\\s*")


def read_rust(text):
    for match in RUST_CONST.finditer(text):
        name = match.group(1)
        pieces = (
            CONTINUATION.sub("", piece) for piece in STRING_PIECE.findall(match.group(2))
        )
        yield name, "".join("".join(piece.split()) for piece in pieces)


def read_listing(text):
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise SystemExit(f"line {number}: expected 'NAME <hex>'")
        yield parts[0], parts[1]


def pack(vectors):
    records = {}
    for name, payload in vectors:
        if not re.fullmatch(r"[A-Z0-9_]+", name):
            raise SystemExit(f"{name}: names are upper-case ASCII, digits and underscores")
        if len(name) > 0xFF:
            raise SystemExit(f"{name}: the name does not fit a single length byte")
        if len(payload) % 2:
            raise SystemExit(f"{name}: an odd number of hex digits")
        if name in records:
            raise SystemExit(f"{name}: duplicate vector")
        records[name] = bytes.fromhex(payload)

    out = bytearray(MAGIC)
    out += struct.pack(">HH", VERSION, len(records))
    for name in sorted(records):
        payload = records[name]
        out.append(len(name))
        out += name.encode("ascii")
        out += struct.pack(">I", len(payload))
        out += payload
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("output")
    parser.add_argument(
        "--from-rust",
        action="store_true",
        help="read ORACLE_* &str constants from a Rust source file",
    )
    args = parser.parse_args()

    with open(args.source, "r", encoding="utf-8") as handle:
        text = handle.read()
    vectors = list(read_rust(text) if args.from_rust else read_listing(text))
    if not vectors:
        raise SystemExit(f"{args.source}: no vectors found")

    blob = pack(vectors)
    with open(args.output, "wb") as handle:
        handle.write(blob)
    print(f"{args.output}: {len(vectors)} vectors, {len(blob)} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
