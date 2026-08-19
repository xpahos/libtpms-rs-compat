#!/usr/bin/env python3
"""Pack per-command C-oracle vectors into the binary test fixtures.

Each family owns one fixture under ``src/library/tpm2/testdata/oracles`` and one
magic; the reader lives in ``src/library/tpm2/oracles``:

    create-loaded      CLORACLE  testdata/oracles/create_loaded.bin
    create-primary     CPORACLE  testdata/oracles/create_primary.bin
    dictionary-attack  DAORACLE  testdata/oracles/dictionary_attack.bin
    evict-control      ECORACLE  testdata/oracles/evict_control.bin
    flush-context      FCORACLE  testdata/oracles/flush_context.bin
    nv-commands        NVORACLE  testdata/oracles/nv_commands.bin
    nv-certify         NVORACLE  testdata/oracles/nv_certify.bin

The record format is the 8-byte magic, a big-endian u16 format version, a
big-endian u16 record count, then one record per vector as a u8 name length, the
upper-case ASCII name, a big-endian u32 payload length and the payload.  Records
are sorted by name, so regenerating a fixture from the same input always yields
byte-identical output.

A record's type follows from its name: ``PERMALL_*`` records hold a captured
permanent-state blob, ``VOLATILE_*`` records hold a captured volatile-state
blob (each paired with the ``PERMALL_*`` record of the same boundary), and
every other record holds a TPM response packet.  The Rust readers validate
each record against its declared type.

Dictionary-attack compatibility contract: every fixture that touches a
DA-protected authorization is captured from the ``target/c-oracle`` build of
the vendored libtpms v0.10.1 sources with SessionProcess.c restored to the
pre-revert ``return TPM_RC_RETRY`` (upstream commit 37779b49 changed it to
TPM_RC_SUCCESS; swtpm's test_tpm2_avoid_da_lockout still expects 0x922).
Under that contract the first authorization of a startup cycle against a
non-lockout DA-protected entity (an NV index or a transient or persistent
object) records the SU_DA_USED marker, rebuilds the NV image and answers
TPM_RC_RETRY.  Lockout authorization takes the separate CheckLockedOut(TRUE)
path: it only checks lockoutAuthEnabled, performs no daUsed transition, and
never answers TPM_RC_RETRY merely because daUsed is clear.  Fixtures captured
before that patch (nv_certify.bin) carry responses from the post-transition
cycle state; their Rust harnesses enter that complete state (daUsed flag,
SU_DA_USED orderly marker and the rebuilt NV image) through the production
transition before the first DA-protected authorization instead of encoding
per-handle behavior.

Regenerate a fixture from a ``NAME <hex>`` listing:

    scripts/generate_command_vectors_fixture.py create-primary vectors.txt
    scripts/generate_command_vectors_fixture.py nv-commands vectors.txt

Recover such a listing from a committed fixture (the round trip is exact):

    scripts/generate_command_vectors_fixture.py create-primary --dump > vectors.txt

Verify a committed fixture without writing to it:

    scripts/generate_command_vectors_fixture.py create-primary vectors.txt --check

``--from-rust`` reads the retired ``pub(in ...) const ORACLE_NAME: &str =
"<hex>";`` declarations instead, dropping the ``ORACLE_`` prefix from each name.
"""

import argparse
import re
import struct
import sys
from pathlib import Path

VERSION = 1
TESTDATA = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "library"
    / "tpm2"
    / "testdata"
    / "oracles"
)

FAMILIES = {
    "create": (b"CRORACLE", "create.bin"),
    "create-loaded": (b"CLORACLE", "create_loaded.bin"),
    "create-primary": (b"CPORACLE", "create_primary.bin"),
    "dictionary-attack": (b"DAORACLE", "dictionary_attack.bin"),
    "evict-control": (b"ECORACLE", "evict_control.bin"),
    "flush-context": (b"FCORACLE", "flush_context.bin"),
    "get-test-result": (b"GTORACLE", "get_test_result.bin"),
    "nv-commands": (b"NVORACLE", "nv_commands.bin"),
    "nv-certify": (b"NVORACLE", "nv_certify.bin"),
    "pcr-event": (b"PEORACLE", "pcr_event.bin"),
}

RUST_CONST = re.compile(
    r'const\s+ORACLE_([A-Z0-9_]+)\s*:\s*&str\s*=\s*((?:\s*"[0-9a-fA-F\\\s]*")+)\s*;',
    re.MULTILINE,
)
STRING_PIECE = re.compile(r'"([0-9a-fA-F\\\s]*)"')
CONTINUATION = re.compile(r"\\\s*")
NAME = re.compile(r"[A-Z0-9_]+")


def read_rust(text):
    for match in RUST_CONST.finditer(text):
        pieces = (
            CONTINUATION.sub("", piece) for piece in STRING_PIECE.findall(match.group(2))
        )
        yield match.group(1), "".join("".join(piece.split()) for piece in pieces)


def read_listing(text):
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise SystemExit(f"line {number}: expected 'NAME <hex>'")
        yield parts[0], parts[1]


def pack(magic, vectors):
    records = {}
    for name, payload in vectors:
        if not NAME.fullmatch(name):
            raise SystemExit(f"{name}: names are upper-case ASCII, digits and underscores")
        if len(name) > 0xFF:
            raise SystemExit(f"{name}: the name does not fit a single length byte")
        if len(payload) % 2:
            raise SystemExit(f"{name}: an odd number of hex digits")
        if name in records:
            raise SystemExit(f"{name}: duplicate vector")
        records[name] = bytes.fromhex(payload)

    out = bytearray(magic)
    out += struct.pack(">HH", VERSION, len(records))
    for name in sorted(records):
        payload = records[name]
        out.append(len(name))
        out += name.encode("ascii")
        out += struct.pack(">I", len(payload))
        out += payload
    return bytes(out)


def unpack(magic, blob):
    if blob[: len(magic)] != magic:
        raise SystemExit(f"bad magic: expected {magic.decode('ascii')}")
    version, count = struct.unpack_from(">HH", blob, len(magic))
    if version != VERSION:
        raise SystemExit(f"unsupported format version {version}")
    at = len(magic) + 4
    for _ in range(count):
        name_length = blob[at]
        at += 1
        name = blob[at : at + name_length].decode("ascii")
        at += name_length
        (payload_length,) = struct.unpack_from(">I", blob, at)
        at += 4
        yield name, blob[at : at + payload_length].hex()
        at += payload_length
    if at != len(blob):
        raise SystemExit(f"{len(blob) - at} trailing bytes")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("family", choices=sorted(FAMILIES))
    parser.add_argument("source", nargs="?", help="a 'NAME <hex>' listing, or - for stdin")
    parser.add_argument("-o", "--output", help="override the fixture path")
    parser.add_argument(
        "--from-rust",
        action="store_true",
        help="read ORACLE_* &str constants from a Rust source file",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare against the committed fixture instead of writing it",
    )
    parser.add_argument(
        "--dump",
        action="store_true",
        help="print the committed fixture as a 'NAME <hex>' listing and exit",
    )
    args = parser.parse_args()

    magic, filename = FAMILIES[args.family]
    output = Path(args.output) if args.output else TESTDATA / filename

    if args.dump:
        for name, payload in unpack(magic, output.read_bytes()):
            print(name, payload)
        return

    if args.source is None:
        parser.error("a source listing is required unless --dump is given")
    text = sys.stdin.read() if args.source == "-" else Path(args.source).read_text("utf-8")
    vectors = list(read_rust(text) if args.from_rust else read_listing(text))
    if not vectors:
        raise SystemExit(f"{args.source}: no vectors found")

    blob = pack(magic, vectors)
    if args.check:
        if output.read_bytes() != blob:
            raise SystemExit(f"{output}: stale; regenerate it from {args.source}")
        print(f"{output}: up to date", file=sys.stderr)
        return

    output.write_bytes(blob)
    print(f"{output}: {len(vectors)} vectors, {len(blob)} bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
