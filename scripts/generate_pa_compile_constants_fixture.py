#!/usr/bin/env python3
"""Regenerate the PA_COMPILE_CONSTANTS test fixture from the vendored libtpms.

Produces ``src/library/tpm2/testdata/pa_compile_constants_v3.bin``: the exact
byte stream ``PACompileConstants_Marshal`` (libtpms/src/tpm2/NVMarshal.c)
emits for the pinned vendored configuration -- NV_HEADER (version 3, magic
0xc9ea6431, min_version 1), the u32 entry count, one big-endian u32 per
``pa_compile_constants[]`` entry, and the empty future-version skip block.

How it works
------------
The ``pa_compile_constants[]`` initializer is extracted *verbatim* from the
vendored ``NVMarshal.c`` (so names, order, and comparison operators cannot
drift from upstream) and compiled into a small C oracle program against the
vendored TPM 2 profile headers.  The compiler therefore evaluates every
``COMPILE_CONSTANT`` macro exactly as the pinned upstream build would.  The
oracle prints one ``index<TAB>name<TAB>value<TAB>cmp`` line per entry (for
eyeballing against the Rust table) and writes the fixture bytes.

Determinism: the output depends only on the vendored sources and headers
under ``libtpms/``; no network access, no timestamps, no environment input
beyond the C compiler and the OpenSSL headers libtpms itself builds against.

Usage:
    python3 scripts/generate_pa_compile_constants_fixture.py
    python3 scripts/generate_pa_compile_constants_fixture.py --check
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NVMARSHAL = REPO_ROOT / "libtpms" / "src" / "tpm2" / "NVMarshal.c"
FIXTURE = (
    REPO_ROOT / "src" / "library" / "tpm2" / "testdata" / "pa_compile_constants_v3.bin"
)

# The marshalled section constants (NVMarshal.c).
PA_COMPILE_CONSTANTS_MAGIC = 0xC9EA6431
PA_COMPILE_CONSTANTS_VERSION = 3
# NV_HEADER_Marshal is called with min_version = 1.
PA_COMPILE_CONSTANTS_MIN_VERSION = 1

ORACLE_TEMPLATE = """\
#include <stdio.h>
#include <stdlib.h>
#include "Tpm.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* ---- begin verbatim extract from NVMarshal.c ---- */
{table}
/* ---- end verbatim extract from NVMarshal.c ---- */

static void put_u16(FILE *f, unsigned v)
{{
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}}

static void put_u32(FILE *f, unsigned long v)
{{
    fputc((int)((v >> 24) & 0xff), f);
    fputc((int)((v >> 16) & 0xff), f);
    fputc((int)((v >> 8) & 0xff), f);
    fputc((int)(v & 0xff), f);
}}

int main(int argc, char **argv)
{{
    static const char *cmp_names[] = {{ "EQ", "LE", "GE", "DONTCARE" }};
    size_t i;
    FILE *f;

    if (argc != 2) {{
        fprintf(stderr, "usage: %s <fixture-path>\\n", argv[0]);
        return 1;
    }}
    f = fopen(argv[1], "wb");
    if (!f) {{
        perror(argv[1]);
        return 1;
    }}

    /* NV_HEADER_Marshal(version=3, magic, min_version=1) */
    put_u16(f, {version}u);
    put_u32(f, 0x{magic:08x}ul);
    put_u16(f, {min_version}u);
    /* declared array size, then the constants */
    put_u32(f, (unsigned long)ARRAY_SIZE(pa_compile_constants));
    for (i = 0; i < ARRAY_SIZE(pa_compile_constants); i++) {{
        put_u32(f, (unsigned long)pa_compile_constants[i].constant);
        printf("%zu\\t%s\\t%lu\\t%s\\n", i, pa_compile_constants[i].name,
               (unsigned long)pa_compile_constants[i].constant,
               cmp_names[pa_compile_constants[i].cmp]);
    }}
    /* BLOCK_SKIP_WRITE_PUSH(TRUE)/POP with nothing appended: 01 00 00 */
    fputc(1, f);
    put_u16(f, 0);

    if (fclose(f) != 0) {{
        perror(argv[1]);
        return 1;
    }}
    return 0;
}}
"""


def extract_table(source: str) -> str:
    """Extract the pa_compile_constants[] definition verbatim.

    The captured block spans from ``static const struct _entry {`` through
    the closing ``};`` and includes the ``COMPILE_CONSTANT`` helper macro
    and the ``CONTEXT_ENCRYPT_ALGORITHM_`` conditional define embedded in
    the initializer.
    """
    match = re.search(
        r"^static const struct _entry \{.*?^\} pa_compile_constants\[\] = \{.*?^\};",
        source,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        raise SystemExit(f"error: pa_compile_constants[] not found in {NVMARSHAL}")
    return match.group(0)


def openssl_include_flags() -> list[str]:
    pkg_config = shutil.which("pkg-config")
    if pkg_config:
        probe = subprocess.run(
            [pkg_config, "--cflags-only-I", "openssl"],
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0 and probe.stdout.strip():
            return probe.stdout.split()
    for prefix in ("/opt/local/libexec/openssl3", "/opt/homebrew/opt/openssl",
                   "/usr/local/opt/openssl", "/usr"):
        if (Path(prefix) / "include" / "openssl" / "bn.h").is_file():
            return [f"-I{prefix}/include"]
    raise SystemExit("error: OpenSSL headers not found (needed by tpm_radix.h)")


def build_fixture() -> tuple[bytes, str]:
    source = NVMARSHAL.read_text()
    table = extract_table(source)
    program = ORACLE_TEMPLATE.format(
        table=table,
        version=PA_COMPILE_CONSTANTS_VERSION,
        magic=PA_COMPILE_CONSTANTS_MAGIC,
        min_version=PA_COMPILE_CONSTANTS_MIN_VERSION,
    )

    tpm2_dir = REPO_ROOT / "libtpms" / "src" / "tpm2"
    include_flags = [
        f"-I{tpm2_dir}",
        f"-I{tpm2_dir / 'crypto'}",
        f"-I{tpm2_dir / 'crypto' / 'openssl'}",
        f"-I{REPO_ROOT / 'libtpms' / 'src'}",
        f"-I{REPO_ROOT / 'libtpms' / 'include' / 'libtpms'}",
        *openssl_include_flags(),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        oracle_c = tmpdir / "oracle.c"
        oracle_bin = tmpdir / "oracle"
        fixture_out = tmpdir / "fixture.bin"
        oracle_c.write_text(program)
        # Same feature macros the upstream tpm2 build passes (Makefile.am).
        subprocess.run(
            ["cc", "-DTPM_POSIX", "-D_POSIX_", *include_flags,
             str(oracle_c), "-o", str(oracle_bin)],
            check=True,
        )
        listing = subprocess.run(
            [str(oracle_bin), str(fixture_out)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return fixture_out.read_bytes(), listing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in fixture instead of rewriting it",
    )
    parser.add_argument(
        "--print-table",
        action="store_true",
        help="print the index/name/value/cmp listing to stdout",
    )
    args = parser.parse_args()

    fixture, listing = build_fixture()
    if args.print_table:
        sys.stdout.write(listing)

    if args.check:
        current = FIXTURE.read_bytes() if FIXTURE.is_file() else None
        if current != fixture:
            print(f"error: {FIXTURE} is stale; rerun {Path(__file__).name}",
                  file=sys.stderr)
            return 1
        print(f"{FIXTURE}: OK ({len(fixture)} bytes)")
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_bytes(fixture)
    print(f"wrote {FIXTURE} ({len(fixture)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
