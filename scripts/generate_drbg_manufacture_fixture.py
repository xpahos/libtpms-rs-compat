#!/usr/bin/env python3
"""Regenerate the Manufacture DRBG test vectors from the vendored libtpms.

Produces ``src/library/tpm2/testdata/drbg_manufacture_vectors.bin``: the
exact AES-256 CTR_DRBG state transitions and generated secrets the pinned
vendored implementation (libtpms/src/tpm2/crypto/openssl/CryptRand.c)
computes during TPM_Manufacture, for a fixed 48-byte entropy input.

How it works
------------
The DRBG primitives ``IncrementIv``, ``EncryptDRBG``, ``DRBG_Update`` and
``DRBG_Reseed`` are extracted *verbatim* from the vendored ``CryptRand.c``
(so the counter, key/IV and lastValue semantics cannot drift from
upstream) and compiled into a small C oracle against OpenSSL's
``AES_encrypt`` -- the same block primitive the vendored build maps
``DRBG_ENCRYPT`` to.  The oracle replays the manufacture sequence:

  1. ``DRBG_Instantiate``'s core: zero state, magic, one
     ``DRBG_Reseed(state, entropy48, NULL)``;
  2. the RAM-only 64-byte ``gr.commitNonce`` draw (CryptStartup);
  3. the six 64-byte hierarchy draws in upstream order: EPSeed, SPSeed,
     PPSeed, phProof, shProof, ehProof (HierarchyPreInstall_Init);

once with the ``drbg-continous-test`` runtime attribute disabled and once
enabled, dumping the DRBG seed/reseedCounter/lastValue after step 1 and
after step 3 plus every generated value.  The fixed entropy input is
``((i + 48) & 0xff) ^ 0xa5`` -- the deterministic test entropy pattern the
Rust test suite injects.

Record layout (big-endian scalars), one record per mode (plain first):
    48  seed after instantiate
    16  lastValue after instantiate (4 x u32)
     8  reseedCounter after instantiate
    64  commitNonce
   384  EPSeed, SPSeed, PPSeed, phProof, shProof, ehProof (64 each)
    48  final seed
     8  final reseedCounter
    16  final lastValue (4 x u32)

``lastValue`` is a native-endian UINT32[4] in C; the oracle writes the
values big-endian (like NVMarshal's UINT32_Marshal), so the fixture is
identical on every little-endian generator host -- the only hosts the
crate supports.

Determinism: the output depends only on the vendored sources under
``libtpms/`` and OpenSSL's AES; no network access, no timestamps, no
environment input beyond the C compiler and the OpenSSL headers libtpms
itself builds against.

Usage:
    python3 scripts/generate_drbg_manufacture_fixture.py
    python3 scripts/generate_drbg_manufacture_fixture.py --check
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CRYPTRAND = REPO_ROOT / "libtpms" / "src" / "tpm2" / "crypto" / "openssl" / "CryptRand.c"
FIXTURE = (
    REPO_ROOT / "src" / "library" / "tpm2" / "testdata" / "drbg_manufacture_vectors.bin"
)

# The verbatim-extracted vendored functions, in definition order.
FUNCTION_STARTS = [
    r"^void IncrementIv\(",
    r"^static BOOL EncryptDRBG\(",
    r"^static BOOL DRBG_Update\(",
    r"^BOOL DRBG_Reseed\(",
]

ORACLE_TEMPLATE = """\
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/aes.h>

/* ---- minimal prelude standing in for Tpm.h (LP64 little-endian) ---- */

typedef uint8_t  BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t  INT32;
typedef int      BOOL;
#define TRUE  1
#define FALSE 0
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define NOT_REFERENCED(x) ((void)(x))
typedef uint64_t crypt_uword_t; /* RADIX_BITS 64 */
#define RADIX_BYTES 8

/* CryptRand.h geometry for the pinned AES-256 build */
#define DRBG_KEY_SIZE_BITS 256
#define DRBG_IV_SIZE_BITS  128
#define DRBG_KEY_SIZE_BYTES (DRBG_KEY_SIZE_BITS / 8)
#define DRBG_IV_SIZE_BYTES  (DRBG_IV_SIZE_BITS / 8)
#define DRBG_KEY_SIZE_WORDS (DRBG_KEY_SIZE_BYTES / RADIX_BYTES)
#define DRBG_IV_SIZE_WORDS  (DRBG_IV_SIZE_BYTES / RADIX_BYTES)
#define DRBG_SEED_SIZE_WORDS (DRBG_KEY_SIZE_WORDS + DRBG_IV_SIZE_WORDS)
#define DRBG_SEED_SIZE_BYTES (DRBG_KEY_SIZE_BYTES + DRBG_IV_SIZE_BYTES)

typedef union {{
    BYTE          bytes[DRBG_KEY_SIZE_BYTES];
    crypt_uword_t words[DRBG_KEY_SIZE_WORDS];
}} DRBG_KEY;
typedef union {{
    BYTE          bytes[DRBG_IV_SIZE_BYTES];
    crypt_uword_t words[DRBG_IV_SIZE_WORDS];
}} DRBG_IV;
typedef union {{
    BYTE          bytes[DRBG_SEED_SIZE_BYTES];
    crypt_uword_t words[DRBG_SEED_SIZE_WORDS];
}} DRBG_SEED;
typedef int SEED_COMPAT_LEVEL;
typedef struct {{
    UINT64    reseedCounter;
    UINT32    magic;
    DRBG_SEED seed;
    SEED_COMPAT_LEVEL seedCompatLevel;
    UINT32    lastValue[4];
}} DRBG_STATE;
#define DRBG_MAGIC ((UINT32)0x47425244)

#define pDRBG_KEY(seed) ((DRBG_KEY*)&(((BYTE*)(seed))[0]))
#define pDRBG_IV(seed)  ((DRBG_IV*)&(((BYTE*)(seed))[DRBG_KEY_SIZE_BYTES]))

/* TpmToOsslSym.h: DRBG_ENCRYPT == OpenSSL AES_encrypt */
typedef AES_KEY tpmKeyScheduleAES;
typedef tpmKeyScheduleAES DRBG_KEY_SCHEDULE;
#define SWIZZLE(keySchedule, in, out) \\
    (const BYTE*)(in), (BYTE*)(out), (void*)(keySchedule)
#define DRBG_ENCRYPT_SETUP(key, keySizeInBits, schedule) \\
    AES_set_encrypt_key((key), (keySizeInBits), (AES_KEY*)(schedule))
#define DRBG_ENCRYPT(keySchedule, in, out) \\
    AES_encrypt(SWIZZLE(keySchedule, in, out))

static void oracle_fail(const char *what)
{{
    fprintf(stderr, "oracle failure: %s\\n", what);
    exit(1);
}}
#define pAssert(x) do {{ if (!(x)) oracle_fail("assert: " #x); }} while (0)
#define FATAL_ERROR_ENTROPY  1
#define FATAL_ERROR_INTERNAL 2
#define FAIL_BOOL(code) do {{ oracle_fail("FAIL_BOOL(" #code ")"); return FALSE; }} while (0)

/* RuntimeProfileRequiresAttributeFlags stub: the oracle switches the
 * drbg-continous-test attribute per record. */
struct RuntimeProfile {{ int unused; }};
static struct RuntimeProfile g_RuntimeProfile;
#define RUNTIME_ATTRIBUTE_DRBG_CONTINOUS_TEST 0x100
static int s_continuousTest;
static BOOL RuntimeProfileRequiresAttributeFlags(struct RuntimeProfile *profile,
                                                 unsigned int attributeFlags)
{{
    (void)profile;
    (void)attributeFlags;
    return s_continuousTest;
}}

/* The oracle always supplies entropy explicitly. */
static BOOL DRBG_GetEntropy(UINT32 requiredEntropy, BYTE *entropy)
{{
    (void)requiredEntropy;
    (void)entropy;
    oracle_fail("DRBG_GetEntropy must not be reached");
    return FALSE;
}}

/* ---- begin verbatim extract from CryptRand.c ---- */
{functions}
/* ---- end verbatim extract from CryptRand.c ---- */

/* The DRBG_STATE branch of DRBG_Generate() for manufacture-time request
 * sizes (no KDF state, reseedCounter far below the reseed threshold,
 * randomSize below every cap): schedule from the current key, generate,
 * update with the same schedule, bump the counter. */
static void Generate(DRBG_STATE *drbgState, BYTE *random, UINT16 randomSize)
{{
    DRBG_KEY_SCHEDULE keySchedule;
    DRBG_SEED        *seed = &drbgState->seed;

    if (DRBG_ENCRYPT_SETUP((BYTE*)pDRBG_KEY(seed), DRBG_KEY_SIZE_BITS, &keySchedule) != 0)
        oracle_fail("AES_set_encrypt_key");
    EncryptDRBG(random, randomSize, &keySchedule, pDRBG_IV(seed), drbgState->lastValue);
    DRBG_Update(drbgState, &keySchedule, NULL);
    drbgState->reseedCounter += 1;
}}

static void put_u32be(FILE *f, UINT32 v)
{{
    fputc((int)((v >> 24) & 0xff), f);
    fputc((int)((v >> 16) & 0xff), f);
    fputc((int)((v >> 8) & 0xff), f);
    fputc((int)(v & 0xff), f);
}}

static void put_u64be(FILE *f, UINT64 v)
{{
    put_u32be(f, (UINT32)(v >> 32));
    put_u32be(f, (UINT32)(v & 0xffffffffu));
}}

static void put_last_value(FILE *f, const UINT32 *lastValue)
{{
    int i;
    for (i = 0; i < 4; i++)
        put_u32be(f, lastValue[i]);
}}

static void dump(const char *label, const BYTE *data, size_t size)
{{
    size_t i;
    printf("%s:", label);
    for (i = 0; i < size; i++)
        printf("%02x", data[i]);
    printf("\\n");
}}

int main(int argc, char **argv)
{{
    static const char *names[] = {{
        "commitNonce", "EPSeed", "SPSeed", "PPSeed",
        "phProof", "shProof", "ehProof",
    }};
    FILE *f;
    int mode;

    if (argc != 2) {{
        fprintf(stderr, "usage: %s <fixture-path>\\n", argv[0]);
        return 1;
    }}
    f = fopen(argv[1], "wb");
    if (!f) {{
        perror(argv[1]);
        return 1;
    }}

    for (mode = 0; mode <= 1; mode++) {{
        DRBG_STATE state;
        DRBG_SEED  entropy;
        BYTE       buf[64];
        int        i;

        s_continuousTest = mode;
        printf("mode %d (drbg-continous-test %s)\\n", mode, mode ? "on" : "off");

        /* DRBG_Instantiate's core with the fixed entropy input. */
        for (i = 0; i < DRBG_SEED_SIZE_BYTES; i++)
            entropy.bytes[i] = (BYTE)(((i + DRBG_SEED_SIZE_BYTES) & 0xff) ^ 0xa5);
        memset(&state, 0, sizeof(state));
        state.magic = DRBG_MAGIC;
        if (!DRBG_Reseed(&state, &entropy, NULL))
            oracle_fail("DRBG_Reseed");
        fwrite(state.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
        put_last_value(f, state.lastValue);
        put_u64be(f, state.reseedCounter);
        dump("  seed after instantiate", state.seed.bytes, DRBG_SEED_SIZE_BYTES);

        /* commitNonce, then the six hierarchy draws, in upstream order. */
        for (i = 0; i < 7; i++) {{
            Generate(&state, buf, sizeof(buf));
            fwrite(buf, 1, sizeof(buf), f);
            dump(names[i], buf, sizeof(buf));
        }}

        fwrite(state.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
        put_u64be(f, state.reseedCounter);
        put_last_value(f, state.lastValue);
        dump("  final seed", state.seed.bytes, DRBG_SEED_SIZE_BYTES);
        printf("  final reseedCounter: %llu\\n",
               (unsigned long long)state.reseedCounter);
    }}

    if (fclose(f) != 0) {{
        perror(argv[1]);
        return 1;
    }}
    return 0;
}}
"""


def extract_functions(source: str) -> str:
    """Extract the four DRBG primitives verbatim.

    Each function runs from its definition line to the first line that
    consists of nothing but the closing brace (the vendored style closes
    every function at column zero with no trailing text).
    """
    parts = []
    for start in FUNCTION_STARTS:
        match = re.search(start + r".*?^\}$", source, re.DOTALL | re.MULTILINE)
        if not match:
            raise SystemExit(f"error: pattern {start!r} not found in {CRYPTRAND}")
        parts.append(match.group(0))
    return "\n\n".join(parts)


def openssl_flags() -> tuple[list[str], list[str]]:
    pkg_config = shutil.which("pkg-config")
    if pkg_config:
        for package in ("libcrypto", "openssl"):
            cflags = subprocess.run(
                [pkg_config, "--cflags", package], capture_output=True, text=True
            )
            libs = subprocess.run(
                [pkg_config, "--libs", package], capture_output=True, text=True
            )
            if cflags.returncode == 0 and libs.returncode == 0:
                return cflags.stdout.split(), libs.stdout.split()
    for prefix in ("/opt/local/libexec/openssl3", "/opt/homebrew/opt/openssl",
                   "/usr/local/opt/openssl", "/usr"):
        if (Path(prefix) / "include" / "openssl" / "aes.h").is_file():
            return ([f"-I{prefix}/include"], [f"-L{prefix}/lib", "-lcrypto"])
    raise SystemExit("error: OpenSSL development files not found")


def build_fixture() -> tuple[bytes, str]:
    source = CRYPTRAND.read_text()
    program = ORACLE_TEMPLATE.format(functions=extract_functions(source))
    include_flags, link_flags = openssl_flags()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        oracle_c = tmpdir / "oracle.c"
        oracle_bin = tmpdir / "oracle"
        fixture_out = tmpdir / "fixture.bin"
        oracle_c.write_text(program)
        subprocess.run(
            ["cc", "-Wno-deprecated-declarations", *include_flags,
             str(oracle_c), "-o", str(oracle_bin), *link_flags],
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
        "--quiet",
        action="store_true",
        help="suppress the oracle's value listing",
    )
    args = parser.parse_args()

    fixture, listing = build_fixture()
    if not args.quiet:
        sys.stdout.write(listing)

    if args.check:
        if not FIXTURE.is_file():
            print(f"error: {FIXTURE} is missing; run {sys.argv[0]}", file=sys.stderr)
            return 1
        if FIXTURE.read_bytes() != fixture:
            print(
                f"error: {FIXTURE} is stale; run {sys.argv[0]} and commit the result",
                file=sys.stderr,
            )
            return 1
        print("check-drbg-fixture: OK")
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_bytes(fixture)
    print(f"wrote {FIXTURE} ({len(fixture)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
