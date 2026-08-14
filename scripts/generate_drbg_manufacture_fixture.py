#!/usr/bin/env python3
"""Regenerate the DRBG test vectors from the vendored libtpms.

Produces three fixtures under ``src/library/tpm2/testdata/``:

``drbg_manufacture_vectors.bin``
    the exact AES-256 CTR_DRBG state transitions and generated secrets the
    pinned vendored implementation (libtpms/src/tpm2/crypto/openssl/
    CryptRand.c) computes during TPM_Manufacture, for a fixed 48-byte
    entropy input;

``drbg_generate_vectors.bin``
    the state transitions and output bytes of a sequence of runtime
    ``DRBG_Generate`` requests (what ``CryptRandomGenerate`` -- and hence
    TPM2_GetRandom -- performs) starting from a pinned DRBG state;

``drbg_stir_vectors.bin``
    the state transitions ``CryptRandomStir`` -- what TPM2_StirRandom
    performs -- produces for a range of additional-data sizes, plus the
    first ``DRBG_Generate`` output that follows each stir.

How it works
------------
The DRBG primitives ``IncrementIv``, ``EncryptDRBG``, ``DRBG_Update`` and
``DRBG_Reseed``, the derivation function (``DfCompute``, ``DfStart``,
``DfUpdate``, ``DfEnd``, ``DfBuffer``) together with the ``DF_COUNT`` /
``DF_STATE`` definitions they need, and ``CryptRandomStir`` itself are
extracted *verbatim* from the vendored ``CryptRand.c``
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

Manufacture record layout (big-endian scalars), one record per mode
(plain first):
    48  seed after instantiate
    16  lastValue after instantiate (4 x u32)
     8  reseedCounter after instantiate
    64  commitNonce
   384  EPSeed, SPSeed, PPSeed, phProof, shProof, ehProof (64 each)
    48  final seed
     8  final reseedCounter
    16  final lastValue (4 x u32)

The generate fixture replays the same extracted primitives through the
equally extracted DRBG_STATE branch of ``DRBG_Generate`` (see "Guarding the
request wrapper") for the request sizes 0, 1, 16, 17, 64 and 64 again, in
that order, each request continuing from the state the previous one left
behind.  The zero-size request is included deliberately: the executed
upstream code only short-circuits on a NULL output pointer, so a zero-byte
request still runs DRBG_Update and increments the reseed counter.  The pinned start state is seed ``((i * 7 + 3) ^ 0x5a) & 0xff``,
reseedCounter 5 and an all-zero lastValue.

Generate record layout (big-endian scalars), one record per mode (plain
first):
    48  initial seed
     8  initial reseedCounter
    16  initial lastValue (4 x u32)
    then six steps of:
     2  requested size
    64  output buffer (zero padded above the requested size)
    48  seed after the request
     8  reseedCounter after the request
    16  lastValue after the request (4 x u32)

Two boundary records -- again one per mode, plain first -- follow the
generate records in the same file.  They pin the automatic reseed the
vendored ``DRBG_Generate()`` performs once ``reseedCounter`` reaches
``CTR_DRBG_MAX_REQUESTS_PER_RESEED`` (1 << 20): the same pinned seed is
replayed at the counters ``limit - 1``, ``limit`` (twice, once for a
64-byte and once for a zero-byte request) and ``limit + 7``.  Only the
threshold cases reach ``DRBG_Reseed(state, NULL, NULL)`` and hence
``DRBG_GetEntropy``, whose single 48-byte block is the deterministic
``((i + 48) & 0xff) ^ 0x63`` pattern the Rust test suite injects; the
recorded draw count makes that observable from Rust.  Upstream reseeds
only for ``drbgDefault`` -- a private PRNG state takes FAIL_IMMEDIATE
instead -- so these cases drive ``drbgDefault`` itself, the state the
runtime generator corresponds to.

Boundary record layout (big-endian scalars):
    48  initial seed
    16  initial lastValue (4 x u32)
    then four cases of:
     8  initial reseedCounter
     2  requested size
     1  entropy blocks drawn while serving the request
    64  output buffer (zero padded above the requested size)
    48  seed after the request
     8  reseedCounter after the request
    16  lastValue after the request (4 x u32)

The stir fixture drives the verbatim ``CryptRandomStir`` -- the whole of
what TPM2_StirRandom does -- once per additional-data size from the same
pinned seed, at a reseedCounter chosen per case (including one at and one
above ``CTR_DRBG_MAX_REQUESTS_PER_RESEED``, to show the stir forces the
counter to 1 regardless).  The sizes are 0, 1, 16, 16 again with different
content, 48 and 128 (``MAX_SYM_DATA``); the zero-size case pins the
``DfBuffer()`` NULL return, i.e. an entropy-only reseed with no
additional-data block.  The single 48-byte entropy block
``CryptRandomStir`` collects is the same deterministic
``((i + 48) & 0xff) ^ 0x63`` pattern the Rust test suite injects, and is
recorded per case so the Rust side pins what it fed in.  Each case also
records the first ``DRBG_Generate(64)`` that follows the stir, which is
what proves the resulting stream -- not just the immediate state.

Stir record layout (big-endian scalars), one record per mode (plain
first), six cases each:
    48  initial seed
     8  initial reseedCounter
    16  initial lastValue (4 x u32)
    48  entropy injected into the stir
     2  additional-data size
   128  additional data (zero padded above the size)
    48  the DfBuffer() result (all zero when it returned NULL)
    48  seed after the stir
     8  reseedCounter after the stir
    16  lastValue after the stir (4 x u32)
    64  the first DRBG_Generate(64) output after the stir

``lastValue`` is a native-endian UINT32[4] in C; the oracle writes the
values big-endian (like NVMarshal's UINT32_Marshal), so the fixtures are
identical on every little-endian generator host -- the only hosts the
crate supports.

Guarding the request wrapper
----------------------------
Both fixtures drive the DRBG through ``Generate()``, the oracle's stand-in
for ``DRBG_Generate``.  Its DRBG-state branch -- the reseed-threshold
check, the request cap, the key schedule, ``EncryptDRBG``, ``DRBG_Update``
and the reseed-counter increment -- is *not* handwritten: it is sliced out
of the vendored ``DRBG_Generate`` (from ``else if(state->drbg.magic ==
DRBG_MAGIC)`` through the closing brace of the trailing ``else``) and
compiled verbatim, so a change to that control flow either fails to
compile or changes the fixture bytes.

What the oracle still mirrors by hand is everything *around* that branch:
the NULL-output guard, the KDF dispatch, and the absence of a zero-size
short circuit.  A change there would not move the fixture bytes on its
own, so the generator also pins a SHA-256 over the complete extracted
``DRBG_Generate`` source and refuses to run when it moves.  Updating
``DRBG_GENERATE_SHA256`` means the wrapper below has been re-read against
the new upstream function -- do not refresh it mechanically.

The stir path needs no such wrapper: ``CryptRandomStir`` is compiled
verbatim, entropy collection and all.  What *is* mirrored by hand is
``TPM2_StirRandom`` (RandomCommands.c), which discards CryptRandomStir's
``TPM_RC_NO_RESULT`` and answers TPM_RC_SUCCESS anyway -- behaviour the
Rust command layer reproduces and no fixture byte can pin.  It is guarded
the same way, by ``TPM2_STIR_RANDOM_SHA256``.

The prelude's ``UINT32_TO_BYTE_ARRAY`` is the one other hand-mirror the
Df extract needs: endian_swap.h resolves it to a big-endian store on the
little-endian hosts this crate supports, and DfStart() is the only
extracted user of it.

Determinism: the output depends only on the vendored sources under
``libtpms/`` and OpenSSL's AES; no network access, no timestamps, no
environment input beyond the C compiler and the OpenSSL headers libtpms
itself builds against.

Usage:
    python3 scripts/generate_drbg_manufacture_fixture.py
    python3 scripts/generate_drbg_manufacture_fixture.py --check
"""

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CRYPTRAND = REPO_ROOT / "libtpms" / "src" / "tpm2" / "crypto" / "openssl" / "CryptRand.c"
RANDOM_COMMANDS = REPO_ROOT / "libtpms" / "src" / "tpm2" / "RandomCommands.c"
TESTDATA = REPO_ROOT / "src" / "library" / "tpm2" / "testdata"
FIXTURE = TESTDATA / "drbg_manufacture_vectors.bin"
GENERATE_FIXTURE = TESTDATA / "drbg_generate_vectors.bin"
STIR_FIXTURE = TESTDATA / "drbg_stir_vectors.bin"

# SHA-256 of the complete vendored DRBG_Generate() source, reviewed against
# the oracle's Generate() wrapper below.  See "Guarding the request wrapper".
DRBG_GENERATE_SHA256 = "788edaa028f470d8f853be0433a2287c671e4869d719f4b70dc02962e98986a4"

# SHA-256 of the complete vendored TPM2_StirRandom() source.  The oracle
# calls CryptRandomStir() directly, so this function's one piece of
# behaviour -- discarding a TPM_RC_NO_RESULT and answering TPM_RC_SUCCESS
# -- lives only in the Rust command layer.  See "Guarding the request
# wrapper".
TPM2_STIR_RANDOM_SHA256 = "a65feab1de2efa7beac60ea9e0dc92066189a9a18a4a684e5045dc85d5e1934b"

DRBG_GENERATE_START = r"^LIB_EXPORT UINT16 DRBG_Generate\("
DRBG_STATE_BRANCH_START = "else if(state->drbg.magic == DRBG_MAGIC)"

TPM2_STIR_RANDOM_START = r"^TPM_RC\nTPM2_StirRandom\("

# The DF_COUNT / DF_STATE definitions the extracted derivation function
# needs, taken verbatim so the block geometry cannot drift either.
DF_DEFINES_START = r"^#define DF_COUNT "
DF_DEFINES_END = r"^\} DF_STATE, \*PDF_STATE;$"

# The verbatim-extracted vendored functions, in definition order.
FUNCTION_STARTS = [
    r"^static void DfCompute\(",
    r"^static void DfStart\(",
    r"^static void DfUpdate\(",
    r"^static DRBG_SEED\* DfEnd\(",
    r"^static DRBG_SEED\* DfBuffer\(",
    r"^void IncrementIv\(",
    r"^static BOOL EncryptDRBG\(",
    r"^static BOOL DRBG_Update\(",
    r"^BOOL DRBG_Reseed\(",
    r"^LIB_EXPORT TPM_RC CryptRandomStir\(",
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
#define LIB_EXPORT
typedef uint64_t crypt_uword_t; /* RADIX_BITS 64 */
#define RADIX_BYTES 8

typedef UINT32 TPM_RC;
#define TPM_RC_SUCCESS   ((TPM_RC)0x000)
#define TPM_RC_NO_RESULT ((TPM_RC)0x154)

/* endian_swap.h resolves UINT32_TO_BYTE_ARRAY to a big-endian store on
 * the little-endian hosts this crate supports.  DfStart() is the only
 * extracted user of it. */
#define UINT32_TO_BYTE_ARRAY(i, b)                                       \\
    do {{                                                                 \\
        UINT32 uint32ToByteArray_ = (UINT32)(i);                         \\
        BYTE*  uint32ToByteArrayOut_ = (BYTE*)(b);                       \\
        uint32ToByteArrayOut_[0] = (BYTE)(uint32ToByteArray_ >> 24);     \\
        uint32ToByteArrayOut_[1] = (BYTE)(uint32ToByteArray_ >> 16);     \\
        uint32ToByteArrayOut_[2] = (BYTE)(uint32ToByteArray_ >> 8);      \\
        uint32ToByteArrayOut_[3] = (BYTE)(uint32ToByteArray_);           \\
    }} while (0)

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

/* CryptRand.h: RAND_STATE is a union of DRBG_STATE and KDF_STATE.  The
 * extracted branch only ever touches the DRBG arm, so the KDF arm is left
 * out rather than dragging in CryptKDFa and its residual buffer. */
typedef union {{
    DRBG_STATE drbg;
}} RAND_STATE;
static DRBG_STATE drbgDefault;

#define CTR_DRBG_MAX_REQUESTS_PER_RESEED ((UINT64)1 << 20)
#define CTR_DRBG_MAX_BYTES_PER_REQUEST   (1 << 16)

#define pDRBG_KEY(seed) ((DRBG_KEY*)&(((BYTE*)(seed))[0]))
#define pDRBG_IV(seed)  ((DRBG_IV*)&(((BYTE*)(seed))[DRBG_KEY_SIZE_BYTES]))

/* TpmToOsslSym.h: DRBG_ENCRYPT == OpenSSL AES_encrypt.  DRBG_KEY_SCHEDULE
 * itself comes from the verbatim DF_STATE extract below. */
typedef AES_KEY tpmKeyScheduleAES;
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
#define FAIL_IMMEDIATE(code, retval) oracle_fail("FAIL_IMMEDIATE(" #code ")")

/* The oracle's entropy source never fails, so the healthy answer is the
 * only one the threshold branch can observe. */
static BOOL IsEntropyBad(void) {{ return FALSE; }}
static BOOL IsSelfTest(void) {{ return FALSE; }}

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

/* Only the automatic reseed the vendored DRBG_Generate() performs at the
 * request limit reaches this; every other sequence supplies its entropy
 * explicitly, and the call count is written into the boundary fixture so
 * the Rust side can pin exactly when the source is consulted.  The pattern
 * is the deterministic 48-byte block the Rust test suite injects. */
static unsigned s_entropyCalls;
static BOOL DRBG_GetEntropy(UINT32 requiredEntropy, BYTE *entropy)
{{
    UINT32 i;

    if (requiredEntropy != sizeof(DRBG_SEED))
        oracle_fail("DRBG_GetEntropy asked for a partial seed");
    for (i = 0; i < requiredEntropy; i++)
        entropy[i] = (BYTE)(((i + DRBG_SEED_SIZE_BYTES) & 0xff) ^ 0x63);
    s_entropyCalls++;
    return TRUE;
}}

/* ---- begin verbatim extract from CryptRand.c ---- */
{df_defines}

{functions}
/* ---- end verbatim extract from CryptRand.c ---- */

/* DRBG_Generate() for a DRBG_STATE caller.  The dispatch around the
 * branch is what the oracle mirrors by hand: upstream returns early only
 * for a NULL output pointer -- there is no zero-size short circuit, so a
 * zero-byte request still runs DRBG_Update and bumps the counter -- and
 * the KDF arm cannot be reached from here.  Everything from the DRBG
 * magic test onwards is the vendored branch, compiled verbatim, and
 * DRBG_GENERATE_SHA256 guards the parts left out. */
static UINT16 Generate(DRBG_STATE *oracleState, BYTE *random, UINT16 randomSize)
{{
    RAND_STATE *state = (RAND_STATE *)oracleState;

    if (random == NULL)
        {{
            oracle_fail("the oracle always generates into a buffer");
        }}
    /* ---- begin verbatim extract from DRBG_Generate() ---- */
    {drbg_state_branch}
    /* ---- end verbatim extract from DRBG_Generate() ---- */
    return randomSize;
}}

static void put_u16be(FILE *f, UINT16 v)
{{
    fputc((int)((v >> 8) & 0xff), f);
    fputc((int)(v & 0xff), f);
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

/* The runtime request sizes replayed into the generate fixture. */
static const UINT16 REQUEST_SIZES[] = {{0, 1, 16, 17, 64, 64}};

/* The reseed-threshold cases replayed into the generate fixture, each
 * starting from the same pinned seed with a different reseedCounter. */
static const struct {{
    UINT64 counter;
    UINT16 size;
}} BOUNDARY_CASES[] = {{
    {{CTR_DRBG_MAX_REQUESTS_PER_RESEED - 1, 64}},
    {{CTR_DRBG_MAX_REQUESTS_PER_RESEED, 64}},
    {{CTR_DRBG_MAX_REQUESTS_PER_RESEED, 0}},
    {{CTR_DRBG_MAX_REQUESTS_PER_RESEED + 7, 64}},
}};

static void pinned_seed(DRBG_STATE *state)
{{
    int i;

    memset(state, 0, sizeof(*state));
    state->magic = DRBG_MAGIC;
    for (i = 0; i < DRBG_SEED_SIZE_BYTES; i++)
        state->seed.bytes[i] = (BYTE)((i * 7 + 3) ^ 0x5a);
}}

/* The threshold branch only reseeds for the default DRBG -- a private PRNG
 * state takes FAIL_IMMEDIATE instead -- so these cases drive drbgDefault,
 * the state the runtime generator corresponds to. */
static void write_boundary_records(FILE *f)
{{
    int mode;

    for (mode = 0; mode <= 1; mode++) {{
        size_t     which;
        DRBG_STATE pinned;

        s_continuousTest = mode;
        printf("boundary mode %d (drbg-continous-test %s)\\n",
               mode, mode ? "on" : "off");

        pinned_seed(&pinned);
        fwrite(pinned.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
        put_last_value(f, pinned.lastValue);

        for (which = 0; which < sizeof(BOUNDARY_CASES) / sizeof(BOUNDARY_CASES[0]); which++) {{
            UINT16 size = BOUNDARY_CASES[which].size;
            BYTE   buf[64];

            pinned_seed(&drbgDefault);
            drbgDefault.reseedCounter = BOUNDARY_CASES[which].counter;
            s_entropyCalls = 0;
            memset(buf, 0, sizeof(buf));
            Generate(&drbgDefault, buf, size);
            if (s_entropyCalls > 1)
                oracle_fail("a request drew more than one seed block");

            put_u64be(f, BOUNDARY_CASES[which].counter);
            put_u16be(f, size);
            fputc((int)s_entropyCalls, f);
            fwrite(buf, 1, sizeof(buf), f);
            fwrite(drbgDefault.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
            put_u64be(f, drbgDefault.reseedCounter);
            put_last_value(f, drbgDefault.lastValue);
            printf("  counter %llu, request %u -> %u entropy draw(s), counter %llu\\n",
                   (unsigned long long)BOUNDARY_CASES[which].counter,
                   (unsigned)size, s_entropyCalls,
                   (unsigned long long)drbgDefault.reseedCounter);
            dump("    output", buf, size);
        }}
    }}
}}

/* TpmProfile_Misc.h: MAX_SYM_DATA, the TPM2B_SENSITIVE_DATA cap on
 * TPM2_StirRandom's inData. */
#define MAX_SYM_DATA 128

/* The additional-data sizes replayed into the stir fixture.  Two 16-byte
 * cases with different content pin that the derivation function -- not
 * just the length -- reaches the reseed.  The last two counters sit at
 * and above the reseed threshold, where the stir still forces 1. */
static const struct {{
    UINT64 counter;
    UINT16 size;
    BYTE   fill;
}} STIR_CASES[] = {{
    {{0,                                    0,   0x00}},
    {{1,                                    1,   0x11}},
    {{5,                                    16,  0x22}},
    {{17,                                   16,  0x33}},
    {{CTR_DRBG_MAX_REQUESTS_PER_RESEED,     48,  0x44}},
    {{CTR_DRBG_MAX_REQUESTS_PER_RESEED + 3, 128, 0x55}},
}};

/* CryptRandomStir() reseeds drbgDefault, so the cases drive that state --
 * the one the runtime generator corresponds to. */
static void write_stir_fixture(const char *path)
{{
    FILE *f = fopen(path, "wb");
    int mode;

    if (!f) {{
        perror(path);
        exit(1);
    }}

    for (mode = 0; mode <= 1; mode++) {{
        size_t which;

        s_continuousTest = mode;
        printf("stir mode %d (drbg-continous-test %s)\\n", mode, mode ? "on" : "off");

        for (which = 0; which < sizeof(STIR_CASES) / sizeof(STIR_CASES[0]); which++) {{
            UINT16 size = STIR_CASES[which].size;
            BYTE      additional[MAX_SYM_DATA];
            BYTE      entropy[DRBG_SEED_SIZE_BYTES];
            BYTE      next[64];
            DRBG_SEED derived;
            UINT32    i;

            memset(additional, 0, sizeof(additional));
            for (i = 0; i < size; i++)
                additional[i] = (BYTE)(((i * 3 + STIR_CASES[which].fill) & 0xff) ^ 0x9c);

            /* The block DRBG_GetEntropy() above injects, recorded so the
             * Rust side pins what its own entropy callback supplied. */
            for (i = 0; i < DRBG_SEED_SIZE_BYTES; i++)
                entropy[i] = (BYTE)(((i + DRBG_SEED_SIZE_BYTES) & 0xff) ^ 0x63);

            pinned_seed(&drbgDefault);
            drbgDefault.reseedCounter = STIR_CASES[which].counter;
            s_entropyCalls = 0;

            fwrite(drbgDefault.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
            put_u64be(f, drbgDefault.reseedCounter);
            put_last_value(f, drbgDefault.lastValue);
            fwrite(entropy, 1, sizeof(entropy), f);
            put_u16be(f, size);
            fwrite(additional, 1, sizeof(additional), f);

            /* The derivation function's own result, recorded so the Rust
             * port of DfBuffer() is pinned on its own rather than only
             * through the reseed it feeds.  A NULL return -- the empty
             * input -- is recorded as a zero block. */
            memset(&derived, 0, sizeof(derived));
            if (DfBuffer(&derived, size, additional) == NULL && size != 0)
                oracle_fail("DfBuffer refused a non-empty input");
            fwrite(derived.bytes, 1, DRBG_SEED_SIZE_BYTES, f);

            /* TPM2_StirRandom() always hands over the TPM2B buffer, even
             * for a zero size; DfBuffer() is what turns that into "no
             * additional data". */
            if (CryptRandomStir(size, additional) != TPM_RC_SUCCESS)
                oracle_fail("CryptRandomStir failed");
            if (s_entropyCalls != 1)
                oracle_fail("CryptRandomStir drew other than one seed block");
            if (drbgDefault.reseedCounter != 1)
                oracle_fail("CryptRandomStir left the reseed counter off 1");

            fwrite(drbgDefault.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
            put_u64be(f, drbgDefault.reseedCounter);
            put_last_value(f, drbgDefault.lastValue);

            memset(next, 0, sizeof(next));
            Generate(&drbgDefault, next, sizeof(next));
            fwrite(next, 1, sizeof(next), f);
            if (s_entropyCalls != 1)
                oracle_fail("the request after a stir reseeded again");
            if (drbgDefault.reseedCounter != 2)
                oracle_fail("the request after a stir left the counter off 2");

            printf("  counter %llu, %u byte(s) of additional data\\n",
                   (unsigned long long)STIR_CASES[which].counter, (unsigned)size);
            dump("    additional", additional, size);
            dump("    derived", derived.bytes, DRBG_SEED_SIZE_BYTES);
            dump("    seed after", drbgDefault.seed.bytes, DRBG_SEED_SIZE_BYTES);
            dump("    next output", next, sizeof(next));
        }}
    }}

    if (fclose(f) != 0) {{
        perror(path);
        exit(1);
    }}
}}

static void write_generate_fixture(const char *path)
{{
    FILE *f = fopen(path, "wb");
    int mode;

    if (!f) {{
        perror(path);
        exit(1);
    }}

    for (mode = 0; mode <= 1; mode++) {{
        DRBG_STATE state;
        size_t     step;

        s_continuousTest = mode;
        printf("generate mode %d (drbg-continous-test %s)\\n",
               mode, mode ? "on" : "off");

        pinned_seed(&state);
        state.reseedCounter = 5;
        s_entropyCalls = 0;

        fwrite(state.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
        put_u64be(f, state.reseedCounter);
        put_last_value(f, state.lastValue);
        dump("  initial seed", state.seed.bytes, DRBG_SEED_SIZE_BYTES);

        for (step = 0; step < sizeof(REQUEST_SIZES) / sizeof(REQUEST_SIZES[0]); step++) {{
            UINT16 size = REQUEST_SIZES[step];
            BYTE   buf[64];

            memset(buf, 0, sizeof(buf));
            Generate(&state, buf, size);
            put_u16be(f, size);
            fwrite(buf, 1, sizeof(buf), f);
            fwrite(state.seed.bytes, 1, DRBG_SEED_SIZE_BYTES, f);
            put_u64be(f, state.reseedCounter);
            put_last_value(f, state.lastValue);
            printf("  request %u -> reseedCounter %llu\\n",
                   (unsigned)size, (unsigned long long)state.reseedCounter);
            dump("    output", buf, size);
        }}
        if (s_entropyCalls != 0)
            oracle_fail("a below-threshold request drew entropy");
    }}

    write_boundary_records(f);

    if (fclose(f) != 0) {{
        perror(path);
        exit(1);
    }}
}}

int main(int argc, char **argv)
{{
    static const char *names[] = {{
        "commitNonce", "EPSeed", "SPSeed", "PPSeed",
        "phProof", "shProof", "ehProof",
    }};
    FILE *f;
    int mode;

    if (argc != 4) {{
        fprintf(stderr,
                "usage: %s <manufacture-fixture> <generate-fixture> <stir-fixture>\\n",
                argv[0]);
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
        s_entropyCalls = 0;
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
        if (s_entropyCalls != 0)
            oracle_fail("the manufacture sequence drew host entropy");
    }}

    if (fclose(f) != 0) {{
        perror(argv[1]);
        return 1;
    }}

    write_generate_fixture(argv[2]);
    write_stir_fixture(argv[3]);
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


def extract_df_defines(source: str) -> str:
    """Extract the DF_COUNT / DF_STATE definitions verbatim."""
    match = re.search(
        DF_DEFINES_START + r".*?" + DF_DEFINES_END, source, re.DOTALL | re.MULTILINE
    )
    if not match:
        raise SystemExit(f"error: the DF_STATE definitions were not found in {CRYPTRAND}")
    return match.group(0)


def guarded_tpm2_stir_random() -> None:
    """Pin TPM2_StirRandom(), whose behaviour no fixture byte can capture.

    The oracle calls CryptRandomStir() directly, so the command wrapper --
    which throws away a TPM_RC_NO_RESULT and answers TPM_RC_SUCCESS -- is
    reproduced only by the Rust command layer.  See "Guarding the request
    wrapper".
    """
    source = RANDOM_COMMANDS.read_text()
    match = re.search(
        TPM2_STIR_RANDOM_START + r".*?^\}$", source, re.DOTALL | re.MULTILINE
    )
    if not match:
        raise SystemExit(f"error: TPM2_StirRandom() not found in {RANDOM_COMMANDS}")
    digest = hashlib.sha256(match.group(0).encode()).hexdigest()
    if digest != TPM2_STIR_RANDOM_SHA256:
        raise SystemExit(
            f"error: {RANDOM_COMMANDS} TPM2_StirRandom() changed\n"
            f"  expected sha256 {TPM2_STIR_RANDOM_SHA256}\n"
            f"  actual   sha256 {digest}\n"
            "The oracle drives CryptRandomStir() directly, so this function's\n"
            "discard of TPM_RC_NO_RESULT lives only in the Rust command layer.\n"
            "Re-read the new upstream function against src/library/tpm2/command/\n"
            "stir_random.rs, and only then update TPM2_STIR_RANDOM_SHA256."
        )


def guarded_drbg_generate(source: str) -> str:
    """Return the vendored DRBG_Generate() source, pinned by digest.

    The oracle compiles only the DRBG-state branch of this function; the
    dispatch around it is mirrored by hand, so a change anywhere in the
    function has to be re-reviewed before the fixtures can be trusted.
    """
    match = re.search(DRBG_GENERATE_START + r".*?^\}$", source, re.DOTALL | re.MULTILINE)
    if not match:
        raise SystemExit(f"error: DRBG_Generate() not found in {CRYPTRAND}")
    text = match.group(0)
    digest = hashlib.sha256(text.encode()).hexdigest()
    if digest != DRBG_GENERATE_SHA256:
        raise SystemExit(
            f"error: {CRYPTRAND} DRBG_Generate() changed\n"
            f"  expected sha256 {DRBG_GENERATE_SHA256}\n"
            f"  actual   sha256 {digest}\n"
            "The oracle compiles this function's DRBG-state branch verbatim but\n"
            "mirrors the surrounding dispatch (NULL-output guard, KDF arm, the\n"
            "absence of a zero-size short circuit) by hand.  Re-read the new\n"
            "upstream function against the Generate() wrapper in this script,\n"
            "regenerate the fixtures, and only then update DRBG_GENERATE_SHA256."
        )
    return text


def close_brace(text: str, start: int) -> int:
    """Index of the brace closing the first '{' at or after ``start``."""
    open_at = text.index("{", start)
    depth = 0
    for index in range(open_at, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise SystemExit(f"error: unbalanced braces in {CRYPTRAND} DRBG_Generate()")


def extract_drbg_state_branch(drbg_generate: str) -> str:
    """Slice out the DRBG-state branch and the invalid-state ``else``."""
    start = drbg_generate.find(DRBG_STATE_BRANCH_START)
    if start < 0:
        raise SystemExit(
            f"error: {DRBG_STATE_BRANCH_START!r} not found in DRBG_Generate()"
        )
    after_branch = close_brace(drbg_generate, start)
    else_at = drbg_generate.find("else", after_branch)
    if else_at < 0:
        raise SystemExit("error: DRBG_Generate() lost its invalid-state else branch")
    branch = drbg_generate[start : close_brace(drbg_generate, else_at) + 1]
    for required in (
        "DRBG_ENCRYPT_SETUP",
        "EncryptDRBG(",
        "DRBG_Update(",
        "reseedCounter += 1",
        "CTR_DRBG_MAX_REQUESTS_PER_RESEED",
        "DRBG_Reseed(drbgState, NULL, NULL)",
        "drbgState == &drbgDefault",
        "IsEntropyBad()",
        "FAIL_IMMEDIATE",
    ):
        if required not in branch:
            raise SystemExit(
                f"error: the extracted DRBG_Generate() branch lost {required!r}"
            )
    return branch


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


def build_fixtures() -> tuple[bytes, bytes, bytes, str]:
    source = CRYPTRAND.read_text()
    guarded_tpm2_stir_random()
    program = ORACLE_TEMPLATE.format(
        df_defines=extract_df_defines(source),
        functions=extract_functions(source),
        drbg_state_branch=extract_drbg_state_branch(guarded_drbg_generate(source)),
    )
    include_flags, link_flags = openssl_flags()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        oracle_c = tmpdir / "oracle.c"
        oracle_bin = tmpdir / "oracle"
        fixture_out = tmpdir / "fixture.bin"
        generate_out = tmpdir / "generate.bin"
        stir_out = tmpdir / "stir.bin"
        oracle_c.write_text(program)
        subprocess.run(
            ["cc", "-Wno-deprecated-declarations", *include_flags,
             str(oracle_c), "-o", str(oracle_bin), *link_flags],
            check=True,
        )
        listing = subprocess.run(
            [str(oracle_bin), str(fixture_out), str(generate_out), str(stir_out)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return (
            fixture_out.read_bytes(),
            generate_out.read_bytes(),
            stir_out.read_bytes(),
            listing,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in fixtures instead of rewriting them",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the oracle's value listing",
    )
    args = parser.parse_args()

    fixture, generate_fixture, stir_fixture, listing = build_fixtures()
    if not args.quiet:
        sys.stdout.write(listing)

    produced = (
        (FIXTURE, fixture),
        (GENERATE_FIXTURE, generate_fixture),
        (STIR_FIXTURE, stir_fixture),
    )

    if args.check:
        for path, content in produced:
            if not path.is_file():
                print(f"error: {path} is missing; run {sys.argv[0]}", file=sys.stderr)
                return 1
            if path.read_bytes() != content:
                print(
                    f"error: {path} is stale; run {sys.argv[0]} and commit the result",
                    file=sys.stderr,
                )
                return 1
        print("check-drbg-fixture: OK")
        return 0

    for path, content in produced:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        print(f"wrote {path} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
