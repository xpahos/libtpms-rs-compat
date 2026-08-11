#!/usr/bin/env python3
"""Regenerate the VOLATILE_STATE test fixtures from the vendored libtpms.

Produces ``src/library/tpm2/testdata/volatile_state_v4.bin`` and
``volatile_state_v4_future.bin`` -- authentic outputs of the *real*
vendored marshaller -- plus ``volatile_state_v{1,2,3}_synthetic.bin``:
synthetic downgraded-layout streams for the historical wire versions.

Authentic fixtures (v4, v4_future)
----------------------------------
The current-version fixtures are produced by executing the actual pinned
C implementation: the vendored ``NVMarshal.c`` (``VolatileState_Marshal``
and every nested section marshaller), ``Marshal.c`` (the primitive
marshallers), and ``Volatile.c`` (``VolatileState_Save``, whose SHA-1
frame covers every byte preceding the trailing 20-byte digest) are
compiled unmodified and driven by a deterministic harness:

  - every serialized global (``g_*``, ``go``/``gc``/``gr``, ``s_*``) is
    instantiated in the harness translation unit (the roles ``Global.c``
    and ``PlatformData.c`` play in the real build) and populated with
    the fixture values;
  - ``ClockGetTime`` is replaced by a deterministic stand-in (the
    CLOCK_REALTIME/CLOCK_MONOTONIC inputs are fixed), ``NvRead`` serves
    an all-zero PERSISTENT_DATA (empty EP/SP/PP seed ties), and
    ``CryptHashBlock`` is backed by an embedded SHA-1 (verified against
    the standard "abc" test vector at startup);
  - every other external the linker demands is satisfied by an
    auto-generated aborting stub, so any upstream change that routes the
    volatile marshal path through new code is detected loudly instead of
    silently absorbed.

``volatile_state_v4.bin`` is the byte-exact return of the real
``VolatileState_Save``.  ``volatile_state_v4_future.bin`` is the real
``VolatileState_Marshal`` payload with forward-compatible bytes appended
between the trailing magic and the digest (what a newer writer may
produce; ``VolatileState_Load`` must skip them), framed by the same
digest-over-every-preceding-byte rule as ``VolatileState_Save``.

Synthetic fixtures (v1..v3)
---------------------------
The pinned writer always emits VOLATILE_STATE_VERSION (4); no vendored
code path can produce a version 1..3 stream, so those fixtures cannot be
genuine outputs of historical writers.  They are emitted by a handwritten
C oracle that transcribes the pinned ``VolatileState_Unmarshal`` layout
for downgraded header versions -- explicitly synthetic, and named
``_synthetic`` to say so.  The oracle imports every ``#define
<SECTION>_MAGIC/_VERSION`` *verbatim* from the vendored ``NVMarshal.c``
and derives every array geometry from the vendored profile headers
(``sizeof``/``ARRAY_SIZE`` over the real structs), so the synthetic
layouts can only drift from upstream where the field order itself
changes -- and that is exactly what the cross-validation below pins.

Cross-validation
----------------
The synthetic oracle also emits its own version-4 stream from the same
fixture values.  Generation *fails* unless the synthetic v4 bytes equal
the authentic ``VolatileState_Save`` output (and likewise for the
``_future`` variant): any upstream change to field order, block framing,
array geometry, section versions, or digest coverage changes the
authentic bytes, breaks the equality, and therefore fails ``--check``.
The v1..v3 synthetic fixtures share the same emitter code paths, so the
equality transitively anchors them to the pinned implementation as well.

Determinism: the output depends only on the vendored sources and headers
under ``libtpms/``; no network access, no timestamps (the harness clock
is fixed), no environment input beyond the C compiler and the OpenSSL
headers libtpms itself builds against.

Usage:
    python3 scripts/generate_volatile_state_fixture.py
    python3 scripts/generate_volatile_state_fixture.py --check
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TPM2_DIR = REPO_ROOT / "libtpms" / "src" / "tpm2"
NVMARSHAL = TPM2_DIR / "NVMarshal.c"
MARSHAL = TPM2_DIR / "Marshal.c"
VOLATILE = TPM2_DIR / "Volatile.c"
TESTDATA = REPO_ROOT / "src" / "library" / "tpm2" / "testdata"

FIXTURES = [
    "volatile_state_v1_synthetic.bin",
    "volatile_state_v2_synthetic.bin",
    "volatile_state_v3_synthetic.bin",
    "volatile_state_v4.bin",
    "volatile_state_v4_future.bin",
]

# The synthetic oracle writes these names into its output directory; the
# v1..v3 entries are renamed to their explicit _synthetic fixture names.
SYNTHETIC_OUTPUTS = {
    "volatile_state_v1.bin": "volatile_state_v1_synthetic.bin",
    "volatile_state_v2.bin": "volatile_state_v2_synthetic.bin",
    "volatile_state_v3.bin": "volatile_state_v3_synthetic.bin",
    "volatile_state_v4.bin": "volatile_state_v4.bin",
    "volatile_state_v4_future.bin": "volatile_state_v4_future.bin",
}

# The authentic harness writes these names into its output directory.
AUTHENTIC_OUTPUTS = ["authentic_v4.bin", "authentic_v4_future.bin"]

# The section magic/version defines the volatile stream consumes, in
# NVMarshal.c order; each is extracted verbatim.
DEFINE_NAMES = [
    "DRBG_STATE_MAGIC",
    "DRBG_STATE_VERSION",
    "ORDERLY_DATA_MAGIC",
    "ORDERLY_DATA_VERSION",
    "PCR_SAVE_MAGIC",
    "PCR_SAVE_VERSION",
    "PCR_AUTHVALUE_MAGIC",
    "PCR_AUTHVALUE_VERSION",
    "STATE_CLEAR_DATA_MAGIC",
    "STATE_CLEAR_DATA_VERSION",
    "STATE_RESET_DATA_MAGIC",
    "STATE_RESET_DATA_VERSION",
    "PCR_MAGIC",
    "PCR_VERSION",
    "ANY_OBJECT_MAGIC",
    "ANY_OBJECT_VERSION",
    "SESSION_MAGIC",
    "SESSION_VERSION",
    "SESSION_SLOT_MAGIC",
    "SESSION_SLOT_VERSION",
    "VOLATILE_STATE_VERSION",
    "VOLATILE_STATE_MAGIC",
]

# Vendored source fragments the authentic oracle drives; a missing
# fragment means the pinned entry points moved or changed shape, and the
# whole strategy must be revisited rather than silently degraded.
MARSHALLER_FRAGMENTS = [
    (
        "NVMarshal.c",
        "VolatileState_Marshal(BYTE **buffer, INT32 *size,"
        " struct RuntimeProfile *RuntimeProfile)",
    ),
    ("NVMarshal.c", "VolatileState_TailV4_Unmarshal"),
    ("NVMarshal.c", "ClockGetTime(CLOCK_REALTIME)"),
    ("NVMarshal.c", "ClockGetTime(CLOCK_MONOTONIC)"),
    ("Volatile.c", "VolatileState_Save(BYTE **buffer, INT32 *size)"),
    ("Volatile.c", "VolatileState_Marshal(buffer, size, &g_RuntimeProfile)"),
]


def extract_defines(source: str) -> str:
    """Extract the listed ``#define`` lines verbatim from NVMarshal.c."""
    lines = []
    for name in DEFINE_NAMES:
        match = re.search(
            rf"^#define {re.escape(name)}\s+\S+.*$", source, re.MULTILINE
        )
        if not match:
            raise SystemExit(f"error: #define {name} not found in {NVMARSHAL}")
        lines.append(match.group(0))
    return "\n".join(lines)


def require_marshaller_fragments(nvmarshal_source: str, volatile_source: str) -> None:
    """Fail when a pinned marshaller entry point cannot be found."""
    sources = {"NVMarshal.c": nvmarshal_source, "Volatile.c": volatile_source}
    for file_name, fragment in MARSHALLER_FRAGMENTS:
        if fragment not in sources[file_name]:
            raise SystemExit(
                f"error: required fragment {fragment!r} not found in the "
                f"vendored {file_name}; the pinned volatile marshaller moved"
            )


# ---------------------------------------------------------------------
# Shared C fragments
# ---------------------------------------------------------------------

# Self-contained SHA-1 (FIPS 180-1); compatibility framing only.
SHA1_C = r"""
typedef struct {
    uint32_t h[5];
    uint64_t len;
    unsigned char block[64];
    size_t fill;
} sha1_ctx;

static void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
    c->len = 0; c->fill = 0;
}

static uint32_t rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

static void sha1_block(sha1_ctx *c, const unsigned char *p)
{
    uint32_t w[80], a, b, d, e, f, k, t, cc;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | p[i * 4 + 3];
    for (i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3]; e = c->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & cc) | ((~b) & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d);  k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;                     k = 0xCA62C1D6; }
        t = rol(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = rol(b, 30); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void sha1_update(sha1_ctx *c, const unsigned char *data, size_t n)
{
    c->len += (uint64_t)n * 8;
    while (n) {
        size_t take = 64 - c->fill;
        if (take > n)
            take = n;
        memcpy(c->block + c->fill, data, take);
        c->fill += take; data += take; n -= take;
        if (c->fill == 64) {
            sha1_block(c, c->block);
            c->fill = 0;
        }
    }
}

static void sha1_final(sha1_ctx *c, unsigned char out[20])
{
    unsigned char pad = 0x80;
    unsigned char lenb[8];
    uint64_t len = c->len;
    int i;
    for (i = 7; i >= 0; i--) {
        lenb[i] = len & 0xff;
        len >>= 8;
    }
    sha1_update(c, &pad, 1);
    {
        static const unsigned char zero[64];
        while (c->fill != 56)
            sha1_update(c, zero, (c->fill < 56 ? 56 : 120) - c->fill);
    }
    sha1_update(c, lenb, 8);
    for (i = 0; i < 5; i++) {
        out[i * 4] = (c->h[i] >> 24) & 0xff;
        out[i * 4 + 1] = (c->h[i] >> 16) & 0xff;
        out[i * 4 + 2] = (c->h[i] >> 8) & 0xff;
        out[i * 4 + 3] = c->h[i] & 0xff;
    }
}

static void sha1_selfcheck(void)
{
    static const unsigned char expect[20] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    };
    unsigned char out[20];
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, (const unsigned char *)"abc", 3);
    sha1_final(&c, out);
    if (memcmp(out, expect, 20) != 0) {
        fprintf(stderr, "SHA-1 self-check failed\n");
        exit(1);
    }
}
"""

# ---------------------------------------------------------------------
# The handwritten synthetic oracle (downgraded layouts v1..v3, plus the
# v4 / v4_future streams the cross-validation compares against the real
# marshaller).
# ---------------------------------------------------------------------

SYNTHETIC_ORACLE_TEMPLATE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Tpm.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* ---- begin verbatim extract from NVMarshal.c ---- */
@DEFINES@
/* ---- end verbatim extract from NVMarshal.c ---- */

@SHA1@

/* ------------------------------------------------------------------ */
/* Memory writer with the upstream deferred block-size patch scheme.   */
/* ------------------------------------------------------------------ */
static unsigned char buf[1 << 20];
static size_t pos;
static size_t block_stack[16];
static size_t block_depth;

static void put_u8(unsigned v)  { buf[pos++] = v & 0xff; }
static void put_u16(unsigned v) { put_u8(v >> 8); put_u8(v); }
static void put_u32(unsigned long v) { put_u16(v >> 16); put_u16(v & 0xffff); }
static void put_u64(unsigned long long v)
{
    put_u32((unsigned long)(v >> 32));
    put_u32((unsigned long)(v & 0xffffffffUL));
}
static void put_bytes(const unsigned char *p, size_t n)
{
    memcpy(buf + pos, p, n);
    pos += n;
}
static void put_fill(unsigned char fill, size_t n)
{
    memset(buf + pos, fill, n);
    pos += n;
}
static void put_ramp(unsigned base, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        buf[pos++] = (unsigned char)((base + i) & 0xff);
}
static void put_tpm2b_fill(unsigned len, unsigned char fill)
{
    put_u16(len);
    put_fill(fill, len);
}

/* BLOCK_SKIP_WRITE_PUSH / _POP: BOOL has_block, then a u16 size that is
 * patched to the nested byte count when the block is popped. */
static void block_push(int has_block)
{
    put_u8(has_block ? 1 : 0);
    block_stack[block_depth++] = pos;
    put_u16(0);
}
static void block_pop(void)
{
    size_t at = block_stack[--block_depth];
    size_t skip = pos - at - 2;
    buf[at] = (skip >> 8) & 0xff;
    buf[at + 1] = skip & 0xff;
}

static void nv_header(unsigned version, unsigned long magic, unsigned min_version)
{
    put_u16(version);
    put_u32(magic);
    if (version >= 2)
        put_u16(min_version);
}

/* ------------------------------------------------------------------ */
/* Nested sections, transcribed from the NVMarshal.c *_Marshal order.  */
/* ------------------------------------------------------------------ */

static void emit_drbg_state(void)
{
    DRBG_STATE probe;
    nv_header(DRBG_STATE_VERSION, DRBG_STATE_MAGIC, 1);
    put_u64(0x99);                            /* reseedCounter */
    put_u32(0x44524247UL);                    /* in-memory magic, raw */
    put_u16(sizeof(probe.seed.bytes));
    put_ramp(0x30, sizeof(probe.seed.bytes)); /* seed */
    put_u16(ARRAY_SIZE(probe.lastValue));
    put_u32(1); put_u32(2); put_u32(3); put_u32(4);
    block_push(1);                            /* future versions */
    block_pop();
}

static void emit_orderly_data(void)
{
    nv_header(ORDERLY_DATA_VERSION, ORDERLY_DATA_MAGIC, 1);
    put_u64(0x0011223344556677ULL);           /* clock */
    put_u8(0);                                /* clockSafe = NO */
    emit_drbg_state();
    block_push(1);                            /* ACCUMULATE_SELF_HEAL_TIMER */
    put_u64(1000);                            /* selfHealTimer */
    put_u64(2000);                            /* lockoutTimer */
    put_u64(3000);                            /* time */
    block_pop();
    block_push(1);                            /* future versions */
    block_pop();
}

static void emit_pcr_save(void)
{
    PCR_SAVE probe;
    nv_header(PCR_SAVE_VERSION, PCR_SAVE_MAGIC, 1);
    put_u16(NUM_STATIC_PCR);
    put_u16(TPM_ALG_SHA1);
    put_u16(sizeof(probe.Sha1));
    put_fill(0x41, sizeof(probe.Sha1));
    put_u16(TPM_ALG_SHA256);
    put_u16(sizeof(probe.Sha256));
    put_fill(0x42, sizeof(probe.Sha256));
    put_u16(TPM_ALG_SHA384);
    put_u16(sizeof(probe.Sha384));
    put_fill(0x43, sizeof(probe.Sha384));
    put_u16(TPM_ALG_SHA512);
    put_u16(sizeof(probe.Sha512));
    put_fill(0x44, sizeof(probe.Sha512));
    put_u16(TPM_ALG_NULL);
    block_push(1);
    block_pop();
}

static void emit_pcr_authvalue(void)
{
    PCR_AUTHVALUE probe;
    size_t i;
    nv_header(PCR_AUTHVALUE_VERSION, PCR_AUTHVALUE_MAGIC, 1);
    put_u16(ARRAY_SIZE(probe.auth));
    for (i = 0; i < ARRAY_SIZE(probe.auth); i++)
        put_tpm2b_fill(20, 0x7e);
    block_push(1);
    block_pop();
}

static void emit_state_clear_data(void)
{
    nv_header(STATE_CLEAR_DATA_VERSION, STATE_CLEAR_DATA_MAGIC, 1);
    put_u8(1);                                /* shEnable */
    put_u8(0);                                /* ehEnable */
    put_u8(1);                                /* phEnableNV */
    put_u16(TPM_ALG_SHA256);                  /* platformAlg */
    put_tpm2b_fill(32, 0x7c);                 /* platformPolicy */
    put_tpm2b_fill(12, 0x7d);                 /* platformAuth */
    emit_pcr_save();
    emit_pcr_authvalue();
    block_push(1);
    block_pop();
}

static void emit_state_reset_data(void)
{
    STATE_RESET_DATA probe;
    size_t i;
    nv_header(STATE_RESET_DATA_VERSION, STATE_RESET_DATA_MAGIC, 4);
    put_tpm2b_fill(16, 0x6a);                 /* nullProof */
    put_tpm2b_fill(16, 0x6b);                 /* nullSeed */
    put_u32(5);                               /* clearCount */
    put_u64(0x77);                            /* objectContextID */
    put_u16(ARRAY_SIZE(probe.contextArray));
    for (i = 0; i < ARRAY_SIZE(probe.contextArray); i++)
        put_u16(i);
    put_u16(0xffff);                          /* s_ContextSlotMask */
    put_u64(0x88);                            /* contextCounter */
    put_tpm2b_fill(32, 0x6c);                 /* commandAuditDigest */
    put_u32(9);                               /* restartCount */
    put_u32(11);                              /* pcrCounter */
    block_push(1);                            /* ALG_ECC */
    put_u64(0x99);                            /* commitCounter */
    put_tpm2b_fill(16, 0x6d);                 /* commitNonce */
    put_u16(sizeof(probe.commitArray));
    put_fill(0x6e, sizeof(probe.commitArray));
    block_pop();
    block_push(1);                            /* seed-compat level */
    put_u8(0);                                /* SEED_COMPAT_LEVEL_ORIGINAL */
    block_push(1);                            /* future versions */
    block_pop();
    block_pop();
}

static void emit_unoccupied_any_object(void)
{
    nv_header(ANY_OBJECT_VERSION, ANY_OBJECT_MAGIC, 1);
    put_u32(0);                               /* attributes: not occupied */
    block_push(1);
    block_pop();
}

static void emit_pcr_slot(unsigned slot)
{
    PCR probe;
    nv_header(PCR_VERSION, PCR_MAGIC, 1);
    put_u16(TPM_ALG_SHA1);
    put_u16(sizeof(probe.Sha1Pcr));
    put_fill((0x50 + slot) & 0xff, sizeof(probe.Sha1Pcr));
    put_u16(TPM_ALG_SHA256);
    put_u16(sizeof(probe.Sha256Pcr));
    put_fill((0x60 + slot) & 0xff, sizeof(probe.Sha256Pcr));
    put_u16(TPM_ALG_SHA384);
    put_u16(sizeof(probe.Sha384Pcr));
    put_fill((0x70 + slot) & 0xff, sizeof(probe.Sha384Pcr));
    put_u16(TPM_ALG_SHA512);
    put_u16(sizeof(probe.Sha512Pcr));
    put_fill((0x80 + slot) & 0xff, sizeof(probe.Sha512Pcr));
    put_u16(TPM_ALG_NULL);
    block_push(1);
    block_pop();
}

static void emit_occupied_session_slot(void)
{
    nv_header(SESSION_SLOT_VERSION, SESSION_SLOT_MAGIC, 1);
    put_u8(1);                                /* occupied */
    nv_header(SESSION_VERSION, SESSION_MAGIC, 1);
    put_u32(0x01010101UL);                    /* attributes (raw bitfield) */
    put_u32(3);                               /* pcrCounter */
    put_u64(100);                             /* startTime */
    put_u64(5000);                            /* timeout */
    put_u8(4);                                /* clocksize (CLOCK_STOPS=NO) */
    put_u32(12);                              /* epoch */
    put_u32(0x176);                           /* commandCode */
    put_u16(TPM_ALG_SHA256);                  /* authHashAlg */
    put_u8(0);                                /* commandLocality */
    put_u16(TPM_ALG_AES);                     /* symmetric.algorithm */
    put_u16(128);                             /* symmetric.keyBits */
    put_u16(TPM_ALG_CFB);                     /* symmetric.mode */
    put_tpm2b_fill(32, 0x33);                 /* sessionKey */
    put_tpm2b_fill(20, 0x34);                 /* nonceTPM */
    put_tpm2b_fill(34, 0x35);                 /* u1.boundEntity */
    put_tpm2b_fill(0, 0);                     /* u2.auditDigest */
    block_push(1);                            /* SESSION future */
    block_pop();
    block_push(1);                            /* SESSION_SLOT future */
    block_pop();
}

static void emit_unoccupied_session_slot(void)
{
    nv_header(SESSION_SLOT_VERSION, SESSION_SLOT_MAGIC, 1);
    put_u8(0);                                /* unoccupied: ends the slot */
}

/* ------------------------------------------------------------------ */
/* The VolatileState_Marshal payload for a given writer version.       */
/* ------------------------------------------------------------------ */
static void emit_volatile_payload(unsigned version, int future_bytes)
{
    unsigned i;

    pos = 0;
    block_depth = 0;

    nv_header(version, VOLATILE_STATE_MAGIC, 1);
    put_u32(0x03000abcUL);                    /* g_exclusiveAuditSession */
    put_u64(0x123456);                        /* g_time */
    put_u8(1);                                /* g_phEnable */
    put_u8(1);                                /* g_pcrReConfig */
    put_u32(0x40000007UL);                    /* g_DRTMHandle */
    put_u8(0);                                /* g_DrtmPreStartup */
    put_u8(1);                                /* g_StartupLocality3 */
    block_push(1);                            /* USE_DA_USED */
    put_u8(1);                                /* g_daUsed */
    block_pop();
    put_u8(1);                                /* g_powerWasLost */
    put_u16(0x8001);                          /* g_prevOrderlyState */
    put_u8(1);                                /* g_nvOk */
    put_u16(0);                               /* retired platform-unique TPM2B */

    emit_orderly_data();
    emit_state_clear_data();
    emit_state_reset_data();

    put_u8(1);                                /* g_manufactured */
    put_u8(1);                                /* g_initialized */

    block_push(1);                            /* SESSION_PROCESS */
    put_u16(MAX_SESSION_NUM);
    /* entry 0: an active authorization session */
    put_u32(0x02000000UL);
    put_u8(0x01);
    put_u32(0x40000001UL);
    put_tpm2b_fill(16, 0x21);
    put_tpm2b_fill(16, 0x22);
    /* entries 1..: unused slots */
    for (i = 1; i < MAX_SESSION_NUM; i++) {
        put_u32(0xffffffffUL);
        put_u8(0);
        put_u32(0xffffffffUL);
        put_tpm2b_fill(0, 0);
        put_tpm2b_fill(0, 0);
    }
    put_u32(7);                               /* s_encryptSessionIndex */
    put_u32(8);                               /* s_decryptSessionIndex */
    put_u32(9);                               /* s_auditSessionIndex */
    block_push(1);                            /* CC_GetCommandAuditDigest */
    put_tpm2b_fill(32, 0x23);                 /* s_cpHashForCommandAudit */
    block_pop();
    put_u8(1);                                /* s_DAPendingOnNV */
    block_pop();

    block_push(0);                            /* DA_C timers: never compiled */
    block_pop();

    block_push(1);                            /* NV_C */
    put_u32(0x00024000UL);                    /* s_evictNvEnd */
    put_u16(RAM_INDEX_SPACE);
    put_ramp(0, RAM_INDEX_SPACE);             /* s_indexOrderlyRam */
    put_u64(0x2a);                            /* s_maxCounter */
    block_pop();

    block_push(1);                            /* OBJECT_C */
    put_u16(MAX_LOADED_OBJECTS);
    for (i = 0; i < MAX_LOADED_OBJECTS; i++)
        emit_unoccupied_any_object();
    block_pop();

    block_push(1);                            /* PCR_C */
    put_u16(IMPLEMENTATION_PCR);
    for (i = 0; i < IMPLEMENTATION_PCR; i++)
        emit_pcr_slot(i);
    block_pop();

    block_push(1);                            /* SESSION_C */
    put_u16(MAX_LOADED_SESSIONS);
    emit_occupied_session_slot();
    for (i = 1; i < MAX_LOADED_SESSIONS; i++)
        emit_unoccupied_session_slot();
    put_u32(1);                               /* s_oldestSavedSession */
    put_u32(2);                               /* s_freeSessionSlots */
    block_pop();

    put_u8(0);                                /* g_inFailureMode */
    put_u8(1);                                /* TPM established */

    block_push(1);                            /* TPM_FAIL_C */
    put_u32(0xa1);                            /* s_failFunction */
    put_u32(0xa2);                            /* s_failLine */
    put_u32(0xa3);                            /* s_failCode */
    block_pop();

    block_push(1);                            /* !HARDWARE_CLOCK */
    put_u64(111222);                          /* s_realTimePrevious */
    put_u64(111000);                          /* s_tpmTime */
    block_pop();

    put_u8(1);                                /* s_timerReset */
    put_u8(0);                                /* s_timerStopped */
    put_u32(30000);                           /* s_adjustRate */
    put_u64(100000000000ULL);                 /* backthen (CLOCK_REALTIME) */

    /* The nested versioned tails: v5 (empty) in v4 in v3. */
    if (version >= 2) {
        block_push(1);                        /* v3 gate */
        if (version >= 3) {
            /* EP/SP/PP seed ties: empty, matching the Rust permanent
             * fixture whose seeds are all zero-length. */
            put_u16(0);
            put_u16(0);
            put_u16(0);
            block_push(1);                    /* v4 gate */
            if (version >= 4) {
                put_u64(5000000);             /* monotonic sample */
                put_u64(60000);               /* s_suspendedElapsedTime */
                put_u64(1600000000500ULL);    /* s_lastSystemTime */
                put_u64(1600000000400ULL);    /* s_lastReportedTime */
                block_push(1);                /* v5 gate */
                block_pop();
            }
            block_pop();
        }
        block_pop();
    }

    put_u32(VOLATILE_STATE_MAGIC);            /* trailing end marker */

    if (future_bytes) {
        /* Forward-compatible bytes a newer writer may leave before the
         * digest; VolatileState_Load must skip them and the digest must
         * cover them. */
        static const unsigned char future[6] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5 };
        put_bytes(future, sizeof(future));
    }

    if (block_depth != 0) {
        fprintf(stderr, "unbalanced block writer\n");
        exit(1);
    }
}

static int write_fixture(const char *path, unsigned version, int future_bytes)
{
    unsigned char digest[20];
    sha1_ctx c;
    FILE *f;

    emit_volatile_payload(version, future_bytes);
    sha1_init(&c);
    sha1_update(&c, buf, pos);
    sha1_final(&c, digest);
    put_bytes(digest, sizeof(digest));

    f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return 1;
    }
    if (fwrite(buf, 1, pos, f) != pos || fclose(f) != 0) {
        perror(path);
        return 1;
    }
    printf("%s\t%u\t%zu\n", path, version, pos);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-directory>\n", argv[0]);
        return 1;
    }
    sha1_selfcheck();
    {
        char path[4096];
        unsigned version;
        for (version = 1; version <= 4; version++) {
            snprintf(path, sizeof(path), "%s/volatile_state_v%u.bin",
                     argv[1], version);
            if (write_fixture(path, version, 0))
                return 1;
        }
        snprintf(path, sizeof(path), "%s/volatile_state_v4_future.bin", argv[1]);
        if (write_fixture(path, 4, 1))
            return 1;
    }
    return 0;
}
"""

# ---------------------------------------------------------------------
# The authentic harness: drives the real vendored VolatileState_Save /
# VolatileState_Marshal over deterministic globals and clock inputs.
# ---------------------------------------------------------------------

AUTHENTIC_HARNESS_TEMPLATE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Instantiate every TPM global in this translation unit (the roles
 * Global.c and PlatformData.c play in the real build); NVMarshal.o and
 * friends resolve their extern references against these instances. */
#define GLOBAL_C
#define _PLATFORM_DATA_C_
#include "Platform.h"
#include "Tpm.h"
#include "NVMarshal.h"
#include "Volatile.h"
#include "TpmTcpProtocol.h"
#include "Simulator_fp.h"
#include "RuntimeProfile_fp.h"

/* Referenced by address only on the marshal path (all objects are
 * unoccupied, so ANY_OBJECT_Marshal never consults the profile). */
struct RuntimeProfile g_RuntimeProfile;

/* Global.h declares this one with a bare extern (Manufacture.c owns it
 * in the real build). */
BOOL g_manufactured;

@SHA1@

/* ------------------------------------------------------------------ */
/* Deterministic platform stand-ins                                    */
/* ------------------------------------------------------------------ */

/* The fixed clock inputs: CLOCK_REALTIME is exactly the serialized
 * `backthen`; CLOCK_MONOTONIC plus the adjustment below is exactly the
 * serialized TailV4 monotonic sample. */
#define FIXTURE_REALTIME_MS   100000000000ULL
#define FIXTURE_MONOTONIC_MS  4000000ULL

uint64_t ClockGetTime(clockid_t clk_id)
{
    if (clk_id == CLOCK_REALTIME)
        return FIXTURE_REALTIME_MS;
    if (clk_id == CLOCK_MONOTONIC)
        return FIXTURE_MONOTONIC_MS;
    fprintf(stderr, "ClockGetTime: unexpected clock id %d\n", (int)clk_id);
    exit(1);
}

void NvRead(void *outBuffer, UINT32 nvOffset, UINT32 size)
{
    /* The TailV3 seed tie reads NV_PERSISTENT_DATA: all-zero seeds,
     * matching the Rust permanent fixture's empty EP/SP/PP seeds. */
    (void)nvOffset;
    memset(outBuffer, 0, size);
}

LIB_EXPORT UINT16 CryptHashBlock(TPM_ALG_ID hashAlg, UINT32 dataSize,
                                 const BYTE *data, UINT32 dOutSize, BYTE *dOut)
{
    sha1_ctx c;
    unsigned char digest[20];
    if (hashAlg != TPM_ALG_SHA1 || dOutSize < 20) {
        fprintf(stderr, "CryptHashBlock: unexpected algorithm/digest size\n");
        exit(1);
    }
    sha1_init(&c);
    sha1_update(&c, data, dataSize);
    sha1_final(&c, digest);
    memcpy(dOut, digest, 20);
    return 20;
}

bool _rpc__Signal_GetTPMEstablished(void)
{
    return true;
}

/* ------------------------------------------------------------------ */
/* Fixture state, identical to the synthetic oracle's values           */
/* ------------------------------------------------------------------ */
static void set_tpm2b(TPM2B *b, unsigned len, unsigned char fill)
{
    b->size = len;
    memset(b->buffer, fill, len);
}

static void populate_globals(void)
{
    size_t i;
    UINT32 session_attributes = 0x01010101UL;
    UINT8 process_attributes = 0x01;

    g_exclusiveAuditSession = 0x03000abcUL;
    g_time = 0x123456;
    g_phEnable = 1;
    g_pcrReConfig = 1;
    g_DRTMHandle = 0x40000007UL;
    g_DrtmPreStartup = 0;
    g_StartupLocality3 = 1;
    g_daUsed = 1;
    g_powerWasLost = 1;
    g_prevOrderlyState = 0x8001;
    g_nvOk = 1;
    g_manufactured = 1;
    g_initialized = 1;
    g_inFailureMode = 0;

    /* ORDERLY_DATA go */
    go.clock = 0x0011223344556677ULL;
    go.clockSafe = 0;
    go.drbgState.reseedCounter = 0x99;
    go.drbgState.magic = 0x44524247UL;
    for (i = 0; i < sizeof(go.drbgState.seed.bytes); i++)
        go.drbgState.seed.bytes[i] = (unsigned char)((0x30 + i) & 0xff);
    go.drbgState.lastValue[0] = 1;
    go.drbgState.lastValue[1] = 2;
    go.drbgState.lastValue[2] = 3;
    go.drbgState.lastValue[3] = 4;
    go.selfHealTimer = 1000;
    go.lockoutTimer = 2000;
    go.time = 3000;

    /* STATE_CLEAR_DATA gc */
    gc.shEnable = 1;
    gc.ehEnable = 0;
    gc.phEnableNV = 1;
    gc.platformAlg = TPM_ALG_SHA256;
    set_tpm2b(&gc.platformPolicy.b, 32, 0x7c);
    set_tpm2b(&gc.platformAuth.b, 12, 0x7d);
    memset(gc.pcrSave.Sha1, 0x41, sizeof(gc.pcrSave.Sha1));
    memset(gc.pcrSave.Sha256, 0x42, sizeof(gc.pcrSave.Sha256));
    memset(gc.pcrSave.Sha384, 0x43, sizeof(gc.pcrSave.Sha384));
    memset(gc.pcrSave.Sha512, 0x44, sizeof(gc.pcrSave.Sha512));
    for (i = 0; i < ARRAY_SIZE(gc.pcrAuthValues.auth); i++)
        set_tpm2b(&gc.pcrAuthValues.auth[i].b, 20, 0x7e);

    /* STATE_RESET_DATA gr */
    set_tpm2b(&gr.nullProof.b, 16, 0x6a);
    set_tpm2b(&gr.nullSeed.b, 16, 0x6b);
    gr.clearCount = 5;
    gr.objectContextID = 0x77;
    for (i = 0; i < ARRAY_SIZE(gr.contextArray); i++)
        gr.contextArray[i] = (CONTEXT_SLOT)i;
    s_ContextSlotMask = 0xffff;
    gr.contextCounter = 0x88;
    set_tpm2b(&gr.commandAuditDigest.b, 32, 0x6c);
    gr.restartCount = 9;
    gr.pcrCounter = 11;
    gr.commitCounter = 0x99;
    set_tpm2b(&gr.commitNonce.b, 16, 0x6d);
    memset(gr.commitArray, 0x6e, sizeof(gr.commitArray));
    gr.nullSeedCompatLevel = 0;

    /* SESSION_PROCESS: one active registration, the rest unused. */
    s_sessionHandles[0] = 0x02000000UL;
    memcpy(&s_attributes[0], &process_attributes, sizeof(process_attributes));
    s_associatedHandles[0] = 0x40000001UL;
    set_tpm2b(&s_nonceCaller[0].b, 16, 0x21);
    set_tpm2b(&s_inputAuthValues[0].b, 16, 0x22);
    for (i = 1; i < ARRAY_SIZE(s_sessionHandles); i++) {
        s_sessionHandles[i] = 0xffffffffUL;
        s_associatedHandles[i] = 0xffffffffUL;
    }
    s_encryptSessionIndex = 7;
    s_decryptSessionIndex = 8;
    s_auditSessionIndex = 9;
    set_tpm2b(&s_cpHashForCommandAudit.b, 32, 0x23);
    s_DAPendingOnNV = 1;

    /* NV_C */
    s_evictNvEnd = 0x00024000UL;
    for (i = 0; i < sizeof(s_indexOrderlyRam); i++)
        s_indexOrderlyRam[i] = (unsigned char)(i & 0xff);
    s_maxCounter = 0x2a;

    /* s_objects: all unoccupied (zero attributes). */

    /* PCR_C: per-slot patterned banks. */
    for (i = 0; i < ARRAY_SIZE(s_pcrs); i++) {
        memset(s_pcrs[i].Sha1Pcr, (unsigned char)((0x50 + i) & 0xff),
               sizeof(s_pcrs[i].Sha1Pcr));
        memset(s_pcrs[i].Sha256Pcr, (unsigned char)((0x60 + i) & 0xff),
               sizeof(s_pcrs[i].Sha256Pcr));
        memset(s_pcrs[i].Sha384Pcr, (unsigned char)((0x70 + i) & 0xff),
               sizeof(s_pcrs[i].Sha384Pcr));
        memset(s_pcrs[i].Sha512Pcr, (unsigned char)((0x80 + i) & 0xff),
               sizeof(s_pcrs[i].Sha512Pcr));
    }

    /* SESSION_C: slot 0 occupied, others empty. */
    s_sessions[0].occupied = 1;
    memcpy(&s_sessions[0].session.attributes, &session_attributes,
           sizeof(session_attributes));
    s_sessions[0].session.pcrCounter = 3;
    s_sessions[0].session.startTime = 100;
    s_sessions[0].session.timeout = 5000;
    s_sessions[0].session.epoch = 12;
    s_sessions[0].session.commandCode = 0x176;
    s_sessions[0].session.authHashAlg = TPM_ALG_SHA256;
    s_sessions[0].session.commandLocality = 0;
    s_sessions[0].session.symmetric.algorithm = TPM_ALG_AES;
    s_sessions[0].session.symmetric.keyBits.aes = 128;
    s_sessions[0].session.symmetric.mode.aes = TPM_ALG_CFB;
    set_tpm2b(&s_sessions[0].session.sessionKey.b, 32, 0x33);
    set_tpm2b(&s_sessions[0].session.nonceTPM.b, 20, 0x34);
    set_tpm2b(&s_sessions[0].session.u1.boundEntity.b, 34, 0x35);
    set_tpm2b(&s_sessions[0].session.u2.auditDigest.b, 0, 0);
    s_oldestSavedSession = 1;
    s_freeSessionSlots = 2;

    /* TPM_FAIL_C */
    s_failFunction = 0xa1;
    s_failLine = 0xa2;
    s_failCode = 0xa3;

    /* clock state */
    s_realTimePrevious = 111222;
    s_tpmTime = 111000;
    s_timerReset = 1;
    s_timerStopped = 0;
    s_adjustRate = 30000;
    s_hostMonotonicAdjustTime = 1000000; /* serialized sample = 5000000 */
    s_suspendedElapsedTime = 60000;
    s_lastSystemTime = 1600000000500ULL;
    s_lastReportedTime = 1600000000400ULL;
}

static unsigned char buf[1 << 20];

static int write_file(const char *dir, const char *name,
                      const unsigned char *data, size_t n)
{
    char path[4096];
    FILE *f;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return 1;
    }
    if (fwrite(data, 1, n, f) != n || fclose(f) != 0) {
        perror(path);
        return 1;
    }
    printf("%s\t%zu\n", path, n);
    return 0;
}

int main(int argc, char **argv)
{
    BYTE *bufptr;
    INT32 sz;
    UINT16 written;
    size_t total;
    static const unsigned char future[6] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5 };
    unsigned char digest[20];
    sha1_ctx c;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-directory>\n", argv[0]);
        return 1;
    }
    sha1_selfcheck();
    populate_globals();

    /* The real VolatileState_Save: payload + the SHA-1 frame over every
     * preceding byte. */
    bufptr = buf;
    sz = sizeof(buf);
    written = VolatileState_Save(&bufptr, &sz);
    if (written <= 20 || bufptr != buf + written) {
        fprintf(stderr, "VolatileState_Save produced no stream\n");
        return 1;
    }
    if (write_file(argv[1], "authentic_v4.bin", buf, written))
        return 1;

    /* The forward-compatible variant: the real VolatileState_Marshal
     * payload, extra bytes a newer writer may leave after the trailing
     * magic, and the digest over every preceding byte -- the exact
     * VolatileState_Save frame. */
    bufptr = buf;
    sz = sizeof(buf);
    written = VolatileState_Marshal(&bufptr, &sz, &g_RuntimeProfile);
    if (written == 0) {
        fprintf(stderr, "VolatileState_Marshal produced no payload\n");
        return 1;
    }
    memcpy(buf + written, future, sizeof(future));
    total = (size_t)written + sizeof(future);
    sha1_init(&c);
    sha1_update(&c, buf, total);
    sha1_final(&c, digest);
    memcpy(buf + total, digest, sizeof(digest));
    total += sizeof(digest);
    if (write_file(argv[1], "authentic_v4_future.bin", buf, total))
        return 1;
    return 0;
}
"""

# The aborting stand-ins for external symbols the linker demands but the
# volatile marshal path never executes (unmarshal helpers, the NV/object
# runtime, the profile machinery).  Any upstream change that routes the
# marshal path into one of these aborts the oracle run loudly.
STUB_TEMPLATE = """\
#include <stdio.h>
#include <stdlib.h>

"""


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


def compile_flags(tmpdir: Path) -> list[str]:
    # Same feature macros the upstream tpm2 build passes (Makefile.am);
    # tmpdir first, for the empty config.h Volatile.c includes.
    return [
        "-DTPM_POSIX",
        "-D_POSIX_",
        f"-I{tmpdir}",
        f"-I{TPM2_DIR}",
        f"-I{TPM2_DIR / 'crypto'}",
        f"-I{TPM2_DIR / 'crypto' / 'openssl'}",
        f"-I{REPO_ROOT / 'libtpms' / 'src'}",
        f"-I{REPO_ROOT / 'libtpms' / 'include' / 'libtpms'}",
        *openssl_include_flags(),
    ]


def compile_object(source: Path, output: Path, flags: list[str]) -> None:
    subprocess.run(
        ["cc", "-c", *flags, str(source), "-o", str(output)],
        check=True,
    )


# ld64 (macOS) and GNU/LLVM ld (Linux) undefined-symbol report formats.
UNDEFINED_SYMBOL_PATTERNS = [
    re.compile(r'"_([A-Za-z_][A-Za-z0-9_]*)", referenced from'),
    re.compile(r"undefined reference to [`']([A-Za-z_][A-Za-z0-9_]*)'"),
    re.compile(r"undefined symbol: _?([A-Za-z_][A-Za-z0-9_]*)"),
]


def link_with_stubs(objects: list[Path], output: Path, tmpdir: Path) -> set[str]:
    """Link, auto-stubbing externals the marshal path never executes.

    Returns the stubbed symbol set.  Symbols the harness must implement
    for real (clock, NV, hashing) are already defined there; everything
    else becomes an aborting stub, so an unexpected call cannot corrupt
    the output silently.
    """
    stub_symbols: set[str] = set()
    stub_object = tmpdir / "stubs.o"
    for _attempt in range(4):
        command = ["cc", *map(str, objects)]
        if stub_symbols:
            command.append(str(stub_object))
        command += ["-o", str(output)]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            return stub_symbols
        found: set[str] = set()
        for pattern in UNDEFINED_SYMBOL_PATTERNS:
            found.update(pattern.findall(result.stderr))
        new = found - stub_symbols
        if not new:
            raise SystemExit(
                "error: cannot link the authentic volatile-state oracle:\n"
                + result.stderr
            )
        stub_symbols |= new
        stub_source = tmpdir / "stubs.c"
        lines = [STUB_TEMPLATE]
        for symbol in sorted(stub_symbols):
            lines.append(f"void {symbol}(void);\n")
            lines.append(
                f'void {symbol}(void) {{ fprintf(stderr, '
                f'"authentic oracle stub {symbol} called unexpectedly\\n"); '
                f"abort(); }}\n"
            )
        stub_source.write_text("".join(lines))
        compile_object(stub_source, stub_object, [])
    raise SystemExit("error: authentic oracle link did not converge")


def run_oracle(binary: Path, outdir: Path) -> str:
    return subprocess.run(
        [str(binary), str(outdir)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def build_synthetic(tmpdir: Path, defines: str, flags: list[str]) -> dict[str, bytes]:
    outdir = tmpdir / "synthetic"
    outdir.mkdir()
    program = SYNTHETIC_ORACLE_TEMPLATE.replace("@DEFINES@", defines).replace(
        "@SHA1@", SHA1_C
    )
    oracle_c = tmpdir / "synthetic_oracle.c"
    oracle_bin = tmpdir / "synthetic_oracle"
    oracle_c.write_text(program)
    subprocess.run(
        ["cc", *flags, str(oracle_c), "-o", str(oracle_bin)],
        check=True,
    )
    run_oracle(oracle_bin, outdir)
    return {name: (outdir / name).read_bytes() for name in SYNTHETIC_OUTPUTS}


def build_authentic(
    tmpdir: Path, nvmarshal_path: Path, flags: list[str]
) -> dict[str, bytes]:
    outdir = tmpdir / "authentic"
    outdir.mkdir()
    harness_c = tmpdir / "authentic_harness.c"
    harness_c.write_text(AUTHENTIC_HARNESS_TEMPLATE.replace("@SHA1@", SHA1_C))
    objects = []
    for name, source in [
        ("nvmarshal.o", nvmarshal_path),
        ("marshal.o", MARSHAL),
        ("volatile.o", VOLATILE),
        ("authentic_harness.o", harness_c),
    ]:
        output = tmpdir / name
        compile_object(source, output, flags)
        objects.append(output)
    oracle_bin = tmpdir / "authentic_oracle"
    link_with_stubs(objects, oracle_bin, tmpdir)
    run_oracle(oracle_bin, outdir)
    return {name: (outdir / name).read_bytes() for name in AUTHENTIC_OUTPUTS}


def build_fixtures(
    nvmarshal_path: Path = NVMARSHAL,
) -> tuple[dict[str, bytes], str]:
    nvmarshal_source = nvmarshal_path.read_text()
    volatile_source = VOLATILE.read_text()
    require_marshaller_fragments(nvmarshal_source, volatile_source)
    defines = extract_defines(nvmarshal_source)

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        # Volatile.c includes the autotools-generated config.h; nothing
        # it could define matters to the marshal path.
        (tmpdir / "config.h").write_text(
            "/* empty stand-in for the autotools-generated config.h */\n"
        )
        flags = compile_flags(tmpdir)
        synthetic = build_synthetic(tmpdir, defines, flags)
        authentic = build_authentic(tmpdir, nvmarshal_path, flags)

        # Cross-validation: the real pinned marshaller must reproduce
        # the synthetic v4 streams byte for byte.  Any change to field
        # order, framing, geometry, section versions, or digest coverage
        # in the vendored implementation lands here.
        for authentic_name, synthetic_name in [
            ("authentic_v4.bin", "volatile_state_v4.bin"),
            ("authentic_v4_future.bin", "volatile_state_v4_future.bin"),
        ]:
            if authentic[authentic_name] != synthetic[synthetic_name]:
                raise SystemExit(
                    f"error: the vendored VolatileState_Save output "
                    f"({authentic_name}) diverged from the synthetic oracle "
                    f"({synthetic_name}); the pinned volatile wire layout "
                    f"changed -- update the oracle, the fixtures, and the "
                    f"Rust decoder together"
                )

        fixtures = {
            SYNTHETIC_OUTPUTS[name]: data for name, data in synthetic.items()
        }
        # The current-version fixtures are the authentic marshaller
        # outputs (byte-identical to the synthetic ones, per the check
        # above).
        fixtures["volatile_state_v4.bin"] = authentic["authentic_v4.bin"]
        fixtures["volatile_state_v4_future.bin"] = authentic[
            "authentic_v4_future.bin"
        ]
        listing = "".join(
            f"{name}\t{len(data)}\n" for name, data in sorted(fixtures.items())
        )
        return fixtures, listing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in fixtures instead of rewriting them",
    )
    args = parser.parse_args()

    fixtures, _listing = build_fixtures()

    if args.check:
        stale = []
        for name, data in fixtures.items():
            path = TESTDATA / name
            current = path.read_bytes() if path.is_file() else None
            if current != data:
                stale.append(path)
        if stale:
            for path in stale:
                print(f"error: {path} is stale; rerun {Path(__file__).name}",
                      file=sys.stderr)
            return 1
        for name, data in fixtures.items():
            print(f"{TESTDATA / name}: OK ({len(data)} bytes)")
        return 0

    TESTDATA.mkdir(parents=True, exist_ok=True)
    for name, data in fixtures.items():
        (TESTDATA / name).write_bytes(data)
        print(f"wrote {TESTDATA / name} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
