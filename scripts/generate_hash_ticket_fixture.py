#!/usr/bin/env python3
"""Regenerate the TPM2_Hash / hash-check ticket vectors from the vendored libtpms.

Produces ``src/library/tpm2/testdata/hash_ticket_vectors.bin``: the exact
response parameters (``TPM2B_DIGEST outHash`` followed by
``TPMT_TK_HASHCHECK validation``) the pinned vendored implementation
produces for a fixed set of inputs and a fixed set of hierarchy proofs.

How it works
------------
``TPM2_Hash`` (libtpms/src/tpm2/SymmetricCommands.c), ``TicketIsSafe`` and
``TicketComputeHashCheck`` (libtpms/src/tpm2/Ticket.c), the ``Hash_In`` /
``Hash_Out`` parameter structures (libtpms/src/tpm2/Hash_fp.h), the
``TPM2B_TYPE`` macro (libtpms/src/tpm2/TPMB.h) and the marshalling chain
that turns ``Hash_Out`` into response bytes (``UINT16_Marshal``,
``UINT32_Marshal``, ``Array_Marshal``, ``TPM2B_Marshal``,
``TPM_HANDLE_Marshal``, ``TPM_ST_Marshal``, ``TPMI_RH_HIERARCHY_Marshal``,
``TPM2B_DIGEST_Marshal``, ``TPMT_TK_HASHCHECK_Marshal`` from
libtpms/src/tpm2/Marshal.c) are extracted *verbatim* and compiled into a
small C oracle against OpenSSL's EVP digests and HMAC -- the same
primitives the vendored build maps its hash and HMAC layers to.  The
branch order inside TPM2_Hash, the TicketIsSafe prefix rule, the HMAC
input composition and the wire layout of the response therefore cannot
drift from upstream without either failing to compile or moving the
fixture bytes.

Guarding the mirrored primitives
--------------------------------
Two groups of vendored functions are mirrored by hand rather than
compiled verbatim, because dragging them in would pull the whole
hash-definition and platform machinery into the oracle:

``CryptHashStart`` / ``CryptDigestUpdate`` / ``CryptHashEnd`` /
``CryptHashEnd2B`` / ``CryptDigestUpdate2B`` / ``CryptDigestUpdateInt`` /
``CryptHmacStart`` / ``CryptHmacEnd`` / ``CryptHmacStart2B`` /
``CryptHmacEnd2B`` (crypto/openssl/CryptHash.c)
    reimplemented on top of OpenSSL EVP/HMAC.  What matters for these
    fixtures is that a 2B update feeds exactly ``size`` bytes with no
    length prefix, that an integer update feeds ``intSize`` big-endian
    bytes, and that the HMAC is a textbook HMAC keyed with the hierarchy
    proof.

``HierarchyGetProof`` / ``DecomposeHandle`` / ``MixAdditionalSecret`` /
``GetAdditionalSecret`` (Hierarchy.c)
    reduced to the plain-handle path: none of TPM_RH_PLATFORM,
    TPM_RH_OWNER, TPM_RH_ENDORSEMENT or TPM_RH_NULL is firmware- or
    SVN-bound, so ``DecomposeHandle`` reports HM_NONE, the additional
    secret is empty and ``MixAdditionalSecret`` copies the base proof
    through unchanged.  The oracle hands out the fixed proofs directly.

A change to any of these would not move a fixture byte on its own, so the
generator pins a SHA-256 over each vendored function and refuses to run
when one moves.  Updating a digest below means the mirror has been
re-read against the new upstream source -- do not refresh it
mechanically.

Fixed inputs
------------
The hierarchy proofs are deterministic 64-byte patterns (see
``fill_proof`` below), which the Rust test suite installs into the
persistent state before dispatching, so the recorded ticket HMACs are
reproducible from the Rust side.

The data cases cover the empty buffer, ``abc``, a full
``MAX_DIGEST_BUFFER`` (1024) buffer, the exact big-endian encoding of
``TPM_GENERATED_VALUE`` alone and with a tail, its one-, two- and
three-byte prefixes (which upstream still tickets, because TPM2_Hash only
consults TicketIsSafe once the buffer reaches four bytes), and a buffer
that differs from ``TPM_GENERATED_VALUE`` only in the fourth byte.  Every
data case is run against every compiled hash algorithm (SHA-1, SHA-256,
SHA-384, SHA-512) and against all four accepted hierarchies (owner,
platform, endorsement, null).

Fixture layout (big-endian scalars):
     2  proof size (64)
    64  phProof
    64  shProof
    64  ehProof
     2  case count
    then one record per case:
     2  data size
     n  data
     2  hashAlg
     4  hierarchy
     2  response parameter size
     n  response parameters (TPM2B_DIGEST outHash || TPMT_TK_HASHCHECK)

Determinism: the output depends only on the vendored sources under
``libtpms/`` and OpenSSL's digests; no network access, no timestamps, no
environment input beyond the C compiler and the OpenSSL headers libtpms
itself builds against.

Usage:
    python3 scripts/generate_hash_ticket_fixture.py
    python3 scripts/generate_hash_ticket_fixture.py --check
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
TPM2 = REPO_ROOT / "libtpms" / "src" / "tpm2"
SYMMETRIC_COMMANDS = TPM2 / "SymmetricCommands.c"
TICKET = TPM2 / "Ticket.c"
HASH_FP = TPM2 / "Hash_fp.h"
TPMB = TPM2 / "TPMB.h"
MARSHAL = TPM2 / "Marshal.c"
CRYPT_HASH = TPM2 / "crypto" / "openssl" / "CryptHash.c"
HIERARCHY = TPM2 / "Hierarchy.c"
TESTDATA = REPO_ROOT / "src" / "library" / "tpm2" / "testdata"
FIXTURE = TESTDATA / "hash_ticket_vectors.bin"

# SHA-256 of the complete vendored source of every primitive the oracle
# mirrors by hand.  See "Guarding the mirrored primitives".
MIRRORED = {
    CRYPT_HASH: [
        "CryptHashStart",
        "CryptDigestUpdate",
        "CryptHashEnd",
        "CryptHashEnd2B",
        "CryptDigestUpdate2B",
        "CryptDigestUpdateInt",
        "CryptHmacStart",
        "CryptHmacEnd",
        "CryptHmacStart2B",
        "CryptHmacEnd2B",
    ],
    HIERARCHY: [
        "DecomposeHandle",
        "GetAdditionalSecret",
        "MixAdditionalSecret",
        "HierarchyGetProof",
    ],
}

MIRRORED_SHA256 = {
    "CryptHashStart": "8dd5b58d4ea479fefff8edf11b238735d1e708451ca847906ac0a0ef55571480",
    "CryptDigestUpdate": "7a67104ee8d6dad645fb7fefe997b3a30b5d6752380f37a8d7fa996eb0e78913",
    "CryptHashEnd": "eced37407a3e5a6bb5d9c34a0c72cfc628b6c36a880a997a759270a06f330214",
    "CryptHashEnd2B": "86a3708873bfc2062584ae6db46b04cccd6159cebaae6f4eed65d9a3f586e797",
    "CryptDigestUpdate2B": "35d997881c53890bf33291874ed54ff0c00049e273430b8d51013767efe86289",
    "CryptDigestUpdateInt": "d1109e957f16fe4af43148196cb8ea19fc8d2e72a0ffd4334a291efe3d213fc5",
    "CryptHmacStart": "c43dddecb6f2ff5143f918237cdf620f9a63bd6a9f96a0c4ef1aaf2b3ffb0ac9",
    "CryptHmacEnd": "960829d93c431a961faf9d0749b377f18c05ec1f42a22b35b336fc27b6ef9e9e",
    "CryptHmacStart2B": "67a7e69bcd285ba89b3d3789709b97ed908a85f37e487d4457179ca2cd5cf18f",
    "CryptHmacEnd2B": "fa045ffedc03c1d165182811884251f7de9ef9ddbbb6275f4cd79b3c7aca773f",
    "DecomposeHandle": "96d74d0d0908f3e443f840d7d52772690a7b17bbaeeff562a7698fccaa18bf8d",
    "GetAdditionalSecret": "d9dd66a335e4817dc2d0d441abb2ac109410ef5a507a8f806fd4bffaead9200b",
    "MixAdditionalSecret": "69c1019e0889664ee10151137364ee3281ab7dd1ce984bf12a03829c5b131995",
    "HierarchyGetProof": "1735e3162dbf3d93ea53792316ec2ed1b76ff8d7c2713c2c0710c1b9076d7a4a",
}

# The verbatim-extracted vendored types, in the order the oracle needs
# them: the 2B macro first, then the command's parameter structures once
# the 2B instantiations they refer to exist.
VERBATIM_TPM2B_MACRO = (TPMB, r"^#define TPM2B_TYPE\(name, bytes\).*?\} TPM2B_##name$")
VERBATIM_HASH_STRUCTS = [
    (HASH_FP, r"^typedef struct \{[^{}]*\} Hash_In;$"),
    (HASH_FP, r"^typedef struct \{[^{}]*\} Hash_Out;$"),
]

# The verbatim-extracted vendored functions, in definition order.  Every
# definition runs from its return type at column zero to the first line
# that consists of nothing but a closing brace.
VERBATIM_FUNCTIONS = [
    (MARSHAL, r"^UINT16\nUINT16_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nUINT32_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nArray_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nTPM2B_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nTPM_HANDLE_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nTPM_ST_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nTPMI_RH_HIERARCHY_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nTPM2B_DIGEST_Marshal\(.*?^\}$"),
    (MARSHAL, r"^UINT16\nTPMT_TK_HASHCHECK_Marshal\(.*?^\}$"),
    (TICKET, r"^BOOL TicketIsSafe\(.*?^\}$"),
    (TICKET, r"^TPM_RC TicketComputeHashCheck\(.*?^\}$"),
    (SYMMETRIC_COMMANDS, r"^TPM_RC\nTPM2_Hash\(.*?^\}$"),
]

ORACLE_TEMPLATE = """\
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* ---- minimal prelude standing in for Tpm.h (LP64 little-endian) ---- */

typedef uint8_t  BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t  INT32;
typedef int      BOOL;
#define TRUE  1
#define FALSE 0
#define LIB_EXPORT

typedef UINT32 TPM_RC;
#define TPM_RC_SUCCESS ((TPM_RC)0x000)

typedef UINT16 TPM_ST;
typedef UINT16 TPM_ALG_ID;
typedef UINT16 NUMBYTES;
typedef UINT32 TPM_HANDLE;
typedef TPM_HANDLE TPMI_RH_HIERARCHY;
typedef TPM_ALG_ID TPMI_ALG_HASH;
typedef UINT32     TPM_CONSTANTS32;

typedef struct
{{
    UINT16 size;
    BYTE   buffer[1];
}} TPM2B, *P2B;
typedef const TPM2B* PC2B;

/* ---- verbatim: TPMB.h ---- */
{tpm2b_macro}
/* ---- end verbatim ---- */

TPM2B_TYPE(DIGEST, 64);       /* sizeof(TPMU_HA) for the pinned build */
TPM2B_TYPE(PROOF, 64);        /* PROOF_SIZE == CONTEXT_INTEGRITY_HASH_SIZE */
TPM2B_TYPE(MAX_BUFFER, 1024); /* MAX_DIGEST_BUFFER */

typedef struct
{{
    TPM_ST            tag;
    TPMI_RH_HIERARCHY hierarchy;
    TPM2B_DIGEST      digest;
}} TPMT_TK_HASHCHECK;

/* ---- verbatim: Hash_fp.h ---- */
{hash_structs}
/* ---- end verbatim ---- */

#define TPM_ALG_SHA1   ((TPM_ALG_ID)0x0004)
#define TPM_ALG_SHA256 ((TPM_ALG_ID)0x000b)
#define TPM_ALG_SHA384 ((TPM_ALG_ID)0x000c)
#define TPM_ALG_SHA512 ((TPM_ALG_ID)0x000d)

#define TPM_RH_OWNER       ((TPM_HANDLE)0x40000001)
#define TPM_RH_NULL        ((TPM_HANDLE)0x40000007)
#define TPM_RH_ENDORSEMENT ((TPM_HANDLE)0x4000000B)
#define TPM_RH_PLATFORM    ((TPM_HANDLE)0x4000000C)

#define TPM_ST_HASHCHECK    ((TPM_ST)0x8024)
#define TPM_GENERATED_VALUE (TPM_CONSTANTS32)(0xFF544347)
#define CONTEXT_INTEGRITY_HASH_ALG TPM_ALG_SHA512

#define MAX_DIGEST_BUFFER 1024

static void oracle_fail(const char* what)
{{
    fprintf(stderr, "oracle failure: %s\\n", what);
    exit(1);
}}
#define pAssert(x)                      \\
    do                                  \\
    {{                                   \\
        if(!(x))                        \\
            oracle_fail("assert: " #x); \\
    }} while(0)

static void MemorySet(void* dest, int value, size_t size)
{{
    memset(dest, value, size);
}}

static BOOL MemoryEqual(const void* a, const void* b, unsigned int size)
{{
    return memcmp(a, b, size) == 0 ? TRUE : FALSE;
}}

UINT16 UINT16_Marshal(UINT16* source, BYTE** buffer, INT32* size);
UINT16 UINT32_Marshal(UINT32* source, BYTE** buffer, INT32* size);

/* Marshal.c: the ticket path needs only the constant's canonical form. */
static UINT16 TPM_CONSTANTS32_Marshal(TPM_CONSTANTS32* source, BYTE** buffer, INT32* size)
{{
    return UINT32_Marshal(source, buffer, size);
}}

/* ---- CryptHash.c mirror on top of OpenSSL (see the module docstring) ---- */

typedef struct
{{
    TPM_ALG_ID  hashAlg;
    EVP_MD_CTX* ctx;
    HMAC_CTX*   hmac;
}} HASH_STATE, *PHASH_STATE;

typedef struct
{{
    HASH_STATE hashState;
}} HMAC_STATE, *PHMAC_STATE;

static const EVP_MD* md_for(TPM_ALG_ID hashAlg)
{{
    switch(hashAlg)
        {{
          case TPM_ALG_SHA1:
            return EVP_sha1();
          case TPM_ALG_SHA256:
            return EVP_sha256();
          case TPM_ALG_SHA384:
            return EVP_sha384();
          case TPM_ALG_SHA512:
            return EVP_sha512();
          default:
            oracle_fail("unsupported hash algorithm");
            return NULL;
        }}
}}

static UINT16 CryptHashStart(PHASH_STATE hashState, TPM_ALG_ID hashAlg)
{{
    const EVP_MD* md = md_for(hashAlg);

    hashState->hashAlg = hashAlg;
    hashState->hmac    = NULL;
    hashState->ctx     = EVP_MD_CTX_new();
    if(hashState->ctx == NULL || EVP_DigestInit_ex(hashState->ctx, md, NULL) != 1)
        oracle_fail("EVP_DigestInit_ex");
    return (UINT16)EVP_MD_size(md);
}}

static void CryptDigestUpdate(PHASH_STATE hashState, UINT32 dataSize, const BYTE* data)
{{
    if(hashState->hmac != NULL)
        {{
            if(HMAC_Update(hashState->hmac, data, dataSize) != 1)
                oracle_fail("HMAC_Update");
        }}
    else if(EVP_DigestUpdate(hashState->ctx, data, dataSize) != 1)
        oracle_fail("EVP_DigestUpdate");
}}

static void CryptDigestUpdate2B(PHASH_STATE state, const TPM2B* bIn)
{{
    pAssert(bIn != NULL);
    CryptDigestUpdate(state, bIn->size, bIn->buffer);
}}

static UINT16 CryptHashEnd(PHASH_STATE hashState, UINT32 dOutSize, BYTE* dOut)
{{
    BYTE     digest[EVP_MAX_MD_SIZE];
    unsigned length = 0;

    if(EVP_DigestFinal_ex(hashState->ctx, digest, &length) != 1)
        oracle_fail("EVP_DigestFinal_ex");
    EVP_MD_CTX_free(hashState->ctx);
    hashState->ctx = NULL;
    if(dOutSize > length)
        dOutSize = length;
    memcpy(dOut, digest, dOutSize);
    return (UINT16)dOutSize;
}}

static UINT16 CryptHashEnd2B(PHASH_STATE state, P2B digest)
{{
    return CryptHashEnd(state, digest->size, digest->buffer);
}}

static void CryptDigestUpdateInt(void* state, UINT32 intSize, UINT64 intValue)
{{
    BYTE   canonical[8];
    UINT32 i;

    if(intSize > sizeof(canonical))
        oracle_fail("CryptDigestUpdateInt: oversized integer");
    for(i = 0; i < sizeof(canonical); i++)
        canonical[i] = (BYTE)(intValue >> (8 * (7 - i)));
    CryptDigestUpdate((PHASH_STATE)state, intSize, &canonical[8 - intSize]);
}}

static UINT16 CryptHmacStart(PHMAC_STATE state,
                             TPM_ALG_ID  hashAlg,
                             UINT16      keySize,
                             const BYTE* key)
{{
    const EVP_MD* md = md_for(hashAlg);

    state->hashState.hashAlg = hashAlg;
    state->hashState.ctx     = NULL;
    state->hashState.hmac    = HMAC_CTX_new();
    if(state->hashState.hmac == NULL
       || HMAC_Init_ex(state->hashState.hmac, key, (int)keySize, md, NULL) != 1)
        oracle_fail("HMAC_Init_ex");
    return (UINT16)EVP_MD_size(md);
}}

static UINT16 CryptHmacStart2B(PHMAC_STATE hmacState, TPM_ALG_ID hashAlg, TPM2B* key)
{{
    return CryptHmacStart(hmacState, hashAlg, key->size, key->buffer);
}}

static UINT16 CryptHmacEnd(PHMAC_STATE state, UINT32 dOutSize, BYTE* dOut)
{{
    BYTE     mac[EVP_MAX_MD_SIZE];
    unsigned length = 0;

    if(HMAC_Final(state->hashState.hmac, mac, &length) != 1)
        oracle_fail("HMAC_Final");
    HMAC_CTX_free(state->hashState.hmac);
    state->hashState.hmac = NULL;
    if(dOutSize > length)
        dOutSize = length;
    memcpy(dOut, mac, dOutSize);
    return (UINT16)dOutSize;
}}

static UINT16 CryptHmacEnd2B(PHMAC_STATE hmacState, P2B digest)
{{
    return CryptHmacEnd(hmacState, digest->size, digest->buffer);
}}

/* ---- Hierarchy.c mirror: the plain-handle path (see the docstring) ---- */

static TPM2B_PROOF s_phProof;
static TPM2B_PROOF s_shProof;
static TPM2B_PROOF s_ehProof;
static TPM2B_PROOF s_nullProof;

static TPM_RC HierarchyGetProof(TPMI_RH_HIERARCHY hierarchy, TPM2B_PROOF* proof)
{{
    switch(hierarchy)
        {{
          case TPM_RH_PLATFORM:
            *proof = s_phProof;
            break;
          case TPM_RH_ENDORSEMENT:
            *proof = s_ehProof;
            break;
          case TPM_RH_OWNER:
            *proof = s_shProof;
            break;
          default:
            *proof = s_nullProof;
            break;
        }}
    return TPM_RC_SUCCESS;
}}

/* ---- begin verbatim extract from the vendored tree ---- */
{verbatim_functions}
/* ---- end verbatim extract ---- */

static void put_u16be(FILE* f, UINT16 value)
{{
    fputc((int)((value >> 8) & 0xff), f);
    fputc((int)(value & 0xff), f);
}}

static void put_u32be(FILE* f, UINT32 value)
{{
    put_u16be(f, (UINT16)(value >> 16));
    put_u16be(f, (UINT16)(value & 0xffff));
}}

/* The deterministic proofs the Rust test suite installs. */
static void fill_proof(TPM2B_PROOF* proof, BYTE seed)
{{
    UINT16 i;

    proof->t.size = 64;
    for(i = 0; i < proof->t.size; i++)
        proof->t.buffer[i] = (BYTE)((((i * 3) + seed) & 0xff) ^ seed);
}}

typedef struct
{{
    const char* name;
    UINT16      size;
    BYTE        buffer[MAX_DIGEST_BUFFER];
}} DATA_CASE;

static DATA_CASE s_data[16];
static int       s_dataCount;

static void add_data(const char* name, const BYTE* bytes, UINT16 size)
{{
    DATA_CASE* entry = &s_data[s_dataCount++];

    entry->name = name;
    entry->size = size;
    memcpy(entry->buffer, bytes, size);
}}

static void build_data_cases(void)
{{
    static BYTE       full[MAX_DIGEST_BUFFER];
    static const BYTE generated[]      = {{0xff, 0x54, 0x43, 0x47}};
    static const BYTE generated_tail[] = {{0xff, 0x54, 0x43, 0x47, 0x00, 0x11, 0x22, 0x33,
                                          0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}};
    static const BYTE fourth_differs[] = {{0xff, 0x54, 0x43, 0x48}};
    int               i;

    for(i = 0; i < MAX_DIGEST_BUFFER; i++)
        full[i] = (BYTE)((((i * 7) + 3) ^ 0x5a) & 0xff);

    add_data("empty", full, 0);
    add_data("abc", (const BYTE*)"abc", 3);
    add_data("max", full, MAX_DIGEST_BUFFER);
    add_data("generated", generated, 4);
    add_data("generated-tail", generated_tail, sizeof(generated_tail));
    add_data("prefix1", generated, 1);
    add_data("prefix2", generated, 2);
    add_data("prefix3", generated, 3);
    add_data("fourth-differs", fourth_differs, 4);
}}

int main(int argc, char** argv)
{{
    static const TPM_ALG_ID algs[] = {{
        TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512}};
    static const TPMI_RH_HIERARCHY hierarchies[] = {{
        TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, TPM_RH_NULL}};
    FILE*    f;
    int      data_index;
    unsigned alg_index;
    unsigned hierarchy_index;

    if(argc != 2)
        {{
            fprintf(stderr, "usage: %s <fixture>\\n", argv[0]);
            return 1;
        }}
    f = fopen(argv[1], "wb");
    if(!f)
        {{
            perror(argv[1]);
            return 1;
        }}

    fill_proof(&s_phProof, 0xb1);
    fill_proof(&s_shProof, 0xc2);
    fill_proof(&s_ehProof, 0xd3);
    memset(&s_nullProof, 0, sizeof(s_nullProof));
    s_nullProof.t.size = 64;

    build_data_cases();

    put_u16be(f, 64);
    fwrite(s_phProof.t.buffer, 1, 64, f);
    fwrite(s_shProof.t.buffer, 1, 64, f);
    fwrite(s_ehProof.t.buffer, 1, 64, f);
    put_u16be(f,
              (UINT16)(s_dataCount * (int)(sizeof(algs) / sizeof(algs[0]))
                       * (int)(sizeof(hierarchies) / sizeof(hierarchies[0]))));

    for(data_index = 0; data_index < s_dataCount; data_index++)
        for(alg_index = 0; alg_index < sizeof(algs) / sizeof(algs[0]); alg_index++)
            for(hierarchy_index = 0;
                hierarchy_index < sizeof(hierarchies) / sizeof(hierarchies[0]);
                hierarchy_index++)
                {{
                    Hash_In  in;
                    Hash_Out out;
                    BYTE     parameters[2 + 64 + 2 + 4 + 2 + 64];
                    BYTE*    cursor  = parameters;
                    INT32    room    = (INT32)sizeof(parameters);
                    UINT16   written = 0;
                    int      i;

                    memset(&in, 0, sizeof(in));
                    memset(&out, 0, sizeof(out));
                    in.data.t.size = s_data[data_index].size;
                    memcpy(in.data.t.buffer, s_data[data_index].buffer, in.data.t.size);
                    in.hashAlg   = algs[alg_index];
                    in.hierarchy = hierarchies[hierarchy_index];

                    if(TPM2_Hash(&in, &out) != TPM_RC_SUCCESS)
                        oracle_fail("TPM2_Hash");

                    written += TPM2B_DIGEST_Marshal(&out.outHash, &cursor, &room);
                    written += TPMT_TK_HASHCHECK_Marshal(&out.validation, &cursor, &room);

                    put_u16be(f, s_data[data_index].size);
                    fwrite(s_data[data_index].buffer, 1, s_data[data_index].size, f);
                    put_u16be(f, in.hashAlg);
                    put_u32be(f, in.hierarchy);
                    put_u16be(f, written);
                    fwrite(parameters, 1, written, f);

                    printf("%-15s alg %04x hierarchy %08x -> ",
                           s_data[data_index].name,
                           (unsigned)in.hashAlg,
                           (unsigned)in.hierarchy);
                    for(i = 0; i < written; i++)
                        printf("%02x", parameters[i]);
                    printf("\\n");
                }}

    if(fclose(f) != 0)
        {{
            perror(argv[1]);
            return 1;
        }}
    return 0;
}}
"""


def extract(path: Path, pattern: str) -> str:
    match = re.search(pattern, path.read_text(), re.DOTALL | re.MULTILINE)
    if not match:
        raise SystemExit(f"error: pattern {pattern!r} not found in {path}")
    return match.group(0)


def function_source(path: Path, name: str) -> str:
    """Return a vendored function definition, from its name to its closing brace.

    The definition line carries the return type and any storage class, so
    anchoring on a line-initial identifier that reaches ``name(`` without
    crossing a newline cannot match a call site.
    """
    pattern = r"^[A-Za-z_][A-Za-z0-9_ *]*\b" + re.escape(name) + r"\(.*?^\}$"
    match = re.search(pattern, path.read_text(), re.DOTALL | re.MULTILINE)
    if not match:
        raise SystemExit(f"error: {name}() not found in {path}")
    return match.group(0)


def guard_mirrored(update: bool = False) -> dict[str, str]:
    """Refuse to run when a hand-mirrored vendored function has changed."""
    digests = {}
    for path, names in MIRRORED.items():
        for name in names:
            digest = hashlib.sha256(function_source(path, name).encode()).hexdigest()
            digests[name] = digest
            if update:
                continue
            expected = MIRRORED_SHA256[name]
            if digest != expected:
                raise SystemExit(
                    f"error: {path} {name}() changed\n"
                    f"  expected sha256 {expected}\n"
                    f"  actual   sha256 {digest}\n"
                    "The oracle mirrors this function by hand, so no fixture byte\n"
                    "moves when it changes.  Re-read the new upstream source against\n"
                    "the mirror in this script, regenerate the fixture, and only then\n"
                    "update the digest above."
                )
    return digests


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
        if (Path(prefix) / "include" / "openssl" / "evp.h").is_file():
            return ([f"-I{prefix}/include"], [f"-L{prefix}/lib", "-lcrypto"])
    raise SystemExit("error: OpenSSL development files not found")


def build_fixture() -> tuple[bytes, str]:
    guard_mirrored()
    program = ORACLE_TEMPLATE.format(
        tpm2b_macro=extract(*VERBATIM_TPM2B_MACRO),
        hash_structs="\n\n".join(extract(path, pattern)
                                 for path, pattern in VERBATIM_HASH_STRUCTS),
        verbatim_functions="\n\n".join(extract(path, pattern)
                                       for path, pattern in VERBATIM_FUNCTIONS),
    )
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
    parser.add_argument(
        "--print-source-digests",
        action="store_true",
        help="print the SHA-256 of every hand-mirrored vendored function",
    )
    args = parser.parse_args()

    if args.print_source_digests:
        for name, digest in guard_mirrored(update=True).items():
            print(f'    "{name}": "{digest}",')
        return 0

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
        print("check-hash-fixture: OK")
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_bytes(fixture)
    print(f"wrote {FIXTURE} ({len(fixture)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
