#!/usr/bin/env python3
"""Regenerate the reserved-NV layout fixture from the vendored libtpms.

Produces ``src/library/tpm2/testdata/nv_layout_lp64.txt``: one
``name<TAB>value`` line per layout fact the Rust NV-image builder
(``src/library/tpm2/nv/layout.rs``) relies on -- struct sizes, field
offsets, and the reserved NV region offsets -- as the C compiler
evaluates them for the pinned vendored configuration.

How it works
------------
A small C oracle program is compiled against the vendored TPM 2 profile
headers (the same include set the PA_COMPILE_CONSTANTS fixture uses), so
``sizeof``/``offsetof`` are evaluated exactly as the pinned upstream
build would on an LP64 little-endian host.  The oracle prints the
name/value table that becomes the fixture verbatim.

Determinism: the output depends only on the vendored sources and headers
under ``libtpms/``; no network access, no timestamps, no environment
input beyond the C compiler and the OpenSSL headers libtpms itself
builds against.

Usage:
    python3 scripts/generate_nv_layout_fixture.py
    python3 scripts/generate_nv_layout_fixture.py --check
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "src" / "library" / "tpm2" / "testdata" / "nv_layout_lp64.txt"
BACKCOMPAT = REPO_ROOT / "libtpms" / "src" / "tpm2" / "BackwardsCompatibilityObject.c"
BITARRAY = REPO_ROOT / "libtpms" / "src" / "tpm2" / "BackwardsCompatibilityBitArray.c"

# Every (fixture name, C expression) pair the Rust layout module pins.
# Keep in sync with the table in src/library/tpm2/nv/layout.rs.
ENTRIES = [
    # Reserved NV regions (Global.h) and the total image size.
    ("NV_PERSISTENT_DATA", "NV_PERSISTENT_DATA"),
    ("NV_STATE_RESET_DATA", "NV_STATE_RESET_DATA"),
    ("NV_STATE_CLEAR_DATA", "NV_STATE_CLEAR_DATA"),
    ("NV_ORDERLY_DATA", "NV_ORDERLY_DATA"),
    ("NV_INDEX_RAM_DATA", "NV_INDEX_RAM_DATA"),
    ("NV_USER_DYNAMIC", "NV_USER_DYNAMIC"),
    ("NV_USER_DYNAMIC_END", "NV_USER_DYNAMIC_END"),
    ("NV_MEMORY_SIZE", "NV_MEMORY_SIZE"),
    ("RAM_INDEX_SPACE", "RAM_INDEX_SPACE"),
    ("SIZEOF_INDEX_ORDERLY_RAM", "sizeof(s_indexOrderlyRam)"),
    # TPM2B layout invariant: 16-bit size directly followed by bytes.
    ("TPM2B_DIGEST_BUFFER", "offsetof(TPM2B_DIGEST, t.buffer)"),
    ("SIZEOF_TPM2B_DIGEST", "sizeof(TPM2B_DIGEST)"),
    ("SIZEOF_TPM2B_PROOF", "sizeof(TPM2B_PROOF)"),
    ("SIZEOF_TPM2B_SEED", "sizeof(TPM2B_SEED)"),
    # PERSISTENT_DATA (gp image at NV_PERSISTENT_DATA).
    ("SIZEOF_PERSISTENT_DATA", "sizeof(PERSISTENT_DATA)"),
    ("PD_DISABLE_CLEAR", "offsetof(PERSISTENT_DATA, disableClear)"),
    ("PD_OWNER_ALG", "offsetof(PERSISTENT_DATA, ownerAlg)"),
    ("PD_ENDORSEMENT_ALG", "offsetof(PERSISTENT_DATA, endorsementAlg)"),
    ("PD_LOCKOUT_ALG", "offsetof(PERSISTENT_DATA, lockoutAlg)"),
    ("PD_OWNER_POLICY", "offsetof(PERSISTENT_DATA, ownerPolicy)"),
    ("PD_ENDORSEMENT_POLICY", "offsetof(PERSISTENT_DATA, endorsementPolicy)"),
    ("PD_LOCKOUT_POLICY", "offsetof(PERSISTENT_DATA, lockoutPolicy)"),
    ("PD_OWNER_AUTH", "offsetof(PERSISTENT_DATA, ownerAuth)"),
    ("PD_ENDORSEMENT_AUTH", "offsetof(PERSISTENT_DATA, endorsementAuth)"),
    ("PD_LOCKOUT_AUTH", "offsetof(PERSISTENT_DATA, lockoutAuth)"),
    ("PD_EP_SEED", "offsetof(PERSISTENT_DATA, EPSeed)"),
    ("PD_SP_SEED", "offsetof(PERSISTENT_DATA, SPSeed)"),
    ("PD_PP_SEED", "offsetof(PERSISTENT_DATA, PPSeed)"),
    ("PD_EP_SEED_COMPAT_LEVEL", "offsetof(PERSISTENT_DATA, EPSeedCompatLevel)"),
    ("PD_SP_SEED_COMPAT_LEVEL", "offsetof(PERSISTENT_DATA, SPSeedCompatLevel)"),
    ("PD_PP_SEED_COMPAT_LEVEL", "offsetof(PERSISTENT_DATA, PPSeedCompatLevel)"),
    ("PD_PH_PROOF", "offsetof(PERSISTENT_DATA, phProof)"),
    ("PD_SH_PROOF", "offsetof(PERSISTENT_DATA, shProof)"),
    ("PD_EH_PROOF", "offsetof(PERSISTENT_DATA, ehProof)"),
    ("PD_TOTAL_RESET_COUNT", "offsetof(PERSISTENT_DATA, totalResetCount)"),
    ("PD_RESET_COUNT", "offsetof(PERSISTENT_DATA, resetCount)"),
    ("PD_PCR_POLICIES", "offsetof(PERSISTENT_DATA, pcrPolicies)"),
    ("PD_PCR_ALLOCATED", "offsetof(PERSISTENT_DATA, pcrAllocated)"),
    ("PD_PP_LIST", "offsetof(PERSISTENT_DATA, ppList)"),
    ("SIZEOF_PD_PP_LIST", "sizeof(((PERSISTENT_DATA *)0)->ppList)"),
    ("PD_FAILED_TRIES", "offsetof(PERSISTENT_DATA, failedTries)"),
    ("PD_MAX_TRIES", "offsetof(PERSISTENT_DATA, maxTries)"),
    ("PD_RECOVERY_TIME", "offsetof(PERSISTENT_DATA, recoveryTime)"),
    ("PD_LOCKOUT_RECOVERY", "offsetof(PERSISTENT_DATA, lockoutRecovery)"),
    ("PD_LOCKOUT_AUTH_ENABLED", "offsetof(PERSISTENT_DATA, lockOutAuthEnabled)"),
    ("PD_ORDERLY_STATE", "offsetof(PERSISTENT_DATA, orderlyState)"),
    ("PD_AUDIT_COMMANDS", "offsetof(PERSISTENT_DATA, auditCommands)"),
    ("SIZEOF_PD_AUDIT_COMMANDS", "sizeof(((PERSISTENT_DATA *)0)->auditCommands)"),
    ("PD_AUDIT_HASH_ALG", "offsetof(PERSISTENT_DATA, auditHashAlg)"),
    ("PD_AUDIT_COUNTER", "offsetof(PERSISTENT_DATA, auditCounter)"),
    ("PD_ALGORITHM_SET", "offsetof(PERSISTENT_DATA, algorithmSet)"),
    ("PD_FIRMWARE_V1", "offsetof(PERSISTENT_DATA, firmwareV1)"),
    ("PD_FIRMWARE_V2", "offsetof(PERSISTENT_DATA, firmwareV2)"),
    ("PD_TIME_EPOCH", "offsetof(PERSISTENT_DATA, timeEpoch)"),
    # PCR_POLICY / TPML_PCR_SELECTION / TPMS_PCR_SELECTION.
    ("SIZEOF_PCR_POLICY", "sizeof(PCR_POLICY)"),
    ("PCR_POLICY_HASH_ALG", "offsetof(PCR_POLICY, hashAlg)"),
    ("PCR_POLICY_POLICY", "offsetof(PCR_POLICY, policy)"),
    ("SIZEOF_TPML_PCR_SELECTION", "sizeof(TPML_PCR_SELECTION)"),
    ("TPML_PCR_SELECTION_COUNT", "offsetof(TPML_PCR_SELECTION, count)"),
    (
        "TPML_PCR_SELECTION_SELECTIONS",
        "offsetof(TPML_PCR_SELECTION, pcrSelections)",
    ),
    ("SIZEOF_TPMS_PCR_SELECTION", "sizeof(TPMS_PCR_SELECTION)"),
    ("TPMS_PCR_SELECTION_HASH", "offsetof(TPMS_PCR_SELECTION, hash)"),
    (
        "TPMS_PCR_SELECTION_SIZEOF_SELECT",
        "offsetof(TPMS_PCR_SELECTION, sizeofSelect)",
    ),
    ("TPMS_PCR_SELECTION_PCR_SELECT", "offsetof(TPMS_PCR_SELECTION, pcrSelect)"),
    (
        "SIZEOF_TPMS_PCR_SELECT_ARRAY",
        "sizeof(((TPMS_PCR_SELECTION *)0)->pcrSelect)",
    ),
    # ORDERLY_DATA (go image at NV_ORDERLY_DATA).
    ("SIZEOF_ORDERLY_DATA", "sizeof(ORDERLY_DATA)"),
    ("OD_CLOCK", "offsetof(ORDERLY_DATA, clock)"),
    ("OD_CLOCK_SAFE", "offsetof(ORDERLY_DATA, clockSafe)"),
    ("OD_DRBG_STATE", "offsetof(ORDERLY_DATA, drbgState)"),
    ("OD_SELF_HEAL_TIMER", "offsetof(ORDERLY_DATA, selfHealTimer)"),
    ("OD_LOCKOUT_TIMER", "offsetof(ORDERLY_DATA, lockoutTimer)"),
    ("OD_TIME", "offsetof(ORDERLY_DATA, time)"),
    ("SIZEOF_DRBG_STATE", "sizeof(DRBG_STATE)"),
    ("DRBG_RESEED_COUNTER", "offsetof(DRBG_STATE, reseedCounter)"),
    ("DRBG_MAGIC_FIELD", "offsetof(DRBG_STATE, magic)"),
    ("DRBG_SEED_FIELD", "offsetof(DRBG_STATE, seed)"),
    ("SIZEOF_DRBG_SEED", "sizeof(DRBG_SEED)"),
    ("DRBG_SEED_COMPAT_LEVEL", "offsetof(DRBG_STATE, seedCompatLevel)"),
    ("DRBG_LAST_VALUE", "offsetof(DRBG_STATE, lastValue)"),
    # STATE_RESET_DATA (gr image at NV_STATE_RESET_DATA).
    ("SIZEOF_STATE_RESET_DATA", "sizeof(STATE_RESET_DATA)"),
    ("SRD_NULL_PROOF", "offsetof(STATE_RESET_DATA, nullProof)"),
    ("SRD_NULL_SEED", "offsetof(STATE_RESET_DATA, nullSeed)"),
    (
        "SRD_NULL_SEED_COMPAT_LEVEL",
        "offsetof(STATE_RESET_DATA, nullSeedCompatLevel)",
    ),
    ("SRD_CLEAR_COUNT", "offsetof(STATE_RESET_DATA, clearCount)"),
    ("SRD_OBJECT_CONTEXT_ID", "offsetof(STATE_RESET_DATA, objectContextID)"),
    ("SRD_CONTEXT_ARRAY", "offsetof(STATE_RESET_DATA, contextArray)"),
    (
        "SIZEOF_SRD_CONTEXT_ARRAY",
        "sizeof(((STATE_RESET_DATA *)0)->contextArray)",
    ),
    ("SIZEOF_CONTEXT_SLOT", "sizeof(CONTEXT_SLOT)"),
    ("SRD_CONTEXT_COUNTER", "offsetof(STATE_RESET_DATA, contextCounter)"),
    (
        "SRD_COMMAND_AUDIT_DIGEST",
        "offsetof(STATE_RESET_DATA, commandAuditDigest)",
    ),
    ("SRD_RESTART_COUNT", "offsetof(STATE_RESET_DATA, restartCount)"),
    ("SRD_PCR_COUNTER", "offsetof(STATE_RESET_DATA, pcrCounter)"),
    ("SRD_COMMIT_COUNTER", "offsetof(STATE_RESET_DATA, commitCounter)"),
    ("SRD_COMMIT_NONCE", "offsetof(STATE_RESET_DATA, commitNonce)"),
    ("SRD_COMMIT_ARRAY", "offsetof(STATE_RESET_DATA, commitArray)"),
    ("SIZEOF_SRD_COMMIT_ARRAY", "sizeof(((STATE_RESET_DATA *)0)->commitArray)"),
    # STATE_CLEAR_DATA (gc image at NV_STATE_CLEAR_DATA).
    ("SIZEOF_STATE_CLEAR_DATA", "sizeof(STATE_CLEAR_DATA)"),
    ("SCD_SH_ENABLE", "offsetof(STATE_CLEAR_DATA, shEnable)"),
    ("SCD_EH_ENABLE", "offsetof(STATE_CLEAR_DATA, ehEnable)"),
    ("SCD_PH_ENABLE_NV", "offsetof(STATE_CLEAR_DATA, phEnableNV)"),
    ("SCD_PLATFORM_ALG", "offsetof(STATE_CLEAR_DATA, platformAlg)"),
    ("SCD_PLATFORM_POLICY", "offsetof(STATE_CLEAR_DATA, platformPolicy)"),
    ("SCD_PLATFORM_AUTH", "offsetof(STATE_CLEAR_DATA, platformAuth)"),
    ("SCD_PCR_SAVE", "offsetof(STATE_CLEAR_DATA, pcrSave)"),
    ("SCD_PCR_AUTH_VALUES", "offsetof(STATE_CLEAR_DATA, pcrAuthValues)"),
    ("SIZEOF_PCR_SAVE", "sizeof(PCR_SAVE)"),
    ("PCR_SAVE_SHA1", "offsetof(PCR_SAVE, Sha1)"),
    ("PCR_SAVE_SHA256", "offsetof(PCR_SAVE, Sha256)"),
    ("PCR_SAVE_SHA384", "offsetof(PCR_SAVE, Sha384)"),
    ("PCR_SAVE_SHA512", "offsetof(PCR_SAVE, Sha512)"),
    ("PCR_SAVE_PCR_COUNTER", "offsetof(PCR_SAVE, pcrCounter)"),
    ("SIZEOF_PCR_AUTHVALUE", "sizeof(PCR_AUTHVALUE)"),
    ("PCR_AUTHVALUE_AUTH", "offsetof(PCR_AUTHVALUE, auth)"),
    # NV_INDEX / TPMS_NV_PUBLIC (USER_NVRAM index images).
    ("SIZEOF_NV_INDEX", "sizeof(NV_INDEX)"),
    ("NV_INDEX_PUBLIC_AREA", "offsetof(NV_INDEX, publicArea)"),
    ("NV_INDEX_AUTH_VALUE", "offsetof(NV_INDEX, authValue)"),
    ("SIZEOF_TPMS_NV_PUBLIC", "sizeof(TPMS_NV_PUBLIC)"),
    ("NV_PUBLIC_NV_INDEX", "offsetof(TPMS_NV_PUBLIC, nvIndex)"),
    ("NV_PUBLIC_NAME_ALG", "offsetof(TPMS_NV_PUBLIC, nameAlg)"),
    ("NV_PUBLIC_ATTRIBUTES", "offsetof(TPMS_NV_PUBLIC, attributes)"),
    ("NV_PUBLIC_AUTH_POLICY", "offsetof(TPMS_NV_PUBLIC, authPolicy)"),
    ("NV_PUBLIC_DATA_SIZE", "offsetof(TPMS_NV_PUBLIC, dataSize)"),
    # Dynamic-area entry framing (NV.h).
    ("SIZEOF_NV_ENTRY_HEADER", "sizeof(NV_ENTRY_HEADER)"),
    ("SIZEOF_NV_RAM_HEADER", "sizeof(NV_RAM_HEADER)"),
    ("NV_RAM_HEADER_SIZE_FIELD", "offsetof(NV_RAM_HEADER, size)"),
    ("NV_RAM_HEADER_HANDLE", "offsetof(NV_RAM_HEADER, handle)"),
    ("NV_RAM_HEADER_ATTRIBUTES", "offsetof(NV_RAM_HEADER, attributes)"),
    ("SIZEOF_NV_LIST_TERMINATOR", "sizeof(NV_LIST_TERMINATOR)"),
    # TPMU_PUBLIC_PARMS members (native images inside RSA3072_OBJECT).
    ("SIZEOF_TPMU_PUBLIC_PARMS", "sizeof(TPMU_PUBLIC_PARMS)"),
    ("SIZEOF_TPMT_SYM_DEF_OBJECT", "sizeof(TPMT_SYM_DEF_OBJECT)"),
    ("SYM_DEF_ALGORITHM", "offsetof(TPMT_SYM_DEF_OBJECT, algorithm)"),
    ("SYM_DEF_KEY_BITS", "offsetof(TPMT_SYM_DEF_OBJECT, keyBits)"),
    ("SYM_DEF_MODE", "offsetof(TPMT_SYM_DEF_OBJECT, mode)"),
    ("SIZEOF_TPMT_KEYEDHASH_SCHEME", "sizeof(TPMT_KEYEDHASH_SCHEME)"),
    ("KEYEDHASH_SCHEME_SCHEME", "offsetof(TPMT_KEYEDHASH_SCHEME, scheme)"),
    ("KEYEDHASH_SCHEME_DETAILS", "offsetof(TPMT_KEYEDHASH_SCHEME, details)"),
    ("SCHEME_XOR_HASH_ALG", "offsetof(TPMS_SCHEME_XOR, hashAlg)"),
    ("SCHEME_XOR_KDF", "offsetof(TPMS_SCHEME_XOR, kdf)"),
    ("SCHEME_ECDAA_HASH_ALG", "offsetof(TPMS_SCHEME_ECDAA, hashAlg)"),
    ("SCHEME_ECDAA_COUNT", "offsetof(TPMS_SCHEME_ECDAA, count)"),
    ("SIZEOF_TPMT_RSA_SCHEME", "sizeof(TPMT_RSA_SCHEME)"),
    ("RSA_SCHEME_SCHEME", "offsetof(TPMT_RSA_SCHEME, scheme)"),
    ("RSA_SCHEME_DETAILS", "offsetof(TPMT_RSA_SCHEME, details)"),
    ("SIZEOF_TPMT_ECC_SCHEME", "sizeof(TPMT_ECC_SCHEME)"),
    ("ECC_SCHEME_SCHEME", "offsetof(TPMT_ECC_SCHEME, scheme)"),
    ("ECC_SCHEME_DETAILS", "offsetof(TPMT_ECC_SCHEME, details)"),
    ("SIZEOF_TPMT_KDF_SCHEME", "sizeof(TPMT_KDF_SCHEME)"),
    ("KDF_SCHEME_SCHEME", "offsetof(TPMT_KDF_SCHEME, scheme)"),
    ("KDF_SCHEME_DETAILS", "offsetof(TPMT_KDF_SCHEME, details)"),
    ("PARMS_KEYEDHASH_SCHEME", "offsetof(TPMU_PUBLIC_PARMS, keyedHashDetail.scheme)"),
    ("PARMS_SYM_SYM", "offsetof(TPMU_PUBLIC_PARMS, symDetail.sym)"),
    ("PARMS_RSA_SYMMETRIC", "offsetof(TPMU_PUBLIC_PARMS, rsaDetail.symmetric)"),
    ("PARMS_RSA_SCHEME", "offsetof(TPMU_PUBLIC_PARMS, rsaDetail.scheme)"),
    ("PARMS_RSA_KEY_BITS", "offsetof(TPMU_PUBLIC_PARMS, rsaDetail.keyBits)"),
    ("PARMS_RSA_EXPONENT", "offsetof(TPMU_PUBLIC_PARMS, rsaDetail.exponent)"),
    ("PARMS_ECC_SYMMETRIC", "offsetof(TPMU_PUBLIC_PARMS, eccDetail.symmetric)"),
    ("PARMS_ECC_SCHEME", "offsetof(TPMU_PUBLIC_PARMS, eccDetail.scheme)"),
    ("PARMS_ECC_CURVE_ID", "offsetof(TPMU_PUBLIC_PARMS, eccDetail.curveID)"),
    ("PARMS_ECC_KDF", "offsetof(TPMU_PUBLIC_PARMS, eccDetail.kdf)"),
    # TPM2B_NAME / TPMS_ECC_POINT / TPM2B_ECC_PARAMETER.
    ("SIZEOF_TPM2B_NAME", "sizeof(TPM2B_NAME)"),
    ("SIZEOF_TPM2B_ECC_PARAMETER", "sizeof(TPM2B_ECC_PARAMETER)"),
    ("SIZEOF_TPMS_ECC_POINT", "sizeof(TPMS_ECC_POINT)"),
    ("ECC_POINT_X", "offsetof(TPMS_ECC_POINT, x)"),
    ("ECC_POINT_Y", "offsetof(TPMS_ECC_POINT, y)"),
    # The current native OBJECT (for the capacity constants only).
    ("SIZEOF_OBJECT", "sizeof(OBJECT)"),
    ("OBJECT_HIERARCHY", "offsetof(OBJECT, hierarchy)"),
    ("SIZEOF_HASH_OBJECT", "sizeof(HASH_OBJECT)"),
    ("HASH_OBJECT_STATE", "offsetof(HASH_OBJECT, state)"),
    ("SIZEOF_SESSION", "sizeof(SESSION)"),
    ("SESSION_ATTRIBUTES", "offsetof(SESSION, attributes)"),
    ("SIZEOF_SESSION_ATTRIBUTES", "sizeof(SESSION_ATTRIBUTES)"),
    ("SESSION_PCR_COUNTER", "offsetof(SESSION, pcrCounter)"),
    ("SESSION_START_TIME", "offsetof(SESSION, startTime)"),
    ("SESSION_TIMEOUT", "offsetof(SESSION, timeout)"),
    ("SESSION_EPOCH", "offsetof(SESSION, epoch)"),
    ("SIZEOF_SESSION_EPOCH", "sizeof(((SESSION *)0)->epoch)"),
    ("SESSION_COMMAND_CODE", "offsetof(SESSION, commandCode)"),
    ("SESSION_AUTH_HASH_ALG", "offsetof(SESSION, authHashAlg)"),
    ("SESSION_COMMAND_LOCALITY", "offsetof(SESSION, commandLocality)"),
    ("SESSION_SYMMETRIC", "offsetof(SESSION, symmetric)"),
    ("SIZEOF_TPMT_SYM_DEF", "sizeof(TPMT_SYM_DEF)"),
    ("SESSION_SESSION_KEY", "offsetof(SESSION, sessionKey)"),
    ("SESSION_NONCE_TPM", "offsetof(SESSION, nonceTPM)"),
    ("SESSION_BOUND_ENTITY", "offsetof(SESSION, u1.boundEntity)"),
    ("SIZEOF_SESSION_U1", "sizeof(((SESSION *)0)->u1)"),
    ("SESSION_AUDIT_DIGEST", "offsetof(SESSION, u2.auditDigest)"),
    ("SIZEOF_SESSION_U2", "sizeof(((SESSION *)0)->u2)"),
    ("CONTEXT_INTEGRITY_HASH_ALG", "CONTEXT_INTEGRITY_HASH_ALG"),
    ("CONTEXT_INTEGRITY_HASH_SIZE", "CONTEXT_INTEGRITY_HASH_SIZE"),
    ("CONTEXT_ENCRYPT_ALG", "CONTEXT_ENCRYPT_ALG"),
    ("CONTEXT_ENCRYPT_KEY_BITS", "CONTEXT_ENCRYPT_KEY_BITS"),
    ("SIZEOF_PRIVATE", "sizeof(_PRIVATE)"),
    ("SIZEOF_TPM2B_SENSITIVE", "sizeof(TPM2B_SENSITIVE)"),
    # RSA3072_OBJECT: the legacy persistent-object NV image
    # (stateFormatLevel < 2), types extracted verbatim from
    # BackwardsCompatibilityObject.c.
    ("SIZEOF_RSA3072_OBJECT", "sizeof(RSA3072_OBJECT)"),
    ("R3K_ATTRIBUTES", "offsetof(RSA3072_OBJECT, attributes)"),
    ("R3K_PUBLIC_AREA", "offsetof(RSA3072_OBJECT, publicArea)"),
    ("R3K_SENSITIVE", "offsetof(RSA3072_OBJECT, sensitive)"),
    ("R3K_PRIVATE_EXPONENT", "offsetof(RSA3072_OBJECT, privateExponent)"),
    ("R3K_QUALIFIED_NAME", "offsetof(RSA3072_OBJECT, qualifiedName)"),
    ("R3K_EVICT_HANDLE", "offsetof(RSA3072_OBJECT, evictHandle)"),
    ("R3K_NAME", "offsetof(RSA3072_OBJECT, name)"),
    ("R3K_SEED_COMPAT_LEVEL", "offsetof(RSA3072_OBJECT, seedCompatLevel)"),
    ("SIZEOF_R3K_PUBLIC", "sizeof(RSA3072_TPMT_PUBLIC)"),
    ("R3K_PUBLIC_TYPE", "offsetof(RSA3072_TPMT_PUBLIC, type)"),
    ("R3K_PUBLIC_NAME_ALG", "offsetof(RSA3072_TPMT_PUBLIC, nameAlg)"),
    (
        "R3K_PUBLIC_OBJECT_ATTRIBUTES",
        "offsetof(RSA3072_TPMT_PUBLIC, objectAttributes)",
    ),
    ("R3K_PUBLIC_AUTH_POLICY", "offsetof(RSA3072_TPMT_PUBLIC, authPolicy)"),
    ("R3K_PUBLIC_PARAMETERS", "offsetof(RSA3072_TPMT_PUBLIC, parameters)"),
    ("R3K_PUBLIC_UNIQUE", "offsetof(RSA3072_TPMT_PUBLIC, unique)"),
    ("SIZEOF_R3K_PUBLIC_ID", "sizeof(RSA3072_TPMU_PUBLIC_ID)"),
    ("SIZEOF_R3K_PUBLIC_KEY_RSA", "sizeof(RSA3072_TPM2B_PUBLIC_KEY_RSA)"),
    ("SIZEOF_R3K_SENSITIVE_STRUCT", "sizeof(RSA3072_TPMT_SENSITIVE)"),
    ("R3K_SENSITIVE_TYPE", "offsetof(RSA3072_TPMT_SENSITIVE, sensitiveType)"),
    ("R3K_SENSITIVE_AUTH_VALUE", "offsetof(RSA3072_TPMT_SENSITIVE, authValue)"),
    ("R3K_SENSITIVE_SEED_VALUE", "offsetof(RSA3072_TPMT_SENSITIVE, seedValue)"),
    ("R3K_SENSITIVE_SENSITIVE", "offsetof(RSA3072_TPMT_SENSITIVE, sensitive)"),
    (
        "SIZEOF_R3K_SENSITIVE_COMPOSITE",
        "sizeof(RSA3072_TPMU_SENSITIVE_COMPOSITE)",
    ),
    ("SIZEOF_R3K_PRIVATE_EXPONENT", "sizeof(RSA3072_privateExponent_t)"),
    ("SIZEOF_BN_RSA3072_PRIME", "sizeof(bn_rsa3072_prime_t)"),
    ("BN_PRIME_ALLOCATED", "offsetof(bn_rsa3072_prime_t, allocated)"),
    ("BN_PRIME_SIZE", "offsetof(bn_rsa3072_prime_t, size)"),
    ("BN_PRIME_D", "offsetof(bn_rsa3072_prime_t, d)"),
    ("SIZEOF_BN_PRIME_D", "sizeof(((bn_rsa3072_prime_t *)0)->d)"),
    # The image is a native little-endian LP64 memory dump.
    ("NATIVE_LITTLE_ENDIAN", "__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__"),
]

ORACLE_TEMPLATE = """\
#include <stdio.h>
#include <stddef.h>
#include "Tpm.h"
#include "NV.h"

/* The EXTERN globals are only declared for NV_C/GLOBAL_C translation
 * units; sizeof(s_indexOrderlyRam) needs the declaration. */
extern BYTE s_indexOrderlyRam[RAM_INDEX_SPACE];

/* ---- begin verbatim extract from BackwardsCompatibilityObject.c ---- */
{rsa3072_types}
/* ---- end verbatim extract from BackwardsCompatibilityObject.c ---- */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* ---- begin verbatim extract from BackwardsCompatibilityBitArray.c ---- */
{cc_table}
/* ---- end verbatim extract from BackwardsCompatibilityBitArray.c ---- */

int main(int argc, char **argv)
{{
    FILE *f;

    if (argc != 2) {{
        fprintf(stderr, "usage: %s <fixture-path>\\n", argv[0]);
        return 1;
    }}
    f = fopen(argv[1], "w");
    if (!f) {{
        perror(argv[1]);
        return 1;
    }}

{lines}

    /* The v0.9 compressed-list bit mapping: compressed bit index ->
     * this build's command bit index (cc - TPM_CC_NV_UndefineSpaceSpecial),
     * consumed by the Rust ConvertFromCompressedBitArray equivalent. */
    {{
        size_t i;
        for (i = 0; i < ARRAY_SIZE(CCToCompressedListIndex); i++)
            fprintf(f, "CC_COMPRESSED_%zu\\t%lu\\n", i,
                    (unsigned long)(CCToCompressedListIndex[i].cc -
                                    TPM_CC_NV_UndefineSpaceSpecial));
    }}

    if (fclose(f) != 0) {{
        perror(argv[1]);
        return 1;
    }}
    return 0;
}}
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


def extract_rsa3072_types(source: str) -> str:
    """Extract the RSA3072_* type definitions verbatim.

    The captured block spans from the RSA3072_TPM2B_PUBLIC_KEY_RSA union
    (the first RSA3072 type) through the RSA3072_OBJECT size assertion,
    including the BN_TYPE(rsa3072_prime, ...) invocation.
    """
    match = re.search(
        r"typedef union \{[^{}]*\{[^{}]*\}\s*t;[^{}]*\} RSA3072_TPM2B_PUBLIC_KEY_RSA;"
        r".*?MUST_BE\(sizeof\(RSA3072_OBJECT\) == 2600\);",
        source,
        re.DOTALL,
    )
    if not match:
        raise SystemExit(f"error: RSA3072_OBJECT types not found in {BACKCOMPAT}")
    return match.group(0)


def extract_cc_table(source: str) -> str:
    """Extract the CCToCompressedListIndex table verbatim."""
    match = re.search(
        r"static const struct \{\s*TPM_CC cc;.*?\} CCToCompressedListIndex\[\] = \{"
        r".*?^\};",
        source,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        raise SystemExit(f"error: CCToCompressedListIndex not found in {BITARRAY}")
    return match.group(0)


def build_fixture() -> str:
    lines = "\n".join(
        f'    fprintf(f, "{name}\\t%lu\\n", (unsigned long)({expr}));'
        for name, expr in ENTRIES
    )
    program = ORACLE_TEMPLATE.format(
        lines=lines,
        rsa3072_types=extract_rsa3072_types(BACKCOMPAT.read_text()),
        cc_table=extract_cc_table(BITARRAY.read_text()),
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
        fixture_out = tmpdir / "fixture.txt"
        oracle_c.write_text(program)
        # Same feature macros the upstream tpm2 build passes (Makefile.am).
        subprocess.run(
            ["cc", "-DTPM_POSIX", "-D_POSIX_", *include_flags,
             str(oracle_c), "-o", str(oracle_bin)],
            check=True,
        )
        subprocess.run([str(oracle_bin), str(fixture_out)], check=True)
        return fixture_out.read_text()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in fixture instead of rewriting it",
    )
    args = parser.parse_args()

    fixture = build_fixture()

    if args.check:
        current = FIXTURE.read_text() if FIXTURE.is_file() else None
        if current != fixture:
            print(f"error: {FIXTURE} is stale; rerun {Path(__file__).name}",
                  file=sys.stderr)
            return 1
        print(f"{FIXTURE}: OK ({len(fixture.splitlines())} entries)")
        return 0

    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(fixture)
    print(f"wrote {FIXTURE} ({len(fixture.splitlines())} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
