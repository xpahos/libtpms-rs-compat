"""Instrument only an isolated libtpms source copy for controlled DRBG timing.

The hook and this patch recipe are both inputs to the reference cache key.
Ordinary vendored sources and ordinary libraries must never receive this patch.
"""

import re
from pathlib import Path


def _replace_once(text, old, new, description):
    if text.count(old) != 1:
        raise ValueError(f"DRBG timing patch: expected one {description}; source changed")
    return text.replace(old, new, 1)


def prepare_reference(source: Path, hook_path: Path | None = None) -> None:
    """Patch a copied libtpms source root, failing closed if anchors drift."""
    source = Path(source)
    vendor = Path(__file__).resolve().parent.parent / "libtpms"
    if source.resolve() == vendor.resolve():
        raise ValueError("DRBG timing patch requires an isolated source copy")
    hook_path = hook_path or Path(__file__).resolve().parent / "c" / "drbg_hook.c"
    hook = Path(hook_path).read_text()
    marker = "/* TPMS_TIMING_DRBG_IMPLEMENTATION */"
    if hook.count(marker) != 1:
        raise ValueError("DRBG timing hook has an invalid declaration/implementation marker")
    declarations, implementation = hook.split(marker)
    rand_path = source / "src/tpm2/crypto/openssl/CryptRand.c"
    map_path = source / "src/libtpms.syms"
    if rand_path.resolve().is_relative_to(vendor.resolve()) or map_path.resolve().is_relative_to(vendor.resolve()):
        raise ValueError("DRBG timing patch refuses links into vendored source")
    rand = rand_path.read_text()
    exports = map_path.read_text()
    if "TPMS_TIMING_DRBG_v1" in rand or "TPMS_TIMING_DRBG_v1" in exports:
        raise ValueError("DRBG timing hook already present in source copy")
    rand = _replace_once(rand, '#include "Tpm.h"', '#include "Tpm.h"\n' + declarations, "Tpm.h include")
    entropy_start = "{\n#if !USE_DEBUG_RNG\n\n    UINT32 obtainedEntropy;"
    entropy_hook = """{
    if(timing_drbg_active) {
        if(requiredEntropy != 48 || timing_drbg_draws != 0) {
            timing_drbg_failed = 1;
            return FALSE;
        }
        memcpy(entropy, timing_drbg_entropy, 48);
        timing_drbg_draws++;
        return TRUE;
    }
#if !USE_DEBUG_RNG

    UINT32 obtainedEntropy;"""
    rand = _replace_once(rand, entropy_start, entropy_hook, "DRBG entropy entry")
    profile = r"if\((RuntimeProfileRequiresAttributeFlags\(&g_RuntimeProfile,\s*// libtpms added\s*RUNTIME_ATTRIBUTE_DRBG_CONTINOUS_TEST\))\)"
    rand, count = re.subn(profile, r"if(timing_drbg_active ? timing_drbg_continuous : \1)", rand)
    if count != 1:
        raise ValueError("DRBG timing patch: expected one continuous-test profile branch; source changed")
    # Outside ExecuteCommand the normal fatal handler has no live longjmp target.
    # Keep ordinary behavior intact, but return a hook failure on a collision.
    rand = _replace_once(rand, "FAIL_BOOL(FATAL_ERROR_ENTROPY);", """if(timing_drbg_active) {
                        timing_drbg_failed = 1;
                        return FALSE;
                    }
                    FAIL_BOOL(FATAL_ERROR_ENTROPY);""", "continuous-test failure")
    rand += "\n" + implementation
    exports = _replace_once(exports, "\tTPMLIB_SetProfile;", "\tTPMLIB_SetProfile;\n\tTPMS_TIMING_DRBG_v1;", "export map entry")
    # Validate every anchor before either file is modified.
    rand_path.write_text(rand)
    map_path.write_text(exports)
