#[cfg(not(target_endian = "little"))]
compile_error!(
    "the pinned native NV layout (nv_layout.rs) describes a little-endian \
     libtpms build; regenerate and validate a dedicated layout before \
     enabling a big-endian target"
);
#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "the pinned native NV layout (nv_layout.rs) describes an LP64 libtpms \
     build; regenerate and validate a dedicated layout before enabling a \
     non-64-bit target"
);
const _: () = {
    assert!(
        core::mem::size_of::<core::ffi::c_int>() == 4,
        "the pinned NV layout requires a 4-byte C int"
    );
    assert!(
        core::mem::size_of::<core::ffi::c_long>() == 8,
        "the pinned NV layout requires an 8-byte C long (LP64)"
    );
    assert!(
        core::mem::align_of::<u64>() == 8,
        "the pinned NV layout requires 8-byte alignment for 64-bit fields"
    );
};

macro_rules! layout {
    ($(($name:ident, $value:expr),)+) => {
        $(#[allow(dead_code)] pub(in crate::library::tpm2) const $name: usize = $value;)+
        #[cfg(test)]
        const ALL: &[(&str, usize)] = &[$((stringify!($name), $name)),+];
    };
}

layout! {
    (NV_PERSISTENT_DATA, 0),
    (NV_STATE_RESET_DATA, 1072),
    (NV_STATE_CLEAR_DATA, 1536),
    (NV_ORDERLY_DATA, 4380),
    (NV_INDEX_RAM_DATA, 5120),
    (NV_USER_DYNAMIC, 5632),
    (NV_USER_DYNAMIC_END, 176_832),
    (NV_MEMORY_SIZE, 176_832),
    (RAM_INDEX_SPACE, 512),
    (SIZEOF_INDEX_ORDERLY_RAM, 512),
    (TPM2B_DIGEST_BUFFER, 2),
    (SIZEOF_TPM2B_DIGEST, 66),
    (SIZEOF_TPM2B_PROOF, 66),
    (SIZEOF_TPM2B_SEED, 66),
    (SIZEOF_PERSISTENT_DATA, 1072),
    (PD_DISABLE_CLEAR, 0),
    (PD_OWNER_ALG, 4),
    (PD_ENDORSEMENT_ALG, 6),
    (PD_LOCKOUT_ALG, 8),
    (PD_OWNER_POLICY, 10),
    (PD_ENDORSEMENT_POLICY, 76),
    (PD_LOCKOUT_POLICY, 142),
    (PD_OWNER_AUTH, 208),
    (PD_ENDORSEMENT_AUTH, 274),
    (PD_LOCKOUT_AUTH, 340),
    (PD_EP_SEED, 406),
    (PD_SP_SEED, 472),
    (PD_PP_SEED, 538),
    (PD_EP_SEED_COMPAT_LEVEL, 604),
    (PD_SP_SEED_COMPAT_LEVEL, 605),
    (PD_PP_SEED_COMPAT_LEVEL, 606),
    (PD_PH_PROOF, 608),
    (PD_SH_PROOF, 674),
    (PD_EH_PROOF, 740),
    (PD_TOTAL_RESET_COUNT, 808),
    (PD_RESET_COUNT, 816),
    (PD_PCR_POLICIES, 820),
    (PD_PCR_ALLOCATED, 956),
    (PD_PP_LIST, 984),
    (SIZEOF_PD_PP_LIST, 17),
    (PD_FAILED_TRIES, 1004),
    (PD_MAX_TRIES, 1008),
    (PD_RECOVERY_TIME, 1012),
    (PD_LOCKOUT_RECOVERY, 1016),
    (PD_LOCKOUT_AUTH_ENABLED, 1020),
    (PD_ORDERLY_STATE, 1024),
    (PD_AUDIT_COMMANDS, 1026),
    (SIZEOF_PD_AUDIT_COMMANDS, 17),
    (PD_AUDIT_HASH_ALG, 1044),
    (PD_AUDIT_COUNTER, 1048),
    (PD_ALGORITHM_SET, 1056),
    (PD_FIRMWARE_V1, 1060),
    (PD_FIRMWARE_V2, 1064),
    (PD_TIME_EPOCH, 1068),
    (SIZEOF_PCR_POLICY, 134),
    (PCR_POLICY_HASH_ALG, 0),
    (PCR_POLICY_POLICY, 68),
    (SIZEOF_TPML_PCR_SELECTION, 28),
    (TPML_PCR_SELECTION_COUNT, 0),
    (TPML_PCR_SELECTION_SELECTIONS, 4),
    (SIZEOF_TPMS_PCR_SELECTION, 6),
    (TPMS_PCR_SELECTION_HASH, 0),
    (TPMS_PCR_SELECTION_SIZEOF_SELECT, 2),
    (TPMS_PCR_SELECTION_PCR_SELECT, 3),
    (SIZEOF_TPMS_PCR_SELECT_ARRAY, 3),
    (SIZEOF_ORDERLY_DATA, 128),
    (OD_CLOCK, 0),
    (OD_CLOCK_SAFE, 8),
    (OD_DRBG_STATE, 16),
    (OD_SELF_HEAL_TIMER, 104),
    (OD_LOCKOUT_TIMER, 112),
    (OD_TIME, 120),
    (SIZEOF_DRBG_STATE, 88),
    (DRBG_RESEED_COUNTER, 0),
    (DRBG_MAGIC_FIELD, 8),
    (DRBG_SEED_FIELD, 16),
    (SIZEOF_DRBG_SEED, 48),
    (DRBG_SEED_COMPAT_LEVEL, 64),
    (DRBG_LAST_VALUE, 68),
    (SIZEOF_STATE_RESET_DATA, 464),
    (SRD_NULL_PROOF, 0),
    (SRD_NULL_SEED, 66),
    (SRD_NULL_SEED_COMPAT_LEVEL, 132),
    (SRD_CLEAR_COUNT, 136),
    (SRD_OBJECT_CONTEXT_ID, 144),
    (SRD_CONTEXT_ARRAY, 152),
    (SIZEOF_SRD_CONTEXT_ARRAY, 128),
    (SIZEOF_CONTEXT_SLOT, 2),
    (SRD_CONTEXT_COUNTER, 280),
    (SRD_COMMAND_AUDIT_DIGEST, 288),
    (SRD_RESTART_COUNT, 356),
    (SRD_PCR_COUNTER, 360),
    (SRD_COMMIT_COUNTER, 368),
    (SRD_COMMIT_NONCE, 376),
    (SRD_COMMIT_ARRAY, 442),
    (SIZEOF_SRD_COMMIT_ARRAY, 16),
    (SIZEOF_STATE_CLEAR_DATA, 2844),
    (SCD_SH_ENABLE, 0),
    (SCD_EH_ENABLE, 4),
    (SCD_PH_ENABLE_NV, 8),
    (SCD_PLATFORM_ALG, 12),
    (SCD_PLATFORM_POLICY, 14),
    (SCD_PLATFORM_AUTH, 80),
    (SCD_PCR_SAVE, 148),
    (SCD_PCR_AUTH_VALUES, 2776),
    (SIZEOF_PCR_SAVE, 2628),
    (PCR_SAVE_SHA1, 0),
    (PCR_SAVE_SHA256, 320),
    (PCR_SAVE_SHA384, 832),
    (PCR_SAVE_SHA512, 1600),
    (PCR_SAVE_PCR_COUNTER, 2624),
    (SIZEOF_PCR_AUTHVALUE, 66),
    (PCR_AUTHVALUE_AUTH, 0),
    (SIZEOF_NV_INDEX, 148),
    (NV_INDEX_PUBLIC_AREA, 0),
    (NV_INDEX_AUTH_VALUE, 80),
    (SIZEOF_TPMS_NV_PUBLIC, 80),
    (NV_PUBLIC_NV_INDEX, 0),
    (NV_PUBLIC_NAME_ALG, 4),
    (NV_PUBLIC_ATTRIBUTES, 8),
    (NV_PUBLIC_AUTH_POLICY, 12),
    (NV_PUBLIC_DATA_SIZE, 78),
    (SIZEOF_NV_ENTRY_HEADER, 8),
    (SIZEOF_NV_RAM_HEADER, 12),
    (NV_RAM_HEADER_SIZE_FIELD, 0),
    (NV_RAM_HEADER_HANDLE, 4),
    (NV_RAM_HEADER_ATTRIBUTES, 8),
    (SIZEOF_NV_LIST_TERMINATOR, 12),
    (SIZEOF_TPMU_PUBLIC_PARMS, 20),
    (SIZEOF_TPMT_SYM_DEF_OBJECT, 6),
    (SYM_DEF_ALGORITHM, 0),
    (SYM_DEF_KEY_BITS, 2),
    (SYM_DEF_MODE, 4),
    (SIZEOF_TPMT_KEYEDHASH_SCHEME, 6),
    (KEYEDHASH_SCHEME_SCHEME, 0),
    (KEYEDHASH_SCHEME_DETAILS, 2),
    (SCHEME_XOR_HASH_ALG, 0),
    (SCHEME_XOR_KDF, 2),
    (SCHEME_ECDAA_HASH_ALG, 0),
    (SCHEME_ECDAA_COUNT, 2),
    (SIZEOF_TPMT_RSA_SCHEME, 6),
    (RSA_SCHEME_SCHEME, 0),
    (RSA_SCHEME_DETAILS, 2),
    (SIZEOF_TPMT_ECC_SCHEME, 6),
    (ECC_SCHEME_SCHEME, 0),
    (ECC_SCHEME_DETAILS, 2),
    (SIZEOF_TPMT_KDF_SCHEME, 4),
    (KDF_SCHEME_SCHEME, 0),
    (KDF_SCHEME_DETAILS, 2),
    (PARMS_KEYEDHASH_SCHEME, 0),
    (PARMS_SYM_SYM, 0),
    (PARMS_RSA_SYMMETRIC, 0),
    (PARMS_RSA_SCHEME, 6),
    (PARMS_RSA_KEY_BITS, 12),
    (PARMS_RSA_EXPONENT, 16),
    (PARMS_ECC_SYMMETRIC, 0),
    (PARMS_ECC_SCHEME, 6),
    (PARMS_ECC_CURVE_ID, 12),
    (PARMS_ECC_KDF, 14),
    (SIZEOF_TPM2B_NAME, 70),
    (SIZEOF_TPM2B_ECC_PARAMETER, 82),
    (SIZEOF_TPMS_ECC_POINT, 164),
    (ECC_POINT_X, 0),
    (ECC_POINT_Y, 82),
    (SIZEOF_OBJECT, 2608),
    (SIZEOF_RSA3072_OBJECT, 2600),
    (R3K_ATTRIBUTES, 0),
    (R3K_PUBLIC_AREA, 4),
    (R3K_SENSITIVE, 488),
    (R3K_PRIVATE_EXPONENT, 1584),
    (R3K_QUALIFIED_NAME, 2448),
    (R3K_EVICT_HANDLE, 2520),
    (R3K_NAME, 2524),
    (R3K_SEED_COMPAT_LEVEL, 2594),
    (SIZEOF_R3K_PUBLIC, 484),
    (R3K_PUBLIC_TYPE, 0),
    (R3K_PUBLIC_NAME_ALG, 2),
    (R3K_PUBLIC_OBJECT_ATTRIBUTES, 4),
    (R3K_PUBLIC_AUTH_POLICY, 8),
    (R3K_PUBLIC_PARAMETERS, 76),
    (R3K_PUBLIC_UNIQUE, 96),
    (SIZEOF_R3K_PUBLIC_ID, 386),
    (SIZEOF_R3K_PUBLIC_KEY_RSA, 386),
    (SIZEOF_R3K_SENSITIVE_STRUCT, 1096),
    (R3K_SENSITIVE_TYPE, 0),
    (R3K_SENSITIVE_AUTH_VALUE, 2),
    (R3K_SENSITIVE_SEED_VALUE, 68),
    (R3K_SENSITIVE_SENSITIVE, 134),
    (SIZEOF_R3K_SENSITIVE_COMPOSITE, 962),
    (SIZEOF_R3K_PRIVATE_EXPONENT, 864),
    (SIZEOF_BN_RSA3072_PRIME, 216),
    (BN_PRIME_ALLOCATED, 0),
    (BN_PRIME_SIZE, 8),
    (BN_PRIME_D, 16),
    (SIZEOF_BN_PRIME_D, 200),
    (NATIVE_LITTLE_ENDIAN, 1),
}

pub(in crate::library::tpm2) const COMPRESSED_COMMAND_BITS: [u16; 110] = [
    0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
    53, 54, 55, 56, 57, 58, 60, 61, 62, 63, 65, 66, 67, 68, 69, 70, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 87, 88, 89, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103,
    104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 120,
];

const _: () = {
    assert!(NV_PERSISTENT_DATA + SIZEOF_PERSISTENT_DATA <= NV_STATE_RESET_DATA);
    assert!(NV_STATE_RESET_DATA + SIZEOF_STATE_RESET_DATA <= NV_STATE_CLEAR_DATA);
    assert!(NV_STATE_CLEAR_DATA + SIZEOF_STATE_CLEAR_DATA <= NV_ORDERLY_DATA);
    assert!(NV_ORDERLY_DATA + SIZEOF_ORDERLY_DATA <= NV_INDEX_RAM_DATA);
    assert!(NV_INDEX_RAM_DATA + SIZEOF_INDEX_ORDERLY_RAM <= NV_USER_DYNAMIC);
    assert!(NV_USER_DYNAMIC < NV_USER_DYNAMIC_END);
    assert!(NV_USER_DYNAMIC_END == NV_MEMORY_SIZE);
    assert!(NV_USER_DYNAMIC + super::user::USER_NVRAM_CAPACITY as usize == NV_USER_DYNAMIC_END);
    assert!(super::user::SIZEOF_NV_INDEX as usize == SIZEOF_NV_INDEX);
    assert!(super::user::SIZEOF_OBJECT as usize == SIZEOF_OBJECT);
    assert!(super::user::SIZEOF_RSA3072_OBJECT as usize == SIZEOF_RSA3072_OBJECT);
    assert!(super::orderly_ram::RAM_INDEX_SPACE as usize == RAM_INDEX_SPACE);
    assert!(super::orderly_ram::NV_RAM_HEADER_SIZE as usize == SIZEOF_NV_RAM_HEADER);
    assert!(crate::library::tpm2::runtime::NV_MEMORY_SIZE == NV_MEMORY_SIZE);
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const FIXTURE: &str = include_str!("../testdata/nv_layout_lp64.txt");

    fn fixture_entries() -> HashMap<&'static str, usize> {
        FIXTURE
            .lines()
            .map(|line| {
                let (name, value) = line.split_once('\t').expect("name<TAB>value");
                (name, value.parse::<usize>().expect("decimal value"))
            })
            .collect()
    }

    #[test]
    fn pinned_layout_requires_a_little_endian_lp64_target() {
        const {
            assert!(cfg!(target_endian = "little"));
            assert!(cfg!(target_pointer_width = "64"));
        }
        assert_eq!(core::mem::size_of::<core::ffi::c_int>(), 4);
        assert_eq!(core::mem::size_of::<core::ffi::c_long>(), 8);
        assert_eq!(core::mem::align_of::<u64>(), 8);
        assert_eq!(NATIVE_LITTLE_ENDIAN, 1);
    }

    #[test]
    fn every_constant_matches_the_compiled_oracle() {
        let fixture = fixture_entries();
        for &(name, value) in ALL {
            assert_eq!(
                fixture.get(name).copied(),
                Some(value),
                "layout constant {name}"
            );
        }
    }

    #[test]
    fn every_fixture_entry_is_pinned() {
        let fixture = fixture_entries();
        let known: std::collections::HashSet<&str> = ALL.iter().map(|&(name, _)| name).collect();
        for name in fixture.keys() {
            if let Some(rest) = name.strip_prefix("CC_COMPRESSED_") {
                let index: usize = rest.parse().unwrap();
                assert_eq!(
                    fixture[name],
                    usize::from(COMPRESSED_COMMAND_BITS[index]),
                    "compressed mapping {index}"
                );
                continue;
            }
            assert!(known.contains(name), "unpinned fixture entry {name}");
        }
        assert_eq!(
            fixture.len(),
            ALL.len() + COMPRESSED_COMMAND_BITS.len(),
            "fixture entry count"
        );
    }
}
