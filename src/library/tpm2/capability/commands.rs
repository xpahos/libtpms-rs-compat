// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CommandCodeAttributes.c
// - libtpms/src/tpm2/PP.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::super::command::implemented_commands;
use super::super::pp_list::physical_presence_is_required;
use super::super::runtime::Tpm2Runtime;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const SIZEOF_TPM_CC: usize = 4;
pub(in crate::library::tpm2) const MAX_CAP_CC: usize = MAX_CAP_DATA / SIZEOF_TPM_CC;

const TPMA_CC_V: u32 = 1 << 29;

pub(in crate::library::tpm2) fn implemented(
    runtime: &Tpm2Runtime,
    starting_command: u32,
    requested_count: u32,
) -> CapabilityPage<u32> {
    paginate(
        implemented_commands()
            .filter(|descriptor| {
                descriptor.code >= starting_command && runtime.command_enabled(descriptor.code)
            })
            .map(|descriptor| descriptor.attributes),
        requested_count,
        MAX_CAP_CC,
    )
}

pub(in crate::library::tpm2) fn physical_presence(
    runtime: &Tpm2Runtime,
    starting_command: u32,
    requested_count: u32,
) -> CapabilityPage<u32> {
    paginate(
        implemented_commands()
            .map(|descriptor| descriptor.code)
            .filter(|&code| {
                code >= starting_command
                    && runtime.command_enabled(code)
                    && physical_presence_is_required(runtime, code)
            }),
        requested_count,
        MAX_CAP_CC,
    )
}

pub(in crate::library::tpm2) fn total_count(runtime: &Tpm2Runtime) -> u32 {
    implemented_commands()
        .filter(|descriptor| runtime.command_enabled(descriptor.code))
        .count() as u32
}

pub(in crate::library::tpm2) fn library_count(runtime: &Tpm2Runtime) -> u32 {
    implemented_commands()
        .filter(|descriptor| {
            descriptor.attributes & TPMA_CC_V == 0 && runtime.command_enabled(descriptor.code)
        })
        .count() as u32
}

pub(in crate::library::tpm2) fn vendor_count(runtime: &Tpm2Runtime) -> u32 {
    implemented_commands()
        .filter(|descriptor| {
            descriptor.attributes & TPMA_CC_V != 0 && runtime.command_enabled(descriptor.code)
        })
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::golden_responses::{
        attestation, certify_x509, create, create_loaded, credential_activation, ecc_commands,
        encrypt_decrypt, flush_context, get_test_result, hierarchy_management, hmac, nv,
        object_lifecycle, object_transfer, platform_state, policy_sessions,
        read_public_verify_signature, rsa_encryption, sequence_commands, sign, test_parms,
    };

    const TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x0440_011f;
    const TPMA_CC_EVICT_CONTROL: u32 = 0x0440_0120;
    const TPMA_CC_HIERARCHY_CONTROL: u32 = 0x02c0_0121;
    const TPMA_CC_NV_UNDEFINE_SPACE: u32 = 0x0440_0122;
    const TPMA_CC_CHANGE_PPS: u32 = 0x02c0_0125;
    const TPMA_CC_CLEAR: u32 = 0x02c0_0126;
    const TPMA_CC_CLEAR_CONTROL: u32 = 0x0240_0127;
    const TPMA_CC_CLOCK_SET: u32 = 0x0240_0128;
    const TPMA_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0240_0129;
    const TPMA_CC_NV_DEFINE_SPACE: u32 = 0x0240_012a;
    const TPMA_CC_PCR_SET_AUTH_POLICY: u32 = 0x0240_012c;
    const TPMA_CC_PP_COMMANDS: u32 = 0x0240_012d;
    const TPMA_CC_SET_PRIMARY_POLICY: u32 = 0x0240_012e;
    const TPMA_CC_NV_GLOBAL_WRITE_LOCK: u32 = 0x0240_0132;
    const TPMA_CC_NV_INCREMENT: u32 = 0x0440_0134;
    const TPMA_CC_NV_SET_BITS: u32 = 0x0440_0135;
    const TPMA_CC_NV_EXTEND: u32 = 0x0440_0136;
    const TPMA_CC_NV_WRITE: u32 = 0x0440_0137;
    const TPMA_CC_NV_WRITE_LOCK: u32 = 0x0440_0138;
    const TPMA_CC_DICTIONARY_ATTACK_LOCK_RESET: u32 = 0x0240_0139;
    const TPMA_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x0240_013a;
    const TPMA_CC_NV_CHANGE_AUTH: u32 = 0x0240_013b;
    const TPMA_CC_PCR_EVENT: u32 = 0x0240_013c;
    const TPMA_CC_NV_READ: u32 = 0x0400_014e;
    const TPMA_CC_NV_READ_LOCK: u32 = 0x0440_014f;
    const TPMA_CC_OBJECT_CHANGE_AUTH: u32 = 0x0400_0150;
    const TPMA_CC_CREATE: u32 = 0x0200_0153;
    const TPMA_CC_RSA_ENCRYPT: u32 = 0x0200_0174;
    const TPMA_CC_LOAD_EXTERNAL: u32 = 0x1000_0167;
    const TPMA_CC_MAKE_CREDENTIAL: u32 = 0x0200_0168;
    const TPMA_CC_NV_READ_PUBLIC: u32 = 0x0200_0169;
    const TPMA_CC_READ_PUBLIC: u32 = 0x0200_0173;
    const TPMA_CC_VERIFY_SIGNATURE: u32 = 0x0200_0177;
    const TPMA_CC_PCR_RESET: u32 = 0x0240_013d;
    const TPMA_CC_INCREMENTAL_SELF_TEST: u32 = 0x0040_0142;
    const TPMA_CC_SELF_TEST: u32 = 0x0040_0143;
    const TPMA_CC_SHUTDOWN: u32 = 0x0040_0145;
    const TPMA_CC_STIR_RANDOM: u32 = 0x0040_0146;
    const TPMA_CC_GET_RANDOM: u32 = 0x0000_017b;
    const TPMA_CC_GET_TEST_RESULT: u32 = 0x0000_017c;
    const TPMA_CC_HASH: u32 = 0x0000_017d;
    const TPMA_CC_PCR_EXTEND: u32 = 0x0240_0182;
    const TPMA_CC_PCR_SET_AUTH_VALUE: u32 = 0x0200_0183;
    const TPMA_CC_NV_CERTIFY: u32 = 0x0600_0184;
    const TPMA_CC_CREATE_LOADED: u32 = 0x1200_0191;
    const TPMA_CC_SET_ALGORITHM_SET: u32 = 0x0240_013f;
    const TPMA_CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0240_0140;
    const TPMA_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0540_0185;
    const TPMA_CC_HASH_SEQUENCE_START: u32 = 0x1000_0186;
    const TPMA_CC_POLICY_AUTH_VALUE: u32 = 0x0200_016b;
    const TPMA_CC_POLICY_COMMAND_CODE: u32 = 0x0200_016c;
    const TPMA_CC_POLICY_OR: u32 = 0x0200_0171;
    const TPMA_CC_START_AUTH_SESSION: u32 = 0x1400_0176;
    const TPMA_CC_POLICY_GET_DIGEST: u32 = 0x0200_0189;
    const TPMA_CC_POLICY_PASSWORD: u32 = 0x0200_018c;
    const TPMA_CC_POLICY_SECRET: u32 = 0x0400_0151;
    const TPMA_CC_REWRAP: u32 = 0x0400_0152;
    const TPMA_CC_POLICY_AUTHORIZE: u32 = 0x0200_016a;
    const TPMA_CC_POLICY_COUNTER_TIMER: u32 = 0x0200_016d;
    const TPMA_CC_POLICY_CP_HASH: u32 = 0x0200_016e;
    const TPMA_CC_POLICY_LOCALITY: u32 = 0x0200_016f;
    const TPMA_CC_POLICY_NAME_HASH: u32 = 0x0200_0170;
    const TPMA_CC_POLICY_PHYSICAL_PRESENCE: u32 = 0x0200_0187;
    const TPMA_CC_POLICY_DUPLICATION_SELECT: u32 = 0x0200_0188;
    const TPMA_CC_POLICY_NV_WRITTEN: u32 = 0x0200_018f;
    const TPMA_CC_POLICY_TEMPLATE: u32 = 0x0200_0190;
    const TPMA_CC_CERTIFY_X509: u32 = 0x0400_0197;
    const TPMA_CC_ECC_ENCRYPT: u32 = 0x0200_0199;
    const TPMA_CC_POLICY_PARAMETERS: u32 = 0x0200_019c;
    const TPMA_CC_COMMIT: u32 = 0x0200_018b;
    const TPMA_CC_ZGEN_2_PHASE: u32 = 0x0200_018d;
    const TPMA_CC_EC_EPHEMERAL: u32 = 0x0000_018e;
    const TPMA_CC_TEST_PARMS: u32 = 0x0000_018a;

    fn default_runtime() -> Tpm2Runtime {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let profile = validate_user_profile(Some(br#"{"Name":"default-v1"}"#))
            .expect("the default-v1 profile validates");
        let state = manufacture_state(profile, |buffer| {
            buffer.fill(0x5a);
            Ok(())
        })
        .expect("manufactures");
        commit_manufactured_state(state).expect("commits")
    }

    fn advertised_from(starting_command: u32) -> usize {
        implemented_commands()
            .filter(|descriptor| descriptor.code >= starting_command)
            .count()
    }

    #[test]
    fn null_profile_hides_disabled_physical_presence_bits() {
        let mut runtime = super::super::test_runtime::started();
        crate::library::tpm2::pp_list::require_physical_presence(&mut runtime, 0x19c);
        let page = physical_presence(&runtime, 0x19c, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn registry_zero_vendor_command_count() {
        assert_eq!(total_count(&default_runtime()), advertised_from(0) as u32);
        assert_eq!(library_count(&default_runtime()), advertised_from(0) as u32);
        assert_eq!(vendor_count(&default_runtime()), 0);
    }

    #[test]
    fn capacity_constant_upstream_match() {
        assert_eq!(MAX_CAP_CC, 254);
    }

    fn reference_command_attributes() -> Vec<u32> {
        use crate::library::tpm2::sequence::replay::vector;

        let response = vector("CAP_CC_ALL");
        let count = u32::from_be_bytes(response[15..19].try_into().unwrap()) as usize;
        let entries = &response[19..];
        assert_eq!(entries.len(), count * SIZEOF_TPM_CC);
        entries
            .chunks_exact(SIZEOF_TPM_CC)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect()
    }

    fn get_capability_commands(starting_command: u32, count: u32) -> Vec<u8> {
        use crate::library::tpm2::sequence::replay::{base_runtime, clock, command, exec_raw};

        let clock = clock();
        let mut runtime = base_runtime(&clock);
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&starting_command.to_be_bytes());
        params.extend_from_slice(&count.to_be_bytes());
        exec_raw(&mut runtime, &clock, command(0x8001, 0x0000_017a, &params))
    }

    #[test]
    fn full_command_list_reference_response() {
        use crate::library::tpm2::sequence::replay::vector;

        assert_eq!(
            get_capability_commands(0, 1000),
            vector("CAP_CC_ALL"),
            "CAP_CC_ALL"
        );
    }

    type Fixture = fn(&str) -> &'static [u8];

    #[rustfmt::skip]
    const REFERENCE_PAGES: &[(Fixture, &str, u32, u32)] = &[
        (attestation::vector, "CCATTR_0133", 0x0133, 1),
        (attestation::vector, "CCATTR_0140", 0x0140, 1),
        (attestation::vector, "CCATTR_0148", 0x0148, 1),
        (attestation::vector, "CCATTR_014A", 0x014a, 1),
        (attestation::vector, "CCATTR_014C", 0x014c, 1),
        (attestation::vector, "CCATTR_014D", 0x014d, 1),
        (attestation::vector, "CCATTR_0158", 0x0158, 1),
        (certify_x509::vector, "CCATTR_0197", 0x0197, 1),
        (certify_x509::vector, "CCATTR_0196", 0x0196, 1),
        (certify_x509::vector, "CCATTR_0198", 0x0198, 1),
        (create::vector, "CAP_CC_CREATE", 0x0153, 1),
        (create_loaded::vector, "CAP_CC_CREATE_LOADED", 0x0191, 1),
        (credential_activation::vector, "CCATTR_0147", 0x0147, 1),
        (credential_activation::vector, "CCATTR_0168", 0x0168, 1),
        (credential_activation::vector, "CCLIST_FROM_ACTIVATE", 0x0147, 4),
        (credential_activation::vector, "CCLIST_FROM_MAKE", 0x0168, 4),
        (ecc_commands::vector, "CCATTR_0154", 0x0154, 1),
        (ecc_commands::vector, "CCATTR_0163", 0x0163, 1),
        (ecc_commands::vector, "CCATTR_0178", 0x0178, 1),
        (ecc_commands::vector, "CCATTR_018B", 0x018b, 1),
        (ecc_commands::vector, "CCATTR_018D", 0x018d, 1),
        (ecc_commands::vector, "CCATTR_018E", 0x018e, 1),
        (ecc_commands::vector, "CCATTR_0199", 0x0199, 1),
        (ecc_commands::vector, "CCATTR_019A", 0x019a, 1),
        (ecc_commands::vector, "CCLIST_FROM_ZGEN", 0x0154, 4),
        (ecc_commands::vector, "CCLIST_FROM_COMMIT", 0x018b, 6),
        (ecc_commands::vector, "CCLIST_FROM_ECC_ENCRYPT", 0x0199, 4),
        (encrypt_decrypt::vector, "CAP_CC_ENCRYPT_DECRYPT", 0x0164, 1),
        (encrypt_decrypt::vector, "CAP_CC_ENCRYPT_DECRYPT2", 0x0193, 1),
        (encrypt_decrypt::vector, "CAP_CC_FROM_ENCRYPT_DECRYPT", 0x0164, 3),
        (flush_context::vector, "CAP_COMMANDS_RESPONSE", 0x0165, 1),
        (get_test_result::vector, "CAP_CC_GTR", 0x017c, 1),
        (get_test_result::vector, "CAP_CC_PAGE", 0x017b, 3),
        (hierarchy_management::vector, "CCATTR_0121", 0x0121, 1),
        (hierarchy_management::vector, "CCATTR_0125", 0x0125, 1),
        (hierarchy_management::vector, "CCATTR_0126", 0x0126, 1),
        (hierarchy_management::vector, "CCATTR_0127", 0x0127, 1),
        (hierarchy_management::vector, "CCATTR_012C", 0x012c, 1),
        (hierarchy_management::vector, "CCATTR_012E", 0x012e, 1),
        (hierarchy_management::vector, "CCATTR_0139", 0x0139, 1),
        (hmac::vector, "CAP_CC_HMAC", 0x0155, 1),
        (hmac::vector, "CAP_CC_FROM_HMAC", 0x0155, 3),
        (nv::certify_vector, "CCATTR_0184", 0x0184, 1),
        (nv::nv_vector, "CCATTR_011F", 0x011f, 1),
        (nv::nv_vector, "CCATTR_0122", 0x0122, 1),
        (nv::nv_vector, "CCATTR_012A", 0x012a, 1),
        (nv::nv_vector, "CCATTR_0132", 0x0132, 1),
        (nv::nv_vector, "CCATTR_0134", 0x0134, 1),
        (nv::nv_vector, "CCATTR_0135", 0x0135, 1),
        (nv::nv_vector, "CCATTR_0136", 0x0136, 1),
        (nv::nv_vector, "CCATTR_0137", 0x0137, 1),
        (nv::nv_vector, "CCATTR_0138", 0x0138, 1),
        (nv::nv_vector, "CCATTR_013B", 0x013b, 1),
        (nv::nv_vector, "CCATTR_014E", 0x014e, 1),
        (nv::nv_vector, "CCATTR_014F", 0x014f, 1),
        (nv::nv_vector, "CCATTR_0169", 0x0169, 1),
        (object_lifecycle::vector, "CCATTR_0150", 0x0150, 1),
        (object_lifecycle::vector, "CCATTR_0157", 0x0157, 1),
        (object_lifecycle::vector, "CCATTR_015E", 0x015e, 1),
        (object_lifecycle::vector, "CCATTR_0161", 0x0161, 1),
        (object_lifecycle::vector, "CCATTR_0162", 0x0162, 1),
        (object_lifecycle::vector, "CCATTR_0167", 0x0167, 1),
        (object_transfer::vector, "CCATTR_014B", 0x014b, 1),
        (object_transfer::vector, "CCATTR_0152", 0x0152, 1),
        (object_transfer::vector, "CCATTR_0156", 0x0156, 1),
        (platform_state::vector, "CCATTR_0128", 0x0128, 1),
        (platform_state::vector, "CCATTR_012D", 0x012d, 1),
        (platform_state::vector, "CCATTR_0130", 0x0130, 1),
        (platform_state::vector, "CCATTR_013F", 0x013f, 1),
        (platform_state::vector, "CCATTR_0181", 0x0181, 1),
        (platform_state::vector, "CCATTR_0183", 0x0183, 1),
        (platform_state::vector, "CCATTR_0198", 0x0198, 1),
        (policy_sessions::vector, "CCATTR_016B", 0x016b, 1),
        (policy_sessions::vector, "CCATTR_016C", 0x016c, 1),
        (policy_sessions::vector, "CCATTR_0171", 0x0171, 1),
        (policy_sessions::vector, "CCATTR_0176", 0x0176, 1),
        (policy_sessions::vector, "CCATTR_017F", 0x017f, 1),
        (policy_sessions::vector, "CCATTR_0180", 0x0180, 1),
        (policy_sessions::vector, "CCATTR_0189", 0x0189, 1),
        (policy_sessions::vector, "CCATTR_018C", 0x018c, 1),
        (policy_sessions::vector, "CCATTR_0149", 0x0149, 1),
        (policy_sessions::vector, "CCATTR_0151", 0x0151, 1),
        (policy_sessions::vector, "CCATTR_0160", 0x0160, 1),
        (policy_sessions::vector, "CCATTR_016A", 0x016a, 1),
        (policy_sessions::vector, "CCATTR_016D", 0x016d, 1),
        (policy_sessions::vector, "CCATTR_016E", 0x016e, 1),
        (policy_sessions::vector, "CCATTR_016F", 0x016f, 1),
        (policy_sessions::vector, "CCATTR_0170", 0x0170, 1),
        (policy_sessions::vector, "CCATTR_0172", 0x0172, 1),
        (policy_sessions::vector, "CCATTR_0187", 0x0187, 1),
        (policy_sessions::vector, "CCATTR_0188", 0x0188, 1),
        (policy_sessions::vector, "CCATTR_018F", 0x018f, 1),
        (policy_sessions::vector, "CCATTR_0190", 0x0190, 1),
        (policy_sessions::vector, "CCATTR_0192", 0x0192, 1),
        (policy_sessions::vector, "CCATTR_019B", 0x019b, 1),
        (policy_sessions::vector, "CCATTR_019C", 0x019c, 1),
        (read_public_verify_signature::vector, "CCATTR_0173", 0x0173, 1),
        (read_public_verify_signature::vector, "CCATTR_0177", 0x0177, 1),
        (rsa_encryption::vector, "CCATTR_0159", 0x0159, 1),
        (rsa_encryption::vector, "CCATTR_0174", 0x0174, 1),
        (rsa_encryption::vector, "CCATTR_AROUND_DECRYPT", 0x0157, 3),
        (rsa_encryption::vector, "CCATTR_AROUND_ENCRYPT", 0x0173, 3),
        (sequence_commands::vector, "CAP_CC_SEQUENCE_COMPLETE", 0x013e, 1),
        (sequence_commands::vector, "CAP_CC_HMAC_START", 0x015b, 1),
        (sequence_commands::vector, "CAP_CC_SEQUENCE_UPDATE", 0x015c, 1),
        (sequence_commands::vector, "CAP_CC_EVENT_SEQUENCE_COMPLETE", 0x0185, 1),
        (sequence_commands::vector, "CAP_CC_HASH_SEQUENCE_START", 0x0186, 1),
        (sign::vector, "CCATTR_015D", 0x015d, 1),
        (test_parms::vector, "CAP_CC_TEST_PARMS", 0x018a, 1),
    ];

    #[test]
    fn recorded_command_pages_reference_responses() {
        for &(fixture, record, property, count) in REFERENCE_PAGES {
            assert_eq!(
                get_capability_commands(property, count),
                fixture(record),
                "{record}: property {property:#06x}, count {count}"
            );
        }
    }

    #[rustfmt::skip]
    const PAGE_WINDOWS: &[(u32, u32, &[u32], bool)] = &[
        (0x0000, 1, &[TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL], true),
        (0x0000, 3, &[TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL, TPMA_CC_EVICT_CONTROL, TPMA_CC_HIERARCHY_CONTROL], true),
        (0x0121, 1, &[TPMA_CC_HIERARCHY_CONTROL], true),
        (0x0122, 1, &[TPMA_CC_NV_UNDEFINE_SPACE], true),
        (0x0125, 3, &[TPMA_CC_CHANGE_PPS, TPMA_CC_CLEAR, TPMA_CC_CLEAR_CONTROL], true),
        (0x0128, 2, &[TPMA_CC_CLOCK_SET, TPMA_CC_HIERARCHY_CHANGE_AUTH], true),
        (0x012a, 1, &[TPMA_CC_NV_DEFINE_SPACE], true),
        (0x012c, 3, &[TPMA_CC_PCR_SET_AUTH_POLICY, TPMA_CC_PP_COMMANDS, TPMA_CC_SET_PRIMARY_POLICY], true),
        (0x012e, 1, &[TPMA_CC_SET_PRIMARY_POLICY], true),
        (0x0132, 1, &[TPMA_CC_NV_GLOBAL_WRITE_LOCK], true),
        (0x0134, 5, &[TPMA_CC_NV_INCREMENT, TPMA_CC_NV_SET_BITS, TPMA_CC_NV_EXTEND, TPMA_CC_NV_WRITE,
                      TPMA_CC_NV_WRITE_LOCK], true),
        (0x0139, 2, &[TPMA_CC_DICTIONARY_ATTACK_LOCK_RESET, TPMA_CC_DICTIONARY_ATTACK_PARAMETERS], true),
        (0x013b, 1, &[TPMA_CC_NV_CHANGE_AUTH], true),
        (0x013b, 2, &[TPMA_CC_NV_CHANGE_AUTH, TPMA_CC_PCR_EVENT], true),
        (0x013c, 1, &[TPMA_CC_PCR_EVENT], true),
        (0x013c, 2, &[TPMA_CC_PCR_EVENT, TPMA_CC_PCR_RESET], true),
        (0x013f, 2, &[TPMA_CC_SET_ALGORITHM_SET, TPMA_CC_SET_COMMAND_CODE_AUDIT_STATUS], true),
        (0x0142, 1, &[TPMA_CC_INCREMENTAL_SELF_TEST], true),
        (0x0142, 2, &[TPMA_CC_INCREMENTAL_SELF_TEST, TPMA_CC_SELF_TEST], true),
        (0x0143, 1, &[TPMA_CC_SELF_TEST], true),
        (0x0145, 1, &[TPMA_CC_SHUTDOWN], true),
        (0x0146, 1, &[TPMA_CC_STIR_RANDOM], true),
        (0x014e, 6, &[TPMA_CC_NV_READ, TPMA_CC_NV_READ_LOCK, TPMA_CC_OBJECT_CHANGE_AUTH,
                      TPMA_CC_POLICY_SECRET, TPMA_CC_REWRAP, TPMA_CC_CREATE], true),
        (0x0169, 4, &[TPMA_CC_NV_READ_PUBLIC, TPMA_CC_POLICY_AUTHORIZE, TPMA_CC_POLICY_AUTH_VALUE,
                      TPMA_CC_POLICY_COMMAND_CODE], true),
        (0x0173, 1, &[TPMA_CC_READ_PUBLIC], true),
        (0x0174, 3, &[TPMA_CC_RSA_ENCRYPT, TPMA_CC_START_AUTH_SESSION, TPMA_CC_VERIFY_SIGNATURE], true),
        (0x0177, 1, &[TPMA_CC_VERIFY_SIGNATURE], true),
        (0x017b, 1, &[TPMA_CC_GET_RANDOM], true),
        (0x017b, 2, &[TPMA_CC_GET_RANDOM, TPMA_CC_GET_TEST_RESULT], true),
        (0x017c, 1, &[TPMA_CC_GET_TEST_RESULT], true),
        (0x017d, 1, &[TPMA_CC_HASH], true),
        (0x0182, 16, &[TPMA_CC_PCR_EXTEND, TPMA_CC_PCR_SET_AUTH_VALUE, TPMA_CC_NV_CERTIFY,
                       TPMA_CC_EVENT_SEQUENCE_COMPLETE, TPMA_CC_HASH_SEQUENCE_START,
                       TPMA_CC_POLICY_PHYSICAL_PRESENCE, TPMA_CC_POLICY_DUPLICATION_SELECT,
                       TPMA_CC_POLICY_GET_DIGEST, TPMA_CC_TEST_PARMS, TPMA_CC_COMMIT,
                       TPMA_CC_POLICY_PASSWORD, TPMA_CC_ZGEN_2_PHASE, TPMA_CC_EC_EPHEMERAL,
                       TPMA_CC_POLICY_NV_WRITTEN, TPMA_CC_POLICY_TEMPLATE, TPMA_CC_CREATE_LOADED], true),
        (0x0184, 14, &[TPMA_CC_NV_CERTIFY, TPMA_CC_EVENT_SEQUENCE_COMPLETE, TPMA_CC_HASH_SEQUENCE_START,
                       TPMA_CC_POLICY_PHYSICAL_PRESENCE, TPMA_CC_POLICY_DUPLICATION_SELECT,
                       TPMA_CC_POLICY_GET_DIGEST, TPMA_CC_TEST_PARMS, TPMA_CC_COMMIT,
                       TPMA_CC_POLICY_PASSWORD, TPMA_CC_ZGEN_2_PHASE, TPMA_CC_EC_EPHEMERAL,
                       TPMA_CC_POLICY_NV_WRITTEN, TPMA_CC_POLICY_TEMPLATE, TPMA_CC_CREATE_LOADED], true),
        (0x0141, 1, &[TPMA_CC_INCREMENTAL_SELF_TEST], true),
        (0x0166, 11, &[TPMA_CC_LOAD_EXTERNAL, TPMA_CC_MAKE_CREDENTIAL, TPMA_CC_NV_READ_PUBLIC,
                       TPMA_CC_POLICY_AUTHORIZE, TPMA_CC_POLICY_AUTH_VALUE, TPMA_CC_POLICY_COMMAND_CODE,
                       TPMA_CC_POLICY_COUNTER_TIMER, TPMA_CC_POLICY_CP_HASH, TPMA_CC_POLICY_LOCALITY,
                       TPMA_CC_POLICY_NAME_HASH, TPMA_CC_POLICY_OR], true),
        (0x0196, 1, &[TPMA_CC_CERTIFY_X509], true),
        (0x0197, 1, &[TPMA_CC_CERTIFY_X509], true),
        (0x0198, 1, &[TPMA_CC_ECC_ENCRYPT], true),
        (0x019c, 1, &[TPMA_CC_POLICY_PARAMETERS], false),
        (0x019d, 10, &[], false),
        (0x0000, 0, &[], true),
        (0x019d, 0, &[], false),
    ];

    #[test]
    fn page_windows_entries_and_more_data() {
        let runtime = default_runtime();
        for &(property, count, entries, more_data) in PAGE_WINDOWS {
            let page = implemented(&runtime, property, count);
            assert_eq!(
                page.entries, entries,
                "property {property:#06x}, count {count}"
            );
            assert_eq!(
                page.more_data, more_data,
                "moreData for property {property:#06x}, count {count}"
            );
        }
    }

    #[rustfmt::skip]
    const OPEN_ENDED_PAGES: &[(u32, u32)] = &[
        (0x0000, 1000), (0x0000, u32::MAX), (0x0120, 1000), (0x0121, 1000), (0x0124, 1000),
        (0x0125, 1000), (0x0129, 1000), (0x012a, 1000), (0x012b, 1000), (0x012c, 1000),
        (0x0131, 1000), (0x0132, 1000), (0x013d, 1000), (0x013e, 1000), (0x0143, 1000),
        (0x0144, 1000), (0x0147, 1000), (0x0178, 1000), (0x017c, 1000), (0x017d, 1000),
        (0x017e, 1000), (0x019c, 1000),
    ];

    #[test]
    fn open_ended_pages_reference_tail() {
        let runtime = default_runtime();
        let reference = reference_command_attributes();
        let exact = (0x0000, reference.len() as u32);
        for &(property, count) in OPEN_ENDED_PAGES.iter().chain([&exact]) {
            let tail: Vec<u32> = reference
                .iter()
                .copied()
                .filter(|attributes| attributes & 0xffff >= property)
                .collect();
            let page = implemented(&runtime, property, count);
            assert_eq!(
                page.entries, tail,
                "property {property:#06x}, count {count}"
            );
            assert!(
                !page.more_data,
                "moreData for property {property:#06x}, count {count}"
            );
        }
    }

    #[test]
    fn pcr_commands_reference_nv_attribute() {
        const TPMA_CC_NV: u32 = 1 << 22;
        let reference = reference_command_attributes();
        for code in [0x0000_013cu32, 0x0000_013d, 0x0000_0182] {
            let expected = *reference
                .iter()
                .find(|&&attributes| attributes & 0xffff == code)
                .unwrap_or_else(|| panic!("the reference advertises {code:#06x}"));
            assert_ne!(expected & TPMA_CC_NV, 0, "reference {code:#06x}");

            let response = get_capability_commands(code, 1);
            let mut wanted = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x00];
            wanted.push(1);
            wanted.extend_from_slice(&2u32.to_be_bytes());
            wanted.extend_from_slice(&1u32.to_be_bytes());
            wanted.extend_from_slice(&expected.to_be_bytes());
            assert_eq!(response, wanted, "GetCapability for {code:#06x}");
        }
    }
}
