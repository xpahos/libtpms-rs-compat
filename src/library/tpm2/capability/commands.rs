use super::super::command::implemented_commands;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const SIZEOF_TPM_CC: usize = 4;
pub(in crate::library::tpm2) const MAX_CAP_CC: usize = MAX_CAP_DATA / SIZEOF_TPM_CC;

const TPMA_CC_V: u32 = 1 << 29;

// TODO: Filter the reported commands through the active profile once the
// dispatcher enforces profile-disabled registry commands.
pub(in crate::library::tpm2) fn implemented(
    starting_command: u32,
    requested_count: u32,
) -> CapabilityPage<u32> {
    paginate(
        implemented_commands()
            .filter(|descriptor| descriptor.code >= starting_command)
            .map(|descriptor| descriptor.attributes),
        requested_count,
        MAX_CAP_CC,
    )
}

pub(in crate::library::tpm2) fn total_count() -> u32 {
    implemented_commands().count() as u32
}

pub(in crate::library::tpm2) fn library_count() -> u32 {
    implemented_commands()
        .filter(|descriptor| descriptor.attributes & TPMA_CC_V == 0)
        .count() as u32
}

pub(in crate::library::tpm2) fn vendor_count() -> u32 {
    implemented_commands()
        .filter(|descriptor| descriptor.attributes & TPMA_CC_V != 0)
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL: u32 = 0x0440_011f;
    const TPMA_CC_EVICT_CONTROL: u32 = 0x0440_0120;
    const TPMA_CC_HIERARCHY_CONTROL: u32 = 0x02c0_0121;
    const TPMA_CC_NV_UNDEFINE_SPACE: u32 = 0x0440_0122;
    const TPMA_CC_CHANGE_EPS: u32 = 0x02c0_0124;
    const TPMA_CC_CHANGE_PPS: u32 = 0x02c0_0125;
    const TPMA_CC_CLEAR: u32 = 0x02c0_0126;
    const TPMA_CC_CLEAR_CONTROL: u32 = 0x0240_0127;
    const TPMA_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0240_0129;
    const TPMA_CC_NV_DEFINE_SPACE: u32 = 0x0240_012a;
    const TPMA_CC_PCR_SET_AUTH_POLICY: u32 = 0x0240_012c;
    const TPMA_CC_SET_PRIMARY_POLICY: u32 = 0x0240_012e;
    const TPMA_CC_NV_GLOBAL_WRITE_LOCK: u32 = 0x0240_0132;
    const TPMA_CC_GET_COMMAND_AUDIT_DIGEST: u32 = 0x0440_0133;
    const TPMA_CC_NV_INCREMENT: u32 = 0x0440_0134;
    const TPMA_CC_NV_SET_BITS: u32 = 0x0440_0135;
    const TPMA_CC_NV_EXTEND: u32 = 0x0440_0136;
    const TPMA_CC_NV_WRITE: u32 = 0x0440_0137;
    const TPMA_CC_NV_WRITE_LOCK: u32 = 0x0440_0138;
    const TPMA_CC_DICTIONARY_ATTACK_LOCK_RESET: u32 = 0x0240_0139;
    const TPMA_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x0240_013a;
    const TPMA_CC_NV_CHANGE_AUTH: u32 = 0x0240_013b;
    const TPMA_CC_PCR_EVENT: u32 = 0x0200_013c;
    const TPMA_CC_NV_READ: u32 = 0x0400_014e;
    const TPMA_CC_NV_READ_LOCK: u32 = 0x0440_014f;
    const TPMA_CC_OBJECT_CHANGE_AUTH: u32 = 0x0400_0150;
    const TPMA_CC_CREATE: u32 = 0x0200_0153;
    const TPMA_CC_LOAD: u32 = 0x1200_0157;
    const TPMA_CC_RSA_DECRYPT: u32 = 0x0200_0159;
    const TPMA_CC_RSA_ENCRYPT: u32 = 0x0200_0174;
    const TPMA_CC_SIGN: u32 = 0x0200_015d;
    const TPMA_CC_UNSEAL: u32 = 0x0200_015e;
    const TPMA_CC_CONTEXT_LOAD: u32 = 0x1000_0161;
    const TPMA_CC_CONTEXT_SAVE: u32 = 0x0200_0162;
    const TPMA_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
    const TPMA_CC_LOAD_EXTERNAL: u32 = 0x1000_0167;
    const TPMA_CC_NV_READ_PUBLIC: u32 = 0x0200_0169;
    const TPMA_CC_READ_PUBLIC: u32 = 0x0200_0173;
    const TPMA_CC_VERIFY_SIGNATURE: u32 = 0x0200_0177;
    const TPMA_CC_PCR_RESET: u32 = 0x0200_013d;
    const TPMA_CC_INCREMENTAL_SELF_TEST: u32 = 0x0040_0142;
    const TPMA_CC_SELF_TEST: u32 = 0x0040_0143;
    const TPMA_CC_STARTUP: u32 = 0x0040_0144;
    const TPMA_CC_SHUTDOWN: u32 = 0x0040_0145;
    const TPMA_CC_STIR_RANDOM: u32 = 0x0040_0146;
    const TPMA_CC_GET_CAPABILITY: u32 = 0x0000_017a;
    const TPMA_CC_GET_RANDOM: u32 = 0x0000_017b;
    const TPMA_CC_GET_TEST_RESULT: u32 = 0x0000_017c;
    const TPMA_CC_HASH: u32 = 0x0000_017d;
    const TPMA_CC_PCR_READ: u32 = 0x0000_017e;
    const TPMA_CC_PCR_EXTEND: u32 = 0x0200_0182;
    const TPMA_CC_NV_CERTIFY: u32 = 0x0600_0184;
    const TPMA_CC_PCR_ALLOCATE: u32 = 0x0240_012b;
    const TPMA_CC_CREATE_PRIMARY: u32 = 0x1200_0131;
    const TPMA_CC_CREATE_LOADED: u32 = 0x1200_0191;
    const TPMA_CC_SEQUENCE_COMPLETE: u32 = 0x0300_013e;
    const TPMA_CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0240_0140;
    const TPMA_CC_CERTIFY: u32 = 0x0400_0148;
    const TPMA_CC_CERTIFY_CREATION: u32 = 0x0400_014a;
    const TPMA_CC_GET_TIME: u32 = 0x0400_014c;
    const TPMA_CC_GET_SESSION_AUDIT_DIGEST: u32 = 0x0600_014d;
    const TPMA_CC_QUOTE: u32 = 0x0200_0158;
    const TPMA_CC_HMAC_START: u32 = 0x1200_015b;
    const TPMA_CC_SEQUENCE_UPDATE: u32 = 0x0200_015c;
    const TPMA_CC_EVENT_SEQUENCE_COMPLETE: u32 = 0x0540_0185;
    const TPMA_CC_HASH_SEQUENCE_START: u32 = 0x1000_0186;
    const TPMA_CC_POLICY_AUTH_VALUE: u32 = 0x0200_016b;
    const TPMA_CC_POLICY_COMMAND_CODE: u32 = 0x0200_016c;
    const TPMA_CC_POLICY_OR: u32 = 0x0200_0171;
    const TPMA_CC_START_AUTH_SESSION: u32 = 0x1400_0176;
    const TPMA_CC_POLICY_PCR: u32 = 0x0200_017f;
    const TPMA_CC_POLICY_RESTART: u32 = 0x0200_0180;
    const TPMA_CC_POLICY_GET_DIGEST: u32 = 0x0200_0189;
    const TPMA_CC_POLICY_PASSWORD: u32 = 0x0200_018c;
    const TPMA_CC_POLICY_NV: u32 = 0x0600_0149;
    const TPMA_CC_POLICY_SECRET: u32 = 0x0400_0151;
    const TPMA_CC_POLICY_SIGNED: u32 = 0x0400_0160;
    const TPMA_CC_POLICY_AUTHORIZE: u32 = 0x0200_016a;
    const TPMA_CC_POLICY_COUNTER_TIMER: u32 = 0x0200_016d;
    const TPMA_CC_POLICY_CP_HASH: u32 = 0x0200_016e;
    const TPMA_CC_POLICY_LOCALITY: u32 = 0x0200_016f;
    const TPMA_CC_POLICY_NAME_HASH: u32 = 0x0200_0170;
    const TPMA_CC_POLICY_TICKET: u32 = 0x0200_0172;
    const TPMA_CC_POLICY_PHYSICAL_PRESENCE: u32 = 0x0200_0187;
    const TPMA_CC_POLICY_DUPLICATION_SELECT: u32 = 0x0200_0188;
    const TPMA_CC_POLICY_NV_WRITTEN: u32 = 0x0200_018f;
    const TPMA_CC_POLICY_TEMPLATE: u32 = 0x0200_0190;
    const TPMA_CC_POLICY_AUTHORIZE_NV: u32 = 0x0600_0192;
    const TPMA_CC_POLICY_CAPABILITY: u32 = 0x0200_019b;
    const TPMA_CC_POLICY_PARAMETERS: u32 = 0x0200_019c;

    #[test]
    fn a_query_from_zero_returns_every_registry_command() {
        let page = implemented(0, 1000);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL,
                TPMA_CC_EVICT_CONTROL,
                TPMA_CC_HIERARCHY_CONTROL,
                TPMA_CC_NV_UNDEFINE_SPACE,
                TPMA_CC_CHANGE_EPS,
                TPMA_CC_CHANGE_PPS,
                TPMA_CC_CLEAR,
                TPMA_CC_CLEAR_CONTROL,
                TPMA_CC_HIERARCHY_CHANGE_AUTH,
                TPMA_CC_NV_DEFINE_SPACE,
                TPMA_CC_PCR_ALLOCATE,
                TPMA_CC_PCR_SET_AUTH_POLICY,
                TPMA_CC_SET_PRIMARY_POLICY,
                TPMA_CC_CREATE_PRIMARY,
                TPMA_CC_NV_GLOBAL_WRITE_LOCK,
                TPMA_CC_GET_COMMAND_AUDIT_DIGEST,
                TPMA_CC_NV_INCREMENT,
                TPMA_CC_NV_SET_BITS,
                TPMA_CC_NV_EXTEND,
                TPMA_CC_NV_WRITE,
                TPMA_CC_NV_WRITE_LOCK,
                TPMA_CC_DICTIONARY_ATTACK_LOCK_RESET,
                TPMA_CC_DICTIONARY_ATTACK_PARAMETERS,
                TPMA_CC_NV_CHANGE_AUTH,
                TPMA_CC_PCR_EVENT,
                TPMA_CC_PCR_RESET,
                TPMA_CC_SEQUENCE_COMPLETE,
                TPMA_CC_SET_COMMAND_CODE_AUDIT_STATUS,
                TPMA_CC_INCREMENTAL_SELF_TEST,
                TPMA_CC_SELF_TEST,
                TPMA_CC_STARTUP,
                TPMA_CC_SHUTDOWN,
                TPMA_CC_STIR_RANDOM,
                TPMA_CC_CERTIFY,
                TPMA_CC_POLICY_NV,
                TPMA_CC_CERTIFY_CREATION,
                TPMA_CC_GET_TIME,
                TPMA_CC_GET_SESSION_AUDIT_DIGEST,
                TPMA_CC_NV_READ,
                TPMA_CC_NV_READ_LOCK,
                TPMA_CC_OBJECT_CHANGE_AUTH,
                TPMA_CC_POLICY_SECRET,
                TPMA_CC_CREATE,
                TPMA_CC_LOAD,
                TPMA_CC_QUOTE,
                TPMA_CC_RSA_DECRYPT,
                TPMA_CC_HMAC_START,
                TPMA_CC_SEQUENCE_UPDATE,
                TPMA_CC_SIGN,
                TPMA_CC_UNSEAL,
                TPMA_CC_POLICY_SIGNED,
                TPMA_CC_CONTEXT_LOAD,
                TPMA_CC_CONTEXT_SAVE,
                TPMA_CC_FLUSH_CONTEXT,
                TPMA_CC_LOAD_EXTERNAL,
                TPMA_CC_NV_READ_PUBLIC,
                TPMA_CC_POLICY_AUTHORIZE,
                TPMA_CC_POLICY_AUTH_VALUE,
                TPMA_CC_POLICY_COMMAND_CODE,
                TPMA_CC_POLICY_COUNTER_TIMER,
                TPMA_CC_POLICY_CP_HASH,
                TPMA_CC_POLICY_LOCALITY,
                TPMA_CC_POLICY_NAME_HASH,
                TPMA_CC_POLICY_OR,
                TPMA_CC_POLICY_TICKET,
                TPMA_CC_READ_PUBLIC,
                TPMA_CC_RSA_ENCRYPT,
                TPMA_CC_START_AUTH_SESSION,
                TPMA_CC_VERIFY_SIGNATURE,
                TPMA_CC_GET_CAPABILITY,
                TPMA_CC_GET_RANDOM,
                TPMA_CC_GET_TEST_RESULT,
                TPMA_CC_HASH,
                TPMA_CC_PCR_READ,
                TPMA_CC_POLICY_PCR,
                TPMA_CC_POLICY_RESTART,
                TPMA_CC_PCR_EXTEND,
                TPMA_CC_NV_CERTIFY,
                TPMA_CC_EVENT_SEQUENCE_COMPLETE,
                TPMA_CC_HASH_SEQUENCE_START,
                TPMA_CC_POLICY_PHYSICAL_PRESENCE,
                TPMA_CC_POLICY_DUPLICATION_SELECT,
                TPMA_CC_POLICY_GET_DIGEST,
                TPMA_CC_POLICY_PASSWORD,
                TPMA_CC_POLICY_NV_WRITTEN,
                TPMA_CC_POLICY_TEMPLATE,
                TPMA_CC_CREATE_LOADED,
                TPMA_CC_POLICY_AUTHORIZE_NV,
                TPMA_CC_POLICY_CAPABILITY,
                TPMA_CC_POLICY_PARAMETERS
            ]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn nv_undefine_space_special_leads_the_registry_because_its_command_code_is_the_lowest() {
        let page = implemented(0, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL]);
        assert!(page.more_data);

        let page = implemented(0x0120, 1000);
        assert_eq!(page.entries.len(), 89);
        assert_eq!(page.entries[0], TPMA_CC_EVICT_CONTROL);

        let page = implemented(0x0121, 1000);
        assert_eq!(page.entries.len(), 88);
        assert_eq!(page.entries[0], TPMA_CC_HIERARCHY_CONTROL);
        assert!(!page.entries.contains(&TPMA_CC_EVICT_CONTROL));
    }

    #[test]
    fn the_hierarchy_administration_commands_are_advertised_in_command_code_order() {
        let page = implemented(0x0121, 1);
        assert_eq!(page.entries, [TPMA_CC_HIERARCHY_CONTROL]);
        assert!(page.more_data);

        let page = implemented(0x0125, 3);
        assert_eq!(
            page.entries,
            [TPMA_CC_CHANGE_PPS, TPMA_CC_CLEAR, TPMA_CC_CLEAR_CONTROL]
        );
        assert!(page.more_data);

        let page = implemented(0x012c, 2);
        assert_eq!(
            page.entries,
            [TPMA_CC_PCR_SET_AUTH_POLICY, TPMA_CC_SET_PRIMARY_POLICY]
        );
        assert!(page.more_data);

        let page = implemented(0x0139, 2);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_DICTIONARY_ATTACK_LOCK_RESET,
                TPMA_CC_DICTIONARY_ATTACK_PARAMETERS
            ]
        );
        assert!(page.more_data);
    }

    #[test]
    fn change_eps_follows_nv_undefine_space() {
        let page = implemented(0x0122, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_UNDEFINE_SPACE]);
        assert!(page.more_data);

        let page = implemented(0x0124, 1000);
        assert_eq!(page.entries.len(), 86);
        assert_eq!(page.entries[0], TPMA_CC_CHANGE_EPS);

        let page = implemented(0x0125, 1000);
        assert_eq!(page.entries.len(), 85);
        assert!(!page.entries.contains(&TPMA_CC_CHANGE_EPS));
    }

    #[test]
    fn hierarchy_change_auth_follows_clear_control() {
        let page = implemented(0x0128, 1);
        assert_eq!(page.entries, [TPMA_CC_HIERARCHY_CHANGE_AUTH]);
        assert!(page.more_data);

        let page = implemented(0x0129, 1000);
        assert_eq!(page.entries.len(), 82);
        assert_eq!(page.entries[0], TPMA_CC_HIERARCHY_CHANGE_AUTH);

        let page = implemented(0x012a, 1000);
        assert_eq!(page.entries.len(), 81);
        assert!(!page.entries.contains(&TPMA_CC_HIERARCHY_CHANGE_AUTH));
    }

    #[test]
    fn nv_define_space_follows_hierarchy_change_auth() {
        let page = implemented(0x012a, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_DEFINE_SPACE]);
        assert!(page.more_data);

        let page = implemented(0x012b, 1000);
        assert_eq!(page.entries.len(), 80);
        assert_eq!(page.entries[0], TPMA_CC_PCR_ALLOCATE);

        let page = implemented(0x012c, 1000);
        assert_eq!(page.entries.len(), 79);
        assert!(!page.entries.contains(&TPMA_CC_PCR_ALLOCATE));
    }

    #[test]
    fn create_primary_follows_set_primary_policy() {
        let page = implemented(0x012e, 1);
        assert_eq!(page.entries, [TPMA_CC_SET_PRIMARY_POLICY]);
        assert!(page.more_data);

        let page = implemented(0x0131, 1000);
        assert_eq!(page.entries.len(), 77);
        assert_eq!(page.entries[0], TPMA_CC_CREATE_PRIMARY);

        let page = implemented(0x0132, 1000);
        assert_eq!(page.entries.len(), 76);
        assert!(!page.entries.contains(&TPMA_CC_CREATE_PRIMARY));
    }

    #[test]
    fn nv_global_write_lock_follows_create_primary() {
        let page = implemented(0x0132, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_GLOBAL_WRITE_LOCK]);
        assert!(page.more_data);

        let page = implemented(0x013d, 1000);
        assert_eq!(page.entries.len(), 65);
        assert_eq!(page.entries[0], TPMA_CC_PCR_RESET);

        let page = implemented(0x013e, 1000);
        assert_eq!(page.entries.len(), 64);
        assert_eq!(page.entries[0], TPMA_CC_SEQUENCE_COMPLETE);
        assert!(!page.entries.contains(&TPMA_CC_PCR_RESET));
    }

    #[test]
    fn the_nv_modification_commands_are_advertised_in_command_code_order() {
        let page = implemented(0x0134, 5);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_INCREMENT,
                TPMA_CC_NV_SET_BITS,
                TPMA_CC_NV_EXTEND,
                TPMA_CC_NV_WRITE,
                TPMA_CC_NV_WRITE_LOCK
            ]
        );
        assert!(page.more_data);

        let page = implemented(0x013b, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_CHANGE_AUTH]);
    }

    #[test]
    fn pcr_event_is_advertised_from_its_own_command_code() {
        let page = implemented(0x013c, 1);
        assert_eq!(page.entries, [TPMA_CC_PCR_EVENT]);
        assert!(page.more_data);

        let page = implemented(0x013c, 2);
        assert_eq!(page.entries, [TPMA_CC_PCR_EVENT, TPMA_CC_PCR_RESET]);
        assert!(page.more_data);

        let page = implemented(0x013b, 2);
        assert_eq!(page.entries, [TPMA_CC_NV_CHANGE_AUTH, TPMA_CC_PCR_EVENT]);
        assert!(page.more_data);

        let page = implemented(0x013d, 1000);
        assert!(!page.entries.contains(&TPMA_CC_PCR_EVENT));
    }

    #[test]
    fn the_nv_read_commands_are_advertised_in_command_code_order() {
        let page = implemented(0x014e, 6);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_READ,
                TPMA_CC_NV_READ_LOCK,
                TPMA_CC_OBJECT_CHANGE_AUTH,
                TPMA_CC_POLICY_SECRET,
                TPMA_CC_CREATE,
                TPMA_CC_LOAD
            ]
        );
        assert!(page.more_data);
    }

    #[test]
    fn self_test_is_advertised_from_its_own_command_code() {
        let page = implemented(0x0143, 1);
        assert_eq!(page.entries, [TPMA_CC_SELF_TEST]);
        assert!(page.more_data);

        let page = implemented(0x0142, 2);
        assert_eq!(
            page.entries,
            [TPMA_CC_INCREMENTAL_SELF_TEST, TPMA_CC_SELF_TEST]
        );
        assert!(page.more_data);

        let page = implemented(0x0144, 1000);
        assert!(!page.entries.contains(&TPMA_CC_SELF_TEST));
    }

    #[test]
    fn incremental_self_test_is_advertised_from_its_own_command_code() {
        let page = implemented(0x0142, 1);
        assert_eq!(page.entries, [TPMA_CC_INCREMENTAL_SELF_TEST]);
        assert!(page.more_data);

        let page = implemented(0x0141, 1);
        assert_eq!(page.entries, [TPMA_CC_INCREMENTAL_SELF_TEST]);
        assert!(page.more_data);

        let page = implemented(0x013f, 1);
        assert_eq!(page.entries, [TPMA_CC_SET_COMMAND_CODE_AUDIT_STATUS]);
        assert!(page.more_data);

        let page = implemented(0x0143, 1000);
        assert!(!page.entries.contains(&TPMA_CC_INCREMENTAL_SELF_TEST));
    }

    #[test]
    fn every_registry_descriptor_is_advertised() {
        let page = implemented(0, 1000);
        assert_eq!(page.entries.len(), implemented_commands().count());
        for descriptor in implemented_commands() {
            assert!(
                page.entries.contains(&descriptor.attributes),
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn the_starting_command_is_inclusive() {
        let page = implemented(0x0145, 1);
        assert_eq!(page.entries, [TPMA_CC_SHUTDOWN]);
        assert!(page.more_data);
    }

    #[test]
    fn a_start_between_entries_skips_to_the_next_command() {
        let page = implemented(0x0147, 11);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_CERTIFY,
                TPMA_CC_POLICY_NV,
                TPMA_CC_CERTIFY_CREATION,
                TPMA_CC_GET_TIME,
                TPMA_CC_GET_SESSION_AUDIT_DIGEST,
                TPMA_CC_NV_READ,
                TPMA_CC_NV_READ_LOCK,
                TPMA_CC_OBJECT_CHANGE_AUTH,
                TPMA_CC_POLICY_SECRET,
                TPMA_CC_CREATE,
                TPMA_CC_LOAD
            ]
        );
        assert!(page.more_data);
    }

    #[test]
    fn stir_random_is_advertised_from_its_own_command_code() {
        let page = implemented(0x0146, 1);
        assert_eq!(page.entries, [TPMA_CC_STIR_RANDOM]);
        assert!(page.more_data);

        let page = implemented(0x0147, 1000);
        assert!(!page.entries.contains(&TPMA_CC_STIR_RANDOM));
    }

    #[test]
    fn get_random_is_advertised_from_its_own_command_code() {
        let page = implemented(0x017b, 1);
        assert_eq!(page.entries, [TPMA_CC_GET_RANDOM]);
        assert!(page.more_data);

        let page = implemented(0x017c, 1000);
        assert!(!page.entries.contains(&TPMA_CC_GET_RANDOM));
    }

    #[test]
    fn get_test_result_is_advertised_from_its_own_command_code() {
        let page = implemented(0x017c, 1);
        assert_eq!(page.entries, [TPMA_CC_GET_TEST_RESULT]);
        assert!(page.more_data);

        let page = implemented(0x017b, 2);
        assert_eq!(page.entries, [TPMA_CC_GET_RANDOM, TPMA_CC_GET_TEST_RESULT]);
        assert!(page.more_data);

        let page = implemented(0x017d, 1000);
        assert!(!page.entries.contains(&TPMA_CC_GET_TEST_RESULT));
    }

    #[test]
    fn hash_is_advertised_from_its_own_command_code() {
        let page = implemented(0x017d, 1);
        assert_eq!(page.entries, [TPMA_CC_HASH]);
        assert!(page.more_data);

        let page = implemented(0x017c, 1);
        assert_eq!(page.entries, [TPMA_CC_GET_TEST_RESULT]);
        assert!(page.more_data);

        let page = implemented(0x017d, 1);
        assert_eq!(page.entries, [TPMA_CC_HASH]);
        assert!(page.more_data);

        let page = implemented(0x017e, 1000);
        assert!(!page.entries.contains(&TPMA_CC_HASH));
    }

    #[test]
    fn read_public_and_verify_signature_are_advertised_between_nv_read_public_and_get_capability() {
        let page = implemented(0x0169, 4);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_READ_PUBLIC,
                TPMA_CC_POLICY_AUTHORIZE,
                TPMA_CC_POLICY_AUTH_VALUE,
                TPMA_CC_POLICY_COMMAND_CODE
            ]
        );
        assert!(page.more_data);

        let page = implemented(0x0173, 1);
        assert_eq!(page.entries, [TPMA_CC_READ_PUBLIC]);
        assert!(page.more_data);

        let page = implemented(0x0174, 3);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_RSA_ENCRYPT,
                TPMA_CC_START_AUTH_SESSION,
                TPMA_CC_VERIFY_SIGNATURE
            ],
            "the unimplemented codes between them are skipped"
        );
        assert!(page.more_data);

        let page = implemented(0x0177, 1);
        assert_eq!(page.entries, [TPMA_CC_VERIFY_SIGNATURE]);
        assert!(page.more_data);

        let page = implemented(0x0178, 1000);
        assert!(!page.entries.contains(&TPMA_CC_READ_PUBLIC));
        assert!(!page.entries.contains(&TPMA_CC_VERIFY_SIGNATURE));
    }

    #[test]
    fn a_start_above_the_last_command_is_empty() {
        let page = implemented(0x019d, 10);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn pcr_extend_is_advertised_from_its_own_command_code() {
        let page = implemented(0x0182, 13);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_PCR_EXTEND,
                TPMA_CC_NV_CERTIFY,
                TPMA_CC_EVENT_SEQUENCE_COMPLETE,
                TPMA_CC_HASH_SEQUENCE_START,
                TPMA_CC_POLICY_PHYSICAL_PRESENCE,
                TPMA_CC_POLICY_DUPLICATION_SELECT,
                TPMA_CC_POLICY_GET_DIGEST,
                TPMA_CC_POLICY_PASSWORD,
                TPMA_CC_POLICY_NV_WRITTEN,
                TPMA_CC_POLICY_TEMPLATE,
                TPMA_CC_CREATE_LOADED,
                TPMA_CC_POLICY_AUTHORIZE_NV,
                TPMA_CC_POLICY_CAPABILITY
            ]
        );
        assert!(page.more_data);
    }

    #[test]
    fn nv_certify_is_advertised_last() {
        let page = implemented(0x0184, 12);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_CERTIFY,
                TPMA_CC_EVENT_SEQUENCE_COMPLETE,
                TPMA_CC_HASH_SEQUENCE_START,
                TPMA_CC_POLICY_PHYSICAL_PRESENCE,
                TPMA_CC_POLICY_DUPLICATION_SELECT,
                TPMA_CC_POLICY_GET_DIGEST,
                TPMA_CC_POLICY_PASSWORD,
                TPMA_CC_POLICY_NV_WRITTEN,
                TPMA_CC_POLICY_TEMPLATE,
                TPMA_CC_CREATE_LOADED,
                TPMA_CC_POLICY_AUTHORIZE_NV,
                TPMA_CC_POLICY_CAPABILITY
            ]
        );
        assert!(page.more_data);
        assert_eq!(
            implemented(0, 1000).entries.last(),
            Some(&TPMA_CC_POLICY_PARAMETERS)
        );
    }

    #[test]
    fn count_zero_reports_more_data_only_when_entries_remain() {
        let page = implemented(0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = implemented(0x019d, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn exact_and_oversized_counts_report_more_data_correctly() {
        let page = implemented(0, 90);
        assert_eq!(page.entries.len(), 90);
        assert!(!page.more_data);

        let page = implemented(0, 3);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL,
                TPMA_CC_EVICT_CONTROL,
                TPMA_CC_HIERARCHY_CONTROL
            ]
        );
        assert!(page.more_data);

        let page = implemented(0, u32::MAX);
        assert_eq!(page.entries.len(), 90);
        assert!(!page.more_data);
    }

    #[test]
    fn registry_counts_have_no_vendor_commands() {
        assert_eq!(total_count(), 90);
        assert_eq!(library_count(), 90);
        assert_eq!(vendor_count(), 0);
    }

    #[test]
    fn the_sequence_commands_are_advertised_with_their_reference_attributes() {
        let page = implemented(0, 1000);
        for (code, attributes) in [
            (0x0000_013eu32, TPMA_CC_SEQUENCE_COMPLETE),
            (0x0000_015b, TPMA_CC_HMAC_START),
            (0x0000_015c, TPMA_CC_SEQUENCE_UPDATE),
            (0x0000_0185, TPMA_CC_EVENT_SEQUENCE_COMPLETE),
            (0x0000_0186, TPMA_CC_HASH_SEQUENCE_START),
        ] {
            assert!(
                page.entries.contains(&attributes),
                "code {code:#010x} is advertised"
            );
            assert_eq!(attributes & 0xffff, code, "the command index is the code");
        }
    }

    #[test]
    fn the_capacity_constant_matches_upstream() {
        assert_eq!(MAX_CAP_CC, 254);
    }
}
