use super::super::command::implemented_commands;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const SIZEOF_TPM_CC: usize = 4;
pub(super) const MAX_CAP_CC: usize = MAX_CAP_DATA / SIZEOF_TPM_CC;

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
    const TPMA_CC_NV_UNDEFINE_SPACE: u32 = 0x0440_0122;
    const TPMA_CC_CHANGE_EPS: u32 = 0x02c0_0124;
    const TPMA_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0240_0129;
    const TPMA_CC_NV_DEFINE_SPACE: u32 = 0x0240_012a;
    const TPMA_CC_NV_GLOBAL_WRITE_LOCK: u32 = 0x0240_0132;
    const TPMA_CC_NV_INCREMENT: u32 = 0x0440_0134;
    const TPMA_CC_NV_SET_BITS: u32 = 0x0440_0135;
    const TPMA_CC_NV_EXTEND: u32 = 0x0440_0136;
    const TPMA_CC_NV_WRITE: u32 = 0x0440_0137;
    const TPMA_CC_NV_WRITE_LOCK: u32 = 0x0440_0138;
    const TPMA_CC_DICTIONARY_ATTACK_PARAMETERS: u32 = 0x0240_013a;
    const TPMA_CC_NV_CHANGE_AUTH: u32 = 0x0240_013b;
    const TPMA_CC_PCR_EVENT: u32 = 0x0200_013c;
    const TPMA_CC_NV_READ: u32 = 0x0400_014e;
    const TPMA_CC_NV_READ_LOCK: u32 = 0x0440_014f;
    const TPMA_CC_CREATE: u32 = 0x0200_0153;
    const TPMA_CC_SIGN: u32 = 0x0200_015d;
    const TPMA_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
    const TPMA_CC_NV_READ_PUBLIC: u32 = 0x0200_0169;
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

    #[test]
    fn a_query_from_zero_returns_every_registry_command() {
        let page = implemented(0, 1000);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL,
                TPMA_CC_EVICT_CONTROL,
                TPMA_CC_NV_UNDEFINE_SPACE,
                TPMA_CC_CHANGE_EPS,
                TPMA_CC_HIERARCHY_CHANGE_AUTH,
                TPMA_CC_NV_DEFINE_SPACE,
                TPMA_CC_PCR_ALLOCATE,
                TPMA_CC_CREATE_PRIMARY,
                TPMA_CC_NV_GLOBAL_WRITE_LOCK,
                TPMA_CC_NV_INCREMENT,
                TPMA_CC_NV_SET_BITS,
                TPMA_CC_NV_EXTEND,
                TPMA_CC_NV_WRITE,
                TPMA_CC_NV_WRITE_LOCK,
                TPMA_CC_DICTIONARY_ATTACK_PARAMETERS,
                TPMA_CC_NV_CHANGE_AUTH,
                TPMA_CC_PCR_EVENT,
                TPMA_CC_PCR_RESET,
                TPMA_CC_INCREMENTAL_SELF_TEST,
                TPMA_CC_SELF_TEST,
                TPMA_CC_STARTUP,
                TPMA_CC_SHUTDOWN,
                TPMA_CC_STIR_RANDOM,
                TPMA_CC_NV_READ,
                TPMA_CC_NV_READ_LOCK,
                TPMA_CC_CREATE,
                TPMA_CC_SIGN,
                TPMA_CC_FLUSH_CONTEXT,
                TPMA_CC_NV_READ_PUBLIC,
                TPMA_CC_GET_CAPABILITY,
                TPMA_CC_GET_RANDOM,
                TPMA_CC_GET_TEST_RESULT,
                TPMA_CC_HASH,
                TPMA_CC_PCR_READ,
                TPMA_CC_PCR_EXTEND,
                TPMA_CC_NV_CERTIFY,
                TPMA_CC_CREATE_LOADED
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
        assert_eq!(page.entries.len(), 36);
        assert_eq!(page.entries[0], TPMA_CC_EVICT_CONTROL);

        let page = implemented(0x0121, 1000);
        assert_eq!(page.entries.len(), 35);
        assert!(!page.entries.contains(&TPMA_CC_EVICT_CONTROL));
    }

    #[test]
    fn change_eps_follows_nv_undefine_space() {
        let page = implemented(0x0121, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_UNDEFINE_SPACE]);
        assert!(page.more_data);

        let page = implemented(0x0124, 1000);
        assert_eq!(page.entries.len(), 34);
        assert_eq!(page.entries[0], TPMA_CC_CHANGE_EPS);

        let page = implemented(0x0125, 1000);
        assert_eq!(page.entries.len(), 33);
        assert!(!page.entries.contains(&TPMA_CC_CHANGE_EPS));
    }

    #[test]
    fn hierarchy_change_auth_follows_change_eps() {
        let page = implemented(0x0125, 1);
        assert_eq!(page.entries, [TPMA_CC_HIERARCHY_CHANGE_AUTH]);
        assert!(page.more_data);

        let page = implemented(0x0129, 1000);
        assert_eq!(page.entries.len(), 33);
        assert_eq!(page.entries[0], TPMA_CC_HIERARCHY_CHANGE_AUTH);

        let page = implemented(0x012a, 1000);
        assert_eq!(page.entries.len(), 32);
        assert!(!page.entries.contains(&TPMA_CC_HIERARCHY_CHANGE_AUTH));
    }

    #[test]
    fn nv_define_space_follows_hierarchy_change_auth() {
        let page = implemented(0x012a, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_DEFINE_SPACE]);
        assert!(page.more_data);

        let page = implemented(0x012b, 1000);
        assert_eq!(page.entries.len(), 31);
        assert_eq!(page.entries[0], TPMA_CC_PCR_ALLOCATE);

        let page = implemented(0x012c, 1000);
        assert_eq!(page.entries.len(), 30);
        assert!(!page.entries.contains(&TPMA_CC_PCR_ALLOCATE));
    }

    #[test]
    fn create_primary_follows_pcr_allocate() {
        let page = implemented(0x012c, 1);
        assert_eq!(page.entries, [TPMA_CC_CREATE_PRIMARY]);
        assert!(page.more_data);

        let page = implemented(0x0131, 1000);
        assert_eq!(page.entries.len(), 30);
        assert_eq!(page.entries[0], TPMA_CC_CREATE_PRIMARY);

        let page = implemented(0x0132, 1000);
        assert_eq!(page.entries.len(), 29);
        assert!(!page.entries.contains(&TPMA_CC_CREATE_PRIMARY));
    }

    #[test]
    fn nv_global_write_lock_follows_create_primary() {
        let page = implemented(0x0132, 1);
        assert_eq!(page.entries, [TPMA_CC_NV_GLOBAL_WRITE_LOCK]);
        assert!(page.more_data);

        let page = implemented(0x013d, 1000);
        assert_eq!(page.entries.len(), 20);
        assert_eq!(page.entries[0], TPMA_CC_PCR_RESET);

        let page = implemented(0x013e, 1000);
        assert_eq!(page.entries.len(), 19);
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
        let page = implemented(0x014e, 4);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_READ,
                TPMA_CC_NV_READ_LOCK,
                TPMA_CC_CREATE,
                TPMA_CC_SIGN
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

        let page = implemented(0x013e, 1);
        assert_eq!(page.entries, [TPMA_CC_INCREMENTAL_SELF_TEST]);
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
        let page = implemented(0x0147, 10);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_READ,
                TPMA_CC_NV_READ_LOCK,
                TPMA_CC_CREATE,
                TPMA_CC_SIGN,
                TPMA_CC_FLUSH_CONTEXT,
                TPMA_CC_NV_READ_PUBLIC,
                TPMA_CC_GET_CAPABILITY,
                TPMA_CC_GET_RANDOM,
                TPMA_CC_GET_TEST_RESULT,
                TPMA_CC_HASH
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
    fn a_start_above_the_last_command_is_empty() {
        let page = implemented(0x0192, 10);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn pcr_extend_is_advertised_from_its_own_command_code() {
        let page = implemented(0x0182, 10);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_PCR_EXTEND,
                TPMA_CC_NV_CERTIFY,
                TPMA_CC_CREATE_LOADED
            ]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn nv_certify_is_advertised_last() {
        let page = implemented(0x0184, 10);
        assert_eq!(page.entries, [TPMA_CC_NV_CERTIFY, TPMA_CC_CREATE_LOADED]);
        assert!(!page.more_data);
        assert_eq!(
            implemented(0, 1000).entries.last(),
            Some(&TPMA_CC_CREATE_LOADED)
        );
    }

    #[test]
    fn count_zero_reports_more_data_only_when_entries_remain() {
        let page = implemented(0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = implemented(0x0192, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn exact_and_oversized_counts_report_more_data_correctly() {
        let page = implemented(0, 37);
        assert_eq!(page.entries.len(), 37);
        assert!(!page.more_data);

        let page = implemented(0, 3);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_NV_UNDEFINE_SPACE_SPECIAL,
                TPMA_CC_EVICT_CONTROL,
                TPMA_CC_NV_UNDEFINE_SPACE
            ]
        );
        assert!(page.more_data);

        let page = implemented(0, u32::MAX);
        assert_eq!(page.entries.len(), 37);
        assert!(!page.more_data);
    }

    #[test]
    fn registry_counts_have_no_vendor_commands() {
        assert_eq!(total_count(), 37);
        assert_eq!(library_count(), 37);
        assert_eq!(vendor_count(), 0);
    }

    #[test]
    fn the_capacity_constant_matches_upstream() {
        assert_eq!(MAX_CAP_CC, 254);
    }
}
