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

    const TPMA_CC_STARTUP: u32 = 0x0040_0144;
    const TPMA_CC_SHUTDOWN: u32 = 0x0040_0145;
    const TPMA_CC_GET_CAPABILITY: u32 = 0x0000_017a;
    const TPMA_CC_PCR_READ: u32 = 0x0000_017e;
    const TPMA_CC_PCR_EXTEND: u32 = 0x0200_0182;

    #[test]
    fn a_query_from_zero_returns_every_registry_command() {
        let page = implemented(0, 1000);
        assert_eq!(
            page.entries,
            [
                TPMA_CC_STARTUP,
                TPMA_CC_SHUTDOWN,
                TPMA_CC_GET_CAPABILITY,
                TPMA_CC_PCR_READ,
                TPMA_CC_PCR_EXTEND
            ]
        );
        assert!(!page.more_data);
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
        let page = implemented(0x0146, 3);
        assert_eq!(
            page.entries,
            [TPMA_CC_GET_CAPABILITY, TPMA_CC_PCR_READ, TPMA_CC_PCR_EXTEND]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn a_start_above_the_last_command_is_empty() {
        let page = implemented(0x0183, 10);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn pcr_extend_is_advertised_from_its_own_command_code() {
        let page = implemented(0x0182, 10);
        assert_eq!(page.entries, [TPMA_CC_PCR_EXTEND]);
        assert!(!page.more_data);
    }

    #[test]
    fn count_zero_reports_more_data_only_when_entries_remain() {
        let page = implemented(0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = implemented(0x0183, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn exact_and_oversized_counts_report_more_data_correctly() {
        let page = implemented(0, 5);
        assert_eq!(page.entries.len(), 5);
        assert!(!page.more_data);

        let page = implemented(0, 3);
        assert_eq!(
            page.entries,
            [TPMA_CC_STARTUP, TPMA_CC_SHUTDOWN, TPMA_CC_GET_CAPABILITY]
        );
        assert!(page.more_data);

        let page = implemented(0, u32::MAX);
        assert_eq!(page.entries.len(), 5);
        assert!(!page.more_data);
    }

    #[test]
    fn registry_counts_have_no_vendor_commands() {
        assert_eq!(total_count(), 5);
        assert_eq!(library_count(), 5);
        assert_eq!(vendor_count(), 0);
    }

    #[test]
    fn the_capacity_constant_matches_upstream() {
        assert_eq!(MAX_CAP_CC, 254);
    }
}
