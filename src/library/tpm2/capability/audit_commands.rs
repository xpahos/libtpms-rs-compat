use super::super::command::{
    command_audit_is_required, upstream_command_codes, upstream_implements,
};
use super::super::runtime::Tpm2Runtime;
use super::commands::MAX_CAP_CC;
use super::{CapabilityPage, paginate};

pub(in crate::library::tpm2) fn is_audited(runtime: &Tpm2Runtime, code: u32) -> bool {
    upstream_implements(code) && command_audit_is_required(runtime, code)
}

pub(in crate::library::tpm2) fn collect(
    runtime: &Tpm2Runtime,
    starting_command: u32,
    requested_count: u32,
) -> CapabilityPage<u32> {
    paginate(
        upstream_command_codes()
            .filter(|&code| code >= starting_command && is_audited(runtime, code)),
        requested_count,
        MAX_CAP_CC,
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_runtime::started;
    use super::*;
    use crate::library::tpm2::audit::AUDIT_COMMANDS_SIZE;
    use crate::library::tpm2::command::command_bitmap_index;
    use crate::library::tpm2::persistent::OwnedCommandBitmap;

    const TPM_CC_GET_RANDOM: u32 = 0x0000_017b;
    const TPM_CC_NV_READ: u32 = 0x0000_014e;
    const TPM_CC_STARTUP: u32 = 0x0000_0144;
    const TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0000_0140;

    fn audited(runtime: &mut Tpm2Runtime, codes: &[u32]) {
        let mut bytes = vec![0u8; AUDIT_COMMANDS_SIZE];
        for &code in codes {
            let index = command_bitmap_index(code).expect("an upstream command index");
            bytes[index / 8] |= 1 << (index % 8);
        }
        runtime
            .state
            .as_mut()
            .expect("decoded state")
            .persistent
            .audit_commands = OwnedCommandBitmap {
            compressed: false,
            bytes,
        };
    }

    fn runtime() -> Box<Tpm2Runtime> {
        started()
    }

    #[test]
    fn a_manufactured_tpm_audits_the_command_that_maintains_the_list() {
        let runtime = runtime();
        let page = collect(&runtime, 0, 100);
        assert_eq!(page.entries, [TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS]);
        assert!(!page.more_data);
    }

    #[test]
    fn an_empty_audit_list_reports_no_more_data() {
        let mut runtime = runtime();
        audited(&mut runtime, &[]);
        let page = collect(&runtime, 0, 100);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
        let page = collect(&runtime, 0, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn the_audited_commands_are_returned_in_command_code_order() {
        let mut runtime = runtime();
        audited(
            &mut runtime,
            &[TPM_CC_GET_RANDOM, TPM_CC_STARTUP, TPM_CC_NV_READ],
        );
        let page = collect(&runtime, 0, 100);
        assert_eq!(
            page.entries,
            [TPM_CC_STARTUP, TPM_CC_NV_READ, TPM_CC_GET_RANDOM]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn the_starting_command_is_inclusive_and_skips_to_the_next_audited_command() {
        let mut runtime = runtime();
        audited(
            &mut runtime,
            &[TPM_CC_GET_RANDOM, TPM_CC_STARTUP, TPM_CC_NV_READ],
        );
        let page = collect(&runtime, TPM_CC_NV_READ, 100);
        assert_eq!(page.entries, [TPM_CC_NV_READ, TPM_CC_GET_RANDOM]);
        assert!(!page.more_data);

        let page = collect(&runtime, TPM_CC_NV_READ + 1, 100);
        assert_eq!(page.entries, [TPM_CC_GET_RANDOM]);
        assert!(!page.more_data);
    }

    #[test]
    fn a_start_past_the_last_audited_command_returns_an_empty_page() {
        let mut runtime = runtime();
        audited(&mut runtime, &[TPM_CC_STARTUP]);
        for start in [TPM_CC_STARTUP + 1, 0x0000_019d, 0x2000_0000, u32::MAX] {
            let page = collect(&runtime, start, 100);
            assert!(page.entries.is_empty(), "{start:#x}");
            assert!(!page.more_data, "{start:#x}");
        }
    }

    #[test]
    fn the_requested_count_truncates_the_page_and_reports_more_data() {
        let mut runtime = runtime();
        audited(
            &mut runtime,
            &[TPM_CC_GET_RANDOM, TPM_CC_STARTUP, TPM_CC_NV_READ],
        );
        let page = collect(&runtime, 0, 2);
        assert_eq!(page.entries, [TPM_CC_STARTUP, TPM_CC_NV_READ]);
        assert!(page.more_data);

        let page = collect(&runtime, 0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = collect(&runtime, 0, 3);
        assert_eq!(page.entries.len(), 3);
        assert!(!page.more_data);
    }

    #[test]
    fn the_capacity_matches_the_command_list_capacity() {
        assert_eq!(MAX_CAP_CC, 254);
    }
}
