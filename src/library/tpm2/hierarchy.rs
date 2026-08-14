pub(super) const TPM_RH_OWNER: u32 = 0x4000_0001;
pub(super) const TPM_RH_NULL: u32 = 0x4000_0007;
pub(super) const TPM_RH_LOCKOUT: u32 = 0x4000_000a;
pub(super) const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
pub(super) const TPM_RH_PLATFORM: u32 = 0x4000_000c;

pub(super) fn is_hierarchy_auth_handle(handle: u32) -> bool {
    matches!(
        handle,
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_LOCKOUT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_permanent_handle_values_match_upstream() {
        assert_eq!(TPM_RH_OWNER, 0x4000_0001);
        assert_eq!(TPM_RH_NULL, 0x4000_0007);
        assert_eq!(TPM_RH_LOCKOUT, 0x4000_000a);
        assert_eq!(TPM_RH_ENDORSEMENT, 0x4000_000b);
        assert_eq!(TPM_RH_PLATFORM, 0x4000_000c);
    }

    #[test]
    fn exactly_the_four_tpmi_rh_hierarchy_auth_handles_are_accepted() {
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_PLATFORM,
            TPM_RH_LOCKOUT,
        ] {
            assert!(is_hierarchy_auth_handle(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn every_other_permanent_handle_is_rejected() {
        for handle in 0x4000_0000..=0x4000_0020u32 {
            let accepted = matches!(
                handle,
                0x4000_0001 | 0x4000_000a | 0x4000_000b | 0x4000_000c
            );
            assert_eq!(
                is_hierarchy_auth_handle(handle),
                accepted,
                "handle {handle:#x}"
            );
        }
    }

    #[test]
    fn non_permanent_handle_ranges_are_rejected() {
        for handle in [
            0x0000_0000u32,
            0x0000_0017,
            0x0100_0000,
            0x0200_0000,
            0x0300_0000,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert!(!is_hierarchy_auth_handle(handle), "handle {handle:#x}");
        }
    }
}
