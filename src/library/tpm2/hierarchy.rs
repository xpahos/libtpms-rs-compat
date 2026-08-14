use super::persistent::OwnedPersistentData;

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

pub(super) fn hierarchy_proof(persistent: &OwnedPersistentData, hierarchy: u32) -> Option<&[u8]> {
    match hierarchy {
        TPM_RH_PLATFORM => Some(persistent.ph_proof.as_bytes()),
        TPM_RH_OWNER => Some(persistent.sh_proof.as_bytes()),
        TPM_RH_ENDORSEMENT => Some(persistent.eh_proof.as_bytes()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_types::TpmResult;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x63;
        }
        Ok(())
    }

    fn manufactured_persistent() -> Box<crate::library::tpm2::Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        commit_manufactured_state(state).expect("commits")
    }

    #[test]
    fn each_hierarchy_selects_its_own_proof() {
        let runtime = manufactured_persistent();
        let persistent = &runtime.state().persistent;
        assert!(persistent.ph_proof.expose() != persistent.sh_proof.expose());
        assert!(persistent.ph_proof.expose() != persistent.eh_proof.expose());
        assert!(persistent.sh_proof.expose() != persistent.eh_proof.expose());

        assert_eq!(
            hierarchy_proof(persistent, TPM_RH_PLATFORM),
            Some(persistent.ph_proof.expose())
        );
        assert_eq!(
            hierarchy_proof(persistent, TPM_RH_OWNER),
            Some(persistent.sh_proof.expose())
        );
        assert_eq!(
            hierarchy_proof(persistent, TPM_RH_ENDORSEMENT),
            Some(persistent.eh_proof.expose())
        );
    }

    #[test]
    fn every_selected_proof_has_the_full_proof_size() {
        let runtime = manufactured_persistent();
        let persistent = &runtime.state().persistent;
        for hierarchy in [TPM_RH_PLATFORM, TPM_RH_OWNER, TPM_RH_ENDORSEMENT] {
            assert_eq!(
                hierarchy_proof(persistent, hierarchy).map(<[u8]>::len),
                Some(64),
                "hierarchy {hierarchy:#010x}"
            );
        }
    }

    #[test]
    fn the_null_hierarchy_and_every_other_handle_select_no_proof() {
        let runtime = manufactured_persistent();
        let persistent = &runtime.state().persistent;
        for hierarchy in [
            TPM_RH_NULL,
            TPM_RH_LOCKOUT,
            0x0000_0000,
            0x0000_0017,
            0x4000_0000,
            0x4000_0009,
            0x4000_000d,
            0x8000_0000,
            u32::MAX,
        ] {
            assert!(
                hierarchy_proof(persistent, hierarchy).is_none(),
                "hierarchy {hierarchy:#010x}"
            );
        }
    }

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
