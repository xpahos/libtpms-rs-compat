use super::persistent::OwnedPersistentData;

pub(super) const TPM_RH_OWNER: u32 = 0x4000_0001;
pub(super) const TPM_RH_NULL: u32 = 0x4000_0007;
pub(super) const TPM_RH_UNASSIGNED: u32 = 0x4000_0008;
pub(super) const TPM_RS_PW: u32 = 0x4000_0009;
pub(super) const TPM_RH_LOCKOUT: u32 = 0x4000_000a;
pub(super) const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
pub(super) const TPM_RH_PLATFORM: u32 = 0x4000_000c;
pub(super) const TPM_RH_PLATFORM_NV: u32 = 0x4000_000d;
pub(super) const TPM_RH_ACT_0: u32 = 0x4000_0110;
pub(super) const TPM_RH_ACT_F: u32 = 0x4000_011f;

pub(super) const IMPLEMENTED_PERMANENT_HANDLES: [u32; 7] = [
    TPM_RH_OWNER,
    TPM_RH_NULL,
    TPM_RS_PW,
    TPM_RH_LOCKOUT,
    TPM_RH_ENDORSEMENT,
    TPM_RH_PLATFORM,
    TPM_RH_PLATFORM_NV,
];

pub(super) fn is_hierarchy_auth_handle(handle: u32) -> bool {
    matches!(
        handle,
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_LOCKOUT
    )
}

pub(super) fn is_hierarchy_handle(handle: u32) -> bool {
    matches!(
        handle,
        TPM_RH_OWNER | TPM_RH_ENDORSEMENT | TPM_RH_PLATFORM | TPM_RH_NULL
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
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    const ENTROPY: crate::library::tpm2::crypto::EntropySource =
        crate::library::tpm2::test_support::counter_entropy::<0x63>;

    fn manufactured_persistent() -> crate::library::tpm2::Tpm2Runtime {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, ENTROPY).expect("manufactures");
        commit_manufactured_state(state).expect("commits")
    }

    #[test]
    fn per_hierarchy_proof_selection() {
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
    fn selected_proof_full_size() {
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
    fn null_hierarchy_other_handles_no_proof() {
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
    fn permanent_handle_values_upstream_match() {
        assert_eq!(TPM_RH_OWNER, 0x4000_0001);
        assert_eq!(TPM_RH_NULL, 0x4000_0007);
        assert_eq!(TPM_RH_UNASSIGNED, 0x4000_0008);
        assert_eq!(TPM_RH_LOCKOUT, 0x4000_000a);
        assert_eq!(TPM_RH_ENDORSEMENT, 0x4000_000b);
        assert_eq!(TPM_RH_PLATFORM, 0x4000_000c);
        assert_eq!(TPM_RS_PW, 0x4000_0009);
        assert_eq!(TPM_RH_PLATFORM_NV, 0x4000_000d);
    }

    #[test]
    fn implemented_permanent_handles_oracle_match() {
        assert_eq!(
            IMPLEMENTED_PERMANENT_HANDLES,
            [
                0x4000_0001,
                0x4000_0007,
                0x4000_0009,
                0x4000_000a,
                0x4000_000b,
                0x4000_000c,
                0x4000_000d,
            ]
        );
        assert!(
            IMPLEMENTED_PERMANENT_HANDLES.is_sorted(),
            "the table is enumerated in ascending order"
        );
        assert!(
            !IMPLEMENTED_PERMANENT_HANDLES.contains(&TPM_RH_UNASSIGNED),
            "0x40000008 is a gap in the permanent range"
        );
    }

    #[test]
    fn hierarchy_auth_four_handle_acceptance() {
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
    fn other_permanent_handle_rejection() {
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
    fn non_permanent_handle_range_rejection() {
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
