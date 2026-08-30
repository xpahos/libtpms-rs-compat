pub(super) mod algorithms;
pub(super) mod audit_commands;
pub(super) mod auth_policies;
pub(super) mod commands;
pub(super) mod ecc_curves;
pub(super) mod handles;
pub(super) mod pcr_properties;
pub(super) mod pcrs;
pub(super) mod properties;
pub(super) mod single;

pub(super) const TPM_CAP_ALGS: u32 = 0x0000_0000;
pub(super) const TPM_CAP_HANDLES: u32 = 0x0000_0001;
pub(super) const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
pub(super) const TPM_CAP_PP_COMMANDS: u32 = 0x0000_0003;
pub(super) const TPM_CAP_AUDIT_COMMANDS: u32 = 0x0000_0004;
pub(super) const TPM_CAP_PCRS: u32 = 0x0000_0005;
pub(super) const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
pub(super) const TPM_CAP_PCR_PROPERTIES: u32 = 0x0000_0007;
pub(super) const TPM_CAP_ECC_CURVES: u32 = 0x0000_0008;
pub(super) const TPM_CAP_AUTH_POLICIES: u32 = 0x0000_0009;
pub(super) const TPM_CAP_ACT: u32 = 0x0000_000a;
pub(super) const TPM_CAP_VENDOR_PROPERTY: u32 = 0x0000_0100;

pub(super) const MAX_CAP_BUFFER: usize = 1024;
pub(super) const MAX_CAP_DATA: usize = MAX_CAP_BUFFER - 4 - 4;

pub(super) struct CapabilityPage<T> {
    pub(super) entries: Vec<T>,
    pub(super) more_data: bool,
}

impl<T> CapabilityPage<T> {
    pub(super) fn empty() -> Self {
        Self {
            entries: Vec::new(),
            more_data: false,
        }
    }
}

pub(super) fn paginate<T>(
    eligible: impl Iterator<Item = T>,
    requested_count: u32,
    capacity: usize,
) -> CapabilityPage<T> {
    let limit = usize::try_from(requested_count)
        .unwrap_or(usize::MAX)
        .min(capacity);
    let mut entries = Vec::with_capacity(limit);
    let mut more_data = false;
    for entry in eligible {
        if entries.len() < limit {
            entries.push(entry);
        } else {
            more_data = true;
            break;
        }
    }
    CapabilityPage { entries, more_data }
}

#[cfg(test)]
pub(in crate::library::tpm2) mod test_runtime {
    use crate::library::CommandInput;
    use crate::library::tpm2::command::{dispatch, parse_command};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{Tpm2Runtime, commit_manufactured_state};

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), crate::types::TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x4b;
        }
        Ok(())
    }

    pub(in crate::library::tpm2) fn started() -> Tpm2Runtime {
        started_with_profile(None)
    }

    pub(in crate::library::tpm2) fn started_with_algorithms(algorithms: &str) -> Tpm2Runtime {
        let json = format!(r#"{{"Name":"custom","Algorithms":"{algorithms}"}}"#);
        started_with_profile(Some(json))
    }

    fn started_with_profile(json: Option<String>) -> Tpm2Runtime {
        let profile = validate_user_profile(json.as_ref().map(|text| text.as_bytes()))
            .expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let bytes = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0, 0,
        ];
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let parsed = parse_command(&input).expect("the header parses");
        assert_eq!(
            dispatch(
                &mut runtime,
                &parsed,
                crate::library::cancel::Cancellation::disabled()
            )
            .code(),
            0,
            "Startup succeeds"
        );
        runtime.nv_update_pending = false;
        runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_requested_count_cap() {
        let page = paginate(0u32..10, 3, 100);
        assert_eq!(page.entries, [0, 1, 2]);
        assert!(page.more_data);
    }

    #[test]
    fn pagination_capacity_count_cap() {
        let page = paginate(0u32..10, 1000, 4);
        assert_eq!(page.entries, [0, 1, 2, 3]);
        assert!(page.more_data);
    }

    #[test]
    fn count_zero_existing_entry_more_data() {
        let page = paginate(0u32..10, 0, 100);
        assert!(page.entries.is_empty());
        assert!(page.more_data);
    }

    #[test]
    fn count_zero_no_eligible_entries_no_more_data() {
        let page = paginate(core::iter::empty::<u32>(), 0, 100);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn exactly_consumed_iterator_no_more_data() {
        let page = paginate(0u32..4, 4, 100);
        assert_eq!(page.entries, [0, 1, 2, 3]);
        assert!(!page.more_data);
    }

    #[test]
    fn oversized_count_allocation_bound() {
        let page = paginate(core::iter::empty::<u32>(), u32::MAX, 254);
        assert!(page.entries.capacity() <= 254);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }
}
