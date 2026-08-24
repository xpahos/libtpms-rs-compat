use super::super::algorithm::TPM_ALG_NULL;
use super::super::command::{command_audit_is_required, find_command, upstream_implements};
use super::super::crypto::COMPILED_HASHES;
use super::super::entity::entity_auth_policy;
use super::super::hierarchy::IMPLEMENTED_PERMANENT_HANDLES;
use super::super::marshal::BlobWriter;
use super::super::object::ATTR_OCCUPIED;
use super::super::pcr::{
    pcr_auth_value_group, pcr_in_tcb_group, pcr_platform_attributes, pcr_policy_group,
};
use super::super::persistent::OwnedUserNvramEntry;
use super::super::pp_list::physical_presence_is_required;
use super::super::public::StateFormatLimit;
use super::super::runtime::Tpm2Runtime;
use super::super::state::MAX_ACTIVE_SESSIONS;
use super::super::template::AlgorithmPolicy;
use super::super::volatile::IMPLEMENTATION_PCR;
use super::{
    TPM_CAP_ALGS, TPM_CAP_AUDIT_COMMANDS, TPM_CAP_AUTH_POLICIES, TPM_CAP_COMMANDS,
    TPM_CAP_ECC_CURVES, TPM_CAP_HANDLES, TPM_CAP_PCR_PROPERTIES, TPM_CAP_PP_COMMANDS,
    TPM_CAP_TPM_PROPERTIES, algorithms, properties,
};

const HR_SHIFT: u32 = 24;
const HR_HANDLE_MASK: u32 = 0x00ff_ffff;

const TPM_HT_PCR: u32 = 0x00;
const TPM_HT_NV_INDEX: u32 = 0x01;
const TPM_HT_LOADED_SESSION: u32 = 0x02;
const TPM_HT_SAVED_SESSION: u32 = 0x03;
const TPM_HT_PERMANENT: u32 = 0x40;
const TPM_HT_TRANSIENT: u32 = 0x80;
const TPM_HT_PERSISTENT: u32 = 0x81;

const TPM_PT_PCR_SAVE: u32 = 0x0000_0000;
const TPM_PT_PCR_EXTEND_L0: u32 = 0x0000_0001;
const TPM_PT_PCR_RESET_L0: u32 = 0x0000_0002;
const TPM_PT_PCR_EXTEND_L1: u32 = 0x0000_0003;
const TPM_PT_PCR_RESET_L1: u32 = 0x0000_0004;
const TPM_PT_PCR_EXTEND_L2: u32 = 0x0000_0005;
const TPM_PT_PCR_RESET_L2: u32 = 0x0000_0006;
const TPM_PT_PCR_EXTEND_L3: u32 = 0x0000_0007;
const TPM_PT_PCR_RESET_L3: u32 = 0x0000_0008;
const TPM_PT_PCR_EXTEND_L4: u32 = 0x0000_0009;
const TPM_PT_PCR_RESET_L4: u32 = 0x0000_000a;
const TPM_PT_PCR_NO_INCREMENT: u32 = 0x0000_0011;
const TPM_PT_PCR_DRTM_RESET: u32 = 0x0000_0012;
const TPM_PT_PCR_POLICY: u32 = 0x0000_0013;
const TPM_PT_PCR_AUTH: u32 = 0x0000_0014;

const PCR_SELECT_BYTES: usize = IMPLEMENTATION_PCR.div_ceil(8);

#[derive(Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum LookupError {
    Capability,
    Property,
    HandleType,
    Internal,
}

pub(in crate::library::tpm2) fn lookup(
    runtime: &Tpm2Runtime,
    capability: u32,
    property: u32,
) -> Result<Vec<u8>, LookupError> {
    match capability {
        TPM_CAP_ALGS => Ok(algorithm_property(runtime, property)),
        TPM_CAP_HANDLES => handle_property(runtime, property),
        TPM_CAP_COMMANDS => Ok(command_attributes(property)),
        TPM_CAP_PP_COMMANDS => Ok(command_code_when(
            physical_presence_is_required(runtime, property),
            property,
        )),
        TPM_CAP_AUDIT_COMMANDS => Ok(command_code_when(
            upstream_implements(property) && command_audit_is_required(runtime, property),
            property,
        )),
        TPM_CAP_PCR_PROPERTIES => Ok(pcr_property(property)),
        TPM_CAP_TPM_PROPERTIES => tpm_property(runtime, property),
        TPM_CAP_ECC_CURVES => ecc_curve(runtime, property),
        TPM_CAP_AUTH_POLICIES => auth_policy(runtime, property),
        _ => Err(LookupError::Capability),
    }
}

fn algorithm_property(runtime: &Tpm2Runtime, property: u32) -> Vec<u8> {
    let Some(state) = runtime.state.as_ref() else {
        return Vec::new();
    };
    if u32::from(property as u16) != property {
        return Vec::new();
    }
    let Some(found) = algorithms::one(&state.profile.algorithms, property as u16) else {
        return Vec::new();
    };
    let mut writer = BlobWriter::with_capacity(6);
    writer.write_u16(found.algorithm);
    writer.write_u32(found.attributes);
    writer.into_bytes()
}

fn handle_property(runtime: &Tpm2Runtime, property: u32) -> Result<Vec<u8>, LookupError> {
    let found = match property >> HR_SHIFT {
        TPM_HT_TRANSIENT => transient_at_or_after(runtime, property),
        TPM_HT_PERSISTENT => user_nvram_holds(runtime, property, false),
        TPM_HT_NV_INDEX => user_nvram_holds(runtime, property, true),
        TPM_HT_LOADED_SESSION | TPM_HT_SAVED_SESSION => context_slot_is_used(runtime, property),
        TPM_HT_PCR => property & HR_HANDLE_MASK < IMPLEMENTATION_PCR as u32,
        TPM_HT_PERMANENT => IMPLEMENTED_PERMANENT_HANDLES.contains(&property),
        _ => return Err(LookupError::HandleType),
    };
    Ok(if found {
        property.to_be_bytes().to_vec()
    } else {
        Vec::new()
    })
}

fn transient_at_or_after(runtime: &Tpm2Runtime, property: u32) -> bool {
    let first = (property & HR_HANDLE_MASK) as usize;
    runtime
        .live
        .objects
        .iter()
        .skip(first)
        .any(|object| object.attributes & ATTR_OCCUPIED != 0)
}

fn user_nvram_holds(runtime: &Tpm2Runtime, property: u32, index: bool) -> bool {
    let Some(state) = runtime.state.as_ref() else {
        return false;
    };
    state.user_nvram.entries.iter().any(|entry| match entry {
        OwnedUserNvramEntry::NvIndex { handle, .. } => index && *handle == property,
        OwnedUserNvramEntry::Persistent { handle, .. } => !index && *handle == property,
    })
}

fn context_slot_is_used(runtime: &Tpm2Runtime, property: u32) -> bool {
    let slot = (property & HR_HANDLE_MASK) as usize;
    slot < MAX_ACTIVE_SESSIONS
        && runtime
            .live
            .state_reset
            .as_ref()
            .and_then(|reset| reset.context_array.get(slot))
            .is_some_and(|context| *context != 0)
}

// TODO: Answer from the vendored attribute table for every profile-enabled
// command once the registry covers it; TPM2_GetCapability reports the same
// ported subset today.
fn command_attributes(property: u32) -> Vec<u8> {
    match find_command(property) {
        Some(descriptor) => descriptor.attributes.to_be_bytes().to_vec(),
        None => Vec::new(),
    }
}

fn command_code_when(found: bool, property: u32) -> Vec<u8> {
    if found {
        property.to_be_bytes().to_vec()
    } else {
        Vec::new()
    }
}

fn pcr_selected(property: u32, pcr: usize) -> Option<bool> {
    let attributes = pcr_platform_attributes(pcr);
    Some(match property {
        TPM_PT_PCR_SAVE => attributes.state_save,
        TPM_PT_PCR_EXTEND_L0 => attributes.extend_locality & 0x01 != 0,
        TPM_PT_PCR_RESET_L0 => attributes.reset_locality & 0x01 != 0,
        TPM_PT_PCR_EXTEND_L1 => attributes.extend_locality & 0x02 != 0,
        TPM_PT_PCR_RESET_L1 => attributes.reset_locality & 0x02 != 0,
        TPM_PT_PCR_EXTEND_L2 => attributes.extend_locality & 0x04 != 0,
        TPM_PT_PCR_RESET_L2 => attributes.reset_locality & 0x04 != 0,
        TPM_PT_PCR_EXTEND_L3 => attributes.extend_locality & 0x08 != 0,
        TPM_PT_PCR_RESET_L3 => attributes.reset_locality & 0x08 != 0,
        TPM_PT_PCR_EXTEND_L4 => attributes.extend_locality & 0x10 != 0,
        TPM_PT_PCR_RESET_L4 | TPM_PT_PCR_DRTM_RESET => attributes.reset_locality & 0x10 != 0,
        TPM_PT_PCR_POLICY => pcr_policy_group(pcr).is_some(),
        TPM_PT_PCR_AUTH => pcr_auth_value_group(pcr).is_some(),
        TPM_PT_PCR_NO_INCREMENT => pcr_in_tcb_group(pcr),
        _ => return None,
    })
}

fn pcr_property(property: u32) -> Vec<u8> {
    let mut select = vec![0u8; PCR_SELECT_BYTES];
    for pcr in 0..IMPLEMENTATION_PCR {
        match pcr_selected(property, pcr) {
            Some(true) => select[pcr / 8] |= 1 << (pcr % 8),
            Some(false) => {}
            None => return Vec::new(),
        }
    }
    let mut writer = BlobWriter::with_capacity(4 + 1 + select.len());
    writer.write_u32(property);
    writer.write_u8(PCR_SELECT_BYTES as u8);
    writer.write_bytes(&select);
    writer.into_bytes()
}

fn tpm_property(runtime: &Tpm2Runtime, property: u32) -> Result<Vec<u8>, LookupError> {
    let state = runtime.state.as_ref().ok_or(LookupError::Internal)?;
    let Some(value) = properties::property_value(runtime, state, property) else {
        return Ok(Vec::new());
    };
    let mut writer = BlobWriter::with_capacity(8);
    writer.write_u32(property);
    writer.write_u32(value);
    Ok(writer.into_bytes())
}

fn ecc_curve(runtime: &Tpm2Runtime, property: u32) -> Result<Vec<u8>, LookupError> {
    let state = runtime.state.as_ref().ok_or(LookupError::Internal)?;
    let policy = AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    };
    let curve = property as u16;
    Ok(
        if u32::from(curve) == property && policy.curve_allowed(curve) {
            curve.to_be_bytes().to_vec()
        } else {
            Vec::new()
        },
    )
}

fn auth_policy(runtime: &Tpm2Runtime, property: u32) -> Result<Vec<u8>, LookupError> {
    if property >> HR_SHIFT != TPM_HT_PERMANENT {
        return Err(LookupError::Property);
    }
    if !IMPLEMENTED_PERMANENT_HANDLES.contains(&property) {
        return Ok(Vec::new());
    }
    let Ok((hash_alg, digest)) = entity_auth_policy(runtime, property) else {
        return Ok(Vec::new());
    };
    let mut writer = BlobWriter::with_capacity(4 + 2 + digest.len());
    writer.write_u32(property);
    writer.write_u16(hash_alg);
    if hash_alg != TPM_ALG_NULL {
        let size = COMPILED_HASHES
            .iter()
            .find(|(algorithm, _)| *algorithm == hash_alg)
            .map(|(_, size)| *size)
            .ok_or(LookupError::Internal)?;
        let mut padded = digest;
        padded.resize(size, 0);
        writer.write_bytes(&padded);
    }
    Ok(writer.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::runtime::empty_state_runtime;

    #[test]
    fn the_pcr_property_selectors_match_the_vendored_table() {
        assert_eq!(PCR_SELECT_BYTES, 3);
        let save = pcr_property(TPM_PT_PCR_SAVE);
        assert_eq!(&save[..4], &TPM_PT_PCR_SAVE.to_be_bytes());
        assert_eq!(save[4], 3);
        assert_eq!(&save[5..], &[0xff, 0xff, 0x00]);

        let extend_l4 = pcr_property(TPM_PT_PCR_EXTEND_L4);
        assert_eq!(&extend_l4[5..], &[0xff, 0xff, 0x87]);

        let drtm = pcr_property(TPM_PT_PCR_DRTM_RESET);
        assert_eq!(pcr_property(TPM_PT_PCR_RESET_L4)[5..], drtm[5..]);
        assert_eq!(&drtm[5..], &[0x00, 0x00, 0x7e]);

        assert!(pcr_property(TPM_PT_PCR_POLICY).ends_with(&[0x00, 0x00, 0x00]));
        assert!(pcr_property(TPM_PT_PCR_AUTH).ends_with(&[0x00, 0x00, 0x00]));
        assert_eq!(
            &pcr_property(TPM_PT_PCR_NO_INCREMENT)[5..],
            &[0x00, 0x00, 0xe1]
        );
    }

    #[test]
    fn an_unsupported_pcr_property_answers_nothing() {
        for property in [0x0000_000bu32, 0x0000_0010, 0x0000_0015, 0xffff_ffff] {
            assert!(pcr_property(property).is_empty(), "{property:#x}");
        }
    }

    #[test]
    fn an_unsupported_capability_is_reported_as_such() {
        let runtime = empty_state_runtime();
        for capability in [0x0000_0005u32, 0x0000_000a, 0x0000_0100, 0xdead_beef] {
            assert_eq!(
                lookup(&runtime, capability, 0),
                Err(LookupError::Capability),
                "{capability:#x}"
            );
        }
    }

    #[test]
    fn an_unsupported_handle_range_is_reported_as_a_handle_error() {
        let runtime = empty_state_runtime();
        for property in [0x0400_0000u32, 0x8200_0000, 0xff00_0000] {
            assert_eq!(
                lookup(&runtime, TPM_CAP_HANDLES, property),
                Err(LookupError::HandleType),
                "{property:#x}"
            );
        }
    }

    #[test]
    fn auth_policies_only_answer_for_permanent_handles() {
        let runtime = empty_state_runtime();
        assert_eq!(
            lookup(&runtime, TPM_CAP_AUTH_POLICIES, 0x8000_0000),
            Err(LookupError::Property)
        );
        assert_eq!(
            lookup(&runtime, TPM_CAP_AUTH_POLICIES, 0x4000_0002),
            Ok(Vec::new()),
            "an unimplemented permanent handle carries no policy"
        );
    }
}
