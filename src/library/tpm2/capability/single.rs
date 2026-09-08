use super::super::command::find_command;
use super::super::hierarchy::IMPLEMENTED_PERMANENT_HANDLES;
use super::super::marshal::BlobWriter;
use super::super::object::ATTR_OCCUPIED;
use super::super::persistent::OwnedUserNvramEntry;
use super::super::pp_list::physical_presence_is_required;
use super::super::runtime::Tpm2Runtime;
use super::super::state::MAX_ACTIVE_SESSIONS;
use super::super::volatile::IMPLEMENTATION_PCR;
use super::{
    TPM_CAP_ALGS, TPM_CAP_AUDIT_COMMANDS, TPM_CAP_AUTH_POLICIES, TPM_CAP_COMMANDS,
    TPM_CAP_ECC_CURVES, TPM_CAP_HANDLES, TPM_CAP_PCR_PROPERTIES, TPM_CAP_PP_COMMANDS,
    TPM_CAP_TPM_PROPERTIES, algorithms, audit_commands, auth_policies, ecc_curves, pcr_properties,
    properties,
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
        TPM_CAP_COMMANDS => Ok(command_attributes(runtime, property)),
        TPM_CAP_PP_COMMANDS => Ok(command_code_when(
            runtime.command_enabled(property) && physical_presence_is_required(runtime, property),
            property,
        )),
        TPM_CAP_AUDIT_COMMANDS => Ok(command_code_when(
            audit_commands::is_audited(runtime, property),
            property,
        )),
        TPM_CAP_PCR_PROPERTIES => Ok(pcr_properties::one(property)
            .map(|selection| selection.marshal())
            .unwrap_or_default()),
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

fn command_attributes(runtime: &Tpm2Runtime, property: u32) -> Vec<u8> {
    find_command(property)
        .filter(|_| runtime.command_enabled(property))
        .map(|descriptor| descriptor.attributes.to_be_bytes().to_vec())
        .unwrap_or_default()
}

fn command_code_when(found: bool, property: u32) -> Vec<u8> {
    if found {
        property.to_be_bytes().to_vec()
    } else {
        Vec::new()
    }
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
    let curve = property as u16;
    Ok(
        if u32::from(curve) == property && ecc_curves::is_usable(state, curve) {
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
    Ok(auth_policies::one(runtime, property)
        .map(|policy| policy.marshal())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::super::test_runtime::started;
    use super::*;
    use crate::library::tpm2::runtime::empty_state_runtime;

    const TPM_PT_PCR_SAVE: u32 = 0x0000_0000;
    const TPM_PT_PCR_AUTH: u32 = 0x0000_0014;
    const TPM_RH_OWNER: u32 = 0x4000_0001;

    #[test]
    fn null_profile_hides_disabled_single_command_capabilities() {
        let mut runtime = started();
        crate::library::tpm2::pp_list::require_physical_presence(&mut runtime, 0x19c);
        for capability in [TPM_CAP_COMMANDS, TPM_CAP_PP_COMMANDS] {
            assert_eq!(
                lookup(&runtime, capability, 0x19c),
                Ok(Vec::new()),
                "capability {capability:#x} excludes a profile-disabled command"
            );
        }
    }

    #[test]
    fn single_lookup_list_selector_equivalence() {
        let runtime = started();
        let state = runtime.state.as_ref().expect("decoded state");

        for entry in pcr_properties::collect(0, 1000).entries {
            assert_eq!(
                lookup(&runtime, TPM_CAP_PCR_PROPERTIES, entry.property),
                Ok(entry.marshal()),
                "{:#x}",
                entry.property
            );
        }
        for curve in ecc_curves::collect(state, 0, 1000).entries {
            assert_eq!(
                lookup(&runtime, TPM_CAP_ECC_CURVES, u32::from(curve)),
                Ok(curve.to_be_bytes().to_vec()),
                "{curve:#x}"
            );
        }
        for policy in auth_policies::collect(&runtime, 0x4000_0000, 1000).entries {
            assert_eq!(
                lookup(&runtime, TPM_CAP_AUTH_POLICIES, policy.handle),
                Ok(policy.marshal()),
                "{:#x}",
                policy.handle
            );
        }
        for code in audit_commands::collect(&runtime, 0, 1000).entries {
            assert_eq!(
                lookup(&runtime, TPM_CAP_AUDIT_COMMANDS, code),
                Ok(code.to_be_bytes().to_vec()),
                "{code:#x}"
            );
        }
    }

    #[test]
    fn single_lookup_absent_property_empty_result() {
        let runtime = started();
        for (capability, property) in [
            (TPM_CAP_PCR_PROPERTIES, 0x0000_000bu32),
            (TPM_CAP_PCR_PROPERTIES, TPM_PT_PCR_AUTH + 1),
            (TPM_CAP_ECC_CURVES, 0x0000_0006),
            (TPM_CAP_ECC_CURVES, 0x0001_0003),
            (TPM_CAP_AUTH_POLICIES, 0x4000_0007),
            (TPM_CAP_AUTH_POLICIES, 0x4000_0009),
            (TPM_CAP_AUTH_POLICIES, 0x4000_000d),
            (TPM_CAP_AUDIT_COMMANDS, 0x0000_017b),
        ] {
            assert_eq!(
                lookup(&runtime, capability, property),
                Ok(Vec::new()),
                "{capability:#x}/{property:#x}"
            );
        }
    }

    #[test]
    fn pcr_property_and_auth_policy_shared_marshalling() {
        let runtime = started();
        assert_eq!(
            lookup(&runtime, TPM_CAP_PCR_PROPERTIES, TPM_PT_PCR_SAVE),
            Ok(pcr_properties::one(TPM_PT_PCR_SAVE)
                .expect("implemented")
                .marshal())
        );
        assert_eq!(
            lookup(&runtime, TPM_CAP_AUTH_POLICIES, TPM_RH_OWNER),
            Ok(auth_policies::one(&runtime, TPM_RH_OWNER)
                .expect("the owner carries a policy")
                .marshal())
        );
    }

    #[test]
    fn unsupported_capability_report() {
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
    fn unsupported_handle_range_handle_error() {
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
    fn auth_policy_response_permanent_handles_only() {
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
