use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_HIERARCHY, TPM_RC_INSUFFICIENT,
    TPM_RC_NV_DEFINED, TPM_RC_NV_SPACE, TPM_RC_NV_UNAVAILABLE, TPM_RC_RANGE, TPM_RC_SIZE,
    TPM_RC_VALUE,
};

use super::super::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::super::marshal::BlobReader;
use super::super::nv::{build_nv_image, persistent_object_image};
use super::super::object::{
    ATTR_EVICT, ATTR_PPS_HIERARCHY, ATTR_PUBLIC_ONLY, ATTR_ST_CLEAR, ATTR_TEMPORARY,
};
use super::super::object_create::{
    PERSISTENT_FIRST, PERSISTENT_LAST, PLATFORM_PERSISTENT, is_persistent_object_handle,
    is_transient_object_handle, occupied_object_slot, persistent_object_entry,
};
use super::super::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedUserNvramEntry, user_nvram_required_capacity,
};
use super::super::runtime::Tpm2Runtime;
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;

const RC_OBJECT_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_PERSISTENT_HANDLE: TpmResult = TPM_RC_P + TPM_RC_1;

const UNPERSISTABLE: u32 = ATTR_TEMPORARY | ATTR_ST_CLEAR | ATTR_PUBLIC_ONLY;

enum Target {
    Transient {
        slot: usize,
        attributes: u32,
    },
    Persistent {
        entry: usize,
        attributes: u32,
        evict_handle: u32,
    },
}

impl Target {
    fn attributes(&self) -> u32 {
        match *self {
            Self::Transient { attributes, .. } | Self::Persistent { attributes, .. } => attributes,
        }
    }

    fn is_evict(&self) -> bool {
        matches!(self, Self::Persistent { .. })
    }
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let object_handle = frame.handles.get(1).copied().ok_or(TPM_RC_FAILURE)?;
    let persistent_handle = parse_parameters(frame.parameters)?;

    let target = resolve(runtime, object_handle)?;
    validate(auth, &target, persistent_handle)?;

    match target {
        Target::Transient { slot, .. } => make_persistent(runtime, slot, persistent_handle),
        Target::Persistent { entry, .. } => remove_persistent(runtime, entry),
    }?;
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<u32, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let persistent_handle = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PERSISTENT_HANDLE)?;
    if !is_persistent_object_handle(persistent_handle) {
        return Err(TPM_RC_VALUE + RC_PERSISTENT_HANDLE);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(persistent_handle)
}

fn resolve(runtime: &Tpm2Runtime, object_handle: u32) -> Result<Target, TpmResult> {
    if is_transient_object_handle(object_handle) {
        let slot =
            occupied_object_slot(runtime, object_handle).ok_or(TPM_RC_HANDLE + RC_OBJECT_HANDLE)?;
        let attributes = runtime
            .live
            .objects
            .get(slot)
            .ok_or(TPM_RC_FAILURE)?
            .attributes;
        return Ok(Target::Transient { slot, attributes });
    }

    let entry =
        persistent_object_entry(runtime, object_handle).ok_or(TPM_RC_HANDLE + RC_OBJECT_HANDLE)?;
    let OwnedUserNvramEntry::Persistent { object, .. } = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .user_nvram
        .entries
        .get(entry)
        .ok_or(TPM_RC_FAILURE)?
    else {
        return Err(TPM_RC_FAILURE);
    };
    Ok(Target::Persistent {
        entry,
        attributes: object.attributes,
        evict_handle: stored_evict_handle(object, object_handle),
    })
}

fn stored_evict_handle(object: &OwnedAnyObject, fallback: u32) -> u32 {
    match &object.body {
        OwnedAnyObjectBody::Object(body) => body.evict_handle,
        _ => fallback,
    }
}

fn validate(auth: u32, target: &Target, persistent_handle: u32) -> Result<(), TpmResult> {
    let attributes = target.attributes();
    if attributes & UNPERSISTABLE != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_OBJECT_HANDLE);
    }
    if let Target::Persistent { evict_handle, .. } = *target
        && evict_handle != persistent_handle
    {
        return Err(TPM_RC_HANDLE + RC_OBJECT_HANDLE);
    }

    match auth {
        TPM_RH_PLATFORM => {
            if !target.is_evict() {
                if attributes & ATTR_PPS_HIERARCHY == 0 {
                    return Err(TPM_RC_HIERARCHY + RC_OBJECT_HANDLE);
                }
                if !(PLATFORM_PERSISTENT..=PERSISTENT_LAST).contains(&persistent_handle) {
                    return Err(TPM_RC_RANGE + RC_PERSISTENT_HANDLE);
                }
            }
        }
        TPM_RH_OWNER => {
            if attributes & ATTR_PPS_HIERARCHY != 0 {
                return Err(TPM_RC_HIERARCHY + RC_OBJECT_HANDLE);
            }
            if !target.is_evict()
                && !(PERSISTENT_FIRST..PLATFORM_PERSISTENT).contains(&persistent_handle)
            {
                return Err(TPM_RC_RANGE + RC_PERSISTENT_HANDLE);
            }
        }
        _ => return Err(TPM_RC_FAILURE),
    }
    Ok(())
}

fn handle_is_defined(runtime: &Tpm2Runtime, handle: u32) -> bool {
    runtime.state.as_ref().is_some_and(|state| {
        state.user_nvram.entries.iter().any(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle: stored, .. }
            | OwnedUserNvramEntry::Persistent { handle: stored, .. } => *stored == handle,
        })
    })
}

fn make_persistent(
    runtime: &mut Tpm2Runtime,
    slot: usize,
    persistent_handle: u32,
) -> Result<(), TpmResult> {
    if handle_is_defined(runtime, persistent_handle) {
        return Err(TPM_RC_NV_DEFINED);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let mut object = runtime
        .live
        .objects
        .get(slot)
        .ok_or(TPM_RC_FAILURE)?
        .clone();
    object.attributes |= ATTR_EVICT;
    let OwnedAnyObjectBody::Object(body) = &mut object.body else {
        return Err(TPM_RC_FAILURE);
    };
    body.evict_handle = persistent_handle;

    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let object_destination_size = persistent_object_image(&object, state.profile.object_format())
        .map_err(|_| TPM_RC_FAILURE)?
        .len() as u64;
    let entry = OwnedUserNvramEntry::Persistent {
        declared_entry_size: 0,
        handle: persistent_handle,
        object,
        object_destination_size,
    };
    let required_capacity = user_nvram_required_capacity(
        state
            .user_nvram
            .entries
            .iter()
            .chain(core::iter::once(&entry)),
    )
    .ok_or(TPM_RC_NV_SPACE)?;

    let backup_capacity =
        core::mem::replace(&mut state.user_nvram.required_capacity, required_capacity);
    state.user_nvram.entries.push(entry);
    let image = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            state.user_nvram.entries.pop();
            state.user_nvram.required_capacity = backup_capacity;
            return Err(TPM_RC_FAILURE);
        }
    };

    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(())
}

fn remove_persistent(runtime: &mut Tpm2Runtime, entry: usize) -> Result<(), TpmResult> {
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    if entry >= state.user_nvram.entries.len() {
        return Err(TPM_RC_FAILURE);
    }
    let removed = state.user_nvram.entries.remove(entry);
    let required_capacity = match user_nvram_required_capacity(&state.user_nvram.entries) {
        Some(required_capacity) => required_capacity,
        None => {
            state.user_nvram.entries.insert(entry, removed);
            return Err(TPM_RC_FAILURE);
        }
    };
    let backup_capacity =
        core::mem::replace(&mut state.user_nvram.required_capacity, required_capacity);
    let image = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            state.user_nvram.entries.insert(entry, removed);
            state.user_nvram.required_capacity = backup_capacity;
            return Err(TPM_RC_FAILURE);
        }
    };

    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::{TPM_CC_EVICT_CONTROL, find};
    use super::super::session::TPM_RS_PW;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::command::registry::{CommandLifecycle, HandleKind};
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_PLATFORM_NV,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::nv::USER_NVRAM_CAPACITY;
    use crate::library::tpm2::object::{ATTR_OCCUPIED, ATTR_SPS_HIERARCHY};
    use crate::library::tpm2::object_create::find_empty_object_slot;
    use crate::library::tpm2::oracles::evict_control::vector;
    use crate::library::tpm2::persistent::{
        OwnedNvIndex, OwnedSecret, persistent_all_store, user_nvram_required_capacity,
    };
    use crate::library::tpm2::process;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::restore_permanent_blob_for_test;
    use crate::library::tpm2::runtime::commit_manufactured_state;
    use crate::library::tpm2::volatile::MAX_LOADED_OBJECTS;

    const RC_SUCCESS: u32 = 0x000;
    const RC_SIZE: u32 = 0x095;
    const RC_INSUFFICIENT: u32 = 0x09a;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_NV_SPACE: u32 = 0x14b;
    const RC_NV_DEFINED: u32 = 0x14c;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_PARAM1_VALUE: u32 = 0x1c4;
    const RC_PARAM1_RANGE: u32 = 0x1cd;
    const RC_PARAM1_INSUFFICIENT: u32 = 0x1da;
    const RC_HANDLE2_ATTRIBUTES: u32 = 0x282;
    const RC_HANDLE2_VALUE: u32 = 0x284;
    const RC_HANDLE2_HIERARCHY: u32 = 0x285;
    const RC_HANDLE2_HANDLE: u32 = 0x28b;
    const RC_HANDLE2_INSUFFICIENT: u32 = 0x29a;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
    const RC_REFERENCE_H1: u32 = 0x911;
    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_OBJECT_MEMORY: u32 = 0x902;

    const OWNER_HANDLE: u32 = 0x8100_0001;
    const SECOND_OWNER_HANDLE: u32 = 0x8100_0002;
    const PLATFORM_HANDLE: u32 = 0x8180_0000;

    const STORAGE_ATTRIBUTES: u32 = 0x0003_0072;
    const TPMA_OBJECT_ST_CLEAR: u32 = 0x0000_0004;

    fn hex(value: &str) -> Vec<u8> {
        let digits: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(digits.len().is_multiple_of(2));
        (0..digits.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex digits"))
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x55;
        }
        Ok(())
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    fn startup_command() -> Vec<u8> {
        hex("80010000000c0000014400 00")
    }

    #[track_caller]
    fn start(runtime: &mut Tpm2Runtime) {
        assert_eq!(
            dispatch_bytes(runtime, &startup_command()),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        start(&mut runtime);
        runtime
    }

    #[track_caller]
    fn oracle_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL"))
            .expect("the oracle permanent state restores");
        start(&mut runtime);
        runtime
    }

    fn pw_session(password: &[u8]) -> Vec<u8> {
        let mut out = TPM_RS_PW.to_be_bytes().to_vec();
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out
    }

    fn framed(code: u32, payload: &[u8], sessions: bool) -> Vec<u8> {
        let tag: u16 = if sessions { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn command(auth: u32, object: u32, password: Option<&[u8]>, parameters: &[u8]) -> Vec<u8> {
        let mut payload = auth.to_be_bytes().to_vec();
        payload.extend_from_slice(&object.to_be_bytes());
        if let Some(password) = password {
            let session = pw_session(password);
            payload.extend_from_slice(&(session.len() as u32).to_be_bytes());
            payload.extend_from_slice(&session);
        }
        payload.extend_from_slice(parameters);
        framed(TPM_CC_EVICT_CONTROL, &payload, password.is_some())
    }

    fn evict_command(auth: u32, object: u32, persistent: u32) -> Vec<u8> {
        command(auth, object, Some(&[]), &persistent.to_be_bytes())
    }

    #[track_caller]
    fn evict(runtime: &mut Tpm2Runtime, auth: u32, object: u32, persistent: u32) -> Vec<u8> {
        dispatch_bytes(runtime, &evict_command(auth, object, persistent))
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn success_response() -> Vec<u8> {
        hex("8002 00000013 00000000 00000000 0000010000")
    }

    fn symcipher_template(attributes: u32) -> Vec<u8> {
        let mut out = 0x0025u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0006u16.to_be_bytes());
        out.extend_from_slice(&0x0080u16.to_be_bytes());
        out.extend_from_slice(&0x0043u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    fn create_primary_command(hierarchy: u32, template: &[u8]) -> Vec<u8> {
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&4u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&(template.len() as u16).to_be_bytes());
        parameters.extend_from_slice(template);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u32.to_be_bytes());

        let session = pw_session(&[]);
        let mut payload = hierarchy.to_be_bytes().to_vec();
        payload.extend_from_slice(&(session.len() as u32).to_be_bytes());
        payload.extend_from_slice(&session);
        payload.extend_from_slice(&parameters);
        framed(0x0000_0131, &payload, true)
    }

    #[track_caller]
    fn create_primary(
        runtime: &mut Tpm2Runtime,
        hierarchy: u32,
        attributes: u32,
    ) -> (u32, Vec<u8>) {
        let response = dispatch_bytes(
            runtime,
            &create_primary_command(hierarchy, &symcipher_template(attributes)),
        );
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "the primary is created"
        );
        let handle = u32::from_be_bytes(response[10..14].try_into().expect("a response handle"));
        (handle, response)
    }

    #[track_caller]
    fn storage_primary(runtime: &mut Tpm2Runtime, hierarchy: u32) -> u32 {
        create_primary(runtime, hierarchy, STORAGE_ATTRIBUTES).0
    }

    fn rsa_storage_template(key_bits: u16, name_alg: u16, sym_key_bits: u16) -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(&STORAGE_ATTRIBUTES.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0006u16.to_be_bytes());
        out.extend_from_slice(&sym_key_bits.to_be_bytes());
        out.extend_from_slice(&0x0043u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    #[track_caller]
    fn rsa_primary(runtime: &mut Tpm2Runtime, key_bits: u16) -> (u32, Vec<u8>) {
        let template = match key_bits {
            3072 => rsa_storage_template(3072, 0x000c, 256),
            _ => rsa_storage_template(key_bits, 0x000b, 128),
        };
        let response = dispatch_bytes(runtime, &create_primary_command(TPM_RH_OWNER, &template));
        assert_eq!(response_code(&response), RC_SUCCESS, "keyBits {key_bits}");
        let handle = u32::from_be_bytes(response[10..14].try_into().expect("a response handle"));
        let public_size = usize::from(u16::from_be_bytes(
            response[18..20].try_into().expect("the outPublic size"),
        ));
        let public = response[20..20 + public_size].to_vec();
        let modulus = public[public.len() - usize::from(key_bits) / 8..].to_vec();
        assert_ne!(modulus[0] & 0x80, 0, "a full-length modulus");
        (handle, modulus)
    }

    fn response_code(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
    }

    fn nvram_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .map(|entry| match entry {
                OwnedUserNvramEntry::NvIndex { handle, .. }
                | OwnedUserNvramEntry::Persistent { handle, .. } => *handle,
            })
            .collect()
    }

    fn persistent_entry(runtime: &Tpm2Runtime, handle: u32) -> &OwnedUserNvramEntry {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .find(|entry| {
                matches!(entry, OwnedUserNvramEntry::Persistent { handle: stored, .. }
                    if *stored == handle)
            })
            .expect("the evict object is stored")
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Snapshot {
        nv_update_pending: bool,
        nvram_handles: Vec<u32>,
        required_capacity: u64,
        occupied_slots: Vec<usize>,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
        permanent: Vec<u8>,
    }

    fn occupied_slots(runtime: &Tpm2Runtime) -> Vec<usize> {
        runtime
            .live
            .objects
            .iter()
            .enumerate()
            .filter(|(_, object)| object.attributes & ATTR_OCCUPIED != 0)
            .map(|(slot, _)| slot)
            .collect()
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            nv_update_pending: runtime.nv_update_pending,
            nvram_handles: nvram_handles(runtime),
            required_capacity: runtime.state().user_nvram.required_capacity,
            occupied_slots: occupied_slots(runtime),
            orderly_state: runtime.state().persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
            permanent: persistent_all_store(runtime.state()).expect("the state serializes"),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(snapshot(runtime), *before);
    }

    fn nv_index_entry(handle: u32) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::NvIndex {
            declared_entry_size: 0,
            handle,
            index: OwnedNvIndex {
                nv_index: handle,
                name_alg: 0x000b,
                attributes: 0,
                auth_policy: Vec::new(),
                data_size: 8,
                auth_value: OwnedSecret::from_vec(Vec::new()),
            },
            data: vec![0; 8],
        }
    }

    #[track_caller]
    fn push_nvram(
        runtime: &mut Tpm2Runtime,
        entries: impl IntoIterator<Item = OwnedUserNvramEntry>,
    ) {
        let user_nvram = &mut runtime.state.as_mut().expect("state present").user_nvram;
        user_nvram.entries.extend(entries);
        user_nvram.required_capacity = user_nvram_required_capacity(&user_nvram.entries)
            .expect("the planted entries fit the dynamic region");
        let state = runtime.state.as_ref().expect("state present");
        runtime.nv_memory = build_nv_image(state).expect("the planted entries serialize");
    }

    #[test]
    fn the_command_code_and_attributes_match_the_oracle() {
        assert_eq!(TPM_CC_EVICT_CONTROL, 0x0000_0120);
        let descriptor = find(TPM_CC_EVICT_CONTROL).expect("a registered command");
        assert_eq!(descriptor.attributes, 0x0440_0120);
        assert_ne!(
            descriptor.attributes & (1 << 22),
            0,
            "EvictControl writes NV"
        );
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!(
            (descriptor.attributes >> 25) & 0x7,
            2,
            "two command handles"
        );
        assert!(descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn only_the_provision_handle_requires_user_authorization() {
        let descriptor = find(TPM_CC_EVICT_CONTROL).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[1].user_auth);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Provision));
        assert!(matches!(descriptor.handles[1].kind, HandleKind::Object));
    }

    #[test]
    fn the_provision_handle_takes_only_owner_and_platform() {
        let kind = find(TPM_CC_EVICT_CONTROL).unwrap().handles[0].kind;
        assert!(kind.accepts(TPM_RH_OWNER));
        assert!(kind.accepts(TPM_RH_PLATFORM));
        for handle in [
            TPM_RH_ENDORSEMENT,
            TPM_RH_LOCKOUT,
            TPM_RH_NULL,
            TPM_RH_PLATFORM_NV,
            TPM_RS_PW,
            0x0000_0000,
            0x0100_0001,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn the_object_handle_takes_the_transient_and_persistent_ranges() {
        let kind = find(TPM_CC_EVICT_CONTROL).unwrap().handles[1].kind;
        for handle in [0x8000_0000, 0x8000_0002, PERSISTENT_FIRST, PERSISTENT_LAST] {
            assert!(kind.accepts(handle), "handle {handle:#010x}");
        }
        for handle in [
            0x7fff_ffff,
            0x8000_0003,
            0x80ff_ffff,
            0x8200_0000,
            TPM_RH_OWNER,
            0x0100_0001,
            0x0200_0000,
            0x0000_0000,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn evict_control_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, 0x8000_0000, OWNER_HANDLE),
            error_response(TPM_RC_INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000a00000120")),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes handle unmarshalling"
        );
    }

    #[test]
    fn a_missing_or_truncated_handle_is_reported_with_its_own_index() {
        let mut runtime = started_runtime();
        for (payload, expected) in [
            (&[][..], RC_HANDLE1_INSUFFICIENT),
            (&[0x40][..], RC_HANDLE1_INSUFFICIENT),
            (&[0x40, 0x00, 0x00][..], RC_HANDLE1_INSUFFICIENT),
            (&[0x40, 0x00, 0x00, 0x01][..], RC_HANDLE2_INSUFFICIENT),
            (
                &[0x40, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00][..],
                RC_HANDLE2_INSUFFICIENT,
            ),
        ] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &framed(TPM_CC_EVICT_CONTROL, payload, true)),
                error_response(expected),
                "payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn every_auth_handle_outside_owner_and_platform_is_rejected() {
        let mut runtime = started_runtime();
        for handle in [
            TPM_RH_ENDORSEMENT,
            TPM_RH_LOCKOUT,
            TPM_RH_NULL,
            TPM_RH_PLATFORM_NV,
            TPM_RS_PW,
            0x0000_0000,
            0x0100_0001,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert_eq!(
                evict(&mut runtime, handle, 0x8000_0000, OWNER_HANDLE),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn every_object_handle_outside_the_object_ranges_is_rejected() {
        let mut runtime = started_runtime();
        for handle in [
            TPM_RH_OWNER,
            0x0100_0001,
            0x0200_0000,
            0x0000_0000,
            0x8000_0005,
            0x8200_0000,
        ] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, handle, OWNER_HANDLE),
                error_response(RC_HANDLE2_VALUE),
                "handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn an_unloaded_transient_object_is_a_reference_error() {
        let mut runtime = started_runtime();
        for slot in 0..3u32 {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, 0x8000_0000 + slot, OWNER_HANDLE),
                error_response(RC_REFERENCE_H1),
                "slot {slot}"
            );
        }
    }

    #[test]
    fn an_undefined_persistent_object_is_an_indexed_handle_error() {
        let mut runtime = started_runtime();
        for handle in [
            PERSISTENT_FIRST,
            OWNER_HANDLE,
            PLATFORM_HANDLE,
            PERSISTENT_LAST,
        ] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, handle, handle),
                error_response(RC_HANDLE2_HANDLE),
                "handle {handle:#010x}"
            );
        }
    }

    #[track_caller]
    fn persist_and_fill_the_object_table(runtime: &mut Tpm2Runtime) {
        let object = storage_primary(runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        while let Some((slot, _)) = find_empty_object_slot(runtime) {
            assert_eq!(
                storage_primary(runtime, TPM_RH_OWNER),
                0x8000_0000 + slot as u32
            );
        }
        assert_eq!(occupied_slots(runtime).len(), MAX_LOADED_OBJECTS);
    }

    fn free_object_slot(runtime: &mut Tpm2Runtime, slot: usize) {
        let object = &mut runtime.live.objects[slot];
        object.attributes &= !ATTR_OCCUPIED;
        object.body = OwnedAnyObjectBody::Unoccupied;
    }

    #[test]
    fn a_persistent_object_is_deleted_while_a_transient_slot_is_free() {
        let mut runtime = started_runtime();
        persist_and_fill_the_object_table(&mut runtime);
        free_object_slot(&mut runtime, MAX_LOADED_OBJECTS - 1);
        let occupied = occupied_slots(&runtime);

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response()
        );
        assert!(nvram_handles(&runtime).is_empty());
        assert_eq!(
            occupied_slots(&runtime),
            occupied,
            "the temporary load leaves no trace in the object table"
        );
    }

    #[test]
    fn a_full_object_table_refuses_to_load_an_evict_object() {
        let mut runtime = started_runtime();
        persist_and_fill_the_object_table(&mut runtime);
        let before = snapshot(&runtime);

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            error_response(RC_OBJECT_MEMORY)
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(occupied_slots(&runtime), [0, 1, 2]);
        assert_eq!(nvram_handles(&runtime), [OWNER_HANDLE]);

        free_object_slot(&mut runtime, 0);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response(),
            "one free slot is enough"
        );
    }

    #[test]
    fn a_full_object_table_wins_over_an_undefined_evict_object() {
        let mut runtime = started_runtime();
        persist_and_fill_the_object_table(&mut runtime);
        let before = snapshot(&runtime);

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, 0x8100_0005, 0x8100_0005),
            error_response(RC_OBJECT_MEMORY),
            "ObjectAllocateSlot() runs before NvGetEvictObject()"
        );
        assert_unchanged(&runtime, &before);

        free_object_slot(&mut runtime, 0);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, 0x8100_0005, 0x8100_0005),
            error_response(RC_HANDLE2_HANDLE)
        );
    }

    #[test]
    fn a_disabled_hierarchy_wins_over_a_full_object_table() {
        let mut runtime = started_runtime();
        persist_and_fill_the_object_table(&mut runtime);
        runtime.live.state_clear.as_mut().unwrap().sh_enable = false;
        let before = snapshot(&runtime);

        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, OWNER_HANDLE, OWNER_HANDLE),
            error_response(RC_HANDLE2_HANDLE),
            "ObjectLoadEvict() checks the hierarchy before allocating a slot"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_object_table_error_codes_match_the_libtpms_oracle() {
        let mut runtime = started_runtime();
        persist_and_fill_the_object_table(&mut runtime);
        for object in [OWNER_HANDLE, 0x8100_0005] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, object, object),
                hex("80010000000a00000902"),
                "object {object:#010x}"
            );
        }
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, OWNER_HANDLE, OWNER_HANDLE),
            hex("80010000000a00000902"),
            "platform authorization takes the same path"
        );
        runtime.live.state_clear.as_mut().unwrap().sh_enable = false;
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, OWNER_HANDLE, OWNER_HANDLE),
            hex("80010000000a0000028b")
        );
    }

    #[test]
    fn the_object_load_status_is_checked_before_the_authorization_area() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_OWNER, 0x8000_0000, None, &OWNER_HANDLE.to_be_bytes())
            ),
            error_response(RC_REFERENCE_H1),
            "the absent object wins over the missing authorization"
        );
    }

    #[test]
    fn a_command_without_an_authorization_area_is_auth_missing() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_OWNER, object, None, &OWNER_HANDLE.to_be_bytes())
            ),
            error_response(RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_authorization_area_framing_matches_the_oracle() {
        let mut runtime = started_runtime();
        storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &hex("8002 00000016 00000120 40000001 80000000 00000000")
            ),
            error_response(RC_SIZE),
            "a zero authorizationSize is below the minimum"
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &hex("8002 00000014 00000120 40000001 80000000 0000")
            ),
            error_response(RC_INSUFFICIENT),
            "a truncated authorizationSize never reaches the session area"
        );
    }

    #[test]
    fn the_owner_and_platform_passwords_are_enforced() {
        for (auth, password, persistent) in [
            (TPM_RH_OWNER, &b"own"[..], OWNER_HANDLE),
            (TPM_RH_PLATFORM, &b"plat"[..], PLATFORM_HANDLE),
        ] {
            let mut runtime = started_runtime();
            let object = storage_primary(&mut runtime, auth);
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_auth_command(auth, &[], password)),
                success_response(),
                "the authValue is installed"
            );

            let before = snapshot(&runtime);
            assert_eq!(
                evict(&mut runtime, auth, object, persistent),
                error_response(RC_SESSION1_BAD_AUTH),
                "the empty password no longer authorizes"
            );
            assert_unchanged(&runtime, &before);

            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(auth, object, Some(password), &persistent.to_be_bytes())
                ),
                success_response()
            );
            assert_eq!(nvram_handles(&runtime), [persistent]);
        }
    }

    fn change_auth_command(hierarchy: u32, password: &[u8], new_auth: &[u8]) -> Vec<u8> {
        let session = pw_session(password);
        let mut payload = hierarchy.to_be_bytes().to_vec();
        payload.extend_from_slice(&(session.len() as u32).to_be_bytes());
        payload.extend_from_slice(&session);
        payload.extend_from_slice(&(new_auth.len() as u16).to_be_bytes());
        payload.extend_from_slice(new_auth);
        framed(0x0000_0129, &payload, true)
    }

    #[test]
    fn a_missing_or_truncated_persistent_handle_is_a_first_parameter_error() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        for parameters in [&[][..], &[0x81][..], &[0x81, 0x00, 0x00][..]] {
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_OWNER, object, Some(&[]), parameters)
                ),
                error_response(RC_PARAM1_INSUFFICIENT),
                "parameters {parameters:02x?}"
            );
        }
    }

    #[test]
    fn a_persistent_handle_outside_the_persistent_range_is_a_value_error() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        for handle in [
            0x0000_0000,
            0x0100_0001,
            TPM_RH_OWNER,
            0x8000_0000,
            0x80ff_ffff,
            0x8200_0000,
            u32::MAX,
        ] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, object, handle),
                error_response(RC_PARAM1_VALUE),
                "handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        for extra in [&[0xee][..], &[0x00][..], &[0xff; 16][..]] {
            let mut parameters = OWNER_HANDLE.to_be_bytes().to_vec();
            parameters.extend_from_slice(extra);
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_OWNER, object, Some(&[]), &parameters)
                ),
                error_response(RC_SIZE),
                "extra {extra:02x?}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn an_owner_primary_becomes_persistent_and_the_transient_copy_survives() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        let live_before = runtime.live.objects[0].clone();

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );

        assert_eq!(nvram_handles(&runtime), [OWNER_HANDLE]);
        let OwnedUserNvramEntry::Persistent {
            object: stored,
            object_destination_size,
            ..
        } = persistent_entry(&runtime, OWNER_HANDLE)
        else {
            panic!("an evict object");
        };
        assert_ne!(stored.attributes & ATTR_EVICT, 0, "the evict bit is set");
        assert_ne!(stored.attributes & ATTR_SPS_HIERARCHY, 0);
        let OwnedAnyObjectBody::Object(body) = &stored.body else {
            panic!("an object body");
        };
        assert_eq!(body.evict_handle, OWNER_HANDLE);
        assert_eq!(
            *object_destination_size,
            persistent_object_image(stored, runtime.state().profile.object_format())
                .expect("the evict object serializes")
                .len() as u64
        );

        assert_eq!(
            runtime.live.objects[0].attributes, live_before.attributes,
            "the transient object keeps its own attributes"
        );
        let (OwnedAnyObjectBody::Object(after), OwnedAnyObjectBody::Object(before)) =
            (&runtime.live.objects[0].body, &live_before.body)
        else {
            panic!("object bodies");
        };
        assert_eq!(after.evict_handle, before.evict_handle);
        assert_eq!(
            after.evict_handle, 0,
            "the transient copy is not an evict object"
        );

        assert!(runtime.nv_update_pending);
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
        assert_eq!(
            runtime.state().user_nvram.required_capacity,
            user_nvram_required_capacity(&runtime.state().user_nvram.entries).unwrap()
        );
    }

    #[track_caller]
    fn persistent_image(runtime: &Tpm2Runtime, handle: u32) -> Vec<u8> {
        let OwnedUserNvramEntry::Persistent { object, .. } = persistent_entry(runtime, handle)
        else {
            panic!("an evict object");
        };
        persistent_object_image(object, runtime.state().profile.object_format())
            .expect("the evict object serializes")
    }

    #[test]
    fn an_rsa_three_thousand_seventy_two_bit_persistent_object_survives_a_state_round_trip() {
        let mut runtime = oracle_runtime();
        let (object, modulus) = rsa_primary(&mut runtime, 3072);
        assert_eq!(modulus.len(), 384);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );

        let image = persistent_image(&runtime, OWNER_HANDLE);
        assert!(
            image.windows(modulus.len()).any(|window| window == modulus),
            "the stored object carries the RSA-3072 modulus"
        );
        let blob = persistent_all_store(runtime.state()).expect("the state serializes");

        let mut restarted = restore_permanent_blob_for_test(&blob).expect("the blob restores");
        start(&mut restarted);

        assert_eq!(nvram_handles(&restarted), [OWNER_HANDLE]);
        assert_eq!(
            persistent_image(&restarted, OWNER_HANDLE),
            image,
            "the evict object is restored byte for byte"
        );
        assert!(
            persistent_image(&restarted, OWNER_HANDLE)
                .windows(modulus.len())
                .any(|window| window == modulus),
            "the restored object still carries the RSA-3072 modulus"
        );
        assert_eq!(
            restarted.state().user_nvram.required_capacity,
            runtime.state().user_nvram.required_capacity
        );

        assert_eq!(
            evict(&mut restarted, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response(),
            "the restored object is still evictable by its own handle"
        );
        assert!(nvram_handles(&restarted).is_empty());
    }

    #[test]
    fn a_persistent_rsa_object_grows_with_the_key_size() {
        let mut owner = oracle_runtime();
        let (small, small_modulus) = rsa_primary(&mut owner, 2048);
        assert_eq!(small_modulus.len(), 256);
        assert_eq!(
            evict(&mut owner, TPM_RH_OWNER, small, OWNER_HANDLE),
            success_response()
        );
        let small_image = persistent_image(&owner, OWNER_HANDLE);

        let mut larger = oracle_runtime();
        let (big, big_modulus) = rsa_primary(&mut larger, 3072);
        assert_eq!(big_modulus.len(), 384);
        assert_eq!(
            evict(&mut larger, TPM_RH_OWNER, big, OWNER_HANDLE),
            success_response()
        );
        let big_image = persistent_image(&larger, OWNER_HANDLE);

        assert!(
            big_image.len() > small_image.len(),
            "an RSA-3072 evict object is larger than an RSA-2048 one"
        );
        assert_ne!(small_modulus, big_modulus);
    }

    #[test]
    fn a_platform_primary_becomes_persistent_in_the_platform_range() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_PLATFORM);
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, object, PLATFORM_HANDLE),
            success_response()
        );
        assert_eq!(nvram_handles(&runtime), [PLATFORM_HANDLE]);
    }

    #[test]
    fn an_endorsement_primary_is_persisted_with_owner_authorization() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_ENDORSEMENT);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, 0x8101_0001),
            success_response(),
            "swtpm_setup persists the EK with ownerAuth"
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, object, 0x8181_0001),
            error_response(RC_HANDLE2_HIERARCHY),
            "platformAuth only persists platform-hierarchy objects"
        );
    }

    #[test]
    fn the_two_hierarchies_never_persist_each_others_objects() {
        let mut runtime = started_runtime();
        let owner = storage_primary(&mut runtime, TPM_RH_OWNER);
        let platform = storage_primary(&mut runtime, TPM_RH_PLATFORM);
        let before = snapshot(&runtime);

        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, owner, PLATFORM_HANDLE),
            error_response(RC_HANDLE2_HIERARCHY),
            "platformAuth cannot persist an owner object"
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, platform, OWNER_HANDLE),
            error_response(RC_HANDLE2_HIERARCHY),
            "ownerAuth cannot persist a platform object"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn each_hierarchy_is_confined_to_its_own_persistent_range() {
        let mut runtime = started_runtime();
        let owner = storage_primary(&mut runtime, TPM_RH_OWNER);
        for handle in [PLATFORM_PERSISTENT, PLATFORM_HANDLE + 1, PERSISTENT_LAST] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, owner, handle),
                error_response(RC_PARAM1_RANGE),
                "owner handle {handle:#010x}"
            );
        }

        let platform = storage_primary(&mut runtime, TPM_RH_PLATFORM);
        for handle in [PERSISTENT_FIRST, OWNER_HANDLE, PLATFORM_PERSISTENT - 1] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_PLATFORM, platform, handle),
                error_response(RC_PARAM1_RANGE),
                "platform handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn temporary_and_st_clear_objects_are_never_persisted() {
        let mut runtime = started_runtime();
        let temporary = storage_primary(&mut runtime, TPM_RH_NULL);
        let st_clear = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            STORAGE_ATTRIBUTES | TPMA_OBJECT_ST_CLEAR,
        )
        .0;
        let before = snapshot(&runtime);

        for object in [temporary, st_clear] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
                error_response(RC_HANDLE2_ATTRIBUTES),
                "object {object:#010x}"
            );
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_public_only_object_is_never_persisted() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        runtime.live.objects[0].attributes |= ATTR_PUBLIC_ONLY;
        let before = snapshot(&runtime);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            error_response(RC_HANDLE2_ATTRIBUTES)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_persistent_handle_already_in_use_is_nv_defined() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        let before = snapshot(&runtime);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            error_response(RC_NV_DEFINED)
        );
        assert_unchanged(&runtime, &before);

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, SECOND_OWNER_HANDLE),
            success_response(),
            "a free handle still works"
        );
        assert_eq!(nvram_handles(&runtime), [OWNER_HANDLE, SECOND_OWNER_HANDLE]);
    }

    #[test]
    fn a_handle_taken_by_an_nv_index_is_nv_defined() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        push_nvram(&mut runtime, [nv_index_entry(OWNER_HANDLE)]);
        let before = snapshot(&runtime);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            error_response(RC_NV_DEFINED),
            "NvFindHandle() searches indexes and evict objects alike"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_object_that_does_not_fit_the_dynamic_region_is_an_nv_space_error() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        push_nvram_without_capacity(&mut runtime, USER_NVRAM_CAPACITY - 100);
        let before = snapshot(&runtime);
        let response = evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE);
        assert_eq!(response, error_response(RC_NV_SPACE));
        assert_eq!(
            response,
            hex("80010000000a0000014b"),
            "TPM_RC_NV_SPACE is RC_VER1 + 0x04b, not a warning"
        );
        assert_unchanged(&runtime, &before);
    }

    fn push_nvram_without_capacity(runtime: &mut Tpm2Runtime, size: u64) {
        let user_nvram = &mut runtime.state.as_mut().expect("state present").user_nvram;
        user_nvram.entries.push(OwnedUserNvramEntry::Persistent {
            declared_entry_size: 0,
            handle: 0x8100_00ff,
            object: OwnedAnyObject {
                attributes: 0,
                body: OwnedAnyObjectBody::Unoccupied,
            },
            object_destination_size: size,
        });
        user_nvram.required_capacity =
            user_nvram_required_capacity(&user_nvram.entries).expect("the planted entry fits");
    }

    #[test]
    fn an_unavailable_nv_refuses_the_command_without_touching_the_state() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            error_response(RC_NV_UNAVAILABLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn an_unavailable_nv_also_refuses_a_deletion() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            error_response(RC_NV_UNAVAILABLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn unavailable_nv_is_reported_after_the_parameter_and_hierarchy_checks() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        runtime.nv_available = false;
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, 0x8000_0000),
            error_response(RC_PARAM1_VALUE),
            "EvictControl_In is unmarshalled before the NV write"
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, PLATFORM_HANDLE),
            error_response(RC_PARAM1_RANGE)
        );
    }

    #[test]
    fn a_persistent_object_is_removed_by_its_own_handle() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        let capacity_with_entry = runtime.state().user_nvram.required_capacity;

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response()
        );
        assert!(nvram_handles(&runtime).is_empty());
        assert!(runtime.state().user_nvram.required_capacity < capacity_with_entry);
        assert_eq!(
            runtime.state().user_nvram.required_capacity,
            user_nvram_required_capacity(&runtime.state().user_nvram.entries).unwrap()
        );
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
    }

    #[test]
    fn a_deletion_needs_the_matching_persistent_handle() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        let before = snapshot(&runtime);
        for handle in [SECOND_OWNER_HANDLE, PERSISTENT_FIRST, PERSISTENT_LAST] {
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, handle),
                error_response(RC_HANDLE2_HANDLE),
                "handle {handle:#010x}"
            );
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn platform_authorization_deletes_any_evict_object_but_owner_stops_at_the_platform_range() {
        let mut runtime = started_runtime();
        let owner = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, owner, OWNER_HANDLE),
            success_response()
        );
        let platform = storage_primary(&mut runtime, TPM_RH_PLATFORM);
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, platform, PLATFORM_HANDLE),
            success_response()
        );

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, PLATFORM_HANDLE, PLATFORM_HANDLE),
            error_response(RC_HANDLE2_HIERARCHY),
            "ownerAuth never touches a platform evict object"
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, OWNER_HANDLE, OWNER_HANDLE),
            success_response(),
            "platformAuth deletes any evict object"
        );
        assert_eq!(nvram_handles(&runtime), [PLATFORM_HANDLE]);
    }

    #[test]
    fn an_endorsement_evict_object_is_removable_with_the_hierarchy_disabled() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_ENDORSEMENT);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, 0x8101_0001),
            success_response()
        );
        runtime.live.state_clear.as_mut().unwrap().eh_enable = false;
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, 0x8101_0001, 0x8101_0001),
            success_response(),
            "TPM2_EvictControl is exempt from the endorsement gate"
        );
        assert!(nvram_handles(&runtime).is_empty());
    }

    #[test]
    fn a_disabled_storage_hierarchy_hides_an_owner_evict_object() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        runtime.live.state_clear.as_mut().unwrap().sh_enable = false;
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            error_response(RC_HANDLE2_HANDLE)
        );
    }

    #[test]
    fn a_disabled_platform_hierarchy_hides_a_platform_evict_object() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_PLATFORM);
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, object, PLATFORM_HANDLE),
            success_response()
        );
        runtime.live.ph_enable = false;
        assert_eq!(
            evict(
                &mut runtime,
                TPM_RH_PLATFORM,
                PLATFORM_HANDLE,
                PLATFORM_HANDLE
            ),
            error_response(RC_HANDLE2_HANDLE)
        );
    }

    #[test]
    fn deleting_one_entry_leaves_every_other_entry_alone() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        push_nvram(&mut runtime, [nv_index_entry(0x0100_0001)]);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, SECOND_OWNER_HANDLE),
            success_response()
        );
        push_nvram(&mut runtime, [nv_index_entry(0x0100_0002)]);
        assert_eq!(
            nvram_handles(&runtime),
            [0x0100_0001, OWNER_HANDLE, SECOND_OWNER_HANDLE, 0x0100_0002]
        );

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response()
        );
        assert_eq!(
            nvram_handles(&runtime),
            [0x0100_0001, SECOND_OWNER_HANDLE, 0x0100_0002]
        );
        assert_eq!(
            runtime.state().user_nvram.required_capacity,
            user_nvram_required_capacity(&runtime.state().user_nvram.entries).unwrap()
        );
    }

    #[test]
    fn a_failed_nv_image_leaves_no_partial_mutation() {
        for delete in [false, true] {
            let mut runtime = started_runtime();
            let object = storage_primary(&mut runtime, TPM_RH_OWNER);
            if delete {
                assert_eq!(
                    evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
                    success_response()
                );
            }
            runtime.state.as_mut().unwrap().persistent.owner_policy = vec![0x5a; 4096];
            assert!(
                build_nv_image(runtime.state()).is_err(),
                "the oversized policy must not serialize"
            );
            let before = snapshot(&runtime);

            let (object_handle, persistent) = if delete {
                (OWNER_HANDLE, OWNER_HANDLE)
            } else {
                (object, OWNER_HANDLE)
            };
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, object_handle, persistent),
                error_response(TPM_RC_FAILURE),
                "delete {delete}"
            );
            assert_unchanged(&runtime, &before);
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn a_successful_command_requests_exactly_one_nv_commit() {
        let commits = core::cell::Cell::new(0u32);
        let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
            commits.set(commits.get() + 1);
            Ok(())
        };

        let mut runtime = manufactured_runtime();
        let startup = startup_command();
        let input = CommandInput::new(startup.len() as u32, startup);
        process(&mut runtime, 0, &input, count).expect("startup processes");
        assert_eq!(commits.get(), 1, "startup itself commits once");

        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(commits.get(), 1, "CreatePrimary writes no NV");

        for bytes in [
            evict_command(TPM_RH_OWNER, object, OWNER_HANDLE),
            evict_command(TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
        ] {
            let input = CommandInput::new(bytes.len() as u32, bytes);
            assert_eq!(
                process(&mut runtime, 0, &input, count).expect("the command processes"),
                success_response()
            );
        }
        assert_eq!(
            commits.get(),
            3,
            "one commit each for the add and the delete"
        );
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_failed_command_requests_no_nv_commit() {
        let commits = core::cell::Cell::new(0u32);
        let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
            commits.set(commits.get() + 1);
            Ok(())
        };

        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        for bytes in [
            evict_command(TPM_RH_ENDORSEMENT, object, OWNER_HANDLE),
            evict_command(TPM_RH_OWNER, object, PLATFORM_HANDLE),
            command(TPM_RH_OWNER, object, None, &OWNER_HANDLE.to_be_bytes()),
            command(TPM_RH_OWNER, object, Some(&[]), &[0xee]),
        ] {
            let input = CommandInput::new(bytes.len() as u32, bytes);
            let response = process(&mut runtime, 0, &input, count).expect("the command processes");
            assert_ne!(response_code(&response), RC_SUCCESS);
        }
        assert_eq!(commits.get(), 0);
    }

    #[test]
    fn the_orderly_state_survives_the_command() {
        for orderly_state in [0x0001u16, 0xfffe, 0xffff] {
            let mut runtime = started_runtime();
            let object = storage_primary(&mut runtime, TPM_RH_OWNER);
            runtime.state.as_mut().unwrap().persistent.orderly_state = orderly_state;
            assert_eq!(
                evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
                success_response()
            );
            assert_eq!(
                runtime.state().persistent.orderly_state,
                orderly_state,
                "TPM2_EvictControl does not set g_clearOrderly"
            );
        }
    }

    #[test]
    fn a_persistent_object_is_visible_through_get_capability() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        let query = hex("8001000000160000017a 00000001 81000000 00000008");
        assert_eq!(
            dispatch_bytes(&mut runtime, &query),
            hex("80010000001300000000000000000100000000"),
            "no evict object yet"
        );

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &query),
            hex("8001000000170000000000000000010000000181000001")
        );

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response()
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &query),
            hex("80010000001300000000000000000100000000"),
            "the deleted object disappears again"
        );
    }

    #[test]
    fn a_persistent_object_survives_a_permanent_state_round_trip() {
        let mut runtime = started_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_OWNER);
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, object, OWNER_HANDLE),
            success_response()
        );
        let blob = persistent_all_store(runtime.state()).expect("the state serializes");

        let restored = restore_permanent_blob_for_test(&blob).expect("the state restores");
        assert_eq!(nvram_handles(&restored), [OWNER_HANDLE]);
        assert_eq!(
            persistent_all_store(restored.state()).expect("the state serializes"),
            blob,
            "the evict object round-trips byte for byte"
        );

        let OwnedUserNvramEntry::Persistent { object: stored, .. } =
            persistent_entry(&restored, OWNER_HANDLE)
        else {
            panic!("an evict object");
        };
        assert_ne!(stored.attributes & ATTR_EVICT, 0);
        let OwnedAnyObjectBody::Object(body) = &stored.body else {
            panic!("an object body");
        };
        assert_eq!(body.evict_handle, OWNER_HANDLE);
    }

    #[test]
    fn the_oracle_permanent_state_survives_startup_unchanged_apart_from_the_time_epoch() {
        let runtime = restore_permanent_blob_for_test(vector("PERMALL")).expect("restores");
        assert_eq!(
            persistent_all_store(runtime.state()).expect("the state serializes"),
            vector("PERMALL"),
            "the manufactured blob round-trips byte for byte"
        );
        assert_eq!(startup_divergence(), [TIME_EPOCH_BYTE]);
    }

    const TIME_EPOCH_BYTE: usize = 1742;

    fn divergence(actual: &[u8], expected: &[u8]) -> Vec<usize> {
        assert_eq!(actual.len(), expected.len(), "blob length");
        (0..actual.len())
            .filter(|&index| actual[index] != expected[index])
            .collect()
    }

    fn startup_divergence() -> Vec<usize> {
        let runtime = oracle_runtime();
        divergence(
            &persistent_all_store(runtime.state()).expect("the state serializes"),
            vector("PERMALL_STARTED"),
        )
    }

    #[track_caller]
    fn assert_matches_oracle(runtime: &Tpm2Runtime, expected: &str, label: &str) {
        let actual = persistent_all_store(runtime.state()).expect("the state serializes");
        assert_eq!(
            divergence(&actual, vector(expected)),
            [TIME_EPOCH_BYTE],
            "{label} diverges from the oracle beyond the known time-epoch gap"
        );
    }

    #[test]
    fn the_whole_oracle_sequence_reproduces_the_libtpms_permanent_state() {
        let mut runtime = oracle_runtime();
        assert_matches_oracle(&runtime, "PERMALL_STARTED", "startup");

        let (owner, response) = create_primary(&mut runtime, TPM_RH_OWNER, STORAGE_ATTRIBUTES);
        assert_eq!(
            response,
            vector("OWNER_PRIMARY_RESPONSE"),
            "the owner primary matches the oracle byte for byte"
        );

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, owner, OWNER_HANDLE),
            success_response()
        );
        assert_matches_oracle(&runtime, "PERMALL_OWNER_PERSIST", "owner persist");

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, owner, SECOND_OWNER_HANDLE),
            success_response()
        );
        assert_matches_oracle(&runtime, "PERMALL_TWO_EVICTS", "second evict");

        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            success_response()
        );
        assert_matches_oracle(&runtime, "PERMALL_AFTER_DELETE", "delete");

        let (platform, response) =
            create_primary(&mut runtime, TPM_RH_PLATFORM, STORAGE_ATTRIBUTES);
        assert_eq!(
            response,
            vector("PLATFORM_PRIMARY_RESPONSE"),
            "the platform primary matches the oracle byte for byte"
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_PLATFORM, platform, PLATFORM_HANDLE),
            success_response()
        );
        assert_matches_oracle(&runtime, "PERMALL_PLATFORM_PERSIST", "platform persist");

        assert_eq!(
            evict(
                &mut runtime,
                TPM_RH_PLATFORM,
                PLATFORM_HANDLE,
                PLATFORM_HANDLE
            ),
            success_response()
        );
        assert_eq!(
            evict(
                &mut runtime,
                TPM_RH_OWNER,
                SECOND_OWNER_HANDLE,
                SECOND_OWNER_HANDLE
            ),
            success_response()
        );
        assert_matches_oracle(&runtime, "PERMALL_ALL_DELETED", "all deleted");
        assert!(nvram_handles(&runtime).is_empty());
    }

    #[test]
    fn the_swtpm_setup_request_answers_the_oracle_bytes() {
        let mut runtime = oracle_runtime();
        let object = storage_primary(&mut runtime, TPM_RH_ENDORSEMENT);
        let request =
            hex("8002 00000023 00000120 40000001 80000000 00000009 40000009 0000 00 0000 81010001");
        assert_eq!(
            request,
            evict_command(TPM_RH_OWNER, object, 0x8101_0001),
            "the helper builds the request swtpm_setup sends"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &request),
            hex("80020000001300000000000000000000010000")
        );
    }

    #[test]
    fn malformed_input_never_panics() {
        let valid = evict_command(TPM_RH_OWNER, 0x8000_0000, OWNER_HANDLE);
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    let input = CommandInput::new(mutated.len() as u32, mutated);
                    let Ok(parsed) = parse_command(&input) else {
                        continue;
                    };
                    let mut runtime = started_runtime();
                    storage_primary(&mut runtime, TPM_RH_OWNER);
                    let _ = serialize_response(&dispatch(&mut runtime, &parsed));
                }
            }
        }
    }

    #[test]
    fn a_runtime_without_decoded_state_never_panics() {
        use crate::library::tpm2::runtime::empty_state_runtime;

        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, 0x8000_0000, OWNER_HANDLE),
            error_response(RC_REFERENCE_H1)
        );
        assert_eq!(
            evict(&mut runtime, TPM_RH_OWNER, OWNER_HANDLE, OWNER_HANDLE),
            error_response(RC_HANDLE2_HANDLE)
        );
    }
}
