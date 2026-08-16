use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE};

use super::super::hierarchy::TPM_RH_PLATFORM;
use super::super::nv::build_nv_image;
use super::super::object::{ATTR_EPS_HIERARCHY, ATTR_OCCUPIED};
use super::super::orderly::prepare_clear_orderly;
use super::super::persistent::{
    OwnedAnyObject, OwnedAnyObjectBody, OwnedPersistentState, OwnedSecret, OwnedUserNvramEntry,
    user_nvram_required_capacity,
};
use super::super::random::generate_random;
use super::super::runtime::Tpm2Runtime;
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_ALG_NULL: u16 = 0x0010;

const PRIMARY_SEED_SIZE: usize = 64;
const PROOF_SIZE: usize = 64;

struct EndorsementSeed {
    ep_seed: OwnedSecret,
    eh_proof: OwnedSecret,
    seed_compat_level: u8,
    orderly_state: Option<u16>,
}

struct Backup {
    ep_seed: OwnedSecret,
    eh_proof: OwnedSecret,
    ep_seed_compat_level: u8,
    endorsement_auth: OwnedSecret,
    endorsement_alg: u16,
    endorsement_policy: Vec<u8>,
    orderly_state: u16,
    flushed: Vec<(usize, OwnedUserNvramEntry)>,
    required_capacity: u64,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    if auth_handle != TPM_RH_PLATFORM {
        return Err(TPM_RC_FAILURE);
    }
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    change_endorsement_primary_seed(runtime)?;
    Ok(CommandOutput::empty())
}

fn change_endorsement_primary_seed(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    if runtime.live.state_clear.is_none() {
        return Err(TPM_RC_FAILURE);
    }
    let orderly_state = prepare_clear_orderly(runtime)?;
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let seed_compat_level = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .seed_compat_level();

    let drbg = runtime.live.orderly.drbg_state.clone();
    reseed_endorsement_hierarchy(runtime, seed_compat_level, orderly_state).inspect_err(|_| {
        runtime.live.orderly.drbg_state = drbg;
    })
}

fn reseed_endorsement_hierarchy(
    runtime: &mut Tpm2Runtime,
    seed_compat_level: u8,
    orderly_state: Option<u16>,
) -> Result<(), TpmResult> {
    let seed = EndorsementSeed {
        ep_seed: OwnedSecret::from_vec(generate_random(runtime, PRIMARY_SEED_SIZE)?),
        eh_proof: OwnedSecret::from_vec(generate_random(runtime, PROOF_SIZE)?),
        seed_compat_level,
        orderly_state,
    };

    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = apply(state, seed)?;
    let image = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            restore(state, backup);
            return Err(TPM_RC_FAILURE);
        }
    };

    runtime.nv_memory = image;
    flush_loaded_endorsement_objects(&mut runtime.live.objects);
    if let Some(clear) = runtime.live.state_clear.as_mut() {
        clear.eh_enable = true;
    }
    runtime.nv_update_pending = true;
    Ok(())
}

fn belongs_to_endorsement(entry: &OwnedUserNvramEntry) -> bool {
    match entry {
        OwnedUserNvramEntry::NvIndex { .. } => false,
        OwnedUserNvramEntry::Persistent { object, .. } => {
            object.attributes & ATTR_EPS_HIERARCHY != 0
        }
    }
}

fn apply(state: &mut OwnedPersistentState, seed: EndorsementSeed) -> Result<Backup, TpmResult> {
    let flushed_capacity = user_nvram_required_capacity(
        state
            .user_nvram
            .entries
            .iter()
            .filter(|entry| !belongs_to_endorsement(entry)),
    )
    .ok_or(TPM_RC_FAILURE)?;

    let persistent = &mut state.persistent;
    let ep_seed = core::mem::replace(&mut persistent.ep_seed, seed.ep_seed);
    let eh_proof = core::mem::replace(&mut persistent.eh_proof, seed.eh_proof);
    let ep_seed_compat_level =
        core::mem::replace(&mut persistent.ep_seed_compat_level, seed.seed_compat_level);
    let endorsement_auth = core::mem::replace(
        &mut persistent.endorsement_auth,
        OwnedSecret::from_vec(Vec::new()),
    );
    let endorsement_alg = core::mem::replace(&mut persistent.endorsement_alg, TPM_ALG_NULL);
    let endorsement_policy = core::mem::take(&mut persistent.endorsement_policy);
    let orderly_state = persistent.orderly_state;
    if let Some(cleared) = seed.orderly_state {
        persistent.orderly_state = cleared;
    }

    let mut flushed = Vec::new();
    let mut kept = Vec::with_capacity(state.user_nvram.entries.len());
    for (index, entry) in core::mem::take(&mut state.user_nvram.entries)
        .into_iter()
        .enumerate()
    {
        if belongs_to_endorsement(&entry) {
            flushed.push((index, entry));
        } else {
            kept.push(entry);
        }
    }
    state.user_nvram.entries = kept;
    let required_capacity =
        core::mem::replace(&mut state.user_nvram.required_capacity, flushed_capacity);

    Ok(Backup {
        ep_seed,
        eh_proof,
        ep_seed_compat_level,
        endorsement_auth,
        endorsement_alg,
        endorsement_policy,
        orderly_state,
        flushed,
        required_capacity,
    })
}

fn restore(state: &mut OwnedPersistentState, backup: Backup) {
    let persistent = &mut state.persistent;
    persistent.ep_seed = backup.ep_seed;
    persistent.eh_proof = backup.eh_proof;
    persistent.ep_seed_compat_level = backup.ep_seed_compat_level;
    persistent.endorsement_auth = backup.endorsement_auth;
    persistent.endorsement_alg = backup.endorsement_alg;
    persistent.endorsement_policy = backup.endorsement_policy;
    persistent.orderly_state = backup.orderly_state;

    for (index, entry) in backup.flushed {
        state.user_nvram.entries.insert(index, entry);
    }
    state.user_nvram.required_capacity = backup.required_capacity;
}

fn flush_loaded_endorsement_objects(objects: &mut [OwnedAnyObject]) {
    const FLUSHED: u32 = ATTR_OCCUPIED | ATTR_EPS_HIERARCHY;
    for object in objects {
        if object.attributes & FLUSHED == FLUSHED {
            object.attributes &= !ATTR_OCCUPIED;
            object.body = OwnedAnyObjectBody::Unoccupied;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::TPM_CC_CHANGE_EPS;
    use super::super::session::TPM_RS_PW;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{TPM_FAIL, TPM_RC_INITIALIZE};
    use crate::library::tpm2::crypto::{CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_MAGIC};
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM_NV,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::marshal::BlobReader;
    use crate::library::tpm2::nv::{USER_NVRAM_CAPACITY, any_object_image};
    use crate::library::tpm2::object::{ATTR_PPS_HIERARCHY, ATTR_SPS_HIERARCHY, parse_any_object};
    use crate::library::tpm2::orderly::{SU_DA_USED_VALUE, SU_NONE_VALUE};
    use crate::library::tpm2::parse_persistent_all_payload;
    use crate::library::tpm2::persistent::own_any_object;
    use crate::library::tpm2::persistent::{
        OwnedNvIndex, PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
    };
    use crate::library::tpm2::process;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::public::StateFormatLimit;
    use crate::library::tpm2::runtime::{commit_manufactured_state, commit_restored_state};
    use crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION;

    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_SIZE: u32 = 0x095;
    const RC_INSUFFICIENT: u32 = 0x09a;
    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;

    const DEFAULT_V1_PROFILE: &[u8] = br#"{"Name":"default-v1"}"#;

    fn hex(value: &str) -> Vec<u8> {
        let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2));
        (0..cleaned.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x55;
        }
        Ok(())
    }

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn manufactured_runtime(profile: Option<&[u8]>) -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(profile).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
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
    fn started_runtime_with(profile: Option<&[u8]>) -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime(profile);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command()),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        started_runtime_with(None)
    }

    fn pw_session(password: &[u8]) -> Vec<u8> {
        let mut out = TPM_RS_PW.to_be_bytes().to_vec();
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out
    }

    fn command(handle: u32, auth: Option<&[u8]>, parameters: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        if let Some(auth) = auth {
            payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            payload.extend_from_slice(auth);
        }
        payload.extend_from_slice(parameters);

        let tag: u16 = if auth.is_some() { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_CHANGE_EPS.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn change_eps() -> Vec<u8> {
        command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &[])
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn success_response() -> Vec<u8> {
        hex("8002 00000013 00000000 00000000 0000010000")
    }

    fn change_auth_command(hierarchy: u32, password: &[u8], new_auth: &[u8]) -> Vec<u8> {
        let mut payload = hierarchy.to_be_bytes().to_vec();
        let auth = pw_session(password);
        payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
        payload.extend_from_slice(&auth);
        payload.extend_from_slice(&(new_auth.len() as u16).to_be_bytes());
        payload.extend_from_slice(new_auth);

        let mut out = hex("8002");
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&0x0000_0129u32.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn occupied_object(hierarchy: u32) -> OwnedAnyObject {
        let bytes = crate::library::tpm2::object::fixtures::any_rsa_object(CURRENT_OBJECT_VERSION);
        let mut reader = BlobReader::new(&bytes);
        let parsed = parse_any_object(&mut reader, StateFormatLimit::CURRENT)
            .expect("the object fixture parses");
        let mut object = own_any_object(&parsed);
        assert_ne!(object.attributes & ATTR_OCCUPIED, 0);
        object.attributes |= hierarchy;
        object
    }

    fn unoccupied_object(attributes: u32) -> OwnedAnyObject {
        assert_eq!(attributes & ATTR_OCCUPIED, 0);
        OwnedAnyObject {
            attributes,
            body: OwnedAnyObjectBody::Unoccupied,
        }
    }

    fn persistent_entry(handle: u32, object: OwnedAnyObject) -> OwnedUserNvramEntry {
        let object_destination_size = any_object_image(&object, CURRENT_OBJECT_VERSION)
            .expect("the evict object serializes")
            .len() as u64;
        OwnedUserNvramEntry::Persistent {
            declared_entry_size: 0,
            handle,
            object,
            object_destination_size,
        }
    }

    fn oversized_persistent_entry(handle: u32) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::Persistent {
            declared_entry_size: 0,
            handle,
            object: unoccupied_object(0),
            object_destination_size: USER_NVRAM_CAPACITY,
        }
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

    fn nvram_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
        runtime
            .state()
            .user_nvram
            .entries
            .iter()
            .map(|entry| match entry {
                OwnedUserNvramEntry::NvIndex { handle, .. } => *handle,
                OwnedUserNvramEntry::Persistent { handle, .. } => *handle,
            })
            .collect()
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

    #[derive(Debug, Eq, PartialEq)]
    struct Drbg {
        reseed_counter: u64,
        drbg_magic: u32,
        seed: Vec<u8>,
        last_value: [u32; 4],
    }

    fn drbg(runtime: &Tpm2Runtime) -> Drbg {
        let state = &runtime.live.orderly.drbg_state;
        Drbg {
            reseed_counter: state.reseed_counter,
            drbg_magic: state.drbg_magic,
            seed: state.seed.expose().to_vec(),
            last_value: state.last_value,
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Snapshot {
        failure_mode: bool,
        nv_update_pending: bool,
        drbg: Drbg,
        ep_seed: Vec<u8>,
        eh_proof: Vec<u8>,
        ep_seed_compat_level: u8,
        endorsement_auth: Vec<u8>,
        endorsement_alg: u16,
        endorsement_policy: Vec<u8>,
        orderly_state: u16,
        eh_enable: Option<bool>,
        nvram_handles: Vec<u32>,
        required_capacity: u64,
        occupied_slots: Vec<usize>,
        nv_memory: Box<[u8]>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let persistent = &runtime.state().persistent;
        Snapshot {
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            drbg: drbg(runtime),
            ep_seed: persistent.ep_seed.expose().to_vec(),
            eh_proof: persistent.eh_proof.expose().to_vec(),
            ep_seed_compat_level: persistent.ep_seed_compat_level,
            endorsement_auth: persistent.endorsement_auth.expose().to_vec(),
            endorsement_alg: persistent.endorsement_alg,
            endorsement_policy: persistent.endorsement_policy.clone(),
            orderly_state: persistent.orderly_state,
            eh_enable: runtime
                .live
                .state_clear
                .as_ref()
                .map(|clear| clear.eh_enable),
            nvram_handles: nvram_handles(runtime),
            required_capacity: runtime.state().user_nvram.required_capacity,
            occupied_slots: occupied_slots(runtime),
            nv_memory: runtime.nv_memory.clone(),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(snapshot(runtime), *before);
    }

    #[track_caller]
    fn reload(state: &OwnedPersistentState) -> OwnedPersistentState {
        let blob = persistent_all_store(state).expect("the state serializes");
        let envelope = PersistentAllEnvelope::parse(&blob).expect("the envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload parses");
        materialize_persistent_state(decoded).expect("the payload materializes")
    }

    #[test]
    fn change_eps_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime(None);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000a00000124")),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes handle unmarshalling"
        );
    }

    #[test]
    fn the_swtpm_setup_request_answers_the_oracle_bytes() {
        let mut runtime = started_runtime();
        let request = hex("8002 0000001b 00000124 4000000c
             00000009 40000009 0000 00 0000");
        assert_eq!(request, change_eps(), "the helper builds the same request");
        assert_eq!(
            dispatch_bytes(&mut runtime, &request),
            hex("8002 00000013 00000000 00000000 0000010000")
        );
    }

    #[test]
    fn a_missing_or_truncated_platform_handle_is_a_first_handle_insufficient_error() {
        let mut runtime = started_runtime();
        for payload in [
            &[][..],
            &[0x40][..],
            &[0x40, 0x00][..],
            &[0x40, 0x00, 0x00][..],
        ] {
            let mut bytes = hex("8002");
            bytes.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&TPM_CC_CHANGE_EPS.to_be_bytes());
            bytes.extend_from_slice(payload);
            assert_eq!(
                dispatch_bytes(&mut runtime, &bytes),
                error_response(RC_HANDLE1_INSUFFICIENT),
                "payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn every_handle_other_than_the_platform_hierarchy_is_rejected() {
        let mut runtime = started_runtime();
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_LOCKOUT,
            TPM_RH_NULL,
            TPM_RH_PLATFORM_NV,
            TPM_RS_PW,
            0x0000_0000,
            0x0000_0017,
            0x0100_0000,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &command(handle, Some(&pw_session(&[])), &[])),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#010x}"
            );
        }
    }

    #[test]
    fn a_command_without_an_authorization_area_is_auth_missing() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &command(TPM_RH_PLATFORM, None, &[])),
            error_response(RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_authorization_area_framing_matches_the_oracle() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &hex("8002 00000012 00000124 4000000c 00000000")
            ),
            error_response(RC_SIZE),
            "a zero authorizationSize is below the minimum"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("8002 00000010 00000124 4000000c 0000")),
            error_response(RC_INSUFFICIENT),
            "a truncated authorizationSize never reaches the session area"
        );
    }

    #[test]
    fn an_empty_password_authorizes_a_freshly_started_tpm() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
    }

    #[test]
    fn the_platform_password_is_enforced() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth_command(TPM_RH_PLATFORM, &[], b"plat")
            ),
            success_response(),
            "the platform authValue is installed"
        );

        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(RC_SESSION1_BAD_AUTH),
            "the empty password no longer authorizes"
        );
        assert_unchanged(&runtime, &before);

        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&pw_session(b"plat")), &[])
            ),
            success_response()
        );
    }

    #[test]
    fn a_wrong_password_never_reaches_the_state() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&pw_session(b"wrong")), &[])
            ),
            error_response(RC_SESSION1_BAD_AUTH)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn any_command_parameter_is_a_size_error() {
        let mut runtime = started_runtime();
        for parameters in [&[0xee][..], &[0x00][..], &[0, 0, 0, 0][..], &[0xff; 16][..]] {
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), parameters)
                ),
                error_response(RC_SIZE),
                "parameters {parameters:02x?}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn an_unavailable_nv_refuses_the_command_without_touching_the_state() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(RC_NV_UNAVAILABLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn unavailable_nv_is_reported_after_the_parameter_check() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &[0xee])
            ),
            error_response(RC_SIZE),
            "ChangeEPS_In is unmarshalled before the NV check"
        );
    }

    #[test]
    fn the_endorsement_seed_and_proof_are_regenerated() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(before.ep_seed.len(), PRIMARY_SEED_SIZE);
        assert_eq!(before.eh_proof.len(), PROOF_SIZE);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        let after = snapshot(&runtime);

        assert_eq!(after.ep_seed.len(), PRIMARY_SEED_SIZE);
        assert_eq!(after.eh_proof.len(), PROOF_SIZE);
        assert_ne!(after.ep_seed, before.ep_seed);
        assert_ne!(after.eh_proof, before.eh_proof);
        assert_ne!(after.ep_seed, after.eh_proof);
        assert!(runtime.nv_update_pending);
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
    }

    #[test]
    fn every_other_hierarchy_seed_and_proof_survives() {
        let mut runtime = started_runtime();
        let secrets = |runtime: &Tpm2Runtime| {
            let persistent = &runtime.state().persistent;
            (
                persistent.sp_seed.expose().to_vec(),
                persistent.pp_seed.expose().to_vec(),
                persistent.ph_proof.expose().to_vec(),
                persistent.sh_proof.expose().to_vec(),
                persistent.sp_seed_compat_level,
                persistent.pp_seed_compat_level,
                persistent.owner_auth.expose().to_vec(),
                persistent.lockout_auth.expose().to_vec(),
            )
        };
        let before = secrets(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        assert_eq!(secrets(&runtime), before);
    }

    #[test]
    fn the_endorsement_seed_compat_level_follows_the_active_profile() {
        for profile in [None, Some(DEFAULT_V1_PROFILE)] {
            let mut runtime = started_runtime_with(profile);
            runtime
                .state
                .as_mut()
                .unwrap()
                .persistent
                .ep_seed_compat_level = 0;
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_eps()),
                success_response()
            );
            assert_eq!(
                runtime.state().persistent.ep_seed_compat_level,
                runtime.state().profile.seed_compat_level(),
                "profile {profile:?}"
            );
            assert_eq!(runtime.state().persistent.ep_seed_compat_level, 1);
        }
    }

    #[test]
    fn the_endorsement_authorization_and_policy_are_reset() {
        let mut runtime = started_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.endorsement_auth = OwnedSecret::copy_of(b"endorsement");
            persistent.endorsement_alg = 0x000b;
            persistent.endorsement_policy = vec![0xa5; 32];
        }
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );

        let persistent = &runtime.state().persistent;
        assert!(persistent.endorsement_auth.expose().is_empty());
        assert_eq!(persistent.endorsement_alg, TPM_ALG_NULL);
        assert!(persistent.endorsement_policy.is_empty());
    }

    #[test]
    fn the_reset_endorsement_authorization_takes_effect_immediately() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth_command(TPM_RH_ENDORSEMENT, &[], b"endo")
            ),
            success_response()
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth_command(TPM_RH_ENDORSEMENT, &[], b"x")
            ),
            error_response(RC_SESSION1_BAD_AUTH),
            "the endorsement authValue is in force"
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &change_auth_command(TPM_RH_ENDORSEMENT, &[], b"y")
            ),
            success_response(),
            "the empty authValue authorizes again"
        );
    }

    #[test]
    fn the_endorsement_hierarchy_is_enabled() {
        let mut runtime = started_runtime();
        runtime.live.state_clear.as_mut().unwrap().eh_enable = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        let clear = runtime.live.state_clear.as_ref().unwrap();
        assert!(clear.eh_enable);
        assert!(clear.sh_enable, "the storage hierarchy is left alone");
        assert!(clear.ph_enable_nv, "platform NV is left alone");
    }

    #[test]
    fn loaded_endorsement_objects_are_flushed_and_other_hierarchies_are_kept() {
        let mut runtime = started_runtime();
        runtime.live.objects[0] = occupied_object(ATTR_EPS_HIERARCHY);
        runtime.live.objects[1] = occupied_object(ATTR_SPS_HIERARCHY);
        runtime.live.objects[2] = occupied_object(ATTR_PPS_HIERARCHY);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );

        assert_eq!(occupied_slots(&runtime), [1, 2]);
        assert_eq!(
            runtime.live.objects[0].attributes, ATTR_EPS_HIERARCHY,
            "only the occupied bit is cleared"
        );
        assert!(matches!(
            runtime.live.objects[0].body,
            OwnedAnyObjectBody::Unoccupied
        ));
    }

    #[test]
    fn an_unoccupied_endorsement_slot_is_left_alone() {
        let mut runtime = started_runtime();
        runtime.live.objects[0] = unoccupied_object(ATTR_EPS_HIERARCHY);
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        assert_eq!(runtime.live.objects[0].attributes, ATTR_EPS_HIERARCHY);
        assert!(occupied_slots(&runtime).is_empty());
    }

    #[test]
    fn persistent_endorsement_objects_are_removed_and_everything_else_survives() {
        let mut runtime = started_runtime_with(Some(DEFAULT_V1_PROFILE));
        push_nvram(
            &mut runtime,
            [
                nv_index_entry(0x0100_0001),
                persistent_entry(0x8100_0001, occupied_object(ATTR_EPS_HIERARCHY)),
                persistent_entry(0x8100_0002, occupied_object(ATTR_SPS_HIERARCHY)),
                nv_index_entry(0x0100_0002),
                persistent_entry(0x8100_0003, occupied_object(ATTR_PPS_HIERARCHY)),
                persistent_entry(0x8100_0004, unoccupied_object(ATTR_EPS_HIERARCHY)),
                persistent_entry(0x8100_0005, occupied_object(0)),
            ],
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );

        assert_eq!(
            nvram_handles(&runtime),
            [
                0x0100_0001,
                0x8100_0002,
                0x0100_0002,
                0x8100_0003,
                0x8100_0005
            ],
            "the endorsement evict objects go, indexes and other hierarchies stay"
        );
        assert_eq!(
            runtime.state().user_nvram.required_capacity,
            user_nvram_required_capacity(&runtime.state().user_nvram.entries).unwrap(),
            "the recorded capacity follows the shortened list"
        );
        assert_eq!(
            runtime.nv_memory,
            build_nv_image(runtime.state()).expect("the state serializes")
        );
    }

    #[test]
    fn a_tpm_without_endorsement_entries_keeps_its_nv_list_intact() {
        let mut runtime = started_runtime_with(Some(DEFAULT_V1_PROFILE));
        push_nvram(
            &mut runtime,
            [
                nv_index_entry(0x0100_0001),
                persistent_entry(0x8100_0002, occupied_object(ATTR_SPS_HIERARCHY)),
            ],
        );
        let before = nvram_handles(&runtime);
        let capacity_before = runtime.state().user_nvram.required_capacity;

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );

        assert_eq!(nvram_handles(&runtime), before);
        assert_eq!(
            runtime.state().user_nvram.required_capacity,
            capacity_before
        );
    }

    #[test]
    fn an_orderly_tpm_records_the_cleared_orderly_state() {
        for (da_used, expected) in [(false, SU_NONE_VALUE), (true, SU_DA_USED_VALUE)] {
            let mut runtime = started_runtime();
            runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
            runtime.live.da_used = da_used;
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_eps()),
                success_response()
            );
            assert_eq!(
                runtime.state().persistent.orderly_state,
                expected,
                "da_used {da_used}"
            );
        }
    }

    #[test]
    fn a_non_orderly_tpm_keeps_its_orderly_state() {
        for orderly_state in [SU_NONE_VALUE, SU_DA_USED_VALUE] {
            let mut runtime = started_runtime();
            runtime.state.as_mut().unwrap().persistent.orderly_state = orderly_state;
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_eps()),
                success_response()
            );
            assert_eq!(runtime.state().persistent.orderly_state, orderly_state);
        }
    }

    #[test]
    fn an_entropy_failure_leaves_no_partial_mutation() {
        let mut runtime = started_runtime();
        runtime.entropy = failing_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        assert_eq!(
            snapshot(&runtime),
            Snapshot {
                failure_mode: true,
                ..before
            },
            "a dead DRBG stops the TPM and changes nothing else"
        );
    }

    #[test]
    fn an_entropy_failure_after_the_first_draw_rolls_back_the_drbg() {
        let mut runtime = started_runtime();
        runtime.entropy = failing_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED - 1;
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE),
            "the endorsement proof needs a reseed the failing entropy cannot serve"
        );
        assert_eq!(
            snapshot(&runtime),
            Snapshot {
                failure_mode: true,
                ..before
            },
            "the seed draw that did succeed is rolled back"
        );
    }

    #[test]
    fn a_dead_drbg_leaves_no_partial_mutation() {
        let mut runtime = started_runtime();
        runtime.live.orderly.drbg_state.drbg_magic = DRBG_MAGIC ^ 0xffff_ffff;
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        assert_eq!(
            snapshot(&runtime),
            Snapshot {
                failure_mode: true,
                ..before
            }
        );
    }

    #[test]
    fn a_failed_nv_image_leaves_no_partial_mutation() {
        let mut runtime = started_runtime_with(Some(DEFAULT_V1_PROFILE));
        push_nvram(
            &mut runtime,
            [
                persistent_entry(0x8100_0001, occupied_object(ATTR_EPS_HIERARCHY)),
                persistent_entry(0x8100_0002, occupied_object(ATTR_SPS_HIERARCHY)),
            ],
        );
        runtime.live.objects[0] = occupied_object(ATTR_EPS_HIERARCHY);
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
        runtime.state.as_mut().unwrap().persistent.owner_policy = vec![0x5a; 4096];
        assert!(
            build_nv_image(runtime.state()).is_err(),
            "the oversized policy must not serialize"
        );
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            drbg(&runtime),
            before.drbg,
            "both draws happened before the image failed and both are rolled back"
        );
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_failed_capacity_check_leaves_no_partial_mutation() {
        let mut runtime = started_runtime_with(Some(DEFAULT_V1_PROFILE));
        push_nvram(
            &mut runtime,
            [persistent_entry(
                0x8100_0002,
                occupied_object(ATTR_SPS_HIERARCHY),
            )],
        );
        runtime
            .state
            .as_mut()
            .unwrap()
            .user_nvram
            .entries
            .push(oversized_persistent_entry(0x8100_0003));
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        assert_unchanged(&runtime, &before);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_successful_change_advances_the_drbg_exactly_twice() {
        let mut runtime = started_runtime();
        let before = drbg(&runtime);

        let mut twin = started_runtime();
        let ep_seed = generate_random(&mut twin, PRIMARY_SEED_SIZE).expect("the seed is drawn");
        let eh_proof = generate_random(&mut twin, PROOF_SIZE).expect("the proof is drawn");

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );

        assert_eq!(
            drbg(&runtime).reseed_counter,
            before.reseed_counter + 2,
            "one draw for the seed and one for the proof"
        );
        assert_eq!(
            drbg(&runtime),
            drbg(&twin),
            "the command draws the same two values in the same order"
        );
        assert_eq!(runtime.state().persistent.ep_seed.expose(), ep_seed);
        assert_eq!(runtime.state().persistent.eh_proof.expose(), eh_proof);
    }

    #[test]
    fn the_new_endorsement_seed_survives_a_permanent_state_round_trip() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        let expected = snapshot(&runtime);

        let once = commit_restored_state(reload(runtime.state())).expect("restores");
        let persistent = &once.state().persistent;
        assert_eq!(persistent.ep_seed.expose(), expected.ep_seed);
        assert_eq!(persistent.eh_proof.expose(), expected.eh_proof);
        assert_eq!(
            persistent.ep_seed_compat_level,
            expected.ep_seed_compat_level
        );
        assert_eq!(persistent.endorsement_alg, TPM_ALG_NULL);
        assert!(persistent.endorsement_auth.expose().is_empty());
        assert!(persistent.endorsement_policy.is_empty());

        let twice = commit_restored_state(reload(once.state())).expect("restores");
        assert_eq!(
            persistent_all_store(once.state()).unwrap(),
            persistent_all_store(twice.state()).unwrap()
        );
    }

    #[test]
    fn rewriting_the_state_keeps_the_permanent_blob_size() {
        let mut runtime = started_runtime();
        let before = persistent_all_store(runtime.state())
            .expect("the state serializes")
            .len();
        for _ in 0..3 {
            assert_eq!(
                dispatch_bytes(&mut runtime, &change_eps()),
                success_response()
            );
            assert_eq!(
                persistent_all_store(runtime.state())
                    .expect("the state serializes")
                    .len(),
                before
            );
        }
    }

    #[test]
    fn a_successful_change_requests_exactly_one_nv_commit() {
        let commits = core::cell::Cell::new(0u32);
        let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
            commits.set(commits.get() + 1);
            Ok(())
        };

        let mut runtime = manufactured_runtime(None);
        let startup = startup_command();
        let input = CommandInput::new(startup.len() as u32, startup);
        process(&mut runtime, 0, &input, count).expect("startup processes");
        assert_eq!(commits.get(), 1, "startup itself commits once");

        let bytes = change_eps();
        let input = CommandInput::new(bytes.len() as u32, bytes);
        assert_eq!(
            process(&mut runtime, 0, &input, count).expect("the command processes"),
            success_response()
        );
        assert_eq!(commits.get(), 2, "one commit for the new seed");
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_failed_change_requests_no_nv_commit() {
        let commits = core::cell::Cell::new(0u32);
        let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
            commits.set(commits.get() + 1);
            Ok(())
        };

        let mut runtime = started_runtime();
        for bytes in [
            command(TPM_RH_OWNER, Some(&pw_session(&[])), &[]),
            command(TPM_RH_PLATFORM, Some(&pw_session(b"wrong")), &[]),
            command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &[0xee]),
            command(TPM_RH_PLATFORM, None, &[]),
        ] {
            let input = CommandInput::new(bytes.len() as u32, bytes);
            let response = process(&mut runtime, 0, &input, count).expect("the command processes");
            assert_ne!(&response[6..10], &[0, 0, 0, 0]);
        }
        assert_eq!(commits.get(), 0);
    }

    #[test]
    fn a_failing_host_commit_fails_the_tpm_like_every_other_nv_command() {
        let mut runtime = started_runtime();
        let bytes = change_eps();
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(&mut runtime, 0, &input, |_| Err(TPM_RC_FAILURE))
            .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert!(runtime.failure_mode);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_runtime_without_decoded_state_never_panics() {
        use crate::library::tpm2::runtime::empty_state_runtime;

        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn malformed_input_never_panics() {
        let valid = change_eps();
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
                    let _ = serialize_response(&dispatch(&mut runtime, &parsed));
                }
            }
        }
    }
}
