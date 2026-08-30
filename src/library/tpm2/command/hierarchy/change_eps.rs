use super::{
    PRIMARY_SEED_SIZE, PROOF_SIZE, commit_persistent_state, flush_loaded_hierarchy_objects,
    hierarchy_object_attribute, regenerate_hierarchy_secrets, remove_hierarchy_persistent_objects,
    with_rollback,
};
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM};
use crate::library::tpm2::orderly::prepare_clear_orderly;
use crate::library::tpm2::persistent::OwnedSecret;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_ALG_NULL: u16 = 0x0010;

pub(in crate::library::tpm2::command) fn execute(
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

    let mut secrets =
        regenerate_hierarchy_secrets(runtime, &[PRIMARY_SEED_SIZE, PROOF_SIZE])?.into_iter();
    let ep_seed = secrets.next().ok_or(TPM_RC_FAILURE)?;
    let eh_proof = secrets.next().ok_or(TPM_RC_FAILURE)?;

    with_rollback(runtime, |runtime| {
        let attribute = hierarchy_object_attribute(TPM_RH_ENDORSEMENT).ok_or(TPM_RC_FAILURE)?;
        let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
        if let Some(ep_seed) = ep_seed {
            state.persistent.ep_seed = ep_seed;
        }
        state.persistent.ep_seed_compat_level = seed_compat_level;
        if let Some(eh_proof) = eh_proof {
            state.persistent.eh_proof = eh_proof;
        }
        state.persistent.endorsement_auth = OwnedSecret::from_vec(Vec::new());
        state.persistent.endorsement_alg = TPM_ALG_NULL;
        state.persistent.endorsement_policy = Vec::new();
        if let Some(orderly_state) = orderly_state {
            state.persistent.orderly_state = orderly_state;
        }
        remove_hierarchy_persistent_objects(state, attribute)?;

        runtime
            .live
            .state_clear
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .eh_enable = true;
        flush_loaded_hierarchy_objects(&mut runtime.live.objects, attribute);
        commit_persistent_state(runtime)
    })
}

#[cfg(test)]
mod tests {
    use crate::library::cancel::CancellationToken;
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::types::TpmResult>,
    ) -> Result<Vec<u8>, crate::types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
            CancellationToken::disabled(),
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{TPM_FAIL, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_CHANGE_EPS;
    use crate::library::tpm2::command::session::processing::TPM_RS_PW;
    use crate::library::tpm2::crypto::{CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_MAGIC};
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM_NV,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::marshal::BlobReader;
    use crate::library::tpm2::nv::build_nv_image;
    use crate::library::tpm2::nv::{USER_NVRAM_CAPACITY, any_object_image};
    use crate::library::tpm2::object::{ATTR_EPS_HIERARCHY, ATTR_OCCUPIED};
    use crate::library::tpm2::object::{ATTR_PPS_HIERARCHY, ATTR_SPS_HIERARCHY, parse_any_object};
    use crate::library::tpm2::orderly::{SU_DA_USED_VALUE, SU_NONE_VALUE};
    use crate::library::tpm2::parse_persistent_all_payload;
    use crate::library::tpm2::persistent::own_any_object;
    use crate::library::tpm2::persistent::{
        OwnedAnyObject, OwnedAnyObjectBody, OwnedPersistentState, OwnedUserNvramEntry,
        user_nvram_required_capacity,
    };
    use crate::library::tpm2::persistent::{
        OwnedNvIndex, PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
    };
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::public::StateFormatLimit;
    use crate::library::tpm2::random::regenerate_secret;
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

    fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        panic!("the entropy-bad latch must short-circuit the platform callback");
    }

    fn manufactured_runtime(profile: Option<&[u8]>) -> Tpm2Runtime {
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
        serialize_response(&dispatch(runtime, &parsed, CancellationToken::disabled()))
            .expect("the response serializes")
    }

    fn startup_command() -> Vec<u8> {
        hex("80010000000c0000014400 00")
    }

    #[track_caller]
    fn started_runtime_with(profile: Option<&[u8]>) -> Tpm2Runtime {
        let mut runtime = manufactured_runtime(profile);
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command()),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[track_caller]
    fn started_runtime() -> Tpm2Runtime {
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
    fn pre_startup_rejection() {
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
    fn swtpm_setup_request_oracle_match() {
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
    fn truncated_platform_handle_insufficient_error() {
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
    fn non_platform_handle_rejection() {
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
    fn missing_authorization_area_auth_missing() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &command(TPM_RH_PLATFORM, None, &[])),
            error_response(RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn authorization_area_framing_oracle_match() {
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
    fn empty_password_fresh_tpm_authorization() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
    }

    #[test]
    fn platform_password_enforcement() {
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
    fn wrong_password_state_preservation() {
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
    fn nonempty_parameter_size_error() {
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
    fn unavailable_nv_rejection_state_preservation() {
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
    fn unavailable_nv_parameter_check_order() {
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
    fn endorsement_seed_proof_regeneration() {
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
    fn other_hierarchy_seed_and_proof_survival() {
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
    fn endorsement_seed_compat_level_profile_match() {
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
    fn endorsement_auth_policy_reset() {
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
    fn reset_authorization_immediate_effect() {
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
    fn endorsement_hierarchy_enablement() {
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
    fn endorsement_object_flush_other_hierarchy_preservation() {
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
    fn unoccupied_endorsement_slot_unchanged() {
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
    fn persistent_endorsement_object_marshalled_format_survival() {
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
        let before = nvram_handles(&runtime);
        let capacity_before = runtime.state().user_nvram.required_capacity;

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );

        assert_eq!(
            nvram_handles(&runtime),
            before,
            "NvFlushHierarchy() reads the ANY_OBJECT header where it expects the \
             attribute word, so no evict object matches the endorsement hierarchy"
        );
        assert_eq!(
            runtime.state().user_nvram.required_capacity,
            capacity_before
        );
    }

    #[test]
    fn missing_endorsement_entries_nv_list_preservation() {
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
    fn orderly_tpm_orderly_state_clear() {
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
    fn non_orderly_tpm_orderly_state_preservation() {
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
    fn entropy_failure_old_secrets_success() {
        let mut runtime = started_runtime();
        runtime.entropy = failing_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
        let before = snapshot(&runtime);
        assert_ne!(before.ep_seed, vec![0u8; before.ep_seed.len()]);
        assert_ne!(before.eh_proof, vec![0u8; before.eh_proof.len()]);

        let mut committed = 0;
        let command = change_eps();
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            committed += 1;
            Ok(())
        })
        .expect("the command processes");
        assert_eq!(response, success_response());
        assert_eq!(
            committed, 1,
            "the NV update is still scheduled and committed"
        );

        let after = snapshot(&runtime);
        assert_eq!(after.ep_seed, before.ep_seed, "the old seed is retained");
        assert_eq!(after.eh_proof, before.eh_proof, "the old proof is retained");
        assert_eq!(after.drbg, before.drbg, "no reseed was stored");
        assert_eq!(after.endorsement_auth, Vec::<u8>::new());
        assert_eq!(after.endorsement_alg, TPM_ALG_NULL);
        assert_eq!(after.eh_enable, Some(true));
        assert_eq!(
            after.orderly_state, SU_NONE_VALUE,
            "g_clearOrderly still runs"
        );
        assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
        assert!(!runtime.failure_mode);
        assert_eq!(runtime.failure_diagnostics, Default::default());
    }

    #[test]
    fn pre_latched_runtime_old_secrets_no_callback() {
        let mut runtime = started_runtime();
        runtime.entropy_bad = true;
        runtime.entropy = unreachable_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response()
        );
        let after = snapshot(&runtime);
        assert_eq!(after.ep_seed, before.ep_seed, "the old seed is retained");
        assert_eq!(after.eh_proof, before.eh_proof, "the old proof is retained");
        assert_eq!(after.drbg, before.drbg, "no reseed was stored");
        assert_eq!(after.endorsement_auth, Vec::<u8>::new());
        assert!(runtime.entropy_bad, "the latch stays set");
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn entropy_failure_after_first_draw_old_proof_only() {
        let mut runtime = started_runtime();
        runtime.entropy = failing_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED - 1;
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0x0001;
        let before = snapshot(&runtime);

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            success_response(),
            "the proof needed a reseed the failing entropy cannot serve"
        );
        let after = snapshot(&runtime);
        assert_ne!(after.ep_seed, before.ep_seed, "the first draw still wrote");
        assert_eq!(after.eh_proof, before.eh_proof, "the old proof is retained");
        assert_eq!(
            after.drbg.reseed_counter, CTR_DRBG_MAX_REQUESTS_PER_RESEED,
            "the successful draw's state advance is kept, like the C generator"
        );
        assert!(runtime.entropy_bad);
        assert!(!runtime.failure_mode);
        assert_eq!(runtime.failure_diagnostics, Default::default());
    }

    #[test]
    fn dead_drbg_no_partial_mutation() {
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
    fn second_draw_continuous_test_failure_drbg_restoration() {
        use crate::library::tpm2::crypto::{DRBG_SEED_SIZE, Drbg};
        use crate::library::tpm2::failure_mode::FailureLocation;
        use aes::cipher::{BlockDecrypt, KeyInit};
        use std::cell::RefCell;

        thread_local! {
            static CRAFTED_ENTROPY: RefCell<[u8; 48]> = const { RefCell::new([0; 48]) };
        }
        fn crafted_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
            CRAFTED_ENTROPY.with(|crafted| buffer.copy_from_slice(&crafted.borrow()[..]));
            Ok(())
        }
        fn zero_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
            buffer.fill(0);
            Ok(())
        }

        const CONTINUOUS_TEST_PROFILE: &[u8] =
            br#"{"Name":"custom","Attributes":"drbg-continous-test"}"#;
        let mut runtime = started_runtime_with(Some(CONTINUOUS_TEST_PROFILE));
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED - 1;
        let before = snapshot(&runtime);

        let mut first_draw = Drbg::restore(
            &before.drbg.seed,
            CTR_DRBG_MAX_REQUESTS_PER_RESEED - 1,
            before.drbg.last_value,
            true,
        )
        .expect("the planted state restores");
        first_draw
            .generate(&mut [0u8; PRIMARY_SEED_SIZE])
            .expect("the first draw survives the continuous test");
        let seed_after_first = *first_draw.seed();
        let last_value_after_first = first_draw.last_value();

        let mut reseed_probe = Drbg::restore(
            &seed_after_first,
            CTR_DRBG_MAX_REQUESTS_PER_RESEED,
            last_value_after_first,
            true,
        )
        .expect("the post-first-draw state restores");
        reseed_probe
            .reseed_from_entropy(zero_entropy)
            .expect("the automatic reseed survives the continuous test");
        let update_stream_as_seed = *reseed_probe.seed();
        let last_value_after_reseed = reseed_probe.last_value();

        let mut colliding_block = [0u8; 16];
        for (index, word) in last_value_after_reseed.iter().enumerate() {
            colliding_block[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let chosen_key = [0x42u8; 32];
        let cipher = aes::Aes256::new(&chosen_key.into());
        let mut block = aes::Block::from(colliding_block);
        cipher.decrypt_block(&mut block);
        let mut chosen_iv: [u8; 16] = block.into();
        for byte in chosen_iv.iter_mut().rev() {
            if *byte == 0 {
                *byte = 0xff;
            } else {
                *byte -= 1;
                break;
            }
        }

        let mut desired_seed = [0u8; DRBG_SEED_SIZE];
        desired_seed[..32].copy_from_slice(&chosen_key);
        desired_seed[32..].copy_from_slice(&chosen_iv);
        CRAFTED_ENTROPY.with(|slot| {
            let mut crafted = [0u8; 48];
            for (index, byte) in crafted.iter_mut().enumerate() {
                *byte = update_stream_as_seed[index] ^ desired_seed[index];
            }
            *slot.borrow_mut() = crafted;
        });

        let mut collision_probe = Drbg::restore(
            &seed_after_first,
            CTR_DRBG_MAX_REQUESTS_PER_RESEED,
            last_value_after_first,
            true,
        )
        .expect("the collision probe restores");
        collision_probe
            .reseed_from_entropy(crafted_entropy)
            .expect("the crafted reseed succeeds");
        assert!(
            collision_probe.generate(&mut [0u8; PROOF_SIZE]).is_err(),
            "the crafted state collides at the second draw"
        );

        runtime.entropy = crafted_entropy;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics()
        );
        assert!(!runtime.entropy_bad);
        assert_eq!(
            snapshot(&runtime),
            Snapshot {
                failure_mode: true,
                ..before
            },
            "the first draw is not published after the fatal second draw"
        );
    }

    #[test]
    fn failed_nv_image_draw_consumption_rollback() {
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
        let counter_before = before.drbg.reseed_counter;

        let mut twin = started_runtime_with(Some(DEFAULT_V1_PROFILE));
        assert_eq!(
            drbg(&twin),
            before.drbg,
            "the twin starts from the same generator state"
        );
        regenerate_secret(&mut twin, PRIMARY_SEED_SIZE)
            .expect("the twin seed draw succeeds")
            .expect("the twin seed is drawn");
        regenerate_secret(&mut twin, PROOF_SIZE)
            .expect("the twin proof draw succeeds")
            .expect("the twin proof is drawn");

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        let after = drbg(&runtime);
        assert_ne!(after.seed, before.drbg.seed, "both draws remain consumed");
        assert_eq!(
            after.reseed_counter,
            counter_before + 2,
            "one advance for the seed draw and one for the proof draw"
        );
        assert_eq!(
            after,
            drbg(&twin),
            "the kept generator matches a twin that performed the same two draws"
        );
        assert_eq!(
            snapshot(&runtime),
            Snapshot {
                drbg: drbg(&twin),
                ..before
            },
            "everything except the consumed draws is rolled back"
        );
        assert!(!runtime.failure_mode);
        assert_eq!(runtime.failure_diagnostics, Default::default());
        assert!(!runtime.entropy_bad);
    }

    #[test]
    fn failed_capacity_check_draw_consumption_rollback() {
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
        let counter_before = before.drbg.reseed_counter;

        let mut twin = started_runtime_with(Some(DEFAULT_V1_PROFILE));
        assert_eq!(
            drbg(&twin),
            before.drbg,
            "the twin starts from the same generator state"
        );
        regenerate_secret(&mut twin, PRIMARY_SEED_SIZE)
            .expect("the twin seed draw succeeds")
            .expect("the twin seed is drawn");
        regenerate_secret(&mut twin, PROOF_SIZE)
            .expect("the twin proof draw succeeds")
            .expect("the twin proof is drawn");

        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
        let after = drbg(&runtime);
        assert_ne!(after.seed, before.drbg.seed, "both draws remain consumed");
        assert_eq!(
            after.reseed_counter,
            counter_before + 2,
            "the capacity failure happens after both draws"
        );
        assert_eq!(
            snapshot(&runtime),
            Snapshot {
                drbg: drbg(&twin),
                ..before
            },
            "everything except the consumed draws is rolled back"
        );
        assert!(!runtime.failure_mode);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn success_drbg_two_draws() {
        let mut runtime = started_runtime();
        let before = drbg(&runtime);

        let mut twin = started_runtime();
        let ep_seed = regenerate_secret(&mut twin, PRIMARY_SEED_SIZE)
            .expect("the seed draw succeeds")
            .expect("the seed is drawn");
        let eh_proof = regenerate_secret(&mut twin, PROOF_SIZE)
            .expect("the proof draw succeeds")
            .expect("the proof is drawn");

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
    fn new_seed_permanent_state_round_trip() {
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
    fn state_rewrite_blob_size_preservation() {
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
    fn success_single_nv_commit() {
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
    fn failure_no_nv_commit() {
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
    fn host_commit_failure_tpm_failure_mode() {
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
    fn undecoded_state_panic_safety() {
        use crate::library::tpm2::runtime::empty_state_runtime;

        let mut runtime = empty_state_runtime();
        runtime.startup_received = true;
        runtime.live.ph_enable = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &change_eps()),
            error_response(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
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
                    let _ = serialize_response(&dispatch(
                        &mut runtime,
                        &parsed,
                        CancellationToken::disabled(),
                    ));
                }
            }
        }
    }
}
