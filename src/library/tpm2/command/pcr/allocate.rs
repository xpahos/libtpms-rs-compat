use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_PCR,
    TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{algorithm_enabled, hash_profile_name};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::TPM_RH_PLATFORM;
use crate::library::tpm2::marshal::{BlobReader, BlobWriter};
use crate::library::tpm2::nv::build_nv_image;
use crate::library::tpm2::pcr::{
    DRTM_PCR, HASH_COUNT, HCRTM_PCR, PCR_SELECT_MAX, PCR_SELECT_MIN, PCR_SLOT_BANKS, bank_slot,
};
use crate::library::tpm2::persistent::{OwnedPcrAllocation, OwnedPcrSelection};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_PCR_ALLOCATE_PCR_ALLOCATION: TpmResult = TPM_RC_P + TPM_RC_1;

const YES: u8 = 1;

const SIZE_AVAILABLE: u32 = {
    let mut per_pcr = 0usize;
    let mut index = 0;
    while index < PCR_SLOT_BANKS.len() {
        per_pcr += PCR_SLOT_BANKS[index].1;
        index += 1;
    }
    (IMPLEMENTATION_PCR * per_pcr) as u32
};

const MAX_PCR: u32 = IMPLEMENTATION_PCR as u32;

struct SelectionIn {
    hash_alg: u16,
    select: Vec<u8>,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    if auth_handle != TPM_RH_PLATFORM {
        return Err(TPM_RC_FAILURE);
    }

    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let requested = parse_parameters(&state.profile.algorithms, frame.parameters)?;

    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let active = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
    let allocation = merge_allocation(active, &requested)?;
    let size_needed = size_needed(&allocation);
    if !covers_required_pcrs(&allocation) {
        return Err(TPM_RC_PCR);
    }
    let active = active.clone();

    commit_allocation(runtime, active, allocation)?;

    Ok(CommandOutput::from_parameters(marshal_response(
        YES,
        size_needed,
    )))
}

fn parse_parameters(
    profile_algorithms: &[u8],
    parameters: &[u8],
) -> Result<Vec<SelectionIn>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let count = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_ALLOCATE_PCR_ALLOCATION)?;
    if count > HASH_COUNT as u32 {
        return Err(TPM_RC_SIZE + RC_PCR_ALLOCATE_PCR_ALLOCATION);
    }
    let mut selections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        selections.push(parse_selection(profile_algorithms, &mut reader)?);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(selections)
}

fn parse_selection(
    profile_algorithms: &[u8],
    reader: &mut BlobReader<'_>,
) -> Result<SelectionIn, TpmResult> {
    let hash_alg = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_ALLOCATE_PCR_ALLOCATION)?;
    let enabled = bank_slot(hash_alg).is_some()
        && hash_profile_name(hash_alg)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH + RC_PCR_ALLOCATE_PCR_ALLOCATION);
    }
    let sizeof_select = usize::from(
        reader
            .read_u8()
            .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_ALLOCATE_PCR_ALLOCATION)?,
    );
    if !(PCR_SELECT_MIN..=PCR_SELECT_MAX).contains(&sizeof_select) {
        return Err(TPM_RC_VALUE + RC_PCR_ALLOCATE_PCR_ALLOCATION);
    }
    let select = reader
        .take(sizeof_select)
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_ALLOCATE_PCR_ALLOCATION)?
        .to_vec();
    Ok(SelectionIn { hash_alg, select })
}

fn merge_allocation(
    active: &OwnedPcrAllocation,
    requested: &[SelectionIn],
) -> Result<OwnedPcrAllocation, TpmResult> {
    let mut allocation = active.clone();
    for selection in requested {
        let slot = allocation
            .selections
            .iter_mut()
            .find(|entry| entry.hash_alg == selection.hash_alg)
            .ok_or(TPM_RC_FAILURE)?;
        *slot = OwnedPcrSelection {
            hash_alg: selection.hash_alg,
            select: selection.select.clone(),
        };
    }
    Ok(allocation)
}

fn selects(selection: &OwnedPcrSelection, pcr: usize) -> bool {
    selection
        .select
        .get(pcr / 8)
        .is_some_and(|byte| byte & (1 << (pcr % 8)) != 0)
}

fn covers_required_pcrs(allocation: &OwnedPcrAllocation) -> bool {
    let covers = |pcr: usize| {
        allocation
            .selections
            .iter()
            .any(|selection| selects(selection, pcr))
    };
    covers(HCRTM_PCR) && covers(DRTM_PCR)
}

fn size_needed(allocation: &OwnedPcrAllocation) -> u32 {
    allocation
        .selections
        .iter()
        .map(|selection| {
            let digest_size = bank_slot(selection.hash_alg).map_or(0, |(_, size)| size) as u32;
            let bits: u32 = selection
                .select
                .iter()
                .map(|byte| byte.count_ones())
                .sum::<u32>();
            digest_size.saturating_mul(bits)
        })
        .fold(0u32, u32::wrapping_add)
}

fn commit_allocation(
    runtime: &mut Tpm2Runtime,
    active: OwnedPcrAllocation,
    allocation: OwnedPcrAllocation,
) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = core::mem::replace(&mut state.persistent.pcr_allocated, allocation);
    let image = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            state.persistent.pcr_allocated = backup;
            return Err(TPM_RC_FAILURE);
        }
    };
    runtime.nv_memory = image;
    runtime.live_pcr_allocated = Some(active);
    runtime.live.pcr_reconfig = true;
    runtime.nv_update_pending = true;
    Ok(())
}

fn marshal_response(allocation_success: u8, size_needed: u32) -> Vec<u8> {
    let mut writer = BlobWriter::with_capacity(13);
    writer.write_u8(allocation_success);
    writer.write_u32(MAX_PCR);
    writer.write_u32(size_needed);
    writer.write_u32(SIZE_AVAILABLE);
    writer.into_bytes()
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
    use crate::library::constants::{TPM_RC_INITIALIZE, TPM_SUCCESS};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_PCR_ALLOCATE;
    use crate::library::tpm2::command::session::processing::TPM_RS_PW;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_LOCKOUT, TPM_RH_NULL, TPM_RH_OWNER,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::parse_persistent_all_payload;
    use crate::library::tpm2::persistent::{
        OwnedPersistentState, PersistentAllEnvelope, materialize_persistent_state,
        persistent_all_store,
    };
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, commit_restored_state};

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const SHA1_SLOT: usize = 0;
    const SHA256_SLOT: usize = 1;
    const SHA384_SLOT: usize = 2;
    const SHA512_SLOT: usize = 3;

    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_PCR_IMPROPER: u32 = 0x127;
    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_SIZE: u32 = 0x095;
    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_PARAM1_INSUFFICIENT: u32 = 0x1da;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM1_HASH: u32 = 0x1c3;
    const RC_PARAM1_VALUE: u32 = 0x1c4;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
    const RC_SHUTDOWN_TYPE_PARAM1: u32 = 0x1ca;

    const ORACLE_SIZE_AVAILABLE: u32 = 0x0f60;
    const ORACLE_MAX_PCR: u32 = 24;

    const FULL_SIZE_NEEDED: u32 = 0x0f60;

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

    fn manufactured_runtime() -> Tpm2Runtime {
        let profile = validate_user_profile(None).expect("the null profile validates");
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
    fn started_runtime() -> Tpm2Runtime {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup_command()),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn sel(hash_alg: u16, bitmap: [u8; 3]) -> Vec<u8> {
        let mut out = hash_alg.to_be_bytes().to_vec();
        out.push(3);
        out.extend_from_slice(&bitmap);
        out
    }

    fn params(selections: &[(u16, [u8; 3])]) -> Vec<u8> {
        let mut out = (selections.len() as u32).to_be_bytes().to_vec();
        for &(hash_alg, bitmap) in selections {
            out.extend_from_slice(&sel(hash_alg, bitmap));
        }
        out
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
        out.extend_from_slice(&TPM_CC_PCR_ALLOCATE.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn allocate(parameters: &[u8]) -> Vec<u8> {
        command(TPM_RH_PLATFORM, Some(&pw_session(&[])), parameters)
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn success_response(size_needed: u32) -> Vec<u8> {
        let mut out = hex("8002 00000020 00000000 0000000d 01");
        out.extend_from_slice(&ORACLE_MAX_PCR.to_be_bytes());
        out.extend_from_slice(&size_needed.to_be_bytes());
        out.extend_from_slice(&ORACLE_SIZE_AVAILABLE.to_be_bytes());
        out.extend_from_slice(&hex("0000 01 0000"));
        out
    }

    fn cap_pcrs_command() -> Vec<u8> {
        hex("80010000001600 00017a 00000005 00000000 00000004")
    }

    fn shutdown_command(shutdown_type: u16) -> Vec<u8> {
        let mut out = hex("80010000000c00000145");
        out.extend_from_slice(&shutdown_type.to_be_bytes());
        out
    }

    fn allocation_of(runtime: &Tpm2Runtime) -> Vec<(u16, Vec<u8>)> {
        runtime
            .state()
            .persistent
            .pcr_allocated
            .selections
            .iter()
            .map(|entry| (entry.hash_alg, entry.select.clone()))
            .collect()
    }

    fn active_allocation_of(runtime: &Tpm2Runtime) -> Vec<(u16, Vec<u8>)> {
        runtime
            .effective_pcr_allocated()
            .expect("the runtime carries an allocation")
            .selections
            .iter()
            .map(|entry| (entry.hash_alg, entry.select.clone()))
            .collect()
    }

    fn manufactured_allocation() -> Vec<(u16, Vec<u8>)> {
        [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512]
            .into_iter()
            .map(|alg| (alg, vec![0xff, 0xff, 0xff]))
            .collect()
    }

    struct Snapshot {
        failure_mode: bool,
        nv_update_pending: bool,
        pcr_reconfig: bool,
        persistent_allocation: Vec<(u16, Vec<u8>)>,
        live_allocation: Option<Vec<(u16, Vec<u8>)>>,
        nv_memory: Box<[u8]>,
        orderly_state: u16,
        pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
        pcr_counter: Option<u32>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            pcr_reconfig: runtime.live.pcr_reconfig,
            persistent_allocation: allocation_of(runtime),
            live_allocation: runtime.live_pcr_allocated.as_ref().map(|allocation| {
                allocation
                    .selections
                    .iter()
                    .map(|entry| (entry.hash_alg, entry.select.clone()))
                    .collect()
            }),
            nv_memory: runtime.nv_memory.clone(),
            orderly_state: runtime.state().persistent.orderly_state,
            pcr_banks: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.to_vec())
                .collect(),
            pcr_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(runtime.failure_mode, before.failure_mode);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(runtime.live.pcr_reconfig, before.pcr_reconfig);
        assert_eq!(allocation_of(runtime), before.persistent_allocation);
        assert_eq!(
            runtime.live_pcr_allocated.as_ref().map(|allocation| {
                allocation
                    .selections
                    .iter()
                    .map(|entry| (entry.hash_alg, entry.select.clone()))
                    .collect::<Vec<_>>()
            }),
            before.live_allocation
        );
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert_eq!(
            runtime.state().persistent.orderly_state,
            before.orderly_state
        );
        let pcr_banks: Vec<Vec<Option<Vec<u8>>>> = runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.to_vec())
            .collect();
        assert_eq!(pcr_banks, before.pcr_banks);
        assert_eq!(
            runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            before.pcr_counter
        );
    }

    #[track_caller]
    fn reload(state: &OwnedPersistentState) -> OwnedPersistentState {
        let blob = persistent_all_store(state).expect("the state serializes");
        let envelope = PersistentAllEnvelope::parse(&blob).expect("the envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload parses");
        materialize_persistent_state(decoded).expect("the payload materializes")
    }

    #[track_caller]
    fn rebooted_runtime(runtime: &Tpm2Runtime) -> Tpm2Runtime {
        let restored = reload(runtime.state());
        let mut rebooted = commit_restored_state(restored).expect("the persisted state restores");
        rebooted.entropy = deterministic_entropy;
        rebooted
    }

    #[test]
    fn pre_startup_rejection() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &allocate(&params(&[]))),
            error_response(TPM_RC_INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000a0000012b")),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes handle unmarshalling"
        );
    }

    #[test]
    fn valid_platform_password_authorization_success() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]))
            ),
            success_response(FULL_SIZE_NEEDED)
        );
    }

    #[test]
    fn platform_hierarchy_only() {
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_ENDORSEMENT,
            TPM_RH_LOCKOUT,
            TPM_RH_NULL,
            0x0000_0000,
            0x0000_0017,
            0x8100_0000,
            u32::MAX,
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let bytes = command(
                handle,
                Some(&pw_session(&[])),
                &params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]),
            );
            assert_eq!(
                dispatch_bytes(&mut runtime, &bytes),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_handle_insufficient_first_handle() {
        for payload in [&[][..], &[0x40][..], &[0x40, 0x00, 0x00][..]] {
            let mut runtime = started_runtime();
            let mut bytes = hex("8002");
            bytes.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&TPM_CC_PCR_ALLOCATE.to_be_bytes());
            bytes.extend_from_slice(payload);
            assert_eq!(
                dispatch_bytes(&mut runtime, &bytes),
                error_response(RC_HANDLE1_INSUFFICIENT),
                "payload {payload:02x?}"
            );
        }
    }

    #[test]
    fn missing_auth_area_auth_missing() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let bytes = command(
            TPM_RH_PLATFORM,
            None,
            &params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]),
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &bytes),
            error_response(RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn wrong_platform_password_bad_auth_first_session() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let bytes = command(
            TPM_RH_PLATFORM,
            Some(&pw_session(b"wrong")),
            &params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]),
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &bytes),
            error_response(RC_SESSION1_BAD_AUTH),
            "the platform hierarchy is DA exempt, so it never answers TPM_RC_AUTH_FAIL"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn configured_platform_password_authorization() {
        let mut runtime = started_runtime();
        runtime
            .live
            .state_clear
            .as_mut()
            .expect("startup installed the clear state")
            .platform_auth = crate::library::tpm2::persistent::OwnedSecret::copy_of(b"platform");
        let selections = params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&pw_session(&[])), &selections)
            ),
            error_response(RC_SESSION1_BAD_AUTH)
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_PLATFORM, Some(&pw_session(b"platform")), &selections)
            ),
            success_response(FULL_SIZE_NEEDED)
        );
    }

    #[test]
    fn truncated_selection_list_insufficient_first_parameter() {
        let full = params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]);
        for len in 0..full.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &allocate(&full[..len])),
                error_response(RC_PARAM1_INSUFFICIENT),
                "parameter length {len}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn count_above_hash_count_size_error_no_entry_read() {
        for count in [5u32, 100, u32::MAX] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &allocate(&count.to_be_bytes())),
                error_response(RC_PARAM1_SIZE),
                "count {count}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn unsupported_hash_algorithm_hash_error() {
        for alg in [0x0000u16, 0x0010, 0x0012, 0x0027, 0xffff] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &allocate(&params(&[(alg, [0xff; 3])]))),
                error_response(RC_PARAM1_HASH),
                "alg {alg:#06x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn later_bad_hash_first_parameter_index() {
        let mut runtime = started_runtime();
        let mut parameters = 2u32.to_be_bytes().to_vec();
        parameters.extend_from_slice(&sel(TPM_ALG_SHA256, [0xff, 0xff, 0xff]));
        parameters.extend_from_slice(&sel(0x0010, [0, 0, 0]));
        assert_eq!(
            dispatch_bytes(&mut runtime, &allocate(&parameters)),
            error_response(RC_PARAM1_HASH)
        );
    }

    #[test]
    fn sizeof_select_out_of_range_value_error() {
        for (size, bitmap_len) in [(0u8, 0usize), (1, 1), (2, 2), (4, 4), (255, 3)] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut parameters = 1u32.to_be_bytes().to_vec();
            parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            parameters.push(size);
            parameters.extend_from_slice(&vec![0xffu8; bitmap_len]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &allocate(&parameters)),
                error_response(RC_PARAM1_VALUE),
                "sizeofSelect {size}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameter_bytes_undecorated_size_error() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let mut parameters = params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]);
        parameters.push(0xee);
        assert_eq!(
            dispatch_bytes(&mut runtime, &allocate(&parameters)),
            error_response(RC_SIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn prefix_bit_flip_panic_safety() {
        let valid = allocate(&params(&[
            (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
            (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
        ]));
        for len in 10..=valid.len() {
            for index in 6..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
                    mutated[index] ^= flip;
                    let mut runtime = started_runtime();
                    let input = CommandInput::new(mutated.len() as u32, mutated);
                    let parsed = parse_command(&input).expect("the header parses");
                    let _ = serialize_response(&dispatch(
                        &mut runtime,
                        &parsed,
                        CancellationToken::disabled(),
                    ));
                }
            }
        }
    }

    #[test]
    fn empty_selection_list_bank_preservation_full_size() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &allocate(&params(&[]))),
            success_response(FULL_SIZE_NEEDED)
        );
        assert_eq!(allocation_of(&runtime), manufactured_allocation());
    }

    #[test]
    fn omitted_bank_allocation_preservation() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA256, [0x01, 0x00, 0x02])]))
            ),
            success_response(0x0ca0),
            "SHA-1, SHA-384 and SHA-512 keep all 24 PCRs; SHA-256 keeps two"
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA256, vec![0x01, 0x00, 0x02]),
                (TPM_ALG_SHA384, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA512, vec![0xff, 0xff, 0xff]),
            ]
        );
    }

    #[test]
    fn supplied_bank_in_place_replacement() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[(TPM_ALG_SHA512, [0x01, 0x00, 0x02])])),
        );
        assert_eq!(
            allocation_of(&runtime)[3],
            (TPM_ALG_SHA512, vec![0x01, 0x00, 0x02]),
            "the bank keeps its position in the list"
        );
    }

    #[test]
    fn duplicated_bank_last_occurrence_precedence() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA256, [0x01, 0x00, 0x02]),
                ]))
            ),
            success_response(0x0640)
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA256, vec![0x01, 0x00, 0x02]),
                (TPM_ALG_SHA384, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, vec![0xff, 0xff, 0xff]),
            ]
        );
    }

    #[test]
    fn missing_hcrtm_pcr_improper() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA1, [0xfe, 0xff, 0xff]),
                    (TPM_ALG_SHA256, [0xfe, 0xff, 0xff]),
                    (TPM_ALG_SHA384, [0xfe, 0xff, 0xff]),
                    (TPM_ALG_SHA512, [0xfe, 0xff, 0xff]),
                ]))
            ),
            error_response(RC_PCR_IMPROPER)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn missing_drtm_pcr_improper() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA1, [0xff, 0xff, 0xfd]),
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xfd]),
                    (TPM_ALG_SHA384, [0xff, 0xff, 0xfd]),
                    (TPM_ALG_SHA512, [0xff, 0xff, 0xfd]),
                ]))
            ),
            error_response(RC_PCR_IMPROPER)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn empty_allocation_improper() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA256, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            error_response(RC_PCR_IMPROPER)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn hcrtm_drtm_split_banks_acceptance() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA1, [0x01, 0x00, 0x00]),
                    (TPM_ALG_SHA256, [0x00, 0x00, 0x02]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            success_response(0x0034),
            "one SHA-1 digest for the H-CRTM PCR and one SHA-256 digest for the DRTM PCR"
        );
    }

    #[test]
    fn sha256_only_allocation_oracle_match() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            hex("800200000020 00000000 0000000d 01 00000018 00000300 00000f60 000001 0000")
        );
    }

    #[test]
    fn two_active_bank_size_sum_reporting() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA384, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            success_response(0x0780),
            "24 * (32 + 48)"
        );
    }

    #[test]
    fn size_needed_per_selected_bit_digest_count() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA1, [0xff, 0x00, 0x02]),
                    (TPM_ALG_SHA256, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            success_response(0x00b4),
            "nine SHA-1 PCRs at 20 bytes each"
        );
    }

    #[test]
    fn max_pcr_size_available_build_constants() {
        assert_eq!(MAX_PCR, ORACLE_MAX_PCR);
        assert_eq!(SIZE_AVAILABLE, ORACLE_SIZE_AVAILABLE);
        assert_eq!(
            SIZE_AVAILABLE,
            (IMPLEMENTATION_PCR * (20 + 32 + 48 + 64)) as u32
        );
    }

    #[test]
    fn response_field_order() {
        assert_eq!(
            marshal_response(YES, 0x0102_0304),
            hex("01 00000018 01020304 00000f60")
        );
    }

    #[test]
    fn second_allocation_active_base() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            success_response(0x0300)
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA384, [0xff, 0xff, 0xff])]))
            ),
            success_response(FULL_SIZE_NEEDED),
            "the omitted banks come from the active allocation, not the pending one"
        );
        assert_eq!(allocation_of(&runtime), manufactured_allocation());
    }

    #[test]
    fn requested_bank_missing_internal_failure() {
        let mut runtime = started_runtime();
        runtime
            .state
            .as_mut()
            .unwrap()
            .persistent
            .pcr_allocated
            .selections
            .retain(|entry| entry.hash_alg != TPM_ALG_SHA1);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA1, [0xff, 0xff, 0xff])]))
            ),
            error_response(TPM_RC_FAILURE),
            "upstream's pAssert(j < newAllocate.count) fails the TPM here"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn same_boot_capability_old_allocation() {
        let mut runtime = started_runtime();
        let before = dispatch_bytes(&mut runtime, &cap_pcrs_command());
        assert_eq!(
            before,
            hex("80010000002b 00000000 00 00000005 00000004 \
                 000403ffffff 000b03ffffff 000c03ffffff 000d03ffffff")
        );
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[
                (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
            ])),
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &cap_pcrs_command()),
            before,
            "the reconfiguration only takes effect on the next startup"
        );
        assert_eq!(active_allocation_of(&runtime), manufactured_allocation());
    }

    #[test]
    fn persistent_state_requested_allocation() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[
                (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
            ])),
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA256, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA384, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, vec![0x00, 0x00, 0x00]),
            ]
        );
        assert!(runtime.live.pcr_reconfig);
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn pending_reconfiguration_state_shutdown_rejection() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])])),
        );
        assert!(runtime.live.pcr_reconfig);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0001)),
            error_response(RC_SHUTDOWN_TYPE_PARAM1)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0000)),
            error_response(TPM_SUCCESS),
            "TPM_SU_CLEAR is the shutdown swtpm_setup uses"
        );
    }

    #[test]
    fn new_allocation_active_after_reload_startup() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[
                (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
            ])),
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0000)),
            error_response(TPM_SUCCESS)
        );

        let mut rebooted = rebooted_runtime(&runtime);
        assert_eq!(
            allocation_of(&rebooted),
            allocation_of(&runtime),
            "serialize/reload preserves the requested allocation"
        );
        assert_eq!(
            dispatch_bytes(&mut rebooted, &startup_command()),
            error_response(TPM_SUCCESS)
        );
        assert!(
            !rebooted.live.pcr_reconfig,
            "startup clears the reconfiguration flag"
        );
        assert_eq!(
            dispatch_bytes(&mut rebooted, &cap_pcrs_command()),
            hex("80010000002b 00000000 00 00000005 00000004 \
                 000403000000 000b03ffffff 000c03000000 000d03000000")
        );
    }

    #[test]
    fn pcr_value_rebuild_new_allocation() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[
                (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
            ])),
        );
        dispatch_bytes(&mut runtime, &shutdown_command(0x0000));
        let mut rebooted = rebooted_runtime(&runtime);
        dispatch_bytes(&mut rebooted, &startup_command());

        for pcr in 0..IMPLEMENTATION_PCR {
            let banks = &rebooted.live.pcrs[pcr].banks;
            assert!(banks[SHA1_SLOT].is_none(), "PCR {pcr} SHA-1 is deallocated");
            assert!(banks[SHA384_SLOT].is_none(), "PCR {pcr} SHA-384");
            assert!(banks[SHA512_SLOT].is_none(), "PCR {pcr} SHA-512");
            assert_eq!(
                banks[SHA256_SLOT].as_ref().map(Vec::len),
                Some(32),
                "PCR {pcr} SHA-256 stays allocated"
            );
        }
        assert_eq!(
            dispatch_bytes(
                &mut rebooted,
                &hex("80010000001400 00017e 00000001 000403010000")
            ),
            hex("80010000001c 00000000 00000014 00000001 000403000000 00000000"),
            "a read of the deallocated SHA-1 bank clears the selection"
        );
    }

    #[test]
    fn nv_unavailable_report_before_state_change() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]))
            ),
            error_response(RC_NV_UNAVAILABLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn malformed_request_report_no_nv() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        assert_eq!(
            dispatch_bytes(&mut runtime, &allocate(&5u32.to_be_bytes())),
            error_response(RC_PARAM1_SIZE),
            "the dispatcher unmarshals the parameters before the NV check"
        );
    }

    #[test]
    fn unbuildable_nv_image_allocation_unchanged() {
        let mut runtime = started_runtime();
        let extra = runtime.state().persistent.pcr_allocated.selections[1].clone();
        runtime
            .state
            .as_mut()
            .unwrap()
            .persistent
            .pcr_allocated
            .selections
            .push(extra);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA256, [0x01, 0x00, 0x02])]))
            ),
            error_response(TPM_RC_FAILURE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn successful_allocation_single_nv_commit() {
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

        let bytes = allocate(&params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]));
        let input = CommandInput::new(bytes.len() as u32, bytes);
        assert_eq!(
            process(&mut runtime, 0, &input, count).expect("the command processes"),
            success_response(FULL_SIZE_NEEDED)
        );
        assert_eq!(commits.get(), 2, "one commit for the allocation");
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn failed_allocation_no_nv_commit() {
        let commits = core::cell::Cell::new(0u32);
        let count = |_: &Tpm2Runtime| -> Result<(), TpmResult> {
            commits.set(commits.get() + 1);
            Ok(())
        };

        let mut runtime = started_runtime();
        for parameters in [
            params(&[
                (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA256, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
            ]),
            params(&[(0x0010, [0xff, 0xff, 0xff])]),
            5u32.to_be_bytes().to_vec(),
        ] {
            let bytes = allocate(&parameters);
            let input = CommandInput::new(bytes.len() as u32, bytes);
            let response = process(&mut runtime, 0, &input, count).expect("the command processes");
            assert_ne!(&response[6..10], &[0, 0, 0, 0], "{parameters:02x?}");
        }
        assert_eq!(commits.get(), 0);
    }

    #[test]
    fn host_commit_failure_tpm_failure_mode() {
        let mut runtime = started_runtime();
        let bytes = allocate(&params(&[(TPM_ALG_SHA256, [0xff, 0xff, 0xff])]));
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(&mut runtime, 0, &input, |_| Err(TPM_RC_FAILURE))
            .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert!(runtime.failure_mode);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn sha1_disabled_profile_rejection() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().profile.algorithms =
            b"sha256,sha384,sha512,aes,null".to_vec();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA1, [0xff, 0xff, 0xff])]))
            ),
            error_response(RC_PARAM1_HASH)
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
                ]))
            ),
            success_response(0x04e0),
            "the disabled SHA-1 bank still holds its 24 allocated PCRs"
        );
    }

    #[test]
    fn sha512_disabled_profile_rejection() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().profile.algorithms =
            b"sha1,sha256,sha384,aes,null".to_vec();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA512, [0xff, 0xff, 0xff])]))
            ),
            error_response(RC_PARAM1_HASH)
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[
                    (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                    (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                    (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                ]))
            ),
            success_response(0x0900),
            "the disabled SHA-512 bank still holds its 24 allocated PCRs"
        );
    }

    #[test]
    fn restored_persistent_allocation_merge_base() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[
                (TPM_ALG_SHA256, [0xff, 0xff, 0xff]),
                (TPM_ALG_SHA1, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
            ])),
        );
        dispatch_bytes(&mut runtime, &shutdown_command(0x0000));

        let mut rebooted = rebooted_runtime(&runtime);
        dispatch_bytes(&mut rebooted, &startup_command());
        rebooted.nv_update_pending = false;
        assert_eq!(
            dispatch_bytes(
                &mut rebooted,
                &allocate(&params(&[(TPM_ALG_SHA1, [0xff, 0xff, 0xff])]))
            ),
            success_response(0x04e0),
            "24 SHA-1 plus the 24 SHA-256 PCRs the restored allocation kept"
        );
    }

    #[test]
    fn restored_shadow_allocation_precedence() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![
                OwnedPcrSelection {
                    hash_alg: TPM_ALG_SHA1,
                    select: vec![0x01, 0x00, 0x02],
                },
                OwnedPcrSelection {
                    hash_alg: TPM_ALG_SHA256,
                    select: vec![0x00, 0x00, 0x00],
                },
                OwnedPcrSelection {
                    hash_alg: TPM_ALG_SHA384,
                    select: vec![0x00, 0x00, 0x00],
                },
                OwnedPcrSelection {
                    hash_alg: TPM_ALG_SHA512,
                    select: vec![0x00, 0x00, 0x00],
                },
            ],
        });
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &allocate(&params(&[(TPM_ALG_SHA256, [0x01, 0x00, 0x02])]))
            ),
            success_response(0x0068),
            "two SHA-1 and two SHA-256 digests, from the shadow allocation"
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0x01, 0x00, 0x02]),
                (TPM_ALG_SHA256, vec![0x01, 0x00, 0x02]),
                (TPM_ALG_SHA384, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, vec![0x00, 0x00, 0x00]),
            ]
        );
    }

    const SWTPM_SETUP_SHA256: &str = "8002 00000037 0000012b 4000000c 00000009 \
         40000009 0000 00 0000 \
         00000004 000b03ffffff 000403000000 000c03000000 000d03000000";

    const SWTPM_SETUP_SHA256_SHA384: &str = "8002 00000037 0000012b 4000000c 00000009 \
         40000009 0000 00 0000 \
         00000004 000b03ffffff 000c03ffffff 000403000000 000d03000000";

    const SWTPM_SETUP_SHA256_NO_SHA1: &str = "8002 00000031 0000012b 4000000c 00000009 \
         40000009 0000 00 0000 \
         00000003 000b03ffffff 000c03000000 000d03000000";

    #[test]
    fn swtpm_setup_sha256_oracle_match() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex(SWTPM_SETUP_SHA256)),
            hex("800200000020 00000000 0000000d 01 00000018 00000300 00000f60 000001 0000")
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA256, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA384, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, vec![0x00, 0x00, 0x00]),
            ],
            "the non-selected banks are disabled for the next boot"
        );
        assert!(runtime.live.pcr_reconfig);
        assert_eq!(
            dispatch_bytes(&mut runtime, &shutdown_command(0x0000)),
            error_response(TPM_SUCCESS),
            "swtpm_setup finishes with TPM2_Shutdown(TPM_SU_CLEAR)"
        );
    }

    #[test]
    fn swtpm_setup_two_bank_oracle_match() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex(SWTPM_SETUP_SHA256_SHA384)),
            hex("800200000020 00000000 0000000d 01 00000018 00000780 00000f60 000001 0000")
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA256, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA384, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA512, vec![0x00, 0x00, 0x00]),
            ]
        );
    }

    #[test]
    fn swtpm_setup_sha1_disabled_profile_oracle_match() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().profile.algorithms =
            b"sha256,sha384,sha512,aes,null".to_vec();
        assert_eq!(
            dispatch_bytes(&mut runtime, &cap_pcrs_command()),
            hex("800100000025 00000000 00 00000005 00000003 \
                 000b03ffffff 000c03ffffff 000d03ffffff"),
            "the SHA-1 bank never reaches swtpm_setup's all_pcr_banks list"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex(SWTPM_SETUP_SHA256_NO_SHA1)),
            hex("800200000020 00000000 0000000d 01 00000018 000004e0 00000f60 000001 0000"),
            "the hidden SHA-1 bank keeps all 24 PCRs and its digests in sizeNeeded"
        );
        assert_eq!(
            allocation_of(&runtime),
            [
                (TPM_ALG_SHA1, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA256, vec![0xff, 0xff, 0xff]),
                (TPM_ALG_SHA384, vec![0x00, 0x00, 0x00]),
                (TPM_ALG_SHA512, vec![0x00, 0x00, 0x00]),
            ]
        );
    }

    #[test]
    fn profile_unavailable_bank_request_rejection() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().profile.algorithms =
            b"sha256,sha384,sha512,aes,null".to_vec();
        let before = snapshot(&runtime);
        let mut request = hex("8002 00000031 0000012b 4000000c 00000009 40000009 0000 00 0000");
        request.extend_from_slice(&params(&[
            (TPM_ALG_SHA1, [0xff, 0xff, 0xff]),
            (TPM_ALG_SHA384, [0x00, 0x00, 0x00]),
            (TPM_ALG_SHA512, [0x00, 0x00, 0x00]),
        ]));
        assert_eq!(
            dispatch_bytes(&mut runtime, &request),
            error_response(RC_PARAM1_HASH),
            "swtpm_setup never builds this, but a hand-built request is refused"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn allocation_serialize_reload_round_trip() {
        let mut runtime = started_runtime();
        dispatch_bytes(
            &mut runtime,
            &allocate(&params(&[(TPM_ALG_SHA384, [0x01, 0x20, 0x02])])),
        );
        let expected = allocation_of(&runtime);
        let once = commit_restored_state(reload(runtime.state())).expect("restores");
        assert_eq!(allocation_of(&once), expected);
        let twice = commit_restored_state(reload(once.state())).expect("restores");
        assert_eq!(allocation_of(&twice), expected);
        assert_eq!(
            persistent_all_store(once.state()).unwrap(),
            persistent_all_store(twice.state()).unwrap()
        );
    }
}
