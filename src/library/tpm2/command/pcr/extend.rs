use super::update::{
    commit_orderly_clear, commit_pcr_counter, live_pcr_counter, pcr_changed, prepare_orderly_clear,
};
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_LOCALITY, TPM_RC_SIZE,
};
use crate::library::tpm2::algorithm::{algorithm_enabled, hash_profile_name};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::TPM_RH_NULL;
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::pcr::{
    BankHasher, HASH_COUNT, PCR_SLOT_BANKS, allocation_selects, bank_slot, pcr_extend_allowed,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_PCR_EXTEND_DIGESTS: TpmResult = TPM_RC_P + TPM_RC_1;

pub(in crate::library::tpm2::command) struct DigestValue<'a> {
    pub(in crate::library::tpm2::command) slot: usize,
    pub(in crate::library::tpm2::command) digest: &'a [u8],
}

pub(in crate::library::tpm2::command) struct PreparedExtend {
    banks: [Option<Vec<u8>>; PCR_SLOT_BANKS.len()],
    pcr_counter: u32,
    orderly_state: Option<u16>,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let pcr_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let digests = parse_digests(&state.profile.algorithms, frame.parameters)?;

    if pcr_handle == TPM_RH_NULL {
        return Ok(CommandOutput::empty());
    }
    let pcr = pcr_handle as usize;
    if !pcr_extend_allowed(pcr, runtime.locality) {
        return Err(TPM_RC_LOCALITY);
    }

    let prepared = prepare_extend(runtime, pcr, &digests)?;
    commit_extend(runtime, pcr, prepared)?;
    Ok(CommandOutput::empty())
}

fn parse_digests<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<Vec<DigestValue<'a>>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let count = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_EXTEND_DIGESTS)?;
    if count > HASH_COUNT as u32 {
        return Err(TPM_RC_SIZE + RC_PCR_EXTEND_DIGESTS);
    }
    let mut digests = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let hash_alg = reader
            .read_u16()
            .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_EXTEND_DIGESTS)?;
        let enabled = hash_profile_name(hash_alg)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
        let Some((slot, digest_size)) = bank_slot(hash_alg).filter(|_| enabled) else {
            return Err(TPM_RC_HASH + RC_PCR_EXTEND_DIGESTS);
        };
        let digest = reader
            .take(digest_size)
            .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_EXTEND_DIGESTS)?;
        digests.push(DigestValue { slot, digest });
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(digests)
}

pub(in crate::library::tpm2::command) fn prepare_extend(
    runtime: &Tpm2Runtime,
    pcr: usize,
    digests: &[DigestValue<'_>],
) -> Result<PreparedExtend, TpmResult> {
    let orderly_state = prepare_orderly_clear(runtime, pcr)?;

    let allocation = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
    let live = runtime.live.pcrs.get(pcr).ok_or(TPM_RC_FAILURE)?;
    let mut banks: [Option<Vec<u8>>; PCR_SLOT_BANKS.len()] = core::array::from_fn(|_| None);
    let mut pcr_counter = live_pcr_counter(runtime)?;

    for entry in digests {
        let (hash_alg, digest_size) = PCR_SLOT_BANKS
            .get(entry.slot)
            .copied()
            .ok_or(TPM_RC_FAILURE)?;
        if !allocation_selects(allocation, hash_alg, pcr) {
            continue;
        }
        let current = match banks[entry.slot].as_deref() {
            Some(value) => value,
            None => live.banks[entry.slot].as_deref().ok_or(TPM_RC_FAILURE)?,
        };
        if current.len() != digest_size {
            return Err(TPM_RC_FAILURE);
        }
        let extended =
            BankHasher::extend(entry.slot, current, entry.digest).ok_or(TPM_RC_FAILURE)?;
        banks[entry.slot] = Some(extended);
        pcr_counter = pcr_changed(pcr_counter, pcr)?;
    }

    Ok(PreparedExtend {
        banks,
        pcr_counter,
        orderly_state,
    })
}

pub(in crate::library::tpm2::command) fn commit_extend(
    runtime: &mut Tpm2Runtime,
    pcr: usize,
    prepared: PreparedExtend,
) -> Result<(), TpmResult> {
    commit_orderly_clear(runtime, prepared.orderly_state)?;

    let live_pcr = runtime.live.pcrs.get_mut(pcr).ok_or(TPM_RC_FAILURE)?;
    for (slot, value) in prepared.banks.into_iter().enumerate() {
        if let Some(value) = value {
            live_pcr.banks[slot] = Some(value);
        }
    }
    commit_pcr_counter(runtime, prepared.pcr_counter)
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
    use crate::library::constants::{TPM_RC_AUTH_MISSING, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_PCR_EXTEND;
    use crate::library::tpm2::command::session::processing::{
        HMAC_SESSION_FIRST, POLICY_SESSION_FIRST, TPM_RS_PW,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::nv::build_nv_image;
    use crate::library::tpm2::persistent::{OwnedPcrAllocation, OwnedPcrSelection};
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const SHA1_SLOT: usize = 0;
    const SHA256_SLOT: usize = 1;

    const STARTUP_PCR_COUNTER: u32 = 20;

    const RC_SUCCESS: u32 = 0x000;
    const RC_SIZE: u32 = 0x095;
    const RC_LOCALITY: u32 = 0x907;
    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_FAILURE: u32 = 0x101;
    const RC_REFERENCE_S0: u32 = 0x918;

    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_HANDLE1_VALUE: u32 = 0x184;

    const RC_DIGESTS_INSUFFICIENT: u32 = 0x1da;
    const RC_DIGESTS_SIZE: u32 = 0x1d5;
    const RC_DIGESTS_HASH: u32 = 0x1c3;

    const RC_SESSION1_HANDLE: u32 = 0x98b;
    const RC_SESSION1_NONCE: u32 = 0x98f;
    const RC_SESSION1_ATTRIBUTES: u32 = 0x982;
    const RC_SESSION1_RESERVED: u32 = 0x9a1;
    const RC_SESSION1_VALUE: u32 = 0x984;
    const RC_SESSION1_INSUFFICIENT: u32 = 0x99a;
    const RC_SESSION1_SIZE: u32 = 0x995;
    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
    const RC_SESSION2_HANDLE: u32 = 0xa8b;
    const RC_SESSION2_INSUFFICIENT: u32 = 0xa9a;

    const EXTEND_AA_SHA1: &str = "d6ebc4e04e1612a1ae465c51c090608bc5e6e174";
    const EXTEND_AA_SHA256: &str =
        "9ef814b42fa0be12d197c44d3e8e03441a4b1118237658368ba1351090e556ed";
    const EXTEND_AA_SHA384: &str = "7bb2c5d8ea033e351e3bbcd999104ba4a95c440e7930e17becc2effd5506\
                                    9425f50dd6852cfd3b664453b66c6cb673ea";
    const EXTEND_AA_SHA512: &str = "c440b662e2efcbe1ee9cb0bf106188de21fe2885765f73d9d8f12f03e3e1\
                                    b90add8404ec9524e7caa58e71acb5f9fa73d5d0ef2fa80bd74ef69a9582\
                                    01647bac";
    const EXTEND_AA_TWICE_SHA256: &str =
        "12a0883f16abf44dcc4cac1dec108eb99c652fed124c6989eddc811fe8effb64";
    const EXTEND_AA_FROM_ONES_SHA256: &str =
        "4d6be99065d55e626d20a31ef68aec4a24a95a85259b45a2e4cfae4691d5d316";

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

    #[track_caller]
    fn started_runtime() -> Tpm2Runtime {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 00")),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn password_session(handle: u32, nonce: &[u8], attributes: u8, password: &[u8]) -> Vec<u8> {
        let mut out = handle.to_be_bytes().to_vec();
        out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
        out.extend_from_slice(nonce);
        out.push(attributes);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out
    }

    fn empty_password_session() -> Vec<u8> {
        password_session(TPM_RS_PW, &[], 0x00, &[])
    }

    fn extend_command(handle: u32, auth: Option<&[u8]>, parameters: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        if let Some(auth) = auth {
            payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            payload.extend_from_slice(auth);
        }
        payload.extend_from_slice(parameters);

        let tag: u16 = if auth.is_some() { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_PCR_EXTEND.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn digest_list(entries: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut out = (entries.len() as u32).to_be_bytes().to_vec();
        for (hash_alg, digest) in entries {
            out.extend_from_slice(&hash_alg.to_be_bytes());
            out.extend_from_slice(digest);
        }
        out
    }

    fn one_digest(hash_alg: u16, fill: u8) -> Vec<u8> {
        let (_, digest_size) = bank_slot(hash_alg).expect("a compiled bank");
        digest_list(&[(hash_alg, vec![fill; digest_size])])
    }

    fn authorized_extend(pcr: u32, parameters: &[u8]) -> Vec<u8> {
        extend_command(pcr, Some(&empty_password_session()), parameters)
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn session_success_response() -> Vec<u8> {
        hex("8002 00000013 00000000 00000000 0000 01 0000")
    }

    struct Snapshot {
        failure_mode: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
        pcr_counter: Option<u32>,
        pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
        free_session_slots: u32,
        sessions_occupied: Vec<bool>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: runtime.state.as_ref().unwrap().persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
            pcr_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            pcr_banks: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.to_vec())
                .collect(),
            free_session_slots: runtime.live.free_session_slots,
            sessions_occupied: runtime
                .live
                .sessions
                .iter()
                .map(|slot| slot.occupied)
                .collect(),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(runtime.failure_mode, before.failure_mode);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            before.orderly_state
        );
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert_eq!(
            runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            before.pcr_counter
        );
        let pcr_banks: Vec<Vec<Option<Vec<u8>>>> = runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.to_vec())
            .collect();
        assert_eq!(pcr_banks, before.pcr_banks);
        assert_eq!(runtime.live.free_session_slots, before.free_session_slots);
        assert_eq!(
            runtime
                .live
                .sessions
                .iter()
                .map(|slot| slot.occupied)
                .collect::<Vec<bool>>(),
            before.sessions_occupied
        );
    }

    #[track_caller]
    fn bank(runtime: &Tpm2Runtime, pcr: usize, slot: usize) -> Vec<u8> {
        runtime.live.pcrs[pcr].banks[slot]
            .clone()
            .expect("an allocated bank")
    }

    fn pcr_counter(runtime: &Tpm2Runtime) -> u32 {
        runtime.live.state_reset.as_ref().unwrap().pcr_counter
    }

    fn make_orderly(runtime: &mut Tpm2Runtime, orderly_state: u16) {
        let state = runtime.state.as_mut().expect("state present");
        state.persistent.orderly_state = orderly_state;
        runtime.nv_memory = build_nv_image(state).expect("the orderly state serializes");
        runtime.nv_update_pending = false;
    }

    #[test]
    fn pcr_extend_pre_startup_initialize_rejection() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(TPM_RC_INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &extend_command(10, None, &[])),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes handle parsing"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn single_empty_password_session_success() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_extend(10, &digest_list(&[]))),
            session_success_response()
        );
    }

    #[test]
    fn password_authorization_five_byte_response() {
        let mut runtime = started_runtime();
        let response = dispatch_bytes(&mut runtime, &authorized_extend(10, &digest_list(&[])));
        assert_eq!(response.len(), 19);
        assert_eq!(&response[..2], &[0x80, 0x02], "TPM_ST_SESSIONS");
        assert_eq!(&response[2..6], &[0x00, 0x00, 0x00, 0x13], "size 19");
        assert_eq!(
            &response[6..10],
            &[0x00, 0x00, 0x00, 0x00],
            "TPM_RC_SUCCESS"
        );
        assert_eq!(
            &response[10..14],
            &[0x00, 0x00, 0x00, 0x00],
            "parameterSize"
        );
        assert_eq!(
            &response[14..],
            &[0x00, 0x00, 0x01, 0x00, 0x00],
            "empty nonce | continueSession | empty hmac"
        );
    }

    #[test]
    fn missing_auth_area_auth_missing() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &extend_command(10, None, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(TPM_RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn nonempty_password_empty_auth_failure() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let auth = password_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &extend_command(10, Some(&auth), &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_SESSION1_BAD_AUTH),
            "every implemented PCR has an empty effective authValue"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn trailing_zero_password_empty_auth_match() {
        let mut runtime = started_runtime();
        for password in [&[0x00][..], &[0x00, 0x00][..], &[0x00; 32][..]] {
            let auth = password_session(TPM_RS_PW, &[], 0x00, password);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &extend_command(10, Some(&auth), &digest_list(&[]))
                ),
                session_success_response(),
                "upstream strips trailing zeros before comparing ({} bytes)",
                password.len()
            );
        }
    }

    #[test]
    fn malformed_authorization_area_oracle_code_parity() {
        let declared_password_size = |size: u16| {
            let mut session = password_session(TPM_RS_PW, &[], 0x00, &[0xaa; 8]);
            session[7..9].copy_from_slice(&size.to_be_bytes());
            session
        };

        for (label, auth, expected) in [
            (
                "authorization_area_below_the_minimum",
                empty_password_session()[..4].to_vec(),
                RC_SIZE,
            ),
            (
                "invalid_handle",
                password_session(0x4000_0008, &[], 0x00, &[]),
                RC_SESSION1_VALUE,
            ),
            (
                "non_empty_nonce",
                password_session(TPM_RS_PW, &[0xaa, 0xbb], 0x00, &[]),
                RC_SESSION1_NONCE,
            ),
            (
                "reserved_attributes",
                password_session(TPM_RS_PW, &[], 0x08, &[]),
                RC_SESSION1_RESERVED,
            ),
            (
                "audit_attribute",
                password_session(TPM_RS_PW, &[], 0x80, &[]),
                RC_SESSION1_ATTRIBUTES,
            ),
            (
                "decrypt_attribute",
                password_session(TPM_RS_PW, &[], 0x20, &[]),
                RC_SESSION1_ATTRIBUTES,
            ),
            (
                "hmac_session",
                password_session(HMAC_SESSION_FIRST, &[], 0x00, &[]),
                RC_REFERENCE_S0,
            ),
            (
                "policy_session",
                password_session(POLICY_SESSION_FIRST, &[], 0x00, &[]),
                RC_REFERENCE_S0,
            ),
            (
                "password_size_above_the_tpm2b_maximum",
                declared_password_size(65),
                RC_SESSION1_SIZE,
            ),
            (
                "password_size_beyond_the_authorization_area",
                declared_password_size(64),
                RC_SESSION1_INSUFFICIENT,
            ),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &extend_command(10, Some(&auth), &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                error_response(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_second_session_decoration() {
        let mut auth = empty_password_session();
        auth.extend_from_slice(&empty_password_session());
        for len in 10..auth.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &extend_command(10, Some(&auth[..len]), &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                error_response(RC_SESSION2_INSUFFICIENT),
                "a truncated second session carries the second session's \
                 decoration, authorization area of {len} bytes"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_password_first_session_decoration() {
        let full = password_session(TPM_RS_PW, &[], 0x00, b"abcd");
        for len in 9..full.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &extend_command(10, Some(&full[..len]), &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                error_response(RC_SESSION1_INSUFFICIENT),
                "authorization area of {len} bytes"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn extra_password_session_no_handle() {
        let mut auth = empty_password_session();
        auth.extend_from_slice(&empty_password_session());
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &extend_command(10, Some(&auth), &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_SESSION2_HANDLE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn handleless_command_password_session_rejection() {
        let mut runtime = started_runtime();
        let mut command = hex("80020000002100 00017e");
        command.extend_from_slice(&(empty_password_session().len() as u32).to_be_bytes());
        command.extend_from_slice(&empty_password_session());
        command.extend_from_slice(&hex("00000001 000b 03 010000"));
        assert_eq!(
            dispatch_bytes(&mut runtime, &command),
            error_response(RC_SESSION1_HANDLE),
            "PCR_Read has no handle for the session to authorize"
        );
    }

    #[test]
    fn auth_failure_runtime_unchanged() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let auth = password_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &extend_command(0, Some(&auth), &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_SESSION1_BAD_AUTH)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn pcr_extend_zero_session_slot_consumption() {
        let mut runtime = started_runtime();
        let free_before = runtime.live.free_session_slots;
        for round in 0..4 {
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                session_success_response(),
                "round {round}"
            );
            assert_eq!(runtime.live.free_session_slots, free_before);
            assert!(
                runtime.live.sessions.iter().all(|slot| !slot.occupied),
                "a password session creates no persistent session object"
            );
        }
    }

    #[test]
    fn zero_digest_entry_success_no_bank_update() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_extend(10, &digest_list(&[]))),
            session_success_response()
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn supported_hash_acceptance() {
        for (hash_alg, expected) in [
            (TPM_ALG_SHA1, EXTEND_AA_SHA1),
            (TPM_ALG_SHA256, EXTEND_AA_SHA256),
            (TPM_ALG_SHA384, EXTEND_AA_SHA384),
            (TPM_ALG_SHA512, EXTEND_AA_SHA512),
        ] {
            let mut runtime = started_runtime();
            let (slot, _) = bank_slot(hash_alg).unwrap();
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(10, &one_digest(hash_alg, 0xaa))
                ),
                session_success_response(),
                "alg {hash_alg:#06x}"
            );
            assert_eq!(
                bank(&runtime, 10, slot),
                hex(expected),
                "alg {hash_alg:#06x} computes Hash(oldPCR || inputDigest)"
            );
            assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + 1);
        }
    }

    #[test]
    fn multiple_algorithm_independent_bank_updates() {
        let mut runtime = started_runtime();
        let parameters = digest_list(&[
            (TPM_ALG_SHA1, vec![0xaa; 20]),
            (TPM_ALG_SHA256, vec![0xaa; 32]),
        ]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_extend(10, &parameters)),
            session_success_response()
        );
        assert_eq!(bank(&runtime, 10, SHA1_SLOT), hex(EXTEND_AA_SHA1));
        assert_eq!(bank(&runtime, 10, SHA256_SLOT), hex(EXTEND_AA_SHA256));
        assert_eq!(bank(&runtime, 10, 2), vec![0u8; 48], "SHA-384 untouched");
        assert_eq!(
            pcr_counter(&runtime),
            STARTUP_PCR_COUNTER + 2,
            "one increment per extended allocated bank"
        );
    }

    #[test]
    fn duplicate_algorithm_sequential_same_bank_extension() {
        let mut runtime = started_runtime();
        let parameters = digest_list(&[
            (TPM_ALG_SHA256, vec![0xaa; 32]),
            (TPM_ALG_SHA256, vec![0xaa; 32]),
        ]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_extend(10, &parameters)),
            session_success_response()
        );
        assert_eq!(
            bank(&runtime, 10, SHA256_SLOT),
            hex(EXTEND_AA_TWICE_SHA256),
            "the second entry extends the result of the first"
        );
        assert_eq!(
            pcr_counter(&runtime),
            STARTUP_PCR_COUNTER + 2,
            "duplicates may increment the counter more than once"
        );
    }

    #[test]
    fn excess_digest_count_size_error() {
        for count in [5u32, 100, 0x00ff_ffff, u32::MAX] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_extend(10, &count.to_be_bytes())),
                error_response(RC_DIGESTS_SIZE),
                "count {count}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn unsupported_hash_rejection() {
        for hash_alg in [0x0000u16, 0x0005, 0x0010, 0x0012, 0x0027, 0xffff] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut parameters = 1u32.to_be_bytes().to_vec();
            parameters.extend_from_slice(&hash_alg.to_be_bytes());
            parameters.extend_from_slice(&[0xaa; 64]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_extend(10, &parameters)),
                error_response(RC_DIGESTS_HASH),
                "alg {hash_alg:#06x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn profile_disabled_hash_rejection() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().profile.algorithms =
            b"sha1,sha256,sha384,hmac,null".to_vec();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA512, 0xaa))
            ),
            error_response(RC_DIGESTS_HASH),
            "SHA-512 is compiled in but disabled by the profile"
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response(),
            "SHA-256 stays enabled"
        );
    }

    #[test]
    fn truncated_parameter_digest_list_decoration() {
        for hash_alg in [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512] {
            let full = one_digest(hash_alg, 0xaa);
            for len in 0..full.len() {
                let mut runtime = started_runtime();
                let before = snapshot(&runtime);
                assert_eq!(
                    dispatch_bytes(&mut runtime, &authorized_extend(10, &full[..len])),
                    error_response(RC_DIGESTS_INSUFFICIENT),
                    "alg {hash_alg:#06x} truncated to {len} bytes"
                );
                assert_unchanged(&runtime, &before);
            }
        }
    }

    #[test]
    fn trailing_parameter_bytes_size_error() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let mut parameters = one_digest(TPM_ALG_SHA256, 0xaa);
        parameters.push(0xee);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_extend(10, &parameters)),
            error_response(RC_SIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn parse_failure_runtime_unchanged() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        for parameters in [
            vec![],
            0u32.to_be_bytes()[..3].to_vec(),
            9u32.to_be_bytes().to_vec(),
            hex("00000001 0012"),
        ] {
            let _ = dispatch_bytes(&mut runtime, &authorized_extend(10, &parameters));
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn implemented_handle_acceptance() {
        for pcr in 0..IMPLEMENTATION_PCR as u32 {
            let mut runtime = started_runtime();
            runtime.locality = 2;
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_extend(pcr, &digest_list(&[]))),
                session_success_response(),
                "PCR {pcr} is extendable from locality 2 in the upstream matrix"
            );
        }
    }

    #[test]
    fn out_of_range_handle_rejection() {
        for handle in [
            IMPLEMENTATION_PCR as u32,
            100,
            0x0100_0000,
            0x0200_0000,
            0x4000_0000,
            0x4000_0001,
            0x8100_0000,
            u32::MAX,
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(handle, &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_handle_decoration() {
        for len in 0..4usize {
            let mut runtime = started_runtime();
            let mut command = hex("8002 00000000 00000182");
            command.extend_from_slice(&[0u8; 4][..len]);
            let size = command.len() as u32;
            command[2..6].copy_from_slice(&size.to_be_bytes());
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(RC_HANDLE1_INSUFFICIENT),
                "{len} of 4 handle bytes"
            );
        }
    }

    #[test]
    fn null_handle_no_extend() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(TPM_RH_NULL, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response(),
            "upstream returns success before any PCR work"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn null_handle_parameter_password_validation() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(TPM_RH_NULL, &0xffff_ffffu32.to_be_bytes())
            ),
            error_response(RC_DIGESTS_SIZE),
            "the digest list is unmarshaled before the null-handle shortcut"
        );
        let auth = password_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &extend_command(TPM_RH_NULL, Some(&auth), &digest_list(&[]))
            ),
            error_response(RC_SESSION1_BAD_AUTH),
            "nullAuth is the empty auth value"
        );
    }

    #[test]
    fn null_handle_locality_exemption() {
        for locality in 0..5u8 {
            let mut runtime = started_runtime();
            runtime.locality = locality;
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(TPM_RH_NULL, &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                session_success_response(),
                "locality {locality}"
            );
        }
    }

    #[test]
    fn unallocated_bank_unchanged_no_counter_advance() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA1, 0xaa))
            ),
            session_success_response(),
            "an unallocated bank is skipped, not an error"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn unallocated_allocated_bank_isolation() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        let parameters = digest_list(&[
            (TPM_ALG_SHA1, vec![0xaa; 20]),
            (TPM_ALG_SHA256, vec![0xaa; 32]),
        ]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_extend(10, &parameters)),
            session_success_response()
        );
        assert_eq!(bank(&runtime, 10, SHA1_SLOT), vec![0u8; 20], "unallocated");
        assert_eq!(bank(&runtime, 10, SHA256_SLOT), hex(EXTEND_AA_SHA256));
        assert_eq!(
            pcr_counter(&runtime),
            STARTUP_PCR_COUNTER + 1,
            "only the allocated bank increments the counter"
        );
    }

    #[test]
    fn non_incrementing_pcr_counter_preservation() {
        for pcr in [16u32, 21, 22, 23] {
            let mut runtime = started_runtime();
            runtime.locality = 2;
            let before = pcr_counter(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(pcr, &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                session_success_response(),
                "PCR {pcr}"
            );
            assert_ne!(
                bank(&runtime, pcr as usize, SHA256_SLOT),
                vec![0u8; 32],
                "PCR {pcr} was still extended"
            );
            assert_eq!(
                pcr_counter(&runtime),
                before,
                "PCR {pcr} is in the TCB group"
            );
        }
    }

    #[test]
    fn pcr_zero_counter_increment_upstream_parity() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(0, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response()
        );
        assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + 1);
    }

    #[test]
    fn dynamic_pcr_all_ones_reset_base() {
        let mut runtime = started_runtime();
        runtime.locality = 2;
        assert_eq!(bank(&runtime, 17, SHA256_SLOT), vec![0xffu8; 32]);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(17, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response()
        );
        assert_eq!(
            bank(&runtime, 17, SHA256_SLOT),
            hex(EXTEND_AA_FROM_ONES_SHA256)
        );
    }

    #[test]
    fn locality_matrix_upstream_match() {
        const EXTEND_LOCALITY: [u8; IMPLEMENTATION_PCR] = [
            0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
            0x1f, 0x1f, 0x1f, 0x1c, 0x1c, 0x0c, 0x0e, 0x04, 0x04, 0x1f,
        ];
        assert_eq!(EXTEND_LOCALITY.len(), IMPLEMENTATION_PCR);
        for (pcr, extend_locality) in EXTEND_LOCALITY.into_iter().enumerate() {
            for locality in 0..5u8 {
                let allowed = extend_locality & (1 << locality) != 0;
                let mut runtime = started_runtime();
                runtime.locality = locality;
                let before = snapshot(&runtime);
                let response = dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(pcr as u32, &one_digest(TPM_ALG_SHA256, 0xaa)),
                );
                if allowed {
                    assert_eq!(
                        response,
                        session_success_response(),
                        "PCR {pcr} from locality {locality}"
                    );
                } else {
                    assert_eq!(
                        response,
                        error_response(RC_LOCALITY),
                        "PCR {pcr} from locality {locality}"
                    );
                    assert_unchanged(&runtime, &before);
                }
            }
        }
    }

    #[test]
    fn upstream_locality_group_coverage() {
        for (pcrs, allowed) in [
            (vec![0u32, 8, 15, 16, 23], vec![0u8, 1, 2, 3, 4]),
            (vec![17, 18], vec![2, 3, 4]),
            (vec![19], vec![2, 3]),
            (vec![20], vec![1, 2, 3]),
            (vec![21, 22], vec![2]),
        ] {
            for pcr in pcrs {
                for locality in 0..5u8 {
                    let mut runtime = started_runtime();
                    runtime.locality = locality;
                    let response = dispatch_bytes(
                        &mut runtime,
                        &authorized_extend(pcr, &one_digest(TPM_ALG_SHA256, 0xaa)),
                    );
                    let expected = if allowed.contains(&locality) {
                        session_success_response()
                    } else {
                        error_response(RC_LOCALITY)
                    };
                    assert_eq!(response, expected, "PCR {pcr} from locality {locality}");
                }
            }
        }
    }

    #[test]
    fn disallowed_locality_pre_orderly_rejection() {
        let mut runtime = started_runtime();
        runtime.locality = 1;
        make_orderly(&mut runtime, 0x0001);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(21, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_LOCALITY),
            "the locality check precedes the NV availability check"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn malformed_bank_panic_safety() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[10].banks[SHA256_SLOT] = None;
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_FAILURE),
            "an allocated bank with no live value is an internal failure"
        );

        let mut runtime = started_runtime();
        runtime.live.pcrs[10].banks[SHA256_SLOT] = Some(vec![0u8; 31]);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_FAILURE),
            "a wrong-length bank is an internal failure"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn invalid_bank_slot_internal_failure() {
        let runtime = started_runtime();
        let digests = [DigestValue {
            slot: PCR_SLOT_BANKS.len(),
            digest: &[0xaa; 32],
        }];
        assert_eq!(
            prepare_extend(&runtime, 10, &digests).err(),
            Some(TPM_RC_FAILURE),
            "a slot outside the compiled banks never selects a hash algorithm"
        );

        let digests = [DigestValue {
            slot: usize::MAX,
            digest: &[0xaa; 32],
        }];
        assert_eq!(
            prepare_extend(&runtime, 10, &digests).err(),
            Some(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn missing_state_reset_panic_safety() {
        let mut runtime = started_runtime();
        runtime.live.state_reset = None;
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_FAILURE)
        );
    }

    #[test]
    fn counter_max_panic_safety() {
        let mut runtime = started_runtime();
        runtime.live.state_reset.as_mut().unwrap().pcr_counter = u32::MAX;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_FAILURE),
            "the overflow is detected before any PCR is written"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn state_saved_pcr_orderly_clear_nv_commit() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        let nv_before = runtime.nv_memory.clone();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response()
        );
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            0xffff,
            "SU_NONE_VALUE"
        );
        assert!(runtime.nv_update_pending);
        assert_ne!(runtime.nv_memory, nv_before, "the NV image was rebuilt");
    }

    #[test]
    fn state_saved_pcr_da_used_marker() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        runtime.live.da_used = true;
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response()
        );
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            0xfffe,
            "SU_DA_USED_VALUE"
        );
    }

    #[test]
    fn state_saved_pcr_orderly_clear_nv_requirement() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(15, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            error_response(RC_NV_UNAVAILABLE),
            "RETURN_IF_ORDERLY fails before any PCR mutation"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn non_state_saved_pcr_orderly_nv_untouched() {
        for pcr in [16u32, 17, 20, 23] {
            let mut runtime = started_runtime();
            runtime.locality = 2;
            make_orderly(&mut runtime, 0x0001);
            runtime.nv_available = false;
            let nv_before = runtime.nv_memory.clone();
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(pcr, &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                session_success_response(),
                "PCR {pcr} is not state saved"
            );
            assert_eq!(
                runtime.state.as_ref().unwrap().persistent.orderly_state,
                0x0001
            );
            assert!(!runtime.nv_update_pending);
            assert_eq!(runtime.nv_memory, nv_before);
        }
    }

    #[test]
    fn non_orderly_state_saved_pcr_no_nv_commit() {
        let mut runtime = started_runtime();
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            0xffff,
            "Startup leaves the TPM non-orderly"
        );
        let nv_before = runtime.nv_memory.clone();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
            ),
            session_success_response()
        );
        assert!(
            !runtime.nv_update_pending,
            "no persistent state changed, so nothing is committed"
        );
        assert_eq!(runtime.nv_memory, nv_before);
    }

    #[test]
    fn persistent_change_only_nv_commit() {
        let mut runtime = started_runtime();
        let command = authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa));
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a non-orderly PCR_Extend must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, session_success_response());

        make_orderly(&mut runtime, 0x0001);
        let command = authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa));
        let input = CommandInput::new(command.len() as u32, command);
        let mut commits = 0u32;
        let response = process(&mut runtime, 0, &input, |_| {
            commits += 1;
            Ok(())
        })
        .expect("the command processes");
        assert_eq!(response, session_success_response());
        assert_eq!(
            commits, 1,
            "clearing the orderly state commits exactly once"
        );
    }

    fn upstream_extend_request(text: &[u8]) -> Vec<u8> {
        let mut digest = text.to_vec();
        digest.resize(32, 0x00);
        let mut out = hex("8002 00000041 00000182 0000000a 00000009");
        out.extend_from_slice(&empty_password_session());
        out.extend_from_slice(&digest_list(&[(TPM_ALG_SHA256, digest)]));
        out
    }

    #[test]
    fn libtpms_pcr10_flow_byte_match() {
        let mut runtime = started_runtime();

        let extend = upstream_extend_request(b"1234");
        assert_eq!(extend.len(), 0x41, "the upstream command size");
        assert_eq!(
            dispatch_bytes(&mut runtime, &extend),
            hex("8002 00000013 00000000 00000000 0000 01 0000"),
            "the 19-byte session-tagged response"
        );

        let read = hex("8001 00000014 0000017e 00000001 000b 03 000400");
        assert_eq!(
            dispatch_bytes(&mut runtime, &read),
            hex(
                "8001 0000003e 00000000 00000015 00000001 000b 03 000400 00000001 0020 \
                 1f7fb100e1b2d195194b58e7c309a586307c346419dcb2d59f522be7f0945101"
            ),
            "digest and update counter match the upstream oracle"
        );
    }

    #[test]
    fn swtpm_pcr10_flow_byte_match() {
        let mut runtime = started_runtime();

        let extend = upstream_extend_request(b"hello");
        assert_eq!(extend.len(), 0x41, "the upstream command size");
        assert_eq!(
            dispatch_bytes(&mut runtime, &extend),
            hex("8002 00000013 00000000 00000000 0000 01 0000")
        );

        let read = hex("8001 00000014 0000017e 00000001 000b 03 000400");
        assert_eq!(
            dispatch_bytes(&mut runtime, &read),
            hex(
                "8001 0000003e 00000000 00000015 00000001 000b 03 000400 00000001 0020 \
                 c3baa56269082672c3db3d110a1074a1a7a6ea43e882161aaf4beaa68317e4b8"
            )
        );
    }

    #[test]
    fn update_counter_advance_per_extend() {
        let mut runtime = started_runtime();
        for round in 1..=3u32 {
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa))
                ),
                session_success_response(),
                "round {round}"
            );
            assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + round);
        }
        let read = hex("8001 00000014 0000017e 00000001 000b 03 000400");
        let response = dispatch_bytes(&mut runtime, &read);
        assert_eq!(&response[10..14], &(STARTUP_PCR_COUNTER + 3).to_be_bytes());
    }

    #[test]
    fn bit_flip_panic_safety() {
        let valid = authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa));
        for index in 6..valid.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut mutated = valid.clone();
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

    #[test]
    fn truncated_prefix_rejection_safety() {
        let valid = authorized_extend(10, &one_digest(TPM_ALG_SHA256, 0xaa));
        for len in 10..valid.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut truncated = valid[..len].to_vec();
            truncated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
            let input = CommandInput::new(truncated.len() as u32, truncated);
            let parsed = parse_command(&input).expect("the header parses");
            let response = serialize_response(&dispatch(
                &mut runtime,
                &parsed,
                CancellationToken::disabled(),
            ))
            .unwrap();
            assert_ne!(&response[6..10], &RC_SUCCESS.to_be_bytes(), "length {len}");
            assert_unchanged(&runtime, &before);
        }
    }
}
