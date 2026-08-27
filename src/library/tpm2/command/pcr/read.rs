use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{algorithm_enabled, hash_profile_name};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::marshal::{BlobReader, BlobWriter};
use crate::library::tpm2::pcr::{HASH_COUNT, PCR_SELECT_MAX, PCR_SELECT_MIN, bank_slot};
use crate::library::tpm2::persistent::OwnedPcrAllocation;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_PCR_READ_PCR_SELECTION_IN: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_DIGEST_COUNT: usize = 8;

struct SelectionIn {
    hash_alg: u16,
    select: Vec<u8>,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let mut selections = parse_parameters(&state.profile.algorithms, frame.parameters)?;
    let update_counter = runtime
        .live
        .state_reset
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .pcr_counter;
    let digests = collect_digests(runtime, &mut selections)?;
    let parameters = marshal_response(update_counter, &selections, &digests)?;
    Ok(CommandOutput::from_parameters(parameters))
}

fn parse_parameters(
    profile_algorithms: &[u8],
    parameters: &[u8],
) -> Result<Vec<SelectionIn>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let count = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_READ_PCR_SELECTION_IN)?;
    if count > HASH_COUNT as u32 {
        return Err(TPM_RC_SIZE + RC_PCR_READ_PCR_SELECTION_IN);
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
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_READ_PCR_SELECTION_IN)?;
    let enabled = bank_slot(hash_alg).is_some()
        && hash_profile_name(hash_alg)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH + RC_PCR_READ_PCR_SELECTION_IN);
    }
    let sizeof_select = usize::from(
        reader
            .read_u8()
            .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_READ_PCR_SELECTION_IN)?,
    );
    if !(PCR_SELECT_MIN..=PCR_SELECT_MAX).contains(&sizeof_select) {
        return Err(TPM_RC_VALUE + RC_PCR_READ_PCR_SELECTION_IN);
    }
    let select = reader
        .take(sizeof_select)
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_PCR_READ_PCR_SELECTION_IN)?
        .to_vec();
    Ok(SelectionIn { hash_alg, select })
}

fn filter_selection(selection: &mut SelectionIn, allocation: &OwnedPcrAllocation) {
    let allocated = allocation
        .selections
        .iter()
        .find(|entry| entry.hash_alg == selection.hash_alg);
    for (index, byte) in selection.select.iter_mut().enumerate() {
        *byte &= allocated
            .and_then(|entry| entry.select.get(index))
            .copied()
            .unwrap_or(0);
    }
}

fn is_selected(selection: &SelectionIn, pcr: usize) -> bool {
    pcr < IMPLEMENTATION_PCR
        && selection
            .select
            .get(pcr / 8)
            .is_some_and(|byte| byte & (1 << (pcr % 8)) != 0)
}

fn read_bank_digest(
    runtime: &Tpm2Runtime,
    pcr: usize,
    slot: usize,
    digest_size: usize,
) -> Result<Vec<u8>, TpmResult> {
    let bank = runtime
        .live
        .pcrs
        .get(pcr)
        .and_then(|entry| entry.banks.get(slot))
        .and_then(Option::as_ref)
        .ok_or(TPM_RC_FAILURE)?;
    if bank.len() != digest_size {
        return Err(TPM_RC_FAILURE);
    }
    Ok(bank.clone())
}

fn collect_digests(
    runtime: &Tpm2Runtime,
    selections: &mut [SelectionIn],
) -> Result<Vec<Vec<u8>>, TpmResult> {
    let allocation = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
    let mut digests: Vec<Vec<u8>> = Vec::new();
    let mut index = 0;
    while index < selections.len() {
        let truncated_mid_selection = {
            let selection = &mut selections[index];
            filter_selection(selection, allocation);
            let (slot, digest_size) = bank_slot(selection.hash_alg).ok_or(TPM_RC_FAILURE)?;
            let mut pcr = 0;
            while pcr < IMPLEMENTATION_PCR {
                if is_selected(selection, pcr) {
                    if digests.len() >= MAX_DIGEST_COUNT {
                        while pcr < IMPLEMENTATION_PCR {
                            let Some(byte) = selection.select.get_mut(pcr / 8) else {
                                break;
                            };
                            *byte &= !(1 << (pcr % 8));
                            pcr += 1;
                        }
                        break;
                    }
                    digests.push(read_bank_digest(runtime, pcr, slot, digest_size)?);
                }
                pcr += 1;
            }
            digests.len() >= MAX_DIGEST_COUNT && pcr < IMPLEMENTATION_PCR
        };
        if truncated_mid_selection {
            for later in &mut selections[index..] {
                later.select.fill(0);
            }
            break;
        }
        index += 1;
    }
    Ok(digests)
}

fn marshal_response(
    update_counter: u32,
    selections: &[SelectionIn],
    digests: &[Vec<u8>],
) -> Result<Vec<u8>, TpmResult> {
    let mut writer = BlobWriter::new();
    writer.write_u32(update_counter);
    writer.write_u32(u32::try_from(selections.len()).map_err(|_| TPM_RC_FAILURE)?);
    for selection in selections {
        writer.write_u16(selection.hash_alg);
        writer.write_u8(u8::try_from(selection.select.len()).map_err(|_| TPM_RC_FAILURE)?);
        writer.write_bytes(&selection.select);
    }
    writer.write_u32(u32::try_from(digests.len()).map_err(|_| TPM_RC_FAILURE)?);
    for digest in digests {
        writer.write_tpm2b(digest).map_err(|_| TPM_RC_FAILURE)?;
    }
    Ok(writer.into_bytes())
}

#[cfg(test)]
mod tests {
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
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::{TPM_RC_INITIALIZE, TPM_SUCCESS};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_PCR_READ;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::persistent::OwnedPcrSelection;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;
    use crate::library::tpm2::tis;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const SHA1_SLOT: usize = 0;
    const SHA256_SLOT: usize = 1;

    const RC_INSUFFICIENT_PARAM1: u32 = 0x1da;
    const RC_SIZE_PARAM1: u32 = 0x1d5;
    const RC_HASH_PARAM1: u32 = 0x1c3;
    const RC_VALUE_PARAM1: u32 = 0x1c4;
    const RC_SIZE: u32 = 0x095;
    const RC_SESSION1_HANDLE: u32 = 0x98b;
    const RC_INSUFFICIENT: u32 = 0x09a;

    const STARTUP_PCR_COUNTER: u32 = 20;

    const DRTM_ABC_SHA256: &str =
        "589f9ffed4c477966bfb8d41f37895b08c69047df8f911d6f3b57fbe08faee8d";

    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2));
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x55;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
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
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        let startup = hex("80010000000c0000014400 00");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn pcr_read_command(parameters: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_PCR_READ.to_be_bytes());
        out.extend_from_slice(parameters);
        out
    }

    fn one_bank_params(hash_alg: u16, bitmap: [u8; 3]) -> Vec<u8> {
        let mut out = 1u32.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out.push(3);
        out.extend_from_slice(&bitmap);
        out
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn digest_entry(size: usize, fill: u8) -> Vec<u8> {
        let mut out = (size as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&vec![fill; size]);
        out
    }

    fn success_header(parameter_len: usize) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + parameter_len as u32).to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out
    }

    fn success_response(parameters: &[u8]) -> Vec<u8> {
        let mut out = success_header(parameters.len());
        out.extend_from_slice(parameters);
        out
    }

    struct Snapshot {
        startup_received: bool,
        failure_mode: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
        pcr_counter: u32,
        pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
        free_session_slots: u32,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        Snapshot {
            startup_received: runtime.startup_received,
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: runtime.state.as_ref().unwrap().persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
            pcr_counter: runtime.live.state_reset.as_ref().unwrap().pcr_counter,
            pcr_banks: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.to_vec())
                .collect(),
            free_session_slots: runtime.live.free_session_slots,
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_eq!(runtime.startup_received, before.startup_received);
        assert_eq!(runtime.failure_mode, before.failure_mode);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            before.orderly_state
        );
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert_eq!(
            runtime.live.state_reset.as_ref().unwrap().pcr_counter,
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
    }

    #[test]
    fn pcr_read_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(&0u32.to_be_bytes())),
            error_response(TPM_RC_INITIALIZE)
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(&[])),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes parameter parsing"
        );
        assert!(!runtime.startup_received);
    }

    #[test]
    fn pcr_read_is_dispatched_after_startup() {
        let mut runtime = started_runtime();
        let response = dispatch_bytes(&mut runtime, &pcr_read_command(&0u32.to_be_bytes()));
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
    }

    #[test]
    fn zero_selections_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(&0u32.to_be_bytes())),
            hex("80010000001600000000000000140000000000000000")
        );
    }

    #[test]
    fn one_sha256_selection_matches_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [1, 0, 0]))
            ),
            hex(
                "80010000003e000000000000001400000001000b0301000000000001002000000000000000000\
                 00000000000000000000000000000000000000000000000"
            )
        );
    }

    #[test]
    fn every_truncated_parameter_returns_insufficient_param1() {
        let full = one_bank_params(TPM_ALG_SHA256, [1, 0, 0]);
        for len in 0..full.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &pcr_read_command(&full[..len])),
                error_response(RC_INSUFFICIENT_PARAM1),
                "parameter length {len}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn count_above_hash_count_is_a_size_error_without_allocation() {
        for count in [5u32, 100, u32::MAX] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &pcr_read_command(&count.to_be_bytes())),
                error_response(RC_SIZE_PARAM1),
                "count {count}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn unsupported_hash_algorithms_return_hash_param1() {
        for alg in [0x0000u16, 0x0010, 0x0012, 0x0027, 0xffff] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &pcr_read_command(&one_bank_params(alg, [0, 0, 0]))
                ),
                error_response(RC_HASH_PARAM1),
                "alg {alg:#06x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn profile_disabled_hash_algorithm_returns_hash_param1() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().profile.algorithms =
            b"sha1,sha256,sha384,hmac,null".to_vec();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &pcr_read_command(&one_bank_params(TPM_ALG_SHA512, [1, 0, 0]))
            ),
            error_response(RC_HASH_PARAM1),
            "SHA-512 is compiled in but disabled by the profile"
        );
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [1, 0, 0])),
        );
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "SHA-256 stays enabled");
    }

    #[test]
    fn out_of_range_sizeof_select_is_value_param1() {
        for (size, bitmap_len) in [(0u8, 0usize), (1, 1), (2, 2), (4, 4), (255, 3)] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut params = 1u32.to_be_bytes().to_vec();
            params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            params.push(size);
            params.extend_from_slice(&vec![0u8; bitmap_len]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &pcr_read_command(&params)),
                error_response(RC_VALUE_PARAM1),
                "sizeofSelect {size}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_second_selection_error_is_reported_with_param1() {
        let mut runtime = started_runtime();
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&hex("000b03010000"));
        params.extend_from_slice(&hex("001003000000"));
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(&params)),
            error_response(RC_HASH_PARAM1)
        );
    }

    #[test]
    fn trailing_parameter_bytes_return_size() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let mut params = one_bank_params(TPM_ALG_SHA256, [1, 0, 0]);
        params.push(0xee);
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(&params)),
            error_response(RC_SIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn session_tagged_requests_match_the_oracle() {
        let pw_auth =
            hex("80020000002100 00017e 00000009 40000009 0000 00 0000 00000001 000b 03 010000");
        let no_authsize = hex("80020000000a0000017e");
        let authsize_zero = hex("80020000001800 00017e 00000000 00000001 000b 03 010000");

        for (label, command, expected) in [
            ("pw_auth", pw_auth, RC_SESSION1_HANDLE),
            ("no_authsize", no_authsize, RC_INSUFFICIENT),
            ("authsize_zero", authsize_zero, RC_SIZE),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let valid = pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [1, 0, 0]));
        for len in 10..=valid.len() {
            for index in 6..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
                    mutated[index] ^= flip;
                    let mut runtime = started_runtime();
                    let input = CommandInput::new(mutated.len() as u32, mutated);
                    let parsed = parse_command(&input).expect("the header parses");
                    let _ = serialize_response(&dispatch(&mut runtime, &parsed));
                }
            }
        }
    }

    #[test]
    fn one_selected_pcr_returns_the_live_digest() {
        let mut runtime = started_runtime();
        let marker: Vec<u8> = (0..32).map(|i| 0xd0 ^ i as u8).collect();
        runtime.live.pcrs[5].banks[SHA256_SLOT] = Some(marker.clone());
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0x20, 0, 0])),
        );
        let mut expected = hex("00000014 00000001 000b03200000 00000001 0020");
        expected.extend_from_slice(&marker);
        assert_eq!(response, success_response(&expected));
    }

    #[test]
    fn multiple_pcrs_from_one_bank_return_in_ascending_order() {
        let mut runtime = started_runtime();
        for pcr in [1usize, 3, 9] {
            runtime.live.pcrs[pcr].banks[SHA256_SLOT] = Some(vec![pcr as u8; 32]);
        }
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0x0a, 0x02, 0])),
        );
        let mut expected = hex("00000014 00000001 000b030a0200 00000003");
        for pcr in [1u8, 3, 9] {
            expected.extend_from_slice(&digest_entry(32, pcr));
        }
        assert_eq!(response, success_response(&expected));
    }

    #[test]
    fn multiple_banks_preserve_the_input_order() {
        let mut runtime = started_runtime();
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&hex("000d03010000"));
        params.extend_from_slice(&hex("000403010000"));
        let response = dispatch_bytes(&mut runtime, &pcr_read_command(&params));
        let mut expected = hex("00000014 00000002 000d03010000 000403010000 00000002");
        expected.extend_from_slice(&digest_entry(64, 0));
        expected.extend_from_slice(&digest_entry(20, 0));
        assert_eq!(
            response,
            success_response(&expected),
            "SHA-512 before SHA-1 exactly as requested"
        );
    }

    #[test]
    fn duplicate_banks_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&hex("000b03010000"));
        params.extend_from_slice(&hex("000b03020000"));
        let response = dispatch_bytes(&mut runtime, &pcr_read_command(&params));
        let mut expected = hex("00000014 00000002 000b03010000 000b03020000 00000002");
        expected.extend_from_slice(&digest_entry(32, 0));
        expected.extend_from_slice(&digest_entry(32, 0));
        assert_eq!(response, success_response(&expected));
        assert_eq!(response.len(), 0x66, "the oracle response size");
    }

    #[test]
    fn unallocated_pcr_bits_are_cleared_in_the_selection_out() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(crate::library::tpm2::persistent::OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0x0f, 0x00, 0x00],
            }],
        });
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0xff, 0xff, 0xff])),
        );
        let mut expected = hex("00000014 00000001 000b030f0000 00000004");
        for _ in 0..4 {
            expected.extend_from_slice(&digest_entry(32, 0));
        }
        assert_eq!(response, success_response(&expected));
    }

    #[test]
    fn an_unallocated_bank_returns_an_empty_selection_and_no_digest() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(crate::library::tpm2::persistent::OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA1, [0xff, 0xff, 0xff])),
        );
        let expected = hex("00000014 00000001 000403000000 00000000");
        assert_eq!(
            response,
            success_response(&expected),
            "the entry and its hash survive with every bit cleared"
        );
    }

    #[test]
    fn a_selection_with_no_bits_set_matches_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0, 0, 0]))
            ),
            hex("80010000001c000000000000001400000001000b0300000000000000")
        );
    }

    fn oracle_sha256_eight() -> Vec<u8> {
        let mut expected = hex("00000014 00000001 000b03ff0000 00000008");
        for _ in 0..8 {
            expected.extend_from_slice(&digest_entry(32, 0));
        }
        success_response(&expected)
    }

    #[test]
    fn a_request_for_exactly_eight_digests_returns_all_eight() {
        let mut runtime = started_runtime();
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0xff, 0, 0])),
        );
        assert_eq!(response, oracle_sha256_eight());
        assert_eq!(response.len(), 0x12c, "the oracle response size");
    }

    #[test]
    fn more_than_eight_digests_clear_the_unreturned_bits() {
        for bitmap in [[0xffu8, 0xff, 0xff], [0xff, 0x01, 0x00]] {
            let mut runtime = started_runtime();
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, bitmap))
                ),
                oracle_sha256_eight(),
                "bitmap {bitmap:02x?}"
            );
        }
    }

    #[test]
    fn an_overflow_mid_selection_clears_later_selections_like_the_oracle() {
        let mut runtime = started_runtime();
        let mut params = 3u32.to_be_bytes().to_vec();
        params.extend_from_slice(&hex("0004033f0000"));
        params.extend_from_slice(&hex("000b033f0000"));
        params.extend_from_slice(&hex("000c033f0000"));
        let response = dispatch_bytes(&mut runtime, &pcr_read_command(&params));
        let mut expected = hex("00000014 00000003 0004033f0000 000b03030000 000c03000000 00000008");
        for _ in 0..6 {
            expected.extend_from_slice(&digest_entry(20, 0));
        }
        for _ in 0..2 {
            expected.extend_from_slice(&digest_entry(32, 0));
        }
        assert_eq!(response, success_response(&expected));
        assert_eq!(response.len(), 0xf0, "the oracle response size");
    }

    #[test]
    fn an_overflow_at_a_selection_boundary_clears_the_next_selection() {
        let mut runtime = started_runtime();
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&hex("000403ff0000"));
        params.extend_from_slice(&hex("000b03030000"));
        let response = dispatch_bytes(&mut runtime, &pcr_read_command(&params));
        let mut expected = hex("00000014 00000002 000403ff0000 000b03000000 00000008");
        for _ in 0..8 {
            expected.extend_from_slice(&digest_entry(20, 0));
        }
        assert_eq!(response, success_response(&expected));
        assert_eq!(response.len(), 0xd2, "the oracle response size");
    }

    #[test]
    fn digest_sizes_match_every_supported_bank() {
        for (alg, size, fill) in [
            (TPM_ALG_SHA1, 20usize, 0x00u8),
            (TPM_ALG_SHA256, 32, 0x00),
            (TPM_ALG_SHA384, 48, 0x00),
            (TPM_ALG_SHA512, 64, 0x00),
        ] {
            let mut runtime = started_runtime();
            let response = dispatch_bytes(
                &mut runtime,
                &pcr_read_command(&one_bank_params(alg, [1, 0, 0])),
            );
            let mut expected = hex("00000014 00000001");
            expected.extend_from_slice(&alg.to_be_bytes());
            expected.extend_from_slice(&hex("03010000 00000001"));
            expected.extend_from_slice(&digest_entry(size, fill));
            assert_eq!(response, success_response(&expected), "alg {alg:#06x}");
        }
    }

    #[test]
    fn the_response_carries_the_current_pcr_update_counter() {
        let mut runtime = started_runtime();
        assert_eq!(
            runtime.live.state_reset.as_ref().unwrap().pcr_counter,
            STARTUP_PCR_COUNTER
        );
        runtime.live.state_reset.as_mut().unwrap().pcr_counter = 0xdead_beef;
        let response = dispatch_bytes(&mut runtime, &pcr_read_command(&0u32.to_be_bytes()));
        assert_eq!(&response[10..14], &0xdead_beefu32.to_be_bytes());
    }

    #[test]
    fn pcr_read_neither_mutates_the_runtime_nor_commits_nv() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let command = pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0xff, 0xff, 0xff]));
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("PCR_Read must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn missing_internal_bank_data_fails_without_panicking() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[0].banks[SHA256_SLOT] = None;
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [1, 0, 0]))
            ),
            error_response(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn wrong_length_internal_bank_data_fails_without_panicking() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[0].banks[SHA256_SLOT] = Some(vec![0u8; 31]);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [1, 0, 0]))
            ),
            error_response(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn the_upstream_initial_pcr_read_matches_byte_for_byte() {
        let mut runtime = started_runtime();
        let request = hex(
            "80010000002600 00017e 00000004 000403010010 000b03010010 000c03010010 000d03010010",
        );
        let mut expected = hex(
            "80010000018600000000 00000014 00000004 000403010010 000b03010010 000c03010010 \
             000d03010010 00000008",
        );
        for (size, fill) in [
            (20usize, 0x00u8),
            (20, 0xff),
            (32, 0x00),
            (32, 0xff),
            (48, 0x00),
            (48, 0xff),
            (64, 0x00),
            (64, 0xff),
        ] {
            expected.extend_from_slice(&digest_entry(size, fill));
        }
        assert_eq!(dispatch_bytes(&mut runtime, &request), expected);
    }

    #[test]
    fn tis_hashing_is_observable_through_pcr_read() {
        let mut runtime = started_runtime();
        assert_eq!(tis::hash_start(&mut runtime), TPM_SUCCESS);
        assert_eq!(tis::hash_data(&mut runtime, b"abc"), TPM_SUCCESS);
        assert_eq!(tis::hash_end(&mut runtime), TPM_SUCCESS);

        let stored = runtime.live.pcrs[17].banks[SHA256_SLOT]
            .clone()
            .expect("the TIS sequence extended PCR 17");
        assert_eq!(stored, hex(DRTM_ABC_SHA256));

        let command = pcr_read_command(&one_bank_params(TPM_ALG_SHA256, [0, 0, 0x02]));
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| Ok(())).expect("the command processes");

        let mut expected = 24u32.to_be_bytes().to_vec();
        expected.extend_from_slice(&hex("00000001 000b03000002 00000001 0020"));
        expected.extend_from_slice(&stored);
        assert_eq!(response, success_response(&expected));
    }

    #[test]
    fn sha1_bank_reads_the_sha1_slot() {
        let mut runtime = started_runtime();
        let marker: Vec<u8> = (0..20).map(|i| 0xa0 | i as u8).collect();
        runtime.live.pcrs[2].banks[SHA1_SLOT] = Some(marker.clone());
        let response = dispatch_bytes(
            &mut runtime,
            &pcr_read_command(&one_bank_params(TPM_ALG_SHA1, [0x04, 0, 0])),
        );
        let mut expected = hex("00000014 00000001 000403040000 00000001 0014");
        expected.extend_from_slice(&marker);
        assert_eq!(response, success_response(&expected));
    }
}
