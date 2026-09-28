// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/IntegrityCommands.c
// - libtpms/src/tpm2/PCR.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2021
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::extend::{DigestValue, commit_extend, prepare_extend};
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_LOCALITY, TPM_RC_SIZE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::TPM_RH_NULL;
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::pcr::{BankHasher, PCR_SLOT_BANKS, pcr_extend_allowed};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_PCR_EVENT_EVENT_DATA: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_EVENT_SIZE: usize = 1024;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let pcr_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let event_data = parse_event_data(frame.parameters)?;

    if pcr_handle != TPM_RH_NULL && !pcr_extend_allowed(pcr_handle as usize, runtime.locality) {
        return Err(TPM_RC_LOCALITY);
    }

    let digests = BankHasher::all().map(|mut hasher| {
        hasher.update(event_data);
        hasher.finalize()
    });

    if pcr_handle != TPM_RH_NULL {
        let entries: Vec<DigestValue<'_>> = digests
            .iter()
            .enumerate()
            .map(|(slot, digest)| DigestValue { slot, digest })
            .collect();
        let prepared = prepare_extend(runtime, pcr_handle as usize, &entries)?;
        commit_extend(runtime, pcr_handle as usize, prepared)?;
    }

    let mut parameters = (PCR_SLOT_BANKS.len() as u32).to_be_bytes().to_vec();
    for (&(hash_alg, _), digest) in PCR_SLOT_BANKS.iter().zip(&digests) {
        parameters.extend_from_slice(&hash_alg.to_be_bytes());
        parameters.extend_from_slice(digest);
    }
    Ok(CommandOutput::from_parameters(parameters))
}

fn parse_event_data(parameters: &[u8]) -> Result<&[u8], TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let event_data = reader
        .read_tpm2b(MAX_EVENT_SIZE)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_PCR_EVENT_EVENT_DATA,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_PCR_EVENT_EVENT_DATA,
        })?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(event_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::constants::{TPM_RC_AUTH_MISSING, TPM_RC_INITIALIZE};
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_PCR_EVENT;
    use crate::library::tpm2::command::core::test_support::{
        auth_session, counter_entropy, dispatch_bytes, dispatch_ignoring_result, error_response,
        for_each_mutation, hex, make_orderly, manufactured_runtime_with, prefix_bit_flips, process,
        pw_session, reload, start,
    };
    use crate::library::tpm2::command::pcr::test_support::{bank, pcr_counter};
    use crate::library::tpm2::command::session::processing::TPM_RS_PW;
    use crate::library::tpm2::crypto::EntropySource;
    use crate::library::tpm2::golden_responses::pcr_event::vector;

    use crate::library::tpm2::persistent::{
        OwnedPcrAllocation, OwnedPcrSelection, persistent_all_store,
    };

    use crate::library::tpm2::runtime::commit_restored_state;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const ENTROPY: EntropySource = counter_entropy::<0x3c>;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    const SHA1_SLOT: usize = 0;
    const SHA256_SLOT: usize = 1;

    const STARTUP_PCR_COUNTER: u32 = 20;

    const RC_SIZE: u32 = 0x095;
    const RC_LOCALITY: u32 = 0x907;
    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_FAILURE: u32 = 0x101;

    const RC_HANDLE1_INSUFFICIENT: u32 = 0x19a;
    const RC_HANDLE1_VALUE: u32 = 0x184;

    const RC_EVENT_INSUFFICIENT: u32 = 0x1da;
    const RC_EVENT_SIZE: u32 = 0x1d5;

    const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;

    const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA384: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                              8086072ba1e7cc2358baeca134c825a7";
    const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                              2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    const EMPTY_SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const EMPTY_SHA384: &str = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                                274edebfe76f65fbd51ad2f14898b95b";
    const EMPTY_SHA512: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                                47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    const BINARY_SHA1: &str = "f83fa0e751b27c7e5c0c8e68757cca55606dc0e4";
    const BINARY_SHA256: &str = "6509423fd9da5c225d2f8619ffae394b40f9f7686fee55a38c54b1424ac65f46";
    const BINARY_SHA384: &str = "13fdc95ab2f4c6849ef08ac11af9b93515494e9afad3bc79e9c21821e09b51ce\
                                 a012962c7cdc250795b57bca9ae5d6fb";
    const BINARY_SHA512: &str = "c7ee3385373eb6b41b25d0c67855b6b843737046771500d8a18c1d80145ad9fe\
                                 f8cc904c052dd6679562de82d5d72b37d2e1151d9f4af0a37f0371f7241cb77d";

    const MAX_SHA1: &str = "5b00669c480d5cffbdfa8bdba99561160f2d1b77";
    const MAX_SHA256: &str = "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9";
    const MAX_SHA384: &str = "55fd17eeb1611f9193f6ac600238ce63aa298c2e332f042b80c8f691f800e4c7\
                              505af20c1a86a31f08504587395f081f";
    const MAX_SHA512: &str = "37f652be867f28ed033269cbba201af2112c2b3fd334a89fd2f757938ddee815\
                              787cc61d6e24a8a33340d0f7e86ffc058816b88530766ba6e231620a130b566c";

    const EXTEND_ABC_SHA1: &str = "ccd5bd41458de644ac34a2478b58ff819bef5acf";
    const EXTEND_ABC_SHA256: &str =
        "589f9ffed4c477966bfb8d41f37895b08c69047df8f911d6f3b57fbe08faee8d";
    const EXTEND_ABC_SHA384: &str = "93732e3733514a841c982cfa75ea76ab55fe011acb9cd980ef452391\
                                     3c65be1b0998e04d77f8c174f81a82151619ca40";
    const EXTEND_ABC_SHA512: &str = "6b9e946755055542adba95a1588a7eaed86323b3bed97d602ee06839\
                                     d734048e02c63f37892d3adde0d25b5a9d89162e8804ab9ec0ac4a26\
                                     3545c4faecfdf53b";

    const ORACLE_EVENT: &[u8] = b"libtpms-rs pcr event";

    fn no_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        panic!("TPM2_PCR_Event must not draw host entropy");
    }

    fn manufactured_runtime() -> Tpm2Runtime {
        manufactured_runtime_with(None, ENTROPY)
    }

    #[track_caller]
    fn started_runtime() -> Tpm2Runtime {
        let mut runtime = manufactured_runtime();
        start(&mut runtime);
        runtime
    }

    fn event_command(handle: u32, auth: Option<&[u8]>, parameters: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        if let Some(auth) = auth {
            payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            payload.extend_from_slice(auth);
        }
        payload.extend_from_slice(parameters);

        let tag: u16 = if auth.is_some() { 0x8002 } else { 0x8001 };
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_PCR_EVENT.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn event_parameters(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    fn authorized_event(handle: u32, data: &[u8]) -> Vec<u8> {
        event_command(handle, Some(&pw_session(&[])), &event_parameters(data))
    }

    fn digest_parameters(digests: &[(u16, &str)]) -> Vec<u8> {
        let mut out = (digests.len() as u32).to_be_bytes().to_vec();
        for (hash_alg, digest) in digests {
            out.extend_from_slice(&hash_alg.to_be_bytes());
            out.extend_from_slice(&hex(digest));
        }
        out
    }

    fn success_response(parameters: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x02];
        out.extend_from_slice(&(19 + parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(parameters);
        out.extend_from_slice(&hex("0000 01 0000"));
        out
    }

    fn abc_digest_response() -> Vec<u8> {
        success_response(&digest_parameters(&[
            (TPM_ALG_SHA1, ABC_SHA1),
            (TPM_ALG_SHA256, ABC_SHA256),
            (TPM_ALG_SHA384, ABC_SHA384),
            (TPM_ALG_SHA512, ABC_SHA512),
        ]))
    }

    fn pcr_read_command(pcr: usize) -> Vec<u8> {
        let mut payload = 4u32.to_be_bytes().to_vec();
        for hash_alg in [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512] {
            payload.extend_from_slice(&hash_alg.to_be_bytes());
            payload.push(3);
            let mut select = [0u8; 3];
            select[pcr / 8] = 1 << (pcr % 8);
            payload.extend_from_slice(&select);
        }
        let mut out = hex("8001");
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&0x0000_017eu32.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    struct Snapshot {
        failure_mode: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
        pcr_counter: Option<u32>,
        pcr_banks: Vec<Vec<Option<Vec<u8>>>>,
        drbg_seed: Vec<u8>,
        drbg_counter: u64,
        live_drbg_seed: Vec<u8>,
        live_drbg_counter: u64,
        free_session_slots: u32,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = runtime.state.as_ref().expect("state present");
        Snapshot {
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: state.persistent.orderly_state,
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
            drbg_seed: state.orderly.drbg_state.seed.expose().to_vec(),
            drbg_counter: state.orderly.drbg_state.reseed_counter,
            live_drbg_seed: runtime.live.orderly.drbg_state.seed.expose().to_vec(),
            live_drbg_counter: runtime.live.orderly.drbg_state.reseed_counter,
            free_session_slots: runtime.live.free_session_slots,
        }
    }

    #[track_caller]
    fn assert_drbg_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let state = runtime.state.as_ref().expect("state present");
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &before.drbg_seed[..]
        );
        assert_eq!(state.orderly.drbg_state.reseed_counter, before.drbg_counter);
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &before.live_drbg_seed[..]
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            before.live_drbg_counter
        );
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
        assert_drbg_unchanged(runtime, before);
        assert_eq!(runtime.live.free_session_slots, before.free_session_slots);
    }

    #[test]
    fn pcr_event_pre_startup_initialize_rejection() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_PCR_Event before TPM2_Startup"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &event_command(10, None, &[])),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_PCR_Event before TPM2_Startup: the lifecycle check precedes handle parsing"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn missing_authorization_area_auth_missing() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, None, &event_parameters(b"abc"))
            ),
            error_response(TPM_RC_AUTH_MISSING)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn nonempty_password_empty_auth_failure() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let auth = auth_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, Some(&auth), &event_parameters(b"abc"))
            ),
            error_response(RC_SESSION1_BAD_AUTH),
            "every implemented PCR has an empty effective authValue"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn out_of_range_handle_decorated_rejection() {
        for handle in [
            IMPLEMENTATION_PCR as u32,
            100,
            0x0100_0000,
            0x4000_0001,
            0x4000_000c,
            0x8000_0000,
            u32::MAX,
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_event(handle, b"abc")),
                error_response(RC_HANDLE1_VALUE),
                "handle {handle:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn truncated_handle_decorated_error() {
        for len in 0..4usize {
            let mut runtime = started_runtime();
            let mut command = hex("8002 00000000 0000013c");
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
    fn short_event_all_bank_digests_and_extension() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            abc_digest_response()
        );
        for (slot, expected) in [
            (0, EXTEND_ABC_SHA1),
            (1, EXTEND_ABC_SHA256),
            (2, EXTEND_ABC_SHA384),
            (3, EXTEND_ABC_SHA512),
        ] {
            assert_eq!(
                bank(&runtime, 10, slot),
                hex(expected),
                "slot {slot} holds Hash(oldPCR || Hash(eventData))"
            );
        }
        assert_eq!(
            pcr_counter(&runtime),
            STARTUP_PCR_COUNTER + 4,
            "one increment per extended allocated bank"
        );
    }

    #[test]
    fn empty_event_hash_and_extension() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, &[])),
            success_response(&digest_parameters(&[
                (TPM_ALG_SHA1, EMPTY_SHA1),
                (TPM_ALG_SHA256, EMPTY_SHA256),
                (TPM_ALG_SHA384, EMPTY_SHA384),
                (TPM_ALG_SHA512, EMPTY_SHA512),
            ]))
        );
        assert_ne!(bank(&runtime, 10, SHA256_SLOT), vec![0u8; 32]);
        assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + 4);
    }

    #[test]
    fn binary_event_reference_digest_match() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &authorized_event(10, &[0x00, 0xff, 0x80, 0x01])
            ),
            success_response(&digest_parameters(&[
                (TPM_ALG_SHA1, BINARY_SHA1),
                (TPM_ALG_SHA256, BINARY_SHA256),
                (TPM_ALG_SHA384, BINARY_SHA384),
                (TPM_ALG_SHA512, BINARY_SHA512),
            ]))
        );
    }

    #[test]
    fn maximum_size_event_acceptance() {
        let mut runtime = started_runtime();
        let data: Vec<u8> = (0..MAX_EVENT_SIZE).map(|index| index as u8).collect();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, &data)),
            success_response(&digest_parameters(&[
                (TPM_ALG_SHA1, MAX_SHA1),
                (TPM_ALG_SHA256, MAX_SHA256),
                (TPM_ALG_SHA384, MAX_SHA384),
                (TPM_ALG_SHA512, MAX_SHA512),
            ]))
        );
        assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + 4);
    }

    #[test]
    fn digest_list_compiled_bank_order_fixed_sizes() {
        let mut runtime = started_runtime();
        let response = dispatch_bytes(&mut runtime, &authorized_event(10, b"abc"));
        assert_eq!(&response[..2], &[0x80, 0x02]);
        let parameters = &response[14..response.len() - 5];
        assert_eq!(&parameters[..4], &4u32.to_be_bytes());
        let mut at = 4;
        for (hash_alg, digest_size) in [
            (TPM_ALG_SHA1, 20usize),
            (TPM_ALG_SHA256, 32),
            (TPM_ALG_SHA384, 48),
            (TPM_ALG_SHA512, 64),
        ] {
            assert_eq!(
                &parameters[at..at + 2],
                &hash_alg.to_be_bytes(),
                "alg {hash_alg:#06x}"
            );
            at += 2 + digest_size;
        }
        assert_eq!(at, parameters.len(), "no TPM2B framing around digests");
    }

    #[test]
    fn oversized_event_indexed_size_error() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        for length in [MAX_EVENT_SIZE + 1, 2048, 4000] {
            let data = vec![0xa5u8; length];
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_event(10, &data)),
                error_response(RC_EVENT_SIZE),
                "length {length}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn declared_size_check_before_payload_length() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, Some(&pw_session(&[])), &hex("ffff"))
            ),
            error_response(RC_EVENT_SIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn truncated_parameter_prefix_event_data_error() {
        let full = event_parameters(b"abcd");
        for len in 0..full.len() {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &event_command(10, Some(&pw_session(&[])), &full[..len])
                ),
                error_response(RC_EVENT_INSUFFICIENT),
                "parameters truncated to {len} bytes"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameter_bytes_size_error() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let mut parameters = event_parameters(b"abc");
        parameters.push(0xee);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, Some(&pw_session(&[])), &parameters)
            ),
            error_response(RC_SIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn null_handle_digests_state_unchanged() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let serialized_before =
            persistent_all_store(runtime.state.as_ref().unwrap()).expect("serializes");
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(TPM_RH_NULL, b"abc")),
            abc_digest_response()
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            persistent_all_store(runtime.state.as_ref().unwrap()).expect("serializes"),
            serialized_before,
            "the serialized persistent state is untouched"
        );
    }

    #[test]
    fn null_handle_locality_independence() {
        for locality in 0..5u8 {
            let mut runtime = started_runtime();
            runtime.locality = locality;
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_event(TPM_RH_NULL, b"abc")),
                abc_digest_response(),
                "locality {locality}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn null_handle_parameter_and_password_validation() {
        let mut runtime = started_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(TPM_RH_NULL, Some(&pw_session(&[])), &hex("ffff"))
            ),
            error_response(RC_EVENT_SIZE),
            "the event data is unmarshaled before the null-handle shortcut"
        );
        let auth = auth_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(TPM_RH_NULL, Some(&auth), &event_parameters(b"abc"))
            ),
            error_response(RC_SESSION1_BAD_AUTH),
            "nullAuth is the empty auth value"
        );
    }

    #[test]
    fn unallocated_bank_report_without_extension() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            abc_digest_response(),
            "the response still carries every compiled digest"
        );
        assert_eq!(bank(&runtime, 10, SHA1_SLOT), vec![0u8; 20], "unallocated");
        assert_eq!(bank(&runtime, 10, SHA256_SLOT), hex(EXTEND_ABC_SHA256));
        assert_eq!(
            pcr_counter(&runtime),
            STARTUP_PCR_COUNTER + 1,
            "only the allocated bank increments the counter"
        );
    }

    #[test]
    fn missing_unallocated_bank_no_creation() {
        let mut runtime = started_runtime();
        runtime.live_pcr_allocated = Some(OwnedPcrAllocation {
            selections: vec![OwnedPcrSelection {
                hash_alg: TPM_ALG_SHA256,
                select: vec![0xff, 0xff, 0xff],
            }],
        });
        runtime.live.pcrs[10].banks[SHA1_SLOT] = None;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            abc_digest_response()
        );
        assert!(
            runtime.live.pcrs[10].banks[SHA1_SLOT].is_none(),
            "no bank storage is created for an unallocated bank"
        );
    }

    #[test]
    fn non_incrementing_pcr_counter_preservation() {
        for pcr in [16u32, 21, 22, 23] {
            let mut runtime = started_runtime();
            runtime.locality = 2;
            let before = pcr_counter(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_event(pcr, b"abc")),
                abc_digest_response(),
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
            dispatch_bytes(&mut runtime, &authorized_event(0, b"abc")),
            abc_digest_response()
        );
        assert_eq!(pcr_counter(&runtime), STARTUP_PCR_COUNTER + 4);
    }

    #[test]
    fn locality_matrix_upstream_table_match() {
        const EVENT_LOCALITY: [u8; IMPLEMENTATION_PCR] = [
            0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f,
            0x1f, 0x1f, 0x1f, 0x1c, 0x1c, 0x0c, 0x0e, 0x04, 0x04, 0x1f,
        ];
        for (pcr, event_locality) in EVENT_LOCALITY.into_iter().enumerate() {
            for locality in 0..5u8 {
                let allowed = event_locality & (1 << locality) != 0;
                let mut runtime = started_runtime();
                runtime.locality = locality;
                let before = snapshot(&runtime);
                let response = dispatch_bytes(&mut runtime, &authorized_event(pcr as u32, b"abc"));
                if allowed {
                    assert_eq!(
                        response,
                        abc_digest_response(),
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
    fn disallowed_locality_rejection_before_orderly_check() {
        let mut runtime = started_runtime();
        runtime.locality = 1;
        make_orderly(&mut runtime, 0x0001);
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(21, b"abc")),
            error_response(RC_LOCALITY),
            "the locality check precedes the NV availability check"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn state_saved_pcr_orderly_clear_and_nv_commit() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        let nv_before = runtime.nv_memory.clone();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            abc_digest_response()
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
    fn state_saved_pcr_da_used_orderly_record() {
        let mut runtime = started_runtime();
        make_orderly(&mut runtime, 0x0001);
        runtime.live.da_used = true;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            abc_digest_response()
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
            dispatch_bytes(&mut runtime, &authorized_event(15, b"abc")),
            error_response(RC_NV_UNAVAILABLE),
            "RETURN_IF_ORDERLY fails before any PCR mutation"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn non_state_saved_pcr_orderly_and_nv_unchanged() {
        for pcr in [16u32, 17, 20, 23] {
            let mut runtime = started_runtime();
            runtime.locality = 2;
            make_orderly(&mut runtime, 0x0001);
            runtime.nv_available = false;
            let nv_before = runtime.nv_memory.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &authorized_event(pcr, b"abc")),
                abc_digest_response(),
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
    fn nv_commit_callback_persistent_change_only() {
        let mut runtime = started_runtime();
        let command = authorized_event(10, b"abc");
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a non-orderly PCR_Event must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, abc_digest_response());

        make_orderly(&mut runtime, 0x0001);
        let command = authorized_event(10, b"abc");
        let input = CommandInput::new(command.len() as u32, command);
        let mut commits = 0u32;
        let response = process(&mut runtime, 0, &input, |_| {
            commits += 1;
            Ok(())
        })
        .expect("the command processes");
        assert_ne!(&response[6..10], &RC_FAILURE.to_be_bytes());
        assert_eq!(
            commits, 1,
            "clearing the orderly state commits exactly once"
        );
    }

    #[test]
    fn missing_host_entropy_drbg_preservation() {
        let mut runtime = started_runtime();
        runtime.entropy = no_entropy;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            abc_digest_response()
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(TPM_RH_NULL, b"abc")),
            abc_digest_response()
        );
        assert_drbg_unchanged(&runtime, &before);
    }

    #[test]
    fn malformed_internal_bank_failure_without_mutation() {
        let mut runtime = started_runtime();
        runtime.live.pcrs[10].banks[SHA256_SLOT] = Some(vec![0u8; 31]);
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            error_response(RC_FAILURE),
            "a wrong-length bank is an internal failure"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn missing_state_reset_panic_free_failure() {
        let mut runtime = started_runtime();
        runtime.live.state_reset = None;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            error_response(RC_FAILURE)
        );
    }

    #[test]
    fn counter_maximum_failure_without_mutation() {
        let mut runtime = started_runtime();
        runtime.live.state_reset.as_mut().unwrap().pcr_counter = u32::MAX;
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, b"abc")),
            error_response(RC_FAILURE),
            "the overflow is detected before any PCR is written"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn bit_flip_panic_safety() {
        let valid = authorized_event(10, b"abc");
        for_each_mutation(
            "TPM2_PCR_Event",
            prefix_bit_flips(&valid, valid.len(), 6, false),
            |bytes| {
                dispatch_ignoring_result(&mut started_runtime(), bytes);
            },
        );
    }

    #[test]
    fn truncated_command_prefix_safe_rejection() {
        let valid = authorized_event(10, b"abc");
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
            assert_ne!(&response[6..10], &[0u8; 4], "length {len}");
            assert_unchanged(&runtime, &before);
        }
    }

    #[track_caller]
    fn rebooted_runtime(runtime: &Tpm2Runtime) -> Tpm2Runtime {
        let restored = reload(runtime.state.as_ref().expect("state present"));
        let mut rebooted = commit_restored_state(restored).expect("the persisted state restores");
        rebooted.entropy = ENTROPY;
        rebooted
    }

    #[test]
    fn upstream_libtpms_flow_byte_match() {
        let mut runtime = manufactured_runtime();

        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, ORACLE_EVENT)),
            vector("EVENT_BEFORE_STARTUP")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 00")),
            vector("STARTUP_CLEAR")
        );
        runtime.nv_update_pending = false;

        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, None, &event_parameters(&[]))
            ),
            vector("EVENT_MISSING_AUTH")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("8002 0000000d 0000013c 000000")),
            vector("EVENT_TRUNCATED_HANDLE")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(24, ORACLE_EVENT)),
            vector("EVENT_HANDLE_24")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(0x4000_0001, ORACLE_EVENT)),
            vector("EVENT_HANDLE_OWNER")
        );
        let wrong = auth_session(TPM_RS_PW, &[], 0x00, b"wrong");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, Some(&wrong), &event_parameters(&[]))
            ),
            vector("EVENT_WRONG_PASSWORD")
        );

        let auth = pw_session(&[]);
        assert_eq!(
            dispatch_bytes(&mut runtime, &event_command(10, Some(&auth), &[0x00])),
            vector("EVENT_TRUNCATED_TPM2B")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, Some(&auth), &[0x00, 0x04, 0x61, 0x62])
            ),
            vector("EVENT_TRUNCATED_PAYLOAD")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &event_command(10, Some(&auth), &[0xff, 0xff])),
            vector("EVENT_DECLARED_FFFF")
        );
        let oversized: Vec<u8> = (0..1025).map(|index| index as u8).collect();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, &oversized)),
            vector("EVENT_OVERSIZED")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &event_command(10, Some(&auth), &[0x00, 0x00, 0xee])
            ),
            vector("EVENT_TRAILING")
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(10)),
            vector("READ_PCR10_BEFORE")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, ORACLE_EVENT)),
            vector("EVENT_PCR10")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(10)),
            vector("READ_PCR10_AFTER")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(TPM_RH_NULL, ORACLE_EVENT)),
            vector("EVENT_NULL")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(10)),
            vector("READ_PCR10_AFTER_NULL")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(TPM_RH_NULL, &[])),
            vector("EVENT_EMPTY")
        );
        let max: Vec<u8> = (0..1024).map(|index| index as u8).collect();
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, &max)),
            vector("EVENT_MAX")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(10)),
            vector("READ_PCR10_AFTER_MAX")
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(21)),
            vector("READ_PCR21_BEFORE")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(21, ORACLE_EVENT)),
            vector("EVENT_PCR21_LOCALITY0")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(21)),
            vector("READ_PCR21_AFTER_LOCALITY0")
        );
        runtime.locality = 4;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(TPM_RH_NULL, ORACLE_EVENT)),
            vector("EVENT_NULL_LOCALITY4")
        );
        runtime.locality = 2;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(21, ORACLE_EVENT)),
            vector("EVENT_PCR21_LOCALITY2")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(21)),
            vector("READ_PCR21_AFTER_LOCALITY2")
        );
        runtime.locality = 0;
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(16, ORACLE_EVENT)),
            vector("EVENT_PCR16")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &pcr_read_command(16)),
            vector("READ_PCR16_AFTER")
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014500 01")),
            vector("SHUTDOWN_STATE")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(10, ORACLE_EVENT)),
            vector("EVENT_PCR10_ORDERLY")
        );
        let mut runtime = rebooted_runtime(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 01")),
            vector("STARTUP_STATE_AFTER_ORDERLY_EVENT"),
            "the state-saved PCR event invalidated the orderly shutdown"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 00")),
            vector("STARTUP_CLEAR_RETRY")
        );

        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014500 01")),
            vector("SHUTDOWN_STATE_SECOND")
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &authorized_event(16, ORACLE_EVENT)),
            vector("EVENT_PCR16_ORDERLY")
        );
        let mut runtime = rebooted_runtime(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &hex("80010000000c0000014400 01")),
            vector("STARTUP_STATE_AFTER_PCR16_EVENT"),
            "a non-state-saved PCR event preserves the orderly shutdown"
        );
    }

    #[test]
    fn oracle_success_parameters_local_digest_match() {
        let oracle = vector("EVENT_PCR10");
        let mut expected = digest_parameters(&[
            (TPM_ALG_SHA1, "3bab2689d25ae6e83dc854bbb7d93cb4e6bd25f5"),
            (
                TPM_ALG_SHA256,
                "93c5d10b05d942e837251f38067049f1179ed38a1d30adcf45643600a10ac293",
            ),
            (
                TPM_ALG_SHA384,
                "cfa3897dea1c4f716d36036c6cdfb5b63e7ae5bf8b318f2a5516f9121a6906f2\
                 43a8de2863de680557efb1cd85de3510",
            ),
            (
                TPM_ALG_SHA512,
                "bbe36c627936413a1e44e9d3539ef7a17a34288c8b8092a6143738735a8abde9\
                 7c9bdb0dd783d5098a6f67a43780119050869633571d43fec9b4f52e085c0a6a",
            ),
        ]);
        let mut hashers = BankHasher::all();
        for hasher in &mut hashers {
            hasher.update(ORACLE_EVENT);
        }
        let mut recomputed = 4u32.to_be_bytes().to_vec();
        for ((hash_alg, _), hasher) in PCR_SLOT_BANKS.into_iter().zip(hashers) {
            recomputed.extend_from_slice(&hash_alg.to_be_bytes());
            recomputed.extend_from_slice(&hasher.finalize());
        }
        assert_eq!(recomputed, expected, "the compiled hashers agree");
        expected.splice(0..0, (expected.len() as u32).to_be_bytes());
        assert_eq!(
            &oracle[10..oracle.len() - 5],
            &expected[..],
            "oracle payload"
        );
    }
}
