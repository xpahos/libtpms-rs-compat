use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::marshal::{BlobReader, BlobWriter};
use crate::library::tpm2::public::DIGEST_SIZE;
use crate::library::tpm2::random::generate_random;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_GET_RANDOM_BYTES_REQUESTED: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_RANDOM_BYTES: usize = DIGEST_SIZE;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let bytes_requested = parse_bytes_requested(frame.parameters)?;
    let length = usize::from(bytes_requested).min(MAX_RANDOM_BYTES);
    let random = generate_random(runtime, length)?;
    let mut writer = BlobWriter::with_capacity(size_of::<u16>() + random.len());
    writer.write_tpm2b(&random).map_err(|_| TPM_RC_FAILURE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

fn parse_bytes_requested(parameters: &[u8]) -> Result<u16, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let bytes_requested = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_GET_RANDOM_BYTES_REQUESTED)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(bytes_requested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::command::core::registry::TPM_CC_GET_RANDOM;
    use crate::library::tpm2::command::core::test_support::{
        counter_entropy, dispatch_bytes, error_response, hex, manufactured_runtime_with, process,
        start,
    };
    use crate::library::tpm2::command::crypto::test_support::assert_live_drbg_unchanged;
    use crate::library::tpm2::crypto::EntropySource;
    use crate::library::tpm2::crypto::{
        CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_MAGIC, DrbgGenerateRecord, boundary_record,
        generate_record,
    };

    use crate::library::tpm2::persistent::{OwnedDrbgState, OwnedSecret};

    const ENTROPY: EntropySource = counter_entropy::<0x63>;

    const RC_INSUFFICIENT_PARAM1: u32 = 0x1da;
    const RC_SIZE: u32 = 0x095;
    const RC_SESSION1_HANDLE: u32 = 0x98b;
    const RC_INSUFFICIENT: u32 = 0x09a;

    fn manufactured_runtime() -> Tpm2Runtime {
        manufactured_runtime_with(None, ENTROPY)
    }

    #[track_caller]
    fn started_runtime() -> Tpm2Runtime {
        let mut runtime = manufactured_runtime();
        start(&mut runtime);
        runtime
    }

    fn get_capability_properties_command() -> Vec<u8> {
        hex("80010000001600 00017a 00000006 00000100 0000000a")
    }

    fn restricted_properties_response() -> Vec<u8> {
        crate::library::tpm2::golden_responses::get_test_result::vector("FM_CAP_PT105_C1").to_vec()
    }

    fn get_random_command(parameters: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_GET_RANDOM.to_be_bytes());
        out.extend_from_slice(parameters);
        out
    }

    #[track_caller]
    fn request(runtime: &mut Tpm2Runtime, bytes_requested: u16) -> Vec<u8> {
        dispatch_bytes(runtime, &get_random_command(&bytes_requested.to_be_bytes()))
    }

    #[track_caller]
    fn random_bytes_of(response: &[u8]) -> Vec<u8> {
        assert_eq!(&response[..2], &[0x80, 0x01], "no-sessions response tag");
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
        assert_eq!(
            u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize,
            response.len(),
            "the header size covers the whole response"
        );
        let declared = u16::from_be_bytes(response[10..12].try_into().unwrap());
        assert_eq!(
            usize::from(declared),
            response.len() - 12,
            "the TPM2B length prefix matches the payload"
        );
        response[12..].to_vec()
    }

    fn install_initial(runtime: &mut Tpm2Runtime, record: &DrbgGenerateRecord) {
        runtime.live.orderly.drbg_state = OwnedDrbgState {
            reseed_counter: record.initial_reseed_counter,
            drbg_magic: DRBG_MAGIC,
            seed: OwnedSecret::copy_of(&record.initial_seed),
            last_value: record.initial_last_value,
        };
    }

    struct Snapshot {
        startup_received: bool,
        nv_update_pending: bool,
        persistent_drbg_seed: Vec<u8>,
        persistent_drbg_counter: u64,
        orderly_state: u16,
        nv_memory: Box<[u8]>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = runtime.state.as_ref().expect("state present");
        Snapshot {
            startup_received: runtime.startup_received,
            nv_update_pending: runtime.nv_update_pending,
            persistent_drbg_seed: state.orderly.drbg_state.seed.expose().to_vec(),
            persistent_drbg_counter: state.orderly.drbg_state.reseed_counter,
            orderly_state: state.persistent.orderly_state,
            nv_memory: runtime.nv_memory.clone(),
        }
    }

    #[track_caller]
    fn assert_persistent_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let state = runtime.state.as_ref().expect("state present");
        assert_eq!(runtime.startup_received, before.startup_received);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(
            state.orderly.drbg_state.seed.expose(),
            &before.persistent_drbg_seed[..]
        );
        assert_eq!(
            state.orderly.drbg_state.reseed_counter,
            before.persistent_drbg_counter
        );
        assert_eq!(state.persistent.orderly_state, before.orderly_state);
        assert_eq!(runtime.nv_memory, before.nv_memory);
    }

    #[test]
    fn pre_startup_rejection() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            request(&mut runtime, 4),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_GetRandom before TPM2_Startup"
        );
        assert_eq!(
            dispatch_bytes(&mut runtime, &get_random_command(&[])),
            error_response(TPM_RC_INITIALIZE),
            "TPM2_GetRandom before TPM2_Startup: the lifecycle check precedes parameter parsing"
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, before.persistent_drbg_counter,
            "TPM2_GetRandom before TPM2_Startup: a rejected command leaves the live DRBG alone"
        );
        assert_persistent_unchanged(&runtime, &before);
        assert!(
            !runtime.failure_mode,
            "TPM2_GetRandom before TPM2_Startup: the lifecycle check is not a fatal error"
        );
    }

    #[test]
    fn truncated_bytes_requested_indexed_error() {
        for parameters in [&[][..], &[0x00][..], &[0xff][..]] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.reseed_counter;
            assert_eq!(
                dispatch_bytes(&mut runtime, &get_random_command(parameters)),
                error_response(RC_INSUFFICIENT_PARAM1),
                "parameters {parameters:02x?}"
            );
            assert_eq!(runtime.live.orderly.drbg_state.reseed_counter, live_before);
            assert_persistent_unchanged(&runtime, &before);
            assert!(
                !runtime.failure_mode,
                "a parse error is not a fatal DRBG error"
            );
        }
    }

    #[test]
    fn trailing_parameter_bytes_return_size() {
        for parameters in [&[0x00, 0x04, 0x00][..], &[0x00, 0x04, 0, 0, 0, 0][..]] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.reseed_counter;
            assert_eq!(
                dispatch_bytes(&mut runtime, &get_random_command(parameters)),
                error_response(RC_SIZE),
                "parameters {parameters:02x?}"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter, live_before,
                "the parse failure precedes generation"
            );
            assert_persistent_unchanged(&runtime, &before);
            assert!(
                !runtime.failure_mode,
                "a parse error is not a fatal DRBG error"
            );
        }
    }

    #[test]
    fn response_shape_oracle_match_all_sizes() {
        let mut runtime = started_runtime();
        assert_eq!(
            request(&mut runtime, 0),
            hex("80010000000c000000000000"),
            "a zero-byte request answers an empty TPM2B"
        );
        for (requested, expected_len) in [
            (1u16, 1usize),
            (16, 16),
            (63, 63),
            (64, 64),
            (65, 64),
            (255, 64),
            (1024, 64),
            (u16::MAX, 64),
        ] {
            let response = request(&mut runtime, requested);
            assert_eq!(
                response.len(),
                12 + expected_len,
                "request for {requested} bytes"
            );
            assert_eq!(
                random_bytes_of(&response).len(),
                expected_len,
                "request for {requested} bytes"
            );
        }
    }

    #[test]
    fn oversized_request_sixty_four_byte_cap() {
        let record = generate_record(false);
        let mut runtime = started_runtime();

        install_initial(&mut runtime, &record);
        let clamped: Vec<Vec<u8>> = [65u16, 255, u16::MAX]
            .into_iter()
            .map(|requested| random_bytes_of(&request(&mut runtime, requested)))
            .collect();

        install_initial(&mut runtime, &record);
        let exact: Vec<Vec<u8>> = [64u16, 64, 64]
            .into_iter()
            .map(|requested| random_bytes_of(&request(&mut runtime, requested)))
            .collect();

        assert_eq!(clamped, exact, "the clamp only limits the request size");
        assert!(clamped.iter().all(|bytes| bytes.len() == 64));
    }

    #[test]
    fn known_drbg_state_oracle_byte_match() {
        let record = generate_record(false);
        let mut runtime = started_runtime();
        install_initial(&mut runtime, &record);

        for (index, step) in record.steps.iter().enumerate() {
            let response = request(&mut runtime, step.requested);
            assert_eq!(random_bytes_of(&response), step.output(), "step {index}");
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter, step.reseed_counter_after,
                "step {index}"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.expose(),
                step.seed_after,
                "step {index}"
            );
        }
    }

    #[test]
    fn repeated_command_runtime_generator_advancement() {
        let mut runtime = started_runtime();
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut counter = runtime.live.orderly.drbg_state.reseed_counter;
        for _ in 0..4 {
            let bytes = random_bytes_of(&request(&mut runtime, 32));
            assert!(!seen.contains(&bytes), "a repeated output");
            seen.push(bytes);
            let next = runtime.live.orderly.drbg_state.reseed_counter;
            assert_eq!(next, counter + 1);
            counter = next;
        }
    }

    #[test]
    fn success_persistent_state_nv_unchanged() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        for requested in [0u16, 1, 64, 65, u16::MAX] {
            let response = request(&mut runtime, requested);
            assert_eq!(&response[6..10], &[0, 0, 0, 0]);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn session_tagged_request_oracle_match() {
        let pw_auth = hex("8002000000190000017b 00000009 40000009 0000 00 0000 0010");
        let no_authsize = hex("8002000000 0c 0000017b 0010");
        let authsize_zero = hex("8002000000 10 0000017b 00000000 0010");

        for (label, command, expected) in [
            ("pw_auth", pw_auth, RC_SESSION1_HANDLE),
            ("no_authsize", no_authsize, RC_INSUFFICIENT),
            ("authsize_zero", authsize_zero, RC_SIZE),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.reseed_counter;
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "{label}"
            );
            assert_eq!(runtime.live.orderly.drbg_state.reseed_counter, live_before);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn sessionless_request_auth_area_omission() {
        let mut runtime = started_runtime();
        let response = request(&mut runtime, 8);
        assert_eq!(&response[..2], &[0x80, 0x01]);
        assert_eq!(response.len(), 12 + 8, "no trailing authorization area");
    }

    #[test]
    fn drbg_failure_bare_error_tpm_stop() {
        for command in [
            get_random_command(&[0x00, 0x00]),
            get_random_command(&[0x00, 0x10]),
            get_random_command(&[0xff, 0xff]),
        ] {
            let mut runtime = started_runtime();
            runtime.live.orderly.drbg_state.seed = OwnedSecret::copy_of(&[0x11; 47]);
            let before = snapshot(&runtime);
            let live_before = runtime.live.orderly.drbg_state.clone();
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(TPM_RC_FAILURE),
                "an error response carries no parameters and no sessions"
            );
            assert!(runtime.failure_mode, "a fatal DRBG error stops the TPM");
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn foreign_drbg_magic_tpm_stop() {
        let mut runtime = started_runtime();
        runtime.live.orderly.drbg_state.drbg_magic = DRBG_MAGIC ^ 1;
        let before = snapshot(&runtime);
        let live_before = runtime.live.orderly.drbg_state.clone();
        assert_eq!(
            dispatch_bytes(&mut runtime, &get_random_command(&[0x00, 0x10])),
            error_response(TPM_RC_FAILURE)
        );
        assert!(runtime.failure_mode);
        assert_live_drbg_unchanged(&runtime, &live_before);
        assert_persistent_unchanged(&runtime, &before);
    }

    #[test]
    fn post_drbg_failure_failure_mode_path() {
        let mut runtime = started_runtime();
        runtime.live.orderly.drbg_state.seed = OwnedSecret::copy_of(&[0x11; 47]);
        let command = get_random_command(&[0x00, 0x10]);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failed GetRandom must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert!(runtime.failure_mode);

        let before = snapshot(&runtime);
        let live_before = runtime.live.orderly.drbg_state.clone();
        for (follow_up, expected) in [
            (
                get_capability_properties_command(),
                restricted_properties_response(),
            ),
            (
                get_random_command(&[0x00, 0x10]),
                error_response(TPM_RC_FAILURE),
            ),
        ] {
            let input = CommandInput::new(follow_up.len() as u32, follow_up);
            let response = process(&mut runtime, 0, &input, |_| {
                panic!("failure mode must not schedule an NV commit")
            })
            .expect("the command processes");
            assert_eq!(
                response, expected,
                "failure mode answers every command itself"
            );
        }
        assert_live_drbg_unchanged(&runtime, &live_before);
        assert_persistent_unchanged(&runtime, &before);
    }

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(crate::library::constants::TPM_FAIL)
    }

    #[test]
    fn reseed_threshold_oracle_match() {
        let record = boundary_record(false);
        let case = &record.cases[1];
        let mut runtime = started_runtime();
        runtime.live.orderly.drbg_state = OwnedDrbgState {
            reseed_counter: case.initial_reseed_counter,
            drbg_magic: DRBG_MAGIC,
            seed: OwnedSecret::copy_of(&record.initial_seed),
            last_value: record.initial_last_value,
        };
        let before = snapshot(&runtime);

        let command = get_random_command(&case.requested.to_be_bytes());
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("an automatic reseed must not schedule an NV commit")
        })
        .expect("the command processes");

        assert_eq!(random_bytes_of(&response), case.output());
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            case.reseed_counter_after
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            case.seed_after
        );
        assert!(!runtime.failure_mode);
        assert_persistent_unchanged(&runtime, &before);
    }

    #[test]
    fn reseed_threshold_entropy_failure_zero_bytes() {
        let mut runtime = started_runtime();
        runtime.entropy = failing_entropy;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        let before = snapshot(&runtime);
        let live_before = runtime.live.orderly.drbg_state.clone();

        let mut expected = hex("80010000001c000000000010");
        expected.extend_from_slice(&[0u8; 16]);

        for attempt in 0..3 {
            if attempt == 1 {
                runtime.entropy = failing_entropy;
                runtime.entropy = |_buffer: &mut [u8]| -> Result<(), TpmResult> {
                    panic!("the latched condition must not retry the source")
                };
            }
            let command = get_random_command(&[0x00, 0x10]);
            let input = CommandInput::new(command.len() as u32, command);
            let response = process(&mut runtime, 0, &input, |_| {
                panic!("a failed automatic reseed must not schedule an NV commit")
            })
            .expect("the command processes");
            assert_eq!(response, expected, "attempt {attempt}");
            assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
            assert!(
                !runtime.failure_mode,
                "an entropy-source failure is not a FAIL() site"
            );
            assert_live_drbg_unchanged(&runtime, &live_before);
            assert_persistent_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn get_random_nv_commit_callback_omission() {
        let mut runtime = started_runtime();
        let command = get_random_command(&[0x00, 0x20]);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("GetRandom must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);

        let failing = get_random_command(&[0x00]);
        let input = CommandInput::new(failing.len() as u32, failing);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failed GetRandom must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(RC_INSUFFICIENT_PARAM1));
    }

    #[test]
    fn short_parameter_upstream_error() {
        let filler = [0x00u8, 0xff, 0x80, 0x7f];
        for length in 0..=6usize {
            for &byte in &filler {
                let mut runtime = started_runtime();
                let before = snapshot(&runtime);
                let response =
                    dispatch_bytes(&mut runtime, &get_random_command(&vec![byte; length]));
                assert_eq!(&response[..2], &[0x80, 0x01], "length {length}");
                assert_eq!(
                    u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize,
                    response.len(),
                    "length {length}"
                );
                let code = u32::from_be_bytes(response[6..10].try_into().unwrap());
                let expected = match length {
                    0 | 1 => RC_INSUFFICIENT_PARAM1,
                    2 => 0,
                    _ => RC_SIZE,
                };
                assert_eq!(code, expected, "length {length}, byte {byte:#04x}");
                if code != 0 {
                    assert_eq!(response.len(), 10);
                    assert_persistent_unchanged(&runtime, &before);
                }
            }
        }
    }
}
