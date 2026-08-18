use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::algorithm::{algorithm_enabled, hash_profile_name};
use super::super::crypto::{COMPILED_HASHES, Hasher};
use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, hierarchy_proof};
use super::super::marshal::{BlobReader, BlobWriter, Tpm2bError};
use super::super::runtime::Tpm2Runtime;
use super::super::ticket::{
    CONTEXT_INTEGRITY_HASH_ALG, GENERATED_VALUE_SIZE, HashCheckTicket, compute_hash_check,
    ticket_is_safe,
};
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;
use super::registry::TPM_RH_NULL;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const TPM_RC_3: TpmResult = 0x300;
const RC_HASH_DATA: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_HASH_HASH_ALG: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_HASH_HIERARCHY: TpmResult = TPM_RC_P + TPM_RC_3;

const MAX_DIGEST_BUFFER: usize = 1024;

struct HashIn<'a> {
    data: &'a [u8],
    hash_alg: u16,
    hierarchy: u32,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let input = {
        // TODO: Support runtimes without decoded state after the NVChip fallback
        // is implemented.
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    self_test_algorithm(runtime, input.hash_alg)?;
    let mut hasher = Hasher::new(input.hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(input.data);
    let out_hash = hasher.finalize();

    let validation = if ticket_required(&input) {
        self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        let proof = hierarchy_proof(&state.persistent, input.hierarchy).ok_or(TPM_RC_FAILURE)?;
        compute_hash_check(input.hierarchy, proof, input.hash_alg, &out_hash)
            .ok_or(TPM_RC_FAILURE)?
    } else {
        HashCheckTicket::empty()
    };

    let mut writer = BlobWriter::with_capacity(2 + out_hash.len() + 8 + validation.digest.len());
    writer.write_tpm2b(&out_hash).map_err(|_| TPM_RC_FAILURE)?;
    validation
        .marshal(&mut writer)
        .map_err(|_| TPM_RC_FAILURE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

fn ticket_required(input: &HashIn<'_>) -> bool {
    input.hierarchy != TPM_RH_NULL
        && (input.data.len() < GENERATED_VALUE_SIZE || ticket_is_safe(input.data))
}

fn self_test_algorithm(runtime: &mut Tpm2Runtime, algorithm: u16) -> Result<(), TpmResult> {
    match runtime.self_test.run_pending_algorithm(algorithm) {
        Ok(()) => Ok(()),
        Err(code) => {
            runtime.failure_mode = true;
            Err(code)
        }
    }
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<HashIn<'a>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let data = reader
        .read_tpm2b(MAX_DIGEST_BUFFER)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_HASH_DATA,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_HASH_DATA,
        })?;

    let hash_alg = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_HASH_HASH_ALG)?;
    let enabled = COMPILED_HASHES.iter().any(|&(alg, _)| alg == hash_alg)
        && hash_profile_name(hash_alg)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
    if !enabled {
        return Err(TPM_RC_HASH + RC_HASH_HASH_ALG);
    }

    let hierarchy = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_HASH_HIERARCHY)?;
    if !matches!(
        hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE + RC_HASH_HIERARCHY);
    }

    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(HashIn {
        data,
        hash_alg,
        hierarchy,
    })
}

#[cfg(test)]
mod tests {
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::ffi_types::TpmResult>,
    ) -> Result<Vec<u8>, crate::ffi_types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            locality,
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
        )
    }
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::TPM_CC_HASH;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::hash_vectors::{HashTicketCase, hash_ticket_record};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::persistent::OwnedSecret;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;
    use crate::library::tpm2::self_test::{PrimitiveTest, SelfTestFailure};
    use std::cell::RefCell;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_AES: u16 = 0x0006;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;
    const TPM_ALG_NULL: u16 = 0x0010;

    const RC_SIZE: u32 = 0x095;

    const RC_DATA_INSUFFICIENT: u32 = 0x1da;
    const RC_DATA_SIZE: u32 = 0x1d5;
    const RC_HASH_ALG_INSUFFICIENT: u32 = 0x2da;
    const RC_HASH_ALG_HASH: u32 = 0x2c3;
    const RC_HIERARCHY_INSUFFICIENT: u32 = 0x3da;
    const RC_HIERARCHY_VALUE: u32 = 0x3c4;

    const RC_SESSION1_HANDLE: u32 = 0x98b;
    const RC_INSUFFICIENT: u32 = 0x09a;

    const MINIMAL_ALGORITHMS: &str = "rsa,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,null,oaep,\
ecdsa,ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,symcipher,cfb,ecc-nist-p256,ecc-nist-p384";

    fn hex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2));
        (0..cleaned.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x63;
        }
        Ok(())
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

    #[track_caller]
    fn started_runtime(profile: Option<&[u8]>) -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime(profile);
        let startup = hex("80010000000c0000014400 00");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn install_oracle_proofs(runtime: &mut Tpm2Runtime) {
        let record = hash_ticket_record();
        let state = runtime.state.as_mut().expect("state present");
        state.persistent.ph_proof = OwnedSecret::copy_of(&record.ph_proof);
        state.persistent.sh_proof = OwnedSecret::copy_of(&record.sh_proof);
        state.persistent.eh_proof = OwnedSecret::copy_of(&record.eh_proof);
    }

    #[track_caller]
    fn oracle_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = started_runtime(None);
        install_oracle_proofs(&mut runtime);
        runtime
    }

    thread_local! {
        static SELF_TESTS_RUN: RefCell<Vec<PrimitiveTest>> = const { RefCell::new(Vec::new()) };
    }

    fn recording_runner(test: PrimitiveTest) -> bool {
        SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
        true
    }

    fn recording_runner_failing_sha256(test: PrimitiveTest) -> bool {
        SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
        test != PrimitiveTest::Sha256
    }

    fn recording_runner_failing_sha512(test: PrimitiveTest) -> bool {
        SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
        test != PrimitiveTest::Sha512
    }

    fn never_runs(test: PrimitiveTest) -> bool {
        panic!("a rejected command must run no self-test, got {test:?}");
    }

    fn take_self_tests_run() -> Vec<PrimitiveTest> {
        SELF_TESTS_RUN.with(|run| core::mem::take(&mut *run.borrow_mut()))
    }

    #[track_caller]
    fn recording_runtime(runner: fn(PrimitiveTest) -> bool) -> Box<Tpm2Runtime> {
        let mut runtime = oracle_runtime();
        runtime.self_test.set_runner(runner);
        take_self_tests_run();
        runtime
    }

    fn command_with(parameters: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_HASH.to_be_bytes());
        out.extend_from_slice(parameters);
        out
    }

    fn parameters_of(data: &[u8], hash_alg: u16, hierarchy: u32) -> Vec<u8> {
        let mut parameters = (data.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(data);
        parameters.extend_from_slice(&hash_alg.to_be_bytes());
        parameters.extend_from_slice(&hierarchy.to_be_bytes());
        parameters
    }

    fn hash_command(data: &[u8], hash_alg: u16, hierarchy: u32) -> Vec<u8> {
        command_with(&parameters_of(data, hash_alg, hierarchy))
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    fn success_response(parameters: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + parameters.len() as u32).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(parameters);
        out
    }

    #[track_caller]
    fn response_parameters(response: &[u8]) -> Vec<u8> {
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
        response[10..].to_vec()
    }

    #[track_caller]
    fn dispatch_case(runtime: &mut Tpm2Runtime, case: &HashTicketCase) -> Vec<u8> {
        let command = hash_command(&case.data, case.hash_alg, case.hierarchy);
        response_parameters(&dispatch_bytes(runtime, &command))
    }

    struct Snapshot {
        startup_received: bool,
        nv_update_pending: bool,
        ph_proof: Vec<u8>,
        sh_proof: Vec<u8>,
        eh_proof: Vec<u8>,
        drbg_seed: Vec<u8>,
        drbg_counter: u64,
        live_drbg_seed: Vec<u8>,
        live_drbg_counter: u64,
        orderly_state: u16,
        pcr_counter: Option<u32>,
        pcrs: Vec<[Option<Vec<u8>>; 4]>,
        nv_memory: Box<[u8]>,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = runtime.state.as_ref().expect("state present");
        Snapshot {
            startup_received: runtime.startup_received,
            nv_update_pending: runtime.nv_update_pending,
            ph_proof: state.persistent.ph_proof.expose().to_vec(),
            sh_proof: state.persistent.sh_proof.expose().to_vec(),
            eh_proof: state.persistent.eh_proof.expose().to_vec(),
            drbg_seed: state.orderly.drbg_state.seed.expose().to_vec(),
            drbg_counter: state.orderly.drbg_state.reseed_counter,
            live_drbg_seed: runtime.live.orderly.drbg_state.seed.expose().to_vec(),
            live_drbg_counter: runtime.live.orderly.drbg_state.reseed_counter,
            orderly_state: state.persistent.orderly_state,
            pcr_counter: runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            pcrs: runtime
                .live
                .pcrs
                .iter()
                .map(|pcr| pcr.banks.clone())
                .collect(),
            nv_memory: runtime.nv_memory.clone(),
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        assert_persistent_and_nv_unchanged(runtime, before);
        assert!(!runtime.failure_mode);
    }

    #[track_caller]
    fn assert_persistent_and_nv_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let state = runtime.state.as_ref().expect("state present");
        assert_eq!(runtime.startup_received, before.startup_received);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert!(
            state.persistent.ph_proof.expose() == &before.ph_proof[..],
            "phProof changed"
        );
        assert!(
            state.persistent.sh_proof.expose() == &before.sh_proof[..],
            "shProof changed"
        );
        assert!(
            state.persistent.eh_proof.expose() == &before.eh_proof[..],
            "ehProof changed"
        );
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
        assert_eq!(state.persistent.orderly_state, before.orderly_state);
        assert_eq!(
            runtime
                .live
                .state_reset
                .as_ref()
                .map(|reset| reset.pcr_counter),
            before.pcr_counter
        );
        let pcrs: Vec<[Option<Vec<u8>>; 4]> = runtime
            .live
            .pcrs
            .iter()
            .map(|pcr| pcr.banks.clone())
            .collect();
        assert_eq!(pcrs, before.pcrs);
        assert_eq!(runtime.nv_memory, before.nv_memory);
    }

    #[test]
    fn hash_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime(None);
        let before = snapshot(&runtime);
        for parameters in [
            &[][..],
            &parameters_of(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER)[..],
            &[0xff, 0xff, 0x00][..],
        ] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &command_with(parameters)),
                error_response(TPM_RC_INITIALIZE),
                "the lifecycle check precedes parameter parsing, {parameters:02x?}"
            );
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn every_oracle_case_reproduces_the_vendored_response_parameters() {
        let record = hash_ticket_record();
        let mut runtime = oracle_runtime();
        for case in &record.cases {
            assert_eq!(
                dispatch_case(&mut runtime, case),
                case.parameters,
                "{}",
                case.label()
            );
        }
    }

    #[test]
    fn every_digest_has_the_length_of_its_algorithm() {
        let record = hash_ticket_record();
        let mut runtime = oracle_runtime();
        for case in &record.cases {
            let expected = match case.hash_alg {
                TPM_ALG_SHA1 => 20usize,
                TPM_ALG_SHA256 => 32,
                TPM_ALG_SHA384 => 48,
                TPM_ALG_SHA512 => 64,
                other => panic!("unexpected algorithm {other:#06x}"),
            };
            let parameters = dispatch_case(&mut runtime, case);
            assert_eq!(
                u16::from_be_bytes(parameters[..2].try_into().unwrap()),
                expected as u16,
                "{}",
                case.label()
            );
        }
    }

    #[test]
    fn the_null_hierarchy_answers_an_empty_ticket() {
        let record = hash_ticket_record();
        let mut runtime = oracle_runtime();
        for case in record
            .cases
            .iter()
            .filter(|case| case.hierarchy == TPM_RH_NULL)
        {
            let parameters = dispatch_case(&mut runtime, case);
            let digest_size = 2 + case.out_hash().len();
            assert_eq!(
                &parameters[digest_size..],
                hex("8024 40000007 0000"),
                "{}",
                case.label()
            );
        }
    }

    #[test]
    fn an_exact_generated_value_prefix_suppresses_the_ticket() {
        let mut runtime = oracle_runtime();
        for data in [
            hex("ff544347"),
            hex("ff544347 00"),
            hex("ff544347 0011223344556677"),
            hex("ff544347 ff544347"),
        ] {
            for hierarchy in [TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT] {
                let parameters = response_parameters(&dispatch_bytes(
                    &mut runtime,
                    &hash_command(&data, TPM_ALG_SHA256, hierarchy),
                ));
                assert_eq!(
                    &parameters[34..],
                    hex("8024 40000007 0000"),
                    "data {data:02x?}, hierarchy {hierarchy:#010x}"
                );
            }
        }
    }

    #[test]
    fn shorter_generated_value_prefixes_still_produce_a_real_ticket() {
        let mut runtime = oracle_runtime();
        for data in [hex("ff"), hex("ff54"), hex("ff5443"), hex("ff544348")] {
            for hierarchy in [TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT] {
                let parameters = response_parameters(&dispatch_bytes(
                    &mut runtime,
                    &hash_command(&data, TPM_ALG_SHA256, hierarchy),
                ));
                let ticket = &parameters[34..];
                assert_eq!(&ticket[..2], &[0x80, 0x24]);
                assert_eq!(
                    u32::from_be_bytes(ticket[2..6].try_into().unwrap()),
                    hierarchy,
                    "data {data:02x?}"
                );
                assert_eq!(
                    u16::from_be_bytes(ticket[6..8].try_into().unwrap()),
                    64,
                    "data {data:02x?}"
                );
            }
        }
    }

    #[test]
    fn each_hierarchy_keys_the_ticket_with_its_own_proof() {
        let record = hash_ticket_record();
        let mut runtime = oracle_runtime();
        let mut tickets = Vec::new();
        for hierarchy in [TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT] {
            let parameters = response_parameters(&dispatch_bytes(
                &mut runtime,
                &hash_command(b"abc", TPM_ALG_SHA256, hierarchy),
            ));
            let case = record
                .cases
                .iter()
                .find(|case| {
                    case.data == b"abc"
                        && case.hash_alg == TPM_ALG_SHA256
                        && case.hierarchy == hierarchy
                })
                .expect("an oracle case");
            assert_eq!(parameters, case.parameters, "{}", case.label());
            tickets.push(parameters[34..].to_vec());
        }
        assert_ne!(tickets[0], tickets[1]);
        assert_ne!(tickets[0], tickets[2]);
        assert_ne!(tickets[1], tickets[2]);
    }

    #[test]
    fn a_changed_proof_changes_the_ticket() {
        let record = hash_ticket_record();
        let case = record
            .cases
            .iter()
            .find(|case| {
                case.data == b"abc"
                    && case.hash_alg == TPM_ALG_SHA256
                    && case.hierarchy == TPM_RH_OWNER
            })
            .expect("an oracle case");

        let mut runtime = oracle_runtime();
        assert_eq!(dispatch_case(&mut runtime, case), case.parameters);

        let mut flipped = record.sh_proof.clone();
        flipped[0] ^= 0x01;
        runtime
            .state
            .as_mut()
            .expect("state present")
            .persistent
            .sh_proof = OwnedSecret::copy_of(&flipped);
        let parameters = dispatch_case(&mut runtime, case);
        assert_eq!(&parameters[..34], &case.parameters[..34], "the digest");
        assert_ne!(&parameters[34..], &case.parameters[34..], "the ticket");
    }

    #[test]
    fn changing_the_hash_algorithm_changes_both_the_digest_and_the_ticket() {
        let record = hash_ticket_record();
        let sha384 = record
            .cases
            .iter()
            .find(|case| {
                case.data == b"abc"
                    && case.hash_alg == TPM_ALG_SHA384
                    && case.hierarchy == TPM_RH_OWNER
            })
            .expect("an oracle case");
        let sha512 = record
            .cases
            .iter()
            .find(|case| {
                case.data == b"abc"
                    && case.hash_alg == TPM_ALG_SHA512
                    && case.hierarchy == TPM_RH_OWNER
            })
            .expect("an oracle case");
        assert_ne!(sha384.out_hash(), sha512.out_hash());
        assert_ne!(sha384.ticket_digest(), sha512.ticket_digest());

        let mut runtime = oracle_runtime();
        assert_eq!(dispatch_case(&mut runtime, sha384), sha384.parameters);
        assert_eq!(dispatch_case(&mut runtime, sha512), sha512.parameters);
    }

    #[test]
    fn changing_the_data_changes_the_digest_and_the_ticket() {
        let mut runtime = oracle_runtime();
        let first = response_parameters(&dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER),
        ));
        let second = response_parameters(&dispatch_bytes(
            &mut runtime,
            &hash_command(b"abd", TPM_ALG_SHA256, TPM_RH_OWNER),
        ));
        assert_ne!(&first[..34], &second[..34]);
        assert_ne!(&first[34..], &second[34..]);
    }

    #[test]
    fn every_input_size_up_to_the_maximum_is_accepted() {
        let mut runtime = oracle_runtime();
        for length in 0..=MAX_DIGEST_BUFFER {
            let data: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let parameters = response_parameters(&dispatch_bytes(
                &mut runtime,
                &hash_command(&data, TPM_ALG_SHA256, TPM_RH_OWNER),
            ));
            assert_eq!(parameters.len(), 2 + 32 + 8 + 64, "length {length}");
            assert!(!runtime.failure_mode, "length {length}");
        }
    }

    #[test]
    fn an_input_above_the_maximum_returns_the_indexed_size_error() {
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for length in [MAX_DIGEST_BUFFER + 1, 1030, 2048, 4000] {
            let data = vec![0xa5u8; length];
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &hash_command(&data, TPM_ALG_SHA256, TPM_RH_OWNER)
                ),
                error_response(RC_DATA_SIZE),
                "length {length}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn the_declared_size_is_checked_before_the_payload_length() {
        let mut runtime = oracle_runtime();
        assert_eq!(
            dispatch_bytes(&mut runtime, &command_with(&hex("ffff"))),
            error_response(RC_DATA_SIZE)
        );
    }

    #[test]
    fn every_compiled_algorithm_is_accepted_under_the_null_profile() {
        let record = hash_ticket_record();
        let mut runtime = oracle_runtime();
        for hash_alg in [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512] {
            let case = record
                .cases
                .iter()
                .find(|case| {
                    case.data == b"abc"
                        && case.hash_alg == hash_alg
                        && case.hierarchy == TPM_RH_PLATFORM
                })
                .expect("an oracle case");
            assert_eq!(dispatch_case(&mut runtime, case), case.parameters);
        }
    }

    #[test]
    fn a_profile_disabled_algorithm_returns_the_indexed_hash_error() {
        let profile = format!(r#"{{"Name":"custom","Algorithms":"{MINIMAL_ALGORITHMS}"}}"#);
        let mut runtime = started_runtime(Some(profile.as_bytes()));
        install_oracle_proofs(&mut runtime);
        let before = snapshot(&runtime);
        for hash_alg in [TPM_ALG_SHA1, TPM_ALG_SHA512] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &hash_command(b"abc", hash_alg, TPM_RH_OWNER)),
                error_response(RC_HASH_ALG_HASH),
                "alg {hash_alg:#06x}"
            );
            assert_unchanged(&runtime, &before);
        }
        for hash_alg in [TPM_ALG_SHA256, TPM_ALG_SHA384] {
            let response =
                dispatch_bytes(&mut runtime, &hash_command(b"abc", hash_alg, TPM_RH_OWNER));
            assert_eq!(&response[6..10], &[0, 0, 0, 0], "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn the_null_and_unknown_algorithms_return_the_indexed_hash_error() {
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for hash_alg in [
            TPM_ALG_NULL,
            0x0000,
            0x0001,
            0x0005,
            0x0006,
            0x000a,
            0x000e,
            0x0012,
            0x0027,
            0xffff,
        ] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &hash_command(b"abc", hash_alg, TPM_RH_OWNER)),
                error_response(RC_HASH_ALG_HASH),
                "alg {hash_alg:#06x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn every_accepted_hierarchy_is_dispatched() {
        let mut runtime = oracle_runtime();
        for hierarchy in [
            TPM_RH_OWNER,
            TPM_RH_PLATFORM,
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
        ] {
            let response = dispatch_bytes(
                &mut runtime,
                &hash_command(b"abc", TPM_ALG_SHA256, hierarchy),
            );
            assert_eq!(
                &response[6..10],
                &[0, 0, 0, 0],
                "hierarchy {hierarchy:#010x}"
            );
        }
    }

    #[test]
    fn an_invalid_hierarchy_returns_the_indexed_value_error() {
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for hierarchy in [
            0x0000_0000u32,
            0x0000_0017,
            0x4000_0000,
            0x4000_0002,
            0x4000_0008,
            0x4000_0009,
            0x4000_000a,
            0x4000_000d,
            0x8000_0000,
            0x8100_0000,
            u32::MAX,
        ] {
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &hash_command(b"abc", TPM_ALG_SHA256, hierarchy)
                ),
                error_response(RC_HIERARCHY_VALUE),
                "hierarchy {hierarchy:#010x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_truncated_parameter_area_returns_the_indexed_error_of_the_missing_field() {
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        let cases: [(&[u8], u32); 9] = [
            (&[], RC_DATA_INSUFFICIENT),
            (&[0x00], RC_DATA_INSUFFICIENT),
            (&[0x00, 0x03], RC_DATA_INSUFFICIENT),
            (&[0x00, 0x03, 0x61], RC_DATA_INSUFFICIENT),
            (&[0x00, 0x03, 0x61, 0x62], RC_DATA_INSUFFICIENT),
            (&[0x00, 0x00], RC_HASH_ALG_INSUFFICIENT),
            (&[0x00, 0x00, 0x00], RC_HASH_ALG_INSUFFICIENT),
            (&[0x00, 0x00, 0x00, 0x0b], RC_HIERARCHY_INSUFFICIENT),
            (
                &[0x00, 0x00, 0x00, 0x0b, 0x40, 0x00, 0x00],
                RC_HIERARCHY_INSUFFICIENT,
            ),
        ];
        for (parameters, expected) in cases {
            assert_eq!(
                dispatch_bytes(&mut runtime, &command_with(parameters)),
                error_response(expected),
                "parameters {parameters:02x?}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameter_bytes_return_size() {
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for tail in [&[0x00u8][..], &[0xff, 0xff][..], &[0x00; 8][..]] {
            let mut parameters = parameters_of(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER);
            parameters.extend_from_slice(tail);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command_with(&parameters)),
                error_response(RC_SIZE),
                "tail {tail:02x?}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn the_algorithm_is_validated_before_the_hierarchy() {
        let mut runtime = oracle_runtime();
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &hash_command(b"abc", TPM_ALG_NULL, 0x0000_0001)
            ),
            error_response(RC_HASH_ALG_HASH)
        );
    }

    #[test]
    fn a_successful_hash_leaves_every_runtime_and_persistent_field_alone() {
        let record = hash_ticket_record();
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for case in &record.cases {
            let command = hash_command(&case.data, case.hash_alg, case.hierarchy);
            let input = CommandInput::new(command.len() as u32, command);
            let response = process(&mut runtime, 0, &input, |_| {
                panic!("TPM2_Hash must not schedule an NV commit")
            })
            .expect("the command processes");
            assert_eq!(
                response,
                success_response(&case.parameters),
                "{}",
                case.label()
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_failed_hash_leaves_every_runtime_and_persistent_field_alone() {
        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for parameters in [
            parameters_of(b"abc", TPM_ALG_NULL, TPM_RH_OWNER),
            parameters_of(b"abc", TPM_ALG_SHA256, 0x4000_000a),
            parameters_of(&[0x11; 1025], TPM_ALG_SHA256, TPM_RH_OWNER),
            vec![0x00],
        ] {
            let command = command_with(&parameters);
            let input = CommandInput::new(command.len() as u32, command);
            let response = process(&mut runtime, 0, &input, |_| {
                panic!("a failed TPM2_Hash must not schedule an NV commit")
            })
            .expect("the command processes");
            assert_eq!(
                response.len(),
                10,
                "an error response carries no parameters"
            );
            assert_ne!(&response[6..10], &[0, 0, 0, 0]);
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn session_tagged_requests_are_answered_from_the_session_area() {
        let pw_auth = {
            let mut out = vec![0x80, 0x02];
            let parameters = parameters_of(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER);
            let auth = hex("40000009 0000 00 0000");
            let mut body = (auth.len() as u32).to_be_bytes().to_vec();
            body.extend_from_slice(&auth);
            body.extend_from_slice(&parameters);
            out.extend_from_slice(&(10 + body.len() as u32).to_be_bytes());
            out.extend_from_slice(&TPM_CC_HASH.to_be_bytes());
            out.extend_from_slice(&body);
            out
        };
        let no_authsize = hex("8002000000 0c 0000017d 0000");

        let mut runtime = oracle_runtime();
        let before = snapshot(&runtime);
        for (label, command, expected) in [
            ("pw_auth", pw_auth, RC_SESSION1_HANDLE),
            ("no_authsize", no_authsize, RC_INSUFFICIENT),
        ] {
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn malformed_parameter_areas_never_panic() {
        let filler = [0x00u8, 0xff, 0x80, 0x7f, 0x01, 0x40];
        let mut runtime = oracle_runtime();
        for length in 0..=10usize {
            for &byte in &filler {
                let response = dispatch_bytes(&mut runtime, &command_with(&vec![byte; length]));
                assert_eq!(&response[..2], &[0x80, 0x01], "length {length}");
                assert_eq!(
                    u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize,
                    response.len(),
                    "length {length}"
                );
                assert!(!runtime.failure_mode, "length {length}, byte {byte:#04x}");
            }
        }
    }

    #[test]
    fn the_first_hash_runs_the_requested_algorithms_pending_self_test() {
        let mut runtime = recording_runtime(recording_runner);
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA256),
            "the requested algorithm starts out untested"
        );

        let response = dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA256, TPM_RH_NULL),
        );
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha256]);
        assert!(
            !runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA256)
        );
        assert!(runtime.self_test.failure.is_none());
    }

    #[test]
    fn a_later_hash_with_the_same_algorithm_does_not_rerun_the_self_test() {
        let mut runtime = recording_runtime(recording_runner);
        for algorithm in [TPM_ALG_SHA1, TPM_ALG_SHA384] {
            let command = hash_command(b"abc", algorithm, TPM_RH_NULL);
            let response = dispatch_bytes(&mut runtime, &command);
            assert_eq!(&response[6..10], &[0, 0, 0, 0], "alg {algorithm:#06x}");
            assert_eq!(take_self_tests_run().len(), 1, "alg {algorithm:#06x}");

            for repeat in 0..3 {
                let response = dispatch_bytes(&mut runtime, &command);
                assert_eq!(&response[6..10], &[0, 0, 0, 0]);
                assert_eq!(
                    take_self_tests_run(),
                    [] as [PrimitiveTest; 0],
                    "alg {algorithm:#06x}, repeat {repeat}"
                );
            }
        }
    }

    #[test]
    fn hashing_with_one_algorithm_leaves_the_other_pending_tests_alone() {
        let mut runtime = recording_runtime(recording_runner);
        let before = runtime.self_test.pending_algorithms();

        dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA384, TPM_RH_NULL),
        );

        assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha384]);
        let after = runtime.self_test.pending_algorithms();
        let expected: Vec<u16> = before
            .into_iter()
            .filter(|&algorithm| algorithm != TPM_ALG_SHA384)
            .collect();
        assert_eq!(after, expected);
    }

    #[test]
    fn a_failed_requested_algorithm_self_test_stops_the_tpm_without_answering_a_digest() {
        let mut runtime = recording_runtime(recording_runner_failing_sha256);
        let before = snapshot(&runtime);

        let response = dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER),
        );

        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert_eq!(response.len(), 10, "no digest and no ticket");
        assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha256]);
        assert!(runtime.failure_mode, "a failed self-test stops the TPM");
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha256
            })
        );
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA256),
            "a failed test stays pending"
        );
        assert_persistent_and_nv_unchanged(&runtime, &before);
    }

    #[test]
    fn the_next_command_after_a_self_test_failure_takes_the_failure_mode_path() {
        let mut runtime = recording_runtime(recording_runner_failing_sha256);
        let command = hash_command(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failed self-test must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert!(runtime.failure_mode);
        take_self_tests_run();

        let follow_up = hash_command(b"abc", TPM_ALG_SHA384, TPM_RH_NULL);
        let input = CommandInput::new(follow_up.len() as u32, follow_up);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("failure mode must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert_eq!(
            take_self_tests_run(),
            [] as [PrimitiveTest; 0],
            "the failure-mode boundary answers before the handler runs"
        );
    }

    #[test]
    fn rejected_parameters_run_no_self_test_and_leave_the_pending_set_alone() {
        let mut runtime = recording_runtime(never_runs);
        let pending = runtime.self_test.pending_algorithms();

        let mut rejected: Vec<Vec<u8>> = vec![
            parameters_of(b"abc", TPM_ALG_NULL, TPM_RH_OWNER),
            parameters_of(b"abc", 0xffff, TPM_RH_OWNER),
            parameters_of(b"abc", TPM_ALG_SHA256, 0x4000_000a),
            parameters_of(&[0x11; 1025], TPM_ALG_SHA256, TPM_RH_OWNER),
            vec![],
            vec![0x00],
            vec![0x00, 0x00],
            vec![0x00, 0x00, 0x00, 0x0b],
        ];
        let mut trailing = parameters_of(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER);
        trailing.push(0x00);
        rejected.push(trailing);
        for byte in [0x00u8, 0xff, 0x80, 0x40] {
            for length in 0..=10usize {
                rejected.push(vec![byte; length]);
            }
        }

        for parameters in rejected {
            let response = dispatch_bytes(&mut runtime, &command_with(&parameters));
            let code = u32::from_be_bytes(response[6..10].try_into().unwrap());
            if code == 0 {
                continue;
            }
            assert_eq!(
                runtime.self_test.pending_algorithms(),
                pending,
                "parameters {parameters:02x?}"
            );
            assert!(runtime.self_test.failure.is_none());
            assert!(!runtime.failure_mode);
        }
    }

    #[test]
    fn an_empty_ticket_path_runs_only_the_requested_hash_self_test() {
        for (label, data, hierarchy) in [
            ("null hierarchy", &b"abc"[..], TPM_RH_NULL),
            (
                "generated value",
                &[0xff, 0x54, 0x43, 0x47][..],
                TPM_RH_OWNER,
            ),
        ] {
            let mut runtime = recording_runtime(recording_runner);
            let response =
                dispatch_bytes(&mut runtime, &hash_command(data, TPM_ALG_SHA256, hierarchy));
            assert_eq!(&response[6..10], &[0, 0, 0, 0], "{label}");
            assert_eq!(&response[44..], hex("8024 40000007 0000"), "{label}");
            assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha256], "{label}");
            assert!(
                runtime
                    .self_test
                    .pending_algorithms()
                    .contains(&TPM_ALG_SHA512),
                "{label}: the context-integrity test is untouched"
            );
        }
    }

    #[test]
    fn a_real_ticket_path_also_runs_the_context_integrity_self_test() {
        let mut runtime = recording_runtime(recording_runner);
        let response = dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER),
        );
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256, PrimitiveTest::Sha512],
            "the requested algorithm is tested before the ticket algorithm"
        );

        let response = dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA1, TPM_RH_PLATFORM),
        );
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha1],
            "the context-integrity test is not repeated"
        );
    }

    #[test]
    fn a_sha512_request_with_a_ticket_runs_its_self_test_once() {
        let mut runtime = recording_runtime(recording_runner);
        let response = dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA512, TPM_RH_ENDORSEMENT),
        );
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha512]);
    }

    #[test]
    fn a_failed_context_integrity_self_test_stops_the_tpm() {
        let mut runtime = recording_runtime(recording_runner_failing_sha512);
        let before = snapshot(&runtime);

        let response = dispatch_bytes(
            &mut runtime,
            &hash_command(b"abc", TPM_ALG_SHA256, TPM_RH_OWNER),
        );

        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert_eq!(response.len(), 10, "no digest and no ticket");
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256, PrimitiveTest::Sha512]
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha512
            })
        );
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA512)
        );
        assert_persistent_and_nv_unchanged(&runtime, &before);
    }

    #[test]
    fn a_profile_without_the_context_integrity_algorithm_still_tickets() {
        let record = hash_ticket_record();
        let case = record
            .cases
            .iter()
            .find(|case| {
                case.data == b"abc"
                    && case.hash_alg == TPM_ALG_SHA256
                    && case.hierarchy == TPM_RH_OWNER
            })
            .expect("an oracle case");

        let profile = format!(r#"{{"Name":"custom","Algorithms":"{MINIMAL_ALGORITHMS}"}}"#);
        let mut runtime = started_runtime(Some(profile.as_bytes()));
        install_oracle_proofs(&mut runtime);
        runtime.self_test.set_runner(recording_runner);
        take_self_tests_run();
        assert!(
            !runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA512),
            "the profile excludes the context-integrity algorithm"
        );

        assert_eq!(dispatch_case(&mut runtime, case), case.parameters);
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256],
            "an algorithm outside the profile is neither tested nor rejected"
        );
        assert!(!runtime.failure_mode);
        assert!(runtime.self_test.failure.is_none());
    }

    #[test]
    fn the_oracle_responses_are_unchanged_by_the_lazy_self_tests() {
        let record = hash_ticket_record();
        let mut runtime = recording_runtime(recording_runner);
        for case in &record.cases {
            assert_eq!(
                dispatch_case(&mut runtime, case),
                case.parameters,
                "{}",
                case.label()
            );
        }
        let executed = take_self_tests_run();
        assert_eq!(executed.len(), 4, "{executed:?}");
        for test in [
            PrimitiveTest::Sha1,
            PrimitiveTest::Sha256,
            PrimitiveTest::Sha384,
            PrimitiveTest::Sha512,
        ] {
            assert_eq!(
                executed.iter().filter(|&&run| run == test).count(),
                1,
                "{test:?} ran exactly once across the whole fixture"
            );
        }
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            [TPM_ALG_AES],
            "only the primitive TPM2_Hash never uses stays pending"
        );
        assert!(!runtime.failure_mode);
    }
}
