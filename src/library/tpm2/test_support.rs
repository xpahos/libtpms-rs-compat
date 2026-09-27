use crate::library::CommandInput;
use crate::library::cancel::CancellationToken;
use crate::library::tpm2::clock::RecordingClock;
use crate::library::tpm2::crypto::{EntropySource, SeededRand};
use crate::library::tpm2::manufacture::manufacture_state;
use crate::library::tpm2::object_create::PRIMARY_OBJECT_CREATION;
use crate::library::tpm2::profile::{DEFAULT_ALGORITHMS_PROFILE, validate_user_profile};
use crate::library::tpm2::public::StateFormatLimit;
use crate::library::tpm2::runtime::{Tpm2Runtime, commit_manufactured_state};
use crate::library::tpm2::template::AlgorithmPolicy;
use crate::library::tpm2::{PlatformInputs, process as process_command};
use crate::types::TpmResult;

pub(in crate::library) fn counter_entropy<const MASK: u8>(
    buffer: &mut [u8],
) -> Result<(), TpmResult> {
    let len = buffer.len() as u8;
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(len) ^ MASK;
    }
    Ok(())
}

pub(in crate::library::tpm2) fn manufactured_runtime_with(
    profile: Option<&[u8]>,
    entropy: EntropySource,
) -> Tpm2Runtime {
    let profile = validate_user_profile(profile).expect("the profile validates");
    let state = manufacture_state(profile, entropy).expect("manufactures");
    let mut runtime = commit_manufactured_state(state).expect("commits");
    runtime.entropy = entropy;
    runtime
}

pub(in crate::library::tpm2) fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(in crate::library::tpm2) fn tpm2b(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    push_tpm2b(&mut out, bytes);
    out
}

pub(in crate::library::tpm2) fn envelope_with_payload(payload: &[u8]) -> Vec<u8> {
    let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
    blob.extend_from_slice(payload);
    blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
    blob
}

pub(in crate::library::tpm2) fn envelope_v4_with_profile(
    profile: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut blob = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
    blob.extend_from_slice(&u16::try_from(profile.len() + 1).unwrap().to_be_bytes());
    blob.extend_from_slice(profile);
    blob.push(0);
    blob.extend_from_slice(payload);
    blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
    blob
}

pub(in crate::library::tpm2) fn default_algorithm_policy() -> AlgorithmPolicy<'static> {
    AlgorithmPolicy {
        profile_algorithms: DEFAULT_ALGORITHMS_PROFILE,
        state_format: StateFormatLimit::CURRENT,
    }
}

pub(in crate::library::tpm2) fn primary_creation_rand(label: &[u8]) -> SeededRand {
    SeededRand::instantiate(&[0x77; 64], PRIMARY_OBJECT_CREATION, label, &[], 1, false)
        .expect("a non-empty derivation input")
}

#[track_caller]
pub(in crate::library::tpm2) fn hex(text: &str) -> Vec<u8> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        digits.len().is_multiple_of(2),
        "an even number of hex digits"
    );
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).expect("hex digits"))
        .collect()
}

pub(in crate::library::tpm2) fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(in crate::library::tpm2) fn process(
    runtime: &mut Tpm2Runtime,
    locality: u8,
    command: &CommandInput,
    commit_nv: impl FnOnce(&Tpm2Runtime) -> Result<(), TpmResult>,
) -> Result<Vec<u8>, TpmResult> {
    process_command(
        runtime,
        PlatformInputs::at_locality(locality),
        command,
        &RecordingClock::new(1_600_000_000_000, 5_000_000),
        commit_nv,
        CancellationToken::disabled(),
    )
}
