// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::dispatcher::dispatch;
use super::header::{parse_command, serialize_response};
use super::registry::{TPM_CC_GET_CAPABILITY, TPM_CC_SHUTDOWN, TPM_CC_STARTUP};
use crate::library::CommandInput;
use crate::library::cancel::CancellationToken;
use crate::library::tpm2::command::session::processing::TPM_RS_PW;
use crate::library::tpm2::crypto::Drbg;
use crate::library::tpm2::nv::build_nv_image;
use crate::library::tpm2::object::ATTR_OCCUPIED;
use crate::library::tpm2::parse_persistent_all_payload;
use crate::library::tpm2::persistent::{
    OwnedPersistentState, PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
};
use crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::state::COMMIT_ARRAY_SIZE;
use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

pub(in crate::library::tpm2::command) const TPM_ALG_SHA1: u16 = 0x0004;
pub(in crate::library::tpm2::command) const TPM_ALG_SHA256: u16 = 0x000b;

pub(in crate::library::tpm2::command) const RC_SUCCESS: u32 = 0x000;

pub(in crate::library::tpm2::command) use crate::library::tpm2::test_support::{
    counter_entropy, hex, manufactured_runtime_with, process, tpm2b,
};

pub(in crate::library::tpm2::command) fn manufactured_runtime() -> Tpm2Runtime {
    manufactured_runtime_with(None, counter_entropy::<0x55>)
}

#[track_caller]
pub(in crate::library::tpm2::command) fn start(runtime: &mut Tpm2Runtime) {
    let startup = framed(0x0000_0144, &[0x00, 0x00], false);
    assert_eq!(
        dispatch_bytes(runtime, &startup),
        error_response(RC_SUCCESS),
        "the TPM starts up"
    );
    runtime.nv_update_pending = false;
}

#[track_caller]
pub(in crate::library::tpm2::command) fn started_runtime() -> Tpm2Runtime {
    let mut runtime = manufactured_runtime();
    start(&mut runtime);
    runtime
}

#[track_caller]
pub(in crate::library::tpm2::command) fn restored_snapshot(
    lookup: fn(&str) -> &'static [u8],
    snapshot: &str,
) -> Tpm2Runtime {
    let mut runtime = restore_permanent_blob_for_test(lookup(&format!("PERMALL_{snapshot}")))
        .expect("the oracle permanent state restores");
    attach_volatile_blob_for_test(&mut runtime, lookup(&format!("VOLATILE_{snapshot}")))
        .expect("the oracle volatile state attaches");
    assert!(
        runtime.startup_received,
        "the {snapshot} snapshot is past TPM2_Startup"
    );
    runtime
}

#[track_caller]
pub(in crate::library::tpm2::command) fn dispatch_bytes(
    runtime: &mut Tpm2Runtime,
    bytes: &[u8],
) -> Vec<u8> {
    dispatch_bytes_with(runtime, bytes, CancellationToken::disabled())
}

#[track_caller]
pub(in crate::library::tpm2::command) fn dispatch_bytes_with(
    runtime: &mut Tpm2Runtime,
    bytes: &[u8],
    cancellation: CancellationToken<'_>,
) -> Vec<u8> {
    let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
    let parsed = parse_command(&input).expect("the header parses");
    serialize_response(&dispatch(runtime, &parsed, cancellation)).expect("the response serializes")
}

pub(in crate::library::tpm2::command) fn framed(
    code: u32,
    payload: &[u8],
    sessions: bool,
) -> Vec<u8> {
    let tag: u16 = if sessions { 0x8002 } else { 0x8001 };
    let mut out = tag.to_be_bytes().to_vec();
    out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(in crate::library::tpm2::command) fn divergence(actual: &[u8], expected: &[u8]) -> Vec<usize> {
    assert_eq!(actual.len(), expected.len(), "blob length");
    (0..actual.len())
        .filter(|&index| actual[index] != expected[index])
        .collect()
}

pub(in crate::library::tpm2::command) fn get_capability(
    capability: u32,
    property: u32,
    count: u32,
) -> Vec<u8> {
    let mut payload = capability.to_be_bytes().to_vec();
    payload.extend_from_slice(&property.to_be_bytes());
    payload.extend_from_slice(&count.to_be_bytes());
    framed(TPM_CC_GET_CAPABILITY, &payload, false)
}

pub(in crate::library::tpm2::command) fn startup(kind: u16) -> Vec<u8> {
    framed(TPM_CC_STARTUP, &kind.to_be_bytes(), false)
}

pub(in crate::library::tpm2::command) fn shutdown(kind: u16) -> Vec<u8> {
    framed(TPM_CC_SHUTDOWN, &kind.to_be_bytes(), false)
}

pub(in crate::library::tpm2::command) fn auth_session(
    handle: u32,
    nonce: &[u8],
    attributes: u8,
    password: &[u8],
) -> Vec<u8> {
    let mut out = handle.to_be_bytes().to_vec();
    out.extend_from_slice(&(nonce.len() as u16).to_be_bytes());
    out.extend_from_slice(nonce);
    out.push(attributes);
    out.extend_from_slice(&(password.len() as u16).to_be_bytes());
    out.extend_from_slice(password);
    out
}

pub(in crate::library::tpm2::command) fn pw_session(password: &[u8]) -> Vec<u8> {
    auth_session(TPM_RS_PW, &[], 0x00, password)
}

pub(in crate::library::tpm2::command) fn command(
    code: u32,
    handles: &[u32],
    passwords: &[&[u8]],
    parameters: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    for handle in handles {
        payload.extend_from_slice(&handle.to_be_bytes());
    }
    if !passwords.is_empty() {
        let mut area = Vec::new();
        for password in passwords {
            area.extend_from_slice(&pw_session(password));
        }
        payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
        payload.extend_from_slice(&area);
    }
    payload.extend_from_slice(parameters);
    framed(code, &payload, !passwords.is_empty())
}

pub(in crate::library::tpm2::command) fn with_trailing(command: Vec<u8>) -> Vec<u8> {
    let mut out = command;
    out.push(0x00);
    let size = (out.len() as u32).to_be_bytes();
    out[2..6].copy_from_slice(&size);
    out
}

pub(in crate::library::tpm2::command) fn truncated(command: Vec<u8>, drop: usize) -> Vec<u8> {
    let mut out = command;
    out.truncate(out.len() - drop);
    let size = (out.len() as u32).to_be_bytes();
    out[2..6].copy_from_slice(&size);
    out
}

pub(in crate::library::tpm2::command) fn flipped(data: &[u8], index: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[index] ^= 0x01;
    out
}

pub(in crate::library::tpm2::command) fn response_code(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
}

pub(in crate::library::tpm2::command) fn response_parameters(response: &[u8]) -> Vec<u8> {
    if response[..2] != [0x80, 0x02] {
        return response[10..].to_vec();
    }
    let size = u32::from_be_bytes(response[10..14].try_into().expect("a parameter size"));
    response[14..14 + size as usize].to_vec()
}

#[track_caller]
pub(in crate::library::tpm2::command) fn create_primary(
    runtime: &mut Tpm2Runtime,
    hierarchy: u32,
    template: &[u8],
) -> (u32, Vec<u8>) {
    let mut parameters = 4u16.to_be_bytes().to_vec();
    parameters.extend_from_slice(&0u16.to_be_bytes());
    parameters.extend_from_slice(&0u16.to_be_bytes());
    parameters.extend_from_slice(&(template.len() as u16).to_be_bytes());
    parameters.extend_from_slice(template);
    parameters.extend_from_slice(&0u16.to_be_bytes());
    parameters.extend_from_slice(&0u32.to_be_bytes());
    let response = dispatch_bytes(
        runtime,
        &command(0x0000_0131, &[hierarchy], &[&[]], &parameters),
    );
    assert_eq!(
        response_code(&response),
        RC_SUCCESS,
        "the primary is created"
    );
    let handle = u32::from_be_bytes(response[10..14].try_into().expect("a response handle"));
    (handle, response)
}

#[derive(Debug, Eq, PartialEq)]
pub(in crate::library::tpm2::command) struct SigningSnapshot {
    pub(in crate::library::tpm2::command) drbg_magic: u32,
    pub(in crate::library::tpm2::command) reseed_counter: u64,
    pub(in crate::library::tpm2::command) seed: Vec<u8>,
    pub(in crate::library::tpm2::command) last_value: [u32; 4],
    pub(in crate::library::tpm2::command) commit_counter: u64,
    pub(in crate::library::tpm2::command) commit_array: [u8; COMMIT_ARRAY_SIZE],
}

pub(in crate::library::tpm2::command) fn signing_snapshot(
    runtime: &Tpm2Runtime,
) -> SigningSnapshot {
    let drbg = &runtime.live.orderly.drbg_state;
    let reset = runtime.live.state_reset.as_ref().expect("a reset section");
    SigningSnapshot {
        drbg_magic: drbg.drbg_magic,
        reseed_counter: drbg.reseed_counter,
        seed: drbg.seed.as_bytes().to_vec(),
        last_value: drbg.last_value,
        commit_counter: reset.commit_counter,
        commit_array: reset.commit_array,
    }
}

pub(in crate::library::tpm2::command) fn all_algorithms() -> String {
    String::from_utf8(DEFAULT_ALGORITHMS_PROFILE.to_vec()).expect("an ascii algorithm list")
}

pub(in crate::library::tpm2::command) fn without(algorithm: &str) -> String {
    all_algorithms()
        .split(',')
        .filter(|token| *token != algorithm)
        .collect::<Vec<_>>()
        .join(",")
}

#[track_caller]
pub(in crate::library::tpm2::command) fn reload(
    state: &OwnedPersistentState,
) -> OwnedPersistentState {
    let blob = persistent_all_store(state).expect("the state serializes");
    let envelope = PersistentAllEnvelope::parse(&blob).expect("the envelope parses");
    let decoded = parse_persistent_all_payload(&envelope).expect("the payload parses");
    materialize_persistent_state(decoded).expect("the payload materializes")
}

pub(in crate::library::tpm2::command) fn colliding_last_value(seed: &[u8]) -> [u32; 4] {
    let mut probe = Drbg::restore(seed, 1, [0; 4], false).expect("the probe restores");
    let mut block = [0u8; 16];
    probe.generate(&mut block).expect("the probe generates");
    core::array::from_fn(|word| {
        u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
    })
}

pub(in crate::library::tpm2::command) fn occupied(runtime: &Tpm2Runtime) -> Vec<bool> {
    runtime
        .live
        .objects
        .iter()
        .map(|object| object.attributes & ATTR_OCCUPIED != 0)
        .collect()
}

pub(in crate::library::tpm2::command) fn occupied_slots(runtime: &Tpm2Runtime) -> Vec<usize> {
    runtime
        .live
        .objects
        .iter()
        .enumerate()
        .filter(|(_, object)| object.attributes & ATTR_OCCUPIED != 0)
        .map(|(slot, _)| slot)
        .collect()
}

pub(in crate::library::tpm2::command) fn context_array(runtime: &Tpm2Runtime) -> Vec<u16> {
    runtime
        .live
        .state_reset
        .as_ref()
        .expect("state reset present")
        .context_array
        .to_vec()
}

pub(in crate::library::tpm2::command) fn symcipher_template(attributes: u32) -> Vec<u8> {
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

pub(in crate::library::tpm2::command) fn session_success_response() -> Vec<u8> {
    hex("8002 00000013 00000000 00000000 0000 01 0000")
}

pub(in crate::library::tpm2::command) fn make_orderly(
    runtime: &mut Tpm2Runtime,
    orderly_state: u16,
) {
    let state = runtime.state.as_mut().expect("state present");
    state.persistent.orderly_state = orderly_state;
    runtime.nv_memory = build_nv_image(state).expect("the orderly state serializes");
    runtime.nv_update_pending = false;
}

pub(in crate::library::tpm2::command) fn error_response(code: u32) -> Vec<u8> {
    let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a];
    out.extend_from_slice(&code.to_be_bytes());
    out
}

const FLIP_MASKS: [u8; 3] = [0x01, 0x80, 0xff];
pub(in crate::library::tpm2::command) const REPLACEMENT_BYTES: [u8; 4] = [0x00, 0x01, 0x7f, 0xff];
pub(in crate::library::tpm2::command) const TAIL_BYTES: [u8; 4] = [0x00, 0x01, 0x80, 0xff];

#[derive(Clone, Copy)]
enum Edit {
    Truncated,
    Xor { offset: usize, mask: u8 },
    Set { offset: usize, value: u8 },
}

pub(in crate::library::tpm2::command) struct Mutation {
    length: usize,
    edit: Edit,
    bytes: Vec<u8>,
}

impl core::fmt::Display for Mutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "length {}", self.length)?;
        match self.edit {
            Edit::Truncated => Ok(()),
            Edit::Xor { offset, mask } => write!(f, ", byte {offset} ^ {mask:#04x}"),
            Edit::Set { offset, value } => write!(f, ", byte {offset} = {value:#04x}"),
        }
    }
}

fn write_command_size(bytes: &mut [u8]) {
    let size = (bytes.len() as u32).to_be_bytes();
    bytes[2..6].copy_from_slice(&size);
}

pub(in crate::library::tpm2::command) fn prefix_bit_flips(
    seed: &[u8],
    shortest: usize,
    first_offset: usize,
    repair_size: bool,
) -> impl Iterator<Item = Mutation> + '_ {
    (shortest..=seed.len()).flat_map(move |length| {
        (first_offset..length).flat_map(move |offset| {
            FLIP_MASKS.into_iter().map(move |mask| {
                let mut bytes = seed[..length].to_vec();
                if repair_size {
                    write_command_size(&mut bytes);
                }
                bytes[offset] ^= mask;
                Mutation {
                    length,
                    edit: Edit::Xor { offset, mask },
                    bytes,
                }
            })
        })
    })
}

pub(in crate::library::tpm2::command) fn byte_replacements<'a>(
    seed: &'a [u8],
    values: &'a [u8],
) -> impl Iterator<Item = Mutation> + 'a {
    (0..seed.len()).flat_map(move |offset| {
        values.iter().map(move |&value| {
            let mut bytes = seed.to_vec();
            bytes[offset] = value;
            Mutation {
                length: seed.len(),
                edit: Edit::Set { offset, value },
                bytes,
            }
        })
    })
}

pub(in crate::library::tpm2::command) fn truncated_tail_replacements<'a>(
    seed: &'a [u8],
    shortest: usize,
    values: &'a [u8],
) -> impl Iterator<Item = Mutation> + 'a {
    (shortest..seed.len()).flat_map(move |length| {
        values.iter().map(move |&value| {
            let mut bytes = seed[..length].to_vec();
            *bytes.last_mut().expect("a non-empty prefix") = value;
            write_command_size(&mut bytes);
            Mutation {
                length,
                edit: Edit::Set {
                    offset: length - 1,
                    value,
                },
                bytes,
            }
        })
    })
}

pub(in crate::library::tpm2::command) fn prefixes(
    seed: &[u8],
    lengths: core::ops::Range<usize>,
    repair_size: bool,
) -> impl Iterator<Item = Mutation> + '_ {
    lengths.map(move |length| {
        let mut bytes = seed[..length].to_vec();
        if repair_size {
            write_command_size(&mut bytes);
        }
        Mutation {
            length,
            edit: Edit::Truncated,
            bytes,
        }
    })
}

#[track_caller]
pub(in crate::library::tpm2::command) fn for_each_mutation(
    case: &str,
    mutations: impl IntoIterator<Item = Mutation>,
    mut run: impl FnMut(Vec<u8>),
) {
    for mutation in mutations {
        let described = mutation.to_string();
        run_scenario(&format!("{case}, {described}"), || run(mutation.bytes));
    }
}

#[track_caller]
pub(in crate::library::tpm2::command) fn assert_scenario_response(
    scenario: &str,
    expected: &[u8],
    run: impl FnOnce() -> Vec<u8>,
) {
    let response = run_scenario(scenario, run);
    assert_eq!(response, expected, "{scenario}");
}

#[track_caller]
pub(in crate::library::tpm2::command) fn run_scenario<T>(
    scenario: &str,
    run: impl FnOnce() -> T,
) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(value) => value,
        Err(panic) => {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("a non-string panic payload");
            panic!("{scenario}: {message}");
        }
    }
}

#[track_caller]
pub(in crate::library::tpm2::command) fn dispatch_ignoring_result(
    runtime: &mut Tpm2Runtime,
    bytes: Vec<u8>,
) {
    let input = CommandInput::new(bytes.len() as u32, bytes);
    let parsed = parse_command(&input).expect("the header parses");
    let _ = serialize_response(&dispatch(runtime, &parsed, CancellationToken::disabled()));
}

pub(in crate::library::tpm2::command) fn dispatch_if_header_parses(
    bytes: Vec<u8>,
    runtime: impl FnOnce() -> Tpm2Runtime,
) {
    let input = CommandInput::new(bytes.len() as u32, bytes);
    let Ok(parsed) = parse_command(&input) else {
        return;
    };
    let mut runtime = runtime();
    let _ = serialize_response(&dispatch(
        &mut runtime,
        &parsed,
        CancellationToken::disabled(),
    ));
}

#[cfg(test)]
mod mutation_generators {
    use super::*;

    fn bytes_of(mutations: impl Iterator<Item = Mutation>) -> Vec<Vec<u8>> {
        mutations.map(|mutation| mutation.bytes).collect()
    }

    #[test]
    fn prefix_flips_repair_command_size_before_flipping() {
        let seed = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x7e, 0xa0, 0xb0];
        let mut expected = Vec::new();
        for (length, offset) in [(11, 10), (12, 10), (12, 11)] {
            for mask in [0x01, 0x80, 0xff] {
                let mut bytes = seed[..length].to_vec();
                bytes[5] = length as u8;
                bytes[offset] ^= mask;
                expected.push(bytes);
            }
        }
        assert_eq!(bytes_of(prefix_bit_flips(&seed, 11, 10, true)), expected);
    }

    #[test]
    fn replacements_and_tail_edits_follow_seed_order() {
        let seed = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x7e, 0xa0, 0xb0];
        let replaced = bytes_of(byte_replacements(&seed[10..], &[0x00, 0xff]));
        assert_eq!(
            replaced,
            [[0x00, 0xb0], [0xff, 0xb0], [0xa0, 0x00], [0xa0, 0xff]]
        );
        let tails = bytes_of(truncated_tail_replacements(&seed, 11, &[0x5a]));
        assert_eq!(tails, [vec![0x80, 0x01, 0, 0, 0, 11, 0, 0, 1, 0x7e, 0x5a]]);
    }

    #[test]
    #[should_panic(expected = "probe, length 11, byte 10 ^ 0x80: boom")]
    fn runner_names_the_failing_mutation() {
        let seed = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x7e, 0xa0, 0xb0];
        for_each_mutation("probe", prefix_bit_flips(&seed, 10, 10, true), |bytes| {
            if bytes == [0x80, 0x01, 0, 0, 0, 11, 0, 0, 1, 0x7e, 0xa0 ^ 0x80] {
                panic!("boom");
            }
        });
    }
}
