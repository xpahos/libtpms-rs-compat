// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

#![cfg(feature = "tpm2")]

mod harness;
mod layout;
mod replay;
mod scenario;

use std::collections::BTreeSet;
use std::ffi::c_uchar;
use std::ptr;
use std::sync::LazyLock;

use harness::{Fixture, State, TPM_SUCCESS, Tpm, TpmResult};

const SCENARIO: &str =
    include_str!("../../scripts/golden_responses/scenarios/get_test_result.scenario");

static FIXTURE: LazyLock<Fixture> = LazyLock::new(|| {
    Fixture::parse(
        b"GTORACLE",
        include_bytes!("../../src/library/tpm2/testdata/golden_responses/get_test_result.bin"),
    )
});

static CASES: LazyLock<Vec<scenario::Case>> = LazyLock::new(|| scenario::cases(SCENARIO));

fn run(name: &str) {
    harness::isolated(name, |tpm: &Tpm| {
        let case = CASES
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("the scenario has no case {name}"));
        replay::replay(tpm, &FIXTURE, case);
    });
}

macro_rules! abi_cases {
    ($($name:ident),* $(,)?) => {
        const REPLAYED: &[&str] = &[$(stringify!($name)),*];

        $(
            #[test]
            fn $name() {
                run(stringify!($name));
            }
        )*
    };
}

abi_cases! {
    failure_mode_state_restored_through_set_state,
    failure_mode_state_restored_through_storage_callbacks,
    failure_mode_tpm_keeps_the_restored_state,
    operational_state_restored_through_set_state,
    processing_while_powered_off,
    platform_init_failure_leaves_staged_state,
    storage_init_failure_leaves_staged_state,
    init_callback_failure_keeps_the_running_tpm,
    malformed_volatile_state_rejected_by_set_state,
    corrupt_failure_mode_volatile_state_from_storage,
    corrupt_operational_volatile_state_from_storage,
    truncated_volatile_state_from_storage,
    late_truncated_volatile_state_from_storage,
    short_volatile_state_from_storage_is_ignored,
    stale_volatile_state_after_manufacture,
    permanent_state_load_failure_after_power_on,
    corrupt_permanent_state_from_storage_keeps_staged_volatile_state,
    terminate_then_fresh_initialization,
    repeated_main_init_after_failure_mode_restore,
    failure_diagnostics_outlive_the_power_cycle,
    partially_restored_volatile_state_keeps_unmarshalled_fields,
    volatile_state_cut_in_the_drbg_seed,
    volatile_state_cut_in_the_pcr_save_area,
    volatile_state_cut_in_the_null_seed,
    volatile_state_cut_in_the_context_array,
    volatile_state_cut_between_loaded_objects,
    volatile_state_cut_in_a_pcr_bank,
    volatile_state_cut_in_a_session_nonce,
    volatile_state_cut_in_the_failure_diagnostics,
    volatile_state_cut_after_an_object_attributes,
    orderly_nv_ram_survives_a_volatile_restore,
    volatile_state_cut_after_the_orderly_nv_ram,
    volatile_state_restores_loaded_sequences,
    volatile_state_cut_in_an_rsa_private_key,
    volatile_state_cut_after_an_odd_number_of_prime_words,
    volatile_state_cut_after_an_even_number_of_prime_words,
    volatile_state_cut_in_an_object_name,
    volatile_state_with_an_object_seed_compat_level_too_new,
    volatile_state_with_an_invalid_object_hierarchy,
    volatile_state_with_invalid_rsa_key_bits,
    volatile_state_cut_in_an_ecc_public_point,
    volatile_state_with_an_invalid_ecc_curve,
    volatile_state_cut_in_a_symmetric_object_key,
    volatile_state_with_an_invalid_symmetric_object_mode,
    volatile_state_cut_after_a_session_symmetric_algorithm,
    volatile_state_cut_after_session_symmetric_key_bits,
    volatile_state_with_invalid_session_symmetric_key_bits,
    volatile_state_with_an_invalid_session_symmetric_mode,
    volatile_state_cut_after_an_xor_session_algorithm,
    volatile_state_with_an_invalid_xor_session_hash,
    volatile_state_with_an_invalid_session_symmetric_algorithm,
    volatile_state_cut_in_a_hash_sequence_state,
    volatile_state_cut_in_a_hash_sequence_digest,
    volatile_state_cut_in_an_hmac_sequence_key,
    orderly_nv_ram_keeps_bytes_outside_its_entries,
    volatile_state_with_a_newer_hash_state_header_is_rejected,
    volatile_state_cut_after_a_newer_hash_state_header,
    volatile_state_with_a_newer_empty_hash_state_header_stops_there,
    orderly_nv_ram_with_a_short_entry_header_survives_shutdown,
    orderly_nv_ram_with_an_oversized_entry_survives_shutdown,
    orderly_nv_ram_with_a_wrapping_entry_size_keeps_the_entries_before_it,
    null_primary_survives_two_state_resumes,
}

const RECORDING_OPS: &[&str] = &[
    "main-init",
    "set-state",
    "get-state",
    "volatile-all-store",
    "set-profile",
    "process",
    "was-manufactured",
    "established",
    "established-reset",
    "hash-start",
    "hash-data",
    "hash-end",
    "callbacks",
];

#[test]
fn every_scenario_case_is_replayed() {
    let scenario: BTreeSet<&str> = CASES.iter().map(|case| case.name.as_str()).collect();
    let replayed: BTreeSet<&str> = REPLAYED.iter().copied().collect();
    assert_eq!(scenario, replayed);
    assert_eq!(REPLAYED.len(), replayed.len(), "a case is listed twice");
}

#[test]
fn every_recorded_case_step_has_a_reference_record() {
    let names: BTreeSet<&str> = FIXTURE.names().collect();
    for case in CASES.iter() {
        assert!(!case.ops.is_empty(), "case {} is empty", case.name);
        for op in &case.ops {
            if RECORDING_OPS.contains(&op.name.as_str()) {
                assert!(
                    names.contains(op.word(0)),
                    "line {}: the fixture lacks {}",
                    op.line,
                    op.word(0)
                );
            }
        }
    }
}

const COLLISION: &str = "\
profile {\"Name\":\"default-v1\"}
snapshot S
send STARTUP 80010000000c000001440000
checkpoint S
case collision
nvram-put volatilestate VOLATILE_S
get-state CASE_INPUT volatile
end-case
";

#[test]
#[should_panic(expected = "line 4: checkpoint S would overwrite the snapshot recorded on line 2")]
fn a_checkpoint_cannot_overwrite_a_recorded_snapshot() {
    scenario::cases(COLLISION);
}

#[test]
#[should_panic(expected = "VOLATILE_S names no snapshot recorded before case early")]
fn a_case_blob_cannot_name_a_checkpoint() {
    scenario::cases(
        "checkpoint S\ncase early\nnvram-put volatilestate VOLATILE_S\nend-case\nsnapshot S\n",
    );
}

#[test]
#[should_panic(expected = "VOLATILE_T@drop=21 names no snapshot recorded before case other")]
fn a_case_blob_cannot_name_an_unknown_snapshot() {
    scenario::cases(
        "snapshot S\ncase other\nset-state RESULT volatile VOLATILE_T@drop=21\nend-case\n",
    );
}

#[test]
fn distinct_snapshot_and_checkpoint_names_remain_valid() {
    let scenario = "\
snapshot S
checkpoint T
restore S
checkpoint T
case distinct
nvram-put permall PERMALL_S
nvram-put volatilestate VOLATILE_S@drop=21
end-case
";
    let cases = scenario::cases(scenario);
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0].ops.len(), 2);
}

fn trailer_of(blob: &[u8]) -> [u8; 20] {
    <sha1::Sha1 as sha1::Digest>::digest(&blob[..blob.len() - 20]).into()
}

fn with_trailer(mut blob: Vec<u8>) -> Vec<u8> {
    let trailer = trailer_of(&blob);
    let payload = blob.len() - 20;
    blob[payload..].copy_from_slice(&trailer);
    blob
}

fn running_export() -> Vec<u8> {
    let blob = FIXTURE.get("VOLATILE_BUSY").to_vec();
    assert_eq!(blob[blob.len() - 20..], trailer_of(&blob));
    blob
}

#[test]
fn blob_modifiers_apply_from_left_to_right() {
    let mut expected = FIXTURE.get("VOLATILE_BUSY").to_vec();
    expected[10..12].copy_from_slice(&[0xab, 0xcd]);
    expected[12] ^= 0xff;
    let expected = with_trailer(expected);
    let expected = &expected[..expected.len() - 1];
    let modified = scenario::blob(&FIXTURE, "VOLATILE_BUSY@set=10:abcd@flip=12@sha1@drop=1");
    assert_eq!(modified, expected);
}

#[test]
fn a_corrupted_checksum_fails_the_running_export_comparison() {
    let expected = running_export();
    let mut actual = expected.clone();
    let last = actual.len() - 1;
    actual[last] ^= 0xff;
    let error = layout::compare_running_export(State::Volatile, &expected, &actual)
        .expect_err("only the trailer differs, and the trailer no longer matches");
    assert!(error.starts_with("actual: the SHA-1 trailer"), "{error}");
    let error = layout::compare_running_export(State::Volatile, &actual, &expected)
        .expect_err("a reference with a broken trailer is not trusted either");
    assert!(error.starts_with("reference: the SHA-1 trailer"), "{error}");
    let error = layout::compare_running_export(State::Volatile, &expected, &actual[..19])
        .expect_err("19 bytes cannot carry a trailer");
    assert!(
        error.contains("no room for its 20-byte SHA-1 trailer"),
        "{error}"
    );
}

#[test]
fn valid_exports_that_differ_only_in_host_time_pass() {
    let expected = running_export();
    let fields = layout::host_time_fields(State::Volatile, &expected).unwrap();
    let mut actual = expected.clone();
    for (name, range) in &fields {
        if *name != "SHA-1 trailer" {
            actual[range.clone()]
                .iter_mut()
                .for_each(|byte| *byte ^= 0x5a);
        }
    }
    let actual = with_trailer(actual);
    assert_ne!(actual[actual.len() - 20..], expected[expected.len() - 20..]);
    layout::compare_running_export(State::Volatile, &expected, &actual)
        .expect("each export is valid and only host time differs");
}

#[test]
fn deterministic_payload_differences_fail_even_with_a_valid_trailer() {
    let expected = running_export();
    let fields = layout::host_time_fields(State::Volatile, &expected).unwrap();
    let at = (100..expected.len())
        .find(|at| fields.iter().all(|(_, range)| !range.contains(at)))
        .unwrap();
    let mut actual = expected.clone();
    actual[at] ^= 0x01;
    let actual = with_trailer(actual);
    let error = layout::compare_running_export(State::Volatile, &expected, &actual)
        .expect_err("a deterministic byte differs");
    let reported = format!("1 bytes outside the host time fields differ, the first at offset {at}");
    assert!(error.starts_with(&reported), "{error}");
}

const GET_TEST_RESULT: [u8; 10] = [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0x01, 0x7c];

unsafe extern "C" fn null_response_with_a_size(
    buffer: *mut *mut c_uchar,
    size: *mut u32,
    capacity: *mut u32,
    _command: *mut c_uchar,
    _length: u32,
) -> TpmResult {
    // SAFETY: the harness passes valid out-pointers.
    unsafe {
        *buffer = ptr::null_mut();
        *size = 123;
        *capacity = 0;
    }
    TPM_SUCCESS
}

unsafe extern "C" fn null_response_without_a_size(
    buffer: *mut *mut c_uchar,
    size: *mut u32,
    capacity: *mut u32,
    _command: *mut c_uchar,
    _length: u32,
) -> TpmResult {
    // SAFETY: the harness passes valid out-pointers.
    unsafe {
        *buffer = ptr::null_mut();
        *size = 0;
        *capacity = 0;
    }
    TPM_SUCCESS
}

unsafe extern "C" fn response_beyond_its_capacity(
    buffer: *mut *mut c_uchar,
    size: *mut u32,
    capacity: *mut u32,
    _command: *mut c_uchar,
    _length: u32,
) -> TpmResult {
    // SAFETY: plain allocation that the harness frees; valid out-pointers.
    unsafe {
        *buffer = libc::calloc(16, 1).cast();
        *size = 17;
        *capacity = 16;
    }
    TPM_SUCCESS
}

unsafe extern "C" fn empty_response_in_a_buffer(
    buffer: *mut *mut c_uchar,
    size: *mut u32,
    capacity: *mut u32,
    _command: *mut c_uchar,
    _length: u32,
) -> TpmResult {
    // SAFETY: plain allocation that the harness frees; valid out-pointers.
    unsafe {
        *buffer = libc::calloc(16, 1).cast();
        *size = 0;
        *capacity = 16;
    }
    TPM_SUCCESS
}

unsafe extern "C" fn failure_with_stale_outputs(
    buffer: *mut *mut c_uchar,
    size: *mut u32,
    capacity: *mut u32,
    _command: *mut c_uchar,
    _length: u32,
) -> TpmResult {
    // SAFETY: plain allocation that the harness frees; valid out-pointers.
    unsafe {
        *buffer = libc::calloc(4, 1).cast();
        *size = 4096;
        *capacity = 4;
    }
    0x0000_0011
}

#[test]
fn null_response_buffer_with_a_nonzero_size_fails_validation() {
    // SAFETY: the fake follows the TPMLIB_Process prototype.
    let reply = unsafe { harness::call_process(null_response_with_a_size, &GET_TEST_RESULT) };
    let violation = reply.expect_err("NULL with resp_size 123 is not a valid response");
    assert!(violation.contains("NULL"), "{violation}");
    assert!(violation.contains("123"), "{violation}");
}

#[test]
fn response_size_beyond_the_buffer_capacity_fails_validation() {
    // SAFETY: the fake follows the TPMLIB_Process prototype.
    let reply = unsafe { harness::call_process(response_beyond_its_capacity, &GET_TEST_RESULT) };
    let violation = reply.expect_err("17 bytes cannot fit a 16-byte buffer");
    assert!(
        violation.contains("17") && violation.contains("16"),
        "{violation}"
    );
}

#[test]
fn empty_responses_remain_valid() {
    for fake in [null_response_without_a_size, empty_response_in_a_buffer] {
        // SAFETY: the fake follows the TPMLIB_Process prototype.
        let reply = unsafe { harness::call_process(fake, &GET_TEST_RESULT) }
            .expect("an empty response is valid");
        assert_eq!(reply.result, TPM_SUCCESS);
        assert_eq!(reply.size, 0);
        assert_eq!(reply.response, Some(Vec::new()));
    }
}

#[test]
fn failed_process_calls_leave_the_response_unread() {
    // SAFETY: the fake follows the TPMLIB_Process prototype.
    let reply = unsafe { harness::call_process(failure_with_stale_outputs, &GET_TEST_RESULT) }
        .expect("an error result carries no response to validate");
    assert_eq!(reply.result, 0x11);
    assert_eq!((reply.size, reply.capacity), (4096, 4));
    assert_eq!(reply.response, None);
}
