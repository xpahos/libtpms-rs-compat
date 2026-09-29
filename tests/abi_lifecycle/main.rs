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
use std::path::Path;
use std::ptr;
use std::sync::LazyLock;

use harness::{Fixture, State, TPM_SUCCESS, Tpm, TpmResult};

struct Family {
    name: &'static str,
    scenario_file: &'static str,
    fixture: LazyLock<Fixture>,
    cases: LazyLock<Vec<scenario::Case>>,
}

macro_rules! family {
    ($name:literal, $magic:literal, $stem:literal) => {
        Family {
            name: $name,
            scenario_file: concat!($stem, ".scenario"),
            fixture: LazyLock::new(|| {
                Fixture::parse(
                    $magic,
                    include_bytes!(concat!(
                        "../../src/library/tpm2/testdata/golden_responses/",
                        $stem,
                        ".bin"
                    )),
                )
            }),
            cases: LazyLock::new(|| {
                scenario::cases(include_str!(concat!(
                    "../../scripts/golden_responses/scenarios/",
                    $stem,
                    ".scenario"
                )))
            }),
        }
    };
}

static LIFECYCLE_CASES: Family = family!("get-test-result", b"GTORACLE", "get_test_result");
static POLICY_SESSION_CASES: Family = family!("policy-sessions", b"PSORACLE", "policy_sessions");

fn run(family: &Family, name: &str) {
    harness::isolated(name, |tpm: &Tpm| {
        let case = family
            .cases
            .iter()
            .find(|case| case.name == name)
            .unwrap_or_else(|| panic!("the {} scenario has no case {name}", family.name));
        replay::replay(tpm, &family.fixture, case);
    });
}

macro_rules! abi_cases {
    ($($family:ident: [$($name:ident),* $(,)?]),* $(,)?) => {
        static REPLAYED: &[(&Family, &[&str])] = &[$((&$family, &[$(stringify!($name)),*])),*];

        $($(
            #[test]
            fn $name() {
                run(&$family, stringify!($name));
            }
        )*)*
    };
}

abi_cases! {
    LIFECYCLE_CASES: [
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
    ],
    POLICY_SESSION_CASES: [
        nv_policy_write_without_policywrite_is_unavailable,
        nv_policy_read_without_policyread_is_unavailable,
        nv_policy_write_with_policywrite_is_available,
        nv_policy_read_with_policyread_is_available,
        nv_policy_access_without_either_attribute_is_unavailable,
        nv_policy_access_with_both_attributes_is_available,
        nv_empty_policy_is_unavailable_whatever_the_attributes,
        nv_write_lock_is_a_policy_write,
        nv_read_lock_is_a_policy_read,
        nv_authorization_for_policy_nv_is_a_policy_read,
        nv_authorization_for_policy_secret_is_a_policy_read,
        nv_certify_gates_the_index_in_its_second_session,
        nv_change_auth_policy_needs_no_access_attribute,
        nv_change_auth_policy_still_needs_the_policy_digest,
        nv_change_auth_policy_still_needs_its_command_code,
        nv_change_auth_empty_policy_is_unavailable,
        nv_change_auth_rejects_password_and_hmac_sessions,
        nv_undefine_space_special_policy_needs_no_access_attribute,
        nv_undefine_space_special_empty_policy_is_unavailable,
        nv_missing_policy_attribute_precedes_a_digest_mismatch,
        nv_trial_session_precedes_the_policy_gate,
        nv_password_authorization_ignores_the_policy_attributes,
    ],
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
    for &(family, replayed) in REPLAYED {
        let scenario: BTreeSet<&str> = family.cases.iter().map(|case| case.name.as_str()).collect();
        let listed: BTreeSet<&str> = replayed.iter().copied().collect();
        assert_eq!(scenario, listed, "{}", family.name);
        assert_eq!(
            replayed.len(),
            listed.len(),
            "{}: a case is listed twice",
            family.name
        );
    }
}

#[test]
fn every_scenario_with_cases_belongs_to_a_replayed_family() {
    let registered: BTreeSet<&str> = REPLAYED
        .iter()
        .map(|(family, _)| family.scenario_file)
        .collect();
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/golden_responses/scenarios");
    let mut scenarios = 0;
    for entry in std::fs::read_dir(&directory).expect("the scenario directory is readable") {
        let path = entry.expect("a directory entry").path();
        let file = path
            .file_name()
            .and_then(|file| file.to_str())
            .expect("a UTF-8 file name");
        if !file.ends_with(".scenario") {
            continue;
        }
        scenarios += 1;
        let text = std::fs::read_to_string(&path).expect("the scenario is readable");
        let has_cases = text
            .lines()
            .any(|line| line.trim_start().starts_with("case "));
        assert!(
            !has_cases || registered.contains(file),
            "{file} holds cases that no replayed family covers"
        );
    }
    assert!(scenarios >= registered.len());
}

#[test]
fn every_recorded_case_step_has_a_reference_record() {
    for &(family, _) in REPLAYED {
        let names: BTreeSet<&str> = family.fixture.names().collect();
        for case in family.cases.iter() {
            assert!(!case.ops.is_empty(), "case {} is empty", case.name);
            for op in &case.ops {
                if RECORDING_OPS.contains(&op.name.as_str()) {
                    assert!(
                        names.contains(op.word(0)),
                        "{} line {}: the fixture lacks {}",
                        family.name,
                        op.line,
                        op.word(0)
                    );
                }
            }
        }
    }
}

const RC_SUCCESS: u32 = 0x000;
const RC_AUTH_TYPE: u32 = 0x124;
const RC_AUTH_UNAVAILABLE: u32 = 0x12f;
const RC_NV_RANGE: u32 = 0x146;
const RC_NV_LOCKED: u32 = 0x148;
const RC_HANDLE_1: u32 = 0x18b;
const RC_SESSION_1_ATTRIBUTES: u32 = 0x982;
const RC_SESSION_1_POLICY_FAIL: u32 = 0x99d;
const RC_SESSION_1_BAD_AUTH: u32 = 0x9a2;
const RC_SESSION_1_POLICY_CC: u32 = 0x9a4;

const ORIGINAL: &[u8] = b"ORIGINAL";
const REPLACED: &[u8] = b"REPLACED";

#[rustfmt::skip]
const NV_GATE_OUTCOMES: &[(&str, u32, Option<&[u8]>)] = &[
    ("NVG_WRITE_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_WRITE_DENIED_OWNER_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_READ_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_WRITE_ALLOWED", RC_SUCCESS, None),
    ("NVG_WRITE_ALLOWED_OWNER_READ", RC_SUCCESS, Some(REPLACED)),
    ("NVG_READ_ALLOWED", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_NONE_WRITE", RC_AUTH_UNAVAILABLE, None),
    ("NVG_NONE_READ", RC_AUTH_UNAVAILABLE, None),
    ("NVG_NONE_OWNER_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_BOTH_WRITE", RC_SUCCESS, None),
    ("NVG_BOTH_READ", RC_SUCCESS, Some(REPLACED)),
    ("NVG_EMPTY_WRITE", RC_AUTH_UNAVAILABLE, None),
    ("NVG_EMPTY_READ", RC_AUTH_UNAVAILABLE, None),
    ("NVG_EMPTY_OWNER_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_WRITE_LOCK_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_WRITE_LOCK_DENIED_OWNER_WRITE", RC_SUCCESS, None),
    ("NVG_WRITE_LOCK_ALLOWED", RC_SUCCESS, None),
    ("NVG_WRITE_LOCK_ALLOWED_OWNER_WRITE", RC_NV_LOCKED, None),
    ("NVG_READ_LOCK_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_READ_LOCK_DENIED_OWNER_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_READ_LOCK_ALLOWED", RC_SUCCESS, None),
    ("NVG_READ_LOCK_ALLOWED_OWNER_READ", RC_NV_LOCKED, None),
    ("NVG_POLICY_NV_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_POLICY_NV_ALLOWED", RC_SUCCESS, None),
    ("NVG_POLICY_SECRET_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_POLICY_SECRET_ALLOWED", RC_SUCCESS, None),
    ("NVG_CERTIFY_DENIED", RC_AUTH_UNAVAILABLE, None),
    ("NVG_CERTIFY_ALLOWED", RC_NV_RANGE, None),
    ("NVG_CHANGE_AUTH", RC_SUCCESS, None),
    ("NVG_CHANGE_AUTH_NEW_PASSWORD_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_CHANGE_AUTH_OLD_PASSWORD_READ", RC_SESSION_1_BAD_AUTH, None),
    ("NVG_CHANGE_AUTH_DIGEST_MISMATCH", RC_SESSION_1_POLICY_FAIL, None),
    ("NVG_CHANGE_AUTH_DIGEST_WITHOUT_COMMAND_CODE", RC_SESSION_1_POLICY_FAIL, None),
    ("NVG_CHANGE_AUTH_DIGEST_OLD_PASSWORD_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_WRITE_COMMAND_USER_WRITE", RC_AUTH_UNAVAILABLE, None),
    ("NVG_WRITE_COMMAND_ADMIN_CHANGE_AUTH", RC_SESSION_1_POLICY_CC, None),
    ("NVG_WRITE_COMMAND_OWNER_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_CHANGE_AUTH_EMPTY", RC_AUTH_UNAVAILABLE, None),
    ("NVG_CHANGE_AUTH_EMPTY_OLD_PASSWORD_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_CHANGE_AUTH_NOT_POLICY_PASSWORD", RC_AUTH_TYPE, None),
    ("NVG_CHANGE_AUTH_NOT_POLICY_HMAC", RC_AUTH_TYPE, None),
    ("NVG_CHANGE_AUTH_NOT_POLICY_OLD_PASSWORD_READ", RC_SUCCESS, Some(ORIGINAL)),
    ("NVG_UNDEFINE", RC_SUCCESS, None),
    ("NVG_UNDEFINE_READ_PUBLIC", RC_HANDLE_1, None),
    ("NVG_UNDEFINE_EMPTY", RC_AUTH_UNAVAILABLE, None),
    ("NVG_UNDEFINE_EMPTY_READ_PUBLIC", RC_SUCCESS, None),
    ("NVG_MISMATCH_WITHOUT_POLICYWRITE", RC_AUTH_UNAVAILABLE, None),
    ("NVG_MISMATCH_WITH_POLICYWRITE", RC_SESSION_1_POLICY_FAIL, None),
    ("NVG_TRIAL_WRITE", RC_SESSION_1_ATTRIBUTES, None),
    ("NVG_PASSWORD_WRITE", RC_SUCCESS, None),
    ("NVG_PASSWORD_READ", RC_SUCCESS, Some(REPLACED)),
    ("NVG_PASSWORD_WRONG", RC_SESSION_1_BAD_AUTH, None),
];

fn reference_response(name: &str) -> &'static [u8] {
    let record = POLICY_SESSION_CASES.fixture.get(name);
    assert_eq!(
        record[..4],
        TPM_SUCCESS.to_be_bytes(),
        "{name}: TPMLIB_Process"
    );
    &record[4..]
}

fn response_code(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
}

fn first_sized_parameter(response: &[u8]) -> &[u8] {
    let at = if response[..2] == [0x80, 0x02] {
        14
    } else {
        10
    };
    let size = usize::from(u16::from_be_bytes([response[at], response[at + 1]]));
    &response[at + 2..at + 2 + size]
}

#[test]
fn nv_policy_gate_reference_outcomes() {
    for &(name, code, data) in NV_GATE_OUTCOMES {
        let response = reference_response(name);
        assert_eq!(response_code(response), code, "{name}");
        if code != RC_SUCCESS {
            assert_eq!(response.len(), 10, "{name}: an error carries no payload");
        }
        if let Some(data) = data {
            assert_eq!(first_sized_parameter(response), data, "{name}");
        }
    }
}

#[test]
fn nv_policy_gate_denials_leave_the_target_policy_untouched() {
    for (denied, allowed) in [
        (
            "NVG_POLICY_NV_DENIED_DIGEST",
            "NVG_POLICY_NV_ALLOWED_DIGEST",
        ),
        (
            "NVG_POLICY_SECRET_DENIED_DIGEST",
            "NVG_POLICY_SECRET_ALLOWED_DIGEST",
        ),
    ] {
        let denied = reference_response(denied);
        let allowed = reference_response(allowed);
        assert_eq!(response_code(denied), RC_SUCCESS);
        assert_eq!(response_code(allowed), RC_SUCCESS);
        assert_eq!(first_sized_parameter(denied), [0u8; 32]);
        assert_ne!(first_sized_parameter(allowed), [0u8; 32]);
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
    let blob = LIFECYCLE_CASES.fixture.get("VOLATILE_BUSY").to_vec();
    assert_eq!(blob[blob.len() - 20..], trailer_of(&blob));
    blob
}

#[test]
fn blob_modifiers_apply_from_left_to_right() {
    let mut expected = LIFECYCLE_CASES.fixture.get("VOLATILE_BUSY").to_vec();
    expected[10..12].copy_from_slice(&[0xab, 0xcd]);
    expected[12] ^= 0xff;
    let expected = with_trailer(expected);
    let expected = &expected[..expected.len() - 1];
    let modified = scenario::blob(
        &LIFECYCLE_CASES.fixture,
        "VOLATILE_BUSY@set=10:abcd@flip=12@sha1@drop=1",
    );
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
