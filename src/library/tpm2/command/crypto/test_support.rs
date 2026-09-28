// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::tpm2::command::core::test_support::tpm2b;
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::persistent::OwnedDrbgState;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::PrimitiveTest;
use std::cell::RefCell;

const TPM_ALG_NULL: u16 = 0x0010;
const RSA_ATTR: u32 = 0x0004_0472;

pub(super) fn plain32() -> Vec<u8> {
    vec![
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51,
    ]
}

pub(super) fn max_buffer() -> Vec<u8> {
    (0..1024).map(|index| (index % 256) as u8).collect()
}

pub(super) fn rsa_public() -> Vec<u8> {
    let mut out = 0x0001u16.to_be_bytes().to_vec();
    out.extend_from_slice(&0x000bu16.to_be_bytes());
    out.extend_from_slice(&RSA_ATTR.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&2048u16.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&tpm2b(&[]));
    out
}

pub(super) fn session_nonce(response: &[u8]) -> Vec<u8> {
    let body = &response[14..];
    let size = usize::from(u16::from_be_bytes([body[0], body[1]]));
    body[2..2 + size].to_vec()
}

pub(super) fn failed_tries(runtime: &Tpm2Runtime) -> u32 {
    runtime
        .state
        .as_ref()
        .expect("decoded state")
        .persistent
        .failed_tries
}

pub(super) fn digest_of(hash_alg: u16, data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
    hasher.update(data);
    hasher.finalize()
}

#[track_caller]
pub(super) fn assert_live_drbg_unchanged(runtime: &Tpm2Runtime, before: &OwnedDrbgState) {
    let now = &runtime.live.orderly.drbg_state;
    assert_eq!(now.seed.expose(), before.seed.expose());
    assert_eq!(now.reseed_counter, before.reseed_counter);
    assert_eq!(now.drbg_magic, before.drbg_magic);
    assert_eq!(now.last_value, before.last_value);
}

thread_local! {
    static SELF_TESTS_RUN: RefCell<Vec<PrimitiveTest>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn recording_runner(test: PrimitiveTest) -> bool {
    SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
    true
}

pub(super) fn recording_runner_failing_sha256(test: PrimitiveTest) -> bool {
    SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
    test != PrimitiveTest::Sha256
}

pub(super) fn recording_runner_failing_sha512(test: PrimitiveTest) -> bool {
    SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
    test != PrimitiveTest::Sha512
}

pub(super) fn never_runs(test: PrimitiveTest) -> bool {
    panic!("a rejected command must run no self-test, got {test:?}");
}

pub(super) fn take_self_tests_run() -> Vec<PrimitiveTest> {
    SELF_TESTS_RUN.with(|run| core::mem::take(&mut *run.borrow_mut()))
}
