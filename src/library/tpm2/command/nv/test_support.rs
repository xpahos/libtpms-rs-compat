// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::tpm2::command::core::test_support::{
    RC_SUCCESS, TPM_ALG_SHA256, command, dispatch_bytes, divergence, response_code,
};
use crate::library::tpm2::hierarchy::TPM_RH_OWNER;
use crate::library::tpm2::nv::{
    NvPublic, OrderlyRamImage, ResolvedIndex, TPMA_NV_TPM_NT_SHIFT, build_nv_image,
    marshal_sized_nv_public, resolve_index,
};
use crate::library::tpm2::persistent::{
    OwnedUserNvramEntry, persistent_all_store, user_nvram_required_capacity,
};
use crate::library::tpm2::runtime::Tpm2Runtime;

pub(in crate::library::tpm2::command) fn nv_public(
    handle: u32,
    attributes: u32,
    data_size: u16,
) -> NvPublic {
    NvPublic {
        nv_index: handle,
        name_alg: TPM_ALG_SHA256,
        attributes,
        auth_policy: Vec::new(),
        data_size,
    }
}
#[track_caller]
pub(in crate::library::tpm2::command) fn define(runtime: &mut Tpm2Runtime, public: &NvPublic) {
    let mut parameters = 0u16.to_be_bytes().to_vec();
    parameters.extend_from_slice(&marshal_sized_nv_public(public));
    assert_eq!(
        response_code(&dispatch_bytes(
            runtime,
            &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &parameters),
        )),
        RC_SUCCESS,
        "the index is defined"
    );
}
pub(in crate::library::tpm2::command) fn nt(index_type: u32) -> u32 {
    index_type << TPMA_NV_TPM_NT_SHIFT
}
pub(in crate::library::tpm2::command) fn resolved(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> ResolvedIndex {
    resolve_index(runtime, handle).expect("the index is defined")
}
pub(in crate::library::tpm2::command) fn index_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
    runtime
        .state()
        .user_nvram
        .entries
        .iter()
        .filter_map(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle, .. } => Some(*handle),
            OwnedUserNvramEntry::Persistent { .. } => None,
        })
        .collect()
}
pub(in crate::library::tpm2::command) fn nvram_handles(runtime: &Tpm2Runtime) -> Vec<u32> {
    runtime
        .state()
        .user_nvram
        .entries
        .iter()
        .map(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle, .. }
            | OwnedUserNvramEntry::Persistent { handle, .. } => *handle,
        })
        .collect()
}
#[track_caller]
pub(in crate::library::tpm2::command) fn push_nvram(
    runtime: &mut Tpm2Runtime,
    entries: impl IntoIterator<Item = OwnedUserNvramEntry>,
) {
    let user_nvram = &mut runtime.state.as_mut().expect("state present").user_nvram;
    user_nvram.entries.extend(entries);
    user_nvram.required_capacity = user_nvram_required_capacity(&user_nvram.entries)
        .expect("the planted entries fit the dynamic region");
    let state = runtime.state.as_ref().expect("state present");
    runtime.nv_memory = build_nv_image(state).expect("the planted entries serialize");
}
#[derive(Debug, Eq, PartialEq)]
pub(in crate::library::tpm2::command) struct Snapshot {
    nv_update_pending: bool,
    index_handles: Vec<u32>,
    required_capacity: u64,
    max_count: u64,
    max_nv_counter: u64,
    orderly_state: u16,
    orderly_ram: OrderlyRamImage,
    nv_memory: Box<[u8]>,
    permanent: Vec<u8>,
}
pub(in crate::library::tpm2::command) fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
    Snapshot {
        nv_update_pending: runtime.nv_update_pending,
        index_handles: index_handles(runtime),
        required_capacity: runtime.state().user_nvram.required_capacity,
        max_count: runtime.state().user_nvram.max_count,
        max_nv_counter: runtime.live.max_nv_counter,
        orderly_state: runtime.state().persistent.orderly_state,
        orderly_ram: runtime.live.index_orderly_ram.clone(),
        nv_memory: runtime.nv_memory.clone(),
        permanent: persistent_all_store(runtime.state()).expect("the state serializes"),
    }
}
#[track_caller]
pub(in crate::library::tpm2::command) fn assert_matches_oracle(
    runtime: &Tpm2Runtime,
    expected: &[u8],
    label: &str,
) {
    assert_matches_oracle_except(runtime, expected, label, &[]);
}
#[track_caller]
pub(in crate::library::tpm2::command) fn assert_matches_oracle_except(
    runtime: &Tpm2Runtime,
    expected: &[u8],
    label: &str,
    host_supplied: &[usize],
) {
    let actual = persistent_all_store(runtime.state()).expect("the state serializes");
    let mut allowed = host_supplied.to_vec();
    allowed.sort_unstable();
    assert_eq!(
        divergence(&actual, expected),
        allowed,
        "{label} diverges from the oracle beyond the known host-supplied bytes"
    );
}
#[track_caller]
pub(in crate::library::tpm2::command) fn assert_unchanged(
    runtime: &Tpm2Runtime,
    before: &Snapshot,
) {
    assert_eq!(&snapshot(runtime), before);
}
