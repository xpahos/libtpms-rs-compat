use crate::library::tpm2::command::core::test_support::TPM_ALG_SHA256;
use crate::library::tpm2::nv::{
    NvPublic, OrderlyRamImage, ResolvedIndex, TPMA_NV_TPM_NT_SHIFT, resolve_index,
};
use crate::library::tpm2::persistent::{OwnedUserNvramEntry, persistent_all_store};
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
fn divergence(actual: &[u8], expected: &[u8]) -> Vec<usize> {
    assert_eq!(actual.len(), expected.len(), "blob length");
    (0..actual.len())
        .filter(|&index| actual[index] != expected[index])
        .collect()
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
