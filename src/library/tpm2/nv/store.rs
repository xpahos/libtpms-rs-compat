use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_NV_SPACE, TPM_RC_NV_UNAVAILABLE,
};
use crate::types::TpmResult;

use super::attributes::{
    TPMA_NV_ORDERLY, TPMA_NV_PLATFORMCREATE, TPMA_NV_WRITTEN, is_counter_index, is_ordinary_index,
};
use super::image::build_nv_image;
use super::orderly_ram::{NV_RAM_HEADER_SIZE, RAM_INDEX_SPACE};
use super::public_area::NvPublic;
use super::user::{SIZEOF_NV_INDEX, USER_NVRAM_CAPACITY};
use crate::library::tpm2::persistent::{
    OwnedIndexOrderlyRam, OwnedNvIndex, OwnedOrderlyRamEntry, OwnedPersistentState, OwnedSecret,
    OwnedUserNvramEntry, user_nvram_required_capacity,
};
use crate::library::tpm2::runtime::Tpm2Runtime;

const NV_ERASED_BYTE: u8 = 0xff;

const NV_LIST_TERMINATOR_SIZE: u64 = 12;
const NV_FORWARD_POINTER_SIZE: u64 = 4;

const MIN_EVICT_OBJECTS: u64 = 7;
const MIN_COUNTER_INDICES: u64 = 8;
const SIZEOF_C_OBJECT: u64 = 2608;
const NV_EVICT_OBJECT_SIZE: u64 = 4 + 4 + SIZEOF_C_OBJECT;
const NV_INDEX_COUNTER_SIZE: u64 = 4 + SIZEOF_NV_INDEX + 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct ResolvedIndex {
    pub(in crate::library::tpm2) entry: usize,
    pub(in crate::library::tpm2) ram: Option<usize>,
    pub(in crate::library::tpm2) public: NvPublic,
}

impl ResolvedIndex {
    pub(in crate::library::tpm2) fn attributes(&self) -> u32 {
        self.public.attributes
    }

    pub(in crate::library::tpm2) fn is_written(&self) -> bool {
        self.public.attributes & TPMA_NV_WRITTEN != 0
    }

    pub(in crate::library::tpm2) fn is_platform_created(&self) -> bool {
        self.public.attributes & TPMA_NV_PLATFORMCREATE != 0
    }
}

fn stored_index(state: &OwnedPersistentState, entry: usize) -> Option<&OwnedNvIndex> {
    match state.user_nvram.entries.get(entry) {
        Some(OwnedUserNvramEntry::NvIndex { index, .. }) => Some(index),
        _ => None,
    }
}

fn stored_index_mut(state: &mut OwnedPersistentState, entry: usize) -> Option<&mut OwnedNvIndex> {
    match state.user_nvram.entries.get_mut(entry) {
        Some(OwnedUserNvramEntry::NvIndex { index, .. }) => Some(index),
        _ => None,
    }
}

fn index_entry_position(state: &OwnedPersistentState, handle: u32) -> Option<usize> {
    state
        .user_nvram
        .entries
        .iter()
        .position(|entry| matches!(entry, OwnedUserNvramEntry::NvIndex { handle: stored, .. } if *stored == handle))
}

fn ram_entry_position(ram: &OwnedIndexOrderlyRam, handle: u32) -> Option<usize> {
    ram.entries.iter().position(|entry| entry.handle == handle)
}

pub(in crate::library::tpm2) fn resolve_index(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Option<ResolvedIndex> {
    let state = runtime.state.as_ref()?;
    let entry = index_entry_position(state, handle)?;
    let index = stored_index(state, entry)?;
    let mut public = NvPublic::of(index);
    let ram = if index.attributes & TPMA_NV_ORDERLY != 0 {
        let position = ram_entry_position(&runtime.live.index_orderly_ram, handle)?;
        public.attributes = runtime.live.index_orderly_ram.entries[position].attributes;
        Some(position)
    } else {
        None
    };
    Some(ResolvedIndex { entry, ram, public })
}

pub(in crate::library::tpm2) fn handle_is_defined(runtime: &Tpm2Runtime, handle: u32) -> bool {
    runtime.state.as_ref().is_some_and(|state| {
        state.user_nvram.entries.iter().any(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle: stored, .. }
            | OwnedUserNvramEntry::Persistent { handle: stored, .. } => *stored == handle,
        })
    })
}

pub(in crate::library::tpm2) fn index_is_accessible(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<(), TpmResult> {
    let Some(resolved) = resolve_index(runtime, handle) else {
        return Err(TPM_RC_HANDLE);
    };
    let clear = runtime.live.state_clear.as_ref().ok_or(TPM_RC_FAILURE)?;
    if !clear.sh_enable || !clear.ph_enable_nv {
        if !resolved.is_platform_created() {
            if !clear.sh_enable {
                return Err(TPM_RC_HANDLE);
            }
        } else if !clear.ph_enable_nv {
            return Err(TPM_RC_HANDLE);
        }
    }
    Ok(())
}

pub(in crate::library::tpm2) fn index_auth_value(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Option<&[u8]> {
    let state = runtime.state.as_ref()?;
    let entry = index_entry_position(state, handle)?;
    stored_index(state, entry).map(|index| index.auth_value.as_bytes())
}

pub(in crate::library::tpm2) fn read_index_data(
    runtime: &Tpm2Runtime,
    resolved: &ResolvedIndex,
    offset: usize,
    size: usize,
) -> Result<Vec<u8>, TpmResult> {
    let end = offset.checked_add(size).ok_or(TPM_RC_FAILURE)?;
    let bytes = match resolved.ram {
        Some(position) => runtime
            .live
            .index_orderly_ram
            .entries
            .get(position)
            .map(|entry| entry.data.as_slice())
            .ok_or(TPM_RC_FAILURE)?,
        None => {
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            match state.user_nvram.entries.get(resolved.entry) {
                Some(OwnedUserNvramEntry::NvIndex { data, .. }) => data.as_slice(),
                _ => return Err(TPM_RC_FAILURE),
            }
        }
    };
    bytes
        .get(offset..end)
        .map(<[u8]>::to_vec)
        .ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2) fn read_uint64_data(
    runtime: &Tpm2Runtime,
    resolved: &ResolvedIndex,
) -> Result<u64, TpmResult> {
    let bytes = read_index_data(runtime, resolved, 0, 8)?;
    Ok(u64::from_be_bytes(
        bytes.as_slice().try_into().map_err(|_| TPM_RC_FAILURE)?,
    ))
}

fn used_dynamic_bytes(state: &OwnedPersistentState) -> u64 {
    state
        .user_nvram
        .entries
        .iter()
        .map(OwnedUserNvramEntry::destination_size)
        .sum()
}

fn persistent_object_count(state: &OwnedPersistentState) -> u64 {
    state
        .user_nvram
        .entries
        .iter()
        .filter(|entry| matches!(entry, OwnedUserNvramEntry::Persistent { .. }))
        .count() as u64
}

fn counter_index_count(state: &OwnedPersistentState) -> u64 {
    state
        .user_nvram
        .entries
        .iter()
        .filter(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { index, .. } => is_counter_index(index.attributes),
            OwnedUserNvramEntry::Persistent { .. } => false,
        })
        .count() as u64
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) fn test_dynamic_space(
    state: &OwnedPersistentState,
    size: u64,
    is_index: bool,
    is_counter: bool,
) -> bool {
    let remaining = USER_NVRAM_CAPACITY.saturating_sub(used_dynamic_bytes(state));
    let mut reserved = NV_FORWARD_POINTER_SIZE + NV_LIST_TERMINATOR_SIZE;
    if is_index {
        let persistent = persistent_object_count(state);
        if persistent < MIN_EVICT_OBJECTS {
            reserved += (MIN_EVICT_OBJECTS - persistent) * NV_EVICT_OBJECT_SIZE;
        }
    }
    if !is_index || !is_counter {
        let counters = counter_index_count(state);
        if counters < MIN_COUNTER_INDICES {
            reserved += (MIN_COUNTER_INDICES - counters) * NV_INDEX_COUNTER_SIZE;
        }
    }
    reserved < remaining && size <= remaining && size + reserved <= remaining
}

#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) fn test_orderly_ram_space(
    runtime: &Tpm2Runtime,
    data_size: u64,
) -> bool {
    let used = runtime.live.index_orderly_ram.used_bytes;
    RAM_INDEX_SPACE.saturating_sub(used) >= NV_RAM_HEADER_SIZE + data_size
}

fn recompute_ram_usage(ram: &mut OwnedIndexOrderlyRam) {
    ram.used_bytes = ram
        .entries
        .iter()
        .map(|entry| NV_RAM_HEADER_SIZE + entry.data.len() as u64)
        .sum();
}

pub(in crate::library::tpm2) fn add_index(
    runtime: &mut Tpm2Runtime,
    public: &NvPublic,
    auth_value: Vec<u8>,
) -> Result<(), TpmResult> {
    let orderly = public.attributes & TPMA_NV_ORDERLY != 0;
    let data_size = u64::from(public.data_size);
    let entry_size = SIZEOF_NV_INDEX + if orderly { 0 } else { data_size };

    {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        if !test_dynamic_space(state, entry_size, true, is_counter_index(public.attributes)) {
            return Err(TPM_RC_NV_SPACE);
        }
    }
    if orderly && !test_orderly_ram_space(runtime, data_size) {
        return Err(TPM_RC_NV_SPACE);
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    state.user_nvram.entries.push(OwnedUserNvramEntry::NvIndex {
        declared_entry_size: 0,
        handle: public.nv_index,
        index: public.clone().into_index(auth_value),
        data: vec![
            0u8;
            if orderly {
                0
            } else {
                public.data_size as usize
            }
        ],
    });

    if orderly {
        runtime
            .live
            .index_orderly_ram
            .entries
            .push(OwnedOrderlyRamEntry {
                declared_size: 0,
                handle: public.nv_index,
                attributes: public.attributes,
                data: vec![0u8; public.data_size as usize],
            });
        recompute_ram_usage(&mut runtime.live.index_orderly_ram);
        sync_orderly_ram(runtime)?;
    }
    Ok(())
}

pub(in crate::library::tpm2) fn delete_index(
    runtime: &mut Tpm2Runtime,
    resolved: &ResolvedIndex,
) -> Result<(), TpmResult> {
    if is_counter_index(resolved.attributes()) && resolved.is_written() {
        let value = read_uint64_data(runtime, resolved)?;
        if value > runtime.live.max_nv_counter {
            runtime.live.max_nv_counter = value;
        }
    }
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    let max_count = runtime.live.max_nv_counter;
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    if resolved.entry >= state.user_nvram.entries.len() {
        return Err(TPM_RC_FAILURE);
    }
    state.user_nvram.entries.remove(resolved.entry);
    state.user_nvram.max_count = max_count;

    if let Some(position) = resolved.ram {
        if position >= runtime.live.index_orderly_ram.entries.len() {
            return Err(TPM_RC_FAILURE);
        }
        runtime.live.index_orderly_ram.entries.remove(position);
        recompute_ram_usage(&mut runtime.live.index_orderly_ram);
        sync_orderly_ram(runtime)?;
    }
    Ok(())
}

pub(in crate::library::tpm2) fn sync_orderly_ram(
    runtime: &mut Tpm2Runtime,
) -> Result<(), TpmResult> {
    let ram = runtime.live.index_orderly_ram.clone();
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    state.index_orderly_ram = ram;
    Ok(())
}

pub(in crate::library::tpm2) fn write_index_attributes(
    runtime: &mut Tpm2Runtime,
    resolved: &ResolvedIndex,
    attributes: u32,
) -> Result<(), TpmResult> {
    match resolved.ram {
        Some(position) => {
            let entry = runtime
                .live
                .index_orderly_ram
                .entries
                .get_mut(position)
                .ok_or(TPM_RC_FAILURE)?;
            entry.attributes = attributes;
            Ok(())
        }
        None => {
            let changed = {
                let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
                stored_index(state, resolved.entry)
                    .ok_or(TPM_RC_FAILURE)?
                    .attributes
                    != attributes
            };
            if changed && !runtime.nv_available {
                return Err(TPM_RC_NV_UNAVAILABLE);
            }
            let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
            stored_index_mut(state, resolved.entry)
                .ok_or(TPM_RC_FAILURE)?
                .attributes = attributes;
            Ok(())
        }
    }
}

pub(in crate::library::tpm2) fn write_index_auth(
    runtime: &mut Tpm2Runtime,
    resolved: &ResolvedIndex,
    auth_value: Vec<u8>,
) -> Result<(), TpmResult> {
    let changed = {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        stored_index(state, resolved.entry)
            .ok_or(TPM_RC_FAILURE)?
            .auth_value
            .as_bytes()
            != auth_value.as_slice()
    };
    if changed && !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    stored_index_mut(state, resolved.entry)
        .ok_or(TPM_RC_FAILURE)?
        .auth_value = OwnedSecret::from_vec(auth_value);
    Ok(())
}

pub(in crate::library::tpm2) struct IndexWrite {
    pub(in crate::library::tpm2) offset: usize,
    pub(in crate::library::tpm2) data: Vec<u8>,
}

pub(in crate::library::tpm2) fn write_index_data(
    runtime: &mut Tpm2Runtime,
    resolved: &ResolvedIndex,
    write: IndexWrite,
) -> Result<bool, TpmResult> {
    let data_size = usize::from(resolved.public.data_size);
    let end = write
        .offset
        .checked_add(write.data.len())
        .ok_or(TPM_RC_FAILURE)?;
    if write.offset > data_size || end > data_size {
        return Err(TPM_RC_FAILURE);
    }

    let mut attributes = resolved.attributes();
    let first_write = attributes & TPMA_NV_WRITTEN == 0;
    if first_write {
        attributes |= TPMA_NV_WRITTEN;
        write_index_attributes(runtime, resolved, attributes)?;
    }

    let mut clear_orderly = false;
    match resolved.ram {
        Some(position) => {
            if first_write && is_ordinary_index(attributes) {
                let entry = runtime
                    .live
                    .index_orderly_ram
                    .entries
                    .get_mut(position)
                    .ok_or(TPM_RC_FAILURE)?;
                entry.data.iter_mut().for_each(|byte| *byte = 0);
            }
            let entry = runtime
                .live
                .index_orderly_ram
                .entries
                .get_mut(position)
                .ok_or(TPM_RC_FAILURE)?;
            let slot = entry
                .data
                .get_mut(write.offset..end)
                .ok_or(TPM_RC_FAILURE)?;
            slot.copy_from_slice(&write.data);
            clear_orderly = true;
            if first_write && is_counter_index(attributes) {
                sync_orderly_ram(runtime)?;
            }
        }
        None => {
            let changed = {
                let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
                match state.user_nvram.entries.get(resolved.entry) {
                    Some(OwnedUserNvramEntry::NvIndex { data, .. }) => {
                        data.get(write.offset..end) != Some(write.data.as_slice())
                    }
                    _ => return Err(TPM_RC_FAILURE),
                }
            };
            if changed && !runtime.nv_available {
                return Err(TPM_RC_NV_UNAVAILABLE);
            }
            let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
            let Some(OwnedUserNvramEntry::NvIndex { data, .. }) =
                state.user_nvram.entries.get_mut(resolved.entry)
            else {
                return Err(TPM_RC_FAILURE);
            };
            if first_write && is_ordinary_index(attributes) && write.data.len() < data_size {
                data.iter_mut().for_each(|byte| *byte = NV_ERASED_BYTE);
            }
            let slot = data.get_mut(write.offset..end).ok_or(TPM_RC_FAILURE)?;
            slot.copy_from_slice(&write.data);
        }
    }
    Ok(clear_orderly)
}

#[derive(Debug)]
pub(in crate::library::tpm2) struct NvSnapshot {
    entries: Vec<OwnedUserNvramEntry>,
    required_capacity: u64,
    max_count: u64,
    nv_orderly_ram: OwnedIndexOrderlyRam,
    orderly_state: u16,
    live_orderly_ram: OwnedIndexOrderlyRam,
    max_nv_counter: u64,
}

pub(in crate::library::tpm2) fn snapshot(runtime: &Tpm2Runtime) -> Result<NvSnapshot, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    Ok(NvSnapshot {
        entries: state.user_nvram.entries.clone(),
        required_capacity: state.user_nvram.required_capacity,
        max_count: state.user_nvram.max_count,
        nv_orderly_ram: state.index_orderly_ram.clone(),
        orderly_state: state.persistent.orderly_state,
        live_orderly_ram: runtime.live.index_orderly_ram.clone(),
        max_nv_counter: runtime.live.max_nv_counter,
    })
}

pub(in crate::library::tpm2) fn rollback(runtime: &mut Tpm2Runtime, snapshot: NvSnapshot) {
    runtime.live.index_orderly_ram = snapshot.live_orderly_ram;
    runtime.live.max_nv_counter = snapshot.max_nv_counter;
    if let Some(state) = runtime.state.as_mut() {
        state.user_nvram.entries = snapshot.entries;
        state.user_nvram.required_capacity = snapshot.required_capacity;
        state.user_nvram.max_count = snapshot.max_count;
        state.index_orderly_ram = snapshot.nv_orderly_ram;
        state.persistent.orderly_state = snapshot.orderly_state;
    }
}

pub(in crate::library::tpm2) fn commit(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    state.user_nvram.required_capacity =
        user_nvram_required_capacity(&state.user_nvram.entries).ok_or(TPM_RC_NV_SPACE)?;
    let image = build_nv_image(state).map_err(|_| TPM_RC_FAILURE)?;
    if image == runtime.nv_memory {
        return Ok(());
    }
    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(())
}

pub(in crate::library::tpm2) fn transact<F>(
    runtime: &mut Tpm2Runtime,
    apply: F,
) -> Result<(), TpmResult>
where
    F: FnOnce(&mut Tpm2Runtime) -> Result<(), TpmResult>,
{
    let backup = snapshot(runtime)?;
    match apply(runtime).and_then(|()| commit(runtime)) {
        Ok(()) => Ok(()),
        Err(code) => {
            rollback(runtime, backup);
            Err(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::TPM_ALG_SHA256;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::nv::attributes::{
        TPM_NT_COUNTER, TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_TPM_NT_SHIFT,
    };
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::{commit_manufactured_state, empty_state_runtime};

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x55;
        }
        Ok(())
    }

    fn runtime() -> Tpm2Runtime {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.live.state_clear = Some(crate::library::tpm2::persistent::OwnedStateClearData {
            sh_enable: true,
            eh_enable: true,
            ph_enable_nv: true,
            platform_alg: 0x0010,
            platform_policy: Vec::new(),
            platform_auth: OwnedSecret::from_vec(Vec::new()),
            pcr_save: core::array::from_fn(|_| None),
            pcr_auth_values: core::array::from_fn(|_| OwnedSecret::from_vec(Vec::new())),
        });
        runtime
    }

    fn public(handle: u32, attributes: u32, data_size: u16) -> NvPublic {
        NvPublic {
            nv_index: handle,
            name_alg: TPM_ALG_SHA256,
            attributes: attributes | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD,
            auth_policy: Vec::new(),
            data_size,
        }
    }

    #[test]
    fn added_index_public_area_resolution() {
        let mut runtime = runtime();
        let area = public(0x0100_0001, 0, 32);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, vec![0x01, 0x02])
        })
        .expect("the index is defined");

        let resolved = resolve_index(&runtime, 0x0100_0001).expect("resolves");
        assert_eq!(resolved.public, area);
        assert_eq!(resolved.ram, None);
        assert_eq!(
            index_auth_value(&runtime, 0x0100_0001),
            Some(&[0x01, 0x02][..])
        );
        assert_eq!(
            read_index_data(&runtime, &resolved, 0, 32).unwrap(),
            vec![0u8; 32],
            "the data area starts zeroed"
        );
        assert!(runtime.nv_update_pending);
    }

    #[test]
    fn orderly_index_ram_data_residence() {
        let mut runtime = runtime();
        let area = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .expect("the index is defined");

        let resolved = resolve_index(&runtime, 0x0100_0002).expect("resolves");
        assert_eq!(resolved.ram, Some(0));
        assert_eq!(runtime.live.index_orderly_ram.entries.len(), 1);
        assert_eq!(runtime.live.index_orderly_ram.entries[0].data, vec![0u8; 8]);
        assert_eq!(
            runtime.live.index_orderly_ram.used_bytes,
            NV_RAM_HEADER_SIZE + 8
        );
        assert_eq!(
            runtime.state().index_orderly_ram.entries.len(),
            1,
            "adding an orderly index writes the RAM image back to NV"
        );
        let OwnedUserNvramEntry::NvIndex { data, .. } =
            &runtime.state().user_nvram.entries[resolved.entry]
        else {
            panic!("expected an NV index entry");
        };
        assert!(data.is_empty(), "orderly indexes allocate no NV data");
    }

    #[test]
    fn orderly_attributes_ram_source() {
        let mut runtime = runtime();
        let area = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0002).unwrap();
        transact(&mut runtime, |runtime| {
            write_index_attributes(runtime, &resolved, resolved.attributes() | TPMA_NV_WRITTEN)
        })
        .unwrap();

        assert_ne!(
            resolve_index(&runtime, 0x0100_0002).unwrap().attributes() & TPMA_NV_WRITTEN,
            0
        );
        let stored = stored_index(runtime.state(), resolved.entry).unwrap();
        assert_eq!(
            stored.attributes & TPMA_NV_WRITTEN,
            0,
            "the NV copy of an orderly index keeps its definition-time attributes"
        );
    }

    #[test]
    fn deleted_index_dual_store_removal() {
        let mut runtime = runtime();
        let ordinary = public(0x0100_0001, 0, 32);
        let orderly = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &ordinary, Vec::new())?;
            add_index(runtime, &orderly, Vec::new())
        })
        .unwrap();

        let resolved = resolve_index(&runtime, 0x0100_0002).unwrap();
        transact(&mut runtime, |runtime| delete_index(runtime, &resolved)).unwrap();

        assert!(resolve_index(&runtime, 0x0100_0002).is_none());
        assert!(runtime.live.index_orderly_ram.entries.is_empty());
        assert_eq!(runtime.live.index_orderly_ram.used_bytes, 0);
        assert!(
            resolve_index(&runtime, 0x0100_0001).is_some(),
            "unrelated indexes survive"
        );
    }

    #[test]
    fn written_counter_delete_max_counter_raise() {
        let mut runtime = runtime();
        let counter = public(0x0100_0003, TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &counter, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0003).unwrap();
        transact(&mut runtime, |runtime| {
            write_index_data(
                runtime,
                &resolved,
                IndexWrite {
                    offset: 0,
                    data: 42u64.to_be_bytes().to_vec(),
                },
            )
            .map(|_| ())
        })
        .unwrap();

        let resolved = resolve_index(&runtime, 0x0100_0003).unwrap();
        assert!(resolved.is_written());
        transact(&mut runtime, |runtime| delete_index(runtime, &resolved)).unwrap();
        assert_eq!(runtime.live.max_nv_counter, 42);
        assert_eq!(runtime.state().user_nvram.max_count, 42);
    }

    #[test]
    fn unwritten_counter_delete_max_counter_unchanged() {
        let mut runtime = runtime();
        let counter = public(0x0100_0003, TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &counter, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0003).unwrap();
        transact(&mut runtime, |runtime| delete_index(runtime, &resolved)).unwrap();
        assert_eq!(runtime.live.max_nv_counter, 0);
    }

    #[test]
    fn first_partial_write_ordinary_index_clear() {
        let mut runtime = runtime();
        let area = public(0x0100_0001, 0, 16);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0001).unwrap();
        transact(&mut runtime, |runtime| {
            write_index_data(
                runtime,
                &resolved,
                IndexWrite {
                    offset: 4,
                    data: vec![0xaa; 4],
                },
            )
            .map(|_| ())
        })
        .unwrap();

        let resolved = resolve_index(&runtime, 0x0100_0001).unwrap();
        assert!(resolved.is_written());
        let mut expected = vec![NV_ERASED_BYTE; 16];
        expected[4..8].copy_from_slice(&[0xaa; 4]);
        assert_eq!(
            read_index_data(&runtime, &resolved, 0, 16).unwrap(),
            expected,
            "the first partial write erases the index to the platform erase value"
        );
    }

    #[test]
    fn first_full_write_no_erase() {
        let mut runtime = runtime();
        let area = public(0x0100_0001, 0, 16);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0001).unwrap();
        transact(&mut runtime, |runtime| {
            write_index_data(
                runtime,
                &resolved,
                IndexWrite {
                    offset: 0,
                    data: vec![0xaa; 16],
                },
            )
            .map(|_| ())
        })
        .unwrap();

        let resolved = resolve_index(&runtime, 0x0100_0001).unwrap();
        assert_eq!(
            read_index_data(&runtime, &resolved, 0, 16).unwrap(),
            vec![0xaa; 16]
        );
    }

    #[test]
    fn non_ordinary_first_write_no_erase() {
        let mut runtime = runtime();
        let counter = public(0x0100_0003, TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &counter, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0003).unwrap();
        transact(&mut runtime, |runtime| {
            write_index_data(
                runtime,
                &resolved,
                IndexWrite {
                    offset: 0,
                    data: 1u64.to_be_bytes().to_vec(),
                },
            )
            .map(|_| ())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0003).unwrap();
        assert_eq!(read_uint64_data(&runtime, &resolved).unwrap(), 1);
    }

    #[test]
    fn orderly_index_write_orderly_clear_request() {
        let mut runtime = runtime();
        let area = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .unwrap();
        let resolved = resolve_index(&runtime, 0x0100_0002).unwrap();

        let mut cleared = false;
        transact(&mut runtime, |runtime| {
            cleared = write_index_data(
                runtime,
                &resolved,
                IndexWrite {
                    offset: 0,
                    data: vec![0x11; 8],
                },
            )?;
            Ok(())
        })
        .unwrap();
        assert!(cleared);

        let resolved = resolve_index(&runtime, 0x0100_0002).unwrap();
        assert_eq!(
            read_index_data(&runtime, &resolved, 0, 8).unwrap(),
            vec![0x11; 8]
        );
    }

    #[test]
    fn mutation_failure_field_rollback() {
        let mut runtime = runtime();
        let area = public(0x0100_0001, 0, 32);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .unwrap();
        runtime.nv_update_pending = false;

        let before = snapshot(&runtime).unwrap();
        let before_image = runtime.nv_memory.clone();
        let orderly = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
        let error = transact(&mut runtime, |runtime| {
            add_index(runtime, &orderly, Vec::new())?;
            Err(TPM_RC_NV_SPACE)
        })
        .unwrap_err();
        assert_eq!(error, TPM_RC_NV_SPACE);

        let after = snapshot(&runtime).unwrap();
        assert_eq!(after.entries.len(), before.entries.len());
        assert_eq!(after.required_capacity, before.required_capacity);
        assert_eq!(after.max_count, before.max_count);
        assert_eq!(after.max_nv_counter, before.max_nv_counter);
        assert_eq!(runtime.nv_memory, before_image);
        assert!(!runtime.nv_update_pending);
        assert!(runtime.live.index_orderly_ram.entries.is_empty());
        assert!(runtime.state().index_orderly_ram.entries.is_empty());
        assert!(resolve_index(&runtime, 0x0100_0002).is_none());
    }

    #[test]
    fn commit_serialization_failure_rollback() {
        for pending in [false, true] {
            let mut runtime = runtime();
            let ordinary = public(0x0100_0001, 0, 32);
            transact(&mut runtime, |runtime| {
                add_index(runtime, &ordinary, vec![0x11])
            })
            .unwrap();
            runtime.nv_update_pending = pending;
            let before_image = runtime.nv_memory.clone();
            let before_capacity = runtime.state().user_nvram.required_capacity;

            let orderly = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
            let mut applied = false;
            let error = transact(&mut runtime, |runtime| {
                add_index(runtime, &orderly, vec![0xaa; 65])?;
                applied = true;
                Ok(())
            })
            .unwrap_err();
            assert!(applied, "the failure occurs while committing the mutation");
            assert_eq!(error, TPM_RC_FAILURE);
            assert!(resolve_index(&runtime, orderly.nv_index).is_none());
            assert!(runtime.live.index_orderly_ram.entries.is_empty());
            assert_eq!(runtime.live.index_orderly_ram.used_bytes, 0);
            assert_eq!(
                runtime.state().user_nvram.required_capacity,
                before_capacity
            );
            assert_eq!(runtime.nv_memory, before_image);
            assert_eq!(runtime.nv_update_pending, pending);
            assert_eq!(
                build_nv_image(runtime.state()).unwrap(),
                before_image,
                "the NV data, including the existing index, is restored"
            );
        }
    }

    #[test]
    fn define_unavailable_nv_unchanged() {
        let mut runtime = runtime();
        runtime.nv_available = false;
        let before_image = runtime.nv_memory.clone();
        let area = public(0x0100_0001, 0, 32);
        assert_eq!(
            transact(&mut runtime, |runtime| add_index(
                runtime,
                &area,
                Vec::new()
            )),
            Err(TPM_RC_NV_UNAVAILABLE)
        );
        assert_eq!(runtime.nv_memory, before_image);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn dynamic_space_evict_counter_reservation() {
        let runtime = runtime();
        let state = runtime.state();
        assert_eq!(persistent_object_count(state), 0);
        assert_eq!(counter_index_count(state), 0);

        let reserved = 4
            + NV_LIST_TERMINATOR_SIZE
            + MIN_EVICT_OBJECTS * NV_EVICT_OBJECT_SIZE
            + MIN_COUNTER_INDICES * NV_INDEX_COUNTER_SIZE;
        let remaining = USER_NVRAM_CAPACITY;
        assert!(test_dynamic_space(state, remaining - reserved, true, false));
        assert!(!test_dynamic_space(
            state,
            remaining - reserved + 1,
            true,
            false
        ));
    }

    #[test]
    fn counter_allocation_no_pool_reservation() {
        let runtime = runtime();
        let state = runtime.state();
        let with_counter_pool = 4
            + NV_LIST_TERMINATOR_SIZE
            + MIN_EVICT_OBJECTS * NV_EVICT_OBJECT_SIZE
            + MIN_COUNTER_INDICES * NV_INDEX_COUNTER_SIZE;
        let without = 4 + NV_LIST_TERMINATOR_SIZE + MIN_EVICT_OBJECTS * NV_EVICT_OBJECT_SIZE;
        let remaining = USER_NVRAM_CAPACITY;
        assert!(test_dynamic_space(state, remaining - without, true, true));
        assert!(!test_dynamic_space(
            state,
            remaining - without + 1,
            true,
            true
        ));
        assert!(with_counter_pool > without);
    }

    #[test]
    fn orderly_ram_header_plus_data_size() {
        let mut runtime = runtime();
        assert!(test_orderly_ram_space(
            &runtime,
            RAM_INDEX_SPACE - NV_RAM_HEADER_SIZE
        ));
        assert!(!test_orderly_ram_space(
            &runtime,
            RAM_INDEX_SPACE - NV_RAM_HEADER_SIZE + 1
        ));
        let area = public(0x0100_0002, TPMA_NV_ORDERLY, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &area, Vec::new())
        })
        .unwrap();
        assert!(!test_orderly_ram_space(
            &runtime,
            RAM_INDEX_SPACE - NV_RAM_HEADER_SIZE
        ));
    }

    #[test]
    fn disabled_hierarchy_index_hiding() {
        let mut runtime = runtime();
        let owner = public(0x0100_0001, 0, 8);
        let platform = public(0x0100_0002, TPMA_NV_PLATFORMCREATE, 8);
        transact(&mut runtime, |runtime| {
            add_index(runtime, &owner, Vec::new())?;
            add_index(runtime, &platform, Vec::new())
        })
        .unwrap();

        assert_eq!(index_is_accessible(&runtime, 0x0100_0001), Ok(()));
        assert_eq!(index_is_accessible(&runtime, 0x0100_0002), Ok(()));
        assert_eq!(
            index_is_accessible(&runtime, 0x0100_0003),
            Err(TPM_RC_HANDLE)
        );

        runtime.live.state_clear.as_mut().unwrap().sh_enable = false;
        assert_eq!(
            index_is_accessible(&runtime, 0x0100_0001),
            Err(TPM_RC_HANDLE)
        );
        assert_eq!(
            index_is_accessible(&runtime, 0x0100_0002),
            Ok(()),
            "a platform-created index survives a disabled storage hierarchy"
        );

        runtime.live.state_clear.as_mut().unwrap().sh_enable = true;
        runtime.live.state_clear.as_mut().unwrap().ph_enable_nv = false;
        assert_eq!(
            index_is_accessible(&runtime, 0x0100_0001),
            Ok(()),
            "an owner-created index survives a disabled phEnableNV"
        );
        assert_eq!(
            index_is_accessible(&runtime, 0x0100_0002),
            Err(TPM_RC_HANDLE)
        );
    }

    #[test]
    fn stateless_runtime_panic_safety() {
        let mut runtime = empty_state_runtime();
        assert!(resolve_index(&runtime, 0x0100_0001).is_none());
        assert!(!handle_is_defined(&runtime, 0x0100_0001));
        assert_eq!(index_auth_value(&runtime, 0x0100_0001), None);
        assert_eq!(
            index_is_accessible(&runtime, 0x0100_0001),
            Err(TPM_RC_HANDLE)
        );
        assert_eq!(snapshot(&runtime).unwrap_err(), TPM_RC_FAILURE);
        assert_eq!(commit(&mut runtime), Err(TPM_RC_FAILURE));
    }
}
