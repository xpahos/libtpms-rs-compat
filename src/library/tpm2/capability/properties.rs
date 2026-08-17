use super::super::live::LiveState;
use super::super::nv::RAM_INDEX_SPACE;
use super::super::orderly::SU_NONE_VALUE;
use super::super::persistent::{OwnedPersistentState, OwnedUserNvramEntry};
use super::super::runtime::Tpm2Runtime;
use super::super::state::{COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS};
use super::super::volatile::{IMPLEMENTATION_PCR, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS};
use super::commands;
use super::{CapabilityPage, MAX_CAP_BUFFER, MAX_CAP_DATA, paginate};

pub(in crate::library::tpm2) const PT_GROUP: u32 = 0x0000_0100;
pub(in crate::library::tpm2) const PT_FIXED: u32 = PT_GROUP;
pub(in crate::library::tpm2) const PT_VAR: u32 = PT_GROUP * 2;

pub(in crate::library::tpm2) const TPM_PT_FAMILY_INDICATOR: u32 = PT_FIXED;
pub(in crate::library::tpm2) const TPM_PT_LEVEL: u32 = PT_FIXED + 1;
pub(in crate::library::tpm2) const TPM_PT_REVISION: u32 = PT_FIXED + 2;
pub(in crate::library::tpm2) const TPM_PT_DAY_OF_YEAR: u32 = PT_FIXED + 3;
pub(in crate::library::tpm2) const TPM_PT_YEAR: u32 = PT_FIXED + 4;
pub(in crate::library::tpm2) const TPM_PT_MANUFACTURER: u32 = PT_FIXED + 5;
pub(in crate::library::tpm2) const TPM_PT_VENDOR_STRING_1: u32 = PT_FIXED + 6;
pub(in crate::library::tpm2) const TPM_PT_VENDOR_STRING_2: u32 = PT_FIXED + 7;
pub(in crate::library::tpm2) const TPM_PT_VENDOR_STRING_3: u32 = PT_FIXED + 8;
pub(in crate::library::tpm2) const TPM_PT_VENDOR_STRING_4: u32 = PT_FIXED + 9;
pub(in crate::library::tpm2) const TPM_PT_VENDOR_TPM_TYPE: u32 = PT_FIXED + 10;
pub(in crate::library::tpm2) const TPM_PT_FIRMWARE_VERSION_1: u32 = PT_FIXED + 11;
pub(in crate::library::tpm2) const TPM_PT_FIRMWARE_VERSION_2: u32 = PT_FIXED + 12;
pub(in crate::library::tpm2) const TPM_PT_INPUT_BUFFER: u32 = PT_FIXED + 13;
pub(in crate::library::tpm2) const TPM_PT_HR_TRANSIENT_MIN: u32 = PT_FIXED + 14;
pub(in crate::library::tpm2) const TPM_PT_HR_PERSISTENT_MIN: u32 = PT_FIXED + 15;
pub(in crate::library::tpm2) const TPM_PT_HR_LOADED_MIN: u32 = PT_FIXED + 16;
pub(in crate::library::tpm2) const TPM_PT_ACTIVE_SESSIONS_MAX: u32 = PT_FIXED + 17;
pub(in crate::library::tpm2) const TPM_PT_PCR_COUNT: u32 = PT_FIXED + 18;
pub(in crate::library::tpm2) const TPM_PT_PCR_SELECT_MIN: u32 = PT_FIXED + 19;
pub(in crate::library::tpm2) const TPM_PT_CONTEXT_GAP_MAX: u32 = PT_FIXED + 20;
pub(in crate::library::tpm2) const TPM_PT_NV_COUNTERS_MAX: u32 = PT_FIXED + 22;
pub(in crate::library::tpm2) const TPM_PT_NV_INDEX_MAX: u32 = PT_FIXED + 23;
pub(in crate::library::tpm2) const TPM_PT_MEMORY: u32 = PT_FIXED + 24;
pub(in crate::library::tpm2) const TPM_PT_CLOCK_UPDATE: u32 = PT_FIXED + 25;
pub(in crate::library::tpm2) const TPM_PT_CONTEXT_HASH: u32 = PT_FIXED + 26;
pub(in crate::library::tpm2) const TPM_PT_CONTEXT_SYM: u32 = PT_FIXED + 27;
pub(in crate::library::tpm2) const TPM_PT_CONTEXT_SYM_SIZE: u32 = PT_FIXED + 28;
pub(in crate::library::tpm2) const TPM_PT_ORDERLY_COUNT: u32 = PT_FIXED + 29;
pub(in crate::library::tpm2) const TPM_PT_MAX_COMMAND_SIZE: u32 = PT_FIXED + 30;
pub(in crate::library::tpm2) const TPM_PT_MAX_RESPONSE_SIZE: u32 = PT_FIXED + 31;
pub(in crate::library::tpm2) const TPM_PT_MAX_DIGEST: u32 = PT_FIXED + 32;
pub(in crate::library::tpm2) const TPM_PT_MAX_OBJECT_CONTEXT: u32 = PT_FIXED + 33;
pub(in crate::library::tpm2) const TPM_PT_MAX_SESSION_CONTEXT: u32 = PT_FIXED + 34;
pub(in crate::library::tpm2) const TPM_PT_PS_FAMILY_INDICATOR: u32 = PT_FIXED + 35;
pub(in crate::library::tpm2) const TPM_PT_PS_LEVEL: u32 = PT_FIXED + 36;
pub(in crate::library::tpm2) const TPM_PT_PS_REVISION: u32 = PT_FIXED + 37;
pub(in crate::library::tpm2) const TPM_PT_PS_DAY_OF_YEAR: u32 = PT_FIXED + 38;
pub(in crate::library::tpm2) const TPM_PT_PS_YEAR: u32 = PT_FIXED + 39;
pub(in crate::library::tpm2) const TPM_PT_SPLIT_MAX: u32 = PT_FIXED + 40;
pub(in crate::library::tpm2) const TPM_PT_TOTAL_COMMANDS: u32 = PT_FIXED + 41;
pub(in crate::library::tpm2) const TPM_PT_LIBRARY_COMMANDS: u32 = PT_FIXED + 42;
pub(in crate::library::tpm2) const TPM_PT_VENDOR_COMMANDS: u32 = PT_FIXED + 43;
pub(in crate::library::tpm2) const TPM_PT_NV_BUFFER_MAX: u32 = PT_FIXED + 44;
pub(in crate::library::tpm2) const TPM_PT_MODES: u32 = PT_FIXED + 45;
pub(in crate::library::tpm2) const TPM_PT_MAX_CAP_BUFFER: u32 = PT_FIXED + 46;

pub(in crate::library::tpm2) const TPM_PT_PERMANENT: u32 = PT_VAR;
pub(in crate::library::tpm2) const TPM_PT_STARTUP_CLEAR: u32 = PT_VAR + 1;
pub(in crate::library::tpm2) const TPM_PT_HR_NV_INDEX: u32 = PT_VAR + 2;
pub(in crate::library::tpm2) const TPM_PT_HR_LOADED: u32 = PT_VAR + 3;
pub(in crate::library::tpm2) const TPM_PT_HR_LOADED_AVAIL: u32 = PT_VAR + 4;
pub(in crate::library::tpm2) const TPM_PT_HR_ACTIVE: u32 = PT_VAR + 5;
pub(in crate::library::tpm2) const TPM_PT_HR_ACTIVE_AVAIL: u32 = PT_VAR + 6;
pub(in crate::library::tpm2) const TPM_PT_HR_TRANSIENT_AVAIL: u32 = PT_VAR + 7;
pub(in crate::library::tpm2) const TPM_PT_HR_PERSISTENT: u32 = PT_VAR + 8;
pub(in crate::library::tpm2) const TPM_PT_HR_PERSISTENT_AVAIL: u32 = PT_VAR + 9;
pub(in crate::library::tpm2) const TPM_PT_NV_COUNTERS: u32 = PT_VAR + 10;
pub(in crate::library::tpm2) const TPM_PT_NV_COUNTERS_AVAIL: u32 = PT_VAR + 11;
pub(in crate::library::tpm2) const TPM_PT_ALGORITHM_SET: u32 = PT_VAR + 12;
pub(in crate::library::tpm2) const TPM_PT_LOADED_CURVES: u32 = PT_VAR + 13;
pub(in crate::library::tpm2) const TPM_PT_LOCKOUT_COUNTER: u32 = PT_VAR + 14;
pub(in crate::library::tpm2) const TPM_PT_MAX_AUTH_FAIL: u32 = PT_VAR + 15;
pub(in crate::library::tpm2) const TPM_PT_LOCKOUT_INTERVAL: u32 = PT_VAR + 16;
pub(in crate::library::tpm2) const TPM_PT_LOCKOUT_RECOVERY: u32 = PT_VAR + 17;
pub(in crate::library::tpm2) const TPM_PT_NV_WRITE_RECOVERY: u32 = PT_VAR + 18;
pub(in crate::library::tpm2) const TPM_PT_AUDIT_COUNTER_0: u32 = PT_VAR + 19;
pub(in crate::library::tpm2) const TPM_PT_AUDIT_COUNTER_1: u32 = PT_VAR + 20;

const SIZEOF_TPMS_TAGGED_PROPERTY: usize = 8;
pub(super) const MAX_TPM_PROPERTIES: usize = MAX_CAP_DATA / SIZEOF_TPMS_TAGGED_PROPERTY;

const TPM_SPEC_FAMILY: u32 = 0x322e_3000;
const TPM_SPEC_LEVEL: u32 = 0;
const TPM_SPEC_VERSION: u32 = 183;
const TPM_SPEC_DAY_OF_YEAR: u32 = 25;
const TPM_SPEC_YEAR: u32 = 2024;

const MANUFACTURER_CODE: u32 = 0x4942_4d00;
const VENDOR_STRING_1: u32 = 0x5357_2020;
const VENDOR_STRING_2: u32 = 0x2054_504d;
const VENDOR_STRING_3: u32 = 0;
const VENDOR_STRING_4: u32 = 0;
const VENDOR_TPM_TYPE: u32 = 1;

const PLATFORM_FAMILY: u32 = 1;
const PLATFORM_LEVEL: u32 = TPM_SPEC_LEVEL;
const PLATFORM_VERSION: u32 = 0x0000_0106;
const PLATFORM_DAY_OF_YEAR: u32 = TPM_SPEC_DAY_OF_YEAR;
const PLATFORM_YEAR: u32 = TPM_SPEC_YEAR;

const MAX_DIGEST_BUFFER: u32 = 1024;
const MAX_NV_BUFFER_SIZE: u32 = 1024;
const MIN_EVICT_OBJECTS: u32 = 7;
const PLATFORM_PCR: u32 = 24;
const PCR_SELECT_MIN: u32 = PLATFORM_PCR.div_ceil(8);
const MAX_NV_INDEX_SIZE: u32 = 2048;
const NV_CLOCK_UPDATE_INTERVAL: u32 = 12;
const MAX_ORDERLY_COUNT: u32 = (1 << 8) - 1;
const FIPS_COMPLIANT_MODES: u32 = 0;
const ECC_CURVE_COUNT: u32 = 8;

const TPM_ALG_AES: u32 = 0x0006;
const TPM_ALG_SHA512: u32 = 0x000d;
const CONTEXT_INTEGRITY_HASH_ALG: u32 = TPM_ALG_SHA512;
const CONTEXT_ENCRYPT_ALG: u32 = TPM_ALG_AES;
const CONTEXT_ENCRYPT_KEY_BITS: u32 = 256;

const SIZEOF_TPMU_HA: u32 = 64;
const SIZEOF_C_OBJECT: u32 = 2608;
const SIZEOF_C_SESSION: u32 = 312;
const SIZEOF_CONTEXT_OVERHEAD: u32 = 8 + 4 + 4 + 2 + 2 + 64 + 8;

const TPMA_MEMORY_SHARED_NV: u32 = 1 << 1;
const TPMA_MEMORY_OBJECT_COPIED_TO_RAM: u32 = 1 << 2;

const TPMA_PERMANENT_OWNER_AUTH_SET: u32 = 1 << 0;
const TPMA_PERMANENT_ENDORSEMENT_AUTH_SET: u32 = 1 << 1;
const TPMA_PERMANENT_LOCKOUT_AUTH_SET: u32 = 1 << 2;
const TPMA_PERMANENT_DISABLE_CLEAR: u32 = 1 << 8;
const TPMA_PERMANENT_IN_LOCKOUT: u32 = 1 << 9;
const TPMA_PERMANENT_TPM_GENERATED_EPS: u32 = 1 << 10;

const TPMA_STARTUP_CLEAR_PH_ENABLE: u32 = 1 << 0;
const TPMA_STARTUP_CLEAR_SH_ENABLE: u32 = 1 << 1;
const TPMA_STARTUP_CLEAR_EH_ENABLE: u32 = 1 << 2;
const TPMA_STARTUP_CLEAR_PH_ENABLE_NV: u32 = 1 << 3;
const TPMA_STARTUP_CLEAR_ORDERLY: u32 = 1 << 31;

const TPMA_NV_TPM_NT_SHIFT: u32 = 4;
const TPMA_NV_TPM_NT_MASK: u32 = 0xf << TPMA_NV_TPM_NT_SHIFT;
const TPM_NT_COUNTER: u32 = 0x1;

const NV_EVICT_OBJECT_SIZE: u64 = 4 + 4 + SIZEOF_C_OBJECT as u64;
const SIZEOF_C_NV_INDEX: u64 = 148;
const NV_INDEX_COUNTER_SIZE: u64 = 4 + SIZEOF_C_NV_INDEX + 8;
const NV_RAM_INDEX_COUNTER_SIZE: u64 = 12 + 8;
const NV_LIST_TERMINATOR_SIZE: u64 = 12;
const MIN_COUNTER_INDICES: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct TaggedProperty {
    pub(in crate::library::tpm2) property: u32,
    pub(in crate::library::tpm2) value: u32,
}

pub(in crate::library::tpm2) fn collect(
    runtime: &Tpm2Runtime,
    state: &OwnedPersistentState,
    starting_property: u32,
    requested_count: u32,
) -> CapabilityPage<TaggedProperty> {
    let start = starting_property.max(PT_FIXED);
    if start >= PT_VAR + PT_GROUP {
        return CapabilityPage::empty();
    }
    let next_group = (start / PT_GROUP) * PT_GROUP + PT_GROUP;
    paginate(
        (start..next_group).filter_map(|property| {
            property_value(runtime, state, property).map(|value| TaggedProperty { property, value })
        }),
        requested_count,
        MAX_TPM_PROPERTIES,
    )
}

fn property_value(
    runtime: &Tpm2Runtime,
    state: &OwnedPersistentState,
    property: u32,
) -> Option<u32> {
    let live = &runtime.live;
    let persistent = &state.persistent;
    match property {
        TPM_PT_FAMILY_INDICATOR => Some(TPM_SPEC_FAMILY),
        TPM_PT_LEVEL => Some(TPM_SPEC_LEVEL),
        TPM_PT_REVISION => Some(TPM_SPEC_VERSION),
        TPM_PT_DAY_OF_YEAR => Some(TPM_SPEC_DAY_OF_YEAR),
        TPM_PT_YEAR => Some(TPM_SPEC_YEAR),
        TPM_PT_MANUFACTURER => Some(MANUFACTURER_CODE),
        TPM_PT_VENDOR_STRING_1 => Some(VENDOR_STRING_1),
        TPM_PT_VENDOR_STRING_2 => Some(VENDOR_STRING_2),
        TPM_PT_VENDOR_STRING_3 => Some(VENDOR_STRING_3),
        TPM_PT_VENDOR_STRING_4 => Some(VENDOR_STRING_4),
        TPM_PT_VENDOR_TPM_TYPE => Some(VENDOR_TPM_TYPE),
        TPM_PT_FIRMWARE_VERSION_1 => Some(persistent.firmware_v1),
        TPM_PT_FIRMWARE_VERSION_2 => Some(persistent.firmware_v2),
        TPM_PT_INPUT_BUFFER => Some(MAX_DIGEST_BUFFER),
        TPM_PT_HR_TRANSIENT_MIN => Some(MAX_LOADED_OBJECTS as u32),
        TPM_PT_HR_PERSISTENT_MIN => Some(MIN_EVICT_OBJECTS),
        TPM_PT_HR_LOADED_MIN => Some(MAX_LOADED_SESSIONS as u32),
        TPM_PT_ACTIVE_SESSIONS_MAX => Some(MAX_ACTIVE_SESSIONS as u32),
        TPM_PT_PCR_COUNT => Some(IMPLEMENTATION_PCR as u32),
        TPM_PT_PCR_SELECT_MIN => Some(PCR_SELECT_MIN),
        TPM_PT_CONTEXT_GAP_MAX => Some(u32::from(live.context_slot_mask)),
        TPM_PT_NV_COUNTERS_MAX => Some(0),
        TPM_PT_NV_INDEX_MAX => Some(MAX_NV_INDEX_SIZE),
        TPM_PT_MEMORY => Some(TPMA_MEMORY_SHARED_NV | TPMA_MEMORY_OBJECT_COPIED_TO_RAM),
        TPM_PT_CLOCK_UPDATE => Some(1 << NV_CLOCK_UPDATE_INTERVAL),
        TPM_PT_CONTEXT_HASH => Some(CONTEXT_INTEGRITY_HASH_ALG),
        TPM_PT_CONTEXT_SYM => Some(CONTEXT_ENCRYPT_ALG),
        TPM_PT_CONTEXT_SYM_SIZE => Some(CONTEXT_ENCRYPT_KEY_BITS),
        TPM_PT_ORDERLY_COUNT => Some(MAX_ORDERLY_COUNT),
        TPM_PT_MAX_COMMAND_SIZE => Some(runtime.buffer_size),
        TPM_PT_MAX_RESPONSE_SIZE => Some(runtime.buffer_size),
        TPM_PT_MAX_DIGEST => Some(SIZEOF_TPMU_HA),
        TPM_PT_MAX_OBJECT_CONTEXT => Some(SIZEOF_CONTEXT_OVERHEAD + SIZEOF_C_OBJECT),
        TPM_PT_MAX_SESSION_CONTEXT => Some(SIZEOF_CONTEXT_OVERHEAD + SIZEOF_C_SESSION),
        TPM_PT_PS_FAMILY_INDICATOR => Some(PLATFORM_FAMILY),
        TPM_PT_PS_LEVEL => Some(PLATFORM_LEVEL),
        TPM_PT_PS_REVISION => Some(PLATFORM_VERSION),
        TPM_PT_PS_DAY_OF_YEAR => Some(PLATFORM_DAY_OF_YEAR),
        TPM_PT_PS_YEAR => Some(PLATFORM_YEAR),
        TPM_PT_SPLIT_MAX => Some(COMMIT_ARRAY_SIZE as u32 * 8),
        TPM_PT_TOTAL_COMMANDS => Some(commands::total_count()),
        TPM_PT_LIBRARY_COMMANDS => Some(commands::library_count()),
        TPM_PT_VENDOR_COMMANDS => Some(commands::vendor_count()),
        TPM_PT_NV_BUFFER_MAX => Some(MAX_NV_BUFFER_SIZE),
        TPM_PT_MODES => Some(FIPS_COMPLIANT_MODES),
        TPM_PT_MAX_CAP_BUFFER => Some(MAX_CAP_BUFFER as u32),
        TPM_PT_PERMANENT => Some(permanent_attributes(state)),
        TPM_PT_STARTUP_CLEAR => Some(startup_clear_attributes(live)),
        TPM_PT_HR_NV_INDEX => Some(nv_index_count(state)),
        TPM_PT_HR_LOADED => {
            Some((MAX_LOADED_SESSIONS as u32).saturating_sub(live.free_session_slots))
        }
        TPM_PT_HR_LOADED_AVAIL => Some(live.free_session_slots),
        TPM_PT_HR_ACTIVE => Some(active_session_count(live)),
        TPM_PT_HR_ACTIVE_AVAIL => Some(MAX_ACTIVE_SESSIONS as u32 - active_session_count(live)),
        TPM_PT_HR_TRANSIENT_AVAIL => Some(unoccupied_object_count(live)),
        TPM_PT_HR_PERSISTENT => Some(persistent_object_count(state)),
        TPM_PT_HR_PERSISTENT_AVAIL => Some(persistent_object_avail(state)),
        TPM_PT_NV_COUNTERS => Some(nv_counter_count(state)),
        TPM_PT_NV_COUNTERS_AVAIL => Some(nv_counter_avail(state, live)),
        TPM_PT_ALGORITHM_SET => Some(persistent.algorithm_set),
        TPM_PT_LOADED_CURVES => Some(ECC_CURVE_COUNT),
        TPM_PT_LOCKOUT_COUNTER => Some(persistent.failed_tries),
        TPM_PT_MAX_AUTH_FAIL => Some(persistent.max_tries),
        TPM_PT_LOCKOUT_INTERVAL => Some(persistent.recovery_time),
        TPM_PT_LOCKOUT_RECOVERY => Some(persistent.lockout_recovery),
        TPM_PT_NV_WRITE_RECOVERY => Some(0),
        TPM_PT_AUDIT_COUNTER_0 => Some((persistent.audit_counter >> 32) as u32),
        TPM_PT_AUDIT_COUNTER_1 => Some(persistent.audit_counter as u32),
        _ => None,
    }
}

fn permanent_attributes(state: &OwnedPersistentState) -> u32 {
    let persistent = &state.persistent;
    let mut flags = TPMA_PERMANENT_TPM_GENERATED_EPS;
    if !persistent.owner_auth.as_bytes().is_empty() {
        flags |= TPMA_PERMANENT_OWNER_AUTH_SET;
    }
    if !persistent.endorsement_auth.as_bytes().is_empty() {
        flags |= TPMA_PERMANENT_ENDORSEMENT_AUTH_SET;
    }
    if !persistent.lockout_auth.as_bytes().is_empty() {
        flags |= TPMA_PERMANENT_LOCKOUT_AUTH_SET;
    }
    if persistent.disable_clear {
        flags |= TPMA_PERMANENT_DISABLE_CLEAR;
    }
    if persistent.failed_tries >= persistent.max_tries {
        flags |= TPMA_PERMANENT_IN_LOCKOUT;
    }
    flags
}

fn startup_clear_attributes(live: &LiveState) -> u32 {
    let mut flags = 0;
    if live.ph_enable {
        flags |= TPMA_STARTUP_CLEAR_PH_ENABLE;
    }
    if let Some(clear) = &live.state_clear {
        if clear.sh_enable {
            flags |= TPMA_STARTUP_CLEAR_SH_ENABLE;
        }
        if clear.eh_enable {
            flags |= TPMA_STARTUP_CLEAR_EH_ENABLE;
        }
        if clear.ph_enable_nv {
            flags |= TPMA_STARTUP_CLEAR_PH_ENABLE_NV;
        }
    }
    if live.prev_orderly_state != SU_NONE_VALUE {
        flags |= TPMA_STARTUP_CLEAR_ORDERLY;
    }
    flags
}

fn active_session_count(live: &LiveState) -> u32 {
    live.state_reset
        .as_ref()
        .map(|reset| {
            reset
                .context_array
                .iter()
                .filter(|&&slot| slot != 0)
                .count() as u32
        })
        .unwrap_or(0)
}

fn unoccupied_object_count(live: &LiveState) -> u32 {
    live.objects
        .iter()
        .filter(|object| object.attributes & super::super::object::ATTR_OCCUPIED == 0)
        .count() as u32
}

fn nv_index_count(state: &OwnedPersistentState) -> u32 {
    state
        .user_nvram
        .entries
        .iter()
        .filter(|entry| matches!(entry, OwnedUserNvramEntry::NvIndex { .. }))
        .count() as u32
}

fn persistent_object_count(state: &OwnedPersistentState) -> u32 {
    state
        .user_nvram
        .entries
        .iter()
        .filter(|entry| matches!(entry, OwnedUserNvramEntry::Persistent { .. }))
        .count() as u32
}

fn nv_counter_count(state: &OwnedPersistentState) -> u32 {
    state
        .user_nvram
        .entries
        .iter()
        .filter(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { index, .. } => {
                (index.attributes & TPMA_NV_TPM_NT_MASK) >> TPMA_NV_TPM_NT_SHIFT == TPM_NT_COUNTER
            }
            OwnedUserNvramEntry::Persistent { .. } => false,
        })
        .count() as u32
}

fn free_nv_bytes(state: &OwnedPersistentState) -> u64 {
    let used: u64 = state
        .user_nvram
        .entries
        .iter()
        .map(OwnedUserNvramEntry::destination_size)
        .sum();
    crate::library::tpm2::nv::USER_NVRAM_CAPACITY.saturating_sub(used)
}

fn persistent_object_avail(state: &OwnedPersistentState) -> u32 {
    let counter_num = u64::from(nv_counter_count(state));
    let mut avail_nv_space = free_nv_bytes(state);
    if counter_num < MIN_COUNTER_INDICES {
        let reserved =
            NV_LIST_TERMINATOR_SIZE + (MIN_COUNTER_INDICES - counter_num) * NV_INDEX_COUNTER_SIZE;
        avail_nv_space = avail_nv_space.saturating_sub(reserved);
    }
    (avail_nv_space / NV_EVICT_OBJECT_SIZE) as u32
}

fn nv_counter_avail(state: &OwnedPersistentState, live: &LiveState) -> u32 {
    let persistent_num = u64::from(persistent_object_count(state));
    let mut avail_nv_space = free_nv_bytes(state);
    if persistent_num < u64::from(MIN_EVICT_OBJECTS) {
        let reserved = NV_LIST_TERMINATOR_SIZE
            + (u64::from(MIN_EVICT_OBJECTS) - persistent_num) * NV_EVICT_OBJECT_SIZE;
        avail_nv_space = avail_nv_space.saturating_sub(reserved);
    }
    let avail_ram_space = RAM_INDEX_SPACE.saturating_sub(live.index_orderly_ram.used_bytes);
    (avail_nv_space / NV_INDEX_COUNTER_SIZE).min(avail_ram_space / NV_RAM_INDEX_COUNTER_SIZE) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi_types::TpmResult;
    use crate::library::CommandInput;
    use crate::library::tpm2::command::{dispatch, parse_command};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::persistent::{
        OwnedAnyObject, OwnedAnyObjectBody, OwnedNvIndex, OwnedSecret, OwnedUserNvramEntry,
    };
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x27;
        }
        Ok(())
    }

    fn started_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let mut bytes = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0, 0,
        ];
        let input = CommandInput::new(bytes.len() as u32, core::mem::take(&mut bytes));
        let parsed = parse_command(&input).expect("the header parses");
        assert_eq!(
            dispatch(&mut runtime, &parsed).code(),
            0,
            "Startup succeeds"
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[track_caller]
    fn value(runtime: &Tpm2Runtime, property: u32) -> u32 {
        let state = runtime.state.as_ref().expect("state present");
        let page = collect(runtime, state, property, 1);
        assert_eq!(page.entries.len(), 1, "property {property:#x} is defined");
        assert_eq!(page.entries[0].property, property);
        page.entries[0].value
    }

    #[track_caller]
    fn page_of(runtime: &Tpm2Runtime, start: u32, count: u32) -> CapabilityPage<TaggedProperty> {
        let state = runtime.state.as_ref().expect("state present");
        collect(runtime, state, start, count)
    }

    const ORACLE_FIXED: [(u32, u32); 45] = [
        (0x100, 0x322e_3000),
        (0x101, 0),
        (0x102, 183),
        (0x103, 25),
        (0x104, 2024),
        (0x105, 0x4942_4d00),
        (0x106, 0x5357_2020),
        (0x107, 0x2054_504d),
        (0x108, 0),
        (0x109, 0),
        (0x10a, 1),
        (0x10b, 0x2024_0125),
        (0x10c, 0x0012_0000),
        (0x10d, 0x400),
        (0x10e, 3),
        (0x10f, 7),
        (0x110, 3),
        (0x111, 0x40),
        (0x112, 24),
        (0x113, 3),
        (0x114, 0xffff),
        (0x116, 0),
        (0x117, 0x800),
        (0x118, 6),
        (0x119, 0x1000),
        (0x11a, 0xd),
        (0x11b, 6),
        (0x11c, 0x100),
        (0x11d, 0xff),
        (0x11e, 0x1000),
        (0x11f, 0x1000),
        (0x120, 0x40),
        (0x121, 0xa8c),
        (0x122, 0x194),
        (0x123, 1),
        (0x124, 0),
        (0x125, 0x106),
        (0x126, 25),
        (0x127, 2024),
        (0x128, 0x80),
        (0x12c, 0x400),
        (0x12d, 0),
        (0x12e, 0x400),
        (0x129, 31),
        (0x12a, 31),
    ];

    #[test]
    fn fixed_properties_match_the_oracle_values() {
        let runtime = started_runtime();
        for (property, expected) in ORACLE_FIXED {
            assert_eq!(
                value(&runtime, property),
                expected,
                "property {property:#x}"
            );
        }
        assert_eq!(value(&runtime, TPM_PT_VENDOR_COMMANDS), 0);
    }

    #[test]
    fn the_command_and_response_size_properties_follow_the_configured_buffer_size() {
        use crate::library::tpm2::buffer_size::{DEFAULT_BUFFER_SIZE, MIN_BUFFER_SIZE};

        let mut runtime = started_runtime();
        assert_eq!(
            value(&runtime, TPM_PT_MAX_COMMAND_SIZE),
            DEFAULT_BUFFER_SIZE
        );
        assert_eq!(
            value(&runtime, TPM_PT_MAX_RESPONSE_SIZE),
            DEFAULT_BUFFER_SIZE
        );

        runtime.buffer_size = MIN_BUFFER_SIZE;
        assert_eq!(value(&runtime, TPM_PT_MAX_COMMAND_SIZE), MIN_BUFFER_SIZE);
        assert_eq!(value(&runtime, TPM_PT_MAX_RESPONSE_SIZE), MIN_BUFFER_SIZE);
        assert_eq!(
            value(&runtime, TPM_PT_MAX_CAP_BUFFER),
            MAX_CAP_BUFFER as u32,
            "the capability buffer is independent of the configured size"
        );
    }

    #[test]
    fn the_full_fixed_group_is_returned_in_order() {
        let runtime = started_runtime();
        let page = page_of(&runtime, 0, 1000);
        assert!(!page.more_data);
        let ids: Vec<u32> = page.entries.iter().map(|entry| entry.property).collect();
        let mut expected: Vec<u32> = (0x100..=0x12e).collect();
        expected.retain(|&pt| pt != 0x115);
        assert_eq!(
            ids, expected,
            "46 defined fixed properties with a gap at 0x115"
        );
    }

    #[test]
    fn the_full_variable_group_is_returned_in_order() {
        let runtime = started_runtime();
        let page = page_of(&runtime, PT_VAR, 1000);
        assert!(!page.more_data);
        let ids: Vec<u32> = page.entries.iter().map(|entry| entry.property).collect();
        let expected: Vec<u32> = (0x200..=0x214).collect();
        assert_eq!(ids, expected);
    }

    #[test]
    fn fresh_variable_properties_match_the_oracle_values() {
        let runtime = started_runtime();
        let expected = [
            (0x200, 0x400),
            (0x201, 0x8000_000f),
            (0x202, 0),
            (0x203, 0),
            (0x204, 3),
            (0x205, 0),
            (0x206, 0x40),
            (0x207, 3),
            (0x208, 0),
            (0x209, 0x40),
            (0x20a, 0),
            (0x20b, 25),
            (0x20c, 0),
            (0x20d, 8),
            (0x20e, 0),
            (0x20f, 3),
            (0x210, 0x3e8),
            (0x211, 0x3e8),
            (0x212, 0),
            (0x213, 0),
            (0x214, 0),
        ];
        for (property, value_expected) in expected {
            assert_eq!(
                value(&runtime, property),
                value_expected,
                "property {property:#x}"
            );
        }
    }

    #[test]
    fn a_start_below_the_fixed_group_clamps_to_pt_fixed() {
        let runtime = started_runtime();
        let page = page_of(&runtime, 0x50, 2);
        assert!(page.more_data);
        assert_eq!(page.entries[0].property, TPM_PT_FAMILY_INDICATOR);
        assert_eq!(page.entries[1].property, TPM_PT_LEVEL);
    }

    #[test]
    fn the_gap_at_0x115_is_skipped() {
        let runtime = started_runtime();
        let page = page_of(&runtime, 0x115, 2);
        assert_eq!(page.entries[0].property, TPM_PT_NV_COUNTERS_MAX);
        assert_eq!(page.entries[1].property, TPM_PT_NV_INDEX_MAX);
        assert!(page.more_data);
    }

    #[test]
    fn the_scan_never_crosses_the_group_boundary() {
        let runtime = started_runtime();

        let page = page_of(&runtime, TPM_PT_MAX_CAP_BUFFER, 5);
        assert_eq!(page.entries.len(), 1, "the last fixed property");
        assert!(!page.more_data, "the variable group is not scanned");

        let page = page_of(&runtime, TPM_PT_MAX_CAP_BUFFER + 1, 5);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);

        let page = page_of(&runtime, 0x1ff, 5);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn starts_at_or_beyond_the_end_of_the_variable_group_are_empty() {
        let runtime = started_runtime();
        for start in [0x215u32, 0x2ff, 0x300, 0x1000, u32::MAX] {
            let page = page_of(&runtime, start, 5);
            assert!(page.entries.is_empty(), "start {start:#x}");
            assert!(!page.more_data, "start {start:#x}");
        }

        let page = page_of(&runtime, TPM_PT_AUDIT_COUNTER_1, 5);
        assert_eq!(page.entries.len(), 1, "the last variable property");
        assert!(!page.more_data);
    }

    #[test]
    fn count_zero_reports_more_data_only_when_a_property_remains() {
        let runtime = started_runtime();

        let page = page_of(&runtime, PT_FIXED, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = page_of(&runtime, 0x2f0, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn oversized_counts_return_the_whole_group() {
        let runtime = started_runtime();
        let page = page_of(&runtime, PT_FIXED, u32::MAX);
        assert_eq!(page.entries.len(), 46);
        assert!(!page.more_data);
    }

    #[test]
    fn pagination_within_the_variable_group_reports_more_data() {
        let runtime = started_runtime();
        let page = page_of(&runtime, PT_VAR, 3);
        let ids: Vec<u32> = page.entries.iter().map(|entry| entry.property).collect();
        assert_eq!(ids, [0x200, 0x201, 0x202]);
        assert!(page.more_data);
    }

    #[test]
    fn lockout_values_track_the_persistent_state() {
        let mut runtime = started_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.failed_tries = 5;
            persistent.max_tries = 5;
            persistent.recovery_time = 77;
            persistent.lockout_recovery = 88;
        }
        assert_eq!(value(&runtime, TPM_PT_LOCKOUT_COUNTER), 5);
        assert_eq!(value(&runtime, TPM_PT_MAX_AUTH_FAIL), 5);
        assert_eq!(value(&runtime, TPM_PT_LOCKOUT_INTERVAL), 77);
        assert_eq!(value(&runtime, TPM_PT_LOCKOUT_RECOVERY), 88);
        assert_eq!(
            value(&runtime, TPM_PT_PERMANENT) & (1 << 9),
            1 << 9,
            "failedTries >= maxTries sets inLockout"
        );
    }

    #[test]
    fn permanent_attributes_track_auths_and_disable_clear() {
        let mut runtime = started_runtime();
        assert_eq!(value(&runtime, TPM_PT_PERMANENT), 0x400);
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.owner_auth = OwnedSecret::from_vec(vec![1; 20]);
            persistent.endorsement_auth = OwnedSecret::from_vec(vec![2; 20]);
            persistent.lockout_auth = OwnedSecret::from_vec(vec![3; 20]);
            persistent.disable_clear = true;
        }
        assert_eq!(value(&runtime, TPM_PT_PERMANENT), 0x400 | 0x100 | 0x7);
    }

    #[test]
    fn startup_clear_attributes_track_the_live_state() {
        let mut runtime = started_runtime();
        assert_eq!(value(&runtime, TPM_PT_STARTUP_CLEAR), 0x8000_000f);

        runtime.live.ph_enable = false;
        runtime.live.state_clear.as_mut().unwrap().sh_enable = false;
        assert_eq!(value(&runtime, TPM_PT_STARTUP_CLEAR), 0x8000_000c);

        runtime.live.prev_orderly_state = 0xffff;
        assert_eq!(
            value(&runtime, TPM_PT_STARTUP_CLEAR),
            0xc,
            "SU_NONE clears the orderly bit"
        );
    }

    #[test]
    fn session_counts_track_the_live_state() {
        let mut runtime = started_runtime();
        runtime.live.free_session_slots = 1;
        assert_eq!(value(&runtime, TPM_PT_HR_LOADED), 2);
        assert_eq!(value(&runtime, TPM_PT_HR_LOADED_AVAIL), 1);

        let reset = runtime.live.state_reset.as_mut().unwrap();
        reset.context_array[3] = 9;
        reset.context_array[7] = 2;
        assert_eq!(value(&runtime, TPM_PT_HR_ACTIVE), 2);
        assert_eq!(value(&runtime, TPM_PT_HR_ACTIVE_AVAIL), 62);
    }

    #[test]
    fn context_gap_max_tracks_the_live_slot_mask() {
        let mut runtime = started_runtime();
        assert_eq!(value(&runtime, TPM_PT_CONTEXT_GAP_MAX), 0xffff);
        runtime.live.context_slot_mask = 0xff;
        assert_eq!(value(&runtime, TPM_PT_CONTEXT_GAP_MAX), 0xff);
    }

    #[test]
    fn transient_availability_tracks_occupied_objects() {
        let mut runtime = started_runtime();
        assert_eq!(value(&runtime, TPM_PT_HR_TRANSIENT_AVAIL), 3);
        runtime.live.objects[0].attributes |= 1 << 15;
        runtime.live.objects[2].attributes |= 1 << 15;
        assert_eq!(value(&runtime, TPM_PT_HR_TRANSIENT_AVAIL), 1);
    }

    fn counter_index_entry(handle: u32, data_len: usize) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::NvIndex {
            declared_entry_size: 0,
            handle,
            index: OwnedNvIndex {
                nv_index: handle,
                name_alg: 0x000b,
                attributes: TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT,
                auth_policy: Vec::new(),
                data_size: data_len as u16,
                auth_value: OwnedSecret::from_vec(Vec::new()),
            },
            data: vec![0; data_len],
        }
    }

    fn ordinary_index_entry(handle: u32, data_len: usize) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::NvIndex {
            declared_entry_size: 0,
            handle,
            index: OwnedNvIndex {
                nv_index: handle,
                name_alg: 0x000b,
                attributes: 0,
                auth_policy: Vec::new(),
                data_size: data_len as u16,
                auth_value: OwnedSecret::from_vec(Vec::new()),
            },
            data: vec![0; data_len],
        }
    }

    fn persistent_entry(handle: u32) -> OwnedUserNvramEntry {
        OwnedUserNvramEntry::Persistent {
            declared_entry_size: 0,
            handle,
            object: OwnedAnyObject {
                attributes: 1 << 15,
                body: OwnedAnyObjectBody::Unoccupied,
            },
            object_destination_size: 2608,
        }
    }

    #[test]
    fn nv_handle_counts_track_the_user_nvram() {
        let mut runtime = started_runtime();
        {
            let user_nvram = &mut runtime.state.as_mut().unwrap().user_nvram;
            user_nvram.entries.push(counter_index_entry(0x0100_0001, 8));
            user_nvram
                .entries
                .push(ordinary_index_entry(0x0100_0002, 32));
            user_nvram.entries.push(persistent_entry(0x8100_0001));
        }
        assert_eq!(value(&runtime, TPM_PT_HR_NV_INDEX), 2);
        assert_eq!(value(&runtime, TPM_PT_HR_PERSISTENT), 1);
        assert_eq!(value(&runtime, TPM_PT_NV_COUNTERS), 1);
    }

    #[test]
    fn persistent_availability_follows_the_upstream_formula() {
        let mut runtime = started_runtime();
        assert_eq!(value(&runtime, TPM_PT_HR_PERSISTENT_AVAIL), 64);

        runtime
            .state
            .as_mut()
            .unwrap()
            .user_nvram
            .entries
            .push(persistent_entry(0x8100_0001));
        assert_eq!(
            value(&runtime, TPM_PT_HR_PERSISTENT_AVAIL),
            63,
            "(171200 - 2616 - 12 - 8*160) / 2616"
        );

        for _ in 0..8 {
            runtime
                .state
                .as_mut()
                .unwrap()
                .user_nvram
                .entries
                .push(counter_index_entry(0x0100_0009, 8));
        }
        assert_eq!(
            value(&runtime, TPM_PT_HR_PERSISTENT_AVAIL),
            63,
            "eight counters drop the reserve but consume 8*160 bytes"
        );
    }

    #[test]
    fn counter_availability_is_limited_by_orderly_ram() {
        let mut runtime = started_runtime();
        assert_eq!(value(&runtime, TPM_PT_NV_COUNTERS_AVAIL), 25);

        runtime.live.index_orderly_ram.used_bytes = 100;
        assert_eq!(
            value(&runtime, TPM_PT_NV_COUNTERS_AVAIL),
            20,
            "(512 - 100) / 20"
        );

        runtime.live.index_orderly_ram.used_bytes = 0;
        for index in 0..7 {
            runtime
                .state
                .as_mut()
                .unwrap()
                .user_nvram
                .entries
                .push(persistent_entry(0x8100_0000 + index));
        }
        assert_eq!(
            value(&runtime, TPM_PT_NV_COUNTERS_AVAIL),
            25,
            "seven evict objects drop the NV reserve; RAM still limits"
        );
    }

    #[test]
    fn audit_counter_words_track_the_persistent_state() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().persistent.audit_counter = 0x1122_3344_5566_7788;
        assert_eq!(value(&runtime, TPM_PT_AUDIT_COUNTER_0), 0x1122_3344);
        assert_eq!(value(&runtime, TPM_PT_AUDIT_COUNTER_1), 0x5566_7788);
    }

    #[test]
    fn firmware_versions_track_the_persistent_state() {
        let mut runtime = started_runtime();
        {
            let persistent = &mut runtime.state.as_mut().unwrap().persistent;
            persistent.firmware_v1 = 0xdead_beef;
            persistent.firmware_v2 = 0x0102_0304;
        }
        assert_eq!(value(&runtime, TPM_PT_FIRMWARE_VERSION_1), 0xdead_beef);
        assert_eq!(value(&runtime, TPM_PT_FIRMWARE_VERSION_2), 0x0102_0304);
    }

    #[test]
    fn algorithm_set_tracks_the_persistent_state() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().persistent.algorithm_set = 0x55;
        assert_eq!(value(&runtime, TPM_PT_ALGORITHM_SET), 0x55);
    }

    #[test]
    fn the_capacity_constant_matches_the_upstream_padded_struct_size() {
        assert_eq!(MAX_TPM_PROPERTIES, 127);
    }
}
