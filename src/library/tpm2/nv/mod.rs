mod attributes;
mod host;
mod image;
mod index;
pub(in crate::library::tpm2) mod layout;
mod orderly_ram;
mod public_area;
mod store;
mod user;

pub(in crate::library::tpm2) use attributes::{
    MAX_ORDERLY_COUNT, TPM_NT_BITS, TPM_NT_COUNTER, TPM_NT_EXTEND, TPM_NT_ORDINARY,
    TPM_NT_PIN_FAIL, TPM_NT_PIN_PASS, TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_CLEAR_STCLEAR,
    TPMA_NV_GLOBALLOCK, TPMA_NV_NO_DA, TPMA_NV_ORDERLY, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE,
    TPMA_NV_PLATFORMCREATE, TPMA_NV_POLICY_DELETE, TPMA_NV_POLICYREAD, TPMA_NV_POLICYWRITE,
    TPMA_NV_PPREAD, TPMA_NV_PPWRITE, TPMA_NV_READ_STCLEAR, TPMA_NV_READLOCKED,
    TPMA_NV_WRITE_STCLEAR, TPMA_NV_WRITEALL, TPMA_NV_WRITEDEFINE, TPMA_NV_WRITELOCKED,
    TPMA_NV_WRITTEN, is_bits_index, is_counter_index, is_extend_index, is_pin_index, nv_index_type,
    startup_attributes,
};
pub(in crate::library::tpm2) use index::MAX_NV_INDEX_SIZE;
pub(in crate::library::tpm2) use public_area::{
    NvPublic, checked_auth_value, is_nv_index_handle, marshal_sized_nv_public, nv_index_name,
    parse_sized_nv_public, strip_trailing_zeros,
};

pub(in crate::library::tpm2) use store::{
    IndexWrite, ResolvedIndex, add_index, delete_index, handle_is_defined, index_auth_value,
    index_is_accessible, read_index_data, read_uint64_data, resolve_index, sync_orderly_ram,
    transact, write_index_attributes, write_index_auth, write_index_data,
};

#[cfg(test)]
pub(in crate::library::tpm2) use attributes::TPMA_NV_TPM_NT_SHIFT;
#[cfg(test)]
pub(in crate::library::tpm2) use public_area::{NV_INDEX_FIRST, NV_INDEX_LAST};

pub(in crate::library) use host::HostNvram;
pub(super) use host::{NvramLoad, NvramWrite, PermanentStateProbe};
pub(super) use image::{
    WireWriter, any_object_image, build_nv_image, command_bitmap_image, marshal_sym_def_object,
    persistent_object_image,
};
pub(super) use index::{NV_INDEX_MAGIC, NvIndex};
pub(super) use layout::{
    COMPRESSED_COMMAND_BITS, NV_INDEX_RAM_DATA, SIZEOF_NV_INDEX as NATIVE_SIZEOF_NV_INDEX,
};
pub(super) use orderly_ram::{
    INDEX_ORDERLY_RAM_MAGIC, IndexOrderlyRam, NV_RAM_HEADER_SIZE, OrderlyRamEntry, RAM_INDEX_SPACE,
    parse_index_orderly_ram,
};
pub(super) use user::{
    SIZEOF_NV_INDEX, USER_NVRAM_CAPACITY, USER_NVRAM_MAGIC, UserNvram, UserNvramEntry,
    parse_user_nvram,
};

#[cfg(test)]
pub(super) use index::NvIndexFixture;
#[cfg(test)]
pub(super) use layout::{
    DRBG_MAGIC_FIELD, DRBG_RESEED_COUNTER, DRBG_SEED_FIELD, NV_MEMORY_SIZE, NV_ORDERLY_DATA,
    NV_STATE_RESET_DATA, OD_CLOCK, OD_CLOCK_SAFE, OD_DRBG_STATE, PD_AUDIT_COMMANDS,
    PD_AUDIT_HASH_ALG, PD_EP_SEED, PD_EP_SEED_COMPAT_LEVEL, PD_FIRMWARE_V1, PD_FIRMWARE_V2,
    PD_LOCKOUT_AUTH_ENABLED, PD_LOCKOUT_RECOVERY, PD_MAX_TRIES, PD_ORDERLY_STATE, PD_PCR_ALLOCATED,
    PD_PP_LIST, PD_RECOVERY_TIME, PD_RESET_COUNT, PD_TOTAL_RESET_COUNT,
};
#[cfg(test)]
pub(super) use orderly_ram::IndexOrderlyRamFixture;
#[cfg(test)]
pub(super) use user::UserNvramFixture;
