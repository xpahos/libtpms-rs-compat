mod host;
mod image;
mod index;
mod layout;
mod orderly_ram;
mod user;

pub(in crate::library) use host::HostNvram;
pub(super) use host::{NvramLoad, PermanentStateProbe};
pub(super) use image::{
    WireWriter, any_object_image, build_nv_image, command_bitmap_image, marshal_sym_def_object,
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
