mod cancel;
#[cfg(feature = "tpm2")]
mod command_input;
mod constants;
mod encoded_blob;
mod library_state;
mod platform;
mod preloaded_state;
mod services;
mod state_blob;
mod storage;
#[cfg(feature = "tpm2")]
mod tpm2;

use core::ffi::c_int;
use std::sync::Arc;

use crate::types::{TpmResult, TpmlibInfoFlags, TpmlibTpmProperty, TpmlibTpmVersion};
#[cfg(feature = "tpm2")]
pub(crate) use command_input::CommandInput;
pub(crate) use constants::TPM_RETRY;
pub use constants::{TPM_BUFFER_MAX, TPM_FAIL, TPM_SIZE, TPM_SUCCESS};
pub use encoded_blob::{EncodedBlobKind, decode_blob};
pub use library_state::BufferSizeLimits;
use library_state::Library;
pub use platform::{NoPlatform, Platform};
pub use services::ExternalServices;
pub use state_blob::{StateBlobKind, StateInput, StateOutput, StateValidationMask};
pub use storage::{NoStorage, Storage, StorageLoad, StorageOperation, StorageProbe};

pub fn get_version() -> u32 {
    crate::version::TPM_LIBRARY_VERSION
}

pub fn choose_tpm_version(version: TpmlibTpmVersion) -> TpmResult {
    Library::global().choose_tpm_version(version)
}

pub fn main_init() -> TpmResult {
    Library::global().main_init()
}

pub fn terminate() {
    Library::global().terminate();
}

pub fn cancel_command() -> TpmResult {
    Library::global().cancel_command()
}

#[cfg(feature = "tpm2")]
pub(crate) fn tpm2_selected() -> bool {
    Library::global().tpm2_selected()
}

#[cfg(feature = "tpm2")]
pub(crate) fn process(command: &CommandInput) -> Result<Vec<u8>, TpmResult> {
    Library::global().process(command)
}

pub fn get_tpm_property(prop: TpmlibTpmProperty) -> Option<c_int> {
    Library::global().get_tpm_property(prop)
}

pub fn get_info(flags: TpmlibInfoFlags) -> Option<String> {
    Library::global().get_info(flags)
}

pub fn register_storage(storage: Arc<dyn Storage>) {
    Library::global().register_storage(storage);
}

pub fn register_platform(platform: Arc<dyn Platform>) {
    Library::global().register_platform(platform);
}

pub fn register_external_services(services: ExternalServices) {
    Library::global().register_external_services(services);
}

pub fn set_profile(profile: Option<&[u8]>) -> TpmResult {
    Library::global().set_profile(profile)
}

pub fn set_buffer_size(wanted_size: u32) -> Option<BufferSizeLimits> {
    Library::global().set_buffer_size(wanted_size)
}

pub fn was_manufactured() -> bool {
    Library::global().was_manufactured()
}

pub fn volatile_all_store() -> Result<Vec<u8>, TpmResult> {
    Library::global().volatile_all_store()
}

pub fn validate_state(mask: StateValidationMask) -> TpmResult {
    Library::global().validate_state(mask)
}

pub fn set_state(kind: StateBlobKind, input: StateInput) -> TpmResult {
    Library::global().set_state(kind, input)
}

pub fn get_state(kind: StateBlobKind) -> Result<StateOutput, TpmResult> {
    Library::global().get_state(kind)
}

pub fn tis_established_get() -> Result<bool, TpmResult> {
    Library::global().tis_established_get()
}

pub fn tis_established_reset() -> TpmResult {
    Library::global().tis_established_reset()
}

pub fn tis_hash_start() -> TpmResult {
    Library::global().tis_hash_start()
}

pub fn tis_hash_data(data: &[u8]) -> TpmResult {
    Library::global().tis_hash_data(data)
}

pub fn tis_hash_end() -> TpmResult {
    Library::global().tis_hash_end()
}

#[cfg(all(test, feature = "tpm2"))]
pub(crate) fn stage_empty_permanent_state_for_tests() {
    Library::global().stage_empty_state(state_blob::StateBlobKind::Permanent);
}
