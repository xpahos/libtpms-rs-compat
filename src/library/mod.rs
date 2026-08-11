mod cached_state;
mod constants;
mod state;
#[cfg(feature = "tpm2")]
mod tpm2;

use core::ffi::c_int;

use crate::ffi_types::{
    LibtpmsCallbacks, TpmResult, TpmlibInfoFlags, TpmlibTpmProperty, TpmlibTpmVersion,
};
pub use constants::{TPM_FAIL, TPM_SUCCESS};
use state::Library;

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

pub fn get_tpm_property(prop: TpmlibTpmProperty) -> Option<c_int> {
    Library::global().get_tpm_property(prop)
}

pub fn get_info(flags: TpmlibInfoFlags) -> Option<String> {
    Library::global().get_info(flags)
}

pub fn register_callbacks(callbacks: LibtpmsCallbacks) {
    Library::global().register_callbacks(callbacks);
}

pub fn set_profile(profile: Option<&[u8]>) -> TpmResult {
    Library::global().set_profile(profile)
}

pub fn was_manufactured() -> bool {
    Library::global().was_manufactured()
}
