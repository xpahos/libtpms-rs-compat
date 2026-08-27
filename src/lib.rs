pub mod ffi;
pub mod library;
pub mod types;
mod version;

#[path = "generated/tpm_library_abi.rs"]
pub mod tpm_library_abi;

#[path = "generated/tpm_tis_abi.rs"]
pub mod tpm_tis_abi;
