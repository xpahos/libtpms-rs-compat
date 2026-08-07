//! Rust reimplementation of the libtpms ABI.
//!
//! Handwritten code lives directly under `src/`; generated code lives under
//! `src/generated/` and must never be edited manually (see `make generate-abi`).

pub mod ffi_types;

#[path = "generated/tpm_library_abi.rs"]
pub mod tpm_library_abi;
