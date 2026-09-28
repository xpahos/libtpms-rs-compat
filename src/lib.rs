// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

pub mod ffi;
pub mod library;
pub mod types;
mod version;

#[path = "generated/tpm_library_abi.rs"]
pub mod tpm_library_abi;

#[path = "generated/tpm_tis_abi.rs"]
pub mod tpm_tis_abi;
