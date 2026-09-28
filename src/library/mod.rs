// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

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

#[cfg(feature = "tpm2")]
pub(crate) use command_input::CommandInput;
pub(crate) use constants::TPM_RETRY;
pub use constants::{TPM_BUFFER_MAX, TPM_FAIL, TPM_SIZE, TPM_SUCCESS};
pub use encoded_blob::{EncodedBlobKind, decode_blob};
pub use library_state::{BufferSizeLimits, InformationFlags, Tpm, TpmProperty, TpmVersion};
pub use platform::{DefaultPlatform, Platform};
pub use services::ExternalServices;
pub use state_blob::{StateBlobKind, StateInput, StateOutput, StateValidationMask};
pub use storage::{NoStorage, Storage, StorageLoad, StorageProbe};
