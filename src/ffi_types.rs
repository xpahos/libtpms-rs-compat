//! Handwritten FFI support types for the libtpms ABI.
//!
//! The generated stubs in `src/generated/` reference these names. They mirror
//! the typedefs and enums of `libtpms/include/libtpms/tpm_types.h` and
//! `tpm_library.h` under Rust-style names; only exported function symbol
//! names matter for the ABI, so type names are free to be idiomatic. The
//! generator (`scripts/generate_libtpms_abi.py`) has an explicit table of the
//! C type names it accepts; adding a new type there requires adding its Rust
//! counterpart here.

/// C `TPM_RESULT` (`uint32_t`).
pub type TpmResult = u32;
/// C `TPM_BOOL` (`unsigned char`).
pub type TpmBool = u8;
/// C `TPM_MODIFIER_INDICATOR` (`uint32_t`).
pub type TpmModifierIndicator = u32;

// C enums passed by value have the ABI of `int`. Aliases avoid inventing
// `#[repr]` enum layouts.

/// C `typedef enum TPMLIB_TPMVersion`.
pub type TpmlibTpmVersion = core::ffi::c_int;
/// C `enum TPMLIB_TPMProperty`.
pub type TpmlibTpmProperty = core::ffi::c_int;
/// C `enum TPMLIB_InfoFlags`.
pub type TpmlibInfoFlags = core::ffi::c_int;
/// C `enum TPMLIB_BlobType`.
pub type TpmlibBlobType = core::ffi::c_int;
/// C `enum TPMLIB_StateType`.
pub type TpmlibStateType = core::ffi::c_int;

/// Opaque stand-in for C `struct libtpms_callbacks`.
///
/// The C layout (7 function pointers plus `sizeOfStruct`) is not mirrored
/// here yet; this type is only valid behind a pointer.
#[repr(C)]
pub struct LibtpmsCallbacks {
    _opaque: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}
