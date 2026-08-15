use core::ffi::c_int;

use crate::ffi_types::{TpmResult, TpmlibTpmProperty, TpmlibTpmVersion};

pub const TPM_SUCCESS: TpmResult = 0;
pub const TPM_FAIL: TpmResult = 9;
pub const TPM_SIZE: TpmResult = 23;
pub(in crate::library) const TPM_INVALID_POSTINIT: TpmResult = 38;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_BAD_TYPE: TpmResult = 52;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_BAD_LOCALITY: TpmResult = 61;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RETRY: TpmResult = 0x800;

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_BAD_PARAMETER: TpmResult = 0x003;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_BAD_TAG: TpmResult = 0x01e;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_BAD_VERSION: TpmResult = 0x02e;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_ATTRIBUTES: TpmResult = 0x082;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_HASH: TpmResult = 0x083;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_VALUE: TpmResult = 0x084;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_KEY_SIZE: TpmResult = 0x087;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_MODE: TpmResult = 0x089;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_TYPE: TpmResult = 0x08a;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_HANDLE: TpmResult = 0x08b;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_KDF: TpmResult = 0x08c;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_FAIL: TpmResult = 0x08e;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NONCE: TpmResult = 0x08f;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SCHEME: TpmResult = 0x092;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SIZE: TpmResult = 0x095;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SYMMETRIC: TpmResult = 0x096;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_INSUFFICIENT: TpmResult = 0x09a;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_RESERVED_BITS: TpmResult = 0x0a1;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_BAD_AUTH: TpmResult = 0x0a2;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_CURVE: TpmResult = 0x0a6;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_INITIALIZE: TpmResult = 0x100;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_FAILURE: TpmResult = 0x101;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_COMMAND_SIZE: TpmResult = 0x142;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_UNINITIALIZED: TpmResult = 0x14a;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_COMMAND_CODE: TpmResult = 0x143;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_MISSING: TpmResult = 0x125;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_CONTEXT: TpmResult = 0x145;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NO_RESULT: TpmResult = 0x154;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_LOCALITY: TpmResult = 0x907;
// TODO: Returned by the upstream cancellation checkpoints (AlgorithmTests.c
// CHECK_CANCELED, CryptEccCommitCompute, RSA key generation). No command
// implemented so far reaches one.
#[allow(dead_code)]
pub(in crate::library) const TPM_RC_CANCELED: TpmResult = 0x909;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_REFERENCE_S0: TpmResult = 0x918;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_LOCKOUT: TpmResult = 0x921;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_UNAVAILABLE: TpmResult = 0x923;

pub(in crate::library) const TPMLIB_TPM_VERSION_1_2: TpmlibTpmVersion = 0;
pub(in crate::library) const TPMLIB_TPM_VERSION_2: TpmlibTpmVersion = 1;

#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPMPROP_TPM_RSA_KEY_LENGTH_MAX: TpmlibTpmProperty = 1;
pub(in crate::library) const TPMPROP_TPM_BUFFER_MAX: TpmlibTpmProperty = 2;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPMPROP_TPM_KEY_HANDLES: TpmlibTpmProperty = 3;

pub const TPM_BUFFER_MAX: c_int = 4096;
