use crate::types::TpmResult;

pub const TPM_SUCCESS: TpmResult = 0;
pub const TPM_FAIL: TpmResult = 9;
pub const TPM_SIZE: TpmResult = 23;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_INVALID_POSTINIT: TpmResult = 38;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_BAD_TYPE: TpmResult = 52;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_BAD_LOCALITY: TpmResult = 61;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(crate) const TPM_RETRY: TpmResult = 0x800;

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
pub(in crate::library) const TPM_RC_HIERARCHY: TpmResult = 0x085;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_MODE: TpmResult = 0x089;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_TYPE: TpmResult = 0x08a;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_HANDLE: TpmResult = 0x08b;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_KDF: TpmResult = 0x08c;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_RANGE: TpmResult = 0x08d;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_FAIL: TpmResult = 0x08e;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NONCE: TpmResult = 0x08f;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SCHEME: TpmResult = 0x092;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SELECTOR: TpmResult = 0x098;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SIGNATURE: TpmResult = 0x09b;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SIZE: TpmResult = 0x095;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SYMMETRIC: TpmResult = 0x096;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_TAG: TpmResult = 0x097;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_INSUFFICIENT: TpmResult = 0x09a;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_INTEGRITY: TpmResult = 0x09f;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_KEY: TpmResult = 0x09c;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_PP: TpmResult = 0x090;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_TICKET: TpmResult = 0x0a0;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_RESERVED_BITS: TpmResult = 0x0a1;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_BAD_AUTH: TpmResult = 0x0a2;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_EXPIRED: TpmResult = 0x0a3;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_POLICY_CC: TpmResult = 0x0a4;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_BINDING: TpmResult = 0x0a5;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_CURVE: TpmResult = 0x0a6;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_ECC_POINT: TpmResult = 0x0a7;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_POLICY_FAIL: TpmResult = 0x09d;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_INITIALIZE: TpmResult = 0x100;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_FAILURE: TpmResult = 0x101;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SEQUENCE: TpmResult = 0x103;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_COMMAND_SIZE: TpmResult = 0x142;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_RANGE: TpmResult = 0x146;
#[allow(dead_code)]
pub(in crate::library) const TPM_RC_NV_SIZE: TpmResult = 0x147;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_LOCKED: TpmResult = 0x148;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_AUTHORIZATION: TpmResult = 0x149;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_UNINITIALIZED: TpmResult = 0x14a;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_COMMAND_CODE: TpmResult = 0x143;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_SPACE: TpmResult = 0x14b;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_DEFINED: TpmResult = 0x14c;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_DISABLED: TpmResult = 0x120;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_EXCLUSIVE: TpmResult = 0x121;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_TYPE: TpmResult = 0x124;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_MISSING: TpmResult = 0x125;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_UNAVAILABLE: TpmResult = 0x12f;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_POLICY: TpmResult = 0x126;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_CPHASH: TpmResult = 0x151;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_PCR: TpmResult = 0x127;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_PCR_CHANGED: TpmResult = 0x128;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_AUTH_CONTEXT: TpmResult = 0x145;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NO_RESULT: TpmResult = 0x154;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SENSITIVE: TpmResult = 0x155;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_TOO_MANY_CONTEXTS: TpmResult = 0x12e;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_CONTEXT_GAP: TpmResult = 0x901;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_OBJECT_MEMORY: TpmResult = 0x902;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SESSION_MEMORY: TpmResult = 0x903;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_SESSION_HANDLES: TpmResult = 0x905;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_LOCALITY: TpmResult = 0x907;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_CANCELED: TpmResult = 0x909;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_REFERENCE_H0: TpmResult = 0x910;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_REFERENCE_S0: TpmResult = 0x918;
#[allow(dead_code)]
pub(in crate::library) const TPM_RC_NV_RATE: TpmResult = 0x920;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_LOCKOUT: TpmResult = 0x921;
#[allow(dead_code)]
pub(in crate::library) const TPM_RC_RETRY: TpmResult = 0x922;
#[cfg_attr(not(feature = "tpm2"), allow(dead_code))]
pub(in crate::library) const TPM_RC_NV_UNAVAILABLE: TpmResult = 0x923;

pub const TPM_BUFFER_MAX: u32 = 4096;

#[cfg(all(test, feature = "tpm2"))]
mod tests {
    use super::*;

    const RC_VER1: TpmResult = 0x100;
    const RC_WARN: TpmResult = 0x900;
    const RC_FMT1: TpmResult = 0x080;

    #[test]
    fn version_one_codes_vendored_header_match() {
        assert_eq!(TPM_RC_INITIALIZE, RC_VER1);
        assert_eq!(TPM_RC_FAILURE, RC_VER1 + 0x001);
        assert_eq!(TPM_RC_AUTH_TYPE, RC_VER1 + 0x024);
        assert_eq!(TPM_RC_AUTH_MISSING, RC_VER1 + 0x025);
        assert_eq!(TPM_RC_PCR, RC_VER1 + 0x027);
        assert_eq!(TPM_RC_COMMAND_SIZE, RC_VER1 + 0x042);
        assert_eq!(TPM_RC_COMMAND_CODE, RC_VER1 + 0x043);
        assert_eq!(TPM_RC_AUTH_CONTEXT, RC_VER1 + 0x045);
        assert_eq!(TPM_RC_AUTH_UNAVAILABLE, RC_VER1 + 0x02f);
        assert_eq!(TPM_RC_NV_RANGE, RC_VER1 + 0x046);
        assert_eq!(TPM_RC_NV_SIZE, RC_VER1 + 0x047);
        assert_eq!(TPM_RC_NV_LOCKED, RC_VER1 + 0x048);
        assert_eq!(TPM_RC_NV_AUTHORIZATION, RC_VER1 + 0x049);
        assert_eq!(TPM_RC_NV_UNINITIALIZED, RC_VER1 + 0x04a);
        assert_eq!(TPM_RC_NV_SPACE, RC_VER1 + 0x04b);
        assert_eq!(TPM_RC_NV_DEFINED, RC_VER1 + 0x04c);
        assert_eq!(TPM_RC_NO_RESULT, RC_VER1 + 0x054);
        assert_eq!(TPM_RC_SENSITIVE, RC_VER1 + 0x055);
        assert_eq!(TPM_RC_TOO_MANY_CONTEXTS, RC_VER1 + 0x02e);
        assert_eq!(TPM_RC_DISABLED, RC_VER1 + 0x020);
        assert_eq!(TPM_RC_EXCLUSIVE, RC_VER1 + 0x021);
        assert_eq!(TPM_RC_POLICY, RC_VER1 + 0x026);
        assert_eq!(TPM_RC_CPHASH, RC_VER1 + 0x051);
        assert_eq!(TPM_RC_POLICY & RC_FMT1, 0);
        assert_eq!(TPM_RC_CPHASH & RC_FMT1, 0);
    }

    #[test]
    fn integrity_code_format_one_classification() {
        assert_eq!(TPM_RC_INTEGRITY, RC_FMT1 + 0x01f);
        assert_ne!(TPM_RC_INTEGRITY & RC_FMT1, 0);
        assert_eq!(TPM_RC_SENSITIVE & RC_FMT1, 0);
        assert_eq!(TPM_RC_TOO_MANY_CONTEXTS & RC_FMT1, 0);
    }

    #[test]
    fn warning_codes_vendored_header_match() {
        assert_eq!(TPM_RC_OBJECT_MEMORY, RC_WARN + 0x002);
        assert_eq!(TPM_RC_LOCALITY, RC_WARN + 0x007);
        assert_eq!(TPM_RC_CANCELED, RC_WARN + 0x009);
        assert_eq!(TPM_RC_REFERENCE_H0, RC_WARN + 0x010);
        assert_eq!(TPM_RC_REFERENCE_S0, RC_WARN + 0x018);
        assert_eq!(TPM_RC_NV_RATE, RC_WARN + 0x020);
        assert_eq!(TPM_RC_LOCKOUT, RC_WARN + 0x021);
        assert_eq!(TPM_RC_RETRY, RC_WARN + 0x022);
        assert_eq!(TPM_RC_NV_UNAVAILABLE, RC_WARN + 0x023);
    }

    #[test]
    fn tpm2_retry_warning_library_retry_distinction() {
        assert_eq!(TPM_RC_RETRY, 0x922);
        assert_eq!(TPM_RETRY, 0x800);
        assert_ne!(TPM_RC_RETRY, TPM_RETRY);
    }

    #[test]
    fn nv_specific_code_format_conformance() {
        for code in [
            TPM_RC_NV_RANGE,
            TPM_RC_NV_SIZE,
            TPM_RC_NV_LOCKED,
            TPM_RC_NV_AUTHORIZATION,
            TPM_RC_NV_UNINITIALIZED,
            TPM_RC_AUTH_UNAVAILABLE,
            TPM_RC_NV_RATE,
        ] {
            assert_eq!(
                code & RC_FMT1,
                0,
                "code {code:#05x} takes no handle or parameter number"
            );
        }
        assert_ne!(TPM_RC_PP & RC_FMT1, 0, "TPM_RC_PP is a format-one code");
        assert_eq!(TPM_RC_PP, RC_FMT1 + 0x010);
    }

    #[test]
    fn handle_parameter_number_format_one_only() {
        for code in [
            TPM_RC_NV_SPACE,
            TPM_RC_NV_DEFINED,
            TPM_RC_OBJECT_MEMORY,
            TPM_RC_NV_UNAVAILABLE,
            TPM_RC_REFERENCE_H0,
        ] {
            assert_eq!(code & RC_FMT1, 0, "code {code:#05x} is undecorated");
        }
        for code in [
            TPM_RC_ATTRIBUTES,
            TPM_RC_HIERARCHY,
            TPM_RC_HANDLE,
            TPM_RC_RANGE,
            TPM_RC_VALUE,
            TPM_RC_SELECTOR,
        ] {
            assert_ne!(code & RC_FMT1, 0, "code {code:#05x} takes a modifier");
        }
        assert_eq!(TPM_RC_SELECTOR, RC_FMT1 + 0x018);
    }
}
