pub(super) const TPM_ALG_ERROR: u16 = 0x0000;
pub(super) const TPM_ALG_RSA: u16 = 0x0001;
pub(super) const TPM_ALG_TDES: u16 = 0x0003;
pub(super) const TPM_ALG_SHA1: u16 = 0x0004;
pub(super) const TPM_ALG_HMAC: u16 = 0x0005;
pub(super) const TPM_ALG_AES: u16 = 0x0006;
pub(super) const TPM_ALG_MGF1: u16 = 0x0007;
pub(super) const TPM_ALG_KEYEDHASH: u16 = 0x0008;
pub(super) const TPM_ALG_XOR: u16 = 0x000a;
pub(super) const TPM_ALG_SHA256: u16 = 0x000b;
pub(super) const TPM_ALG_SHA384: u16 = 0x000c;
pub(super) const TPM_ALG_SHA512: u16 = 0x000d;
pub(super) const TPM_ALG_NULL: u16 = 0x0010;
pub(super) const TPM_ALG_RSASSA: u16 = 0x0014;
pub(super) const TPM_ALG_RSAES: u16 = 0x0015;
pub(super) const TPM_ALG_RSAPSS: u16 = 0x0016;
pub(super) const TPM_ALG_OAEP: u16 = 0x0017;
pub(super) const TPM_ALG_ECDSA: u16 = 0x0018;
pub(super) const TPM_ALG_ECDH: u16 = 0x0019;
pub(super) const TPM_ALG_ECDAA: u16 = 0x001a;
pub(super) const TPM_ALG_SM2: u16 = 0x001b;
pub(super) const TPM_ALG_ECSCHNORR: u16 = 0x001c;
pub(super) const TPM_ALG_ECMQV: u16 = 0x001d;
pub(super) const TPM_ALG_KDF1_SP800_56A: u16 = 0x0020;
pub(super) const TPM_ALG_KDF2: u16 = 0x0021;
pub(super) const TPM_ALG_KDF1_SP800_108: u16 = 0x0022;
pub(super) const TPM_ALG_ECC: u16 = 0x0023;
pub(super) const TPM_ALG_SYMCIPHER: u16 = 0x0025;
pub(super) const TPM_ALG_CAMELLIA: u16 = 0x0026;
pub(super) const TPM_ALG_CMAC: u16 = 0x003f;
pub(super) const TPM_ALG_CTR: u16 = 0x0040;
pub(super) const TPM_ALG_OFB: u16 = 0x0041;
pub(super) const TPM_ALG_CBC: u16 = 0x0042;
pub(super) const TPM_ALG_CFB: u16 = 0x0043;
pub(super) const TPM_ALG_ECB: u16 = 0x0044;

pub(in crate::library::tpm2) fn algorithm_enabled(
    profile_algorithms: &[u8],
    profile_name: &[u8],
) -> bool {
    profile_algorithms
        .split(|&byte| byte == b',')
        .any(|token| token == profile_name)
}

pub(in crate::library::tpm2) const fn hash_profile_name(algorithm: u16) -> Option<&'static [u8]> {
    match algorithm {
        TPM_ALG_SHA1 => Some(b"sha1"),
        TPM_ALG_SHA256 => Some(b"sha256"),
        TPM_ALG_SHA384 => Some(b"sha384"),
        TPM_ALG_SHA512 => Some(b"sha512"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_matching_is_exact() {
        assert!(algorithm_enabled(b"sha384", b"sha384"));
        assert!(!algorithm_enabled(b"sha384", b"sha3"));
        assert!(!algorithm_enabled(b"sha3", b"sha384"));
        assert!(!algorithm_enabled(b"ecb2,2ecb", b"ecb"));
        assert!(algorithm_enabled(b"a,ecb,b", b"ecb"));
    }

    #[test]
    fn every_supported_hash_maps_to_its_profile_token() {
        assert_eq!(hash_profile_name(TPM_ALG_SHA1), Some(b"sha1".as_slice()));
        assert_eq!(
            hash_profile_name(TPM_ALG_SHA256),
            Some(b"sha256".as_slice())
        );
        assert_eq!(
            hash_profile_name(TPM_ALG_SHA384),
            Some(b"sha384".as_slice())
        );
        assert_eq!(
            hash_profile_name(TPM_ALG_SHA512),
            Some(b"sha512".as_slice())
        );
    }

    #[test]
    fn alg_null_has_no_profile_token() {
        assert_eq!(hash_profile_name(TPM_ALG_NULL), None);
    }

    #[test]
    fn non_hash_algorithms_have_no_profile_token() {
        assert_eq!(hash_profile_name(TPM_ALG_AES), None);
        assert_eq!(hash_profile_name(TPM_ALG_RSA), None);
        assert_eq!(hash_profile_name(TPM_ALG_HMAC), None);
    }

    #[test]
    fn unknown_algorithm_ids_have_no_profile_token() {
        assert_eq!(hash_profile_name(0x0012), None);
        assert_eq!(hash_profile_name(0x0027), None);
        assert_eq!(hash_profile_name(0xffff), None);
    }
}
