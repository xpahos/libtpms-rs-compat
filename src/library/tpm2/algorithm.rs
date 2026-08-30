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

pub(in crate::library::tpm2) const ECC_CURVE_SHORTCUTS: [(&[u8], &[u8]); 2] =
    [(b"ecc-nist", b"ecc-nist-p"), (b"ecc-bn", b"ecc-bn-p")];

pub(in crate::library::tpm2) const fn curve_profile_name(curve_id: u16) -> Option<&'static [u8]> {
    match curve_id {
        0x0001 => Some(b"ecc-nist-p192"),
        0x0002 => Some(b"ecc-nist-p224"),
        0x0003 => Some(b"ecc-nist-p256"),
        0x0004 => Some(b"ecc-nist-p384"),
        0x0005 => Some(b"ecc-nist-p521"),
        0x0010 => Some(b"ecc-bn-p256"),
        0x0011 => Some(b"ecc-bn-p638"),
        0x0020 => Some(b"ecc-sm2-p256"),
        _ => None,
    }
}

pub(in crate::library::tpm2) fn curve_enabled(profile_algorithms: &[u8], curve_id: u16) -> bool {
    let Some(name) = curve_profile_name(curve_id) else {
        return false;
    };
    profile_algorithms.split(|&byte| byte == b',').any(|token| {
        token == name
            || ECC_CURVE_SHORTCUTS
                .iter()
                .any(|&(shortcut, prefix)| token == shortcut && name.starts_with(prefix))
    })
}

pub(in crate::library::tpm2) const fn algorithm_default_min_key_size(algorithm: u16) -> u16 {
    match algorithm {
        TPM_ALG_RSA => 1024,
        TPM_ALG_ECC => 192,
        TPM_ALG_TDES | TPM_ALG_AES | TPM_ALG_CAMELLIA => 128,
        _ => 0,
    }
}

pub(in crate::library::tpm2) fn algorithm_min_key_size(
    profile_algorithms: &[u8],
    algorithm: u16,
) -> u16 {
    let Some(name) = algorithm_profile_name(algorithm) else {
        return 0;
    };
    for token in profile_algorithms.split(|&byte| byte == b',') {
        let Some(digits) = token
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(b"-min-size="))
        else {
            continue;
        };
        let mut value: u32 = 0;
        let mut seen = false;
        for &byte in digits {
            if !byte.is_ascii_digit() {
                return algorithm_default_min_key_size(algorithm);
            }
            value = value
                .saturating_mul(10)
                .saturating_add(u32::from(byte - b'0'));
            seen = true;
        }
        if seen {
            return u16::try_from(value).unwrap_or(u16::MAX);
        }
    }
    algorithm_default_min_key_size(algorithm)
}

pub(in crate::library::tpm2) const fn algorithm_profile_name(
    algorithm: u16,
) -> Option<&'static [u8]> {
    match algorithm {
        TPM_ALG_RSA => Some(b"rsa"),
        TPM_ALG_TDES => Some(b"tdes"),
        TPM_ALG_HMAC => Some(b"hmac"),
        TPM_ALG_AES => Some(b"aes"),
        TPM_ALG_MGF1 => Some(b"mgf1"),
        TPM_ALG_KEYEDHASH => Some(b"keyedhash"),
        TPM_ALG_XOR => Some(b"xor"),
        TPM_ALG_RSASSA => Some(b"rsassa"),
        TPM_ALG_RSAES => Some(b"rsaes"),
        TPM_ALG_RSAPSS => Some(b"rsapss"),
        TPM_ALG_OAEP => Some(b"oaep"),
        TPM_ALG_ECDSA => Some(b"ecdsa"),
        TPM_ALG_ECDH => Some(b"ecdh"),
        TPM_ALG_ECDAA => Some(b"ecdaa"),
        TPM_ALG_SM2 => Some(b"sm2"),
        TPM_ALG_ECSCHNORR => Some(b"ecschnorr"),
        TPM_ALG_ECMQV => Some(b"ecmqv"),
        TPM_ALG_KDF1_SP800_56A => Some(b"kdf1-sp800-56a"),
        TPM_ALG_KDF2 => Some(b"kdf2"),
        TPM_ALG_KDF1_SP800_108 => Some(b"kdf1-sp800-108"),
        TPM_ALG_ECC => Some(b"ecc"),
        TPM_ALG_SYMCIPHER => Some(b"symcipher"),
        TPM_ALG_CAMELLIA => Some(b"camellia"),
        TPM_ALG_CMAC => Some(b"cmac"),
        TPM_ALG_CTR => Some(b"ctr"),
        TPM_ALG_OFB => Some(b"ofb"),
        TPM_ALG_CBC => Some(b"cbc"),
        TPM_ALG_CFB => Some(b"cfb"),
        TPM_ALG_ECB => Some(b"ecb"),
        _ => hash_profile_name(algorithm),
    }
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
    fn exact_token_matching() {
        assert!(algorithm_enabled(b"sha384", b"sha384"));
        assert!(!algorithm_enabled(b"sha384", b"sha3"));
        assert!(!algorithm_enabled(b"sha3", b"sha384"));
        assert!(!algorithm_enabled(b"ecb2,2ecb", b"ecb"));
        assert!(algorithm_enabled(b"a,ecb,b", b"ecb"));
    }

    #[test]
    fn supported_hash_profile_token_mapping() {
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
    fn alg_null_no_profile_token() {
        assert_eq!(hash_profile_name(TPM_ALG_NULL), None);
    }

    #[test]
    fn non_hash_algorithm_no_profile_token() {
        assert_eq!(hash_profile_name(TPM_ALG_AES), None);
        assert_eq!(hash_profile_name(TPM_ALG_RSA), None);
        assert_eq!(hash_profile_name(TPM_ALG_HMAC), None);
    }

    #[test]
    fn compiled_curve_profile_token_mapping() {
        assert_eq!(
            curve_profile_name(0x0001),
            Some(b"ecc-nist-p192".as_slice())
        );
        assert_eq!(
            curve_profile_name(0x0002),
            Some(b"ecc-nist-p224".as_slice())
        );
        assert_eq!(
            curve_profile_name(0x0003),
            Some(b"ecc-nist-p256".as_slice())
        );
        assert_eq!(
            curve_profile_name(0x0004),
            Some(b"ecc-nist-p384".as_slice())
        );
        assert_eq!(
            curve_profile_name(0x0005),
            Some(b"ecc-nist-p521".as_slice())
        );
        assert_eq!(curve_profile_name(0x0010), Some(b"ecc-bn-p256".as_slice()));
        assert_eq!(curve_profile_name(0x0011), Some(b"ecc-bn-p638".as_slice()));
        assert_eq!(curve_profile_name(0x0020), Some(b"ecc-sm2-p256".as_slice()));
        assert_eq!(curve_profile_name(0x0000), None);
        assert_eq!(curve_profile_name(0x0006), None);
        assert_eq!(curve_profile_name(0xffff), None);
    }

    #[test]
    fn family_shortcut_all_family_curves() {
        for curve in [0x0001u16, 0x0002, 0x0003, 0x0004, 0x0005] {
            assert!(curve_enabled(b"ecc,ecc-nist", curve), "curve {curve:#06x}");
            assert!(!curve_enabled(b"ecc,ecc-bn", curve), "curve {curve:#06x}");
        }
        for curve in [0x0010u16, 0x0011] {
            assert!(curve_enabled(b"ecc,ecc-bn", curve), "curve {curve:#06x}");
            assert!(!curve_enabled(b"ecc,ecc-nist", curve), "curve {curve:#06x}");
        }
    }

    #[test]
    fn sm2_curve_no_family_shortcut() {
        assert!(!curve_enabled(b"ecc,ecc-nist,ecc-bn", 0x0020));
        assert!(curve_enabled(b"ecc,ecc-sm2-p256", 0x0020));
    }

    #[test]
    fn individual_curve_token_single_curve_scope() {
        assert!(curve_enabled(b"ecc,ecc-nist-p384", 0x0004));
        assert!(!curve_enabled(b"ecc,ecc-nist-p384", 0x0003));
        assert!(!curve_enabled(b"ecc,ecc-nist-p384", 0x0005));
    }

    #[test]
    fn family_prefix_no_cross_family_match() {
        assert!(!curve_enabled(b"ecc-nist", 0x0010), "ecc-bn-p256");
        assert!(!curve_enabled(b"ecc-bn", 0x0001), "ecc-nist-p192");
        assert!(!curve_enabled(b"", 0x0004));
    }

    #[test]
    fn default_min_key_size_vendored_table_match() {
        assert_eq!(algorithm_default_min_key_size(TPM_ALG_RSA), 1024);
        assert_eq!(algorithm_default_min_key_size(TPM_ALG_ECC), 192);
        assert_eq!(algorithm_default_min_key_size(TPM_ALG_AES), 128);
        assert_eq!(algorithm_default_min_key_size(TPM_ALG_CAMELLIA), 128);
        assert_eq!(algorithm_default_min_key_size(TPM_ALG_TDES), 128);
        assert_eq!(algorithm_default_min_key_size(TPM_ALG_SHA256), 0);
    }

    #[test]
    fn min_size_token_default_override() {
        let profile = b"rsa,rsa-min-size=3072,ecc,ecc-min-size=384,aes,aes-min-size=256,\
tdes,tdes-min-size=192,camellia,camellia-min-size=256";
        assert_eq!(algorithm_min_key_size(profile, TPM_ALG_RSA), 3072);
        assert_eq!(algorithm_min_key_size(profile, TPM_ALG_ECC), 384);
        assert_eq!(algorithm_min_key_size(profile, TPM_ALG_AES), 256);
        assert_eq!(algorithm_min_key_size(profile, TPM_ALG_TDES), 192);
        assert_eq!(algorithm_min_key_size(profile, TPM_ALG_CAMELLIA), 256);
    }

    #[test]
    fn missing_min_size_token_default_preservation() {
        assert_eq!(algorithm_min_key_size(b"rsa,ecc,aes", TPM_ALG_RSA), 1024);
        assert_eq!(algorithm_min_key_size(b"rsa,ecc,aes", TPM_ALG_ECC), 192);
        assert_eq!(algorithm_min_key_size(b"rsa,ecc,aes", TPM_ALG_AES), 128);
    }

    #[test]
    fn min_size_token_no_cross_algorithm_borrowing() {
        assert_eq!(
            algorithm_min_key_size(b"aes-min-size=256", TPM_ALG_RSA),
            1024
        );
        assert_eq!(
            algorithm_min_key_size(b"rsa-min-size=3072", TPM_ALG_AES),
            128
        );
    }

    #[test]
    fn malformed_min_size_token_default_fallback() {
        assert_eq!(algorithm_min_key_size(b"rsa-min-size=", TPM_ALG_RSA), 1024);
        assert_eq!(algorithm_min_key_size(b"rsa-min-size=x", TPM_ALG_RSA), 1024);
        assert_eq!(
            algorithm_min_key_size(b"rsa-min-size=99999999", TPM_ALG_RSA),
            u16::MAX
        );
    }

    #[test]
    fn unknown_algorithm_id_no_profile_token() {
        assert_eq!(hash_profile_name(0x0012), None);
        assert_eq!(hash_profile_name(0x0027), None);
        assert_eq!(hash_profile_name(0xffff), None);
    }
}
