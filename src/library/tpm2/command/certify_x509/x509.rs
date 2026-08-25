use super::super::super::algorithm::{
    TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_RSA, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA1,
    TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512,
};
use super::super::super::crypto::RSA_DEFAULT_PUBLIC_EXPONENT;
use super::super::super::persistent::{OwnedPublicId, OwnedTpmtPublic};
use super::super::super::public::PublicParms;
use super::super::super::signature::{SigScheme, pss_salt_size};
use super::super::super::template::digest_size;
use super::der::{
    DerWriter, TAG_APPLICATION_SPECIFIC, TAG_BIT_STRING, TAG_CONSTRUCTED_SEQUENCE,
    TAG_OBJECT_IDENTIFIER,
};

pub(super) const OID_KEY_USAGE_EXTENSION: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x0f];
pub(super) const OID_TCG_TPMA_OBJECT: [u8; 9] =
    [0x06, 0x07, 0x67, 0x81, 0x05, 0x0a, 0x01, 0x01, 0x01];

const OID_SHA1: [u8; 7] = [0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_SHA256: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
const OID_SHA384: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
];
const OID_SHA512: [u8; 11] = [
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
];

const OID_PKCS1_SHA1: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
];
const OID_PKCS1_SHA256: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];
const OID_PKCS1_SHA384: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
];
const OID_PKCS1_SHA512: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
];

const OID_ECDSA_SHA1: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
const OID_ECDSA_SHA256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];

const OID_MGF1: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
];
const OID_RSAPSS: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
];
const OID_PKCS1_PUB: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

const OID_ECC_PUBLIC: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ECC_NIST_P192: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01];
const OID_ECC_NIST_P224: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21];
const OID_ECC_NIST_P256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_ECC_NIST_P384: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const OID_ECC_NIST_P521: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];
const OID_ECC_BN_P638: [u8; 1] = [0x00];
const OID_ECC_SM2_P256: [u8; 10] = [0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d];

const TPM_ECC_NIST_P192: u16 = 0x0001;
const TPM_ECC_NIST_P224: u16 = 0x0002;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ECC_NIST_P384: u16 = 0x0004;
const TPM_ECC_NIST_P521: u16 = 0x0005;
const TPM_ECC_BN_P638: u16 = 0x0011;
const TPM_ECC_SM2_P256: u16 = 0x0020;

fn hash_oid(hash_alg: u16) -> Option<&'static [u8]> {
    match hash_alg {
        TPM_ALG_SHA1 => Some(&OID_SHA1),
        TPM_ALG_SHA256 => Some(&OID_SHA256),
        TPM_ALG_SHA384 => Some(&OID_SHA384),
        TPM_ALG_SHA512 => Some(&OID_SHA512),
        _ => None,
    }
}

fn pkcs1_oid(hash_alg: u16) -> Option<&'static [u8]> {
    match hash_alg {
        TPM_ALG_SHA1 => Some(&OID_PKCS1_SHA1),
        TPM_ALG_SHA256 => Some(&OID_PKCS1_SHA256),
        TPM_ALG_SHA384 => Some(&OID_PKCS1_SHA384),
        TPM_ALG_SHA512 => Some(&OID_PKCS1_SHA512),
        _ => None,
    }
}

fn ecdsa_oid(hash_alg: u16) -> Option<&'static [u8]> {
    match hash_alg {
        TPM_ALG_SHA1 => Some(&OID_ECDSA_SHA1),
        TPM_ALG_SHA256 => Some(&OID_ECDSA_SHA256),
        TPM_ALG_SHA384 => Some(&OID_ECDSA_SHA384),
        TPM_ALG_SHA512 => Some(&OID_ECDSA_SHA512),
        _ => None,
    }
}

fn curve_oid(curve_id: u16) -> Option<&'static [u8]> {
    match curve_id {
        TPM_ECC_NIST_P192 => Some(&OID_ECC_NIST_P192),
        TPM_ECC_NIST_P224 => Some(&OID_ECC_NIST_P224),
        TPM_ECC_NIST_P256 => Some(&OID_ECC_NIST_P256),
        TPM_ECC_NIST_P384 => Some(&OID_ECC_NIST_P384),
        TPM_ECC_NIST_P521 => Some(&OID_ECC_NIST_P521),
        TPM_ECC_BN_P638 => Some(&OID_ECC_BN_P638),
        TPM_ECC_SM2_P256 => Some(&OID_ECC_SM2_P256),
        _ => None,
    }
}

fn usable_curve_oid(curve_id: u16) -> Option<&'static [u8]> {
    let oid = curve_oid(curve_id)?;
    match oid.first() {
        Some(&TAG_OBJECT_IDENTIFIER) => Some(oid),
        _ => None,
    }
}

pub(super) fn push_algorithm_identifier_sequence(writer: &mut DerWriter, oid: &[u8]) -> i32 {
    writer.start();
    writer.push_null();
    writer.push_oid(oid);
    writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE)
}

pub(super) fn public_key_is_encodable(public: &OwnedTpmtPublic) -> bool {
    match public.object_type {
        TPM_ALG_RSA => true,
        TPM_ALG_ECC => match public.parameters {
            PublicParms::Ecc { curve_id, .. } => usable_curve_oid(curve_id).is_some(),
            _ => false,
        },
        _ => false,
    }
}

pub(super) fn add_public_key(writer: &mut DerWriter, public: &OwnedTpmtPublic) -> i32 {
    match public.object_type {
        TPM_ALG_RSA => add_public_rsa(writer, public),
        TPM_ALG_ECC => add_public_ecc(writer, public),
        _ => 0,
    }
}

fn add_public_rsa(writer: &mut DerWriter, public: &OwnedTpmtPublic) -> i32 {
    let OwnedPublicId::Rsa(modulus) = &public.unique else {
        return 0;
    };
    let exponent = match public.parameters {
        PublicParms::Rsa { exponent, .. } if exponent != 0 => exponent,
        PublicParms::Rsa { .. } => RSA_DEFAULT_PUBLIC_EXPONENT,
        _ => return 0,
    };
    writer.start();
    writer.start();
    writer.start();
    writer.push_uint(exponent);
    writer.push_integer(modulus);
    writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
    writer.end_encapsulation(TAG_BIT_STRING);
    push_algorithm_identifier_sequence(writer, &OID_PKCS1_PUB);
    writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE)
}

fn add_public_ecc(writer: &mut DerWriter, public: &OwnedTpmtPublic) -> i32 {
    let PublicParms::Ecc { curve_id, .. } = public.parameters else {
        return 0;
    };
    let Some(oid) = usable_curve_oid(curve_id) else {
        return 0;
    };
    let OwnedPublicId::Ecc { x, y } = &public.unique else {
        return 0;
    };
    writer.start();
    push_point(writer, x, y);
    writer.start();
    writer.push_oid(oid);
    writer.push_oid(&OID_ECC_PUBLIC);
    writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
    writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE)
}

fn push_point(writer: &mut DerWriter, x: &[u8], y: &[u8]) -> i32 {
    writer.start();
    writer.push_bytes(y);
    writer.push_bytes(x);
    writer.push_byte(0x04);
    writer.end_encapsulation(TAG_BIT_STRING)
}

pub(super) fn signing_algorithm_is_encodable(public: &OwnedTpmtPublic, scheme: &SigScheme) -> bool {
    if digest_size(scheme.hash_alg).is_none() {
        return false;
    }
    match public.object_type {
        TPM_ALG_RSA => match scheme.scheme {
            TPM_ALG_RSASSA => pkcs1_oid(scheme.hash_alg).is_some(),
            TPM_ALG_RSAPSS => true,
            _ => false,
        },
        TPM_ALG_ECC => match scheme.scheme {
            TPM_ALG_ECDSA => ecdsa_oid(scheme.hash_alg).is_some(),
            _ => false,
        },
        _ => false,
    }
}

pub(super) fn add_signing_algorithm(
    writer: &mut DerWriter,
    public: &OwnedTpmtPublic,
    scheme: &SigScheme,
) -> i32 {
    match public.object_type {
        TPM_ALG_RSA => add_signing_algorithm_rsa(writer, public, scheme),
        TPM_ALG_ECC => add_signing_algorithm_ecc(scheme, writer),
        _ => 0,
    }
}

fn add_signing_algorithm_rsa(
    writer: &mut DerWriter,
    public: &OwnedTpmtPublic,
    scheme: &SigScheme,
) -> i32 {
    let Some(hash_size) = digest_size(scheme.hash_alg) else {
        return 0;
    };
    match scheme.scheme {
        TPM_ALG_RSASSA => match pkcs1_oid(scheme.hash_alg) {
            Some(oid) => push_algorithm_identifier_sequence(writer, oid),
            None => 0,
        },
        TPM_ALG_RSAPSS => {
            if scheme.hash_alg == TPM_ALG_SHA1 {
                return push_algorithm_identifier_sequence(writer, &OID_RSAPSS);
            }
            let Some(hash) = hash_oid(scheme.hash_alg) else {
                return 0;
            };
            let modulus_size = match &public.unique {
                OwnedPublicId::Rsa(modulus) => modulus.len(),
                _ => return 0,
            };
            let salt = pss_salt_size(hash_size, modulus_size);
            writer.start();
            writer.start();
            writer.start();
            writer.push_uint(salt as u32);
            writer.end_encapsulation(TAG_APPLICATION_SPECIFIC + 2);
            writer.start();
            writer.start();
            push_algorithm_identifier_sequence(writer, hash);
            writer.push_oid(&OID_MGF1);
            writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
            writer.end_encapsulation(TAG_APPLICATION_SPECIFIC + 1);
            writer.start();
            push_algorithm_identifier_sequence(writer, hash);
            writer.end_encapsulation(TAG_APPLICATION_SPECIFIC);
            writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
            writer.push_oid(&OID_RSAPSS);
            writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE)
        }
        _ => 0,
    }
}

fn add_signing_algorithm_ecc(scheme: &SigScheme, writer: &mut DerWriter) -> i32 {
    if digest_size(scheme.hash_alg).is_none() || scheme.scheme != TPM_ALG_ECDSA {
        return 0;
    }
    let Some(oid) = ecdsa_oid(scheme.hash_alg) else {
        return 0;
    };
    writer.start();
    writer.push_oid(oid);
    writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE)
}

#[cfg(test)]
mod tests {
    use super::super::super::super::crypto::COMPILED_HASHES;
    use super::*;

    #[test]
    fn every_compiled_hash_carries_the_three_object_identifiers() {
        for (hash_alg, _) in COMPILED_HASHES {
            assert!(hash_oid(hash_alg).is_some(), "hash {hash_alg:#06x}");
            assert!(pkcs1_oid(hash_alg).is_some(), "pkcs1 {hash_alg:#06x}");
            assert!(ecdsa_oid(hash_alg).is_some(), "ecdsa {hash_alg:#06x}");
        }
        assert!(hash_oid(0x0012).is_none());
    }

    #[test]
    fn every_object_identifier_is_self_describing() {
        for oid in [
            &OID_SHA1[..],
            &OID_SHA256,
            &OID_SHA384,
            &OID_SHA512,
            &OID_PKCS1_SHA1,
            &OID_PKCS1_SHA256,
            &OID_PKCS1_SHA384,
            &OID_PKCS1_SHA512,
            &OID_ECDSA_SHA1,
            &OID_ECDSA_SHA256,
            &OID_ECDSA_SHA384,
            &OID_ECDSA_SHA512,
            &OID_MGF1,
            &OID_RSAPSS,
            &OID_PKCS1_PUB,
            &OID_ECC_PUBLIC,
            &OID_ECC_NIST_P192,
            &OID_ECC_NIST_P224,
            &OID_ECC_NIST_P256,
            &OID_ECC_NIST_P384,
            &OID_ECC_NIST_P521,
            &OID_ECC_SM2_P256,
            &OID_KEY_USAGE_EXTENSION,
            &OID_TCG_TPMA_OBJECT,
        ] {
            assert_eq!(oid[0], TAG_OBJECT_IDENTIFIER);
            assert_eq!(usize::from(oid[1]) + 2, oid.len());
        }
    }

    #[test]
    fn the_anonymous_curves_have_no_usable_object_identifier() {
        assert!(usable_curve_oid(0x0010).is_none(), "BN_P256");
        assert!(usable_curve_oid(TPM_ECC_BN_P638).is_none());
        assert!(usable_curve_oid(TPM_ECC_NIST_P256).is_some());
    }

    fn rsa_public(modulus: &[u8], exponent: u32) -> OwnedTpmtPublic {
        OwnedTpmtPublic {
            object_type: TPM_ALG_RSA,
            name_alg: 0x000b,
            object_attributes: 0x0004_0072,
            auth_policy: Vec::new(),
            parameters: PublicParms::Rsa {
                symmetric: symmetric_null(),
                scheme: scheme_null(),
                key_bits: (modulus.len() * 8) as u16,
                exponent,
            },
            unique: OwnedPublicId::Rsa(modulus.to_vec()),
        }
    }

    fn ecc_public(curve_id: u16, x: &[u8], y: &[u8]) -> OwnedTpmtPublic {
        OwnedTpmtPublic {
            object_type: TPM_ALG_ECC,
            name_alg: 0x000b,
            object_attributes: 0x0004_0072,
            auth_policy: Vec::new(),
            parameters: PublicParms::Ecc {
                symmetric: symmetric_null(),
                scheme: scheme_null(),
                curve_id,
                kdf: scheme_null(),
            },
            unique: OwnedPublicId::Ecc {
                x: x.to_vec(),
                y: y.to_vec(),
            },
        }
    }

    fn symmetric_null() -> super::super::super::super::public::SymDefObject {
        super::super::super::super::public::SymDefObject {
            algorithm: 0x0010,
            key_bits: None,
            mode: None,
        }
    }

    fn scheme_null() -> super::super::super::super::public::Scheme {
        super::super::super::super::public::Scheme {
            scheme: 0x0010,
            hash_alg: None,
            count: None,
            kdf: None,
        }
    }

    #[track_caller]
    fn encoded(length: i32, writer: &DerWriter) -> Vec<u8> {
        writer
            .slice_at(writer.offset(), length)
            .expect("the marshaled bytes")
            .to_vec()
    }

    #[test]
    fn an_rsa_public_key_is_encoded_as_a_pkcs1_subject_public_key_info() {
        let mut modulus = vec![0xaau8; 256];
        modulus[0] = 0x7f;
        let mut writer = DerWriter::new(1024);
        let public = rsa_public(&modulus, 0);
        let length = add_public_key(&mut writer, &public);
        let bytes = encoded(length, &writer);
        assert_eq!(length as usize, bytes.len());
        assert_eq!(
            &bytes[..24],
            [
                0x30, 0x82, 0x01, 0x21, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0e, 0x00,
            ],
            "the algorithm identifier and the bit string wrapper"
        );
        assert_eq!(&bytes[24..31], [0x30, 0x82, 0x01, 0x09, 0x02, 0x82, 0x01]);
        assert_eq!(&bytes[31..33], [0x00, 0x7f], "no leading zero is added");
        assert_eq!(
            &bytes[bytes.len() - 5..],
            [0x02, 0x03, 0x01, 0x00, 0x01],
            "the default exponent"
        );
    }

    #[test]
    fn a_high_bit_modulus_gains_a_leading_zero() {
        let modulus = vec![0x80u8; 256];
        let mut writer = DerWriter::new(1024);
        let public = rsa_public(&modulus, 0);
        let length = add_public_key(&mut writer, &public);
        let bytes = encoded(length, &writer);
        assert_eq!(
            &bytes[24..32],
            [0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01]
        );
        assert_eq!(bytes[32], 0x00, "the integer is forced positive");
    }

    #[test]
    fn a_non_default_exponent_is_encoded_as_written() {
        let mut modulus = vec![0x11u8; 128];
        modulus[0] = 0x01;
        let mut writer = DerWriter::new(1024);
        let public = rsa_public(&modulus, 3);
        let length = add_public_key(&mut writer, &public);
        let bytes = encoded(length, &writer);
        assert_eq!(&bytes[bytes.len() - 3..], [0x02, 0x01, 0x03]);
    }

    #[test]
    fn an_ecc_public_key_is_encoded_as_a_named_curve_point() {
        let x = [0x11u8; 32];
        let y = [0x22u8; 32];
        let mut writer = DerWriter::new(1024);
        let public = ecc_public(TPM_ECC_NIST_P256, &x, &y);
        let length = add_public_key(&mut writer, &public);
        let bytes = encoded(length, &writer);
        let mut expected = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        expected.extend_from_slice(&x);
        expected.extend_from_slice(&y);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn an_anonymous_curve_cannot_be_encoded() {
        let public = ecc_public(0x0010, &[0x11; 32], &[0x22; 32]);
        assert!(!public_key_is_encodable(&public));
        let mut writer = DerWriter::new(1024);
        assert_eq!(add_public_key(&mut writer, &public), 0);
    }

    #[test]
    fn an_rsassa_signing_algorithm_is_a_pkcs1_identifier() {
        let public = rsa_public(&[0x11; 256], 0);
        let scheme = SigScheme {
            scheme: TPM_ALG_RSASSA,
            hash_alg: 0x000c,
            count: 0,
        };
        let mut writer = DerWriter::new(1024);
        let length = add_signing_algorithm(&mut writer, &public, &scheme);
        assert_eq!(
            encoded(length, &writer),
            [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05,
                0x00,
            ]
        );
    }

    #[test]
    fn an_rsapss_signing_algorithm_carries_the_hash_mask_and_salt() {
        let public = rsa_public(&[0x11; 256], 0);
        let scheme = SigScheme {
            scheme: TPM_ALG_RSAPSS,
            hash_alg: TPM_ALG_SHA256,
            count: 0,
        };
        let mut writer = DerWriter::new(1024);
        let length = add_signing_algorithm(&mut writer, &public, &scheme);
        assert_eq!(
            encoded(length, &writer),
            [
                0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
                0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
            ]
        );
    }

    #[test]
    fn an_rsapss_over_sha1_uses_the_defaulted_identifier() {
        let public = rsa_public(&[0x11; 256], 0);
        let scheme = SigScheme {
            scheme: TPM_ALG_RSAPSS,
            hash_alg: TPM_ALG_SHA1,
            count: 0,
        };
        let mut writer = DerWriter::new(1024);
        let length = add_signing_algorithm(&mut writer, &public, &scheme);
        assert_eq!(
            encoded(length, &writer),
            [
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x05,
                0x00,
            ]
        );
    }

    #[test]
    fn an_rsapss_salt_follows_the_modulus_and_digest_sizes() {
        for (hash_alg, expected) in [(TPM_ALG_SHA256, 0x20u8), (TPM_ALG_SHA384, 0x30)] {
            let public = rsa_public(&[0x11; 256], 0);
            let scheme = SigScheme {
                scheme: TPM_ALG_RSAPSS,
                hash_alg,
                count: 0,
            };
            let mut writer = DerWriter::new(1024);
            let length = add_signing_algorithm(&mut writer, &public, &scheme);
            let bytes = encoded(length, &writer);
            assert_eq!(bytes[bytes.len() - 3..], [0x02, 0x01, expected]);
        }
    }

    #[test]
    fn an_ecdsa_signing_algorithm_has_no_parameters() {
        let public = ecc_public(TPM_ECC_NIST_P256, &[0x11; 32], &[0x22; 32]);
        let scheme = SigScheme {
            scheme: TPM_ALG_ECDSA,
            hash_alg: TPM_ALG_SHA256,
            count: 0,
        };
        let mut writer = DerWriter::new(1024);
        let length = add_signing_algorithm(&mut writer, &public, &scheme);
        assert_eq!(
            encoded(length, &writer),
            [
                0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
            ]
        );
    }

    #[test]
    fn an_unsupported_signing_scheme_is_not_encodable() {
        let public = ecc_public(TPM_ECC_NIST_P256, &[0x11; 32], &[0x22; 32]);
        for scheme in [0x001a_u16, 0x0016, 0x0005] {
            let scheme = SigScheme {
                scheme,
                hash_alg: TPM_ALG_SHA256,
                count: 0,
            };
            assert!(!signing_algorithm_is_encodable(&public, &scheme));
        }
        let public = rsa_public(&[0x11; 256], 0);
        let scheme = SigScheme {
            scheme: TPM_ALG_RSASSA,
            hash_alg: 0x0012,
            count: 0,
        };
        assert!(!signing_algorithm_is_encodable(&public, &scheme));
    }

    #[test]
    fn an_algorithm_identifier_sequence_wraps_an_object_identifier_and_a_null() {
        let mut writer = DerWriter::new(64);
        let length = push_algorithm_identifier_sequence(&mut writer, &OID_SHA256);
        assert_eq!(length, 15);
        assert_eq!(
            writer.slice_at(writer.offset(), length).expect("bytes"),
            [
                0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00,
            ]
        );
    }
}
