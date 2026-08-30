use crate::library::constants::{
    TPM_RC_BINDING, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_SCHEME, TPM_RC_SELECTOR, TPM_RC_SIZE,
    TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::algorithm::{
    TPM_ALG_ERROR, TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSAES, algorithm_enabled,
    algorithm_profile_name,
};
use super::crypto::{
    BigUint, SeededRand, oaep_decode, oaep_encode, rsa_private_key_op, rsa_public_key_op,
    rsaes_decode, rsaes_encode, rsaes_padding_length,
};
use super::persistent::{OwnedObjectBody, OwnedPublicId, OwnedTpmtPublic};
use super::profile::ValidatedProfile;
use super::public::PublicParms;
use super::self_test::LazySelfTest;
use super::signature::{rsa_key_parts, rsa_modulus};
use super::template::{TemplateReader, digest_size};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RsaDecryptScheme {
    pub(super) scheme: u16,
    pub(super) hash_alg: u16,
}

impl RsaDecryptScheme {
    pub(super) const NULL: Self = Self {
        scheme: TPM_ALG_NULL,
        hash_alg: TPM_ALG_ERROR,
    };
}

pub(super) fn is_label_properly_formatted(label: &[u8]) -> bool {
    label.last().is_none_or(|&last| last == 0)
}

pub(super) fn parse_rsa_decrypt_scheme(
    reader: &mut TemplateReader<'_>,
    profile: &ValidatedProfile,
) -> Result<RsaDecryptScheme, TpmResult> {
    let selector = reader.u16()?;
    if selector == TPM_ALG_NULL {
        return Ok(RsaDecryptScheme::NULL);
    }
    if !matches!(selector, TPM_ALG_RSAES | TPM_ALG_OAEP) {
        return Err(TPM_RC_VALUE);
    }
    if !profile_enables(profile, selector) {
        return Err(TPM_RC_SELECTOR);
    }
    let hash_alg = if selector == TPM_ALG_OAEP {
        let hash_alg = reader.u16()?;
        if digest_size(hash_alg).is_none() || !profile_enables(profile, hash_alg) {
            return Err(TPM_RC_HASH);
        }
        hash_alg
    } else {
        TPM_ALG_ERROR
    };
    Ok(RsaDecryptScheme {
        scheme: selector,
        hash_alg,
    })
}

fn profile_enables(profile: &ValidatedProfile, algorithm: u16) -> bool {
    algorithm_profile_name(algorithm)
        .is_some_and(|name| algorithm_enabled(&profile.algorithms, name))
}

fn key_scheme(body: &OwnedObjectBody) -> Option<RsaDecryptScheme> {
    let PublicParms::Rsa { scheme, .. } = &body.public.parameters else {
        return None;
    };
    Some(RsaDecryptScheme {
        scheme: scheme.scheme,
        hash_alg: scheme.hash_alg.unwrap_or(TPM_ALG_ERROR),
    })
}

pub(super) fn select_rsa_scheme(
    body: &OwnedObjectBody,
    requested: RsaDecryptScheme,
) -> Option<RsaDecryptScheme> {
    let stored = key_scheme(body)?;
    if stored.scheme == TPM_ALG_NULL {
        return Some(requested);
    }
    if requested.scheme == TPM_ALG_NULL {
        return Some(stored);
    }
    if stored.scheme == requested.scheme && stored.hash_alg == requested.hash_alg {
        return Some(requested);
    }
    None
}

fn public_area_modulus(public: &OwnedTpmtPublic) -> Result<Vec<u8>, TpmResult> {
    match &public.unique {
        OwnedPublicId::Rsa(modulus) => Ok(modulus.clone()),
        _ => Err(TPM_RC_FAILURE),
    }
}

fn public_modulus(body: &OwnedObjectBody) -> Result<Vec<u8>, TpmResult> {
    rsa_modulus(body).map(<[u8]>::to_vec).ok_or(TPM_RC_FAILURE)
}

fn public_area_exponent(public: &OwnedTpmtPublic) -> Result<u32, TpmResult> {
    match &public.parameters {
        PublicParms::Rsa { exponent, .. } => Ok(*exponent),
        _ => Err(TPM_RC_FAILURE),
    }
}

fn right_aligned(modulus_len: usize, message: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let significant = message
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(message.len());
    let value = &message[significant..];
    if value.len() > modulus_len {
        return Err(TPM_RC_VALUE);
    }
    let mut out = vec![0u8; modulus_len];
    out[modulus_len - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn draw(rand: &mut SeededRand, length: usize) -> Result<Vec<u8>, TpmResult> {
    let mut out = vec![0u8; length];
    match rand.generate(&mut out) {
        Ok(()) => {}
        Err(_) if rand.live_entropy_starved() => {}
        Err(code) => return Err(code),
    }
    Ok(out)
}

pub(super) fn crypt_rsa_encrypt(
    public: &OwnedTpmtPublic,
    scheme: &RsaDecryptScheme,
    message: &[u8],
    label: &[u8],
    forbids_unpadded: bool,
    gate: &mut LazySelfTest<'_>,
    rand: &mut SeededRand,
) -> Result<Vec<u8>, TpmResult> {
    let modulus = public_area_modulus(public)?;
    let modulus_len = modulus.len();
    let encoded = match scheme.scheme {
        TPM_ALG_NULL => {
            if forbids_unpadded {
                return Err(TPM_RC_SCHEME);
            }
            right_aligned(modulus_len, message)?
        }
        TPM_ALG_RSAES => {
            let pad_len = rsaes_padding_length(modulus_len, message.len()).ok_or(TPM_RC_VALUE)?;
            let padding = draw(rand, pad_len)?;
            rsaes_encode(modulus_len, message, &padding).ok_or(TPM_RC_VALUE)?
        }
        TPM_ALG_OAEP => {
            let hash_len = digest_size(scheme.hash_alg).ok_or(TPM_RC_VALUE)?;
            if modulus_len < 2 * hash_len + 2 {
                return Err(TPM_RC_HASH);
            }
            if message.len() + 2 * hash_len + 2 > modulus_len {
                return Err(TPM_RC_VALUE);
            }
            gate.algorithm(scheme.hash_alg)?;
            let seed = draw(rand, hash_len)?;
            oaep_encode(scheme.hash_alg, label, message, &seed, modulus_len)
                .ok_or(TPM_RC_FAILURE)?
        }
        _ => return Err(TPM_RC_SCHEME),
    };
    let value = BigUint::from_be_bytes(&encoded);
    let modulus = BigUint::from_be_bytes(&modulus);
    rsa_public_key_op(&modulus, public_area_exponent(public)?, &value)
        .and_then(|result| result.to_be_bytes(modulus_len))
        .ok_or(TPM_RC_SIZE)
}

pub(super) fn check_ciphertext_size(
    body: &OwnedObjectBody,
    ciphertext: &[u8],
) -> Result<(), TpmResult> {
    if ciphertext.len() != public_modulus(body)?.len() {
        return Err(TPM_RC_SIZE);
    }
    Ok(())
}

pub(super) fn crypt_rsa_decrypt(
    body: &OwnedObjectBody,
    scheme: &RsaDecryptScheme,
    ciphertext: &[u8],
    label: &[u8],
    forbids_unpadded: bool,
    gate: &mut LazySelfTest<'_>,
) -> Result<Vec<u8>, TpmResult> {
    check_ciphertext_size(body, ciphertext)?;
    let modulus = public_modulus(body)?;
    let recovered = private_operation(body, &modulus, ciphertext)?;
    match scheme.scheme {
        TPM_ALG_NULL => {
            if forbids_unpadded {
                Err(TPM_RC_SCHEME)
            } else {
                Ok(recovered)
            }
        }
        TPM_ALG_RSAES => rsaes_decode(&recovered).ok_or(TPM_RC_VALUE),
        TPM_ALG_OAEP => {
            digest_size(scheme.hash_alg).ok_or(TPM_RC_VALUE)?;
            oaep_decode(scheme.hash_alg, label, &recovered, gate)?.ok_or(TPM_RC_VALUE)
        }
        _ => Err(TPM_RC_SCHEME),
    }
}

fn private_operation(
    body: &OwnedObjectBody,
    modulus: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let value = BigUint::from_be_bytes(ciphertext);
    if value >= BigUint::from_be_bytes(modulus) {
        return Err(TPM_RC_SIZE);
    }
    let (p, q, d_p, d_q, q_inv) = rsa_key_parts(body).ok_or(TPM_RC_BINDING)?;
    rsa_private_key_op(&p, &q, &d_p, &d_q, &q_inv, &value)
        .and_then(|plain| plain.to_be_bytes(modulus.len()))
        .ok_or(TPM_RC_FAILURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_gate() -> LazySelfTest<'static> {
        LazySelfTest::untested()
    }
    use crate::library::constants::TPM_RC_INSUFFICIENT;
    use crate::library::tpm2::algorithm::{
        TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
        TPM_ALG_SHA512,
    };
    use crate::library::tpm2::crypto::recover_rsa_private_exponent;
    use crate::library::tpm2::object_create::owned_prime;
    use crate::library::tpm2::persistent::{
        OwnedObjectBody, OwnedPrivateExponent, OwnedPublicId, OwnedSecret, OwnedTpmtPublic,
        OwnedTpmtSensitive,
    };
    use crate::library::tpm2::profile::{DEFAULT_ALGORITHMS_PROFILE, validate_user_profile};
    use crate::library::tpm2::public::{Scheme, SymDefObject};
    use crate::library::tpm2::rsa_vectors::{TEST_MODULUS, TEST_PRIME};

    fn default_profile() -> ValidatedProfile {
        validate_user_profile(None).expect("the null profile validates")
    }

    fn profile_without(removed: &[u8]) -> ValidatedProfile {
        let kept: Vec<&[u8]> = DEFAULT_ALGORITHMS_PROFILE
            .split(|&byte| byte == b',')
            .filter(|token| *token != removed)
            .collect();
        let mut profile = default_profile();
        profile.algorithms = kept.join(&b',');
        profile
    }

    fn rsa_body(scheme: u16, hash_alg: Option<u16>, modulus: &[u8]) -> OwnedObjectBody {
        OwnedObjectBody {
            section_version: 1,
            public: OwnedTpmtPublic {
                object_type: crate::library::tpm2::algorithm::TPM_ALG_RSA,
                name_alg: TPM_ALG_SHA256,
                object_attributes: 0,
                auth_policy: Vec::new(),
                parameters: PublicParms::Rsa {
                    symmetric: SymDefObject {
                        algorithm: TPM_ALG_NULL,
                        key_bits: None,
                        mode: None,
                    },
                    scheme: Scheme {
                        scheme,
                        hash_alg,
                        count: None,
                        kdf: None,
                    },
                    key_bits: (modulus.len() * 8) as u16,
                    exponent: 0,
                },
                unique: OwnedPublicId::Rsa(modulus.to_vec()),
            },
            sensitive: OwnedTpmtSensitive {
                sensitive_type: crate::library::tpm2::algorithm::TPM_ALG_RSA,
                auth_value: OwnedSecret::from_vec(Vec::new()),
                seed_value: OwnedSecret::from_vec(Vec::new()),
                sensitive: Some(OwnedSecret::copy_of(TEST_PRIME.as_slice())),
            },
            private_exponent: recover_rsa_private_exponent(modulus, &TEST_PRIME, 0).map(
                |recovered| OwnedPrivateExponent {
                    primes: [
                        owned_prime(&recovered.q),
                        owned_prime(&recovered.d_p),
                        owned_prime(&recovered.d_q),
                        owned_prime(&recovered.q_inv),
                    ],
                },
            ),
            qualified_name: Vec::new(),
            evict_handle: 0,
            name: Vec::new(),
            seed_compat_level: 1,
            hierarchy: None,
        }
    }

    fn requested(scheme: u16, hash_alg: u16) -> RsaDecryptScheme {
        RsaDecryptScheme { scheme, hash_alg }
    }

    fn parse(bytes: &[u8]) -> Result<RsaDecryptScheme, TpmResult> {
        parse_with(bytes, &default_profile())
    }

    fn parse_with(bytes: &[u8], profile: &ValidatedProfile) -> Result<RsaDecryptScheme, TpmResult> {
        let mut reader = TemplateReader::new(bytes);
        let scheme = parse_rsa_decrypt_scheme(&mut reader, profile)?;
        assert!(
            reader.remaining().is_empty(),
            "the scheme consumes its bytes"
        );
        Ok(scheme)
    }

    #[test]
    fn null_scheme_no_details() {
        assert_eq!(parse(&[0x00, 0x10]), Ok(RsaDecryptScheme::NULL));
        assert_eq!(RsaDecryptScheme::NULL.scheme, TPM_ALG_NULL);
        assert_eq!(RsaDecryptScheme::NULL.hash_alg, TPM_ALG_ERROR);
    }

    #[test]
    fn rsaes_scheme_no_details() {
        assert_eq!(
            parse(&[0x00, 0x15]),
            Ok(requested(TPM_ALG_RSAES, TPM_ALG_ERROR))
        );
    }

    #[test]
    fn oaep_scheme_hash_detail() {
        for hash_alg in [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512] {
            let mut bytes = TPM_ALG_OAEP.to_be_bytes().to_vec();
            bytes.extend_from_slice(&hash_alg.to_be_bytes());
            assert_eq!(parse(&bytes), Ok(requested(TPM_ALG_OAEP, hash_alg)));
        }
    }

    #[test]
    fn signature_scheme_selector_value_error() {
        for scheme in [TPM_ALG_RSASSA, TPM_ALG_RSAPSS, 0x0000, 0x0018, 0xffff] {
            let mut bytes = scheme.to_be_bytes().to_vec();
            bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            let mut reader = TemplateReader::new(&bytes);
            assert_eq!(
                parse_rsa_decrypt_scheme(&mut reader, &default_profile()),
                Err(TPM_RC_VALUE),
                "scheme {scheme:#06x}"
            );
        }
    }

    #[test]
    fn truncated_scheme_insufficient_error() {
        for bytes in [
            &[][..],
            &[0x00][..],
            &[0x00, 0x17][..],
            &[0x00, 0x17, 0x00][..],
        ] {
            let mut reader = TemplateReader::new(bytes);
            assert_eq!(
                parse_rsa_decrypt_scheme(&mut reader, &default_profile()),
                Err(TPM_RC_INSUFFICIENT),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn invalid_oaep_hash_error() {
        for hash_alg in [TPM_ALG_NULL, 0x0000u16, 0x0012, 0xffff] {
            let mut bytes = TPM_ALG_OAEP.to_be_bytes().to_vec();
            bytes.extend_from_slice(&hash_alg.to_be_bytes());
            let mut reader = TemplateReader::new(&bytes);
            assert_eq!(
                parse_rsa_decrypt_scheme(&mut reader, &default_profile()),
                Err(TPM_RC_HASH),
                "hash {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn profile_disabled_scheme_selector_error() {
        let without_oaep = profile_without(b"oaep");
        let mut bytes = TPM_ALG_OAEP.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        let mut reader = TemplateReader::new(&bytes);
        assert_eq!(
            parse_rsa_decrypt_scheme(&mut reader, &without_oaep),
            Err(TPM_RC_SELECTOR)
        );
        assert_eq!(
            parse_with(&[0x00, 0x15], &without_oaep),
            Ok(requested(TPM_ALG_RSAES, TPM_ALG_ERROR)),
            "the still-enabled scheme is accepted"
        );
        assert_eq!(
            parse_with(&[0x00, 0x10], &without_oaep),
            Ok(RsaDecryptScheme::NULL),
            "the null scheme can never be disabled"
        );
    }

    #[test]
    fn profile_disabled_hash_error() {
        let without_sha1 = profile_without(b"sha1");
        let mut bytes = TPM_ALG_OAEP.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA1.to_be_bytes());
        let mut reader = TemplateReader::new(&bytes);
        assert_eq!(
            parse_rsa_decrypt_scheme(&mut reader, &without_sha1),
            Err(TPM_RC_HASH)
        );
    }

    #[test]
    fn label_format_empty_or_nul_terminated() {
        assert!(is_label_properly_formatted(b""));
        assert!(is_label_properly_formatted(b"\0"));
        assert!(is_label_properly_formatted(b"label\0"));
        assert!(is_label_properly_formatted(b"em\0bedded\0"));
        assert!(!is_label_properly_formatted(b"label"));
        assert!(!is_label_properly_formatted(b"\0label"));
        assert!(!is_label_properly_formatted(&[0x00, 0x01]));
    }

    #[test]
    fn schemeless_key_command_scheme_adoption() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        for scheme in [
            RsaDecryptScheme::NULL,
            requested(TPM_ALG_RSAES, TPM_ALG_ERROR),
            requested(TPM_ALG_OAEP, TPM_ALG_SHA256),
        ] {
            assert_eq!(select_rsa_scheme(&key, scheme), Some(scheme));
        }
    }

    #[test]
    fn null_command_scheme_key_scheme_fallback() {
        let rsaes = rsa_body(TPM_ALG_RSAES, None, &TEST_MODULUS);
        assert_eq!(
            select_rsa_scheme(&rsaes, RsaDecryptScheme::NULL),
            Some(requested(TPM_ALG_RSAES, TPM_ALG_ERROR))
        );
        let oaep = rsa_body(TPM_ALG_OAEP, Some(TPM_ALG_SHA384), &TEST_MODULUS);
        assert_eq!(
            select_rsa_scheme(&oaep, RsaDecryptScheme::NULL),
            Some(requested(TPM_ALG_OAEP, TPM_ALG_SHA384))
        );
    }

    #[test]
    fn command_scheme_match_requirement() {
        let oaep = rsa_body(TPM_ALG_OAEP, Some(TPM_ALG_SHA256), &TEST_MODULUS);
        assert_eq!(
            select_rsa_scheme(&oaep, requested(TPM_ALG_OAEP, TPM_ALG_SHA256)),
            Some(requested(TPM_ALG_OAEP, TPM_ALG_SHA256))
        );
        assert_eq!(
            select_rsa_scheme(&oaep, requested(TPM_ALG_OAEP, TPM_ALG_SHA384)),
            None,
            "a different hash is incompatible"
        );
        assert_eq!(
            select_rsa_scheme(&oaep, requested(TPM_ALG_RSAES, TPM_ALG_ERROR)),
            None,
            "a different scheme is incompatible"
        );

        let rsaes = rsa_body(TPM_ALG_RSAES, None, &TEST_MODULUS);
        assert_eq!(
            select_rsa_scheme(&rsaes, requested(TPM_ALG_RSAES, TPM_ALG_ERROR)),
            Some(requested(TPM_ALG_RSAES, TPM_ALG_ERROR))
        );
        assert_eq!(
            select_rsa_scheme(&rsaes, requested(TPM_ALG_OAEP, TPM_ALG_SHA256)),
            None
        );
    }

    #[test]
    fn non_rsa_object_no_scheme() {
        let mut key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        key.public.parameters = PublicParms::SymCipher(SymDefObject {
            algorithm: TPM_ALG_NULL,
            key_bits: None,
            mode: None,
        });
        assert_eq!(key_scheme(&key), None);
        assert_eq!(select_rsa_scheme(&key, RsaDecryptScheme::NULL), None);
    }

    fn rand() -> SeededRand {
        SeededRand::instantiate(&[0x37; 64], b"RSA-ENC", &[0x11; 34], &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn recorded_encrypt(
        public: &OwnedTpmtPublic,
        scheme: &RsaDecryptScheme,
        message: &[u8],
        failing: bool,
        generator: &mut SeededRand,
    ) -> (Result<Vec<u8>, TpmResult>, Vec<u16>) {
        let mut calls = Vec::new();
        let outcome = {
            let mut run = |algorithm: u16| {
                calls.push(algorithm);
                if failing {
                    return Err(crate::library::constants::TPM_RC_FAILURE);
                }
                Ok(())
            };
            crypt_rsa_encrypt(
                public,
                scheme,
                message,
                b"SECRET\0",
                false,
                &mut LazySelfTest::runtime(&mut run),
                generator,
            )
        };
        (outcome, calls)
    }

    fn oaep_scheme() -> RsaDecryptScheme {
        RsaDecryptScheme {
            scheme: TPM_ALG_OAEP,
            hash_alg: TPM_ALG_SHA256,
        }
    }

    #[test]
    fn oaep_hash_self_test_before_seed_draw() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let mut generator = rand();
        let (outcome, calls) = recorded_encrypt(
            &key.public,
            &oaep_scheme(),
            b"payload",
            true,
            &mut generator,
        );
        assert_eq!(outcome, Err(crate::library::constants::TPM_RC_FAILURE));
        assert_eq!(calls, [TPM_ALG_SHA256]);
        assert_eq!(
            generator.random_bytes(32).expect("the generator runs"),
            rand().random_bytes(32).expect("the generator runs"),
            "the reference hashes the label before it draws the OAEP seed"
        );
    }

    #[test]
    fn oaep_size_rejection_no_hash_self_test() {
        let wide = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let narrow = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS[..128]);
        for (what, key, scheme, message) in [
            (
                "a message that cannot fit",
                &wide,
                oaep_scheme(),
                vec![0u8; 256 - 65],
            ),
            (
                "a digest too large for the modulus",
                &narrow,
                RsaDecryptScheme {
                    scheme: TPM_ALG_OAEP,
                    hash_alg: TPM_ALG_SHA512,
                },
                b"payload".to_vec(),
            ),
        ] {
            let mut generator = rand();
            let (outcome, calls) =
                recorded_encrypt(&key.public, &scheme, &message, false, &mut generator);
            assert!(outcome.is_err(), "{what}");
            assert!(calls.is_empty(), "{what}");
            assert_eq!(
                generator.random_bytes(32).expect("the generator runs"),
                rand().random_bytes(32).expect("the generator runs"),
                "{what} draws no padding seed"
            );
        }
    }

    #[test]
    fn oaep_success_single_hash_self_test() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let mut generator = rand();
        let (outcome, calls) = recorded_encrypt(
            &key.public,
            &oaep_scheme(),
            b"payload",
            false,
            &mut generator,
        );
        assert!(outcome.is_ok());
        assert_eq!(calls, [TPM_ALG_SHA256]);
    }

    #[test]
    fn unpadded_rsaes_no_hash_self_test() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        for scheme in [
            RsaDecryptScheme::NULL,
            RsaDecryptScheme {
                scheme: TPM_ALG_RSAES,
                hash_alg: TPM_ALG_ERROR,
            },
        ] {
            let mut generator = rand();
            let (outcome, calls) =
                recorded_encrypt(&key.public, &scheme, b"payload", false, &mut generator);
            assert!(outcome.is_ok(), "{:#06x}", scheme.scheme);
            assert!(calls.is_empty(), "{:#06x}", scheme.scheme);
        }
    }

    #[test]
    fn oaep_hash_exceeding_modulus_hash_error() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS[..128]);
        assert_eq!(
            crypt_rsa_encrypt(
                &key.public,
                &requested(TPM_ALG_OAEP, TPM_ALG_SHA512),
                b"x",
                b"",
                false,
                &mut no_gate(),
                &mut rand(),
            ),
            Err(TPM_RC_HASH)
        );
    }

    #[test]
    fn oversized_oaep_message_value_error_no_draw() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let mut generator = rand();
        let before = generator.random_bytes(0).expect("a zero draw");
        assert!(before.is_empty());
        assert_eq!(
            crypt_rsa_encrypt(
                &key.public,
                &requested(TPM_ALG_OAEP, TPM_ALG_SHA256),
                &[0u8; 191],
                b"",
                false,
                &mut no_gate(),
                &mut generator
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[test]
    fn oversized_rsaes_message_value_error() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        assert_eq!(
            crypt_rsa_encrypt(
                &key.public,
                &requested(TPM_ALG_RSAES, TPM_ALG_ERROR),
                &[0u8; 246],
                b"",
                false,
                &mut no_gate(),
                &mut rand()
            ),
            Err(TPM_RC_VALUE)
        );
        assert!(
            crypt_rsa_encrypt(
                &key.public,
                &requested(TPM_ALG_RSAES, TPM_ALG_ERROR),
                &[0u8; 245],
                b"",
                false,
                &mut no_gate(),
                &mut rand()
            )
            .is_ok(),
            "one byte less is the largest accepted message"
        );
    }

    #[test]
    fn unpadded_scheme_profile_attribute_gate() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        assert_eq!(
            crypt_rsa_encrypt(
                &key.public,
                &RsaDecryptScheme::NULL,
                b"x",
                b"",
                true,
                &mut no_gate(),
                &mut rand()
            ),
            Err(TPM_RC_SCHEME)
        );
        let mut ciphertext = TEST_MODULUS;
        ciphertext[0] -= 1;
        assert_eq!(
            crypt_rsa_decrypt(
                &key,
                &RsaDecryptScheme::NULL,
                &ciphertext,
                b"",
                true,
                &mut no_gate()
            ),
            Err(TPM_RC_SCHEME)
        );
        assert!(
            crypt_rsa_decrypt(
                &key,
                &RsaDecryptScheme::NULL,
                &ciphertext,
                b"",
                false,
                &mut no_gate()
            )
            .is_ok()
        );
        assert!(
            crypt_rsa_encrypt(
                &key.public,
                &RsaDecryptScheme::NULL,
                b"x",
                b"",
                false,
                &mut no_gate(),
                &mut rand()
            )
            .is_ok()
        );
    }

    #[test]
    fn raw_message_at_or_above_modulus_size_error() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        assert_eq!(
            crypt_rsa_encrypt(
                &key.public,
                &RsaDecryptScheme::NULL,
                &TEST_MODULUS,
                b"",
                false,
                &mut no_gate(),
                &mut rand(),
            ),
            Err(TPM_RC_SIZE)
        );
        let mut below = TEST_MODULUS;
        below[0] -= 1;
        assert!(
            crypt_rsa_encrypt(
                &key.public,
                &RsaDecryptScheme::NULL,
                &below,
                b"",
                false,
                &mut no_gate(),
                &mut rand()
            )
            .is_ok()
        );
    }

    #[test]
    fn long_raw_message_leading_zero_requirement() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let mut padded = vec![0u8; 4];
        padded.extend_from_slice(&TEST_MODULUS[..255]);
        assert!(
            crypt_rsa_encrypt(
                &key.public,
                &RsaDecryptScheme::NULL,
                &padded,
                b"",
                false,
                &mut no_gate(),
                &mut rand()
            )
            .is_ok(),
            "leading zeros are stripped"
        );
        let mut significant = vec![0x01u8];
        significant.extend_from_slice(&TEST_MODULUS);
        assert_eq!(
            crypt_rsa_encrypt(
                &key.public,
                &RsaDecryptScheme::NULL,
                &significant,
                b"",
                false,
                &mut no_gate(),
                &mut rand(),
            ),
            Err(TPM_RC_VALUE)
        );
    }

    #[track_caller]
    fn round_trip(scheme: RsaDecryptScheme, message: &[u8], label: &[u8]) -> Vec<u8> {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let ciphertext = crypt_rsa_encrypt(
            &key.public,
            &scheme,
            message,
            label,
            false,
            &mut no_gate(),
            &mut rand(),
        )
        .expect("encrypts");
        assert_eq!(ciphertext.len(), TEST_MODULUS.len());
        ciphertext
    }

    #[test]
    fn scheme_shared_layer_round_trip() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        for (scheme, label) in [
            (RsaDecryptScheme::NULL, &b""[..]),
            (requested(TPM_ALG_RSAES, TPM_ALG_ERROR), b""),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA1), b""),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA256), b"label\0"),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA384), b""),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA512), b"other\0"),
        ] {
            let message = b"round trip payload";
            let ciphertext = round_trip(scheme, message, label);
            let recovered =
                crypt_rsa_decrypt(&key, &scheme, &ciphertext, label, false, &mut no_gate())
                    .expect("decrypts");
            if scheme.scheme == TPM_ALG_NULL {
                assert_eq!(&recovered[TEST_MODULUS.len() - message.len()..], message);
                assert!(
                    recovered[..TEST_MODULUS.len() - message.len()]
                        .iter()
                        .all(|&byte| byte == 0)
                );
            } else {
                assert_eq!(recovered, message, "scheme {:#06x}", scheme.scheme);
            }
        }
    }

    #[test]
    fn oaep_decode_label_hash_mismatch_failure() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        let scheme = requested(TPM_ALG_OAEP, TPM_ALG_SHA256);
        let ciphertext = round_trip(scheme, b"payload", b"right\0");
        assert_eq!(
            crypt_rsa_decrypt(
                &key,
                &scheme,
                &ciphertext,
                b"wrong\0",
                false,
                &mut no_gate()
            ),
            Err(TPM_RC_VALUE)
        );
        assert_eq!(
            crypt_rsa_decrypt(&key, &scheme, &ciphertext, b"", false, &mut no_gate()),
            Err(TPM_RC_VALUE)
        );
        assert_eq!(
            crypt_rsa_decrypt(
                &key,
                &requested(TPM_ALG_OAEP, TPM_ALG_SHA384),
                &ciphertext,
                b"right\0",
                false,
                &mut no_gate()
            ),
            Err(TPM_RC_VALUE)
        );
        assert_eq!(
            crypt_rsa_decrypt(
                &key,
                &requested(TPM_ALG_RSAES, TPM_ALG_ERROR),
                &ciphertext,
                b"",
                false,
                &mut no_gate()
            ),
            Err(TPM_RC_VALUE),
            "the padding of another scheme is rejected"
        );
    }

    #[test]
    fn malformed_ciphertext_no_partial_plaintext() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        for scheme in [
            requested(TPM_ALG_RSAES, TPM_ALG_ERROR),
            requested(TPM_ALG_OAEP, TPM_ALG_SHA256),
        ] {
            let mut ciphertext = round_trip(scheme, b"payload", b"");
            for position in [0usize, 1, 128, 255] {
                let original = ciphertext[position];
                ciphertext[position] ^= 0x01;
                assert!(
                    crypt_rsa_decrypt(&key, &scheme, &ciphertext, b"", false, &mut no_gate())
                        .is_err(),
                    "scheme {:#06x}, byte {position}",
                    scheme.scheme
                );
                ciphertext[position] = original;
            }
        }
    }

    #[test]
    fn ciphertext_at_or_above_modulus_size_error() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        assert_eq!(
            crypt_rsa_decrypt(
                &key,
                &RsaDecryptScheme::NULL,
                &TEST_MODULUS,
                b"",
                false,
                &mut no_gate()
            ),
            Err(TPM_RC_SIZE)
        );
    }

    #[test]
    fn encryption_reference_random_consumption() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        for (scheme, expected) in [
            (RsaDecryptScheme::NULL, 0usize),
            (requested(TPM_ALG_RSAES, TPM_ALG_ERROR), 256 - 7 - 3),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA1), 20),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA256), 32),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA384), 48),
            (requested(TPM_ALG_OAEP, TPM_ALG_SHA512), 64),
        ] {
            let mut generator = rand();
            let mut reference = rand();
            crypt_rsa_encrypt(
                &key.public,
                &scheme,
                b"payload",
                b"",
                false,
                &mut no_gate(),
                &mut generator,
            )
            .expect("encrypts");
            if expected > 0 {
                reference.random_bytes(expected).expect("draws");
            }
            assert_eq!(
                generator.random_bytes(16).expect("draws"),
                reference.random_bytes(16).expect("draws"),
                "scheme {:#06x} draws {expected} bytes",
                scheme.scheme
            );
        }
    }

    #[test]
    fn wrong_length_ciphertext_size_error() {
        let key = rsa_body(TPM_ALG_NULL, None, &TEST_MODULUS);
        for length in [0usize, 1, 255, 257, 384] {
            assert_eq!(
                check_ciphertext_size(&key, &vec![0u8; length]),
                Err(TPM_RC_SIZE),
                "length {length}"
            );
        }
        assert_eq!(check_ciphertext_size(&key, &[0u8; 256]), Ok(()));
    }
}
