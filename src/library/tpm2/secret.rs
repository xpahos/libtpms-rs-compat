// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CryptUtil.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccCrypt.c
// - libtpms/src/tpm2/crypto/openssl/CryptRsa.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2022 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_BINDING, TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT,
    TPM_RC_KEY, TPM_RC_NO_RESULT, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::algorithm::{TPM_ALG_ECC, TPM_ALG_ECDH, TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSA};
use super::crypto::{
    BigUint, EccKeyError, curve_parameters, kdfe, oaep_decode, rsa_private_key_op,
};
use super::marshal::{BlobReader, Tpm2bError};
use super::persistent::{OwnedObjectBody, OwnedPrivateExponent, OwnedPublicId};
use super::public::PublicParms;
use super::rsa_encryption::{RsaDecryptScheme, crypt_rsa_encrypt};
use super::self_test::{LazySelfTest, self_test_algorithm, self_test_reached, self_test_rsa_oaep};
use super::session::digest_size;
use super::template::TPMA_OBJECT_DECRYPT;

pub(super) const SECRET_LABEL: &[u8] = b"SECRET\0";
pub(super) const DUPLICATE_LABEL: &[u8] = b"DUPLICATE\0";
pub(super) const IDENTITY_LABEL: &[u8] = b"IDENTITY\0";

pub(super) const MAX_ENCRYPTED_SECRET: usize = 384;

const MAX_ECC_PARAMETER: usize = 80;

pub(super) fn is_asymmetric(object_type: u16) -> bool {
    matches!(object_type, TPM_ALG_RSA | TPM_ALG_ECC)
}

fn limbs_to_big(data: &[u8]) -> BigUint {
    let mut value = BigUint::zero();
    for (index, chunk) in data.chunks_exact(8).enumerate() {
        let limb = u64::from_be_bytes(chunk.try_into().expect("eight bytes"));
        value = value.add(&BigUint::from_u64(limb).shl(index * 64));
    }
    value
}

fn oaep_hash_algorithm(body: &OwnedObjectBody) -> Result<u16, TpmResult> {
    let PublicParms::Rsa { scheme, .. } = &body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let hash_alg = if scheme.scheme == TPM_ALG_NULL {
        body.public.name_alg
    } else if scheme.scheme == TPM_ALG_OAEP {
        scheme.hash_alg.ok_or(TPM_RC_SCHEME)?
    } else {
        return Err(TPM_RC_SCHEME);
    };
    digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;
    Ok(hash_alg)
}

fn rsa_modulus(body: &OwnedObjectBody) -> Result<&[u8], TpmResult> {
    match &body.public.unique {
        OwnedPublicId::Rsa(modulus) => Ok(modulus),
        _ => Err(TPM_RC_FAILURE),
    }
}

fn rsa_decrypt(
    body: &OwnedObjectBody,
    label: &[u8],
    secret: &[u8],
    gate: &mut LazySelfTest<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let hash_alg = oaep_hash_algorithm(body)?;
    let limit = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;

    let modulus = rsa_modulus(body)?;
    if secret.len() != modulus.len() {
        return Err(TPM_RC_SIZE);
    }
    gate.algorithm(TPM_ALG_OAEP)?;
    if BigUint::from_be_bytes(secret) >= BigUint::from_be_bytes(modulus) {
        return Err(TPM_RC_SIZE);
    }

    let prime = body.sensitive.sensitive.as_ref().ok_or(TPM_RC_BINDING)?;
    let exponent: &OwnedPrivateExponent = body.private_exponent.as_ref().ok_or(TPM_RC_BINDING)?;
    let p = BigUint::from_be_bytes(prime.as_bytes());
    let q = limbs_to_big(exponent.primes[0].data.as_bytes());
    let d_p = limbs_to_big(exponent.primes[1].data.as_bytes());
    let d_q = limbs_to_big(exponent.primes[2].data.as_bytes());
    let q_inv = limbs_to_big(exponent.primes[3].data.as_bytes());

    let value = BigUint::from_be_bytes(secret);
    let plain = rsa_private_key_op(&p, &q, &d_p, &d_q, &q_inv, &value).ok_or(TPM_RC_FAILURE)?;
    let padded = plain.to_be_bytes(modulus.len()).ok_or(TPM_RC_FAILURE)?;

    let recovered = oaep_decode(hash_alg, label, &padded, gate)?.ok_or(TPM_RC_VALUE)?;
    if recovered.len() > limit {
        return Err(TPM_RC_VALUE);
    }
    Ok(recovered)
}

fn read_ecc_point(secret: &[u8]) -> Result<(&[u8], &[u8]), TpmResult> {
    let mut reader = BlobReader::new(secret);
    let mut read = || {
        reader
            .read_tpm2b(MAX_ECC_PARAMETER)
            .map_err(|error| match error {
                Tpm2bError::Truncated => TPM_RC_INSUFFICIENT,
                Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE,
            })
    };
    let x = read()?;
    let y = read()?;
    Ok((x, y))
}

fn ecc_decrypt(
    body: &OwnedObjectBody,
    label: &[u8],
    secret: &[u8],
    gate: &mut LazySelfTest<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let PublicParms::Ecc { curve_id, .. } = &body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let curve = curve_parameters(*curve_id).ok_or(TPM_RC_FAILURE)?;
    let (public_x, public_y) = read_ecc_point(secret)?;
    gate.algorithm(TPM_ALG_ECDH)?;

    let peer_x = BigUint::from_be_bytes(public_x);
    let peer_y = BigUint::from_be_bytes(public_y);
    if !curve.is_point_on_curve(&peer_x, &peer_y) {
        return Err(TPM_RC_ECC_POINT);
    }

    let private = body.sensitive.sensitive.as_ref().ok_or(TPM_RC_BINDING)?;
    let scalar = BigUint::from_be_bytes(private.as_bytes());
    let (shared_x, _) = curve
        .multiply_point((&peer_x, &peer_y), &scalar)
        .ok_or(TPM_RC_NO_RESULT)?;
    let z = shared_x
        .to_be_bytes(curve.key_size_bytes)
        .ok_or(TPM_RC_FAILURE)?;

    let OwnedPublicId::Ecc { x, .. } = &body.public.unique else {
        return Err(TPM_RC_FAILURE);
    };
    let bits = digest_size(body.public.name_alg).ok_or(TPM_RC_SCHEME)? * 8;
    gate.algorithm(body.public.name_alg)?;
    kdfe(body.public.name_alg, &z, label, public_x, x, bits as u32).ok_or(TPM_RC_FAILURE)
}

pub(super) fn secret_decrypt(
    body: &OwnedObjectBody,
    label: &[u8],
    secret: &[u8],
    gate: &mut LazySelfTest<'_>,
) -> Result<Vec<u8>, TpmResult> {
    match body.public.object_type {
        TPM_ALG_RSA => rsa_decrypt(body, label, secret, gate),
        TPM_ALG_ECC => ecc_decrypt(body, label, secret, gate),
        _ => Err(TPM_RC_KEY),
    }
}

pub(super) fn secret_decrypt_with_runtime(
    runtime: &mut super::runtime::Tpm2Runtime,
    body: &OwnedObjectBody,
    label: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let mut run = |algorithm: u16| self_test_reached(runtime, algorithm);
    secret_decrypt(body, label, secret, &mut LazySelfTest::runtime(&mut run))
}

pub(super) struct EncryptedSecret {
    pub(super) data: Vec<u8>,
    pub(super) secret: Vec<u8>,
}

fn rsa_secret_encrypt(
    runtime: &mut super::runtime::Tpm2Runtime,
    public: &super::persistent::OwnedTpmtPublic,
    label: &[u8],
    length: usize,
) -> Result<EncryptedSecret, TpmResult> {
    let scheme = RsaDecryptScheme {
        scheme: TPM_ALG_OAEP,
        hash_alg: public.name_alg,
    };
    let data = super::random::generate_random(runtime, length)?;
    self_test_rsa_oaep(runtime)?;
    let mut rand = super::random::take_live_rand(runtime)?;
    let secret = {
        let mut run = |algorithm: u16| self_test_algorithm(runtime, algorithm);
        crypt_rsa_encrypt(
            public,
            &scheme,
            &data,
            label,
            false,
            &mut LazySelfTest::runtime(&mut run),
            &mut rand,
        )
    };
    super::random::finish_live_rand(runtime, rand)?;
    Ok(EncryptedSecret {
        data,
        secret: secret?,
    })
}

fn ecc_secret_encrypt(
    runtime: &mut super::runtime::Tpm2Runtime,
    public: &super::persistent::OwnedTpmtPublic,
    label: &[u8],
    length: usize,
) -> Result<EncryptedSecret, TpmResult> {
    let PublicParms::Ecc { curve_id, .. } = &public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let OwnedPublicId::Ecc { x, y } = &public.unique else {
        return Err(TPM_RC_FAILURE);
    };
    let curve = curve_parameters(*curve_id).ok_or(TPM_RC_KEY)?;
    let peer_x = BigUint::from_be_bytes(x);
    let peer_y = BigUint::from_be_bytes(y);
    if !curve.is_point_on_curve(&peer_x, &peer_y) {
        return Err(TPM_RC_KEY);
    }
    self_test_algorithm(runtime, TPM_ALG_ECDH)?;

    let mut rand = super::random::take_live_rand(runtime)?;
    let ephemeral = super::crypto::generate_ecc_key(*curve_id, &mut rand);
    super::random::finish_live_rand(runtime, rand)?;
    let ephemeral = ephemeral.map_err(|error| match error {
        EccKeyError::Curve => TPM_RC_KEY,
        EccKeyError::NoResult => TPM_RC_NO_RESULT,
    })?;

    let mut secret = Vec::with_capacity(4 + ephemeral.x.len() + ephemeral.y.len());
    secret.extend_from_slice(&(ephemeral.x.len() as u16).to_be_bytes());
    secret.extend_from_slice(&ephemeral.x);
    secret.extend_from_slice(&(ephemeral.y.len() as u16).to_be_bytes());
    secret.extend_from_slice(&ephemeral.y);

    let scalar = BigUint::from_be_bytes(&ephemeral.private);
    let (shared_x, _) = curve
        .multiply_point((&peer_x, &peer_y), &scalar)
        .ok_or(TPM_RC_KEY)?;
    let z = shared_x
        .to_be_bytes(curve.key_size_bytes)
        .ok_or(TPM_RC_FAILURE)?;
    self_test_algorithm(runtime, public.name_alg)?;
    let data = kdfe(
        public.name_alg,
        &z,
        label,
        &ephemeral.x,
        x,
        (length * 8) as u32,
    )
    .unwrap_or_default();
    Ok(EncryptedSecret { data, secret })
}

pub(super) fn secret_encrypt(
    runtime: &mut super::runtime::Tpm2Runtime,
    public: &super::persistent::OwnedTpmtPublic,
    label: &[u8],
) -> Result<EncryptedSecret, TpmResult> {
    let length = digest_size(public.name_alg).unwrap_or(0);
    if public.object_attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES);
    }
    match public.object_type {
        TPM_ALG_RSA => rsa_secret_encrypt(runtime, public, label, length),
        TPM_ALG_ECC => ecc_secret_encrypt(runtime, public, label, length),
        _ => Err(TPM_RC_FAILURE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::crypto::CTR_DRBG_MAX_REQUESTS_PER_RESEED;
    use crate::library::tpm2::golden_responses::object_transfer::vector;
    use crate::library::tpm2::object_create::resolve_any_object;
    use crate::library::tpm2::object_load::replay::{clock, runtime_from};
    use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedSecret};
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const ECC_PARENT: u32 = 0x8000_0001;

    fn ecc_runtime(clock: &SteppingClock) -> Tpm2Runtime {
        runtime_from(
            vector("PERMALL_ECC_READY"),
            vector("VOLATILE_ECC_READY"),
            clock,
        )
    }

    fn ecc_parent(runtime: &Tpm2Runtime) -> Box<OwnedObjectBody> {
        let object = resolve_any_object(runtime, ECC_PARENT).expect("the ECC parent is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("an object body");
        };
        body.clone()
    }

    fn starve_the_generator(runtime: &mut Tpm2Runtime) {
        runtime.entropy_bad = true;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
    }

    const RSA_PARENT: u32 = 0x8000_0001;
    const ALG_SHA256: u16 = 0x000b;

    fn rsa_runtime(clock: &SteppingClock) -> Tpm2Runtime {
        runtime_from(
            vector("PERMALL_RSA_READY"),
            vector("VOLATILE_RSA_READY"),
            clock,
        )
    }

    fn loaded_object(runtime: &Tpm2Runtime, handle: u32) -> Box<OwnedObjectBody> {
        let object = resolve_any_object(runtime, handle).expect("the parent is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("an object body");
        };
        body.clone()
    }

    fn recorded_recovery(
        body: &OwnedObjectBody,
        secret: &[u8],
        failing: Option<u16>,
    ) -> (Result<Vec<u8>, TpmResult>, Vec<u16>) {
        let mut calls = Vec::new();
        let outcome = {
            let mut run = |algorithm: u16| {
                calls.push(algorithm);
                if failing == Some(algorithm) {
                    return Err(TPM_RC_FAILURE);
                }
                Ok(())
            };
            secret_decrypt(
                body,
                DUPLICATE_LABEL,
                secret,
                &mut LazySelfTest::runtime(&mut run),
            )
        };
        (outcome, calls)
    }

    #[test]
    fn ecc_recovery_test_order_ecdh_name_algorithm() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let parent = ecc_parent(&runtime);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the ECC seed is encrypted");

        let (recovered, calls) = recorded_recovery(&parent, &encrypted.secret, None);
        assert_eq!(recovered, Ok(encrypted.data));
        assert_eq!(calls, [TPM_ALG_ECDH, ALG_SHA256]);
    }

    #[test]
    fn ecc_recovery_unusable_point_no_name_algorithm_test() {
        let clock = clock();
        let runtime = ecc_runtime(&clock);
        let parent = ecc_parent(&runtime);
        let mut off_curve = 32u16.to_be_bytes().to_vec();
        off_curve.extend_from_slice(&[0x07; 32]);
        off_curve.extend_from_slice(&32u16.to_be_bytes());
        off_curve.extend_from_slice(&[0x08; 32]);

        for (what, secret, expected, calls_expected) in [
            (
                "an unparsable point",
                Vec::new(),
                TPM_RC_INSUFFICIENT,
                vec![],
            ),
            (
                "a truncated point",
                off_curve[..35].to_vec(),
                TPM_RC_INSUFFICIENT,
                vec![],
            ),
            (
                "a point off the curve",
                off_curve.clone(),
                TPM_RC_ECC_POINT,
                vec![TPM_ALG_ECDH],
            ),
        ] {
            let (recovered, calls) = recorded_recovery(&parent, &secret, None);
            assert_eq!(recovered, Err(expected), "{what}");
            assert_eq!(calls, calls_expected, "{what}");
        }
    }

    #[test]
    fn ecc_recovery_empty_multiplication_no_derivation() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let mut parent = ecc_parent(&runtime);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the ECC seed is encrypted");
        parent.sensitive.sensitive = Some(OwnedSecret::from_vec(vec![0u8; 32]));

        let (recovered, calls) = recorded_recovery(&parent, &encrypted.secret, None);
        assert_eq!(
            recovered,
            Err(TPM_RC_NO_RESULT),
            "a zero scalar multiplies the on-curve point to infinity"
        );
        assert_eq!(
            calls,
            [TPM_ALG_ECDH],
            "the point multiply is reached, but KDFe never starts"
        );
    }

    #[test]
    fn ecc_name_algorithm_test_failure_derivation_stop() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let parent = ecc_parent(&runtime);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the ECC seed is encrypted");

        let (recovered, calls) = recorded_recovery(&parent, &encrypted.secret, Some(ALG_SHA256));
        assert_eq!(recovered, Err(TPM_RC_FAILURE));
        assert_eq!(calls, [TPM_ALG_ECDH, ALG_SHA256]);
    }

    #[test]
    fn rsa_recovery_test_order_scheme_name_algorithm() {
        let clock = clock();
        let mut runtime = rsa_runtime(&clock);
        let parent = loaded_object(&runtime, RSA_PARENT);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the RSA seed is encrypted");

        let (recovered, calls) = recorded_recovery(&parent, &encrypted.secret, None);
        assert_eq!(recovered, Ok(encrypted.data));
        assert_eq!(calls, [TPM_ALG_OAEP, ALG_SHA256]);
    }

    #[test]
    fn rsa_recovery_size_check_rejection_no_test() {
        let clock = clock();
        let mut runtime = rsa_runtime(&clock);
        let parent = loaded_object(&runtime, RSA_PARENT);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the RSA seed is encrypted");

        let (recovered, calls) = recorded_recovery(&parent, &encrypted.secret[..255], None);
        assert_eq!(recovered, Err(TPM_RC_SIZE));
        assert!(calls.is_empty());
    }

    #[test]
    fn rsa_name_algorithm_test_failure_decoding_stop() {
        let clock = clock();
        let mut runtime = rsa_runtime(&clock);
        let parent = loaded_object(&runtime, RSA_PARENT);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the RSA seed is encrypted");

        let (recovered, calls) = recorded_recovery(&parent, &encrypted.secret, Some(ALG_SHA256));
        assert_eq!(recovered, Err(TPM_RC_FAILURE));
        assert_eq!(calls, [TPM_ALG_OAEP, ALG_SHA256]);
    }

    #[test]
    fn ecc_secret_encryption_parent_key_round_trip() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let parent = ecc_parent(&runtime);
        let encrypted = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL)
            .expect("the ECC seed is encrypted");

        assert_eq!(encrypted.data.len(), 32);
        let (x, y) = read_ecc_point(&encrypted.secret).expect("a marshalled point");
        assert_eq!(x.len(), 32);
        assert_eq!(y.len(), 32);
        let PublicParms::Ecc { curve_id, .. } = &parent.public.parameters else {
            panic!("an ECC parent");
        };
        let curve = curve_parameters(*curve_id).expect("a compiled curve");
        assert!(curve.is_point_on_curve(&BigUint::from_be_bytes(x), &BigUint::from_be_bytes(y)));

        assert_eq!(
            secret_decrypt(
                &parent,
                DUPLICATE_LABEL,
                &encrypted.secret,
                &mut LazySelfTest::untested(),
            ),
            Ok(encrypted.data)
        );
        assert!(!runtime.entropy_bad);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn starved_generator_no_result_not_key_error() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let parent = ecc_parent(&runtime);
        starve_the_generator(&mut runtime);

        let outcome = secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL).err();
        assert_eq!(outcome, Some(TPM_RC_NO_RESULT));
        assert_ne!(
            outcome,
            Some(TPM_RC_KEY),
            "a valid ECC parent is never blamed for a generator failure"
        );
    }

    #[test]
    fn starved_generator_runtime_usability() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let parent = ecc_parent(&runtime);
        starve_the_generator(&mut runtime);

        assert!(secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL).is_err());
        assert!(runtime.entropy_bad, "the entropy failure is recorded");
        assert!(
            !runtime.failure_mode,
            "a starved generator is not a fatal self-test failure"
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.drbg_magic,
            crate::library::tpm2::crypto::DRBG_MAGIC,
            "the live generator is returned to the runtime"
        );
    }

    #[test]
    fn off_curve_public_point_key_error() {
        let clock = clock();
        let mut runtime = ecc_runtime(&clock);
        let mut parent = ecc_parent(&runtime);
        let OwnedPublicId::Ecc { y, .. } = &mut parent.public.unique else {
            panic!("an ECC parent");
        };
        let last = y.len() - 1;
        y[last] ^= 0x01;

        assert_eq!(
            secret_encrypt(&mut runtime, &parent.public, DUPLICATE_LABEL).err(),
            Some(TPM_RC_KEY)
        );
    }
}
