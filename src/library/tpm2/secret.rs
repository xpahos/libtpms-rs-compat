use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_BINDING, TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_KEY,
    TPM_RC_NO_RESULT, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::algorithm::{TPM_ALG_ECC, TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSA};
use super::crypto::{BigUint, curve_parameters, kdfe, oaep_decode, rsa_private_key_op};
use super::marshal::{BlobReader, Tpm2bError};
use super::persistent::{OwnedObjectBody, OwnedPrivateExponent, OwnedPublicId};
use super::public::PublicParms;
use super::session::digest_size;

pub(super) const SECRET_LABEL: &[u8] = b"SECRET\0";

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

pub(super) fn rsa_secret_reaches_self_test(body: &OwnedObjectBody, secret: &[u8]) -> bool {
    let Ok(modulus) = rsa_modulus(body) else {
        return false;
    };
    oaep_hash_algorithm(body).is_ok() && secret.len() == modulus.len()
}

fn rsa_decrypt(body: &OwnedObjectBody, secret: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let hash_alg = oaep_hash_algorithm(body)?;
    let limit = digest_size(hash_alg).ok_or(TPM_RC_SCHEME)?;

    let modulus = rsa_modulus(body)?;
    if secret.len() != modulus.len() {
        return Err(TPM_RC_SIZE);
    }
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

    let recovered = oaep_decode(hash_alg, SECRET_LABEL, &padded).ok_or(TPM_RC_VALUE)?;
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

fn ecc_decrypt(body: &OwnedObjectBody, secret: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let PublicParms::Ecc { curve_id, .. } = &body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let curve = curve_parameters(*curve_id).ok_or(TPM_RC_FAILURE)?;
    let (public_x, public_y) = read_ecc_point(secret)?;

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
    kdfe(
        body.public.name_alg,
        &z,
        SECRET_LABEL,
        public_x,
        x,
        bits as u32,
    )
    .ok_or(TPM_RC_FAILURE)
}

pub(super) fn secret_decrypt(body: &OwnedObjectBody, secret: &[u8]) -> Result<Vec<u8>, TpmResult> {
    match body.public.object_type {
        TPM_ALG_RSA => rsa_decrypt(body, secret),
        TPM_ALG_ECC => ecc_decrypt(body, secret),
        _ => Err(TPM_RC_KEY),
    }
}
