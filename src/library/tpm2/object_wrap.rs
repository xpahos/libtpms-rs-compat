use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INTEGRITY, TPM_RC_SENSITIVE, TPM_RC_SIZE, TPM_RC_SYMMETRIC, TPM_RC_VALUE,
};
use crate::types::TpmResult;

use super::crypto::{
    Hasher, HmacState, SeededRand, kdfa, sym_block_size, sym_cfb_decrypt, sym_cfb_encrypt,
};
use super::persistent::{OwnedTpmtPublic, OwnedTpmtSensitive};
use super::public::{DIGEST_SIZE, PublicParms, SymDefObject, TPM_ALG_NULL};
use super::self_test::LazySelfTest;
use super::session::digests_equal;
use super::template::{TemplateReader, digest_size};

pub(super) const STORAGE_KEY_LABEL: &[u8] = b"STORAGE\0";
pub(super) const INTEGRITY_KEY_LABEL: &[u8] = b"INTEGRITY\0";

pub(super) const MAX_PRIVATE: usize = 1230;

pub(super) const MAX_ID_OBJECT: usize = 2 * (2 + DIGEST_SIZE);

const MAX_SYM_BLOCK_SIZE: usize = 16;

pub(super) struct Protector<'a> {
    pub(super) public: &'a OwnedTpmtPublic,
    pub(super) seed_value: &'a [u8],
}

impl Protector<'_> {
    fn kdf_seed<'a>(&'a self, external: Option<&'a [u8]>) -> &'a [u8] {
        external.unwrap_or(self.seed_value)
    }
}

pub(super) fn parent_storage_symmetric(
    parent_public: &OwnedTpmtPublic,
) -> Result<(u16, u16), TpmResult> {
    let symmetric = match &parent_public.parameters {
        PublicParms::Rsa { symmetric, .. } | PublicParms::Ecc { symmetric, .. } => symmetric,
        PublicParms::SymCipher(sym) => sym,
        PublicParms::KeyedHash(_) => return Err(TPM_RC_FAILURE),
    };
    Ok((symmetric.algorithm, symmetric.key_bits.unwrap_or(0)))
}

fn storage_key(
    hash_alg: u16,
    seed: &[u8],
    name: &[u8],
    key_bits: u16,
) -> Result<Vec<u8>, TpmResult> {
    let key_bytes = usize::from(key_bits).div_ceil(8);
    kdfa(
        hash_alg,
        seed,
        STORAGE_KEY_LABEL,
        name,
        &[],
        (key_bytes * 8) as u32,
    )
    .ok_or(TPM_RC_FAILURE)
}

fn outer_integrity(
    hash_alg: u16,
    seed: &[u8],
    name: &[u8],
    protected: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let digest = digest_size(hash_alg).ok_or(TPM_RC_FAILURE)?;
    let hmac_key = kdfa(
        hash_alg,
        seed,
        INTEGRITY_KEY_LABEL,
        &[],
        &[],
        (digest * 8) as u32,
    )
    .ok_or(TPM_RC_FAILURE)?;
    let mut hmac = HmacState::new(hash_alg, &hmac_key).ok_or(TPM_RC_FAILURE)?;
    hmac.update(protected);
    hmac.update(name);
    Ok(hmac.finalize())
}

pub(super) fn produce_outer_wrap(
    protector: &Protector<'_>,
    name: &[u8],
    hash_alg: u16,
    seed: Option<&[u8]>,
    use_iv: bool,
    data: &[u8],
    gate: &mut LazySelfTest<'_>,
    rand: &mut SeededRand,
) -> Result<Vec<u8>, TpmResult> {
    let (sym_alg, key_bits) = parent_storage_symmetric(protector.public)?;
    let iv = if use_iv {
        let block_size = sym_block_size(sym_alg).ok_or(TPM_RC_SYMMETRIC)?;
        match rand.random_bytes(block_size) {
            Ok(iv) => iv,
            Err(_) if rand.live_entropy_starved() => vec![0; block_size],
            Err(code) => return Err(code),
        }
    } else {
        Vec::new()
    };

    let kdf_seed = protector.kdf_seed(seed);
    gate.algorithm(hash_alg)?;
    let sym_key = storage_key(hash_alg, kdf_seed, name, key_bits)?;
    let cipher_iv = if use_iv {
        iv.clone()
    } else {
        vec![0u8; sym_block_size(sym_alg).ok_or(TPM_RC_SYMMETRIC)?]
    };
    let mut encrypted = data.to_vec();
    if !encrypted.is_empty() {
        gate.algorithm(sym_alg)?;
    }
    sym_cfb_encrypt(sym_alg, &sym_key, &cipher_iv, &mut encrypted)?;

    let mut protected = Vec::with_capacity(2 + iv.len() + encrypted.len());
    if use_iv {
        protected.extend_from_slice(&(iv.len() as u16).to_be_bytes());
        protected.extend_from_slice(&iv);
    }
    protected.extend_from_slice(&encrypted);

    let integrity = outer_integrity(hash_alg, kdf_seed, name, &protected)?;
    let mut out = Vec::with_capacity(2 + integrity.len() + protected.len());
    out.extend_from_slice(&(integrity.len() as u16).to_be_bytes());
    out.extend_from_slice(&integrity);
    out.extend_from_slice(&protected);
    Ok(out)
}

pub(super) fn unwrap_outer(
    protector: &Protector<'_>,
    name: &[u8],
    hash_alg: u16,
    seed: Option<&[u8]>,
    use_iv: bool,
    blob: &[u8],
    block_size_error: TpmResult,
    gate: &mut LazySelfTest<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let (sym_alg, key_bits) = parent_storage_symmetric(protector.public)?;
    let block_size = sym_block_size(sym_alg).ok_or(block_size_error)?;

    let mut reader = TemplateReader::new(blob);
    let integrity = reader.tpm2b(DIGEST_SIZE)?;
    let protected_start = reader.consumed();
    let protected = blob.get(protected_start..).ok_or(TPM_RC_FAILURE)?;

    let kdf_seed = protector.kdf_seed(seed);
    gate.algorithm(hash_alg)?;
    if !digests_equal(
        integrity,
        &outer_integrity(hash_alg, kdf_seed, name, protected)?,
    ) {
        return Err(TPM_RC_INTEGRITY);
    }

    let sym_key = storage_key(hash_alg, kdf_seed, name, key_bits)?;
    let (iv, cipher_start) = if use_iv {
        let mut iv_reader = TemplateReader::new(protected);
        let iv = iv_reader.tpm2b(MAX_SYM_BLOCK_SIZE)?.to_vec();
        if iv.len() != block_size {
            return Err(TPM_RC_VALUE);
        }
        let consumed = iv_reader.consumed();
        (iv, consumed)
    } else {
        (vec![0u8; block_size], 0)
    };

    let mut payload = protected
        .get(cipher_start..)
        .ok_or(TPM_RC_FAILURE)?
        .to_vec();
    if !payload.is_empty() {
        gate.algorithm(sym_alg)?;
    }
    sym_cfb_decrypt(sym_alg, &sym_key, &iv, &mut payload)?;
    Ok(payload)
}

pub(super) fn secret_to_credential(
    credential: &[u8],
    name: &[u8],
    seed: &[u8],
    protector: &Protector<'_>,
    gate: &mut LazySelfTest<'_>,
    rand: &mut SeededRand,
) -> Result<Vec<u8>, TpmResult> {
    let outer_hash = protector.public.name_alg;
    let mut marshalled = Vec::with_capacity(2 + credential.len());
    marshalled.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    marshalled.extend_from_slice(credential);
    produce_outer_wrap(
        protector,
        name,
        outer_hash,
        Some(seed),
        false,
        &marshalled,
        gate,
        rand,
    )
}

pub(super) fn credential_to_secret(
    blob: &[u8],
    name: &[u8],
    seed: &[u8],
    protector: &Protector<'_>,
    gate: &mut LazySelfTest<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let outer_hash = protector.public.name_alg;
    let payload = unwrap_outer(
        protector,
        name,
        outer_hash,
        Some(seed),
        false,
        blob,
        TPM_RC_FAILURE,
        gate,
    )?;
    let mut reader = TemplateReader::new(&payload);
    let secret = reader.tpm2b(DIGEST_SIZE)?.to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(secret)
}

fn inner_integrity(hash_alg: u16, name: &[u8], data: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(data);
    hasher.update(name);
    Ok(hasher.finalize())
}

pub(super) fn produce_inner_integrity(
    name: &[u8],
    hash_alg: u16,
    data: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let integrity = inner_integrity(hash_alg, name, data)?;
    let mut out = Vec::with_capacity(2 + integrity.len() + data.len());
    out.extend_from_slice(&(integrity.len() as u16).to_be_bytes());
    out.extend_from_slice(&integrity);
    out.extend_from_slice(data);
    Ok(out)
}

pub(super) fn check_inner_integrity(
    name: &[u8],
    hash_alg: u16,
    blob: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let mut reader = TemplateReader::new(blob);
    let integrity = reader.tpm2b(DIGEST_SIZE)?;
    let payload = reader.remaining();
    if !digests_equal(integrity, &inner_integrity(hash_alg, name, payload)?) {
        return Err(TPM_RC_INTEGRITY);
    }
    Ok(payload.to_vec())
}

pub(super) fn marshal_sensitive(
    sensitive: &OwnedTpmtSensitive,
    name_alg: u16,
) -> Result<Vec<u8>, TpmResult> {
    let digest = digest_size(name_alg).ok_or(TPM_RC_FAILURE)?;
    let mut auth_value = sensitive.auth_value.as_bytes().to_vec();
    if auth_value.len() < digest {
        auth_value.resize(digest, 0);
    }
    let mut writer = super::marshal::BlobWriter::new();
    writer.write_u16(sensitive.sensitive_type);
    writer
        .write_tpm2b(&auth_value)
        .map_err(|_| TPM_RC_FAILURE)?;
    writer
        .write_tpm2b(sensitive.seed_value.as_bytes())
        .map_err(|_| TPM_RC_FAILURE)?;
    writer
        .write_tpm2b(
            sensitive
                .sensitive
                .as_ref()
                .map_or(&[][..], |secret| secret.as_bytes()),
        )
        .map_err(|_| TPM_RC_FAILURE)?;
    let body = writer.into_bytes();
    let mut out = (body.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

fn inner_wrap_key_bytes(symmetric: &SymDefObject) -> usize {
    usize::from(symmetric.key_bits.unwrap_or(0)).div_ceil(8)
}

fn inner_cipher_iv(symmetric: &SymDefObject) -> Result<Vec<u8>, TpmResult> {
    Ok(vec![
        0u8;
        sym_block_size(symmetric.algorithm)
            .ok_or(TPM_RC_SYMMETRIC)?
    ])
}

pub(super) struct DuplicationBlob {
    pub(super) blob: Vec<u8>,
    pub(super) generated_inner_key: Option<Vec<u8>>,
}

pub(super) fn sensitive_to_duplicate(
    sensitive: &OwnedTpmtSensitive,
    name: &[u8],
    parent: Option<&Protector<'_>>,
    name_alg: u16,
    seed: &[u8],
    symmetric: &SymDefObject,
    inner_key: &[u8],
    rand: &mut SeededRand,
) -> Result<DuplicationBlob, TpmResult> {
    let mut data = marshal_sensitive(sensitive, name_alg)?;
    let mut generated_inner_key = None;

    if symmetric.algorithm != TPM_ALG_NULL {
        data = produce_inner_integrity(name, name_alg, &data)?;
        let key = if inner_key.is_empty() {
            let bytes = inner_wrap_key_bytes(symmetric);
            let generated = match rand.random_bytes(bytes) {
                Ok(key) => key,
                Err(_) if rand.live_entropy_starved() => vec![0; bytes],
                Err(code) => return Err(code),
            };
            generated_inner_key = Some(generated.clone());
            generated
        } else {
            inner_key.to_vec()
        };
        let iv = inner_cipher_iv(symmetric)?;
        sym_cfb_encrypt(symmetric.algorithm, &key, &iv, &mut data)?;
    }

    if !seed.is_empty() {
        let parent = parent.ok_or(TPM_RC_FAILURE)?;
        let outer_hash = parent.public.name_alg;
        data = produce_outer_wrap(
            parent,
            name,
            outer_hash,
            Some(seed),
            false,
            &data,
            &mut LazySelfTest::untested(),
            rand,
        )?;
    }

    Ok(DuplicationBlob {
        blob: data,
        generated_inner_key,
    })
}

pub(super) fn duplicate_to_sensitive(
    blob: &[u8],
    name: &[u8],
    parent: Option<&Protector<'_>>,
    name_alg: u16,
    seed: &[u8],
    symmetric: &SymDefObject,
    inner_key: &[u8],
) -> Result<OwnedTpmtSensitive, TpmResult> {
    let mut payload = if seed.is_empty() {
        blob.to_vec()
    } else {
        let parent = parent.ok_or(TPM_RC_FAILURE)?;
        let outer_hash = parent.public.name_alg;
        unwrap_outer(
            parent,
            name,
            outer_hash,
            Some(seed),
            false,
            blob,
            TPM_RC_FAILURE,
            &mut LazySelfTest::untested(),
        )?
    };

    if symmetric.algorithm != TPM_ALG_NULL {
        let iv = inner_cipher_iv(symmetric)?;
        sym_cfb_decrypt(symmetric.algorithm, inner_key, &iv, &mut payload)?;
        payload = check_inner_integrity(name, name_alg, &payload)?;
    }

    unmarshal_sized_sensitive(&payload, TPM_RC_SIZE)
}

fn unmarshal_sized_sensitive(
    payload: &[u8],
    length_error: TpmResult,
) -> Result<OwnedTpmtSensitive, TpmResult> {
    let mut reader = TemplateReader::new(payload);
    let declared = usize::from(reader.u16()?);
    if declared + 2 != payload.len() {
        return Err(length_error);
    }
    let sensitive = super::object_load::read_sensitive_area(&mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(length_error);
    }
    Ok(sensitive)
}

pub(super) fn sensitive_to_private(
    sensitive: &OwnedTpmtSensitive,
    name: &[u8],
    parent: &Protector<'_>,
    name_alg: u16,
    rand: &mut SeededRand,
) -> Result<Vec<u8>, TpmResult> {
    let hash_alg = parent.public.name_alg;
    let data = marshal_sensitive(sensitive, name_alg)?;
    produce_outer_wrap(
        parent,
        name,
        hash_alg,
        None,
        true,
        &data,
        &mut LazySelfTest::untested(),
        rand,
    )
}

pub(super) fn private_to_sensitive(
    in_private: &[u8],
    name: &[u8],
    parent: &Protector<'_>,
) -> Result<OwnedTpmtSensitive, TpmResult> {
    let hash_alg = parent.public.name_alg;
    let payload = unwrap_outer(
        parent,
        name,
        hash_alg,
        None,
        true,
        in_private,
        TPM_RC_FAILURE,
        &mut LazySelfTest::untested(),
    )?;
    let mut reader = TemplateReader::new(&payload);
    let declared = usize::from(reader.u16().map_err(|_| TPM_RC_SENSITIVE)?);
    if declared + 2 != payload.len() {
        return Err(TPM_RC_SENSITIVE);
    }
    let sensitive =
        super::object_load::read_sensitive_area(&mut reader).map_err(|_| TPM_RC_SENSITIVE)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SENSITIVE);
    }
    Ok(sensitive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RC_TYPE};
    use crate::library::tpm2::object_create::PRIMARY_OBJECT_CREATION;
    use crate::library::tpm2::persistent::OwnedSecret;
    use crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE;
    use crate::library::tpm2::public::{
        StateFormatLimit, TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_CFB, TPM_ALG_ECC,
        TPM_ALG_KEYEDHASH, TPM_ALG_RSA, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SYMCIPHER,
        TPM_ALG_TDES,
    };
    use crate::library::tpm2::template::{
        AlgorithmPolicy, TPMA_OBJECT_DECRYPT, TPMA_OBJECT_FIXED_PARENT, TPMA_OBJECT_FIXED_TPM,
        TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN, TPMA_OBJECT_SIGN,
        TPMA_OBJECT_USER_WITH_AUTH, TemplateReader, parse_public_area,
    };

    const NAME: [u8; 34] = [0x11; 34];
    const OTHER_NAME: [u8; 34] = [0x12; 34];
    const SEED: [u8; 32] = [0x22; 32];

    fn no_gate() -> LazySelfTest<'static> {
        LazySelfTest::untested()
    }

    fn rand(label: &[u8]) -> SeededRand {
        SeededRand::instantiate(&[0x77; 64], PRIMARY_OBJECT_CREATION, label, &[], 1, false)
            .expect("a non-empty derivation input")
    }

    fn policy() -> AlgorithmPolicy<'static> {
        AlgorithmPolicy {
            profile_algorithms: DEFAULT_ALGORITHMS_PROFILE,
            state_format: StateFormatLimit::CURRENT,
        }
    }

    fn named_template(
        object_type: u16,
        name_alg: u16,
        attributes: u32,
        tail: &[u8],
    ) -> OwnedTpmtPublic {
        let mut bytes = object_type.to_be_bytes().to_vec();
        bytes.extend_from_slice(&name_alg.to_be_bytes());
        bytes.extend_from_slice(&attributes.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(tail);
        let mut reader = TemplateReader::new(&bytes);
        parse_public_area(&mut reader, &policy(), false).expect("a valid template")
    }

    fn template(object_type: u16, attributes: u32, tail: &[u8]) -> OwnedTpmtPublic {
        named_template(object_type, TPM_ALG_SHA256, attributes, tail)
    }

    fn parent(sym_algorithm: u16) -> OwnedTpmtPublic {
        parent_named(sym_algorithm, TPM_ALG_SHA256)
    }

    fn parent_named(sym_algorithm: u16, name_alg: u16) -> OwnedTpmtPublic {
        let mut tail = sym_algorithm.to_be_bytes().to_vec();
        tail.extend_from_slice(&128u16.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&2048u16.to_be_bytes());
        tail.extend_from_slice(&0u32.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        named_template(
            TPM_ALG_RSA,
            name_alg,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT,
            &tail,
        )
    }

    fn keyed_hash_parent() -> OwnedTpmtPublic {
        let mut tail = TPM_ALG_NULL.to_be_bytes().to_vec();
        tail.extend_from_slice(&0u16.to_be_bytes());
        template(
            TPM_ALG_KEYEDHASH,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_SIGN
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN,
            &tail,
        )
    }

    fn child_sensitive() -> OwnedTpmtSensitive {
        OwnedTpmtSensitive {
            sensitive_type: TPM_ALG_SYMCIPHER,
            auth_value: OwnedSecret::from_vec(vec![0u8; 32]),
            seed_value: OwnedSecret::from_vec(vec![0x44; 32]),
            sensitive: Some(OwnedSecret::from_vec(vec![0x55; 16])),
        }
    }

    fn protector<'a>(public: &'a OwnedTpmtPublic, seed: &'a [u8]) -> Protector<'a> {
        Protector {
            public,
            seed_value: seed,
        }
    }

    fn sym(algorithm: u16, key_bits: u16) -> SymDefObject {
        SymDefObject {
            algorithm,
            key_bits: Some(key_bits),
            mode: Some(TPM_ALG_CFB),
        }
    }

    fn null_sym() -> SymDefObject {
        SymDefObject {
            algorithm: TPM_ALG_NULL,
            key_bits: None,
            mode: None,
        }
    }

    fn wrap(sym_algorithm: u16, name: &[u8], seed: &[u8], rand_label: &[u8]) -> Vec<u8> {
        sensitive_to_private(
            &child_sensitive(),
            name,
            &protector(&parent(sym_algorithm), seed),
            TPM_ALG_SHA256,
            &mut rand(rand_label),
        )
        .expect("the wrap succeeds")
    }

    #[test]
    fn the_iv_length_follows_the_parent_block_size() {
        for (algorithm, iv_len) in [
            (TPM_ALG_AES, 16u16),
            (TPM_ALG_TDES, 8),
            (TPM_ALG_CAMELLIA, 16),
        ] {
            let blob = wrap(algorithm, &NAME, &SEED, b"iv");
            let declared = u16::from_be_bytes(blob[34..36].try_into().unwrap());
            assert_eq!(declared, iv_len, "algorithm {algorithm:#06x}");
        }
    }

    #[test]
    fn the_child_name_and_parent_seed_bind_the_wrap() {
        let baseline = wrap(TPM_ALG_AES, &NAME, &SEED, b"bind");
        assert_eq!(baseline, wrap(TPM_ALG_AES, &NAME, &SEED, b"bind"));
        assert_ne!(baseline, wrap(TPM_ALG_AES, &OTHER_NAME, &SEED, b"bind"));
        assert_ne!(baseline, wrap(TPM_ALG_AES, &NAME, &[0x23; 32], b"bind"));
        assert_ne!(baseline, wrap(TPM_ALG_TDES, &NAME, &SEED, b"bind"));
    }

    #[test]
    fn a_keyed_hash_parent_cannot_wrap() {
        assert_eq!(
            sensitive_to_private(
                &child_sensitive(),
                &NAME,
                &protector(&keyed_hash_parent(), &SEED),
                TPM_ALG_SHA256,
                &mut rand(b"kh"),
            ),
            Err(TPM_RC_FAILURE)
        );
    }

    #[test]
    fn the_private_blob_round_trips_through_the_shared_layer() {
        let parent = parent(TPM_ALG_AES);
        let blob = wrap(TPM_ALG_AES, &NAME, &SEED, b"round");
        let recovered = private_to_sensitive(&blob, &NAME, &protector(&parent, &SEED))
            .expect("the unwrap succeeds");
        assert_eq!(recovered.sensitive_type, TPM_ALG_SYMCIPHER);
        assert_eq!(recovered.seed_value.as_bytes(), &[0x44; 32]);
        assert_eq!(
            recovered.sensitive.as_ref().unwrap().as_bytes(),
            &[0x55; 16]
        );
    }

    #[test]
    fn a_private_blob_is_bound_to_its_name_and_its_parent_seed() {
        let parent = parent(TPM_ALG_AES);
        let blob = wrap(TPM_ALG_AES, &NAME, &SEED, b"bound");
        assert_eq!(
            private_to_sensitive(&blob, &OTHER_NAME, &protector(&parent, &SEED)).err(),
            Some(TPM_RC_INTEGRITY)
        );
        assert_eq!(
            private_to_sensitive(&blob, &NAME, &protector(&parent, &[0x23; 32])).err(),
            Some(TPM_RC_INTEGRITY)
        );
        for position in [0usize, 2, 34, 40, blob.len() - 1] {
            let mut corrupt = blob.clone();
            corrupt[position] ^= 0x01;
            assert!(
                private_to_sensitive(&corrupt, &NAME, &protector(&parent, &SEED)).is_err(),
                "byte {position}"
            );
        }
    }

    #[test]
    fn the_outer_wrapper_of_a_duplicate_carries_no_initialization_vector() {
        let parent = parent(TPM_ALG_AES);
        let wrapped = produce_outer_wrap(
            &protector(&parent, &[]),
            &NAME,
            TPM_ALG_SHA256,
            Some(&SEED),
            false,
            b"payload",
            &mut no_gate(),
            &mut rand(b"outer"),
        )
        .expect("the wrap succeeds");
        assert_eq!(wrapped.len(), 2 + 32 + 7);
        assert_eq!(&wrapped[..2], &32u16.to_be_bytes());
        let recovered = unwrap_outer(
            &protector(&parent, &[]),
            &NAME,
            TPM_ALG_SHA256,
            Some(&SEED),
            false,
            &wrapped,
            TPM_RC_FAILURE,
            &mut no_gate(),
        )
        .expect("the unwrap succeeds");
        assert_eq!(recovered, b"payload");
    }

    #[test]
    fn the_outer_integrity_is_the_reference_hmac_over_the_protected_bytes() {
        let parent = parent(TPM_ALG_AES);
        let wrapped = produce_outer_wrap(
            &protector(&parent, &[]),
            &NAME,
            TPM_ALG_SHA256,
            Some(&SEED),
            false,
            b"payload",
            &mut no_gate(),
            &mut rand(b"hmac"),
        )
        .expect("the wrap succeeds");
        let hmac_key = kdfa(TPM_ALG_SHA256, &SEED, INTEGRITY_KEY_LABEL, &[], &[], 32 * 8)
            .expect("the integrity key derives");
        let mut hmac = HmacState::new(TPM_ALG_SHA256, &hmac_key).expect("sha256 hmac");
        hmac.update(&wrapped[34..]);
        hmac.update(&NAME);
        assert_eq!(&wrapped[2..34], hmac.finalize().as_slice());

        let sym_key = kdfa(TPM_ALG_SHA256, &SEED, STORAGE_KEY_LABEL, &NAME, &[], 128)
            .expect("the storage key derives");
        let mut plaintext = wrapped[34..].to_vec();
        sym_cfb_decrypt(TPM_ALG_AES, &sym_key, &[0u8; 16], &mut plaintext)
            .expect("the payload decrypts");
        assert_eq!(plaintext, b"payload");
    }

    #[test]
    fn a_wrong_outer_seed_or_name_is_an_integrity_failure() {
        let parent = parent(TPM_ALG_AES);
        let wrapped = produce_outer_wrap(
            &protector(&parent, &[]),
            &NAME,
            TPM_ALG_SHA256,
            Some(&SEED),
            false,
            b"payload",
            &mut no_gate(),
            &mut rand(b"reject"),
        )
        .expect("the wrap succeeds");
        for (name, seed) in [(&OTHER_NAME[..], &SEED[..]), (&NAME[..], &[0x23u8; 32][..])] {
            assert_eq!(
                unwrap_outer(
                    &protector(&parent, &[]),
                    name,
                    TPM_ALG_SHA256,
                    Some(seed),
                    false,
                    &wrapped,
                    TPM_RC_FAILURE,
                    &mut no_gate(),
                ),
                Err(TPM_RC_INTEGRITY)
            );
        }
    }

    #[test]
    fn the_inner_integrity_hashes_the_payload_and_the_name() {
        let wrapped = produce_inner_integrity(&NAME, TPM_ALG_SHA256, b"payload")
            .expect("the integrity is produced");
        let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("sha256");
        hasher.update(b"payload");
        hasher.update(&NAME);
        assert_eq!(&wrapped[..2], &32u16.to_be_bytes());
        assert_eq!(&wrapped[2..34], hasher.finalize().as_slice());
        assert_eq!(&wrapped[34..], b"payload");
        assert_eq!(
            check_inner_integrity(&NAME, TPM_ALG_SHA256, &wrapped).expect("the check passes"),
            b"payload"
        );
        assert_eq!(
            check_inner_integrity(&OTHER_NAME, TPM_ALG_SHA256, &wrapped),
            Err(TPM_RC_INTEGRITY)
        );
        assert_eq!(
            check_inner_integrity(&NAME, TPM_ALG_SHA384, &wrapped),
            Err(TPM_RC_INTEGRITY)
        );
        assert_eq!(
            check_inner_integrity(&NAME, TPM_ALG_SHA256, &[]),
            Err(TPM_RC_INSUFFICIENT)
        );
    }

    #[test]
    fn every_duplication_wrapper_combination_round_trips() {
        let parent = parent(TPM_ALG_AES);
        for (label, seed, symmetric, key) in [
            (&b"plain"[..], &[][..], null_sym(), &[][..]),
            (&b"outer"[..], &SEED[..], null_sym(), &[][..]),
            (
                &b"inner"[..],
                &[][..],
                sym(TPM_ALG_AES, 128),
                &[0xa5u8; 16][..],
            ),
            (
                &b"both"[..],
                &SEED[..],
                sym(TPM_ALG_AES, 128),
                &[0xa5u8; 16][..],
            ),
        ] {
            let produced = sensitive_to_duplicate(
                &child_sensitive(),
                &NAME,
                Some(&protector(&parent, &[])),
                TPM_ALG_SHA256,
                seed,
                &symmetric,
                key,
                &mut rand(label),
            )
            .expect("the duplication blob is produced");
            assert!(produced.generated_inner_key.is_none());
            let recovered = duplicate_to_sensitive(
                &produced.blob,
                &NAME,
                Some(&protector(&parent, &[])),
                TPM_ALG_SHA256,
                seed,
                &symmetric,
                key,
            )
            .expect("the duplication blob is recovered");
            assert_eq!(
                recovered.sensitive.as_ref().unwrap().as_bytes(),
                &[0x55; 16],
                "{}",
                String::from_utf8_lossy(label)
            );
            assert_eq!(recovered.seed_value.as_bytes(), &[0x44; 32]);
        }
    }

    #[test]
    fn an_absent_inner_key_is_generated_from_the_supplied_generator() {
        let parent = parent(TPM_ALG_AES);
        let produced = sensitive_to_duplicate(
            &child_sensitive(),
            &NAME,
            Some(&protector(&parent, &[])),
            TPM_ALG_SHA256,
            &SEED,
            &sym(TPM_ALG_AES, 128),
            &[],
            &mut rand(b"generated"),
        )
        .expect("the duplication blob is produced");
        let key = produced
            .generated_inner_key
            .as_ref()
            .expect("the TPM generated a key");
        assert_eq!(key.len(), 16);
        assert_eq!(
            key.as_slice(),
            rand(b"generated").random_bytes(16).unwrap().as_slice(),
            "the key is the next block from the generator"
        );
        assert!(
            duplicate_to_sensitive(
                &produced.blob,
                &NAME,
                Some(&protector(&parent, &[])),
                TPM_ALG_SHA256,
                &SEED,
                &sym(TPM_ALG_AES, 128),
                key,
            )
            .is_ok()
        );
    }

    #[test]
    fn a_duplicate_is_bound_to_its_name_its_seed_and_its_inner_key() {
        let parent = parent(TPM_ALG_AES);
        let key = [0xa5u8; 16];
        let produced = sensitive_to_duplicate(
            &child_sensitive(),
            &NAME,
            Some(&protector(&parent, &[])),
            TPM_ALG_SHA256,
            &SEED,
            &sym(TPM_ALG_AES, 128),
            &key,
            &mut rand(b"bound"),
        )
        .expect("the duplication blob is produced");
        let recover = |name: &[u8], seed: &[u8], key: &[u8]| {
            duplicate_to_sensitive(
                &produced.blob,
                name,
                Some(&protector(&parent, &[])),
                TPM_ALG_SHA256,
                seed,
                &sym(TPM_ALG_AES, 128),
                key,
            )
        };
        assert_eq!(
            recover(&OTHER_NAME, &SEED, &key).err(),
            Some(TPM_RC_INTEGRITY)
        );
        assert_eq!(
            recover(&NAME, &[0x23; 32], &key).err(),
            Some(TPM_RC_INTEGRITY)
        );
        assert!(recover(&NAME, &SEED, &[0x5a; 16]).is_err());
        assert!(recover(&NAME, &SEED, &key).is_ok());
    }

    #[test]
    fn a_corrupted_duplication_blob_never_yields_a_sensitive_area() {
        let parent = parent(TPM_ALG_AES);
        let produced = sensitive_to_duplicate(
            &child_sensitive(),
            &NAME,
            Some(&protector(&parent, &[])),
            TPM_ALG_SHA256,
            &SEED,
            &null_sym(),
            &[],
            &mut rand(b"corrupt"),
        )
        .expect("the duplication blob is produced");
        for position in 0..produced.blob.len() {
            let mut corrupt = produced.blob.clone();
            corrupt[position] ^= 0x01;
            assert!(
                duplicate_to_sensitive(
                    &corrupt,
                    &NAME,
                    Some(&protector(&parent, &[])),
                    TPM_ALG_SHA256,
                    &SEED,
                    &null_sym(),
                    &[],
                )
                .is_err(),
                "byte {position}"
            );
        }
    }

    #[test]
    fn every_prefix_of_a_duplication_blob_is_rejected_without_panicking() {
        let parent = parent(TPM_ALG_AES);
        let produced = sensitive_to_duplicate(
            &child_sensitive(),
            &NAME,
            Some(&protector(&parent, &[])),
            TPM_ALG_SHA256,
            &[],
            &sym(TPM_ALG_AES, 128),
            &[0xa5; 16],
            &mut rand(b"prefix"),
        )
        .expect("the duplication blob is produced");
        for length in 0..produced.blob.len() {
            let outcome = duplicate_to_sensitive(
                &produced.blob[..length],
                &NAME,
                Some(&protector(&parent, &[])),
                TPM_ALG_SHA256,
                &[],
                &sym(TPM_ALG_AES, 128),
                &[0xa5; 16],
            );
            assert!(outcome.is_err(), "prefix {length}");
        }
    }

    fn ecc_parent() -> OwnedTpmtPublic {
        let mut tail = TPM_ALG_AES.to_be_bytes().to_vec();
        tail.extend_from_slice(&128u16.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&0x0003u16.to_be_bytes());
        tail.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        tail.extend_from_slice(&0u16.to_be_bytes());
        template(
            TPM_ALG_ECC,
            TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT,
            &tail,
        )
    }

    const RSA_DERIVED_SEED: [u8; 32] = [0x31; 32];
    const ECC_DERIVED_SEED: [u8; 32] = [0x32; 32];
    const CREDENTIAL: [u8; 32] = [0x77; 32];

    fn credential_protectors() -> [(&'static str, OwnedTpmtPublic, [u8; 32]); 2] {
        [
            ("an RSA-derived seed", parent(TPM_ALG_AES), RSA_DERIVED_SEED),
            ("an ECC-derived seed", ecc_parent(), ECC_DERIVED_SEED),
        ]
    }

    fn credential_blob(public: &OwnedTpmtPublic, credential: &[u8], seed: &[u8]) -> Vec<u8> {
        secret_to_credential(
            credential,
            &NAME,
            seed,
            &protector(public, &[]),
            &mut no_gate(),
            &mut rand(b"credential"),
        )
        .expect("the credential is produced")
    }

    #[test]
    fn a_credential_round_trips_for_every_protector_shape() {
        for (label, public, seed) in credential_protectors() {
            for credential in [&[][..], &[0xaa][..], &CREDENTIAL[..]] {
                let blob = credential_blob(&public, credential, &seed);
                assert_eq!(
                    blob.len(),
                    2 + 32 + 2 + credential.len(),
                    "{label}: integrity, then the marshalled digest"
                );
                assert_eq!(&blob[..2], &32u16.to_be_bytes());
                assert_eq!(
                    blob,
                    credential_blob(&public, credential, &seed),
                    "{label}: the wrap is deterministic"
                );
                assert_eq!(
                    credential_to_secret(
                        &blob,
                        &NAME,
                        &seed,
                        &protector(&public, &[]),
                        &mut no_gate()
                    ),
                    Ok(credential.to_vec()),
                    "{label}"
                );
            }
        }
    }

    #[test]
    fn a_credential_is_bound_to_its_name_and_its_seed() {
        for (label, public, seed) in credential_protectors() {
            let blob = credential_blob(&public, &CREDENTIAL, &seed);
            for (what, name, other_seed) in [
                ("another name", &OTHER_NAME[..], &seed[..]),
                ("another seed", &NAME[..], &[0x33u8; 32][..]),
            ] {
                assert_eq!(
                    credential_to_secret(
                        &blob,
                        name,
                        other_seed,
                        &protector(&public, &[]),
                        &mut no_gate()
                    ),
                    Err(TPM_RC_INTEGRITY),
                    "{label}: {what}"
                );
            }
            assert_ne!(
                blob,
                credential_blob(&public, &CREDENTIAL, &[0x33; 32]),
                "{label}: the seed changes the blob"
            );
        }
    }

    #[test]
    fn every_corruption_of_a_credential_is_refused() {
        let public = parent(TPM_ALG_AES);
        let blob = credential_blob(&public, &CREDENTIAL, &RSA_DERIVED_SEED);
        for position in 0..blob.len() {
            let corrupt = {
                let mut out = blob.clone();
                out[position] ^= 0x01;
                out
            };
            let outcome = credential_to_secret(
                &corrupt,
                &NAME,
                &RSA_DERIVED_SEED,
                &protector(&public, &[]),
                &mut no_gate(),
            );
            let expected = if position == 0 {
                Err(TPM_RC_SIZE)
            } else {
                Err(TPM_RC_INTEGRITY)
            };
            assert_eq!(outcome, expected, "byte {position}");
        }
    }

    #[test]
    fn every_prefix_of_a_credential_is_refused_without_panicking() {
        let public = parent(TPM_ALG_AES);
        let blob = credential_blob(&public, &CREDENTIAL, &RSA_DERIVED_SEED);
        for length in 0..blob.len() {
            assert!(
                credential_to_secret(
                    &blob[..length],
                    &NAME,
                    &RSA_DERIVED_SEED,
                    &protector(&public, &[]),
                    &mut no_gate(),
                )
                .is_err(),
                "prefix {length}"
            );
        }
    }

    fn wrapped_payload(public: &OwnedTpmtPublic, payload: &[u8]) -> Vec<u8> {
        produce_outer_wrap(
            &protector(public, &[]),
            &NAME,
            TPM_ALG_SHA256,
            Some(&RSA_DERIVED_SEED),
            false,
            payload,
            &mut no_gate(),
            &mut rand(b"payload"),
        )
        .expect("the payload is wrapped")
    }

    #[test]
    fn the_decrypted_credential_must_be_exactly_one_digest() {
        let public = parent(TPM_ALG_AES);
        let mut digest = 32u16.to_be_bytes().to_vec();
        digest.extend_from_slice(&CREDENTIAL);
        for (what, payload, expected) in [
            (
                "trailing bytes",
                [digest.clone(), vec![0x00]].concat(),
                TPM_RC_SIZE,
            ),
            (
                "a truncated digest",
                digest[..digest.len() - 1].to_vec(),
                TPM_RC_INSUFFICIENT,
            ),
            ("a missing length", Vec::new(), TPM_RC_INSUFFICIENT),
            ("a single length byte", vec![0x00], TPM_RC_INSUFFICIENT),
            (
                "an oversized digest",
                65u16.to_be_bytes().to_vec(),
                TPM_RC_SIZE,
            ),
        ] {
            let blob = wrapped_payload(&public, &payload);
            assert_eq!(
                credential_to_secret(
                    &blob,
                    &NAME,
                    &RSA_DERIVED_SEED,
                    &protector(&public, &[]),
                    &mut no_gate()
                ),
                Err(expected),
                "{what}"
            );
        }
    }

    #[test]
    fn the_integrity_of_a_credential_is_compared_in_constant_time() {
        let public = parent(TPM_ALG_AES);
        let blob = credential_blob(&public, &CREDENTIAL, &RSA_DERIVED_SEED);
        for position in 2..34 {
            let mut corrupt = blob.clone();
            corrupt[position] ^= 0xff;
            assert_eq!(
                credential_to_secret(
                    &corrupt,
                    &NAME,
                    &RSA_DERIVED_SEED,
                    &protector(&public, &[]),
                    &mut no_gate()
                ),
                Err(TPM_RC_INTEGRITY),
                "a wrong digest never reveals how many leading bytes matched, byte {position}"
            );
        }
        let mut short = blob.clone();
        short[1] = 31;
        short.remove(33);
        assert_eq!(
            credential_to_secret(
                &short,
                &NAME,
                &RSA_DERIVED_SEED,
                &protector(&public, &[]),
                &mut no_gate()
            ),
            Err(TPM_RC_INTEGRITY),
            "a shorter integrity value never matches"
        );
    }

    fn recorded<'a>(
        calls: &'a mut Vec<u16>,
        failing: Option<u16>,
    ) -> impl FnMut(u16) -> Result<(), TpmResult> + 'a {
        move |algorithm| {
            calls.push(algorithm);
            if failing == Some(algorithm) {
                return Err(TPM_RC_FAILURE);
            }
            Ok(())
        }
    }

    fn gated_credential(
        public: &OwnedTpmtPublic,
        seed: &[u8],
        failing: Option<u16>,
    ) -> (Result<Vec<u8>, TpmResult>, Vec<u16>) {
        let mut calls = Vec::new();
        let produced = {
            let mut run = recorded(&mut calls, failing);
            secret_to_credential(
                &CREDENTIAL,
                &NAME,
                seed,
                &protector(public, &[]),
                &mut LazySelfTest::runtime(&mut run),
                &mut rand(b"credential"),
            )
        };
        (produced, calls)
    }

    fn gated_open(
        public: &OwnedTpmtPublic,
        seed: &[u8],
        blob: &[u8],
        failing: Option<u16>,
    ) -> (Result<Vec<u8>, TpmResult>, Vec<u16>) {
        let mut calls = Vec::new();
        let opened = {
            let mut run = recorded(&mut calls, failing);
            credential_to_secret(
                blob,
                &NAME,
                seed,
                &protector(public, &[]),
                &mut LazySelfTest::runtime(&mut run),
            )
        };
        (opened, calls)
    }

    #[test]
    fn creating_a_credential_tests_the_name_algorithm_then_the_symmetric_algorithm() {
        for (label, public, symmetric, name_alg) in [
            (
                "RSA SHA-256/AES",
                parent(TPM_ALG_AES),
                TPM_ALG_AES,
                TPM_ALG_SHA256,
            ),
            (
                "RSA SHA-384/AES",
                parent_named(TPM_ALG_AES, TPM_ALG_SHA384),
                TPM_ALG_AES,
                TPM_ALG_SHA384,
            ),
            (
                "RSA SHA-256/Camellia",
                parent(TPM_ALG_CAMELLIA),
                TPM_ALG_CAMELLIA,
                TPM_ALG_SHA256,
            ),
            ("ECC SHA-256/AES", ecc_parent(), TPM_ALG_AES, TPM_ALG_SHA256),
        ] {
            let (produced, calls) = gated_credential(&public, &RSA_DERIVED_SEED, None);
            assert!(produced.is_ok(), "{label}");
            assert_eq!(calls, [name_alg, symmetric], "{label}");
        }
    }

    #[test]
    fn a_failing_self_test_stops_the_credential_at_its_own_boundary() {
        let public = parent(TPM_ALG_AES);
        for (label, failing, expected) in [
            ("the name algorithm", TPM_ALG_SHA256, vec![TPM_ALG_SHA256]),
            (
                "the symmetric algorithm",
                TPM_ALG_AES,
                vec![TPM_ALG_SHA256, TPM_ALG_AES],
            ),
        ] {
            let (produced, calls) = gated_credential(&public, &RSA_DERIVED_SEED, Some(failing));
            assert_eq!(produced, Err(TPM_RC_FAILURE), "{label}");
            assert_eq!(calls, expected, "{label}");
        }
    }

    #[test]
    fn opening_a_credential_tests_the_symmetric_algorithm_only_after_the_integrity_matches() {
        let public = parent(TPM_ALG_AES);
        let blob = credential_blob(&public, &CREDENTIAL, &RSA_DERIVED_SEED);
        let mut oversized = blob.clone();
        oversized[0] = 0x01;

        for (label, candidate, outcome, expected) in [
            (
                "an unparsable integrity length",
                Vec::new(),
                Err(TPM_RC_INSUFFICIENT),
                vec![],
            ),
            (
                "an oversized integrity length",
                oversized,
                Err(TPM_RC_SIZE),
                vec![],
            ),
            (
                "a truncated integrity value",
                blob[..20].to_vec(),
                Err(TPM_RC_INSUFFICIENT),
                vec![],
            ),
            (
                "a wrong integrity value",
                {
                    let mut wrong = blob.clone();
                    wrong[10] ^= 0xff;
                    wrong
                },
                Err(TPM_RC_INTEGRITY),
                vec![TPM_ALG_SHA256],
            ),
            (
                "a matching integrity value",
                blob.clone(),
                Ok(CREDENTIAL.to_vec()),
                vec![TPM_ALG_SHA256, TPM_ALG_AES],
            ),
        ] {
            let (opened, calls) = gated_open(&public, &RSA_DERIVED_SEED, &candidate, None);
            assert_eq!(opened, outcome, "{label}");
            assert_eq!(calls, expected, "{label}");
        }
    }

    #[test]
    fn a_failing_self_test_stops_the_credential_open_at_its_own_boundary() {
        let public = parent(TPM_ALG_AES);
        let blob = credential_blob(&public, &CREDENTIAL, &RSA_DERIVED_SEED);
        for (label, failing, expected) in [
            ("the name algorithm", TPM_ALG_SHA256, vec![TPM_ALG_SHA256]),
            (
                "the symmetric algorithm",
                TPM_ALG_AES,
                vec![TPM_ALG_SHA256, TPM_ALG_AES],
            ),
        ] {
            let (opened, calls) = gated_open(&public, &RSA_DERIVED_SEED, &blob, Some(failing));
            assert_eq!(opened, Err(TPM_RC_FAILURE), "{label}");
            assert_eq!(calls, expected, "{label}");
        }
    }

    #[test]
    fn a_marshalled_sensitive_area_pads_its_authorization_value_to_the_digest() {
        let mut sensitive = child_sensitive();
        sensitive.auth_value = OwnedSecret::from_vec(b"short".to_vec());
        let marshalled = marshal_sensitive(&sensitive, TPM_ALG_SHA256).expect("it marshals");
        let declared = u16::from_be_bytes(marshalled[..2].try_into().unwrap()) as usize;
        assert_eq!(declared + 2, marshalled.len());
        assert_eq!(&marshalled[2..4], &TPM_ALG_SYMCIPHER.to_be_bytes());
        assert_eq!(&marshalled[4..6], &32u16.to_be_bytes());
        assert_eq!(&marshalled[6..11], b"short");
        assert!(marshalled[11..38].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn an_unknown_sensitive_type_is_a_type_error() {
        let parent = parent(TPM_ALG_AES);
        let mut payload = 0u16.to_be_bytes().to_vec();
        for field in [&[][..], &[][..], &[][..]] {
            payload.extend_from_slice(&(field.len() as u16).to_be_bytes());
            payload.extend_from_slice(field);
        }
        let mut sized = (payload.len() as u16).to_be_bytes().to_vec();
        sized.extend_from_slice(&payload);
        let produced = produce_outer_wrap(
            &protector(&parent, &[]),
            &NAME,
            TPM_ALG_SHA256,
            Some(&SEED),
            false,
            &sized,
            &mut no_gate(),
            &mut rand(b"type"),
        )
        .expect("the wrap succeeds");
        assert_eq!(
            duplicate_to_sensitive(
                &produced,
                &NAME,
                Some(&protector(&parent, &[])),
                TPM_ALG_SHA256,
                &SEED,
                &null_sym(),
                &[],
            )
            .err(),
            Some(TPM_RC_TYPE)
        );
    }
}
