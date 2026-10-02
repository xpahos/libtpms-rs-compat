// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

mod cmac;
mod des;
mod df;
mod drbg;
#[cfg(test)]
mod drbg_vectors;
mod ecc;
mod entropy;
mod hash;
mod hmac;
mod kdf;
mod ossl;
mod prime;
mod rand_state;
mod rsa;
mod sha_state;
mod sym;
#[cfg(test)]
pub(in crate::library::tpm2) mod work;

pub(super) use cmac::CmacState;
pub(super) use des::{generate_tdes_key, validate_tdes_key};
pub(super) use df::df_buffer;
pub(super) use drbg::{DRBG_MAGIC, Drbg, ReseedError, StirError};
pub(super) use ecc::{
    EccEphemeral, EccKeyError, compiled_curves, curve_detail, curve_key_size_bits,
    generate_ecc_ephemeral, generate_ecc_key, is_compiled_curve,
};
pub(in crate::library) use entropy::{EntropySource, os_entropy};
pub(super) use hash::{COMPILED_HASHES, Hasher};
pub(super) use hmac::HmacState;
#[cfg(test)]
pub(super) use kdf::kdfe;
pub(super) use kdf::{kdfa, kdfa_from, mgf1};
#[cfg(test)]
pub(super) use ossl::{
    BigUint, crt_words_be, curve_parameters, prepared_key_count, review_keys, validated_factor_sets,
};
pub(super) use ossl::{
    CRT_WORDS, CrtWords, EccAffine, EccCurve, EccPublicScalar, EccScalar, EcdsaAttempt,
    PRIVATE_SCALAR_BYTES, PublicCheck, RecoveredExponent, RecoveryError, RsaCrtKey,
    RsaRuntimeCache, RsaSignaturePadding, normalized_word_count, recover_rsa_components,
    recover_rsa_private_exponent, rsa_private_key_op, rsa_verify_signature, rsassa_sign,
};
pub(super) use ossl::{EccBackendError, SecretBytes, SharedPointError, wipe};
#[cfg(test)]
pub(super) use ossl::{FaultBoundary, arm_fault, disarm_fault, faults_fired};
pub(super) use rand_state::{LiveDrbg, SeededRand};
pub(super) use rsa::{RSA_DEFAULT_PUBLIC_EXPONENT, oaep_decode, oaep_encode};
pub(super) use rsa::{
    RsaKeyError, generate_rsa_key, rsa_public_key_op, rsaes_decode, rsaes_encode,
    rsaes_padding_length,
};
pub(super) use sha_state::{SequenceHmac, ShaState, ShaStatePayload};
pub(super) use sym::{
    SymDirection, sym_block_size, sym_cfb_decrypt, sym_cfb_encrypt, sym_crypt, sym_key_block_size,
    sym_mode_is_block_cipher,
};

#[cfg(test)]
pub(super) use drbg::{CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_SEED_SIZE};

#[cfg(test)]
pub(super) use drbg_vectors::{
    DrbgBoundaryCase, DrbgBoundaryRecord, DrbgGenerateRecord, DrbgStirCase, DrbgVectorRecord,
    boundary_record, generate_record, stir_record, vector_record,
};
