mod bignum;
mod cfb;
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
mod prime;
mod rand_state;
mod rsa;
mod sha_state;
#[cfg(test)]
pub(in crate::library::tpm2) mod work;

pub(super) use bignum::BigUint;
pub(super) use cfb::{sym_block_size, sym_cfb_decrypt, sym_cfb_encrypt};
pub(super) use des::{generate_tdes_key, validate_tdes_key};
pub(super) use df::df_buffer;
pub(super) use drbg::{DRBG_MAGIC, Drbg, ReseedError, StirError};
pub(super) use ecc::{
    CurveParameters, EccKeyError, curve_key_size_bits, curve_parameters, generate_ecc_key,
    is_compiled_curve,
};
pub(in crate::library) use entropy::{EntropySource, os_entropy};
pub(super) use hash::{COMPILED_HASHES, Hasher};
pub(super) use hmac::HmacState;
pub(super) use kdf::kdfe;
pub(super) use kdf::{kdfa, kdfa_from, mgf1};
pub(super) use rand_state::{LiveDrbg, SeededRand};
pub(super) use rsa::{RSA_DEFAULT_PUBLIC_EXPONENT, oaep_decode, oaep_encode};
pub(super) use rsa::{
    RsaKeyError, generate_rsa_key, recover_rsa_private_exponent, rsa_private_key_op,
    rsa_public_key_op, rsaes_decode, rsaes_encode, rsaes_padding_length,
};
pub(super) use sha_state::{SequenceHmac, ShaState, ShaStatePayload};

#[cfg(test)]
pub(super) use drbg::{CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_SEED_SIZE};

#[cfg(test)]
pub(super) use drbg_vectors::{
    DrbgBoundaryCase, DrbgBoundaryRecord, DrbgGenerateRecord, DrbgStirCase, DrbgVectorRecord,
    boundary_record, generate_record, stir_record, vector_record,
};
