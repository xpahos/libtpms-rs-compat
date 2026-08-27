use super::marshal::{BlobReader, Tpm2bError};
use super::persistent::{AlgInterface, PersistentAllError, PersistentField, StateSection};

pub(super) use super::algorithm::*;

#[cfg(test)]
pub(super) const TPM_ECC_NONE: u16 = 0x0000;
const COMPILED_ECC_CURVES: [u16; 8] = [
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0010, 0x0011, 0x0020,
];

pub(super) const DIGEST_SIZE: usize = 64;
pub(super) const NAME_SIZE: usize = 68;
pub(super) const MAX_RSA_KEY_BYTES: usize = 384;
pub(super) const RSA_PRIVATE_SIZE: usize = 960;
pub(super) const MAX_ECC_KEY_BYTES: usize = 80;
pub(super) const MAX_SYM_KEY_BYTES: usize = 32;
pub(super) const MAX_SYM_DATA: usize = 128;

const TPMA_OBJECT_RESERVED: u32 = 0xfff0_f009;

const COMPILED_HASHES: [u16; 4] = [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512];
const COMPILED_SYM_OBJECTS: [u16; 3] = [TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_TDES];
const COMPILED_SYM_MODES: [u16; 6] = [
    TPM_ALG_CTR,
    TPM_ALG_OFB,
    TPM_ALG_CBC,
    TPM_ALG_CFB,
    TPM_ALG_ECB,
    TPM_ALG_CMAC,
];
const COMPILED_KDFS: [u16; 4] = [
    TPM_ALG_MGF1,
    TPM_ALG_KDF1_SP800_56A,
    TPM_ALG_KDF2,
    TPM_ALG_KDF1_SP800_108,
];
const COMPILED_KEYEDHASH_SCHEMES: [u16; 2] = [TPM_ALG_HMAC, TPM_ALG_XOR];
const COMPILED_RSA_SCHEMES: [u16; 4] =
    [TPM_ALG_RSASSA, TPM_ALG_RSAPSS, TPM_ALG_RSAES, TPM_ALG_OAEP];
const COMPILED_ECC_SCHEMES: [u16; 6] = [
    TPM_ALG_ECDSA,
    TPM_ALG_SM2,
    TPM_ALG_ECDAA,
    TPM_ALG_ECSCHNORR,
    TPM_ALG_ECDH,
    TPM_ALG_ECMQV,
];
const COMPILED_PUBLIC_TYPES: [u16; 4] = [
    TPM_ALG_KEYEDHASH,
    TPM_ALG_RSA,
    TPM_ALG_ECC,
    TPM_ALG_SYMCIPHER,
];

fn truncated(section: StateSection) -> PersistentAllError {
    PersistentAllError::Truncated { section }
}

pub(super) fn read_tpm2b<'a>(
    reader: &mut BlobReader<'a>,
    section: StateSection,
    field: PersistentField,
    maximum: usize,
) -> Result<&'a [u8], PersistentAllError> {
    reader.read_tpm2b(maximum).map_err(|error| match error {
        Tpm2bError::Truncated => truncated(section),
        Tpm2bError::SizeExceeded { actual, maximum } => PersistentAllError::Tpm2bSizeExceeded {
            section,
            field,
            actual,
            maximum,
        },
    })
}

fn read_alg_interface(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    interface: AlgInterface,
    compiled: &[u16],
    allow_null: bool,
) -> Result<u16, PersistentAllError> {
    let actual = reader.read_u16().map_err(|_| truncated(section))?;
    if compiled.contains(&actual) || (allow_null && actual == TPM_ALG_NULL) {
        return Ok(actual);
    }
    Err(PersistentAllError::InvalidAlgorithm {
        section,
        interface,
        actual,
    })
}

pub(super) fn read_hash_alg(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    allow_null: bool,
) -> Result<u16, PersistentAllError> {
    read_alg_interface(
        reader,
        section,
        AlgInterface::Hash,
        &COMPILED_HASHES,
        allow_null,
    )
}

fn read_object_attributes(
    reader: &mut BlobReader<'_>,
    section: StateSection,
) -> Result<u32, PersistentAllError> {
    let actual = reader.read_u32().map_err(|_| truncated(section))?;
    if actual & TPMA_OBJECT_RESERVED != 0 {
        return Err(PersistentAllError::ReservedBitsSet { section, actual });
    }
    Ok(actual)
}

fn read_key_bits(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    algorithm: u16,
) -> Result<u16, PersistentAllError> {
    let bits = reader.read_u16().map_err(|_| truncated(section))?;
    let valid = match algorithm {
        TPM_ALG_AES | TPM_ALG_CAMELLIA => matches!(bits, 128 | 192 | 256),
        TPM_ALG_TDES => matches!(bits, 128 | 192),
        _ => false,
    };
    if !valid {
        return Err(PersistentAllError::InvalidAlgorithm {
            section,
            interface: AlgInterface::KeyBits,
            actual: bits,
        });
    }
    Ok(bits)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StateFormatLimit(u32);

impl StateFormatLimit {
    pub(super) const NONE: Self = Self(0);
    pub(super) const CURRENT: Self = Self(super::profile::STATE_FORMAT_LEVEL_CURRENT);

    pub(super) const fn new(level: u32) -> Self {
        Self(level)
    }

    fn required_symmetric_level(algorithm: u16, key_bits: u16) -> u32 {
        match (algorithm, key_bits) {
            (TPM_ALG_AES | TPM_ALG_CAMELLIA, 192) => 4,
            (TPM_ALG_AES | TPM_ALG_CAMELLIA, 128 | 256) => 1,
            (TPM_ALG_TDES, 128 | 192) => 1,
            _ => 0,
        }
    }

    fn required_rsa_level(key_bits: u16) -> u32 {
        match key_bits {
            1024 | 2048 | 3072 => 1,
            _ => 0,
        }
    }

    fn required_ecc_level(curve: u16) -> u32 {
        if COMPILED_ECC_CURVES.contains(&curve) {
            1
        } else {
            0
        }
    }

    fn check_symmetric_key_bits(
        self,
        section: StateSection,
        algorithm: u16,
        key_bits: u16,
    ) -> Result<(), PersistentAllError> {
        self.check_key_bits(
            section,
            Self::required_symmetric_level(algorithm, key_bits),
            key_bits,
        )
    }

    fn check_rsa_key_bits(
        self,
        section: StateSection,
        key_bits: u16,
    ) -> Result<(), PersistentAllError> {
        self.check_key_bits(section, Self::required_rsa_level(key_bits), key_bits)
    }

    fn check_key_bits(
        self,
        section: StateSection,
        required: u32,
        key_bits: u16,
    ) -> Result<(), PersistentAllError> {
        if required <= self.0 {
            return Ok(());
        }
        Err(PersistentAllError::InvalidAlgorithm {
            section,
            interface: AlgInterface::KeyBits,
            actual: key_bits,
        })
    }

    pub(super) fn key_bits_allowed(self, algorithm: u16, key_bits: u16) -> bool {
        let required = match algorithm {
            TPM_ALG_RSA => Self::required_rsa_level(key_bits),
            _ => Self::required_symmetric_level(algorithm, key_bits),
        };
        required <= self.0
    }

    pub(super) fn ecc_curve_allowed(self, curve: u16) -> bool {
        Self::required_ecc_level(curve) <= self.0
    }

    fn check_ecc_curve(self, section: StateSection, curve: u16) -> Result<(), PersistentAllError> {
        if Self::required_ecc_level(curve) <= self.0 {
            return Ok(());
        }
        Err(PersistentAllError::InvalidAlgorithm {
            section,
            interface: AlgInterface::EccCurve,
            actual: curve,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SymDefObject {
    pub(super) algorithm: u16,
    pub(super) key_bits: Option<u16>,
    pub(super) mode: Option<u16>,
}

pub(super) fn parse_sym_def_object(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    allow_null: bool,
    state_format: StateFormatLimit,
) -> Result<SymDefObject, PersistentAllError> {
    let algorithm = read_alg_interface(
        reader,
        section,
        AlgInterface::SymObject,
        &COMPILED_SYM_OBJECTS,
        allow_null,
    )?;
    if algorithm == TPM_ALG_NULL {
        return Ok(SymDefObject {
            algorithm,
            key_bits: None,
            mode: None,
        });
    }
    let key_bits = read_key_bits(reader, section, algorithm)?;
    state_format.check_symmetric_key_bits(section, algorithm, key_bits)?;
    let mode = read_alg_interface(
        reader,
        section,
        AlgInterface::SymMode,
        &COMPILED_SYM_MODES,
        true,
    )?;
    Ok(SymDefObject {
        algorithm,
        key_bits: Some(key_bits),
        mode: Some(mode),
    })
}

const COMPILED_SYMS: [u16; 4] = [TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_TDES, TPM_ALG_XOR];

pub(super) fn parse_sym_def(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    state_format: StateFormatLimit,
) -> Result<SymDefObject, PersistentAllError> {
    let algorithm = read_alg_interface(reader, section, AlgInterface::Sym, &COMPILED_SYMS, true)?;
    if algorithm == TPM_ALG_NULL {
        return Ok(SymDefObject {
            algorithm,
            key_bits: None,
            mode: None,
        });
    }
    if algorithm == TPM_ALG_XOR {
        let hash_alg = read_hash_alg(reader, section, false)?;
        return Ok(SymDefObject {
            algorithm,
            key_bits: Some(hash_alg),
            mode: None,
        });
    }
    let key_bits = read_key_bits(reader, section, algorithm)?;
    state_format.check_symmetric_key_bits(section, algorithm, key_bits)?;
    let mode = read_alg_interface(
        reader,
        section,
        AlgInterface::SymMode,
        &COMPILED_SYM_MODES,
        true,
    )?;
    Ok(SymDefObject {
        algorithm,
        key_bits: Some(key_bits),
        mode: Some(mode),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Scheme {
    pub(super) scheme: u16,
    pub(super) hash_alg: Option<u16>,
    pub(super) count: Option<u16>,
    pub(super) kdf: Option<u16>,
}

impl Scheme {
    fn empty(scheme: u16) -> Self {
        Self {
            scheme,
            hash_alg: None,
            count: None,
            kdf: None,
        }
    }
}

fn parse_keyedhash_scheme(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    allow_null: bool,
) -> Result<Scheme, PersistentAllError> {
    let scheme = read_alg_interface(
        reader,
        section,
        AlgInterface::KeyedHashScheme,
        &COMPILED_KEYEDHASH_SCHEMES,
        allow_null,
    )?;
    match scheme {
        TPM_ALG_HMAC => Ok(Scheme {
            hash_alg: Some(read_hash_alg(reader, section, false)?),
            ..Scheme::empty(scheme)
        }),
        TPM_ALG_XOR => {
            let hash_alg = read_hash_alg(reader, section, false)?;
            let kdf = read_alg_interface(reader, section, AlgInterface::Kdf, &COMPILED_KDFS, true)?;
            Ok(Scheme {
                hash_alg: Some(hash_alg),
                kdf: Some(kdf),
                ..Scheme::empty(scheme)
            })
        }
        _ => Ok(Scheme::empty(scheme)),
    }
}

fn parse_asym_scheme_details(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    scheme: u16,
) -> Result<Scheme, PersistentAllError> {
    match scheme {
        TPM_ALG_ECDAA => {
            let hash_alg = read_hash_alg(reader, section, false)?;
            let count = reader.read_u16().map_err(|_| truncated(section))?;
            Ok(Scheme {
                hash_alg: Some(hash_alg),
                count: Some(count),
                ..Scheme::empty(scheme)
            })
        }
        TPM_ALG_RSASSA | TPM_ALG_RSAPSS | TPM_ALG_OAEP | TPM_ALG_ECDSA | TPM_ALG_SM2
        | TPM_ALG_ECSCHNORR | TPM_ALG_ECDH | TPM_ALG_ECMQV => Ok(Scheme {
            hash_alg: Some(read_hash_alg(reader, section, false)?),
            ..Scheme::empty(scheme)
        }),
        _ => Ok(Scheme::empty(scheme)),
    }
}

fn parse_rsa_scheme(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    allow_null: bool,
) -> Result<Scheme, PersistentAllError> {
    let scheme = read_alg_interface(
        reader,
        section,
        AlgInterface::RsaScheme,
        &COMPILED_RSA_SCHEMES,
        allow_null,
    )?;
    parse_asym_scheme_details(reader, section, scheme)
}

fn parse_ecc_scheme(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    allow_null: bool,
) -> Result<Scheme, PersistentAllError> {
    let scheme = read_alg_interface(
        reader,
        section,
        AlgInterface::EccScheme,
        &COMPILED_ECC_SCHEMES,
        allow_null,
    )?;
    parse_asym_scheme_details(reader, section, scheme)
}

fn parse_kdf_scheme(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    allow_null: bool,
) -> Result<Scheme, PersistentAllError> {
    let scheme = read_alg_interface(
        reader,
        section,
        AlgInterface::Kdf,
        &COMPILED_KDFS,
        allow_null,
    )?;
    if scheme == TPM_ALG_NULL {
        return Ok(Scheme::empty(scheme));
    }
    Ok(Scheme {
        hash_alg: Some(read_hash_alg(reader, section, false)?),
        ..Scheme::empty(scheme)
    })
}

fn read_ecc_curve(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    state_format: StateFormatLimit,
) -> Result<u16, PersistentAllError> {
    let actual = reader.read_u16().map_err(|_| truncated(section))?;
    if COMPILED_ECC_CURVES.contains(&actual) {
        state_format.check_ecc_curve(section, actual)?;
        return Ok(actual);
    }
    Err(PersistentAllError::InvalidAlgorithm {
        section,
        interface: AlgInterface::EccCurve,
        actual,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicParms {
    KeyedHash(Scheme),
    SymCipher(SymDefObject),
    Rsa {
        symmetric: SymDefObject,
        scheme: Scheme,
        key_bits: u16,
        exponent: u32,
    },
    Ecc {
        symmetric: SymDefObject,
        scheme: Scheme,
        curve_id: u16,
        kdf: Scheme,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PublicId<'a> {
    KeyedHash(&'a [u8]),
    Sym(&'a [u8]),
    Rsa(&'a [u8]),
    Ecc { x: &'a [u8], y: &'a [u8] },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TpmtPublic<'a> {
    pub(super) object_type: u16,
    pub(super) name_alg: u16,
    pub(super) object_attributes: u32,
    pub(super) auth_policy: &'a [u8],
    pub(super) parameters: PublicParms,
    pub(super) unique: PublicId<'a>,
}

pub(super) fn parse_tpmt_public<'a>(
    reader: &mut BlobReader<'a>,
    section: StateSection,
    allow_null_name_alg: bool,
    state_format: StateFormatLimit,
) -> Result<TpmtPublic<'a>, PersistentAllError> {
    use PersistentField as F;

    let object_type = read_alg_interface(
        reader,
        section,
        AlgInterface::Public,
        &COMPILED_PUBLIC_TYPES,
        false,
    )?;
    let name_alg = read_hash_alg(reader, section, allow_null_name_alg)?;
    let object_attributes = read_object_attributes(reader, section)?;
    let auth_policy = read_tpm2b(reader, section, F::ObjectAuthPolicy, DIGEST_SIZE)?;

    let parameters = match object_type {
        TPM_ALG_KEYEDHASH => PublicParms::KeyedHash(parse_keyedhash_scheme(reader, section, true)?),
        TPM_ALG_SYMCIPHER => {
            PublicParms::SymCipher(parse_sym_def_object(reader, section, false, state_format)?)
        }
        TPM_ALG_RSA => {
            let symmetric = parse_sym_def_object(reader, section, true, state_format)?;
            let scheme = parse_rsa_scheme(reader, section, true)?;
            let key_bits = reader.read_u16().map_err(|_| truncated(section))?;
            if !matches!(key_bits, 1024 | 2048 | 3072) {
                return Err(PersistentAllError::InvalidAlgorithm {
                    section,
                    interface: AlgInterface::KeyBits,
                    actual: key_bits,
                });
            }
            state_format.check_rsa_key_bits(section, key_bits)?;
            let exponent = reader.read_u32().map_err(|_| truncated(section))?;
            PublicParms::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            }
        }
        _ => {
            let symmetric = parse_sym_def_object(reader, section, true, state_format)?;
            let scheme = parse_ecc_scheme(reader, section, true)?;
            let curve_id = read_ecc_curve(reader, section, state_format)?;
            let kdf = parse_kdf_scheme(reader, section, true)?;
            PublicParms::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            }
        }
    };

    let unique = match object_type {
        TPM_ALG_KEYEDHASH => {
            PublicId::KeyedHash(read_tpm2b(reader, section, F::ObjectUnique, DIGEST_SIZE)?)
        }
        TPM_ALG_SYMCIPHER => {
            PublicId::Sym(read_tpm2b(reader, section, F::ObjectUnique, DIGEST_SIZE)?)
        }
        TPM_ALG_RSA => PublicId::Rsa(read_tpm2b(
            reader,
            section,
            F::RsaPublicKey,
            MAX_RSA_KEY_BYTES,
        )?),
        _ => PublicId::Ecc {
            x: read_tpm2b(reader, section, F::EccParameter, MAX_ECC_KEY_BYTES)?,
            y: read_tpm2b(reader, section, F::EccParameter, MAX_ECC_KEY_BYTES)?,
        },
    };

    Ok(TpmtPublic {
        object_type,
        name_alg,
        object_attributes,
        auth_policy,
        parameters,
        unique,
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct TpmtSensitive<'a> {
    pub(super) sensitive_type: u16,
    pub(super) auth_value: &'a [u8],
    pub(super) seed_value: &'a [u8],
    pub(super) sensitive: Option<&'a [u8]>,
}

impl core::fmt::Debug for TpmtSensitive<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TpmtSensitive")
            .field("sensitive_type", &self.sensitive_type)
            .field("auth_value_len", &self.auth_value.len())
            .field("seed_value_len", &self.seed_value.len())
            .field("sensitive_len", &self.sensitive.map(<[u8]>::len))
            .finish()
    }
}

pub(super) fn parse_nv_tpmt_sensitive<'a>(
    reader: &mut BlobReader<'a>,
    section: StateSection,
) -> Result<TpmtSensitive<'a>, PersistentAllError> {
    use PersistentField as F;

    let sensitive_type = reader.read_u16().map_err(|_| truncated(section))?;
    let auth_value = read_tpm2b(reader, section, F::ObjectAuthValue, DIGEST_SIZE)?;
    let seed_value = read_tpm2b(reader, section, F::ObjectSeedValue, DIGEST_SIZE)?;

    let sensitive = match sensitive_type {
        TPM_ALG_RSA => Some(read_tpm2b(
            reader,
            section,
            F::RsaPrivateKey,
            RSA_PRIVATE_SIZE,
        )?),
        TPM_ALG_ECC => Some(read_tpm2b(
            reader,
            section,
            F::EccParameter,
            MAX_ECC_KEY_BYTES,
        )?),
        TPM_ALG_KEYEDHASH => Some(read_tpm2b(reader, section, F::SensitiveData, MAX_SYM_DATA)?),
        TPM_ALG_SYMCIPHER => Some(read_tpm2b(reader, section, F::SymKey, MAX_SYM_KEY_BYTES)?),
        _ => {
            if sensitive_type != TPM_ALG_ERROR || !auth_value.is_empty() || !seed_value.is_empty() {
                return Err(PersistentAllError::InvalidPublicOnlySensitive {
                    actual_type: sensitive_type,
                });
            }
            None
        }
    };

    Ok(TpmtSensitive {
        sensitive_type,
        auth_value,
        seed_value,
        sensitive,
    })
}

#[cfg(test)]
pub(super) mod fixtures {
    use super::*;

    pub(in crate::library::tpm2) fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    pub(in crate::library::tpm2) fn rsa_public(unique_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        out.extend_from_slice(&128u16.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&65537u32.to_be_bytes());
        push_tpm2b(&mut out, &vec![0xab; unique_len]);
        out
    }

    pub(in crate::library::tpm2) fn keyedhash_public() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&TPM_ALG_HMAC.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        push_tpm2b(&mut out, &[0xcd; 32]);
        out
    }

    pub(in crate::library::tpm2) fn symcipher_public(key_bits: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_SYMCIPHER.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        push_tpm2b(&mut out, &[0x33; 32]);
        out
    }

    pub(in crate::library::tpm2) fn ecc_public() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0000_0002u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_ECDSA.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&0x0003u16.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        push_tpm2b(&mut out, &[0x11; 32]);
        push_tpm2b(&mut out, &[0x22; 32]);
        out
    }

    pub(in crate::library::tpm2) fn rsa_sensitive(prime_len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        push_tpm2b(&mut out, &[0x77; 4]);
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &vec![0x99; prime_len]);
        out
    }

    pub(in crate::library::tpm2) fn public_only_sensitive() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ERROR.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_CURVE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_MODE,
        TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_VALUE,
    };

    const SECTION: StateSection = StateSection::Object;

    fn parse_public(data: &[u8]) -> Result<TpmtPublic<'_>, PersistentAllError> {
        let mut reader = BlobReader::new(data);
        let public = parse_tpmt_public(&mut reader, SECTION, true, StateFormatLimit::CURRENT)?;
        assert_eq!(reader.remaining(), &[] as &[u8], "exact consumption");
        Ok(public)
    }

    fn parse_public_at(
        data: &[u8],
        state_format: StateFormatLimit,
    ) -> crate::ffi::types::TpmResult {
        let mut reader = BlobReader::new(data);
        match parse_tpmt_public(&mut reader, SECTION, true, state_format) {
            Ok(_) => crate::library::constants::TPM_SUCCESS,
            Err(error) => error.tpm_result(),
        }
    }

    #[test]
    fn key_sizes_and_curves_follow_the_state_format_level() {
        use crate::library::constants::TPM_SUCCESS;

        let levels = [
            ("none", StateFormatLimit::NONE),
            ("one", StateFormatLimit::new(1)),
            ("four", StateFormatLimit::new(4)),
            ("current", StateFormatLimit::CURRENT),
        ];
        for (name, limit) in levels {
            let unavailable = limit == StateFormatLimit::NONE;
            assert_eq!(
                parse_public_at(&rsa_public(256), limit),
                if unavailable {
                    TPM_RC_VALUE
                } else {
                    TPM_SUCCESS
                },
                "rsa 2048 at level {name}"
            );
            assert_eq!(
                parse_public_at(&ecc_public(), limit),
                if unavailable {
                    TPM_RC_CURVE
                } else {
                    TPM_SUCCESS
                },
                "ecc curve at level {name}"
            );
            for key_bits in [128u16, 256] {
                assert_eq!(
                    parse_public_at(&symcipher_public(key_bits), limit),
                    if unavailable {
                        TPM_RC_VALUE
                    } else {
                        TPM_SUCCESS
                    },
                    "aes {key_bits} at level {name}"
                );
            }
            assert_eq!(
                parse_public_at(&symcipher_public(192), limit),
                if limit == StateFormatLimit::new(4) || limit == StateFormatLimit::CURRENT {
                    TPM_SUCCESS
                } else {
                    TPM_RC_VALUE
                },
                "aes 192 at level {name}"
            );
        }
    }

    #[test]
    fn rsa_public_decodes() {
        let data = rsa_public(256);
        let public = parse_public(&data).unwrap();
        assert_eq!(public.object_type, TPM_ALG_RSA);
        assert_eq!(public.name_alg, TPM_ALG_SHA256);
        assert_eq!(public.object_attributes, 2);
        let PublicParms::Rsa {
            symmetric,
            scheme,
            key_bits,
            exponent,
        } = public.parameters
        else {
            panic!("expected RSA parms");
        };
        assert_eq!(symmetric.algorithm, TPM_ALG_AES);
        assert_eq!(symmetric.key_bits, Some(128));
        assert_eq!(symmetric.mode, Some(TPM_ALG_CFB));
        assert_eq!(scheme.scheme, TPM_ALG_NULL);
        assert_eq!(key_bits, 2048);
        assert_eq!(exponent, 65537);
        assert!(matches!(public.unique, PublicId::Rsa(key) if key.len() == 256));
    }

    #[test]
    fn keyedhash_and_ecc_publics_decode() {
        let data = keyedhash_public();
        let public = parse_public(&data).unwrap();
        let PublicParms::KeyedHash(scheme) = public.parameters else {
            panic!("expected keyedhash parms");
        };
        assert_eq!(scheme.scheme, TPM_ALG_HMAC);
        assert_eq!(scheme.hash_alg, Some(TPM_ALG_SHA256));

        let data = ecc_public();
        let public = parse_public(&data).unwrap();
        let PublicParms::Ecc {
            symmetric,
            scheme,
            curve_id,
            kdf,
        } = public.parameters
        else {
            panic!("expected ECC parms");
        };
        assert_eq!(symmetric.algorithm, TPM_ALG_NULL);
        assert_eq!(scheme.scheme, TPM_ALG_ECDSA);
        assert_eq!(curve_id, 0x0003);
        assert_eq!(kdf.scheme, TPM_ALG_NULL);
        assert!(matches!(
            public.unique,
            PublicId::Ecc { x, y } if x.len() == 32 && y.len() == 32
        ));
    }

    #[test]
    fn xor_keyedhash_scheme_reads_hash_and_kdf() {
        let mut data = Vec::new();
        data.extend_from_slice(&TPM_ALG_KEYEDHASH.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_SHA1.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut data, &[]);
        data.extend_from_slice(&TPM_ALG_XOR.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_KDF1_SP800_108.to_be_bytes());
        push_tpm2b(&mut data, &[]);
        let public = parse_public(&data).unwrap();
        let PublicParms::KeyedHash(scheme) = public.parameters else {
            panic!("expected keyedhash parms");
        };
        assert_eq!(scheme.scheme, TPM_ALG_XOR);
        assert_eq!(scheme.hash_alg, Some(TPM_ALG_SHA256));
        assert_eq!(scheme.kdf, Some(TPM_ALG_KDF1_SP800_108));
    }

    #[test]
    fn invalid_public_type_is_rc_type() {
        for object_type in [0x0000u16, TPM_ALG_NULL, 0xffff] {
            let mut data = rsa_public(4);
            data[0..2].copy_from_slice(&object_type.to_be_bytes());
            let error = parse_public(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidAlgorithm {
                    section: SECTION,
                    interface: AlgInterface::Public,
                    actual: object_type,
                },
                "type {object_type:#06x}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_TYPE);
        }
    }

    #[test]
    fn name_alg_null_is_gated_by_allow_null() {
        let mut data = rsa_public(4);
        data[2..4].copy_from_slice(&TPM_ALG_NULL.to_be_bytes());
        let mut reader = BlobReader::new(&data);
        assert!(parse_tpmt_public(&mut reader, SECTION, true, StateFormatLimit::CURRENT).is_ok());
        let mut reader = BlobReader::new(&data);
        let error =
            parse_tpmt_public(&mut reader, SECTION, false, StateFormatLimit::CURRENT).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_HASH);
    }

    #[test]
    fn reserved_object_attribute_bits_are_rejected() {
        let mut data = rsa_public(4);
        data[4..8].copy_from_slice(&0x0000_0009u32.to_be_bytes());
        let error = parse_public(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ReservedBitsSet {
                section: SECTION,
                actual: 9,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_RESERVED_BITS);
    }

    #[test]
    fn sym_def_algorithm_and_mode_are_validated() {
        let mut data = rsa_public(4);
        data[10..12].copy_from_slice(&TPM_ALG_XOR.to_be_bytes());
        let error = parse_public(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SYMMETRIC);

        let mut data = rsa_public(4);
        data[14..16].copy_from_slice(&TPM_ALG_SHA1.to_be_bytes());
        let error = parse_public(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_MODE);
    }

    #[test]
    fn invalid_key_bits_are_rc_value() {
        let mut data = rsa_public(4);
        data[12..14].copy_from_slice(&64u16.to_be_bytes());
        let error = parse_public(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_VALUE);

        let mut data = rsa_public(4);
        data[18..20].copy_from_slice(&4096u16.to_be_bytes());
        let error = parse_public(&data).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidAlgorithm {
                section: SECTION,
                interface: AlgInterface::KeyBits,
                actual: 4096,
            }
        );
    }

    #[test]
    fn tdes_key_bits_accept_only_128_and_192() {
        for (bits, ok) in [(128u16, true), (192, true), (256, false), (64, false)] {
            let mut data = Vec::new();
            data.extend_from_slice(&TPM_ALG_SYMCIPHER.to_be_bytes());
            data.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            data.extend_from_slice(&0u32.to_be_bytes());
            push_tpm2b(&mut data, &[]);
            data.extend_from_slice(&TPM_ALG_TDES.to_be_bytes());
            data.extend_from_slice(&bits.to_be_bytes());
            data.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
            push_tpm2b(&mut data, &[0x55; 20]);
            let result = parse_public(&data);
            assert_eq!(result.is_ok(), ok, "bits {bits}");
        }
    }

    #[test]
    fn symcipher_null_symmetric_is_rejected() {
        let mut data = Vec::new();
        data.extend_from_slice(&TPM_ALG_SYMCIPHER.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut data, &[]);
        data.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        push_tpm2b(&mut data, &[]);
        let error = parse_public(&data).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SYMMETRIC);
    }

    #[test]
    fn ecdaa_scheme_reads_hash_and_count() {
        let mut data = Vec::new();
        data.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut data, &[]);
        data.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_ECDAA.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        data.extend_from_slice(&7u16.to_be_bytes());
        data.extend_from_slice(&0x0010u16.to_be_bytes());
        data.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        push_tpm2b(&mut data, &[0x11; 32]);
        push_tpm2b(&mut data, &[0x22; 32]);
        let public = parse_public(&data).unwrap();
        let PublicParms::Ecc { scheme, .. } = public.parameters else {
            panic!("expected ECC parms");
        };
        assert_eq!(scheme.scheme, TPM_ALG_ECDAA);
        assert_eq!(scheme.count, Some(7));
    }

    #[test]
    fn invalid_or_none_curve_is_rc_curve() {
        for curve in [TPM_ECC_NONE, 0x0006u16, 0xffff] {
            let mut data = ecc_public();
            data[16..18].copy_from_slice(&curve.to_be_bytes());
            let error = parse_public(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidAlgorithm {
                    section: SECTION,
                    interface: AlgInterface::EccCurve,
                    actual: curve,
                },
                "curve {curve:#06x}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_CURVE);
        }
    }

    #[test]
    fn oversized_unique_fields_are_size_errors() {
        let error = parse_public(&rsa_public(MAX_RSA_KEY_BYTES + 1)).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        assert!(parse_public(&rsa_public(MAX_RSA_KEY_BYTES)).is_ok());
    }

    #[test]
    fn sensitive_composites_use_their_own_capacities() {
        let mut reader = BlobReader::new(&[]);
        assert!(parse_nv_tpmt_sensitive(&mut reader, SECTION).is_err());

        let data = rsa_sensitive(RSA_PRIVATE_SIZE);
        let mut reader = BlobReader::new(&data);
        let sensitive = parse_nv_tpmt_sensitive(&mut reader, SECTION).unwrap();
        assert_eq!(sensitive.sensitive_type, TPM_ALG_RSA);
        assert_eq!(sensitive.sensitive.unwrap().len(), RSA_PRIVATE_SIZE);

        let data = rsa_sensitive(RSA_PRIVATE_SIZE + 1);
        let mut reader = BlobReader::new(&data);
        let error = parse_nv_tpmt_sensitive(&mut reader, SECTION).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_SIZE);
    }

    #[test]
    fn public_only_sensitive_requires_error_type_and_empty_fields() {
        let data = public_only_sensitive();
        let mut reader = BlobReader::new(&data);
        let sensitive = parse_nv_tpmt_sensitive(&mut reader, SECTION).unwrap();
        assert!(sensitive.sensitive.is_none());

        let mut data = Vec::new();
        data.extend_from_slice(&TPM_ALG_SHA1.to_be_bytes());
        push_tpm2b(&mut data, &[]);
        push_tpm2b(&mut data, &[]);
        let mut reader = BlobReader::new(&data);
        let error = parse_nv_tpmt_sensitive(&mut reader, SECTION).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidPublicOnlySensitive { actual_type: 4 }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn truncation_at_every_boundary_is_insufficient() {
        for full in [rsa_public(16), keyedhash_public(), ecc_public()] {
            for len in 0..full.len() {
                let mut reader = BlobReader::new(&full[..len]);
                let error =
                    parse_tpmt_public(&mut reader, SECTION, true, StateFormatLimit::CURRENT)
                        .unwrap_err();
                assert_eq!(
                    error.tpm_result(),
                    TPM_RC_INSUFFICIENT,
                    "prefix length {len} of {}",
                    full.len()
                );
            }
        }
    }

    #[test]
    fn public_area_byte_mutations_do_not_panic() {
        let full = rsa_public(8);
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x10, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let mut reader = BlobReader::new(&data);
                let _ = parse_tpmt_public(&mut reader, SECTION, true, StateFormatLimit::CURRENT);
            }
        }
    }
}
