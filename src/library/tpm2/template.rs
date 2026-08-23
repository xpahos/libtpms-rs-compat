use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_CURVE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_KDF, TPM_RC_MODE,
    TPM_RC_RESERVED_BITS, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_VALUE,
};

use super::algorithm::{
    algorithm_enabled, algorithm_min_key_size, algorithm_profile_name, curve_enabled,
};
use super::crypto::{Hasher, curve_key_size_bits, is_compiled_curve};
use super::marshal::{BlobWriter, Tpm2bError};
use super::persistent::{OwnedPublicId, OwnedTpmtPublic};
use super::public::{
    DIGEST_SIZE, MAX_ECC_KEY_BYTES, MAX_RSA_KEY_BYTES, MAX_SYM_DATA, PublicParms, Scheme,
    StateFormatLimit, SymDefObject, TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_CBC, TPM_ALG_CFB,
    TPM_ALG_CMAC, TPM_ALG_CTR, TPM_ALG_ECB, TPM_ALG_ECC, TPM_ALG_ECDAA, TPM_ALG_ECDH,
    TPM_ALG_ECDSA, TPM_ALG_ECMQV, TPM_ALG_ECSCHNORR, TPM_ALG_HMAC, TPM_ALG_KDF1_SP800_56A,
    TPM_ALG_KDF1_SP800_108, TPM_ALG_KDF2, TPM_ALG_KEYEDHASH, TPM_ALG_MGF1, TPM_ALG_NULL,
    TPM_ALG_OAEP, TPM_ALG_OFB, TPM_ALG_RSA, TPM_ALG_RSAES, TPM_ALG_RSAPSS, TPM_ALG_RSASSA,
    TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SM2, TPM_ALG_SYMCIPHER,
    TPM_ALG_TDES, TPM_ALG_XOR,
};

pub(super) const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
pub(super) const TPMA_OBJECT_ST_CLEAR: u32 = 1 << 2;
pub(super) const TPMA_OBJECT_FIXED_PARENT: u32 = 1 << 4;
pub(super) const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const TPMA_OBJECT_USER_WITH_AUTH: u32 = 1 << 6;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const TPMA_OBJECT_ADMIN_WITH_POLICY: u32 = 1 << 7;
pub(super) const TPMA_OBJECT_FIRMWARE_LIMITED: u32 = 1 << 8;
pub(super) const TPMA_OBJECT_SVN_LIMITED: u32 = 1 << 9;
pub(super) const TPMA_OBJECT_NO_DA: u32 = 1 << 10;
pub(super) const TPMA_OBJECT_ENCRYPTED_DUPLICATION: u32 = 1 << 11;
pub(super) const TPMA_OBJECT_RESTRICTED: u32 = 1 << 16;
pub(super) const TPMA_OBJECT_DECRYPT: u32 = 1 << 17;
pub(super) const TPMA_OBJECT_SIGN: u32 = 1 << 18;
pub(super) const TPMA_OBJECT_X509_SIGN: u32 = 1 << 19;

const TPMA_OBJECT_RESERVED: u32 = 0xfff0_f009;

const MAX_SYM_KEY_BYTES: usize = 32;

pub(super) struct TemplateReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> TemplateReader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(super) fn remaining(&self) -> &'a [u8] {
        &self.data[self.position..]
    }

    pub(super) fn consumed(&self) -> usize {
        self.position
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TpmResult> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(TPM_RC_INSUFFICIENT)?;
        if end > self.data.len() {
            return Err(TPM_RC_INSUFFICIENT);
        }
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    pub(super) fn u8(&mut self) -> Result<u8, TpmResult> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, TpmResult> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    pub(super) fn u32(&mut self) -> Result<u32, TpmResult> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("four bytes"),
        ))
    }

    pub(super) fn bytes(&mut self, length: usize) -> Result<&'a [u8], TpmResult> {
        self.take(length)
    }

    pub(super) fn tpm2b(&mut self, maximum: usize) -> Result<&'a [u8], TpmResult> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(TPM_RC_SIZE);
        }
        self.take(length)
    }
}

impl From<Tpm2bError> for TpmResult {
    fn from(error: Tpm2bError) -> Self {
        match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE,
        }
    }
}

pub(super) struct AlgorithmPolicy<'a> {
    pub(super) profile_algorithms: &'a [u8],
    pub(super) state_format: StateFormatLimit,
}

impl AlgorithmPolicy<'_> {
    fn enabled(&self, algorithm: u16) -> bool {
        algorithm_profile_name(algorithm)
            .is_some_and(|name| algorithm_enabled(self.profile_algorithms, name))
    }

    pub(super) fn key_size_allowed(&self, algorithm: u16, key_bits: u16) -> bool {
        self.enabled(algorithm)
            && algorithm_min_key_size(self.profile_algorithms, algorithm) <= key_bits
            && self.state_format.key_bits_allowed(algorithm, key_bits)
    }

    pub(super) fn curve_allowed(&self, curve_id: u16) -> bool {
        let Some(key_bits) = curve_key_size_bits(curve_id) else {
            return false;
        };
        self.enabled(TPM_ALG_ECC)
            && algorithm_min_key_size(self.profile_algorithms, TPM_ALG_ECC) <= key_bits
            && curve_enabled(self.profile_algorithms, curve_id)
            && self.state_format.ecc_curve_allowed(curve_id)
    }

    fn hash(&self, reader: &mut TemplateReader<'_>, allow_null: bool) -> Result<u16, TpmResult> {
        let algorithm = reader.u16()?;
        let compiled = matches!(
            algorithm,
            TPM_ALG_SHA1 | TPM_ALG_SHA256 | TPM_ALG_SHA384 | TPM_ALG_SHA512
        );
        if compiled && self.enabled(algorithm) {
            return Ok(algorithm);
        }
        if algorithm == TPM_ALG_NULL && allow_null {
            return Ok(algorithm);
        }
        Err(TPM_RC_HASH)
    }

    fn sym_object(
        &self,
        reader: &mut TemplateReader<'_>,
        allow_null: bool,
    ) -> Result<SymDefObject, TpmResult> {
        let algorithm = reader.u16()?;
        self.sym_object_body(algorithm, reader, allow_null)
    }

    fn sym_object_body(
        &self,
        algorithm: u16,
        reader: &mut TemplateReader<'_>,
        allow_null: bool,
    ) -> Result<SymDefObject, TpmResult> {
        let compiled = matches!(algorithm, TPM_ALG_AES | TPM_ALG_CAMELLIA | TPM_ALG_TDES);
        if !((compiled && self.enabled(algorithm)) || (algorithm == TPM_ALG_NULL && allow_null)) {
            return Err(TPM_RC_SYMMETRIC);
        }
        if algorithm == TPM_ALG_NULL {
            return Ok(SymDefObject {
                algorithm,
                key_bits: None,
                mode: None,
            });
        }
        let key_bits = reader.u16()?;
        let valid = match algorithm {
            TPM_ALG_AES | TPM_ALG_CAMELLIA => matches!(key_bits, 128 | 192 | 256),
            _ => matches!(key_bits, 128 | 192),
        };
        if !valid || !self.key_size_allowed(algorithm, key_bits) {
            return Err(TPM_RC_VALUE);
        }
        let mode = reader.u16()?;
        let mode_compiled = matches!(
            mode,
            TPM_ALG_CTR | TPM_ALG_OFB | TPM_ALG_CBC | TPM_ALG_CFB | TPM_ALG_ECB | TPM_ALG_CMAC
        );
        if !((mode_compiled && self.enabled(mode)) || mode == TPM_ALG_NULL) {
            return Err(TPM_RC_MODE);
        }
        Ok(SymDefObject {
            algorithm,
            key_bits: Some(key_bits),
            mode: Some(mode),
        })
    }

    pub(super) fn hash_algorithm(&self, reader: &mut TemplateReader<'_>) -> Result<u16, TpmResult> {
        self.hash(reader, false)
    }

    pub(super) fn sym_session(
        &self,
        reader: &mut TemplateReader<'_>,
    ) -> Result<SymDefObject, TpmResult> {
        let algorithm = reader.u16()?;
        if algorithm == TPM_ALG_XOR {
            if !self.enabled(TPM_ALG_XOR) {
                return Err(TPM_RC_SYMMETRIC);
            }
            let hash_alg = self.hash(reader, false)?;
            return Ok(SymDefObject {
                algorithm,
                key_bits: Some(hash_alg),
                mode: None,
            });
        }
        self.sym_object_body(algorithm, reader, true)
    }

    fn asym_scheme_details(
        &self,
        reader: &mut TemplateReader<'_>,
        scheme: u16,
    ) -> Result<Scheme, TpmResult> {
        Ok(match scheme {
            TPM_ALG_ECDAA => {
                let hash_alg = self.hash(reader, false)?;
                Scheme {
                    scheme,
                    hash_alg: Some(hash_alg),
                    count: Some(reader.u16()?),
                    kdf: None,
                }
            }
            TPM_ALG_RSASSA | TPM_ALG_RSAPSS | TPM_ALG_OAEP | TPM_ALG_ECDSA | TPM_ALG_SM2
            | TPM_ALG_ECSCHNORR | TPM_ALG_ECDH | TPM_ALG_ECMQV => Scheme {
                scheme,
                hash_alg: Some(self.hash(reader, false)?),
                count: None,
                kdf: None,
            },
            _ => Scheme {
                scheme,
                hash_alg: None,
                count: None,
                kdf: None,
            },
        })
    }

    fn rsa_scheme(&self, reader: &mut TemplateReader<'_>) -> Result<Scheme, TpmResult> {
        let scheme = reader.u16()?;
        let compiled = matches!(
            scheme,
            TPM_ALG_RSASSA | TPM_ALG_RSAPSS | TPM_ALG_RSAES | TPM_ALG_OAEP
        );
        if !((compiled && self.enabled(scheme)) || scheme == TPM_ALG_NULL) {
            return Err(TPM_RC_VALUE);
        }
        self.asym_scheme_details(reader, scheme)
    }

    fn ecc_scheme(&self, reader: &mut TemplateReader<'_>) -> Result<Scheme, TpmResult> {
        let scheme = reader.u16()?;
        let compiled = matches!(
            scheme,
            TPM_ALG_ECDSA
                | TPM_ALG_SM2
                | TPM_ALG_ECDAA
                | TPM_ALG_ECSCHNORR
                | TPM_ALG_ECDH
                | TPM_ALG_ECMQV
        );
        if !((compiled && self.enabled(scheme)) || scheme == TPM_ALG_NULL) {
            return Err(TPM_RC_SCHEME);
        }
        self.asym_scheme_details(reader, scheme)
    }

    fn keyedhash_scheme(&self, reader: &mut TemplateReader<'_>) -> Result<Scheme, TpmResult> {
        let scheme = reader.u16()?;
        match scheme {
            TPM_ALG_HMAC => Ok(Scheme {
                scheme,
                hash_alg: Some(self.hash(reader, false)?),
                count: None,
                kdf: None,
            }),
            TPM_ALG_XOR => {
                let hash_alg = self.hash(reader, false)?;
                Ok(Scheme {
                    scheme,
                    hash_alg: Some(hash_alg),
                    count: None,
                    kdf: Some(self.kdf_algorithm(reader)?),
                })
            }
            TPM_ALG_NULL => Ok(Scheme {
                scheme,
                hash_alg: None,
                count: None,
                kdf: None,
            }),
            _ => Err(TPM_RC_VALUE),
        }
    }

    fn kdf_algorithm(&self, reader: &mut TemplateReader<'_>) -> Result<u16, TpmResult> {
        let kdf = reader.u16()?;
        let compiled = matches!(
            kdf,
            TPM_ALG_MGF1 | TPM_ALG_KDF1_SP800_56A | TPM_ALG_KDF2 | TPM_ALG_KDF1_SP800_108
        );
        if compiled || kdf == TPM_ALG_NULL {
            Ok(kdf)
        } else {
            Err(TPM_RC_KDF)
        }
    }

    fn kdf_scheme(&self, reader: &mut TemplateReader<'_>) -> Result<Scheme, TpmResult> {
        let kdf = self.kdf_algorithm(reader)?;
        if kdf == TPM_ALG_NULL {
            return Ok(Scheme {
                scheme: kdf,
                hash_alg: None,
                count: None,
                kdf: None,
            });
        }
        Ok(Scheme {
            scheme: kdf,
            hash_alg: Some(self.hash(reader, false)?),
            count: None,
            kdf: None,
        })
    }
}

fn parse_public_head(
    reader: &mut TemplateReader<'_>,
    policy: &AlgorithmPolicy<'_>,
    allow_null_name_alg: bool,
) -> Result<OwnedTpmtPublic, TpmResult> {
    let object_type = reader.u16()?;
    if !matches!(
        object_type,
        TPM_ALG_KEYEDHASH | TPM_ALG_RSA | TPM_ALG_ECC | TPM_ALG_SYMCIPHER
    ) {
        return Err(TPM_RC_TYPE);
    }
    let name_alg = policy.hash(reader, allow_null_name_alg)?;
    let object_attributes = reader.u32()?;
    if object_attributes & TPMA_OBJECT_RESERVED != 0 {
        return Err(TPM_RC_RESERVED_BITS);
    }
    let auth_policy = reader.tpm2b(DIGEST_SIZE)?.to_vec();
    let parameters = parse_public_parms(reader, policy, object_type)?;
    Ok(OwnedTpmtPublic {
        object_type,
        name_alg,
        object_attributes,
        auth_policy,
        parameters,
        unique: empty_unique(object_type),
    })
}

pub(super) fn parse_public_area(
    reader: &mut TemplateReader<'_>,
    policy: &AlgorithmPolicy<'_>,
    allow_null_name_alg: bool,
) -> Result<OwnedTpmtPublic, TpmResult> {
    let mut public = parse_public_head(reader, policy, allow_null_name_alg)?;
    let object_type = public.object_type;

    let unique = match object_type {
        TPM_ALG_KEYEDHASH => OwnedPublicId::KeyedHash(reader.tpm2b(DIGEST_SIZE)?.to_vec()),
        TPM_ALG_SYMCIPHER => OwnedPublicId::Sym(reader.tpm2b(DIGEST_SIZE)?.to_vec()),
        TPM_ALG_RSA => OwnedPublicId::Rsa(reader.tpm2b(MAX_RSA_KEY_BYTES)?.to_vec()),
        _ => OwnedPublicId::Ecc {
            x: reader.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec(),
            y: reader.tpm2b(MAX_ECC_KEY_BYTES)?.to_vec(),
        },
    };
    public.unique = unique;
    Ok(public)
}

pub(super) const LABEL_MAX_BUFFER: usize = 32;

#[derive(Clone, Default)]
pub(super) struct DeriveLabelContext {
    pub(super) label: Vec<u8>,
    pub(super) context: Vec<u8>,
}

pub(super) fn parse_derive(
    reader: &mut TemplateReader<'_>,
) -> Result<DeriveLabelContext, TpmResult> {
    let label = reader.tpm2b(LABEL_MAX_BUFFER)?.to_vec();
    let context = reader.tpm2b(LABEL_MAX_BUFFER)?.to_vec();
    Ok(DeriveLabelContext { label, context })
}

fn empty_unique(object_type: u16) -> OwnedPublicId {
    match object_type {
        TPM_ALG_KEYEDHASH => OwnedPublicId::KeyedHash(Vec::new()),
        TPM_ALG_SYMCIPHER => OwnedPublicId::Sym(Vec::new()),
        TPM_ALG_RSA => OwnedPublicId::Rsa(Vec::new()),
        _ => OwnedPublicId::Ecc {
            x: Vec::new(),
            y: Vec::new(),
        },
    }
}

pub(super) fn parse_template_to_public(
    template: &[u8],
    policy: &AlgorithmPolicy<'_>,
    derivation: bool,
) -> Result<(OwnedTpmtPublic, DeriveLabelContext), TpmResult> {
    let mut reader = TemplateReader::new(template);
    let (public, label_context) = if derivation {
        let public = parse_public_head(&mut reader, policy, false)?;
        let label_context = parse_derive(&mut reader)?;
        (public, label_context)
    } else {
        (
            parse_public_area(&mut reader, policy, false)?,
            DeriveLabelContext::default(),
        )
    };
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok((public, label_context))
}

fn parse_public_parms(
    reader: &mut TemplateReader<'_>,
    policy: &AlgorithmPolicy<'_>,
    object_type: u16,
) -> Result<PublicParms, TpmResult> {
    Ok(match object_type {
        TPM_ALG_KEYEDHASH => PublicParms::KeyedHash(policy.keyedhash_scheme(reader)?),
        TPM_ALG_SYMCIPHER => PublicParms::SymCipher(policy.sym_object(reader, false)?),
        TPM_ALG_RSA => {
            let symmetric = policy.sym_object(reader, true)?;
            let scheme = policy.rsa_scheme(reader)?;
            let key_bits = reader.u16()?;
            if !matches!(key_bits, 1024 | 2048 | 3072)
                || !policy.key_size_allowed(TPM_ALG_RSA, key_bits)
            {
                return Err(TPM_RC_VALUE);
            }
            let exponent = reader.u32()?;
            PublicParms::Rsa {
                symmetric,
                scheme,
                key_bits,
                exponent,
            }
        }
        _ => {
            let symmetric = policy.sym_object(reader, true)?;
            let scheme = policy.ecc_scheme(reader)?;
            let curve_id = reader.u16()?;
            if !is_compiled_curve(curve_id) || !policy.curve_allowed(curve_id) {
                return Err(TPM_RC_CURVE);
            }
            let kdf = policy.kdf_scheme(reader)?;
            PublicParms::Ecc {
                symmetric,
                scheme,
                curve_id,
                kdf,
            }
        }
    })
}

pub(super) struct SensitiveCreate {
    pub(super) user_auth: Vec<u8>,
    pub(super) data: Vec<u8>,
}

pub(super) fn parse_sensitive_create(
    reader: &mut TemplateReader<'_>,
) -> Result<SensitiveCreate, TpmResult> {
    let user_auth = reader.tpm2b(DIGEST_SIZE)?.to_vec();
    let data = reader.tpm2b(MAX_SYM_DATA)?.to_vec();
    Ok(SensitiveCreate { user_auth, data })
}

fn marshal_scheme(writer: &mut BlobWriter, scheme: &Scheme) {
    writer.write_u16(scheme.scheme);
    if let Some(hash_alg) = scheme.hash_alg {
        writer.write_u16(hash_alg);
    }
    if let Some(count) = scheme.count {
        writer.write_u16(count);
    }
    if let Some(kdf) = scheme.kdf {
        writer.write_u16(kdf);
    }
}

fn marshal_sym_def_object(writer: &mut BlobWriter, sym: &SymDefObject) {
    writer.write_u16(sym.algorithm);
    if let Some(key_bits) = sym.key_bits {
        writer.write_u16(key_bits);
    }
    if let Some(mode) = sym.mode {
        writer.write_u16(mode);
    }
}

pub(super) fn marshal_public_area(public: &OwnedTpmtPublic) -> Result<Vec<u8>, TpmResult> {
    let mut writer = BlobWriter::new();
    writer.write_u16(public.object_type);
    writer.write_u16(public.name_alg);
    writer.write_u32(public.object_attributes);
    writer
        .write_tpm2b(&public.auth_policy)
        .map_err(|_| TPM_RC_SIZE)?;
    match &public.parameters {
        PublicParms::KeyedHash(scheme) => marshal_scheme(&mut writer, scheme),
        PublicParms::SymCipher(sym) => marshal_sym_def_object(&mut writer, sym),
        PublicParms::Rsa {
            symmetric,
            scheme,
            key_bits,
            exponent,
        } => {
            marshal_sym_def_object(&mut writer, symmetric);
            marshal_scheme(&mut writer, scheme);
            writer.write_u16(*key_bits);
            writer.write_u32(*exponent);
        }
        PublicParms::Ecc {
            symmetric,
            scheme,
            curve_id,
            kdf,
        } => {
            marshal_sym_def_object(&mut writer, symmetric);
            marshal_scheme(&mut writer, scheme);
            writer.write_u16(*curve_id);
            marshal_scheme(&mut writer, kdf);
        }
    }
    match &public.unique {
        OwnedPublicId::KeyedHash(bytes) | OwnedPublicId::Sym(bytes) | OwnedPublicId::Rsa(bytes) => {
            writer.write_tpm2b(bytes).map_err(|_| TPM_RC_SIZE)?;
        }
        OwnedPublicId::Ecc { x, y } => {
            writer.write_tpm2b(x).map_err(|_| TPM_RC_SIZE)?;
            writer.write_tpm2b(y).map_err(|_| TPM_RC_SIZE)?;
        }
    }
    Ok(writer.into_bytes())
}

pub(super) fn digest_size(hash_alg: u16) -> Option<usize> {
    super::crypto::COMPILED_HASHES
        .iter()
        .find(|(algorithm, _)| *algorithm == hash_alg)
        .map(|(_, size)| *size)
}

pub(super) fn object_name(public: &OwnedTpmtPublic) -> Result<Vec<u8>, TpmResult> {
    if public.name_alg == TPM_ALG_NULL {
        return Ok(Vec::new());
    }
    let marshalled = marshal_public_area(public)?;
    let mut hasher = Hasher::new(public.name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&marshalled);
    let mut name = public.name_alg.to_be_bytes().to_vec();
    name.extend_from_slice(&hasher.finalize());
    Ok(name)
}

fn has(attributes: u32, bit: u32) -> bool {
    attributes & bit != 0
}

pub(super) struct ParentPublicInfo {
    pub(super) attributes: u32,
    pub(super) name_alg: u16,
    pub(super) symmetric: [u16; 3],
    pub(super) derivation_parent: bool,
}

pub(super) fn parent_public_info(
    public: &OwnedTpmtPublic,
    derivation_parent: bool,
) -> ParentPublicInfo {
    let symmetric = match &public.parameters {
        PublicParms::Rsa { symmetric, .. } | PublicParms::Ecc { symmetric, .. } => [
            symmetric.algorithm,
            symmetric.key_bits.unwrap_or(0),
            symmetric.mode.unwrap_or(0),
        ],
        PublicParms::SymCipher(sym) => [
            sym.algorithm,
            sym.key_bits.unwrap_or(0),
            sym.mode.unwrap_or(0),
        ],
        PublicParms::KeyedHash(scheme) => [
            scheme.scheme,
            scheme.hash_alg.unwrap_or(0),
            scheme.kdf.unwrap_or(0),
        ],
    };
    ParentPublicInfo {
        attributes: public.object_attributes,
        name_alg: public.name_alg,
        symmetric,
        derivation_parent,
    }
}

pub(super) fn create_checks(
    parent: Option<&ParentPublicInfo>,
    public: &OwnedTpmtPublic,
    sensitive_data_size: usize,
) -> Result<(), TpmResult> {
    let attributes = public.object_attributes;
    if !has(attributes, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN) && sensitive_data_size == 0 {
        return Err(TPM_RC_ATTRIBUTES);
    }
    if parent.is_some()
        && has(attributes, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN)
        && sensitive_data_size != 0
    {
        return Err(TPM_RC_ATTRIBUTES);
    }
    match public.object_type {
        TPM_ALG_KEYEDHASH => {
            if !has(attributes, TPMA_OBJECT_SIGN)
                && !has(attributes, TPMA_OBJECT_DECRYPT)
                && has(attributes, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN)
            {
                return Err(TPM_RC_ATTRIBUTES);
            }
            restricted_symmetric_check(attributes)?;
        }
        TPM_ALG_SYMCIPHER => restricted_symmetric_check(attributes)?,
        _ => {
            if !has(attributes, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN) {
                return Err(TPM_RC_ATTRIBUTES);
            }
        }
    }
    public_attributes_validation(parent, public)
}

fn restricted_symmetric_check(attributes: u32) -> Result<(), TpmResult> {
    if has(attributes, TPMA_OBJECT_RESTRICTED)
        && !has(attributes, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN)
        && (has(attributes, TPMA_OBJECT_FIXED_PARENT) || has(attributes, TPMA_OBJECT_FIXED_TPM))
    {
        return Err(TPM_RC_ATTRIBUTES);
    }
    Ok(())
}

pub(super) fn public_attributes_validation(
    parent: Option<&ParentPublicInfo>,
    public: &OwnedTpmtPublic,
) -> Result<(), TpmResult> {
    let attributes = public.object_attributes;
    let parent_attributes = parent.map_or(0, |info| info.attributes);
    if public.name_alg == TPM_ALG_NULL {
        return Err(TPM_RC_HASH);
    }
    if !public.auth_policy.is_empty()
        && Some(public.auth_policy.len()) != digest_size(public.name_alg)
    {
        return Err(TPM_RC_SIZE);
    }
    if parent.is_none() || has(parent_attributes, TPMA_OBJECT_FIXED_TPM) {
        if has(attributes, TPMA_OBJECT_FIXED_PARENT) != has(attributes, TPMA_OBJECT_FIXED_TPM) {
            return Err(TPM_RC_ATTRIBUTES);
        }
    } else if has(attributes, TPMA_OBJECT_FIXED_TPM) {
        return Err(TPM_RC_ATTRIBUTES);
    }
    if has(attributes, TPMA_OBJECT_SIGN) == has(attributes, TPMA_OBJECT_DECRYPT) {
        if has(attributes, TPMA_OBJECT_RESTRICTED) {
            return Err(TPM_RC_ATTRIBUTES);
        }
        if public.object_type != TPM_ALG_KEYEDHASH && !has(attributes, TPMA_OBJECT_SIGN) {
            return Err(TPM_RC_ATTRIBUTES);
        }
    }
    if has(attributes, TPMA_OBJECT_FIXED_TPM) && has(attributes, TPMA_OBJECT_ENCRYPTED_DUPLICATION)
    {
        return Err(TPM_RC_ATTRIBUTES);
    }
    if parent.is_some()
        && !has(parent_attributes, TPMA_OBJECT_FIXED_TPM)
        && has(attributes, TPMA_OBJECT_ENCRYPTED_DUPLICATION)
            != has(parent_attributes, TPMA_OBJECT_ENCRYPTED_DUPLICATION)
    {
        return Err(TPM_RC_ATTRIBUTES);
    }
    if has(attributes, TPMA_OBJECT_FIRMWARE_LIMITED) || has(attributes, TPMA_OBJECT_SVN_LIMITED) {
        return Err(TPM_RC_ATTRIBUTES);
    }
    if let Some(info) = parent
        && info.derivation_parent
    {
        if has(attributes, TPMA_OBJECT_FIXED_TPM) != has(info.attributes, TPMA_OBJECT_FIXED_TPM) {
            return Err(TPM_RC_ATTRIBUTES);
        }
        if !has(attributes, TPMA_OBJECT_FIXED_PARENT) {
            return Err(TPM_RC_ATTRIBUTES);
        }
    }
    scheme_checks(parent, public)
}

pub(super) fn scheme_checks(
    parent: Option<&ParentPublicInfo>,
    public: &OwnedTpmtPublic,
) -> Result<(), TpmResult> {
    let attributes = public.object_attributes;
    let symmetric = match &public.parameters {
        PublicParms::SymCipher(sym) => {
            if has(attributes, TPMA_OBJECT_DECRYPT)
                && !matches!(
                    sym.mode,
                    Some(TPM_ALG_CTR | TPM_ALG_OFB | TPM_ALG_CBC | TPM_ALG_CFB | TPM_ALG_ECB)
                )
            {
                return Err(TPM_RC_SCHEME);
            }
            Some(*sym)
        }
        PublicParms::KeyedHash(scheme) => {
            if has(attributes, TPMA_OBJECT_SIGN) == has(attributes, TPMA_OBJECT_DECRYPT) {
                if scheme.scheme != TPM_ALG_NULL {
                    return Err(TPM_RC_SCHEME);
                }
            } else if has(attributes, TPMA_OBJECT_SIGN) {
                if scheme.scheme != TPM_ALG_HMAC {
                    return Err(TPM_RC_SCHEME);
                }
            } else {
                if scheme.scheme != TPM_ALG_XOR {
                    return Err(TPM_RC_SCHEME);
                }
                if has(attributes, TPMA_OBJECT_RESTRICTED) {
                    if scheme.kdf != Some(TPM_ALG_KDF1_SP800_108) {
                        return Err(TPM_RC_SCHEME);
                    }
                    if scheme.hash_alg.and_then(digest_size).is_none() {
                        return Err(TPM_RC_HASH);
                    }
                }
            }
            None
        }
        PublicParms::Rsa {
            symmetric, scheme, ..
        } => {
            asymmetric_scheme_checks(public.object_type, attributes, scheme, symmetric)?;
            Some(*symmetric)
        }
        PublicParms::Ecc {
            symmetric,
            scheme,
            kdf,
            ..
        } => {
            asymmetric_scheme_checks(public.object_type, attributes, scheme, symmetric)?;
            if kdf.scheme != TPM_ALG_NULL {
                return Err(TPM_RC_KDF);
            }
            Some(*symmetric)
        }
    };

    if let Some(symmetric) = symmetric
        && has(attributes, TPMA_OBJECT_RESTRICTED)
        && has(attributes, TPMA_OBJECT_DECRYPT)
    {
        if symmetric.algorithm == TPM_ALG_NULL {
            return Err(TPM_RC_SYMMETRIC);
        }
        if has(attributes, TPMA_OBJECT_FIXED_PARENT)
            && let Some(info) = parent
        {
            if public.name_alg != info.name_alg {
                return Err(TPM_RC_HASH);
            }
            let child = [
                symmetric.algorithm,
                symmetric.key_bits.unwrap_or(0),
                symmetric.mode.unwrap_or(0),
            ];
            if child != info.symmetric {
                return Err(TPM_RC_SYMMETRIC);
            }
        }
    }
    Ok(())
}

pub(super) fn set_label_and_context(
    label_context: &mut DeriveLabelContext,
    sensitive_data: &[u8],
) -> Result<(), TpmResult> {
    if sensitive_data.is_empty() {
        return Ok(());
    }
    let mut reader = TemplateReader::new(sensitive_data);
    let sensitive_value = parse_derive(&mut reader)?;
    if label_context.label.is_empty() {
        label_context.label = sensitive_value.label;
    }
    if label_context.context.is_empty() {
        label_context.context = sensitive_value.context;
    }
    Ok(())
}

fn is_asym_sign_scheme(object_type: u16, scheme: u16) -> bool {
    match object_type {
        TPM_ALG_RSA => matches!(scheme, TPM_ALG_RSASSA | TPM_ALG_RSAPSS),
        TPM_ALG_ECC => matches!(
            scheme,
            TPM_ALG_ECDSA | TPM_ALG_ECDAA | TPM_ALG_SM2 | TPM_ALG_ECSCHNORR
        ),
        _ => false,
    }
}

fn is_asym_decrypt_scheme(object_type: u16, scheme: u16) -> bool {
    match object_type {
        TPM_ALG_RSA => matches!(scheme, TPM_ALG_RSAES | TPM_ALG_OAEP),
        TPM_ALG_ECC => matches!(scheme, TPM_ALG_ECDH | TPM_ALG_ECMQV | TPM_ALG_SM2),
        _ => false,
    }
}

fn asymmetric_scheme_checks(
    object_type: u16,
    attributes: u32,
    scheme: &Scheme,
    symmetric: &SymDefObject,
) -> Result<(), TpmResult> {
    if has(attributes, TPMA_OBJECT_SIGN) == has(attributes, TPMA_OBJECT_DECRYPT) {
        if scheme.scheme != TPM_ALG_NULL {
            return Err(TPM_RC_SCHEME);
        }
    } else if has(attributes, TPMA_OBJECT_SIGN) {
        if is_asym_sign_scheme(object_type, scheme.scheme) {
            if scheme.hash_alg == Some(TPM_ALG_NULL) || scheme.hash_alg.is_none() {
                return Err(TPM_RC_SCHEME);
            }
        } else if has(attributes, TPMA_OBJECT_RESTRICTED) || scheme.scheme != TPM_ALG_NULL {
            return Err(TPM_RC_SCHEME);
        }
    } else if has(attributes, TPMA_OBJECT_RESTRICTED) {
        if scheme.scheme != TPM_ALG_NULL {
            return Err(TPM_RC_SCHEME);
        }
    } else if scheme.scheme != TPM_ALG_NULL && !is_asym_decrypt_scheme(object_type, scheme.scheme) {
        return Err(TPM_RC_SCHEME);
    }
    if (!has(attributes, TPMA_OBJECT_RESTRICTED) || !has(attributes, TPMA_OBJECT_DECRYPT))
        && symmetric.algorithm != TPM_ALG_NULL
    {
        return Err(TPM_RC_SYMMETRIC);
    }
    Ok(())
}

pub(super) fn adjusted_auth_value(auth: &[u8], name_alg: u16) -> Result<Vec<u8>, TpmResult> {
    let digest_size = digest_size(name_alg).unwrap_or(DIGEST_SIZE);
    let trimmed = auth
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |position| position + 1);
    if digest_size < trimmed {
        return Err(TPM_RC_SIZE);
    }
    let mut adjusted = auth.to_vec();
    adjusted.resize(digest_size, 0);
    Ok(adjusted)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn ecc_key_size_bytes(curve_id: u16) -> Option<usize> {
    curve_key_size_bits(curve_id).map(|bits| usize::from(bits).div_ceil(8))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) const MAX_SYMMETRIC_KEY_BYTES: usize = MAX_SYM_KEY_BYTES;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE;

    fn policy() -> AlgorithmPolicy<'static> {
        AlgorithmPolicy {
            profile_algorithms: DEFAULT_ALGORITHMS_PROFILE,
            state_format: StateFormatLimit::CURRENT,
        }
    }

    fn parse(bytes: &[u8]) -> Result<OwnedTpmtPublic, TpmResult> {
        let mut reader = TemplateReader::new(bytes);
        parse_public_area(&mut reader, &policy(), false)
    }

    fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    pub(super) fn rsa_storage_template(key_bits: u16, name_alg: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(
            &(TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT)
                .to_be_bytes(),
        );
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        out.extend_from_slice(&128u16.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(super) fn ecc_storage_template(curve_id: u16, name_alg: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(
            &(TPMA_OBJECT_FIXED_TPM
                | TPMA_OBJECT_FIXED_PARENT
                | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
                | TPMA_OBJECT_USER_WITH_AUTH
                | TPMA_OBJECT_RESTRICTED
                | TPMA_OBJECT_DECRYPT)
                .to_be_bytes(),
        );
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        out.extend_from_slice(&128u16.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&curve_id.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }

    #[test]
    fn the_object_attribute_bits_match_the_published_table() {
        assert_eq!(TPMA_OBJECT_FIXED_TPM, 0x0000_0002);
        assert_eq!(TPMA_OBJECT_ST_CLEAR, 0x0000_0004);
        assert_eq!(TPMA_OBJECT_FIXED_PARENT, 0x0000_0010);
        assert_eq!(TPMA_OBJECT_SENSITIVE_DATA_ORIGIN, 0x0000_0020);
        assert_eq!(TPMA_OBJECT_USER_WITH_AUTH, 0x0000_0040);
        assert_eq!(TPMA_OBJECT_ADMIN_WITH_POLICY, 0x0000_0080);
        assert_eq!(TPMA_OBJECT_NO_DA, 0x0000_0400);
        assert_eq!(TPMA_OBJECT_ENCRYPTED_DUPLICATION, 0x0000_0800);
        assert_eq!(TPMA_OBJECT_RESTRICTED, 0x0001_0000);
        assert_eq!(TPMA_OBJECT_DECRYPT, 0x0002_0000);
        assert_eq!(TPMA_OBJECT_SIGN, 0x0004_0000);
        assert_eq!(TPMA_OBJECT_RESERVED, 0xfff0_f009);
    }

    #[test]
    fn the_rsa_storage_template_round_trips_through_the_marshaller() {
        let bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let public = parse(&bytes).expect("a valid template");
        assert_eq!(public.object_type, TPM_ALG_RSA);
        assert_eq!(public.name_alg, TPM_ALG_SHA256);
        assert_eq!(marshal_public_area(&public).unwrap(), bytes);
    }

    #[test]
    fn the_ecc_storage_template_round_trips_through_the_marshaller() {
        let bytes = ecc_storage_template(0x0004, TPM_ALG_SHA384);
        let public = parse(&bytes).expect("a valid template");
        assert_eq!(public.object_type, TPM_ALG_ECC);
        assert_eq!(marshal_public_area(&public).unwrap(), bytes);
    }

    #[test]
    fn every_strict_prefix_of_a_template_is_insufficient() {
        let bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        for length in 0..bytes.len() {
            assert_eq!(
                parse(&bytes[..length]).unwrap_err(),
                TPM_RC_INSUFFICIENT,
                "prefix {length}"
            );
        }
        assert!(parse(&bytes).is_ok());
    }

    #[test]
    fn an_unsupported_object_type_is_a_type_error() {
        for object_type in [0x0000u16, 0x0004, 0x0010, 0x0024, 0xffff] {
            let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
            bytes[0..2].copy_from_slice(&object_type.to_be_bytes());
            assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_TYPE);
        }
    }

    #[test]
    fn an_unsupported_name_algorithm_is_a_hash_error() {
        for name_alg in [0x0000u16, 0x0005, 0x0010, 0x0012, 0xffff] {
            let bytes = rsa_storage_template(2048, name_alg);
            assert_eq!(
                parse(&bytes).unwrap_err(),
                TPM_RC_HASH,
                "alg {name_alg:#06x}"
            );
        }
    }

    #[test]
    fn a_null_name_algorithm_is_accepted_only_when_allowed() {
        let bytes = rsa_storage_template(2048, TPM_ALG_NULL);
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_HASH);
        let mut reader = TemplateReader::new(&bytes);
        assert!(parse_public_area(&mut reader, &policy(), true).is_ok());
    }

    #[test]
    fn reserved_object_attribute_bits_are_rejected() {
        for bit in [0u32, 3, 12, 15, 20, 31] {
            let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
            let attributes = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) | (1 << bit);
            bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
            assert_eq!(
                parse(&bytes).unwrap_err(),
                TPM_RC_RESERVED_BITS,
                "bit {bit}"
            );
        }
    }

    #[test]
    fn an_oversized_auth_policy_is_a_size_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        bytes[8..10].copy_from_slice(&(DIGEST_SIZE as u16 + 1).to_be_bytes());
        bytes.splice(10..10, core::iter::repeat_n(0u8, DIGEST_SIZE + 1));
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_SIZE);
    }

    #[test]
    fn an_unsupported_rsa_key_size_is_a_value_error() {
        for key_bits in [0u16, 512, 1536, 4096, 0xffff] {
            let bytes = rsa_storage_template(key_bits, TPM_ALG_SHA256);
            assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_VALUE, "bits {key_bits}");
        }
    }

    #[test]
    fn an_unsupported_curve_is_a_curve_error() {
        for curve_id in [0x0000u16, 0x0006, 0x0012, 0xffff] {
            let bytes = ecc_storage_template(curve_id, TPM_ALG_SHA384);
            assert_eq!(
                parse(&bytes).unwrap_err(),
                TPM_RC_CURVE,
                "curve {curve_id:#06x}"
            );
        }
    }

    #[test]
    fn an_unsupported_symmetric_algorithm_is_a_symmetric_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        bytes[10..12].copy_from_slice(&0x0099u16.to_be_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_SYMMETRIC);
    }

    #[test]
    fn an_unsupported_symmetric_key_size_is_a_value_error() {
        for key_bits in [0u16, 64, 129, 512] {
            let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
            bytes[12..14].copy_from_slice(&key_bits.to_be_bytes());
            assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_VALUE, "bits {key_bits}");
        }
    }

    #[test]
    fn an_unsupported_symmetric_mode_is_a_mode_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        bytes[14..16].copy_from_slice(&0x0099u16.to_be_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_MODE);
    }

    #[test]
    fn an_unsupported_rsa_scheme_is_a_value_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        bytes[16..18].copy_from_slice(&0x0099u16.to_be_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_VALUE);
    }

    #[test]
    fn an_unsupported_ecc_scheme_is_a_scheme_error() {
        let mut bytes = ecc_storage_template(0x0004, TPM_ALG_SHA384);
        bytes[16..18].copy_from_slice(&0x0099u16.to_be_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_SCHEME);
    }

    #[test]
    fn an_unsupported_key_derivation_function_is_a_kdf_error() {
        let mut bytes = ecc_storage_template(0x0004, TPM_ALG_SHA384);
        let position = bytes.len() - 6;
        bytes[position..position + 2].copy_from_slice(&0x0099u16.to_be_bytes());
        assert_eq!(parse(&bytes).unwrap_err(), TPM_RC_KDF);
    }

    #[test]
    fn a_disabled_profile_algorithm_is_rejected_like_an_unknown_one() {
        let restricted = AlgorithmPolicy {
            profile_algorithms: b"rsa,sha256,aes,cfb,null",
            state_format: StateFormatLimit::CURRENT,
        };
        let bytes = rsa_storage_template(2048, TPM_ALG_SHA384);
        let mut reader = TemplateReader::new(&bytes);
        assert_eq!(
            parse_public_area(&mut reader, &restricted, false).unwrap_err(),
            TPM_RC_HASH
        );
    }

    #[test]
    fn the_computed_name_is_the_algorithm_followed_by_the_template_digest() {
        let bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let public = parse(&bytes).unwrap();
        let name = object_name(&public).unwrap();
        assert_eq!(name.len(), 2 + 32);
        assert_eq!(&name[..2], &TPM_ALG_SHA256.to_be_bytes());
        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(&bytes);
        assert_eq!(&name[2..], &hasher.finalize()[..]);
    }

    #[test]
    fn the_name_length_follows_the_name_algorithm() {
        for (name_alg, size) in [
            (TPM_ALG_SHA1, 20usize),
            (TPM_ALG_SHA256, 32),
            (TPM_ALG_SHA384, 48),
            (TPM_ALG_SHA512, 64),
        ] {
            let bytes = rsa_storage_template(2048, name_alg);
            let public = parse(&bytes).unwrap();
            assert_eq!(object_name(&public).unwrap().len(), 2 + size);
        }
    }

    #[test]
    fn a_storage_template_passes_the_creation_checks() {
        let public = parse(&rsa_storage_template(2048, TPM_ALG_SHA256)).unwrap();
        assert_eq!(create_checks(None, &public, 0), Ok(()));
        let public = parse(&ecc_storage_template(0x0004, TPM_ALG_SHA384)).unwrap();
        assert_eq!(create_checks(None, &public, 0), Ok(()));
    }

    #[test]
    fn an_asymmetric_key_without_sensitive_data_origin_is_an_attributes_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let attributes = u32::from_be_bytes(bytes[4..8].try_into().unwrap())
            & !TPMA_OBJECT_SENSITIVE_DATA_ORIGIN;
        bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
        let public = parse(&bytes).unwrap();
        assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_ATTRIBUTES));
        assert_eq!(create_checks(None, &public, 16), Err(TPM_RC_ATTRIBUTES));
    }

    #[test]
    fn fixed_tpm_and_fixed_parent_must_agree_for_a_primary_object() {
        for attribute in [TPMA_OBJECT_FIXED_TPM, TPMA_OBJECT_FIXED_PARENT] {
            let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
            let attributes = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) & !attribute;
            bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
            let public = parse(&bytes).unwrap();
            assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_ATTRIBUTES));
        }
    }

    #[test]
    fn a_restricted_key_with_both_sign_and_decrypt_is_an_attributes_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let attributes = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) | TPMA_OBJECT_SIGN;
        bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
        let public = parse(&bytes).unwrap();
        assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_ATTRIBUTES));
    }

    #[test]
    fn a_fixed_tpm_key_may_not_ask_for_encrypted_duplication() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let attributes =
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()) | TPMA_OBJECT_ENCRYPTED_DUPLICATION;
        bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
        let public = parse(&bytes).unwrap();
        assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_ATTRIBUTES));
    }

    #[test]
    fn firmware_and_svn_limited_objects_are_not_supported() {
        for attribute in [TPMA_OBJECT_FIRMWARE_LIMITED, TPMA_OBJECT_SVN_LIMITED] {
            let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
            let attributes = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) | attribute;
            bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
            let public = parse(&bytes).unwrap();
            assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_ATTRIBUTES));
        }
    }

    #[test]
    fn an_auth_policy_of_the_wrong_length_is_a_size_error() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        bytes[8..10].copy_from_slice(&20u16.to_be_bytes());
        bytes.splice(10..10, core::iter::repeat_n(0xaau8, 20));
        let public = parse(&bytes).unwrap();
        assert_eq!(public.auth_policy.len(), 20);
        assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_SIZE));
    }

    #[test]
    fn a_restricted_decryption_key_needs_symmetric_algorithms() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        bytes.splice(10..16, TPM_ALG_NULL.to_be_bytes().iter().copied());
        let public = parse(&bytes).unwrap();
        assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_SYMMETRIC));
    }

    #[test]
    fn an_unrestricted_signing_key_must_not_carry_symmetric_algorithms() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let attributes = (u32::from_be_bytes(bytes[4..8].try_into().unwrap())
            & !(TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT))
            | TPMA_OBJECT_SIGN;
        bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
        let public = parse(&bytes).unwrap();
        assert_eq!(create_checks(None, &public, 0), Err(TPM_RC_SYMMETRIC));
    }

    #[test]
    fn a_signing_key_with_a_signing_scheme_needs_a_hash() {
        let mut bytes = rsa_storage_template(2048, TPM_ALG_SHA256);
        let attributes = (u32::from_be_bytes(bytes[4..8].try_into().unwrap())
            & !(TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT))
            | TPMA_OBJECT_SIGN;
        bytes[4..8].copy_from_slice(&attributes.to_be_bytes());
        bytes.splice(10..16, TPM_ALG_NULL.to_be_bytes().iter().copied());
        let public = parse(&bytes).unwrap();
        assert_eq!(create_checks(None, &public, 0), Ok(()));
    }

    #[test]
    fn the_adjusted_auth_value_is_padded_to_the_name_algorithm_digest() {
        assert_eq!(
            adjusted_auth_value(&[], TPM_ALG_SHA256).unwrap(),
            vec![0u8; 32]
        );
        let mut expected = vec![0u8; 48];
        expected[..3].copy_from_slice(b"abc");
        assert_eq!(
            adjusted_auth_value(b"abc", TPM_ALG_SHA384).unwrap(),
            expected
        );
    }

    #[test]
    fn an_auth_value_longer_than_the_digest_is_a_size_error() {
        assert_eq!(
            adjusted_auth_value(&[0xaa; 33], TPM_ALG_SHA256),
            Err(TPM_RC_SIZE)
        );
        assert_eq!(
            adjusted_auth_value(&[0xaa; 32], TPM_ALG_SHA256)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn trailing_zeros_do_not_count_towards_the_auth_value_length() {
        let mut oversized = vec![0u8; 40];
        oversized[..20].copy_from_slice(&[0x11; 20]);
        assert_eq!(
            adjusted_auth_value(&oversized, TPM_ALG_SHA256)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn the_ecc_key_size_follows_the_curve() {
        assert_eq!(ecc_key_size_bytes(0x0003), Some(32));
        assert_eq!(ecc_key_size_bytes(0x0004), Some(48));
        assert_eq!(ecc_key_size_bytes(0x0005), Some(66));
        assert_eq!(ecc_key_size_bytes(0x0099), None);
    }

    #[test]
    fn the_maximum_symmetric_key_size_matches_upstream() {
        assert_eq!(MAX_SYMMETRIC_KEY_BYTES, 32);
    }
}
