use crate::scalar::{Point, SCALAR_BYTES, Scalar521};

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_ECDH_ZGEN: u32 = 0x0000_0154;
pub const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
pub const TPM_SU_CLEAR: u16 = 0x0000;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_SHA256: u16 = 0x000b;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ECC_NIST_P521: u16 = 0x0005;
pub const TPM_RH_NULL: u32 = 0x4000_0007;
pub const TPM_RS_PW: u32 = 0x4000_0009;
pub const OBJECT_ATTRIBUTES: u32 = 0x0000_0040 | 0x0000_0400 | 0x0002_0000;
pub const FIRST_TRANSIENT_HANDLE: u32 = 0x8000_0000;

pub fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn tpm2b(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

fn ecc_point(point: &Point) -> Vec<u8> {
    let mut out = tpm2b(&point.x);
    out.extend_from_slice(&tpm2b(&point.y));
    out
}

pub fn startup_clear() -> Vec<u8> {
    command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_STARTUP,
        &TPM_SU_CLEAR.to_be_bytes(),
    )
}

pub fn flush_context(handle: u32) -> Vec<u8> {
    command(
        TPM_ST_NO_SESSIONS,
        TPM_CC_FLUSH_CONTEXT,
        &handle.to_be_bytes(),
    )
}

pub fn public_area(public: &Point) -> Vec<u8> {
    let mut area = Vec::new();
    area.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    area.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    area.extend_from_slice(&OBJECT_ATTRIBUTES.to_be_bytes());
    area.extend_from_slice(&tpm2b(&[]));
    area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    area.extend_from_slice(&TPM_ECC_NIST_P521.to_be_bytes());
    area.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    area.extend_from_slice(&ecc_point(public));
    area
}

pub fn load_external(private: &Scalar521, public: &Point) -> Vec<u8> {
    let mut sensitive = Vec::new();
    sensitive.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
    sensitive.extend_from_slice(&tpm2b(&[]));
    sensitive.extend_from_slice(&tpm2b(&[]));
    sensitive.extend_from_slice(&tpm2b(private.bytes()));
    let mut body = tpm2b(&sensitive);
    body.extend_from_slice(&tpm2b(&public_area(public)));
    body.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
    command(TPM_ST_NO_SESSIONS, TPM_CC_LOAD_EXTERNAL, &body)
}

pub fn password_session() -> Vec<u8> {
    let mut session = Vec::new();
    session.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    session.extend_from_slice(&tpm2b(&[]));
    session.push(0x01);
    session.extend_from_slice(&tpm2b(&[]));
    let mut out = (session.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&session);
    out
}

pub fn ecdh_zgen(handle: u32, peer: &Point) -> Vec<u8> {
    let mut body = handle.to_be_bytes().to_vec();
    body.extend_from_slice(&password_session());
    body.extend_from_slice(&tpm2b(&ecc_point(peer)));
    command(TPM_ST_SESSIONS, TPM_CC_ECDH_ZGEN, &body)
}

pub fn expected_zgen_response(shared: &Point) -> Vec<u8> {
    let parameters = tpm2b(&ecc_point(shared));
    let mut body = (parameters.len() as u32).to_be_bytes().to_vec();
    body.extend_from_slice(&parameters);
    body.extend_from_slice(&tpm2b(&[]));
    body.push(0x01);
    body.extend_from_slice(&tpm2b(&[]));
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&TPM_ST_SESSIONS.to_be_bytes());
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseError {
    Short(usize),
    SizeMismatch { declared: usize, actual: usize },
    Code(u32),
}

impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short(len) => write!(f, "response of {len} bytes is shorter than a header"),
            Self::SizeMismatch { declared, actual } => {
                write!(f, "response declares {declared} bytes but carries {actual}")
            }
            Self::Code(code) => write!(f, "TPM response code 0x{code:08x}"),
        }
    }
}

impl std::error::Error for ResponseError {}

pub fn response_code(response: &[u8]) -> Result<u32, ResponseError> {
    if response.len() < 10 {
        return Err(ResponseError::Short(response.len()));
    }
    let declared = u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize;
    if declared != response.len() {
        return Err(ResponseError::SizeMismatch {
            declared,
            actual: response.len(),
        });
    }
    Ok(u32::from_be_bytes(response[6..10].try_into().unwrap()))
}

pub fn expect_success(response: &[u8]) -> Result<(), ResponseError> {
    match response_code(response)? {
        0 => Ok(()),
        code => Err(ResponseError::Code(code)),
    }
}

pub fn loaded_handle(response: &[u8]) -> Result<u32, ResponseError> {
    expect_success(response)?;
    if response.len() < 14 {
        return Err(ResponseError::Short(response.len()));
    }
    Ok(u32::from_be_bytes(response[10..14].try_into().unwrap()))
}

pub fn zgen_command_len() -> usize {
    let dummy = Point {
        x: vec![0; SCALAR_BYTES],
        y: vec![0; SCALAR_BYTES],
    };
    ecdh_zgen(FIRST_TRANSIENT_HANDLE, &dummy).len()
}

pub const TPM_ST_HASHCHECK: u16 = 0x8024;
pub const TPM_RH_OWNER: u32 = 0x4000_0001;
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
pub const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
pub const TPM_SE_HMAC: u8 = 0x00;

pub const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
pub const TPM_CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
pub const TPM_CC_CREATE: u32 = 0x0000_0153;
pub const TPM_CC_MAC: u32 = 0x0000_0155;
pub const TPM_CC_LOAD: u32 = 0x0000_0157;
pub const TPM_CC_RSA_DECRYPT: u32 = 0x0000_0159;
pub const TPM_CC_SIGN: u32 = 0x0000_015d;
pub const TPM_CC_MAKE_CREDENTIAL: u32 = 0x0000_0168;
pub const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
pub const TPM_CC_VERIFY_SIGNATURE: u32 = 0x0000_0177;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017b;
pub const TPM_CC_HASH: u32 = 0x0000_017d;
pub const TPM_CC_ENCRYPT_DECRYPT2: u32 = 0x0000_0193;

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_HMAC: u16 = 0x0005;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM_ALG_RSASSA: u16 = 0x0014;
pub const TPM_ALG_RSAES: u16 = 0x0015;
pub const TPM_ALG_RSAPSS: u16 = 0x0016;
pub const TPM_ALG_OAEP: u16 = 0x0017;
pub const TPM_ALG_ECDSA: u16 = 0x0018;
pub const TPM_ALG_SM2: u16 = 0x001b;
pub const TPM_ALG_ECSCHNORR: u16 = 0x001c;
pub const TPM_ALG_SYMCIPHER: u16 = 0x0025;
pub const TPM_ALG_CFB: u16 = 0x0043;

pub const ATTR_FIXED_TPM: u32 = 0x0000_0002;
pub const ATTR_FIXED_PARENT: u32 = 0x0000_0010;
pub const ATTR_SENSITIVE_DATA_ORIGIN: u32 = 0x0000_0020;
pub const ATTR_USER_WITH_AUTH: u32 = 0x0000_0040;
pub const ATTR_NO_DA: u32 = 0x0000_0400;
pub const ATTR_RESTRICTED: u32 = 0x0001_0000;
pub const ATTR_DECRYPT: u32 = 0x0002_0000;
pub const ATTR_SIGN: u32 = 0x0004_0000;

pub const TPM_RC_SIZE: u32 = 0x95;

pub const TPM_RC_VALUE: u32 = 0x084;
pub const TPM_RC_SIGNATURE: u32 = 0x09b;
pub const TPM_RC_INTEGRITY: u32 = 0x09f;
pub const TPM_RC_TICKET: u32 = 0x0a0;
pub const TPM_RC_BAD_AUTH: u32 = 0x0a2;
pub const TPM_RC_ECC_POINT: u32 = 0x0a7;
pub const TPM_RC_P: u32 = 0x040;
pub const TPM_RC_S: u32 = 0x800;

pub fn parameter_error(rc: u32, parameter: u32) -> u32 {
    rc | TPM_RC_P | (parameter << 8)
}

pub fn session_error(rc: u32, session: u32) -> u32 {
    rc | TPM_RC_S | (session << 8)
}

pub fn handle_error(rc: u32, handle: u32) -> u32 {
    rc | (handle << 8)
}

pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub fn put_2b(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u16(out, bytes.len() as u16);
    out.extend_from_slice(bytes);
}

pub fn sized(bytes: &[u8]) -> Vec<u8> {
    tpm2b(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub bytes: Vec<u8>,
    pub parameters_at: usize,
}

pub fn password_sessions(passwords: &[&[u8]]) -> Vec<u8> {
    let mut area = Vec::new();
    for password in passwords {
        put_u32(&mut area, TPM_RS_PW);
        put_2b(&mut area, &[]);
        area.push(0x01);
        put_2b(&mut area, password);
    }
    let mut out = (area.len() as u32).to_be_bytes().to_vec();
    out.extend(area);
    out
}

pub fn build_command(code: u32, handles: &[u32], passwords: &[&[u8]], parameters: &[u8]) -> Built {
    let mut body = Vec::new();
    for handle in handles {
        put_u32(&mut body, *handle);
    }
    let tag = if passwords.is_empty() {
        TPM_ST_NO_SESSIONS
    } else {
        body.extend(password_sessions(passwords));
        TPM_ST_SESSIONS
    };
    let parameters_at = 10 + body.len();
    body.extend_from_slice(parameters);
    Built {
        bytes: command(tag, code, &body),
        parameters_at,
    }
}

pub fn success_response(handles: &[u32], parameters: &[u8], sessions: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for handle in handles {
        put_u32(&mut body, *handle);
    }
    let tag = if sessions == 0 {
        body.extend_from_slice(parameters);
        TPM_ST_NO_SESSIONS
    } else {
        put_u32(&mut body, parameters.len() as u32);
        body.extend_from_slice(parameters);
        for _ in 0..sessions {
            body.extend_from_slice(&[0, 0, 0x01, 0, 0]);
        }
        TPM_ST_SESSIONS
    };
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend(body);
    out
}

pub fn success_parameters_at(handles: usize, sessions: usize) -> usize {
    10 + 4 * handles + if sessions == 0 { 0 } else { 4 }
}

pub fn error_response(rc: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    out.extend_from_slice(&10u32.to_be_bytes());
    out.extend_from_slice(&rc.to_be_bytes());
    out
}

pub fn flush_response() -> Vec<u8> {
    error_response(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymDef {
    Null,
    Cipher { alg: u16, bits: u16, mode: u16 },
}

impl SymDef {
    pub fn marshal(self, out: &mut Vec<u8>) {
        match self {
            Self::Null => put_u16(out, TPM_ALG_NULL),
            Self::Cipher { alg, bits, mode } => {
                put_u16(out, alg);
                put_u16(out, bits);
                put_u16(out, mode);
            }
        }
    }

    pub fn aes128_cfb() -> Self {
        Self::Cipher {
            alg: TPM_ALG_AES,
            bits: 128,
            mode: TPM_ALG_CFB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Null,
    WithHash(u16, u16),
    Ecdaa { hash: u16, count: u16 },
    NoHash(u16),
}

impl Scheme {
    pub fn marshal(self, out: &mut Vec<u8>) {
        match self {
            Self::Null => put_u16(out, TPM_ALG_NULL),
            Self::WithHash(scheme, hash) => {
                put_u16(out, scheme);
                put_u16(out, hash);
            }
            Self::Ecdaa { hash, count } => {
                put_u16(out, 0x1a);
                put_u16(out, hash);
                put_u16(out, count);
            }
            Self::NoHash(scheme) => put_u16(out, scheme),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicDetail {
    Rsa {
        symmetric: SymDef,
        scheme: Scheme,
        bits: u16,
        modulus: Vec<u8>,
    },
    Ecc {
        symmetric: SymDef,
        scheme: Scheme,
        curve: u16,
        x: Vec<u8>,
        y: Vec<u8>,
    },
    KeyedHash {
        scheme: Scheme,
        unique: Vec<u8>,
    },
    Symcipher {
        symmetric: SymDef,
        unique: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public {
    pub name_alg: u16,
    pub attributes: u32,
    pub detail: PublicDetail,
}

impl Public {
    pub fn object_type(&self) -> u16 {
        match self.detail {
            PublicDetail::Rsa { .. } => TPM_ALG_RSA,
            PublicDetail::Ecc { .. } => TPM_ALG_ECC,
            PublicDetail::KeyedHash { .. } => TPM_ALG_KEYEDHASH,
            PublicDetail::Symcipher { .. } => TPM_ALG_SYMCIPHER,
        }
    }

    pub fn marshal(&self) -> Vec<u8> {
        self.marshal_with_policy(&[])
    }

    pub fn marshal_with_policy(&self, policy: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_u16(&mut out, self.object_type());
        put_u16(&mut out, self.name_alg);
        put_u32(&mut out, self.attributes);
        put_2b(&mut out, policy);
        match &self.detail {
            PublicDetail::Rsa {
                symmetric,
                scheme,
                bits,
                modulus,
            } => {
                symmetric.marshal(&mut out);
                scheme.marshal(&mut out);
                put_u16(&mut out, *bits);
                put_u32(&mut out, 0);
                put_2b(&mut out, modulus);
            }
            PublicDetail::Ecc {
                symmetric,
                scheme,
                curve,
                x,
                y,
            } => {
                symmetric.marshal(&mut out);
                scheme.marshal(&mut out);
                put_u16(&mut out, *curve);
                put_u16(&mut out, TPM_ALG_NULL);
                put_2b(&mut out, x);
                put_2b(&mut out, y);
            }
            PublicDetail::KeyedHash { scheme, unique } => {
                scheme.marshal(&mut out);
                put_2b(&mut out, unique);
            }
            PublicDetail::Symcipher { symmetric, unique } => {
                symmetric.marshal(&mut out);
                put_2b(&mut out, unique);
            }
        }
        out
    }

    pub fn name(&self) -> Vec<u8> {
        self.name_with_policy(&[])
    }

    pub fn name_with_policy(&self, policy: &[u8]) -> Vec<u8> {
        let hash = crate::oracle::hash::HashAlg::ALL
            .into_iter()
            .find(|h| h.alg_id() == self.name_alg)
            .expect("name algorithm is a supported hash");
        let mut out = self.name_alg.to_be_bytes().to_vec();
        out.extend(hash.digest(&[&self.marshal_with_policy(policy)]));
        out
    }
}

pub fn sensitive(object_type: u16, auth: &[u8], seed: &[u8], secret: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, object_type);
    put_2b(&mut out, auth);
    put_2b(&mut out, seed);
    put_2b(&mut out, secret);
    out
}

pub fn load_external_command(sensitive: Option<&[u8]>, public: &Public, hierarchy: u32) -> Vec<u8> {
    let mut parameters = Vec::new();
    put_2b(&mut parameters, sensitive.unwrap_or(&[]));
    put_2b(&mut parameters, &public.marshal());
    put_u32(&mut parameters, hierarchy);
    build_command(TPM_CC_LOAD_EXTERNAL, &[], &[], &parameters).bytes
}

pub fn create_primary_command(hierarchy: u32, auth: &[u8], public: &Public) -> Vec<u8> {
    let mut parameters = Vec::new();
    let mut sensitive_create = Vec::new();
    put_2b(&mut sensitive_create, auth);
    put_2b(&mut sensitive_create, &[]);
    put_2b(&mut parameters, &sensitive_create);
    put_2b(&mut parameters, &public.marshal());
    put_2b(&mut parameters, &[]);
    put_u32(&mut parameters, 0);
    build_command(TPM_CC_CREATE_PRIMARY, &[hierarchy], &[&[]], &parameters).bytes
}

pub fn response_parameters(response: &[u8], handles: usize) -> Option<&[u8]> {
    if response_code(response).ok()? != 0 {
        return None;
    }
    let tag = u16::from_be_bytes(response[0..2].try_into().ok()?);
    let start = 10 + 4 * handles;
    if tag == TPM_ST_SESSIONS {
        let size = u32::from_be_bytes(response.get(start..start + 4)?.try_into().ok()?) as usize;
        response.get(start + 4..start + 4 + size)
    } else {
        response.get(start..)
    }
}

pub fn read_2b(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let size = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
    Some((bytes.get(at + 2..at + 2 + size)?, at + 2 + size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_matches_the_known_encoding() {
        assert_eq!(hex::encode(startup_clear()), "80010000000c000001440000");
        assert_eq!(
            hex::encode(flush_context(0x8000_0000)),
            "80010000000e0000016580000000"
        );
    }

    #[test]
    fn zgen_layout_is_fixed_width() {
        let point = Point {
            x: vec![1; SCALAR_BYTES],
            y: vec![2; SCALAR_BYTES],
        };
        let cmd = ecdh_zgen(0x8000_0001, &point);
        assert_eq!(cmd.len(), 10 + 4 + 4 + 9 + 2 + 136);
        assert_eq!(cmd.len(), zgen_command_len());
        assert_eq!(&cmd[10..14], &[0x80, 0, 0, 1]);
        let response = expected_zgen_response(&point);
        assert_eq!(response.len(), 10 + 4 + 2 + 136 + 5);
        assert_eq!(response_code(&response), Ok(0));
    }

    #[test]
    fn response_parsing_rejects_inconsistent_sizes() {
        assert_eq!(response_code(&[0; 4]), Err(ResponseError::Short(4)));
        let mut bad = expected_zgen_response(&Point {
            x: vec![0; SCALAR_BYTES],
            y: vec![0; SCALAR_BYTES],
        });
        bad.push(0);
        assert!(matches!(
            response_code(&bad),
            Err(ResponseError::SizeMismatch { .. })
        ));
        let failure = hex::decode("80010000000a00000184").unwrap();
        assert_eq!(expect_success(&failure), Err(ResponseError::Code(0x184)));
    }
}
