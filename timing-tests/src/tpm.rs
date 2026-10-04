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

fn command(tag: u16, code: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&tag.to_be_bytes());
    out.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn tpm2b(bytes: &[u8]) -> Vec<u8> {
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
