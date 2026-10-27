use serde::{Deserialize, Serialize};

use super::catalog::{EccScheme, KeygenKind, Scenario};
use super::layout::{Post, Step};
use super::{InputPair, Seed, SeedKind, SplitMix};
use crate::oracle::bytes::from_be;
use crate::oracle::ec::CurveId;
use crate::oracle::hash::HashAlg;
use crate::oracle::rsa::{RsaBits, pss_verify};
use crate::scalar::Point;
use crate::tpm;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "check", rename_all = "kebab-case")]
pub enum Check {
    Ecc {
        oracle: Box<crate::oracle::ecc::Oracle>,
        program: crate::program::Program,
    },
    Protection {
        oracle: Box<super::remaining_auth::Oracle>,
        program: Option<crate::program::Program>,
    },
    Program {
        program: crate::program::Program,
    },
    EccSignature {
        scheme: String,
        curve: CurveId,
        hash: HashAlg,
        #[serde(with = "crate::scalar::hex_bytes")]
        public_x: Vec<u8>,
        #[serde(with = "crate::scalar::hex_bytes")]
        public_y: Vec<u8>,
        #[serde(with = "crate::scalar::hex_bytes")]
        digest: Vec<u8>,
    },
    RsaPss {
        bits: RsaBits,
        hash: HashAlg,
        #[serde(with = "crate::scalar::hex_bytes")]
        digest: Vec<u8>,
    },
    PrimaryKey {
        kind: String,
    },
    SessionNonce {
        size: usize,
    },
    RandomBytes {
        len: usize,
    },
}

fn signature_components(response: &[u8]) -> Result<(u16, Vec<u8>, Vec<u8>), String> {
    let params = tpm::response_parameters(response, 0).ok_or("not a success response")?;
    if params.len() < 4 {
        return Err("signature too short".into());
    }
    let alg = u16::from_be_bytes([params[0], params[1]]);
    let (r, next) = tpm::read_2b(params, 4).ok_or("malformed r")?;
    let (s, _) = tpm::read_2b(params, next).ok_or("malformed s")?;
    Ok((alg, r.to_vec(), s.to_vec()))
}

impl Check {
    pub fn check(&self, response: &[u8]) -> Result<(), String> {
        match self {
            Self::Ecc { oracle, program } => oracle.check(response, program),
            Self::Protection { oracle, program } => oracle.check(response, program.as_ref()),
            Self::Program { program } => program.transcript(response).map(|_| ()),
            Self::EccSignature {
                scheme,
                curve,
                hash,
                public_x,
                public_y,
                digest,
            } => {
                let (_, r, s) = signature_components(response)?;
                let c = curve.curve();
                let q = c.decode(public_x, public_y);
                let ok = match scheme.as_str() {
                    "ecdsa" => c.ecdsa_verify(&q, digest, &r, &s),
                    "ecschnorr" => c.schnorr_verify(*hash, &q, digest, &r, &s),
                    "sm2" => c.sm2_verify(&q, digest, &r, &s),
                    other => return Err(format!("unknown scheme {other}")),
                };
                ok.then_some(())
                    .ok_or_else(|| format!("{scheme} signature does not verify independently"))
            }
            Self::RsaPss { bits, hash, digest } => {
                let params =
                    tpm::response_parameters(response, 0).ok_or("not a success response")?;
                let (sig, _) = tpm::read_2b(params, 4).ok_or("malformed signature")?;
                let em = bits
                    .key()
                    .public(sig)
                    .ok_or("signature not below the modulus")?;
                pss_verify(*hash, &em, digest, bits.bits())
                    .map(|_| ())
                    .ok_or_else(|| "RSA-PSS signature does not verify independently".into())
            }
            Self::PrimaryKey { kind } => check_primary(kind, response),
            Self::SessionNonce { size } => {
                let params =
                    tpm::response_parameters(response, 1).ok_or("not a success response")?;
                let (nonce, _) = tpm::read_2b(params, 0).ok_or("malformed nonce")?;
                (nonce.len() == *size && nonce.iter().any(|b| *b != 0))
                    .then_some(())
                    .ok_or_else(|| "session nonce has the wrong size or is all zero".into())
            }
            Self::RandomBytes { len } => {
                let params =
                    tpm::response_parameters(response, 0).ok_or("not a success response")?;
                let (bytes, _) = tpm::read_2b(params, 0).ok_or("malformed random bytes")?;
                (bytes.len() == *len && (*len < 8 || bytes.iter().any(|b| *b != bytes[0])))
                    .then_some(())
                    .ok_or_else(|| "random output has the wrong size or is constant".into())
            }
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(len).ok_or("length overflow")?;
        let slice = self.bytes.get(self.at..end).ok_or_else(|| {
            format!(
                "{what}: response ends after {} of {end} bytes",
                self.bytes.len()
            )
        })?;
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &str) -> Result<u8, String> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &str) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2, what)?.try_into().unwrap()))
    }

    fn u32(&mut self, what: &str) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4, what)?.try_into().unwrap()))
    }

    fn sized(&mut self, what: &str) -> Result<&'a [u8], String> {
        let len = self.u16(what)? as usize;
        self.take(len, what)
    }

    fn expect_u16(&mut self, what: &str, value: u16) -> Result<(), String> {
        let actual = self.u16(what)?;
        if actual != value {
            return Err(format!("{what} is 0x{actual:04x}, expected 0x{value:04x}"));
        }
        Ok(())
    }

    fn done(&self, what: &str) -> Result<(), String> {
        if self.at != self.bytes.len() {
            return Err(format!(
                "{what}: {} trailing bytes after the structure",
                self.bytes.len() - self.at
            ));
        }
        Ok(())
    }
}

fn primary_expectation(kind: &str) -> Result<(u16, Vec<u16>), String> {
    if let Some(curve) = CurveId::ALL.iter().find(|c| kind == c.name()) {
        return Ok((
            crate::tpm::TPM_ALG_ECC,
            vec![
                crate::tpm::TPM_ALG_NULL,
                crate::tpm::TPM_ALG_NULL,
                curve.tpm_id(),
                crate::tpm::TPM_ALG_NULL,
            ],
        ));
    }
    if let Some(bits) = RsaBits::ALL.iter().find(|b| kind == b.name()) {
        return Ok((
            crate::tpm::TPM_ALG_RSA,
            vec![
                crate::tpm::TPM_ALG_NULL,
                crate::tpm::TPM_ALG_NULL,
                bits.bits() as u16,
            ],
        ));
    }
    match kind {
        "aes128" => Ok((
            crate::tpm::TPM_ALG_SYMCIPHER,
            vec![crate::tpm::TPM_ALG_AES, 128, crate::tpm::TPM_ALG_NULL],
        )),
        "hmac-sha256" => Ok((
            crate::tpm::TPM_ALG_KEYEDHASH,
            vec![crate::tpm::TPM_ALG_HMAC, crate::tpm::TPM_ALG_SHA256],
        )),
        other => Err(format!("unknown primary key kind {other}")),
    }
}

fn check_primary(kind: &str, response: &[u8]) -> Result<(), String> {
    let (expected_type, parameters) = primary_expectation(kind)?;
    let params = crate::tpm::response_parameters(response, 1)
        .ok_or("CreatePrimary response has no parameter area")?;
    let mut r = Reader::new(params);
    let public = r.sized("outPublic")?;
    {
        let mut p = Reader::new(public);
        p.expect_u16("outPublic.type", expected_type)?;
        p.expect_u16("outPublic.nameAlg", crate::tpm::TPM_ALG_SHA256)?;
        let attributes = p.u32("outPublic.objectAttributes")?;
        let required = crate::tpm::ATTR_FIXED_TPM
            | crate::tpm::ATTR_FIXED_PARENT
            | crate::tpm::ATTR_SENSITIVE_DATA_ORIGIN
            | crate::tpm::ATTR_USER_WITH_AUTH;
        if attributes & required != required {
            return Err(format!(
                "outPublic.objectAttributes 0x{attributes:08x} lacks the fixed template bits 0x{required:08x}"
            ));
        }
        if !p.sized("outPublic.authPolicy")?.is_empty() {
            return Err("outPublic.authPolicy is not empty".into());
        }
        for (index, value) in parameters.iter().enumerate() {
            p.expect_u16(&format!("outPublic.parameters[{index}]"), *value)?;
        }
        if expected_type == crate::tpm::TPM_ALG_RSA {
            let exponent = p.u32("outPublic.parameters.exponent")?;
            if exponent != 0 {
                return Err(format!(
                    "outPublic exponent is {exponent}, expected the default 0"
                ));
            }
        }
        match expected_type {
            t if t == crate::tpm::TPM_ALG_ECC => {
                let curve = CurveId::ALL
                    .into_iter()
                    .find(|c| c.name() == kind)
                    .expect("checked above");
                let c = curve.curve();
                let x = p.sized("outPublic.unique.x")?;
                let y = p.sized("outPublic.unique.y")?;
                if x.len() != c.bytes || y.len() != c.bytes {
                    return Err(format!(
                        "generated point has {}/{} coordinate bytes, expected {} each",
                        x.len(),
                        y.len(),
                        c.bytes
                    ));
                }
                if !c.on_curve(&c.decode(x, y)) {
                    return Err("generated public point is not on the curve".into());
                }
            }
            t if t == crate::tpm::TPM_ALG_RSA => {
                let bits = RsaBits::ALL
                    .into_iter()
                    .find(|b| b.name() == kind)
                    .expect("checked above");
                let modulus = p.sized("outPublic.unique.rsa")?;
                if modulus.len() != bits.bytes() {
                    return Err(format!(
                        "generated modulus has {} bytes, expected {}",
                        modulus.len(),
                        bits.bytes()
                    ));
                }
                let n = from_be(modulus);
                if n.bits() as usize != bits.bits() {
                    return Err(format!(
                        "generated modulus is {} bits, expected {}",
                        n.bits(),
                        bits.bits()
                    ));
                }
                if !n.bit(0) {
                    return Err("generated modulus is even".into());
                }
            }
            _ => {
                let unique = p.sized("outPublic.unique")?;
                if unique.len() != HashAlg::Sha256.size() {
                    return Err(format!(
                        "generated unique field has {} bytes, expected {}",
                        unique.len(),
                        HashAlg::Sha256.size()
                    ));
                }
                if unique.iter().all(|b| *b == 0) {
                    return Err("generated unique field is all zero".into());
                }
            }
        }
        p.done("outPublic")?;
    }
    let creation = r.sized("creationData")?;
    {
        let mut c = Reader::new(creation);
        let count = c.u32("creationData.pcrSelect.count")?;
        if count != 0 {
            return Err(format!(
                "creationData selects {count} PCR banks, expected none"
            ));
        }
        let pcr_digest = c.sized("creationData.pcrDigest")?;
        if pcr_digest != HashAlg::Sha256.digest(&[]) {
            return Err("creationData.pcrDigest is not the digest of an empty selection".into());
        }
        c.u8("creationData.locality")?;
        c.expect_u16("creationData.parentNameAlg", crate::tpm::TPM_ALG_NULL)?;
        for field in ["parentName", "parentQualifiedName"] {
            let name = c.sized(&format!("creationData.{field}"))?;
            if name != crate::tpm::TPM_RH_OWNER.to_be_bytes() {
                return Err(format!(
                    "creationData.{field} is {}, expected the owner handle",
                    hex::encode(name)
                ));
            }
        }
        if !c.sized("creationData.outsideInfo")?.is_empty() {
            return Err("creationData.outsideInfo is not empty".into());
        }
        c.done("creationData")?;
    }
    let creation_hash = r.sized("creationHash")?;
    if creation_hash != HashAlg::Sha256.digest(&[creation]) {
        return Err("creationHash is not the digest of the returned creationData".into());
    }
    r.expect_u16("creationTicket.tag", 0x8021)?;
    let hierarchy = r.u32("creationTicket.hierarchy")?;
    if hierarchy != crate::tpm::TPM_RH_OWNER {
        return Err(format!(
            "creationTicket.hierarchy is 0x{hierarchy:08x}, expected the owner hierarchy"
        ));
    }
    let ticket = r.sized("creationTicket.digest")?;
    if ticket.len() != 64 {
        return Err(format!(
            "creationTicket.digest has {} bytes, expected 64 (structure only: the ticket HMAC uses the hierarchy proof and is not verifiable here)",
            ticket.len()
        ));
    }
    if ticket.iter().all(|b| *b == 0) {
        return Err("creationTicket.digest is all zero".into());
    }
    let name = r.sized("name")?;
    let mut n = Reader::new(name);
    n.expect_u16("name.nameAlg", crate::tpm::TPM_ALG_SHA256)?;
    let digest = n.take(HashAlg::Sha256.size(), "name.digest")?;
    n.done("name")?;
    if digest != HashAlg::Sha256.digest(&[public]) {
        return Err("name is not nameAlg || SHA-256(outPublic) of the returned public area".into());
    }
    r.done("CreatePrimary parameters")?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaltedSessionValidation {
    pub hash: HashAlg,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub nonce_caller: Vec<u8>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub salt: Vec<u8>,
    pub key_handle: u32,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub key_name: Vec<u8>,
    pub command_code: u32,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub parameters: Vec<u8>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub expected_parameters: Vec<u8>,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "validation", rename_all = "kebab-case")]
pub enum Validation {
    SaltedSession(SaltedSessionValidation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationStep {
    pub label: String,
    pub command: Vec<u8>,
    pub expect: Expect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    SessionAuthenticated {
        key: Vec<u8>,
        hash: HashAlg,
        nonce_caller: Vec<u8>,
        command_code: u32,
        parameters: Vec<u8>,
    },
}

pub const SESSION_ATTRIBUTES: u8 = 0x01;

pub fn session_key(hash: HashAlg, salt: &[u8], nonce_tpm: &[u8], nonce_caller: &[u8]) -> Vec<u8> {
    crate::oracle::kdf::kdfa(hash, salt, b"ATH", nonce_tpm, nonce_caller, hash.size() * 8)
}

pub fn cp_hash(hash: HashAlg, command_code: u32, names: &[&[u8]], parameters: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    let code = command_code.to_be_bytes();
    parts.push(&code);
    parts.extend_from_slice(names);
    parts.push(parameters);
    hash.digest(&parts)
}

pub fn rp_hash(hash: HashAlg, command_code: u32, parameters: &[u8]) -> Vec<u8> {
    hash.digest(&[&0u32.to_be_bytes(), &command_code.to_be_bytes(), parameters])
}

impl Expect {
    pub fn verify(&self, response: &[u8]) -> Result<(), String> {
        match self {
            Self::SessionAuthenticated {
                key,
                hash,
                nonce_caller,
                command_code,
                parameters,
            } => {
                let code = crate::tpm::response_code(response).map_err(|e| e.to_string())?;
                if code & 0x0000_08bf == 0x0000_08a2 {
                    return Err(format!(
                        "the TPM rejected the command authorization HMAC (TPM_RC_AUTH_FAIL, 0x{code:08x}): it derived a different salt or session key than the independent computation"
                    ));
                }
                if code != 0 {
                    return Err(format!(
                        "authenticated command returned TPM_RC 0x{code:08x}"
                    ));
                }
                let actual = crate::tpm::response_parameters(response, 0)
                    .ok_or("authenticated response has no parameter area")?;
                if actual != parameters.as_slice() {
                    return Err(format!(
                        "authenticated command returned {} where the independent computation gives {}",
                        hex::encode(actual),
                        hex::encode(parameters)
                    ));
                }
                let auth_start = 10 + 4 + actual.len();
                let (nonce_tpm, next) = crate::tpm::read_2b(response, auth_start)
                    .ok_or("malformed response authorization nonce")?;
                let attributes = *response
                    .get(next)
                    .ok_or("malformed response session attributes")?;
                let (mac, end) = crate::tpm::read_2b(response, next + 1)
                    .ok_or("malformed response authorization HMAC")?;
                if end != response.len() {
                    return Err("trailing bytes after the response authorization".into());
                }
                let expected = hash.hmac(
                    key,
                    &[
                        &rp_hash(*hash, *command_code, actual),
                        nonce_tpm,
                        nonce_caller,
                        &[attributes],
                    ],
                );
                if mac != expected.as_slice() {
                    return Err(format!(
                        "response authorization HMAC {} does not match the HMAC {} computed with the independently derived session key: the TPM derived a different salt or session key",
                        hex::encode(mac),
                        hex::encode(expected)
                    ));
                }
                Ok(())
            }
        }
    }
}

impl Validation {
    pub fn steps(&self, measured_response: &[u8]) -> Result<Vec<ValidationStep>, String> {
        match self {
            Self::SaltedSession(v) => {
                if crate::tpm::response_code(measured_response).map_err(|e| e.to_string())? != 0 {
                    return Ok(Vec::new());
                }
                let handle = measured_response
                    .get(10..14)
                    .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
                    .ok_or("salted session response carries no session handle")?;
                let (nonce_tpm, _) = crate::tpm::read_2b(measured_response, 14)
                    .ok_or("salted session response carries no nonceTPM")?;
                let key = session_key(v.hash, &v.salt, nonce_tpm, &v.nonce_caller);
                let cp = cp_hash(v.hash, v.command_code, &[&v.key_name], &v.parameters);
                let mac = v.hash.hmac(
                    &key,
                    &[&cp, &v.nonce_caller, nonce_tpm, &[SESSION_ATTRIBUTES]],
                );
                let mut session = Vec::new();
                crate::tpm::put_u32(&mut session, handle);
                crate::tpm::put_2b(&mut session, &v.nonce_caller);
                session.push(SESSION_ATTRIBUTES);
                crate::tpm::put_2b(&mut session, &mac);
                let mut body = v.key_handle.to_be_bytes().to_vec();
                crate::tpm::put_u32(&mut body, session.len() as u32);
                body.extend(session);
                body.extend_from_slice(&v.parameters);
                Ok(vec![ValidationStep {
                    label: v.label.clone(),
                    command: crate::tpm::command(
                        crate::tpm::TPM_ST_SESSIONS,
                        v.command_code,
                        &body,
                    ),
                    expect: Expect::SessionAuthenticated {
                        key,
                        hash: v.hash,
                        nonce_caller: v.nonce_caller.clone(),
                        command_code: v.command_code,
                        parameters: v.expected_parameters.clone(),
                    },
                }])
            }
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::SaltedSession(v) => format!(
                "derives the salt and session key independently (KDFa(\"ATH\", nonceTPM, nonceCaller)) and uses the session to authorize {} on the salt key, checking the response parameters and the response authorization HMAC",
                v.label
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClassSpec {
    pub setup: Vec<Step>,
    pub measured: Step,
    pub post: Option<Post>,
    pub validation: Option<Validation>,
    pub expected: Vec<u8>,
    pub mask: Vec<u8>,
    pub check: Option<Check>,
    pub public: Option<Point>,
    pub shared: Option<Point>,
}

impl ClassSpec {
    /// Semantic TPM outcome, independently of the padded transport envelope.
    pub fn response_semantics(&self) -> Result<(u32, usize, usize), String> {
        if self.measured.command.starts_with(crate::program::MAGIC) {
            let program = crate::program::Program::decode(&self.measured.command)?;
            let outcome = program.outcome_contract()?;
            Ok((outcome.code, outcome.min as usize, outcome.max as usize))
        } else {
            let code = self
                .expected
                .get(6..10)
                .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
                .unwrap_or(u32::MAX);
            Ok((code, self.expected.len(), self.expected.len()))
        }
    }
    pub fn new(measured: Step, expected: Vec<u8>) -> Self {
        Self {
            setup: Vec::new(),
            measured,
            post: None,
            validation: None,
            expected,
            mask: Vec::new(),
            check: None,
            public: None,
            shared: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairModel {
    pub secret_differs: bool,
    pub public_differences: Vec<String>,
    pub confounders: Vec<String>,
}

impl PairModel {
    pub fn secret(differs: bool) -> Self {
        Self {
            secret_differs: differs,
            public_differences: Vec::new(),
            confounders: Vec::new(),
        }
    }

    pub fn public(mut self, name: &str, differs: bool) -> Self {
        if differs {
            self.public_differences.push(name.to_string());
        }
        self
    }

    pub fn confounder(mut self, applies: bool, text: &str) -> Self {
        if applies {
            self.confounders.push(text.to_string());
        }
        self
    }
}

pub const PER_CLASS_OBJECTS: &str =
    "each class uses its own loaded object, so transient handles differ between classes";
pub const PER_CLASS_KEYS: &str = "the classes load different key objects: public key or unique field, object name and handle differ";

#[derive(Debug, Clone)]
pub struct Built {
    pub shared: Vec<Step>,
    pub classes: [ClassSpec; 2],
    pub model: PairModel,
    pub varying_public_values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioDoc {
    pub harness: String,
    pub entry_point: String,
    pub secret: String,
    pub attacker_inputs: String,
    pub observable_outputs: String,
    pub classes: String,
    pub fixed: String,
    pub timed_region: String,
    pub correctness: String,
    pub interpretation: String,
    pub randomized: bool,
}

pub const COMMAND_LEVEL: &str =
    "command-level: TPMLIB_Process of the public libtpms ABI in a dedicated worker process";

pub fn mask_range(len: usize, from: usize, to: usize) -> Vec<u8> {
    let mut mask = vec![0xffu8; len];
    for byte in mask.iter_mut().take(to).skip(from) {
        *byte = 0;
    }
    mask
}

pub fn scheme_name(scheme: EccScheme) -> String {
    scheme.name().to_string()
}

pub fn keygen_kind_name(kind: KeygenKind) -> String {
    kind.name().to_string()
}

pub fn seed(name: impl Into<String>, a: Vec<u8>, b: Vec<u8>) -> Seed {
    Seed {
        name: name.into(),
        kind: SeedKind::Boundary,
        pair: InputPair::new(a, b),
    }
}

pub fn random_seeds(
    scenario: Scenario,
    campaign_seed: u64,
    count: usize,
    mut generate: impl FnMut(&mut SplitMix) -> Vec<u8>,
) -> Vec<Seed> {
    let mut rng = SplitMix::new(campaign_seed ^ fnv(scenario.name().as_bytes()));
    (0..count)
        .map(|i| Seed {
            name: format!("random-pair-{i}"),
            kind: SeedKind::Random,
            pair: InputPair::new(generate(&mut rng), generate(&mut rng)),
        })
        .collect()
}

pub fn fnv(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ *b as u64).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

pub fn generic_byte_boundary(op: usize, r: u64, current: &[u8], other: &[u8]) -> Vec<u8> {
    let mut out = current.to_vec();
    let n = out.len().max(1);
    match op % 6 {
        0 => {
            out.iter_mut().for_each(|b| *b = 0);
            if let Some(last) = out.last_mut() {
                *last = (r as u8).max(1);
            }
        }
        1 => out.iter_mut().for_each(|b| *b = 0xff),
        2 => {
            let at = (r as usize) % n;
            if let Some(byte) = out.get_mut(at) {
                *byte ^= 1 << ((r >> 32) % 8);
            }
        }
        3 => {
            out.clone_from_slice(other);
            let at = (r as usize) % n;
            if let Some(byte) = out.get_mut(at) {
                *byte ^= 1 << ((r >> 40) % 8);
            }
        }
        4 => {
            let zeros = 1 + (r as usize) % n;
            out.iter_mut().take(zeros).for_each(|b| *b = 0);
        }
        _ => {
            let at = (r as usize) % n;
            out.iter_mut().skip(at).for_each(|b| *b = 0);
        }
    }
    out
}
