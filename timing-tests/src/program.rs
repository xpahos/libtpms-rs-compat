//! Bounded test-worker command programs. Whole programs (including cleanup) are timed.
use crate::oracle::hash::HashAlg;
use serde::{Deserialize, Serialize};

pub const MAGIC: &[u8; 4] = b"\xffTPG";
pub const MAX_BYTES: usize = 4096;
pub const MAX_TRANSCRIPT: usize = 2048;
pub const MAX_STEPS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseArea {
    Raw,
    Parameters,
    ParametersTail,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseRange {
    pub step: u8,
    pub area: ResponseArea,
    pub offset: u16,
    pub len: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Part {
    Literal(Vec<u8>),
    Response(ResponseRange),
}
/// cpHash material for a command with request-parameter protection: both
/// backends authorize sessions before decrypting, so the cpHash in the
/// request HMAC covers the still-encrypted first parameter. The cipher region
/// is computed at run time from the decrypt session's fresh nonceTPM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCpHash {
    pub cc: u32,
    pub name: Vec<u8>,
    pub cfb: bool,
    pub key: CipherKey,
    pub caller: Vec<u8>,
    pub nonce: ResponseRange,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub plain: Vec<u8>,
}

/// Key material for the request-parameter cipher: a fixed byte string, or the
/// run-time session key of a secret-bearing decrypt session, derived with the
/// same single-block KDFa(hash, kdf_key, "ATH", u_parts, v_parts) the
/// authorization HMAC uses, optionally followed by fixed bytes (for example
/// the authValue of an associated entity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherKey {
    Fixed(Vec<u8>),
    Session {
        kdf_key: Vec<u8>,
        u_parts: Vec<Part>,
        v_parts: Vec<Part>,
        extra: Vec<u8>,
    },
}

/// Fixed bound shared with the C interpreter: the resolved mask-key length
/// (session digest plus trailing bytes) fits a 64+1024-byte buffer.
pub const MAX_CIPHER_KEY: usize = 64 + 1024;

/// A wire-oriented encoding tree: variant payloads are built once per
/// scenario, so the size spread is harmless and saves allocation bookkeeping.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Patch {
    Copy {
        at: u16,
        source: ResponseRange,
        xor: Vec<u8>,
    },
    Hmac {
        at: u16,
        hash: HashAlg,
        key: Vec<u8>,
        parts: Vec<Part>,
        xor: Vec<u8>,
    },
    /// Session-key-deriving authorization HMAC: derives the session key with a
    /// single-block KDFa(hash, kdf_key, "ATH", u_parts, v_parts) as the TPM does
    /// in SessionCreate, optionally appends an entity authValue, and computes
    /// HMAC(session_key || extra_key, parts). Reaches bound and salted session
    /// authorization, whose runtime key depends on the fresh session nonce.
    SessionHmac {
        at: u16,
        hash: HashAlg,
        kdf_key: Vec<u8>,
        u_parts: Vec<Part>,
        v_parts: Vec<Part>,
        extra_key: Vec<u8>,
        parts: Vec<Part>,
        xor: Vec<u8>,
        cp_hash: Option<EncryptedCpHash>,
    },
    /// Request-parameter protection: encrypts a literal plaintext with the
    /// request-decryption KDF (XOR mask, or AES-128-CFB with a key/IV block)
    /// derived from a literal nonceCaller and a runtime response nonceTPM,
    /// mirroring CryptParameterDecryption. An empty fixed key matches an
    /// unbound unsalted decrypt session; a session key derives it from fresh
    /// nonces for bound or salted decrypt sessions. The TPM recovers the
    /// plaintext during dispatch.
    Encrypt {
        at: u16,
        hash: HashAlg,
        cfb: bool,
        key: CipherKey,
        caller: Vec<u8>,
        nonce: ResponseRange,
        plain: Vec<u8>,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resource {
    None,
    Handle,
    Counter,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub code: u32,
    pub handles: u8,
    /// Exact number of response authorization records (zero on errors).
    pub auth_count: u8,
    pub min: u16,
    pub max: u16,
    pub expected: Vec<u8>,
    pub mask: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub command: Vec<u8>,
    pub slot: u16,
    pub contract: Contract,
    pub produces: Resource,
    pub consumes: Vec<u8>,
    pub patches: Vec<Patch>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Program {
    /// The semantically measured result; None selects the final step.
    #[serde(default)]
    pub outcome_step: Option<u8>,
    pub steps: Vec<Step>,
}
#[derive(Debug, Clone)]
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub command_offsets: Vec<usize>,
}

impl Contract {
    pub fn exact(expected: Vec<u8>, handles: u8) -> Self {
        Self {
            code: crate::tpm::response_code(&expected).expect("valid expected TPM frame"),
            handles,
            auth_count: frame_auth_count(&expected, handles)
                .expect("valid expected TPM authorization"),
            min: expected.len() as u16,
            max: expected.len() as u16,
            mask: vec![255; expected.len()],
            expected,
        }
    }
    pub fn bounded(handles: u8, min: u16, max: u16) -> Self {
        Self {
            code: 0,
            handles,
            auth_count: 0,
            min,
            max,
            expected: vec![],
            mask: vec![],
        }
    }
}
impl Step {
    pub fn new(command: Vec<u8>, mut contract: Contract) -> Self {
        if contract.expected.is_empty()
            && command.get(..2) == Some(&[0x80, 2])
            && contract.auth_count == 0
        {
            contract.auth_count = 1;
        }
        Self {
            command,
            slot: contract.max,
            contract,
            produces: Resource::None,
            consumes: vec![],
            patches: vec![],
        }
    }
}
impl Program {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            outcome_step: None,
            steps,
        }
    }
    pub fn outcome_contract(&self) -> Result<&Contract, String> {
        let index = self
            .outcome_step
            .map(usize::from)
            .unwrap_or_else(|| self.steps.len().saturating_sub(1));
        self.steps
            .get(index)
            .map(|step| &step.contract)
            .ok_or_else(|| "program outcome step is out of bounds".into())
    }
    pub fn encode(&self) -> Result<Encoded, String> {
        self.validate()?;
        let mut out = vec![255, b'T', b'P', b'G', 1, self.steps.len() as u8, 0, 0];
        out.push(self.outcome_step.unwrap_or(255));
        let mut offsets = vec![];
        for step in &self.steps {
            put16(&mut out, step.command.len());
            put16(&mut out, step.slot as usize);
            out.extend_from_slice(&[
                step.contract.handles,
                step.contract.auth_count,
                match step.produces {
                    Resource::None => 0,
                    Resource::Handle => 1,
                    Resource::Counter => 2,
                },
                step.consumes.iter().fold(0, |a, i| a | (1 << i)),
                step.patches.len() as u8,
            ]);
            out.extend_from_slice(&step.contract.code.to_be_bytes());
            put16(&mut out, step.contract.min as usize);
            put16(&mut out, step.contract.max as usize);
            put16(&mut out, step.contract.expected.len());
            offsets.push(out.len());
            out.extend_from_slice(&step.command);
            out.extend_from_slice(&step.contract.expected);
            out.resize(
                out.len() + step.slot as usize - step.contract.expected.len(),
                0,
            );
            out.extend_from_slice(&step.contract.mask);
            out.resize(out.len() + step.slot as usize - step.contract.mask.len(), 0);
            for patch in &step.patches {
                match patch {
                    Patch::Copy { at, source, xor } => {
                        out.push(0);
                        put16(&mut out, *at as usize);
                        source.write(&mut out);
                        out.extend_from_slice(xor);
                    }
                    Patch::Hmac {
                        at,
                        hash,
                        key,
                        parts,
                        xor,
                    } => {
                        out.push(1);
                        put16(&mut out, *at as usize);
                        put16(&mut out, hash.alg_id() as usize);
                        put16(&mut out, key.len());
                        out.push(parts.len() as u8);
                        out.extend_from_slice(key);
                        for part in parts {
                            write_part(&mut out, part);
                        }
                        out.extend_from_slice(xor);
                    }
                    Patch::SessionHmac {
                        at,
                        hash,
                        kdf_key,
                        u_parts,
                        v_parts,
                        extra_key,
                        parts,
                        xor,
                        cp_hash,
                    } => {
                        out.push(2);
                        put16(&mut out, *at as usize);
                        put16(&mut out, hash.alg_id() as usize);
                        put16(&mut out, kdf_key.len());
                        out.push(u_parts.len() as u8);
                        out.push(v_parts.len() as u8);
                        put16(&mut out, extra_key.len());
                        out.push(parts.len() as u8);
                        out.extend_from_slice(kdf_key);
                        for part in u_parts.iter().chain(v_parts.iter()) {
                            write_part(&mut out, part);
                        }
                        out.extend_from_slice(extra_key);
                        for part in parts {
                            write_part(&mut out, part);
                        }
                        out.extend_from_slice(xor);
                        match cp_hash {
                            None => out.push(0),
                            Some(cp) => {
                                out.push(1);
                                out.extend_from_slice(&cp.cc.to_be_bytes());
                                put16(&mut out, cp.name.len());
                                put16(&mut out, cp.caller.len());
                                put16(&mut out, cp.prefix.len());
                                put16(&mut out, cp.suffix.len());
                                put16(&mut out, cp.plain.len());
                                out.push(u8::from(cp.cfb));
                                out.extend_from_slice(&cp.name);
                                write_cipher_key(&mut out, &cp.key);
                                out.extend_from_slice(&cp.caller);
                                cp.nonce.write(&mut out);
                                out.extend_from_slice(&cp.prefix);
                                out.extend_from_slice(&cp.suffix);
                                out.extend_from_slice(&cp.plain);
                            }
                        }
                    }
                    Patch::Encrypt {
                        at,
                        hash,
                        cfb,
                        key,
                        caller,
                        nonce,
                        plain,
                    } => {
                        out.push(3);
                        put16(&mut out, *at as usize);
                        put16(&mut out, hash.alg_id() as usize);
                        out.push(u8::from(*cfb));
                        put16(&mut out, caller.len());
                        put16(&mut out, plain.len());
                        out.extend_from_slice(caller);
                        write_cipher_key(&mut out, key);
                        nonce.write(&mut out);
                        out.extend_from_slice(plain);
                    }
                }
            }
        }
        if out.len() > MAX_BYTES {
            return Err("program exceeds 4096 bytes".into());
        }
        let len = out.len() as u16;
        out[6..8].copy_from_slice(&len.to_be_bytes());
        Ok(Encoded {
            bytes: out,
            command_offsets: offsets,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_BYTES {
            return Err("program oversized".into());
        }
        let mut r = Reader { bytes, at: 0 };
        if r.take(4)? != MAGIC || r.byte()? != 1 {
            return Err("program magic/version".into());
        }
        let count = r.byte()? as usize;
        if count == 0 || count > MAX_STEPS || r.u16()? as usize != bytes.len() {
            return Err("program length/count".into());
        }
        let outcome_step = match r.byte()? {
            255 => None,
            index => Some(index),
        };
        let mut steps = vec![];
        for _ in 0..count {
            let command_len = r.u16()? as usize;
            let slot = r.u16()?;
            let handles = r.byte()?;
            let auth_count = r.byte()?;
            let produces = match r.byte()? {
                0 => Resource::None,
                1 => Resource::Handle,
                2 => Resource::Counter,
                _ => return Err("resource kind".into()),
            };
            let bitmap = r.byte()?;
            let patches_len = r.byte()? as usize;
            let code = r.u32()?;
            let min = r.u16()?;
            let max = r.u16()?;
            let expected_len = r.u16()? as usize;
            let command = r.take(command_len)?.to_vec();
            if expected_len > slot as usize {
                return Err("contract exceeds slot".into());
            }
            let padded_expected = r.take(slot as usize)?;
            let padded_mask = r.take(slot as usize)?;
            if padded_expected[expected_len..]
                .iter()
                .chain(&padded_mask[expected_len..])
                .any(|b| *b != 0)
            {
                return Err("nonzero contract padding".into());
            }
            let expected = padded_expected[..expected_len].to_vec();
            let mask = padded_mask[..expected_len].to_vec();
            if patches_len > 16 {
                return Err("too many patches".into());
            }
            let mut patches = vec![];
            for _ in 0..patches_len {
                let kind = r.byte()?;
                let at = r.u16()?;
                patches.push(match kind {
                    0 => {
                        let source = r.range()?;
                        let xor = r.take(source.len as usize)?.to_vec();
                        Patch::Copy { at, source, xor }
                    }
                    1 => {
                        let alg = r.u16()?;
                        let hash = HashAlg::ALL
                            .into_iter()
                            .find(|h| h.alg_id() == alg)
                            .ok_or("unsupported HMAC hash")?;
                        let key_len = r.u16()? as usize;
                        let part_count = r.byte()? as usize;
                        if part_count > 16 {
                            return Err("too many HMAC parts".into());
                        }
                        let key = r.take(key_len)?.to_vec();
                        let mut parts = vec![];
                        for _ in 0..part_count {
                            parts.push(match r.byte()? {
                                0 => {
                                    let n = r.u16()? as usize;
                                    Part::Literal(r.take(n)?.to_vec())
                                }
                                1 => Part::Response(r.range()?),
                                _ => return Err("HMAC part kind".into()),
                            });
                        }
                        let xor = r.take(hash.size())?.to_vec();
                        Patch::Hmac {
                            at,
                            hash,
                            key,
                            parts,
                            xor,
                        }
                    }
                    2 => {
                        let alg = r.u16()?;
                        let hash = HashAlg::ALL
                            .into_iter()
                            .find(|h| h.alg_id() == alg)
                            .ok_or("unsupported session HMAC hash")?;
                        let kdf_key_len = r.u16()? as usize;
                        let u_count = r.byte()? as usize;
                        let v_count = r.byte()? as usize;
                        let extra_len = r.u16()? as usize;
                        let part_count = r.byte()? as usize;
                        if kdf_key_len > 1024
                            || extra_len > 1024
                            || u_count > 16
                            || v_count > 16
                            || part_count > 16
                            || u_count + v_count == 0
                        {
                            return Err("session HMAC bounds".into());
                        }
                        let kdf_key = r.take(kdf_key_len)?.to_vec();
                        let read_parts = |r: &mut Reader| -> Result<Vec<Part>, String> {
                            let mut parts = vec![];
                            for _ in 0..(u_count + v_count) {
                                parts.push(match r.byte()? {
                                    0 => {
                                        let n = r.u16()? as usize;
                                        Part::Literal(r.take(n)?.to_vec())
                                    }
                                    1 => Part::Response(r.range()?),
                                    _ => return Err("HMAC part kind".into()),
                                });
                            }
                            Ok(parts)
                        };
                        let derivation = read_parts(&mut r)?;
                        let extra_key = r.take(extra_len)?.to_vec();
                        let mut parts = vec![];
                        for _ in 0..part_count {
                            parts.push(match r.byte()? {
                                0 => {
                                    let n = r.u16()? as usize;
                                    Part::Literal(r.take(n)?.to_vec())
                                }
                                1 => Part::Response(r.range()?),
                                _ => return Err("HMAC part kind".into()),
                            });
                        }
                        let xor = r.take(hash.size())?.to_vec();
                        let cp_hash = match r.byte()? {
                            0 => None,
                            1 => {
                                let cc = r.u32()?;
                                let name_len = r.u16()? as usize;
                                let caller_len = r.u16()? as usize;
                                let prefix_len = r.u16()? as usize;
                                let suffix_len = r.u16()? as usize;
                                let plain_len = r.u16()? as usize;
                                let cfb = match r.byte()? {
                                    0 => false,
                                    1 => true,
                                    _ => return Err("cpHash mode".into()),
                                };
                                if name_len > 128
                                    || caller_len == 0
                                    || caller_len > 64
                                    || prefix_len > 512
                                    || suffix_len > 512
                                    || plain_len == 0
                                    || plain_len > 512
                                    || (cfb && hash.size() < 32)
                                {
                                    return Err("cpHash bounds".into());
                                }
                                let name = r.take(name_len)?.to_vec();
                                let key = r.cipher_key(hash)?;
                                let caller = r.take(caller_len)?.to_vec();
                                let nonce = r.range()?;
                                if nonce.len == 0 || nonce.len > 64 {
                                    return Err("cpHash nonce bounds".into());
                                }
                                let prefix = r.take(prefix_len)?.to_vec();
                                let suffix = r.take(suffix_len)?.to_vec();
                                let plain = r.take(plain_len)?.to_vec();
                                Some(EncryptedCpHash {
                                    cc,
                                    name,
                                    cfb,
                                    key,
                                    caller,
                                    nonce,
                                    prefix,
                                    suffix,
                                    plain,
                                })
                            }
                            _ => return Err("cpHash presence".into()),
                        };
                        Patch::SessionHmac {
                            at,
                            hash,
                            kdf_key,
                            u_parts: derivation[..u_count].to_vec(),
                            v_parts: derivation[u_count..].to_vec(),
                            extra_key,
                            parts,
                            xor,
                            cp_hash,
                        }
                    }
                    3 => {
                        let id = r.u16()?;
                        let hash = HashAlg::ALL
                            .into_iter()
                            .find(|h| h.alg_id() == id)
                            .ok_or("encrypt hash")?;
                        let cfb = match r.byte()? {
                            0 => false,
                            1 => true,
                            _ => return Err("encrypt mode".into()),
                        };
                        let caller_len = r.u16()? as usize;
                        let plain_len = r.u16()? as usize;
                        if caller_len == 0 || caller_len > 64 {
                            return Err("encrypt caller bounds".into());
                        }
                        if plain_len == 0 || plain_len > MAX_BYTES {
                            return Err("encrypt plaintext bounds".into());
                        }
                        let caller = r.take(caller_len)?.to_vec();
                        let key = r.cipher_key(hash)?;
                        let nonce = r.range()?;
                        if nonce.len == 0 || nonce.len > 64 {
                            return Err("encrypt nonce bounds".into());
                        }
                        let plain = r.take(plain_len)?.to_vec();
                        Patch::Encrypt {
                            at,
                            hash,
                            cfb,
                            key,
                            caller,
                            nonce,
                            plain,
                        }
                    }
                    _ => return Err("patch kind".into()),
                });
            }
            steps.push(Step {
                command,
                slot,
                contract: Contract {
                    code,
                    handles,
                    auth_count,
                    min,
                    max,
                    expected,
                    mask,
                },
                produces,
                consumes: (0..8).filter(|i| bitmap & (1 << i) != 0).collect(),
                patches,
            });
        }
        if r.at != bytes.len() {
            return Err("trailing program bytes".into());
        }
        let program = Self {
            outcome_step,
            steps,
        };
        program.validate()?;
        Ok(program)
    }
    /// Validates a request-cipher key: fixed bytes stay within one kilobyte, and a
    /// session derivation keeps the KDF input (counter, label, U, V, bit length)
    /// within the interpreter message buffer and the resolved within-session
    /// digest-plus-trailer length within the shared key buffer bound.
    fn validate_cipher_key(
        hash: HashAlg,
        key: &CipherKey,
        index: usize,
        program: &Program,
    ) -> Result<(), String> {
        match key {
            CipherKey::Fixed(bytes) => {
                if bytes.len() > 1024 {
                    return Err("cipher key bounds".into());
                }
            }
            CipherKey::Session {
                kdf_key,
                u_parts,
                v_parts,
                extra,
            } => {
                if kdf_key.len() > 1024
                    || extra.len() > 1024
                    || u_parts.is_empty()
                    || v_parts.is_empty()
                    || u_parts.len() > 16
                    || v_parts.len() > 16
                {
                    return Err("cipher session-key bounds".into());
                }
                let mut size = 4 + 4 + 4;
                for part in u_parts.iter().chain(v_parts.iter()) {
                    size += match part {
                        Part::Literal(v) => v.len(),
                        Part::Response(r) => {
                            r.validate(index, program)?;
                            r.len as usize
                        }
                    };
                }
                if size > MAX_BYTES {
                    return Err("cipher session-key derivation oversized".into());
                }
                if hash.size() + extra.len() > MAX_CIPHER_KEY {
                    return Err("cipher session key oversized".into());
                }
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        self.outcome_contract()?;
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err("program count".into());
        }
        let mut transcript_len = 16usize;
        let mut consumed = vec![false; self.steps.len()];
        for (index, step) in self.steps.iter().enumerate() {
            let c = &step.contract;
            transcript_len += 4 + step.slot as usize;
            if step.command.len() < 10
                || step.command.len() > MAX_BYTES
                || c.handles > 1
                || c.auth_count > 3
                || c.min < 10
                || c.min > c.max
                || c.max > step.slot
                || c.expected.len() > MAX_TRANSCRIPT
                || c.expected.len() != c.mask.len()
                || step.patches.len() > 16
                || (!c.expected.is_empty()
                    && (c.expected.len() != c.min as usize || c.min != c.max))
            {
                return Err(format!("step {index}: bounds"));
            }
            if crate::tpm::response_code(&step.command).is_err()
                || !matches!(&step.command[..2], [0x80, 1 | 2])
            {
                return Err("nested command frame".into());
            }
            if (c.code == 0 && ((step.command[1] == 2) != (c.auth_count > 0)))
                || (c.code != 0 && c.auth_count != 0)
            {
                return Err("response authorization contract does not match command tag".into());
            }
            let cc = u32::from_be_bytes(step.command[6..10].try_into().unwrap());
            let resource = match cc {
                0x18b | 0x18e => Resource::Counter,
                0x131 | 0x157 | 0x161 | 0x167 | 0x176 | 0x15b | 0x186 | 0x191 => Resource::Handle,
                _ => Resource::None,
            };
            if resource != step.produces || (resource == Resource::Handle && c.handles != 1) {
                return Err("producer declaration does not match command".into());
            }
            if c.code != 0 && index + 1 != self.steps.len() {
                return Err("only final step may expect an error".into());
            }
            for &prior in &step.consumes {
                let prior = prior as usize;
                if prior >= index
                    || consumed[prior]
                    || self.steps[prior].produces == Resource::None
                    || c.code != 0
                {
                    return Err("invalid consumption".into());
                }
                let valid = match self.steps[prior].produces {
                    Resource::Handle => matches!(cc, 0x13e | 0x185 | 0x165),
                    Resource::Counter => matches!(cc, 0x15d | 0x18d),
                    Resource::None => false,
                };
                if !valid {
                    return Err("invalid consuming command".into());
                }
                consumed[prior] = true;
            }
            for patch in &step.patches {
                let (at, len) = match patch {
                    Patch::Copy { at, source, xor } => {
                        source.validate(index, self)?;
                        if xor.len() != source.len as usize {
                            return Err("copy xor size".into());
                        }
                        (*at, xor.len())
                    }
                    Patch::Hmac {
                        at,
                        hash,
                        key,
                        parts,
                        xor,
                    } => {
                        if key.len() > 1024
                            || parts.is_empty()
                            || parts.len() > 16
                            || xor.len() != hash.size()
                        {
                            return Err("HMAC bounds".into());
                        }
                        let mut size = 0;
                        for part in parts {
                            size += match part {
                                Part::Literal(v) => v.len(),
                                Part::Response(r) => {
                                    r.validate(index, self)?;
                                    r.len as usize
                                }
                            };
                        }
                        if size > MAX_BYTES {
                            return Err("HMAC message oversized".into());
                        }
                        (*at, hash.size())
                    }
                    Patch::SessionHmac {
                        at,
                        hash,
                        kdf_key,
                        u_parts,
                        v_parts,
                        extra_key,
                        parts,
                        xor,
                        cp_hash,
                    } => {
                        let message_len = |list: &[Part]| -> Result<usize, String> {
                            let mut size = 0;
                            for part in list {
                                size += match part {
                                    Part::Literal(v) => v.len(),
                                    Part::Response(r) => {
                                        r.validate(index, self)?;
                                        r.len as usize
                                    }
                                };
                            }
                            if size > MAX_BYTES {
                                return Err("session HMAC message oversized".into());
                            }
                            Ok(size)
                        };
                        if kdf_key.len() > 1024
                            || extra_key.len() > 1024
                            || u_parts.len() > 16
                            || v_parts.len() > 16
                            || parts.len() > 16
                            || parts.is_empty()
                            || u_parts.is_empty()
                            || v_parts.is_empty()
                            || xor.len() != hash.size()
                        {
                            return Err("session HMAC bounds".into());
                        }
                        message_len(u_parts)?;
                        // KDF input = counter || "ATH" || U || V || bit length.
                        let derivation = message_len(v_parts)? + message_len(u_parts)? + 4 + 4 + 4;
                        if derivation > MAX_BYTES {
                            return Err("session HMAC derivation oversized".into());
                        }
                        let mut message = message_len(parts)?;
                        if let Some(cp) = cp_hash {
                            if cp.name.len() > 128
                                || cp.caller.is_empty()
                                || cp.caller.len() > 64
                                || cp.prefix.len() > 512
                                || cp.suffix.len() > 512
                                || cp.plain.is_empty()
                                || cp.plain.len() > 512
                                || (cp.cfb && hash.size() < 32)
                                || cp.prefix.len() + cp.plain.len() + cp.suffix.len() > MAX_BYTES
                            {
                                return Err("cpHash bounds".into());
                            }
                            Self::validate_cipher_key(*hash, &cp.key, index, self)?;
                            cp.nonce.validate(index, self)?;
                            if cp.nonce.len == 0 || cp.nonce.len > 64 {
                                return Err("cpHash nonce bounds".into());
                            }
                            message += hash.size();
                        }
                        if message > MAX_BYTES {
                            return Err("session HMAC message oversized".into());
                        }
                        (*at, hash.size())
                    }
                    Patch::Encrypt {
                        at,
                        hash,
                        cfb,
                        key,
                        caller,
                        nonce,
                        plain,
                    } => {
                        if plain.is_empty()
                            || plain.len() > MAX_BYTES
                            || caller.len() > 64
                            || caller.is_empty()
                            || (*cfb && hash.size() < 32)
                        {
                            return Err("encrypt bounds".into());
                        }
                        Self::validate_cipher_key(*hash, key, index, self)?;
                        nonce.validate(index, self)?;
                        if nonce.len == 0 || nonce.len > 64 {
                            return Err("encrypt nonce bounds".into());
                        }
                        (*at, plain.len())
                    }
                };
                if at < 10 || at as usize + len > step.command.len() {
                    return Err("patch destination bounds".into());
                }
            }
            if !c.expected.is_empty() {
                c.check(&c.expected)?;
            }
        }
        if transcript_len > MAX_TRANSCRIPT {
            return Err("transcript oversized".into());
        }
        if self
            .steps
            .iter()
            .enumerate()
            .any(|(i, s)| s.produces == Resource::Counter && !consumed[i])
        {
            return Err("unconsumed counter".into());
        }
        Ok(())
    }
    /// Decode raw response slots, checking outer and nested frames, contracts and zero padding.
    pub fn transcript<'a>(&self, bytes: &'a [u8]) -> Result<Vec<&'a [u8]>, String> {
        let params = frame_parameters(bytes, 0)?;
        if bytes[..2] != [0x80, 1]
            || crate::tpm::response_code(bytes).map_err(|e| e.to_string())? != 0
        {
            return Err("outer transcript frame".into());
        }
        let mut r = Reader {
            bytes: params,
            at: 0,
        };
        if r.take(4)? != b"TPTR" || r.byte()? != 1 || r.byte()? as usize != self.steps.len() {
            return Err("transcript version/count".into());
        }
        let mut out = vec![];
        for (i, step) in self.steps.iter().enumerate() {
            let len = r.u16()? as usize;
            let slot = r.u16()?;
            if slot != step.slot || len > slot as usize {
                return Err("transcript slot bounds".into());
            }
            let data = r.take(slot as usize)?;
            if data[len..].iter().any(|b| *b != 0) {
                return Err("nonzero transcript padding".into());
            }
            step.contract
                .check(&data[..len])
                .map_err(|e| format!("step {i}: {e}"))?;
            out.push(&data[..len]);
        }
        if r.at != params.len() {
            return Err("trailing transcript bytes".into());
        }
        Ok(out)
    }
    /// Outer timing matcher: slots are masked, and Check::Program provides structural validation.
    /// The C interpreter validates each nested contract on every timed execution.
    pub fn expectation(&self) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.validate()?;
        let mut params = b"TPTR\x01".to_vec();
        params.push(self.steps.len() as u8);
        let mut mask = vec![255; 6];
        for step in &self.steps {
            put16(&mut params, 0);
            put16(&mut params, step.slot as usize);
            params.resize(params.len() + step.slot as usize, 0);
            mask.extend_from_slice(&[0, 0, 255, 255]);
            mask.resize(mask.len() + step.slot as usize, 0);
        }
        let response = crate::tpm::success_response(&[], &params, 0);
        let mut response_mask = vec![255; 10];
        response_mask.extend_from_slice(&mask);
        Ok((response, response_mask))
    }
}
impl Contract {
    pub fn check(&self, bytes: &[u8]) -> Result<(), String> {
        frame_parameters(bytes, self.handles)?;
        if frame_auth_count(bytes, self.handles)? != self.auth_count {
            return Err("response authorization count differs from contract".into());
        }
        if bytes.len() < self.min as usize
            || bytes.len() > self.max as usize
            || crate::tpm::response_code(bytes).map_err(|e| e.to_string())? != self.code
        {
            return Err("response bounds/code".into());
        }
        if !self.expected.is_empty()
            && !crate::scenario::layout::masked_equal(bytes, &self.expected, &self.mask)
        {
            return Err("response contract mismatch".into());
        }
        Ok(())
    }
}
/// Strict TPM framing, including every authorization trailer. Error responses have no parameters.
pub fn frame_parameters(bytes: &[u8], handles: u8) -> Result<&[u8], String> {
    let code = crate::tpm::response_code(bytes).map_err(|e| e.to_string())?;
    if handles > 1 {
        return Err("response handle count".into());
    }
    let tag = u16::from_be_bytes(bytes[..2].try_into().unwrap());
    if code != 0 {
        return if tag == 0x8001 && bytes.len() == 10 {
            Ok(&bytes[10..])
        } else {
            Err("error response frame".into())
        };
    }
    let start = 10 + handles as usize * 4;
    let mut r = Reader { bytes, at: start };
    match tag {
        0x8001 => r.take(
            bytes
                .len()
                .checked_sub(start)
                .ok_or("missing response handle")?,
        ),
        0x8002 => {
            let len = r.u32()? as usize;
            let params = r.take(len)?;
            let mut count = 0;
            while r.at < bytes.len() {
                let n = r.u16()? as usize;
                r.take(n)?;
                r.byte()?;
                let n = r.u16()? as usize;
                r.take(n)?;
                count += 1;
            }
            if !(1..=3).contains(&count) {
                return Err("response authorization count".into());
            }
            Ok(params)
        }
        _ => Err("response tag".into()),
    }
}
fn frame_auth_count(bytes: &[u8], handles: u8) -> Result<u8, String> {
    let parameters = frame_parameters(bytes, handles)?;
    if bytes[1] != 2 {
        return Ok(0);
    }
    let mut r = Reader {
        bytes,
        at: 14 + 4 * handles as usize + parameters.len(),
    };
    let mut count = 0;
    while r.at < bytes.len() {
        let n = r.u16()? as usize;
        r.take(n)?;
        r.byte()?;
        let n = r.u16()? as usize;
        r.take(n)?;
        count += 1;
    }
    Ok(count)
}
impl ResponseRange {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[
            self.step,
            match self.area {
                ResponseArea::Raw => 0,
                ResponseArea::Parameters => 1,
                ResponseArea::ParametersTail => 2,
            },
        ]);
        put16(out, self.offset as usize);
        put16(out, self.len as usize);
    }
    fn validate(&self, current: usize, program: &Program) -> Result<(), String> {
        if self.step as usize >= current
            || self.len == 0
            || self.offset as usize + self.len as usize
                > program.steps[self.step as usize].slot as usize
        {
            return Err("response range bounds/forward reference".into());
        }
        Ok(())
    }
}
fn put16(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&(value as u16).to_be_bytes());
}
fn write_part(out: &mut Vec<u8>, part: &Part) {
    match part {
        Part::Literal(bytes) => {
            out.push(0);
            put16(out, bytes.len());
            out.extend_from_slice(bytes);
        }
        Part::Response(source) => {
            out.push(1);
            source.write(out);
        }
    }
}
fn write_cipher_key(out: &mut Vec<u8>, key: &CipherKey) {
    match key {
        CipherKey::Fixed(bytes) => {
            out.push(0);
            put16(out, bytes.len());
            out.extend_from_slice(bytes);
        }
        CipherKey::Session {
            kdf_key,
            u_parts,
            v_parts,
            extra,
        } => {
            out.push(1);
            put16(out, kdf_key.len());
            out.push(u_parts.len() as u8);
            out.push(v_parts.len() as u8);
            put16(out, extra.len());
            out.extend_from_slice(kdf_key);
            for part in u_parts.iter().chain(v_parts.iter()) {
                write_part(out, part);
            }
            out.extend_from_slice(extra);
        }
    }
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).ok_or("length overflow")?;
        let v = self.bytes.get(self.at..end).ok_or("truncated frame")?;
        self.at = end;
        Ok(v)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn range(&mut self) -> Result<ResponseRange, String> {
        Ok(ResponseRange {
            step: self.byte()?,
            area: match self.byte()? {
                0 => ResponseArea::Raw,
                1 => ResponseArea::Parameters,
                2 => ResponseArea::ParametersTail,
                _ => return Err("response area".into()),
            },
            offset: self.u16()?,
            len: self.u16()?,
        })
    }
    fn part(&mut self) -> Result<Part, String> {
        match self.byte()? {
            0 => {
                let n = self.u16()? as usize;
                Ok(Part::Literal(self.take(n)?.to_vec()))
            }
            1 => Ok(Part::Response(self.range()?)),
            _ => Err("HMAC part kind".into()),
        }
    }
    fn cipher_key(&mut self, hash: HashAlg) -> Result<CipherKey, String> {
        match self.byte()? {
            0 => {
                let len = self.u16()? as usize;
                if len > 1024 {
                    return Err("cipher key bounds".into());
                }
                Ok(CipherKey::Fixed(self.take(len)?.to_vec()))
            }
            1 => {
                let kdf_key_len = self.u16()? as usize;
                let u_count = self.byte()? as usize;
                let v_count = self.byte()? as usize;
                let extra_len = self.u16()? as usize;
                if kdf_key_len > 1024
                    || extra_len > 1024
                    || hash.size() + extra_len > MAX_CIPHER_KEY
                    || u_count == 0
                    || v_count == 0
                    || u_count > 16
                    || v_count > 16
                {
                    return Err("cipher session key bounds".into());
                }
                let kdf_key = self.take(kdf_key_len)?.to_vec();
                let mut derivation = vec![];
                for _ in 0..u_count + v_count {
                    derivation.push(self.part()?);
                }
                let extra = self.take(extra_len)?.to_vec();
                Ok(CipherKey::Session {
                    kdf_key,
                    u_parts: derivation[..u_count].to_vec(),
                    v_parts: derivation[u_count..].to_vec(),
                    extra,
                })
            }
            _ => Err("cipher key kind".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Program {
        let response = crate::tpm::success_response(&[], &[], 0);
        Program {
            outcome_step: None,
            steps: vec![Step::new(
                crate::tpm::startup_clear(),
                Contract::exact(response, 0),
            )],
        }
    }
    #[test]
    fn encoding_roundtrip_and_every_truncation() {
        let p = fixture();
        let encoded = p.encode().unwrap();
        assert_eq!(Program::decode(&encoded.bytes).unwrap(), p);
        for n in 0..encoded.bytes.len() {
            assert!(Program::decode(&encoded.bytes[..n]).is_err(), "{n}");
        }
        let mut extra = encoded.bytes;
        extra.push(0);
        assert!(Program::decode(&extra).is_err());
    }
    #[test]
    fn forward_patches_oversized_slots_and_unconsumed_counters_rejected() {
        let mut p = fixture();
        p.steps[0].patches.push(Patch::Copy {
            at: 10,
            source: ResponseRange {
                step: 0,
                area: ResponseArea::Raw,
                offset: 0,
                len: 1,
            },
            xor: vec![0],
        });
        assert!(p.encode().is_err());
        let mut p = fixture();
        p.steps[0].slot = 2048;
        assert!(p.encode().is_err());
        let mut producer = Step::new(
            crate::tpm::build_command(0x18e, &[], &[], &[0, 3]).bytes,
            Contract::bounded(0, 12, 82),
        );
        producer.produces = Resource::Counter;
        let p = Program {
            outcome_step: None,
            steps: vec![producer],
        };
        assert_eq!(p.encode().unwrap_err(), "unconsumed counter");
    }
    #[test]
    fn copy_hmac_roundtrip_and_patch_bounds() {
        let mut p = fixture();
        let mut command = crate::tpm::startup_clear();
        command.resize(80, 0);
        command[2..6].copy_from_slice(&80u32.to_be_bytes());
        let response = crate::tpm::success_response(&[], &[], 0);
        let mut step = Step::new(command, Contract::exact(response, 0));
        step.patches.push(Patch::Copy {
            at: 10,
            source: ResponseRange {
                step: 0,
                area: ResponseArea::ParametersTail,
                offset: 0,
                len: 2,
            },
            xor: vec![0; 2],
        });
        step.patches.push(Patch::Hmac {
            at: 20,
            hash: HashAlg::Sha256,
            key: vec![5; 32],
            parts: vec![
                Part::Literal(vec![3; 32]),
                Part::Response(ResponseRange {
                    step: 0,
                    area: ResponseArea::Raw,
                    offset: 0,
                    len: 4,
                }),
            ],
            xor: vec![0; 32],
        });
        p.steps.push(step);
        let encoded = p.encode().unwrap();
        assert_eq!(Program::decode(&encoded.bytes).unwrap(), p);
        for n in 0..encoded.bytes.len() {
            assert!(Program::decode(&encoded.bytes[..n]).is_err(), "{n}");
        }
        let mut bad = p.clone();
        if let Patch::Hmac { at, .. } = &mut bad.steps[1].patches[1] {
            *at = 60;
        }
        assert!(bad.encode().is_err());
        let mut bad = p.clone();
        if let Patch::Hmac { parts, .. } = &mut bad.steps[1].patches[1] {
            parts.push(Part::Literal(vec![0; MAX_BYTES]));
        }
        assert!(bad.encode().is_err());
        let mut bad = p.clone();
        if let Patch::Copy { xor, .. } = &mut bad.steps[1].patches[0] {
            xor.pop();
        }
        assert!(bad.encode().is_err());
    }
    #[test]
    fn response_sessions_require_exact_complete_authorization_frames() {
        let good = crate::tpm::success_response(&[], &[1, 2], 1);
        assert_eq!(frame_parameters(&good, 0).unwrap(), &[1, 2]);
        let mut extra = good.clone();
        extra.push(0);
        let len = extra.len() as u32;
        extra[2..6].copy_from_slice(&len.to_be_bytes());
        assert!(frame_parameters(&extra, 0).is_err());
        let mut missing = good.clone();
        missing.truncate(16);
        missing[2..6].copy_from_slice(&16u32.to_be_bytes());
        assert!(frame_parameters(&missing, 0).is_err());
        let mut error = good;
        error[9] = 1;
        assert!(frame_parameters(&error, 0).is_err());
    }
    #[test]
    fn transcript_rejects_corrupt_nested_frame_and_nonzero_padding() {
        let mut p = fixture();
        p.steps[0].slot = 16;
        let mut transcript = crate::tpm::success_response(&[], &[0; 28], 0);
        transcript[10..14].copy_from_slice(b"TPTR");
        transcript[14] = 1;
        transcript[15] = 1;
        transcript[16..18].copy_from_slice(&10u16.to_be_bytes());
        transcript[18..20].copy_from_slice(&16u16.to_be_bytes());
        transcript[20..30].copy_from_slice(&p.steps[0].contract.expected);
        transcript.truncate(36);
        transcript[2..6].copy_from_slice(&36u32.to_be_bytes());
        assert!(p.transcript(&transcript).is_ok());
        transcript[35] = 1;
        assert!(p.transcript(&transcript).is_err());
        transcript[35] = 0;
        transcript[25] ^= 1;
        assert!(p.transcript(&transcript).is_err());
    }
}

#[test]
fn session_hmac_roundtrip_bounds_and_out_of_range_nonce_reference() {
    // A realistic StartAuthSession producer: the response carries a fresh session
    // handle plus a nonce, so response references stay inside the declared slot.
    let caller = vec![0x56; 32];
    let mut params = crate::tpm::sized(&caller);
    crate::tpm::put_2b(&mut params, &[]);
    params.extend_from_slice(&[0, 0, 0x10, 0, 11]);
    let nonce = crate::tpm::sized(&[0x92; 32]);
    let mut contract = Contract::exact(crate::tpm::success_response(&[0], &nonce, 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    let mut start = Step::new(
        crate::tpm::build_command(
            0x176,
            &[crate::tpm::TPM_RH_NULL, crate::tpm::TPM_RH_NULL],
            &[],
            &params,
        )
        .bytes,
        contract,
    );
    start.produces = Resource::Handle;
    let mut command =
        crate::tpm::build_command(crate::tpm::TPM_CC_MAC, &[crate::tpm::TPM_RH_NULL], &[], &[])
            .bytes;
    command.resize(96, 0);
    command[2..6].copy_from_slice(&96u32.to_be_bytes());
    let mut mac = Step::new(
        command,
        Contract::exact(crate::tpm::success_response(&[], &[], 0), 0),
    );
    mac.patches.push(Patch::SessionHmac {
        at: 30,
        hash: HashAlg::Sha256,
        kdf_key: vec![7; 32],
        u_parts: vec![Part::Response(ResponseRange {
            step: 0,
            area: ResponseArea::Parameters,
            offset: 2,
            len: 32,
        })],
        v_parts: vec![Part::Literal(caller)],
        extra_key: vec![0x61; 32],
        parts: vec![
            Part::Literal(vec![0x44; 32]),
            Part::Response(ResponseRange {
                step: 0,
                area: ResponseArea::Parameters,
                offset: 2,
                len: 32,
            }),
            Part::Literal(vec![1]),
        ],
        xor: vec![0; 32],
        cp_hash: None,
    });
    let p = Program {
        outcome_step: None,
        steps: vec![start, mac],
    };
    let encoded = p.encode().unwrap();
    assert_eq!(Program::decode(&encoded.bytes).unwrap(), p);
    for n in 0..encoded.bytes.len() {
        assert!(Program::decode(&encoded.bytes[..n]).is_err(), "{n}");
    }
    let mut bad = p.clone();
    if let Patch::SessionHmac { u_parts, .. } = &mut bad.steps[1].patches[0] {
        u_parts.clear();
    }
    assert_eq!(bad.encode().unwrap_err(), "session HMAC bounds");
    let mut bad = p.clone();
    if let Patch::SessionHmac { kdf_key, .. } = &mut bad.steps[1].patches[0] {
        kdf_key.resize(1025, 0);
    }
    assert_eq!(bad.encode().unwrap_err(), "session HMAC bounds");
    let mut bad = p.clone();
    if let Patch::SessionHmac { at, .. } = &mut bad.steps[1].patches[0] {
        *at = 74;
    }
    assert_eq!(bad.encode().unwrap_err(), "patch destination bounds");
    let mut bad = p.clone();
    if let Patch::SessionHmac { parts, .. } = &mut bad.steps[1].patches[0] {
        *parts = vec![Part::Literal(vec![0; MAX_BYTES + 1])];
    }
    assert_eq!(bad.encode().unwrap_err(), "session HMAC message oversized");
    // Out-of-range nonce references (beyond the producer's declared slot) must fail.
    let mut bad = p.clone();
    if let Patch::SessionHmac { u_parts, .. } = &mut bad.steps[1].patches[0] {
        u_parts[0] = Part::Response(ResponseRange {
            step: 0,
            area: ResponseArea::Parameters,
            offset: 32,
            len: 32,
        });
    }
    assert_eq!(
        bad.encode().unwrap_err(),
        "response range bounds/forward reference"
    );
}
