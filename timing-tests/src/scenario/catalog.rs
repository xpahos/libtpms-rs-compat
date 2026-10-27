use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::oracle::ec::CurveId;
use crate::oracle::hash::HashAlg;
use crate::oracle::rsa::RsaBits;
use crate::oracle::sym::{SymKey, SymMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EccScheme {
    Ecdsa,
    EcSchnorr,
    Sm2,
}

impl EccScheme {
    pub const ALL: [EccScheme; 3] = [Self::Ecdsa, Self::EcSchnorr, Self::Sm2];

    pub fn name(self) -> &'static str {
        match self {
            Self::Ecdsa => "ecdsa",
            Self::EcSchnorr => "ecschnorr",
            Self::Sm2 => "sm2",
        }
    }

    pub fn alg_id(self) -> u16 {
        match self {
            Self::Ecdsa => crate::tpm::TPM_ALG_ECDSA,
            Self::EcSchnorr => crate::tpm::TPM_ALG_ECSCHNORR,
            Self::Sm2 => crate::tpm::TPM_ALG_SM2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExchangeScheme {
    Ecdh,
    Sm2,
    Ecmqv,
}
impl ExchangeScheme {
    pub const ALL: [Self; 3] = [Self::Ecdh, Self::Sm2, Self::Ecmqv];
    pub fn name(self) -> &'static str {
        match self {
            Self::Ecdh => "ecdh",
            Self::Sm2 => "sm2",
            Self::Ecmqv => "ecmqv",
        }
    }
    pub fn alg_id(self) -> u16 {
        match self {
            Self::Ecdh => 0x19,
            Self::Sm2 => 0x1b,
            Self::Ecmqv => 0x1d,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RsaPadding {
    Raw,
    Rsaes,
    OaepSha1,
    OaepSha256,
    OaepSha384,
    OaepSha512,
}

impl RsaPadding {
    pub const ALL: [RsaPadding; 6] = [
        Self::Raw,
        Self::Rsaes,
        Self::OaepSha1,
        Self::OaepSha256,
        Self::OaepSha384,
        Self::OaepSha512,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Rsaes => "rsaes",
            Self::OaepSha1 => "oaep-sha1",
            Self::OaepSha256 => "oaep-sha256",
            Self::OaepSha384 => "oaep-sha384",
            Self::OaepSha512 => "oaep-sha512",
        }
    }

    pub fn oaep_hash(self) -> Option<HashAlg> {
        match self {
            Self::OaepSha1 => Some(HashAlg::Sha1),
            Self::OaepSha256 => Some(HashAlg::Sha256),
            Self::OaepSha384 => Some(HashAlg::Sha384),
            Self::OaepSha512 => Some(HashAlg::Sha512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RsaSigScheme {
    Rsassa,
    Rsapss,
}

impl RsaSigScheme {
    pub const ALL: [RsaSigScheme; 2] = [Self::Rsassa, Self::Rsapss];

    pub fn name(self) -> &'static str {
        match self {
            Self::Rsassa => "rsassa",
            Self::Rsapss => "rsapss",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

impl Direction {
    pub const ALL: [Direction; 2] = [Self::Encrypt, Self::Decrypt];

    pub fn name(self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AsymKind {
    Rsa(RsaBits),
    Ecc(CurveId),
}

impl AsymKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rsa(bits) => bits.name(),
            Self::Ecc(curve) => curve.name(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ResponseProtection {
    None,
    Aes128Cfb,
    Xor,
}
impl ResponseProtection {
    pub const ALL: [Self; 3] = [Self::None, Self::Aes128Cfb, Self::Xor];
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes128Cfb => "aes128-cfb",
            Self::Xor => "xor",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RequestProtection {
    Aes128Cfb,
    Xor,
}
impl RequestProtection {
    pub const ALL: [Self; 2] = [Self::Aes128Cfb, Self::Xor];
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Cfb => "aes128-cfb",
            Self::Xor => "xor",
        }
    }
}
/// Key lengths around the SHA-1/SHA-256 block size for NULL-scheme MAC objects.
/// The sharp 128-byte transport limit (TPM2B_SENSITIVE_DATA = MAX_SYM_DATA)
/// bounds every variant in both backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LongKeyLength {
    BelowBlock,
    Block,
    AboveBlock,
    Max,
}
impl LongKeyLength {
    pub const ALL: [Self; 4] = [Self::BelowBlock, Self::Block, Self::AboveBlock, Self::Max];
    /// SHA-1 and SHA-256 share the 64-byte HMAC block size.
    pub fn bytes(self) -> usize {
        match self {
            Self::BelowBlock => 63,
            Self::Block => 64,
            Self::AboveBlock => 65,
            Self::Max => 128,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::BelowBlock => "63",
            Self::Block => "64",
            Self::AboveBlock => "65",
            Self::Max => "128",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImportLayer {
    Outer,
    Inner,
    Layered,
}
impl ImportLayer {
    pub const ALL: [Self; 3] = [Self::Outer, Self::Inner, Self::Layered];
    pub fn name(self) -> &'static str {
        match self {
            Self::Outer => "outer",
            Self::Inner => "inner",
            Self::Layered => "layered",
        }
    }
}
pub fn storage_kinds() -> Vec<AsymKind> {
    RsaBits::ALL
        .into_iter()
        .map(AsymKind::Rsa)
        .chain(CurveId::ALL.into_iter().map(AsymKind::Ecc))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeygenKind {
    Rsa(RsaBits),
    Ecc(CurveId),
    Aes128,
    HmacSha256,
}

impl KeygenKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rsa(bits) => bits.name(),
            Self::Ecc(curve) => curve.name(),
            Self::Aes128 => "aes128",
            Self::HmacSha256 => "hmac-sha256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Area {
    Control,
    EcdhKeyExchange,
    EccSignature,
    Rsa,
    Symmetric,
    Mac,
    KeyDerivation,
    KeyGeneration,
    Random,
    AuthenticationIntegrity,
}

impl Area {
    pub const ALL: [Area; 10] = [
        Self::EcdhKeyExchange,
        Self::EccSignature,
        Self::Rsa,
        Self::Symmetric,
        Self::Mac,
        Self::KeyDerivation,
        Self::KeyGeneration,
        Self::Random,
        Self::AuthenticationIntegrity,
        Self::Control,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::EcdhKeyExchange => "ecdh",
            Self::EccSignature => "ecc-signature",
            Self::Rsa => "rsa",
            Self::Symmetric => "symmetric",
            Self::Mac => "mac",
            Self::KeyDerivation => "kdf",
            Self::KeyGeneration => "keygen",
            Self::Random => "random",
            Self::AuthenticationIntegrity => "auth-integrity",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Control => "Controls",
            Self::EcdhKeyExchange => "ECDH and ECC key exchange",
            Self::EccSignature => "ECC signatures",
            Self::Rsa => "RSA",
            Self::Symmetric => "Symmetric encryption",
            Self::Mac => "MAC",
            Self::KeyDerivation => "Key derivation",
            Self::KeyGeneration => "Key generation",
            Self::Random => "Random generation",
            Self::AuthenticationIntegrity => "Authentication and integrity comparisons",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scenario {
    EcdhP521,
    ControlPositive,
    ControlNegative,
    TpmControlPositive,
    TpmControlNegative,
    Ecdh(CurveId),
    EccSign(EccScheme, CurveId),
    EccDecrypt(CurveId, HashAlg),
    Ecdaa(CurveId),
    Zgen(CurveId, ExchangeScheme),
    RsaDecrypt(RsaBits, RsaPadding),
    RsaSign(RsaBits, RsaSigScheme),
    Sym(SymKey, SymMode, Direction),
    SymPartial(SymKey, SymMode, Direction),
    Hmac(HashAlg),
    Cmac(SymKey),
    HmacSequence(HashAlg),
    CmacSequence(SymKey),
    HmacVerify(HashAlg),
    SaltedSession(AsymKind),
    ActivateCredential(AsymKind),
    LoadIntegrity(AsymKind),
    SignTicket,
    PasswordAuth,
    HmacAuth(HashAlg, ResponseProtection),
    HmacAuthBound(HashAlg),
    HmacAuthSalted,
    HmacAuthRequest(RequestProtection),
    HmacAuthBoundSecret(HashAlg),
    HmacAuthSaltedSecret,
    HmacAuthRequestSecret(RequestProtection),
    MacLongKey(HashAlg, LongKeyLength),
    Import(AsymKind, ImportLayer),
    Duplicate(Option<AsymKind>, bool),
    Rewrap(AsymKind, Option<AsymKind>),
    KeygenPrimary(KeygenKind),
    DrbgGenerate,
    DrbgStir,
    DrbgControlled { reseed: bool, continuous: bool },
}

pub fn all_scenarios() -> Vec<Scenario> {
    let mut out = vec![
        Scenario::ControlPositive,
        Scenario::ControlNegative,
        Scenario::TpmControlPositive,
        Scenario::TpmControlNegative,
    ];
    for curve in CurveId::ALL {
        out.push(if curve == CurveId::NistP521 {
            Scenario::EcdhP521
        } else {
            Scenario::Ecdh(curve)
        });
    }
    for curve in CurveId::ALL {
        out.push(Scenario::Ecdaa(curve));
        for hash in HashAlg::ALL {
            out.push(Scenario::EccDecrypt(curve, hash));
        }
        for scheme in ExchangeScheme::ALL {
            out.push(Scenario::Zgen(curve, scheme));
        }
    }
    for scheme in EccScheme::ALL {
        for curve in CurveId::ALL {
            out.push(Scenario::EccSign(scheme, curve));
        }
    }
    for bits in RsaBits::ALL {
        for padding in RsaPadding::ALL {
            if padding
                .oaep_hash()
                .is_none_or(|h| bits.bytes() >= 2 * h.size() + 2)
            {
                out.push(Scenario::RsaDecrypt(bits, padding));
            }
        }
        for scheme in RsaSigScheme::ALL {
            out.push(Scenario::RsaSign(bits, scheme));
        }
    }
    for key in SymKey::ALL {
        for mode in SymMode::ALL {
            for direction in Direction::ALL {
                out.push(Scenario::Sym(key, mode, direction));
                out.push(Scenario::SymPartial(key, mode, direction));
            }
        }
    }
    for hash in HashAlg::ALL {
        out.push(Scenario::Hmac(hash));
        out.push(Scenario::HmacSequence(hash));
    }
    for key in SymKey::ALL {
        out.push(Scenario::Cmac(key));
        out.push(Scenario::CmacSequence(key));
    }
    for bits in RsaBits::ALL {
        out.push(Scenario::SaltedSession(AsymKind::Rsa(bits)));
    }
    for curve in CurveId::ALL {
        out.push(Scenario::SaltedSession(AsymKind::Ecc(curve)));
    }
    for bits in RsaBits::ALL {
        out.push(Scenario::KeygenPrimary(KeygenKind::Rsa(bits)));
    }
    for curve in CurveId::ALL {
        out.push(Scenario::KeygenPrimary(KeygenKind::Ecc(curve)));
    }
    out.push(Scenario::KeygenPrimary(KeygenKind::Aes128));
    out.push(Scenario::KeygenPrimary(KeygenKind::HmacSha256));
    out.push(Scenario::DrbgGenerate);
    out.push(Scenario::DrbgStir);
    for reseed in [false, true] {
        for continuous in [false, true] {
            out.push(Scenario::DrbgControlled { reseed, continuous });
        }
    }
    for hash in HashAlg::ALL {
        out.push(Scenario::HmacVerify(hash));
    }
    for hash in HashAlg::ALL {
        for protection in ResponseProtection::ALL {
            out.push(Scenario::HmacAuth(hash, protection));
        }
        out.push(Scenario::HmacAuthBound(hash));
    }
    out.push(Scenario::HmacAuthSalted);
    for protection in RequestProtection::ALL {
        out.push(Scenario::HmacAuthRequest(protection));
        out.push(Scenario::HmacAuthRequestSecret(protection));
    }
    // One representative hash per secret-varying family: the distinct path is
    // the secret-dependent derivation, not the digest width.
    out.push(Scenario::HmacAuthBoundSecret(HashAlg::Sha256));
    out.push(Scenario::HmacAuthSaltedSecret);
    for hash in [HashAlg::Sha1, HashAlg::Sha256] {
        for length in LongKeyLength::ALL {
            out.push(Scenario::MacLongKey(hash, length));
        }
    }
    for generated in [false, true] {
        out.push(Scenario::Duplicate(None, generated));
    }
    for kind in storage_kinds() {
        for layer in ImportLayer::ALL {
            out.push(Scenario::Import(kind, layer));
        }
        for generated in [false, true] {
            out.push(Scenario::Duplicate(Some(kind), generated));
        }
        out.push(Scenario::Rewrap(kind, None));
        for new in storage_kinds() {
            out.push(Scenario::Rewrap(kind, Some(new)));
        }
    }
    out.push(Scenario::PasswordAuth);
    out.push(Scenario::SignTicket);
    for kind in [
        AsymKind::Rsa(RsaBits::B2048),
        AsymKind::Ecc(CurveId::NistP256),
    ] {
        out.push(Scenario::ActivateCredential(kind));
        out.push(Scenario::LoadIntegrity(kind));
    }
    out
}

fn compute_name(scenario: Scenario) -> String {
    match scenario {
        Scenario::EcdhP521 => "ecdh-p521".into(),
        Scenario::ControlPositive => "control-positive".into(),
        Scenario::ControlNegative => "control-negative".into(),
        Scenario::TpmControlPositive => "control-tpm-positive".into(),
        Scenario::TpmControlNegative => "control-tpm-negative".into(),
        Scenario::Ecdh(curve) => format!("ecdh-{}", curve.name()),
        Scenario::EccDecrypt(curve, hash) => {
            format!("ecc-decrypt-{}-{}", curve.name(), hash.name())
        }
        Scenario::Ecdaa(curve) => format!("ecdaa-commit-sign-{}", curve.name()),
        Scenario::Zgen(curve, scheme) => format!("zgen-2phase-{}-{}", scheme.name(), curve.name()),
        Scenario::EccSign(scheme, curve) => format!("ecsign-{}-{}", scheme.name(), curve.name()),
        Scenario::RsaDecrypt(bits, padding) => {
            format!("rsa-decrypt-{}-{}", bits.bits(), padding.name())
        }
        Scenario::RsaSign(bits, scheme) => format!("rsa-sign-{}-{}", bits.bits(), scheme.name()),
        Scenario::Sym(key, mode, direction) => {
            format!("sym-{}-{}-{}", key.name(), mode.name(), direction.name())
        }
        Scenario::SymPartial(key, mode, direction) => format!(
            "sym-partial-{}-{}-{}",
            key.name(),
            mode.name(),
            direction.name()
        ),
        Scenario::HmacSequence(hash) => format!("mac-sequence-hmac-{}", hash.name()),
        Scenario::CmacSequence(key) => format!("mac-sequence-cmac-{}", key.name()),
        Scenario::Hmac(hash) => format!("mac-hmac-{}", hash.name()),
        Scenario::Cmac(key) => format!("mac-cmac-{}", key.name()),
        Scenario::HmacVerify(hash) => format!("hmac-verify-{}", hash.name()),
        Scenario::SaltedSession(kind) => format!("kdf-salted-session-{}", kind.name()),
        Scenario::ActivateCredential(kind) => {
            format!("integrity-activate-credential-{}", kind.name())
        }
        Scenario::LoadIntegrity(kind) => format!("integrity-load-{}", kind.name()),
        Scenario::SignTicket => "integrity-sign-ticket-hmac-sha256".into(),
        Scenario::PasswordAuth => "auth-password".into(),
        Scenario::HmacAuth(hash, protection) => {
            format!("auth-hmac-{}-{}", hash.name(), protection.name())
        }
        Scenario::HmacAuthBound(hash) => format!("auth-hmac-bound-{}", hash.name()),
        Scenario::HmacAuthSalted => "auth-hmac-salted-sha256".into(),
        Scenario::HmacAuthRequest(protection) => {
            format!("auth-hmac-request-{}", protection.name())
        }
        Scenario::HmacAuthBoundSecret(hash) => {
            format!("auth-hmac-bound-secret-{}", hash.name())
        }
        Scenario::HmacAuthSaltedSecret => "auth-hmac-salted-secret-sha256".into(),
        Scenario::HmacAuthRequestSecret(protection) => {
            format!("auth-hmac-request-secret-{}", protection.name())
        }
        Scenario::MacLongKey(hash, length) => {
            format!("mac-hmac-long-{}-{}", hash.name(), length.name())
        }
        Scenario::Import(kind, layer) => {
            format!("integrity-import-{}-{}", kind.name(), layer.name())
        }
        Scenario::Duplicate(kind, generated) => format!(
            "duplicate-{}-{}",
            kind.map_or("null", AsymKind::name),
            if generated { "generated" } else { "supplied" }
        ),
        Scenario::Rewrap(old, new) => format!(
            "integrity-rewrap-{}-{}",
            old.name(),
            new.map_or("null", AsymKind::name)
        ),
        Scenario::KeygenPrimary(kind) => format!("keygen-primary-{}", kind.name()),
        Scenario::DrbgGenerate => "drbg-getrandom".into(),
        Scenario::DrbgStir => "drbg-stirrandom".into(),
        Scenario::DrbgControlled { reseed, continuous } => format!(
            "drbg-controlled-{}-continuous-{}",
            if reseed { "auto-reseed" } else { "generate" },
            if continuous { "on" } else { "off" }
        ),
    }
}

struct Names {
    by_scenario: BTreeMap<Scenario, &'static str>,
    by_name: BTreeMap<&'static str, Scenario>,
}

fn names() -> &'static Names {
    static NAMES: OnceLock<Names> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut by_scenario = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        for scenario in all_scenarios() {
            let name: &'static str = Box::leak(compute_name(scenario).into_boxed_str());
            assert!(
                by_name.insert(name, scenario).is_none(),
                "duplicate scenario name {name}"
            );
            by_scenario.insert(scenario, name);
        }
        Names {
            by_scenario,
            by_name,
        }
    })
}

impl Scenario {
    pub fn name(self) -> &'static str {
        names()
            .by_scenario
            .get(&self)
            .copied()
            .unwrap_or_else(|| Box::leak(compute_name(self).into_boxed_str()))
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        names().by_name.get(text).copied().ok_or_else(|| {
            format!(
                "unknown scenario {text:?}; run `tpms-timing-tests list-scenarios` for the catalog"
            )
        })
    }

    pub fn is_control(self) -> bool {
        matches!(self, Self::ControlPositive | Self::ControlNegative)
    }

    pub fn is_tpm_control(self) -> bool {
        matches!(self, Self::TpmControlPositive | Self::TpmControlNegative)
    }

    pub fn needs_library(self) -> bool {
        !self.is_control()
    }

    pub fn area(self) -> Area {
        match self {
            Self::ControlPositive
            | Self::ControlNegative
            | Self::TpmControlPositive
            | Self::TpmControlNegative => Area::Control,
            Self::EcdhP521 | Self::Ecdh(_) | Self::EccDecrypt(..) | Self::Zgen(..) => {
                Area::EcdhKeyExchange
            }
            Self::EccSign(..) | Self::Ecdaa(_) => Area::EccSignature,
            Self::RsaDecrypt(..) | Self::RsaSign(..) => Area::Rsa,
            Self::Sym(..) | Self::SymPartial(..) => Area::Symmetric,
            Self::Hmac(_)
            | Self::Cmac(_)
            | Self::HmacVerify(_)
            | Self::HmacSequence(_)
            | Self::CmacSequence(_)
            | Self::MacLongKey(..) => Area::Mac,
            Self::SaltedSession(_) => Area::KeyDerivation,
            Self::KeygenPrimary(_) => Area::KeyGeneration,
            Self::DrbgGenerate | Self::DrbgStir | Self::DrbgControlled { .. } => Area::Random,
            Self::ActivateCredential(_)
            | Self::LoadIntegrity(_)
            | Self::SignTicket
            | Self::PasswordAuth
            | Self::HmacAuth(..)
            | Self::HmacAuthBound(..)
            | Self::HmacAuthSalted
            | Self::HmacAuthRequest(..)
            | Self::HmacAuthBoundSecret(..)
            | Self::HmacAuthSaltedSecret
            | Self::HmacAuthRequestSecret(..)
            | Self::Import(..)
            | Self::Duplicate(..)
            | Self::Rewrap(..) => Area::AuthenticationIntegrity,
        }
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Scenario {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        Self::parse(text)
    }
}

impl Serialize for Scenario {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for Scenario {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip_and_keep_the_legacy_spellings() {
        for scenario in all_scenarios() {
            assert_eq!(Scenario::parse(scenario.name()).unwrap(), scenario);
            let json = serde_json::to_string(&scenario).unwrap();
            assert_eq!(serde_json::from_str::<Scenario>(&json).unwrap(), scenario);
            assert!(crate::artifacts::is_plain_label(scenario.name()));
        }
        assert_eq!(Scenario::EcdhP521.name(), "ecdh-p521");
        assert_eq!(Scenario::ControlPositive.name(), "control-positive");
        assert_eq!(Scenario::ControlNegative.name(), "control-negative");
        assert!(Scenario::parse("ecdh-p999").is_err());
        assert!(!all_scenarios().contains(&Scenario::Ecdh(CurveId::NistP521)));
    }
}
