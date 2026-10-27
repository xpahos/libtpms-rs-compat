pub mod catalog;
pub mod family;
pub mod layout;
pub mod matrix;
pub mod remaining_auth;

mod asym;
mod controls;
mod drbg;
mod ecc;
mod integrity;
mod keygen;
mod mac;
mod p521;
mod random;
mod sym;

use serde::{Deserialize, Serialize};

/// Select a CFB chaining contract from observed probe responses: every probe
/// response must match exactly one independently computed contract candidate.
pub fn sym_chaining_select(
    vectors: &[crate::expectation::SymProbeVector],
) -> Result<crate::oracle::sym::ChainingContract, String> {
    use crate::oracle::sym::ChainingContract;
    let zero = vectors
        .iter()
        .all(|v| v.observed_response == v.zero_suffix_response);
    let retained = vectors
        .iter()
        .all(|v| v.observed_response == v.retained_suffix_response);
    match (zero, retained) {
        (true, false) => Ok(ChainingContract::ZeroSuffix),
        (false, true) => Ok(ChainingContract::RetainedSuffix),
        _ => Err("CFB chaining probes did not uniquely match a known independent contract".into()),
    }
}

pub use asym::{RsaesSelectorSpace, rsaes_kind_byte, rsaes_selector_kind};
pub use catalog::{
    Area, AsymKind, Direction, EccScheme, KeygenKind, RsaPadding, RsaSigScheme, Scenario,
    all_scenarios,
};
pub use family::{Check, Expect, ScenarioDoc, Validation, ValidationStep};
pub use layout::{Creates, HandleRef, Layout, Patch, Post, Resolved, Step, StepRef};
pub use p521::{
    CONTROL_BASE_ITERATIONS, CONTROL_COUNTED_BYTES, CONTROL_ITERATIONS_PER_BIT, CONTROL_MASK,
    LIMB_EXPONENTS, boundary_scalar, boundary_seeds, control_output, masked_tail_bits, peer_point,
    seeds, valid_scalar,
};
pub use sym::{
    chaining_probe_pair as sym_chaining_probe_pair, deterministic_key as sym_deterministic_key,
    effective_input as sym_effective_input, fixed_iv as sym_fixed_iv,
    partial_cfb_chaining as sym_partial_cfb, scenario_key as sym_scenario_key,
};

use crate::measure::LoadOrder;
use crate::oracle::bytes::{bit_length, hamming_weight, leading_zero_bytes};
use crate::scalar::{Point, ScalarPair};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InputPair {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    /// The RSAES selector-encoding version this input is measured with. The
    /// version is an explicit property of the recorded input and never inferred
    /// from a selector byte; program-generated inputs always use the current
    /// versioned encoding, inputs loaded from saved candidates keep the version
    /// the candidate recorded. Only RSAES-decoding scenarios read it.
    pub selector_space: RsaesSelectorSpace,
}

impl InputPair {
    /// Program-generated input in the current selector encoding.
    pub fn new(a: Vec<u8>, b: Vec<u8>) -> Self {
        Self {
            a,
            b,
            selector_space: RsaesSelectorSpace::V2Tagged,
        }
    }

    /// Input measured with an explicitly recorded selector encoding, used when
    /// replaying inputs loaded from saved candidates.
    pub fn with_selector_space(a: Vec<u8>, b: Vec<u8>, space: RsaesSelectorSpace) -> Self {
        Self {
            a,
            b,
            selector_space: space,
        }
    }

    pub fn class(&self, index: usize) -> &[u8] {
        if index == 0 { &self.a } else { &self.b }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.a.clone();
        out.extend_from_slice(&self.b);
        out
    }

    pub fn reversed(&self) -> Self {
        Self {
            a: self.b.clone(),
            b: self.a.clone(),
            selector_space: self.selector_space,
        }
    }

    pub fn unordered_key(&self) -> (&[u8], &[u8]) {
        if self.a <= self.b {
            (&self.a, &self.b)
        } else {
            (&self.b, &self.a)
        }
    }

    pub fn as_scalar_pair(&self) -> Option<ScalarPair> {
        ScalarPair::from_bytes(&self.to_bytes()).ok()
    }
}

impl Scenario {
    /// Whether this scenario interprets an RSAES selector byte whose meaning
    /// depends on the recorded selector encoding. Only RSAES decryption reads
    /// the encoding; for every other scenario the field is inert metadata and
    /// identical bytes keep one identity.
    pub fn selector_semantics_matter(&self) -> bool {
        matches!(self, Scenario::RsaDecrypt(_, RsaPadding::Rsaes))
    }
}

impl From<ScalarPair> for InputPair {
    fn from(pair: ScalarPair) -> Self {
        InputPair::new(pair.a.bytes().to_vec(), pair.b.bytes().to_vec())
    }
}

impl From<&ScalarPair> for InputPair {
    fn from(pair: &ScalarPair) -> Self {
        (*pair).into()
    }
}

impl From<&InputPair> for InputPair {
    fn from(pair: &InputPair) -> Self {
        Self {
            a: pair.a.clone(),
            b: pair.b.clone(),
            selector_space: pair.selector_space,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeedKind {
    Random,
    Boundary,
}

#[derive(Debug, Clone)]
pub struct Seed {
    pub name: String,
    pub kind: SeedKind,
    pub pair: InputPair,
}

pub struct SplitMix(u64);

impl SplitMix {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next_u64().to_be_bytes());
        }
        out.truncate(len);
        out
    }

    pub fn scalar(&mut self) -> crate::scalar::Scalar521 {
        p521::random_scalar(self)
    }

    pub fn full_width_scalar(&mut self) -> crate::scalar::Scalar521 {
        loop {
            let scalar = self.scalar();
            if scalar.bit_length() == 521 {
                return scalar;
            }
        }
    }

    pub fn below(&mut self, bound: &num_bigint::BigUint, width: usize) -> Vec<u8> {
        loop {
            let bytes = self.bytes(width);
            let value = num_bigint::BigUint::from_bytes_be(&bytes);
            let excess = width * 8 - bound.bits() as usize;
            let value = value >> excess;
            if value > num_bigint::BigUint::from(0u32) && &value < bound {
                return crate::oracle::bytes::to_fixed(&value, width);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DifferenceKind {
    #[default]
    Unclassified,
    SecretOnly,
    Mixed,
    PublicInput,
    OutputSize,
    VisibleOutcome,
    DifferentOperation,
    Identical,
}

pub fn classify_difference(
    scenario: Scenario,
    pair: &InputPair,
    codes: [u32; 2],
    lengths: [usize; 2],
    model: &family::PairModel,
) -> DifferenceKind {
    if scenario == Scenario::TpmControlPositive {
        return DifferenceKind::DifferentOperation;
    }
    if scenario == Scenario::TpmControlNegative || pair.a == pair.b {
        return DifferenceKind::Identical;
    }
    if codes[0] != codes[1] {
        return DifferenceKind::VisibleOutcome;
    }
    if lengths[0] != lengths[1] {
        return DifferenceKind::OutputSize;
    }
    let public = !model.public_differences.is_empty() || !model.confounders.is_empty();
    match (model.secret_differs, public) {
        (true, false) => DifferenceKind::SecretOnly,
        (true, true) => DifferenceKind::Mixed,
        (false, true) => DifferenceKind::PublicInput,
        (false, false) => DifferenceKind::Identical,
    }
}

impl DifferenceKind {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Unclassified => {
                "no difference classification recorded (legacy artifact); secret dependence is not established"
            }
            Self::SecretOnly => {
                "only the secret component differs; public inputs, objects, response code and length are identical"
            }
            Self::Mixed => {
                "the secret component differs together with public values (listed); a signal is not isolated to the secret"
            }
            Self::PublicInput => {
                "only caller-chosen public values differ (listed); a signal shows dependence on them, possibly combined with fixed secret state, and is not automatically harmless"
            }
            Self::OutputSize => {
                "classes return responses of different length; output size is a confounder of any signal"
            }
            Self::VisibleOutcome => {
                "classes return different response codes; the different code paths are a confounder, and a signal may still reveal more than the response code"
            }
            Self::DifferentOperation => {
                "classes run explicitly different operations (positive control)"
            }
            Self::Identical => {
                "both classes send identical commands; any signal is a measurement artefact"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassPrep {
    #[serde(with = "crate::scalar::hex_bytes")]
    pub scalar: Vec<u8>,
    pub public: Option<Point>,
    pub shared: Option<Point>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub expected_response: Vec<u8>,
    #[serde(default, with = "crate::scalar::hex_bytes")]
    pub mask: Vec<u8>,
    #[serde(default)]
    pub check: Option<Check>,
    #[serde(default)]
    pub validation: Option<family::Validation>,
}

impl ClassPrep {
    pub fn matches(&self, response: &[u8]) -> bool {
        layout::masked_equal(response, &self.expected_response, &self.mask)
    }

    pub fn validate(&self, response: &[u8]) -> Result<(), String> {
        if !self.matches(response) {
            return Err(format!(
                "response {} differs from the independently derived expectation {}",
                hex::encode(response),
                hex::encode(&self.expected_response)
            ));
        }
        match &self.check {
            Some(check) => check.check(response),
            None => Ok(()),
        }
    }

    pub fn masked(&self, response: &[u8]) -> Vec<u8> {
        response
            .iter()
            .enumerate()
            .map(|(i, b)| b & self.mask.get(i).copied().unwrap_or(0xff))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMetadata {
    #[serde(default)]
    pub rsaes_evidence: Option<crate::expectation::RsaesEvidence>,
    /// Backend-resolved CFB chaining evidence (ivOut contract for partial final
    /// blocks); provenance only, never authority over the applied contract.
    #[serde(default)]
    pub sym_evidence: Option<crate::expectation::SymChainingEvidence>,
    /// True when the measured data ends in a partial CFB block, where the two
    /// supported backends return different chaining values.
    #[serde(default)]
    pub sym_partial_chaining: bool,
    pub varying_public_values: Vec<String>,
    pub bit_length: [usize; 2],
    pub leading_zero_bytes: [usize; 2],
    pub hamming_weight: [u32; 2],
    pub shared_x_leading_zero_bytes: [usize; 2],
    pub public_x_leading_zero_bytes: [usize; 2],
    #[serde(default)]
    pub expected_response_codes: [u32; 2],
    #[serde(default)]
    pub expected_response_lengths: [usize; 2],
    /// Minimum semantic response lengths; upper bounds are expected_response_lengths.
    #[serde(default)]
    pub expected_response_min_lengths: [usize; 2],
    /// Encoded transport sizes, including command-program padding when present.
    #[serde(default)]
    pub expected_transport_response_lengths: [usize; 2],
    #[serde(default)]
    pub difference: DifferenceKind,
    #[serde(default)]
    pub public_differences: Vec<String>,
    #[serde(default)]
    pub confounders: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PreparedPair {
    pub scenario: Scenario,
    pub pair: InputPair,
    pub classes: [ClassPrep; 2],
    pub metadata: PublicMetadata,
    pub layout: Layout,
}

impl PreparedPair {
    pub fn prepare(scenario: Scenario, pair: impl Into<InputPair>) -> Self {
        let pair = pair.into();
        Self::try_prepare(scenario, pair.clone()).unwrap_or_else(|error| {
            panic!(
                "{scenario}: cannot prepare {}: {error}",
                hex::encode(pair.to_bytes())
            )
        })
    }

    pub fn try_prepare(scenario: Scenario, pair: impl Into<InputPair>) -> Result<Self, String> {
        let pair = pair.into();
        for class in 0..2 {
            validate_input(scenario, pair.class(class))
                .map_err(|e| format!("class {class}: {e}"))?;
        }
        let built = build(scenario, &pair)?;
        Self::from_built(scenario, pair, built)
    }

    pub(crate) fn try_prepare_profile(
        scenario: Scenario,
        pair: InputPair,
        profile: crate::expectation::RsaesProfile,
    ) -> Result<Self, String> {
        for input in [&pair.a, &pair.b] {
            validate_input(scenario, input)?;
        }
        let mut built = build(scenario, &pair)?;
        asym::apply_rsaes_profile(scenario, &pair, &mut built, profile)?;
        Self::from_built(scenario, pair, built)
    }

    /// Prepare a pair under an explicit backend CFB chaining contract (partial
    /// final blocks: zeroed vs retained ivOut suffix).
    pub(crate) fn try_prepare_chaining(
        scenario: Scenario,
        pair: InputPair,
        contract: crate::oracle::sym::ChainingContract,
    ) -> Result<Self, String> {
        for input in [&pair.a, &pair.b] {
            validate_input(scenario, input)?;
        }
        let mut built = build(scenario, &pair)?;
        sym::apply_chaining_contract(scenario, &pair, &mut built, contract)?;
        Self::from_built(scenario, pair, built)
    }

    /// Test-facing wrapper around [`Self::try_prepare_chaining`].
    pub fn try_prepare_backend_chaining(
        scenario: Scenario,
        pair: impl Into<InputPair>,
        contract: crate::oracle::sym::ChainingContract,
    ) -> Result<Self, String> {
        Self::try_prepare_chaining(scenario, pair.into(), contract)
    }

    /// Test-facing wrapper around [`Self::try_prepare_profile`]: prepares a
    /// pair under an explicitly chosen RSAES backend contract.
    pub fn try_prepare_backend(
        scenario: Scenario,
        pair: impl Into<InputPair>,
        profile: crate::expectation::RsaesProfile,
    ) -> Result<Self, String> {
        Self::try_prepare_profile(scenario, pair.into(), profile)
    }

    fn from_built(
        scenario: Scenario,
        pair: InputPair,
        built: family::Built,
    ) -> Result<Self, String> {
        let [c0, c1] = built.classes;
        let leading = |p: &Option<Point>| p.as_ref().map(|p| leading_zero_bytes(&p.x)).unwrap_or(0);
        let semantics = [c0.response_semantics()?, c1.response_semantics()?];
        let codes = semantics.map(|s| s.0);
        let minimums = semantics.map(|s| s.1);
        let lengths = semantics.map(|s| s.2);
        let transport_lengths = [c0.expected.len(), c1.expected.len()];
        let difference = if codes[0] == codes[1] && minimums[0] != minimums[1] {
            DifferenceKind::OutputSize
        } else {
            classify_difference(scenario, &pair, codes, lengths, &built.model)
        };
        let mut confounders = built.model.confounders.clone();
        if minimums != lengths {
            confounders.push(format!("semantic TPM response lengths vary within {minimums:?}..={lengths:?}; padded transcript sizes do not hide raw response lengths"));
        }
        let metadata = PublicMetadata {
            rsaes_evidence: None,
            sym_evidence: None,
            sym_partial_chaining: sym::partial_cfb_chaining(scenario, &pair.a),
            varying_public_values: built.varying_public_values.clone(),
            bit_length: [bit_length(&pair.a), bit_length(&pair.b)],
            leading_zero_bytes: [leading_zero_bytes(&pair.a), leading_zero_bytes(&pair.b)],
            hamming_weight: [hamming_weight(&pair.a), hamming_weight(&pair.b)],
            shared_x_leading_zero_bytes: [leading(&c0.shared), leading(&c1.shared)],
            public_x_leading_zero_bytes: [leading(&c0.public), leading(&c1.public)],
            expected_response_codes: codes,
            expected_response_lengths: lengths,
            expected_response_min_lengths: minimums,
            expected_transport_response_lengths: transport_lengths,
            difference,
            public_differences: built.model.public_differences.clone(),
            confounders,
        };
        let classes = [
            ClassPrep {
                scalar: pair.a.clone(),
                public: c0.public,
                shared: c0.shared,
                expected_response: c0.expected,
                mask: c0.mask,
                check: c0.check,
                validation: c0.validation,
            },
            ClassPrep {
                scalar: pair.b.clone(),
                public: c1.public,
                shared: c1.shared,
                expected_response: c1.expected,
                mask: c1.mask,
                validation: c1.validation,
                check: c1.check,
            },
        ];
        let layout = Layout {
            shared: built.shared,
            per_class: [c0.setup, c1.setup],
            measured: [c0.measured, c1.measured],
            post: [c0.post, c1.post],
        };
        layout.resolve(LoadOrder::ClassAFirst)?;
        Ok(Self {
            scenario,
            pair,
            classes,
            metadata,
            layout,
        })
    }

    pub fn resolve(&self, order: LoadOrder) -> Resolved {
        self.layout
            .resolve(order)
            .expect("layouts are validated when the pair is prepared")
    }

    pub fn load_command(&self, class: usize) -> Option<Vec<u8>> {
        self.layout.per_class[class]
            .first()
            .map(|step| step.command.clone())
    }

    pub fn measured_command(&self, class: usize, handle: u32) -> Vec<u8> {
        let step = &self.layout.measured[class];
        let mut bytes = step.command.clone();
        for (at, reference) in &step.handles {
            if matches!(reference, HandleRef::Class(0)) {
                bytes[*at..*at + 4].copy_from_slice(&handle.to_be_bytes());
            }
        }
        bytes
    }

    pub fn has_tpm_state(&self) -> bool {
        !self.scenario.is_control()
    }
}

pub fn input_width(scenario: Scenario) -> usize {
    match scenario {
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            crate::scalar::SCALAR_BYTES
        }
        Scenario::TpmControlPositive | Scenario::TpmControlNegative => controls::INPUT_BYTES,
        Scenario::Ecdh(_)
        | Scenario::EccSign(..)
        | Scenario::RsaDecrypt(..)
        | Scenario::RsaSign(..)
        | Scenario::SaltedSession(_) => asym::input_width(scenario),
        Scenario::EccDecrypt(..) | Scenario::Ecdaa(_) | Scenario::Zgen(..) => {
            ecc::input_width(scenario)
        }
        Scenario::Sym(..) | Scenario::SymPartial(..) => sym::input_width(scenario),
        Scenario::Hmac(_)
        | Scenario::Cmac(_)
        | Scenario::HmacVerify(_)
        | Scenario::HmacSequence(_)
        | Scenario::CmacSequence(_)
        | Scenario::MacLongKey(..) => mac::input_width(scenario),
        Scenario::ActivateCredential(_)
        | Scenario::LoadIntegrity(_)
        | Scenario::SignTicket
        | Scenario::PasswordAuth => integrity::input_width(scenario),
        Scenario::HmacAuth(..)
        | Scenario::HmacAuthBound(..)
        | Scenario::HmacAuthSalted
        | Scenario::HmacAuthRequest(..)
        | Scenario::HmacAuthBoundSecret(..)
        | Scenario::HmacAuthSaltedSecret
        | Scenario::HmacAuthRequestSecret(..)
        | Scenario::Import(..)
        | Scenario::Duplicate(..)
        | Scenario::Rewrap(..) => remaining_auth::input_width(scenario),
        Scenario::KeygenPrimary(_) => keygen::input_width(scenario),
        Scenario::DrbgControlled { .. } => drbg::input_width(scenario),
        Scenario::DrbgGenerate | Scenario::DrbgStir => random::input_width(scenario),
    }
}

pub fn validate_input(scenario: Scenario, bytes: &[u8]) -> Result<(), String> {
    let width = input_width(scenario);
    if bytes.len() != width {
        return Err(format!("expected {width} input bytes, got {}", bytes.len()));
    }
    match scenario {
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            crate::scalar::Scalar521::from_slice(bytes)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        Scenario::TpmControlPositive | Scenario::TpmControlNegative => Ok(()),
        Scenario::Ecdh(_)
        | Scenario::EccSign(..)
        | Scenario::RsaDecrypt(..)
        | Scenario::RsaSign(..)
        | Scenario::SaltedSession(_) => asym::validate(scenario, bytes),
        Scenario::EccDecrypt(..) | Scenario::Ecdaa(_) | Scenario::Zgen(..) => {
            ecc::validate(scenario, bytes)
        }
        Scenario::Sym(..) | Scenario::SymPartial(..) => sym::validate(scenario, bytes),
        Scenario::Hmac(_)
        | Scenario::Cmac(_)
        | Scenario::HmacVerify(_)
        | Scenario::HmacSequence(_)
        | Scenario::CmacSequence(_)
        | Scenario::MacLongKey(..) => mac::validate(scenario, bytes),
        Scenario::ActivateCredential(_)
        | Scenario::LoadIntegrity(_)
        | Scenario::SignTicket
        | Scenario::PasswordAuth => integrity::validate(scenario, bytes),
        Scenario::HmacAuth(..)
        | Scenario::HmacAuthBound(..)
        | Scenario::HmacAuthSalted
        | Scenario::HmacAuthRequest(..)
        | Scenario::HmacAuthBoundSecret(..)
        | Scenario::HmacAuthSaltedSecret
        | Scenario::HmacAuthRequestSecret(..)
        | Scenario::Import(..)
        | Scenario::Duplicate(..)
        | Scenario::Rewrap(..) => remaining_auth::validate(scenario, bytes),
        Scenario::KeygenPrimary(_) => keygen::validate(scenario, bytes),
        Scenario::DrbgControlled { .. } => drbg::validate(scenario, bytes),
        Scenario::DrbgGenerate | Scenario::DrbgStir => random::validate(scenario, bytes),
    }
}

pub fn parse_pair(scenario: Scenario, bytes: &[u8]) -> Result<InputPair, String> {
    let width = input_width(scenario);
    if bytes.len() != 2 * width {
        return Err(format!(
            "expected {} bytes for a {scenario} pair, got {}",
            2 * width,
            bytes.len()
        ));
    }
    let pair = InputPair::new(bytes[..width].to_vec(), bytes[width..].to_vec());
    for class in 0..2 {
        validate_input(scenario, pair.class(class)).map_err(|e| format!("class {class}: {e}"))?;
    }
    Ok(pair)
}

pub fn scenario_seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let seeds = match scenario {
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            seeds(campaign_seed, random_pairs)
        }
        Scenario::TpmControlPositive | Scenario::TpmControlNegative => {
            controls::seeds(scenario, campaign_seed, random_pairs)
        }
        Scenario::Ecdh(_)
        | Scenario::EccSign(..)
        | Scenario::RsaDecrypt(..)
        | Scenario::RsaSign(..)
        | Scenario::SaltedSession(_) => asym::seeds(scenario, campaign_seed, random_pairs),
        Scenario::EccDecrypt(..) | Scenario::Ecdaa(_) | Scenario::Zgen(..) => {
            ecc::seeds(scenario, campaign_seed, random_pairs)
        }
        Scenario::Sym(..) | Scenario::SymPartial(..) => {
            sym::seeds(scenario, campaign_seed, random_pairs)
        }
        Scenario::Hmac(_)
        | Scenario::Cmac(_)
        | Scenario::HmacVerify(_)
        | Scenario::HmacSequence(_)
        | Scenario::CmacSequence(_)
        | Scenario::MacLongKey(..) => mac::seeds(scenario, campaign_seed, random_pairs),
        Scenario::ActivateCredential(_)
        | Scenario::LoadIntegrity(_)
        | Scenario::SignTicket
        | Scenario::PasswordAuth => integrity::seeds(scenario, campaign_seed, random_pairs),
        Scenario::HmacAuth(..)
        | Scenario::HmacAuthBound(..)
        | Scenario::HmacAuthSalted
        | Scenario::HmacAuthRequest(..)
        | Scenario::HmacAuthBoundSecret(..)
        | Scenario::HmacAuthSaltedSecret
        | Scenario::HmacAuthRequestSecret(..)
        | Scenario::Import(..)
        | Scenario::Duplicate(..)
        | Scenario::Rewrap(..) => remaining_auth::seeds(scenario, campaign_seed, random_pairs),
        Scenario::KeygenPrimary(_) => keygen::seeds(scenario, campaign_seed, random_pairs),
        Scenario::DrbgControlled { .. } => drbg::seeds(scenario, campaign_seed, random_pairs),
        Scenario::DrbgGenerate | Scenario::DrbgStir => {
            random::seeds(scenario, campaign_seed, random_pairs)
        }
    };
    for seed in &seeds {
        for class in 0..2 {
            if let Err(error) = validate_input(scenario, seed.pair.class(class)) {
                panic!(
                    "{scenario}: seed {} class {class} is invalid: {error}",
                    seed.name
                );
            }
        }
    }
    seeds
}

pub fn diagnostic_order(scenario: Scenario) -> Vec<String> {
    match scenario {
        Scenario::DrbgControlled { .. } => drbg::diagnostic_order(scenario),
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            p521::DIAGNOSTIC_SEED_ORDER
                .iter()
                .map(|s| s.to_string())
                .collect()
        }
        _ => scenario_seeds(scenario, 0, 0)
            .into_iter()
            .filter(|s| s.kind == SeedKind::Boundary)
            .map(|s| s.name)
            .collect(),
    }
}

pub fn boundary_mutation(
    scenario: Scenario,
    op: usize,
    r: u64,
    current: &[u8],
    other: &[u8],
) -> Vec<u8> {
    match scenario {
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            let current: [u8; crate::scalar::SCALAR_BYTES] = current.try_into().expect("width");
            let other: [u8; crate::scalar::SCALAR_BYTES] = other.try_into().expect("width");
            boundary_scalar(op, r, &current, &other).to_vec()
        }
        Scenario::Ecdh(_)
        | Scenario::EccSign(..)
        | Scenario::RsaDecrypt(..)
        | Scenario::RsaSign(..)
        | Scenario::SaltedSession(_) => asym::boundary(scenario, op, r, current, other),
        Scenario::Sym(..) | Scenario::SymPartial(..) => {
            sym::boundary(scenario, op, r, current, other)
        }
        Scenario::DrbgControlled { .. } => drbg::boundary(op, r, current, other),
        _ => family::generic_byte_boundary(op, r, current, other),
    }
}

fn build(scenario: Scenario, pair: &InputPair) -> Result<family::Built, String> {
    match scenario {
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            p521::build(scenario, pair)
        }
        Scenario::TpmControlPositive | Scenario::TpmControlNegative => {
            controls::build(scenario, pair)
        }
        Scenario::Ecdh(_)
        | Scenario::EccSign(..)
        | Scenario::RsaDecrypt(..)
        | Scenario::RsaSign(..)
        | Scenario::SaltedSession(_) => asym::build(scenario, pair),
        Scenario::EccDecrypt(..) | Scenario::Ecdaa(_) | Scenario::Zgen(..) => {
            ecc::build(scenario, pair)
        }
        Scenario::Sym(..) | Scenario::SymPartial(..) => sym::build(scenario, pair),
        Scenario::Hmac(_)
        | Scenario::Cmac(_)
        | Scenario::HmacVerify(_)
        | Scenario::HmacSequence(_)
        | Scenario::CmacSequence(_)
        | Scenario::MacLongKey(..) => mac::build(scenario, pair),
        Scenario::ActivateCredential(_)
        | Scenario::LoadIntegrity(_)
        | Scenario::SignTicket
        | Scenario::PasswordAuth => integrity::build(scenario, pair),
        Scenario::HmacAuth(..)
        | Scenario::HmacAuthBound(..)
        | Scenario::HmacAuthSalted
        | Scenario::HmacAuthRequest(..)
        | Scenario::HmacAuthBoundSecret(..)
        | Scenario::HmacAuthSaltedSecret
        | Scenario::HmacAuthRequestSecret(..)
        | Scenario::Import(..)
        | Scenario::Duplicate(..)
        | Scenario::Rewrap(..) => remaining_auth::build(scenario, pair),
        Scenario::KeygenPrimary(_) => keygen::build(scenario, pair),
        Scenario::DrbgControlled { .. } => drbg::build(scenario, pair),
        Scenario::DrbgGenerate | Scenario::DrbgStir => random::build(scenario, pair),
    }
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    match scenario {
        Scenario::EcdhP521 | Scenario::ControlPositive | Scenario::ControlNegative => {
            p521::doc(scenario)
        }
        Scenario::TpmControlPositive | Scenario::TpmControlNegative => controls::doc(scenario),
        Scenario::Ecdh(_)
        | Scenario::EccSign(..)
        | Scenario::RsaDecrypt(..)
        | Scenario::RsaSign(..)
        | Scenario::SaltedSession(_) => asym::doc(scenario),
        Scenario::EccDecrypt(..) | Scenario::Ecdaa(_) | Scenario::Zgen(..) => ecc::doc(scenario),
        Scenario::Sym(..) | Scenario::SymPartial(..) => sym::doc(scenario),
        Scenario::Hmac(_)
        | Scenario::Cmac(_)
        | Scenario::HmacVerify(_)
        | Scenario::HmacSequence(_)
        | Scenario::CmacSequence(_)
        | Scenario::MacLongKey(..) => mac::doc(scenario),
        Scenario::ActivateCredential(_)
        | Scenario::LoadIntegrity(_)
        | Scenario::SignTicket
        | Scenario::PasswordAuth => integrity::doc(scenario),
        Scenario::HmacAuth(..)
        | Scenario::HmacAuthBound(..)
        | Scenario::HmacAuthSalted
        | Scenario::HmacAuthRequest(..)
        | Scenario::HmacAuthBoundSecret(..)
        | Scenario::HmacAuthSaltedSecret
        | Scenario::HmacAuthRequestSecret(..)
        | Scenario::Import(..)
        | Scenario::Duplicate(..)
        | Scenario::Rewrap(..) => remaining_auth::doc(scenario),
        Scenario::KeygenPrimary(_) => keygen::doc(scenario),
        Scenario::DrbgControlled { .. } => drbg::doc(scenario),
        Scenario::DrbgGenerate | Scenario::DrbgStir => random::doc(scenario),
    }
}

#[cfg(test)]
mod program_metadata_tests {
    use super::*;
    use crate::{
        oracle::hash::HashAlg,
        program::{Contract, Program, Step as ProgramStep},
        tpm,
    };
    #[test]
    fn padded_programs_keep_semantic_error_and_response_length_classification() {
        let scenario = Scenario::Hmac(HashAlg::Sha256);
        let pair = scenario_seeds(scenario, 1, 0).remove(0).pair;
        for (response, expected_difference, outcome_step) in [
            (
                vec![0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x43],
                DifferenceKind::VisibleOutcome,
                None,
            ),
            (
                tpm::success_response(&[], &[1, 2, 3], 0),
                DifferenceKind::OutputSize,
                None,
            ),
            (
                tpm::success_response(&[], &[1, 2, 3], 0),
                DifferenceKind::OutputSize,
                Some(0),
            ),
        ] {
            let mut built = build(scenario, &pair).unwrap();
            for (class, expected) in [tpm::success_response(&[], &[], 0), response]
                .into_iter()
                .enumerate()
            {
                let mut step = ProgramStep::new(tpm::startup_clear(), Contract::exact(expected, 0));
                step.slot = 64;
                let mut program = Program {
                    outcome_step,
                    steps: vec![step],
                };
                if outcome_step.is_some() {
                    program.steps.push(ProgramStep::new(
                        tpm::startup_clear(),
                        Contract::exact(tpm::success_response(&[], &[], 0), 0),
                    ));
                }
                let encoded = program.encode().unwrap();
                let (expected, mask) = program.expectation().unwrap();
                built.classes[class].measured = Step::new("program", encoded.bytes);
                built.classes[class].expected = expected;
                built.classes[class].mask = mask;
                built.classes[class].check = Some(Check::Program { program });
            }
            let prepared = PreparedPair::from_built(scenario, pair.clone(), built).unwrap();
            assert_eq!(
                prepared.classes[0].expected_response.len(),
                prepared.classes[1].expected_response.len()
            );
            assert_eq!(
                prepared.metadata.difference, expected_difference,
                "padded outer responses must not erase visible outcomes"
            );
        }
    }
}
