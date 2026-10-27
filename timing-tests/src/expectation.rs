//! RSAES contracts are selected by exact, fixed TPM capability probes, never fuzz output.
use crate::{
    identity,
    measure::{LoadOrder, Measurer, WorkerMeasurer},
    oracle::rsa::RsaBits,
    scenario::{InputPair, PreparedPair, RsaPadding, Scenario},
    worker::BackendSpec,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RsaesProfile {
    ExplicitValue,
    OpenSslImplicitV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeVector {
    pub scenario: Scenario,
    pub input: String,
    pub explicit_response: String,
    pub implicit_response: String,
    pub observed_response: String,
}

/// Recorded evidence. Deserialization does not grant authority to select a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaesEvidence {
    pub contract: RsaesProfile,
    pub contract_version: u32,
    pub private_exponent_rule: String,
    pub backend: String,
    pub library_sha256: String,
    pub openssl: identity::OpensslObservation,
    pub worker_info: crate::worker::WorkerInfo,
    pub probe_sha256: String,
    pub vectors: Vec<ProbeVector>,
}

impl RsaesEvidence {
    /// A serialized record is provenance, never authority: its own probe vectors must
    /// still select the contract it claims. A forged or edited record fails this check.
    pub fn consistent(&self) -> bool {
        select(&self.vectors).is_ok_and(|contract| contract == self.contract)
    }
}

// ---------------------------------------------------------------------------
// Symmetric CFB chaining contracts (partial final blocks)
// ---------------------------------------------------------------------------

/// Recorded evidence for a backend's CFB chaining contract: the ivOut suffix
/// after a partial final block is zeroed (this repository's Rust port) or the
/// unused encrypted-feedback suffix is retained (the OpenSSL-backed C
/// reference). As with RSAES, a serialized record is provenance, never
/// authority: its own probe vectors must still select the claimed contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymChainingEvidence {
    pub contract: crate::oracle::sym::ChainingContract,
    pub contract_version: u32,
    pub backend: String,
    pub library_sha256: String,
    pub openssl: identity::OpensslObservation,
    pub worker_info: crate::worker::WorkerInfo,
    pub probe_sha256: String,
    pub vectors: Vec<SymProbeVector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymProbeVector {
    pub scenario: Scenario,
    pub input: String,
    pub zero_suffix_response: String,
    pub retained_suffix_response: String,
    pub observed_response: String,
}

impl SymChainingEvidence {
    pub fn consistent(&self) -> bool {
        crate::scenario::sym_chaining_select(&self.vectors)
            .is_ok_and(|contract| contract == self.contract)
    }
}

pub fn is_partial_cfb(scenario: Scenario) -> bool {
    matches!(
        scenario,
        Scenario::SymPartial(_, crate::oracle::sym::SymMode::Cfb, _)
    )
}

pub(crate) fn chaining_probe(
    measurer: &mut WorkerMeasurer,
    scenario: Scenario,
    backend: &BackendSpec,
) -> Result<SymChainingEvidence, String> {
    let BackendSpec::Library { path, .. } = backend else {
        return Err("CFB chaining probes need a library backend".into());
    };
    if !is_partial_cfb(scenario) {
        return Err("CFB chaining probes need a partial CFB scenario".into());
    }
    let library = identity::library_identity(path).map_err(|e| e.to_string())?;
    let pair = crate::scenario::sym_chaining_probe_pair(scenario)?;
    let zero = PreparedPair::try_prepare_chaining(
        scenario,
        pair.clone(),
        crate::oracle::sym::ChainingContract::ZeroSuffix,
    )?;
    let retained = PreparedPair::try_prepare_chaining(
        scenario,
        pair.clone(),
        crate::oracle::sym::ChainingContract::RetainedSuffix,
    )?;
    if zero.classes[0].expected_response == retained.classes[0].expected_response {
        return Err(format!(
            "{scenario}: the fixed chaining probe did not produce contract-distinct expectations"
        ));
    }
    let loaded = measurer
        .load(&zero, LoadOrder::ClassAFirst)
        .map_err(|e| e.to_string())?;
    let responses = measurer.execute_once(&loaded).map_err(|e| e.to_string())?;
    let vectors: Vec<SymProbeVector> = responses
        .iter()
        .map(|response| SymProbeVector {
            scenario,
            input: hex::encode(&pair.a),
            zero_suffix_response: hex::encode(&zero.classes[0].expected_response),
            retained_suffix_response: hex::encode(&retained.classes[0].expected_response),
            observed_response: hex::encode(response),
        })
        .collect();
    let contract = crate::scenario::sym_chaining_select(&vectors)
        .map_err(|e| format!("CFB chaining probes: {e}"))?;
    let info = measurer.info();
    let openssl = identity::observe_openssl(&backend.label(), &info);
    if openssl.libcrypto_sha256.is_none() {
        return Err("CFB chaining backend has no identifiable loaded libcrypto".into());
    }
    let probe_sha256 =
        identity::sha256_bytes(&serde_json::to_vec(&vectors).map_err(|e| e.to_string())?);
    Ok(SymChainingEvidence {
        contract,
        contract_version: 1,
        backend: backend.label(),
        library_sha256: library.sha256,
        openssl,
        worker_info: info,
        probe_sha256,
        vectors,
    })
}

/// Fields shared by every per-backend contract record, so replay can compare
/// recorded provenance against a fresh probe of the *same* backend generically.
pub trait ContractRecord {
    fn contract_kind(&self) -> &'static str;
    fn contract_label(&self) -> String;
    fn record_consistent(&self) -> bool;
    fn backend_label(&self) -> &str;
    fn library_sha256(&self) -> &str;
    fn libcrypto_sha256(&self) -> &Option<String>;
    fn openssl_version(&self) -> &str;
    fn probe_sha256(&self) -> &str;
}

impl ContractRecord for RsaesEvidence {
    fn contract_kind(&self) -> &'static str {
        "RSAES profile"
    }
    fn contract_label(&self) -> String {
        format!("{:?}", self.contract)
    }
    fn record_consistent(&self) -> bool {
        RsaesEvidence::consistent(self)
    }
    fn backend_label(&self) -> &str {
        &self.backend
    }
    fn library_sha256(&self) -> &str {
        &self.library_sha256
    }
    fn libcrypto_sha256(&self) -> &Option<String> {
        &self.openssl.libcrypto_sha256
    }
    fn openssl_version(&self) -> &str {
        &self.openssl.openssl_version
    }
    fn probe_sha256(&self) -> &str {
        &self.probe_sha256
    }
}

impl ContractRecord for SymChainingEvidence {
    fn contract_kind(&self) -> &'static str {
        "CFB chaining"
    }
    fn contract_label(&self) -> String {
        format!("{:?}", self.contract)
    }
    fn record_consistent(&self) -> bool {
        SymChainingEvidence::consistent(self)
    }
    fn backend_label(&self) -> &str {
        &self.backend
    }
    fn library_sha256(&self) -> &str {
        &self.library_sha256
    }
    fn libcrypto_sha256(&self) -> &Option<String> {
        &self.openssl.libcrypto_sha256
    }
    fn openssl_version(&self) -> &str {
        &self.openssl.openssl_version
    }
    fn probe_sha256(&self) -> &str {
        &self.probe_sha256
    }
}

/// How a freshly probed backend differs from the identities recorded when the
/// candidate was produced. Provenance belonging to other backends is excluded:
/// each fresh backend is compared only against its own recorded evidence, and
/// missing provenance is reported separately from a real upgrade. Original
/// provenance is never rewritten; only labels are added.
pub fn identity_changes<R: ContractRecord>(
    recorded: &[&R],
    fresh: &R,
    backend: &str,
) -> Vec<String> {
    let recorded: Vec<&&R> = recorded
        .iter()
        .filter(|old| old.backend_label() == fresh.backend_label())
        .collect();
    if recorded.is_empty() {
        return vec![format!(
            "backend {backend}: no recorded {} provenance for this backend (missing provenance, new backend, or backend substitution); the {} contract was freshly probed",
            fresh.contract_kind(),
            fresh.contract_kind(),
        )];
    }
    let mut out = Vec::new();
    for (index, old) in recorded.iter().enumerate() {
        let at = format!("provenance record {index}");
        let kind = fresh.contract_kind();
        if !old.record_consistent() {
            out.push(format!(
                "{at}: forged or edited {} record (contract {} does not match its own probe vectors)",
                kind.to_ascii_lowercase(),
                old.contract_label()
            ));
        }
        if old.library_sha256() != fresh.library_sha256() {
            out.push(format!(
                "{at}: backend {backend} library sha256 changed {} -> {}",
                old.library_sha256(),
                fresh.library_sha256()
            ));
        }
        if old.libcrypto_sha256() != fresh.libcrypto_sha256() {
            out.push(format!(
                "{at}: backend {backend} libcrypto sha256 changed {:?} -> {:?}",
                old.libcrypto_sha256(),
                fresh.libcrypto_sha256()
            ));
        }
        if old.openssl_version() != fresh.openssl_version() {
            out.push(format!(
                "{at}: backend {backend} OpenSSL version changed {} -> {}",
                old.openssl_version(),
                fresh.openssl_version()
            ));
        }
        if old.probe_sha256() != fresh.probe_sha256() {
            out.push(format!(
                "{at}: backend {backend} {} probe changed {} -> {} (contract {} -> {})",
                kind.to_ascii_lowercase(),
                old.probe_sha256(),
                fresh.probe_sha256(),
                old.contract_label(),
                fresh.contract_label()
            ));
        }
    }
    out
}

pub fn is_rsaes(scenario: Scenario) -> bool {
    matches!(scenario, Scenario::RsaDecrypt(_, RsaPadding::Rsaes))
}

fn select(vectors: &[ProbeVector]) -> Result<RsaesProfile, String> {
    let explicit = vectors
        .iter()
        .all(|v| v.observed_response == v.explicit_response);
    let implicit = vectors
        .iter()
        .all(|v| v.observed_response == v.implicit_response);
    match (explicit, implicit) {
        (true, false) => Ok(RsaesProfile::ExplicitValue),
        (false, true) => Ok(RsaesProfile::OpenSslImplicitV1),
        _ => Err(
            "RSAES capability probes did not uniquely match a known independent contract".into(),
        ),
    }
}

pub(crate) fn probe(
    measurer: &mut WorkerMeasurer,
    backend: &BackendSpec,
) -> Result<RsaesEvidence, String> {
    let BackendSpec::Library { path, .. } = backend else {
        return Err("RSAES needs a library backend".into());
    };
    let library = identity::library_identity(path).map_err(|e| e.to_string())?;
    let mut vectors = Vec::new();
    // Fixed fixtures are independent of candidates, and exercise every imported exponent rule.
    for bits in RsaBits::ALL {
        let scenario = Scenario::RsaDecrypt(bits, RsaPadding::Rsaes);
        for kind in 0..5 {
            let mut input: Vec<u8> = (0..crate::scenario::input_width(scenario))
                .map(|i| (i * 17 + 29) as u8)
                .collect();
            input[0] = kind;
            let pair = InputPair::new(input.clone(), input.clone());
            let explicit = PreparedPair::try_prepare_profile(
                scenario,
                pair.clone(),
                RsaesProfile::ExplicitValue,
            )?;
            let implicit =
                PreparedPair::try_prepare_profile(scenario, pair, RsaesProfile::OpenSslImplicitV1)?;
            let loaded = measurer
                .load(&explicit, LoadOrder::ClassAFirst)
                .map_err(|e| e.to_string())?;
            let responses = measurer.execute_once(&loaded).map_err(|e| e.to_string())?;
            for response in responses {
                vectors.push(ProbeVector {
                    scenario,
                    input: hex::encode(&input),
                    explicit_response: hex::encode(&explicit.classes[0].expected_response),
                    implicit_response: hex::encode(&implicit.classes[0].expected_response),
                    observed_response: hex::encode(response),
                });
            }
        }
    }
    let contract = select(&vectors)?;
    let info = measurer.info();
    let openssl = identity::observe_openssl(&backend.label(), &info);
    if openssl.libcrypto_sha256.is_none() {
        return Err("RSAES backend has no identifiable loaded libcrypto".into());
    }
    let probe_sha256 =
        identity::sha256_bytes(&serde_json::to_vec(&vectors).map_err(|e| e.to_string())?);
    Ok(RsaesEvidence { contract, contract_version: 1, private_exponent_rule: "libtpms: Euler for <2048 bits or exponent <=16 bits; Carmichael otherwise, Euler fallback for short d".into(), backend: backend.label(), library_sha256: library.sha256, openssl, worker_info: info, probe_sha256, vectors })
}

/// Only malformed RSAES with independently validated, different known contracts may diverge.
/// Cross-backend response divergence is expected (and therefore not a
/// functional failure) only when every backend resolved an independently
/// validated contract, the resolved contracts differ, and the inputs put the
/// pair on exactly the path where the contracts disagree:
/// - malformed RSAES padding (explicit TPM_RC_VALUE vs OpenSSL implicit
///   rejection), or
/// - a partial final CFB block, where the Rust port zero-pads the returned
///   chaining value while the OpenSSL-backed reference retains the unused
///   encrypted-feedback suffix.
pub fn expected_divergence(
    scenario: Scenario,
    metadata: &[&crate::scenario::PublicMetadata],
) -> bool {
    if metadata.len() < 2 {
        return false;
    }
    if is_rsaes(scenario) {
        return metadata.iter().all(|m| m.rsaes_evidence.is_some())
            && metadata.windows(2).any(|m| {
                m[0].rsaes_evidence.as_ref().unwrap().contract
                    != m[1].rsaes_evidence.as_ref().unwrap().contract
            })
            && metadata.iter().any(|m| {
                m.expected_response_codes
                    .contains(&crate::tpm::TPM_RC_VALUE)
            });
    }
    if is_partial_cfb(scenario) {
        return metadata.iter().all(|m| m.sym_evidence.is_some())
            && metadata.windows(2).any(|m| {
                m[0].sym_evidence.as_ref().unwrap().contract
                    != m[1].sym_evidence.as_ref().unwrap().contract
            })
            // The classes transmit one data length; the chaining-value suffix
            // only differs when that length actually ends in a partial block.
            && metadata.iter().all(|m| m.sym_partial_chaining);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{DifferenceKind, Direction};
    #[test]
    fn capability_requires_complete_consistent_independent_responses() {
        let v = ProbeVector {
            scenario: Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes),
            input: "fixed".into(),
            explicit_response: "value".into(),
            implicit_response: "oracle".into(),
            observed_response: "oracle".into(),
        };
        assert_eq!(
            select(std::slice::from_ref(&v)).unwrap(),
            RsaesProfile::OpenSslImplicitV1
        );
        let mut bad = v.clone();
        bad.observed_response = "forged".into();
        assert!(select(&[v.clone(), bad]).is_err());
        let mut mixed = v.clone();
        mixed.observed_response = "value".into();
        assert!(select(&[v, mixed]).is_err());
        assert!(select(&[]).is_err());
    }

    fn probe_vector() -> ProbeVector {
        ProbeVector {
            scenario: Scenario::RsaDecrypt(RsaBits::B1024, RsaPadding::Rsaes),
            input: "00".into(),
            explicit_response: "08400001".into(),
            implicit_response: "00decafbad".into(),
            observed_response: "00decafbad".into(),
        }
    }

    fn record(contract: RsaesProfile, vectors: Vec<ProbeVector>) -> RsaesEvidence {
        RsaesEvidence {
            contract,
            contract_version: 1,
            private_exponent_rule: "test rule".into(),
            backend: "libtpms-fixture".into(),
            library_sha256: "aa".into(),
            openssl: identity::OpensslObservation {
                backend: "libtpms-fixture".into(),
                libcrypto_path: "libcrypto.so.3".into(),
                libcrypto_sha256: Some("bb".into()),
                openssl_version: "OpenSSL 3.0.13 30 Jan 2024".into(),
            },
            worker_info: Default::default(),
            probe_sha256: "cc".into(),
            vectors,
        }
    }

    #[test]
    fn a_forged_record_fails_its_own_consistency_check_even_with_a_valid_contract() {
        let honest = record(RsaesProfile::OpenSslImplicitV1, vec![probe_vector()]);
        assert!(honest.consistent());
        let forged_claim = record(RsaesProfile::ExplicitValue, vec![probe_vector()]);
        assert!(!forged_claim.consistent());
        let mut edited_vectors = honest.clone();
        edited_vectors.vectors[0].observed_response = "edited".into();
        assert!(!edited_vectors.consistent());
    }

    #[test]
    fn identity_changes_labels_every_backend_relevant_edit_and_nothing_else() {
        let old = record(RsaesProfile::OpenSslImplicitV1, vec![probe_vector()]);
        let mut fresh = old.clone();
        assert!(identity_changes(&[&old], &fresh, "libtpms-fixture").is_empty());

        fresh.library_sha256 = "changed".into();
        fresh.openssl.libcrypto_sha256 = Some("changed too".into());
        fresh.openssl.openssl_version = "OpenSSL 3.5.1".into();
        fresh.probe_sha256 = "changed as well".into();
        let labels = identity_changes(&[&old], &fresh, "libtpms-fixture");
        assert_eq!(labels.len(), 4, "{labels:?}");
        assert!(
            labels
                .iter()
                .any(|l| l.contains("library sha256 changed aa -> changed"))
        );
        assert!(
            labels
                .iter()
                .any(|l| l.contains("libcrypto sha256 changed"))
        );
        assert!(labels.iter().any(|l| l.contains("OpenSSL version changed")));
        assert!(
            labels
                .iter()
                .any(|l| l.contains("rsaes profile probe changed cc -> changed as well")),
            "{labels:?}"
        );

        let mut forged = old.clone();
        forged.contract = RsaesProfile::ExplicitValue;
        let labels = identity_changes(&[&forged], &old, "libtpms-fixture");
        assert!(
            labels
                .iter()
                .any(|l| l.contains("forged or edited rsaes profile record")),
            "{labels:?}"
        );
    }

    #[test]
    fn merged_provenance_of_two_unchanged_backends_reports_no_change_at_all() {
        // A candidate carrying both backends' provenance must not report upgrades
        // just because the *other* backend's record is present.
        let mut rust_record = record(RsaesProfile::OpenSslImplicitV1, vec![probe_vector()]);
        rust_record.backend = "rust".into();
        let mut reference_record = rust_record.clone();
        reference_record.backend = "reference".into();
        let fresh_rust = rust_record.clone();
        let fresh_reference = reference_record.clone();
        let recorded = vec![&rust_record, &reference_record];
        assert!(identity_changes(&recorded, &fresh_rust, "rust").is_empty());
        assert!(identity_changes(&recorded, &fresh_reference, "reference").is_empty(),);
    }

    #[test]
    fn missing_provenance_is_reported_separately_from_an_upgrade() {
        let mut rust_record = record(RsaesProfile::OpenSslImplicitV1, vec![probe_vector()]);
        rust_record.backend = "rust".into();
        let mut reference_fresh = rust_record.clone();
        reference_fresh.backend = "reference".into();
        // Backend substitution / new backend: no record of this backend exists.
        let labels = identity_changes(&[&rust_record], &reference_fresh, "reference");
        assert_eq!(labels.len(), 1, "{labels:?}");
        assert!(
            labels[0].contains("no recorded RSAES profile provenance for this backend"),
            "{labels:?}"
        );
        assert!(
            labels[0].contains("missing provenance, new backend, or backend substitution"),
            "{labels:?}"
        );
        // It must not be misreported as a library or contract upgrade.
        assert!(!labels[0].contains("sha256 changed"), "{labels:?}");
        assert!(!labels[0].contains("probe changed"), "{labels:?}");

        // A real upgrade of the same backend is still detected next to the
        // other backend's unchanged record.
        let mut upgraded = rust_record.clone();
        upgraded.library_sha256 = "new build".into();
        let labels = identity_changes(&[&rust_record, &reference_fresh], &upgraded, "rust");
        assert_eq!(labels.len(), 1, "{labels:?}");
        assert!(
            labels[0].contains("library sha256 changed aa -> new build"),
            "{labels:?}"
        );
    }

    #[test]
    fn inconsistent_recorded_evidence_is_labelled_and_never_selects_a_contract() {
        let mut rust_record = record(RsaesProfile::OpenSslImplicitV1, vec![probe_vector()]);
        rust_record.backend = "rust".into();
        let mut reference_record = rust_record.clone();
        // The reference record is forged: it claims a contract its own probe
        // vectors do not select.
        reference_record.contract = RsaesProfile::ExplicitValue;
        reference_record.backend = "reference".into();
        let fresh = reference_record.clone();
        let labels = identity_changes(&[&rust_record, &reference_record], &fresh, "reference");
        assert_eq!(labels.len(), 1, "{labels:?}");
        assert!(
            labels[0].contains("forged or edited rsaes profile record (contract ExplicitValue"),
            "{labels:?}"
        );
        assert!(!rust_record.backend.is_empty());
    }

    #[test]
    fn sym_chaining_evidence_selects_and_validates_its_own_contract() {
        let vector = SymProbeVector {
            scenario: Scenario::SymPartial(
                crate::oracle::sym::SymKey::Aes128,
                crate::oracle::sym::SymMode::Cfb,
                Direction::Decrypt,
            ),
            input: "00".into(),
            zero_suffix_response: "zero".into(),
            retained_suffix_response: "kept".into(),
            observed_response: "kept".into(),
        };
        let evidence = SymChainingEvidence {
            contract: crate::oracle::sym::ChainingContract::RetainedSuffix,
            contract_version: 1,
            backend: "reference".into(),
            library_sha256: "aa".into(),
            openssl: identity::OpensslObservation {
                backend: "reference".into(),
                libcrypto_path: "libcrypto.so.3".into(),
                libcrypto_sha256: Some("bb".into()),
                openssl_version: "OpenSSL 3.0.13 30 Jan 2024".into(),
            },
            worker_info: Default::default(),
            probe_sha256: "cc".into(),
            vectors: vec![vector.clone()],
        };
        assert!(evidence.consistent());
        // A forged claim about the contract fails its own consistency check.
        let mut forged = evidence.clone();
        forged.contract = crate::oracle::sym::ChainingContract::ZeroSuffix;
        assert!(!forged.consistent());
        // The select helper applies the same independence rule as RSAES.
        assert_eq!(
            crate::scenario::sym_chaining_select(std::slice::from_ref(&vector)).unwrap(),
            crate::oracle::sym::ChainingContract::RetainedSuffix
        );
        let mut ambiguous = vector.clone();
        ambiguous.zero_suffix_response = "kept".into();
        assert!(crate::scenario::sym_chaining_select(&[ambiguous]).is_err());
        assert!(crate::scenario::sym_chaining_select(&[]).is_err());
        // Per-backend identity comparison covers the chaining record too.
        let labels = identity_changes(&[&evidence], &evidence, "reference");
        assert!(labels.is_empty(), "{labels:?}");
        let mut upgraded = evidence.clone();
        upgraded.backend = "rust".into();
        let labels = identity_changes(&[&evidence], &upgraded, "rust");
        assert!(
            labels
                .iter()
                .any(|l| l.contains("no recorded CFB chaining provenance for this backend")),
            "{labels:?}"
        );
    }

    #[test]
    fn partial_cfb_divergence_is_expected_only_with_partial_lengths_and_differing_contracts() {
        use crate::oracle::sym::ChainingContract;
        use crate::scenario::PublicMetadata;
        let scenario = Scenario::SymPartial(
            crate::oracle::sym::SymKey::Aes128,
            crate::oracle::sym::SymMode::Cfb,
            Direction::Encrypt,
        );
        let mut meta = PublicMetadata {
            rsaes_evidence: None,
            sym_evidence: None,
            sym_partial_chaining: true,
            varying_public_values: Vec::new(),
            bit_length: [0, 0],
            leading_zero_bytes: [0, 0],
            hamming_weight: [0, 0],
            shared_x_leading_zero_bytes: [0, 0],
            public_x_leading_zero_bytes: [0, 0],
            expected_response_lengths: [10, 10],
            expected_response_min_lengths: [10, 10],
            expected_response_codes: [0, 0],
            expected_transport_response_lengths: [10, 10],
            difference: DifferenceKind::Identical,
            public_differences: Vec::new(),
            confounders: Vec::new(),
        };
        let references = [&meta];
        // Without any probed contract there is no divergence to expect.
        assert!(!expected_divergence(scenario, &references));
        for (backend, contract) in [
            ("rust", ChainingContract::ZeroSuffix),
            ("reference", ChainingContract::RetainedSuffix),
        ] {
            meta.sym_evidence = Some(SymChainingEvidence {
                contract,
                contract_version: 1,
                backend: backend.into(),
                library_sha256: "aa".into(),
                openssl: identity::OpensslObservation {
                    backend: backend.into(),
                    libcrypto_path: "l".into(),
                    libcrypto_sha256: Some("bb".into()),
                    openssl_version: "OpenSSL 3.0.13 30 Jan 2024".into(),
                },
                worker_info: Default::default(),
                probe_sha256: "cc".into(),
                vectors: Vec::new(),
            });
        }
        let _ = &meta.sym_evidence; // constructed with both backends below
        let mut rust_meta = meta.clone();
        rust_meta.sym_evidence.as_mut().unwrap().contract = ChainingContract::ZeroSuffix;
        assert!(expected_divergence(scenario, &[&rust_meta, &meta]));
        // An aligned final block: same input, no partial-block chaining suffix.
        rust_meta.sym_partial_chaining = false;
        meta.sym_partial_chaining = false;
        assert!(!expected_divergence(scenario, &[&rust_meta, &meta]));
        // The same resolved contract on every backend is not a divergence.
        rust_meta.sym_partial_chaining = true;
        meta.sym_partial_chaining = true;
        rust_meta.sym_evidence.as_mut().unwrap().contract =
            meta.sym_evidence.as_ref().unwrap().contract;
        assert!(!expected_divergence(scenario, &[&rust_meta, &meta]));
        // Non-CFB partial scenarios never expect divergence.
        assert!(!expected_divergence(
            Scenario::SymPartial(
                crate::oracle::sym::SymKey::Aes128,
                crate::oracle::sym::SymMode::Ctr,
                Direction::Encrypt
            ),
            &[&rust_meta, &meta]
        ));
    }
}
