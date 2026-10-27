//! Named timing exclusions shared by LibAFL search and dudect verification.

use serde::{Deserialize, Serialize};

use crate::scalar::{Scalar521, order_minus};
use crate::scenario::{InputPair, Scenario};
use crate::worker::WorkerInfo;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KnownIssueKind {
    #[default]
    Timing,
    FunctionalFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownIssue {
    #[serde(default)]
    pub kind: KnownIssueKind,
    pub id: String,
    pub reason: String,
}

/// Match inputs and the observed backend, never a candidate's mutable label.
pub fn timing_skip(
    scenario: Scenario,
    pair: impl Into<InputPair>,
    backend: &str,
    info: &WorkerInfo,
) -> Option<KnownIssue> {
    if scenario != Scenario::EcdhP521 || backend != "reference" {
        return None;
    }
    // Keep the exclusion limited to the version tested on the C reference backend.
    if info.get("openssl_version").map(String::as_str) != Some("OpenSSL 3.0.13 30 Jan 2024") {
        return None;
    }
    let endpoints = (
        Scalar521::from_u128(1).expect("one is a valid scalar"),
        Scalar521::new(order_minus(1)).expect("n-1 is a valid scalar"),
    );
    let pair = pair.into().as_scalar_pair()?;
    if pair.unordered_key() != endpoints {
        return None;
    }
    Some(KnownIssue {
        kind: KnownIssueKind::Timing,
        id: "openssl-p521-one-vs-order-minus-one".into(),
        reason: "Known timing difference for P-521 scalars 1 and n-1 in the C reference with OpenSSL 3.0.13: the explicit-curve ladder_post takes the s->Z == 0 shortcut for n-1 and skips field inversion. Confirmed on the VM on 2026-10-24; timing only, not a functional failure. Use --disable-known-case-skips to retest.".into(),
    })
}

/// Functional exclusions precede any TPM command. Opt-out must use a disposable worker.
pub fn functional_skip(scenario: Scenario, backend: &str) -> Option<KnownIssue> {
    use crate::scenario::catalog::ExchangeScheme;
    if matches!(scenario, Scenario::Zgen(_, ExchangeScheme::Ecmqv))
        && matches!(backend, "rust" | "reference")
    {
        Some(KnownIssue {
            kind: KnownIssueKind::FunctionalFailure,
            id:"ecmqv-uninitialized-order-failure-mode".into(),
            reason:"Pinned ECMQV is a known functional failure: C C_2_2_MQV uses an uninitialized order (and peer x), causing divide-by-zero; Rust preserves failure mode. No functional pass or timing result. --disable-known-case-skips runs an isolated functional probe and reports failure, discarding its worker.".into(),
        })
    } else if backend == "reference"
        && matches!(
            scenario,
            Scenario::Zgen(
                crate::oracle::ec::CurveId::NistP521 | crate::oracle::ec::CurveId::BnP638,
                ExchangeScheme::Sm2
            )
        )
    {
        Some(KnownIssue {
            kind: KnownIssueKind::FunctionalFailure,
            id:"reference-sm2-large-curve-product-overflow".into(),
            reason:"Native-reproduced on the pinned 64-bit default-v1 C reference (2026-10-25): P521 and BN638 SM2KeyExchange multiply the fresh scalar by its associated value into CRYPT_ECC_NUM(Ta) before reduction. MAX_ECC_KEY_BITS=638 gives 704 allocated bits including the spare word; typical products need about 838/897 bits, so BnFromBytes:90 asserts and enters TPM failure mode (0x101). Rust uses modular arithmetic and remains enabled. No timing claim; --disable-known-case-skips uses a disposable functional probe.".into(),
        })
    } else {
        None
    }
}
