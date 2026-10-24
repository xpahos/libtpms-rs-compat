//! Named timing exclusions shared by LibAFL search and dudect verification.

use serde::{Deserialize, Serialize};

use crate::scalar::{Scalar521, ScalarPair, order_minus};
use crate::scenario::Scenario;
use crate::worker::WorkerInfo;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnownIssue {
    pub id: String,
    pub reason: String,
}

/// Match inputs and the observed backend, never a candidate's mutable label.
pub fn timing_skip(
    scenario: Scenario,
    pair: ScalarPair,
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
    if pair.unordered_key() != endpoints {
        return None;
    }
    Some(KnownIssue {
        id: "openssl-p521-one-vs-order-minus-one".into(),
        reason: "Known timing difference for P-521 scalars 1 and n-1 in the C reference with OpenSSL 3.0.13: the explicit-curve ladder_post takes the s->Z == 0 shortcut for n-1 and skips field inversion. Confirmed on the VM on 2026-10-24; timing only, not a functional failure. Use --disable-known-case-skips to retest.".into(),
    })
}
