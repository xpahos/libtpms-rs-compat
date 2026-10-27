use super::catalog::Scenario;
use super::family::{Built, COMMAND_LEVEL, ClassSpec, ScenarioDoc, random_seeds, seed};
use super::layout::{Creates, HandleRef, Step};
use super::sym::{encrypt_decrypt2, encrypt_decrypt2_expected, symcipher_load};
use super::{InputPair, Seed};
use crate::oracle::hash::HashAlg;
use crate::oracle::sym::{SymKey, SymMode};

pub const INPUT_BYTES: usize = 16;
pub const DATA_BYTES: usize = 1024;

fn key(spec: SymKey) -> Vec<u8> {
    HashAlg::Sha256.digest(&[b"tpms-timing-tests control key", spec.name().as_bytes()])
        [..spec.key_bytes()]
        .to_vec()
}

fn data(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < DATA_BYTES {
        out.extend(HashAlg::Sha256.digest(&[input, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(DATA_BYTES);
    out
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let mut out = vec![seed(
        "zero-vs-ones",
        vec![0; INPUT_BYTES],
        vec![0xff; INPUT_BYTES],
    )];
    out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
        rng.bytes(INPUT_BYTES)
    }));
    out
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let fast = SymKey::Aes128;
    let slow = SymKey::Tdes192;
    let positive = scenario == Scenario::TpmControlPositive;
    let fixed = data(b"tpms-timing-tests negative control");
    let class = |index: usize, input: &[u8]| {
        let spec_key = if positive && index == 1 { slow } else { fast };
        let payload = if positive { data(input) } else { fixed.clone() };
        let mut step = encrypt_decrypt2(spec_key, SymMode::Ecb, false, &payload);
        step.handles = vec![(10, HandleRef::Shared(if positive { index } else { 0 }))];
        ClassSpec::new(
            step,
            encrypt_decrypt2_expected(spec_key, SymMode::Ecb, false, &key(spec_key), &payload),
        )
    };
    let mut shared = vec![
        Step::new("LoadExternal AES-128", symcipher_load(fast, &key(fast)))
            .creates(Creates::Object),
    ];
    if positive {
        shared.push(
            Step::new("LoadExternal TDES-192", symcipher_load(slow, &key(slow)))
                .creates(Creates::Object),
        );
    }
    Ok(Built {
        shared,
        classes: [class(0, &pair.a), class(1, &pair.b)],
        model: super::family::PairModel::default(),
        varying_public_values: if positive {
            vec![
                "cipher: class 0 AES-128, class 1 TDES-192 (explicitly different operations)"
                    .into(),
            ]
        } else {
            vec!["none: both classes send the identical command".into()]
        },
    })
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    let positive = scenario == Scenario::TpmControlPositive;
    ScenarioDoc {
        harness: COMMAND_LEVEL.into(),
        entry_point: "TPM2_EncryptDecrypt2 ECB encryption of 1 KiB through the same worker, ABI and dudect path as every other scenario".into(),
        secret: "none (control)".into(),
        attacker_inputs: "16 bytes expanded into the data (positive control only)".into(),
        observable_outputs: "ciphertext".into(),
        classes: if positive { "class 0 encrypts with AES-128, class 1 with TDES-192: different work by construction".into() } else { "both classes send the byte-identical AES-128 command on the same key".into() },
        fixed: "data length, mode, keys".into(),
        timed_region: "one TPMLIB_Process call of EncryptDecrypt2".into(),
        correctness: "ciphertext computed with RustCrypto; exact response match".into(),
        interpretation: if positive { "must be detected as a reproducible signal on every backend; otherwise the command-level pipeline is not sensitive on this host".into() } else { "must not be reported as a reproducible signal; a signal would be a pipeline or ordering artefact".into() },
        randomized: false,
    }
}
