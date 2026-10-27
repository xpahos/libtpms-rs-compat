use super::catalog::Scenario;
use super::family::{Built, ClassSpec, PairModel, ScenarioDoc, random_seeds, seed};
use super::layout::Step;
use super::{InputPair, Seed};
use crate::oracle::drbg::{self, INPUT_BYTES, Input, RESEED_INTERVAL};

pub fn input_width(_: Scenario) -> usize {
    INPUT_BYTES
}

fn settings(scenario: Scenario) -> (bool, bool) {
    match scenario {
        Scenario::DrbgControlled { reseed, continuous } => (reseed, continuous),
        _ => unreachable!("controlled DRBG dispatch"),
    }
}

pub fn validate(scenario: Scenario, bytes: &[u8]) -> Result<(), String> {
    let input = Input::decode(bytes)?;
    let (reseed, continuous) = settings(scenario);
    if input.continuous != continuous {
        return Err("continuous-test flag differs from scenario configuration".into());
    }
    let allowed = if reseed {
        (RESEED_INTERVAL - 1..=RESEED_INTERVAL + 7).contains(&input.counter)
    } else {
        input.counter < RESEED_INTERVAL
    };
    if !allowed {
        return Err("counter is outside this scenario's generation/reseed range".into());
    }
    // Reject rare repeated-block states before they can poison a worker. The
    // continuous-test failure path is not part of this success-only experiment.
    drbg::generate(&input).map(|_| ())
}

fn baseline(scenario: Scenario) -> Input {
    let (reseed, continuous) = settings(scenario);
    Input {
        seed: std::array::from_fn(|i| i as u8),
        counter: if reseed { RESEED_INTERVAL } else { 1 },
        last_value: [0x5a; 16],
        entropy: std::array::from_fn(|i| (i as u8).wrapping_add(48) ^ 0x63),
        continuous,
        requested: 32,
    }
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let base = baseline(scenario);
    let (reseed, continuous) = settings(scenario);
    let mut out = vec![seed("same-state", base.encode(), base.encode())];
    // Keep the reproduced pairs and their matched controls in the ordinary
    // corpus; timing findings remain measurements, never implicit skips.
    let mut a = base.clone();
    let mut b = base.clone();
    if reseed {
        a.seed[..32].fill(0);
        b.seed[..32].fill(0xff);
        out.push(seed("same-zero-key", a.encode(), a.encode()));
        out.push(seed("same-ones-key", b.encode(), b.encode()));
    } else {
        a.requested = 15;
        b.requested = 15;
        a.seed.fill(0);
        b.seed.fill(0xff);
        out.push(seed("same-zero-state-length-15", a.encode(), a.encode()));
        out.push(seed("same-ones-state-length-15", b.encode(), b.encode()));
        for (name, range) in [
            ("secret-key-length-15", 0..32),
            ("secret-v-length-15", 32..48),
        ] {
            let mut b = a.clone();
            b.seed[range].fill(0xff);
            out.push(seed(name, a.encode(), b.encode()));
        }
    }
    for (name, range) in [("key", 0..32), ("v", 32..48), ("key-and-v", 0..48)] {
        let mut a = base.clone();
        let mut b = base.clone();
        a.seed[range.clone()].fill(0);
        b.seed[range].fill(0xff);
        out.push(seed(format!("{name}-zero-vs-ones"), a.encode(), b.encode()));
    }
    for carry in [1usize, 2, 4, 8, 12, 15, 16] {
        let mut a = base.clone();
        let mut b = base.clone();
        a.seed[32..].fill(0);
        b.seed[32..].fill(0);
        b.seed[48 - carry..].fill(0xff);
        out.push(seed(
            format!("v-carry-{carry}-bytes"),
            a.encode(),
            b.encode(),
        ));
    }
    for requested in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64] {
        let mut a = base.clone();
        let mut b = base.clone();
        a.requested = requested;
        b.requested = requested;
        a.seed.fill(0);
        b.seed.fill(0xff);
        out.push(seed(
            format!("secret-state-length-{requested}"),
            a.encode(),
            b.encode(),
        ));
    }
    for counter in if reseed {
        vec![RESEED_INTERVAL, RESEED_INTERVAL + 1, RESEED_INTERVAL + 7]
    } else {
        vec![2, RESEED_INTERVAL - 2, RESEED_INTERVAL - 1]
    } {
        let mut a = base.clone();
        let mut b = base.clone();
        a.counter = counter;
        b.counter = counter;
        b.seed[..32].fill(0xff);
        out.push(seed(
            format!("secret-key-counter-{counter}"),
            a.encode(),
            b.encode(),
        ));
    }
    if reseed {
        let mut a = base.clone();
        let mut b = base.clone();
        a.entropy.fill(0);
        b.entropy.fill(0xff);
        out.push(seed("entropy-zero-vs-ones", a.encode(), b.encode()));
        for requested in [0, 16] {
            let mut a = base.clone();
            let mut b = base.clone();
            a.counter = RESEED_INTERVAL - 1;
            a.requested = requested;
            b.requested = requested;
            out.push(seed(
                format!("public-reseed-threshold-length-{requested}"),
                a.encode(),
                b.encode(),
            ));
        }
    }
    if continuous {
        let first = drbg::first_block(&base.seed);
        for prefix in [0usize, 4, 8, 12, 15] {
            let mut a = base.clone();
            let mut b = base.clone();
            // Both differ from the first generated block, but B shares a
            // selected prefix. This exercises comparison work without failure.
            a.last_value = first.map(|b| b ^ 0xff);
            b.last_value = first;
            b.last_value[prefix..].iter_mut().for_each(|b| *b ^= 0xff);
            out.push(seed(
                format!("last-value-prefix-{prefix}"),
                a.encode(),
                b.encode(),
            ));
        }
    }
    let mut b = base.clone();
    b.requested = 1;
    out.push(seed("public-length-32-vs-1", base.encode(), b.encode()));
    let mut b = base.clone();
    b.counter += 1;
    out.push(seed("public-counter", base.encode(), b.encode()));
    out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
        let mut input = base.clone();
        input.seed.copy_from_slice(&rng.bytes(48));
        if continuous {
            input.last_value.copy_from_slice(&rng.bytes(16));
        }
        if reseed {
            input.entropy.copy_from_slice(&rng.bytes(48));
        }
        input.encode()
    }));
    out
}

pub fn diagnostic_order(scenario: Scenario) -> Vec<String> {
    let preferred = if settings(scenario).0 {
        [
            "same-zero-key",
            "same-ones-key",
            "key-zero-vs-ones",
            "entropy-zero-vs-ones",
        ]
    } else {
        [
            "same-zero-state-length-15",
            "same-ones-state-length-15",
            "secret-state-length-15",
            "secret-v-length-15",
        ]
    };
    preferred
        .iter()
        .map(|name| (*name).to_owned())
        .chain(
            seeds(scenario, 0, 0)
                .into_iter()
                .filter(|seed| !preferred.contains(&seed.name.as_str()))
                .map(|seed| seed.name),
        )
        .collect()
}

pub fn boundary(op: usize, r: u64, current: &[u8], other: &[u8]) -> Vec<u8> {
    let mut out = current.to_vec();
    // Keep counter, length, mode and the selected reseed branch unchanged.
    let range = match op % 4 {
        0 => 0..32,
        1 => 32..48,
        2 if current[120] == 1 => 56..72,
        _ if u64::from_be_bytes(current[48..56].try_into().unwrap()) >= RESEED_INTERVAL => 72..120,
        _ => 0..48,
    };
    let changed = super::family::generic_byte_boundary(
        op / 4,
        r,
        &current[range.clone()],
        &other[range.clone()],
    );
    out[range].copy_from_slice(&changed);
    // Havoc applies several mutations before ValidPairMutator validates the
    // result, so earlier byte mutations may have invalidated public fields.
    if Input::decode(&out)
        .and_then(|input| drbg::generate(&input))
        .is_err()
    {
        return current.to_vec();
    }
    out
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let a = Input::decode(&pair.a)?;
    let b = Input::decode(&pair.b)?;
    let class = |input: &Input| -> Result<ClassSpec, String> {
        let mut command = drbg::MAGIC.to_vec();
        command.extend(input.encode());
        Ok(ClassSpec::new(
            Step::new("controlled DRBG generate", command),
            drbg::generate(input)?.response(),
        ))
    };
    let entropy_used = a.counter >= RESEED_INTERVAL || b.counter >= RESEED_INTERVAL;
    let model = PairModel::secret(
        a.seed != b.seed
            || (a.continuous && a.last_value != b.last_value)
            || (entropy_used && a.entropy != b.entropy),
    )
    .public("requested byte count", a.requested != b.requested)
    .public(
        "reseed counter and automatic-reseed branch",
        a.counter != b.counter,
    )
    .confounder(
        !a.continuous && a.last_value != b.last_value,
        "inactive continuous-test state differs in adapter restore/serialization",
    )
    .confounder(
        !entropy_used && a.entropy != b.entropy,
        "unused entropy payload differs in the instrumented adapter",
    );
    let _ = settings(scenario);
    Ok(Built {
        shared: Vec::new(),
        classes: [class(&a)?, class(&b)?],
        varying_public_values: model.public_differences.clone(),
        model,
    })
}

pub fn doc(_: Scenario) -> ScenarioDoc {
    ScenarioDoc {
        harness: "isolated instrumented-library DRBG adapter; requires timing-test-hooks builds".into(),
        entry_point: "TPMS_TIMING_DRBG_v1 -> production generate/default-state automatic reseed path".into(),
        secret: "class-selected AES-256 key, V, continuous-test last value and reseed entropy".into(),
        attacker_inputs: "public requested length and reseed counter; continuous-test mode fixed by scenario".into(),
        observable_outputs: "synthetic exact response: generated bytes, final seed/counter/last value, entropy draw count".into(),
        classes: "key/V/carry-chain, entropy and continuous-comparison prefix sweeps; equal-state controls; explicitly public length/counter diagnostics".into(),
        fixed: "every invocation restores its complete starting state; secret pairs have equal counter, length and continuous mode".into(),
        timed_region: "fixed-size state restore + production DRBG generate/automatic reseed + state serialization inside the timed adapter; not primitive-only timing".into(),
        correctness: "every response byte checked against an independent AES model anchored to C-generated vectors; no masked bytes".into(),
        interpretation: "secret-only comparisons isolate controlled state within this instrumented adapter, including restore and serialization; length/counter differences are public confounders, and same-state pairs are measurement controls; this is not a claim about observable production ABI state disclosure".into(),
        randomized: false,
    }
}
