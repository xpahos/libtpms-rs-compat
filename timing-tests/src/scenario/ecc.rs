use super::catalog::ExchangeScheme;
use super::family::{
    Built, COMMAND_LEVEL, Check, ClassSpec, PER_CLASS_KEYS, PER_CLASS_OBJECTS, PairModel,
    ScenarioDoc, random_seeds, seed,
};
use super::layout::{Creates, HandleRef, Step as LayoutStep};
use super::{InputPair, Scenario, Seed};
use crate::{
    oracle::{
        bytes::{from_be, to_fixed},
        ec::CurveId,
        ecc::{self, Oracle},
        hash::HashAlg,
    },
    program::{Contract, Patch, Program, Resource, ResponseArea, ResponseRange, Step},
    tpm::{self, Scheme},
};
use num_bigint::BigUint;

fn curve(s: Scenario) -> CurveId {
    match s {
        Scenario::EccDecrypt(c, _) | Scenario::Ecdaa(c) | Scenario::Zgen(c, _) => c,
        _ => unreachable!(),
    }
}
pub fn input_width(s: Scenario) -> usize {
    curve(s).key_bytes()
        + if matches!(s, Scenario::EccDecrypt(..)) {
            33
        } else {
            0
        }
}
pub fn validate(s: Scenario, bytes: &[u8]) -> Result<(), String> {
    let c = curve(s).curve();
    let d = if matches!(s, Scenario::EccDecrypt(..)) {
        if bytes[0] > 4 {
            return Err("ECC decrypt comparison selector".into());
        }
        &bytes[1..1 + c.bytes]
    } else {
        bytes
    };
    c.valid_scalar(d)
        .then_some(())
        .ok_or_else(|| "ECC scalar outside 1..n".into())
}
pub fn seeds(s: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let c = curve(s).curve();
    let scalar = |v: u32| to_fixed(&BigUint::from(v), c.bytes);
    let mut out = Vec::new();
    if matches!(s, Scenario::EccDecrypt(..)) {
        let input = |mode: u8, d: Vec<u8>, msg: u8| [vec![mode], d, vec![msg; 32]].concat();
        out.push(seed(
            "valid-vs-valid",
            input(0, scalar(2), 0x41),
            input(0, scalar(2), 0x42),
        ));
        for (label, a, b) in [
            ("valid-vs-first-c3", 0, 1),
            ("first-vs-last-c3", 1, 2),
            ("last-vs-whole-c3", 2, 3),
        ] {
            out.push(seed(
                label,
                input(a, scalar(2), 0x41),
                input(b, scalar(2), 0x41),
            ));
        }
        out.push(seed(
            "same-ciphertext-distinct-private-keys",
            input(4, scalar(2), 0x41),
            input(4, scalar(3), 0x41),
        ));
        out.push(seed(
            "valid-distinct-private-keys",
            input(0, scalar(2), 0x41),
            input(0, to_fixed(&(&c.n - 1u32), c.bytes), 0x41),
        ));
        out.extend(random_seeds(s, campaign_seed, random_pairs, |rng| {
            input(0, rng.below(&c.n, c.bytes), rng.next_u64() as u8)
        }));
    } else {
        out.push(seed("small-2-vs-small-3", scalar(2), scalar(3)));
        out.push(seed(
            "one-vs-order-minus-one",
            scalar(1),
            to_fixed(&(&c.n - 1u32), c.bytes),
        ));
        out.extend(random_seeds(s, campaign_seed, random_pairs, |rng| {
            rng.below(&c.n, c.bytes)
        }));
    }
    out
}
fn load(curve: CurveId, d: &[u8], sign: bool) -> LayoutStep {
    let attrs = tpm::ATTR_USER_WITH_AUTH
        | tpm::ATTR_NO_DA
        | if sign {
            tpm::ATTR_SIGN
        } else {
            tpm::ATTR_DECRYPT
        };
    let scheme = if sign {
        Scheme::Ecdaa {
            hash: tpm::TPM_ALG_SHA256,
            count: 0,
        }
    } else {
        Scheme::Null
    };
    LayoutStep::new(
        "LoadExternal ECC",
        super::asym::ecc_load(curve, attrs, scheme, d).0,
    )
    .creates(Creates::Object)
}
fn counter_patch(at: usize) -> Patch {
    Patch::Copy {
        at: at as u16,
        source: ResponseRange {
            step: 0,
            area: ResponseArea::ParametersTail,
            offset: 0,
            len: 2,
        },
        xor: vec![0; 2],
    }
}
fn masked_points(
    curve: CurveId,
    count: usize,
    empty_last: bool,
    counter: bool,
    sessions: usize,
) -> Contract {
    let c = curve.curve();
    let mut p = Vec::new();
    let mut ranges = Vec::new();
    let start = if sessions == 0 { 10 } else { 14 };
    for i in 0..count {
        if empty_last && i + 1 == count {
            p.extend([0, 4, 0, 0, 0, 0]);
            continue;
        }
        let at = p.len();
        p.extend(ecc::point_bytes(curve, &c.g));
        ranges.push(start + at + 4..start + at + 4 + c.bytes);
        ranges.push(start + at + 6 + c.bytes..start + at + 6 + 2 * c.bytes);
    }
    if counter {
        let at = p.len();
        p.extend([0, 0]);
        ranges.push(start + at..start + at + 2);
    }
    let mut contract = Contract::exact(tpm::success_response(&[], &p, sessions), 0);
    for range in ranges {
        contract.mask[range].fill(0);
    }
    contract
}
fn envelope(program: Program, oracle: Oracle, key_steps: &[usize]) -> Result<ClassSpec, String> {
    let encoded = program.encode()?;
    let (expected, mask) = program.expectation()?;
    let mut step = LayoutStep::new("fresh ECC producer + consumer", encoded.bytes);
    for index in key_steps {
        step = step.handle_at(encoded.command_offsets[*index] + 10, HandleRef::Class(0));
    }
    let mut spec = ClassSpec::new(step, expected);
    spec.mask = mask;
    spec.check = Some(Check::Ecc {
        oracle: Box::new(oracle),
        program,
    });
    Ok(spec)
}
fn ecdaa(curve: CurveId, d: &[u8]) -> Result<ClassSpec, String> {
    let c = curve.curve();
    let (s2, p2) = ecc::commit_point(curve);
    let mut params = ecc::point_bytes(curve, &c.g);
    params.extend(tpm::sized(s2));
    params.extend(tpm::sized(&to_fixed(&p2.y, c.bytes)));
    let mut commit = Step::new(
        tpm::build_command(0x18b, &[0], &[&[]], &params).bytes,
        masked_points(curve, 3, false, true, 1),
    );
    commit.produces = Resource::Counter;
    let digest = HashAlg::Sha256.digest(&[b"ECDAA timing digest v1"]);
    let mut params = tpm::sized(&digest);
    params.extend([0, 0x1a, 0, 0x0b]);
    let count = params.len();
    params.extend([0, 0]);
    params.extend(super::asym::null_ticket());
    let cmd = tpm::build_command(0x15d, &[0], &[&[]], &params);
    let at = cmd.bytes.len() - params.len() + count;
    // nonceK is minimally encoded; s is fixed width. The C worker checks nested fields.
    let mut sign = Step::new(
        cmd.bytes,
        Contract::bounded(
            0,
            (28 + c.order_bytes()) as u16,
            (27 + 2 * c.order_bytes()) as u16,
        ),
    );
    sign.patches.push(counter_patch(at));
    sign.consumes.push(0);
    let mut spec = envelope(
        Program::new(vec![commit, sign]),
        Oracle::Ecdaa {
            curve,
            private: d.to_vec(),
            hash: HashAlg::Sha256,
            digest,
        },
        &[0, 1],
    )?;
    spec.setup.push(load(curve, d, true));
    Ok(spec)
}
fn zgen(curve: CurveId, scheme: ExchangeScheme, d: &[u8]) -> Result<ClassSpec, String> {
    let c = curve.curve();
    let mut ephemeral = Step::new(
        tpm::build_command(0x18e, &[], &[], &curve.tpm_id().to_be_bytes()).bytes,
        masked_points(curve, 1, false, true, 0),
    );
    ephemeral.produces = Resource::Counter;
    let mut params = ecc::point_bytes(curve, &c.mul_g(&BigUint::from(5u32)).unwrap());
    params.extend(ecc::point_bytes(
        curve,
        &c.mul_g(&BigUint::from(11u32)).unwrap(),
    ));
    tpm::put_u16(&mut params, scheme.alg_id());
    let count = params.len();
    params.extend([0, 0]);
    let cmd = tpm::build_command(0x18d, &[0], &[&[]], &params);
    let at = cmd.bytes.len() - params.len() + count;
    let mut consumer = Step::new(
        cmd.bytes,
        masked_points(curve, 2, scheme != ExchangeScheme::Ecdh, false, 1),
    );
    consumer.patches.push(counter_patch(at));
    consumer.consumes.push(0);
    let mut spec = envelope(
        Program::new(vec![ephemeral, consumer]),
        Oracle::Zgen {
            curve,
            private: d.to_vec(),
            scheme,
        },
        &[1],
    )?;
    spec.setup.push(load(curve, d, false));
    Ok(spec)
}
fn decrypt(curve: CurveId, hash: HashAlg, input: &[u8]) -> ClassSpec {
    let c = curve.curve();
    let mode = input[0];
    let d = &input[1..1 + c.bytes];
    let message = &input[1 + c.bytes..];
    let encryption_key = if mode == 4 {
        BigUint::from(7u32)
    } else {
        from_be(d)
    };
    let mut cipher = ecc::encrypt(curve, hash, &encryption_key, &BigUint::from(11u32), message);
    match mode {
        1 => cipher.c3[0] ^= 1,
        2 => *cipher.c3.last_mut().unwrap() ^= 1,
        3 => cipher.c3.iter_mut().for_each(|b| *b ^= 0xff),
        _ => (),
    }
    let mut params = ecc::point_bytes(curve, &cipher.c1);
    params.extend(tpm::sized(&cipher.c2));
    params.extend(tpm::sized(&cipher.c3));
    params.extend([0, 0x21]);
    tpm::put_u16(&mut params, hash.alg_id());
    let ok = mode == 0 || (mode == 4 && from_be(d) == BigUint::from(7u32));
    let expected = if ok {
        tpm::success_response(&[], &tpm::sized(message), 1)
    } else {
        tpm::error_response(0x84)
    };
    let mut spec = ClassSpec::new(
        LayoutStep::new(
            "ECC_Decrypt",
            tpm::build_command(0x19a, &[0], &[&[]], &params).bytes,
        )
        .handle_at(10, HandleRef::Class(0)),
        expected,
    );
    spec.setup.push(load(curve, d, false));
    spec
}
pub fn build(s: Scenario, pair: &InputPair) -> Result<Built, String> {
    let one = |input: &[u8]| match s {
        Scenario::Ecdaa(c) => ecdaa(c, input),
        Scenario::Zgen(c, scheme) => zgen(c, scheme, input),
        Scenario::EccDecrypt(c, h) => Ok(decrypt(c, h, input)),
        _ => unreachable!(),
    };
    let classes = [one(&pair.a)?, one(&pair.b)?];
    let d = |input: &[u8]| {
        if matches!(s, Scenario::EccDecrypt(..)) {
            input[1..1 + curve(s).key_bytes()].to_vec()
        } else {
            input.to_vec()
        }
    };
    let distinct = d(&pair.a) != d(&pair.b);
    let public = classes[0].measured.command != classes[1].measured.command;
    let model = PairModel::secret(distinct)
        .public("ciphertext or comparison bytes", public)
        .public("loaded public key/name", distinct)
        .confounder(
            true,
            if distinct {
                PER_CLASS_KEYS
            } else {
                PER_CLASS_OBJECTS
            },
        );
    Ok(Built {
        shared: vec![],
        classes,
        model,
        varying_public_values: vec![
            "per-class key handles; public keys when private scalar varies".into(),
        ],
    })
}
pub fn doc(s: Scenario) -> ScenarioDoc {
    let (entry, secret, correctness, interpretation, randomized) = match s {
        Scenario::EccDecrypt(..) => (
            "ECC_Decrypt(KDF2)",
            "loaded private scalar and C3 comparison",
            "independently construct C1=kG, C2=M XOR KDF2(kQ), C3=H(x||M||y); exact plaintext or bare VALUE on first/last/whole C3 mismatch",
            "Fixed ciphertext across distinct private keys is available; public key, name and handle still change. Other comparisons deliberately vary ciphertext or C3.",
            false,
        ),
        Scenario::Ecdaa(_) => (
            "Commit(P1=G,P2) + Sign(ECDAA)",
            "loaded private scalar; fresh uncontrolled commitment and signature nonces",
            "retain actual minimal-width nonceK; recover r=(s-H(nonceK||digest)*d) mod n; verify K=dP2,L=rP2,E=rG and sG=E+TQ; complete structural check each sample",
            "Combined two-command timing, including patches and structural checks. Random nonces are not assigned to classes; variable nonce encoding length remains an explicit confounder.",
            true,
        ),
        Scenario::Zgen(_, ExchangeScheme::Ecdh) => (
            "EC_Ephemeral + ZGen_2Phase(ECDH)",
            "loaded static private scalar; fresh uncontrolled ephemeral scalar",
            "actual QeA from producer; independently verify Z1=dsB*QsA and Z2=deB*QeA",
            "Combined two-command timing; fixed peer points, distinct static keys. Fresh ephemeral generation alone is not a secret-conditioned two-class test.",
            true,
        ),
        Scenario::Zgen(_, ExchangeScheme::Sm2) => (
            "EC_Ephemeral + ZGen_2Phase(SM2 compatibility)",
            "loaded static private scalar; fresh uncontrolled ephemeral scalar",
            "peer-side compatibility equation using actual QeA and pinned 64-bit BnMaskBits behavior; exact empty Z2",
            "The pinned C reference fails on P521/BN638 because its unreduced scalar product exceeds its temporary allocation; these two C cases have named skips and isolated opt-out probes, while Rust remains measured. Vendored behavior differs from standard SM2: associated-value bit masking uses the remainder rather than its complement and a different w. This explicitly checks compatibility, not standards agreement. Combined two-call timing.",
            true,
        ),
        Scenario::Zgen(_, ExchangeScheme::Ecmqv) => (
            "EC_Ephemeral + ZGen_2Phase(ECMQV known failure)",
            "loaded static private scalar; fresh ephemeral scalar",
            "no passing oracle: pinned C uninitialized order causes divide-by-zero; Rust preserves failure mode",
            "Named known-functional-failure SKIP before normal execution; opt-out probes must use an isolated worker and report failure, never timing success.",
            true,
        ),
        _ => unreachable!(),
    };
    ScenarioDoc{harness:COMMAND_LEVEL.into(),entry_point:entry.into(),secret:secret.into(),attacker_inputs:"known test scalars, fixed generator/peer points, digest or independently constructed ciphertext".into(),observable_outputs:"full TPM transcript, exact codes and framing; generated points/signatures remain unmasked for the independent oracle".into(),classes:"scalar boundary/random pairs and ciphertext comparison boundaries".into(),fixed:"curve, scheme, hash and message dimensions; TPM profile default-v1".into(),timed_region:format!("{entry}; setup LoadExternal and Rust cryptographic oracle outside timing; fresh counter produced and consumed each invocation"),correctness:correctness.into(),interpretation:interpretation.into(),randomized}
}
