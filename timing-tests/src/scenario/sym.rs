use super::catalog::{Direction, Scenario};
use super::family::{
    Built, COMMAND_LEVEL, ClassSpec, PER_CLASS_KEYS, PER_CLASS_OBJECTS, PairModel, ScenarioDoc,
    random_seeds, seed,
};
use super::layout::{Creates, HandleRef, Step};
use super::{InputPair, Seed, SplitMix};
use crate::oracle::hash::HashAlg;
use crate::oracle::sym::{ChainingContract, SymKey, SymMode, crypt_contract};
use crate::tpm::{
    self, ATTR_DECRYPT, ATTR_NO_DA, ATTR_SIGN, ATTR_USER_WITH_AUTH, Public, PublicDetail, SymDef,
    TPM_ALG_NULL, TPM_ALG_SHA256, TPM_ALG_SYMCIPHER, TPM_RH_NULL,
};

pub const DATA_BLOCKS: usize = 4;

fn parts(scenario: Scenario) -> (SymKey, SymMode, Direction) {
    match scenario {
        Scenario::Sym(key, mode, direction) | Scenario::SymPartial(key, mode, direction) => {
            (key, mode, direction)
        }
        _ => unreachable!("not a symmetric scenario"),
    }
}

/// Key spec of a symmetric (partial-input aware) scenario, for callers that
/// need the block size or key length of its inputs.
pub fn scenario_key(scenario: Scenario) -> SymKey {
    parts(scenario).0
}

/// Deterministic valid key for a key spec (TPM validation rules included).
pub fn deterministic_key(key: SymKey) -> Vec<u8> {
    valid_key(key, &mut SplitMix::new(key.bits() as u64 ^ 0x1234_5678))
}

/// Effective command data for a partial-input scenario: the selector byte picks
/// the transmitted length, everything past it never reaches the TPM. The
/// original candidate bytes stay untouched for provenance.
pub fn effective_input(scenario: Scenario, input: &[u8]) -> (&[u8], usize, &[u8]) {
    let (key, _, _) = parts(scenario);
    let kb = key.key_bytes();
    let (secret, rest) = input.split_at(kb);
    if matches!(scenario, Scenario::SymPartial(..)) {
        let len = rest[0] as usize % (data_bytes(key) + 1);
        (secret, len, &rest[1..1 + len])
    } else {
        (secret, rest.len(), rest)
    }
}

/// Returns true when the scenario's measured data ends in a partial CFB block
/// on this input: the two supported backends then return different chaining
/// values (ivOut suffix) and each backend needs its own exact expectation.
pub fn partial_cfb_chaining(scenario: Scenario, input: &[u8]) -> bool {
    let Scenario::SymPartial(key, SymMode::Cfb, _) = scenario else {
        return false;
    };
    let len = effective_input(scenario, input).1;
    len != 0 && !len.is_multiple_of(key.block())
}

pub fn data_bytes(key: SymKey) -> usize {
    DATA_BLOCKS * key.block()
}

pub fn input_width(scenario: Scenario) -> usize {
    let (key, _, _) = parts(scenario);
    key.key_bytes() + data_bytes(key) + usize::from(matches!(scenario, Scenario::SymPartial(..)))
}

pub fn validate(scenario: Scenario, bytes: &[u8]) -> Result<(), String> {
    let (key, _, _) = parts(scenario);
    key.valid_key(&bytes[..key.key_bytes()])
        .then_some(())
        .ok_or_else(|| {
            format!(
                "{} key rejected by the TPM key validation rules",
                key.name()
            )
        })
}

pub fn fixed_iv(key: SymKey) -> Vec<u8> {
    HashAlg::Sha256.digest(&[b"tpms-timing-tests iv", key.name().as_bytes()])[..key.block()]
        .to_vec()
}

pub fn symcipher_load(key: SymKey, secret: &[u8]) -> Vec<u8> {
    let seed = vec![0x11u8; 32];
    let public = Public {
        name_alg: TPM_ALG_SHA256,
        attributes: ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_DECRYPT | ATTR_SIGN,
        detail: PublicDetail::Symcipher {
            symmetric: SymDef::Cipher {
                alg: key.alg_id(),
                bits: key.bits(),
                mode: TPM_ALG_NULL,
            },
            unique: HashAlg::Sha256.digest(&[&seed, secret]),
        },
    };
    let sensitive = tpm::sensitive(TPM_ALG_SYMCIPHER, &[], &seed, secret);
    tpm::load_external_command(Some(&sensitive), &public, TPM_RH_NULL)
}

pub fn encrypt_decrypt2(key: SymKey, mode: SymMode, decrypt: bool, data: &[u8]) -> Step {
    let mut parameters = Vec::new();
    tpm::put_2b(&mut parameters, data);
    parameters.push(u8::from(decrypt));
    tpm::put_u16(&mut parameters, mode.alg_id());
    let iv = if mode.uses_iv() {
        fixed_iv(key)
    } else {
        Vec::new()
    };
    tpm::put_2b(&mut parameters, &iv);
    let built = tpm::build_command(tpm::TPM_CC_ENCRYPT_DECRYPT2, &[0], &[&[]], &parameters);
    Step::new("EncryptDecrypt2", built.bytes).handle_at(10, HandleRef::Class(0))
}

pub fn encrypt_decrypt2_expected(
    key: SymKey,
    mode: SymMode,
    decrypt: bool,
    secret: &[u8],
    data: &[u8],
) -> Vec<u8> {
    encrypt_decrypt2_expected_chaining(
        key,
        mode,
        decrypt,
        secret,
        data,
        ChainingContract::RetainedSuffix,
    )
}

pub fn encrypt_decrypt2_expected_chaining(
    key: SymKey,
    mode: SymMode,
    decrypt: bool,
    secret: &[u8],
    data: &[u8],
    contract: ChainingContract,
) -> Vec<u8> {
    let iv = if mode.uses_iv() {
        fixed_iv(key)
    } else {
        Vec::new()
    };
    if matches!(mode, SymMode::Cbc | SymMode::Ecb) && !data.len().is_multiple_of(key.block()) {
        return tpm::error_response(tpm::parameter_error(tpm::TPM_RC_SIZE, 1));
    }
    let (out, iv_out) = crypt_contract(key, mode, secret, &iv, data, !decrypt, contract);
    let mut params = Vec::new();
    tpm::put_2b(&mut params, &out);
    tpm::put_2b(&mut params, &iv_out);
    tpm::success_response(&[], &params, 1)
}

/// Rebuild the measured-class expectations under a specific backend chaining
/// contract. Only partial CFB blocks differ between the two contracts; the
/// response bytes are always compared exactly, never masked.
pub(crate) fn apply_chaining_contract(
    scenario: Scenario,
    pair: &InputPair,
    built: &mut Built,
    contract: ChainingContract,
) -> Result<(), String> {
    let Scenario::SymPartial(key, mode, direction) = scenario else {
        return Ok(());
    };
    if mode != SymMode::Cfb {
        return Ok(());
    }
    for (class, spec) in built.classes.iter_mut().enumerate() {
        let (secret, _, data) = effective_input(scenario, pair.class(class));
        spec.expected = encrypt_decrypt2_expected_chaining(
            key,
            mode,
            direction == Direction::Decrypt,
            secret,
            data,
            contract,
        );
    }
    Ok(())
}

/// Fixed probe input used to select a backend's CFB chaining contract with
/// fresh TPM probes: a valid key, one selector picking a partial length, and
/// deterministic material. The two candidate expectations are derived offline.
pub fn chaining_probe_pair(scenario: Scenario) -> Result<InputPair, String> {
    let Scenario::SymPartial(key, SymMode::Cfb, _) = scenario else {
        return Err("CFB chaining probes need a partial CFB scenario".into());
    };
    let mut rng = SplitMix::new(0x0cfb_c0de ^ key.alg_id() as u64 ^ key.bits() as u64);
    let secret = loop {
        let candidate = rng.bytes(key.key_bytes());
        if key.valid_key(&candidate) {
            break candidate;
        }
    };
    let partial = key.block() / 2;
    let data = rng.bytes(data_bytes(key));
    let input = [secret, vec![partial as u8], data].concat();
    let pair = InputPair::new(input.clone(), input);
    validate(scenario, &pair.a).map_err(|e| format!("probe input: {e}"))?;
    assert!(partial_cfb_chaining(scenario, &pair.a));
    Ok(pair)
}

fn valid_key(key: SymKey, rng: &mut SplitMix) -> Vec<u8> {
    loop {
        let candidate = rng.bytes(key.key_bytes());
        if key.valid_key(&candidate) {
            return candidate;
        }
    }
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    if let Scenario::SymPartial(key, mode, direction) = scenario {
        let kb = key.key_bytes();
        let mut out = seeds(
            Scenario::Sym(key, mode, direction),
            campaign_seed,
            random_pairs,
        );
        for seed in &mut out {
            seed.pair.a.insert(kb, (key.block() + 1) as u8);
            seed.pair.b.insert(kb, (key.block() + 1) as u8);
        }
        for len in [
            0,
            1,
            key.block() - 1,
            key.block(),
            key.block() + 1,
            2 * key.block() - 1,
        ] {
            let mut a = out[0].pair.a.clone();
            a[kb] = len as u8;
            let mut b = out[0].pair.b.clone();
            b[kb] = len as u8;
            out.push(seed(format!("length-{len}"), a, b));
        }
        return out;
    }

    let (key, _, _) = parts(scenario);
    let mut rng = SplitMix::new(0x5e5e_0001 ^ key.alg_id() as u64 ^ key.bits() as u64);
    let n = data_bytes(key);
    let k = valid_key(key, &mut rng);
    let k2 = valid_key(key, &mut rng);
    let d = rng.bytes(n);
    let mut out = vec![
        seed(
            "same-data-different-key",
            [k.clone(), d.clone()].concat(),
            [k2.clone(), d.clone()].concat(),
        ),
        seed(
            "same-key-zero-vs-ones-data",
            [k.clone(), vec![0; n]].concat(),
            [k.clone(), vec![0xff; n]].concat(),
        ),
        seed(
            "same-key-random-data",
            [k.clone(), d.clone()].concat(),
            [k.clone(), rng.bytes(n)].concat(),
        ),
    ];
    if !key.is_tdes() {
        out.push(seed(
            "zero-key-vs-ones-key",
            [vec![0; key.key_bytes()], d.clone()].concat(),
            [vec![0xff; key.key_bytes()], d.clone()].concat(),
        ));
    }
    let mut low = k.clone();
    low.iter_mut().for_each(|b| *b &= 0x0f);
    if key.valid_key(&low) {
        out.push(seed(
            "low-nibble-key-vs-random-key",
            [low, d.clone()].concat(),
            [k2, d].concat(),
        ));
    }
    out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
        [valid_key(key, rng), rng.bytes(n)].concat()
    }));
    out
}

pub fn boundary(scenario: Scenario, op: usize, r: u64, current: &[u8], other: &[u8]) -> Vec<u8> {
    let (key, _, _) = parts(scenario);
    let kb = key.key_bytes();
    let mut out = current.to_vec();
    match op % 4 {
        0 => out[..kb].copy_from_slice(&other[..kb]),
        1 => out[kb..].copy_from_slice(&other[kb..]),
        2 => {
            let fill = if r & 1 == 0 { 0x00 } else { 0xff };
            out[kb..].iter_mut().for_each(|b| *b = fill);
        }
        _ => {
            let at = (r as usize) % kb;
            out[at] ^= 1 << ((r >> 16) % 8);
        }
    }
    out
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let (key, mode, direction) = parts(scenario);
    let decrypt = direction == Direction::Decrypt;
    let partial = matches!(scenario, Scenario::SymPartial(..));
    let class = |input: &[u8]| -> Result<ClassSpec, String> {
        let (secret, _len, data) = effective_input(scenario, input);
        let mut spec = ClassSpec::new(
            encrypt_decrypt2(key, mode, decrypt, data),
            encrypt_decrypt2_expected(key, mode, decrypt, secret, data),
        );
        spec.setup = vec![
            Step::new("LoadExternal symcipher", symcipher_load(key, secret))
                .creates(Creates::Object),
        ];
        Ok(spec)
    };
    let model = {
        let kb = key.key_bytes();
        let keys = pair.a[..kb] != pair.b[..kb];
        // Public-input differences compare the data actually supplied to the
        // TPM: unused tails and equivalent selector encodings are excluded.
        let data_differs = if partial {
            let (_, len_a, data_a) = effective_input(scenario, &pair.a);
            let (_, len_b, data_b) = effective_input(scenario, &pair.b);
            len_a != len_b || data_a != data_b
        } else {
            pair.a[kb..] != pair.b[kb..]
        };
        PairModel::secret(keys)
            .public("data", data_differs)
            // For partial-input scenarios the per-class objects hold the loaded
            // keys, so they differ exactly when the keys differ; bytes that
            // never reach the TPM cannot make the loaded objects different.
            .confounder(
                if partial { keys } else { pair.a != pair.b },
                PER_CLASS_OBJECTS,
            )
            .confounder(keys, PER_CLASS_KEYS)
    };
    Ok(Built {
        shared: Vec::new(),
        classes: [class(&pair.a)?, class(&pair.b)?],
        model,
        varying_public_values: vec![
            "object name and handle of each class key".into(),
            "output data and chaining value".into(),
        ],
    })
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    let (key, mode, direction) = parts(scenario);
    ScenarioDoc {
        harness: COMMAND_LEVEL.into(),
        entry_point: format!(
            "TPM2_EncryptDecrypt2 (0x193), {} {} {}, key loaded by TPM2_LoadExternal with mode NULL so the command selects the mode",
            key.name(),
            mode.name(),
            direction.name()
        ),
        secret: "the symmetric key and the data being processed".into(),
        attacker_inputs: format!(
            "{} key bytes (TPM-valid keys only) and {} data bytes",
            key.key_bytes(),
            data_bytes(key)
        ),
        observable_outputs: "output data and ivOut".into(),
        classes: "two key/data inputs, each with its own loaded key".into(),
        fixed: if matches!(scenario, Scenario::SymPartial(_, SymMode::Cfb, _)) { "IV (SHA-256 derived), mode, direction; length selector covers partial blocks and CBC/ECB SIZE rejection; for partial final blocks the returned chaining value follows this backend's probed CFB contract (zeroed or retained suffix)".into() } else if matches!(scenario, Scenario::SymPartial(..)) { "IV (SHA-256 derived), mode, direction; length selector covers partial blocks and CBC/ECB SIZE rejection".into() } else { "IV (SHA-256 derived), mode, direction, data length (whole blocks)".into() },
        timed_region: "one TPMLIB_Process call of EncryptDecrypt2".into(),
        correctness: "output and chaining value computed with the RustCrypto block ciphers and the harness's own mode code (FIPS-197 vector and round trips tested); exact response match".into(),
        interpretation: "a signal shows cipher or mode time depends on the key or data; table-based software ciphers are the expected source".into(),
        randomized: false,
    }
}
