use super::catalog::Scenario;
use super::family::{
    Built, COMMAND_LEVEL, ClassSpec, PER_CLASS_KEYS, PER_CLASS_OBJECTS, PairModel, ScenarioDoc,
    random_seeds, seed,
};
use super::layout::{Creates, HandleRef, Step};
use super::{InputPair, Seed, SplitMix};
use crate::oracle::hash::HashAlg;
use crate::oracle::sym::{SymKey, tpm_cmac};
use crate::tpm::{
    self, ATTR_DECRYPT, ATTR_NO_DA, ATTR_SIGN, ATTR_USER_WITH_AUTH, Public, PublicDetail, Scheme,
    SymDef, TPM_ALG_HMAC, TPM_ALG_KEYEDHASH, TPM_ALG_NULL, TPM_ALG_SHA256, TPM_ALG_SYMCIPHER,
    TPM_RH_NULL,
};

pub const MESSAGE_BYTES: usize = 64;
pub const TPM_ALG_CMAC: u16 = 0x003f;
pub const TPM_ST_VERIFIED: u16 = 0x8022;

pub fn hmac_key_load(hash: HashAlg, key: &[u8], auth: &[u8]) -> Vec<u8> {
    let seed = vec![0x22u8; 32];
    let public = Public {
        name_alg: TPM_ALG_SHA256,
        attributes: ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_SIGN,
        detail: PublicDetail::KeyedHash {
            scheme: Scheme::WithHash(TPM_ALG_HMAC, hash.alg_id()),
            unique: HashAlg::Sha256.digest(&[&seed, key]),
        },
    };
    let sensitive = tpm::sensitive(TPM_ALG_KEYEDHASH, auth, &seed, key);
    tpm::load_external_command(Some(&sensitive), &public, TPM_RH_NULL)
}

pub fn cmac_key_load(key: SymKey, secret: &[u8]) -> Vec<u8> {
    let seed = vec![0x33u8; 32];
    let public = Public {
        name_alg: TPM_ALG_SHA256,
        attributes: ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_SIGN,
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

pub fn mac_command(message: &[u8], scheme: u16, password: &[u8]) -> Step {
    let mut parameters = Vec::new();
    tpm::put_2b(&mut parameters, message);
    tpm::put_u16(&mut parameters, scheme);
    let built = tpm::build_command(tpm::TPM_CC_MAC, &[0], &[password], &parameters);
    Step::new("MAC", built.bytes).handle_at(10, HandleRef::Class(0))
}

pub fn mac_response(mac: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    tpm::put_2b(&mut params, mac);
    tpm::success_response(&[], &params, 1)
}

fn verify_key() -> Vec<u8> {
    HashAlg::Sha512.digest(&[b"tpms-timing-tests hmac verify key"])
}

fn verify_message(hash: HashAlg) -> Vec<u8> {
    hash.digest(&[b"tpms-timing-tests hmac verify message"])
}

pub fn keyed_model(a: &[u8], b: &[u8], key_bytes: usize) -> PairModel {
    let keys = a[..key_bytes] != b[..key_bytes];
    PairModel::secret(keys)
        .public("message", a[key_bytes..] != b[key_bytes..])
        .confounder(a != b, PER_CLASS_OBJECTS)
        .confounder(keys, PER_CLASS_KEYS)
}

fn sequence_base(scenario: Scenario) -> Option<Scenario> {
    match scenario {
        Scenario::HmacSequence(hash) => Some(Scenario::Hmac(hash)),
        Scenario::CmacSequence(key) => Some(Scenario::Cmac(key)),
        _ => None,
    }
}

const SEQUENCE_BYTES: usize = 256;

/// NULL-scheme keyed-hash MAC object with sign and decrypt both set: the only
/// construction that reaches HMAC keys past the scheme bound, up to the
/// 128-byte TPM2B_SENSITIVE_DATA transport limit shared by both backends.
pub fn null_scheme_key_load(key: &[u8]) -> Vec<u8> {
    let seed = vec![0x22u8; 32];
    let public = Public {
        name_alg: TPM_ALG_SHA256,
        attributes: ATTR_USER_WITH_AUTH | ATTR_NO_DA | ATTR_SIGN | ATTR_DECRYPT,
        detail: PublicDetail::KeyedHash {
            scheme: Scheme::Null,
            unique: HashAlg::Sha256.digest(&[&seed, key]),
        },
    };
    let sensitive = tpm::sensitive(TPM_ALG_KEYEDHASH, &[], &seed, key);
    tpm::load_external_command(Some(&sensitive), &public, TPM_RH_NULL)
}

fn long_key_message() -> Vec<u8> {
    (0..64u8).collect()
}

pub fn long_key_build(
    hash: HashAlg,
    _length: crate::scenario::catalog::LongKeyLength,
    pair: &InputPair,
) -> Result<Built, String> {
    let message = long_key_message();
    let class = |key: &[u8]| {
        let mut spec = ClassSpec::new(
            mac_command(&message, hash.alg_id(), &[]),
            mac_response(&hash.hmac(key, &[&message])),
        );
        spec.setup = vec![
            Step::new(
                "LoadExternal NULL-scheme MAC key",
                null_scheme_key_load(key),
            )
            .creates(Creates::Object),
        ];
        spec
    };
    Ok(Built {
        shared: Vec::new(),
        classes: [class(&pair.a), class(&pair.b)],
        model: PairModel::secret(pair.a != pair.b).confounder(
            pair.a != pair.b,
            "different keys produce different MAC values and object names",
        ),
        varying_public_values: vec![
            "object name and handle of each key".into(),
            "MAC value".into(),
        ],
    })
}

pub fn long_key_seeds(
    scenario: Scenario,
    length: crate::scenario::catalog::LongKeyLength,
    campaign_seed: u64,
    random_pairs: usize,
) -> Vec<Seed> {
    let n = length.bytes();
    let mut first = vec![0u8; n];
    first[0] = 1;
    let mut last = vec![0u8; n];
    last[n - 1] = 1;
    let mut out = vec![
        seed(
            "mismatch-first-byte-vs-last-byte",
            first.clone(),
            last.clone(),
        ),
        seed("mismatch-all-bytes-vs-last-byte", vec![0xff; n], last),
        seed("zero-key-vs-ones-key", vec![0; n], vec![0xff; n]),
        seed("valid-vs-valid", vec![0; n], vec![0; n]),
    ];
    out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
        rng.bytes(n)
    }));
    out
}

pub fn long_key_doc(hash: HashAlg, length: crate::scenario::catalog::LongKeyLength) -> ScenarioDoc {
    let block = 64;
    let position = match length {
        crate::scenario::catalog::LongKeyLength::BelowBlock => "immediately below",
        crate::scenario::catalog::LongKeyLength::Block => "exactly at",
        crate::scenario::catalog::LongKeyLength::AboveBlock => "immediately above",
        crate::scenario::catalog::LongKeyLength::Max => {
            "at the 128-byte transport maximum, far above"
        }
    };
    ScenarioDoc {
        harness: COMMAND_LEVEL.into(),
        entry_point: format!(
            "TPM2_MAC (0x155) with a NULL-scheme keyed-hash key and explicit inScheme HMAC-{}, key length {}",
            hash.name(),
            length.bytes()
        ),
        secret: format!("the {}-byte HMAC key", length.bytes()),
        attacker_inputs: format!("{}-byte key per class; classes compare equal-length keys", length.bytes()),
        observable_outputs: "MAC value".into(),
        classes: "equal-length keys with different content, identical-input control, random pairs; across lengths only the public key length changes".into(),
        fixed: "hash, message, key length within one scenario; class keys always have equal length".into(),
        timed_region: "one TPMLIB_Process call of MAC".into(),
        correctness: format!(
            "HMAC computed with the RustCrypto hmac crate over the loaded key; both backends normalize keys longer than the {block}-byte block by hashing; exact response match"
        ),
        interpretation: format!(
            "a signal shows HMAC time depends on key content for the {position} the {block}-byte SHA-1/SHA-256 block"
        ),
        randomized: false,
    }
}

pub fn input_width(scenario: Scenario) -> usize {
    if let Some(base) = sequence_base(scenario) {
        return input_width(base) - MESSAGE_BYTES + 1 + SEQUENCE_BYTES;
    }
    match scenario {
        Scenario::Hmac(hash) => hash.size() + MESSAGE_BYTES,
        Scenario::Cmac(key) => key.key_bytes() + MESSAGE_BYTES,
        Scenario::HmacVerify(hash) => hash.size(),
        Scenario::MacLongKey(_, length) => length.bytes(),
        _ => unreachable!(),
    }
}

pub fn validate(scenario: Scenario, bytes: &[u8]) -> Result<(), String> {
    if let Some(base) = sequence_base(scenario) {
        return validate(base, bytes);
    }
    match scenario {
        Scenario::Cmac(key) => key
            .valid_key(&bytes[..key.key_bytes()])
            .then_some(())
            .ok_or_else(|| "key rejected by the TPM key validation rules".into()),
        _ => Ok(()),
    }
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    if let Some(base) = sequence_base(scenario) {
        let kb = input_width(base) - MESSAGE_BYTES;
        let expand = |mut input: Vec<u8>| {
            input.resize(kb + SEQUENCE_BYTES, 0x5a);
            input.insert(kb, 0);
            input
        };
        let mut out: Vec<_> = seeds(base, campaign_seed, random_pairs)
            .into_iter()
            .map(|mut seed| {
                seed.pair.a = expand(seed.pair.a);
                seed.pair.b = expand(seed.pair.b);
                seed
            })
            .collect();
        for selector in 0..5 {
            let mut input = out[0].pair.a.clone();
            input[kb] = selector;
            out.push(seed(
                format!("split-boundary-{selector}"),
                input.clone(),
                input,
            ));
        }
        return out;
    }

    if let Scenario::MacLongKey(_, length) = scenario {
        return long_key_seeds(scenario, length, campaign_seed, random_pairs);
    }
    let mut rng =
        SplitMix::new(0x3a3a_0002 ^ crate::scenario::family::fnv(scenario.name().as_bytes()));
    let mut out = Vec::new();
    match scenario {
        Scenario::HmacVerify(hash) => {
            let n = hash.size();
            let mut first = vec![0u8; n];
            first[0] = 1;
            let mut last = vec![0u8; n];
            last[n - 1] = 1;
            out.push(seed(
                "mismatch-first-byte-vs-last-byte",
                first.clone(),
                last.clone(),
            ));
            out.push(seed(
                "mismatch-all-bytes-vs-last-byte",
                vec![0xff; n],
                last.clone(),
            ));
            out.push(seed("valid-vs-mismatch-last-byte", vec![0; n], last));
            out.push(seed("valid-vs-valid", vec![0; n], vec![0; n]));
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                rng.bytes(n)
            }));
        }
        _ => {
            let kb = input_width(scenario) - MESSAGE_BYTES;
            let key_gen = |rng: &mut SplitMix| loop {
                let k = rng.bytes(kb);
                if validate(scenario, &[k.clone(), vec![0; MESSAGE_BYTES]].concat()).is_ok() {
                    return k;
                }
            };
            let k = key_gen(&mut rng);
            let k2 = key_gen(&mut rng);
            let m = rng.bytes(MESSAGE_BYTES);
            out.push(seed(
                "same-message-different-key",
                [k.clone(), m.clone()].concat(),
                [k2, m.clone()].concat(),
            ));
            out.push(seed(
                "same-key-zero-vs-ones-message",
                [k.clone(), vec![0; MESSAGE_BYTES]].concat(),
                [k.clone(), vec![0xff; MESSAGE_BYTES]].concat(),
            ));
            if matches!(scenario, Scenario::Hmac(_)) {
                out.push(seed(
                    "zero-key-vs-ones-key",
                    [vec![0; kb], m.clone()].concat(),
                    [vec![0xff; kb], m].concat(),
                ));
            }
            out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
                [key_gen(rng), rng.bytes(MESSAGE_BYTES)].concat()
            }));
        }
    }
    out
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    if let Some(base) = sequence_base(scenario) {
        return build_sequence(scenario, base, pair);
    }

    match scenario {
        Scenario::Hmac(hash) => {
            let class = |input: &[u8]| {
                let (key, message) = input.split_at(hash.size());
                let mut spec = ClassSpec::new(
                    mac_command(message, TPM_ALG_NULL, &[]),
                    mac_response(&hash.hmac(key, &[message])),
                );
                spec.setup = vec![
                    Step::new("LoadExternal HMAC key", hmac_key_load(hash, key, &[]))
                        .creates(Creates::Object),
                ];
                spec
            };
            Ok(Built {
                shared: Vec::new(),
                classes: [class(&pair.a), class(&pair.b)],
                model: keyed_model(&pair.a, &pair.b, hash.size()),
                varying_public_values: vec![
                    "object name and handle of each key".into(),
                    "MAC value".into(),
                ],
            })
        }
        Scenario::Cmac(key) => {
            let class = |input: &[u8]| {
                let (secret, message) = input.split_at(key.key_bytes());
                let mut spec = ClassSpec::new(
                    mac_command(message, TPM_ALG_CMAC, &[]),
                    mac_response(&tpm_cmac(key, secret, message)),
                );
                spec.setup = vec![
                    Step::new("LoadExternal CMAC key", cmac_key_load(key, secret))
                        .creates(Creates::Object),
                ];
                spec
            };
            Ok(Built {
                shared: Vec::new(),
                classes: [class(&pair.a), class(&pair.b)],
                model: keyed_model(&pair.a, &pair.b, key.key_bytes()),
                varying_public_values: vec![
                    "object name and handle of each key".into(),
                    "MAC value".into(),
                ],
            })
        }
        Scenario::MacLongKey(hash, length) => long_key_build(hash, length, pair),
        Scenario::HmacVerify(hash) => {
            let key = &verify_key()[..hash.size()];
            let message = verify_message(hash);
            let correct = hash.hmac(key, &[&message]);
            let class = |delta: &[u8]| {
                let claimed: Vec<u8> = correct.iter().zip(delta).map(|(a, b)| a ^ b).collect();
                let mut parameters = Vec::new();
                tpm::put_2b(&mut parameters, &message);
                tpm::put_u16(&mut parameters, TPM_ALG_HMAC);
                tpm::put_u16(&mut parameters, hash.alg_id());
                parameters.extend_from_slice(&claimed);
                let built =
                    tpm::build_command(tpm::TPM_CC_VERIFY_SIGNATURE, &[0], &[], &parameters);
                let expected = if delta.iter().all(|b| *b == 0) {
                    let mut params = Vec::new();
                    tpm::put_u16(&mut params, TPM_ST_VERIFIED);
                    tpm::put_u32(&mut params, TPM_RH_NULL);
                    tpm::put_2b(&mut params, &[]);
                    tpm::success_response(&[], &params, 0)
                } else {
                    tpm::error_response(tpm::parameter_error(tpm::TPM_RC_SIGNATURE, 2))
                };
                ClassSpec::new(
                    Step::new("VerifySignature", built.bytes).handle_at(10, HandleRef::Shared(0)),
                    expected,
                )
            };
            Ok(Built {
                shared: vec![
                    Step::new("LoadExternal HMAC key", hmac_key_load(hash, key, &[]))
                        .creates(Creates::Object),
                ],
                classes: [class(&pair.a), class(&pair.b)],
                model: PairModel::secret(false).public("claimed HMAC value", pair.a != pair.b),
                varying_public_values: vec![
                    "claimed HMAC value (correct value XOR the class delta)".into(),
                ],
            })
        }
        _ => unreachable!(),
    }
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    if let Some(base) = sequence_base(scenario) {
        let mut doc = doc(base);
        doc.entry_point = "TPM2_MAC_Start / SequenceUpdate / SequenceComplete".into();
        doc.attacker_inputs = "key, chunk split selector, and 256-byte message".into();
        doc.fixed =
            "algorithm, total message length; split selects zero, one, block-1, block, block+1"
                .into();
        doc.timed_region = "all three commands in a command program; every sample creates and consumes a fresh sequence".into();
        return doc;
    }

    match scenario {
        Scenario::Hmac(hash) => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_MAC (0x155) with an HMAC-{} keyed-hash key loaded by TPM2_LoadExternal, inScheme NULL", hash.name()),
            secret: "the HMAC key and the message".into(),
            attacker_inputs: format!("{}-byte key and {MESSAGE_BYTES}-byte message per class", hash.size()),
            observable_outputs: "MAC value".into(),
            classes: "two key/message inputs, each key loaded as its own object".into(),
            fixed: "hash, message length, key length".into(),
            timed_region: "one TPMLIB_Process call of MAC".into(),
            correctness: "HMAC computed with the RustCrypto hmac crate (RFC 4231-style vector tested); exact response match".into(),
            interpretation: "a signal shows HMAC time depends on key or message content".into(),
            randomized: false,
        },
        Scenario::Cmac(key) => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: format!("TPM2_MAC (0x155) with a {} symcipher key, inScheme CMAC", key.name()),
            secret: "the CMAC key and the message".into(),
            attacker_inputs: format!("{}-byte key and {MESSAGE_BYTES}-byte message per class", key.key_bytes()),
            observable_outputs: "MAC value".into(),
            classes: "two key/message inputs, each key loaded as its own object".into(),
            fixed: "cipher, message length".into(),
            timed_region: "one TPMLIB_Process call of MAC".into(),
            correctness: if key.block() == 8 { "CMAC computed by the harness's SP800-38B implementation with the subkey constant Rb = 0x87 that libtpms uses for every block size (SP800-38B prescribes 0x1B for 64-bit blocks; both backends follow libtpms); exact response match".into() } else { "CMAC computed by the harness's SP800-38B implementation (NIST examples tested); exact response match".into() },
            interpretation: "a signal shows CMAC time depends on key or message content".into(),
            randomized: false,
        },
        Scenario::MacLongKey(hash, length) => long_key_doc(hash, length),
        _ => ScenarioDoc {
            harness: COMMAND_LEVEL.into(),
            entry_point: "TPM2_VerifySignature (0x177) with an HMAC keyed-hash key: the TPM recomputes the HMAC and compares it with the claimed value".into(),
            secret: "the HMAC key, hence the correct HMAC value the claim is compared against".into(),
            attacker_inputs: "an XOR delta applied to the correct HMAC (zero delta = valid claim)".into(),
            observable_outputs: "NULL verification ticket or TPM_RC_SIGNATURE on the signature parameter".into(),
            classes: "two claimed HMAC values for the same key and message".into(),
            fixed: "key, message, hash".into(),
            timed_region: "one TPMLIB_Process call of VerifySignature".into(),
            correctness: "correct HMAC computed with the hmac crate; exact response match".into(),
            interpretation: "mismatch-versus-mismatch pairs probe the secret-dependent comparison (early exit on the first differing byte); valid-versus-invalid pairs are visibly different outcomes".into(),
            randomized: false,
        },
    }
}

fn build_sequence(scenario: Scenario, base: Scenario, pair: &InputPair) -> Result<Built, String> {
    use crate::program::{
        Contract, Patch, Program, Resource, ResponseArea, ResponseRange, Step as ProgramStep,
    };
    let kb = input_width(base) - MESSAGE_BYTES;
    let without_selector = |input: &[u8]| [&input[..kb], &input[kb + 1..]].concat();
    let inputs = InputPair::new(without_selector(&pair.a), without_selector(&pair.b));
    let mut built = build(base, &inputs)?;
    let (scheme, block) = match scenario {
        Scenario::HmacSequence(hash) => (hash.alg_id(), if hash.size() > 32 { 128 } else { 64 }),
        Scenario::CmacSequence(key) => (TPM_ALG_CMAC, key.block()),
        _ => unreachable!(),
    };
    for (class, spec) in built.classes.iter_mut().enumerate() {
        let input = pair.class(class);
        let message = &input[kb + 1..];
        let split = [0, 1, block - 1, block, block + 1][input[kb] as usize % 5];
        let mut params = vec![0, 0];
        tpm::put_u16(&mut params, scheme);
        let mut contract = Contract::exact(tpm::success_response(&[0], &[], 1), 1);
        contract.mask[10..14].fill(0);
        let mut start = ProgramStep::new(
            tpm::build_command(0x15b, &[0], &[&[]], &params).bytes,
            contract,
        );
        start.produces = Resource::Handle;
        let patch = Patch::Copy {
            at: 10,
            source: ResponseRange {
                step: 0,
                area: ResponseArea::Raw,
                offset: 10,
                len: 4,
            },
            xor: vec![0; 4],
        };
        let mut update = ProgramStep::new(
            tpm::build_command(0x15c, &[0], &[&[]], &tpm::sized(&message[..split])).bytes,
            Contract::exact(tpm::success_response(&[], &[], 1), 0),
        );
        update.patches.push(patch.clone());
        let mut params = tpm::sized(&message[split..]);
        tpm::put_u32(&mut params, TPM_RH_NULL);
        let mac = match scenario {
            Scenario::HmacSequence(hash) => hash.hmac(&input[..kb], &[message]),
            Scenario::CmacSequence(key) => tpm_cmac(key, &input[..kb], message),
            _ => unreachable!(),
        };
        let mut result = tpm::sized(&mac);
        result.extend_from_slice(&[0x80, 0x24, 0x40, 0, 0, 7, 0, 0]);
        let mut complete = ProgramStep::new(
            tpm::build_command(0x13e, &[0], &[&[]], &params).bytes,
            Contract::exact(tpm::success_response(&[], &result, 1), 0),
        );
        complete.patches.push(patch);
        complete.consumes.push(0);
        let program = Program {
            outcome_step: None,
            steps: vec![start, update, complete],
        };
        let encoded = program.encode()?;
        (spec.expected, spec.mask) = program.expectation()?;
        spec.measured = Step::new("MAC sequence", encoded.bytes)
            .handle_at(encoded.command_offsets[0] + 10, HandleRef::Class(0));
        spec.check = Some(super::Check::Program { program });
    }
    built.model = built
        .model
        .public("sequence chunk boundary", pair.a[kb] % 5 != pair.b[kb] % 5);
    Ok(built)
}
