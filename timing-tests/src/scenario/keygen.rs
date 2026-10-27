use super::catalog::{KeygenKind, Scenario};
use super::family::{Built, COMMAND_LEVEL, Check, ClassSpec, ScenarioDoc, random_seeds, seed};
use super::layout::{HandleRef, Post, Step};
use super::{InputPair, Seed};
use crate::oracle::hash::HashAlg;
use crate::tpm::{
    self, ATTR_DECRYPT, ATTR_FIXED_PARENT, ATTR_FIXED_TPM, ATTR_NO_DA, ATTR_SENSITIVE_DATA_ORIGIN,
    ATTR_SIGN, ATTR_USER_WITH_AUTH, Public, PublicDetail, Scheme, SymDef, TPM_ALG_HMAC,
    TPM_ALG_NULL, TPM_ALG_SHA256, TPM_RH_OWNER,
};

pub const UNIQUE_BYTES: usize = 32;
const BASE_ATTRIBUTES: u32 = ATTR_FIXED_TPM
    | ATTR_FIXED_PARENT
    | ATTR_SENSITIVE_DATA_ORIGIN
    | ATTR_USER_WITH_AUTH
    | ATTR_NO_DA;

fn kind(scenario: Scenario) -> KeygenKind {
    match scenario {
        Scenario::KeygenPrimary(kind) => kind,
        _ => unreachable!("not a key generation scenario"),
    }
}

pub fn template(kind: KeygenKind, unique: &[u8]) -> Public {
    let detail = match kind {
        KeygenKind::Rsa(bits) => PublicDetail::Rsa {
            symmetric: SymDef::Null,
            scheme: Scheme::Null,
            bits: bits.bits() as u16,
            modulus: unique.to_vec(),
        },
        KeygenKind::Ecc(curve) => PublicDetail::Ecc {
            symmetric: SymDef::Null,
            scheme: Scheme::Null,
            curve: curve.tpm_id(),
            x: unique.to_vec(),
            y: Vec::new(),
        },
        KeygenKind::Aes128 => PublicDetail::Symcipher {
            symmetric: SymDef::Cipher {
                alg: tpm::TPM_ALG_AES,
                bits: 128,
                mode: TPM_ALG_NULL,
            },
            unique: unique.to_vec(),
        },
        KeygenKind::HmacSha256 => PublicDetail::KeyedHash {
            scheme: Scheme::WithHash(TPM_ALG_HMAC, TPM_ALG_SHA256),
            unique: unique.to_vec(),
        },
    };
    let usage = match kind {
        KeygenKind::Aes128 => ATTR_DECRYPT,
        _ => ATTR_SIGN,
    };
    Public {
        name_alg: TPM_ALG_SHA256,
        attributes: BASE_ATTRIBUTES | usage,
        detail,
    }
}

fn output_unique(kind: KeygenKind) -> Vec<u8> {
    match kind {
        KeygenKind::Rsa(bits) => vec![0; bits.bytes()],
        KeygenKind::Ecc(curve) => vec![0; curve.key_bytes()],
        KeygenKind::Aes128 | KeygenKind::HmacSha256 => vec![0; HashAlg::Sha256.size()],
    }
}

pub fn output_public(kind: KeygenKind) -> Public {
    let unique = output_unique(kind);
    let mut public = template(kind, &unique);
    if let (KeygenKind::Ecc(_), PublicDetail::Ecc { y, .. }) = (kind, &mut public.detail) {
        *y = unique.clone();
    }
    public
}

pub fn creation_data() -> Vec<u8> {
    let mut out = Vec::new();
    tpm::put_u32(&mut out, 0);
    tpm::put_2b(&mut out, &HashAlg::Sha256.digest(&[]));
    out.push(0x01);
    tpm::put_u16(&mut out, TPM_ALG_NULL);
    tpm::put_2b(&mut out, &TPM_RH_OWNER.to_be_bytes());
    tpm::put_2b(&mut out, &TPM_RH_OWNER.to_be_bytes());
    tpm::put_2b(&mut out, &[]);
    out
}

pub const TICKET_DIGEST_BYTES: usize = 64;
pub const TPM_ST_CREATION: u16 = 0x8021;

pub fn expected_response(kind: KeygenKind) -> (Vec<u8>, Vec<u8>) {
    let digest = HashAlg::Sha256.size();
    let public = output_public(kind).marshal();
    let creation = creation_data();
    let mut params = Vec::new();
    let mut variable: Vec<(usize, usize)> = Vec::new();
    let base = tpm::success_parameters_at(1, 1);
    tpm::put_2b(&mut params, &public);
    let unique_len = output_unique(kind).len();
    let unique_at = base + params.len() - unique_len;
    variable.push((unique_at, unique_len));
    if let KeygenKind::Ecc(_) = kind {
        variable.push((unique_at - 2 - unique_len, unique_len));
    }
    tpm::put_2b(&mut params, &creation);
    tpm::put_2b(&mut params, &HashAlg::Sha256.digest(&[&creation]));
    tpm::put_u16(&mut params, TPM_ST_CREATION);
    tpm::put_u32(&mut params, TPM_RH_OWNER);
    tpm::put_2b(&mut params, &[0; TICKET_DIGEST_BYTES]);
    variable.push((
        base + params.len() - TICKET_DIGEST_BYTES,
        TICKET_DIGEST_BYTES,
    ));
    let mut name = TPM_ALG_SHA256.to_be_bytes().to_vec();
    name.extend(vec![0; digest]);
    tpm::put_2b(&mut params, &name);
    variable.push((base + params.len() - digest, digest));
    let response = tpm::success_response(&[tpm::FIRST_TRANSIENT_HANDLE], &params, 1);
    let mut mask = vec![0xffu8; response.len()];
    for (at, len) in variable {
        mask[at..at + len].iter_mut().for_each(|b| *b = 0);
    }
    (response, mask)
}

pub fn input_width(_scenario: Scenario) -> usize {
    UNIQUE_BYTES
}

pub fn validate(_scenario: Scenario, _bytes: &[u8]) -> Result<(), String> {
    Ok(())
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let n = UNIQUE_BYTES;
    let mut one = vec![0u8; n];
    one[n - 1] = 1;
    let mut out = vec![
        seed("unique-zero-vs-ones", vec![0; n], vec![0xff; n]),
        seed("unique-zero-vs-one", vec![0; n], one),
        seed("unique-same-vs-same", vec![0x42; n], vec![0x42; n]),
    ];
    out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
        rng.bytes(n)
    }));
    out
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let kind = kind(scenario);
    let class = |unique: &[u8]| {
        let command = tpm::create_primary_command(TPM_RH_OWNER, &[], &template(kind, unique));
        let (expected, mask) = expected_response(kind);
        let mut spec = ClassSpec::new(Step::new("CreatePrimary", command), expected);
        spec.mask = mask;
        spec.check = Some(Check::PrimaryKey {
            kind: kind.name().into(),
        });
        spec.post = Some(Post {
            step: Step::new("FlushContext primary", tpm::flush_context(0))
                .handle_at(10, HandleRef::NextObject),
            expected: tpm::flush_response(),
        });
        spec
    };
    Ok(Built {
        shared: Vec::new(),
        classes: [class(&pair.a), class(&pair.b)],
        model: super::family::PairModel::secret(pair.a != pair.b)
            .public("template unique field", pair.a != pair.b),
        varying_public_values: vec![
            "template unique field (public input that selects the derived key)".into(),
            "generated public key, name and creation ticket (masked)".into(),
        ],
    })
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    let kind = kind(scenario);
    ScenarioDoc {
        harness: COMMAND_LEVEL.into(),
        entry_point: format!(
            "TPM2_CreatePrimary (0x131) under the owner hierarchy for a {} template, followed by FlushContext of the new object",
            kind.name()
        ),
        secret: "the primary key derived from the owner seed and the template (for RSA: the primes found by the seeded prime search, including rejected candidates)".into(),
        attacker_inputs: "the 32-byte unique field of the template".into(),
        observable_outputs: "handle, public key, creation data and ticket (all key material masked)".into(),
        classes: "two unique values; each selects a different derived key".into(),
        fixed: "template other than unique, hierarchy, response length".into(),
        timed_region: "CreatePrimary plus FlushContext of the created object (identical for both classes)".into(),
        correctness: "response code, handle and lengths exact; generated public key checked for validity (ECC point on curve, RSA modulus size and parity)".into(),
        interpretation: "the owner seed is fresh in every worker process, so the derived keys differ between processes; RSA generation time is expected to depend on the number of rejected prime candidates, which is a property of the derived key; ECC, AES and HMAC derivation have no rejection loop in either backend's seeded path".into(),
        randomized: false,
    }
}
