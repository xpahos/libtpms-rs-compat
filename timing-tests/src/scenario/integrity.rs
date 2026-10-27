use super::catalog::{AsymKind, Scenario};
use super::family::{Built, COMMAND_LEVEL, ClassSpec, PairModel, ScenarioDoc, random_seeds, seed};
use super::layout::{Creates, HandleRef, Patch, Post, Step, StepRef};
use super::{InputPair, Seed};
use crate::oracle::hash::HashAlg;
use crate::oracle::rsa::{RsaBits, pkcs1_sign_encode};
use crate::tpm::{self, Public, PublicDetail, Scheme, SymDef};

pub const IMPLEMENTED: bool = true;
pub const DELTA_BYTES: usize = 32;
const TICKET_BYTES: usize = 64;
const AUTH: [u8; 32] = [0x61; 32];
const KEY: [u8; 32] = [0x6b; 32];
const SEED: [u8; 32] = [0x73; 32];
const MESSAGE: &[u8] = b"tpms-timing integrity independent message";
const CREDENTIAL: [u8; 32] = [0x43; 32];
const TPM_CC_IMPORT: u32 = 0x156;

pub fn input_width(scenario: Scenario) -> usize {
    if scenario == Scenario::SignTicket {
        TICKET_BYTES
    } else {
        DELTA_BYTES
    }
}

pub fn validate(_scenario: Scenario, _bytes: &[u8]) -> Result<(), String> {
    Ok(())
}

pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let n = input_width(scenario);
    let mut first = vec![0; n];
    first[0] = 1;
    let mut last = vec![0; n];
    last[n - 1] = 1;
    let mut out = vec![
        seed("mismatch-first-byte-vs-last-byte", first, last.clone()),
        seed(
            "mismatch-all-bytes-vs-last-byte",
            vec![0xff; n],
            last.clone(),
        ),
        seed("valid-vs-mismatch-last-byte", vec![0; n], last),
        seed("valid-vs-valid", vec![0; n], vec![0; n]),
    ];
    out.extend(random_seeds(scenario, campaign_seed, random_pairs, |rng| {
        rng.bytes(n)
    }));
    out
}

fn valid(delta: &[u8]) -> bool {
    delta.iter().all(|b| *b == 0)
}

fn keyed_public() -> Public {
    Public {
        name_alg: tpm::TPM_ALG_SHA256,
        attributes: tpm::ATTR_USER_WITH_AUTH | tpm::ATTR_NO_DA | tpm::ATTR_SIGN,
        detail: PublicDetail::KeyedHash {
            scheme: Scheme::WithHash(tpm::TPM_ALG_HMAC, tpm::TPM_ALG_SHA256),
            unique: HashAlg::Sha256.digest(&[&SEED, &KEY]),
        },
    }
}

fn storage_primary(kind: AsymKind) -> Step {
    let detail = match kind {
        AsymKind::Rsa(bits) => PublicDetail::Rsa {
            symmetric: SymDef::aes128_cfb(),
            scheme: Scheme::Null,
            bits: bits.bits() as u16,
            modulus: Vec::new(),
        },
        AsymKind::Ecc(curve) => PublicDetail::Ecc {
            symmetric: SymDef::aes128_cfb(),
            scheme: Scheme::Null,
            curve: curve.tpm_id(),
            x: Vec::new(),
            y: Vec::new(),
        },
    };
    let public = Public {
        name_alg: tpm::TPM_ALG_SHA256,
        attributes: tpm::ATTR_FIXED_TPM
            | tpm::ATTR_FIXED_PARENT
            | tpm::ATTR_SENSITIVE_DATA_ORIGIN
            | tpm::ATTR_USER_WITH_AUTH
            | tpm::ATTR_NO_DA
            | tpm::ATTR_RESTRICTED
            | tpm::ATTR_DECRYPT,
        detail,
    };
    Step::new(
        "CreatePrimary storage parent",
        tpm::create_primary_command(tpm::TPM_RH_OWNER, &[], &public),
    )
    .creates(Creates::Object)
}

fn password(delta: &[u8]) -> ClassSpec {
    let supplied: Vec<_> = AUTH.iter().zip(delta).map(|(a, b)| a ^ b).collect();
    let mut parameters = Vec::new();
    tpm::put_2b(&mut parameters, MESSAGE);
    tpm::put_u16(&mut parameters, tpm::TPM_ALG_NULL);
    let measured = Step::new(
        "MAC password comparison",
        tpm::build_command(tpm::TPM_CC_MAC, &[0], &[&supplied], &parameters).bytes,
    )
    .handle_at(10, HandleRef::Shared(0));
    let expected = if valid(delta) {
        super::mac::mac_response(&HashAlg::Sha256.hmac(&KEY, &[MESSAGE]))
    } else {
        tpm::error_response(tpm::session_error(tpm::TPM_RC_BAD_AUTH, 1))
    };
    ClassSpec::new(measured, expected)
}

fn sign_ticket(delta: &[u8]) -> ClassSpec {
    let digest = HashAlg::Sha256.digest(&[MESSAGE]);
    let mut parameters = Vec::new();
    tpm::put_2b(&mut parameters, &digest);
    Scheme::WithHash(tpm::TPM_ALG_RSASSA, tpm::TPM_ALG_SHA256).marshal(&mut parameters);
    tpm::put_u16(&mut parameters, tpm::TPM_ST_HASHCHECK);
    tpm::put_u32(&mut parameters, tpm::TPM_RH_OWNER);
    tpm::put_2b(&mut parameters, &[0; TICKET_BYTES]);
    let built = tpm::build_command(tpm::TPM_CC_SIGN, &[0], &[&[]], &parameters);
    let at = built.parameters_at + 34 + 4 + 8;
    let measured = Step::new("Sign hashcheck ticket comparison", built.bytes)
        .handle_at(10, HandleRef::Shared(0))
        .patch(Patch {
            at,
            source: StepRef::Shared(1),
            from: 10 + 34 + 8,
            len: TICKET_BYTES,
            xor: delta.to_vec(),
        });
    let expected = if valid(delta) {
        let encoded = pkcs1_sign_encode(HashAlg::Sha256, &digest, RsaBits::B2048.bytes());
        let signature = RsaBits::B2048
            .key()
            .private(&encoded)
            .expect("encoded signature below modulus");
        let mut out = Vec::new();
        tpm::put_u16(&mut out, tpm::TPM_ALG_RSASSA);
        tpm::put_u16(&mut out, tpm::TPM_ALG_SHA256);
        tpm::put_2b(&mut out, &signature);
        tpm::success_response(&[], &out, 1)
    } else {
        tpm::error_response(tpm::parameter_error(tpm::TPM_RC_TICKET, 3))
    };
    ClassSpec::new(measured, expected)
}

fn activate(kind: AsymKind, delta: &[u8]) -> ClassSpec {
    // MakeCredential returns TPM2B_ID_OBJECT || TPM2B_ENCRYPTED_SECRET.
    // ID_OBJECT contains a sized SHA-256 HMAC and encrypted sized credential.
    let secret_bytes = match kind {
        AsymKind::Rsa(bits) => bits.bytes(),
        AsymKind::Ecc(curve) => 4 + 2 * curve.key_bytes(),
    };
    let len = 2 + 2 + 32 + 2 + CREDENTIAL.len() + 2 + secret_bytes;
    let built = tpm::build_command(
        tpm::TPM_CC_ACTIVATE_CREDENTIAL,
        &[0, 0],
        &[&[], &[]],
        &vec![0; len],
    );
    let mut xor = vec![0; len];
    xor[4..36].copy_from_slice(delta);
    let measured = Step::new("ActivateCredential outer HMAC comparison", built.bytes)
        .handle_at(10, HandleRef::Shared(1))
        .handle_at(14, HandleRef::Shared(0))
        .patch(Patch {
            at: built.parameters_at,
            source: StepRef::Shared(2),
            from: 10,
            len,
            xor,
        });
    let expected = if valid(delta) {
        tpm::success_response(&[], &tpm::sized(&CREDENTIAL), 2)
    } else {
        tpm::error_response(tpm::parameter_error(tpm::TPM_RC_INTEGRITY, 1))
    };
    ClassSpec::new(measured, expected)
}

fn load(delta: &[u8]) -> ClassSpec {
    // Import pads auth to SHA-256 width. Sensitive: type + sized auth/seed/key;
    // private: sized HMAC + sized AES IV + encrypted TPM2B_SENSITIVE.
    let private_bytes = 34 + 18 + 2 + (2 + 34 + 34 + 34);
    let public = keyed_public();
    let mut parameters = tpm::sized(&vec![0; private_bytes]);
    tpm::put_2b(&mut parameters, &public.marshal());
    let built = tpm::build_command(tpm::TPM_CC_LOAD, &[0], &[&[]], &parameters);
    let mut xor = vec![0; private_bytes + 2];
    xor[4..36].copy_from_slice(delta);
    let measured = Step::new("Load outer HMAC comparison", built.bytes)
        .handle_at(10, HandleRef::Shared(0))
        .patch(Patch {
            at: built.parameters_at,
            source: StepRef::Shared(1),
            from: 14,
            len: private_bytes + 2,
            xor,
        });
    let expected = if valid(delta) {
        tpm::success_response(
            &[tpm::FIRST_TRANSIENT_HANDLE + 1],
            &tpm::sized(&public.name()),
            1,
        )
    } else {
        tpm::error_response(tpm::parameter_error(tpm::TPM_RC_INTEGRITY, 1))
    };
    let mut spec = ClassSpec::new(measured, expected);
    // Cleanup follows actual TPM success, including unexpected acceptance of an
    // invalid blob; registering it only for expected success would leak a child.
    spec.post = Some(Post {
        step: Step::new("Flush loaded child", tpm::flush_context(0))
            .handle_at(10, HandleRef::NextObject),
        expected: tpm::flush_response(),
    });
    spec
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let (shared, classes, input) = match scenario {
        Scenario::PasswordAuth => {
            let sensitive = tpm::sensitive(tpm::TPM_ALG_KEYEDHASH, &AUTH, &SEED, &KEY);
            let setup = Step::new(
                "LoadExternal password protected key",
                tpm::load_external_command(Some(&sensitive), &keyed_public(), tpm::TPM_RH_NULL),
            )
            .creates(Creates::Object);
            (
                vec![setup],
                [password(&pair.a), password(&pair.b)],
                "supplied password",
            )
        }
        Scenario::SignTicket => {
            let key = Step::new(
                "LoadExternal RSA signer",
                super::asym::rsa_load(
                    RsaBits::B2048,
                    tpm::ATTR_SIGN | tpm::ATTR_USER_WITH_AUTH | tpm::ATTR_NO_DA,
                    Scheme::WithHash(tpm::TPM_ALG_RSASSA, tpm::TPM_ALG_SHA256),
                ),
            )
            .creates(Creates::Object);
            let mut parameters = tpm::sized(MESSAGE);
            tpm::put_u16(&mut parameters, tpm::TPM_ALG_SHA256);
            tpm::put_u32(&mut parameters, tpm::TPM_RH_OWNER);
            let hash = Step::new(
                "Hash message to obtain hierarchy ticket",
                tpm::build_command(tpm::TPM_CC_HASH, &[], &[], &parameters).bytes,
            );
            (
                vec![key, hash],
                [sign_ticket(&pair.a), sign_ticket(&pair.b)],
                "supplied hashcheck ticket HMAC",
            )
        }
        Scenario::ActivateCredential(kind) => {
            let public = keyed_public();
            let sensitive = tpm::sensitive(tpm::TPM_ALG_KEYEDHASH, &[], &SEED, &KEY);
            let target = Step::new(
                "LoadExternal activation target",
                tpm::load_external_command(Some(&sensitive), &public, tpm::TPM_RH_NULL),
            )
            .creates(Creates::Object);
            let mut parameters = tpm::sized(&CREDENTIAL);
            tpm::put_2b(&mut parameters, &public.name());
            let make = Step::new(
                "MakeCredential for independently chosen plaintext",
                tpm::build_command(tpm::TPM_CC_MAKE_CREDENTIAL, &[0], &[], &parameters).bytes,
            )
            .handle_at(10, HandleRef::Shared(0));
            (
                vec![storage_primary(kind), target, make],
                [activate(kind, &pair.a), activate(kind, &pair.b)],
                "supplied credential integrity HMAC",
            )
        }
        Scenario::LoadIntegrity(kind) => {
            let public = keyed_public();
            let sensitive = tpm::sensitive(tpm::TPM_ALG_KEYEDHASH, &[], &SEED, &KEY);
            let mut parameters = tpm::sized(&[]);
            tpm::put_2b(&mut parameters, &public.marshal());
            tpm::put_2b(&mut parameters, &tpm::sized(&sensitive));
            tpm::put_2b(&mut parameters, &[]);
            tpm::put_u16(&mut parameters, tpm::TPM_ALG_NULL);
            let import = Step::new(
                "Import independently specified child",
                tpm::build_command(TPM_CC_IMPORT, &[0], &[&[]], &parameters).bytes,
            )
            .handle_at(10, HandleRef::Shared(0));
            (
                vec![storage_primary(kind), import],
                [load(&pair.a), load(&pair.b)],
                "supplied private blob integrity HMAC",
            )
        }
        _ => {
            return Err(format!(
                "{scenario}: not an authentication/integrity scenario"
            ));
        }
    };
    Ok(Built {
        shared,
        classes,
        model: PairModel::secret(false).public(input, pair.a != pair.b),
        varying_public_values: vec![input.into()],
    })
}

pub fn doc(scenario: Scenario) -> ScenarioDoc {
    let (entry, secret, correctness) = match scenario {
        Scenario::PasswordAuth => (
            "TPM2_MAC password authorization",
            "fixed object authValue",
            "exact independent HMAC-SHA256 response on success; session-1 BAD_AUTH on mismatch",
        ),
        Scenario::SignTicket => (
            "TPM2_Sign hashcheck ticket verification",
            "fixed hierarchy proof",
            "exact independent RSA PKCS#1 v1.5 signature over SHA-256(message); parameter-3 TICKET on mismatch. Setup Hash supplies the opaque 64-byte context-integrity ticket HMAC",
        ),
        Scenario::ActivateCredential(_) => (
            "TPM2_ActivateCredential outer integrity verification",
            "fixed storage key and per-setup encrypted seed",
            "exact independently chosen credential plaintext on success; parameter-1 INTEGRITY on mismatch. MakeCredential supplies the opaque wrapping in setup",
        ),
        Scenario::LoadIntegrity(_) => (
            "TPM2_Load outer integrity verification",
            "fixed storage-parent seed",
            "exact independently computed child Name and allocated handle on success; parameter-1 INTEGRITY on mismatch. Import wraps the independently specified child in setup; every actual successful Load is flushed, including unexpected acceptance",
        ),
        _ => unreachable!(),
    };
    ScenarioDoc {
        harness: COMMAND_LEVEL.into(), entry_point: entry.into(), secret: secret.into(),
        attacker_inputs: "caller-supplied authentication bytes, represented as a full-width XOR delta from a valid value".into(),
        observable_outputs: "response code, response size and successful result".into(),
        classes: "same-outcome first/last-byte and full-width mismatches; valid/invalid and identical-valid controls; random deltas".into(),
        fixed: "one shared object and shared setup material for both classes; object handles and all other command bytes".into(),
        timed_region: if matches!(scenario, Scenario::LoadIntegrity(_)) {
            "TPM2_Load plus FlushContext after successful Load; setup and warmup excluded".into()
        } else {
            "one TPMLIB_Process command; setup and warmup excluded".into()
        },
        correctness: correctness.into(),
        interpretation: "public-input comparisons against fixed secret state; different response codes are visible-outcome confounders; no secret-only claim".into(),
        randomized: false,
    }
}
