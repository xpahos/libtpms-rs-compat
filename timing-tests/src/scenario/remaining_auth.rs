//! Stateful authorization and independently checked object protection.
use super::{
    InputPair, Seed,
    catalog::{AsymKind, ImportLayer, RequestProtection, ResponseProtection, Scenario},
    family::{self, Built, Check, ClassSpec, PairModel, ScenarioDoc},
    layout::{Creates, HandleRef, Patch as SetupPatch, Step as LayoutStep, StepRef},
};
use crate::{
    oracle::{
        ec::CurveId,
        hash::HashAlg,
        kdf::{kdfa, kdfe},
        protection as wrap,
    },
    program::{Contract, Part, Patch, Program, Resource, ResponseArea, ResponseRange, Step},
    tpm::{self, Public, PublicDetail, Scheme, SymDef},
};
use serde::{Deserialize, Serialize};

const AUTH: [u8; 32] = [0x61; 32];
const KEY: [u8; 32] = [0x6b; 32];
const SEED: [u8; 32] = [0x73; 32];
const INNER: [u8; 16] = [0x49; 16];
const MESSAGE: &[u8] = b"remaining authorization independent MAC";
const IMPORT: u32 = 0x156;
const DUPLICATE: u32 = 0x14b;
const REWRAP: u32 = 0x152;

pub fn input_width(scenario: Scenario) -> usize {
    match scenario {
        Scenario::HmacAuth(hash, _) | Scenario::HmacAuthBound(hash) => hash.size(),
        Scenario::Duplicate(..) => 16,
        _ => 32,
    }
}
pub fn validate(_: Scenario, _: &[u8]) -> Result<(), String> {
    Ok(())
}
fn valid(delta: &[u8]) -> bool {
    delta.iter().all(|b| *b == 0)
}
fn secret_session(scenario: Scenario) -> bool {
    matches!(
        scenario,
        Scenario::HmacAuthBoundSecret(..)
            | Scenario::HmacAuthSaltedSecret
            | Scenario::HmacAuthRequestSecret(..)
    )
}
pub fn seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    if secret_session(scenario) {
        return secret_session_seeds(scenario, campaign_seed, random_pairs);
    }
    let n = input_width(scenario);
    let mut first = vec![0; n];
    first[0] = 1;
    let mut last = vec![0; n];
    last[n - 1] = 1;
    let mut out = vec![
        family::seed("mismatch-first-byte-vs-last-byte", first, last.clone()),
        family::seed(
            "mismatch-all-bytes-vs-last-byte",
            vec![255; n],
            last.clone(),
        ),
        family::seed("valid-vs-mismatch-last-byte", vec![0; n], last),
        family::seed("valid-vs-valid", vec![0; n], vec![0; n]),
    ];
    if matches!(scenario, Scenario::Duplicate(..)) {
        for seed in &mut out {
            seed.name = seed
                .name
                .replace("mismatch", "key-variation")
                .replace("valid", "baseline");
        }
    }
    out.extend(family::random_seeds(
        scenario,
        campaign_seed,
        random_pairs,
        |rng| rng.bytes(n),
    ));
    out
}
/// Secret-varying seed set: every class pair authorizes successfully, so the
/// only differences are the equal-length secret bytes. The last pair is the
/// identical-input control.
fn secret_session_seeds(scenario: Scenario, campaign_seed: u64, random_pairs: usize) -> Vec<Seed> {
    let mut first = vec![0; 32];
    first[0] = 1;
    let mut last = vec![0; 32];
    last[31] = 1;
    let mut out = vec![
        family::seed("secret-zero-vs-ones", vec![0; 32], vec![255; 32]),
        family::seed("secret-first-byte-vs-last-byte", first, last.clone()),
        family::seed("secret-ones-vs-last-byte", vec![255; 32], last),
        family::seed("secret-same-vs-same", vec![0; 32], vec![0; 32]),
    ];
    out.extend(family::random_seeds(
        scenario,
        campaign_seed,
        random_pairs,
        |rng| rng.bytes(32),
    ));
    out
}
fn child() -> Public {
    Public {
        name_alg: tpm::TPM_ALG_SHA256,
        attributes: tpm::ATTR_USER_WITH_AUTH | tpm::ATTR_NO_DA | tpm::ATTR_SIGN,
        detail: PublicDetail::KeyedHash {
            scheme: Scheme::WithHash(tpm::TPM_ALG_HMAC, tpm::TPM_ALG_SHA256),
            unique: HashAlg::Sha256.digest(&[&SEED, &KEY]),
        },
    }
}
fn sensitive() -> Vec<u8> {
    sensitive_with(&AUTH)
}
fn sensitive_with(auth: &[u8]) -> Vec<u8> {
    tpm::sized(&tpm::sensitive(tpm::TPM_ALG_KEYEDHASH, auth, &SEED, &KEY))
}
fn policy() -> Vec<u8> {
    HashAlg::Sha256.digest(&[&[0; 32], &0x16cu32.to_be_bytes(), &DUPLICATE.to_be_bytes()])
}
fn start(hash: HashAlg, protection: ResponseProtection, policy: bool) -> Step {
    let n = hash.size();
    let mut params = tpm::sized(&vec![0x56; n]);
    tpm::put_2b(&mut params, &[]);
    params.push(u8::from(policy));
    match protection {
        ResponseProtection::None => SymDef::Null.marshal(&mut params),
        ResponseProtection::Aes128Cfb => SymDef::aes128_cfb().marshal(&mut params),
        ResponseProtection::Xor => {
            tpm::put_u16(&mut params, 0x000a);
            tpm::put_u16(&mut params, hash.alg_id());
        }
    }
    tpm::put_u16(&mut params, hash.alg_id());
    let mut contract = Contract::exact(tpm::success_response(&[0], &tpm::sized(&vec![0; n]), 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    let mut step = Step::new(
        tpm::build_command(0x176, &[tpm::TPM_RH_NULL, tpm::TPM_RH_NULL], &[], &params).bytes,
        contract,
    );
    step.produces = Resource::Handle;
    step
}
fn copy_session(at: u16) -> Patch {
    copy_response_handle(0, at)
}
fn copy_response_handle(step: u8, at: u16) -> Patch {
    Patch::Copy {
        at,
        source: ResponseRange {
            step,
            area: ResponseArea::Raw,
            offset: 10,
            len: 4,
        },
        xor: vec![0; 4],
    }
}
/// A LoadExternal step inside a per-class program: its response carries the
/// loaded object handle followed by the object's Name. The Name is derived
/// independently from the public object and validated exactly; only the
/// dynamic handle is masked. Later steps read the handle through a raw copy.
fn loaded_step(command: Vec<u8>, name: &[u8]) -> Step {
    let mut contract = Contract::exact(tpm::success_response(&[0], &tpm::tpm2b(name), 0), 1);
    contract.mask[10..14].fill(0);
    let mut step = Step::new(command, contract);
    step.produces = Resource::Handle;
    step
}
fn session_command(
    code: u32,
    handles: &[u32],
    caller: &[u8],
    attributes: u8,
    auth: &[u8],
    params: &[u8],
) -> Vec<u8> {
    let mut session = vec![0; 4];
    tpm::put_2b(&mut session, caller);
    session.push(attributes);
    tpm::put_2b(&mut session, auth);
    let mut body = Vec::new();
    for handle in handles {
        tpm::put_u32(&mut body, *handle);
    }
    tpm::put_u32(&mut body, session.len() as u32);
    body.extend(session);
    body.extend(params);
    tpm::command(tpm::TPM_ST_SESSIONS, code, &body)
}
fn session_response(params: &[u8], hash: HashAlg, attributes: u8, policy: bool) -> Vec<u8> {
    let mut response = tpm::success_response(&[], params, 1);
    response.truncate(response.len() - 5);
    tpm::put_2b(&mut response, &vec![0; hash.size()]);
    response.push(attributes);
    tpm::put_2b(
        &mut response,
        &vec![0; if policy { 0 } else { hash.size() }],
    );
    let len = response.len() as u32;
    response[2..6].copy_from_slice(&len.to_be_bytes());
    response
}
fn program_spec(
    program: Program,
    label: &str,
    handles: &[(usize, HandleRef)],
    oracle: Oracle,
) -> Result<ClassSpec, String> {
    let last = program.steps.len() - 1;
    program_spec_absolute(
        program,
        label,
        &handles
            .iter()
            .map(|(nested, reference)| (last, *nested, *reference))
            .collect::<Vec<_>>(),
        oracle,
    )
}
fn program_spec_absolute(
    program: Program,
    label: &str,
    handles: &[(usize, usize, HandleRef)],
    oracle: Oracle,
) -> Result<ClassSpec, String> {
    let encoded = program.encode()?;
    let (expected, mask) = program.expectation()?;
    let mut measured = LayoutStep::new(label, encoded.bytes);
    for (step, nested, reference) in handles {
        measured = measured.handle_at(encoded.command_offsets[*step] + nested, *reference);
    }
    let mut spec = ClassSpec::new(measured, expected);
    spec.mask = mask;
    spec.check = Some(Check::Protection {
        oracle: Box::new(oracle),
        program: Some(program),
    });
    Ok(spec)
}
fn hmac(hash: HashAlg, protection: ResponseProtection, delta: &[u8]) -> Result<ClassSpec, String> {
    let n = hash.size();
    let caller = vec![0x56; n];
    let attributes = if protection == ResponseProtection::None {
        1
    } else {
        0x41
    };
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    let command = session_command(
        tpm::TPM_CC_MAC,
        &[0],
        &caller,
        attributes,
        &vec![0; n],
        &params,
    );
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = session_response(&out, hash, attributes, false);
    let slot = success.len() as u16;
    let mut contract = if valid(delta) {
        Contract::exact(success, 0)
    } else {
        Contract::exact(tpm::error_response(0x9a2), 0)
    };
    if valid(delta) {
        if protection != ResponseProtection::None {
            contract.mask[16..14 + out.len()].fill(0);
        }
        let auth = 14 + out.len();
        contract.mask[auth + 2..auth + 2 + n].fill(0);
        contract.mask[auth + 5 + n..].fill(0);
    }
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_session(18));
    command.patches.push(Patch::Hmac {
        at: (27 + n) as u16,
        hash,
        key: AUTH.to_vec(),
        parts: vec![
            Part::Literal(family::cp_hash(
                hash,
                tpm::TPM_CC_MAC,
                &[&child().name()],
                &params,
            )),
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 0,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![attributes]),
        ],
        xor: delta.to_vec(),
    });
    let program = Program::new(vec![start(hash, protection, false), command]);
    program_spec(
        program,
        "fresh HMAC authorization and response protection",
        &[(10, HandleRef::Shared(0))],
        Oracle::Hmac {
            hash,
            protection,
            valid: valid(delta),
        },
    )
}

/// Deterministic public salt-key material: the caller chooses the salt point
/// and the decrypting key scalar, so the recovered salt is a public constant.
fn session_salt() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use crate::oracle::bytes::{from_be, to_fixed};
    let curve = CurveId::NistP256;
    let d = to_fixed(
        &from_be(&HashAlg::Sha256.digest(&[b"tpms-timing-tests salted auth key v1"])),
        curve.key_bytes(),
    );
    salt_material(&d)
}
/// Salt material for a caller-chosen salt-key scalar: the loaded key object
/// with its independently derived Name, and the salt recovered from the fixed
/// peer point (label SECRET, u = peer x, v = key x, mirroring secret.rs
/// kdfe_shared).
fn salt_material(from_be_bytes: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use crate::oracle::bytes::{from_be, to_fixed};
    let curve = CurveId::NistP256;
    let c = curve.curve();
    let d = from_be(from_be_bytes);
    let attributes = tpm::ATTR_USER_WITH_AUTH | tpm::ATTR_NO_DA | tpm::ATTR_DECRYPT;
    let (load, q) = super::asym::ecc_load(
        curve,
        attributes,
        Scheme::Null,
        &to_fixed(&d, curve.key_bytes()),
    );
    // The expected response Name is derived independently from the public
    // point of the class salt key.
    let name = super::asym::ecc_public(curve, attributes, Scheme::Null, &q).name();
    let peer_scalar = to_fixed(
        &from_be(&HashAlg::Sha256.digest(&[b"tpms-timing-tests salted auth peer v1"])),
        curve.key_bytes(),
    );
    let peer = c.mul_g(&from_be(&peer_scalar)).expect("salt peer point");
    let shared = c.mul(&d, &peer).expect("salt shared point");
    let (shared_x, _) = c.encode(&shared);
    let (peer_x, _) = c.encode(&peer);
    let (key_x, _) = c.encode(&q);
    let salt = kdfe(
        HashAlg::Sha256,
        &shared_x,
        b"SECRET\0",
        &peer_x,
        &key_x,
        256,
    );
    (load, name, salt)
}
/// Maps a class secret to a valid P-256 salt-key scalar: the scalar is
/// (input mod (n-1)) + 1, so distinct inputs keep distinct scalars and every
/// seed value, including all-zero, stays usable.
fn salt_scalar(input: &[u8]) -> Vec<u8> {
    use crate::oracle::bytes::{from_be, to_fixed};
    let curve = CurveId::NistP256;
    let c = curve.curve();
    let d = (from_be(input) % (&c.n - 1u32)) + 1u32;
    to_fixed(&d, curve.key_bytes())
}
fn start_nonce(frame: &[u8], hash: HashAlg) -> Result<Vec<u8>, String> {
    let initial = tpm::response_parameters(frame, 1).ok_or("start response")?;
    let (initial_nonce, end) = tpm::read_2b(initial, 0).ok_or("start nonce framing")?;
    if end != initial.len() || initial_nonce.len() != hash.size() {
        return Err("start nonce width".into());
    }
    Ok(initial_nonce.to_vec())
}
/// StartAuthSession with an explicit symmetric definition (parameter-protection
/// sessions keep symmetric != NULL) for the given session hash.
fn start_symmetric(hash: HashAlg, protection: RequestProtection) -> Step {
    let n = hash.size();
    let caller = vec![0x57; n];
    let mut params = tpm::sized(&caller);
    tpm::put_2b(&mut params, &[]);
    params.push(0);
    match protection {
        RequestProtection::Aes128Cfb => SymDef::aes128_cfb().marshal(&mut params),
        RequestProtection::Xor => {
            tpm::put_u16(&mut params, 0x000a);
            tpm::put_u16(&mut params, hash.alg_id());
        }
    }
    tpm::put_u16(&mut params, hash.alg_id());
    let mut contract = Contract::exact(tpm::success_response(&[0], &tpm::sized(&vec![0; n]), 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    let mut step = Step::new(
        tpm::build_command(0x176, &[tpm::TPM_RH_NULL, tpm::TPM_RH_NULL], &[], &params).bytes,
        contract,
    );
    step.produces = Resource::Handle;
    step
}
fn hmac_bound(hash: HashAlg, delta: &[u8]) -> Result<ClassSpec, String> {
    let n = hash.size();
    let caller = vec![0x56; n];
    let mut params = tpm::sized(&caller);
    tpm::put_2b(&mut params, &[]);
    params.push(0);
    SymDef::Null.marshal(&mut params);
    tpm::put_u16(&mut params, hash.alg_id());
    let nonce = tpm::sized(&vec![0; n]);
    let mut contract = Contract::exact(tpm::success_response(&[0], &nonce, 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    // Bind to the HMAC key object itself (0x80000000 placeholder, substituted
    // with the shared object handle at an absolute program offset). Handle 1
    // is tpmKey (TPM_RH_NULL); handle 2 is bind (the shared object).
    let mut session = Step::new(
        tpm::build_command(0x176, &[tpm::TPM_RH_NULL, 0x8000_0000], &[], &params).bytes,
        contract,
    );
    session.produces = Resource::Handle;
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    let command = session_command(tpm::TPM_CC_MAC, &[0], &caller, 1, &vec![0; n], &params);
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = session_response(&out, hash, 1, false);
    let slot = success.len() as u16;
    let mut contract = if valid(delta) {
        Contract::exact(success, 0)
    } else {
        Contract::exact(tpm::error_response(0x9a2), 0)
    };
    if valid(delta) {
        let auth = 14 + out.len();
        contract.mask[auth + 2..auth + 2 + n].fill(0);
        contract.mask[auth + 5 + n..].fill(0);
    }
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_session(18));
    command.patches.push(Patch::SessionHmac {
        at: (27 + n) as u16,
        hash,
        // A session bound to the authorized entity derives its key from the
        // bind authValue (the salt stays empty) and omits includeAuthValue.
        kdf_key: AUTH.to_vec(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 0,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(caller.clone())],
        extra_key: vec![],
        parts: vec![
            Part::Literal(family::cp_hash(
                hash,
                tpm::TPM_CC_MAC,
                &[&child().name()],
                &params,
            )),
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 0,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![1]),
        ],
        xor: delta.to_vec(),
        cp_hash: None,
    });
    let program = Program::new(vec![session, command]);
    program_spec_absolute(
        program,
        "fresh bound HMAC authorization",
        &[(0, 14, HandleRef::Shared(0)), (1, 10, HandleRef::Shared(0))],
        Oracle::HmacBound {
            hash,
            valid: valid(delta),
        },
    )
}
fn hmac_salted(delta: &[u8]) -> Result<ClassSpec, String> {
    let hash = HashAlg::Sha256;
    let n = hash.size();
    let caller = vec![0x56; n];
    let (_, _, salt) = session_salt();
    let mut params = tpm::sized(&caller);
    // encryptedSalt carries the caller-chosen salt point.
    tpm::put_2b(&mut params, &salt_point_bytes());
    params.push(0);
    SymDef::Null.marshal(&mut params);
    tpm::put_u16(&mut params, hash.alg_id());
    let nonce = tpm::sized(&vec![0; n]);
    let mut contract = Contract::exact(tpm::success_response(&[0], &nonce, 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    // Handle 1 is tpmKey (the shared ECC salt-decryption key); bind comes
    // from the encryptedSalt seed, so handle 2 stays TPM_RH_NULL.
    let mut session = Step::new(
        tpm::build_command(0x176, &[0x8000_0000, tpm::TPM_RH_NULL], &[], &params).bytes,
        contract,
    );
    session.produces = Resource::Handle;
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    let command = session_command(tpm::TPM_CC_MAC, &[0], &caller, 1, &vec![0; n], &params);
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = session_response(&out, hash, 1, false);
    let slot = success.len() as u16;
    let mut contract = if valid(delta) {
        Contract::exact(success, 0)
    } else {
        Contract::exact(tpm::error_response(0x9a2), 0)
    };
    if valid(delta) {
        let auth = 14 + out.len();
        contract.mask[auth + 2..auth + 2 + n].fill(0);
        contract.mask[auth + 5 + n..].fill(0);
    }
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_session(18));
    command.patches.push(Patch::SessionHmac {
        at: (27 + n) as u16,
        hash,
        // bind is NULL (empty authValue); the KDF key is the decrypted salt.
        kdf_key: salt,
        u_parts: vec![Part::Response(ResponseRange {
            step: 0,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(caller.clone())],
        // The authorized entity is unbound, so includeAuthValue appends AUTH.
        extra_key: AUTH.to_vec(),
        parts: vec![
            Part::Literal(family::cp_hash(
                hash,
                tpm::TPM_CC_MAC,
                &[&child().name()],
                &params,
            )),
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 0,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![1]),
        ],
        xor: delta.to_vec(),
        cp_hash: None,
    });
    let program = Program::new(vec![session, command]);
    program_spec_absolute(
        program,
        "fresh salted HMAC authorization",
        &[(0, 10, HandleRef::Shared(1)), (1, 10, HandleRef::Shared(0))],
        Oracle::HmacSalted {
            valid: valid(delta),
        },
    )
}
fn salt_point_bytes() -> Vec<u8> {
    use crate::oracle::bytes::{from_be, to_fixed};
    let curve = CurveId::NistP256;
    let c = curve.curve();
    let peer_scalar = to_fixed(
        &from_be(&HashAlg::Sha256.digest(&[b"tpms-timing-tests salted auth peer v1"])),
        curve.key_bytes(),
    );
    let peer = c.mul_g(&from_be(&peer_scalar)).expect("salt peer point");
    super::asym::ecc_point_bytes(curve, &peer)
}
fn hmac_request(protection: RequestProtection, delta: &[u8]) -> Result<ClassSpec, String> {
    let hash = HashAlg::Sha256;
    let n = hash.size();
    let caller = vec![0x56; n];
    let session_caller = vec![0x57; n];
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    // Two sessions: an authorization session and a decrypt session whose
    // nonceTPM must enter the authorization HMAC (nonce binding).
    let mut session0 = vec![0; 4];
    tpm::put_2b(&mut session0, &caller);
    session0.push(1);
    tpm::put_2b(&mut session0, &vec![0; n]);
    let mut session1 = vec![0; 4];
    tpm::put_2b(&mut session1, &session_caller);
    session1.push(0x21);
    tpm::put_2b(&mut session1, &[]);
    // The decrypt session's key is legitimately empty, so its empty request
    // HMAC is accepted without computation. The command body starts with the
    // MAC object handle as a zero placeholder for the layout handle reference
    // at command offset 10, followed by an explicit u32 authorizationSize.
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    tpm::put_u32(&mut body, (session0.len() + session1.len()) as u32);
    body.extend_from_slice(&session0);
    body.extend_from_slice(&session1);
    body.extend_from_slice(&params);
    let command = tpm::command(tpm::TPM_ST_SESSIONS, tpm::TPM_CC_MAC, &body);
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = request_response(&out, n, &[]);
    let slot = success.len() as u16;
    let mut contract = if valid(delta) {
        Contract::exact(success, 0)
    } else {
        Contract::exact(tpm::error_response(0x9a2), 0)
    };
    if valid(delta) {
        // MAC output is deterministic (the TPM always decrypts the same
        // plaintext); only the fresh authorization nonces are masked.
        let auth = 14 + out.len();
        let session1_at = 14 + out.len() + 5 + 2 * n;
        contract.mask[auth + 2..auth + 2 + n].fill(0);
        // The bound session signs the response with its runtime session key;
        // the oracle recomputes the same HMAC from the fresh nonces instead.
        contract.mask[auth + 5 + n..auth + 5 + 2 * n].fill(0);
        contract.mask[session1_at + 2..session1_at + 2 + n].fill(0);
    }
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_session(18));
    command.patches.push(Patch::Copy {
        at: (18 + 9 + 2 * n) as u16,
        source: ResponseRange {
            step: 1,
            area: ResponseArea::Raw,
            offset: 10,
            len: 4,
        },
        xor: vec![0; 4],
    });
    // Runtime request-parameter encryption using the fresh session-1 nonces.
    command.patches.push(Patch::Encrypt {
        at: (36 + 3 * n + 2) as u16,
        hash,
        cfb: protection == RequestProtection::Aes128Cfb,
        key: crate::program::CipherKey::Fixed(vec![]),
        caller: session_caller.clone(),
        nonce: ResponseRange {
            step: 1,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        },
        plain: MESSAGE.to_vec(),
    });
    command.patches.push(Patch::SessionHmac {
        at: (27 + n) as u16,
        hash,
        // The authorization session is bound to the MAC'd object: its key is
        // the sessionKey derived from the bind authValue, and the fresh
        // nonceTPM of the decrypt session is folded into this HMAC, binding
        // the request to session 1 (nonce binding).
        kdf_key: AUTH.to_vec(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 0,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(caller.clone())],
        // A session bound to the authorized entity omits includeAuthValue.
        extra_key: vec![],
        parts: vec![
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 0,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Response(ResponseRange {
                step: 1,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![1]),
        ],
        xor: delta.to_vec(),
        // Both backends authorize BEFORE decrypting: the cpHash inside this
        // request HMAC covers the first parameter in its encrypted form, and
        // the ciphertext depends on the decrypt session's fresh nonceTPM, so
        // the cpHash is derived at run time alongside the cipher.
        cp_hash: Some(crate::program::EncryptedCpHash {
            cc: tpm::TPM_CC_MAC,
            name: child().name(),
            cfb: protection == RequestProtection::Aes128Cfb,
            key: crate::program::CipherKey::Fixed(vec![]),
            caller: session_caller.clone(),
            nonce: ResponseRange {
                step: 1,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            },
            prefix: params[..2].to_vec(),
            suffix: params[2 + MESSAGE.len()..].to_vec(),
            plain: MESSAGE.to_vec(),
        }),
    });
    let mut bind_params = tpm::sized(&caller);
    tpm::put_2b(&mut bind_params, &[]);
    bind_params.push(0);
    SymDef::Null.marshal(&mut bind_params);
    tpm::put_u16(&mut bind_params, hash.alg_id());
    let bind_nonce = tpm::sized(&vec![0; n]);
    let mut bind_contract = Contract::exact(tpm::success_response(&[0], &bind_nonce, 0), 1);
    bind_contract.mask[10..14].fill(0);
    bind_contract.mask[16..].fill(0);
    // Handle 1 is tpmKey (TPM_RH_NULL); handle 2 is bind (the shared object).
    let mut bound_start = Step::new(
        tpm::build_command(0x176, &[tpm::TPM_RH_NULL, 0x8000_0000], &[], &bind_params).bytes,
        bind_contract,
    );
    bound_start.produces = Resource::Handle;
    let program = Program::new(vec![
        bound_start,
        start_symmetric(hash, protection),
        command,
    ]);
    program_spec_absolute(
        program,
        "fresh two-session authorization with request parameter protection",
        &[(0, 14, HandleRef::Shared(0)), (2, 10, HandleRef::Shared(0))],
        Oracle::HmacRequest {
            protection,
            valid: valid(delta),
        },
    )
}
/// Builds the two-session MAC response frame. The decrypt session's HMAC is
/// `session1_hmac`: empty for the legitimately empty session key of the
/// empty-key scenarios, or `n` masked bytes for a salt-derived key.
fn request_response(params: &[u8], n: usize, session1_hmac: &[u8]) -> Vec<u8> {
    let mut response = tpm::success_response(&[], params, 2);
    response.truncate(response.len() - 10);
    tpm::put_2b(&mut response, &vec![0; n]);
    response.push(1);
    tpm::put_2b(&mut response, &vec![0; n]);
    tpm::put_2b(&mut response, &vec![0; n]);
    response.push(0x21);
    tpm::put_2b(&mut response, session1_hmac);
    let len = response.len() as u32;
    response[2..6].copy_from_slice(&len.to_be_bytes());
    response
}
/// How the decrypt session's authorization is verified: an empty session key
/// legitimately produces an empty HMAC, while a salt-derived key produces a
/// full HMAC that must verify against an independent derivation.
enum Session1Key<'a> {
    Empty,
    Salted(&'a [u8]),
}
fn check_request_response(
    response: &[u8],
    frames: &[&[u8]],
    session0: usize,
    session1: usize,
    session1_key: Session1Key<'_>,
) -> Result<(), String> {
    let hash = HashAlg::Sha256;
    let n = hash.size();
    let n0 = start_nonce(frames[session0], hash)?;
    let n1 = start_nonce(frames[session1], hash)?;
    if n0 == n1 {
        return Err("distinct session nonces expected".into());
    }
    let params = tpm::response_parameters(response, 0).ok_or("MAC response")?;
    let (mac, end) = tpm::read_2b(params, 0).ok_or("MAC output framing")?;
    if end != params.len() {
        return Err("MAC trailing parameters".into());
    }
    // Whatever ciphertext the interpreter produced, the TPM must have
    // recovered the known plaintext: the MAC is computed over the decrypted
    // parameter bytes and is checked against the independent oracle.
    exact(mac, &hash.hmac(&KEY, &[MESSAGE]), "decrypted parameter MAC")?;
    let auth_at = 14 + params.len();
    let caller = vec![0x56; n];
    let (nonce0, at) = tpm::read_2b(response, auth_at).ok_or("response session0 nonce")?;
    let attributes0 = *response.get(at).ok_or("response session0 attributes")?;
    let (hmac0, at) = tpm::read_2b(response, at + 1).ok_or("response session0 HMAC")?;
    let (nonce1, at) = tpm::read_2b(response, at).ok_or("response session1 nonce")?;
    let attributes1 = *response.get(at).ok_or("response session1 attributes")?;
    let (hmac1, end) = tpm::read_2b(response, at + 1).ok_or("response session1 HMAC")?;
    if nonce0.len() != n
        || nonce1.len() != n
        || nonce0 == n0
        || nonce1 == n1
        || attributes0 != 1
        || attributes1 != 0x21
        || hmac0.len() != n
        || end != response.len()
    {
        return Err("response authorization framing/freshness".into());
    }
    let rp = hash.digest(&[&0u32.to_be_bytes(), &tpm::TPM_CC_MAC.to_be_bytes(), params]);
    let session_key = kdfa(hash, &AUTH, b"ATH", &n0, &caller, hash.size() * 8);
    // A session bound to the authorized entity signs the response with the
    // sessionKey alone, folding the bind authValue into the derivation.
    exact(
        hmac0,
        &hash.hmac(&session_key, &[&rp, nonce0, &caller, &[attributes0]]),
        "response HMAC",
    )?;
    match session1_key {
        // An empty session key legitimately produces an empty HMAC: the
        // backend accepts it without computing anything.
        Session1Key::Empty => {
            if !hmac1.is_empty() {
                return Err("response session1 HMAC must be empty".into());
            }
        }
        // The salted decrypt session signs the response with its
        // salt-derived sessionKey: derive it independently over the recovered
        // salt, the fresh creation nonceTPM and the caller nonce.
        Session1Key::Salted(salt) => {
            if hmac1.len() != n {
                return Err("response session1 HMAC width".into());
            }
            let session_caller = vec![0x57; n];
            let session_key = kdfa(hash, salt, b"ATH", &n1, &session_caller, hash.size() * 8);
            exact(
                hmac1,
                &hash.hmac(
                    &session_key,
                    &[&rp, nonce1, &session_caller, &[attributes1]],
                ),
                "response session1 HMAC",
            )?;
        }
    }
    // Protected contents are validated end-to-end: the request HMACs only
    // pass when the cpHash over the encrypted parameter matches the runtime
    // derivation, and the TPM accepts the ciphertext only when its decryption
    // recovers the plaintext whose independent MAC is checked above.
    Ok(())
}

/// Secret-varying bound HMAC pair: both classes start a session bound to a
/// key object loaded with the class authValue and MAC successfully. The
/// public object material, Name and payload are identical between classes.
fn hmac_bound_secret(hash: HashAlg, auth: &[u8]) -> Result<ClassSpec, String> {
    let n = hash.size();
    let caller = vec![0x56; n];
    let load = loaded_step(
        tpm::load_external_command(Some(&sensitive_with(auth)[2..]), &child(), tpm::TPM_RH_NULL),
        &child().name(),
    );
    let mut params = tpm::sized(&caller);
    tpm::put_2b(&mut params, &[]);
    params.push(0);
    SymDef::Null.marshal(&mut params);
    tpm::put_u16(&mut params, hash.alg_id());
    let nonce = tpm::sized(&vec![0; n]);
    let mut contract = Contract::exact(tpm::success_response(&[0], &nonce, 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    let mut session = Step::new(
        tpm::build_command(0x176, &[tpm::TPM_RH_NULL, 0x8000_0000], &[], &params).bytes,
        contract,
    );
    session.produces = Resource::Handle;
    session.patches.push(copy_response_handle(0, 14));
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    let command = session_command(tpm::TPM_CC_MAC, &[0], &caller, 1, &vec![0; n], &params);
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = session_response(&out, hash, 1, false);
    let slot = success.len() as u16;
    let mut contract = Contract::exact(success, 0);
    let sess = 14 + out.len();
    contract.mask[sess + 2..sess + 2 + n].fill(0);
    contract.mask[sess + 5 + n..].fill(0);
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_response_handle(1, 18));
    command.patches.push(copy_response_handle(0, 10));
    command.patches.push(Patch::SessionHmac {
        at: (27 + n) as u16,
        hash,
        // A session bound to the authorized entity derives its key from the
        // bind authValue and omits includeAuthValue.
        kdf_key: auth.to_vec(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 1,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(caller.clone())],
        extra_key: vec![],
        parts: vec![
            Part::Literal(family::cp_hash(
                hash,
                tpm::TPM_CC_MAC,
                &[&child().name()],
                &params,
            )),
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 1,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![1]),
        ],
        xor: vec![0; n],
        cp_hash: None,
    });
    let program = Program::new(vec![load, session, command]);
    program_spec_absolute(
        program,
        "fresh bound HMAC authorization over a class authValue",
        &[],
        Oracle::HmacBoundSecret {
            hash,
            auth: auth.to_vec(),
        },
    )
}

/// Secret-varying salted HMAC pair: both classes recover a distinct salt from
/// an ECC salt key loaded with the class secret and MAC successfully. The key
/// object's public point, Name and handle are class-dependent confounders.
fn hmac_salted_secret(input: &[u8]) -> Result<ClassSpec, String> {
    let hash = HashAlg::Sha256;
    let n = hash.size();
    let caller = vec![0x56; n];
    let (load_command, name, salt) = salt_material(&salt_scalar(input));
    let load = loaded_step(load_command, &name);
    let mut params = tpm::sized(&caller);
    tpm::put_2b(&mut params, &salt_point_bytes());
    params.push(0);
    SymDef::Null.marshal(&mut params);
    tpm::put_u16(&mut params, hash.alg_id());
    let nonce = tpm::sized(&vec![0; n]);
    let mut contract = Contract::exact(tpm::success_response(&[0], &nonce, 0), 1);
    contract.mask[10..14].fill(0);
    contract.mask[16..].fill(0);
    let mut session = Step::new(
        tpm::build_command(0x176, &[0x8000_0000, tpm::TPM_RH_NULL], &[], &params).bytes,
        contract,
    );
    session.produces = Resource::Handle;
    session.patches.push(copy_response_handle(0, 10));
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    let command = session_command(tpm::TPM_CC_MAC, &[0], &caller, 1, &vec![0; n], &params);
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = session_response(&out, hash, 1, false);
    let slot = success.len() as u16;
    let mut contract = Contract::exact(success, 0);
    let sess = 14 + out.len();
    contract.mask[sess + 2..sess + 2 + n].fill(0);
    contract.mask[sess + 5 + n..].fill(0);
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_response_handle(1, 18));
    command.patches.push(Patch::SessionHmac {
        at: (27 + n) as u16,
        hash,
        // bind is NULL (empty authValue); the KDF key is the decrypted salt.
        kdf_key: salt.clone(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 1,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(caller.clone())],
        // The authorized entity is unbound, so includeAuthValue appends AUTH.
        extra_key: AUTH.to_vec(),
        parts: vec![
            Part::Literal(family::cp_hash(
                hash,
                tpm::TPM_CC_MAC,
                &[&child().name()],
                &params,
            )),
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 1,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![1]),
        ],
        xor: vec![0; n],
        cp_hash: None,
    });
    let program = Program::new(vec![load, session, command]);
    program_spec_absolute(
        program,
        "fresh salted HMAC authorization over a class salt",
        &[(2, 10, HandleRef::Shared(0))],
        Oracle::HmacSaltedSecret { salt },
    )
}

/// Secret-varying request-protection pair: the parameter-decryption session is
/// salted to an ECC key loaded with the class secret, so the request cipher
/// runs on a salt-derived run-time session key. Both classes deliver the same
/// plaintext and MAC successfully.
fn hmac_request_secret(protection: RequestProtection, input: &[u8]) -> Result<ClassSpec, String> {
    let hash = HashAlg::Sha256;
    let n = hash.size();
    let caller = vec![0x56; n];
    let session_caller = vec![0x57; n];
    let (load_command, name, salt) = salt_material(&salt_scalar(input));
    let load = loaded_step(load_command, &name);
    let mut params = tpm::sized(MESSAGE);
    tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
    let session_key = crate::program::CipherKey::Session {
        kdf_key: salt.clone(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 2,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(session_caller.clone())],
        extra: vec![],
    };
    let mut bound_params = tpm::sized(&caller);
    tpm::put_2b(&mut bound_params, &[]);
    bound_params.push(0);
    SymDef::Null.marshal(&mut bound_params);
    tpm::put_u16(&mut bound_params, hash.alg_id());
    let bind_nonce = tpm::sized(&vec![0; n]);
    let mut bind_contract = Contract::exact(tpm::success_response(&[0], &bind_nonce, 0), 1);
    bind_contract.mask[10..14].fill(0);
    bind_contract.mask[16..].fill(0);
    let mut bound_start = Step::new(
        tpm::build_command(0x176, &[tpm::TPM_RH_NULL, 0x8000_0000], &[], &bound_params).bytes,
        bind_contract,
    );
    bound_start.produces = Resource::Handle;
    // The decrypt session is salted to the class key with parameter protection.
    let mut symmetric_params = tpm::sized(&session_caller);
    tpm::put_2b(&mut symmetric_params, &salt_point_bytes());
    symmetric_params.push(0);
    match protection {
        RequestProtection::Aes128Cfb => SymDef::aes128_cfb().marshal(&mut symmetric_params),
        RequestProtection::Xor => {
            tpm::put_u16(&mut symmetric_params, 0x000a);
            tpm::put_u16(&mut symmetric_params, hash.alg_id());
        }
    }
    tpm::put_u16(&mut symmetric_params, hash.alg_id());
    let symmetric_nonce = tpm::sized(&vec![0; n]);
    let mut symmetric_contract =
        Contract::exact(tpm::success_response(&[0], &symmetric_nonce, 0), 1);
    symmetric_contract.mask[10..14].fill(0);
    symmetric_contract.mask[16..].fill(0);
    let mut symmetric_start = Step::new(
        tpm::build_command(
            0x176,
            &[0x8000_0000, tpm::TPM_RH_NULL],
            &[],
            &symmetric_params,
        )
        .bytes,
        symmetric_contract,
    );
    symmetric_start.produces = Resource::Handle;
    symmetric_start.patches.push(copy_response_handle(0, 10));
    // Two sessions: a bound authorization session (session 0) and the salted
    // decrypt session (session 1). The decrypt session's session key is
    // salt-derived and nonempty, so it must send a full request HMAC,
    // built at run time by a matching patch below.
    let mut session0 = vec![0; 4];
    tpm::put_2b(&mut session0, &caller);
    session0.push(1);
    tpm::put_2b(&mut session0, &vec![0; n]);
    let mut session1 = vec![0; 4];
    tpm::put_2b(&mut session1, &session_caller);
    session1.push(0x21);
    tpm::put_2b(&mut session1, &vec![0; n]);
    // The command body starts with the MAC object handle as a zero
    // placeholder for the layout handle reference at command offset 10,
    // followed by an explicit u32 authorizationSize.
    let mut body = Vec::new();
    body.extend_from_slice(&[0; 4]);
    tpm::put_u32(&mut body, (session0.len() + session1.len()) as u32);
    body.extend_from_slice(&session0);
    body.extend_from_slice(&session1);
    body.extend_from_slice(&params);
    let command = tpm::command(tpm::TPM_ST_SESSIONS, tpm::TPM_CC_MAC, &body);
    let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
    let out = tpm::sized(&mac);
    let success = request_response(&out, n, &vec![0; n]);
    let slot = success.len() as u16;
    let mut contract = Contract::exact(success, 0);
    // MAC output is deterministic; the fresh nonces and both run-time
    // response session keys are masked, and the oracle recomputes both
    // response HMACs independently.
    let auth = 14 + out.len();
    let session1_at = 14 + out.len() + 5 + 2 * n;
    contract.mask[auth + 2..auth + 2 + n].fill(0);
    contract.mask[auth + 5 + n..auth + 5 + 2 * n].fill(0);
    contract.mask[session1_at + 2..session1_at + 2 + n].fill(0);
    contract.mask[session1_at + 5 + n..session1_at + 5 + 2 * n].fill(0);
    let mut command = Step::new(command, contract);
    command.slot = slot;
    command.patches.push(copy_response_handle(1, 18));
    command.patches.push(Patch::Copy {
        at: (18 + 9 + 2 * n) as u16,
        source: ResponseRange {
            step: 2,
            area: ResponseArea::Raw,
            offset: 10,
            len: 4,
        },
        xor: vec![0; 4],
    });
    // Request-parameter encryption with the salt-derived run-time session key.
    // The decrypt session's n-byte request HMAC shifts the parameter area n
    // bytes later than in the empty-key scenarios.
    command.patches.push(Patch::Encrypt {
        at: (36 + 4 * n + 2) as u16,
        hash,
        cfb: protection == RequestProtection::Aes128Cfb,
        key: session_key.clone(),
        caller: session_caller.clone(),
        nonce: ResponseRange {
            step: 2,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        },
        plain: MESSAGE.to_vec(),
    });
    command.patches.push(Patch::SessionHmac {
        at: (27 + n) as u16,
        hash,
        // The authorization session is bound to the MAC'd object: its key is
        // derived from the bind authValue, with the fresh nonceTPM of the
        // decrypt session folded in (multiple-session nonce binding).
        kdf_key: AUTH.to_vec(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 1,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(caller.clone())],
        extra_key: vec![],
        parts: vec![
            Part::Literal(caller.clone()),
            Part::Response(ResponseRange {
                step: 1,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Response(ResponseRange {
                step: 2,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![1]),
        ],
        xor: vec![0; n],
        // The cpHash covers the still-encrypted parameter; its cipher runs
        // on the same salt-derived run-time session key.
        cp_hash: Some(crate::program::EncryptedCpHash {
            cc: tpm::TPM_CC_MAC,
            name: child().name(),
            cfb: protection == RequestProtection::Aes128Cfb,
            key: session_key.clone(),
            caller: session_caller.clone(),
            nonce: ResponseRange {
                step: 2,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            },
            prefix: params[..2].to_vec(),
            suffix: params[2 + MESSAGE.len()..].to_vec(),
            plain: MESSAGE.to_vec(),
        }),
    });
    // The decrypt session's own request HMAC: the backend checks it before
    // parameter decryption. Its key is the salt-derived sessionKey with no
    // authValue (the session has no associated handle), and it covers the
    // runtime cpHash, the session's own nonces and its attributes.
    command.patches.push(Patch::SessionHmac {
        at: (36 + 3 * n) as u16,
        hash,
        kdf_key: salt.clone(),
        u_parts: vec![Part::Response(ResponseRange {
            step: 2,
            area: ResponseArea::Parameters,
            offset: 2,
            len: n as u16,
        })],
        v_parts: vec![Part::Literal(session_caller.clone())],
        // No associated handle means no authValue in the HMAC key.
        extra_key: vec![],
        parts: vec![
            Part::Literal(session_caller.clone()),
            Part::Response(ResponseRange {
                step: 2,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            }),
            Part::Literal(vec![0x21]),
        ],
        xor: vec![0; n],
        cp_hash: Some(crate::program::EncryptedCpHash {
            cc: tpm::TPM_CC_MAC,
            name: child().name(),
            cfb: protection == RequestProtection::Aes128Cfb,
            key: session_key,
            caller: session_caller,
            nonce: ResponseRange {
                step: 2,
                area: ResponseArea::Parameters,
                offset: 2,
                len: n as u16,
            },
            prefix: params[..2].to_vec(),
            suffix: params[2 + MESSAGE.len()..].to_vec(),
            plain: MESSAGE.to_vec(),
        }),
    });
    let program = Program::new(vec![load, bound_start, symmetric_start, command]);
    program_spec_absolute(
        program,
        "fresh two-session authorization with a salted decrypt session",
        &[(1, 14, HandleRef::Shared(0)), (3, 10, HandleRef::Shared(0))],
        Oracle::HmacRequestSecret { protection, salt },
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Oracle {
    Hmac {
        hash: HashAlg,
        protection: ResponseProtection,
        valid: bool,
    },
    HmacBound {
        hash: HashAlg,
        valid: bool,
    },
    HmacSalted {
        valid: bool,
    },
    HmacRequest {
        protection: RequestProtection,
        valid: bool,
    },
    HmacBoundSecret {
        hash: HashAlg,
        auth: Vec<u8>,
    },
    HmacSaltedSecret {
        salt: Vec<u8>,
    },
    HmacRequestSecret {
        protection: RequestProtection,
        /// Recovered class salt: the decrypt session's salt-derived key is
        /// re-derived and verified independently.
        salt: Vec<u8>,
    },
    Import {
        valid: bool,
    },
    Duplicate {
        parent: Option<AsymKind>,
        generated: bool,
        key: Vec<u8>,
    },
    Rewrap {
        parent: Option<AsymKind>,
        valid: bool,
    },
}
impl Oracle {
    pub fn check(&self, response: &[u8], program: Option<&Program>) -> Result<(), String> {
        let frames = if let Some(program) = program {
            program.transcript(response)?
        } else {
            vec![response]
        };
        let response = *frames.last().ok_or("empty transcript")?;
        match self {
            Self::Hmac {
                hash,
                protection,
                valid,
            } => {
                if !valid {
                    return expect_error(response, 0x9a2);
                }
                let initial = tpm::response_parameters(frames[0], 1).ok_or("start response")?;
                let (initial_nonce, end) = tpm::read_2b(initial, 0).ok_or("start nonce framing")?;
                if end != initial.len() || initial_nonce.len() != hash.size() {
                    return Err("start nonce width".into());
                }
                check_hmac_response(response, *hash, *protection, initial_nonce, &[], &AUTH)
            }
            Self::HmacBound { hash, valid } => {
                if !valid {
                    return expect_error(response, 0x9a2);
                }
                let initial_nonce = start_nonce(frames[0], *hash)?;
                let caller = vec![0x56; hash.size()];
                let session_key = kdfa(
                    *hash,
                    &AUTH,
                    b"ATH",
                    &initial_nonce,
                    &caller,
                    hash.size() * 8,
                );
                // A session bound to the authorized entity folds the authValue
                // into the session key and excludes it from both HMACs.
                check_hmac_response(
                    response,
                    *hash,
                    ResponseProtection::None,
                    &initial_nonce,
                    &session_key,
                    &[],
                )
            }
            Self::HmacSalted { valid } => {
                if !valid {
                    return expect_error(response, 0x9a2);
                }
                let hash = HashAlg::Sha256;
                let initial_nonce = start_nonce(frames[0], hash)?;
                let caller = vec![0x56; 32];
                let session_key = kdfa(
                    hash,
                    &session_salt().2,
                    b"ATH",
                    &initial_nonce,
                    &caller,
                    hash.size() * 8,
                );
                check_hmac_response(
                    response,
                    hash,
                    ResponseProtection::None,
                    &initial_nonce,
                    &session_key,
                    &AUTH,
                )
            }
            Self::HmacRequest { valid, .. } => {
                if !valid {
                    return expect_error(response, 0x9a2);
                }
                check_request_response(response, &frames, 0, 1, Session1Key::Empty)
            }
            Self::HmacBoundSecret { hash, auth } => {
                // The program starts with a per-class LoadExternal whose
                // response carries the object handle and its exact Name; the
                // session follows.
                let initial_nonce = start_nonce(frames[1], *hash)?;
                let caller = vec![0x56; hash.size()];
                let session_key = kdfa(
                    *hash,
                    auth,
                    b"ATH",
                    &initial_nonce,
                    &caller,
                    hash.size() * 8,
                );
                check_hmac_response(
                    response,
                    *hash,
                    ResponseProtection::None,
                    &initial_nonce,
                    &session_key,
                    &[],
                )
            }
            Self::HmacSaltedSecret { salt } => {
                let hash = HashAlg::Sha256;
                let initial_nonce = start_nonce(frames[1], hash)?;
                let caller = vec![0x56; 32];
                let session_key = kdfa(hash, salt, b"ATH", &initial_nonce, &caller, 256);
                check_hmac_response(
                    response,
                    hash,
                    ResponseProtection::None,
                    &initial_nonce,
                    &session_key,
                    &AUTH,
                )
            }
            Self::HmacRequestSecret {
                protection: _,
                salt,
            } => {
                // Program layout: class ECC key load, bound authorization
                // session, salted decrypt session, MAC.
                check_request_response(response, &frames, 1, 2, Session1Key::Salted(salt))
            }
            Self::Import { valid } => {
                if !valid {
                    return expect_error(response, 0x3df);
                }
                let params = tpm::response_parameters(response, 0).ok_or("Import response")?;
                let (blob, end) = tpm::read_2b(params, 0).ok_or("Import private framing")?;
                if end != params.len() {
                    return Err("Import trailing parameters".into());
                }
                let actual = wrap::outer_unwrap(blob, &child().name(), &wrap::PARENT_SEED, true)?;
                exact(&actual, &sensitive(), "Import sensitive")
            }
            Self::Duplicate {
                parent,
                generated,
                key,
            } => {
                let params = tpm::response_parameters(response, 0).ok_or("Duplicate response")?;
                let (key_out, at) = tpm::read_2b(params, 0).ok_or("Duplicate key")?;
                let (duplicate, at) = tpm::read_2b(params, at).ok_or("Duplicate blob")?;
                let (seed, end) = tpm::read_2b(params, at).ok_or("Duplicate seed")?;
                if end != params.len() {
                    return Err("Duplicate trailing parameters".into());
                }
                let actual_key = if *generated {
                    if key_out.len() != 16 {
                        return Err("generated inner key width".into());
                    }
                    key_out
                } else {
                    if !key_out.is_empty() {
                        return Err("supplied inner key must not be echoed".into());
                    }
                    key
                };
                let name = child().name_with_policy(&policy());
                let payload = unwrap_optional(*parent, duplicate, seed, &name)?;
                exact(
                    &wrap::inner_unwrap(&payload, &name, actual_key)?,
                    &sensitive(),
                    "Duplicate sensitive",
                )
            }
            Self::Rewrap { parent, valid } => {
                if !valid {
                    return expect_error(response, 0x1df);
                }
                let params = tpm::response_parameters(response, 0).ok_or("Rewrap response")?;
                let (blob, at) = tpm::read_2b(params, 0).ok_or("Rewrap blob")?;
                let (seed, end) = tpm::read_2b(params, at).ok_or("Rewrap seed")?;
                if end != params.len() {
                    return Err("Rewrap trailing parameters".into());
                }
                exact(
                    &unwrap_optional(*parent, blob, seed, &child().name())?,
                    &rewrap_payload(),
                    "Rewrap unchanged payload",
                )
            }
        }
    }
}
fn expect_error(response: &[u8], code: u32) -> Result<(), String> {
    exact(response, &tpm::error_response(code), "error response")
}
fn exact(actual: &[u8], expected: &[u8], what: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{what} differs from independent expectation"))
    }
}
fn unwrap_optional(
    parent: Option<AsymKind>,
    blob: &[u8],
    seed: &[u8],
    name: &[u8],
) -> Result<Vec<u8>, String> {
    if let Some(parent) = parent {
        wrap::outer_unwrap(blob, name, &wrap::decrypt_seed(parent, seed)?, false)
    } else {
        if !seed.is_empty() {
            return Err("NULL parent returned a seed".into());
        }
        Ok(blob.to_vec())
    }
}
fn check_hmac_response(
    response: &[u8],
    hash: HashAlg,
    protection: ResponseProtection,
    initial: &[u8],
    session_key: &[u8],
    extra_key: &[u8],
) -> Result<(), String> {
    let params = tpm::response_parameters(response, 0).ok_or("MAC response")?;
    let auth_at = 14 + params.len();
    let (nonce, at) = tpm::read_2b(response, auth_at).ok_or("response nonce")?;
    let attributes = *response.get(at).ok_or("response attributes")?;
    let (hmac, end) = tpm::read_2b(response, at + 1).ok_or("response HMAC")?;
    let expected_attributes = if protection == ResponseProtection::None {
        1
    } else {
        0x41
    };
    if nonce.len() != hash.size()
        || nonce == initial
        || attributes != expected_attributes
        || hmac.len() != hash.size()
        || end != response.len()
    {
        return Err("response authorization framing/freshness".into());
    }
    let caller = vec![0x56; hash.size()];
    let rp = hash.digest(&[&0u32.to_be_bytes(), &tpm::TPM_CC_MAC.to_be_bytes(), params]);
    exact(
        hmac,
        &hash.hmac(
            &[session_key, extra_key].concat(),
            &[&rp, nonce, &caller, &[attributes]],
        ),
        "response HMAC",
    )?;
    let (cipher, end) = tpm::read_2b(params, 0).ok_or("MAC output framing")?;
    if end != params.len() {
        return Err("MAC trailing parameters".into());
    }
    let plain = match protection {
        ResponseProtection::None => cipher.to_vec(),
        ResponseProtection::Aes128Cfb => {
            let material = kdfa(hash, &AUTH, b"CFB", nonce, &caller, 256);
            wrap::cfb(&material[..16], &material[16..], cipher, false)
        }
        ResponseProtection::Xor => {
            let mask = kdfa(hash, &AUTH, b"XOR", nonce, &caller, cipher.len() * 8);
            cipher.iter().zip(mask).map(|(x, y)| x ^ y).collect()
        }
    };
    exact(
        &plain,
        &HashAlg::Sha256.hmac(&KEY, &[MESSAGE]),
        "MAC plaintext",
    )
}

fn seed_width(kind: AsymKind) -> usize {
    match kind {
        AsymKind::Rsa(bits) => bits.bytes(),
        AsymKind::Ecc(curve) => 4 + 2 * curve.key_bytes(),
    }
}
fn private_size(sensitive: &[u8]) -> usize {
    34 + 18 + 2 + sensitive.len()
}
fn bootstrap(kind: AsymKind) -> Vec<LayoutStep> {
    // Always use a fast ECC primary; the imported child has known private material.
    let (mut primary, _) =
        wrap::parent_material(AsymKind::Ecc(crate::oracle::ec::CurveId::NistP256));
    primary.attributes |=
        tpm::ATTR_FIXED_TPM | tpm::ATTR_FIXED_PARENT | tpm::ATTR_SENSITIVE_DATA_ORIGIN;
    if let PublicDetail::Ecc { x, y, .. } = &mut primary.detail {
        x.clear();
        y.clear();
    }
    let create = LayoutStep::new(
        "CreatePrimary bootstrap storage key",
        tpm::create_primary_command(tpm::TPM_RH_OWNER, &[], &primary),
    )
    .creates(Creates::Object);
    let (public, sensitive) = wrap::parent_material(kind);
    let mut params = tpm::sized(&[]);
    tpm::put_2b(&mut params, &public.marshal());
    tpm::put_2b(&mut params, &tpm::sized(&sensitive));
    tpm::put_2b(&mut params, &[]);
    SymDef::Null.marshal(&mut params);
    let import = LayoutStep::new(
        "Import known storage parent",
        tpm::build_command(IMPORT, &[0], &[&[]], &params).bytes,
    )
    .handle_at(10, HandleRef::Shared(0));
    // Import pads empty authValue to the parent's name digest width.
    let private_len = private_size(&sensitive) + 32;
    let mut params = tpm::sized(&vec![0; private_len]);
    tpm::put_2b(&mut params, &public.marshal());
    let command = tpm::build_command(tpm::TPM_CC_LOAD, &[0], &[&[]], &params);
    let load = LayoutStep::new("Load known storage parent", command.bytes)
        .handle_at(10, HandleRef::Shared(0))
        .patch(SetupPatch {
            at: command.parameters_at,
            source: StepRef::Shared(1),
            from: 14,
            len: private_len + 2,
            xor: vec![0; private_len + 2],
        })
        .creates(Creates::Object);
    vec![create, import, load]
}
fn public_parent(kind: AsymKind) -> LayoutStep {
    LayoutStep::new(
        "LoadExternal public wrapping parent",
        tpm::load_external_command(None, &wrap::parent_material(kind).0, tpm::TPM_RH_NULL),
    )
    .creates(Creates::Object)
}
fn check_spec(measured: LayoutStep, response: Vec<u8>, random: bool, oracle: Oracle) -> ClassSpec {
    let mut spec = ClassSpec::new(measured, response);
    if random {
        spec.mask = family::mask_range(spec.expected.len(), 16, spec.expected.len() - 5);
    }
    spec.check = Some(Check::Protection {
        oracle: Box::new(oracle),
        program: None,
    });
    spec
}
fn import(kind: AsymKind, layer: ImportLayer, delta: &[u8]) -> ClassSpec {
    let name = child().name();
    let inner = layer != ImportLayer::Outer;
    let payload = if inner {
        wrap::inner_wrap(&sensitive(), &name, &INNER, delta)
    } else {
        sensitive()
    };
    let (mut duplicate, seed) = if layer != ImportLayer::Inner {
        let (secret, seed) = wrap::encrypt_seed(kind);
        (wrap::outer_wrap(&payload, &name, &secret), seed)
    } else {
        (payload, vec![])
    };
    if layer == ImportLayer::Outer {
        for (byte, xor) in duplicate[2..34].iter_mut().zip(delta) {
            *byte ^= xor;
        }
    }
    let mut params = tpm::sized(if inner { &INNER } else { &[] });
    tpm::put_2b(&mut params, &child().marshal());
    tpm::put_2b(&mut params, &duplicate);
    tpm::put_2b(&mut params, &seed);
    if inner {
        SymDef::aes128_cfb()
    } else {
        SymDef::Null
    }
    .marshal(&mut params);
    let measured = LayoutStep::new(
        "Import wrapped child",
        tpm::build_command(IMPORT, &[0], &[&[]], &params).bytes,
    )
    .handle_at(10, HandleRef::Shared(1));
    let response = if valid(delta) {
        tpm::success_response(&[], &tpm::sized(&vec![0; 34 + 18 + sensitive().len()]), 1)
    } else {
        tpm::error_response(0x3df)
    };
    check_spec(
        measured,
        response,
        valid(delta),
        Oracle::Import {
            valid: valid(delta),
        },
    )
}
fn rewrap_payload() -> Vec<u8> {
    wrap::inner_wrap(&sensitive(), &child().name(), &INNER, &[0; 32])
}
fn rewrap(old: AsymKind, new: Option<AsymKind>, delta: &[u8]) -> ClassSpec {
    let name = child().name();
    let payload = rewrap_payload();
    let (secret, seed) = wrap::encrypt_seed(old);
    let mut duplicate = wrap::outer_wrap(&payload, &name, &secret);
    for (byte, xor) in duplicate[2..34].iter_mut().zip(delta) {
        *byte ^= xor;
    }
    let mut params = tpm::sized(&duplicate);
    tpm::put_2b(&mut params, &name);
    tpm::put_2b(&mut params, &seed);
    let mut measured = LayoutStep::new(
        "Rewrap independently wrapped payload",
        tpm::build_command(REWRAP, &[0, tpm::TPM_RH_NULL], &[&[]], &params).bytes,
    )
    .handle_at(10, HandleRef::Shared(1));
    if new.is_some() {
        measured = measured.handle_at(14, HandleRef::Shared(2));
    }
    let response = if valid(delta) {
        let mut out = tpm::sized(&if new.is_some() {
            vec![0; 34 + payload.len()]
        } else {
            payload
        });
        tpm::put_2b(&mut out, &vec![0; new.map_or(0, seed_width)]);
        tpm::success_response(&[], &out, 1)
    } else {
        tpm::error_response(0x1df)
    };
    check_spec(
        measured,
        response,
        valid(delta) && new.is_some(),
        Oracle::Rewrap {
            parent: new,
            valid: valid(delta),
        },
    )
}
fn duplicate(parent: Option<AsymKind>, generated: bool, input: &[u8]) -> Result<ClassSpec, String> {
    let hash = HashAlg::Sha256;
    let caller = vec![0x56; 32];
    let key: Vec<_> = INNER.iter().zip(input).map(|(a, b)| a ^ b).collect();
    let mut policy_step = Step::new(
        tpm::build_command(0x16c, &[0], &[], &DUPLICATE.to_be_bytes()).bytes,
        Contract::exact(tpm::flush_response(), 0),
    );
    policy_step.patches.push(copy_session(10));
    let mut params = tpm::sized(if generated { &[] } else { &key });
    SymDef::aes128_cfb().marshal(&mut params);
    let command = session_command(DUPLICATE, &[0, tpm::TPM_RH_NULL], &caller, 1, &[], &params);
    let name = child().name_with_policy(&policy());
    let inner = wrap::inner_wrap(&sensitive(), &name, &key, &[0; 32]);
    let mut out = tpm::sized(&vec![0; if generated { 16 } else { 0 }]);
    tpm::put_2b(
        &mut out,
        &if parent.is_some() {
            vec![0; 34 + inner.len()]
        } else {
            inner
        },
    );
    tpm::put_2b(&mut out, &vec![0; parent.map_or(0, seed_width)]);
    let response = session_response(&out, hash, 1, true);
    let mut contract = Contract::exact(response, 0);
    if generated || parent.is_some() {
        contract.mask[14..14 + out.len()].fill(0);
    }
    let auth = 14 + out.len();
    contract.mask[auth + 2..auth + 34].fill(0);
    let mut dup = Step::new(command, contract);
    dup.patches.push(copy_session(22));
    let program = Program::new(vec![
        start(hash, ResponseProtection::None, true),
        policy_step,
        dup,
    ]);
    let mut handles = vec![(10, HandleRef::Shared(0))];
    if parent.is_some() {
        handles.push((14, HandleRef::Shared(1)));
    }
    program_spec(
        program,
        "fresh policy session and Duplicate",
        &handles,
        Oracle::Duplicate {
            parent,
            generated,
            key,
        },
    )
}

/// The shared MAC'd key object used by every HMAC authorization family.
fn hmac_key_setup() -> Vec<LayoutStep> {
    vec![
        LayoutStep::new(
            "LoadExternal authenticated HMAC key",
            tpm::load_external_command(Some(&sensitive()[2..]), &child(), tpm::TPM_RH_NULL),
        )
        .creates(Creates::Object),
    ]
}

/// Secret-varying session scenarios keep the model accurate: the classes both
/// succeed, only the secret differs, and publicly visible consequences of
/// the differing key material are listed as confounders.
fn secret_session_model(scenario: Scenario, pair: &InputPair) -> PairModel {
    let differs = pair.a != pair.b;
    let model = PairModel::secret(differs).confounder(differs, family::PER_CLASS_OBJECTS);
    if matches!(
        scenario,
        Scenario::HmacAuthSaltedSecret | Scenario::HmacAuthRequestSecret(..)
    ) {
        model.confounder(differs, family::PER_CLASS_KEYS)
    } else {
        model
    }
}

pub fn build(scenario: Scenario, pair: &InputPair) -> Result<Built, String> {
    let (shared, classes) = match scenario {
        Scenario::HmacAuth(hash, protection) => (
            hmac_key_setup(),
            [
                hmac(hash, protection, &pair.a)?,
                hmac(hash, protection, &pair.b)?,
            ],
        ),
        Scenario::HmacAuthBound(hash) => (
            hmac_key_setup(),
            [hmac_bound(hash, &pair.a)?, hmac_bound(hash, &pair.b)?],
        ),
        Scenario::HmacAuthSalted => {
            let (salt_load, _, _) = session_salt();
            let mut setup = hmac_key_setup();
            setup.push(
                LayoutStep::new("LoadExternal ECC salt key", salt_load).creates(Creates::Object),
            );
            (setup, [hmac_salted(&pair.a)?, hmac_salted(&pair.b)?])
        }
        Scenario::HmacAuthRequest(protection) => {
            let setup = hmac_key_setup();
            (
                setup,
                [
                    hmac_request(protection, &pair.a)?,
                    hmac_request(protection, &pair.b)?,
                ],
            )
        }
        Scenario::HmacAuthBoundSecret(hash) => (
            vec![],
            [
                hmac_bound_secret(hash, &pair.a)?,
                hmac_bound_secret(hash, &pair.b)?,
            ],
        ),
        Scenario::HmacAuthSaltedSecret => {
            let setup = hmac_key_setup();
            (
                setup,
                [hmac_salted_secret(&pair.a)?, hmac_salted_secret(&pair.b)?],
            )
        }
        Scenario::HmacAuthRequestSecret(protection) => {
            let setup = hmac_key_setup();
            (
                setup,
                [
                    hmac_request_secret(protection, &pair.a)?,
                    hmac_request_secret(protection, &pair.b)?,
                ],
            )
        }
        Scenario::Import(kind, layer) => (
            bootstrap(kind),
            [import(kind, layer, &pair.a), import(kind, layer, &pair.b)],
        ),
        Scenario::Rewrap(old, new) => {
            let mut shared = bootstrap(old);
            if let Some(kind) = new {
                shared.push(public_parent(kind));
            }
            (
                shared,
                [rewrap(old, new, &pair.a), rewrap(old, new, &pair.b)],
            )
        }
        Scenario::Duplicate(parent, generated) => {
            let mut params = tpm::sized(&sensitive()[2..]);
            tpm::put_2b(&mut params, &child().marshal_with_policy(&policy()));
            tpm::put_u32(&mut params, tpm::TPM_RH_NULL);
            let mut shared = vec![
                LayoutStep::new(
                    "LoadExternal child with Duplicate policy",
                    tpm::build_command(tpm::TPM_CC_LOAD_EXTERNAL, &[], &[], &params).bytes,
                )
                .creates(Creates::Object),
            ];
            if let Some(kind) = parent {
                shared.push(public_parent(kind));
            }
            (
                shared,
                [
                    duplicate(parent, generated, &pair.a)?,
                    duplicate(parent, generated, &pair.b)?,
                ],
            )
        }
        _ => return Err("not a remaining authentication scenario".into()),
    };
    if secret_session(scenario) {
        let salt_bearing = !matches!(scenario, Scenario::HmacAuthBoundSecret(..));
        return Ok(Built {
            shared,
            classes,
            model: secret_session_model(scenario, pair),
            varying_public_values: if salt_bearing {
                vec!["ECC salt key public point".into()]
            } else {
                Vec::new()
            },
        });
    }
    let input = if matches!(scenario, Scenario::Duplicate(..)) {
        "inner wrapping key"
    } else {
        "supplied authentication/integrity delta"
    };
    let differs = pair.a != pair.b && !matches!(scenario, Scenario::Duplicate(_, true));
    Ok(Built {
        shared,
        classes,
        model: PairModel::secret(false)
            .public(input, differs)
            .confounder(differs, "fresh session nonces or wrapper entropy can vary; correctness is independently checked"),
        varying_public_values: vec![input.into()],
    })
}
pub fn doc(scenario: Scenario) -> ScenarioDoc {
    let (entry, correctness, timed, interpretation, classes, secret, attacker_inputs) =
        match scenario {
            Scenario::HmacAuth(..) => (
                "StartAuthSession + TPM2_MAC authorization/response protection".into(),
                "exact independent MAC plaintext, response HMAC over encrypted wire parameters, fresh nonce and attributes; exact session-1 BAD_AUTH on mismatch".into(),
                "whole program: fresh session, request HMAC patch, MAC, automatic FlushContext and bounded interpreter".into(),
                "authentication-delta probes: public XOR deltas flip the request HMAC between success and BAD_AUTH against fixed secrets, so these comparisons target authorization processing, not a secret-dependent path. Sessions in this family are unbound, unsalted and protect responses only; fresh nonces are masked or independently checked, and an identical-input control is included".into(),
                "equal-width first/last and all/last deltas, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "full-width request-HMAC XOR delta".into(),
            ),
            Scenario::HmacAuthBound(hash) => (
                format!("StartAuthSession bound to the key object + TPM2_MAC ({})", hash.name()),
                "fresh-nonce session key KDFa from the bind authValue, request HMAC without includeAuthValue, exact MAC plaintext and response HMAC keyed only by the session key; exact session-1 BAD_AUTH on mismatch".into(),
                "whole program: fresh bound session, request-session-key patch, MAC, automatic FlushContext".into(),
                "authentication-delta probes of bound sessions: the delta flips the request HMAC between success and BAD_AUTH while the bind authValue stays fixed, so a BAD_AUTH class is rejected before further work and the pair does not time authValue-dependent processing. Bound-session secret dependence is measured by the auth-hmac-bound-secret family; fresh nonces are masked or independently checked, and an identical-input control is included".into(),
                "equal-width first/last and all/last deltas, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "full-width request-HMAC XOR delta".into(),
            ),
            Scenario::HmacAuthSalted => (
                "StartAuthSession with an ECC salt key + TPM2_MAC".into(),
                "independently recovered ECC salt, KDFa session key from the salt, request HMAC with includeAuthValue, exact MAC plaintext and response HMAC; exact session-1 BAD_AUTH on mismatch".into(),
                "whole program: fresh salted session, request-session-key patch, MAC, automatic FlushContext".into(),
                "authentication-delta probes of salted sessions: the delta flips the request HMAC between success and BAD_AUTH while the recovered salt stays a fixed constant, so the pair does not time salt-dependent processing. Salt secret dependence is measured by the auth-hmac-salted-secret family; fresh nonces are masked or independently checked, and an identical-input control is included".into(),
                "equal-width first/last and all/last deltas, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "full-width request-HMAC XOR delta".into(),
            ),
            Scenario::HmacAuthRequest(protection) => (
                format!(
                    "StartAuthSession + two-session MAC with request parameter protection ({}) and multiple-session nonce binding",
                    protection.name()
                ),
                "request parameter re-encrypted at runtime for every fresh session-1 nonce; independently derived XOR/AES-CFB session key; authorization HMAC binds both fresh nonceTPM values; exact decrypted-parameter plaintext through the MAC result, response HMAC and attribute echo; exact session-1 BAD_AUTH on mismatch".into(),
                "whole program: fresh authorization and decrypt sessions, runtime parameter-encryption patch, MAC, automatic FlushContext".into(),
                "authentication-delta probes of request-protected commands: a corrupted request HMAC fails with BAD_AUTH before parameter decryption, so the invalid-authorization class does not time the decryption path at all. The decrypt session in this family is unbound and unsalted with an empty session key; request-protection secret dependence is measured by the auth-hmac-request-secret family; fresh nonces are masked or independently checked, and an identical-input control is included".into(),
                "equal-width first/last and all/last deltas, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "full-width request-HMAC XOR delta".into(),
            ),
            Scenario::HmacAuthBoundSecret(hash) => (
                format!("Bound HMAC sessions with a class authValue ({})", hash.name()),
                "per-class key object load, session key KDFa from the class authValue, request HMAC without includeAuthValue, exact MAC plaintext and response HMAC recomputed independently from the fresh nonce".into(),
                "whole program: class LoadExternal, fresh bound session, MAC, automatic FlushContext".into(),
                "secret-varying timing pairs: equal-length bind authValues differ between two successful classes with identical public object material, Name, payload and response length, so a timing difference would point at authValue-dependent processing. Remaining confounders: fresh session nonces (masked and independently checked) and per-class transient handles; an identical-secret control is included. Public-input delta probes stay in the auth-hmac-bound family".into(),
                "equal-length secret variations (zero/ones, first/last byte, ones/last), identical-secret control, random pairs; every class succeeds".into(),
                "the class bind authValue; all other object secrets are fixed".into(),
                "the per-class authValue bytes".into(),
            ),
            Scenario::HmacAuthSaltedSecret => (
                "Salted HMAC sessions with a class salt key".into(),
                "class ECC salt key load, independently recovered salt, session key KDFa from the class salt, request HMAC with includeAuthValue, exact MAC plaintext and response HMAC recomputed from the fresh nonce and class salt".into(),
                "whole program: class ECC key load, fresh salted session, MAC, automatic FlushContext".into(),
                "secret-varying timing pairs: equal-length salt-key scalars yield distinct recovered salts across two successful classes with identical commands, payload and response length, so a timing difference would point at salt-dependent session-key processing. Remaining confounders: the class key's public point, Name and handle differ (the command wire and cpHash do not depend on them), fresh session nonces are masked and independently checked, and an identical-secret control is included".into(),
                "equal-length secret variations (zero/ones, first/last byte, ones/last), identical-secret control, random pairs; every class succeeds".into(),
                "the class salt-key scalar and its recovered salt; all other object secrets are fixed".into(),
                "the per-class salt-key scalar".into(),
            ),
            Scenario::HmacAuthRequestSecret(protection) => (
                format!(
                    "Two-session MAC with a salted decrypt session and request parameter protection ({})",
                    protection.name()
                ),
                "class ECC salt key load; the request parameter cipher, the encrypted-parameter cpHash and the decrypt session's own request HMAC run on a run-time session key KDFa-derived from the class salt and fresh decrypt-session nonce; the response is checked for exact decrypted-parameter MAC, both response session HMACs, session nonces and attribute echo".into(),
                "whole program: class ECC key load, fresh bound authorization and salted decrypt sessions, runtime parameter-encryption patch, MAC, automatic FlushContext".into(),
                "secret-varying timing pairs with request-parameter protection: the decrypt session is salted to the class key, so both the request cipher and the request HMAC cover the same secret-dependent session key, and both classes deliver identical plaintexts and succeed. Remaining confounders: the class ECC key's public point, Name and handle, fresh session nonces (masked and independently checked), and an identical-secret control. This family does not compose request protection with response protection".into(),
                "equal-length secret variations (zero/ones, first/last byte, ones/last), identical-secret control, random pairs; every class succeeds".into(),
                "the class salt-key scalar and its salt-derived session key; all other object secrets are fixed".into(),
                "the per-class salt-key scalar".into(),
            ),
            Scenario::Import(..) => (
                "TPM2_Import inner/outer protection".into(),
                "independently construct input; validate output HMAC and random IV, decrypt and compare all sensitive bytes; exact parameter-3 INTEGRITY on mismatch".into(),
                "one Import command; known-parent bootstrap excluded".into(),
                "public-input timing against fixed secrets: integrity deltas flip the response between success and structured errors, so valid/error outcome is an explicit confounder; wrapper IVs and entropy are independently checked; no session-secret dependence is claimed".into(),
                "equal-width first/last and all/last deltas, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "full-width integrity XOR delta".into(),
            ),
            Scenario::Duplicate(..) => (
                "StartAuthSession + PolicyCommandCode + TPM2_Duplicate".into(),
                "recover RSA/ECC output seed, authenticate/decrypt outer wrapper and inner integrity; exact known sensitive bytes and supplied/generated key semantics".into(),
                "whole program: fresh policy session, PolicyCommandCode, Duplicate and automatic FlushContext".into(),
                "public-input timing against fixed secrets: key-variation seeds change the supplied inner wrapping key across successful classes, and fresh policy-session nonces and wrapper entropy are confounders that are independently checked; no session-secret dependence is claimed".into(),
                "equal-width first/last and all/last key variations, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "supplied inner wrapping key or integrity delta".into(),
            ),
            Scenario::Rewrap(..) => (
                "TPM2_Rewrap outer protection".into(),
                "recover output seed and verify/decrypt complete outer wrapper to exact unchanged input payload; parameter-1 INTEGRITY on mismatch".into(),
                "one Rewrap command; known-parent bootstrap excluded".into(),
                "public-input timing against fixed secrets: integrity deltas flip the response between success and structured errors, so valid/error outcome is an explicit confounder; wrapper IVs and entropy are independently checked; no session-secret dependence is claimed".into(),
                "equal-width first/last and all/last deltas, zero/nonzero and identical-zero controls, random pairs".into(),
                "fixed known object authValue, private key and/or seed".into(),
                "full-width integrity XOR delta".into(),
            ),
            _ => unreachable!(),
        };
    let classes = if matches!(scenario, Scenario::Duplicate(_, true)) {
        "identical generated-key requests; random input bytes do not enter either command".into()
    } else {
        classes
    };
    ScenarioDoc {
        harness: family::COMMAND_LEVEL.into(),
        entry_point: entry,
        secret,
        attacker_inputs,
        observable_outputs: "response code, size, authenticated output and random wrapping/session nonce".into(),
        classes,
        fixed: "object secret beyond the varied class secret, public Name where fixed, parent keys and non-varied command fields".into(),
        timed_region: timed,
        correctness,
        interpretation,
        randomized: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn signed_response(hash: HashAlg, protection: ResponseProtection, plain: &[u8]) -> Vec<u8> {
        let caller = vec![0x56; hash.size()];
        let nonce = vec![0x92; hash.size()];
        let cipher = match protection {
            ResponseProtection::None => plain.to_vec(),
            ResponseProtection::Aes128Cfb => {
                let material = kdfa(hash, &AUTH, b"CFB", &nonce, &caller, 256);
                wrap::cfb(&material[..16], &material[16..], plain, true)
            }
            ResponseProtection::Xor => {
                let mask = kdfa(hash, &AUTH, b"XOR", &nonce, &caller, plain.len() * 8);
                plain.iter().zip(mask).map(|(a, b)| a ^ b).collect()
            }
        };
        let attributes = if protection == ResponseProtection::None {
            1
        } else {
            0x41
        };
        let params = tpm::sized(&cipher);
        let rp = hash.digest(&[&0u32.to_be_bytes(), &tpm::TPM_CC_MAC.to_be_bytes(), &params]);
        let auth = hash.hmac(&AUTH, &[&rp, &nonce, &caller, &[attributes]]);
        let mut response = session_response(&params, hash, attributes, false);
        let at = 14 + params.len();
        response[at + 2..at + 2 + nonce.len()].copy_from_slice(&nonce);
        response[at + 5 + nonce.len()..].copy_from_slice(&auth);
        response
    }
    #[test]
    fn authorization_oracle_rejects_forged_plaintext_nonce_hmac_attributes_and_lengths() {
        let mac = HashAlg::Sha256.hmac(&KEY, &[MESSAGE]);
        for hash in HashAlg::ALL {
            for protection in ResponseProtection::ALL {
                let initial = vec![0x22; hash.size()];
                let good = signed_response(hash, protection, &mac);
                check_hmac_response(&good, hash, protection, &initial, &[], &AUTH).unwrap();
                let auth = 14 + 2 + mac.len();
                for at in [
                    14,
                    16,
                    auth,
                    auth + 2,
                    auth + 2 + hash.size(),
                    auth + 5 + hash.size(),
                    good.len() - 1,
                ] {
                    let mut bad = good.clone();
                    bad[at] ^= 1;
                    assert!(
                        check_hmac_response(&bad, hash, protection, &initial, &[], &AUTH).is_err(),
                        "{hash:?}/{protection:?} corruption at {at}"
                    );
                }
                let mut bad_mac = mac.clone();
                bad_mac[0] ^= 1;
                assert!(
                    check_hmac_response(
                        &signed_response(hash, protection, &bad_mac),
                        hash,
                        protection,
                        &initial,
                        &[],
                        &AUTH
                    )
                    .is_err(),
                    "correct response HMAC must not hide an incorrect MAC result"
                );
                assert!(
                    check_hmac_response(
                        &good,
                        hash,
                        protection,
                        &vec![0x92; hash.size()],
                        &[],
                        &AUTH
                    )
                    .is_err(),
                    "nonce must refresh"
                );
                let mut trailing = good.clone();
                trailing.push(0);
                let len = trailing.len() as u32;
                trailing[2..6].copy_from_slice(&len.to_be_bytes());
                assert!(
                    check_hmac_response(&trailing, hash, protection, &initial, &[], &AUTH).is_err()
                );
            }
        }
    }
    #[test]
    fn policy_name_hashes_actual_nonempty_policy_bytes() {
        let public = child();
        let policy = policy();
        let bytes = public.marshal_with_policy(&policy);
        assert_eq!(&bytes[8..10], &[0, 32]);
        assert_eq!(&bytes[10..42], &policy);
        assert_ne!(public.name(), public.name_with_policy(&policy));
        assert_eq!(
            &public.name_with_policy(&policy)[2..],
            HashAlg::Sha256.digest(&[&bytes])
        );
        assert_eq!(public.marshal(), public.marshal_with_policy(&[]));
    }
    #[test]
    fn duplicate_oracle_checks_supplied_and_generated_key_semantics() {
        let name = child().name_with_policy(&policy());
        for generated in [false, true] {
            for parent in [
                None,
                Some(AsymKind::Rsa(crate::oracle::rsa::RsaBits::B2048)),
                Some(AsymKind::Ecc(crate::oracle::ec::CurveId::NistP256)),
            ] {
                let payload = wrap::inner_wrap(&sensitive(), &name, &INNER, &[0; 32]);
                let (blob, seed) = if let Some(kind) = parent {
                    let (secret, seed) = wrap::encrypt_seed(kind);
                    (wrap::outer_wrap(&payload, &name, &secret), seed)
                } else {
                    (payload, vec![])
                };
                let mut params = tpm::sized(if generated { &INNER } else { &[] });
                tpm::put_2b(&mut params, &blob);
                tpm::put_2b(&mut params, &seed);
                let response = session_response(&params, HashAlg::Sha256, 1, true);
                let oracle = Oracle::Duplicate {
                    parent,
                    generated,
                    key: INNER.to_vec(),
                };
                oracle.check(&response, None).unwrap();
                let opposite = Oracle::Duplicate {
                    parent,
                    generated: !generated,
                    key: INNER.to_vec(),
                };
                assert!(
                    opposite.check(&response, None).is_err(),
                    "supplied/generated key contract differs"
                );
                let mut bad = response.clone();
                bad[18 + if generated { 16 } else { 0 }] ^= 1;
                assert!(oracle.check(&bad, None).is_err());
                if generated {
                    let mut bad = response.clone();
                    bad[16] ^= 1;
                    assert!(
                        oracle.check(&bad, None).is_err(),
                        "wrong returned key must not recover sensitive bytes"
                    );
                }
            }
        }
    }

    #[test]
    fn import_and_rewrap_oracles_check_integrity_and_full_payload() {
        let name = child().name();
        let key = kdfa(
            HashAlg::Sha256,
            &wrap::PARENT_SEED,
            b"STORAGE",
            &name,
            &[],
            128,
        );
        let integrity_key = kdfa(
            HashAlg::Sha256,
            &wrap::PARENT_SEED,
            b"INTEGRITY",
            &[],
            &[],
            256,
        );
        let mut protected = tpm::sized(&[0x37; 16]);
        protected.extend(wrap::cfb(&key, &[0x37; 16], &sensitive(), true));
        let mut blob = tpm::sized(&HashAlg::Sha256.hmac(&integrity_key, &[&protected, &name]));
        blob.extend(protected);
        let response = tpm::success_response(&[], &tpm::sized(&blob), 1);
        assert_eq!(response.len(), 179);
        let oracle = Oracle::Import { valid: true };
        oracle.check(&response, None).unwrap();
        for index in [16, 18, 49, 52, 69, 170] {
            let mut bad = response.clone();
            bad[index] ^= 1;
            assert!(
                oracle.check(&bad, None).is_err(),
                "Import corrupted byte {index}"
            );
        }
        // Authenticated but incorrect plaintext must still fail independent recovery.
        let mut wrong = sensitive();
        *wrong.last_mut().unwrap() ^= 1;
        let mut protected = tpm::sized(&[0x37; 16]);
        protected.extend(wrap::cfb(&key, &[0x37; 16], &wrong, true));
        let mut blob = tpm::sized(&HashAlg::Sha256.hmac(&integrity_key, &[&protected, &name]));
        blob.extend(protected);
        assert!(
            oracle
                .check(&tpm::success_response(&[], &tpm::sized(&blob), 1), None)
                .is_err()
        );
        for parent in [
            None,
            Some(AsymKind::Rsa(crate::oracle::rsa::RsaBits::B2048)),
            Some(AsymKind::Ecc(crate::oracle::ec::CurveId::NistP256)),
        ] {
            let payload = rewrap_payload();
            let (blob, seed) = if let Some(kind) = parent {
                let (secret, seed) = wrap::encrypt_seed(kind);
                (wrap::outer_wrap(&payload, &name, &secret), seed)
            } else {
                (payload, vec![])
            };
            let mut params = tpm::sized(&blob);
            tpm::put_2b(&mut params, &seed);
            let response = tpm::success_response(&[], &params, 1);
            let oracle = Oracle::Rewrap {
                parent,
                valid: true,
            };
            oracle.check(&response, None).unwrap();
            let mut bad = response;
            bad[20] ^= 1;
            assert!(oracle.check(&bad, None).is_err());
        }
    }
}
