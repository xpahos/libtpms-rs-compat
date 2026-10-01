// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::tpm2::algorithm::{
    TPM_ALG_ECC, TPM_ALG_ECDAA, TPM_ALG_ECDH, TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_KDF2,
    TPM_ALG_NULL, TPM_ALG_SHA256, TPM_ALG_SM2,
};
use crate::library::tpm2::clock::SteppingClock;
use crate::library::tpm2::crypto::{
    BigUint, EccAffine, EccCurve, Hasher, SeededRand, curve_parameters, work,
};
use crate::library::tpm2::ecc::{EccPoint, crypt_ecc_encrypt, write_ecc_point};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object_load::public_marshal_and_compute_name;
use crate::library::tpm2::object_load::replay::{
    RH_NULL, RH_OWNER, clock, context_load, context_save, exec_raw, load, plain,
    response_parameters, runtime_at, runtime_from, sessioned, tpm2b,
};
use crate::library::tpm2::object_wrap::{Protector, sensitive_to_private};
use crate::library::tpm2::persistent::{
    OwnedAnyObjectBody, OwnedObjectBody, OwnedPublicId, OwnedSecret, OwnedTpmtPublic,
    OwnedTpmtSensitive, OwnedUserNvramEntry, SECRET_STORAGE_BYTES,
};
use crate::library::tpm2::public::{MAX_ECC_KEY_BYTES, PublicParms, Scheme, SymDefObject};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::{
    TPMA_OBJECT_DECRYPT, TPMA_OBJECT_SIGN, TPMA_OBJECT_USER_WITH_AUTH, marshal_public_area,
};
use crate::library::tpm2::test_support::primary_creation_rand;
use crate::library::tpm2::volatile::volatile_all_store;

const SNAPSHOT: &str = "AFTER_CREATE";
const PARENT: u32 = 0x8000_0000;
const KEY: u32 = 0x8000_0001;
const DAA_KEY: u32 = 0x8000_0002;
const PERSISTENT: u32 = 0x8100_0ecc;
const CC_EVICT_CONTROL: u32 = 0x0000_0120;
const CC_ECDH_ZGEN: u32 = 0x0000_0154;
const CC_SIGN: u32 = 0x0000_015d;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const CC_GET_RANDOM: u32 = 0x0000_017b;
const CC_COMMIT: u32 = 0x0000_018b;
const CC_ZGEN_2PHASE: u32 = 0x0000_018d;
const CC_EC_EPHEMERAL: u32 = 0x0000_018e;
const CC_ECC_DECRYPT: u32 = 0x0000_019a;
const ST_HASHCHECK: u16 = 0x8024;
const DIGEST: [u8; 32] = [0x3c; 32];
const MESSAGE: &[u8] = b"hidden scalar width";

fn null_scheme() -> Scheme {
    Scheme {
        scheme: TPM_ALG_NULL,
        hash_alg: None,
        count: None,
        kdf: None,
    }
}

fn kdf2_sha256() -> Scheme {
    Scheme {
        scheme: TPM_ALG_KDF2,
        hash_alg: Some(TPM_ALG_SHA256),
        count: None,
        kdf: None,
    }
}

fn curve(curve_id: u16) -> EccCurve {
    EccCurve::lookup(curve_id).expect("a compiled curve")
}

fn public_point(curve_id: u16, value: &[u8]) -> EccAffine {
    let curve = curve(curve_id);
    curve
        .mul_generator(&curve.scalar(value).expect("the value reduces"))
        .expect("a finite public point")
}

fn key_public(curve_id: u16, value: &[u8], attributes: u32, scheme: Scheme) -> OwnedTpmtPublic {
    let point = public_point(curve_id, value);
    OwnedTpmtPublic {
        object_type: TPM_ALG_ECC,
        name_alg: TPM_ALG_SHA256,
        object_attributes: attributes,
        auth_policy: Vec::new(),
        parameters: PublicParms::Ecc {
            symmetric: SymDefObject {
                algorithm: TPM_ALG_NULL,
                key_bits: None,
                mode: None,
            },
            scheme,
            curve_id,
            kdf: null_scheme(),
        },
        unique: OwnedPublicId::Ecc {
            x: point.x,
            y: point.y,
        },
    }
}

fn exchange_key(curve_id: u16, value: &[u8]) -> OwnedTpmtPublic {
    key_public(
        curve_id,
        value,
        TPMA_OBJECT_USER_WITH_AUTH | TPMA_OBJECT_SIGN | TPMA_OBJECT_DECRYPT,
        null_scheme(),
    )
}

fn daa_key(curve_id: u16, value: &[u8]) -> OwnedTpmtPublic {
    key_public(
        curve_id,
        value,
        TPMA_OBJECT_USER_WITH_AUTH | TPMA_OBJECT_SIGN,
        Scheme {
            scheme: TPM_ALG_ECDAA,
            hash_alg: Some(TPM_ALG_SHA256),
            count: Some(0),
            kdf: None,
        },
    )
}

#[derive(Clone, Debug)]
struct Encoding {
    scalar: Vec<u8>,
    seed: Vec<u8>,
}

impl Encoding {
    fn padded(value: &[u8], width: usize, seed: usize) -> Self {
        assert!(width >= value.len());
        let mut scalar = vec![0u8; width - value.len()];
        scalar.extend_from_slice(value);
        Self {
            scalar,
            seed: vec![0x44; seed],
        }
    }
}

fn object_body(runtime: &Tpm2Runtime, slot: usize) -> &OwnedObjectBody {
    let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[slot].body else {
        panic!("slot {slot} holds an object");
    };
    body
}

fn persistent_body(runtime: &Tpm2Runtime, handle: u32) -> &OwnedObjectBody {
    let state = runtime.state.as_ref().expect("a decoded state");
    for entry in &state.user_nvram.entries {
        if let OwnedUserNvramEntry::Persistent {
            handle: stored,
            object,
            ..
        } = entry
            && *stored == handle
            && let OwnedAnyObjectBody::Object(body) = &object.body
        {
            return body;
        }
    }
    panic!("no persistent object {handle:#010x}");
}

fn stored_encoding(body: &OwnedObjectBody) -> Encoding {
    Encoding {
        scalar: body
            .sensitive
            .sensitive
            .as_ref()
            .expect("a private scalar")
            .as_bytes()
            .to_vec(),
        seed: body.sensitive.seed_value.as_bytes().to_vec(),
    }
}

fn runtime_form(body: &OwnedObjectBody) -> [u8; SECRET_STORAGE_BYTES] {
    *body
        .sensitive
        .sensitive
        .as_ref()
        .expect("a private scalar")
        .fixed_width()
        .expect("the scalar fits the fixed-width storage")
}

fn wrapped_private(
    runtime: &Tpm2Runtime,
    public: &OwnedTpmtPublic,
    encoding: &Encoding,
) -> Vec<u8> {
    let parent = object_body(runtime, 0);
    let protector = Protector {
        public: &parent.public,
        seed_value: parent.sensitive.seed_value.as_bytes(),
    };
    let sensitive = OwnedTpmtSensitive {
        sensitive_type: TPM_ALG_ECC,
        auth_value: OwnedSecret::from_vec(Vec::new()),
        seed_value: OwnedSecret::copy_of(&encoding.seed),
        sensitive: Some(OwnedSecret::copy_of(&encoding.scalar)),
    };
    let name = public_marshal_and_compute_name(public).expect("the public area has a name");
    sensitive_to_private(
        &sensitive,
        &name,
        &protector,
        TPM_ALG_SHA256,
        &mut primary_creation_rand(b"ecc scalar encoding"),
    )
    .expect("the sensitive area wraps")
}

fn load_command(runtime: &Tpm2Runtime, public: &OwnedTpmtPublic, encoding: &Encoding) -> Vec<u8> {
    let private = wrapped_private(runtime, public, encoding);
    let public_area = marshal_public_area(public).expect("the public area marshals");
    load(PARENT, &[], &private, &public_area)
}

struct Session {
    runtime: Tpm2Runtime,
    clock: SteppingClock,
    load_lengths: Vec<usize>,
    load_responses: Vec<Vec<u8>>,
}

impl Session {
    fn new() -> Self {
        let clock = clock();
        let runtime = runtime_at(SNAPSHOT, &clock);
        Self {
            runtime,
            clock,
            load_lengths: Vec::new(),
            load_responses: Vec::new(),
        }
    }

    fn load(&mut self, public: &OwnedTpmtPublic, encoding: &Encoding) {
        let command = load_command(&self.runtime, public, encoding);
        self.load_lengths.push(command.len());
        let response = exec_raw(&mut self.runtime, &self.clock, command);
        assert_eq!(response[6..10], [0; 4], "TPM2_Load succeeds");
        self.load_responses.push(response);
    }

    fn run(&mut self, command: Vec<u8>) -> Vec<u8> {
        exec_raw(&mut self.runtime, &self.clock, command)
    }

    fn measure(&mut self, command: Vec<u8>) -> Measured {
        measure_command(&mut self.runtime, &self.clock, command)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct Measured {
    response: Vec<u8>,
    counters: work::Counters,
}

fn point_2b(point: &EccAffine) -> Vec<u8> {
    let mut writer = BlobWriter::new();
    write_ecc_point(
        &mut writer,
        &EccPoint {
            x: point.x.clone(),
            y: point.y.clone(),
        },
    )
    .expect("the point marshals");
    writer.into_bytes()
}

fn zgen(handle: u32, point: &EccAffine) -> Vec<u8> {
    sessioned(CC_ECDH_ZGEN, &[handle], &[], &point_2b(point))
}

fn sign(handle: u32, scheme: u16, count: Option<u16>) -> Vec<u8> {
    let mut parameters = tpm2b(&DIGEST);
    parameters.extend_from_slice(&scheme.to_be_bytes());
    parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    if let Some(count) = count {
        parameters.extend_from_slice(&count.to_be_bytes());
    }
    parameters.extend_from_slice(&ST_HASHCHECK.to_be_bytes());
    parameters.extend_from_slice(&RH_NULL.to_be_bytes());
    parameters.extend_from_slice(&tpm2b(&[]));
    sessioned(CC_SIGN, &[handle], &[], &parameters)
}

fn ecc_decrypt(handle: u32, curve_id: u16, public: &OwnedTpmtPublic) -> Vec<u8> {
    let OwnedPublicId::Ecc { x, y } = &public.unique else {
        panic!("an ECC key");
    };
    let mut rand = SeededRand::instantiate(
        &[0x5e; 64],
        b"ECCENC",
        &curve_id.to_be_bytes(),
        &[],
        1,
        false,
    )
    .expect("a seeded generator");
    let ciphertext = crypt_ecc_encrypt(
        curve_id,
        &EccPoint {
            x: x.clone(),
            y: y.clone(),
        },
        kdf2_sha256(),
        MESSAGE,
        &mut rand,
        &mut |_| Ok(()),
    )
    .expect("the message encrypts to the key");
    let mut writer = BlobWriter::new();
    write_ecc_point(&mut writer, &ciphertext.c1).expect("C1 marshals");
    let mut parameters = writer.into_bytes();
    parameters.extend_from_slice(&tpm2b(&ciphertext.c2));
    parameters.extend_from_slice(&tpm2b(&ciphertext.c3));
    parameters.extend_from_slice(&TPM_ALG_KDF2.to_be_bytes());
    parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    sessioned(CC_ECC_DECRYPT, &[handle], &[], &parameters)
}

fn salted_session(handle: u32, point: &EccAffine) -> Vec<u8> {
    let mut parameters = handle.to_be_bytes().to_vec();
    parameters.extend_from_slice(&RH_NULL.to_be_bytes());
    parameters.extend_from_slice(&tpm2b(&[0x11; 16]));
    parameters.extend_from_slice(&point_2b(point));
    parameters.push(0x00);
    parameters.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    parameters.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    plain(CC_START_AUTH_SESSION, &parameters)
}

fn flush(handle: u32) -> Vec<u8> {
    plain(CC_FLUSH_CONTEXT, &handle.to_be_bytes())
}

fn ec_ephemeral(curve_id: u16) -> Vec<u8> {
    plain(CC_EC_EPHEMERAL, &curve_id.to_be_bytes())
}

fn zgen_2phase(
    handle: u32,
    static_point: &EccAffine,
    ephemeral: &EccAffine,
    scheme: u16,
    counter: u16,
) -> Vec<u8> {
    let mut parameters = point_2b(static_point);
    parameters.extend_from_slice(&point_2b(ephemeral));
    parameters.extend_from_slice(&scheme.to_be_bytes());
    parameters.extend_from_slice(&counter.to_be_bytes());
    sessioned(CC_ZGEN_2PHASE, &[handle], &[], &parameters)
}

fn commit(handle: u32, p1: &EccAffine, s2: &[u8], y2: &[u8]) -> Vec<u8> {
    let mut parameters = point_2b(p1);
    parameters.extend_from_slice(&tpm2b(s2));
    parameters.extend_from_slice(&tpm2b(y2));
    sessioned(CC_COMMIT, &[handle], &[], &parameters)
}

fn get_random(count: u16) -> Vec<u8> {
    plain(CC_GET_RANDOM, &count.to_be_bytes())
}

fn evict_control(object: u32, persistent: u32) -> Vec<u8> {
    sessioned(
        CC_EVICT_CONTROL,
        &[RH_OWNER, object],
        &[],
        &persistent.to_be_bytes(),
    )
}

fn trailing_counter(response: &[u8]) -> u16 {
    let parameters = response_parameters(response);
    u16::from_be_bytes(
        parameters[parameters.len() - 2..]
            .try_into()
            .expect("a trailing counter"),
    )
}

fn response_handle(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[10..14].try_into().expect("a response handle"))
}

fn square_root(value: &BigUint, prime: &BigUint) -> Option<BigUint> {
    let one = BigUint::from_u64(1)?;
    if value.is_zero() {
        return BigUint::zero();
    }
    let minus_one = prime.sub_u64(1)?;
    let half = minus_one.shr(1)?;
    if value.mod_exp(&half, prime)? != one {
        return None;
    }
    let mut odd = minus_one.clone();
    let mut twos = 0usize;
    while !odd.is_odd() {
        odd = odd.shr(1)?;
        twos += 1;
    }
    let mut non_residue = BigUint::from_u64(2)?;
    while non_residue.mod_exp(&half, prime)? != minus_one {
        non_residue = non_residue.add_u64(1)?;
    }
    let mut order = twos;
    let mut c = non_residue.mod_exp(&odd, prime)?;
    let mut t = value.mod_exp(&odd, prime)?;
    let mut root = value.mod_exp(&odd.add_u64(1)?.shr(1)?, prime)?;
    while t != one {
        let mut least = 0usize;
        let mut probe = t.clone();
        while probe != one {
            probe = probe.mod_mul(&probe, prime)?;
            least += 1;
        }
        let mut b = c.clone();
        for _ in 0..order - least - 1 {
            b = b.mod_mul(&b, prime)?;
        }
        order = least;
        c = b.mod_mul(&b, prime)?;
        t = t.mod_mul(&c, prime)?;
        root = root.mod_mul(&b, prime)?;
    }
    Some(root)
}

fn commit_operand(curve_id: u16) -> (Vec<u8>, Vec<u8>) {
    let reference = curve_parameters(curve_id).expect("a compiled curve");
    let width = curve(curve_id).field_bytes();
    for index in 0u32.. {
        let s2 = format!("ecc scalar encoding commit {curve_id:#06x} {index}").into_bytes();
        let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("SHA-256");
        hasher.update(&s2);
        let x = BigUint::from_be_bytes(&hasher.finalize())
            .unwrap()
            .rem(&reference.prime)
            .expect("a reduced abscissa");
        let right = x
            .mod_mul(&x, &reference.prime)
            .and_then(|square| square.mod_mul(&x, &reference.prime))
            .and_then(|cube| {
                cube.mod_add(
                    &reference.a.mod_mul(&x, &reference.prime)?,
                    &reference.prime,
                )
            })
            .and_then(|sum| sum.mod_add(&reference.b, &reference.prime))
            .expect("the curve equation evaluates");
        if let Some(y) = square_root(&right, &reference.prime) {
            return (s2, y.to_be_bytes(width).expect("a field element"));
        }
    }
    unreachable!("half of all abscissas are on the curve")
}

fn hidden_value(curve_id: u16, hidden_bytes: usize) -> Vec<u8> {
    let order_bytes = curve(curve_id).order_bytes();
    (0..order_bytes - hidden_bytes)
        .map(|index| 0x5a ^ (index as u8).wrapping_mul(29))
        .collect()
}

#[test]
fn encrypted_scalar_encoding_leaves_zgen_work_unchanged() {
    const P256: u16 = 0x0003;
    let value = [0x5au8; 24];
    let public = exchange_key(P256, &value);
    let generator = public_point(P256, &[1]);
    let mut sessions = Vec::new();
    let mut work = Vec::new();
    for encoding in [
        Encoding::padded(&value, 24, 8),
        Encoding::padded(&value, 32, 0),
    ] {
        let mut session = Session::new();
        session.load(&public, &encoding);
        assert_eq!(
            stored_encoding(object_body(&session.runtime, 1)).scalar,
            encoding.scalar,
            "the object keeps the encoding it was loaded with"
        );
        let warm = session.run(zgen(KEY, &generator));
        assert_eq!(
            warm[6..10],
            [0; 4],
            "the warm-up ZGen runs the ECDH self-test"
        );
        let measured = session.measure(zgen(KEY, &generator));
        assert_eq!(measured.response[6..10], [0; 4]);
        work.push(measured);
        sessions.push(session);
    }
    assert_eq!(
        sessions[0].load_lengths, sessions[1].load_lengths,
        "the encrypted private areas have the same length"
    );
    assert_eq!(sessions[0].load_responses, sessions[1].load_responses);
    assert_eq!(work[0].response, work[1].response);
    assert_eq!(
        work[0].counters, work[1].counters,
        "a 24-byte scalar and its 32-byte zero-padded encoding must do the same ZGen work"
    );
    assert_eq!(
        runtime_form(object_body(&sessions[0].runtime, 1)),
        runtime_form(object_body(&sessions[1].runtime, 1)),
        "both encodings give the arithmetic the same fixed-width storage"
    );
}

struct Operations {
    labels: Vec<&'static str>,
    measured: Vec<Measured>,
}

impl Operations {
    fn record(&mut self, pass: usize, label: &'static str, measured: Measured) {
        if pass == 1 {
            self.labels.push(label);
            self.measured.push(measured);
        }
    }
}

fn private_operations(curve_id: u16, encoding: &Encoding, value: &[u8]) -> (Session, Operations) {
    let exchange = exchange_key(curve_id, value);
    let daa = daa_key(curve_id, value);
    let peer = public_point(curve_id, &[0x21, 0x43]);
    let peer_ephemeral = public_point(curve_id, &[0x65, 0x87]);
    let salt_point = public_point(curve_id, &[0x0f, 0x1e]);
    let (s2, y2) = commit_operand(curve_id);
    let mut session = Session::new();
    session.load(&exchange, encoding);
    session.load(&daa, encoding);
    let mut operations = Operations {
        labels: Vec::new(),
        measured: Vec::new(),
    };
    for pass in 0..2 {
        let measured = session.measure(zgen(KEY, &peer));
        operations.record(pass, "ECDH_ZGen", measured);
        let measured = session.measure(ecc_decrypt(KEY, curve_id, &exchange));
        operations.record(pass, "ECC_Decrypt", measured);
        for (label, scheme) in [
            ("Sign ECDSA", TPM_ALG_ECDSA),
            ("Sign ECSCHNORR", TPM_ALG_ECSCHNORR),
            ("Sign SM2", TPM_ALG_SM2),
        ] {
            let measured = session.measure(sign(KEY, scheme, None));
            operations.record(pass, label, measured);
        }
        let salted = session.measure(salted_session(KEY, &salt_point));
        assert_eq!(salted.response[6..10], [0; 4], "the salted session starts");
        let flushed = session.run(flush(response_handle(&salted.response)));
        assert_eq!(flushed[6..10], [0; 4]);
        operations.record(pass, "StartAuthSession salted", salted);
        for (label, scheme) in [
            ("ZGen_2Phase ECDH", TPM_ALG_ECDH),
            ("ZGen_2Phase SM2", TPM_ALG_SM2),
        ] {
            let ephemeral = session.run(ec_ephemeral(curve_id));
            assert_eq!(ephemeral[6..10], [0; 4], "EC_Ephemeral succeeds");
            let counter = trailing_counter(&ephemeral);
            let measured =
                session.measure(zgen_2phase(KEY, &peer, &peer_ephemeral, scheme, counter));
            operations.record(pass, label, measured);
        }
        let committed = session.measure(commit(DAA_KEY, &peer, &s2, &y2));
        assert_eq!(committed.response[6..10], [0; 4], "TPM2_Commit succeeds");
        let counter = trailing_counter(&committed.response);
        operations.record(pass, "Commit", committed);
        let measured = session.measure(sign(DAA_KEY, TPM_ALG_ECDAA, Some(counter)));
        operations.record(pass, "Sign ECDAA", measured);
        let measured = session.measure(get_random(32));
        operations.record(pass, "GetRandom", measured);
    }
    (session, operations)
}

fn check_curve(curve_id: u16) {
    const HIDDEN: usize = 8;
    let value = hidden_value(curve_id, HIDDEN);
    let order_bytes = curve(curve_id).order_bytes();
    let mut encodings = vec![
        (
            "minimal",
            Encoding::padded(&value, order_bytes - HIDDEN, HIDDEN),
        ),
        ("order width", Encoding::padded(&value, order_bytes, 0)),
    ];
    if order_bytes < MAX_ECC_KEY_BYTES {
        encodings.push((
            "largest TPM2B_ECC_PARAMETER",
            Encoding::padded(&value, MAX_ECC_KEY_BYTES, 0),
        ));
    }
    let mut results = Vec::new();
    for (label, encoding) in &encodings {
        let (session, operations) = private_operations(curve_id, encoding, &value);
        for slot in [1, 2] {
            assert_eq!(
                stored_encoding(object_body(&session.runtime, slot)).scalar,
                encoding.scalar,
                "curve {curve_id:#06x} {label}: the loaded object keeps its encoding"
            );
        }
        results.push((label, session, operations));
    }
    assert_eq!(
        results[0].1.load_lengths, results[1].1.load_lengths,
        "curve {curve_id:#06x}: the seed compensates the scalar width inside the encrypted blob"
    );
    let (reference_label, reference, reference_operations) = &results[0];
    for (label, session, operations) in &results[1..] {
        assert_eq!(
            session.load_responses, reference.load_responses,
            "curve {curve_id:#06x}: {label} vs {reference_label} TPM2_Load responses"
        );
        assert_eq!(operations.labels, reference_operations.labels);
        for ((name, measured), expected) in operations
            .labels
            .iter()
            .zip(&operations.measured)
            .zip(&reference_operations.measured)
        {
            assert_eq!(
                measured.response[6..10],
                [0; 4],
                "curve {curve_id:#06x} {label}: {name} succeeds"
            );
            assert_eq!(
                measured.response, expected.response,
                "curve {curve_id:#06x}: {name} output for {label} vs {reference_label}"
            );
            assert_eq!(
                measured.counters, expected.counters,
                "curve {curve_id:#06x}: {name} work for {label} vs {reference_label}"
            );
        }
    }
    for (_, session, _) in &results[1..] {
        assert_eq!(
            runtime_form(object_body(&session.runtime, 1)),
            runtime_form(object_body(&reference.runtime, 1)),
            "curve {curve_id:#06x}: every encoding has the same fixed-width storage"
        );
    }
}

#[test]
fn nist_p192_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0001);
}

#[test]
fn nist_p224_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0002);
}

#[test]
fn nist_p256_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0003);
}

#[test]
fn nist_p384_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0004);
}

#[test]
fn nist_p521_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0005);
}

#[test]
fn bn_p256_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0010);
}

#[test]
fn bn_p638_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0011);
}

#[test]
fn sm2_p256_scalar_encodings_leave_private_operations_unchanged() {
    check_curve(0x0020);
}

#[derive(Debug, Eq, PartialEq)]
struct DrbgState {
    reseed_counter: u64,
    magic: u32,
    seed: Vec<u8>,
    last_value: Vec<u32>,
}

fn drbg_state(runtime: &Tpm2Runtime) -> DrbgState {
    let state = &runtime.live.orderly.drbg_state;
    DrbgState {
        reseed_counter: state.reseed_counter,
        magic: state.drbg_magic,
        seed: state.seed.as_bytes().to_vec(),
        last_value: state.last_value.to_vec(),
    }
}

fn measure_command(runtime: &mut Tpm2Runtime, clock: &SteppingClock, command: Vec<u8>) -> Measured {
    let (response, counters) = work::measure(|| exec_raw(runtime, clock, command));
    Measured { response, counters }
}

struct RestoredPath {
    kept: Encoding,
    storage: [u8; SECRET_STORAGE_BYTES],
    drbg_at_start: DrbgState,
    zgen: Measured,
    drbg_before_sign: DrbgState,
    sign: Measured,
    random: Measured,
}

fn restored_forms(body: &OwnedObjectBody) -> (Encoding, [u8; SECRET_STORAGE_BYTES]) {
    (stored_encoding(body), runtime_form(body))
}

fn exercise_restored(
    runtime: &mut Tpm2Runtime,
    clock: &SteppingClock,
    handle: u32,
    (kept, storage): (Encoding, [u8; SECRET_STORAGE_BYTES]),
    peer: &EccAffine,
) -> RestoredPath {
    let drbg_at_start = drbg_state(runtime);
    let warm = exec_raw(runtime, clock, zgen(handle, peer));
    assert_eq!(warm[6..10], [0; 4], "the warm-up ZGen succeeds");
    let zgen = measure_command(runtime, clock, zgen(handle, peer));
    let warm = exec_raw(runtime, clock, sign(handle, TPM_ALG_ECDSA, None));
    assert_eq!(warm[6..10], [0; 4], "the warm-up ECDSA signature succeeds");
    let drbg_before_sign = drbg_state(runtime);
    let sign = measure_command(runtime, clock, sign(handle, TPM_ALG_ECDSA, None));
    let random = measure_command(runtime, clock, get_random(32));
    RestoredPath {
        kept,
        storage,
        drbg_at_start,
        zgen,
        drbg_before_sign,
        sign,
        random,
    }
}

const RESTORE_PATHS: [&str; 3] = ["ContextLoad", "volatile state", "persistent object"];

struct Restored {
    saved_context_length: usize,
    paths: [RestoredPath; 3],
}

fn restore_paths(encoding: &Encoding) -> Restored {
    const P256: u16 = 0x0003;
    let value = [0x5au8; 24];
    let public = exchange_key(P256, &value);
    let peer = public_point(P256, &[0x21, 0x43]);
    let mut session = Session::new();
    session.load(&public, encoding);
    let warm = session.run(zgen(KEY, &peer));
    assert_eq!(warm[6..10], [0; 4]);

    let saved = session.run(context_save(KEY));
    assert_eq!(saved[6..10], [0; 4], "ContextSave succeeds");
    let blob = response_parameters(&saved);
    let flushed = session.run(flush(KEY));
    assert_eq!(flushed[6..10], [0; 4]);
    let loaded = session.run(context_load(&blob));
    assert_eq!(loaded[6..10], [0; 4], "ContextLoad succeeds");
    let handle = response_handle(&loaded);
    let slot = (handle - PARENT) as usize;
    let forms = restored_forms(object_body(&session.runtime, slot));
    let context = exercise_restored(&mut session.runtime, &session.clock, handle, forms, &peer);

    let evicted = session.run(evict_control(handle, PERSISTENT));
    assert_eq!(evicted[6..10], [0; 4], "EvictControl succeeds");
    let permanent = crate::library::tpm2::persistent_all_store(&session.runtime)
        .expect("the permanent state serializes");
    let volatile = volatile_all_store(&session.runtime, &session.clock)
        .expect("the volatile state serializes");

    let volatile_clock = clock();
    let mut volatile_runtime = runtime_from(&permanent, &volatile, &volatile_clock);
    let forms = restored_forms(object_body(&volatile_runtime, slot));
    let volatile_path =
        exercise_restored(&mut volatile_runtime, &volatile_clock, handle, forms, &peer);

    let persistent_clock = clock();
    let mut persistent_runtime = runtime_from(&permanent, &volatile, &persistent_clock);
    let forms = restored_forms(persistent_body(&persistent_runtime, PERSISTENT));
    let persistent_path = exercise_restored(
        &mut persistent_runtime,
        &persistent_clock,
        PERSISTENT,
        forms,
        &peer,
    );
    Restored {
        saved_context_length: blob.len(),
        paths: [context, volatile_path, persistent_path],
    }
}

#[test]
fn restored_scalar_encodings_keep_serialization_and_leave_work_unchanged() {
    let value = [0x5au8; 24];
    let encodings = [
        Encoding::padded(&value, 24, 8),
        Encoding::padded(&value, 32, 0),
    ];
    let mut expected_storage = [0u8; SECRET_STORAGE_BYTES];
    expected_storage[SECRET_STORAGE_BYTES - value.len()..].copy_from_slice(&value);
    let restored: Vec<Restored> = encodings.iter().map(restore_paths).collect();
    for (encoding, restored) in encodings.iter().zip(&restored) {
        for (path, evidence) in RESTORE_PATHS.iter().zip(&restored.paths) {
            assert_eq!(
                evidence.kept.scalar,
                encoding.scalar,
                "{path} keeps the {}-byte scalar encoding",
                encoding.scalar.len()
            );
            assert_eq!(evidence.kept.seed, encoding.seed, "{path} keeps the seed");
            assert_eq!(
                evidence.storage, expected_storage,
                "{path} rebuilds the right-aligned fixed-width storage"
            );
            for (command, measured) in [
                ("ZGen", &evidence.zgen),
                ("ECDSA Sign", &evidence.sign),
                ("GetRandom", &evidence.random),
            ] {
                assert_eq!(
                    measured.response[6..10],
                    [0; 4],
                    "{path}: {command} succeeds"
                );
            }
            assert!(
                response_parameters(&evidence.sign.response).len() > 4,
                "{path}: the response carries a signature"
            );
            assert_ne!(
                evidence.drbg_at_start, evidence.drbg_before_sign,
                "{path}: the warm-up signature draws from the DRBG, so the compared signatures depend on it"
            );
        }
    }
    assert_eq!(
        restored[0].saved_context_length, restored[1].saved_context_length,
        "the saved contexts have the same length"
    );
    for (index, path) in RESTORE_PATHS.iter().enumerate() {
        let (left, right) = (&restored[0].paths[index], &restored[1].paths[index]);
        assert_eq!(
            left.drbg_at_start, right.drbg_at_start,
            "{path}: both encodings start from the same DRBG state"
        );
        assert_eq!(
            left.zgen.response, right.zgen.response,
            "{path}: ZGen output"
        );
        assert_eq!(left.zgen.counters, right.zgen.counters, "{path}: ZGen work");
        assert_eq!(
            left.drbg_before_sign, right.drbg_before_sign,
            "{path}: both signatures start from the same DRBG state"
        );
        assert_eq!(
            left.sign.response, right.sign.response,
            "{path}: ECDSA result and signature bytes"
        );
        assert_eq!(
            left.sign.counters, right.sign.counters,
            "{path}: ECDSA work"
        );
        assert_eq!(
            left.random.response, right.random.response,
            "{path}: DRBG output after the signature"
        );
        assert_eq!(
            left.random.counters, right.random.counters,
            "{path}: GetRandom work"
        );
        assert_eq!(
            left.storage, right.storage,
            "{path}: both encodings have the same fixed-width storage"
        );
    }
}

#[test]
fn key_validation_depends_on_the_value_not_the_encoding() {
    use crate::library::constants::{TPM_RC_BINDING, TPM_RC_KEY_SIZE};
    use crate::library::tpm2::object_load::validate_keys;
    const P256: u16 = 0x0003;
    let order = BigUint::from_be_bytes(&curve(P256).order()).unwrap();
    let public_of_one = exchange_key(P256, &[1]);
    let cases = [
        (
            "one",
            BigUint::from_u64(1).unwrap(),
            exchange_key(P256, &[1]),
            Ok(()),
        ),
        (
            "n - 1",
            order.sub_u64(1).unwrap(),
            exchange_key(P256, &order.sub_u64(1).unwrap().to_be_bytes(32).unwrap()),
            Ok(()),
        ),
        (
            "zero",
            BigUint::zero().unwrap(),
            public_of_one.clone(),
            Err(TPM_RC_KEY_SIZE),
        ),
        (
            "n",
            order.clone(),
            public_of_one.clone(),
            Err(TPM_RC_KEY_SIZE),
        ),
        (
            "n + 1",
            order.add_u64(1).unwrap(),
            public_of_one.clone(),
            Err(TPM_RC_KEY_SIZE),
        ),
        (
            "two",
            BigUint::from_u64(2).unwrap(),
            public_of_one.clone(),
            Err(TPM_RC_BINDING),
        ),
    ];
    for (label, value, public, expected) in cases {
        for width in [value.byte_len(), 32, 33, MAX_ECC_KEY_BYTES] {
            let Some(encoded) = value.to_be_bytes(width) else {
                continue;
            };
            let sensitive = OwnedTpmtSensitive {
                sensitive_type: TPM_ALG_ECC,
                auth_value: OwnedSecret::from_vec(Vec::new()),
                seed_value: OwnedSecret::from_vec(Vec::new()),
                sensitive: Some(OwnedSecret::copy_of(&encoded)),
            };
            let outcome = validate_keys(&public, Some(&sensitive), 0, 0);
            assert_eq!(outcome, expected, "{label} encoded in {width} bytes");
        }
    }
}
