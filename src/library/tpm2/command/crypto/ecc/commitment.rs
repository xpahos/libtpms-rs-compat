// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/EphemeralCommands.c
// - libtpms/src/tpm2/crypto/openssl/CryptEccSignature.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::key::{RC_KEY_HANDLE, ecc_key, ecc_key_derivation_allowed, object_is_public_only};
use super::parameters::parse_curve_id;
use crate::library::constants::{
    TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_NO_RESULT, TPM_RC_SCHEME, TPM_RC_SIZE,
};
use crate::library::tpm2::algorithm::{TPM_ALG_ECDAA, TPM_ALG_ECDH};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_P};
use crate::library::tpm2::commit::CommitState;
use crate::library::tpm2::crypto::EccCurve;
use crate::library::tpm2::ecc::{
    EccPoint, commit_compute, commit_point_from_s2, commit_value, ecc_curve_id, ecc_key_scheme,
    ecc_stored_private, parse_ecc_point, point_is_on_curve, point_multiply_by, write_ecc_point,
};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::public::{MAX_ECC_KEY_BYTES, MAX_SYM_DATA};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::template::TemplateReader;
use crate::library::tpm2::ticket::CONTEXT_INTEGRITY_HASH_ALG;
use crate::types::TpmResult;

const RC_P1: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_S2: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_Y2: TpmResult = TPM_RC_P + TPM_RC_3;

const EMPTY_POINT_SIZE: usize = 4;
const EPHEMERAL_ATTEMPTS: usize = 64;

struct CommitRequest {
    p1: EccPoint,
    p1_size: usize,
    s2: Vec<u8>,
    y2: Vec<u8>,
}

fn parse_commit(parameters: &[u8]) -> Result<CommitRequest, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let before = reader.consumed();
    let p1 = parse_ecc_point(&mut reader).map_err(|code| code + RC_P1)?;
    let p1_size = reader.consumed() - before - 2;
    let s2 = reader
        .tpm2b(MAX_SYM_DATA)
        .map_err(|code| code + RC_S2)?
        .to_vec();
    let y2 = reader
        .tpm2b(MAX_ECC_KEY_BYTES)
        .map_err(|code| code + RC_Y2)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(CommitRequest {
        p1,
        p1_size,
        s2,
        y2,
    })
}

pub(in crate::library::tpm2::command) fn execute_commit(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sign_handle = handle_at(frame, 0)?;
    let request = parse_commit(frame.parameters)?;
    ecc_key_derivation_allowed(runtime)?;

    let key = ecc_key(runtime, sign_handle)?;
    let scheme = ecc_key_scheme(&key).ok_or(TPM_RC_FAILURE)?;
    if scheme.scheme != TPM_ALG_ECDAA {
        return Err(TPM_RC_SCHEME + RC_KEY_HANDLE);
    }
    if request.s2.is_empty() != request.y2.is_empty() {
        return Err(TPM_RC_SIZE + RC_Y2);
    }
    let curve_id = ecc_curve_id(&key).ok_or(TPM_RC_FAILURE)?;

    let mut commit = CommitState::load(runtime)?;
    self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    let r = commit_value(&commit, curve_id, &key.name, None)?.ok_or(TPM_RC_NO_RESULT)?;

    let p2 = if request.s2.is_empty() {
        None
    } else {
        self_test_algorithm(runtime, key.public.name_alg)?;
        let p2 = commit_point_from_s2(curve_id, key.public.name_alg, &request.s2, &request.y2)
            .map_err(|_| crate::library::constants::TPM_RC_HASH + RC_KEY_HANDLE)?;
        if !point_is_on_curve(curve_id, &p2)? {
            return Err(TPM_RC_ECC_POINT + RC_S2);
        }
        if object_is_public_only(runtime, sign_handle) {
            return Err(TPM_RC_KEY + RC_KEY_HANDLE);
        }
        Some(p2)
    };

    let p1 = if request.p1_size > EMPTY_POINT_SIZE {
        if !point_is_on_curve(curve_id, &request.p1)? {
            return Err(TPM_RC_ECC_POINT + RC_P1);
        }
        Some(&request.p1)
    } else {
        None
    };

    let private = ecc_stored_private(&key);
    self_test_algorithm(runtime, TPM_ALG_ECDH)?;
    let cancellation = frame.cancellation;
    let (k, l, e) = commit_compute(curve_id, p1, p2.as_ref(), private, &r, &|| {
        cancellation.check().is_err()
    })?;
    let counter = commit.commit();
    commit.publish(runtime)?;

    let mut writer = BlobWriter::new();
    for point in [&k, &l, &e] {
        write_ecc_point(&mut writer, point)?;
    }
    writer.write_u16(counter);
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(in crate::library::tpm2::command) fn execute_ephemeral(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let mut reader = TemplateReader::new(frame.parameters);
    let curve_id = parse_curve_id(runtime, &mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    ecc_key_derivation_allowed(runtime)?;

    let mut commit = CommitState::load(runtime)?;
    self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    let mut produced = None;
    let curve = EccCurve::lookup(curve_id).ok_or(TPM_RC_NO_RESULT)?;
    for _ in 0..EPHEMERAL_ATTEMPTS {
        let r = commit_value(&commit, curve_id, &[], None)?.ok_or(TPM_RC_NO_RESULT)?;
        self_test_algorithm(runtime, TPM_ALG_ECDH)?;
        match point_multiply_by(&curve, None, &r) {
            Ok(point) => {
                produced = Some((point, commit.commit()));
                break;
            }
            Err(TPM_RC_NO_RESULT) => {
                commit.commit();
            }
            Err(code) => return Err(code),
        }
    }
    let (point, counter) = produced.ok_or(TPM_RC_NO_RESULT)?;
    commit.publish(runtime)?;

    let mut writer = BlobWriter::new();
    write_ecc_point(&mut writer, &point)?;
    writer.write_u16(counter);
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::library::tpm2::command::core::test_support::{dispatch_bytes, response_parameters};
    use crate::library::tpm2::command::crypto::ecc::key::test_support::{
        ATTR_SIGN, CC_COMMIT, CC_EC_EPHEMERAL, CURVE_P256, CURVE_P384, H0, KDF_NULL, KEYED_AUTH,
        PRIVATE_SCALAR, SCHEME_ECDAA, SHA256, cmd, ecc_private, ecc_public, expect,
        generator_multiple, keyed_object, load_external, off_curve_point, point2b, public_point,
        pw, raw_point2b, ready, ready_with, restored, sign_key, tpm2b,
    };
    use crate::library::tpm2::crypto::{Hasher, curve_parameters};
    use crate::library::tpm2::ecc::point_is_on_curve;

    fn ecdaa_key(private: bool) -> Vec<u8> {
        let point = public_point();
        let public = ecc_public(
            ATTR_SIGN,
            &SCHEME_ECDAA,
            CURVE_P256,
            &KDF_NULL,
            &point.x,
            &point.y,
        );
        let sensitive = if private {
            ecc_private(&PRIVATE_SCALAR, &[])
        } else {
            tpm2b(&[])
        };
        load_external(&sensitive, &public)
    }

    fn commit(p1: &[u8], s2: &[u8], y2: &[u8]) -> Vec<u8> {
        let mut parameters = p1.to_vec();
        parameters.extend_from_slice(&tpm2b(s2));
        parameters.extend_from_slice(&tpm2b(y2));
        cmd(CC_COMMIT, &[H0], Some(&pw(&[])), &parameters)
    }

    fn empty_point() -> Vec<u8> {
        raw_point2b(&[], &[])
    }

    fn commit_operand(seed: &str) -> (Vec<u8>, Vec<u8>) {
        let curve = curve_parameters(CURVE_P256).expect("NIST P256");
        for index in 0..100_000u32 {
            let s2 = format!("{seed}{index}").into_bytes();
            let mut hasher = Hasher::new(SHA256).expect("SHA-256");
            hasher.update(&s2);
            let x = crate::library::tpm2::crypto::BigUint::from_be_bytes(&hasher.finalize())
                .unwrap()
                .rem(&curve.prime)
                .expect("a reduced abscissa");
            let x_bytes = x.to_be_bytes(32).expect("32 bytes");
            let square = square_root_of_curve_ordinate(&x_bytes);
            if let Some(y) = square {
                return (s2, y);
            }
        }
        panic!("no quadratic residue found");
    }

    fn square_root_of_curve_ordinate(x: &[u8]) -> Option<Vec<u8>> {
        use crate::library::tpm2::crypto::BigUint;
        let curve = curve_parameters(CURVE_P256).expect("NIST P256");
        let x_value = BigUint::from_be_bytes(x).unwrap();
        let cube = x_value
            .mod_mul(&x_value, &curve.prime)?
            .mod_mul(&x_value, &curve.prime)?;
        let a_x = curve.a.mod_mul(&x_value, &curve.prime)?;
        let rhs = cube
            .mod_add(&a_x, &curve.prime)?
            .mod_add(&curve_b(), &curve.prime)?;
        let exponent = curve.prime.add_u64(1).unwrap().shr(2).unwrap();
        let root = rhs.mod_exp(&exponent, &curve.prime)?;
        if root.mod_mul(&root, &curve.prime)? == rhs {
            root.to_be_bytes(32)
        } else {
            None
        }
    }

    fn curve_b() -> crate::library::tpm2::crypto::BigUint {
        crate::library::tpm2::crypto::BigUint::from_be_bytes(&[
            0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98,
            0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e,
            0x27, 0xd2, 0x60, 0x4b,
        ])
        .unwrap()
    }

    fn bad_operand() -> Vec<u8> {
        for index in 0..100_000u32 {
            let s2 = format!("commit-bad-{index}").into_bytes();
            let mut hasher = Hasher::new(SHA256).expect("SHA-256");
            hasher.update(&s2);
            let curve = curve_parameters(CURVE_P256).expect("NIST P256");
            let x = crate::library::tpm2::crypto::BigUint::from_be_bytes(&hasher.finalize())
                .unwrap()
                .rem(&curve.prime)
                .expect("a reduced abscissa")
                .to_be_bytes(32)
                .expect("32 bytes");
            if square_root_of_curve_ordinate(&x).is_none() {
                return s2;
            }
        }
        panic!("no non-residue found");
    }

    #[test]
    fn ephemeral_points_counters_reference_match() {
        let mut runtime = ready();
        for (record, curve) in [
            ("ECEPH_FIRST", CURVE_P256),
            ("ECEPH_SECOND", CURVE_P256),
            ("ECEPH_P384", CURVE_P384),
        ] {
            let response = expect(
                &mut runtime,
                record,
                &cmd(CC_EC_EPHEMERAL, &[], None, &curve.to_be_bytes()),
            );
            let parameters = response_parameters(&response);
            let counter = u16::from_be_bytes(
                parameters[parameters.len() - 2..]
                    .try_into()
                    .expect("two bytes"),
            );
            assert!(counter < 3, "{record} allocates an early counter");
        }
        let commit = CommitState::load(&runtime).expect("the commitment state loads");
        assert_eq!(commit.counter, 3, "three commitments were allocated");
        for count in 0..3u16 {
            assert!(commit.is_set(count), "count {count} stays live");
        }
    }

    #[test]
    fn ephemeral_failures_reference_match() {
        let mut runtime = ready();
        for (record, curve) in [("ECEPH_UNKNOWN_CURVE", 0x0006u16), ("ECEPH_NONE", 0x0000)] {
            expect(
                &mut runtime,
                record,
                &cmd(CC_EC_EPHEMERAL, &[], None, &curve.to_be_bytes()),
            );
        }
        expect(
            &mut runtime,
            "ECEPH_TRUNCATED",
            &cmd(CC_EC_EPHEMERAL, &[], None, &[0x00]),
        );
        let mut trailing = CURVE_P256.to_be_bytes().to_vec();
        trailing.push(0xff);
        expect(
            &mut runtime,
            "ECEPH_TRAILING",
            &cmd(CC_EC_EPHEMERAL, &[], None, &trailing),
        );
        expect(
            &mut runtime,
            "ECEPH_WITH_SESSION",
            &cmd(
                CC_EC_EPHEMERAL,
                &[],
                Some(&pw(&[])),
                &CURVE_P256.to_be_bytes(),
            ),
        );
    }

    #[test]
    fn rejected_ephemeral_no_counter_allocation() {
        let mut runtime = ready();
        let before = CommitState::load(&runtime).expect("the commitment state loads");
        for packet in [
            cmd(CC_EC_EPHEMERAL, &[], None, &0x0006u16.to_be_bytes()),
            cmd(CC_EC_EPHEMERAL, &[], None, &[0x00]),
            cmd(CC_EC_EPHEMERAL, &[], None, &[0x00, 0x03, 0xff]),
        ] {
            dispatch_bytes(&mut runtime, &packet);
            let now = CommitState::load(&runtime).expect("the commitment state loads");
            assert_eq!(now.counter, before.counter);
            assert_eq!(now.array, before.array);
        }
    }

    #[test]
    fn commit_outputs_operand_shape_reference_match() {
        let (s2, y2) = commit_operand("commit-point-");
        let mut runtime = ready_with(&[ecdaa_key(true)]);
        let empty = [0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        let p1 = point2b(&generator_multiple(2));
        let p3 = point2b(&generator_multiple(3));

        let plain = response_parameters(&expect(
            &mut runtime,
            "COMMIT_PLAIN",
            &commit(&empty_point(), &[], &[]),
        ));
        assert_eq!(&plain[..6], empty, "K is empty without s2");
        assert_eq!(&plain[6..12], empty, "L is empty without s2");
        assert_ne!(&plain[12..18], empty, "E is [r]G");
        assert_eq!(&plain[plain.len() - 2..], [0x00, 0x00], "counter zero");

        let with_p1 =
            response_parameters(&expect(&mut runtime, "COMMIT_P1", &commit(&p1, &[], &[])));
        assert_eq!(&with_p1[..6], empty, "K is empty without s2");
        assert_eq!(&with_p1[6..12], empty, "L is empty without s2");
        assert_ne!(&with_p1[12..18], empty, "E is [r]P1");
        assert_ne!(&with_p1[12..], &plain[12..], "P1 changes E");

        let with_s2 = response_parameters(&expect(
            &mut runtime,
            "COMMIT_S2_Y2",
            &commit(&empty_point(), &s2, &y2),
        ));
        assert_ne!(&with_s2[..6], empty, "K is [d]P2");
        assert_ne!(&with_s2[70..76], empty, "L is [r]P2");
        assert_eq!(
            &with_s2[140..146],
            empty,
            "E is empty when only s2 is supplied"
        );

        let all = response_parameters(&expect(&mut runtime, "COMMIT_ALL", &commit(&p3, &s2, &y2)));
        for offset in [0usize, 70, 140] {
            assert_ne!(
                &all[offset..offset + 6],
                empty,
                "K, L and E are all present"
            );
        }
        assert_eq!(&all[all.len() - 2..], [0x00, 0x03], "the fourth commitment");

        let commit_state = CommitState::load(&runtime).expect("the commitment state loads");
        assert_eq!(commit_state.counter, 4, "four commitments were allocated");
        for count in 0..4u16 {
            assert!(commit_state.is_set(count), "count {count} stays live");
        }
    }

    #[test]
    fn commit_failures_reference_match() {
        let (s2, y2) = commit_operand("commit-point-");
        let mut runtime = restored("COMMIT_AFTER");
        expect(
            &mut runtime,
            "COMMIT_S2_NO_Y2",
            &commit(&empty_point(), &s2, &[]),
        );
        expect(
            &mut runtime,
            "COMMIT_Y2_NO_S2",
            &commit(&empty_point(), &[], &y2),
        );
        expect(
            &mut runtime,
            "COMMIT_BAD_P1",
            &commit(&point2b(&off_curve_point()), &[], &[]),
        );
        expect(
            &mut runtime,
            "COMMIT_BAD_S2",
            &commit(&empty_point(), &bad_operand(), &y2),
        );
        expect(
            &mut runtime,
            "COMMIT_NO_SESSION",
            &cmd(
                CC_COMMIT,
                &[H0],
                None,
                &[&empty_point()[..], &tpm2b(&[]), &tpm2b(&[])].concat(),
            ),
        );
        let mut trailing = [&empty_point()[..], &tpm2b(&[]), &tpm2b(&[])].concat();
        trailing.push(0x00);
        expect(
            &mut runtime,
            "COMMIT_TRAILING",
            &cmd(CC_COMMIT, &[H0], Some(&pw(&[])), &trailing),
        );
        expect(
            &mut runtime,
            "COMMIT_TRUNCATED",
            &cmd(
                CC_COMMIT,
                &[H0],
                Some(&pw(&[])),
                &[&empty_point()[..], &tpm2b(&[])].concat(),
            ),
        );
        expect(
            &mut runtime,
            "COMMIT_OVERSIZE_S2",
            &commit(&empty_point(), &[0x01; 129], &y2),
        );
    }

    #[test]
    fn out_of_field_operand_reference_reduction() {
        use crate::library::tpm2::crypto::{BigUint, curve_parameters};
        let curve = curve_parameters(CURVE_P256).expect("NIST P256");
        let plus_prime = |coordinate: &[u8]| {
            BigUint::from_be_bytes(coordinate)
                .unwrap()
                .add(&curve.prime)
                .unwrap()
                .to_be_bytes(33)
                .expect("a 33-byte alias")
        };
        let (s2, y2) = commit_operand("commit-point-");
        let mut runtime = restored("COMMIT_AFTER");
        let p1 = generator_multiple(2);
        expect(
            &mut runtime,
            "COMMIT_P1_PLUS_PRIME",
            &commit(&raw_point2b(&plus_prime(&p1.x), &p1.y), &[], &[]),
        );
        expect(
            &mut runtime,
            "COMMIT_Y2_PLUS_PRIME",
            &commit(&empty_point(), &s2, &plus_prime(&y2)),
        );
    }

    #[test]
    fn rejected_commit_no_counter_allocation() {
        let (_, y2) = commit_operand("commit-point-");
        let mut runtime = restored("COMMIT_AFTER");
        let before = CommitState::load(&runtime).expect("the commitment state loads");
        for packet in [
            commit(&point2b(&off_curve_point()), &[], &[]),
            commit(&empty_point(), &bad_operand(), &y2),
            commit(&empty_point(), &[0x01; 129], &y2),
        ] {
            dispatch_bytes(&mut runtime, &packet);
            let now = CommitState::load(&runtime).expect("the commitment state loads");
            assert_eq!(now.counter, before.counter);
            assert_eq!(now.array, before.array);
        }
    }

    #[test]
    fn commit_key_checks_reference_match() {
        let mut runtime = ready_with(&[sign_key()]);
        expect(
            &mut runtime,
            "COMMIT_WRONG_SCHEME",
            &commit(&empty_point(), &[], &[]),
        );

        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        let mut parameters = empty_point();
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&tpm2b(&[]));
        expect(
            &mut runtime,
            "COMMIT_WRONG_TYPE",
            &cmd(CC_COMMIT, &[H0], Some(&pw(KEYED_AUTH)), &parameters),
        );
    }

    #[test]
    fn public_only_key_authorization_rejection() {
        let (s2, y2) = commit_operand("commit-point-");
        let mut runtime = ready_with(&[ecdaa_key(false)]);
        expect(
            &mut runtime,
            "COMMIT_PUBLIC_ONLY",
            &commit(&empty_point(), &s2, &y2),
        );
        expect(
            &mut runtime,
            "COMMIT_PUBLIC_ONLY_PLAIN",
            &commit(&empty_point(), &[], &[]),
        );
    }

    #[test]
    fn derived_commit_point_curve_membership() {
        let (s2, y2) = commit_operand("commit-point-");
        let point = commit_point_from_s2(CURVE_P256, SHA256, &s2, &y2).expect("a point");
        assert_eq!(point_is_on_curve(CURVE_P256, &point), Ok(true));
        assert_eq!(point.x.len(), 32);
        assert_eq!(point.y, y2);
        let bad = commit_point_from_s2(CURVE_P256, SHA256, &bad_operand(), &y2).expect("a point");
        assert_eq!(point_is_on_curve(CURVE_P256, &bad), Ok(false));
    }
}
