use super::key::{RC_KEY_HANDLE, ecc_key, ecc_key_derivation_allowed};
use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_ECC_POINT, TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_NO_RESULT,
    TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{TPM_ALG_ECDH, TPM_ALG_ECMQV, TPM_ALG_NULL, TPM_ALG_SM2};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_P,
};
use crate::library::tpm2::commit::CommitState;
use crate::library::tpm2::crypto::{EccKeyError, generate_ecc_key};
use crate::library::tpm2::ecc::{
    EccPoint, TwoPhaseOutcome, commit_value, ecc_curve_id, ecc_key_scheme, ecc_private_scalar,
    ecc_public_point, parse_ecc_point, point_is_on_curve, point_multiply, two_phase_key_exchange,
    write_ecc_point,
};
use crate::library::tpm2::failure_mode::{FailureLocation, enter_failure_mode};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::template::{TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TemplateReader};
use crate::library::tpm2::ticket::CONTEXT_INTEGRITY_HASH_ALG;

const RC_IN_POINT: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_QS_B: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_QE_B: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_COUNTER: TpmResult = TPM_RC_P + TPM_RC_4;

const KEY_GEN_ATTEMPTS: usize = 64;

fn safe_add_to_result(code: TpmResult, modifier: TpmResult) -> TpmResult {
    if code & 0x080 != 0 && code & 0xf40 == 0 {
        code + modifier
    } else {
        code
    }
}

fn point_output(points: &[&EccPoint]) -> Result<CommandOutput, TpmResult> {
    let mut writer = BlobWriter::new();
    for point in points {
        write_ecc_point(&mut writer, point)?;
    }
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(in crate::library::tpm2::command) fn execute_zgen(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let in_point = parse_ecc_point(&mut reader).map_err(|code| code + RC_IN_POINT)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let key = ecc_key(runtime, key_handle)?;
    let attributes = key.public.object_attributes;
    if attributes & TPMA_OBJECT_RESTRICTED != 0 || attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }
    let scheme = ecc_key_scheme(&key).ok_or(TPM_RC_FAILURE)?;
    if scheme.scheme != TPM_ALG_ECDH && scheme.scheme != TPM_ALG_NULL {
        return Err(TPM_RC_SCHEME + RC_KEY_HANDLE);
    }
    let curve_id = ecc_curve_id(&key).ok_or(TPM_RC_FAILURE)?;
    let private = ecc_private_scalar(&key).unwrap_or_default();
    self_test_algorithm(runtime, TPM_ALG_ECDH)?;
    let out_point = point_multiply(curve_id, Some(&in_point), private)
        .map_err(|code| safe_add_to_result(code, RC_IN_POINT))?;
    point_output(&[&out_point])
}

pub(in crate::library::tpm2::command) fn execute_key_gen(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let key = ecc_key(runtime, key_handle)?;
    let curve_id = ecc_curve_id(&key).ok_or(TPM_RC_FAILURE)?;
    let public = ecc_public_point(&key).ok_or(TPM_RC_FAILURE)?;

    self_test_algorithm(runtime, TPM_ALG_ECDH)?;
    let mut rand = take_live_rand(runtime)?;
    let mut outcome = Err(TPM_RC_NO_RESULT);
    for _ in 0..KEY_GEN_ATTEMPTS {
        let ephemeral = match generate_ecc_key(curve_id, &mut rand) {
            Ok(ephemeral) => ephemeral,
            Err(EccKeyError::Curve) => {
                outcome = Err(crate::library::constants::TPM_RC_CURVE);
                break;
            }
            Err(EccKeyError::NoResult) => continue,
        };
        let pub_point = EccPoint {
            x: ephemeral.x,
            y: ephemeral.y,
        };
        match point_multiply(curve_id, Some(&public), &ephemeral.private) {
            Ok(z_point) => {
                outcome = Ok((z_point, pub_point));
                break;
            }
            Err(TPM_RC_ECC_POINT) => {
                outcome = Err(TPM_RC_KEY + RC_KEY_HANDLE);
                break;
            }
            Err(_) => continue,
        }
    }
    finish_live_rand(runtime, rand)?;
    let (z_point, pub_point) = outcome?;
    point_output(&[&z_point, &pub_point])
}

struct TwoPhaseRequest {
    in_qs_b: EccPoint,
    in_qe_b: EccPoint,
    in_scheme: u16,
    counter: u16,
}

fn parse_two_phase(runtime: &Tpm2Runtime, parameters: &[u8]) -> Result<TwoPhaseRequest, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let in_qs_b = parse_ecc_point(&mut reader).map_err(|code| code + RC_IN_QS_B)?;
    let in_qe_b = parse_ecc_point(&mut reader).map_err(|code| code + RC_IN_QE_B)?;
    let in_scheme = parse_key_exchange_scheme(runtime, &mut reader)?;
    let counter = reader.u16().map_err(|code| code + RC_COUNTER)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(TwoPhaseRequest {
        in_qs_b,
        in_qe_b,
        in_scheme,
        counter,
    })
}

fn parse_key_exchange_scheme(
    runtime: &Tpm2Runtime,
    reader: &mut TemplateReader<'_>,
) -> Result<u16, TpmResult> {
    let scheme = reader.u16().map_err(|code| code + RC_IN_SCHEME)?;
    if !matches!(scheme, TPM_ALG_ECDH | TPM_ALG_ECMQV | TPM_ALG_SM2) {
        return Err(TPM_RC_SCHEME + RC_IN_SCHEME);
    }
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let enabled =
        crate::library::tpm2::algorithm::algorithm_profile_name(scheme).is_some_and(|name| {
            crate::library::tpm2::algorithm::algorithm_enabled(&state.profile.algorithms, name)
        });
    if !enabled {
        return Err(TPM_RC_SCHEME + RC_IN_SCHEME);
    }
    Ok(scheme)
}

pub(in crate::library::tpm2::command) fn execute_two_phase(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let request = parse_two_phase(runtime, frame.parameters)?;
    ecc_key_derivation_allowed(runtime)?;

    let key = ecc_key(runtime, key_handle)?;
    let attributes = key.public.object_attributes;
    if attributes & TPMA_OBJECT_RESTRICTED != 0 || attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }
    let key_scheme = ecc_key_scheme(&key).ok_or(TPM_RC_FAILURE)?;
    let scheme = if key_scheme.scheme != TPM_ALG_NULL {
        if key_scheme.scheme != request.in_scheme {
            return Err(TPM_RC_SCHEME + RC_IN_SCHEME);
        }
        key_scheme.scheme
    } else {
        request.in_scheme
    };

    let curve_id = ecc_curve_id(&key).ok_or(TPM_RC_FAILURE)?;
    if !point_is_on_curve(curve_id, &request.in_qs_b) {
        return Err(TPM_RC_ECC_POINT + RC_IN_QS_B);
    }
    if !point_is_on_curve(curve_id, &request.in_qe_b) {
        return Err(TPM_RC_ECC_POINT + RC_IN_QE_B);
    }

    let mut commit = CommitState::load(runtime)?;
    self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
    let r = commit_value(&commit, curve_id, &[], Some(request.counter))
        .ok_or(TPM_RC_VALUE + RC_COUNTER)?;

    if scheme != TPM_ALG_SM2 {
        self_test_algorithm(runtime, TPM_ALG_ECDH)?;
    }
    let private = ecc_private_scalar(&key).unwrap_or_default();
    let result = two_phase_key_exchange(
        curve_id,
        scheme,
        private,
        &r,
        &request.in_qs_b,
        &request.in_qe_b,
    )
    .map_err(|code| {
        if code == TPM_RC_SCHEME {
            TPM_RC_SCHEME + RC_IN_SCHEME
        } else {
            code
        }
    })?;
    if result.outcome == TwoPhaseOutcome::DivideByZero {
        enter_failure_mode(runtime, FailureLocation::MathDivideZero);
        return Err(TPM_RC_FAILURE);
    }
    commit.end_commit(request.counter);
    commit.publish(runtime)?;
    point_output(&[&result.z1, &result.z2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        AuthRole, CommandLifecycle, HandleKind, NvAccess, TPM_CC_ECDH_KEY_GEN, TPM_CC_ECDH_ZGEN,
        TPM_CC_ZGEN_2_PHASE, find,
    };
    use crate::library::tpm2::command::core::test_support::{dispatch_bytes, response_parameters};
    use crate::library::tpm2::command::crypto::ecc::key::test_support::{
        ATTR_DECRYPT, ATTR_SIGN, CC_EC_EPHEMERAL, CC_ECDH_KEYGEN, CC_ECDH_ZGEN, CC_ZGEN_2PHASE,
        CURVE_P256, H0, KDF_NULL, KEY_AUTH, KEYED_AUTH, PRIVATE_SCALAR, SCHEME_ECDH, SCHEME_ECMQV,
        SCHEME_NULL, cmd, ecc_private, ecc_public, expect, framed, generator_multiple,
        keyed_object, load_external, off_curve_point, point2b, public_point, pw, raw_point2b,
        ready_with, restored,
    };
    use crate::library::tpm2::ecc::point_is_on_curve;
    use crate::library::tpm2::golden_responses::ecc_commands::vector;

    const TPM_RH_OWNER: u32 = 0x4000_0001;

    fn decrypt_key(auth: &[u8]) -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, auth),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn scheme_key(scheme: &[u8]) -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_DECRYPT,
                scheme,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn sign_key() -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_SIGN,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn zgen(auth: &[u8], point: &[u8]) -> Vec<u8> {
        cmd(CC_ECDH_ZGEN, &[H0], Some(&pw(auth)), point)
    }

    fn two_phase(auth: &[u8], qs_b: &[u8], qe_b: &[u8], scheme: u16, counter: u16) -> Vec<u8> {
        let mut parameters = qs_b.to_vec();
        parameters.extend_from_slice(qe_b);
        parameters.extend_from_slice(&scheme.to_be_bytes());
        parameters.extend_from_slice(&counter.to_be_bytes());
        cmd(CC_ZGEN_2PHASE, &[H0], Some(&pw(auth)), &parameters)
    }

    #[test]
    fn the_commands_are_registered_with_the_upstream_attributes() {
        let zgen = find(TPM_CC_ECDH_ZGEN).expect("TPM2_ECDH_ZGen is registered");
        assert_eq!(zgen.attributes, 0x0200_0154);
        assert_eq!((zgen.decrypt_size, zgen.encrypt_size), (2, 2));
        assert_eq!(zgen.handles.len(), 1);
        assert!(zgen.handles[0].user_auth);
        assert!(matches!(zgen.handles[0].kind, HandleKind::Object));
        assert!(zgen.handles[0].role == AuthRole::User);
        assert!(matches!(zgen.lifecycle, CommandLifecycle::RequiresStarted));
        assert!(matches!(zgen.nv_access, NvAccess::Neither));

        let key_gen = find(TPM_CC_ECDH_KEY_GEN).expect("TPM2_ECDH_KeyGen is registered");
        assert_eq!(key_gen.attributes, 0x0200_0163);
        assert_eq!((key_gen.decrypt_size, key_gen.encrypt_size), (0, 2));
        assert_eq!(key_gen.handles.len(), 1);
        assert!(
            !key_gen.handles[0].user_auth,
            "the reference does not set HANDLE_1_USER"
        );

        let two_phase = find(TPM_CC_ZGEN_2_PHASE).expect("TPM2_ZGen_2Phase is registered");
        assert_eq!(two_phase.attributes, 0x0200_018d);
        assert_eq!((two_phase.decrypt_size, two_phase.encrypt_size), (2, 2));
        assert!(two_phase.handles[0].user_auth);
    }

    #[test]
    fn the_agreement_matches_the_reference_for_every_peer_point() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        for (record, scalar) in [("ZGEN_G2", 2u64), ("ZGEN_G3", 3), ("ZGEN_G5", 5)] {
            let peer = generator_multiple(scalar);
            let response = expect(&mut runtime, record, &zgen(KEY_AUTH, &point2b(&peer)));
            let parameters = response_parameters(&response);
            let expected =
                point_multiply(CURVE_P256, Some(&peer), &PRIVATE_SCALAR).expect("the shared point");
            assert_eq!(parameters, point2b(&expected), "{record} is [d]peer");
            assert!(point_is_on_curve(CURVE_P256, &expected));
        }
    }

    #[test]
    fn the_agreement_is_symmetric_in_the_two_private_scalars() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let peer = generator_multiple(3);
        let response = expect(&mut runtime, "ZGEN_G3", &zgen(KEY_AUTH, &point2b(&peer)));
        let curve = crate::library::tpm2::crypto::curve_parameters(CURVE_P256).expect("P256");
        let peer_scalar = crate::library::tpm2::crypto::BigUint::from_u64(3)
            .to_be_bytes(curve.order.byte_len())
            .expect("a scalar");
        let mirrored = point_multiply(CURVE_P256, Some(&public_point()), &peer_scalar)
            .expect("the mirrored point");
        assert_eq!(response_parameters(&response), point2b(&mirrored));
    }

    fn plus_prime(coordinate: &[u8]) -> Vec<u8> {
        let curve = crate::library::tpm2::crypto::curve_parameters(CURVE_P256).expect("P256");
        crate::library::tpm2::crypto::BigUint::from_be_bytes(coordinate)
            .add(&curve.prime)
            .to_be_bytes(33)
            .expect("a 33-byte alias")
    }

    #[test]
    fn an_out_of_field_peer_point_answers_the_canonical_agreement() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let peer = generator_multiple(2);
        let canonical = expect(&mut runtime, "ZGEN_G2", &zgen(KEY_AUTH, &point2b(&peer)));

        let aliased_x = raw_point2b(&plus_prime(&peer.x), &peer.y);
        let aliased_y = raw_point2b(&peer.x, &plus_prime(&peer.y));
        for (record, packet) in [
            ("ZGEN_X_PLUS_PRIME", zgen(KEY_AUTH, &aliased_x)),
            ("ZGEN_Y_PLUS_PRIME", zgen(KEY_AUTH, &aliased_y)),
        ] {
            let response = expect(&mut runtime, record, &packet);
            assert_eq!(
                response_parameters(&response),
                response_parameters(&canonical),
                "{record} reduces to the canonical point"
            );
        }

        let curve = crate::library::tpm2::crypto::curve_parameters(CURVE_P256).expect("P256");
        let prime = curve.prime.to_be_bytes(32).expect("the prime");
        expect(
            &mut runtime,
            "ZGEN_X_IS_PRIME",
            &zgen(KEY_AUTH, &raw_point2b(&prime, &peer.y)),
        );
    }

    #[test]
    fn an_out_of_field_two_phase_point_passes_the_curve_check() {
        let mut runtime = restored("ZGEN2_AFTER");
        let qs_b = generator_multiple(2);
        let qe_b = generator_multiple(3);
        expect(
            &mut runtime,
            "ZGEN2_QSB_PLUS_PRIME",
            &two_phase(
                &[],
                &raw_point2b(&plus_prime(&qs_b.x), &qs_b.y),
                &point2b(&qe_b),
                0x0019,
                1,
            ),
        );
        expect(
            &mut runtime,
            "ZGEN2_QEB_PLUS_PRIME",
            &two_phase(
                &[],
                &point2b(&qs_b),
                &raw_point2b(&plus_prime(&qe_b.x), &qe_b.y),
                0x0019,
                1,
            ),
        );
    }

    #[test]
    fn the_authorization_failures_match_the_reference() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let peer = point2b(&generator_multiple(2));
        expect(&mut runtime, "ZGEN_BAD_AUTH", &zgen(b"bad", &peer));
        expect(
            &mut runtime,
            "ZGEN_NO_SESSION",
            &cmd(CC_ECDH_ZGEN, &[H0], None, &peer),
        );
    }

    #[test]
    fn the_point_failures_match_the_reference() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let peer = point2b(&generator_multiple(2));
        expect(
            &mut runtime,
            "ZGEN_OFF_CURVE",
            &zgen(KEY_AUTH, &point2b(&off_curve_point())),
        );
        expect(
            &mut runtime,
            "ZGEN_EMPTY_POINT",
            &zgen(KEY_AUTH, &[0x00, 0x00]),
        );
        expect(
            &mut runtime,
            "ZGEN_EMPTY_COORDS",
            &zgen(KEY_AUTH, &raw_point2b(&[], &[])),
        );
        expect(
            &mut runtime,
            "ZGEN_OVERSIZE_COORD",
            &zgen(
                KEY_AUTH,
                &raw_point2b(&[0x01; 81], &generator_multiple(2).y),
            ),
        );
        expect(
            &mut runtime,
            "ZGEN_TRUNCATED_POINT",
            &zgen(KEY_AUTH, &peer[..peer.len() - 1]),
        );
        let mut trailing = peer.clone();
        trailing.push(0x00);
        expect(&mut runtime, "ZGEN_TRAILING", &zgen(KEY_AUTH, &trailing));
        expect(&mut runtime, "ZGEN_MISSING_POINT", &zgen(KEY_AUTH, &[]));
    }

    #[test]
    fn the_handle_failures_match_the_reference() {
        let mut runtime = ready_with(&[decrypt_key(KEY_AUTH)]);
        let peer = point2b(&generator_multiple(2));
        expect(
            &mut runtime,
            "ZGEN_TRUNCATED_HANDLE",
            &framed(0x8001, CC_ECDH_ZGEN, &[0x80, 0x00, 0x00]),
        );
        expect(
            &mut runtime,
            "ZGEN_UNLOADED",
            &cmd(CC_ECDH_ZGEN, &[0x8000_0002], Some(&pw(KEY_AUTH)), &peer),
        );
        expect(
            &mut runtime,
            "ZGEN_HIERARCHY_HANDLE",
            &cmd(CC_ECDH_ZGEN, &[TPM_RH_OWNER], Some(&pw(KEY_AUTH)), &peer),
        );
    }

    #[test]
    fn the_key_checks_match_the_reference() {
        let peer = point2b(&generator_multiple(2));
        let mut runtime = ready_with(&[sign_key()]);
        expect(&mut runtime, "ZGEN_NO_DECRYPT", &zgen(&[], &peer));

        let mut runtime = ready_with(&[scheme_key(&SCHEME_ECMQV)]);
        expect(&mut runtime, "ZGEN_WRONG_SCHEME", &zgen(&[], &peer));

        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        expect(&mut runtime, "ZGEN_WRONG_TYPE", &zgen(KEYED_AUTH, &peer));
    }

    #[test]
    fn an_ecdh_scheme_key_is_accepted_by_the_two_phase_command() {
        let mut runtime = ready_with(&[scheme_key(&SCHEME_ECDH)]);
        expect(
            &mut runtime,
            "ZGEN2_EPHEMERAL",
            &cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
        );
        let qs_b = point2b(&generator_multiple(2));
        let qe_b = point2b(&generator_multiple(3));
        expect(
            &mut runtime,
            "ZGEN2_ECDH",
            &two_phase(&[], &qs_b, &qe_b, 0x0019, 0),
        );
        expect(
            &mut runtime,
            "ZGEN2_REUSE",
            &two_phase(&[], &qs_b, &qe_b, 0x0019, 0),
        );
        expect(
            &mut runtime,
            "ZGEN2_UNKNOWN_COUNTER",
            &two_phase(&[], &qs_b, &qe_b, 0x0019, 0x1234),
        );
    }

    #[test]
    fn the_two_phase_validation_matches_the_reference() {
        let mut runtime = restored("ZGEN2_AFTER");
        let qs_b = point2b(&generator_multiple(2));
        let qe_b = point2b(&generator_multiple(3));
        let off = point2b(&off_curve_point());
        expect(
            &mut runtime,
            "ZGEN2_BAD_QSB",
            &two_phase(&[], &off, &qe_b, 0x0019, 1),
        );
        expect(
            &mut runtime,
            "ZGEN2_BAD_QEB",
            &two_phase(&[], &qs_b, &off, 0x0019, 1),
        );
        expect(
            &mut runtime,
            "ZGEN2_SCHEME_MISMATCH",
            &two_phase(&[], &qs_b, &qe_b, 0x001b, 1),
        );
        expect(
            &mut runtime,
            "ZGEN2_NULL_SCHEME",
            &two_phase(&[], &qs_b, &qe_b, 0x0010, 1),
        );
        expect(
            &mut runtime,
            "ZGEN2_BAD_SCHEME",
            &two_phase(&[], &qs_b, &qe_b, 0x0018, 1),
        );
        let mut parameters = qs_b.clone();
        parameters.extend_from_slice(&qe_b);
        parameters.extend_from_slice(&0x0019u16.to_be_bytes());
        parameters.extend_from_slice(&1u16.to_be_bytes());
        parameters.push(0x00);
        expect(
            &mut runtime,
            "ZGEN2_TRAILING",
            &cmd(CC_ZGEN_2PHASE, &[H0], Some(&pw(&[])), &parameters),
        );
        parameters.truncate(qs_b.len() + qe_b.len() + 2);
        expect(
            &mut runtime,
            "ZGEN2_TRUNCATED",
            &cmd(CC_ZGEN_2PHASE, &[H0], Some(&pw(&[])), &parameters),
        );
        parameters.extend_from_slice(&1u16.to_be_bytes());
        expect(
            &mut runtime,
            "ZGEN2_NO_SESSION",
            &cmd(CC_ZGEN_2PHASE, &[H0], None, &parameters),
        );
    }

    #[test]
    fn the_sm2_exchange_returns_one_point_and_an_empty_second_point() {
        let mut runtime = ready_with(&[
            decrypt_key(&[]),
            cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
        ]);
        let response = expect(
            &mut runtime,
            "ZGEN2_SM2",
            &two_phase(
                &[],
                &point2b(&generator_multiple(2)),
                &point2b(&generator_multiple(3)),
                0x001b,
                0,
            ),
        );
        let parameters = response_parameters(&response);
        assert_eq!(
            &parameters[parameters.len() - 6..],
            [0x00, 0x04, 0x00, 0x00, 0x00, 0x00],
            "the SM2 exchange leaves outZ2 empty"
        );
    }

    #[test]
    fn a_two_phase_attribute_failure_matches_the_reference() {
        let mut runtime = ready_with(&[
            sign_key(),
            cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
        ]);
        expect(
            &mut runtime,
            "ZGEN2_ATTRIBUTES",
            &two_phase(
                &[],
                &point2b(&generator_multiple(2)),
                &point2b(&generator_multiple(3)),
                0x0019,
                0,
            ),
        );
    }

    #[test]
    fn the_ephemeral_key_pair_matches_the_reference() {
        let mut runtime = ready_with(&[decrypt_key(&[])]);
        for record in ["KEYGEN_FIRST", "KEYGEN_SECOND"] {
            let response = expect(&mut runtime, record, &cmd(CC_ECDH_KEYGEN, &[H0], None, &[]));
            let parameters = response_parameters(&response);
            assert_eq!(parameters.len(), 2 * (2 + 68), "two points");
            let z = &parameters[4..4 + 32];
            let public = &parameters[70 + 4..70 + 4 + 32];
            assert_ne!(z, public, "the shared point differs from the public point");
        }
    }

    #[test]
    fn the_key_generation_failures_match_the_reference() {
        let mut runtime = ready_with(&[decrypt_key(&[])]);
        expect(
            &mut runtime,
            "KEYGEN_TRAILING",
            &cmd(CC_ECDH_KEYGEN, &[H0], None, &[0x00]),
        );
        expect(
            &mut runtime,
            "KEYGEN_WITH_SESSION",
            &cmd(CC_ECDH_KEYGEN, &[H0], Some(&pw(&[])), &[]),
        );
        expect(
            &mut runtime,
            "KEYGEN_TRUNCATED_HANDLE",
            &framed(0x8001, CC_ECDH_KEYGEN, &[0x80, 0x00]),
        );
        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        expect(
            &mut runtime,
            "KEYGEN_WRONG_TYPE",
            &cmd(CC_ECDH_KEYGEN, &[H0], None, &[]),
        );
    }

    #[test]
    fn a_failed_key_generation_still_publishes_the_generator_state() {
        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        let before = runtime.live.orderly.drbg_state.seed.expose().to_vec();
        dispatch_bytes(&mut runtime, &cmd(CC_ECDH_KEYGEN, &[H0], None, &[]));
        assert_eq!(
            runtime.live.orderly.drbg_state.seed.expose(),
            &before[..],
            "a rejected key type never reaches the generator"
        );
    }

    #[test]
    fn a_failed_two_phase_exchange_leaves_the_commitment_untouched() {
        let mut runtime = restored("ZGEN2_AFTER");
        let before = CommitState::load(&runtime).expect("the commitment state loads");
        let qs_b = point2b(&generator_multiple(2));
        let qe_b = point2b(&generator_multiple(3));
        for packet in [
            two_phase(&[], &point2b(&off_curve_point()), &qe_b, 0x0019, 1),
            two_phase(&[], &qs_b, &qe_b, 0x0018, 1),
            two_phase(&[], &qs_b, &qe_b, 0x0019, 0x1234),
            two_phase(b"bad", &qs_b, &qe_b, 0x0019, 1),
        ] {
            dispatch_bytes(&mut runtime, &packet);
            let now = CommitState::load(&runtime).expect("the commitment state loads");
            assert_eq!(now.counter, before.counter);
            assert_eq!(now.array, before.array);
        }
    }

    #[test]
    fn the_ecmqv_scheme_reaches_the_vendored_divide_by_zero() {
        let mut runtime = ready_with(&[
            decrypt_key(&[]),
            cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
        ]);
        expect(
            &mut runtime,
            "ZGEN2_ECMQV",
            &two_phase(
                &[],
                &point2b(&generator_multiple(2)),
                &point2b(&generator_multiple(3)),
                0x001d,
                0,
            ),
        );
        assert!(runtime.failure_mode, "the TPM stops after the divide");
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::MathDivideZero.diagnostics()
        );
        let follow_up = cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes());
        assert_eq!(
            crate::library::tpm2::failure_mode::process(
                &mut runtime,
                &crate::library::CommandInput::new(follow_up.len() as u32, follow_up)
            )
            .expect("the failure-mode route answers"),
            vector("ZGEN2_AFTER_ECMQV"),
            "record ZGEN2_AFTER_ECMQV"
        );
    }
}
