use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE};

use super::super::algorithm::TPM_ALG_NULL;
use super::super::hierarchy::TPM_RH_NULL;
use super::super::object::ATTR_PUBLIC_ONLY;
use super::super::object_create::{object_hierarchy, resolve_any_object};
use super::super::persistent::OwnedAnyObjectBody;
use super::super::profile::ValidatedProfile;
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::self_test_algorithm;
use super::super::signature::{Signature, Verification, parse_signature, validate_signature};
use super::super::template::{TPMA_OBJECT_SIGN, TemplateReader};
use super::super::ticket::{CONTEXT_INTEGRITY_HASH_ALG, TPM_ST_VERIFIED, Ticket, compute_verified};
use super::create_primary::add_modifier;
use super::dispatcher::CommandFrame;
use super::nv_common::{TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P, handle_at};
use super::output::CommandOutput;
use super::signing::hierarchy_proof_for;

const RC_KEY_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_DIGEST: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_SIGNATURE: TpmResult = TPM_RC_P + TPM_RC_2;

const DIGEST_TPM2B_MAX: usize = 64;

struct Parameters {
    digest: Vec<u8>,
    signature: Signature,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let profile = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile;
    let parameters = parse_parameters(frame.parameters, profile)?;

    let object = resolve_any_object(runtime, key_handle).ok_or(TPM_RC_FAILURE)?;
    let attributes = match &object.body {
        OwnedAnyObjectBody::Object(body) => body.public.object_attributes,
        OwnedAnyObjectBody::Sequence(body) => body.object_attributes,
        OwnedAnyObjectBody::Unoccupied => return Err(TPM_RC_FAILURE),
    };
    if attributes & TPMA_OBJECT_SIGN == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(add_modifier(TPM_RC_SCHEME, RC_SIGNATURE));
    };
    let public_only = object.attributes & ATTR_PUBLIC_ONLY != 0;
    let hierarchy = object_hierarchy(object.attributes, body);
    let name_alg = body.public.name_alg;
    let key_name = body.name.clone();

    let verification = validate_signature(
        body,
        public_only,
        &parameters.digest,
        &parameters.signature,
        profile,
    )
    .map_err(|code| add_modifier(code, RC_SIGNATURE))?;

    if let Verification::Hmac(hmac) = verification {
        self_test_algorithm(runtime, hmac.hash_alg())?;
        hmac.finish(&parameters.digest)
            .map_err(|code| add_modifier(code, RC_SIGNATURE))?;
    }

    let ticket = if hierarchy == TPM_RH_NULL || name_alg == TPM_ALG_NULL {
        Ticket::empty(TPM_ST_VERIFIED)
    } else {
        self_test_algorithm(runtime, CONTEXT_INTEGRITY_HASH_ALG)?;
        let proof = hierarchy_proof_for(runtime, hierarchy)?;
        compute_verified(hierarchy, proof, &parameters.digest, &key_name).ok_or(TPM_RC_FAILURE)?
    };
    Ok(CommandOutput::from_parameters(
        ticket.into_bytes().map_err(|_| TPM_RC_SIZE)?,
    ))
}

fn parse_parameters(
    parameters: &[u8],
    profile: &ValidatedProfile,
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let digest = reader
        .tpm2b(DIGEST_TPM2B_MAX)
        .map_err(|code| code + RC_DIGEST)?
        .to_vec();
    let signature = parse_signature(&mut reader, profile).map_err(|code| code + RC_SIGNATURE)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters { digest, signature })
}

#[cfg(test)]
mod tests {
    use super::super::nv_common::harness::*;
    use super::super::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_VERIFY_SIGNATURE, find,
    };
    use super::*;
    use crate::library::tpm2::crypto::Hasher;
    use crate::library::tpm2::golden_responses::read_public_verify_signature::vector;
    use crate::library::tpm2::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM};
    use crate::library::tpm2::object::ATTR_PUBLIC_ONLY;
    use crate::library::tpm2::persistent::OwnedAnyObject;
    use crate::library::tpm2::public::PublicParms;
    use crate::library::tpm2::self_test::{PrimitiveTest, SelfTestFailure};
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};
    use std::cell::RefCell;

    const TPM_CC: u32 = 0x0000_0177;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;
    const TPM_ALG_HMAC: u16 = 0x0005;
    const TPM_ALG_RSASSA: u16 = 0x0014;
    const TPM_ALG_RSAPSS: u16 = 0x0016;
    const TPM_ALG_ECDSA: u16 = 0x0018;
    const TPM_ALG_ECDAA: u16 = 0x001a;
    const TPM_ALG_ECSCHNORR: u16 = 0x001c;
    const TPM_ALG_NULL_ID: u16 = 0x0010;

    const RC_SIZE: u32 = 0x095;
    const RC_HANDLE1_ATTRIBUTES: u32 = 0x182;
    const RC_PARAM2_SCHEME: u32 = 0x2d2;
    const RC_PARAM2_SIGNATURE: u32 = 0x2db;
    const RC_PARAM2_HASH: u32 = 0x2c3;

    #[track_caller]
    fn restored(snapshot: &str) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector(&format!("PERMALL_{snapshot}")))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector(&format!("VOLATILE_{snapshot}")))
            .expect("the oracle volatile state attaches");
        assert!(
            runtime.startup_received,
            "the snapshot is past TPM2_Startup"
        );
        runtime
    }

    fn digest_of(hash_alg: u16, data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
        hasher.update(data);
        hasher.finalize()
    }

    fn abc(hash_alg: u16) -> Vec<u8> {
        digest_of(hash_alg, b"abc")
    }

    fn xyz() -> Vec<u8> {
        digest_of(TPM_ALG_SHA256, b"xyz")
    }

    /// The signature bytes the reference TPM2_Sign produced for the same key.
    fn oracle_signature(record: &str) -> Vec<u8> {
        let response = vector(record);
        assert_eq!(&response[6..10], [0, 0, 0, 0], "{record} succeeded");
        let size = u32::from_be_bytes(response[10..14].try_into().expect("a parameter size"));
        response[14..14 + size as usize].to_vec()
    }

    fn flip_last(mut signature: Vec<u8>) -> Vec<u8> {
        let last = signature.len() - 1;
        signature[last] ^= 0x01;
        signature
    }

    fn relabel(mut signature: Vec<u8>, scheme: u16) -> Vec<u8> {
        signature[..2].copy_from_slice(&scheme.to_be_bytes());
        signature
    }

    fn t2b(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn rsa_signature(scheme: u16, hash_alg: u16, signature: &[u8]) -> Vec<u8> {
        let mut out = scheme.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out.extend_from_slice(&t2b(signature));
        out
    }

    fn ecc_signature(scheme: u16, hash_alg: u16, r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut out = scheme.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out.extend_from_slice(&t2b(r));
        out.extend_from_slice(&t2b(s));
        out
    }

    fn hmac_signature(hash_alg: u16, digest: &[u8]) -> Vec<u8> {
        let mut out = TPM_ALG_HMAC.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out.extend_from_slice(digest);
        out
    }

    fn bogus_rsa_signature() -> Vec<u8> {
        rsa_signature(TPM_ALG_RSASSA, TPM_ALG_SHA256, &[0x00; 256])
    }

    fn parameters(digest: &[u8], signature: &[u8]) -> Vec<u8> {
        let mut out = t2b(digest);
        out.extend_from_slice(signature);
        out
    }

    #[track_caller]
    fn verify(runtime: &mut Tpm2Runtime, handle: u32, digest: &[u8], signature: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(TPM_CC, &[handle], &[], &parameters(digest, signature)),
        )
    }

    #[track_caller]
    fn assert_matches_oracle(
        snapshot: &str,
        record: &str,
        handle: u32,
        digest: &[u8],
        signature: &[u8],
    ) {
        let mut runtime = restored(snapshot);
        assert_eq!(
            verify(&mut runtime, handle, digest, signature),
            vector(record),
            "{record} from {snapshot}"
        );
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0177");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        assert_eq!(TPM_CC_VERIFY_SIGNATURE, TPM_CC);
        let descriptor = find(TPM_CC_VERIFY_SIGNATURE).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0200_0177);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "TPM2_VerifySignature does not use NV"
        );
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn the_key_handle_needs_no_authorization() {
        let descriptor = find(TPM_CC_VERIFY_SIGNATURE).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(
            !descriptor.handles[0].user_auth,
            "upstream declares no HANDLE_1_USER for TPM2_VerifySignature"
        );
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn signatures_produced_by_tpm2_sign_verify_against_their_own_key() {
        for (snapshot, record, source, handle, hash_alg) in [
            (
                "KEYS",
                "VERIFYSIG_RSASSA_OK",
                "SIGN_RSASSA",
                0x8000_0000,
                TPM_ALG_SHA256,
            ),
            (
                "KEYS",
                "VERIFYSIG_ECDSA_OK",
                "SIGN_ECDSA",
                0x8000_0001,
                TPM_ALG_SHA256,
            ),
            (
                "ALT_KEYS",
                "VERIFYSIG_ECSCHNORR_OK",
                "SIGN_ECSCHNORR",
                0x8000_0000,
                TPM_ALG_SHA256,
            ),
            (
                "ALT_KEYS",
                "VERIFYSIG_ECDSA_NULL_SCHEME_OK",
                "SIGN_ECDSA_NULL_SCHEME",
                0x8000_0001,
                TPM_ALG_SHA256,
            ),
            (
                "ALT_KEYS",
                "VERIFYSIG_RSAPSS_OK",
                "SIGN_RSAPSS",
                0x8000_0002,
                TPM_ALG_SHA256,
            ),
            (
                "HMAC_KEYS",
                "VERIFYSIG_HMAC_SHA256_OK",
                "SIGN_HMAC_SHA256",
                0x8000_0000,
                TPM_ALG_SHA256,
            ),
            (
                "HMAC_KEYS",
                "VERIFYSIG_HMAC_SHA1_OK",
                "SIGN_HMAC_SHA1",
                0x8000_0001,
                TPM_ALG_SHA1,
            ),
            (
                "HMAC_KEYS",
                "VERIFYSIG_HMAC_SHA384_OK",
                "SIGN_HMAC_SHA384",
                0x8000_0002,
                TPM_ALG_SHA384,
            ),
            (
                "HMAC_SHA512",
                "VERIFYSIG_HMAC_SHA512_OK",
                "SIGN_HMAC_SHA512",
                0x8000_0000,
                TPM_ALG_SHA512,
            ),
            (
                "MISC_KEYS",
                "VERIFYSIG_POLICY_OK",
                "SIGN_POLICY_SHA384",
                0x8000_0002,
                TPM_ALG_SHA384,
            ),
            (
                "NO_SHA1_VERIFY",
                "VERIFYSIG_NO_SHA1_VERIFY_RSA",
                "SIGN_NO_SHA1_VERIFY_RSA",
                0x8000_0000,
                TPM_ALG_SHA1,
            ),
        ] {
            let signature = oracle_signature(source);
            assert_matches_oracle(snapshot, record, handle, &abc(hash_alg), &signature);
            assert_eq!(
                response_code(vector(record)),
                RC_SUCCESS,
                "{record} succeeds"
            );
        }
    }

    #[test]
    fn a_verified_ticket_is_deterministic() {
        let signature = oracle_signature("SIGN_RSASSA");
        let mut runtime = restored("KEYS");
        let first = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);
        let second = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);
        assert_eq!(first, second);
        assert_eq!(first, vector("VERIFYSIG_RSASSA_OK"));
        assert_eq!(second, vector("VERIFYSIG_RSASSA_OK_AGAIN"));
    }

    #[test]
    fn every_hierarchy_proof_produces_its_own_ticket() {
        for (record, source, handle) in [
            ("VERIFYSIG_ENDORSEMENT_OK", "SIGN_ENDORSEMENT", 0x8000_0000),
            ("VERIFYSIG_PLATFORM_OK", "SIGN_PLATFORM", 0x8000_0001),
        ] {
            let signature = oracle_signature(source);
            assert_matches_oracle(
                "HIERARCHY_KEYS",
                record,
                handle,
                &abc(TPM_ALG_SHA256),
                &signature,
            );
        }
        let owner = ticket_of("VERIFYSIG_RSASSA_OK");
        let endorsement = ticket_of("VERIFYSIG_ENDORSEMENT_OK");
        let platform = ticket_of("VERIFYSIG_PLATFORM_OK");
        assert_eq!(&owner[..6], &ticket_header(TPM_RH_OWNER)[..]);
        assert_eq!(&endorsement[..6], &ticket_header(TPM_RH_ENDORSEMENT)[..]);
        assert_eq!(&platform[..6], &ticket_header(TPM_RH_PLATFORM)[..]);
        assert_ne!(owner[6..], endorsement[6..], "different hierarchy proofs");
        assert_ne!(endorsement[6..], platform[6..]);
    }

    fn ticket_header(hierarchy: u32) -> Vec<u8> {
        let mut out = TPM_ST_VERIFIED.to_be_bytes().to_vec();
        out.extend_from_slice(&hierarchy.to_be_bytes());
        out
    }

    fn ticket_of(record: &str) -> Vec<u8> {
        vector(record)[10..].to_vec()
    }

    #[test]
    fn a_key_below_the_runtime_minimum_size_is_rejected() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = restored("HMAC_KEYS");
        runtime
            .state
            .as_mut()
            .expect("restored state")
            .profile
            .algorithms
            .extend_from_slice(b",hmac-min-size=4096");
        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);
        assert_eq!(
            response_code(&response),
            0x2c7,
            "TPM_RC_KEY_SIZE decorated against parameter two"
        );
    }

    #[test]
    fn the_key_size_policy_is_checked_before_the_signature_scheme() {
        let mut runtime = restored("HMAC_KEYS");
        runtime
            .state
            .as_mut()
            .expect("restored state")
            .profile
            .algorithms
            .extend_from_slice(b",hmac-min-size=4096");
        let response = verify(
            &mut runtime,
            0x8000_0000,
            &abc(TPM_ALG_SHA256),
            &bogus_rsa_signature(),
        );
        assert_eq!(
            response_code(&response),
            0x2c7,
            "upstream runs the key-size check ahead of the sigAlg check"
        );
    }

    #[test]
    fn an_uncompiled_curve_is_a_value_error() {
        let ecdsa = oracle_signature("SIGN_ECDSA");
        let mut runtime = restored("KEYS");
        let slot = runtime.live.objects.get_mut(1).expect("a loaded key");
        let OwnedAnyObjectBody::Object(body) = &mut slot.body else {
            panic!("a key object");
        };
        let PublicParms::Ecc { curve_id, .. } = &mut body.public.parameters else {
            panic!("an ECC key");
        };
        *curve_id = 0xffff;
        let response = verify(&mut runtime, 0x8000_0001, &abc(TPM_ALG_SHA256), &ecdsa);
        assert_eq!(
            response_code(&response),
            0x2c4,
            "TPM_RC_VALUE decorated against parameter two"
        );
    }

    #[test]
    fn a_null_hierarchy_key_produces_the_empty_verified_ticket() {
        let signature = oracle_signature("SIGN_NULL_HIERARCHY");
        assert_matches_oracle(
            "HIERARCHY_KEYS",
            "VERIFYSIG_NULL_HIERARCHY_OK",
            0x8000_0002,
            &abc(TPM_ALG_SHA256),
            &signature,
        );
        assert_eq!(
            ticket_of("VERIFYSIG_NULL_HIERARCHY_OK"),
            [0x80, 0x22, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00],
            "TPM_ST_VERIFIED, TPM_RH_NULL and an empty digest"
        );
    }

    #[test]
    fn a_null_name_algorithm_produces_the_empty_verified_ticket() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = restored("HMAC_KEYS");
        let slot = runtime.live.objects.get_mut(0).expect("a loaded key");
        let OwnedAnyObjectBody::Object(body) = &mut slot.body else {
            panic!("a key object");
        };
        body.public.name_alg = TPM_ALG_NULL;
        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            response[10..],
            [0x80, 0x22, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00],
            "a nameAlg of TPM_ALG_NULL forces the empty ticket"
        );
    }

    #[test]
    fn the_ticket_follows_the_digest_and_the_key_name() {
        let signature = oracle_signature("SIGN_PERSISTENT");
        assert_matches_oracle(
            "PERSISTENT",
            "VERIFYSIG_PERSISTENT_OK",
            0x8100_0001,
            &abc(TPM_ALG_SHA256),
            &signature,
        );
        assert_eq!(
            vector("VERIFYSIG_PERSISTENT_OK"),
            vector("VERIFYSIG_PERSISTENT_TRANSIENT_SIG"),
            "the persisted key keeps its Name, so the ticket is unchanged"
        );
        assert_eq!(
            vector("VERIFYSIG_PERSISTENT_OK"),
            vector("VERIFYSIG_RSASSA_OK"),
            "the transient and persistent copies share one Name and hierarchy"
        );
        assert_ne!(
            ticket_of("VERIFYSIG_RSASSA_OK"),
            ticket_of("VERIFYSIG_POLICY_OK"),
            "a different key Name gives a different ticket"
        );
    }

    #[test]
    fn a_persistent_key_verifies_a_transient_signature() {
        let signature = oracle_signature("SIGN_RSASSA");
        assert_matches_oracle(
            "PERSISTENT",
            "VERIFYSIG_PERSISTENT_TRANSIENT_SIG",
            0x8100_0001,
            &abc(TPM_ALG_SHA256),
            &signature,
        );
    }

    #[test]
    fn a_wrong_digest_an_altered_signature_and_a_foreign_key_are_all_rejected() {
        let rsassa = oracle_signature("SIGN_RSASSA");
        let ecdsa = oracle_signature("SIGN_ECDSA");
        for (record, handle, digest, signature) in [
            (
                "VERIFYSIG_RSASSA_WRONG_DIGEST",
                0x8000_0000u32,
                xyz(),
                rsassa.clone(),
            ),
            (
                "VERIFYSIG_RSASSA_ALTERED",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                flip_last(rsassa.clone()),
            ),
            (
                "VERIFYSIG_RSASSA_AS_RSAPSS",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                relabel(rsassa.clone(), TPM_ALG_RSAPSS),
            ),
            (
                "VERIFYSIG_RSASSA_ON_ECC_KEY",
                0x8000_0001,
                abc(TPM_ALG_SHA256),
                rsassa.clone(),
            ),
            (
                "VERIFYSIG_ECDSA_WRONG_DIGEST",
                0x8000_0001,
                xyz(),
                ecdsa.clone(),
            ),
            (
                "VERIFYSIG_ECDSA_ALTERED",
                0x8000_0001,
                abc(TPM_ALG_SHA256),
                flip_last(ecdsa.clone()),
            ),
            (
                "VERIFYSIG_ECDSA_AS_ECSCHNORR",
                0x8000_0001,
                abc(TPM_ALG_SHA256),
                relabel(ecdsa.clone(), TPM_ALG_ECSCHNORR),
            ),
            (
                "VERIFYSIG_ECDSA_ON_RSA_KEY",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                ecdsa.clone(),
            ),
        ] {
            assert_matches_oracle("KEYS", record, handle, &digest, &signature);
        }
    }

    #[test]
    fn the_other_asymmetric_schemes_reject_altered_signatures() {
        let ecschnorr = oracle_signature("SIGN_ECSCHNORR");
        let rsapss = oracle_signature("SIGN_RSAPSS");
        for (record, handle, digest, signature) in [
            (
                "VERIFYSIG_ECSCHNORR_ALTERED",
                0x8000_0000u32,
                abc(TPM_ALG_SHA256),
                flip_last(ecschnorr),
            ),
            (
                "VERIFYSIG_RSAPSS_WRONG_DIGEST",
                0x8000_0002,
                xyz(),
                rsapss.clone(),
            ),
            (
                "VERIFYSIG_RSAPSS_ALTERED",
                0x8000_0002,
                abc(TPM_ALG_SHA256),
                flip_last(rsapss.clone()),
            ),
            (
                "VERIFYSIG_RSAPSS_AS_RSASSA",
                0x8000_0002,
                abc(TPM_ALG_SHA256),
                relabel(rsapss, TPM_ALG_RSASSA),
            ),
        ] {
            assert_matches_oracle("ALT_KEYS", record, handle, &digest, &signature);
        }
    }

    #[test]
    fn a_signature_from_a_different_key_of_the_same_type_is_rejected() {
        let signature = oracle_signature("SIGN_ENDORSEMENT");
        assert_matches_oracle(
            "HIERARCHY_KEYS",
            "VERIFYSIG_ENDORSEMENT_OTHER_KEY",
            0x8000_0001,
            &abc(TPM_ALG_SHA256),
            &signature,
        );
        assert_eq!(
            response_code(vector("VERIFYSIG_ENDORSEMENT_OTHER_KEY")),
            RC_PARAM2_SIGNATURE
        );
    }

    #[test]
    fn keyed_hash_rejections_match_the_oracle() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        for (record, handle, digest, signature) in [
            (
                "VERIFYSIG_HMAC_SHA256_WRONG_DIGEST",
                0x8000_0000u32,
                xyz(),
                signature.clone(),
            ),
            (
                "VERIFYSIG_HMAC_SHA256_ALTERED",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                flip_last(signature.clone()),
            ),
            (
                "VERIFYSIG_HMAC_SHA256_OTHER_KEY",
                0x8000_0001,
                abc(TPM_ALG_SHA256),
                signature.clone(),
            ),
            (
                "VERIFYSIG_HMAC_SCHEME_MISMATCH",
                0x8000_0000,
                abc(TPM_ALG_SHA384),
                hmac_signature(TPM_ALG_SHA384, &abc(TPM_ALG_SHA384)),
            ),
            (
                "VERIFYSIG_HMAC_RSA_SIG",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                bogus_rsa_signature(),
            ),
            (
                "VERIFYSIG_HMAC_BOGUS",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                hmac_signature(TPM_ALG_SHA256, &[0u8; 32]),
            ),
        ] {
            assert_matches_oracle("HMAC_KEYS", record, handle, &digest, &signature);
        }
        assert_eq!(
            response_code(vector("VERIFYSIG_HMAC_SCHEME_MISMATCH")),
            RC_PARAM2_SIGNATURE,
            "a key scheme that disagrees with the signature is a signature error"
        );
        assert_eq!(
            response_code(vector("VERIFYSIG_HMAC_RSA_SIG")),
            RC_PARAM2_SCHEME
        );
    }

    #[test]
    fn objects_without_the_sign_attribute_are_rejected_before_the_signature() {
        for (snapshot, record, handle) in [
            ("MISC_KEYS", "VERIFYSIG_STORAGE_KEY", 0x8000_0000),
            ("MISC_KEYS", "VERIFYSIG_SYMCIPHER_KEY", 0x8000_0001),
            ("SEQUENCE_OBJECT", "VERIFYSIG_SEQUENCE", 0x8000_0002),
            (
                "EVENT_SEQUENCE_OBJECT",
                "VERIFYSIG_EVENT_SEQUENCE",
                0x8000_0002,
            ),
            (
                "HMAC_SEQUENCE_OBJECT",
                "VERIFYSIG_HMAC_SEQUENCE",
                0x8000_0001,
            ),
        ] {
            let signature = if record.contains("SEQUENCE") {
                hmac_signature(TPM_ALG_SHA256, &abc(TPM_ALG_SHA256))
            } else {
                bogus_rsa_signature()
            };
            assert_matches_oracle(snapshot, record, handle, &abc(TPM_ALG_SHA256), &signature);
            assert_eq!(
                response_code(vector(record)),
                RC_HANDLE1_ATTRIBUTES,
                "{record}"
            );
        }
    }

    #[test]
    fn a_public_only_keyed_hash_key_reports_a_handle_error() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = restored("HMAC_KEYS");
        let slot = runtime.live.objects.get_mut(0).expect("a loaded key");
        slot.attributes |= ATTR_PUBLIC_ONLY;
        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);
        assert_eq!(
            response_code(&response),
            0x2cb,
            "TPM_RCS_HANDLE decorated against parameter two"
        );
    }

    #[test]
    fn a_public_only_asymmetric_key_still_verifies() {
        let signature = oracle_signature("SIGN_RSASSA");
        let mut runtime = restored("KEYS");
        let slot = runtime.live.objects.get_mut(0).expect("a loaded key");
        slot.attributes |= ATTR_PUBLIC_ONLY;
        let OwnedAnyObjectBody::Object(body) = &mut slot.body else {
            panic!("a key object");
        };
        body.sensitive.sensitive = None;
        body.private_exponent = None;
        assert_eq!(
            verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature),
            vector("VERIFYSIG_RSASSA_OK"),
            "verification only needs the public modulus and exponent"
        );
    }

    #[test]
    fn every_malformed_parameter_matches_the_oracle() {
        let long = [0u8; 0x181];
        for (record, payload) in [
            ("VERIFYSIG_EMPTY_PARAMETERS", Vec::new()),
            (
                "VERIFYSIG_OVERSIZED_DIGEST",
                0xffffu16.to_be_bytes().to_vec(),
            ),
            ("VERIFYSIG_TRUNCATED_SIGALG", {
                let mut out = t2b(&abc(TPM_ALG_SHA256));
                out.push(0x00);
                out
            }),
            (
                "VERIFYSIG_BAD_SIGALG",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &rsa_signature(0x0015, TPM_ALG_SHA256, &[0u8; 256]),
                ),
            ),
            (
                "VERIFYSIG_NULL_SIGALG",
                parameters(&abc(TPM_ALG_SHA256), &TPM_ALG_NULL_ID.to_be_bytes()),
            ),
            (
                "VERIFYSIG_BAD_HASH",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &rsa_signature(TPM_ALG_RSASSA, 0x0012, &[0u8; 256]),
                ),
            ),
            (
                "VERIFYSIG_NULL_HASH",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &rsa_signature(TPM_ALG_RSASSA, TPM_ALG_NULL_ID, &[0u8; 256]),
                ),
            ),
            ("VERIFYSIG_TRUNCATED_RSA_SIG", {
                let mut signature = TPM_ALG_RSASSA.to_be_bytes().to_vec();
                signature.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                signature.extend_from_slice(&0x0100u16.to_be_bytes());
                signature.extend_from_slice(&[0u8; 8]);
                parameters(&abc(TPM_ALG_SHA256), &signature)
            }),
            (
                "VERIFYSIG_OVERSIZED_RSA_SIG",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &rsa_signature(TPM_ALG_RSASSA, TPM_ALG_SHA256, &long),
                ),
            ),
            (
                "VERIFYSIG_SHORT_RSA_SIG",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &rsa_signature(TPM_ALG_RSASSA, TPM_ALG_SHA256, &[0u8; 128]),
                ),
            ),
            (
                "VERIFYSIG_ZERO_RSA_SIG",
                parameters(&abc(TPM_ALG_SHA256), &bogus_rsa_signature()),
            ),
            ("VERIFYSIG_TRAILING", {
                let mut out = parameters(&abc(TPM_ALG_SHA256), &bogus_rsa_signature());
                out.push(0x00);
                out
            }),
            (
                "VERIFYSIG_RSA_KEY_HMAC_SIG",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &hmac_signature(TPM_ALG_SHA256, &abc(TPM_ALG_SHA256)),
                ),
            ),
            (
                "VERIFYSIG_RSA_KEY_ECDSA_SIG",
                parameters(
                    &abc(TPM_ALG_SHA256),
                    &ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &[0x11; 32], &[0x22; 32]),
                ),
            ),
            (
                "VERIFYSIG_RSA_SHORT_DIGEST",
                parameters(&abc(TPM_ALG_SHA1), &bogus_rsa_signature()),
            ),
        ] {
            let mut runtime = restored("KEYS");
            let mut framed_payload = 0x8000_0000u32.to_be_bytes().to_vec();
            framed_payload.extend_from_slice(&payload);
            assert_eq!(
                dispatch_bytes(&mut runtime, &framed(TPM_CC, &framed_payload, false)),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(response_code(vector("VERIFYSIG_TRAILING")), RC_SIZE);
    }

    #[test]
    fn every_malformed_ecc_signature_field_matches_the_oracle() {
        let order = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let oversized = [0u8; 0x51];
        for (record, signature) in [
            (
                "VERIFYSIG_ECC_OVERSIZED_R",
                ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &oversized, &[0x22; 32]),
            ),
            ("VERIFYSIG_ECC_TRUNCATED_S", {
                let mut signature = TPM_ALG_ECDSA.to_be_bytes().to_vec();
                signature.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                signature.extend_from_slice(&t2b(&[0x11; 32]));
                signature.extend_from_slice(&0x0020u16.to_be_bytes());
                signature.extend_from_slice(&[0x22; 8]);
                signature
            }),
            (
                "VERIFYSIG_ECC_ZERO_R",
                ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &[], &[0x22; 32]),
            ),
            (
                "VERIFYSIG_ECC_ZERO_S",
                ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &[0x11; 32], &[]),
            ),
            (
                "VERIFYSIG_ECC_ORDER_R",
                ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &order, &[0x22; 32]),
            ),
            (
                "VERIFYSIG_ECC_ECDAA_SIG",
                ecc_signature(TPM_ALG_ECDAA, TPM_ALG_SHA256, &[0x11; 32], &[0x22; 32]),
            ),
            (
                "VERIFYSIG_ECC_BOGUS",
                ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &[0x11; 32], &[0x22; 32]),
            ),
        ] {
            assert_matches_oracle(
                "KEYS",
                record,
                0x8000_0001,
                &abc(TPM_ALG_SHA256),
                &signature,
            );
        }
        assert_eq!(
            response_code(vector("VERIFYSIG_ECC_ECDAA_SIG")),
            RC_PARAM2_SCHEME,
            "ECDAA has no verification path upstream"
        );
    }

    #[test]
    fn every_rejected_handle_matches_the_oracle() {
        for (record, handle) in [
            ("VERIFYSIG_EMPTY_TRANSIENT", 0x8000_0000),
            ("VERIFYSIG_UNKNOWN_TRANSIENT", 0x8000_0005),
            ("VERIFYSIG_UNKNOWN_PERSISTENT", 0x8100_0009),
            ("VERIFYSIG_SESSION_HANDLE", 0x0200_0000),
            ("VERIFYSIG_NV_HANDLE", 0x0100_0000),
            ("VERIFYSIG_PCR_HANDLE", 0x0000_0000),
            ("VERIFYSIG_PERMANENT_HANDLE", 0x4000_0001),
            ("VERIFYSIG_NULL_HANDLE", 0x4000_0007),
        ] {
            let mut runtime = restored("READY");
            assert_eq!(
                verify(
                    &mut runtime,
                    handle,
                    &abc(TPM_ALG_SHA256),
                    &bogus_rsa_signature()
                ),
                vector(record),
                "{record}"
            );
        }
        for (record, payload) in [
            ("VERIFYSIG_NO_HANDLE", &[][..]),
            ("VERIFYSIG_SHORT_HANDLE", &[0x80, 0x00, 0x00][..]),
        ] {
            let mut runtime = restored("READY");
            assert_eq!(
                dispatch_bytes(&mut runtime, &framed(TPM_CC, payload, false)),
                vector(record),
                "{record}"
            );
        }
    }

    #[test]
    fn the_runtime_profile_forbids_sha1_hmac_verification() {
        let signature = oracle_signature("SIGN_NO_SHA1_HMAC");
        assert_matches_oracle(
            "NO_SHA1_HMAC",
            "VERIFYSIG_NO_SHA1_HMAC",
            0x8000_0000,
            &abc(TPM_ALG_SHA1),
            &signature,
        );
        assert_eq!(
            response_code(vector("VERIFYSIG_NO_SHA1_HMAC")),
            RC_PARAM2_HASH,
            "RUNTIME_ATTRIBUTE_NO_SHA1_HMAC_VERIFICATION"
        );
    }

    #[test]
    fn the_runtime_profile_forbids_sha1_ecc_verification_but_not_rsa() {
        let ecc = oracle_signature("SIGN_NO_SHA1_VERIFY_ECC");
        assert_matches_oracle(
            "NO_SHA1_VERIFY",
            "VERIFYSIG_NO_SHA1_VERIFY_ECC",
            0x8000_0001,
            &abc(TPM_ALG_SHA1),
            &ecc,
        );
        assert_eq!(
            response_code(vector("VERIFYSIG_NO_SHA1_VERIFY_ECC")),
            RC_PARAM2_HASH
        );
        assert_eq!(
            response_code(vector("VERIFYSIG_NO_SHA1_VERIFY_RSA")),
            RC_SUCCESS,
            "the vendored RSA verifier carries no SHA-1 restriction"
        );
    }

    thread_local! {
        static SELF_TESTS_RUN: RefCell<Vec<PrimitiveTest>> = const { RefCell::new(Vec::new()) };
    }

    fn recording_runner(test: PrimitiveTest) -> bool {
        SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
        true
    }

    fn recording_runner_failing_sha256(test: PrimitiveTest) -> bool {
        SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
        test != PrimitiveTest::Sha256
    }

    fn recording_runner_failing_sha512(test: PrimitiveTest) -> bool {
        SELF_TESTS_RUN.with(|run| run.borrow_mut().push(test));
        test != PrimitiveTest::Sha512
    }

    fn never_runs(test: PrimitiveTest) -> bool {
        panic!("a rejected command must run no self-test, got {test:?}");
    }

    fn take_self_tests_run() -> Vec<PrimitiveTest> {
        SELF_TESTS_RUN.with(|run| core::mem::take(&mut *run.borrow_mut()))
    }

    #[track_caller]
    fn recording_runtime(snapshot: &str, runner: fn(PrimitiveTest) -> bool) -> Box<Tpm2Runtime> {
        let mut runtime = restored(snapshot);
        runtime.self_test.set_runner(runner);
        take_self_tests_run();
        runtime
    }

    #[test]
    fn verifying_an_hmac_signature_runs_the_pending_test_for_its_hash() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = recording_runtime("HMAC_KEYS", recording_runner);
        for algorithm in [TPM_ALG_SHA256, TPM_ALG_SHA512] {
            assert!(
                runtime.self_test.pending_algorithms().contains(&algorithm),
                "{algorithm:#06x} starts out untested"
            );
        }

        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);

        assert_eq!(response, vector("VERIFYSIG_HMAC_SHA256_OK"));
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256, PrimitiveTest::Sha512],
            "the MAC hash is tested before the primitive, the ticket hash before the ticket"
        );
        for algorithm in [TPM_ALG_SHA256, TPM_ALG_SHA512] {
            assert!(!runtime.self_test.pending_algorithms().contains(&algorithm));
        }
        assert!(runtime.self_test.failure.is_none());
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_failed_hmac_hash_self_test_stops_the_tpm_without_answering_a_ticket() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = recording_runtime("HMAC_KEYS", recording_runner_failing_sha256);

        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);

        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256],
            "the ticket hash is never reached"
        );
        assert!(runtime.failure_mode, "a failed self-test stops the TPM");
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha256
            })
        );
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA256),
            "a failed test stays pending"
        );
    }

    #[test]
    fn a_non_empty_ticket_runs_the_pending_context_integrity_test() {
        let signature = oracle_signature("SIGN_RSASSA");
        let mut runtime = recording_runtime("KEYS", recording_runner);
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA512)
        );

        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);

        assert_eq!(response, vector("VERIFYSIG_RSASSA_OK"));
        assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha512]);
        assert!(
            !runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA512)
        );
        assert!(runtime.self_test.failure.is_none());
    }

    #[test]
    fn a_failed_context_integrity_self_test_stops_the_tpm_without_answering_a_ticket() {
        let signature = oracle_signature("SIGN_RSASSA");
        let mut runtime = recording_runtime("KEYS", recording_runner_failing_sha512);

        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);

        assert_eq!(response, error_response(TPM_RC_FAILURE));
        assert_eq!(response.len(), 10, "no ticket");
        assert_eq!(take_self_tests_run(), [PrimitiveTest::Sha512]);
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha512
            })
        );
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA512)
        );
    }

    #[test]
    fn an_empty_ticket_path_runs_no_context_integrity_test() {
        let signature = oracle_signature("SIGN_NULL_HIERARCHY");
        let mut runtime = recording_runtime("HIERARCHY_KEYS", recording_runner);
        let before = runtime.self_test.pending_algorithms();

        let response = verify(&mut runtime, 0x8000_0002, &abc(TPM_ALG_SHA256), &signature);

        assert_eq!(response, vector("VERIFYSIG_NULL_HIERARCHY_OK"));
        assert_eq!(
            take_self_tests_run(),
            [] as [PrimitiveTest; 0],
            "a null-hierarchy key never reaches the ticket hash"
        );
        assert_eq!(runtime.self_test.pending_algorithms(), before);
    }

    #[test]
    fn an_empty_ticket_from_a_null_name_algorithm_runs_no_context_integrity_test() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = recording_runtime("HMAC_KEYS", recording_runner);
        let slot = runtime.live.objects.get_mut(0).expect("a loaded key");
        let OwnedAnyObjectBody::Object(body) = &mut slot.body else {
            panic!("a key object");
        };
        body.public.name_alg = TPM_ALG_NULL;

        let response = verify(&mut runtime, 0x8000_0000, &abc(TPM_ALG_SHA256), &signature);

        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256],
            "the MAC hash is still tested, the ticket hash is not"
        );
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_SHA512)
        );
    }

    #[test]
    fn a_rejected_command_runs_no_self_test_and_keeps_its_response_code() {
        for (snapshot, record, handle, digest, signature) in [
            (
                "KEYS",
                "VERIFYSIG_ZERO_RSA_SIG",
                0x8000_0000u32,
                abc(TPM_ALG_SHA256),
                bogus_rsa_signature(),
            ),
            (
                "KEYS",
                "VERIFYSIG_BAD_SIGALG",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                rsa_signature(0x0015, TPM_ALG_SHA256, &[0u8; 256]),
            ),
            (
                "KEYS",
                "VERIFYSIG_ECC_BOGUS",
                0x8000_0001,
                abc(TPM_ALG_SHA256),
                ecc_signature(TPM_ALG_ECDSA, TPM_ALG_SHA256, &[0x11; 32], &[0x22; 32]),
            ),
            (
                "MISC_KEYS",
                "VERIFYSIG_STORAGE_KEY",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                bogus_rsa_signature(),
            ),
            (
                "HMAC_KEYS",
                "VERIFYSIG_HMAC_RSA_SIG",
                0x8000_0000,
                abc(TPM_ALG_SHA256),
                bogus_rsa_signature(),
            ),
            (
                "HMAC_KEYS",
                "VERIFYSIG_HMAC_SCHEME_MISMATCH",
                0x8000_0000,
                abc(TPM_ALG_SHA384),
                hmac_signature(TPM_ALG_SHA384, &abc(TPM_ALG_SHA384)),
            ),
            (
                "NO_SHA1_HMAC",
                "VERIFYSIG_NO_SHA1_HMAC",
                0x8000_0000,
                abc(TPM_ALG_SHA1),
                oracle_signature("SIGN_NO_SHA1_HMAC"),
            ),
        ] {
            let mut runtime = recording_runtime(snapshot, never_runs);
            let pending = runtime.self_test.pending_algorithms();
            assert_eq!(
                verify(&mut runtime, handle, &digest, &signature),
                vector(record),
                "{record}"
            );
            assert_eq!(runtime.self_test.pending_algorithms(), pending, "{record}");
            assert!(runtime.self_test.failure.is_none(), "{record}");
            assert!(!runtime.failure_mode, "{record}");
        }
    }

    #[test]
    fn a_failing_mac_comparison_still_runs_its_hash_self_test_and_keeps_the_signature_code() {
        let signature = oracle_signature("SIGN_HMAC_SHA256");
        let mut runtime = recording_runtime("HMAC_KEYS", recording_runner);

        let response = verify(&mut runtime, 0x8000_0000, &xyz(), &signature);

        assert_eq!(response, vector("VERIFYSIG_HMAC_SHA256_WRONG_DIGEST"));
        assert_eq!(response_code(&response), RC_PARAM2_SIGNATURE);
        assert_eq!(
            take_self_tests_run(),
            [PrimitiveTest::Sha256],
            "the MAC primitive ran, the ticket hash did not"
        );
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn verification_never_touches_the_signing_state() {
        let signature = oracle_signature("SIGN_RSASSA");
        let mut runtime = restored("KEYS");
        let before = fingerprint(&runtime);
        assert_eq!(
            response_code(&verify(
                &mut runtime,
                0x8000_0000,
                &abc(TPM_ALG_SHA256),
                &signature
            )),
            RC_SUCCESS
        );
        assert_eq!(fingerprint(&runtime), before, "a successful verification");

        for (handle, digest, signature) in [
            (0x8000_0000u32, xyz(), signature.clone()),
            (0x8000_0001, abc(TPM_ALG_SHA256), signature.clone()),
            (0x8000_0000, abc(TPM_ALG_SHA256), bogus_rsa_signature()),
        ] {
            let _ = verify(&mut runtime, handle, &digest, &signature);
            assert_eq!(fingerprint(&runtime), before, "handle {handle:#010x}");
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Fingerprint {
        nv_memory: Vec<u8>,
        nv_update_pending: bool,
        objects: Vec<u32>,
        reseed_counter: u64,
        drbg_seed: Vec<u8>,
        drbg_last_value: [u32; 4],
        commit_counter: u64,
        commit_array: Vec<u8>,
        failed_tries: u32,
    }

    fn fingerprint(runtime: &Tpm2Runtime) -> Fingerprint {
        let reset = runtime
            .live
            .state_reset
            .as_ref()
            .expect("restored reset state");
        Fingerprint {
            nv_memory: runtime.nv_memory.to_vec(),
            nv_update_pending: runtime.nv_update_pending,
            objects: runtime
                .live
                .objects
                .iter()
                .map(|object: &OwnedAnyObject| object.attributes)
                .collect(),
            reseed_counter: runtime.live.orderly.drbg_state.reseed_counter,
            drbg_seed: runtime.live.orderly.drbg_state.seed.as_bytes().to_vec(),
            drbg_last_value: runtime.live.orderly.drbg_state.last_value,
            commit_counter: reset.commit_counter,
            commit_array: reset.commit_array.to_vec(),
            failed_tries: runtime
                .state
                .as_ref()
                .expect("restored state")
                .persistent
                .failed_tries,
        }
    }
}
