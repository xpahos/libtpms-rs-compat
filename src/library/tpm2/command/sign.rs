use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_TAG,
    TPM_RC_TICKET, TPM_RC_VALUE,
};

use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::super::persistent::OwnedObjectBody;
use super::super::profile::ValidatedProfile;
use super::super::runtime::Tpm2Runtime;
use super::super::signature::{
    SigScheme, is_signing_object, marshal_signature, parse_sig_scheme, select_sign_scheme,
    sign_digest,
};
use super::super::template::{
    TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_X509_SIGN, TemplateReader, digest_size,
};
use super::super::ticket::{TPM_ST_HASHCHECK, Ticket, compute_hash_check};
use super::dispatcher::CommandFrame;
use super::nv_common::{TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_P, handle_at};
use super::output::CommandOutput;
use super::signing::{
    RC_SIGN_HANDLE, hierarchy_proof_for, load_signing_state, publish_signing_outcome,
    signing_object,
};

const RC_DIGEST: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_VALIDATION: TpmResult = TPM_RC_P + TPM_RC_3;

const DIGEST_TPM2B_MAX: usize = 64;

struct Parameters {
    digest: Vec<u8>,
    scheme: SigScheme,
    validation: Ticket,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, key_handle)?.ok_or(TPM_RC_FAILURE)?;
    if !is_signing_object(&sign_object) {
        return Err(TPM_RC_KEY + RC_SIGN_HANDLE);
    }
    if sign_object.public.object_attributes & TPMA_OBJECT_X509_SIGN != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_SIGN_HANDLE);
    }
    let scheme = select_sign_scheme(Some(&sign_object), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;
    check_validation(runtime, &sign_object, &scheme, &parameters)?;

    let mut signing = load_signing_state(runtime)?;
    let signature = sign_digest(
        Some(&sign_object),
        &scheme,
        &parameters.digest,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
        &mut signing,
    );
    let signature = publish_signing_outcome(runtime, signing, signature)?;
    Ok(CommandOutput::from_parameters(marshal_signature(
        &signature,
    )))
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
    let scheme = parse_sig_scheme(&mut reader, profile).map_err(|code| code + RC_IN_SCHEME)?;
    let validation = parse_hash_check(&mut reader).map_err(|code| code + RC_VALIDATION)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        digest,
        scheme,
        validation,
    })
}

fn parse_hash_check(reader: &mut TemplateReader<'_>) -> Result<Ticket, TpmResult> {
    let tag = reader.u16()?;
    if tag != TPM_ST_HASHCHECK {
        return Err(TPM_RC_TAG);
    }
    let hierarchy = reader.u32()?;
    if !matches!(
        hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE);
    }
    let digest = reader.tpm2b(DIGEST_TPM2B_MAX)?.to_vec();
    Ok(Ticket {
        tag,
        hierarchy,
        digest,
    })
}

fn check_validation(
    runtime: &Tpm2Runtime,
    sign_object: &OwnedObjectBody,
    scheme: &SigScheme,
    parameters: &Parameters,
) -> Result<(), TpmResult> {
    let restricted = sign_object.public.object_attributes & TPMA_OBJECT_RESTRICTED != 0;
    if parameters.validation.digest.is_empty() && !restricted {
        return if digest_size(scheme.hash_alg) == Some(parameters.digest.len()) {
            Ok(())
        } else {
            Err(TPM_RC_SIZE + RC_DIGEST)
        };
    }
    let hierarchy = parameters.validation.hierarchy;
    let proof = hierarchy_proof_for(runtime, hierarchy)?;
    let expected = compute_hash_check(hierarchy, proof, scheme.hash_alg, &parameters.digest)
        .ok_or(TPM_RC_FAILURE)?;
    if expected.digest != parameters.validation.digest {
        return Err(TPM_RC_TICKET + RC_VALIDATION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::nv_common::harness::*;
    use super::super::registry::{CommandLifecycle, HandleKind, NvAccess, TPM_CC_SIGN, find};
    use super::*;
    use crate::library::tpm2::crypto::Hasher;
    use crate::library::tpm2::golden_responses::sign::vector;
    use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody, OwnedSecret};
    use crate::library::tpm2::state::COMMIT_ARRAY_SIZE;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;
    const TPM_ALG_HMAC: u16 = 0x0005;
    const TPM_ALG_RSASSA: u16 = 0x0014;
    const TPM_ALG_RSAPSS: u16 = 0x0016;
    const TPM_ALG_ECDSA: u16 = 0x0018;
    const TPM_ALG_ECDAA: u16 = 0x001a;
    const TPM_ALG_ECSCHNORR: u16 = 0x001c;
    const TPM_ALG_NULL_ID: u16 = 0x0010;

    const TYPE_RSA: u16 = 0x0001;
    const TYPE_KEYEDHASH: u16 = 0x0008;
    const TYPE_ECC: u16 = 0x0023;
    const TPM_ECC_NIST_P256: u16 = 0x0003;

    const SIGN_ATTRS: u32 = 0x0004_0072;
    const RESTRICTED_SIGN_ATTRS: u32 = 0x0005_0072;
    const X509_SIGN_ATTRS: u32 = 0x000c_0072;
    const STORAGE_ATTRS: u32 = 0x0003_0072;
    const NO_DA_SIGN_ATTRS: u32 = SIGN_ATTRS | 0x0400;

    const AES128_CFB: [u8; 6] = [0x00, 0x06, 0x00, 0x80, 0x00, 0x43];
    const NULL_SYMMETRIC: [u8; 2] = [0x00, 0x10];

    const TRANSIENT: [u32; 3] = [0x8000_0000, 0x8000_0001, 0x8000_0002];
    const PERSISTENT: u32 = 0x8100_0001;

    const RC_HANDLE1_KEY: u32 = 0x19c;
    const RC_HANDLE1_ATTRIBUTES: u32 = 0x182;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM2_SCHEME: u32 = 0x2d2;
    const RC_PARAM3_TICKET: u32 = 0x3e0;
    const RC_VALUE: u32 = 0x084;
    const RC_HASH: u32 = 0x083;
    const RC_NO_RESULT: u32 = 0x154;
    const RC_FAILURE: u32 = 0x101;

    const OWNER_TICKET_HIERARCHY: u32 = TPM_RH_OWNER;

    fn digest_of(hash_alg: u16, data: &[u8]) -> Vec<u8> {
        let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
        hasher.update(data);
        hasher.finalize()
    }

    fn sha256() -> Vec<u8> {
        digest_of(TPM_ALG_SHA256, b"abc")
    }

    fn scheme_bytes(scheme: u16, hash_alg: u16, count: Option<u16>) -> Vec<u8> {
        if scheme == TPM_ALG_NULL_ID {
            return TPM_ALG_NULL_ID.to_be_bytes().to_vec();
        }
        let mut out = scheme.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        if let Some(count) = count {
            out.extend_from_slice(&count.to_be_bytes());
        }
        out
    }

    fn rsa_template(scheme: u16, hash_alg: u16, attributes: u32) -> Vec<u8> {
        let mut out = TYPE_RSA.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL_ID.to_be_bytes());
        out.extend_from_slice(&scheme_bytes(scheme, hash_alg, None));
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    fn ecc_template(scheme: u16, hash_alg: u16, attributes: u32, symmetric: &[u8]) -> Vec<u8> {
        let mut out = TYPE_ECC.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(symmetric);
        out.extend_from_slice(&scheme_bytes(scheme, hash_alg, None));
        out.extend_from_slice(&TPM_ECC_NIST_P256.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL_ID.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    fn keyedhash_template(scheme: u16, hash_alg: u16, attributes: u32) -> Vec<u8> {
        let mut out = TYPE_KEYEDHASH.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&scheme_bytes(scheme, hash_alg, None));
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    #[track_caller]
    fn create_primary(
        runtime: &mut Tpm2Runtime,
        hierarchy: u32,
        template: &[u8],
    ) -> (u32, Vec<u8>) {
        let mut parameters = 4u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&(template.len() as u16).to_be_bytes());
        parameters.extend_from_slice(template);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u32.to_be_bytes());
        let response = dispatch_bytes(
            runtime,
            &command(0x0000_0131, &[hierarchy], &[&[]], &parameters),
        );
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "the primary is created"
        );
        let handle = u32::from_be_bytes(response[10..14].try_into().expect("a response handle"));
        (handle, response)
    }

    fn null_ticket() -> Vec<u8> {
        let mut out = TPM_ST_HASHCHECK.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    fn hash_check(tag: u16, hierarchy: u32, digest: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&hierarchy.to_be_bytes());
        out.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        out.extend_from_slice(digest);
        out
    }

    fn sign_parameters(digest: &[u8], scheme: u16, hash_alg: u16, validation: &[u8]) -> Vec<u8> {
        let mut out = (digest.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(digest);
        out.extend_from_slice(&scheme_bytes(scheme, hash_alg, None));
        out.extend_from_slice(validation);
        out
    }

    #[track_caller]
    fn sign_raw(runtime: &mut Tpm2Runtime, handle: u32, parameters: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(TPM_CC_SIGN, &[handle], &[&[]], parameters),
        )
    }

    #[track_caller]
    fn sign(
        runtime: &mut Tpm2Runtime,
        handle: u32,
        digest: &[u8],
        scheme: u16,
        hash_alg: u16,
    ) -> Vec<u8> {
        sign_raw(
            runtime,
            handle,
            &sign_parameters(digest, scheme, hash_alg, &null_ticket()),
        )
    }

    #[track_caller]
    fn sign_with_ticket(
        runtime: &mut Tpm2Runtime,
        handle: u32,
        digest: &[u8],
        scheme: u16,
        hash_alg: u16,
        validation: &[u8],
    ) -> Vec<u8> {
        sign_raw(
            runtime,
            handle,
            &sign_parameters(digest, scheme, hash_alg, validation),
        )
    }

    fn owner_ticket_digest() -> Vec<u8> {
        let hash = vector("HASH_TICKET_OWNER");
        let parameters = &hash[10..];
        let digest_size = usize::from(u16::from_be_bytes([parameters[0], parameters[1]]));
        let ticket = &parameters[2 + digest_size..];
        let mac_size = usize::from(u16::from_be_bytes([ticket[6], ticket[7]]));
        ticket[8..8 + mac_size].to_vec()
    }

    fn owner_ticket() -> Vec<u8> {
        hash_check(
            TPM_ST_HASHCHECK,
            OWNER_TICKET_HIERARCHY,
            &owner_ticket_digest(),
        )
    }

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

    #[track_caller]
    fn asym_runtime() -> Box<Tpm2Runtime> {
        restored("ASYM")
    }

    #[track_caller]
    fn mixed_runtime() -> Box<Tpm2Runtime> {
        restored("MIXED")
    }

    #[track_caller]
    fn misc_runtime() -> Box<Tpm2Runtime> {
        restored("MISC")
    }

    #[track_caller]
    fn no_sha1_runtime() -> Box<Tpm2Runtime> {
        restored("NO_SHA1")
    }

    #[track_caller]
    fn persistent_runtime() -> Box<Tpm2Runtime> {
        restored("PERSISTENT")
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_015D");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        assert_eq!(TPM_CC_SIGN, 0x0000_015d);
        let descriptor = find(TPM_CC_SIGN).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0200_015d);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "TPM2_Sign does not use NV"
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
    fn the_handle_carries_the_upstream_role() {
        let descriptor = find(TPM_CC_SIGN).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));

        let kind = descriptor.handles[0].kind;
        assert!(kind.accepts(0x8000_0000));
        assert!(kind.accepts(0x8100_0000));
        for handle in [TPM_RH_NULL, TPM_RH_OWNER, 0x0100_0001, 0x0200_0000] {
            assert!(!kind.accepts(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn the_capability_list_advertises_sign() {
        use crate::library::tpm2::capability::commands::implemented;
        let page = implemented(TPM_CC_SIGN, 1);
        assert_eq!(page.entries, [0x0200_015d]);
        assert!(implemented(0, 1000).entries.contains(&0x0200_015d));
    }

    #[track_caller]
    fn started_from(permall: &str) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector(permall))
            .expect("the oracle permanent state restores");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );
        runtime
    }

    #[test]
    fn every_signing_key_is_generated_like_the_oracle() {
        for (permall, group) in [
            (
                "PERMALL_BASE",
                vec![
                    (
                        "CREATE_RSASSA",
                        rsa_template(TPM_ALG_RSASSA, TPM_ALG_SHA256, SIGN_ATTRS),
                    ),
                    (
                        "CREATE_RSAPSS",
                        rsa_template(TPM_ALG_RSAPSS, TPM_ALG_SHA256, SIGN_ATTRS),
                    ),
                    (
                        "CREATE_ECDSA",
                        ecc_template(TPM_ALG_ECDSA, TPM_ALG_SHA256, SIGN_ATTRS, &NULL_SYMMETRIC),
                    ),
                ],
            ),
            (
                "PERMALL_BASE",
                vec![
                    (
                        "CREATE_RESTRICTED",
                        rsa_template(TPM_ALG_RSASSA, TPM_ALG_SHA256, RESTRICTED_SIGN_ATTRS),
                    ),
                    (
                        "CREATE_HMAC",
                        keyedhash_template(TPM_ALG_HMAC, TPM_ALG_SHA256, SIGN_ATTRS),
                    ),
                    (
                        "CREATE_STORAGE",
                        ecc_template(TPM_ALG_NULL_ID, 0, STORAGE_ATTRS, &AES128_CFB),
                    ),
                ],
            ),
            (
                "PERMALL_BASE",
                vec![
                    (
                        "CREATE_X509",
                        ecc_template(
                            TPM_ALG_ECDSA,
                            TPM_ALG_SHA256,
                            X509_SIGN_ATTRS,
                            &NULL_SYMMETRIC,
                        ),
                    ),
                    (
                        "CREATE_ECC_NO_SCHEME",
                        ecc_template(TPM_ALG_NULL_ID, 0, SIGN_ATTRS, &NULL_SYMMETRIC),
                    ),
                ],
            ),
            (
                "PERMALL_NO_SHA1_BASE",
                vec![
                    (
                        "CREATE_NO_SHA1_ECC",
                        ecc_template(TPM_ALG_NULL_ID, 0, SIGN_ATTRS, &NULL_SYMMETRIC),
                    ),
                    (
                        "CREATE_NO_SHA1_HMAC",
                        keyedhash_template(TPM_ALG_HMAC, TPM_ALG_SHA1, SIGN_ATTRS),
                    ),
                ],
            ),
        ] {
            let mut runtime = started_from(permall);
            for (name, template) in group {
                let (_, response) = create_primary(&mut runtime, TPM_RH_OWNER, &template);
                assert_eq!(response, vector(name), "{name}");
            }
        }
    }

    #[test]
    fn the_rsassa_signatures_match_the_oracle() {
        let digest = sha256();
        let mut runtime = asym_runtime();
        assert_eq!(
            sign(&mut runtime, TRANSIENT[0], &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_RSASSA_DEFAULT"),
            "TPM_ALG_NULL selects the key's own scheme"
        );
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[0],
                &digest,
                TPM_ALG_RSASSA,
                TPM_ALG_SHA256
            ),
            vector("SIGN_RSASSA_EXPLICIT")
        );
        assert_eq!(
            sign_with_ticket(
                &mut runtime,
                TRANSIENT[0],
                &digest,
                TPM_ALG_NULL_ID,
                0,
                &owner_ticket()
            ),
            vector("SIGN_RSASSA_TICKET"),
            "a valid hash-check ticket is accepted"
        );
    }

    #[test]
    fn the_ticket_errors_match_the_oracle() {
        let digest = sha256();
        let mut runtime = asym_runtime();
        for (name, validation) in [
            (
                "SIGN_RSASSA_BAD_TICKET",
                hash_check(TPM_ST_HASHCHECK, TPM_RH_OWNER, &[0u8; 64]),
            ),
            (
                "SIGN_RSASSA_SHORT_TICKET",
                hash_check(TPM_ST_HASHCHECK, TPM_RH_OWNER, &[0u8; 32]),
            ),
            (
                "SIGN_RSASSA_WRONG_TICKET_HIERARCHY",
                hash_check(TPM_ST_HASHCHECK, TPM_RH_PLATFORM, &owner_ticket_digest()),
            ),
            (
                "SIGN_RSASSA_TICKET_BAD_TAG",
                hash_check(0x8023, TPM_RH_OWNER, &owner_ticket_digest()),
            ),
            (
                "SIGN_RSASSA_TICKET_BAD_HIERARCHY",
                hash_check(TPM_ST_HASHCHECK, 0x4000_000a, &owner_ticket_digest()),
            ),
        ] {
            assert_eq!(
                sign_with_ticket(
                    &mut runtime,
                    TRANSIENT[0],
                    &digest,
                    TPM_ALG_NULL_ID,
                    0,
                    &validation
                ),
                vector(name),
                "{name}"
            );
        }
    }

    #[test]
    fn the_scheme_and_digest_errors_match_the_oracle() {
        let mut runtime = asym_runtime();
        for (name, digest, scheme, hash_alg) in [
            (
                "SIGN_RSASSA_WRONG_SCHEME",
                sha256(),
                TPM_ALG_RSAPSS,
                TPM_ALG_SHA256,
            ),
            (
                "SIGN_RSASSA_WRONG_HASH",
                sha256(),
                TPM_ALG_RSASSA,
                TPM_ALG_SHA1,
            ),
            (
                "SIGN_RSASSA_SHORT_DIGEST",
                digest_of(TPM_ALG_SHA1, b"abc"),
                TPM_ALG_NULL_ID,
                0,
            ),
            (
                "SIGN_RSASSA_LONG_DIGEST",
                digest_of(TPM_ALG_SHA512, b"abc"),
                TPM_ALG_NULL_ID,
                0,
            ),
        ] {
            assert_eq!(
                sign(&mut runtime, TRANSIENT[0], &digest, scheme, hash_alg),
                vector(name),
                "{name}"
            );
        }
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TRANSIENT[0],
                &sha256(),
                TPM_ALG_RSAPSS,
                TPM_ALG_SHA256
            )),
            RC_PARAM2_SCHEME
        );
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TRANSIENT[0],
                &digest_of(TPM_ALG_SHA1, b"abc"),
                TPM_ALG_NULL_ID,
                0
            )),
            RC_PARAM1_SIZE
        );
    }

    #[test]
    fn the_parameter_errors_match_the_oracle() {
        let mut runtime = asym_runtime();
        let mut trailing = sign_parameters(&sha256(), TPM_ALG_NULL_ID, 0, &null_ticket());
        trailing.push(0x00);
        let mut truncated_validation = 32u16.to_be_bytes().to_vec();
        truncated_validation.extend_from_slice(&sha256());
        truncated_validation.extend_from_slice(&TPM_ALG_NULL_ID.to_be_bytes());
        truncated_validation.extend_from_slice(&TPM_ST_HASHCHECK.to_be_bytes());
        let mut truncated_scheme = 32u16.to_be_bytes().to_vec();
        truncated_scheme.extend_from_slice(&sha256());

        for (name, parameters) in [
            ("SIGN_RSASSA_TRAILING", trailing),
            ("SIGN_EMPTY_PARAMETERS", Vec::new()),
            ("SIGN_OVERSIZED_DIGEST", 0xffffu16.to_be_bytes().to_vec()),
            ("SIGN_TRUNCATED_SCHEME", truncated_scheme),
            ("SIGN_TRUNCATED_VALIDATION", truncated_validation),
        ] {
            assert_eq!(
                sign_raw(&mut runtime, TRANSIENT[0], &parameters),
                vector(name),
                "{name}"
            );
        }
        assert_eq!(
            response_code(&sign_raw(&mut runtime, TRANSIENT[0], &[])),
            0x1da,
            "a missing digest is reported against the first parameter"
        );
    }

    #[test]
    fn the_handle_errors_match_the_oracle() {
        let digest = sha256();
        let mut runtime = asym_runtime();
        for (name, handle) in [
            ("SIGN_UNLOADED_HANDLE", 0x8000_0005),
            ("SIGN_HIERARCHY_HANDLE", TPM_RH_OWNER),
            ("SIGN_UNDEFINED_PERSISTENT", 0x8100_0009),
        ] {
            assert_eq!(
                sign(&mut runtime, handle, &digest, TPM_ALG_NULL_ID, 0),
                vector(name),
                "{name}"
            );
        }
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TPM_RH_OWNER,
                &digest,
                TPM_ALG_NULL_ID,
                0
            )),
            RC_HANDLE1_VALUE
        );
    }

    #[test]
    fn the_randomized_signatures_consume_the_live_drbg() {
        let digest = sha256();
        let mut runtime = asym_runtime();
        let pss_first = sign(&mut runtime, TRANSIENT[1], &digest, TPM_ALG_NULL_ID, 0);
        let pss_second = sign(&mut runtime, TRANSIENT[1], &digest, TPM_ALG_NULL_ID, 0);
        let ecdsa_first = sign(&mut runtime, TRANSIENT[2], &digest, TPM_ALG_NULL_ID, 0);
        let ecdsa_second = sign(&mut runtime, TRANSIENT[2], &digest, TPM_ALG_NULL_ID, 0);
        assert_eq!(pss_first, vector("SIGN_RSAPSS_FIRST"));
        assert_eq!(pss_second, vector("SIGN_RSAPSS_SECOND"));
        assert_eq!(ecdsa_first, vector("SIGN_ECDSA_FIRST"));
        assert_eq!(ecdsa_second, vector("SIGN_ECDSA_SECOND"));
        assert_ne!(pss_first, pss_second, "the PSS salt advances the DRBG");
        assert_ne!(ecdsa_first, ecdsa_second, "the nonce advances the DRBG");
    }

    #[test]
    fn a_scheme_hash_that_disagrees_with_the_key_is_rejected() {
        let mut runtime = asym_runtime();
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[2],
                &digest_of(TPM_ALG_SHA1, b"abc"),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA1
            ),
            vector("SIGN_ECDSA_SHA1")
        );
    }

    #[test]
    fn the_persistent_key_signs_like_the_oracle() {
        let digest = sha256();
        let mut runtime = persistent_runtime();
        assert_matches_oracle(&runtime, vector("PERMALL_PERSISTENT"), "after eviction");
        assert_eq!(
            sign(&mut runtime, PERSISTENT, &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_PERSISTENT")
        );
        assert_eq!(
            sign_with_ticket(
                &mut runtime,
                PERSISTENT,
                &digest,
                TPM_ALG_NULL_ID,
                0,
                &owner_ticket()
            ),
            vector("SIGN_PERSISTENT_TICKET")
        );
        assert_eq!(
            sign(&mut runtime, TRANSIENT[0], &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_FLUSHED_TRANSIENT"),
            "a flushed transient object is a reference error"
        );
        assert_eq!(
            sign(&mut runtime, 0x8100_0009, &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_MISSING_PERSISTENT"),
            "a free object slot exposes the handle error"
        );
    }

    #[test]
    fn the_restricted_and_keyed_hash_keys_match_the_oracle() {
        let digest = sha256();
        let sha1 = digest_of(TPM_ALG_SHA1, b"abc");
        let mut runtime = mixed_runtime();
        assert_eq!(
            sign(&mut runtime, TRANSIENT[0], &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_RESTRICTED_NO_TICKET"),
            "a restricted key always needs a ticket"
        );
        assert_eq!(
            sign_with_ticket(
                &mut runtime,
                TRANSIENT[0],
                &digest,
                TPM_ALG_NULL_ID,
                0,
                &owner_ticket()
            ),
            vector("SIGN_RESTRICTED_TICKET")
        );
        assert_eq!(
            sign(&mut runtime, TRANSIENT[0], &sha1, TPM_ALG_NULL_ID, 0),
            vector("SIGN_RESTRICTED_SHORT_DIGEST"),
            "the ticket check precedes the digest-size check"
        );
        assert_eq!(
            sign(&mut runtime, TRANSIENT[1], &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_HMAC_DEFAULT")
        );
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[1],
                &digest,
                TPM_ALG_HMAC,
                TPM_ALG_SHA256
            ),
            vector("SIGN_HMAC_EXPLICIT")
        );
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[1],
                &digest,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            ),
            vector("SIGN_HMAC_WRONG_SCHEME")
        );
        assert_eq!(
            sign(&mut runtime, TRANSIENT[2], &digest, TPM_ALG_NULL_ID, 0),
            vector("SIGN_STORAGE_KEY")
        );
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[2],
                &digest,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            ),
            vector("SIGN_STORAGE_KEY_EXPLICIT")
        );
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TRANSIENT[2],
                &digest,
                TPM_ALG_NULL_ID,
                0
            )),
            RC_HANDLE1_KEY
        );
    }

    #[test]
    fn the_x509_and_scheme_selection_errors_match_the_oracle() {
        let digest = sha256();
        let mut runtime = misc_runtime();
        for (name, handle, scheme, hash_alg) in [
            ("SIGN_X509_KEY", TRANSIENT[0], TPM_ALG_NULL_ID, 0),
            (
                "SIGN_X509_KEY_EXPLICIT",
                TRANSIENT[0],
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
            ),
            ("SIGN_NO_SCHEME_NULL", TRANSIENT[1], TPM_ALG_NULL_ID, 0),
            (
                "SIGN_NO_SCHEME_RSASSA",
                TRANSIENT[1],
                TPM_ALG_RSASSA,
                TPM_ALG_SHA256,
            ),
            (
                "SIGN_NO_SCHEME_BAD_SCHEME",
                TRANSIENT[1],
                0x0015,
                TPM_ALG_SHA256,
            ),
            (
                "SIGN_NO_SCHEME_BAD_HASH",
                TRANSIENT[1],
                TPM_ALG_ECDSA,
                0x0012,
            ),
            (
                "SIGN_NO_SCHEME_SHA384",
                TRANSIENT[1],
                TPM_ALG_ECDSA,
                TPM_ALG_SHA384,
            ),
        ] {
            assert_eq!(
                sign(&mut runtime, handle, &digest, scheme, hash_alg),
                vector(name),
                "{name}"
            );
        }
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TRANSIENT[0],
                &digest,
                TPM_ALG_NULL_ID,
                0
            )),
            RC_HANDLE1_ATTRIBUTES,
            "an x509sign key cannot be used by TPM2_Sign"
        );
        let mut ecdaa = (digest.len() as u16).to_be_bytes().to_vec();
        ecdaa.extend_from_slice(&digest);
        ecdaa.extend_from_slice(&scheme_bytes(TPM_ALG_ECDAA, TPM_ALG_SHA256, Some(0)));
        ecdaa.extend_from_slice(&null_ticket());
        assert_eq!(
            sign_raw(&mut runtime, TRANSIENT[1], &ecdaa),
            vector("SIGN_NO_SCHEME_ECDAA"),
            "a split signature without a commitment is a value error"
        );
    }

    #[test]
    fn every_selected_scheme_signs_like_the_oracle() {
        let mut runtime = misc_runtime();
        for (name, scheme, hash_alg) in [
            ("SIGN_NO_SCHEME_ECDSA", TPM_ALG_ECDSA, TPM_ALG_SHA256),
            (
                "SIGN_NO_SCHEME_ECSCHNORR",
                TPM_ALG_ECSCHNORR,
                TPM_ALG_SHA256,
            ),
            (
                "SIGN_NO_SCHEME_SHA384_DIGEST",
                TPM_ALG_ECDSA,
                TPM_ALG_SHA384,
            ),
            (
                "SIGN_NO_SCHEME_SHA512_DIGEST",
                TPM_ALG_ECDSA,
                TPM_ALG_SHA512,
            ),
        ] {
            let digest = digest_of(hash_alg, b"abc");
            assert_eq!(
                sign(&mut runtime, TRANSIENT[1], &digest, scheme, hash_alg),
                vector(name),
                "{name}"
            );
        }
    }

    #[test]
    fn the_sha1_restrictions_match_the_oracle() {
        let mut runtime = no_sha1_runtime();
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[0],
                &digest_of(TPM_ALG_SHA1, b"abc"),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA1
            ),
            vector("SIGN_NO_SHA1_ECDSA")
        );
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[0],
                &sha256(),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            ),
            vector("SIGN_NO_SHA1_ECDSA_SHA256"),
            "only SHA-1 is refused"
        );
        assert_eq!(
            sign(
                &mut runtime,
                TRANSIENT[1],
                &digest_of(TPM_ALG_SHA1, b"abc"),
                TPM_ALG_NULL_ID,
                0
            ),
            vector("SIGN_NO_SHA1_HMAC")
        );
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TRANSIENT[1],
                &digest_of(TPM_ALG_SHA1, b"abc"),
                TPM_ALG_NULL_ID,
                0
            )),
            RC_HASH
        );
    }

    #[test]
    fn the_authorization_failure_matches_the_oracle() {
        let digest = sha256();
        let mut runtime = asym_runtime();
        let response = dispatch_bytes(
            &mut runtime,
            &command(
                TPM_CC_SIGN,
                &[TRANSIENT[0]],
                &[&[0x01, 0x02, 0x03, 0x04]],
                &sign_parameters(&digest, TPM_ALG_NULL_ID, 0, &null_ticket()),
            ),
        );
        assert_eq!(response, vector("SIGN_RSASSA_BAD_AUTH"));
        assert_matches_oracle(
            &runtime,
            vector("PERMALL_AFTER_BAD_AUTH"),
            "after a failed authorization",
        );
    }

    #[test]
    fn a_successful_signature_records_the_dictionary_attack_marker() {
        let mut runtime = asym_runtime();
        assert_matches_oracle(&runtime, vector("PERMALL_ASYM"), "before signing");
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                TRANSIENT[0],
                &sha256(),
                TPM_ALG_NULL_ID,
                0
            )),
            RC_SUCCESS
        );
        assert_matches_oracle(&runtime, vector("PERMALL_AFTER_SIGN"), "after signing");
        assert!(runtime.live.da_used);
    }

    #[test]
    fn a_missing_authorization_area_is_auth_missing() {
        const RC_AUTH_MISSING: u32 = 0x125;
        let mut runtime = asym_runtime();
        let mut payload = TRANSIENT[0].to_be_bytes().to_vec();
        payload.extend_from_slice(&sign_parameters(
            &sha256(),
            TPM_ALG_NULL_ID,
            0,
            &null_ticket(),
        ));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(TPM_CC_SIGN, &payload, false)
            )),
            RC_AUTH_MISSING
        );
    }

    #[test]
    fn parameter_mutations_do_not_panic() {
        let full = sign_parameters(&sha256(), TPM_ALG_RSASSA, TPM_ALG_SHA256, &owner_ticket());
        let mut runtime = asym_runtime();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let response = sign_raw(&mut runtime, TRANSIENT[0], &parameters);
                assert!(
                    response[..2] == [0x80, 0x01] || response[..2] == [0x80, 0x02],
                    "index {index} byte {byte:#04x}"
                );
                assert!(!runtime.failure_mode, "index {index} byte {byte:#04x}");
            }
        }
        for length in 0..=full.len() {
            let response = sign_raw(&mut runtime, TRANSIENT[0], &full[..length]);
            assert!(response.len() >= 10, "length {length}");
            assert!(!runtime.failure_mode, "length {length}");
        }
    }

    fn all_algorithms() -> String {
        String::from_utf8(crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE.to_vec())
            .expect("an ascii algorithm list")
    }

    fn without(algorithm: &str) -> String {
        all_algorithms()
            .split(',')
            .filter(|token| *token != algorithm)
            .collect::<Vec<_>>()
            .join(",")
    }

    #[track_caller]
    fn profile_runtime(algorithms: &str, attributes: &str) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let json = format!(
            r#"{{"Name":"custom","Algorithms":"{algorithms}","Attributes":"{attributes}"}}"#
        );
        let profile =
            validate_user_profile(Some(json.as_bytes())).expect("the custom profile validates");
        let state = manufacture_state(profile, |buffer| {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x55;
            }
            Ok(())
        })
        .expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );
        runtime.nv_update_pending = false;
        runtime
    }

    #[derive(Debug, Eq, PartialEq)]
    struct SigningSnapshot {
        drbg_magic: u32,
        reseed_counter: u64,
        seed: Vec<u8>,
        last_value: [u32; 4],
        commit_counter: u64,
        commit_array: [u8; COMMIT_ARRAY_SIZE],
    }

    fn signing_snapshot(runtime: &Tpm2Runtime) -> SigningSnapshot {
        let drbg = &runtime.live.orderly.drbg_state;
        let reset = runtime.live.state_reset.as_ref().expect("a reset section");
        SigningSnapshot {
            drbg_magic: drbg.drbg_magic,
            reseed_counter: drbg.reseed_counter,
            seed: drbg.seed.as_bytes().to_vec(),
            last_value: drbg.last_value,
            commit_counter: reset.commit_counter,
            commit_array: reset.commit_array,
        }
    }

    #[track_caller]
    fn commitable_ecc_runtime(attributes: &str) -> (Box<Tpm2Runtime>, u32) {
        let mut runtime = profile_runtime(&all_algorithms(), attributes);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(TPM_ALG_NULL_ID, 0, NO_DA_SIGN_ATTRS, &NULL_SYMMETRIC),
        );
        {
            let reset = runtime.live.state_reset.as_mut().expect("a reset section");
            reset.commit_nonce = OwnedSecret::copy_of(&[0x21; 32]);
            reset.commit_counter = 1;
            reset.commit_array[0] = 0x01;
        }
        runtime
            .state
            .as_mut()
            .expect("decoded state")
            .persistent
            .orderly_state = 0;
        runtime.nv_update_pending = false;
        (runtime, key)
    }

    #[track_caller]
    fn sign_split(runtime: &mut Tpm2Runtime, handle: u32, count: u16) -> Vec<u8> {
        let digest = sha256();
        let mut parameters = (digest.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(&digest);
        parameters.extend_from_slice(&scheme_bytes(TPM_ALG_ECDAA, TPM_ALG_SHA256, Some(count)));
        parameters.extend_from_slice(&null_ticket());
        sign_raw(runtime, handle, &parameters)
    }

    #[test]
    fn a_committed_ecdaa_signature_consumes_its_commitment() {
        let (mut runtime, key) = commitable_ecc_runtime("");
        let response = sign_split(&mut runtime, key, 0);
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            runtime.live.state_reset.as_ref().unwrap().commit_array[0],
            0x00,
            "a completed split signature releases its commit slot"
        );
        assert_eq!(
            response_code(&sign_split(&mut runtime, key, 0)),
            RC_VALUE,
            "the commitment cannot be reused"
        );
    }

    #[test]
    fn a_successful_signature_publishes_the_signing_state() {
        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        let before = signing_snapshot(&runtime);
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                key,
                &sha256(),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            )),
            RC_SUCCESS
        );
        let after = signing_snapshot(&runtime);
        assert_ne!(after.seed, before.seed, "signing advanced the DRBG");
        assert_ne!(after.reseed_counter, before.reseed_counter);
        assert_ne!(after.last_value, before.last_value);
        assert_eq!(
            after.commit_array, before.commit_array,
            "a non-split scheme keeps every commitment"
        );
    }

    #[test]
    fn signing_never_clears_the_orderly_state() {
        let (mut runtime, key) = commitable_ecc_runtime("");
        let nv_memory_before = runtime.nv_memory.clone();
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                key,
                &sha256(),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            )),
            RC_SUCCESS
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0,
            "TPM2_Sign never reads the clock, so the TPM stays orderly"
        );
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_rejected_signature_leaves_the_signing_state_untouched() {
        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        let before = signing_snapshot(&runtime);
        let nv_memory_before = runtime.nv_memory.clone();
        for (label, response, expected) in [
            (
                "an unusable split commitment",
                sign_split(&mut runtime, key, 5),
                RC_VALUE,
            ),
            (
                "a wrong digest size",
                sign(
                    &mut runtime,
                    key,
                    &digest_of(TPM_ALG_SHA1, b"abc"),
                    TPM_ALG_ECDSA,
                    TPM_ALG_SHA256,
                ),
                RC_PARAM1_SIZE,
            ),
            (
                "an invalid ticket",
                sign_with_ticket(
                    &mut runtime,
                    key,
                    &sha256(),
                    TPM_ALG_ECDSA,
                    TPM_ALG_SHA256,
                    &hash_check(TPM_ST_HASHCHECK, TPM_RH_OWNER, &[0u8; 64]),
                ),
                RC_PARAM3_TICKET,
            ),
        ] {
            assert_eq!(response_code(&response), expected, "{label}");
            assert_eq!(signing_snapshot(&runtime), before, "{label}");
            assert_eq!(runtime.nv_memory, nv_memory_before, "{label}");
            assert!(!runtime.failure_mode, "{label}");
        }
    }

    #[test]
    fn a_continuous_test_failure_during_signing_is_fatal_and_publishes_nothing() {
        use crate::library::tpm2::crypto::Drbg;
        use crate::library::tpm2::failure_mode::FailureLocation;

        fn colliding_last_value(seed: &[u8]) -> [u32; 4] {
            let mut probe = Drbg::restore(seed, 1, [0; 4], false).expect("the probe restores");
            let mut block = [0u8; 16];
            probe.generate(&mut block).expect("the probe generates");
            core::array::from_fn(|word| {
                u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
            })
        }

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        let seed = runtime.live.orderly.drbg_state.seed.as_bytes().to_vec();
        runtime.live.orderly.drbg_state.last_value = colliding_last_value(&seed);
        let before = signing_snapshot(&runtime);

        assert_eq!(
            response_code(&sign(
                &mut runtime,
                key,
                &sha256(),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            )),
            RC_FAILURE
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics()
        );
        assert_eq!(
            signing_snapshot(&runtime),
            before,
            "no partially advanced state is published"
        );
    }

    #[test]
    fn a_reseed_due_signature_draw_follows_the_live_drbg_policy() {
        use crate::library::tpm2::crypto::CTR_DRBG_MAX_REQUESTS_PER_RESEED;

        fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
            Err(crate::library::constants::TPM_FAIL)
        }
        fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x1d;
            }
            Ok(())
        }

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.entropy = failing_entropy;
        let before = signing_snapshot(&runtime);
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                key,
                &sha256(),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            )),
            RC_NO_RESULT
        );
        assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
        assert!(!runtime.failure_mode);
        assert_eq!(signing_snapshot(&runtime), before, "nothing was published");

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.entropy = deterministic_entropy;
        assert_eq!(
            response_code(&sign(
                &mut runtime,
                key,
                &sha256(),
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256
            )),
            RC_SUCCESS
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, 2,
            "one automatic reseed and one nonce draw"
        );
        assert!(!runtime.entropy_bad);
    }

    #[test]
    fn a_profile_disabled_scheme_or_hash_is_reported_against_the_scheme_parameter() {
        const RC_PARAM2_HASH: u32 = 0x2c3;
        for (dropped, scheme, hash_alg, expected) in [
            (
                "ecschnorr",
                TPM_ALG_ECSCHNORR,
                TPM_ALG_SHA256,
                RC_PARAM2_SCHEME,
            ),
            ("sha512", TPM_ALG_ECDSA, TPM_ALG_SHA512, RC_PARAM2_HASH),
        ] {
            let mut runtime = profile_runtime(&without(dropped), "");
            let (key, _) = create_primary(
                &mut runtime,
                TPM_RH_OWNER,
                &ecc_template(TPM_ALG_NULL_ID, 0, SIGN_ATTRS, &NULL_SYMMETRIC),
            );
            assert_eq!(
                response_code(&sign(
                    &mut runtime,
                    key,
                    &digest_of(hash_alg, b"abc"),
                    scheme,
                    hash_alg
                )),
                expected,
                "{dropped} disabled"
            );
        }
    }

    #[test]
    fn a_loaded_signing_object_is_resolved_from_both_stores() {
        let mut runtime = persistent_runtime();
        let persistent = signing_object(&runtime, PERSISTENT)
            .expect("the persistent object resolves")
            .expect("a signing object");
        assert!(is_signing_object(&persistent));
        assert!(signing_object(&runtime, TRANSIENT[0]).is_err());

        let (transient, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(TPM_ALG_ECDSA, TPM_ALG_SHA256, SIGN_ATTRS, &NULL_SYMMETRIC),
        );
        let loaded = signing_object(&runtime, transient)
            .expect("the transient object resolves")
            .expect("a signing object");
        assert!(is_signing_object(&loaded));
        assert_ne!(loaded.name, persistent.name);
    }

    #[test]
    fn a_transient_and_a_persistent_copy_of_one_key_sign_identically() {
        let digest = sha256();
        let mut transient = asym_runtime();
        let from_transient = sign(&mut transient, TRANSIENT[0], &digest, TPM_ALG_NULL_ID, 0);
        let mut persistent = persistent_runtime();
        let from_persistent = sign(&mut persistent, PERSISTENT, &digest, TPM_ALG_NULL_ID, 0);
        assert_eq!(response_code(&from_transient), RC_SUCCESS);
        assert_eq!(response_code(&from_persistent), RC_SUCCESS);
        assert_eq!(
            response_parameters(&from_transient),
            response_parameters(&from_persistent)
        );
    }

    #[test]
    fn a_loaded_body_carries_the_expected_attributes() {
        let runtime = misc_runtime();
        let x509 = loaded_body(&runtime, TRANSIENT[0]);
        assert_ne!(x509.public.object_attributes & TPMA_OBJECT_X509_SIGN, 0);
        let plain = loaded_body(&runtime, TRANSIENT[1]);
        assert_eq!(plain.public.object_attributes & TPMA_OBJECT_X509_SIGN, 0);
        assert_eq!(plain.public.object_attributes & TPMA_OBJECT_RESTRICTED, 0);
        let restricted = loaded_body(&mixed_runtime(), TRANSIENT[0]);
        assert_ne!(
            restricted.public.object_attributes & TPMA_OBJECT_RESTRICTED,
            0
        );
    }

    #[track_caller]
    fn loaded_body(runtime: &Tpm2Runtime, handle: u32) -> Box<OwnedObjectBody> {
        use crate::library::tpm2::object_create::occupied_object_slot;
        let slot = occupied_object_slot(runtime, handle).expect("a loaded object");
        match &runtime.live.objects[slot].body {
            OwnedAnyObjectBody::Object(body) => body.clone(),
            _ => panic!("the handle names a key"),
        }
    }
}
