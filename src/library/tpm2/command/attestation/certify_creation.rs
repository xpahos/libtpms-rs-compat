// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/Attest_spt.c
// - libtpms/src/tpm2/AttestationCommands.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2018
// (c) Copyright IBM Corp. and others, 2016 - 2021
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::builder::{
    Attested, DIGEST_MAX, check_signing_object, fill_in_attest_info, parse_qualifying_data,
    parse_scheme, sign_and_respond,
};
use super::certify::certified_object;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_TAG, TPM_RC_TICKET, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_P,
};
use crate::library::tpm2::command::crypto::signing_state::{RC_SIGN_HANDLE, signing_object};
use crate::library::tpm2::command::object::create_primary::{
    TPM_ST_CREATION, compute_creation_ticket,
};
use crate::library::tpm2::hierarchy::{
    TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
};
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::digests_equal;
use crate::library::tpm2::signature::{SigScheme, select_sign_scheme};
use crate::library::tpm2::template::TemplateReader;
use crate::types::TpmResult;

const RC_QUALIFYING_DATA: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_CREATION_HASH: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_CREATION_TICKET: TpmResult = TPM_RC_P + TPM_RC_4;

struct Ticket {
    hierarchy: u32,
    digest: Vec<u8>,
}

struct Parameters {
    qualifying_data: Vec<u8>,
    creation_hash: Vec<u8>,
    scheme: SigScheme,
    ticket: Ticket,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sign_handle = handle_at(frame, 0)?;
    let object_handle = handle_at(frame, 1)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, sign_handle)?;
    check_signing_object(sign_object.as_deref(), RC_SIGN_HANDLE)?;
    let scheme = select_sign_scheme(sign_object.as_deref(), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    let certified = certified_object(runtime, object_handle)?;
    let recomputed = compute_creation_ticket(
        runtime,
        parameters.ticket.hierarchy,
        &certified.name,
        &parameters.creation_hash,
    )?;
    if !digests_equal(&recomputed, &parameters.ticket.digest) {
        return Err(TPM_RC_TICKET + RC_CREATION_TICKET);
    }

    let attested = Attested::Creation {
        object_name: certified.name.clone(),
        creation_hash: parameters.creation_hash.clone(),
    };
    let attest = fill_in_attest_info(
        runtime,
        sign_object.as_deref(),
        &scheme,
        &parameters.qualifying_data,
        attested,
    )?;
    sign_and_respond(runtime, sign_object.as_deref(), &scheme, &attest)
}

fn parse_parameters(
    parameters: &[u8],
    profile: &ValidatedProfile,
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let qualifying_data = parse_qualifying_data(&mut reader, RC_QUALIFYING_DATA)?;
    let creation_hash = reader
        .tpm2b(DIGEST_MAX)
        .map_err(|code| code + RC_CREATION_HASH)?
        .to_vec();
    let scheme = parse_scheme(&mut reader, profile, RC_IN_SCHEME)?;
    let ticket = parse_ticket(&mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        qualifying_data,
        creation_hash,
        scheme,
        ticket,
    })
}

fn parse_ticket(reader: &mut TemplateReader<'_>) -> Result<Ticket, TpmResult> {
    let tag = reader.u16().map_err(|code| code + RC_CREATION_TICKET)?;
    if tag != TPM_ST_CREATION {
        return Err(TPM_RC_TAG + RC_CREATION_TICKET);
    }
    let hierarchy = reader.u32().map_err(|code| code + RC_CREATION_TICKET)?;
    if !matches!(
        hierarchy,
        TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
    ) {
        return Err(TPM_RC_VALUE + RC_CREATION_TICKET);
    }
    let digest = reader
        .tpm2b(DIGEST_MAX)
        .map_err(|code| code + RC_CREATION_TICKET)?
        .to_vec();
    Ok(Ticket { hierarchy, digest })
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::attestation::builder::test_support::{
        ALG_NULL, ALG_RSASSA, ALG_SHA256, KEY0, QUALIFY, SIGN_ATTRS, TPM_RH_ENDORSEMENT,
        TPM_RH_NULL, TPM_RH_OWNER, attest_prefix, attested_body, attested_bytes, command,
        create_primary, creation_ticket, pw, ready_runtime, replay_clock, rsa_template, run,
        sig_scheme, tpm2b,
    };
    use crate::library::tpm2::command::core::registry::TPM_CC_CERTIFY_CREATION;
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, REPLACEMENT_BYTES, byte_replacements, for_each_mutation, response_code,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const RC_PARAM2_SIZE: u32 = 0x2d5;
    const RC_PARAM4_TICKET: u32 = 0x4e0;
    const RC_PARAM4_TAG: u32 = 0x4d7;
    const RC_PARAM4_VALUE: u32 = 0x4c4;
    const RC_PARAM4_INSUFFICIENT: u32 = 0x4da;
    const RC_SIZE: u32 = 0x095;

    const TPM_ST_CREATION_TAG: u16 = 0x8021;

    #[track_caller]
    fn created_primary() -> (Tpm2Runtime, Vec<u8>, Vec<u8>) {
        let mut runtime = ready_runtime();
        let response = run(
            &mut runtime,
            &create_primary(
                TPM_RH_OWNER,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
        );
        assert_eq!(
            response,
            vector("CREATE_CERTIFIED_PRIMARY"),
            "the certified primary matches the oracle"
        );
        let (creation_hash, ticket) = creation_outputs(&response);
        (runtime, creation_hash, ticket)
    }

    #[track_caller]
    fn creation_outputs(response: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let size = u32::from_be_bytes(response[14..18].try_into().expect("four bytes")) as usize;
        let parameters = &response[18..18 + size];
        let mut at = 0;
        for _ in 0..2 {
            let length = u16::from_be_bytes([parameters[at], parameters[at + 1]]) as usize;
            at += 2 + length;
        }
        let hash_len = u16::from_be_bytes([parameters[at], parameters[at + 1]]) as usize;
        let creation_hash = parameters[at + 2..at + 2 + hash_len].to_vec();
        at += 2 + hash_len;
        let digest_len = u16::from_be_bytes([parameters[at + 6], parameters[at + 7]]) as usize;
        let ticket = parameters[at..at + 8 + digest_len].to_vec();
        (creation_hash, ticket)
    }

    fn certify_creation_command(
        sign: u32,
        object: u32,
        qualifying: &[u8],
        creation_hash: &[u8],
        scheme: u16,
        ticket: &[u8],
    ) -> Vec<u8> {
        let mut parameters = tpm2b(qualifying);
        parameters.extend_from_slice(&tpm2b(creation_hash));
        parameters.extend_from_slice(&sig_scheme(scheme, ALG_SHA256));
        parameters.extend_from_slice(ticket);
        command(
            TPM_CC_CERTIFY_CREATION,
            &[sign, object],
            Some(&[pw()]),
            &parameters,
        )
    }

    #[track_caller]
    fn assert_certify_creation(record: &str, sign: u32, qualifying: &[u8], scheme: u16) {
        let (mut runtime, creation_hash, ticket) = created_primary();
        let expected = vector(record);
        replay_clock(&mut runtime, expected);
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(sign, KEY0, qualifying, &creation_hash, scheme, &ticket)
            ),
            expected,
            "{record}"
        );
    }

    #[test]
    fn matching_ticket_certification_oracle_match() {
        assert_certify_creation("CERTIFY_CREATION_OK", KEY0, &QUALIFY, ALG_NULL);
        assert_certify_creation("CERTIFY_CREATION_EXPLICIT", KEY0, &QUALIFY, ALG_RSASSA);
        assert_certify_creation("CERTIFY_CREATION_NO_QUALIFYING", KEY0, &[], ALG_NULL);
        assert_certify_creation(
            "CERTIFY_CREATION_NULL_SIGNER",
            TPM_RH_NULL,
            &QUALIFY,
            ALG_NULL,
        );
    }

    #[test]
    fn attested_data_object_name_creation_hash() {
        let (mut runtime, creation_hash, ticket) = created_primary();
        let expected = vector("CERTIFY_CREATION_OK");
        replay_clock(&mut runtime, expected);
        let response = run(
            &mut runtime,
            &certify_creation_command(KEY0, KEY0, &QUALIFY, &creation_hash, ALG_NULL, &ticket),
        );
        let attest = attested_bytes(&response);
        assert_eq!(attest_prefix(&attest).0, 0x801a, "TPM_ST_ATTEST_CREATION");
        let body = attested_body(&attest);
        let name_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        let hash_len = u16::from_be_bytes([body[2 + name_len], body[3 + name_len]]) as usize;
        assert_eq!(
            &body[4 + name_len..4 + name_len + hash_len],
            &creation_hash[..],
            "the attested creation hash is the supplied one"
        );
        assert_eq!(body.len(), 4 + name_len + hash_len);
    }

    #[test]
    fn altered_hash_or_ticket_error() {
        let (mut runtime, creation_hash, ticket) = created_primary();
        let mut altered_hash = creation_hash.clone();
        altered_hash[0] ^= 0xff;
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(KEY0, KEY0, &QUALIFY, &altered_hash, ALG_NULL, &ticket)
            ),
            vector("CERTIFY_CREATION_ALTERED_HASH")
        );
        let mut altered_ticket = ticket.clone();
        altered_ticket[8] ^= 0xff;
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(
                    KEY0,
                    KEY0,
                    &QUALIFY,
                    &creation_hash,
                    ALG_NULL,
                    &altered_ticket
                )
            ),
            vector("CERTIFY_CREATION_ALTERED_TICKET")
        );
        assert_eq!(
            response_code(vector("CERTIFY_CREATION_ALTERED_HASH")),
            RC_PARAM4_TICKET
        );
        assert_eq!(
            response_code(vector("CERTIFY_CREATION_ALTERED_TICKET")),
            RC_PARAM4_TICKET
        );
    }

    #[test]
    fn foreign_hierarchy_ticket_verification_failure() {
        let (mut runtime, creation_hash, ticket) = created_primary();
        let digest = &ticket[8..];
        for (record, hierarchy) in [
            ("CERTIFY_CREATION_WRONG_HIERARCHY", TPM_RH_ENDORSEMENT),
            ("CERTIFY_CREATION_NULL_HIERARCHY", TPM_RH_NULL),
        ] {
            assert_eq!(
                run(
                    &mut runtime,
                    &certify_creation_command(
                        KEY0,
                        KEY0,
                        &QUALIFY,
                        &creation_hash,
                        ALG_NULL,
                        &creation_ticket(TPM_ST_CREATION_TAG, hierarchy, digest)
                    )
                ),
                vector(record),
                "{record}"
            );
            assert_eq!(response_code(vector(record)), RC_PARAM4_TICKET);
        }
    }

    #[test]
    fn malformed_ticket_parameter_error() {
        let (mut runtime, creation_hash, ticket) = created_primary();
        let digest = &ticket[8..];
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(
                    KEY0,
                    KEY0,
                    &QUALIFY,
                    &creation_hash,
                    ALG_NULL,
                    &creation_ticket(0x8022, TPM_RH_OWNER, digest)
                )
            ),
            vector("CERTIFY_CREATION_BAD_TAG")
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(
                    KEY0,
                    KEY0,
                    &QUALIFY,
                    &creation_hash,
                    ALG_NULL,
                    &creation_ticket(TPM_ST_CREATION_TAG, 0x4000_0005, digest)
                )
            ),
            vector("CERTIFY_CREATION_BAD_TICKET_HIERARCHY")
        );
        let mut truncated = TPM_ST_CREATION_TAG.to_be_bytes().to_vec();
        truncated.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(
                    KEY0,
                    KEY0,
                    &QUALIFY,
                    &creation_hash,
                    ALG_NULL,
                    &truncated
                )
            ),
            vector("CERTIFY_CREATION_TRUNCATED_TICKET")
        );
        assert_eq!(
            response_code(vector("CERTIFY_CREATION_BAD_TAG")),
            RC_PARAM4_TAG
        );
        assert_eq!(
            response_code(vector("CERTIFY_CREATION_BAD_TICKET_HIERARCHY")),
            RC_PARAM4_VALUE
        );
        assert_eq!(
            response_code(vector("CERTIFY_CREATION_TRUNCATED_TICKET")),
            RC_PARAM4_INSUFFICIENT
        );
    }

    #[test]
    fn parameter_limits_oracle_match() {
        let (mut runtime, creation_hash, ticket) = created_primary();
        let oversized: Vec<u8> = (0..65).collect();
        assert_eq!(
            run(
                &mut runtime,
                &certify_creation_command(KEY0, KEY0, &QUALIFY, &oversized, ALG_NULL, &ticket)
            ),
            vector("CERTIFY_CREATION_OVERSIZED_HASH")
        );
        let mut trailing =
            certify_creation_command(KEY0, KEY0, &QUALIFY, &creation_hash, ALG_NULL, &ticket);
        trailing.push(0x00);
        let size = (trailing.len() as u32).to_be_bytes();
        trailing[2..6].copy_from_slice(&size);
        assert_eq!(
            run(&mut runtime, &trailing),
            vector("CERTIFY_CREATION_TRAILING")
        );
        assert_eq!(
            response_code(vector("CERTIFY_CREATION_OVERSIZED_HASH")),
            RC_PARAM2_SIZE
        );
        assert_eq!(response_code(vector("CERTIFY_CREATION_TRAILING")), RC_SIZE);
    }

    #[test]
    fn rejected_certification_no_state_change() {
        let (mut runtime, creation_hash, ticket) = created_primary();
        run(
            &mut runtime,
            &certify_creation_command(KEY0, KEY0, &QUALIFY, &creation_hash, ALG_NULL, &ticket),
        );
        runtime.nv_update_pending = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let mut altered = creation_hash.clone();
        altered[0] ^= 0xff;
        assert_ne!(
            response_code(&run(
                &mut runtime,
                &certify_creation_command(KEY0, KEY0, &QUALIFY, &altered, ALG_NULL, &ticket)
            )),
            RC_SUCCESS
        );
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the state serializes"),
            before
        );
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let (_, creation_hash, ticket) = created_primary();
        let mut full = tpm2b(&QUALIFY);
        full.extend_from_slice(&tpm2b(&creation_hash));
        full.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        full.extend_from_slice(&ticket);
        let mut runtime = ready_runtime();
        run(
            &mut runtime,
            &create_primary(
                TPM_RH_OWNER,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
        );
        for_each_mutation(
            "TPM2_CertifyCreation",
            byte_replacements(&full, &REPLACEMENT_BYTES),
            |parameters| {
                let _ = run(
                    &mut runtime,
                    &command(
                        TPM_CC_CERTIFY_CREATION,
                        &[KEY0, KEY0],
                        Some(&[pw()]),
                        &parameters,
                    ),
                );
            },
        );
    }
}
