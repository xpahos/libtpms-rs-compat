// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/EACommands.c
// - libtpms/src/tpm2/PCR.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::session::{PolicySession, extend_policy_digest, policy_session};
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_PCR_CHANGED, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{algorithm_enabled, hash_profile_name};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::TPM_CC_POLICY_PCR;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_P};
use crate::library::tpm2::marshal::{BlobReader, BlobWriter, Tpm2bError};
use crate::library::tpm2::pcr::{HASH_COUNT, PCR_SELECT_MAX, PCR_SELECT_MIN, bank_slot};
use crate::library::tpm2::persistent::OwnedPcrAllocation;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::{digests_equal, loaded_session_mut};
use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;
use crate::types::TpmResult;

const RC_POLICY_PCR_PCR_DIGEST: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_POLICY_PCR_PCRS: TpmResult = TPM_RC_P + TPM_RC_2;

const MAX_DIGEST_SIZE: usize = 64;

struct Selection {
    hash_alg: u16,
    select: Vec<u8>,
}

struct PolicyPcrIn<'a> {
    pcr_digest: &'a [u8],
    selections: Vec<Selection>,
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<PolicyPcrIn<'a>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let pcr_digest = reader
        .read_tpm2b(MAX_DIGEST_SIZE)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_POLICY_PCR_PCR_DIGEST,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_POLICY_PCR_PCR_DIGEST,
        })?;

    let count = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_POLICY_PCR_PCRS)?;
    if count > HASH_COUNT as u32 {
        return Err(TPM_RC_SIZE + RC_POLICY_PCR_PCRS);
    }
    let mut selections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let hash_alg = reader
            .read_u16()
            .map_err(|_| TPM_RC_INSUFFICIENT + RC_POLICY_PCR_PCRS)?;
        let enabled = bank_slot(hash_alg).is_some()
            && hash_profile_name(hash_alg)
                .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
        if !enabled {
            return Err(TPM_RC_HASH + RC_POLICY_PCR_PCRS);
        }
        let sizeof_select = usize::from(
            reader
                .read_u8()
                .map_err(|_| TPM_RC_INSUFFICIENT + RC_POLICY_PCR_PCRS)?,
        );
        if !(PCR_SELECT_MIN..=PCR_SELECT_MAX).contains(&sizeof_select) {
            return Err(TPM_RC_VALUE + RC_POLICY_PCR_PCRS);
        }
        let select = reader
            .take(sizeof_select)
            .map_err(|_| TPM_RC_INSUFFICIENT + RC_POLICY_PCR_PCRS)?
            .to_vec();
        selections.push(Selection { hash_alg, select });
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(PolicyPcrIn {
        pcr_digest,
        selections,
    })
}

fn filter(selection: &mut Selection, allocation: &OwnedPcrAllocation) {
    let allocated = allocation
        .selections
        .iter()
        .find(|entry| entry.hash_alg == selection.hash_alg);
    for (index, byte) in selection.select.iter_mut().enumerate() {
        *byte &= allocated
            .and_then(|entry| entry.select.get(index))
            .copied()
            .unwrap_or(0);
    }
}

fn is_selected(selection: &Selection, pcr: usize) -> bool {
    selection
        .select
        .get(pcr / 8)
        .is_some_and(|byte| byte & (1 << (pcr % 8)) != 0)
}

fn marshal_selections(selections: &[Selection]) -> Vec<u8> {
    let mut writer = BlobWriter::new();
    writer.write_u32(selections.len() as u32);
    for selection in selections {
        writer.write_u16(selection.hash_alg);
        writer.write_u8(selection.select.len() as u8);
        writer.write_bytes(&selection.select);
    }
    writer.into_bytes()
}

fn compute_current_digest(
    runtime: &mut Tpm2Runtime,
    session: &PolicySession,
    selections: &mut [Selection],
) -> Result<Vec<u8>, TpmResult> {
    let mut hasher = crate::library::tpm2::command::policy::session::start_policy_hash(
        runtime,
        session.hash_alg,
    )?;
    let allocation = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
    for selection in selections.iter_mut() {
        filter(selection, allocation);
        let (slot, digest_size) = bank_slot(selection.hash_alg).ok_or(TPM_RC_FAILURE)?;
        for pcr in 0..IMPLEMENTATION_PCR {
            if !is_selected(selection, pcr) {
                continue;
            }
            let bank = runtime
                .live
                .pcrs
                .get(pcr)
                .and_then(|entry| entry.banks.get(slot))
                .and_then(Option::as_ref)
                .ok_or(TPM_RC_FAILURE)?;
            if bank.len() != digest_size {
                return Err(TPM_RC_FAILURE);
            }
            hasher.update(bank);
        }
    }
    Ok(hasher.finalize())
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let mut input = {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    let mut pcr_digest = compute_current_digest(runtime, &session, &mut input.selections)?;
    let pcr_counter = runtime
        .live
        .state_reset
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .pcr_counter;

    if session.is_trial {
        if !input.pcr_digest.is_empty() {
            pcr_digest = input.pcr_digest.to_vec();
        }
    } else {
        let recorded = crate::library::tpm2::session::loaded_session(&runtime.live, session.handle)
            .ok_or(TPM_RC_FAILURE)?
            .pcr_counter;
        if recorded != 0 && recorded != pcr_counter {
            return Err(TPM_RC_PCR_CHANGED);
        }
        if !input.pcr_digest.is_empty() && !digests_equal(input.pcr_digest, &pcr_digest) {
            return Err(TPM_RC_VALUE + RC_POLICY_PCR_PCR_DIGEST);
        }
    }

    let marshaled = marshal_selections(&input.selections);
    extend_policy_digest(
        runtime,
        &session,
        TPM_CC_POLICY_PCR,
        &[&marshaled, &pcr_digest],
    )?;

    if !session.is_trial {
        loaded_session_mut(&mut runtime.live, session.handle)
            .ok_or(TPM_RC_FAILURE)?
            .pcr_counter = pcr_counter;
    }
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, TAIL_BYTES, command, dispatch_bytes, for_each_mutation, response_code,
        truncated_tail_replacements,
    };
    use crate::library::tpm2::command::policy::session::test_support::{
        CC_POLICY_PCR, POLICY_SESSION_0, digest, restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;

    const ALG_SHA1: u16 = 0x0004;
    const ALG_SHA256: u16 = 0x000b;
    const ALG_SHA384: u16 = 0x000c;
    const ALG_SHA512: u16 = 0x000d;
    const ALG_NULL: u16 = 0x0010;

    const SELECT_PCR0: [u8; 3] = [0x01, 0x00, 0x00];
    const SELECT_ALL: [u8; 3] = [0xff, 0xff, 0xff];

    fn parameters(pcr_digest: &[u8], selections: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = (pcr_digest.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(pcr_digest);
        out.extend_from_slice(&(selections.len() as u32).to_be_bytes());
        for (hash_alg, select) in selections {
            out.extend_from_slice(&hash_alg.to_be_bytes());
            out.push(select.len() as u8);
            out.extend_from_slice(select);
        }
        out
    }

    #[track_caller]
    fn policy_pcr(runtime: &mut Tpm2Runtime, parameters: &[u8]) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(CC_POLICY_PCR, &[POLICY_SESSION_0], &[], parameters),
        )
    }

    fn pcr0_sha256_digest() -> Vec<u8> {
        let read = vector("PCR_READ_SHA256_PCR0");
        let value = &read[read.len() - 32..];
        let mut hasher = crate::library::tpm2::crypto::Hasher::new(ALG_SHA256).expect("sha256");
        hasher.update(value);
        hasher.finalize()
    }

    #[test]
    fn current_pcr_read_shared_bank_code() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(0x0000_017e, &[], &[], &{
                    let mut out = 1u32.to_be_bytes().to_vec();
                    out.extend_from_slice(&ALG_SHA256.to_be_bytes());
                    out.push(3);
                    out.extend_from_slice(&SELECT_PCR0);
                    out
                })
            ),
            vector("PCR_READ_SHA256_PCR0")
        );
    }

    #[test]
    fn empty_selection_policy_extension() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_pcr(&mut runtime, &parameters(&[], &[])),
            vector("PPCR_EMPTY_SELECTION")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_EMPTY_SELECTION"));
    }

    #[test]
    fn single_bank_selection_counter_capture() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("PPCR_SHA256_PCR0")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_SHA256_PCR0"));
        let counter = runtime
            .live
            .state_reset
            .as_ref()
            .expect("state reset present")
            .pcr_counter;
        assert_eq!(session_of(&runtime, POLICY_SESSION_0).pcr_counter, counter);
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("PPCR_REPEATED")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_REPEATED_PCR"));
    }

    #[test]
    fn allocated_bank_simultaneous_selection_acceptance() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(
                    &[],
                    &[
                        (ALG_SHA1, &SELECT_ALL),
                        (ALG_SHA256, &SELECT_ALL),
                        (ALG_SHA384, &SELECT_ALL),
                        (ALG_SHA512, &SELECT_ALL),
                    ]
                )
            ),
            vector("PPCR_MULTI_BANK")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_MULTI_BANK"));
    }

    #[test]
    fn explicit_digest_match_requirement() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&pcr0_sha256_digest(), &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("PPCR_EXPLICIT_DIGEST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_EXPLICIT_DIGEST"));
        assert_eq!(
            vector("PGD_AFTER_EXPLICIT_DIGEST"),
            vector("PGD_AFTER_SHA256_PCR0"),
            "an explicit digest that matches produces the same policy"
        );
    }

    #[test]
    fn rejected_selection_and_digest_oracle_parity() {
        let mut runtime = restored("POLICY_FRESH");
        for (record, request) in [
            (
                "PPCR_WRONG_DIGEST",
                parameters(&[0u8; 32], &[(ALG_SHA256, &SELECT_PCR0)]),
            ),
            (
                "PPCR_SHORT_DIGEST",
                parameters(&[0u8; 20], &[(ALG_SHA256, &SELECT_PCR0)]),
            ),
            (
                "PPCR_OVERSIZED_DIGEST",
                parameters(&[0u8; 65], &[(ALG_SHA256, &SELECT_PCR0)]),
            ),
            (
                "PPCR_UNKNOWN_BANK",
                parameters(&[], &[(0x0005, &SELECT_PCR0)]),
            ),
            (
                "PPCR_NULL_BANK",
                parameters(&[], &[(ALG_NULL, &SELECT_PCR0)]),
            ),
            (
                "PPCR_SHORT_SELECT",
                parameters(&[], &[(ALG_SHA256, &[0x01, 0x00])]),
            ),
            (
                "PPCR_LONG_SELECT",
                parameters(&[], &[(ALG_SHA256, &[0x01, 0x00, 0x00, 0x00])]),
            ),
            ("PPCR_TOO_MANY_BANKS", {
                let mut out = 0u16.to_be_bytes().to_vec();
                out.extend_from_slice(&5u32.to_be_bytes());
                out
            }),
            ("PPCR_TRUNCATED", {
                let mut out = 0u16.to_be_bytes().to_vec();
                out.extend_from_slice(&1u32.to_be_bytes());
                out
            }),
            ("PPCR_TRAILING", {
                let mut out = parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)]);
                out.push(0x00);
                out
            }),
        ] {
            assert_eq!(
                policy_pcr(&mut runtime, &request),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_PCR_FAILURES"));
    }

    #[test]
    fn pcr_change_counter_invalidation() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("PPCR_SHA256_PCR0")
        );
        let mut extend = 1u32.to_be_bytes().to_vec();
        extend.extend_from_slice(&ALG_SHA256.to_be_bytes());
        extend.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0182, &[0x0000_0000], &[&[][..]], &extend)
            )),
            RC_SUCCESS
        );
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("PPCR_AFTER_PCR_CHANGE")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_PCR_CHANGE"));
    }

    #[test]
    fn trial_session_supplied_digest_acceptance() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("TRIAL_PPCR_EMPTY_DIGEST")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_PCR"));

        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[0u8; 32], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("TRIAL_PPCR_EXPLICIT_DIGEST")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_EXPLICIT_PCR"));
        assert_eq!(
            session_of(&runtime, POLICY_SESSION_0).pcr_counter,
            0,
            "a trial session never captures the counter"
        );
    }

    #[test]
    fn rejected_request_session_unchanged() {
        let mut runtime = restored("POLICY_FRESH");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for request in [
            parameters(&[0u8; 32], &[(ALG_SHA256, &SELECT_PCR0)]),
            parameters(&[], &[(0x0005, &SELECT_PCR0)]),
            parameters(&[], &[(ALG_SHA256, &[0x01, 0x00])]),
            parameters(&[0u8; 65], &[(ALG_SHA256, &SELECT_PCR0)]),
        ] {
            assert_ne!(
                response_code(&policy_pcr(&mut runtime, &request)),
                RC_SUCCESS
            );
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.pcr_counter, before.pcr_counter);
            assert_eq!(after.attributes, before.attributes);
        }
    }

    #[test]
    fn success_digest_counter_only_mutation() {
        let mut runtime = restored("POLICY_FRESH");
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        assert_eq!(
            policy_pcr(
                &mut runtime,
                &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)])
            ),
            vector("PPCR_SHA256_PCR0")
        );
        let after = session_of(&runtime, POLICY_SESSION_0);
        assert_ne!(after.audit_digest, before.audit_digest);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.command_code, before.command_code);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
        assert_eq!(after.start_time, before.start_time);
    }

    #[test]
    fn canonical_selection_pre_digest_filtering() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(
            policy_pcr(&mut runtime, &parameters(&[], &[(ALG_SHA256, &SELECT_ALL)])),
            vector("PPCR_ALL_PCRS")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_ALL_PCRS"));
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let valid = command(
            CC_POLICY_PCR,
            &[POLICY_SESSION_0],
            &[],
            &parameters(&[], &[(ALG_SHA256, &SELECT_PCR0)]),
        );
        for_each_mutation(
            "TPM2_PolicyPCR",
            truncated_tail_replacements(&valid, 10, &TAIL_BYTES),
            |bytes| {
                let _ = dispatch_bytes(&mut restored("POLICY_FRESH"), &bytes);
            },
        );
    }
}
