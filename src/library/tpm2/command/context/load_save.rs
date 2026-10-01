// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/ContextCommands.c
// - libtpms/src/tpm2/Context_spt.c
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

use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_HIERARCHY, TPM_RC_INTEGRITY, TPM_RC_OBJECT_MEMORY,
    TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::context::{
    CONTEXT_ENCRYPT_ALG, CONTEXT_INTEGRITY_HASH_ALG, ContextIntegrityInput, FINGERPRINT_SIZE,
    INTEGRITY_SIZE, SAVED_OBJECT, SAVED_SEQUENCE, SAVED_ST_CLEAR, context_integrity,
    context_protection_key, fingerprint, parse_session_image, session_image,
};
use crate::library::tpm2::crypto::{
    recover_rsa_private_exponent, sym_cfb_decrypt, sym_cfb_encrypt,
};
use crate::library::tpm2::hierarchy::{TPM_RH_NULL, hierarchy_proof, is_hierarchy_handle};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::nv::any_object_image;
use crate::library::tpm2::nv::layout::{
    CONTEXT_INTEGRITY_HASH_SIZE, SIZEOF_OBJECT, SIZEOF_SESSION, SIZEOF_TPM2B_DIGEST,
};
use crate::library::tpm2::object::{
    ATTR_OCCUPIED, ATTR_PRIVATE_EXP, ATTR_PUBLIC_ONLY, ATTR_ST_CLEAR,
};
use crate::library::tpm2::object_create::{
    empty_object_slots, hierarchy_is_enabled, is_transient_object_handle, occupied_object_slot,
    owned_prime,
};
use crate::library::tpm2::object_load::{add_modifier, parse_object_context_image};
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::persistent::{
    OwnedAnyObjectBody, OwnedPrivateExponent, OwnedPublicId, OwnedSecret,
};
use crate::library::tpm2::public::{PublicParms, StateFormatLimit, TPM_ALG_RSA};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::sequence::sequence_kind;
use crate::library::tpm2::session::{
    is_session_handle, loaded_session, sequence_number_for_saved_context_is_valid,
    session_context_load, session_context_save,
};
use crate::library::tpm2::template::TemplateReader;
use crate::library::tpm2::volatile::volatile_object_version;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_CONTEXT: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_CONTEXT_DATA: usize = SIZEOF_TPM2B_DIGEST + 2 + 2680;
const TPM_PT_MAX_OBJECT_CONTEXT_SIZE: usize = 92 + SIZEOF_OBJECT;

struct SavedContext {
    sequence: u64,
    saved_handle: u32,
    hierarchy: u32,
    payload: Vec<u8>,
}

fn proof_for(runtime: &Tpm2Runtime, hierarchy: u32) -> Result<Vec<u8>, TpmResult> {
    if hierarchy == TPM_RH_NULL {
        return Ok(runtime
            .live
            .state_reset
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .null_proof
            .as_bytes()
            .to_vec());
    }
    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    hierarchy_proof(persistent, hierarchy)
        .map(<[u8]>::to_vec)
        .ok_or(TPM_RC_FAILURE)
}

fn ensure_private_exponent(runtime: &mut Tpm2Runtime, slot: usize) -> Result<(), TpmResult> {
    let entry = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    if entry.attributes & (ATTR_PUBLIC_ONLY | ATTR_PRIVATE_EXP) != 0 {
        return Ok(());
    }
    let OwnedAnyObjectBody::Object(body) = &entry.body else {
        return Ok(());
    };
    if body.public.object_type != TPM_ALG_RSA {
        return Ok(());
    }
    let PublicParms::Rsa { exponent, .. } = &body.public.parameters else {
        return Err(TPM_RC_FAILURE);
    };
    let OwnedPublicId::Rsa(modulus) = &body.public.unique else {
        return Err(TPM_RC_FAILURE);
    };
    let prime = body
        .sensitive
        .sensitive
        .as_ref()
        .map_or(&[][..], OwnedSecret::as_bytes);
    let recovered =
        recover_rsa_private_exponent(modulus, prime, *exponent).ok_or(TPM_RC_FAILURE)?;
    let private_exponent = OwnedPrivateExponent {
        primes: [
            owned_prime(recovered.q),
            owned_prime(recovered.d_p),
            owned_prime(recovered.d_q),
            owned_prime(recovered.q_inv),
        ],
        runtime: crate::library::tpm2::crypto::RsaRuntimeCache::default(),
    };
    let entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    if let OwnedAnyObjectBody::Object(body) = &mut entry.body {
        body.private_exponent = Some(private_exponent);
    }
    entry.attributes |= ATTR_PRIVATE_EXP;
    Ok(())
}

fn save_object(runtime: &mut Tpm2Runtime, handle: u32) -> Result<SavedContext, TpmResult> {
    let slot = occupied_object_slot(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    ensure_private_exponent(runtime, slot)?;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let object_version = volatile_object_version(state.profile.state_format_level)?;
    let entry = runtime.live.objects.get(slot).ok_or(TPM_RC_FAILURE)?;
    let payload = any_object_image(entry, object_version)?;
    let attributes = entry.attributes;
    let hierarchy = match &entry.body {
        OwnedAnyObjectBody::Object(body) => body.hierarchy.unwrap_or(TPM_RH_NULL),
        _ => TPM_RH_NULL,
    };
    let saved_handle = if sequence_kind(attributes).is_some() {
        SAVED_SEQUENCE
    } else if attributes & ATTR_ST_CLEAR != 0 {
        SAVED_ST_CLEAR
    } else {
        SAVED_OBJECT
    };
    let reset = runtime.live.state_reset.as_mut().ok_or(TPM_RC_FAILURE)?;
    let sequence = reset.object_context_id.wrapping_add(1);
    if sequence == 0 {
        return Err(TPM_RC_FAILURE);
    }
    reset.object_context_id = sequence;
    Ok(SavedContext {
        sequence,
        saved_handle,
        hierarchy,
        payload,
    })
}

fn save_session(runtime: &mut Tpm2Runtime, handle: u32) -> Result<SavedContext, TpmResult> {
    let session = loaded_session(&runtime.live, handle)
        .ok_or(TPM_RC_FAILURE)?
        .clone();
    let payload = session_image(&session)?;
    let sequence = session_context_save(&mut runtime.live, handle)?;
    Ok(SavedContext {
        sequence,
        saved_handle: handle,
        hierarchy: TPM_RH_NULL,
        payload,
    })
}

pub(in crate::library::tpm2::command) fn execute_save(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let save_handle = handle_at(frame, 0)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    let orderly_state = prepare_clear_orderly(runtime)?;

    let saved = if is_transient_object_handle(save_handle) {
        save_object(runtime, save_handle)?
    } else {
        save_session(runtime, save_handle)?
    };

    let mut blob = vec![0u8; INTEGRITY_SIZE + FINGERPRINT_SIZE + saved.payload.len()];
    blob[INTEGRITY_SIZE..INTEGRITY_SIZE + FINGERPRINT_SIZE]
        .copy_from_slice(&fingerprint(saved.sequence));
    blob[INTEGRITY_SIZE + FINGERPRINT_SIZE..].copy_from_slice(&saved.payload);

    let proof = proof_for(runtime, saved.hierarchy)?;
    let protection = context_protection_key(&proof, saved.sequence, saved.saved_handle)?;
    sym_cfb_encrypt(
        CONTEXT_ENCRYPT_ALG,
        &protection.key,
        &protection.iv,
        &mut blob[INTEGRITY_SIZE..],
    )?;

    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let total_reset_count = state.persistent.total_reset_count;
    let clear_count = runtime
        .live
        .state_reset
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .clear_count;
    let integrity = context_integrity(&ContextIntegrityInput {
        proof: &proof,
        total_reset_count,
        clear_count,
        sequence: saved.sequence,
        saved_handle: saved.saved_handle,
        protected: &blob[INTEGRITY_SIZE..],
    })?;
    blob[..2].copy_from_slice(&(integrity.len() as u16).to_be_bytes());
    blob[2..INTEGRITY_SIZE].copy_from_slice(&integrity);

    commit_clear_orderly(runtime, orderly_state)?;

    let mut writer = BlobWriter::new();
    writer.write_u64(saved.sequence);
    writer.write_u32(saved.saved_handle);
    writer.write_u32(saved.hierarchy);
    writer.write_tpm2b(&blob).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

struct LoadedContext {
    sequence: u64,
    saved_handle: u32,
    hierarchy: u32,
    blob: Vec<u8>,
}

fn parse_context(parameters: &[u8]) -> Result<LoadedContext, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let sequence = reader
        .u64()
        .map_err(|code| add_modifier(code, RC_CONTEXT))?;
    let saved_handle = reader
        .u32()
        .map_err(|code| add_modifier(code, RC_CONTEXT))?;
    if !matches!(saved_handle, SAVED_OBJECT | SAVED_SEQUENCE | SAVED_ST_CLEAR)
        && !is_session_handle(saved_handle)
    {
        return Err(TPM_RC_VALUE + RC_CONTEXT);
    }
    let hierarchy = reader
        .u32()
        .map_err(|code| add_modifier(code, RC_CONTEXT))?;
    if !is_hierarchy_handle(hierarchy) {
        return Err(TPM_RC_VALUE + RC_CONTEXT);
    }
    let blob = reader
        .tpm2b(MAX_CONTEXT_DATA)
        .map_err(|code| add_modifier(code, RC_CONTEXT))?
        .to_vec();
    if !reader.remaining().is_empty() && parameters.len() != TPM_PT_MAX_OBJECT_CONTEXT_SIZE {
        return Err(TPM_RC_SIZE);
    }
    Ok(LoadedContext {
        sequence,
        saved_handle,
        hierarchy,
        blob,
    })
}

fn recover_payload(runtime: &Tpm2Runtime, context: &LoadedContext) -> Result<Vec<u8>, TpmResult> {
    let mut reader = TemplateReader::new(&context.blob);
    let integrity = reader
        .tpm2b(CONTEXT_INTEGRITY_HASH_SIZE)
        .map_err(|_| TPM_RC_SIZE + RC_CONTEXT)?
        .to_vec();
    if integrity.len() != CONTEXT_INTEGRITY_HASH_SIZE {
        return Err(TPM_RC_SIZE + RC_CONTEXT);
    }
    let protected_start = reader.consumed();
    if context.blob.len() - protected_start < FINGERPRINT_SIZE {
        return Err(TPM_RC_SIZE + RC_CONTEXT);
    }
    let proof = proof_for(runtime, context.hierarchy)?;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let clear_count = runtime
        .live
        .state_reset
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .clear_count;
    let expected = context_integrity(&ContextIntegrityInput {
        proof: &proof,
        total_reset_count: state.persistent.total_reset_count,
        clear_count,
        sequence: context.sequence,
        saved_handle: context.saved_handle,
        protected: &context.blob[protected_start..],
    })?;
    if !crate::library::tpm2::session::digests_equal(&integrity, &expected) {
        return Err(TPM_RC_INTEGRITY + RC_CONTEXT);
    }
    let protection = context_protection_key(&proof, context.sequence, context.saved_handle)?;
    let mut payload = context.blob[protected_start..].to_vec();
    sym_cfb_decrypt(
        CONTEXT_ENCRYPT_ALG,
        &protection.key,
        &protection.iv,
        &mut payload,
    )?;
    if payload[..FINGERPRINT_SIZE] != fingerprint(context.sequence) {
        return Err(TPM_RC_FAILURE);
    }
    Ok(payload.split_off(FINGERPRINT_SIZE))
}

fn load_object(
    runtime: &mut Tpm2Runtime,
    context: &LoadedContext,
    payload: &[u8],
) -> Result<u32, TpmResult> {
    if payload.len() > SIZEOF_OBJECT {
        return Err(TPM_RC_FAILURE);
    }
    if !hierarchy_is_enabled(runtime, context.hierarchy) {
        return Err(TPM_RC_HIERARCHY + RC_CONTEXT);
    }
    let (slot, handle) = empty_object_slots(runtime)
        .next()
        .ok_or(TPM_RC_OBJECT_MEMORY)?;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let state_format = StateFormatLimit::new(state.profile.state_format_level);
    let object = parse_object_context_image(payload, state_format).ok_or(TPM_RC_OBJECT_MEMORY)?;
    if object.attributes & ATTR_OCCUPIED == 0 {
        return Err(TPM_RC_OBJECT_MEMORY);
    }
    let entry = runtime.live.objects.get_mut(slot).ok_or(TPM_RC_FAILURE)?;
    *entry = object;
    Ok(handle)
}

fn load_session(
    runtime: &mut Tpm2Runtime,
    context: &LoadedContext,
    payload: &[u8],
) -> Result<u32, TpmResult> {
    if payload.len() != SIZEOF_SESSION {
        return Err(TPM_RC_FAILURE);
    }
    let orderly_state = prepare_clear_orderly(runtime)?;
    if !sequence_number_for_saved_context_is_valid(
        &runtime.live,
        context.saved_handle,
        context.sequence,
    ) {
        return Err(TPM_RC_HANDLE + RC_CONTEXT);
    }
    let session = parse_session_image(payload)?;
    session_context_load(&mut runtime.live, context.saved_handle, session)?;
    commit_clear_orderly(runtime, orderly_state)?;
    Ok(context.saved_handle)
}

pub(in crate::library::tpm2::command) fn execute_load(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let context = parse_context(frame.parameters)?;
    let payload = recover_payload(runtime, &context)?;
    let handle = if is_session_handle(context.saved_handle) {
        load_session(runtime, &context, &payload)?
    } else {
        load_object(runtime, &context, &payload)?
    };
    Ok(CommandOutput::with_handle(handle, Vec::new()))
}

const _: () = {
    assert!(CONTEXT_INTEGRITY_HASH_ALG == crate::library::tpm2::public::TPM_ALG_SHA512);
    assert!(INTEGRITY_SIZE == 2 + CONTEXT_INTEGRITY_HASH_SIZE);
};

#[cfg(test)]
mod tests {

    use crate::library::tpm2::object_load::replay::*;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const CC_SAVE: u32 = 0x0000_0162;
    const CC_LOAD: u32 = 0x0000_0161;
    const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    const CC_HASH_SEQUENCE_START: u32 = 0x0000_0186;
    const CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
    const CC_POLICY_AUTH_VALUE: u32 = 0x0000_016b;

    fn start_auth_session(session_type: u8) -> Vec<u8> {
        let mut payload = handles(&[RH_NULL, RH_NULL]);
        push_tpm2b(&mut payload, &[0x5a; 32]);
        push_tpm2b(&mut payload, &[]);
        payload.push(session_type);
        payload.extend_from_slice(&0x0010u16.to_be_bytes());
        payload.extend_from_slice(&0x000bu16.to_be_bytes());
        plain(CC_START_AUTH_SESSION, &payload)
    }

    fn hash_sequence_start() -> Vec<u8> {
        let mut payload = Vec::new();
        push_tpm2b(&mut payload, &[]);
        payload.extend_from_slice(&0x000bu16.to_be_bytes());
        plain(CC_HASH_SEQUENCE_START, &payload)
    }

    fn synthetic_context(saved_handle: u32, hierarchy: u32, blob: &[u8]) -> Vec<u8> {
        let mut payload = 0u64.to_be_bytes().to_vec();
        payload[7] = 1;
        payload.extend_from_slice(&saved_handle.to_be_bytes());
        payload.extend_from_slice(&hierarchy.to_be_bytes());
        payload.extend_from_slice(&tpm2b(blob));
        context_load(&payload)
    }

    fn occupied(runtime: &Tpm2Runtime) -> Vec<bool> {
        runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & 0x8000 != 0)
            .collect()
    }

    #[test]
    fn external_object_context_save_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        let public = rsa_sign_public(&external_modulus());
        exec_raw(&mut runtime, &clock, load_external(&[], &public, RH_NULL));
        exec_raw(&mut runtime, &clock, load_external(&[], &public, RH_OWNER));
        exec_raw(
            &mut runtime,
            &clock,
            load_external(&[], &public, RH_PLATFORM),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_EXTERNAL_RSA",
            context_save(0x8000_0000),
        );
    }

    #[test]
    fn primary_object_context_save_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_PRIMARY",
            context_save(0x8000_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "CAP_TRANSIENT_AFTER_CTXSAVE",
            cap_transient(),
        );
    }

    #[test]
    fn loaded_child_context_save_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_LOAD", &clock);
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_LOADED_AES",
            context_save(0x8000_0001),
        );
    }

    #[test]
    fn sequence_object_context_save_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "HASH_SEQUENCE_START",
            hash_sequence_start(),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_SEQUENCE",
            context_save(0x8000_0000),
        );
    }

    #[test]
    fn session_context_save_oracle_match() {
        for (session_type, handle, label) in [
            (0x00u8, 0x0200_0000u32, "CTXSAVE_HMAC_SESSION"),
            (0x01, 0x0300_0000, "CTXSAVE_POLICY_SESSION"),
            (0x03, 0x0300_0000, "CTXSAVE_TRIAL_SESSION"),
        ] {
            let clock = clock();
            let mut runtime = runtime_at("READY", &clock);
            exec_raw(&mut runtime, &clock, start_auth_session(session_type));
            exec(&mut runtime, &clock, label, context_save(handle));
            assert_eq!(
                runtime.live.free_session_slots, 3,
                "{label} releases the loaded slot"
            );
        }
    }

    #[test]
    fn repeated_session_save_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec_raw(&mut runtime, &clock, start_auth_session(0x00));
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_HMAC_SESSION",
            context_save(0x0200_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_HMAC_AGAIN",
            context_save(0x0200_0000),
        );
    }

    #[test]
    fn context_save_rejection_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        for (label, command) in [
            ("CTXSAVE_UNLOADED_OBJECT", context_save(0x8000_0000)),
            ("CTXSAVE_UNLOADED_SESSION", context_save(0x0200_0000)),
            (
                "CTXSAVE_BAD_HANDLE",
                plain(CC_SAVE, &RH_OWNER.to_be_bytes()),
            ),
            (
                "CTXSAVE_PERSISTENT_HANDLE",
                plain(CC_SAVE, &0x8100_0000u32.to_be_bytes()),
            ),
            ("CTXSAVE_TRAILING", {
                let mut payload = 0x8000_0000u32.to_be_bytes().to_vec();
                payload.push(0x00);
                plain(CC_SAVE, &payload)
            }),
            (
                "CTXSAVE_WITH_SESSION",
                sessioned(CC_SAVE, &[0x8000_0000], &[], &[]),
            ),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
    }

    #[test]
    fn context_load_rejection_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        for (label, command) in [
            ("CTXLOAD_EMPTY", plain(CC_LOAD, &[])),
            (
                "CTXLOAD_TRUNCATED",
                plain(CC_LOAD, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            ),
            (
                "CTXLOAD_BAD_SAVED_HANDLE",
                synthetic_context(0x8100_0000, RH_NULL, &[0x00; 80]),
            ),
            (
                "CTXLOAD_BAD_HIERARCHY",
                synthetic_context(0x8000_0000, RH_LOCKOUT, &[0x00; 80]),
            ),
            ("CTXLOAD_SHORT_INTEGRITY", {
                let mut blob = 4u16.to_be_bytes().to_vec();
                blob.extend_from_slice(&[0x00; 4]);
                synthetic_context(0x8000_0000, RH_NULL, &blob)
            }),
            ("CTXLOAD_NO_FINGERPRINT", {
                let mut blob = 64u16.to_be_bytes().to_vec();
                blob.extend_from_slice(&[0x00; 68]);
                synthetic_context(0x8000_0000, RH_NULL, &blob)
            }),
            ("CTXLOAD_ZERO_INTEGRITY", {
                let mut blob = 64u16.to_be_bytes().to_vec();
                blob.extend_from_slice(&[0x00; 72]);
                synthetic_context(0x8000_0000, RH_NULL, &blob)
            }),
            ("CTXLOAD_STALE_SESSION", {
                let mut blob = 64u16.to_be_bytes().to_vec();
                blob.extend_from_slice(&[0x00; 384]);
                synthetic_context(0x0200_0000, RH_NULL, &blob)
            }),
            ("CTXLOAD_WITH_SESSION", {
                let mut parameters = 0u64.to_be_bytes().to_vec();
                parameters[7] = 1;
                parameters.extend_from_slice(&0x8000_0000u32.to_be_bytes());
                parameters.extend_from_slice(&RH_NULL.to_be_bytes());
                parameters.extend_from_slice(&tpm2b(&[0x00; 80]));
                sessioned(CC_LOAD, &[], &[], &parameters)
            }),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
    }

    #[test]
    fn object_context_round_trip_replay() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_PRIMARY", &clock);
        let context = saved_context("CTXSAVE_PRIMARY");
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_PRIMARY",
            context_load(&context),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_RESTORED_PRIMARY",
            read_public(0x8000_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_PRIMARY_REPLAY",
            context_load(&context),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_PRIMARY_THIRD",
            context_load(&context),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_PRIMARY_NO_SLOT",
            context_load(&context),
        );
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn corrupted_object_context_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_PRIMARY", &clock);
        let context = saved_context("CTXSAVE_PRIMARY");
        let mutate = |index: usize, mask: u8| {
            let mut copy = context.clone();
            copy[index] ^= mask;
            copy
        };
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_PRIMARY_CORRUPT_BLOB",
            context_load(&mutate(100, 0x01)),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_PRIMARY_CORRUPT_INTEGRITY",
            context_load(&mutate(20, 0x80)),
        );
        exec(&mut runtime, &clock, "CTXLOAD_PRIMARY_WRONG_SEQUENCE", {
            let mut copy = context.clone();
            copy[7] = 2;
            context_load(&copy)
        });
        exec(&mut runtime, &clock, "CTXLOAD_PRIMARY_WRONG_HIERARCHY", {
            let mut copy = context.clone();
            copy[12..16].copy_from_slice(&RH_NULL.to_be_bytes());
            context_load(&copy)
        });
        exec(&mut runtime, &clock, "CTXLOAD_PRIMARY_SHORT_BLOB", {
            let mut copy = context[..16].to_vec();
            copy.extend_from_slice(&tpm2b(&context[18..context.len() - 1]));
            context_load(&copy)
        });
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_EXTERNAL_RSA",
            context_load(&saved_context("CTXSAVE_EXTERNAL_RSA")),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_SEQUENCE",
            context_load(&saved_context("CTXSAVE_SEQUENCE")),
        );
    }

    #[test]
    fn session_context_round_trip_replay_rejection() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_HMAC", &clock);
        let context = saved_context("CTXSAVE_HMAC_SESSION");
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_HMAC_SESSION",
            context_load(&context),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_HMAC_REPLAY",
            context_load(&context),
        );
        exec(
            &mut runtime,
            &clock,
            "CTXSAVE_HMAC_ROUNDTRIP",
            context_save(0x0200_0000),
        );
    }

    #[test]
    fn policy_session_context_state_restoration() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_POLICY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_POLICY_SESSION",
            context_load(&saved_context("CTXSAVE_POLICY_SESSION")),
        );
        exec(
            &mut runtime,
            &clock,
            "POLICY_GET_DIGEST_RESTORED",
            plain(CC_POLICY_GET_DIGEST, &0x0300_0000u32.to_be_bytes()),
        );

        let mut runtime = runtime_at("AFTER_CTXSAVE_TRIAL", &clock);
        exec(
            &mut runtime,
            &clock,
            "CTXLOAD_TRIAL_SESSION",
            context_load(&saved_context("CTXSAVE_TRIAL_SESSION")),
        );
        exec(
            &mut runtime,
            &clock,
            "POLICY_AUTH_VALUE_RESTORED",
            plain(CC_POLICY_AUTH_VALUE, &0x0300_0000u32.to_be_bytes()),
        );
        exec(
            &mut runtime,
            &clock,
            "POLICY_GET_DIGEST_TRIAL",
            plain(CC_POLICY_GET_DIGEST, &0x0300_0000u32.to_be_bytes()),
        );
    }

    #[test]
    fn session_context_reinterpretation_corruption_rejection() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_HMAC", &clock);
        let context = saved_context("CTXSAVE_HMAC_SESSION");
        exec(&mut runtime, &clock, "CTXLOAD_HMAC_AS_OBJECT", {
            let mut copy = context.clone();
            copy[8..12].copy_from_slice(&0x8000_0000u32.to_be_bytes());
            context_load(&copy)
        });
        exec(&mut runtime, &clock, "CTXLOAD_HMAC_CORRUPT", {
            let mut copy = context.clone();
            copy[200] ^= 0x01;
            context_load(&copy)
        });
    }

    #[test]
    fn context_blob_prefix_and_mutation_panic_safety() {
        let clock = clock();
        let context = saved_context("CTXSAVE_HMAC_SESSION");
        for length in 0..context.len().min(64) {
            let mut runtime = runtime_at("AFTER_CTXSAVE_HMAC", &clock);
            let _ = exec_raw(&mut runtime, &clock, context_load(&context[..length]));
        }
        for index in [0usize, 7, 8, 11, 12, 15, 16, 17, 18, 40, 90, 300] {
            for mask in [0x01u8, 0x80, 0xff] {
                let mut runtime = runtime_at("AFTER_CTXSAVE_HMAC", &clock);
                let mut copy = context.clone();
                copy[index] ^= mask;
                let _ = exec_raw(&mut runtime, &clock, context_load(&copy));
            }
        }
    }
}

#[cfg(test)]
mod tracking_tests {
    use crate::library::tpm2::object_load::replay::*;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::state::MAX_ACTIVE_SESSIONS;

    const CC_SAVE: u32 = 0x0000_0162;
    const CC_LOAD: u32 = 0x0000_0161;
    const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
    const NO_OLDEST: u32 = MAX_ACTIVE_SESSIONS as u32 + 1;

    fn start_hmac_session(nonce: u8) -> Vec<u8> {
        let mut payload = handles(&[RH_NULL, RH_NULL]);
        push_tpm2b(&mut payload, &[nonce; 32]);
        push_tpm2b(&mut payload, &[]);
        payload.push(0x00);
        payload.extend_from_slice(&0x0010u16.to_be_bytes());
        payload.extend_from_slice(&0x000bu16.to_be_bytes());
        plain(CC_START_AUTH_SESSION, &payload)
    }

    fn context_array(runtime: &Tpm2Runtime) -> Vec<u16> {
        runtime
            .live
            .state_reset
            .as_ref()
            .expect("state reset data")
            .context_array
            .to_vec()
    }

    fn context_counter(runtime: &Tpm2Runtime) -> u64 {
        runtime
            .live
            .state_reset
            .as_ref()
            .expect("state reset data")
            .context_counter
    }

    #[track_caller]
    fn assert_tracking_is_consistent(runtime: &Tpm2Runtime) {
        let array = context_array(runtime);
        let loaded = array
            .iter()
            .filter(|&&entry| entry != 0 && usize::from(entry) <= runtime.live.sessions.len())
            .count();
        let occupied = runtime
            .live
            .sessions
            .iter()
            .filter(|slot| slot.occupied)
            .count();
        assert_eq!(loaded, occupied, "context array agrees with the slot table");
        assert_eq!(
            runtime.live.free_session_slots as usize,
            runtime.live.sessions.len() - occupied,
            "the free slot count agrees with the slot table"
        );
        let saved: Vec<usize> = array
            .iter()
            .enumerate()
            .filter(|(_, entry)| usize::from(**entry) > runtime.live.sessions.len())
            .map(|(index, _)| index)
            .collect();
        if saved.is_empty() {
            assert_eq!(runtime.live.oldest_saved_session, NO_OLDEST);
        } else {
            assert!(saved.contains(&(runtime.live.oldest_saved_session as usize)));
        }
    }

    #[test]
    fn session_save_slot_release_and_counter_advance() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec_raw(&mut runtime, &clock, start_hmac_session(0x5a));
        assert_eq!(runtime.live.free_session_slots, 2);
        let before = context_counter(&runtime);
        exec_raw(&mut runtime, &clock, context_save(0x0200_0000));
        assert_eq!(runtime.live.free_session_slots, 3);
        assert_eq!(context_counter(&runtime), before + 1);
        assert_eq!(runtime.live.oldest_saved_session, 0);
        assert_tracking_is_consistent(&runtime);
    }

    #[test]
    fn saved_session_state_round_trip() {
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{attach_volatile_blob, restore_permanent_blob_for_test};

        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec_raw(&mut runtime, &clock, start_hmac_session(0x5a));
        let saved = exec_raw(&mut runtime, &clock, context_save(0x0200_0000));
        assert_eq!(saved[6..10], [0, 0, 0, 0], "the save succeeds");

        let permanent = persistent_all_store(runtime.state.as_ref().expect("state"))
            .expect("the permanent state serializes");
        let volatile = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let mut restored =
            restore_permanent_blob_for_test(&permanent).expect("the permanent state restores");
        attach_volatile_blob(&mut restored, &volatile, &clock)
            .expect("the volatile state attaches");

        assert_eq!(context_array(&restored), context_array(&runtime));
        assert_eq!(context_counter(&restored), context_counter(&runtime));
        assert_eq!(
            restored.live.oldest_saved_session,
            runtime.live.oldest_saved_session
        );
        assert_eq!(
            restored.live.free_session_slots,
            runtime.live.free_session_slots
        );
        assert_tracking_is_consistent(&restored);

        let context = response_parameters(&saved);
        let loaded = exec_raw(&mut restored, &clock, context_load(&context));
        assert_eq!(loaded[6..10], [0, 0, 0, 0], "the restored context loads");
        assert_tracking_is_consistent(&restored);
    }

    #[test]
    fn rejected_load_session_tracking_unchanged() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_HMAC", &clock);
        let before_array = context_array(&runtime);
        let before_counter = context_counter(&runtime);
        let before_free = runtime.live.free_session_slots;
        let before_oldest = runtime.live.oldest_saved_session;

        let mut corrupted = saved_context("CTXSAVE_HMAC_SESSION");
        corrupted[200] ^= 0x01;
        let response = exec_raw(&mut runtime, &clock, context_load(&corrupted));
        assert_ne!(response[6..10], [0, 0, 0, 0], "the load fails");

        assert_eq!(context_array(&runtime), before_array);
        assert_eq!(context_counter(&runtime), before_counter);
        assert_eq!(runtime.live.free_session_slots, before_free);
        assert_eq!(runtime.live.oldest_saved_session, before_oldest);
        assert_tracking_is_consistent(&runtime);
    }

    #[test]
    fn rejected_save_loaded_session_preservation() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec_raw(&mut runtime, &clock, start_hmac_session(0x5a));
        let before_array = context_array(&runtime);
        let before_counter = context_counter(&runtime);

        let mut command = 0x0200_0000u32.to_be_bytes().to_vec();
        command.push(0x00);
        let response = exec_raw(&mut runtime, &clock, plain(CC_SAVE, &command));
        assert_ne!(response[6..10], [0, 0, 0, 0], "trailing bytes are rejected");

        assert_eq!(context_array(&runtime), before_array);
        assert_eq!(context_counter(&runtime), before_counter);
        assert_eq!(runtime.live.free_session_slots, 2);
        assert_tracking_is_consistent(&runtime);
    }

    #[test]
    fn saved_session_flush_context_slot_clearing() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_HMAC", &clock);
        assert_eq!(runtime.live.oldest_saved_session, 0);
        let response = exec_raw(
            &mut runtime,
            &clock,
            plain(CC_FLUSH_CONTEXT, &0x0200_0000u32.to_be_bytes()),
        );
        assert_eq!(response[6..10], [0, 0, 0, 0], "the flush succeeds");
        assert_eq!(context_array(&runtime)[0], 0);
        assert_eq!(runtime.live.oldest_saved_session, NO_OLDEST);
        assert_tracking_is_consistent(&runtime);
    }

    #[test]
    fn failed_object_load_no_slot_occupation() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CTXSAVE_PRIMARY", &clock);
        let mut corrupted = saved_context("CTXSAVE_PRIMARY");
        corrupted[100] ^= 0x01;
        let before: Vec<u32> = runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes)
            .collect();
        let response = exec_raw(&mut runtime, &clock, context_load(&corrupted));
        assert_ne!(response[6..10], [0, 0, 0, 0], "the load fails");
        let after: Vec<u32> = runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes)
            .collect();
        assert_eq!(after, before, "no slot is touched");
        assert_eq!(
            after.iter().filter(|&&value| value & 0x8000 != 0).count(),
            1,
            "only the still-loaded primary occupies a slot"
        );
    }

    #[test]
    fn object_round_trip_saved_object_match() {
        use crate::library::tpm2::nv::any_object_image;
        use crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION;

        let clock = clock();
        let mut source = runtime_at("AFTER_CREATE", &clock);
        let before = any_object_image(&source.live.objects[0], CURRENT_OBJECT_VERSION)
            .expect("the object serializes");
        let saved = exec_raw(&mut source, &clock, context_save(0x8000_0000));
        assert_eq!(saved[6..10], [0, 0, 0, 0], "the save succeeds");

        let mut target = runtime_at("AFTER_CTXSAVE_PRIMARY", &clock);
        let loaded = exec_raw(
            &mut target,
            &clock,
            context_load(&response_parameters(&saved)),
        );
        assert_eq!(loaded[6..10], [0, 0, 0, 0], "the load succeeds");
        let after = any_object_image(&target.live.objects[0], CURRENT_OBJECT_VERSION)
            .expect("the object serializes");
        assert_eq!(after, before, "the restored object is byte-identical");
    }

    #[test]
    fn truncated_command_load_panic_safety() {
        let clock = clock();
        let context = saved_context("CTXSAVE_PRIMARY");
        for length in 0..40 {
            let mut runtime = runtime_at("AFTER_CTXSAVE_PRIMARY", &clock);
            let _ = exec_raw(&mut runtime, &clock, plain(CC_LOAD, &context[..length]));
        }
    }
}
