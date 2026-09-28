// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/ObjectCommands.c
// - libtpms/src/tpm2/Object_spt.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2024
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::create_loaded::{object_hierarchy, resolve_parent};
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_HIERARCHY, TPM_RC_OBJECT_MEMORY,
    TPM_RC_SIZE, TPM_RC_TYPE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::TPM_RH_NULL;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object::ATTR_IS_PARENT;
use crate::library::tpm2::object_create::{empty_object_slots, hierarchy_is_enabled};
use crate::library::tpm2::object_load::{
    ParentContext, add_modifier, object_load, public_marshal_and_compute_name,
    read_sized_sensitive_area, store_child_object, store_external_object,
};
use crate::library::tpm2::object_wrap::{MAX_PRIVATE, private_to_sensitive};
use crate::library::tpm2::persistent::OwnedTpmtPublic;
use crate::library::tpm2::public::StateFormatLimit;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::{
    AlgorithmPolicy, TPMA_OBJECT_FIXED_PARENT, TPMA_OBJECT_FIXED_TPM, TPMA_OBJECT_RESTRICTED,
    TemplateReader, parse_public_area,
};
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_PARENT_HANDLE: TpmResult = TPM_RC_1;
const RC_IN_PRIVATE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_PUBLIC: TpmResult = TPM_RC_P + TPM_RC_1 * 2;
const RC_HIERARCHY: TpmResult = TPM_RC_P + TPM_RC_1 * 3;

pub(in crate::library::tpm2::command) fn algorithm_policy(
    runtime: &Tpm2Runtime,
) -> Result<AlgorithmPolicy<'_>, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    Ok(AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    })
}

pub(in crate::library::tpm2::command) fn parse_sized_public(
    reader: &mut TemplateReader<'_>,
    policy: &AlgorithmPolicy<'_>,
    allow_null_name_alg: bool,
) -> Result<OwnedTpmtPublic, TpmResult> {
    let declared = usize::from(reader.u16()?);
    if declared == 0 {
        return Err(TPM_RC_SIZE);
    }
    let start = reader.consumed();
    let public = parse_public_area(reader, policy, allow_null_name_alg)?;
    if reader.consumed() - start != declared {
        return Err(TPM_RC_SIZE);
    }
    Ok(public)
}

fn parent_context(
    runtime: &Tpm2Runtime,
    parent_handle: u32,
) -> Result<(ParentContext, bool), TpmResult> {
    let parent = resolve_parent(runtime, parent_handle)?.ok_or(TPM_RC_FAILURE)?;
    let body = parent.body.as_deref().ok_or(TPM_RC_FAILURE)?;
    Ok((
        ParentContext {
            slot_attributes: parent.slot_attributes,
            public: body.public.clone(),
            seed_value: body.sensitive.seed_value.as_bytes().to_vec(),
            hierarchy: object_hierarchy(body, parent.slot_attributes),
            qualified_name: body.qualified_name.clone(),
            seed_compat_level: body.seed_compat_level,
        },
        parent.persistent,
    ))
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parent_handle = handle_at(frame, 0)?;
    let policy = algorithm_policy(runtime)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let in_private = reader
        .tpm2b(MAX_PRIVATE)
        .map_err(|code| add_modifier(code, RC_IN_PRIVATE))?
        .to_vec();
    let public = parse_sized_public(&mut reader, &policy, false)
        .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let (parent, parent_is_persistent) = parent_context(runtime, parent_handle)?;
    let (slot, object_handle) = {
        let mut free_slots = empty_object_slots(runtime);
        if parent_is_persistent {
            free_slots.next();
        }
        free_slots.next().ok_or(TPM_RC_OBJECT_MEMORY)?
    };
    if in_private.is_empty() {
        return Err(TPM_RC_SIZE + RC_IN_PRIVATE);
    }
    if parent.slot_attributes & ATTR_IS_PARENT == 0 {
        return Err(TPM_RC_TYPE + RC_PARENT_HANDLE);
    }

    let name = public_marshal_and_compute_name(&public)?;
    if name.is_empty() {
        return Err(TPM_RC_HASH + RC_IN_PUBLIC);
    }
    let sensitive = private_to_sensitive(&in_private, &name, &parent.protector())
        .map_err(|code| add_modifier(code, RC_IN_PRIVATE))?;

    let loaded = object_load(
        Some(&parent),
        public,
        Some(sensitive),
        RC_IN_PUBLIC,
        RC_IN_PRIVATE,
        name.clone(),
    )?;
    store_child_object(runtime, slot, &parent, loaded)?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&name).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::with_handle(
        object_handle,
        writer.into_bytes(),
    ))
}

pub(in crate::library::tpm2::command) fn execute_external(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let policy = algorithm_policy(runtime)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let sensitive =
        read_sized_sensitive_area(&mut reader).map_err(|code| add_modifier(code, RC_IN_PRIVATE))?;
    let public = parse_sized_public(&mut reader, &policy, true)
        .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
    let hierarchy = reader
        .u32()
        .map_err(|code| add_modifier(code, RC_HIERARCHY))?;
    if !crate::library::tpm2::hierarchy::is_hierarchy_handle(hierarchy) {
        return Err(crate::library::constants::TPM_RC_VALUE + RC_HIERARCHY);
    }
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let (slot, object_handle) = empty_object_slots(runtime)
        .next()
        .ok_or(TPM_RC_OBJECT_MEMORY)?;
    if !hierarchy_is_enabled(runtime, hierarchy) {
        return Err(TPM_RC_HIERARCHY + RC_HIERARCHY);
    }
    if sensitive.is_some() {
        if hierarchy != TPM_RH_NULL {
            return Err(TPM_RC_HIERARCHY + RC_HIERARCHY);
        }
        if public.object_attributes
            & (TPMA_OBJECT_FIXED_TPM | TPMA_OBJECT_FIXED_PARENT | TPMA_OBJECT_RESTRICTED)
            != 0
        {
            return Err(TPM_RC_ATTRIBUTES + RC_IN_PUBLIC);
        }
    }

    let name = public_marshal_and_compute_name(&public)?;
    let loaded = object_load(
        None,
        public,
        sensitive,
        RC_IN_PUBLIC,
        RC_IN_PRIVATE,
        name.clone(),
    )?;
    store_external_object(runtime, slot, hierarchy, loaded)?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&name).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::with_handle(
        object_handle,
        writer.into_bytes(),
    ))
}

#[cfg(test)]
mod tests {

    use crate::library::tpm2::command::core::test_support::occupied;
    use crate::library::tpm2::object::{ATTR_EXTERNAL, ATTR_PUBLIC_ONLY, ATTR_TEMPORARY};
    use crate::library::tpm2::object_load::replay::*;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const TPM_CC_LOAD: u32 = 0x0000_0157;
    const TPM_CC_LOAD_EXTERNAL: u32 = 0x0000_0167;

    fn sealed_public(attributes: u32) -> Vec<u8> {
        keyed_hash_public(&seal_unique(), attributes)
    }

    fn sealed_sensitive() -> Vec<u8> {
        keyed_hash_sensitive(&seal_seed(), SEAL_DATA, b"ext-auth")
    }

    #[test]
    fn public_only_external_key_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        let public = rsa_sign_public(&external_modulus());
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_RSA_NULL",
            load_external(&[], &public, RH_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_RSA_NULL",
            read_public(0x8000_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_RSA_OWNER",
            load_external(&[], &public, RH_OWNER),
        );
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_RSA_PLATFORM",
            load_external(&[], &public, RH_PLATFORM),
        );
        exec(
            &mut runtime,
            &clock,
            "CAP_TRANSIENT_AFTER_EXTERNAL",
            cap_transient(),
        );
        assert_eq!(occupied(&runtime), [true, true, true]);
        for slot in 0..3 {
            let attributes = runtime.live.objects[slot].attributes;
            assert_ne!(attributes & ATTR_EXTERNAL, 0, "slot {slot} is external");
            assert_ne!(
                attributes & ATTR_PUBLIC_ONLY,
                0,
                "slot {slot} is public only"
            );
        }
        assert_ne!(runtime.live.objects[0].attributes & ATTR_TEMPORARY, 0);
        assert_eq!(runtime.live.objects[1].attributes & ATTR_TEMPORARY, 0);
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_NO_SLOT",
            load_external(&[], &public, RH_NULL),
        );
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn external_qualified_name_identity() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        let public = rsa_sign_public(&external_modulus());
        exec_raw(&mut runtime, &clock, load_external(&[], &public, RH_NULL));
        let response = exec_raw(&mut runtime, &clock, read_public(0x8000_0000));
        let parameters = response_parameters(&response);
        let public_len = u16::from_be_bytes(parameters[..2].try_into().unwrap()) as usize;
        let rest = &parameters[2 + public_len..];
        let name_len = u16::from_be_bytes(rest[..2].try_into().unwrap()) as usize;
        let name = &rest[2..2 + name_len];
        let qualified = &rest[2 + name_len..];
        assert_eq!(&qualified[..2], &(name_len as u16).to_be_bytes());
        assert_eq!(&qualified[2..], name);
    }

    #[test]
    fn external_rejection_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        let public = rsa_sign_public(&external_modulus());
        for (label, command) in [
            (
                "LOADEXT_SENSITIVE_OWNER",
                load_external(&sealed_sensitive(), &sealed_public(0x0000_0440), RH_OWNER),
            ),
            (
                "LOADEXT_SENSITIVE_FIXEDTPM",
                load_external(&sealed_sensitive(), &sealed_public(0x0000_0452), RH_NULL),
            ),
            (
                "LOADEXT_SENSITIVE_FIXEDPARENT",
                load_external(&sealed_sensitive(), &sealed_public(0x0000_0450), RH_NULL),
            ),
            (
                "LOADEXT_SENSITIVE_RESTRICTED",
                load_external(&sealed_sensitive(), &sealed_public(0x0001_0440), RH_NULL),
            ),
            (
                "LOADEXT_BAD_HIERARCHY",
                load_external(&[], &public, RH_LOCKOUT),
            ),
            ("LOADEXT_EMPTY_PUBLIC", {
                let mut payload = tpm2b(&[]);
                payload.extend_from_slice(&0u16.to_be_bytes());
                payload.extend_from_slice(&RH_NULL.to_be_bytes());
                plain(TPM_CC_LOAD_EXTERNAL, &payload)
            }),
            (
                "LOADEXT_TRUNCATED",
                vec![
                    0x80, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x01, 0x67, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
            ),
            ("LOADEXT_TRAILING", {
                let mut payload = tpm2b(&[]);
                payload.extend_from_slice(&tpm2b(&public));
                payload.extend_from_slice(&RH_NULL.to_be_bytes());
                payload.push(0x00);
                plain(TPM_CC_LOAD_EXTERNAL, &payload)
            }),
            ("LOADEXT_PASSWORD_SESSION", {
                let mut parameters = tpm2b(&[]);
                parameters.extend_from_slice(&tpm2b(&public));
                parameters.extend_from_slice(&RH_NULL.to_be_bytes());
                sessioned(TPM_CC_LOAD_EXTERNAL, &[], &[], &parameters)
            }),
            (
                "LOADEXT_KEYEDHASH_BAD_SCHEME",
                load_external(
                    &[],
                    &keyed_hash_public(&empty_sha256(), 0x0004_0440),
                    RH_NULL,
                ),
            ),
            (
                "LOADEXT_RSA_SHORT_MODULUS",
                load_external(&[], &rsa_sign_public(&external_modulus()[..128]), RH_NULL),
            ),
            ("LOADEXT_RSA_LOW_MODULUS", {
                let mut modulus = external_modulus();
                modulus[0] = 0x01;
                load_external(&[], &rsa_sign_public(&modulus), RH_NULL)
            }),
            ("LOADEXT_SENSITIVE_TYPE_MISMATCH", {
                let mut sensitive = 0x0001u16.to_be_bytes().to_vec();
                push_tpm2b(&mut sensitive, &[]);
                push_tpm2b(&mut sensitive, &seal_seed());
                push_tpm2b(&mut sensitive, SEAL_DATA);
                load_external(&sensitive, &sealed_public(0x0000_0440), RH_NULL)
            }),
            (
                "LOADEXT_SENSITIVE_BAD_BINDING",
                load_external(
                    &keyed_hash_sensitive(&seal_seed(), b"other payload", &[]),
                    &sealed_public(0x0000_0440),
                    RH_NULL,
                ),
            ),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
        assert_eq!(occupied(&runtime), [false, false, false]);
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes == 0),
            "a failed load leaves no residue in any slot"
        );
    }

    fn empty_sha256() -> Vec<u8> {
        let hasher = crate::library::tpm2::crypto::Hasher::new(0x000b).expect("sha256");
        hasher.finalize()
    }

    #[test]
    fn external_sealed_object_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_SEALED_NULL",
            load_external(&sealed_sensitive(), &sealed_public(0x0000_0440), RH_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_SEALED_NULL",
            read_public(0x8000_0000),
        );
        assert_eq!(runtime.live.objects[0].attributes & ATTR_PUBLIC_ONLY, 0);
        assert_ne!(runtime.live.objects[0].attributes & ATTR_EXTERNAL, 0);
    }

    #[test]
    fn created_child_load_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let (aes_private, aes_public) = created_child("CREATE_AES_CHILD");
        let (sealed_private, sealed_public) = created_child("CREATE_SEALED_CHILD");
        exec(
            &mut runtime,
            &clock,
            "LOAD_AES_CHILD",
            load(0x8000_0000, &[], &aes_private, &aes_public),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_LOADED_AES",
            read_public(0x8000_0001),
        );
        exec(
            &mut runtime,
            &clock,
            "LOAD_SEALED_CHILD",
            load(0x8000_0000, &[], &sealed_private, &sealed_public),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_LOADED_SEALED",
            read_public(0x8000_0002),
        );
        exec(
            &mut runtime,
            &clock,
            "CAP_TRANSIENT_AFTER_LOAD",
            cap_transient(),
        );
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn load_rejection_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let (_, aes_public) = created_child("CREATE_AES_CHILD");
        let aes_template = &aes_public;
        for (label, command) in [
            (
                "LOAD_EMPTY_PRIVATE",
                load(0x8000_0000, &[], &[], &rsa_sign_public(&external_modulus())),
            ),
            ("LOAD_EMPTY_PUBLIC", {
                let mut parameters = tpm2b(&[0x11; 70]);
                parameters.extend_from_slice(&0u16.to_be_bytes());
                sessioned(TPM_CC_LOAD, &[0x8000_0000], &[], &parameters)
            }),
            (
                "LOAD_CORRUPT_PRIVATE",
                load(0x8000_0000, &[], &[0x00; 70], aes_template),
            ),
            ("LOAD_TRAILING", {
                let mut parameters = tpm2b(&[0x00; 70]);
                parameters.extend_from_slice(&tpm2b(aes_template));
                parameters.push(0x00);
                sessioned(TPM_CC_LOAD, &[0x8000_0000], &[], &parameters)
            }),
            (
                "LOAD_TRUNCATED",
                vec![
                    0x80, 0x02, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x01, 0x57, 0x80, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00,
                    0x00,
                ],
            ),
            ("LOAD_NO_SESSIONS", {
                let mut payload = handles(&[0x8000_0000]);
                payload.extend_from_slice(&tpm2b(&[0x00; 70]));
                payload.extend_from_slice(&tpm2b(aes_template));
                plain(TPM_CC_LOAD, &payload)
            }),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn post_load_reference_state_reproduction() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let (aes_private, aes_public) = created_child("CREATE_AES_CHILD");
        let (sealed_private, sealed_public) = created_child("CREATE_SEALED_CHILD");
        exec_raw(
            &mut runtime,
            &clock,
            load(0x8000_0000, &[], &aes_private, &aes_public),
        );
        exec_raw(
            &mut runtime,
            &clock,
            load(0x8000_0000, &[], &sealed_private, &sealed_public),
        );
        assert_object_slots_match(&runtime, "AFTER_LOAD");
    }

    #[track_caller]
    fn assert_object_slots_match(runtime: &Tpm2Runtime, snapshot: &str) {
        use crate::library::tpm2::nv::any_object_image;
        use crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION;
        let expected = crate::library::tpm2::object_load::replay::decode_volatile(snapshot);
        let images = |objects: &[crate::library::tpm2::persistent::OwnedAnyObject]| {
            objects
                .iter()
                .map(|object| {
                    any_object_image(object, CURRENT_OBJECT_VERSION).expect("the object serializes")
                })
                .collect::<Vec<Vec<u8>>>()
        };
        assert_eq!(
            images(&runtime.live.objects),
            images(&expected.objects),
            "object slots at {snapshot}"
        );
    }
}

#[cfg(test)]
mod encryption_tests {
    use crate::library::tpm2::object_load::replay::*;

    fn nonce() -> Vec<u8> {
        session_nonce_tpm("SAS_ENC")
    }

    fn srk_name() -> Vec<u8> {
        object_name(&primary_public("CP_SRK"))
    }

    fn sealed_child_name() -> Vec<u8> {
        object_name(&created_public("CREATE_SEALED_CHILD"))
    }

    #[test]
    fn encrypting_session_creation_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let (private, public) = created_child("CREATE_SEALED_CHILD");
        exec_raw(
            &mut runtime,
            &clock,
            load(0x8000_0000, &[], &private, &public),
        );
        exec(&mut runtime, &clock, "SAS_ENC", encrypting_session());
    }

    #[test]
    fn parameter_encryption_oracle_match() {
        let clock = clock();
        let (aes_private, aes_public) = created_child("CREATE_AES_CHILD");
        let mut load_parameters = tpm2b(&aes_private);
        load_parameters.extend_from_slice(&tpm2b(&aes_public));

        let mut runtime = runtime_at("AFTER_SAS_ENC", &clock);
        exec(
            &mut runtime,
            &clock,
            "LOAD_ENCRYPTED",
            EncryptedCommand {
                code: CC_LOAD,
                handle_list: &[0x8000_0000],
                names: &[srk_name()],
                parameters: load_parameters,
                session_value: &[],
                attributes: 0x61,
                nonce_tpm: nonce(),
            }
            .build(),
        );

        let mut runtime = runtime_at("AFTER_SAS_ENC", &clock);
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_ENCRYPTED",
            EncryptedCommand {
                code: CC_UNSEAL,
                handle_list: &[0x8000_0001],
                names: &[sealed_child_name()],
                parameters: Vec::new(),
                session_value: b"seal-auth",
                attributes: 0x41,
                nonce_tpm: nonce(),
            }
            .build(),
        );

        let mut runtime = runtime_at("AFTER_SAS_ENC", &clock);
        exec(
            &mut runtime,
            &clock,
            "OCA_ENCRYPTED",
            EncryptedCommand {
                code: CC_OBJECT_CHANGE_AUTH,
                handle_list: &[0x8000_0001, 0x8000_0000],
                names: &[sealed_child_name(), srk_name()],
                parameters: tpm2b(b"rotated-auth"),
                session_value: b"seal-auth",
                attributes: 0x61,
                nonce_tpm: nonce(),
            }
            .build(),
        );

        let mut runtime = runtime_at("AFTER_SAS_ENC", &clock);
        let mut external_parameters = tpm2b(&[]);
        external_parameters.extend_from_slice(&tpm2b(&rsa_sign_public(&external_modulus())));
        external_parameters.extend_from_slice(&RH_NULL.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_ENCRYPTED",
            EncryptedCommand {
                code: CC_LOAD_EXTERNAL,
                handle_list: &[],
                names: &[],
                parameters: external_parameters,
                session_value: &[],
                attributes: 0x61,
                nonce_tpm: nonce(),
            }
            .build(),
        );
    }
}
