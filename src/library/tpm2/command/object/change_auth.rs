use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SIZE, TPM_RC_TYPE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object_create::{compute_qualified_name_from, resolve_any_object};
use crate::library::tpm2::object_wrap::{Protector, sensitive_to_private};
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedSecret};
use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::sequence::sequence_kind;
use crate::library::tpm2::session::digests_equal;
use crate::library::tpm2::template::{TemplateReader, adjusted_auth_value};
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_OBJECT_HANDLE: TpmResult = TPM_RC_1;
const RC_PARENT_HANDLE: TpmResult = TPM_RC_1 * 2;
const RC_NEW_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_AUTH_SIZE: usize = 64;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let object_handle = handle_at(frame, 0)?;
    let parent_handle = handle_at(frame, 1)?;
    let mut reader = TemplateReader::new(frame.parameters);
    let new_auth = reader
        .tpm2b(MAX_AUTH_SIZE)
        .map_err(|code| code + RC_NEW_AUTH)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let object = resolve_any_object(runtime, object_handle).ok_or(TPM_RC_FAILURE)?;
    if sequence_kind(object.attributes).is_some() {
        return Err(TPM_RC_TYPE + RC_OBJECT_HANDLE);
    }
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_TYPE + RC_OBJECT_HANDLE);
    };
    let name_alg = body.public.name_alg;
    let name = body.name.clone();
    let qualified_name = body.qualified_name.clone();
    let mut sensitive = body.sensitive.clone();

    let adjusted =
        adjusted_auth_value(&new_auth, name_alg).map_err(|_| TPM_RC_SIZE + RC_NEW_AUTH)?;

    let parent = resolve_any_object(runtime, parent_handle).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(parent_body) = &parent.body else {
        return Err(TPM_RC_TYPE + RC_PARENT_HANDLE);
    };
    let expected = compute_qualified_name_from(&parent_body.qualified_name, name_alg, &name)?;
    if !digests_equal(&qualified_name, &expected) {
        return Err(TPM_RC_TYPE + RC_PARENT_HANDLE);
    }
    let parent_public = parent_body.public.clone();
    let parent_seed = parent_body.sensitive.seed_value.as_bytes().to_vec();

    sensitive.auth_value = OwnedSecret::from_vec(adjusted);

    let mut rand = take_live_rand(runtime)?;
    let out_private = sensitive_to_private(
        &sensitive,
        &name,
        &Protector {
            public: &parent_public,
            seed_value: &parent_seed,
        },
        name_alg,
        &mut rand,
    );
    finish_live_rand(runtime, rand)?;
    let out_private = out_private?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&out_private).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::{
        self, CommandLifecycle, HandleKind, NvAccess,
    };
    use crate::library::tpm2::object_load::replay::*;
    use crate::library::tpm2::persistent::OwnedAnyObjectBody;

    const TPM_CC: u32 = 0x0000_0150;

    #[test]
    fn command_registration_upstream_attributes() {
        let descriptor = registry::find(TPM_CC).expect("TPM2_ObjectChangeAuth is registered");
        assert_eq!(descriptor.attributes, 0x0400_0150);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles[0].user_auth);
        assert!(descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
        assert!(!descriptor.handles[1].user_auth);
        assert!(!descriptor.handles[1].admin_role());
        assert!(matches!(descriptor.handles[1].kind, HandleKind::Object));
    }

    #[test]
    fn command_attributes_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(&mut runtime, &clock, "CCATTR_0150", cap_cc(0x0150));
    }

    #[test]
    fn argument_validation_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        exec(
            &mut runtime,
            &clock,
            "OCA_ON_PRIMARY",
            object_change_auth(0x8000_0000, 0x8000_0000, &[], b"new-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "OCA_OVERSIZED_AUTH",
            object_change_auth(0x8000_0000, 0x8000_0000, &[], &[0x61; 33]),
        );
        exec(&mut runtime, &clock, "OCA_TRAILING", {
            let mut payload = handles(&[0x8000_0000, 0x8000_0000]);
            payload.extend_from_slice(&password_area(&[]));
            payload.extend_from_slice(&tpm2b(b"x"));
            payload.push(0x00);
            framed(0x8002, TPM_CC, &payload)
        });
        exec(
            &mut runtime,
            &clock,
            "OCA_TRUNCATED",
            vec![
                0x80, 0x02, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x01, 0x50, 0x80, 0x00, 0x00, 0x00,
                0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00,
            ],
        );
    }

    #[test]
    fn loaded_child_rotation_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let (private, public) = created_child("CREATE_SEALED_CHILD");
        exec_raw(
            &mut runtime,
            &clock,
            load(0x8000_0000, &[], &private, &public),
        );
        exec(
            &mut runtime,
            &clock,
            "OCA_SEALED_CHILD",
            object_change_auth(0x8000_0001, 0x8000_0000, b"seal-auth", b"rotated-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "OCA_WRONG_PARENT",
            object_change_auth(0x8000_0001, 0x8000_0001, b"seal-auth", b"rotated-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "OCA_WRONG_AUTH",
            object_change_auth(0x8000_0001, 0x8000_0000, b"wrong", b"rotated-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "OCA_EMPTY_AUTH",
            object_change_auth(0x8000_0001, 0x8000_0000, b"seal-auth", &[]),
        );
        let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[1].body else {
            panic!("an object body");
        };
        assert_eq!(
            crate::library::tpm2::entity::strip_trailing_zeros(body.sensitive.auth_value.expose()),
            b"seal-auth",
            "the loaded object keeps its original authorization value"
        );
    }

    #[test]
    fn replacement_blob_load_new_auth_success() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_CREATE", &clock);
        let (private, public) = created_child("CREATE_SEALED_CHILD");
        exec_raw(
            &mut runtime,
            &clock,
            load(0x8000_0000, &[], &private, &public),
        );
        exec_raw(
            &mut runtime,
            &clock,
            object_change_auth(0x8000_0001, 0x8000_0000, b"seal-auth", b"rotated-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_BEFORE_ROTATION",
            unseal(0x8000_0001, b"seal-auth"),
        );
        let rotated = rotated_private("OCA_SEALED_CHILD");
        exec(
            &mut runtime,
            &clock,
            "LOAD_ROTATED_CHILD",
            load(0x8000_0000, &[], &rotated, &public),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_ROTATED_CHILD",
            read_public(0x8000_0002),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_ROTATED_NEW_AUTH",
            unseal(0x8000_0002, b"rotated-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_ROTATED_OLD_AUTH",
            unseal(0x8000_0002, b"seal-auth"),
        );
    }
}
