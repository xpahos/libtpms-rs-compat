use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_SIZE, TPM_RC_TYPE};

use super::super::marshal::BlobWriter;
use super::super::object_create::resolve_any_object;
use super::super::persistent::{OwnedAnyObjectBody, OwnedSecret};
use super::super::public::TPM_ALG_KEYEDHASH;
use super::super::runtime::Tpm2Runtime;
use super::super::template::{TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SIGN};
use super::dispatcher::CommandFrame;
use super::nv_common::handle_at;
use super::output::CommandOutput;

const TPM_RC_1: TpmResult = 0x100;
const RC_ITEM_HANDLE: TpmResult = TPM_RC_1;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let item_handle = handle_at(frame, 0)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    let object = resolve_any_object(runtime, item_handle).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_TYPE + RC_ITEM_HANDLE);
    };
    if body.public.object_type != TPM_ALG_KEYEDHASH {
        return Err(TPM_RC_TYPE + RC_ITEM_HANDLE);
    }
    if body.public.object_attributes
        & (TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN | TPMA_OBJECT_RESTRICTED)
        != 0
    {
        return Err(TPM_RC_ATTRIBUTES + RC_ITEM_HANDLE);
    }
    let data = body
        .sensitive
        .sensitive
        .as_ref()
        .map_or(&[][..], OwnedSecret::as_bytes);
    let mut writer = BlobWriter::new();
    writer.write_tpm2b(data).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::super::registry::{self, CommandLifecycle, HandleKind, NvAccess};
    use crate::library::tpm2::object_load::replay::*;
    use crate::library::tpm2::persistent::OwnedAnyObjectBody;

    const TPM_CC: u32 = 0x0000_015e;

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = registry::find(TPM_CC).expect("TPM2_Unseal is registered");
        assert_eq!(descriptor.attributes, 0x0200_015e);
        assert_eq!(descriptor.decrypt_size, 0);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(&mut runtime, &clock, "CCATTR_015E", cap_cc(0x015e));
    }

    #[test]
    fn an_external_sealed_object_unseals_only_with_its_authorization() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec_raw(
            &mut runtime,
            &clock,
            load_external(
                &keyed_hash_sensitive(&seal_seed(), SEAL_DATA, b"ext-auth"),
                &keyed_hash_public(&seal_unique(), 0x0000_0440),
                RH_NULL,
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_EXTERNAL",
            unseal(0x8000_0000, b"ext-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_WRONG_AUTH",
            unseal(0x8000_0000, b"wrong-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_NO_SESSIONS",
            plain(TPM_CC, &0x8000_0000u32.to_be_bytes()),
        );
        exec(&mut runtime, &clock, "UNSEAL_TRAILING", {
            let mut payload = handles(&[0x8000_0000]);
            payload.extend_from_slice(&password_area(b"ext-auth"));
            payload.push(0x00);
            framed(0x8002, TPM_CC, &payload)
        });
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_UNLOADED",
            unseal(0x8000_0002, &[]),
        );
    }

    #[test]
    fn type_and_attribute_rejections_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_PUBLIC_ONLY_SEAL",
            load_external(
                &[],
                &keyed_hash_public(&seal_unique(), 0x0000_0440),
                RH_NULL,
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_PUBLIC_ONLY",
            unseal(0x8000_0000, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "LOADEXT_RSA_FOR_UNSEAL",
            load_external(&[], &rsa_sign_public(&external_modulus()), RH_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_WRONG_TYPE",
            unseal(0x8000_0001, &[]),
        );
    }

    #[test]
    fn a_loaded_data_object_unseals_and_a_key_object_does_not() {
        let clock = clock();
        let mut runtime = runtime_at("AFTER_LOAD", &clock);
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_LOADED_CHILD",
            unseal(0x8000_0002, b"seal-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_LOADED_CHILD_WRONG_AUTH",
            unseal(0x8000_0002, b"nope"),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_LOADED_AES",
            unseal(0x8000_0001, &[]),
        );
    }

    const SEALED_CHILD_DATA: &[u8] = b"sealed child payload";

    #[test]
    fn the_unsealed_data_never_reaches_debug_output() {
        let clock = clock();
        let runtime = runtime_at("AFTER_LOAD", &clock);
        let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[2].body else {
            panic!("a loaded data object");
        };
        let secret = body.sensitive.sensitive.as_ref().expect("the sealed data");
        assert_eq!(secret.expose(), SEALED_CHILD_DATA);

        let plaintext = core::str::from_utf8(SEALED_CHILD_DATA).expect("ascii");
        let numeric = format!("{SEALED_CHILD_DATA:?}");
        let numeric = numeric
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let leak = format!("{:?}", secret.expose());
        assert!(leak.contains(&numeric), "the numeric probe detects a leak");
        assert!(
            String::from_utf8_lossy(secret.expose()).contains(plaintext),
            "the plaintext probe detects a leak"
        );

        for rendered in [format!("{secret:?}"), format!("{:?}", runtime.live.objects)] {
            assert!(!rendered.contains(plaintext), "{rendered}");
            assert!(!rendered.contains(&numeric), "{rendered}");
        }
        assert_eq!(
            format!("{secret:?}"),
            format!("OwnedSecret {{ len: {} }}", SEALED_CHILD_DATA.len())
        );
    }
}
