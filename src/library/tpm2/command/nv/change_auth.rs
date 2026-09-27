use super::access::resolve;
use crate::library::constants::TPM_RC_SIZE;
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_P};
use crate::library::tpm2::nv::{checked_auth_value, transact, write_index_auth};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::TemplateReader;
use crate::types::TpmResult;

const RC_NEW_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;

const AUTH_TPM2B_MAX: usize = 64;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let nv_handle = handle_at(frame, 0)?;
    let new_auth = parse_parameters(frame.parameters)?;

    let resolved = resolve(runtime, nv_handle)?;
    let auth_value = checked_auth_value(&new_auth, resolved.public.name_alg)
        .map_err(|code| code + RC_NEW_AUTH)?;

    transact(runtime, |runtime| {
        write_index_auth(runtime, &resolved, auth_value.clone())
    })?;
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<Vec<u8>, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let new_auth = reader
        .tpm2b(AUTH_TPM2B_MAX)
        .map_err(|code| code + RC_NEW_AUTH)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(new_auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::cancel::CancellationToken;
    use crate::library::tpm2::command::core::registry::TPM_CC_NV_CHANGE_AUTH;
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, REPLACEMENT_BYTES, TPM_ALG_SHA1, byte_replacements, command, dispatch_bytes,
        for_each_mutation, response_code, started_runtime,
    };
    use crate::library::tpm2::command::nv::test_support::{
        assert_unchanged, define, nv_public, resolved, snapshot,
    };
    use crate::library::tpm2::golden_responses::nv::nv_vector;

    use crate::library::tpm2::nv::{
        NvPublic, TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, index_auth_value,
    };
    use crate::library::tpm2::persistent::OwnedUserNvramEntry;

    const RC_AUTH_TYPE: u32 = 0x124;
    const RC_HANDLE1_HANDLE: u32 = 0x18b;
    const RC_PARAM1_SIZE: u32 = 0x1d5;

    const INDEX: u32 = 0x0100_0001;

    fn auth_read_write() -> NvPublic {
        nv_public(INDEX, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, 8)
    }

    fn change_auth_frame(new_auth: &[u8]) -> Vec<u8> {
        let mut out = (new_auth.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(new_auth);
        out
    }

    #[track_caller]
    fn change_auth(runtime: &mut Tpm2Runtime, new_auth: &[u8]) -> Result<(), TpmResult> {
        let frame = CommandFrame {
            handles: vec![INDEX],
            parameters: &change_auth_frame(new_auth),
            cancellation: CancellationToken::disabled(),
        };
        execute(runtime, &frame).map(|_| ())
    }

    #[test]
    fn password_session_upstream_rejection() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        define(&mut runtime, &auth_read_write());
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_CHANGE_AUTH,
                    &[INDEX],
                    &[&[]],
                    &change_auth_frame(b"pass")
                ),
            ),
            nv_vector("CHANGEAUTH_PASSWORD_SESSION")
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_CHANGE_AUTH,
                    &[INDEX],
                    &[&[]],
                    &change_auth_frame(b"pass")
                ),
            )),
            RC_AUTH_TYPE
        );
        assert_eq!(index_auth_value(&runtime, INDEX), Some(&[][..]));
    }

    #[test]
    fn undefined_index_handle_decorated_error() {
        let mut runtime = started_runtime();
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_CHANGE_AUTH,
                    &[INDEX],
                    &[&[]],
                    &change_auth_frame(b"pass")
                ),
            )),
            RC_HANDLE1_HANDLE
        );
    }

    #[test]
    fn new_secret_replacement() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, b"secret"), Ok(()));
        assert_eq!(index_auth_value(&runtime, INDEX), Some(&b"secret"[..]));
        assert!(runtime.nv_update_pending);

        assert_eq!(change_auth(&mut runtime, b"other"), Ok(()));
        assert_eq!(index_auth_value(&runtime, INDEX), Some(&b"other"[..]));
    }

    #[test]
    fn new_secret_subsequent_authorization() {
        let mut runtime = started_runtime();
        runtime.live.da_used = true;
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, b"secret"), Ok(()));

        let mut parameters = 0u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0137, &[INDEX, INDEX], &[b"wrong"], &parameters),
            )),
            0x98e,
            "the old empty password no longer authorizes the index"
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_0137, &[INDEX, INDEX], &[b"secret"], &parameters),
            )),
            RC_SUCCESS
        );
    }

    #[test]
    fn new_secret_trailing_zero_strip() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        let mut padded = b"ab".to_vec();
        padded.extend_from_slice(&[0x00; 30]);
        assert_eq!(change_auth(&mut runtime, &padded), Ok(()));
        assert_eq!(index_auth_value(&runtime, INDEX), Some(&b"ab"[..]));

        assert_eq!(change_auth(&mut runtime, &[0x00; 32]), Ok(()));
        assert_eq!(
            index_auth_value(&runtime, INDEX),
            Some(&[][..]),
            "an all-zero secret normalizes to the empty authorization value"
        );
    }

    #[test]
    fn secret_above_name_alg_digest_size_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, &[0xaa; 33]), Err(RC_PARAM1_SIZE));
        assert_eq!(change_auth(&mut runtime, &[0xaa; 32]), Ok(()));
        assert_eq!(index_auth_value(&runtime, INDEX), Some(&[0xaa; 32][..]));

        let mut sha1 = auth_read_write();
        sha1.nv_index = 0x0100_0002;
        sha1.name_alg = TPM_ALG_SHA1;
        define(&mut runtime, &sha1);
        let frame = CommandFrame {
            handles: vec![0x0100_0002],
            parameters: &change_auth_frame(&[0xaa; 21]),
            cancellation: CancellationToken::disabled(),
        };
        assert_eq!(execute(&mut runtime, &frame).err(), Some(RC_PARAM1_SIZE));
    }

    #[test]
    fn oversized_tpm2b_size_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, &[0xaa; 65]), Err(RC_PARAM1_SIZE));
    }

    #[test]
    fn trailing_parameter_bytes_size_error() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        let mut parameters = change_auth_frame(b"pass");
        parameters.push(0x00);
        let frame = CommandFrame {
            handles: vec![INDEX],
            parameters: &parameters,
            cancellation: CancellationToken::disabled(),
        };
        assert_eq!(execute(&mut runtime, &frame).err(), Some(TPM_RC_SIZE));
    }

    #[test]
    fn failed_change_old_secret_preservation() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, b"secret"), Ok(()));
        runtime.nv_update_pending = false;
        let before = snapshot(&runtime);

        assert_eq!(change_auth(&mut runtime, &[0xaa; 33]), Err(RC_PARAM1_SIZE));
        assert_unchanged(&runtime, &before);

        runtime.nv_available = false;
        assert_eq!(change_auth(&mut runtime, b"other"), Err(0x923));
        assert_unchanged(&runtime, &before);
        assert_eq!(index_auth_value(&runtime, INDEX), Some(&b"secret"[..]));
    }

    #[test]
    fn same_secret_rewrite_no_nv_access() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, b"secret"), Ok(()));
        runtime.nv_update_pending = false;
        runtime.nv_available = false;
        assert_eq!(change_auth(&mut runtime, b"secret"), Ok(()));
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn new_secret_permanent_state_round_trip() {
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::restore_permanent_blob_for_test;

        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, b"secret"), Ok(()));
        let blob = persistent_all_store(runtime.state()).expect("the state serializes");
        let reloaded = restore_permanent_blob_for_test(&blob).expect("the blob restores");
        let entry = reloaded
            .state()
            .user_nvram
            .entries
            .iter()
            .find(|entry| matches!(entry, OwnedUserNvramEntry::NvIndex { handle, .. } if *handle == INDEX))
            .expect("the index survives");
        let OwnedUserNvramEntry::NvIndex { index, .. } = entry else {
            panic!("expected an NV index entry");
        };
        assert_eq!(index.auth_value.expose(), b"secret");
    }

    #[test]
    fn debug_output_secret_redaction() {
        let mut runtime = started_runtime();
        define(&mut runtime, &auth_read_write());
        assert_eq!(change_auth(&mut runtime, b"Zaphod"), Ok(()));
        for rendered in [
            format!("{:?}", runtime.state().user_nvram.entries),
            format!("{:?}", runtime.state().user_nvram),
            format!("{runtime:?}"),
        ] {
            assert!(
                !rendered.contains("Zaphod"),
                "the debug output must not carry the secret: {rendered}"
            );
            assert!(
                !rendered.contains("90, 97, 112"),
                "the debug output must not carry the secret bytes: {rendered}"
            );
        }
        assert_eq!(
            format!("{:?}", resolved(&runtime, INDEX).public.auth_policy),
            "[]",
            "the public area carries no secret at all"
        );
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let full = change_auth_frame(b"pass");
        for_each_mutation(
            "TPM2_NV_ChangeAuth",
            byte_replacements(&full, &REPLACEMENT_BYTES),
            |parameters| {
                let mut runtime = started_runtime();
                define(&mut runtime, &auth_read_write());
                let frame = CommandFrame {
                    handles: vec![INDEX],
                    parameters: &parameters,
                    cancellation: CancellationToken::disabled(),
                };
                let _ = execute(&mut runtime, &frame);
            },
        );
    }
}
