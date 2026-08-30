use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::nv::build_nv_image;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_NEW_MAX_TRIES: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_NEW_RECOVERY_TIME: TpmResult = TPM_RC_P + TPM_RC_1 * 2;
const RC_LOCKOUT_RECOVERY: TpmResult = TPM_RC_P + TPM_RC_1 * 3;

struct Parameters {
    new_max_tries: u32,
    new_recovery_time: u32,
    lockout_recovery: u32,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parameters = parse_parameters(frame.parameters)?;
    if !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }

    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = (
        state.persistent.max_tries,
        state.persistent.recovery_time,
        state.persistent.lockout_recovery,
    );
    state.persistent.max_tries = parameters.new_max_tries;
    state.persistent.recovery_time = parameters.new_recovery_time;
    state.persistent.lockout_recovery = parameters.lockout_recovery;

    let image = match build_nv_image(state) {
        Ok(image) => image,
        Err(_) => {
            let (max_tries, recovery_time, lockout_recovery) = backup;
            state.persistent.max_tries = max_tries;
            state.persistent.recovery_time = recovery_time;
            state.persistent.lockout_recovery = lockout_recovery;
            return Err(TPM_RC_FAILURE);
        }
    };
    runtime.nv_memory = image;
    runtime.nv_update_pending = true;
    Ok(CommandOutput::empty())
}

fn parse_parameters(parameters: &[u8]) -> Result<Parameters, TpmResult> {
    let mut reader = crate::library::tpm2::marshal::BlobReader::new(parameters);
    let new_max_tries = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_NEW_MAX_TRIES)?;
    let new_recovery_time = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_NEW_RECOVERY_TIME)?;
    let lockout_recovery = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_LOCKOUT_RECOVERY)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        new_max_tries,
        new_recovery_time,
        lockout_recovery,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::CommandInput;
    use crate::library::cancel::CancellationToken;
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::parse_command;
    use crate::library::tpm2::command::core::registry::TPM_CC_DICTIONARY_ATTACK_PARAMETERS;
    use crate::library::tpm2::hierarchy::{TPM_RH_LOCKOUT, TPM_RH_OWNER, TPM_RS_PW};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::persistent::OwnedSecret;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    const RC_SUCCESS: u32 = 0x000;
    const RC_SIZE: u32 = 0x095;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_PARAM1_INSUFFICIENT: u32 = 0x1da;
    const RC_PARAM2_INSUFFICIENT: u32 = 0x2da;
    const RC_PARAM3_INSUFFICIENT: u32 = 0x3da;
    const RC_SESSION1_AUTH_FAIL: u32 = 0x98e;
    const RC_LOCKOUT: u32 = 0x921;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x71;
        }
        Ok(())
    }

    fn started_runtime() -> Tpm2Runtime {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let bytes = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0, 0,
        ];
        assert_eq!(dispatch_bytes(&mut runtime, &bytes)[6..], [0, 0, 0, 0]);
        runtime.nv_update_pending = false;
        runtime
    }

    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        let response = dispatch(runtime, &parsed, CancellationToken::disabled());
        crate::library::tpm2::command::core::header::serialize_response(&response)
            .expect("the response serializes")
    }

    fn response_code(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("four bytes"))
    }

    fn command(handle: u32, password: &[u8], params: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x02, 0, 0, 0, 0];
        out.extend_from_slice(&TPM_CC_DICTIONARY_ATTACK_PARAMETERS.to_be_bytes());
        out.extend_from_slice(&handle.to_be_bytes());
        out.extend_from_slice(&(9 + password.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out.extend_from_slice(params);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    fn parameters(max_tries: u32, recovery: u32, lockout_recovery: u32) -> Vec<u8> {
        let mut out = max_tries.to_be_bytes().to_vec();
        out.extend_from_slice(&recovery.to_be_bytes());
        out.extend_from_slice(&lockout_recovery.to_be_bytes());
        out
    }

    fn da_fields(runtime: &Tpm2Runtime) -> (u32, u32, u32, u32, bool) {
        let persistent = &runtime.state.as_ref().unwrap().persistent;
        (
            persistent.failed_tries,
            persistent.max_tries,
            persistent.recovery_time,
            persistent.lockout_recovery,
            persistent.lockout_auth_enabled,
        )
    }

    #[test]
    fn success_parameter_update_failed_tries_preservation() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().persistent.failed_tries = 2;
        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, &[], &parameters(9, 8, 7)),
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(da_fields(&runtime), (2, 9, 8, 7, true));
        assert!(runtime.nv_update_pending, "the command needs an NV update");
    }

    #[test]
    fn first_cycle_lockout_authorization_non_retry() {
        let mut runtime = started_runtime();
        assert!(!runtime.live.da_used, "the cycle starts before any DA use");
        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, &[], &parameters(9, 8, 7)),
        );
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "lockoutAuth skips the first-use DA transition entirely"
        );
        assert!(
            !runtime.live.da_used,
            "the successful lockout authorization records no DA-used marker"
        );
    }

    #[test]
    fn nv_unavailable_full_field_preservation_no_commit() {
        let mut runtime = started_runtime();
        runtime.nv_available = false;
        let before = da_fields(&runtime);
        let nv_before = runtime.nv_memory.clone();
        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, &[], &parameters(9, 8, 7)),
        );
        assert_eq!(response_code(&response), RC_NV_UNAVAILABLE);
        assert_eq!(da_fields(&runtime), before);
        assert!(!runtime.nv_update_pending);
        assert_eq!(runtime.nv_memory, nv_before);
    }

    #[test]
    fn persistence_failure_parameter_rollback() {
        let mut runtime = started_runtime();
        let before = da_fields(&runtime);
        runtime.state.as_mut().unwrap().persistent.owner_auth =
            OwnedSecret::from_vec(vec![0xaa; 4096]);
        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, &[], &parameters(9, 8, 7)),
        );
        assert_eq!(response_code(&response), 0x101);
        assert_eq!(da_fields(&runtime), before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn truncated_parameter_indexed_error_no_mutation() {
        let mut runtime = started_runtime();
        let before = da_fields(&runtime);
        for (params, expected) in [
            (&[][..], RC_PARAM1_INSUFFICIENT),
            (&parameters(9, 8, 7)[..4], RC_PARAM2_INSUFFICIENT),
            (&parameters(9, 8, 7)[..8], RC_PARAM3_INSUFFICIENT),
            (&[0u8; 13][..], RC_SIZE),
        ] {
            let response = dispatch_bytes(&mut runtime, &command(TPM_RH_LOCKOUT, &[], params));
            assert_eq!(response_code(&response), expected, "params {params:02x?}");
            assert_eq!(da_fields(&runtime), before);
            assert!(!runtime.nv_update_pending);
        }
        for len in 1..4usize {
            let response =
                dispatch_bytes(&mut runtime, &command(TPM_RH_LOCKOUT, &[], &vec![0; len]));
            assert_eq!(
                response_code(&response),
                RC_PARAM1_INSUFFICIENT,
                "{len} of 4 bytes"
            );
        }
    }

    #[test]
    fn wrong_command_handle_indexed_value_error() {
        let mut runtime = started_runtime();
        for handle in [TPM_RH_OWNER, 0x4000_000c, 0x0100_0000, 0, u32::MAX] {
            let response =
                dispatch_bytes(&mut runtime, &command(handle, &[], &parameters(9, 8, 7)));
            assert_eq!(
                response_code(&response),
                RC_HANDLE1_VALUE,
                "handle {handle:#x}"
            );
        }
    }

    #[test]
    fn missing_authorization_area_auth_missing() {
        let mut runtime = started_runtime();
        let mut bytes = vec![0x80, 0x01, 0, 0, 0, 0];
        bytes.extend_from_slice(&TPM_CC_DICTIONARY_ATTACK_PARAMETERS.to_be_bytes());
        bytes.extend_from_slice(&TPM_RH_LOCKOUT.to_be_bytes());
        bytes.extend_from_slice(&parameters(9, 8, 7));
        let size = (bytes.len() as u32).to_be_bytes();
        bytes[2..6].copy_from_slice(&size);
        let response = dispatch_bytes(&mut runtime, &bytes);
        assert_eq!(response_code(&response), RC_AUTH_MISSING);
    }

    #[test]
    fn wrong_lockout_password_auth_disable_parameter_preservation() {
        let mut runtime = started_runtime();
        runtime.state.as_mut().unwrap().persistent.lockout_auth =
            OwnedSecret::from_vec(b"secret".to_vec());
        let before = da_fields(&runtime);
        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, b"wrong", &parameters(9, 8, 7)),
        );
        assert_eq!(response_code(&response), RC_SESSION1_AUTH_FAIL);
        let (failed, max, recovery, lockout, enabled) = da_fields(&runtime);
        assert!(!enabled, "the failure disables lockoutAuth");
        assert_eq!(
            (failed, max, recovery, lockout),
            (before.0, before.1, before.2, before.3)
        );

        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, b"secret", &parameters(9, 8, 7)),
        );
        assert_eq!(
            response_code(&response),
            RC_LOCKOUT,
            "even the right password is refused while lockoutAuth is disabled"
        );
    }

    #[test]
    fn pre_startup_execution_rejection() {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        let response = dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_LOCKOUT, &[], &parameters(9, 8, 7)),
        );
        assert_eq!(response_code(&response), 0x100);
    }
}
