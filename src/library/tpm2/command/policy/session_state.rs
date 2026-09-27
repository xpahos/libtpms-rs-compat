use super::session::{extend_policy_digest, no_parameters, policy_digest, policy_session};
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_POLICY_CC, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::registry::{
    TPM_CC_POLICY_AUTH_VALUE, TPM_CC_POLICY_COMMAND_CODE,
};
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_P};
use crate::library::tpm2::command::core::upstream_codes::upstream_implements;
use crate::library::tpm2::marshal::{BlobReader, BlobWriter};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::session::{
    SESSION_ATTR_IS_AUTH_VALUE_NEEDED, SESSION_ATTR_IS_PASSWORD_NEEDED, loaded_session_mut,
    reset_policy_data,
};
use crate::types::TpmResult;

const RC_POLICY_COMMAND_CODE_CODE: TpmResult = TPM_RC_P + TPM_RC_1;

fn set_authorization_flags(
    runtime: &mut Tpm2Runtime,
    handle: u32,
    set: u32,
    cleared: u32,
) -> Result<(), TpmResult> {
    let session = loaded_session_mut(&mut runtime.live, handle).ok_or(TPM_RC_FAILURE)?;
    session.attributes = (session.attributes & !cleared) | set;
    Ok(())
}

pub(in crate::library::tpm2::command) fn execute_auth_value(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    no_parameters(frame)?;
    extend_policy_digest(runtime, &session, TPM_CC_POLICY_AUTH_VALUE, &[])?;
    set_authorization_flags(
        runtime,
        session.handle,
        SESSION_ATTR_IS_AUTH_VALUE_NEEDED,
        SESSION_ATTR_IS_PASSWORD_NEEDED,
    )?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_password(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    no_parameters(frame)?;
    extend_policy_digest(runtime, &session, TPM_CC_POLICY_AUTH_VALUE, &[])?;
    set_authorization_flags(
        runtime,
        session.handle,
        SESSION_ATTR_IS_PASSWORD_NEEDED,
        SESSION_ATTR_IS_AUTH_VALUE_NEEDED,
    )?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_restart(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    no_parameters(frame)?;
    let entry = loaded_session_mut(&mut runtime.live, session.handle).ok_or(TPM_RC_FAILURE)?;
    reset_policy_data(entry);
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_get_digest(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    no_parameters(frame)?;
    let digest = policy_digest(runtime, session.handle)?;
    let mut writer = BlobWriter::with_capacity(2 + digest.len());
    writer.write_tpm2b(&digest).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(in crate::library::tpm2::command) fn execute_command_code(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let session = policy_session(runtime, frame)?;
    let mut reader = BlobReader::new(frame.parameters);
    let code = reader
        .read_u32()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_POLICY_COMMAND_CODE_CODE)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let recorded = loaded_session_mut(&mut runtime.live, session.handle)
        .ok_or(TPM_RC_FAILURE)?
        .command_code;
    if recorded != 0 && recorded != code {
        return Err(TPM_RC_VALUE + RC_POLICY_COMMAND_CODE_CODE);
    }
    if !upstream_implements(code) || !runtime.command_enabled(code) {
        return Err(TPM_RC_POLICY_CC + RC_POLICY_COMMAND_CODE_CODE);
    }

    extend_policy_digest(
        runtime,
        &session,
        TPM_CC_POLICY_COMMAND_CODE,
        &[&code.to_be_bytes()],
    )?;
    loaded_session_mut(&mut runtime.live, session.handle)
        .ok_or(TPM_RC_FAILURE)?
        .command_code = code;
    Ok(CommandOutput::empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, TAIL_BYTES, assert_scenario_response, command, dispatch_bytes,
        for_each_mutation, manufactured_runtime, response_code, truncated_tail_replacements,
    };
    use crate::library::tpm2::command::policy::session::test_support::{
        CC_POLICY_AUTH_VALUE, CC_POLICY_COMMAND_CODE, CC_POLICY_GET_DIGEST, CC_POLICY_PASSWORD,
        CC_POLICY_RESTART, CC_START_AUTH_SESSION, HMAC_SESSION_0, POLICY_SESSION_0, digest,
        restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::session::{
        SESSION_ATTR_IS_POLICY, SESSION_ATTR_IS_TRIAL_POLICY, loaded_session,
    };

    fn policy_command(code: u32, handle: u32, extra: &[u8]) -> Vec<u8> {
        command(code, &[handle], &[], extra)
    }

    #[track_caller]
    fn run(runtime: &mut Tpm2Runtime, code: u32, extra: &[u8]) -> Vec<u8> {
        dispatch_bytes(runtime, &policy_command(code, POLICY_SESSION_0, extra))
    }

    #[test]
    fn pre_startup_command_rejection() {
        let mut runtime = manufactured_runtime();
        assert_scenario_response(
            "TPM2_PolicyGetDigest before TPM2_Startup: policy-sessions PGD_BEFORE_STARTUP",
            vector("PGD_BEFORE_STARTUP"),
            || {
                dispatch_bytes(
                    &mut runtime,
                    &policy_command(CC_POLICY_GET_DIGEST, POLICY_SESSION_0, &[]),
                )
            },
        );
    }

    #[test]
    fn policy_digest_evolution_reference_match() {
        let mut runtime = restored("POLICY_FRESH");
        assert_eq!(digest(&mut runtime), vector("PGD_INITIAL"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]),
            vector("PAV_FIRST")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_AUTH_VALUE"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_PASSWORD, &[]),
            vector("PPW_AFTER_AUTH_VALUE")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_PASSWORD"));
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_015du32.to_be_bytes()
            ),
            vector("PCC_SIGN")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_COMMAND_CODE"));
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_015du32.to_be_bytes()
            ),
            vector("PCC_SIGN_AGAIN")
        );
        assert_eq!(
            digest(&mut runtime),
            vector("PGD_AFTER_REPEATED_COMMAND_CODE")
        );
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_0153u32.to_be_bytes()
            ),
            vector("PCC_CONFLICT")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_CONFLICT"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_RESTART, &[]),
            vector("PRESTART")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_RESTART"));
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_0153u32.to_be_bytes()
            ),
            vector("PCC_AFTER_RESTART")
        );
        assert_eq!(digest(&mut runtime), vector("PGD_REBUILT"));
    }

    #[test]
    fn policy_password_and_auth_value_same_digest_extension() {
        let mut first = restored("POLICY_FRESH");
        run(&mut first, CC_POLICY_AUTH_VALUE, &[]);
        let mut second = restored("POLICY_FRESH");
        run(&mut second, CC_POLICY_PASSWORD, &[]);
        assert_eq!(digest(&mut first), digest(&mut second));
    }

    #[test]
    fn authorization_flag_mutual_exclusion() {
        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_AUTH_VALUE_NEEDED, 0);
        assert_eq!(session.attributes & SESSION_ATTR_IS_PASSWORD_NEEDED, 0);

        run(&mut runtime, CC_POLICY_PASSWORD, &[]);
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.attributes & SESSION_ATTR_IS_AUTH_VALUE_NEEDED, 0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_PASSWORD_NEEDED, 0);

        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_AUTH_VALUE_NEEDED, 0);
        assert_eq!(session.attributes & SESSION_ATTR_IS_PASSWORD_NEEDED, 0);
    }

    #[test]
    fn unimplemented_reference_command_code_rejection() {
        let mut runtime = restored("POLICY_FRESH");
        for (record, code) in [
            ("PCC_UNIMPLEMENTED", 0x0000_0179u32),
            ("PCC_RESERVED_GAP", 0x0000_0175),
            ("PCC_ZERO", 0x0000_0000),
            ("PCC_VENDOR", 0x2000_0000),
        ] {
            assert_eq!(
                run(&mut runtime, CC_POLICY_COMMAND_CODE, &code.to_be_bytes()),
                vector(record),
                "{record}"
            );
        }
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_0157u32.to_be_bytes()
            ),
            vector("PCC_LOAD"),
            "a command this port has not ported yet is still implemented upstream"
        );
        assert_eq!(digest(&mut runtime), vector("PGD_AFTER_LOAD"));
    }

    #[test]
    fn profile_disabled_policy_command_code_rejection() {
        use crate::library::tpm2::profile::validate_user_profile;

        const SIGN: u32 = 0x0000_015d;
        const LOAD: u32 = 0x0000_0157;
        const PROFILE: &[u8] = br#"{"Name":"custom","Commands":"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15c,0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197"}"#;

        for snapshot in ["POLICY_FRESH", "TRIAL_FRESH"] {
            let mut runtime = restored(snapshot);
            runtime.state.as_mut().expect("decoded state").profile =
                validate_user_profile(Some(PROFILE)).expect("Sign can be disabled");
            let before = session_of(&runtime, POLICY_SESSION_0).clone();

            assert_eq!(
                response_code(&run(
                    &mut runtime,
                    CC_POLICY_COMMAND_CODE,
                    &SIGN.to_be_bytes()
                )),
                TPM_RC_POLICY_CC + RC_POLICY_COMMAND_CODE_CODE,
                "{snapshot}: a profile-disabled target cannot be bound"
            );
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.audit_digest, before.audit_digest, "{snapshot}");
            assert_eq!(after.command_code, before.command_code, "{snapshot}");

            assert_eq!(
                response_code(&run(
                    &mut runtime,
                    CC_POLICY_COMMAND_CODE,
                    &LOAD.to_be_bytes()
                )),
                RC_SUCCESS,
                "{snapshot}: an enabled target still binds"
            );
            assert_eq!(
                response_code(&run(
                    &mut runtime,
                    CC_POLICY_COMMAND_CODE,
                    &SIGN.to_be_bytes()
                )),
                TPM_RC_VALUE + RC_POLICY_COMMAND_CODE_CODE,
                "{snapshot}: a conflicting restriction takes precedence"
            );
        }
    }

    #[test]
    fn malformed_parameter_oracle_parity() {
        let mut runtime = restored("POLICY_FRESH");
        for (record, code, extra) in [
            ("PCC_NO_CODE", CC_POLICY_COMMAND_CODE, Vec::new()),
            (
                "PCC_SHORT_CODE",
                CC_POLICY_COMMAND_CODE,
                vec![0x00, 0x00, 0x00],
            ),
            (
                "PCC_TRAILING",
                CC_POLICY_COMMAND_CODE,
                vec![0x00, 0x00, 0x01, 0x5d, 0x00],
            ),
            ("PAV_TRAILING", CC_POLICY_AUTH_VALUE, vec![0x00]),
            ("PPW_TRAILING", CC_POLICY_PASSWORD, vec![0x00]),
            ("PGD_TRAILING", CC_POLICY_GET_DIGEST, vec![0x00]),
            ("PRESTART_TRAILING", CC_POLICY_RESTART, vec![0x00]),
        ] {
            assert_eq!(run(&mut runtime, code, &extra), vector(record), "{record}");
        }
        assert_eq!(
            dispatch_bytes(&mut runtime, &command(CC_POLICY_AUTH_VALUE, &[], &[], &[])),
            vector("PAV_NO_HANDLE")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(CC_POLICY_AUTH_VALUE, &[], &[], &[0x03, 0x00, 0x00])
            ),
            vector("PAV_SHORT_HANDLE")
        );
    }

    #[test]
    fn non_policy_session_handle_oracle_match() {
        let mut runtime = restored("THREE_SESSIONS");
        for (suffix, handle) in [
            ("HMAC_RANGE", HMAC_SESSION_0),
            ("HMAC_SESSION", POLICY_SESSION_0),
            ("UNLOADED", 0x0300_0005),
            ("OUT_OF_RANGE", 0x0300_0040),
            ("OBJECT", 0x8000_0000),
            ("PERMANENT", 0x4000_0001),
        ] {
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &policy_command(CC_POLICY_GET_DIGEST, handle, &[])
                ),
                vector(&format!("PGD_{suffix}")),
                "PGD_{suffix}"
            );
            assert_eq!(
                dispatch_bytes(
                    &mut runtime,
                    &policy_command(CC_POLICY_AUTH_VALUE, handle, &[])
                ),
                vector(&format!("PAV_{suffix}")),
                "PAV_{suffix}"
            );
        }
    }

    #[test]
    fn policy_get_digest_session_preservation() {
        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for _ in 0..3 {
            assert_eq!(digest(&mut runtime), vector("PGD_AFTER_AUTH_VALUE"));
        }
        let after = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.audit_digest, before.audit_digest);
        assert_eq!(after.command_code, before.command_code);
        assert_eq!(after.pcr_counter, before.pcr_counter);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
        assert_eq!(after.start_time, before.start_time);
    }

    #[test]
    fn policy_restart_policy_state_clear_transport_preservation() {
        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        run(
            &mut runtime,
            CC_POLICY_COMMAND_CODE,
            &0x0000_015du32.to_be_bytes(),
        );
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        assert_ne!(before.command_code, 0);
        assert_ne!(before.attributes & SESSION_ATTR_IS_AUTH_VALUE_NEEDED, 0);

        assert_eq!(
            run(&mut runtime, CC_POLICY_RESTART, &[]),
            vector("PRESTART")
        );
        let after = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(after.command_code, 0);
        assert_eq!(after.command_locality, 0);
        assert_eq!(after.timeout, 0);
        assert_eq!(after.pcr_counter, 0);
        assert!(after.bound_entity.is_empty());
        assert_eq!(after.audit_digest, vec![0u8; 32]);
        assert_eq!(after.attributes, SESSION_ATTR_IS_POLICY);

        assert_eq!(after.auth_hash_alg, before.auth_hash_alg);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
        assert_eq!(after.session_key.as_bytes(), before.session_key.as_bytes());
        assert_eq!(after.start_time, before.start_time);
        assert_eq!(after.epoch, before.epoch);
        assert_eq!(after.symmetric.algorithm, before.symmetric.algorithm);
    }

    #[test]
    fn policy_restart_trial_and_binding_attribute_preservation() {
        let mut runtime = restored("TRIAL_FRESH");
        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        assert_eq!(
            run(&mut runtime, CC_POLICY_RESTART, &[]),
            vector("TRIAL_PRESTART")
        );
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(
            session.attributes,
            SESSION_ATTR_IS_POLICY | SESSION_ATTR_IS_TRIAL_POLICY
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_RESTART"));
    }

    #[test]
    fn trial_session_digest_parity() {
        let mut runtime = restored("TRIAL_FRESH");
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_INITIAL"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]),
            vector("TRIAL_PAV")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_AUTH_VALUE"));
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_015du32.to_be_bytes()
            ),
            vector("TRIAL_PCC")
        );
        assert_eq!(digest(&mut runtime), vector("TRIAL_PGD_AFTER_COMMAND_CODE"));
    }

    #[test]
    fn sha1_session_digest_size_preservation() {
        let mut runtime = restored("READY");
        let mut parameters = 20u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&[0x5a; 20]);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.push(0x01);
        parameters.extend_from_slice(&[0x00, 0x10]);
        parameters.extend_from_slice(&0x0004u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    CC_START_AUTH_SESSION,
                    &[0x4000_0007, 0x4000_0007],
                    &[],
                    &parameters
                )
            )),
            RC_SUCCESS
        );
        assert_eq!(digest(&mut runtime), vector("SHA1_PGD_INITIAL"));
        assert_eq!(
            run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]),
            vector("SHA1_PAV")
        );
        assert_eq!(digest(&mut runtime), vector("SHA1_PGD_AFTER_AUTH_VALUE"));
        assert_eq!(
            session_of(&runtime, POLICY_SESSION_0).audit_digest.len(),
            20
        );
    }

    #[test]
    fn failed_policy_command_session_unchanged() {
        let mut runtime = restored("POLICY_FRESH");
        run(
            &mut runtime,
            CC_POLICY_COMMAND_CODE,
            &0x0000_015du32.to_be_bytes(),
        );
        let before = session_of(&runtime, POLICY_SESSION_0).clone();
        for (code, extra) in [
            (CC_POLICY_COMMAND_CODE, vec![0x00, 0x00, 0x01, 0x53]),
            (CC_POLICY_COMMAND_CODE, vec![0x00, 0x00, 0x01, 0x79]),
            (CC_POLICY_COMMAND_CODE, vec![0x00, 0x00, 0x00]),
            (CC_POLICY_AUTH_VALUE, vec![0x00]),
            (CC_POLICY_PASSWORD, vec![0x00]),
            (CC_POLICY_RESTART, vec![0x00]),
        ] {
            let response = run(&mut runtime, code, &extra);
            assert_ne!(response_code(&response), RC_SUCCESS);
            let after = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(after.attributes, before.attributes);
            assert_eq!(after.audit_digest, before.audit_digest);
            assert_eq!(after.command_code, before.command_code);
            assert_eq!(after.pcr_counter, before.pcr_counter);
        }
    }

    #[test]
    fn failing_hash_self_test_no_policy_update() {
        use crate::library::tpm2::self_test::always_fails;
        let mut runtime = restored("POLICY_FRESH");
        let before = session_of(&runtime, POLICY_SESSION_0).audit_digest.clone();
        runtime.self_test.set_runner(always_fails);
        let response = run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        assert_eq!(response_code(&response), 0x101, "TPM_RC_FAILURE");
        assert!(runtime.failure_mode);
        assert_eq!(
            loaded_session(&runtime.live, POLICY_SESSION_0)
                .expect("the session survives")
                .audit_digest,
            before
        );
    }

    #[test]
    fn pending_hash_self_test_use_time_consumption() {
        use crate::library::tpm2::self_test::PrimitiveTest;
        let mut runtime = restored("POLICY_FRESH");
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha256));
        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha256));
    }

    #[test]
    fn session_isolation_during_policy_build() {
        let mut runtime = restored("THREE_SESSIONS");
        let hmac_before = session_of(&runtime, HMAC_SESSION_0).clone();
        let trial_before = session_of(&runtime, 0x0300_0002).clone();
        let response = dispatch_bytes(
            &mut runtime,
            &policy_command(CC_POLICY_AUTH_VALUE, 0x0300_0001, &[]),
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        let hmac_after = session_of(&runtime, HMAC_SESSION_0);
        assert_eq!(hmac_after.attributes, hmac_before.attributes);
        assert_eq!(hmac_after.audit_digest, hmac_before.audit_digest);
        let trial_after = session_of(&runtime, 0x0300_0002);
        assert_eq!(trial_after.attributes, trial_before.attributes);
        assert_eq!(trial_after.audit_digest, trial_before.audit_digest);
    }

    #[test]
    fn policy_state_volatile_round_trip() {
        let mut runtime = restored("POLICY_SAVED");
        assert_eq!(digest(&mut runtime), vector("RESTORED_PGD"));
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_015du32.to_be_bytes()
            ),
            vector("RESTORED_PCC_SAME")
        );
        assert_eq!(
            run(
                &mut runtime,
                CC_POLICY_COMMAND_CODE,
                &0x0000_0153u32.to_be_bytes()
            ),
            vector("RESTORED_PCC_CONFLICT")
        );
        assert_eq!(digest(&mut runtime), vector("RESTORED_PGD_AFTER"));
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(0x0000_0165, &[], &[], &POLICY_SESSION_0.to_be_bytes())
            ),
            vector("RESTORED_FLUSH")
        );
        assert_eq!(digest(&mut runtime), vector("RESTORED_PGD_AFTER_FLUSH"));
    }

    #[test]
    fn session_save_reload_field_preservation() {
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{
            attach_volatile_blob_for_test, restore_permanent_blob_for_test,
        };

        let mut runtime = restored("POLICY_FRESH");
        run(&mut runtime, CC_POLICY_AUTH_VALUE, &[]);
        run(
            &mut runtime,
            CC_POLICY_COMMAND_CODE,
            &0x0000_015du32.to_be_bytes(),
        );
        let before = session_of(&runtime, POLICY_SESSION_0).clone();

        let clock = RecordingClock::new(1_700_000_100_000, 4_000_000);
        let volatile = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let permanent =
            crate::library::tpm2::persistent::persistent_all_store(runtime.state()).expect("saves");
        let mut reloaded = restore_permanent_blob_for_test(&permanent).expect("restores");
        attach_volatile_blob_for_test(&mut reloaded, &volatile).expect("attaches");

        let after = session_of(&reloaded, POLICY_SESSION_0);
        assert_eq!(after.attributes, before.attributes);
        assert_eq!(after.auth_hash_alg, before.auth_hash_alg);
        assert_eq!(after.audit_digest, before.audit_digest);
        assert_eq!(after.command_code, before.command_code);
        assert_eq!(after.pcr_counter, before.pcr_counter);
        assert_eq!(after.start_time, before.start_time);
        assert_eq!(after.epoch, before.epoch);
        assert_eq!(after.timeout, before.timeout);
        assert_eq!(after.nonce_tpm.as_bytes(), before.nonce_tpm.as_bytes());
        assert_eq!(after.session_key.as_bytes(), before.session_key.as_bytes());
        assert_eq!(after.bound_entity, before.bound_entity);
        assert_eq!(digest(&mut reloaded), digest(&mut runtime));
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let valid = policy_command(CC_POLICY_COMMAND_CODE, POLICY_SESSION_0, &[0, 0, 1, 0x5d]);
        for_each_mutation(
            "TPM2_PolicyCommandCode",
            truncated_tail_replacements(&valid, 10, &TAIL_BYTES),
            |bytes| {
                let _ = dispatch_bytes(&mut restored("POLICY_FRESH"), &bytes);
            },
        );
    }
}
