use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_NV_UNAVAILABLE};
use crate::library::tpm2::audit::AUDIT_COMMANDS_SIZE;
use crate::library::tpm2::command::core::registry::{
    CommandDescriptor, TPM_CC_GET_COMMAND_AUDIT_DIGEST, TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
    TPM_CC_SHUTDOWN,
};
use crate::library::tpm2::command::session::processing::{
    CommandContext, compute_cp_hash, compute_rp_hash,
};
use crate::library::tpm2::command_bitmap::COMMAND_COUNT;
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::nv::{build_nv_image, command_bitmap_image};
use crate::library::tpm2::persistent::OwnedCommandBitmap;
use crate::library::tpm2::profile::command_enabled;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::template::digest_size;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) const COMMAND_FIRST: u32 = 0x0000_011f;

pub(in crate::library::tpm2) fn command_index(code: u32) -> Option<usize> {
    let index = code.checked_sub(COMMAND_FIRST)? as usize;
    (index < COMMAND_COUNT).then_some(index)
}

pub(in crate::library::tpm2::command) fn command_code(index: usize) -> u32 {
    COMMAND_FIRST + index as u32
}

pub(in crate::library::tpm2::command) fn audit_bitmap(
    runtime: &Tpm2Runtime,
) -> Result<Vec<u8>, TpmResult> {
    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    command_bitmap_image(&persistent.audit_commands, AUDIT_COMMANDS_SIZE)
}

fn bit_is_set(bitmap: &[u8], index: usize) -> bool {
    bitmap
        .get(index / 8)
        .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

pub(in crate::library::tpm2) fn is_required(runtime: &Tpm2Runtime, code: u32) -> bool {
    let Some(index) = command_index(code) else {
        return false;
    };
    audit_bitmap(runtime).is_ok_and(|bitmap| bit_is_set(&bitmap, index))
}

pub(in crate::library::tpm2::command) fn set_command(
    bitmap: &mut [u8],
    profile_commands: &[u8],
    code: u32,
) -> bool {
    let Some(index) = command_index(code) else {
        return false;
    };
    if !command_enabled(profile_commands, code) || code == TPM_CC_SHUTDOWN {
        return false;
    }
    if bit_is_set(bitmap, index) {
        return false;
    }
    bitmap[index / 8] |= 1 << (index % 8);
    true
}

pub(in crate::library::tpm2::command) fn clear_command(
    bitmap: &mut [u8],
    profile_commands: &[u8],
    code: u32,
) -> bool {
    let Some(index) = command_index(code) else {
        return false;
    };
    if !command_enabled(profile_commands, code) || code == TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS {
        return false;
    }
    if !bit_is_set(bitmap, index) {
        return false;
    }
    bitmap[index / 8] &= !(1 << (index % 8));
    true
}

pub(in crate::library::tpm2::command) fn store_bitmap(
    runtime: &mut Tpm2Runtime,
    bitmap: Vec<u8>,
) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = state.persistent.audit_commands.clone();
    state.persistent.audit_commands = OwnedCommandBitmap {
        compressed: false,
        bytes: bitmap,
    };
    commit_persistent(runtime, |state| {
        state.persistent.audit_commands = backup;
    })
}

fn commit_persistent(
    runtime: &mut Tpm2Runtime,
    restore: impl FnOnce(&mut crate::library::tpm2::persistent::OwnedPersistentState),
) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    match build_nv_image(state) {
        Ok(image) => {
            runtime.nv_memory = image;
            runtime.nv_update_pending = true;
            Ok(())
        }
        Err(_) => {
            restore(state);
            Err(TPM_RC_FAILURE)
        }
    }
}

pub(in crate::library::tpm2::command) fn command_list_digest(
    runtime: &mut Tpm2Runtime,
) -> Result<Vec<u8>, TpmResult> {
    let hash_alg = audit_hash_alg(runtime)?;
    let bitmap = audit_bitmap(runtime)?;
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    for index in 0..COMMAND_COUNT {
        if bit_is_set(&bitmap, index) {
            hasher.update(&command_code(index).to_be_bytes());
        }
    }
    Ok(hasher.finalize())
}

pub(in crate::library::tpm2::command) fn audit_hash_alg(
    runtime: &Tpm2Runtime,
) -> Result<u16, TpmResult> {
    Ok(runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .persistent
        .audit_hash_alg)
}

pub(in crate::library::tpm2::command) fn audit_counter(
    runtime: &Tpm2Runtime,
) -> Result<u64, TpmResult> {
    Ok(runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .persistent
        .audit_counter)
}

pub(in crate::library::tpm2::command) fn audit_digest(
    runtime: &Tpm2Runtime,
) -> Result<Vec<u8>, TpmResult> {
    Ok(runtime
        .live
        .state_reset
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .command_audit_digest
        .clone())
}

fn set_audit_digest(runtime: &mut Tpm2Runtime, digest: Vec<u8>) -> Result<(), TpmResult> {
    runtime
        .live
        .state_reset
        .as_mut()
        .ok_or(TPM_RC_FAILURE)?
        .command_audit_digest = digest;
    Ok(())
}

pub(in crate::library::tpm2::command) fn mark_algorithm_change(
    runtime: &mut Tpm2Runtime,
) -> Result<(), TpmResult> {
    set_audit_digest(runtime, vec![0u8])
}

pub(in crate::library::tpm2::command) fn reset_digest(
    runtime: &mut Tpm2Runtime,
) -> Result<(), TpmResult> {
    set_audit_digest(runtime, Vec::new())
}

pub(in crate::library::tpm2::command) fn prepare(
    runtime: &mut Tpm2Runtime,
    context: &CommandContext<'_>,
) -> Result<Option<Vec<u8>>, TpmResult> {
    if !is_required(runtime, context.code) {
        return Ok(None);
    }
    let needs_nv =
        audit_digest(runtime)?.is_empty() || context.code == TPM_CC_GET_COMMAND_AUDIT_DIGEST;
    if needs_nv && !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    let hash_alg = audit_hash_alg(runtime)?;
    Ok(Some(compute_cp_hash(runtime, context, hash_alg)?))
}

pub(in crate::library::tpm2::command) fn update(
    runtime: &mut Tpm2Runtime,
    descriptor: &CommandDescriptor,
    cp_hash: Option<&[u8]>,
    parameters: &[u8],
) -> Result<(), TpmResult> {
    if !is_required(runtime, descriptor.code) {
        return Ok(());
    }
    let cp_hash = cp_hash.ok_or(TPM_RC_FAILURE)?;
    let mut digest = audit_digest(runtime)?;
    if digest.len() == 1 {
        return reset_digest(runtime);
    }
    let hash_alg = audit_hash_alg(runtime)?;
    if digest.is_empty() {
        digest = vec![0u8; digest_size(hash_alg).ok_or(TPM_RC_FAILURE)?];
        bump_counter(runtime)?;
    }
    let rp_hash = compute_rp_hash(runtime, descriptor.code, parameters, hash_alg)?;
    self_test_algorithm(runtime, hash_alg)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_FAILURE)?;
    hasher.update(&digest);
    hasher.update(cp_hash);
    hasher.update(&rp_hash);
    let extended = hasher.finalize();
    set_audit_digest(runtime, extended)
}

fn bump_counter(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let state = runtime.state.as_mut().ok_or(TPM_RC_FAILURE)?;
    let backup = state.persistent.audit_counter;
    state.persistent.audit_counter = backup.wrapping_add(1);
    commit_persistent(runtime, |state| {
        state.persistent.audit_counter = backup;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::attestation::builder::test_support::{
        ALG_NULL, ALG_RSASSA, ALG_SHA256, CC_CERTIFY, CC_GET_COMMAND_AUDIT_DIGEST, CC_GET_RANDOM,
        CC_QUOTE, CC_START_AUTH_SESSION, HMAC_SESSION, NONCE_CALLER, QUALIFY, SIGN_ATTRS,
        TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, audited_get_random, command, create_primary,
        pw, ready_runtime, rsa_template, run, run_ok, sig_scheme, tpm2b,
    };
    use crate::library::tpm2::command::core::registry::{
        TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, TPM_CC_SHUTDOWN,
    };
    use crate::library::tpm2::command::core::test_support::{RC_SUCCESS, response_code};
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::session::loaded_session;

    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const CC_STARTUP: u32 = 0x0000_0144;
    const CC_CLEAR: u32 = 0x0000_0126;
    const TPM_RH_LOCKOUT: u32 = 0x4000_000a;

    fn audit_status(set_list: &[u32], clear_list: &[u32]) -> Vec<u8> {
        let mut parameters = ALG_NULL.to_be_bytes().to_vec();
        parameters.extend_from_slice(&(set_list.len() as u32).to_be_bytes());
        for code in set_list {
            parameters.extend_from_slice(&code.to_be_bytes());
        }
        parameters.extend_from_slice(&(clear_list.len() as u32).to_be_bytes());
        for code in clear_list {
            parameters.extend_from_slice(&code.to_be_bytes());
        }
        command(
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
            &[TPM_RH_OWNER],
            Some(&[pw()]),
            &parameters,
        )
    }

    fn get_random() -> Vec<u8> {
        command(CC_GET_RANDOM, &[], None, &4u16.to_be_bytes())
    }

    #[track_caller]
    fn audited_runtime() -> Tpm2Runtime {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &audit_status(&[CC_GET_RANDOM], &[]),
            "the audit is enabled",
        );
        runtime
    }

    #[test]
    fn command_index_upstream_table_match() {
        assert_eq!(COMMAND_FIRST, 0x0000_011f);
        assert_eq!(command_index(0x0000_011f), Some(0));
        assert_eq!(command_index(0x0000_019f), Some(COMMAND_COUNT - 1));
        assert_eq!(command_index(0x0000_01a0), None);
        assert_eq!(command_index(0x0000_011e), None);
        assert_eq!(command_index(0x2000_0000), None);
        assert_eq!(command_index(0), None);
        for index in 0..COMMAND_COUNT {
            assert_eq!(command_index(command_code(index)), Some(index));
        }
    }

    #[test]
    fn manufactured_default_audit_status_only() {
        let runtime = ready_runtime();
        assert!(is_required(&runtime, TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS));
        for code in [CC_GET_RANDOM, CC_CERTIFY, CC_QUOTE, TPM_CC_SHUTDOWN] {
            assert!(!is_required(&runtime, code), "{code:#010x}");
        }
        assert_eq!(
            audit_hash_alg(&runtime).expect("the algorithm reads"),
            0x000d
        );
        assert_eq!(audit_counter(&runtime).expect("the counter reads"), 0);
        assert!(audit_digest(&runtime).expect("the digest reads").is_empty());
    }

    #[test]
    fn audit_status_removal_shutdown_addition_rejection() {
        let mut bitmap = vec![0u8; AUDIT_COMMANDS_SIZE];
        let runtime = ready_runtime();
        let commands = runtime.state().profile.commands.clone();
        assert!(set_command(
            &mut bitmap,
            &commands,
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS
        ));
        assert!(!set_command(
            &mut bitmap,
            &commands,
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS
        ));
        assert!(!clear_command(
            &mut bitmap,
            &commands,
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS
        ));
        assert!(!set_command(&mut bitmap, &commands, TPM_CC_SHUTDOWN));
        assert!(!set_command(&mut bitmap, &commands, 0x0000_0123));
        assert!(!set_command(&mut bitmap, &commands, 0x2000_0000));
        assert!(set_command(&mut bitmap, &commands, CC_GET_RANDOM));
        assert!(clear_command(&mut bitmap, &commands, CC_GET_RANDOM));
        assert!(!clear_command(&mut bitmap, &commands, CC_GET_RANDOM));
    }

    #[test]
    fn command_list_digest_ascending_order() {
        use crate::library::tpm2::crypto::Hasher;
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &audit_status(&[CC_QUOTE, CC_GET_RANDOM, CC_CERTIFY], &[]),
            "three commands are audited",
        );
        let mut hasher = Hasher::new(0x000d).expect("a compiled hash");
        for code in [
            TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS,
            CC_CERTIFY,
            CC_QUOTE,
            CC_GET_RANDOM,
        ] {
            hasher.update(&code.to_be_bytes());
        }
        assert_eq!(
            command_list_digest(&mut runtime).expect("the digest computes"),
            hasher.finalize(),
            "the digest follows the command index order, not the request order"
        );
    }

    #[test]
    fn audited_command_digest_extension() {
        use crate::library::tpm2::crypto::Hasher;
        let mut runtime = audited_runtime();
        let start = audit_digest(&runtime).expect("the digest reads");
        assert_eq!(start.len(), 64, "the log started with the SHA-512 size");
        let counter = audit_counter(&runtime).expect("the counter reads");

        let response = run(&mut runtime, &get_random());
        assert_eq!(response_code(&response), RC_SUCCESS);

        let mut hasher = Hasher::new(0x000d).expect("a compiled hash");
        hasher.update(&CC_GET_RANDOM.to_be_bytes());
        hasher.update(&4u16.to_be_bytes());
        let cp_hash = hasher.finalize();
        let mut hasher = Hasher::new(0x000d).expect("a compiled hash");
        hasher.update(&0u32.to_be_bytes());
        hasher.update(&CC_GET_RANDOM.to_be_bytes());
        hasher.update(&response[10..]);
        let rp_hash = hasher.finalize();
        let mut hasher = Hasher::new(0x000d).expect("a compiled hash");
        hasher.update(&start);
        hasher.update(&cp_hash);
        hasher.update(&rp_hash);

        assert_eq!(
            audit_digest(&runtime).expect("the digest reads"),
            hasher.finalize()
        );
        assert_eq!(
            audit_counter(&runtime).expect("the counter reads"),
            counter,
            "an ongoing log does not bump the counter"
        );
    }

    #[test]
    fn unaudited_command_log_unchanged() {
        let mut runtime = audited_runtime();
        let before = audit_digest(&runtime).expect("the digest reads");
        run_ok(
            &mut runtime,
            &create_primary(
                TPM_RH_OWNER,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            "an unaudited command runs",
        );
        assert_eq!(audit_digest(&runtime).expect("the digest reads"), before);
    }

    #[test]
    fn failed_command_audit_exclusion() {
        let mut runtime = audited_runtime();
        let before = audit_digest(&runtime).expect("the digest reads");
        let counter = audit_counter(&runtime).expect("the counter reads");
        let mut truncated = get_random();
        truncated.truncate(10);
        truncated[2..6].copy_from_slice(&10u32.to_be_bytes());
        assert_ne!(response_code(&run(&mut runtime, &truncated)), RC_SUCCESS);
        assert_eq!(audit_digest(&runtime).expect("the digest reads"), before);
        assert_eq!(audit_counter(&runtime).expect("the counter reads"), counter);
    }

    #[test]
    fn new_log_nv_requirement() {
        let mut runtime = audited_runtime();
        reset_digest(&mut runtime).expect("the log clears");
        runtime.nv_available = false;
        assert_eq!(
            response_code(&run(&mut runtime, &get_random())),
            RC_NV_UNAVAILABLE,
            "a new log needs to persist the counter"
        );
        assert!(audit_digest(&runtime).expect("the digest reads").is_empty());
        assert_eq!(audit_counter(&runtime).expect("the counter reads"), 1);
    }

    #[test]
    fn ongoing_log_nv_unavailable_preservation() {
        let mut runtime = audited_runtime();
        runtime.nv_available = false;
        assert_eq!(response_code(&run(&mut runtime, &get_random())), RC_SUCCESS);
        assert!(!audit_digest(&runtime).expect("the digest reads").is_empty());
    }

    #[test]
    fn digest_report_nv_requirement() {
        let mut runtime = audited_runtime();
        run_ok(&mut runtime, &get_random(), "the log is open");
        run_ok(
            &mut runtime,
            &audit_status(&[CC_GET_COMMAND_AUDIT_DIGEST], &[]),
            "the report is audited too",
        );
        runtime.nv_available = false;
        let mut parameters = tpm2b(&QUALIFY);
        parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        assert_eq!(
            response_code(&run(
                &mut runtime,
                &command(
                    CC_GET_COMMAND_AUDIT_DIGEST,
                    &[TPM_RH_ENDORSEMENT, TPM_RH_NULL],
                    Some(&[pw(), pw()]),
                    &parameters
                )
            )),
            RC_NV_UNAVAILABLE
        );
    }

    #[test]
    fn session_and_command_log_dual_audit() {
        let mut runtime = audited_runtime();
        let mut parameters = tpm2b(&NONCE_CALLER);
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.push(0x00);
        parameters.extend_from_slice(&ALG_NULL.to_be_bytes());
        parameters.extend_from_slice(&ALG_SHA256.to_be_bytes());
        let session = run_ok(
            &mut runtime,
            &command(
                CC_START_AUTH_SESSION,
                &[TPM_RH_NULL, TPM_RH_NULL],
                None,
                &parameters,
            ),
            "the audit session starts",
        );
        let log_before = audit_digest(&runtime).expect("the digest reads");
        run_ok(
            &mut runtime,
            &audited_get_random(&session),
            "the audited command runs",
        );
        assert_ne!(
            audit_digest(&runtime).expect("the digest reads"),
            log_before,
            "the command log advanced"
        );
        let session_digest = loaded_session(&runtime.live, HMAC_SESSION)
            .expect("the session is loaded")
            .audit_digest
            .clone();
        assert_eq!(session_digest.len(), 32, "the session log is SHA-256");
        assert_ne!(session_digest, vec![0u8; 32]);
    }

    #[test]
    fn reset_log_clearing_restart_preservation() {
        const CC_SHUTDOWN: u32 = 0x0000_0145;

        let mut restart = audited_runtime();
        run_ok(&mut restart, &get_random(), "the log is open");
        let open = audit_digest(&restart).expect("the digest reads");
        assert!(!open.is_empty());
        run_ok(
            &mut restart,
            &command(CC_SHUTDOWN, &[], None, &1u16.to_be_bytes()),
            "the TPM saves its state",
        );
        restart.startup_received = false;
        run_ok(
            &mut restart,
            &command(CC_STARTUP, &[], None, &0u16.to_be_bytes()),
            "the TPM restarts",
        );
        assert_eq!(
            audit_digest(&restart).expect("the digest reads"),
            open,
            "a TPM Restart keeps the command audit log"
        );

        let mut reset = audited_runtime();
        run_ok(&mut reset, &get_random(), "the log is open");
        assert!(!audit_digest(&reset).expect("the digest reads").is_empty());
        reset.startup_received = false;
        run_ok(
            &mut reset,
            &command(CC_STARTUP, &[], None, &0u16.to_be_bytes()),
            "the TPM resets",
        );
        assert!(
            audit_digest(&reset).expect("the digest reads").is_empty(),
            "a TPM Reset clears the command audit log"
        );
    }

    #[test]
    fn tpm_clear_audit_counter_reset() {
        let mut runtime = audited_runtime();
        run_ok(&mut runtime, &get_random(), "the log is open");
        assert_ne!(audit_counter(&runtime).expect("the counter reads"), 0);
        run_ok(
            &mut runtime,
            &command(CC_CLEAR, &[TPM_RH_LOCKOUT], Some(&[pw()]), &[]),
            "the TPM clears",
        );
        assert_eq!(
            audit_counter(&runtime).expect("the counter reads"),
            0,
            "TPM2_Clear resets the audit counter"
        );
        assert!(
            is_required(&runtime, TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS),
            "TPM2_Clear keeps the audited-command list"
        );
    }

    #[test]
    fn log_volatile_state_round_trip() {
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::volatile::volatile_all_store;
        use crate::library::tpm2::{
            attach_volatile_blob_for_test, restore_permanent_blob_for_test,
        };

        let mut runtime = audited_runtime();
        run_ok(&mut runtime, &get_random(), "the log is open");
        let open = audit_digest(&runtime).expect("the digest reads");
        let clock = RecordingClock::new(1_600_000_000_000, 5_000_000);
        let volatile = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
        let permanent = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the permanent state saves");

        let mut restored =
            restore_permanent_blob_for_test(&permanent).expect("the permanent state restores");
        attach_volatile_blob_for_test(&mut restored, &volatile)
            .expect("the volatile state attaches");
        assert_eq!(
            audit_digest(&restored).expect("the digest reads"),
            open,
            "the command audit log round trips through the volatile blob"
        );
        assert_eq!(
            audit_counter(&restored).expect("the counter reads"),
            audit_counter(&runtime).expect("the counter reads")
        );
        assert!(is_required(&restored, CC_GET_RANDOM));
    }

    #[test]
    fn algorithm_change_single_byte_marker() {
        let mut runtime = ready_runtime();
        mark_algorithm_change(&mut runtime).expect("the marker is set");
        assert_eq!(audit_digest(&runtime).expect("the digest reads"), vec![0u8]);
        reset_digest(&mut runtime).expect("the marker clears");
        assert!(audit_digest(&runtime).expect("the digest reads").is_empty());
    }
}
