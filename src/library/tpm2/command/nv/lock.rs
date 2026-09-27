use super::access::{read_access_checks, resolve, write_access_checks};
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED,
    TPM_RC_NV_UNAVAILABLE, TPM_RC_SIZE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_2, TPM_RC_H};
use crate::library::tpm2::nv::{
    ResolvedIndex, TPMA_NV_GLOBALLOCK, TPMA_NV_ORDERLY, TPMA_NV_READ_STCLEAR, TPMA_NV_READLOCKED,
    TPMA_NV_WRITE_STCLEAR, TPMA_NV_WRITEDEFINE, TPMA_NV_WRITELOCKED, resolve_index, transact,
    write_index_attributes,
};
use crate::library::tpm2::persistent::OwnedUserNvramEntry;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const RC_NV_INDEX: TpmResult = TPM_RC_H + TPM_RC_2;

pub(in crate::library::tpm2::command) fn execute_write_lock(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let resolved = resolve(runtime, nv_handle)?;
    let attributes = resolved.attributes();
    match write_access_checks(auth_handle, nv_handle, attributes) {
        Ok(()) => {}
        Err(TPM_RC_NV_AUTHORIZATION) => return Err(TPM_RC_NV_AUTHORIZATION),
        Err(_) => return Ok(CommandOutput::empty()),
    }
    if attributes & (TPMA_NV_WRITEDEFINE | TPMA_NV_WRITE_STCLEAR) == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_NV_INDEX);
    }

    set_lock(runtime, &resolved, attributes | TPMA_NV_WRITELOCKED)?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_read_lock(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let auth_handle = handle_at(frame, 0)?;
    let nv_handle = handle_at(frame, 1)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let resolved = resolve(runtime, nv_handle)?;
    let attributes = resolved.attributes();
    match read_access_checks(auth_handle, nv_handle, attributes) {
        Ok(()) => {}
        Err(TPM_RC_NV_AUTHORIZATION) => return Err(TPM_RC_NV_AUTHORIZATION),
        Err(TPM_RC_NV_LOCKED) => return Ok(CommandOutput::empty()),
        Err(_) => {}
    }
    if attributes & TPMA_NV_READ_STCLEAR == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_NV_INDEX);
    }

    set_lock(runtime, &resolved, attributes | TPMA_NV_READLOCKED)?;
    Ok(CommandOutput::empty())
}

pub(in crate::library::tpm2::command) fn execute_global_write_lock(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    handle_at(frame, 0)?;
    if !frame.parameters.is_empty() {
        return Err(TPM_RC_SIZE);
    }

    transact(runtime, apply_global_lock)?;
    Ok(CommandOutput::empty())
}

fn set_lock(
    runtime: &mut Tpm2Runtime,
    resolved: &ResolvedIndex,
    attributes: u32,
) -> Result<(), TpmResult> {
    transact(runtime, |runtime| {
        write_index_attributes(runtime, resolved, attributes)
    })
}

fn apply_global_lock(runtime: &mut Tpm2Runtime) -> Result<(), TpmResult> {
    let stored: Vec<(u32, u32)> = runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .user_nvram
        .entries
        .iter()
        .filter_map(|entry| match entry {
            OwnedUserNvramEntry::NvIndex { handle, index, .. } => Some((*handle, index.attributes)),
            OwnedUserNvramEntry::Persistent { .. } => None,
        })
        .filter(|(_, attributes)| {
            attributes & TPMA_NV_ORDERLY == 0 && attributes & TPMA_NV_GLOBALLOCK != 0
        })
        .collect();

    if !stored.is_empty() && !runtime.nv_available {
        return Err(TPM_RC_NV_UNAVAILABLE);
    }
    for (handle, attributes) in stored {
        let resolved = resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)?;
        write_index_attributes(runtime, &resolved, attributes | TPMA_NV_WRITELOCKED)?;
    }

    let ram = &mut runtime.live.index_orderly_ram;
    let entries: Vec<_> = ram.entries().collect();
    for entry in entries {
        let attributes = ram.attributes(entry);
        if attributes & TPMA_NV_GLOBALLOCK != 0 {
            ram.set_attributes(entry, attributes | TPMA_NV_WRITELOCKED);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        TPM_CC_NV_GLOBAL_WRITE_LOCK, TPM_CC_NV_READ_LOCK, TPM_CC_NV_WRITE_LOCK,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, command, dispatch_bytes, framed, response_code, started_runtime,
    };
    use crate::library::tpm2::command::nv::test_support::{
        assert_unchanged, define, nv_public, snapshot,
    };
    use crate::library::tpm2::golden_responses::nv::nv_vector;
    use crate::library::tpm2::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
    use crate::library::tpm2::nv::{
        TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE, TPMA_NV_PPREAD,
    };

    const RC_SIZE: u32 = 0x095;
    const RC_NV_LOCKED: u32 = 0x148;
    const RC_HANDLE2_ATTRIBUTES: u32 = 0x282;
    const RC_HANDLE2_HANDLE: u32 = 0x28b;

    const INDEX: u32 = 0x0100_0001;
    const READ_WRITE: u32 = TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD;

    #[track_caller]
    fn write(runtime: &mut Tpm2Runtime, index: u32, data: &[u8]) -> Vec<u8> {
        let mut parameters = (data.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(data);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        dispatch_bytes(
            runtime,
            &command(0x0000_0137, &[TPM_RH_OWNER, index], &[&[]], &parameters),
        )
    }

    #[track_caller]
    fn read(runtime: &mut Tpm2Runtime, index: u32, size: u16) -> Vec<u8> {
        let mut parameters = size.to_be_bytes().to_vec();
        parameters.extend_from_slice(&0u16.to_be_bytes());
        dispatch_bytes(
            runtime,
            &command(0x0000_014e, &[TPM_RH_OWNER, index], &[&[]], &parameters),
        )
    }

    #[track_caller]
    fn lock(runtime: &mut Tpm2Runtime, code: u32, auth: u32, index: u32) -> Vec<u8> {
        dispatch_bytes(runtime, &command(code, &[auth, index], &[&[]], &[]))
    }

    #[track_caller]
    fn global_lock(runtime: &mut Tpm2Runtime, auth: u32) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(TPM_CC_NV_GLOBAL_WRITE_LOCK, &[auth], &[&[]], &[]),
        )
    }

    const DATA8: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn write_lock_write_blocking_idempotence() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_WRITE_STCLEAR, 8),
        );
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_WRITE_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("WRITELOCK_STCLEAR")
        );
        assert_eq!(
            write(&mut runtime, INDEX, &DATA8),
            nv_vector("WRITE_AFTER_WRITELOCK")
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_NV_LOCKED
        );
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_WRITE_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("WRITELOCK_AGAIN_IS_SUCCESS"),
            "locking an already locked index is not an error"
        );
    }

    #[test]
    fn write_define_index_lock_acceptance() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_WRITEDEFINE, 8),
        );
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_WRITE_LOCK,
                TPM_RH_OWNER,
                INDEX
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_NV_LOCKED
        );
    }

    #[test]
    fn missing_lock_attribute_write_lock_rejection() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_WRITE_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("WRITELOCK_UNLOCKABLE_IS_ATTRIBUTES")
        );
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_WRITE_LOCK,
                TPM_RH_OWNER,
                INDEX
            )),
            RC_HANDLE2_ATTRIBUTES
        );
    }

    #[test]
    fn read_lock_read_blocking_idempotence() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_READ_STCLEAR, 8),
        );
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_READ_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("READLOCK_UNWRITTEN"),
            "an uninitialized index may still be read locked"
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_SUCCESS
        );
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_READ_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("READLOCK_WRITTEN")
        );
        assert_eq!(
            read(&mut runtime, INDEX, 8),
            nv_vector("READ_AFTER_READLOCK")
        );
        assert_eq!(response_code(&read(&mut runtime, INDEX, 8)), RC_NV_LOCKED);
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_READ_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("READLOCK_AGAIN_IS_SUCCESS")
        );
    }

    #[test]
    fn missing_read_stclear_read_lock_rejection() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_SUCCESS
        );
        assert_eq!(
            lock(&mut runtime, TPM_CC_NV_READ_LOCK, TPM_RH_OWNER, INDEX),
            nv_vector("READLOCK_UNLOCKABLE_IS_ATTRIBUTES")
        );
    }

    #[test]
    fn lock_authorization_failure_attribute_check_precedence() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_OWNERWRITE | TPMA_NV_PPREAD, 8),
        );
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_READ_LOCK,
                TPM_RH_OWNER,
                INDEX
            )),
            TPM_RC_NV_AUTHORIZATION,
            "the owner has no read authorization"
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0002, TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD, 8),
        );
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_WRITE_LOCK,
                TPM_RH_OWNER,
                0x0100_0002
            )),
            TPM_RC_NV_AUTHORIZATION,
            "the owner has no write authorization"
        );
    }

    #[test]
    fn global_write_lock_global_lock_index_scope() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_GLOBALLOCK, 8),
        );
        define(&mut runtime, &nv_public(0x0100_0002, READ_WRITE, 8));
        assert_eq!(
            global_lock(&mut runtime, TPM_RH_OWNER),
            nv_vector("GLOBALWRITELOCK")
        );
        assert_eq!(
            write(&mut runtime, INDEX, &DATA8),
            nv_vector("WRITE_AFTER_GLOBALLOCK")
        );
        assert_eq!(
            response_code(&write(&mut runtime, 0x0100_0002, &DATA8)),
            RC_SUCCESS,
            "an index without GLOBALLOCK is untouched"
        );
    }

    #[test]
    fn global_write_lock_orderly_index_inclusion() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_GLOBALLOCK | TPMA_NV_ORDERLY, 8),
        );
        assert_eq!(
            response_code(&global_lock(&mut runtime, TPM_RH_OWNER)),
            RC_SUCCESS
        );
        assert_ne!(
            runtime.live.index_orderly_ram.views()[0].attributes & TPMA_NV_WRITELOCKED,
            0
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_NV_LOCKED
        );
        let stored = &runtime.state().index_orderly_ram.views()[0];
        assert_eq!(
            stored.attributes & TPMA_NV_WRITELOCKED,
            0,
            "an orderly global lock stays in RAM until the next orderly shutdown"
        );
    }

    #[test]
    fn global_write_lock_no_targets_nv_unchanged() {
        let mut runtime = started_runtime();
        define(&mut runtime, &nv_public(INDEX, READ_WRITE, 8));
        runtime.nv_update_pending = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&global_lock(&mut runtime, TPM_RH_OWNER)),
            RC_SUCCESS
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn global_write_lock_owner_and_platform_auth_acceptance() {
        for auth in [TPM_RH_OWNER, TPM_RH_PLATFORM] {
            let mut runtime = started_runtime();
            define(
                &mut runtime,
                &nv_public(INDEX, READ_WRITE | TPMA_NV_GLOBALLOCK, 8),
            );
            assert_eq!(
                response_code(&global_lock(&mut runtime, auth)),
                RC_SUCCESS,
                "auth {auth:#010x}"
            );
        }
    }

    #[test]
    fn undefined_index_error_handle_attribution() {
        let mut runtime = started_runtime();
        for code in [TPM_CC_NV_WRITE_LOCK, TPM_CC_NV_READ_LOCK] {
            assert_eq!(
                response_code(&lock(&mut runtime, code, TPM_RH_OWNER, INDEX)),
                RC_HANDLE2_HANDLE,
                "code {code:#x}"
            );
        }
    }

    #[test]
    fn trailing_parameters_size_error() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_WRITE_STCLEAR, 8),
        );
        for code in [TPM_CC_NV_WRITE_LOCK, TPM_CC_NV_READ_LOCK] {
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &command(code, &[TPM_RH_OWNER, INDEX], &[&[]], &[0x00]),
                )),
                RC_SIZE,
                "code {code:#x}"
            );
        }
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_GLOBAL_WRITE_LOCK,
                    &[TPM_RH_OWNER],
                    &[&[]],
                    &[0x00]
                ),
            )),
            RC_SIZE
        );
    }

    #[test]
    fn failed_lock_no_state_change() {
        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_WRITE_STCLEAR, 8),
        );
        runtime.nv_update_pending = false;
        runtime.nv_available = false;
        let before = snapshot(&runtime);
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_WRITE_LOCK,
                TPM_RH_OWNER,
                INDEX
            )),
            TPM_RC_NV_UNAVAILABLE
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn startup_lock_clearing_per_attributes() {
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::restore_permanent_blob_for_test;

        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(0x0100_0030, READ_WRITE | TPMA_NV_READ_STCLEAR, 8),
        );
        define(
            &mut runtime,
            &nv_public(0x0100_0031, READ_WRITE | TPMA_NV_WRITEDEFINE, 8),
        );
        assert_eq!(
            response_code(&write(&mut runtime, 0x0100_0030, &DATA8)),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&write(&mut runtime, 0x0100_0031, &DATA8)),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_READ_LOCK,
                TPM_RH_OWNER,
                0x0100_0030
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&lock(
                &mut runtime,
                TPM_CC_NV_WRITE_LOCK,
                TPM_RH_OWNER,
                0x0100_0031
            )),
            RC_SUCCESS
        );

        let blob = persistent_all_store(runtime.state()).expect("the state serializes");
        let mut restarted = restore_permanent_blob_for_test(&blob).expect("the blob restores");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut restarted,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );

        assert_eq!(
            read(&mut restarted, 0x0100_0030, 8),
            nv_vector("STCLEAR_READ_AFTER_RESTART"),
            "the read lock is cleared by TPM Reset"
        );
        assert_eq!(
            write(&mut restarted, 0x0100_0031, &DATA8),
            nv_vector("STCLEAR_WRITE_AFTER_RESTART"),
            "a written WRITEDEFINE index keeps its write lock"
        );
        assert_eq!(
            dispatch_bytes(
                &mut restarted,
                &framed(0x0000_0169, &0x0100_0031u32.to_be_bytes(), false)
            ),
            nv_vector("STCLEAR_READPUBLIC_AFTER_RESTART")
        );
    }

    #[test]
    fn global_lock_restart_clearing_without_write_define() {
        use crate::library::tpm2::persistent::persistent_all_store;
        use crate::library::tpm2::restore_permanent_blob_for_test;

        let mut runtime = started_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, READ_WRITE | TPMA_NV_GLOBALLOCK, 8),
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&global_lock(&mut runtime, TPM_RH_OWNER)),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&write(&mut runtime, INDEX, &DATA8)),
            RC_NV_LOCKED
        );

        let blob = persistent_all_store(runtime.state()).expect("the state serializes");
        let mut restarted = restore_permanent_blob_for_test(&blob).expect("the blob restores");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut restarted,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&write(&mut restarted, INDEX, &DATA8)),
            RC_SUCCESS,
            "TPM Reset unlocks an index that does not have WRITEDEFINE"
        );
    }
}
