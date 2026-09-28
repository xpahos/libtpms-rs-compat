// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/NVCommands.c
// - libtpms/src/tpm2/NV_spt.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2024
// (c) Copyright IBM Corp. and others, 2016 -2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, TPM_RC_NV_UNINITIALIZED,
};
use crate::library::tpm2::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
use crate::library::tpm2::nv::{
    ResolvedIndex, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE, TPMA_NV_PPREAD, TPMA_NV_PPWRITE,
    TPMA_NV_READLOCKED, TPMA_NV_WRITELOCKED, TPMA_NV_WRITTEN, resolve_index,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(in crate::library::tpm2::command) const MAX_NV_BUFFER_SIZE: usize = 1024;

pub(in crate::library::tpm2::command) fn resolve(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<ResolvedIndex, TpmResult> {
    resolve_index(runtime, handle).ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn read_access_checks(
    auth_handle: u32,
    nv_handle: u32,
    attributes: u32,
) -> Result<(), TpmResult> {
    if attributes & TPMA_NV_READLOCKED != 0 {
        return Err(TPM_RC_NV_LOCKED);
    }
    if auth_handle == TPM_RH_OWNER {
        if attributes & TPMA_NV_OWNERREAD == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle == TPM_RH_PLATFORM {
        if attributes & TPMA_NV_PPREAD == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle != nv_handle {
        return Err(TPM_RC_NV_AUTHORIZATION);
    }
    if attributes & TPMA_NV_WRITTEN == 0 {
        return Err(TPM_RC_NV_UNINITIALIZED);
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn write_access_checks(
    auth_handle: u32,
    nv_handle: u32,
    attributes: u32,
) -> Result<(), TpmResult> {
    if attributes & TPMA_NV_WRITELOCKED != 0 {
        return Err(TPM_RC_NV_LOCKED);
    }
    if auth_handle == TPM_RH_OWNER {
        if attributes & TPMA_NV_OWNERWRITE == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle == TPM_RH_PLATFORM {
        if attributes & TPMA_NV_PPWRITE == 0 {
            return Err(TPM_RC_NV_AUTHORIZATION);
        }
    } else if auth_handle != nv_handle {
        return Err(TPM_RC_NV_AUTHORIZATION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::nv::{TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE};

    const INDEX: u32 = 0x0100_0001;
    const OTHER_INDEX: u32 = 0x0100_0002;

    #[test]
    fn read_lock_check_precedence() {
        for attributes in [
            TPMA_NV_READLOCKED,
            TPMA_NV_READLOCKED | TPMA_NV_OWNERREAD | TPMA_NV_WRITTEN,
            TPMA_NV_READLOCKED | TPMA_NV_WRITTEN,
        ] {
            assert_eq!(
                read_access_checks(TPM_RH_OWNER, INDEX, attributes),
                Err(TPM_RC_NV_LOCKED),
                "attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn owner_platform_read_own_attribute_requirement() {
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_WRITTEN),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERREAD | TPMA_NV_WRITTEN),
            Ok(())
        );
        assert_eq!(
            read_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_OWNERREAD | TPMA_NV_WRITTEN),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            read_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_PPREAD | TPMA_NV_WRITTEN),
            Ok(())
        );
    }

    #[test]
    fn read_authorization_self_index_only() {
        assert_eq!(
            read_access_checks(INDEX, INDEX, TPMA_NV_AUTHREAD | TPMA_NV_WRITTEN),
            Ok(())
        );
        assert_eq!(
            read_access_checks(INDEX, INDEX, TPMA_NV_WRITTEN),
            Ok(()),
            "the attribute gate for index authorization is applied by the session layer"
        );
        assert_eq!(
            read_access_checks(OTHER_INDEX, INDEX, TPMA_NV_AUTHREAD | TPMA_NV_WRITTEN),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
    }

    #[test]
    fn unwritten_index_uninitialized_after_authorization() {
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERREAD),
            Err(TPM_RC_NV_UNINITIALIZED)
        );
        assert_eq!(
            read_access_checks(TPM_RH_OWNER, INDEX, 0),
            Err(TPM_RC_NV_AUTHORIZATION),
            "the authorization failure is reported before the uninitialized state"
        );
    }

    #[test]
    fn write_lock_check_precedence() {
        for attributes in [
            TPMA_NV_WRITELOCKED,
            TPMA_NV_WRITELOCKED | TPMA_NV_OWNERWRITE,
        ] {
            assert_eq!(
                write_access_checks(TPM_RH_OWNER, INDEX, attributes),
                Err(TPM_RC_NV_LOCKED),
                "attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn owner_platform_write_own_attribute_requirement() {
        assert_eq!(
            write_access_checks(TPM_RH_OWNER, INDEX, 0),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            write_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERWRITE),
            Ok(())
        );
        assert_eq!(
            write_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_OWNERWRITE),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
        assert_eq!(
            write_access_checks(TPM_RH_PLATFORM, INDEX, TPMA_NV_PPWRITE),
            Ok(())
        );
    }

    #[test]
    fn write_authorization_self_index_only() {
        assert_eq!(write_access_checks(INDEX, INDEX, TPMA_NV_AUTHWRITE), Ok(()));
        assert_eq!(
            write_access_checks(OTHER_INDEX, INDEX, TPMA_NV_AUTHWRITE),
            Err(TPM_RC_NV_AUTHORIZATION)
        );
    }

    #[test]
    fn unwritten_index_write_acceptance() {
        assert_eq!(
            write_access_checks(TPM_RH_OWNER, INDEX, TPMA_NV_OWNERWRITE),
            Ok(()),
            "an unwritten index is still writable"
        );
    }
}
