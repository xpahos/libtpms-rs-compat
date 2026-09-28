// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CapabilityCommands.c
// - libtpms/src/tpm2/Entity.c
// - libtpms/src/tpm2/PCR.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::super::algorithm::TPM_ALG_NULL;
use super::super::crypto::COMPILED_HASHES;
use super::super::entity::entity_auth_policy;
use super::super::hierarchy::{IMPLEMENTED_PERMANENT_HANDLES, is_hierarchy_auth_handle};
use super::super::marshal::BlobWriter;
use super::super::runtime::Tpm2Runtime;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const SIZEOF_TPMT_HA: usize = 2 + 64;
const SIZEOF_TPMS_TAGGED_POLICY: usize = (4 + SIZEOF_TPMT_HA).next_multiple_of(4);
const MAX_TAGGED_POLICIES: usize = MAX_CAP_DATA / SIZEOF_TPMS_TAGGED_POLICY;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct TaggedPolicy {
    pub(in crate::library::tpm2) handle: u32,
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) digest: Vec<u8>,
}

impl TaggedPolicy {
    pub(in crate::library::tpm2) fn marshal(&self) -> Vec<u8> {
        let mut writer = BlobWriter::with_capacity(4 + 2 + self.digest.len());
        writer.write_u32(self.handle);
        writer.write_u16(self.hash_alg);
        writer.write_bytes(&self.digest);
        writer.into_bytes()
    }
}

fn carries_a_policy(handle: u32) -> bool {
    IMPLEMENTED_PERMANENT_HANDLES.contains(&handle) && is_hierarchy_auth_handle(handle)
}

pub(in crate::library::tpm2) fn one(runtime: &Tpm2Runtime, handle: u32) -> Option<TaggedPolicy> {
    if !carries_a_policy(handle) {
        return None;
    }
    let (hash_alg, digest) = entity_auth_policy(runtime, handle).ok()?;
    if hash_alg == TPM_ALG_NULL {
        return Some(TaggedPolicy {
            handle,
            hash_alg,
            digest: Vec::new(),
        });
    }
    let size = COMPILED_HASHES
        .iter()
        .find(|(algorithm, _)| *algorithm == hash_alg)
        .map(|(_, size)| *size)?;
    let mut padded = digest;
    padded.resize(size, 0);
    Some(TaggedPolicy {
        handle,
        hash_alg,
        digest: padded,
    })
}

pub(in crate::library::tpm2) fn collect(
    runtime: &Tpm2Runtime,
    starting_handle: u32,
    requested_count: u32,
) -> CapabilityPage<TaggedPolicy> {
    let mut handles = IMPLEMENTED_PERMANENT_HANDLES;
    handles.sort_unstable();
    paginate(
        handles
            .into_iter()
            .filter(|&handle| handle >= starting_handle)
            .filter_map(|handle| one(runtime, handle)),
        requested_count,
        MAX_TAGGED_POLICIES,
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_runtime::started;
    use super::*;

    const TPM_RH_OWNER: u32 = 0x4000_0001;
    const TPM_RH_NULL: u32 = 0x4000_0007;
    const TPM_RS_PW: u32 = 0x4000_0009;
    const TPM_RH_LOCKOUT: u32 = 0x4000_000a;
    const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
    const TPM_RH_PLATFORM: u32 = 0x4000_000c;
    const TPM_RH_PLATFORM_NV: u32 = 0x4000_000d;
    const TPM_ALG_SHA256: u16 = 0x000b;

    const POLICY_HANDLES: [u32; 4] = [
        TPM_RH_OWNER,
        TPM_RH_LOCKOUT,
        TPM_RH_ENDORSEMENT,
        TPM_RH_PLATFORM,
    ];

    fn handles(page: &CapabilityPage<TaggedPolicy>) -> Vec<u32> {
        page.entries.iter().map(|entry| entry.handle).collect()
    }

    fn set_owner_policy(runtime: &mut Tpm2Runtime, digest: &[u8]) {
        let persistent = &mut runtime.state.as_mut().expect("decoded state").persistent;
        persistent.owner_alg = TPM_ALG_SHA256;
        persistent.owner_policy = digest.to_vec();
    }

    #[test]
    fn capacity_vendored_structure_size_match() {
        assert_eq!(SIZEOF_TPMS_TAGGED_POLICY, 72);
        assert_eq!(MAX_TAGGED_POLICIES, 14);
    }

    #[test]
    fn policy_capable_hierarchies_only() {
        let runtime = started();
        let page = collect(&runtime, 0x4000_0000, 1000);
        assert_eq!(handles(&page), POLICY_HANDLES);
        assert!(!page.more_data);
        for absent in [TPM_RH_NULL, TPM_RS_PW, TPM_RH_PLATFORM_NV, 0x4000_0002] {
            assert!(one(&runtime, absent).is_none(), "{absent:#x}");
        }
    }

    #[test]
    fn unset_policy_null_hash_empty_digest() {
        let runtime = started();
        let page = collect(&runtime, 0x4000_0000, 1000);
        for entry in &page.entries {
            assert_eq!(entry.hash_alg, TPM_ALG_NULL, "{:#x}", entry.handle);
            assert!(entry.digest.is_empty(), "{:#x}", entry.handle);
            assert_eq!(entry.marshal().len(), 6, "{:#x}", entry.handle);
        }
    }

    #[test]
    fn set_policy_digest_size_padding() {
        let mut runtime = started();
        set_owner_policy(&mut runtime, &[0xa5; 20]);
        let owner = one(&runtime, TPM_RH_OWNER).expect("the owner carries a policy");
        assert_eq!(owner.hash_alg, TPM_ALG_SHA256);
        assert_eq!(owner.digest.len(), 32);
        assert_eq!(&owner.digest[..20], &[0xa5; 20]);
        assert!(owner.digest[20..].iter().all(|&byte| byte == 0));
        let marshalled = owner.marshal();
        assert_eq!(marshalled.len(), 4 + 2 + 32);
        assert_eq!(&marshalled[..4], &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(&marshalled[4..6], &TPM_ALG_SHA256.to_be_bytes());
    }

    #[test]
    fn starting_handle_inclusive_boundary() {
        let runtime = started();
        let page = collect(&runtime, TPM_RH_ENDORSEMENT, 1000);
        assert_eq!(handles(&page), [TPM_RH_ENDORSEMENT, TPM_RH_PLATFORM]);
        assert!(!page.more_data);

        let page = collect(&runtime, TPM_RH_ENDORSEMENT + 1, 1000);
        assert_eq!(handles(&page), [TPM_RH_PLATFORM]);
        assert!(!page.more_data);
    }

    #[test]
    fn start_past_last_handle_empty_page() {
        let runtime = started();
        for start in [TPM_RH_PLATFORM + 1, 0x4000_ffff, u32::MAX] {
            let page = collect(&runtime, start, 1000);
            assert!(page.entries.is_empty(), "{start:#x}");
            assert!(!page.more_data, "{start:#x}");
        }
    }

    #[test]
    fn zero_count_more_data_remainder_dependence() {
        let runtime = started();
        let page = collect(&runtime, 0x4000_0000, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = collect(&runtime, TPM_RH_PLATFORM + 1, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn requested_count_page_truncation() {
        let runtime = started();
        let page = collect(&runtime, 0x4000_0000, 2);
        assert_eq!(handles(&page), [TPM_RH_OWNER, TPM_RH_LOCKOUT]);
        assert!(page.more_data);

        let page = collect(&runtime, 0x4000_0000, 4);
        assert_eq!(handles(&page).len(), 4);
        assert!(!page.more_data);

        let page = collect(&runtime, 0x4000_0000, 3);
        assert_eq!(handles(&page).len(), 3);
        assert!(page.more_data);
    }
}
