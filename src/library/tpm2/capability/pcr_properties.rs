// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/PCR.c
// - libtpms/src/tpm2/TpmTypes.h
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

use super::super::marshal::BlobWriter;
use super::super::pcr::{
    pcr_auth_value_group, pcr_in_tcb_group, pcr_platform_attributes, pcr_policy_group,
};
use super::super::volatile::IMPLEMENTATION_PCR;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

pub(in crate::library::tpm2) const TPM_PT_PCR_SAVE: u32 = 0x0000_0000;
pub(in crate::library::tpm2) const TPM_PT_PCR_EXTEND_L0: u32 = 0x0000_0001;
pub(in crate::library::tpm2) const TPM_PT_PCR_RESET_L0: u32 = 0x0000_0002;
pub(in crate::library::tpm2) const TPM_PT_PCR_EXTEND_L1: u32 = 0x0000_0003;
pub(in crate::library::tpm2) const TPM_PT_PCR_RESET_L1: u32 = 0x0000_0004;
pub(in crate::library::tpm2) const TPM_PT_PCR_EXTEND_L2: u32 = 0x0000_0005;
pub(in crate::library::tpm2) const TPM_PT_PCR_RESET_L2: u32 = 0x0000_0006;
pub(in crate::library::tpm2) const TPM_PT_PCR_EXTEND_L3: u32 = 0x0000_0007;
pub(in crate::library::tpm2) const TPM_PT_PCR_RESET_L3: u32 = 0x0000_0008;
pub(in crate::library::tpm2) const TPM_PT_PCR_EXTEND_L4: u32 = 0x0000_0009;
pub(in crate::library::tpm2) const TPM_PT_PCR_RESET_L4: u32 = 0x0000_000a;
pub(in crate::library::tpm2) const TPM_PT_PCR_NO_INCREMENT: u32 = 0x0000_0011;
pub(in crate::library::tpm2) const TPM_PT_PCR_DRTM_RESET: u32 = 0x0000_0012;
pub(in crate::library::tpm2) const TPM_PT_PCR_POLICY: u32 = 0x0000_0013;
pub(in crate::library::tpm2) const TPM_PT_PCR_AUTH: u32 = 0x0000_0014;

const TPM_PT_PCR_LAST: u32 = TPM_PT_PCR_AUTH;

pub(in crate::library::tpm2) const PCR_SELECT_BYTES: usize = IMPLEMENTATION_PCR.div_ceil(8);

const SIZEOF_TPMS_TAGGED_PCR_SELECT: usize = (4 + 1 + PCR_SELECT_BYTES).next_multiple_of(4);
const MAX_PCR_PROPERTIES: usize = MAX_CAP_DATA / SIZEOF_TPMS_TAGGED_PCR_SELECT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct TaggedPcrSelect {
    pub(in crate::library::tpm2) property: u32,
    pub(in crate::library::tpm2) select: Vec<u8>,
}

impl TaggedPcrSelect {
    pub(in crate::library::tpm2) fn marshal(&self) -> Vec<u8> {
        let mut writer = BlobWriter::with_capacity(4 + 1 + self.select.len());
        writer.write_u32(self.property);
        writer.write_u8(self.select.len() as u8);
        writer.write_bytes(&self.select);
        writer.into_bytes()
    }
}

fn selected(property: u32, pcr: usize) -> Option<bool> {
    let attributes = pcr_platform_attributes(pcr);
    Some(match property {
        TPM_PT_PCR_SAVE => attributes.state_save,
        TPM_PT_PCR_EXTEND_L0 => attributes.extend_locality & 0x01 != 0,
        TPM_PT_PCR_RESET_L0 => attributes.reset_locality & 0x01 != 0,
        TPM_PT_PCR_EXTEND_L1 => attributes.extend_locality & 0x02 != 0,
        TPM_PT_PCR_RESET_L1 => attributes.reset_locality & 0x02 != 0,
        TPM_PT_PCR_EXTEND_L2 => attributes.extend_locality & 0x04 != 0,
        TPM_PT_PCR_RESET_L2 => attributes.reset_locality & 0x04 != 0,
        TPM_PT_PCR_EXTEND_L3 => attributes.extend_locality & 0x08 != 0,
        TPM_PT_PCR_RESET_L3 => attributes.reset_locality & 0x08 != 0,
        TPM_PT_PCR_EXTEND_L4 => attributes.extend_locality & 0x10 != 0,
        TPM_PT_PCR_RESET_L4 | TPM_PT_PCR_DRTM_RESET => attributes.reset_locality & 0x10 != 0,
        TPM_PT_PCR_POLICY => pcr_policy_group(pcr).is_some(),
        TPM_PT_PCR_AUTH => pcr_auth_value_group(pcr).is_some(),
        TPM_PT_PCR_NO_INCREMENT => pcr_in_tcb_group(pcr),
        _ => return None,
    })
}

pub(in crate::library::tpm2) fn one(property: u32) -> Option<TaggedPcrSelect> {
    let mut select = vec![0u8; PCR_SELECT_BYTES];
    for pcr in 0..IMPLEMENTATION_PCR {
        if selected(property, pcr)? {
            select[pcr / 8] |= 1 << (pcr % 8);
        }
    }
    Some(TaggedPcrSelect { property, select })
}

pub(in crate::library::tpm2) fn collect(
    starting_property: u32,
    requested_count: u32,
) -> CapabilityPage<TaggedPcrSelect> {
    paginate(
        (starting_property..=TPM_PT_PCR_LAST).filter_map(one),
        requested_count,
        MAX_PCR_PROPERTIES,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMPLEMENTED: [u32; 15] = [
        TPM_PT_PCR_SAVE,
        TPM_PT_PCR_EXTEND_L0,
        TPM_PT_PCR_RESET_L0,
        TPM_PT_PCR_EXTEND_L1,
        TPM_PT_PCR_RESET_L1,
        TPM_PT_PCR_EXTEND_L2,
        TPM_PT_PCR_RESET_L2,
        TPM_PT_PCR_EXTEND_L3,
        TPM_PT_PCR_RESET_L3,
        TPM_PT_PCR_EXTEND_L4,
        TPM_PT_PCR_RESET_L4,
        TPM_PT_PCR_NO_INCREMENT,
        TPM_PT_PCR_DRTM_RESET,
        TPM_PT_PCR_POLICY,
        TPM_PT_PCR_AUTH,
    ];

    fn tags(page: &CapabilityPage<TaggedPcrSelect>) -> Vec<u32> {
        page.entries.iter().map(|entry| entry.property).collect()
    }

    #[test]
    fn capacity_vendored_structure_size_match() {
        assert_eq!(PCR_SELECT_BYTES, 3);
        assert_eq!(SIZEOF_TPMS_TAGGED_PCR_SELECT, 8);
        assert_eq!(MAX_PCR_PROPERTIES, 127);
    }

    #[test]
    fn complete_page_implemented_property_order() {
        let page = collect(0, 1000);
        assert_eq!(tags(&page), IMPLEMENTED);
        assert!(!page.more_data);
    }

    #[test]
    fn unimplemented_property_skip_scan_continuation() {
        for property in [0x0000_000bu32, 0x0000_000c, 0x0000_0010] {
            assert!(one(property).is_none(), "{property:#x}");
        }
        let page = collect(0x0000_000b, 1000);
        assert_eq!(
            tags(&page),
            [
                TPM_PT_PCR_NO_INCREMENT,
                TPM_PT_PCR_DRTM_RESET,
                TPM_PT_PCR_POLICY,
                TPM_PT_PCR_AUTH
            ]
        );
        assert!(!page.more_data);
    }

    #[test]
    fn mid_range_start_inclusion() {
        let page = collect(TPM_PT_PCR_RESET_L2, 1000);
        assert_eq!(tags(&page)[0], TPM_PT_PCR_RESET_L2);
        assert_eq!(tags(&page).len(), IMPLEMENTED.len() - 6);
        assert!(!page.more_data);
    }

    #[test]
    fn past_end_start_empty_page() {
        for start in [TPM_PT_PCR_AUTH + 1, 0x0000_00ff, u32::MAX] {
            let page = collect(start, 1000);
            assert!(page.entries.is_empty(), "{start:#x}");
            assert!(!page.more_data, "{start:#x}");
        }
    }

    #[test]
    fn zero_count_conditional_more_data() {
        let page = collect(0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = collect(TPM_PT_PCR_AUTH + 1, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn requested_count_page_truncation() {
        let page = collect(0, 3);
        assert_eq!(
            tags(&page),
            [TPM_PT_PCR_SAVE, TPM_PT_PCR_EXTEND_L0, TPM_PT_PCR_RESET_L0]
        );
        assert!(page.more_data);

        let page = collect(0, IMPLEMENTED.len() as u32);
        assert_eq!(tags(&page).len(), IMPLEMENTED.len());
        assert!(!page.more_data);

        let page = collect(0, IMPLEMENTED.len() as u32 - 1);
        assert_eq!(tags(&page).len(), IMPLEMENTED.len() - 1);
        assert!(page.more_data);
    }

    #[test]
    fn selection_bytes_vendored_platform_table_match() {
        let save = one(TPM_PT_PCR_SAVE).expect("implemented").marshal();
        assert_eq!(&save[..4], &TPM_PT_PCR_SAVE.to_be_bytes());
        assert_eq!(save[4], 3);
        assert_eq!(&save[5..], &[0xff, 0xff, 0x00]);

        assert_eq!(
            &one(TPM_PT_PCR_EXTEND_L4).expect("implemented").marshal()[5..],
            &[0xff, 0xff, 0x87]
        );
        assert_eq!(
            one(TPM_PT_PCR_RESET_L4).expect("implemented").select,
            one(TPM_PT_PCR_DRTM_RESET).expect("implemented").select
        );
        assert_eq!(
            &one(TPM_PT_PCR_NO_INCREMENT).expect("implemented").marshal()[5..],
            &[0x00, 0x00, 0xe1]
        );
        for empty in [TPM_PT_PCR_POLICY, TPM_PT_PCR_AUTH] {
            assert_eq!(
                one(empty).expect("implemented").select,
                [0x00, 0x00, 0x00],
                "{empty:#x}"
            );
        }
    }
}
