// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/CommandCodeAttributes.c
// - libtpms/src/tpm2/NVMarshal.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// Written by Stefan Berger
// (c) Copyright IBM Corporation 2017,2018.
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::marshal::BlobReader;
use super::persistent::{PersistentAllError, StateSection};

pub(super) const COMMAND_COUNT: usize = 129;

const COMPRESSED_UNTIL_VERSION: u16 = 4;

pub(super) fn parse_command_bitmap<'a>(
    reader: &mut BlobReader<'a>,
    blob_version: u16,
    section: StateSection,
    capacity: usize,
) -> Result<(bool, &'a [u8]), PersistentAllError> {
    let array_size = reader
        .read_u16()
        .map_err(|_| PersistentAllError::Truncated { section })?;
    let compressed = blob_version <= COMPRESSED_UNTIL_VERSION;

    if !compressed && usize::from(array_size) > capacity {
        return Err(PersistentAllError::CommandArraySizeExceeded {
            section,
            actual: array_size,
            maximum: capacity,
        });
    }

    let array = reader
        .take(usize::from(array_size))
        .map_err(|_| PersistentAllError::Truncated { section })?;
    Ok((compressed, array))
}
