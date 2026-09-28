// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/PropertyCap.c
// - libtpms/src/tpm2/TpmProfile.h
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
// (c) Copyright IBM Corp. and others, 2019 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::TPM_BUFFER_MAX;

const MAX_CONTEXT_SIZE: u32 = 2680;

pub(in crate::library) const MIN_BUFFER_SIZE: u32 = MAX_CONTEXT_SIZE + 128;
pub(in crate::library) const MAX_BUFFER_SIZE: u32 = TPM_BUFFER_MAX;
pub(in crate::library) const DEFAULT_BUFFER_SIZE: u32 = MAX_BUFFER_SIZE;

pub(in crate::library) fn clamp_buffer_size(wanted_size: u32) -> u32 {
    wanted_size.clamp(MIN_BUFFER_SIZE, MAX_BUFFER_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reference_build_match() {
        assert_eq!(MIN_BUFFER_SIZE, 2808);
        assert_eq!(MAX_BUFFER_SIZE, 4096);
        assert_eq!(DEFAULT_BUFFER_SIZE, 4096);
    }

    #[test]
    fn wanted_size_inclusive_range_clamp() {
        assert_eq!(clamp_buffer_size(1), MIN_BUFFER_SIZE);
        assert_eq!(clamp_buffer_size(MIN_BUFFER_SIZE - 1), MIN_BUFFER_SIZE);
        assert_eq!(clamp_buffer_size(MIN_BUFFER_SIZE), MIN_BUFFER_SIZE);
        assert_eq!(clamp_buffer_size(3000), 3000);
        assert_eq!(clamp_buffer_size(MAX_BUFFER_SIZE), MAX_BUFFER_SIZE);
        assert_eq!(clamp_buffer_size(MAX_BUFFER_SIZE + 1), MAX_BUFFER_SIZE);
        assert_eq!(clamp_buffer_size(u32::MAX), MAX_BUFFER_SIZE);
    }
}
