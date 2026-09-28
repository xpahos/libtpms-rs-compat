// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/include/libtpms/tpm_library.h
//
// Original upstream authors and copyright notices:
// Written by Stefan Berger
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corporation 2010.
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateBlobKind {
    Permanent,
    Volatile,
    SaveState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateValidationMask(u32);

impl StateValidationMask {
    pub const NONE: Self = Self(0);
    pub const PERMANENT: Self = Self(1);
    pub const VOLATILE: Self = Self(2);
    pub const SAVE_STATE: Self = Self(4);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & 7)
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn permanent(self) -> bool {
        self.0 & Self::PERMANENT.0 != 0
    }

    pub const fn volatile(self) -> bool {
        self.0 & Self::VOLATILE.0 != 0
    }

    pub const fn save_state(self) -> bool {
        self.0 & Self::SAVE_STATE.0 != 0
    }

    pub const fn selects_permanent_blob(self) -> bool {
        self.permanent() || self.save_state()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateInput {
    Empty,
    Data(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateOutput {
    Empty,
    Data(Vec<u8>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(value: u32) -> (bool, bool, bool) {
        let mask = StateValidationMask::from_bits(value);
        (mask.permanent(), mask.volatile(), mask.save_state())
    }

    #[test]
    fn zero_mask_empty_selection() {
        assert_eq!(mask(0), (false, false, false));
        assert_eq!(StateValidationMask::from_bits(0), StateValidationMask::NONE);
        assert_eq!(StateValidationMask::default(), StateValidationMask::NONE);
        assert!(!StateValidationMask::NONE.selects_permanent_blob());
    }

    #[test]
    fn known_bit_single_state_selection() {
        assert_eq!(mask(1), (true, false, false));
        assert_eq!(mask(2), (false, true, false));
        assert_eq!(mask(4), (false, false, true));
    }

    #[test]
    fn known_bit_combination() {
        assert_eq!(mask(1 | 2), (true, true, false));
        assert_eq!(mask(1 | 4), (true, false, true));
        assert_eq!(mask(2 | 4), (false, true, true));
        assert_eq!(mask(1 | 2 | 4), (true, true, true));
    }

    #[test]
    fn unknown_bits_ignored() {
        for value in [8_u32, 16, 0x4000, 1 << 30] {
            assert_eq!(
                StateValidationMask::from_bits(value),
                StateValidationMask::NONE,
                "value {value}"
            );
        }
        assert_eq!(mask(8 | 1), (true, false, false));
        assert_eq!(mask(16 | 2), (false, true, false));
        assert_eq!(mask(1 << 30 | 4), (false, false, true));
        assert_eq!(mask(u32::MAX), (true, true, true));
    }

    #[test]
    fn save_state_bit_permanent_blob_selection() {
        for (value, what) in [(4, "the save-state bit"), (1, "the permanent bit")] {
            assert!(
                StateValidationMask::from_bits(value).selects_permanent_blob(),
                "{what}: TPM2_ValidateState tests st & (PERMANENT | SAVE_STATE) together"
            );
        }
        assert!(!StateValidationMask::from_bits(2).selects_permanent_blob());
    }

    #[test]
    fn empty_state_zero_length_distinction() {
        assert_ne!(StateInput::Empty, StateInput::Data(Vec::new()));
        assert_ne!(StateOutput::Empty, StateOutput::Data(Vec::new()));
    }
}
