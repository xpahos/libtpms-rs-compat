use crate::types::TpmlibStateType;

const TPMLIB_STATE_PERMANENT: TpmlibStateType = 1;
const TPMLIB_STATE_VOLATILE: TpmlibStateType = 2;
const TPMLIB_STATE_SAVE_STATE: TpmlibStateType = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateBlobKind {
    Permanent,
    Volatile,
    SaveState,
}

impl StateBlobKind {
    pub fn from_c(value: TpmlibStateType) -> Option<Self> {
        match value {
            TPMLIB_STATE_PERMANENT => Some(Self::Permanent),
            TPMLIB_STATE_VOLATILE => Some(Self::Volatile),
            TPMLIB_STATE_SAVE_STATE => Some(Self::SaveState),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateValidationMask {
    permanent: bool,
    volatile: bool,
    save_state: bool,
}

impl StateValidationMask {
    pub const NONE: Self = Self {
        permanent: false,
        volatile: false,
        save_state: false,
    };

    pub const fn from_c(value: TpmlibStateType) -> Self {
        Self {
            permanent: value & TPMLIB_STATE_PERMANENT != 0,
            volatile: value & TPMLIB_STATE_VOLATILE != 0,
            save_state: value & TPMLIB_STATE_SAVE_STATE != 0,
        }
    }

    pub const fn permanent(self) -> bool {
        self.permanent
    }

    pub const fn volatile(self) -> bool {
        self.volatile
    }

    pub const fn save_state(self) -> bool {
        self.save_state
    }

    pub const fn selects_permanent_blob(self) -> bool {
        self.permanent || self.save_state
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

    #[test]
    fn kind_maps_exact_c_values() {
        assert_eq!(StateBlobKind::from_c(1), Some(StateBlobKind::Permanent));
        assert_eq!(StateBlobKind::from_c(2), Some(StateBlobKind::Volatile));
        assert_eq!(StateBlobKind::from_c(4), Some(StateBlobKind::SaveState));
    }

    #[test]
    fn kind_rejects_invalid_values() {
        for value in [0, 3, -1, -4, 5, 6, 7, 8, i32::MAX, i32::MIN] {
            assert_eq!(StateBlobKind::from_c(value), None, "value {value}");
        }
    }

    fn mask(value: TpmlibStateType) -> (bool, bool, bool) {
        let mask = StateValidationMask::from_c(value);
        (mask.permanent(), mask.volatile(), mask.save_state())
    }

    #[test]
    fn a_zero_mask_selects_nothing() {
        assert_eq!(mask(0), (false, false, false));
        assert_eq!(StateValidationMask::from_c(0), StateValidationMask::NONE);
        assert_eq!(StateValidationMask::default(), StateValidationMask::NONE);
        assert!(!StateValidationMask::NONE.selects_permanent_blob());
    }

    #[test]
    fn every_known_bit_selects_exactly_its_own_state() {
        assert_eq!(mask(1), (true, false, false));
        assert_eq!(mask(2), (false, true, false));
        assert_eq!(mask(4), (false, false, true));
    }

    #[test]
    fn known_bits_combine() {
        assert_eq!(mask(1 | 2), (true, true, false));
        assert_eq!(mask(1 | 4), (true, false, true));
        assert_eq!(mask(2 | 4), (false, true, true));
        assert_eq!(mask(1 | 2 | 4), (true, true, true));
    }

    #[test]
    fn unknown_bits_are_ignored() {
        for value in [8, 16, 0x4000, i32::MIN, 1 << 30] {
            assert_eq!(
                StateValidationMask::from_c(value),
                StateValidationMask::NONE,
                "value {value}"
            );
        }
        assert_eq!(mask(8 | 1), (true, false, false));
        assert_eq!(mask(16 | 2), (false, true, false));
        assert_eq!(mask(i32::MIN | 4), (false, false, true));
        assert_eq!(mask(-1), (true, true, true));
        assert_eq!(mask(i32::MAX), (true, true, true));
    }

    #[test]
    fn the_save_state_bit_selects_the_permanent_blob_like_upstream() {
        for (value, what) in [(4, "the save-state bit"), (1, "the permanent bit")] {
            assert!(
                StateValidationMask::from_c(value).selects_permanent_blob(),
                "{what}: TPM2_ValidateState tests st & (PERMANENT | SAVE_STATE) together"
            );
        }
        assert!(!StateValidationMask::from_c(2).selects_permanent_blob());
    }

    #[test]
    fn an_empty_state_is_distinct_from_a_zero_length_blob() {
        assert_ne!(StateInput::Empty, StateInput::Data(Vec::new()));
        assert_ne!(StateOutput::Empty, StateOutput::Data(Vec::new()));
    }
}
