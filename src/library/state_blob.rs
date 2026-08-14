use crate::ffi_types::TpmlibStateType;

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

    #[test]
    fn an_empty_state_is_distinct_from_a_zero_length_blob() {
        assert_ne!(StateInput::Empty, StateInput::Data(Vec::new()));
        assert_ne!(StateOutput::Empty, StateOutput::Data(Vec::new()));
    }
}
