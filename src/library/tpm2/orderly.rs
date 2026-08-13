pub(super) const SU_NONE_VALUE: u16 = 0xffff;
pub(super) const SU_DA_USED_VALUE: u16 = 0xfffe;

pub(super) fn is_orderly(orderly_state: u16) -> bool {
    orderly_state < SU_DA_USED_VALUE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_values_match_upstream() {
        assert_eq!(SU_NONE_VALUE, 0xffff);
        assert_eq!(SU_DA_USED_VALUE, 0xfffe);
    }

    #[test]
    fn values_below_the_da_used_marker_are_orderly() {
        for orderly_state in [0x0000u16, 0x0001, 0x8001, 0x4001, SU_DA_USED_VALUE - 1] {
            assert!(is_orderly(orderly_state), "state {orderly_state:#06x}");
        }
    }

    #[test]
    fn the_da_used_marker_is_not_orderly() {
        assert!(!is_orderly(SU_DA_USED_VALUE));
    }

    #[test]
    fn the_none_marker_is_not_orderly() {
        assert!(!is_orderly(SU_NONE_VALUE));
    }

    #[test]
    fn the_boundary_is_exact() {
        assert!(is_orderly(SU_DA_USED_VALUE - 1));
        assert!(!is_orderly(SU_DA_USED_VALUE));
        assert!(!is_orderly(SU_NONE_VALUE));
    }
}
