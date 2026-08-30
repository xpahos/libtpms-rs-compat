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
