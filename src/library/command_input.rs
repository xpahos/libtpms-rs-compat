use super::constants::TPM_BUFFER_MAX;

const TAG_AND_SIZE_LEN: usize = 6;

#[derive(Debug)]
pub(crate) struct CommandInput {
    received_size: u32,
    bytes: Vec<u8>,
}

impl CommandInput {
    pub(crate) fn required_prefix_len(received_size: u32) -> usize {
        if received_size <= TPM_BUFFER_MAX as u32 {
            received_size as usize
        } else {
            TAG_AND_SIZE_LEN
        }
    }

    pub(crate) fn new(received_size: u32, bytes: Vec<u8>) -> Self {
        assert_eq!(
            bytes.len(),
            Self::required_prefix_len(received_size),
            "callers copy exactly the required prefix of the request"
        );
        Self {
            received_size,
            bytes,
        }
    }

    pub(crate) fn received_size(&self) -> u32 {
        self.received_size
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_range_size_full_prefix() {
        for size in [0u32, 1, 5, 6, 10, 4095, 4096] {
            assert_eq!(
                CommandInput::required_prefix_len(size),
                size as usize,
                "size {size}"
            );
        }
    }

    #[test]
    fn large_received_size_allocation_bound() {
        for size in [
            4097u32,
            0x1_0000,
            i32::MAX as u32,
            i32::MAX as u32 + 1,
            u32::MAX,
        ] {
            assert_eq!(
                CommandInput::required_prefix_len(size),
                TAG_AND_SIZE_LEN,
                "size {size}"
            );
        }
        for size in 0..=u32::MAX >> 16 {
            assert!(CommandInput::required_prefix_len(size << 16) <= TPM_BUFFER_MAX as usize);
        }
    }

    #[test]
    #[should_panic(expected = "required prefix")]
    fn mismatched_prefix_length_panic() {
        let _ = CommandInput::new(100, vec![0u8; 6]);
    }
}
