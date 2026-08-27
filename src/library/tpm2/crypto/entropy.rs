use crate::ffi::types::TpmResult;
use crate::library::constants::TPM_FAIL;

pub(in crate::library) type EntropySource = fn(&mut [u8]) -> Result<(), TpmResult>;

const MAX_GETENTROPY_CHUNK: usize = 256;

pub(in crate::library) fn os_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
    for chunk in buffer.chunks_mut(MAX_GETENTROPY_CHUNK) {
        // SAFETY: the pointer/length pair denotes a live, writable,
        // uniquely borrowed buffer of at most 256 bytes.
        let result = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        if result != 0 {
            return Err(TPM_FAIL);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills_small_and_chunked_requests() {
        let mut small = [0u8; 48];
        os_entropy(&mut small).expect("48 bytes");
        let mut large = vec![0u8; MAX_GETENTROPY_CHUNK * 2 + 5];
        os_entropy(&mut large).expect("chunked request");
        assert!(small.iter().any(|&byte| byte != 0));
        assert!(large.iter().any(|&byte| byte != 0));
    }

    #[test]
    fn zero_length_request_is_a_no_op() {
        os_entropy(&mut []).expect("empty request");
    }
}
