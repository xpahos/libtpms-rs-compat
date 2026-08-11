pub(crate) const TPM_LIBRARY_VER_MAJOR: u32 = 0;
pub(crate) const TPM_LIBRARY_VER_MINOR: u32 = 10;
pub(crate) const TPM_LIBRARY_VER_MICRO: u32 = 1;

const fn encode_version(major: u32, minor: u32, micro: u32) -> u32 {
    assert!(major <= u8::MAX as u32);
    assert!(minor <= u8::MAX as u32);
    assert!(micro <= u8::MAX as u32);
    (major << 16) | (minor << 8) | micro
}

pub(crate) const TPM_LIBRARY_VERSION: u32 = encode_version(
    TPM_LIBRARY_VER_MAJOR,
    TPM_LIBRARY_VER_MINOR,
    TPM_LIBRARY_VER_MICRO,
);
