use crate::types::TpmResult;

pub(in crate::library::tpm2::command) const TPM_RC_H: TpmResult = 0x000;
pub(in crate::library::tpm2::command) const TPM_RC_P: TpmResult = 0x040;
pub(in crate::library::tpm2::command) const TPM_RC_1: TpmResult = 0x100;
pub(in crate::library::tpm2::command) const TPM_RC_2: TpmResult = 0x200;
pub(in crate::library::tpm2::command) const TPM_RC_3: TpmResult = 0x300;
pub(in crate::library::tpm2::command) const TPM_RC_4: TpmResult = 0x400;
pub(in crate::library::tpm2::command) const TPM_RC_5: TpmResult = 0x500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_index_constants_vendored_layout_match() {
        assert_eq!(TPM_RC_H, 0x000);
        assert_eq!(TPM_RC_P, 0x040);
        assert_eq!(TPM_RC_1, 0x100);
        assert_eq!(TPM_RC_2, 0x200);
        assert_eq!(TPM_RC_3, 0x300);
        assert_eq!(TPM_RC_4, 0x400);
        assert_eq!(TPM_RC_5, 0x500);
    }
}
