pub(in crate::library::tpm2) const TPMA_NV_PPWRITE: u32 = 1 << 0;
pub(in crate::library::tpm2) const TPMA_NV_OWNERWRITE: u32 = 1 << 1;
pub(in crate::library::tpm2) const TPMA_NV_AUTHWRITE: u32 = 1 << 2;
pub(in crate::library::tpm2) const TPMA_NV_POLICYWRITE: u32 = 1 << 3;
pub(in crate::library::tpm2) const TPMA_NV_POLICY_DELETE: u32 = 1 << 10;
pub(in crate::library::tpm2) const TPMA_NV_WRITELOCKED: u32 = 1 << 11;
pub(in crate::library::tpm2) const TPMA_NV_WRITEALL: u32 = 1 << 12;
pub(in crate::library::tpm2) const TPMA_NV_WRITEDEFINE: u32 = 1 << 13;
pub(in crate::library::tpm2) const TPMA_NV_WRITE_STCLEAR: u32 = 1 << 14;
pub(in crate::library::tpm2) const TPMA_NV_GLOBALLOCK: u32 = 1 << 15;
pub(in crate::library::tpm2) const TPMA_NV_PPREAD: u32 = 1 << 16;
pub(in crate::library::tpm2) const TPMA_NV_OWNERREAD: u32 = 1 << 17;
pub(in crate::library::tpm2) const TPMA_NV_AUTHREAD: u32 = 1 << 18;
pub(in crate::library::tpm2) const TPMA_NV_POLICYREAD: u32 = 1 << 19;
pub(in crate::library::tpm2) const TPMA_NV_NO_DA: u32 = 1 << 25;
pub(in crate::library::tpm2) const TPMA_NV_ORDERLY: u32 = 1 << 26;
pub(in crate::library::tpm2) const TPMA_NV_CLEAR_STCLEAR: u32 = 1 << 27;
pub(in crate::library::tpm2) const TPMA_NV_READLOCKED: u32 = 1 << 28;
pub(in crate::library::tpm2) const TPMA_NV_WRITTEN: u32 = 1 << 29;
pub(in crate::library::tpm2) const TPMA_NV_PLATFORMCREATE: u32 = 1 << 30;
pub(in crate::library::tpm2) const TPMA_NV_READ_STCLEAR: u32 = 1 << 31;

pub(in crate::library::tpm2) const TPMA_NV_RESERVED: u32 = 0x01f0_0300;

pub(in crate::library::tpm2) const TPMA_NV_TPM_NT_SHIFT: u32 = 4;
pub(in crate::library::tpm2) const TPMA_NV_TPM_NT_MASK: u32 = 0xf << TPMA_NV_TPM_NT_SHIFT;

pub(in crate::library::tpm2) const TPM_NT_ORDINARY: u32 = 0x0;
pub(in crate::library::tpm2) const TPM_NT_COUNTER: u32 = 0x1;
pub(in crate::library::tpm2) const TPM_NT_BITS: u32 = 0x2;
pub(in crate::library::tpm2) const TPM_NT_EXTEND: u32 = 0x4;
pub(in crate::library::tpm2) const TPM_NT_PIN_FAIL: u32 = 0x8;
pub(in crate::library::tpm2) const TPM_NT_PIN_PASS: u32 = 0x9;

pub(in crate::library::tpm2) const MAX_ORDERLY_COUNT: u64 = (1 << 8) - 1;

pub(in crate::library::tpm2) const fn nv_index_type(attributes: u32) -> u32 {
    (attributes & TPMA_NV_TPM_NT_MASK) >> TPMA_NV_TPM_NT_SHIFT
}

pub(in crate::library::tpm2) const fn is_ordinary_index(attributes: u32) -> bool {
    nv_index_type(attributes) == TPM_NT_ORDINARY
}

pub(in crate::library::tpm2) const fn is_counter_index(attributes: u32) -> bool {
    nv_index_type(attributes) == TPM_NT_COUNTER
}

pub(in crate::library::tpm2) const fn is_bits_index(attributes: u32) -> bool {
    nv_index_type(attributes) == TPM_NT_BITS
}

pub(in crate::library::tpm2) const fn is_extend_index(attributes: u32) -> bool {
    nv_index_type(attributes) == TPM_NT_EXTEND
}

pub(in crate::library::tpm2) const fn is_pin_fail_index(attributes: u32) -> bool {
    nv_index_type(attributes) == TPM_NT_PIN_FAIL
}

pub(in crate::library::tpm2) const fn is_pin_pass_index(attributes: u32) -> bool {
    nv_index_type(attributes) == TPM_NT_PIN_PASS
}

pub(in crate::library::tpm2) const fn is_pin_index(attributes: u32) -> bool {
    is_pin_fail_index(attributes) || is_pin_pass_index(attributes)
}

pub(in crate::library::tpm2) fn startup_attributes(mut attributes: u32, reset: bool) -> u32 {
    attributes &= !TPMA_NV_READLOCKED;
    if !is_counter_index(attributes)
        && (attributes & TPMA_NV_CLEAR_STCLEAR != 0 || (attributes & TPMA_NV_ORDERLY != 0 && reset))
    {
        attributes &= !TPMA_NV_WRITTEN;
    }
    if attributes & TPMA_NV_WRITTEN == 0 || attributes & TPMA_NV_WRITEDEFINE == 0 {
        attributes &= !TPMA_NV_WRITELOCKED;
    }
    attributes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_bit_position_tpma_nv_match() {
        assert_eq!(TPMA_NV_PPWRITE, 0x0000_0001);
        assert_eq!(TPMA_NV_OWNERWRITE, 0x0000_0002);
        assert_eq!(TPMA_NV_AUTHWRITE, 0x0000_0004);
        assert_eq!(TPMA_NV_POLICYWRITE, 0x0000_0008);
        assert_eq!(TPMA_NV_TPM_NT_MASK, 0x0000_00f0);
        assert_eq!(TPMA_NV_POLICY_DELETE, 0x0000_0400);
        assert_eq!(TPMA_NV_WRITELOCKED, 0x0000_0800);
        assert_eq!(TPMA_NV_WRITEALL, 0x0000_1000);
        assert_eq!(TPMA_NV_WRITEDEFINE, 0x0000_2000);
        assert_eq!(TPMA_NV_WRITE_STCLEAR, 0x0000_4000);
        assert_eq!(TPMA_NV_GLOBALLOCK, 0x0000_8000);
        assert_eq!(TPMA_NV_PPREAD, 0x0001_0000);
        assert_eq!(TPMA_NV_OWNERREAD, 0x0002_0000);
        assert_eq!(TPMA_NV_AUTHREAD, 0x0004_0000);
        assert_eq!(TPMA_NV_POLICYREAD, 0x0008_0000);
        assert_eq!(TPMA_NV_NO_DA, 0x0200_0000);
        assert_eq!(TPMA_NV_ORDERLY, 0x0400_0000);
        assert_eq!(TPMA_NV_CLEAR_STCLEAR, 0x0800_0000);
        assert_eq!(TPMA_NV_READLOCKED, 0x1000_0000);
        assert_eq!(TPMA_NV_WRITTEN, 0x2000_0000);
        assert_eq!(TPMA_NV_PLATFORMCREATE, 0x4000_0000);
        assert_eq!(TPMA_NV_READ_STCLEAR, 0x8000_0000);
    }

    #[test]
    fn reserved_mask_unassigned_bit_coverage() {
        const ASSIGNED: u32 = TPMA_NV_PPWRITE
            | TPMA_NV_OWNERWRITE
            | TPMA_NV_AUTHWRITE
            | TPMA_NV_POLICYWRITE
            | TPMA_NV_TPM_NT_MASK
            | TPMA_NV_POLICY_DELETE
            | TPMA_NV_WRITELOCKED
            | TPMA_NV_WRITEALL
            | TPMA_NV_WRITEDEFINE
            | TPMA_NV_WRITE_STCLEAR
            | TPMA_NV_GLOBALLOCK
            | TPMA_NV_PPREAD
            | TPMA_NV_OWNERREAD
            | TPMA_NV_AUTHREAD
            | TPMA_NV_POLICYREAD
            | TPMA_NV_NO_DA
            | TPMA_NV_ORDERLY
            | TPMA_NV_CLEAR_STCLEAR
            | TPMA_NV_READLOCKED
            | TPMA_NV_WRITTEN
            | TPMA_NV_PLATFORMCREATE
            | TPMA_NV_READ_STCLEAR;
        assert_eq!(ASSIGNED & TPMA_NV_RESERVED, 0);
        assert_eq!(ASSIGNED | TPMA_NV_RESERVED, u32::MAX);
        assert_eq!(TPMA_NV_RESERVED, 0x01f0_0300);
    }

    #[test]
    fn index_type_nibble_extraction() {
        for nt in 0..16u32 {
            assert_eq!(nv_index_type(nt << TPMA_NV_TPM_NT_SHIFT), nt);
            assert_eq!(
                nv_index_type(0xffff_ff0f | (nt << TPMA_NV_TPM_NT_SHIFT)),
                nt
            );
        }
    }

    #[test]
    fn index_type_predicate_exclusivity() {
        let predicates: [(u32, fn(u32) -> bool); 6] = [
            (TPM_NT_ORDINARY, is_ordinary_index),
            (TPM_NT_COUNTER, is_counter_index),
            (TPM_NT_BITS, is_bits_index),
            (TPM_NT_EXTEND, is_extend_index),
            (TPM_NT_PIN_FAIL, is_pin_fail_index),
            (TPM_NT_PIN_PASS, is_pin_pass_index),
        ];
        for (owner, predicate) in predicates {
            for nt in 0..16u32 {
                assert_eq!(
                    predicate(nt << TPMA_NV_TPM_NT_SHIFT),
                    nt == owner,
                    "type {nt} against owner {owner}"
                );
            }
        }
        for nt in 0..16u32 {
            assert_eq!(
                is_pin_index(nt << TPMA_NV_TPM_NT_SHIFT),
                nt == TPM_NT_PIN_FAIL || nt == TPM_NT_PIN_PASS,
                "type {nt}"
            );
        }
    }

    #[test]
    fn index_type_value_tpm_nt_match() {
        assert_eq!(TPM_NT_ORDINARY, 0);
        assert_eq!(TPM_NT_COUNTER, 1);
        assert_eq!(TPM_NT_BITS, 2);
        assert_eq!(TPM_NT_EXTEND, 4);
        assert_eq!(TPM_NT_PIN_FAIL, 8);
        assert_eq!(TPM_NT_PIN_PASS, 9);
    }

    #[test]
    fn startup_read_lock_clearing() {
        for reset in [false, true] {
            assert_eq!(startup_attributes(TPMA_NV_READLOCKED, reset), 0);
            assert_eq!(
                startup_attributes(TPMA_NV_READLOCKED | TPMA_NV_WRITTEN, reset)
                    & TPMA_NV_READLOCKED,
                0
            );
        }
    }

    #[test]
    fn clear_stclear_index_startup_written_loss() {
        for reset in [false, true] {
            assert_eq!(
                startup_attributes(TPMA_NV_CLEAR_STCLEAR | TPMA_NV_WRITTEN, reset),
                TPMA_NV_CLEAR_STCLEAR
            );
        }
    }

    #[test]
    fn orderly_index_written_loss_reset_only() {
        assert_eq!(
            startup_attributes(TPMA_NV_ORDERLY | TPMA_NV_WRITTEN, true),
            TPMA_NV_ORDERLY
        );
        assert_eq!(
            startup_attributes(TPMA_NV_ORDERLY | TPMA_NV_WRITTEN, false),
            TPMA_NV_ORDERLY | TPMA_NV_WRITTEN
        );
    }

    #[test]
    fn counter_written_startup_preservation() {
        let counter = TPM_NT_COUNTER << TPMA_NV_TPM_NT_SHIFT;
        for extra in [TPMA_NV_CLEAR_STCLEAR, TPMA_NV_ORDERLY] {
            for reset in [false, true] {
                assert_ne!(
                    startup_attributes(counter | extra | TPMA_NV_WRITTEN, reset) & TPMA_NV_WRITTEN,
                    0,
                    "extra {extra:#x} reset {reset}"
                );
            }
        }
    }

    #[test]
    fn written_writedefine_write_lock_preservation() {
        assert_eq!(
            startup_attributes(
                TPMA_NV_WRITEDEFINE | TPMA_NV_WRITTEN | TPMA_NV_WRITELOCKED,
                true
            ),
            TPMA_NV_WRITEDEFINE | TPMA_NV_WRITTEN | TPMA_NV_WRITELOCKED
        );
        assert_eq!(
            startup_attributes(TPMA_NV_WRITEDEFINE | TPMA_NV_WRITELOCKED, true),
            TPMA_NV_WRITEDEFINE
        );
        assert_eq!(
            startup_attributes(TPMA_NV_WRITTEN | TPMA_NV_WRITELOCKED, true),
            TPMA_NV_WRITTEN
        );
    }

    #[test]
    fn orderly_counter_mask_profile_match() {
        assert_eq!(MAX_ORDERLY_COUNT, 255);
    }
}
