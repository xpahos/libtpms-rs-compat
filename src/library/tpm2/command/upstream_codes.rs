pub(super) static UPSTREAM_IMPLEMENTED: [u32; 114] = [
    0x0000_011f,
    0x0000_0120,
    0x0000_0121,
    0x0000_0122,
    0x0000_0124,
    0x0000_0125,
    0x0000_0126,
    0x0000_0127,
    0x0000_0128,
    0x0000_0129,
    0x0000_012a,
    0x0000_012b,
    0x0000_012c,
    0x0000_012d,
    0x0000_012e,
    0x0000_0130,
    0x0000_0131,
    0x0000_0132,
    0x0000_0133,
    0x0000_0134,
    0x0000_0135,
    0x0000_0136,
    0x0000_0137,
    0x0000_0138,
    0x0000_0139,
    0x0000_013a,
    0x0000_013b,
    0x0000_013c,
    0x0000_013d,
    0x0000_013e,
    0x0000_013f,
    0x0000_0140,
    0x0000_0142,
    0x0000_0143,
    0x0000_0144,
    0x0000_0145,
    0x0000_0146,
    0x0000_0147,
    0x0000_0148,
    0x0000_0149,
    0x0000_014a,
    0x0000_014b,
    0x0000_014c,
    0x0000_014d,
    0x0000_014e,
    0x0000_014f,
    0x0000_0150,
    0x0000_0151,
    0x0000_0152,
    0x0000_0153,
    0x0000_0154,
    0x0000_0155,
    0x0000_0156,
    0x0000_0157,
    0x0000_0158,
    0x0000_0159,
    0x0000_015b,
    0x0000_015c,
    0x0000_015d,
    0x0000_015e,
    0x0000_0160,
    0x0000_0161,
    0x0000_0162,
    0x0000_0163,
    0x0000_0164,
    0x0000_0165,
    0x0000_0167,
    0x0000_0168,
    0x0000_0169,
    0x0000_016a,
    0x0000_016b,
    0x0000_016c,
    0x0000_016d,
    0x0000_016e,
    0x0000_016f,
    0x0000_0170,
    0x0000_0171,
    0x0000_0172,
    0x0000_0173,
    0x0000_0174,
    0x0000_0176,
    0x0000_0177,
    0x0000_0178,
    0x0000_017a,
    0x0000_017b,
    0x0000_017c,
    0x0000_017d,
    0x0000_017e,
    0x0000_017f,
    0x0000_0180,
    0x0000_0181,
    0x0000_0182,
    0x0000_0183,
    0x0000_0184,
    0x0000_0185,
    0x0000_0186,
    0x0000_0187,
    0x0000_0188,
    0x0000_0189,
    0x0000_018a,
    0x0000_018b,
    0x0000_018c,
    0x0000_018d,
    0x0000_018e,
    0x0000_018f,
    0x0000_0190,
    0x0000_0191,
    0x0000_0192,
    0x0000_0193,
    0x0000_0197,
    0x0000_0199,
    0x0000_019a,
    0x0000_019b,
    0x0000_019c,
];

pub(super) fn upstream_implements(code: u32) -> bool {
    UPSTREAM_IMPLEMENTED.binary_search(&code).is_ok()
}

#[cfg(test)]
mod tests {
    use super::super::registry::implemented;
    use super::*;

    #[test]
    fn the_table_is_strictly_sorted() {
        assert!(
            UPSTREAM_IMPLEMENTED
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn every_ported_command_is_also_implemented_upstream() {
        for descriptor in implemented() {
            assert!(
                upstream_implements(descriptor.code),
                "code {:#x}",
                descriptor.code
            );
        }
    }

    #[test]
    fn commands_compiled_out_of_the_reference_are_absent() {
        for code in [
            0x0000_012f,
            0x0000_0141,
            0x0000_0179,
            0x0000_0194,
            0x0000_0195,
            0x0000_0196,
            0x0000_0198,
            0x0000_019d,
            0x0000_019e,
            0x0000_019f,
            0x2000_0000,
        ] {
            assert!(!upstream_implements(code), "code {code:#x}");
        }
    }

    #[test]
    fn reserved_gaps_and_out_of_range_codes_are_absent() {
        for code in [
            0x0000_0000,
            0x0000_011e,
            0x0000_0123,
            0x0000_015a,
            0x0000_015f,
            0x0000_0166,
            0x0000_0175,
            0x0000_01a0,
            u32::MAX,
        ] {
            assert!(!upstream_implements(code), "code {code:#x}");
        }
    }
}
