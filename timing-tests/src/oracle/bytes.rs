use num_bigint::BigUint;

pub fn to_fixed(value: &BigUint, width: usize) -> Vec<u8> {
    let raw = value.to_bytes_be();
    let raw = if raw == [0] { Vec::new() } else { raw };
    assert!(raw.len() <= width, "value does not fit in {width} bytes");
    let mut out = vec![0u8; width - raw.len()];
    out.extend_from_slice(&raw);
    out
}

pub fn from_be(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

pub fn from_hex(text: &str) -> BigUint {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BigUint::parse_bytes(clean.as_bytes(), 16).expect("valid hex constant")
}

pub fn bit_length(bytes: &[u8]) -> usize {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    if zeros == bytes.len() {
        return 0;
    }
    (bytes.len() - zeros) * 8 - bytes[zeros].leading_zeros() as usize
}

pub fn leading_zero_bytes(bytes: &[u8]) -> usize {
    bytes.iter().take_while(|b| **b == 0).count()
}

pub fn hamming_weight(bytes: &[u8]) -> u32 {
    bytes.iter().map(|b| b.count_ones()).sum()
}
