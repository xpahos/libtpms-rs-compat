use super::hash::HashAlg;

fn with_terminator(label: &[u8]) -> Vec<u8> {
    let mut out = label.to_vec();
    if out.last() != Some(&0) {
        out.push(0);
    }
    out
}

fn truncate_bits(mut out: Vec<u8>, bits: usize) -> Vec<u8> {
    out.truncate(bits.div_ceil(8));
    if !bits.is_multiple_of(8) {
        out[0] &= 0xff >> (8 - bits % 8);
    }
    out
}

pub fn kdfa(hash: HashAlg, key: &[u8], label: &[u8], u: &[u8], v: &[u8], bits: usize) -> Vec<u8> {
    let label = with_terminator(label);
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() * 8 < bits {
        counter += 1;
        out.extend(hash.hmac(
            key,
            &[
                &counter.to_be_bytes(),
                &label,
                u,
                v,
                &(bits as u32).to_be_bytes(),
            ],
        ));
    }
    truncate_bits(out, bits)
}

pub fn kdfe(hash: HashAlg, z: &[u8], label: &[u8], u: &[u8], v: &[u8], bits: usize) -> Vec<u8> {
    let label = with_terminator(label);
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() * 8 < bits {
        counter += 1;
        out.extend(hash.digest(&[&counter.to_be_bytes(), z, &label, u, v]));
    }
    truncate_bits(out, bits)
}

pub fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut counter = 0u32;
    while out.len() < len {
        out.extend(hash.digest(&[seed, &counter.to_be_bytes()]));
        counter += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mgf1_matches_the_rfc8017_construction() {
        let out = mgf1(HashAlg::Sha1, b"foo", 3);
        assert_eq!(hex::encode(out), "1ac907");
        let out = mgf1(HashAlg::Sha1, b"foo", 5);
        assert_eq!(hex::encode(out), "1ac9075cd4");
        let out = mgf1(HashAlg::Sha256, b"bar", 5);
        assert_eq!(hex::encode(out), "382576a784");
    }

    #[test]
    fn kdfa_matches_its_definition() {
        let manual = HashAlg::Sha256.hmac(
            b"key",
            &[
                &1u32.to_be_bytes(),
                b"STORAGE\0",
                b"u",
                b"v",
                &128u32.to_be_bytes(),
            ],
        );
        assert_eq!(
            kdfa(HashAlg::Sha256, b"key", b"STORAGE", b"u", b"v", 128),
            manual[..16]
        );
        assert_eq!(
            kdfa(HashAlg::Sha256, b"key", b"STORAGE\0", b"u", b"v", 128),
            kdfa(HashAlg::Sha256, b"key", b"STORAGE", b"u", b"v", 128)
        );
        let long = kdfa(HashAlg::Sha256, b"k", b"L", b"", b"", 517);
        assert_eq!(long.len(), 65);
        assert_eq!(long[0] & 0xe0, 0);
    }

    #[test]
    fn kdfe_matches_its_definition() {
        let manual = HashAlg::Sha256.digest(&[&1u32.to_be_bytes(), b"z", b"SECRET\0", b"u", b"v"]);
        assert_eq!(
            kdfe(HashAlg::Sha256, b"z", b"SECRET", b"u", b"v", 256),
            manual
        );
    }
}
