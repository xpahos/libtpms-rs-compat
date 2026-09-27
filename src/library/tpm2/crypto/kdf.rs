use super::hash::Hasher;
use super::hmac::HmacState;

pub(in crate::library::tpm2) fn kdfa(
    hash_alg: u16,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    size_in_bits: u32,
) -> Option<Vec<u8>> {
    let mut counter = 0;
    kdfa_from(
        hash_alg,
        key,
        label,
        context_u,
        context_v,
        size_in_bits,
        &mut counter,
    )
}

pub(in crate::library::tpm2) fn kdfa_from(
    hash_alg: u16,
    key: &[u8],
    label: &[u8],
    context_u: &[u8],
    context_v: &[u8],
    size_in_bits: u32,
    counter: &mut u32,
) -> Option<Vec<u8>> {
    let digest_size = super::hash::COMPILED_HASHES
        .iter()
        .find(|(algorithm, _)| *algorithm == hash_alg)
        .map(|(_, size)| *size)?;

    let wanted = usize::try_from(size_in_bits.div_ceil(8)).ok()?;
    let mut out = Vec::with_capacity(wanted.next_multiple_of(digest_size));
    while out.len() < wanted {
        *counter = counter.checked_add(1)?;
        let counter = *counter;
        let mut hmac = HmacState::new(hash_alg, key)?;
        hmac.update(&counter.to_be_bytes());
        hmac.update(label);
        if label.last() != Some(&0) {
            hmac.update(&[0]);
        }
        hmac.update(context_u);
        hmac.update(context_v);
        hmac.update(&size_in_bits.to_be_bytes());
        out.extend_from_slice(&hmac.finalize());
    }
    out.truncate(wanted);
    Some(out)
}

pub(in crate::library::tpm2) fn kdfe(
    hash_alg: u16,
    z: &[u8],
    label: &[u8],
    party_u_info: &[u8],
    party_v_info: &[u8],
    size_in_bits: u32,
) -> Option<Vec<u8>> {
    let digest_size = super::hash::COMPILED_HASHES
        .iter()
        .find(|(algorithm, _)| *algorithm == hash_alg)
        .map(|(_, size)| *size)?;

    let wanted = usize::try_from(size_in_bits.div_ceil(8)).ok()?;
    let mut out = Vec::with_capacity(wanted.next_multiple_of(digest_size));
    let mut counter: u32 = 0;
    while out.len() < wanted {
        counter = counter.checked_add(1)?;
        let mut hasher = Hasher::new(hash_alg)?;
        hasher.update(&counter.to_be_bytes());
        hasher.update(z);
        hasher.update(label);
        hasher.update(party_u_info);
        hasher.update(party_v_info);
        out.extend_from_slice(&hasher.finalize());
    }
    out.truncate(wanted);
    if !size_in_bits.is_multiple_of(8) {
        out[0] &= (1u8 << (size_in_bits % 8)) - 1;
    }
    Some(out)
}

pub(in crate::library::tpm2) fn mgf1(hash_alg: u16, seed: &[u8], length: usize) -> Option<Vec<u8>> {
    let digest_size = super::hash::COMPILED_HASHES
        .iter()
        .find(|(algorithm, _)| *algorithm == hash_alg)
        .map(|(_, size)| *size)?;

    let mut out = Vec::with_capacity(length.next_multiple_of(digest_size));
    let mut counter: u32 = 0;
    while out.len() < length {
        let mut hasher = Hasher::new(hash_alg)?;
        hasher.update(seed);
        hasher.update(&counter.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    out.truncate(length);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::{TPM_ALG_NULL, TPM_ALG_SHA1, TPM_ALG_SHA256};
    use crate::library::tpm2::test_support::hex_string;

    #[test]
    fn unsupported_hash_empty_key_stream() {
        assert!(kdfa(TPM_ALG_NULL, b"key", b"L", &[], &[], 128).is_none());
        assert!(mgf1(TPM_ALG_NULL, b"seed", 32).is_none());
    }

    #[test]
    fn key_stream_length_requested_bits() {
        for (bits, expected) in [(8u32, 1usize), (128, 16), (256, 32), (264, 33), (1024, 128)] {
            let stream = kdfa(TPM_ALG_SHA256, b"key", b"L", &[], &[], bits).unwrap();
            assert_eq!(stream.len(), expected, "{bits} bits");
        }
    }

    #[test]
    fn null_terminated_label_no_repadding() {
        let padded = kdfa(TPM_ALG_SHA256, b"key", b"L\0", &[], &[], 128).unwrap();
        let unpadded = kdfa(TPM_ALG_SHA256, b"key", b"L", &[], &[], 128).unwrap();
        assert_eq!(
            padded, unpadded,
            "upstream appends the terminating zero only when the label lacks one"
        );
    }

    #[test]
    fn empty_label_zero_byte_contribution() {
        let empty = kdfa(TPM_ALG_SHA256, b"key", &[], &[], &[], 128).unwrap();
        let zero = kdfa(TPM_ALG_SHA256, b"key", &[0], &[], &[], 128).unwrap();
        assert_eq!(empty, zero);
    }

    #[test]
    fn key_stream_input_sensitivity() {
        let base = kdfa(TPM_ALG_SHA256, b"key", b"L", b"u", b"v", 128).unwrap();
        for other in [
            kdfa(TPM_ALG_SHA256, b"KEY", b"L", b"u", b"v", 128).unwrap(),
            kdfa(TPM_ALG_SHA256, b"key", b"M", b"u", b"v", 128).unwrap(),
            kdfa(TPM_ALG_SHA256, b"key", b"L", b"U", b"v", 128).unwrap(),
            kdfa(TPM_ALG_SHA256, b"key", b"L", b"u", b"V", 128).unwrap(),
            kdfa(TPM_ALG_SHA1, b"key", b"L", b"u", b"v", 128).unwrap(),
        ] {
            assert_ne!(base, other);
        }
        assert_eq!(
            kdfa(TPM_ALG_SHA256, b"key", b"L", b"u", b"v", 256).unwrap()[..16],
            *kdfa(TPM_ALG_SHA256, b"key", b"L", b"u", b"v", 256).unwrap()[..16]
                .to_vec()
                .as_slice()
        );
    }

    #[test]
    fn size_in_bits_hmac_input_inclusion() {
        let short = kdfa(TPM_ALG_SHA256, b"key", b"L", &[], &[], 128).unwrap();
        let long = kdfa(TPM_ALG_SHA256, b"key", b"L", &[], &[], 256).unwrap();
        assert_ne!(
            short[..],
            long[..16],
            "a different sizeInBits produces a different first block"
        );
    }

    #[test]
    fn mask_length_exactness_prefix_stability() {
        let long = mgf1(TPM_ALG_SHA256, b"seed", 100).unwrap();
        assert_eq!(long.len(), 100);
        for length in [1usize, 31, 32, 33, 64] {
            let mask = mgf1(TPM_ALG_SHA256, b"seed", length).unwrap();
            assert_eq!(mask.len(), length);
            assert_eq!(mask[..], long[..length], "length {length}");
        }
    }

    #[test]
    fn mask_counter_chain_match() {
        let mut expected = Vec::new();
        for counter in 0u32..2 {
            let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
            hasher.update(b"seed");
            hasher.update(&counter.to_be_bytes());
            expected.extend_from_slice(&hasher.finalize());
        }
        assert_eq!(mgf1(TPM_ALG_SHA256, b"seed", 64).unwrap(), expected);
    }

    #[test]
    fn mask_oracle_match() {
        for (algorithm, seed, expected) in [
            (
                TPM_ALG_SHA256,
                &b"seed"[..],
                "336f28a022193939585a1b4edc989f870917f3a5f6ddd16e4fb357084a6bdfc2",
            ),
            (
                TPM_ALG_SHA256,
                b"seed",
                "336f28a022193939585a1b4edc989f870917f3a5f6ddd16e4fb357084a6bdfc2\
                 73a649427664d03bbb062e456425488416c52c64ef46fe011ed2a983f30ea9b9",
            ),
            (
                TPM_ALG_SHA256,
                b"seed",
                "336f28a022193939585a1b4edc989f870917f3a5f6ddd16e4fb357084a6bdfc2\
                 73a649427664d03bbb062e456425488416c52c64ef46fe011ed2a983f30ea9b9\
                 0eeb559ba5193bb7741a6ed9186af9c424eb25f7840996ed9712bf5a5a327db3\
                 f1875c59",
            ),
            (
                TPM_ALG_SHA256,
                b"",
                "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119\
                 b40711a88c7039756fb8a73827eabe2c",
            ),
            (
                TPM_ALG_SHA1,
                b"seed",
                "09d8db2214e56d4dec8f9a3099b851a46886fe3f682e3c4f6a35ff98dd072c11\
                 24a6b7b411e543f2",
            ),
            (TPM_ALG_SHA256, b"abc", "cf"),
            (
                TPM_ALG_SHA256,
                b"abc",
                "cf2db1ac9867debdf8ce91f99f141e5544bf26ca36b3fd4f8e4035eec42cab0d\
                 46c386ebccef82ba0bb0b095aaa5548b03cdff6951871c6fb505af68af688332\
                 f885d324a47d2145a3d8392c37978d7dc984c95728950c4cf3de6becc59e60ea\
                 506951bd40e6de38630950643ab2edbb47dc66cb54beb2d188a78a47471604ce\
                 34f4b92b9b8c0edd75b7227297c3a0b21719f48f877565fe0e884adfda6cf767\
                 e3c86e8353bf35ad766e97037294c6f54953e84f2da6a48d39b6e0335a32783f\
                 3fbbfd5fb505e0d6064e585ad9b4b2e7fae67e9fff608e9925a6b895d5fc51",
            ),
        ] {
            let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            let mask = mgf1(algorithm, seed, expected.len() / 2).unwrap();
            assert_eq!(
                hex_string(&mask),
                expected,
                "{algorithm:#06x} seed {seed:?}"
            );
        }
    }

    #[test]
    fn counter_after_seed_block_layout() {
        let seed = b"an-mgf1-seed";
        let mask = mgf1(TPM_ALG_SHA256, seed, 96).unwrap();

        let mut reversed = Vec::new();
        for counter in 0u32..3 {
            let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
            hasher.update(&counter.to_be_bytes());
            hasher.update(seed);
            reversed.extend_from_slice(&hasher.finalize());
        }
        assert_ne!(
            mask, reversed,
            "hashing the counter before the seed is not the upstream ordering"
        );

        for (block, chunk) in mask.chunks(32).enumerate() {
            let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
            hasher.update(seed);
            hasher.update(&u32::try_from(block).unwrap().to_be_bytes());
            assert_eq!(chunk, &hasher.finalize()[..], "block {block}");
        }
    }

    #[test]
    fn resumed_counter_key_stream_continuation() {
        let block = |counter: &mut u32| {
            kdfa_from(TPM_ALG_SHA256, b"key", b"L", &[], &[], 256, counter).unwrap()
        };
        let mut counter = 0u32;
        let first = block(&mut counter);
        assert_eq!(counter, 1, "one block advances the counter once");
        let second = block(&mut counter);
        assert_eq!(counter, 2);
        assert_ne!(first, second);
        assert_eq!(
            first,
            kdfa(TPM_ALG_SHA256, b"key", b"L", &[], &[], 256).unwrap(),
            "a zero counter is the plain key stream"
        );
        let mut resumed = 1u32;
        assert_eq!(second, block(&mut resumed));
    }

    #[test]
    fn zero_length_request_empty_output() {
        assert!(mgf1(TPM_ALG_SHA256, b"seed", 0).unwrap().is_empty());
        assert!(
            kdfa(TPM_ALG_SHA256, b"key", b"L", &[], &[], 0)
                .unwrap()
                .is_empty()
        );
    }
}
