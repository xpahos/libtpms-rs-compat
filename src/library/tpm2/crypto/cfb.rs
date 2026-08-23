use aes::cipher::{BlockEncrypt, KeyInit};

use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_SYMMETRIC;

use super::super::algorithm::{TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_TDES};

const WIDE_BLOCK_SIZE: usize = 16;
const TDES_BLOCK_SIZE: usize = 8;

pub(in crate::library::tpm2) fn sym_block_size(algorithm: u16) -> Option<usize> {
    match algorithm {
        TPM_ALG_AES | TPM_ALG_CAMELLIA => Some(WIDE_BLOCK_SIZE),
        TPM_ALG_TDES => Some(TDES_BLOCK_SIZE),
        _ => None,
    }
}

enum SymCipher {
    Aes128(Box<aes::Aes128>),
    Aes192(Box<aes::Aes192>),
    Aes256(Box<aes::Aes256>),
    TdesEde2(Box<des::TdesEde2>),
    TdesEde3(Box<des::TdesEde3>),
    Camellia128(Box<camellia::Camellia128>),
    Camellia192(Box<camellia::Camellia192>),
    Camellia256(Box<camellia::Camellia256>),
}

impl SymCipher {
    fn new(algorithm: u16, key: &[u8]) -> Result<Self, TpmResult> {
        match (algorithm, key.len()) {
            (TPM_ALG_AES, 16) => Ok(Self::Aes128(Box::new(aes::Aes128::new(key.into())))),
            (TPM_ALG_AES, 24) => Ok(Self::Aes192(Box::new(aes::Aes192::new(key.into())))),
            (TPM_ALG_AES, 32) => Ok(Self::Aes256(Box::new(aes::Aes256::new(key.into())))),
            (TPM_ALG_TDES, 16) => Ok(Self::TdesEde2(Box::new(des::TdesEde2::new(key.into())))),
            (TPM_ALG_TDES, 24) => Ok(Self::TdesEde3(Box::new(des::TdesEde3::new(key.into())))),
            (TPM_ALG_CAMELLIA, 16) => Ok(Self::Camellia128(Box::new(camellia::Camellia128::new(
                key.into(),
            )))),
            (TPM_ALG_CAMELLIA, 24) => Ok(Self::Camellia192(Box::new(camellia::Camellia192::new(
                key.into(),
            )))),
            (TPM_ALG_CAMELLIA, 32) => Ok(Self::Camellia256(Box::new(camellia::Camellia256::new(
                key.into(),
            )))),
            _ => Err(TPM_RC_SYMMETRIC),
        }
    }

    fn block_size(&self) -> usize {
        match self {
            Self::TdesEde2(_) | Self::TdesEde3(_) => TDES_BLOCK_SIZE,
            _ => WIDE_BLOCK_SIZE,
        }
    }

    fn encrypt_block(&self, block: &mut [u8]) {
        fn apply<C: BlockEncrypt>(cipher: &C, block: &mut [u8]) {
            let mut buffer = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
            cipher.encrypt_block(&mut buffer);
            block.copy_from_slice(&buffer);
        }
        match self {
            Self::Aes128(cipher) => apply(cipher.as_ref(), block),
            Self::Aes192(cipher) => apply(cipher.as_ref(), block),
            Self::Aes256(cipher) => apply(cipher.as_ref(), block),
            Self::TdesEde2(cipher) => apply(cipher.as_ref(), block),
            Self::TdesEde3(cipher) => apply(cipher.as_ref(), block),
            Self::Camellia128(cipher) => apply(cipher.as_ref(), block),
            Self::Camellia192(cipher) => apply(cipher.as_ref(), block),
            Self::Camellia256(cipher) => apply(cipher.as_ref(), block),
        }
    }
}

pub(in crate::library::tpm2) fn sym_cfb_encrypt(
    algorithm: u16,
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> Result<(), TpmResult> {
    let cipher = SymCipher::new(algorithm, key)?;
    let block_size = cipher.block_size();
    if iv.len() != block_size {
        return Err(TPM_RC_SYMMETRIC);
    }
    let mut feedback = iv.to_vec();
    for chunk in data.chunks_mut(block_size) {
        cipher.encrypt_block(&mut feedback);
        for (byte, mask) in chunk.iter_mut().zip(feedback.iter()) {
            *byte ^= mask;
        }
        feedback[..chunk.len()].copy_from_slice(chunk);
    }
    Ok(())
}

pub(in crate::library::tpm2) fn sym_cfb_decrypt(
    algorithm: u16,
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> Result<(), TpmResult> {
    let cipher = SymCipher::new(algorithm, key)?;
    let block_size = cipher.block_size();
    if iv.len() != block_size {
        return Err(TPM_RC_SYMMETRIC);
    }
    let mut feedback = iv.to_vec();
    for chunk in data.chunks_mut(block_size) {
        let cipher_text = chunk.to_vec();
        cipher.encrypt_block(&mut feedback);
        for (byte, mask) in chunk.iter_mut().zip(feedback.iter()) {
            *byte ^= mask;
        }
        feedback[..cipher_text.len()].copy_from_slice(&cipher_text);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn pattern(length: usize, base: u8) -> Vec<u8> {
        (0..length)
            .map(|index| base.wrapping_add(index as u8))
            .collect()
    }

    #[test]
    fn the_block_sizes_follow_the_algorithm() {
        assert_eq!(sym_block_size(TPM_ALG_AES), Some(16));
        assert_eq!(sym_block_size(TPM_ALG_CAMELLIA), Some(16));
        assert_eq!(sym_block_size(TPM_ALG_TDES), Some(8));
        assert_eq!(sym_block_size(0x0010), None);
        assert_eq!(sym_block_size(0xffff), None);
    }

    #[test]
    fn the_nist_sp800_38a_aes_cfb128_vector_matches() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut data = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ];
        sym_cfb_encrypt(TPM_ALG_AES, &key, &iv, &mut data).expect("a supported key size");
        assert_eq!(
            data,
            [
                0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20, 0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c,
                0xfb, 0x4a, 0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f, 0xcd, 0xe3, 0xcd, 0xad,
                0x9f, 0x1c, 0xe5, 0x8b
            ]
        );
    }

    #[test]
    fn the_openssl_known_answers_match() {
        let key = pattern(32, 0x10);
        let iv16 = pattern(16, 0xa0);
        let iv8 = pattern(8, 0xa0);
        let cases: [(u16, usize, &[u8], usize, &str); 7] = [
            (
                TPM_ALG_TDES,
                24,
                &iv8,
                48,
                "dee0eefbe8da9715150a1260225d4732b727499e4320ed2ba4e522e5bb427ba2\
                 d6b30b5b05c3c55cd04e3b2d1ef8ef29",
            ),
            (TPM_ALG_TDES, 24, &iv8, 13, "dee0eefbe8da9715150a126022"),
            (
                TPM_ALG_TDES,
                16,
                &iv8,
                48,
                "3fe76ee4948cd716522e3eef6ceaff8d7065404a4a0555c2c5c5391aec88a76a\
                 dc037ba50f09becd7536628172d08511",
            ),
            (TPM_ALG_TDES, 16, &iv8, 5, "3fe76ee494"),
            (
                TPM_ALG_CAMELLIA,
                16,
                &iv16,
                48,
                "8153f747bc5d854faf1c44bc497f1988f614988322a8cd75142a4ae6799c8556\
                 37b6717d85c62e3287b384e036045986",
            ),
            (
                TPM_ALG_CAMELLIA,
                24,
                &iv16,
                32,
                "f64688d1d50597b5a381eefd127b67cfd3d065754529b5c15aca9777b061cf36",
            ),
            (
                TPM_ALG_CAMELLIA,
                32,
                &iv16,
                32,
                "7c527c251dedf20cee64cca9d4905986a1a947591c46d05992c81e5256826aa6",
            ),
        ];
        for (algorithm, key_len, iv, length, expected) in cases {
            let mut data = pattern(length, 0x30);
            sym_cfb_encrypt(algorithm, &key[..key_len], iv, &mut data).expect("encrypts");
            let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            assert_eq!(hex(&data), expected, "alg {algorithm:#06x} key {key_len}");
        }
        let mut data = pattern(32, 0x30);
        sym_cfb_encrypt(TPM_ALG_AES, &key[..16], &iv16, &mut data).expect("encrypts");
        assert_eq!(
            hex(&data),
            "f9209121d841aa98f3cbafb5d8682c142d66f6cbbc020e1626de56bde274be27"
        );
    }

    #[test]
    fn a_partial_final_block_is_truncated_key_stream() {
        for (algorithm, key_len, block) in [
            (TPM_ALG_AES, 16usize, 16usize),
            (TPM_ALG_TDES, 16, 8),
            (TPM_ALG_CAMELLIA, 16, 16),
        ] {
            let key = pattern(key_len, 0x11);
            let iv = pattern(block, 0x22);
            let mut full = pattern(3 * block, 0x33);
            sym_cfb_encrypt(algorithm, &key, &iv, &mut full).expect("encrypts");
            for length in [
                0usize,
                1,
                block - 1,
                block,
                block + 1,
                2 * block,
                3 * block - 1,
            ] {
                let mut partial = pattern(length, 0x33);
                sym_cfb_encrypt(algorithm, &key, &iv, &mut partial).expect("encrypts");
                assert_eq!(
                    partial[..],
                    full[..length],
                    "alg {algorithm:#06x} length {length}"
                );
            }
        }
    }

    #[test]
    fn every_supported_key_size_encrypts_and_others_are_rejected() {
        for (algorithm, sizes, block) in [
            (TPM_ALG_AES, &[16usize, 24, 32][..], 16usize),
            (TPM_ALG_TDES, &[16, 24][..], 8),
            (TPM_ALG_CAMELLIA, &[16, 24, 32][..], 16),
        ] {
            for &size in sizes {
                let mut data = pattern(block, 0xaa);
                sym_cfb_encrypt(algorithm, &vec![0x55; size], &vec![0u8; block], &mut data)
                    .expect("a valid key");
                assert_ne!(data, pattern(block, 0xaa));
            }
            for size in [0usize, 8, 15, 17, 33, 64] {
                if sizes.contains(&size) {
                    continue;
                }
                let mut data = pattern(block, 0xaa);
                assert_eq!(
                    sym_cfb_encrypt(algorithm, &vec![0x55; size], &vec![0u8; block], &mut data),
                    Err(TPM_RC_SYMMETRIC),
                    "alg {algorithm:#06x} key size {size}"
                );
            }
        }
        let mut data = [0xaa; 16];
        assert_eq!(
            sym_cfb_encrypt(0x0099, &[0x55; 16], &[0u8; 16], &mut data),
            Err(TPM_RC_SYMMETRIC),
            "an unknown algorithm is rejected"
        );
    }

    #[test]
    fn a_wrong_iv_length_is_rejected() {
        for (algorithm, key_len, block) in [
            (TPM_ALG_AES, 16usize, 16usize),
            (TPM_ALG_TDES, 16, 8),
            (TPM_ALG_CAMELLIA, 16, 16),
        ] {
            for iv_len in [0usize, block - 1, block + 1, 2 * block] {
                let mut data = [0xaa; 8];
                assert_eq!(
                    sym_cfb_encrypt(
                        algorithm,
                        &vec![0x55; key_len],
                        &vec![0u8; iv_len],
                        &mut data
                    ),
                    Err(TPM_RC_SYMMETRIC),
                    "alg {algorithm:#06x} iv {iv_len}"
                );
            }
        }
    }
}
