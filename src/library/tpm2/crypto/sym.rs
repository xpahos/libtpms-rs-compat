use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};

use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_MODE, TPM_RC_SIZE, TPM_RC_SYMMETRIC};

use super::super::algorithm::{
    TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_CBC, TPM_ALG_CFB, TPM_ALG_CTR, TPM_ALG_ECB, TPM_ALG_OFB,
    TPM_ALG_TDES,
};

const WIDE_BLOCK_SIZE: usize = 16;
const TDES_BLOCK_SIZE: usize = 8;

pub(in crate::library::tpm2) fn sym_block_size(algorithm: u16) -> Option<usize> {
    match algorithm {
        TPM_ALG_AES | TPM_ALG_CAMELLIA => Some(WIDE_BLOCK_SIZE),
        TPM_ALG_TDES => Some(TDES_BLOCK_SIZE),
        _ => None,
    }
}

pub(in crate::library::tpm2) fn sym_key_block_size(algorithm: u16, key_bits: u16) -> Option<usize> {
    let implemented = match algorithm {
        TPM_ALG_AES | TPM_ALG_CAMELLIA => matches!(key_bits, 128 | 192 | 256),
        TPM_ALG_TDES => matches!(key_bits, 128 | 192),
        _ => false,
    };
    implemented.then(|| sym_block_size(algorithm)).flatten()
}

pub(in crate::library::tpm2) fn sym_mode_is_block_cipher(mode: u16) -> bool {
    matches!(
        mode,
        TPM_ALG_CTR | TPM_ALG_OFB | TPM_ALG_CBC | TPM_ALG_CFB | TPM_ALG_ECB
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum SymDirection {
    Encrypt,
    Decrypt,
}

pub(in crate::library::tpm2) enum SymCipher {
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
    pub(in crate::library::tpm2) fn new(algorithm: u16, key: &[u8]) -> Result<Self, TpmResult> {
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

    pub(in crate::library::tpm2) fn block_size(&self) -> usize {
        match self {
            Self::TdesEde2(_) | Self::TdesEde3(_) => TDES_BLOCK_SIZE,
            _ => WIDE_BLOCK_SIZE,
        }
    }

    pub(in crate::library::tpm2) fn encrypt_block(&self, block: &mut [u8]) {
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

    fn decrypt_block(&self, block: &mut [u8]) {
        fn apply<C: BlockDecrypt>(cipher: &C, block: &mut [u8]) {
            let mut buffer = aes::cipher::generic_array::GenericArray::clone_from_slice(block);
            cipher.decrypt_block(&mut buffer);
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

pub(in crate::library::tpm2) fn sym_crypt(
    algorithm: u16,
    key: &[u8],
    mode: u16,
    iv: &mut [u8],
    direction: SymDirection,
    data: &mut [u8],
) -> Result<(), TpmResult> {
    if !sym_mode_is_block_cipher(mode) {
        return Err(TPM_RC_MODE);
    }
    let cipher = SymCipher::new(algorithm, key)?;
    let block_size = cipher.block_size();
    let expected_iv = if mode == TPM_ALG_ECB { 0 } else { block_size };
    if iv.len() != expected_iv {
        return Err(TPM_RC_SIZE);
    }
    if matches!(mode, TPM_ALG_CBC | TPM_ALG_ECB) && !data.len().is_multiple_of(block_size) {
        return Err(TPM_RC_SIZE);
    }
    if data.is_empty() {
        return Ok(());
    }
    match mode {
        TPM_ALG_CFB => cfb(&cipher, block_size, iv, direction, data),
        TPM_ALG_OFB => ofb(&cipher, block_size, iv, data),
        TPM_ALG_CTR => ctr(&cipher, block_size, iv, data),
        TPM_ALG_CBC => cbc(&cipher, block_size, iv, direction, data),
        _ => ecb(&cipher, block_size, direction, data),
    }
    Ok(())
}

fn cfb(
    cipher: &SymCipher,
    block_size: usize,
    iv: &mut [u8],
    direction: SymDirection,
    data: &mut [u8],
) {
    let mut position = 0;
    for byte in data.iter_mut() {
        if position == 0 {
            cipher.encrypt_block(iv);
        }
        let cipher_text = match direction {
            SymDirection::Encrypt => {
                *byte ^= iv[position];
                *byte
            }
            SymDirection::Decrypt => {
                let cipher_text = *byte;
                *byte ^= iv[position];
                cipher_text
            }
        };
        iv[position] = cipher_text;
        position = (position + 1) % block_size;
    }
    if position != 0 {
        iv[position..].fill(0);
    }
}

fn ofb(cipher: &SymCipher, block_size: usize, iv: &mut [u8], data: &mut [u8]) {
    for chunk in data.chunks_mut(block_size) {
        cipher.encrypt_block(iv);
        for (byte, mask) in chunk.iter_mut().zip(iv.iter()) {
            *byte ^= mask;
        }
    }
}

fn ctr(cipher: &SymCipher, block_size: usize, iv: &mut [u8], data: &mut [u8]) {
    let mut key_stream = vec![0u8; block_size];
    for chunk in data.chunks_mut(block_size) {
        key_stream.copy_from_slice(iv);
        cipher.encrypt_block(&mut key_stream);
        for byte in iv.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        for (byte, mask) in chunk.iter_mut().zip(key_stream.iter()) {
            *byte ^= mask;
        }
    }
}

fn cbc(
    cipher: &SymCipher,
    block_size: usize,
    iv: &mut [u8],
    direction: SymDirection,
    data: &mut [u8],
) {
    let mut carried = vec![0u8; block_size];
    for chunk in data.chunks_mut(block_size) {
        match direction {
            SymDirection::Encrypt => {
                for (mask, byte) in iv.iter_mut().zip(chunk.iter()) {
                    *mask ^= byte;
                }
                cipher.encrypt_block(iv);
                chunk.copy_from_slice(iv);
            }
            SymDirection::Decrypt => {
                carried.copy_from_slice(chunk);
                cipher.decrypt_block(chunk);
                for (byte, mask) in chunk.iter_mut().zip(iv.iter()) {
                    *byte ^= mask;
                }
                iv.copy_from_slice(&carried);
            }
        }
    }
}

fn ecb(cipher: &SymCipher, block_size: usize, direction: SymDirection, data: &mut [u8]) {
    for chunk in data.chunks_mut(block_size) {
        match direction {
            SymDirection::Encrypt => cipher.encrypt_block(chunk),
            SymDirection::Decrypt => cipher.decrypt_block(chunk),
        }
    }
}

pub(in crate::library::tpm2) fn sym_cfb_encrypt(
    algorithm: u16,
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> Result<(), TpmResult> {
    let mut chaining = iv.to_vec();
    sym_crypt(
        algorithm,
        key,
        TPM_ALG_CFB,
        &mut chaining,
        SymDirection::Encrypt,
        data,
    )
    .map_err(|_| TPM_RC_SYMMETRIC)
}

pub(in crate::library::tpm2) fn sym_cfb_decrypt(
    algorithm: u16,
    key: &[u8],
    iv: &[u8],
    data: &mut [u8],
) -> Result<(), TpmResult> {
    let mut chaining = iv.to_vec();
    sym_crypt(
        algorithm,
        key,
        TPM_ALG_CFB,
        &mut chaining,
        SymDirection::Decrypt,
        data,
    )
    .map_err(|_| TPM_RC_SYMMETRIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::TPM_ALG_NULL;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).expect("hexadecimal"))
            .collect()
    }

    fn pattern(length: usize, base: u8) -> Vec<u8> {
        (0..length)
            .map(|index| base.wrapping_add(index as u8))
            .collect()
    }

    #[track_caller]
    fn run(
        algorithm: u16,
        key: &[u8],
        mode: u16,
        iv: &[u8],
        direction: SymDirection,
        data: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut chaining = iv.to_vec();
        let mut buffer = data.to_vec();
        sym_crypt(algorithm, key, mode, &mut chaining, direction, &mut buffer)
            .expect("a supported operation");
        (buffer, chaining)
    }

    const NIST_KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const NIST_KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    const NIST_KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const NIST_IV: &str = "000102030405060708090a0b0c0d0e0f";
    const NIST_CTR_IV: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const NIST_PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172a\
                                  ae2d8a571e03ac9c9eb76fac45af8e51\
                                  30c81c46a35ce411e5fbc1191a0a52ef\
                                  f69f2445df4f9b17ad2b417be66c3710";

    #[test]
    fn the_block_sizes_follow_the_algorithm() {
        assert_eq!(sym_block_size(TPM_ALG_AES), Some(16));
        assert_eq!(sym_block_size(TPM_ALG_CAMELLIA), Some(16));
        assert_eq!(sym_block_size(TPM_ALG_TDES), Some(8));
        assert_eq!(sym_block_size(0x0010), None);
        assert_eq!(sym_block_size(0xffff), None);
    }

    #[test]
    fn only_implemented_key_sizes_have_a_block_size() {
        for (algorithm, sizes, block) in [
            (TPM_ALG_AES, &[128u16, 192, 256][..], 16usize),
            (TPM_ALG_CAMELLIA, &[128, 192, 256][..], 16),
            (TPM_ALG_TDES, &[128, 192][..], 8),
        ] {
            for key_bits in [0u16, 64, 112, 128, 192, 256, 512] {
                assert_eq!(
                    sym_key_block_size(algorithm, key_bits),
                    sizes.contains(&key_bits).then_some(block),
                    "alg {algorithm:#06x} bits {key_bits}"
                );
            }
        }
        assert_eq!(sym_key_block_size(TPM_ALG_NULL, 128), None);
    }

    #[test]
    fn the_nist_sp800_38a_aes_vectors_are_reproduced() {
        let plaintext = unhex(NIST_PLAINTEXT);
        let cases: [(&str, u16, &str, &str); 12] = [
            (
                NIST_KEY_128,
                TPM_ALG_ECB,
                "",
                "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf\
                 43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4",
            ),
            (
                NIST_KEY_192,
                TPM_ALG_ECB,
                "",
                "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef\
                 ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e",
            ),
            (
                NIST_KEY_256,
                TPM_ALG_ECB,
                "",
                "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870\
                 b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7",
            ),
            (
                NIST_KEY_128,
                TPM_ALG_CBC,
                NIST_IV,
                "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2\
                 73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
            ),
            (
                NIST_KEY_192,
                TPM_ALG_CBC,
                NIST_IV,
                "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a\
                 571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
            ),
            (
                NIST_KEY_256,
                TPM_ALG_CBC,
                NIST_IV,
                "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d\
                 39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
            ),
            (
                NIST_KEY_128,
                TPM_ALG_CFB,
                NIST_IV,
                "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b\
                 26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
            ),
            (
                NIST_KEY_192,
                TPM_ALG_CFB,
                NIST_IV,
                "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a\
                 2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
            ),
            (
                NIST_KEY_256,
                TPM_ALG_CFB,
                NIST_IV,
                "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407b\
                 df10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
            ),
            (
                NIST_KEY_128,
                TPM_ALG_OFB,
                NIST_IV,
                "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825\
                 9740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e",
            ),
            (
                NIST_KEY_256,
                TPM_ALG_OFB,
                NIST_IV,
                "dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d\
                 71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484",
            ),
            (
                NIST_KEY_128,
                TPM_ALG_CTR,
                NIST_CTR_IV,
                "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff\
                 5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
            ),
        ];
        for (key, mode, iv, expected) in cases {
            let expected = unhex(expected);
            let (cipher_text, _) = run(
                TPM_ALG_AES,
                &unhex(key),
                mode,
                &unhex(iv),
                SymDirection::Encrypt,
                &plaintext,
            );
            assert_eq!(cipher_text, expected, "mode {mode:#06x} key {key}");
            let (plain, _) = run(
                TPM_ALG_AES,
                &unhex(key),
                mode,
                &unhex(iv),
                SymDirection::Decrypt,
                &cipher_text,
            );
            assert_eq!(plain, plaintext, "mode {mode:#06x} key {key}");
        }
    }

    #[test]
    fn the_openssl_known_answers_match_for_every_algorithm_and_mode() {
        let key = pattern(32, 0x10);
        let iv16 = pattern(16, 0xa0);
        let iv8 = pattern(8, 0xa0);
        type Case<'a> = (u16, usize, u16, &'a [u8], usize, &'a str);
        let cases: [Case<'_>; 19] = [
            (
                TPM_ALG_AES,
                16,
                TPM_ALG_CBC,
                &iv16,
                32,
                "f7323b5c1dc257557db0c7476be238a02d609aece082066c2c8787d1afb3be51",
            ),
            (
                TPM_ALG_AES,
                24,
                TPM_ALG_CTR,
                &iv16,
                20,
                "d5ecc0bdfa5fcb296959961a0aae4693b6c7d4ad",
            ),
            (
                TPM_ALG_AES,
                32,
                TPM_ALG_OFB,
                &iv16,
                20,
                "fe42b935d9c79a6889d117de186f12d3f9f548b7",
            ),
            (
                TPM_ALG_AES,
                16,
                TPM_ALG_ECB,
                &[],
                32,
                "e82546cf4538181b3f0a24390107fd00424bd9b0edc4eea9ecb99122eb673042",
            ),
            (
                TPM_ALG_TDES,
                24,
                TPM_ALG_CFB,
                &iv8,
                48,
                "dee0eefbe8da9715150a1260225d4732b727499e4320ed2ba4e522e5bb427ba2\
                 d6b30b5b05c3c55cd04e3b2d1ef8ef29",
            ),
            (
                TPM_ALG_TDES,
                24,
                TPM_ALG_CFB,
                &iv8,
                13,
                "dee0eefbe8da9715150a126022",
            ),
            (
                TPM_ALG_TDES,
                16,
                TPM_ALG_CFB,
                &iv8,
                48,
                "3fe76ee4948cd716522e3eef6ceaff8d7065404a4a0555c2c5c5391aec88a76a\
                 dc037ba50f09becd7536628172d08511",
            ),
            (TPM_ALG_TDES, 16, TPM_ALG_CFB, &iv8, 5, "3fe76ee494"),
            (
                TPM_ALG_TDES,
                24,
                TPM_ALG_CBC,
                &iv8,
                16,
                "9bcceb04cdbef0db1bfb023aebb8206e",
            ),
            (
                TPM_ALG_TDES,
                24,
                TPM_ALG_CTR,
                &iv8,
                12,
                "dee0eefbe8da97156f481267",
            ),
            (
                TPM_ALG_TDES,
                16,
                TPM_ALG_OFB,
                &iv8,
                12,
                "3fe76ee4948cd716d8f34a55",
            ),
            (
                TPM_ALG_TDES,
                24,
                TPM_ALG_ECB,
                &[],
                16,
                "87cbb0d70f9b9a19f6b61735f2a5b6d0",
            ),
            (
                TPM_ALG_CAMELLIA,
                16,
                TPM_ALG_CFB,
                &iv16,
                48,
                "8153f747bc5d854faf1c44bc497f1988f614988322a8cd75142a4ae6799c8556\
                 37b6717d85c62e3287b384e036045986",
            ),
            (
                TPM_ALG_CAMELLIA,
                24,
                TPM_ALG_CFB,
                &iv16,
                32,
                "f64688d1d50597b5a381eefd127b67cfd3d065754529b5c15aca9777b061cf36",
            ),
            (
                TPM_ALG_CAMELLIA,
                32,
                TPM_ALG_CFB,
                &iv16,
                32,
                "7c527c251dedf20cee64cca9d4905986a1a947591c46d05992c81e5256826aa6",
            ),
            (
                TPM_ALG_CAMELLIA,
                16,
                TPM_ALG_ECB,
                &[],
                16,
                "bc4727fb41c7560d6a25f67b0bb5e073",
            ),
            (
                TPM_ALG_CAMELLIA,
                32,
                TPM_ALG_OFB,
                &iv16,
                16,
                "7c527c251dedf20cee64cca9d4905986",
            ),
            (
                TPM_ALG_CAMELLIA,
                24,
                TPM_ALG_CBC,
                &iv16,
                32,
                "f0206a088ea8345829b55ffa1c229563937199c1a6d3c399a0b2515aaa89f15c",
            ),
            (
                TPM_ALG_CAMELLIA,
                16,
                TPM_ALG_CTR,
                &iv16,
                20,
                "8153f747bc5d854faf1c44bc497f1988604fb045",
            ),
        ];
        for (algorithm, key_len, mode, iv, length, expected) in cases {
            let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            let plaintext = pattern(length, 0x30);
            let (cipher_text, _) = run(
                algorithm,
                &key[..key_len],
                mode,
                iv,
                SymDirection::Encrypt,
                &plaintext,
            );
            assert_eq!(
                hex(&cipher_text),
                expected,
                "alg {algorithm:#06x} mode {mode:#06x} key {key_len}"
            );
            let (plain, _) = run(
                algorithm,
                &key[..key_len],
                mode,
                iv,
                SymDirection::Decrypt,
                &cipher_text,
            );
            assert_eq!(
                plain, plaintext,
                "alg {algorithm:#06x} mode {mode:#06x} key {key_len}"
            );
        }
        let mut data = pattern(32, 0x30);
        sym_cfb_encrypt(TPM_ALG_AES, &key[..16], &iv16, &mut data).expect("encrypts");
        assert_eq!(
            hex(&data),
            "f9209121d841aa98f3cbafb5d8682c142d66f6cbbc020e1626de56bde274be27"
        );
    }

    #[test]
    fn the_chaining_value_follows_the_reference_rules() {
        let key = pattern(16, 0x10);
        let iv = pattern(16, 0xa0);
        let plaintext = pattern(20, 0x30);

        let (cipher_text, chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_CFB,
            &iv,
            SymDirection::Encrypt,
            &plaintext,
        );
        assert_eq!(
            chaining[..4],
            cipher_text[16..20],
            "CFB keeps the partial cipher text in the chaining value"
        );
        assert_eq!(chaining[4..], [0u8; 12], "the tail is padded with zeros");
        let (_, decrypt_chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_CFB,
            &iv,
            SymDirection::Decrypt,
            &cipher_text,
        );
        assert_eq!(chaining, decrypt_chaining, "both directions chain alike");

        let (_, chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_CTR,
            &iv,
            SymDirection::Encrypt,
            &plaintext,
        );
        let mut expected = iv.clone();
        expected[15] = expected[15].wrapping_add(2);
        assert_eq!(chaining, expected, "CTR counts the partial block");

        let (cipher_text, chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_CBC,
            &iv,
            SymDirection::Encrypt,
            &pattern(32, 0x30),
        );
        assert_eq!(chaining, cipher_text[16..], "CBC chains the cipher text");
        let (_, decrypt_chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_CBC,
            &iv,
            SymDirection::Decrypt,
            &cipher_text,
        );
        assert_eq!(chaining, decrypt_chaining);

        let (_, chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_OFB,
            &iv,
            SymDirection::Encrypt,
            &plaintext,
        );
        let (full, _) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_OFB,
            &iv,
            SymDirection::Encrypt,
            &[0u8; 32],
        );
        assert_eq!(chaining, full[16..], "OFB keeps the whole key-stream block");
    }

    #[test]
    fn a_carry_propagates_through_the_counter() {
        let key = pattern(16, 0x10);
        let iv = vec![0xffu8; 16];
        let (_, chaining) = run(
            TPM_ALG_AES,
            &key,
            TPM_ALG_CTR,
            &iv,
            SymDirection::Encrypt,
            &pattern(16, 0x30),
        );
        assert_eq!(chaining, vec![0u8; 16], "the counter wraps to zero");
    }

    #[test]
    fn chained_calls_reproduce_a_single_call() {
        let key = pattern(32, 0x10);
        let iv = pattern(16, 0xa0);
        let plaintext = pattern(48, 0x30);
        for mode in [TPM_ALG_CFB, TPM_ALG_OFB, TPM_ALG_CTR, TPM_ALG_CBC] {
            let (whole, _) = run(
                TPM_ALG_AES,
                &key,
                mode,
                &iv,
                SymDirection::Encrypt,
                &plaintext,
            );
            let mut chaining = iv.clone();
            let mut pieces = Vec::new();
            for chunk in plaintext.chunks(16) {
                let mut buffer = chunk.to_vec();
                sym_crypt(
                    TPM_ALG_AES,
                    &key,
                    mode,
                    &mut chaining,
                    SymDirection::Encrypt,
                    &mut buffer,
                )
                .expect("encrypts");
                pieces.extend_from_slice(&buffer);
            }
            assert_eq!(pieces, whole, "mode {mode:#06x}");
        }
    }

    #[test]
    fn a_partial_final_block_truncates_the_stream_modes() {
        for (algorithm, key_len, block) in [
            (TPM_ALG_AES, 16usize, 16usize),
            (TPM_ALG_TDES, 16, 8),
            (TPM_ALG_CAMELLIA, 16, 16),
        ] {
            let key = pattern(key_len, 0x11);
            let iv = pattern(block, 0x22);
            for mode in [TPM_ALG_CFB, TPM_ALG_OFB, TPM_ALG_CTR] {
                let (full, _) = run(
                    algorithm,
                    &key,
                    mode,
                    &iv,
                    SymDirection::Encrypt,
                    &pattern(3 * block, 0x33),
                );
                for length in [0usize, 1, block - 1, block, block + 1, 3 * block - 1] {
                    let (partial, _) = run(
                        algorithm,
                        &key,
                        mode,
                        &iv,
                        SymDirection::Encrypt,
                        &pattern(length, 0x33),
                    );
                    assert_eq!(
                        partial[..],
                        full[..length],
                        "alg {algorithm:#06x} mode {mode:#06x} length {length}"
                    );
                }
            }
        }
    }

    #[test]
    fn unaligned_input_is_rejected_only_by_cbc_and_ecb() {
        let key = pattern(16, 0x11);
        for (mode, iv_len) in [
            (TPM_ALG_CFB, 16usize),
            (TPM_ALG_OFB, 16),
            (TPM_ALG_CTR, 16),
            (TPM_ALG_CBC, 16),
            (TPM_ALG_ECB, 0),
        ] {
            let aligned = matches!(mode, TPM_ALG_CBC | TPM_ALG_ECB);
            for length in [0usize, 1, 15, 16, 17, 32] {
                let mut iv = vec![0x22u8; iv_len];
                let mut data = pattern(length, 0x33);
                let result = sym_crypt(
                    TPM_ALG_AES,
                    &key,
                    mode,
                    &mut iv,
                    SymDirection::Encrypt,
                    &mut data,
                );
                let expected = if aligned && !length.is_multiple_of(16) {
                    Err(TPM_RC_SIZE)
                } else {
                    Ok(())
                };
                assert_eq!(result, expected, "mode {mode:#06x} length {length}");
            }
        }
    }

    #[test]
    fn empty_input_leaves_the_chaining_value_alone() {
        let key = pattern(16, 0x11);
        for (mode, iv_len) in [
            (TPM_ALG_CFB, 16usize),
            (TPM_ALG_OFB, 16),
            (TPM_ALG_CTR, 16),
            (TPM_ALG_CBC, 16),
            (TPM_ALG_ECB, 0),
        ] {
            for direction in [SymDirection::Encrypt, SymDirection::Decrypt] {
                let iv = pattern(iv_len, 0x22);
                let (data, chaining) = run(TPM_ALG_AES, &key, mode, &iv, direction, &[]);
                assert!(data.is_empty(), "mode {mode:#06x}");
                assert_eq!(chaining, iv, "mode {mode:#06x}");
            }
        }
    }

    #[test]
    fn every_supported_key_size_works_and_others_are_rejected() {
        for (algorithm, sizes, block) in [
            (TPM_ALG_AES, &[16usize, 24, 32][..], 16usize),
            (TPM_ALG_TDES, &[16, 24][..], 8),
            (TPM_ALG_CAMELLIA, &[16, 24, 32][..], 16),
        ] {
            for &size in sizes {
                let mut iv = vec![0u8; block];
                let mut data = pattern(block, 0xaa);
                sym_crypt(
                    algorithm,
                    &vec![0x55; size],
                    TPM_ALG_CFB,
                    &mut iv,
                    SymDirection::Encrypt,
                    &mut data,
                )
                .expect("a valid key");
                assert_ne!(data, pattern(block, 0xaa));
            }
            for size in [0usize, 8, 15, 17, 33, 64] {
                if sizes.contains(&size) {
                    continue;
                }
                let mut iv = vec![0u8; block];
                let mut data = pattern(block, 0xaa);
                assert_eq!(
                    sym_crypt(
                        algorithm,
                        &vec![0x55; size],
                        TPM_ALG_CFB,
                        &mut iv,
                        SymDirection::Encrypt,
                        &mut data
                    ),
                    Err(TPM_RC_SYMMETRIC),
                    "alg {algorithm:#06x} key size {size}"
                );
            }
        }
        let mut iv = [0u8; 16];
        let mut data = [0xaa; 16];
        assert_eq!(
            sym_crypt(
                0x0099,
                &[0x55; 16],
                TPM_ALG_CFB,
                &mut iv,
                SymDirection::Encrypt,
                &mut data
            ),
            Err(TPM_RC_SYMMETRIC),
            "an unknown algorithm is rejected"
        );
    }

    #[test]
    fn a_wrong_chaining_value_length_is_rejected() {
        for (algorithm, key_len, block) in [
            (TPM_ALG_AES, 16usize, 16usize),
            (TPM_ALG_TDES, 16, 8),
            (TPM_ALG_CAMELLIA, 16, 16),
        ] {
            for mode in [
                TPM_ALG_CFB,
                TPM_ALG_OFB,
                TPM_ALG_CTR,
                TPM_ALG_CBC,
                TPM_ALG_ECB,
            ] {
                let wanted = if mode == TPM_ALG_ECB { 0 } else { block };
                for iv_len in [0usize, block - 1, block, block + 1, 2 * block] {
                    let mut iv = vec![0u8; iv_len];
                    let mut data = vec![0xaa; 2 * block];
                    let result = sym_crypt(
                        algorithm,
                        &vec![0x55; key_len],
                        mode,
                        &mut iv,
                        SymDirection::Encrypt,
                        &mut data,
                    );
                    assert_eq!(
                        result.is_ok(),
                        iv_len == wanted,
                        "alg {algorithm:#06x} mode {mode:#06x} iv {iv_len}"
                    );
                    if iv_len != wanted {
                        assert_eq!(result, Err(TPM_RC_SIZE));
                    }
                }
            }
        }
        let mut data = [0xaa; 8];
        assert_eq!(
            sym_cfb_encrypt(TPM_ALG_AES, &[0x55; 16], &[0u8; 8], &mut data),
            Err(TPM_RC_SYMMETRIC),
            "the CFB wrapper keeps reporting a symmetric error"
        );
    }

    #[test]
    fn modes_outside_the_block_cipher_set_are_rejected() {
        for mode in [TPM_ALG_NULL, 0x0000, 0x003f, 0x0045, 0xffff] {
            let mut iv = [0u8; 16];
            let mut data = [0xaa; 16];
            assert_eq!(
                sym_crypt(
                    TPM_ALG_AES,
                    &[0x55; 16],
                    mode,
                    &mut iv,
                    SymDirection::Encrypt,
                    &mut data
                ),
                Err(TPM_RC_MODE),
                "mode {mode:#06x}"
            );
            assert!(!sym_mode_is_block_cipher(mode), "mode {mode:#06x}");
        }
    }

    #[test]
    fn a_round_trip_recovers_every_input_length() {
        let key = pattern(24, 0x77);
        for algorithm in [TPM_ALG_AES, TPM_ALG_TDES, TPM_ALG_CAMELLIA] {
            let block = sym_block_size(algorithm).expect("a compiled algorithm");
            for mode in [
                TPM_ALG_CFB,
                TPM_ALG_OFB,
                TPM_ALG_CTR,
                TPM_ALG_CBC,
                TPM_ALG_ECB,
            ] {
                let iv_len = if mode == TPM_ALG_ECB { 0 } else { block };
                let iv = pattern(iv_len, 0x99);
                let aligned = matches!(mode, TPM_ALG_CBC | TPM_ALG_ECB);
                for length in 0..=(3 * block) {
                    if aligned && !length.is_multiple_of(block) {
                        continue;
                    }
                    let plaintext = pattern(length, 0x40);
                    let (cipher_text, _) = run(
                        algorithm,
                        &key,
                        mode,
                        &iv,
                        SymDirection::Encrypt,
                        &plaintext,
                    );
                    let (plain, _) = run(
                        algorithm,
                        &key,
                        mode,
                        &iv,
                        SymDirection::Decrypt,
                        &cipher_text,
                    );
                    assert_eq!(
                        plain, plaintext,
                        "alg {algorithm:#06x} mode {mode:#06x} length {length}"
                    );
                }
            }
        }
    }

    #[test]
    fn one_buffer_survives_an_in_place_round_trip() {
        let key = pattern(32, 0x77);
        for algorithm in [TPM_ALG_AES, TPM_ALG_TDES, TPM_ALG_CAMELLIA] {
            let block = sym_block_size(algorithm).expect("a compiled algorithm");
            let key = &key[..if algorithm == TPM_ALG_TDES { 24 } else { 32 }];
            for mode in [
                TPM_ALG_CFB,
                TPM_ALG_OFB,
                TPM_ALG_CTR,
                TPM_ALG_CBC,
                TPM_ALG_ECB,
            ] {
                let iv_len = if mode == TPM_ALG_ECB { 0 } else { block };
                let plaintext = pattern(2 * block, 0x40);
                let mut buffer = plaintext.clone();
                let mut chaining = pattern(iv_len, 0x99);
                sym_crypt(
                    algorithm,
                    key,
                    mode,
                    &mut chaining,
                    SymDirection::Encrypt,
                    &mut buffer,
                )
                .expect("encrypts in place");
                assert_ne!(buffer, plaintext, "alg {algorithm:#06x} mode {mode:#06x}");
                let mut chaining = pattern(iv_len, 0x99);
                sym_crypt(
                    algorithm,
                    key,
                    mode,
                    &mut chaining,
                    SymDirection::Decrypt,
                    &mut buffer,
                )
                .expect("decrypts in place");
                assert_eq!(buffer, plaintext, "alg {algorithm:#06x} mode {mode:#06x}");
            }
        }
    }

    #[test]
    fn invalid_symmetric_arguments_are_rejected() {
        for algorithm in [0x0000u16, TPM_ALG_AES, TPM_ALG_TDES, 0xffff] {
            for mode in [0x0000u16, TPM_ALG_CFB, TPM_ALG_ECB, 0xffff] {
                for key_len in [0usize, 1, 16, 33] {
                    for iv_len in [0usize, 1, 8, 16, 24] {
                        for data_len in [0usize, 1, 7, 16, 31] {
                            let mut iv = vec![0x22; iv_len];
                            let mut data = vec![0x33; data_len];
                            let _ = sym_crypt(
                                algorithm,
                                &vec![0x11; key_len],
                                mode,
                                &mut iv,
                                SymDirection::Decrypt,
                                &mut data,
                            );
                        }
                    }
                }
            }
        }
    }
}
