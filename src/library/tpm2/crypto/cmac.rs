use crate::library::constants::TPM_RC_SYMMETRIC;
use crate::types::TpmResult;

use super::sym::{SymCipher, sym_key_block_size};

const SUBKEY_CONSTANT: u8 = 0x87;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct CmacState {
    algorithm: u16,
    key: Vec<u8>,
    accumulator: Vec<u8>,
    filled: usize,
}

impl CmacState {
    pub(in crate::library::tpm2) fn start(
        algorithm: u16,
        key_bits: u16,
        key: &[u8],
    ) -> Result<Self, TpmResult> {
        let block_size = sym_key_block_size(algorithm, key_bits).ok_or(TPM_RC_SYMMETRIC)?;
        if key.len() != usize::from(key_bits) / 8 {
            return Err(TPM_RC_SYMMETRIC);
        }
        SymCipher::new(algorithm, key)?;
        Ok(Self {
            algorithm,
            key: key.to_vec(),
            accumulator: vec![0u8; block_size],
            filled: 0,
        })
    }

    pub(in crate::library::tpm2) fn update(&mut self, data: &[u8]) -> Result<(), TpmResult> {
        if data.is_empty() {
            return Ok(());
        }
        let cipher = SymCipher::new(self.algorithm, &self.key)?;
        for byte in data {
            if self.filled == self.accumulator.len() {
                cipher.encrypt_block(&mut self.accumulator);
                self.filled = 0;
            }
            self.accumulator[self.filled] ^= byte;
            self.filled += 1;
        }
        Ok(())
    }

    pub(in crate::library::tpm2) fn finalize(mut self) -> Result<Vec<u8>, TpmResult> {
        let cipher = SymCipher::new(self.algorithm, &self.key)?;
        let mut subkey = vec![0u8; self.accumulator.len()];
        cipher.encrypt_block(&mut subkey);
        shift_left(&mut subkey);
        if self.filled < self.accumulator.len() {
            self.accumulator[self.filled] ^= 0x80;
            shift_left(&mut subkey);
        }
        for (byte, mask) in self.accumulator.iter_mut().zip(subkey.iter()) {
            *byte ^= mask;
        }
        cipher.encrypt_block(&mut self.accumulator);
        Ok(self.accumulator)
    }
}

fn shift_left(value: &mut [u8]) {
    let Some(&first) = value.first() else {
        return;
    };
    let carry = if first & 0x80 == 0 {
        0
    } else {
        SUBKEY_CONSTANT
    };
    for index in 0..value.len() - 1 {
        value[index] = (value[index] << 1) | (value[index + 1] >> 7);
    }
    if let Some(last) = value.last_mut() {
        *last <<= 1;
        *last ^= carry;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::{
        TPM_ALG_AES, TPM_ALG_CAMELLIA, TPM_ALG_NULL, TPM_ALG_TDES,
    };

    fn unhex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).expect("hexadecimal"))
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[track_caller]
    fn mac(algorithm: u16, key: &[u8], data: &[u8]) -> String {
        let mut state =
            CmacState::start(algorithm, (key.len() * 8) as u16, key).expect("a supported key");
        state.update(data).expect("the update succeeds");
        hex(&state.finalize().expect("the digest completes"))
    }

    const RFC_4493_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const SP800_38B_KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    const SP800_38B_KEY_256: &str =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    const SP800_38B_MESSAGE: &str = "6bc1bee22e409f96e93d7e117393172a\
                                     ae2d8a571e03ac9c9eb76fac45af8e51\
                                     30c81c46a35ce411e5fbc1191a0a52ef\
                                     f69f2445df4f9b17ad2b417be66c3710";

    #[test]
    fn the_rfc_4493_aes_128_vectors_are_reproduced() {
        let key = unhex(RFC_4493_KEY);
        let message = unhex(SP800_38B_MESSAGE);
        for (length, expected) in [
            (0usize, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            assert_eq!(
                mac(TPM_ALG_AES, &key, &message[..length]),
                expected,
                "message length {length}"
            );
        }
    }

    #[test]
    fn the_sp800_38b_aes_192_and_256_vectors_are_reproduced() {
        let message = unhex(SP800_38B_MESSAGE);
        for (key, cases) in [
            (
                SP800_38B_KEY_192,
                [
                    (0usize, "d17ddf46adaacde531cac483de7a9367"),
                    (16, "9e99a7bf31e710900662f65e617c5184"),
                    (40, "8a1de5be2eb31aad089a82e6ee908b0e"),
                    (64, "a1d5df0eed790f794d77589659f39a11"),
                ],
            ),
            (
                SP800_38B_KEY_256,
                [
                    (0, "028962f61b7bf89efc6b551f4667d983"),
                    (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
                    (40, "aaf3d8f1de5640c232f5b169b9c911e6"),
                    (64, "e1992190549f6ed5696a2c056c315410"),
                ],
            ),
        ] {
            let key = unhex(key);
            for (length, expected) in cases {
                assert_eq!(
                    mac(TPM_ALG_AES, &key, &message[..length]),
                    expected,
                    "key {} message length {length}",
                    key.len() * 8
                );
            }
        }
    }

    #[test]
    fn every_supported_cipher_and_key_size_matches_its_reference_value() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let message = unhex(SP800_38B_MESSAGE);
        let cases: [(u16, usize, usize, &str); 16] = [
            (TPM_ALG_AES, 16, 0, "97dd6e5a882cbd564c39ae7d1c5a31aa"),
            (TPM_ALG_AES, 16, 5, "893cb82d6abab924d7c503eefe541fc3"),
            (TPM_ALG_AES, 16, 16, "d0bc5bb4d6f60d5b17b7bf794b45436d"),
            (TPM_ALG_AES, 16, 40, "989bafbfce64b39b28edf0379e6ef5dd"),
            (TPM_ALG_AES, 24, 0, "ec12390ea0a7ed15d9d37a6eca1fc990"),
            (TPM_ALG_AES, 24, 40, "395673cd987d20d1f2458168af475082"),
            (TPM_ALG_AES, 32, 0, "6bf0a293d8cba0101f0089727691b7fb"),
            (TPM_ALG_AES, 32, 40, "d8f1006134177e136ccda9d687ffdfb5"),
            (TPM_ALG_CAMELLIA, 16, 0, "b5664c5148ffb45297703bcc46c19e4e"),
            (TPM_ALG_CAMELLIA, 16, 40, "fa07d173a1e0298ac8ee80d479a7d48e"),
            (TPM_ALG_CAMELLIA, 24, 0, "392700e3dba24ca440a4b611390b8532"),
            (TPM_ALG_CAMELLIA, 24, 40, "1894217dc17c213c9a4735901dfdb207"),
            (TPM_ALG_CAMELLIA, 32, 0, "094c224d76948b19ee25e3ad91f983ec"),
            (TPM_ALG_CAMELLIA, 32, 40, "1dc0db3b426d59175135df9131390ef6"),
            (TPM_ALG_TDES, 16, 0, "3ca5952d4524bff5"),
            (TPM_ALG_TDES, 24, 40, "abcb1bda5a604c4e"),
        ];
        for (algorithm, key_bytes, length, expected) in cases {
            assert_eq!(
                mac(algorithm, &key[..key_bytes], &message[..length]),
                expected,
                "alg {algorithm:#06x} key {key_bytes} length {length}"
            );
        }
    }

    #[test]
    fn incremental_updates_match_the_one_shot_result() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let message: Vec<u8> = (0..100u32).map(|index| index as u8).collect();
        for (algorithm, key_bytes) in [
            (TPM_ALG_AES, 16usize),
            (TPM_ALG_AES, 24),
            (TPM_ALG_AES, 32),
            (TPM_ALG_CAMELLIA, 16),
            (TPM_ALG_TDES, 24),
        ] {
            let key = &key[..key_bytes];
            let whole = mac(algorithm, key, &message);
            for split in [0usize, 1, 7, 8, 15, 16, 17, 31, 32, 63, 64, 99, 100] {
                let mut state = CmacState::start(algorithm, (key_bytes * 8) as u16, key)
                    .expect("a supported key");
                state.update(&message[..split]).expect("the first part");
                state.update(&message[split..]).expect("the second part");
                assert_eq!(
                    hex(&state.finalize().expect("the digest completes")),
                    whole,
                    "alg {algorithm:#06x} key {key_bytes} split {split}"
                );
            }
            let mut state =
                CmacState::start(algorithm, (key_bytes * 8) as u16, key).expect("a supported key");
            for chunk in message.chunks(3) {
                state.update(chunk).expect("a chunk");
            }
            assert_eq!(
                hex(&state.finalize().expect("the digest completes")),
                whole,
                "alg {algorithm:#06x} key {key_bytes} in three-byte chunks"
            );
        }
    }

    #[test]
    fn the_digest_size_follows_the_block_size() {
        for (algorithm, key_bytes, size) in [
            (TPM_ALG_AES, 16usize, 16usize),
            (TPM_ALG_CAMELLIA, 32, 16),
            (TPM_ALG_TDES, 24, 8),
        ] {
            let state = CmacState::start(algorithm, (key_bytes * 8) as u16, &vec![0x11; key_bytes])
                .expect("a supported key");
            assert_eq!(
                state.finalize().expect("the digest completes").len(),
                size,
                "alg {algorithm:#06x}"
            );
        }
    }

    #[test]
    fn unsupported_keys_are_rejected_without_panicking() {
        for (algorithm, key_bits, key_len) in [
            (TPM_ALG_AES, 64u16, 8usize),
            (TPM_ALG_AES, 128, 32),
            (TPM_ALG_TDES, 256, 32),
            (TPM_ALG_NULL, 128, 16),
            (0xffff, 128, 16),
            (TPM_ALG_CAMELLIA, 0, 0),
        ] {
            assert_eq!(
                CmacState::start(algorithm, key_bits, &vec![0x11; key_len]).err(),
                Some(TPM_RC_SYMMETRIC),
                "alg {algorithm:#06x} bits {key_bits} key {key_len}"
            );
        }
    }
}
