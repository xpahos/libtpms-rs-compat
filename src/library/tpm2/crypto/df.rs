// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/crypto/openssl/CryptRand.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2023
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use aes::cipher::KeyInit;

use super::drbg::{DRBG_IV_SIZE, DRBG_KEY_SIZE, DRBG_SEED_SIZE, encrypt_block};

const DF_COUNT: usize = DRBG_KEY_SIZE / DRBG_IV_SIZE + 1;

const _: () = assert!(DF_COUNT * DRBG_IV_SIZE == DRBG_SEED_SIZE);

const DF_KEY: [u8; DRBG_KEY_SIZE] = {
    let mut key = [0u8; DRBG_KEY_SIZE];
    let mut index = 0;
    while index < DRBG_KEY_SIZE {
        key[index] = index as u8;
        index += 1;
    }
    key
};

struct DfState {
    key_schedule: aes::Aes256,
    iv: [[u8; DRBG_IV_SIZE]; DF_COUNT],
    buf: [u8; DRBG_IV_SIZE],
    contents: usize,
}

impl DfState {
    fn start(input_length: u32) -> Self {
        let mut state = Self {
            key_schedule: aes::Aes256::new(&DF_KEY.into()),
            iv: [[0; DRBG_IV_SIZE]; DF_COUNT],
            buf: [0; DRBG_IV_SIZE],
            contents: 0,
        };
        for (index, block) in state.iv.iter_mut().enumerate() {
            block[3] = index as u8;
        }
        state.compute();
        state.iv[0][..4].copy_from_slice(&input_length.to_be_bytes());
        state.iv[0][4..8].copy_from_slice(&(DRBG_SEED_SIZE as u32).to_be_bytes());
        state.contents = 4;
        state
    }

    fn compute(&mut self) {
        let buf = self.buf;
        let mut temp = [0u8; DRBG_IV_SIZE];
        for block in &mut self.iv {
            for (index, byte) in temp.iter_mut().enumerate() {
                *byte ^= block[index] ^ buf[index];
            }
            *block = encrypt_block(&self.key_schedule, temp);
        }
        self.buf = [0; DRBG_IV_SIZE];
        self.contents = 0;
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let to_fill = (DRBG_IV_SIZE - self.contents).min(data.len());
            self.buf[self.contents..self.contents + to_fill].copy_from_slice(&data[..to_fill]);
            data = &data[to_fill..];
            self.contents += to_fill;
            if self.contents == DRBG_IV_SIZE {
                self.compute();
            }
        }
    }

    fn end(&mut self) -> [u8; DRBG_SEED_SIZE] {
        self.buf[self.contents] = 0x80;
        self.contents += 1;
        while self.contents < DRBG_IV_SIZE {
            self.buf[self.contents] = 0;
            self.contents += 1;
        }
        self.compute();
        let mut seed = [0u8; DRBG_SEED_SIZE];
        for (index, block) in self.iv.iter().enumerate() {
            seed[index * DRBG_IV_SIZE..(index + 1) * DRBG_IV_SIZE].copy_from_slice(block);
        }
        seed
    }
}

pub(in crate::library::tpm2) fn df_buffer(data: &[u8]) -> Option<[u8; DRBG_SEED_SIZE]> {
    if data.is_empty() {
        return None;
    }
    let mut state = DfState::start(data.len() as u32);
    state.update(data);
    Some(state.end())
}

#[cfg(test)]
mod tests {
    use super::super::drbg_vectors::stir_record;
    use super::*;

    #[test]
    fn derivation_key_upstream_ascending_pattern() {
        assert_eq!(DF_KEY[0], 0x00);
        assert_eq!(DF_KEY[31], 0x1f);
        assert!(
            DF_KEY
                .iter()
                .enumerate()
                .all(|(index, &byte)| byte == index as u8)
        );
    }

    #[test]
    fn empty_input_no_additional_data_block() {
        assert_eq!(df_buffer(&[]), None, "upstream DfBuffer returns NULL");
    }

    #[test]
    fn non_empty_input_single_seed_block() {
        for length in [1usize, 4, 11, 12, 15, 16, 17, 47, 48, 127, 128] {
            let data: Vec<u8> = (0..length).map(|index| index as u8).collect();
            let derived = df_buffer(&data).expect("a non-empty input derives a block");
            assert_eq!(derived.len(), DRBG_SEED_SIZE, "length {length}");
        }
    }

    #[test]
    fn derivation_determinism_input_sensitivity() {
        let base: Vec<u8> = (0..48u8).collect();
        let derived = df_buffer(&base).expect("derives");
        assert_eq!(df_buffer(&base), Some(derived), "the same input repeats");

        let mut flipped = base.clone();
        flipped[47] ^= 0x01;
        assert_ne!(df_buffer(&flipped), Some(derived), "one flipped bit");

        let mut shorter = base.clone();
        shorter.pop();
        assert_ne!(df_buffer(&shorter), Some(derived), "the length is absorbed");
    }

    #[test]
    fn zero_prefix_shorter_input_no_collision() {
        let short = df_buffer(&[0x11]).expect("derives");
        let padded = df_buffer(&[0x11, 0x00]).expect("derives");
        assert_ne!(short, padded);
    }

    #[test]
    fn derived_block_vendored_oracle_match() {
        let record = stir_record(false);
        let mut seen: Vec<[u8; DRBG_SEED_SIZE]> = Vec::new();
        for (index, case) in record.cases.iter().enumerate() {
            let additional = case.additional();
            let Some(derived) = df_buffer(additional) else {
                assert!(additional.is_empty(), "case {index}");
                assert_eq!(case.derived, [0; DRBG_SEED_SIZE], "case {index}");
                continue;
            };
            assert_eq!(derived, case.derived, "case {index}");
            assert!(
                !seen.contains(&derived),
                "case {index} repeats an earlier block"
            );
            seen.push(derived);
        }
        assert_eq!(seen.len(), record.cases.len() - 1, "one empty input");
    }

    #[test]
    fn derivation_continuous_test_mode_independence() {
        let plain = stir_record(false);
        let continuous = stir_record(true);
        for (index, (left, right)) in plain.cases.iter().zip(&continuous.cases).enumerate() {
            assert_eq!(left.derived, right.derived, "case {index}");
        }
    }
}
