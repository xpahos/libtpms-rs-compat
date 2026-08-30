use aes::cipher::{BlockEncrypt, KeyInit};

use crate::library::constants::TPM_FAIL;
use crate::types::TpmResult;

use super::entropy::EntropySource;

pub(in crate::library::tpm2) const DRBG_MAGIC: u32 = 0x4742_5244;

pub(in crate::library::tpm2) const DRBG_KEY_SIZE: usize = 32;
pub(in crate::library::tpm2) const DRBG_IV_SIZE: usize = 16;
pub(in crate::library::tpm2) const DRBG_SEED_SIZE: usize = DRBG_KEY_SIZE + DRBG_IV_SIZE;

pub(in crate::library::tpm2) const CTR_DRBG_MAX_REQUESTS_PER_RESEED: u64 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum StirError {
    Entropy,
    ContinuousTest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum ReseedError {
    Entropy,
    ContinuousTest,
}

pub(in crate::library::tpm2) struct Drbg {
    reseed_counter: u64,
    seed: [u8; DRBG_SEED_SIZE],
    last_value: [u32; 4],
    continuous_test: bool,
}

fn increment_iv(iv: &mut [u8; DRBG_IV_SIZE]) {
    for byte in iv.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

pub(super) fn encrypt_block(cipher: &aes::Aes256, block: [u8; DRBG_IV_SIZE]) -> [u8; DRBG_IV_SIZE] {
    let mut block = aes::Block::from(block);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn block_words(block: &[u8; DRBG_IV_SIZE]) -> [u32; 4] {
    core::array::from_fn(|word| {
        u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
    })
}

impl Drbg {
    pub(in crate::library::tpm2) fn instantiate(
        entropy: EntropySource,
        continuous_test: bool,
    ) -> Result<Self, ReseedError> {
        let mut seed_material = [0u8; DRBG_SEED_SIZE];
        entropy(&mut seed_material).map_err(|_| ReseedError::Entropy)?;
        let mut drbg = Self {
            reseed_counter: 0,
            seed: [0; DRBG_SEED_SIZE],
            last_value: [0; 4],
            continuous_test,
        };
        drbg.reseed(&seed_material)
            .map_err(|_| ReseedError::ContinuousTest)?;
        Ok(drbg)
    }

    pub(in crate::library::tpm2) fn instantiate_seeded(
        inputs: &[&[u8]],
        continuous_test: bool,
    ) -> Result<Self, TpmResult> {
        let mut concatenated = Vec::new();
        for input in inputs {
            concatenated.extend_from_slice(input);
        }
        let derived = super::df::df_buffer(&concatenated).ok_or(TPM_FAIL)?;
        let mut drbg = Self {
            reseed_counter: 0,
            seed: [0; DRBG_SEED_SIZE],
            last_value: [0; 4],
            continuous_test,
        };
        drbg.reseed(&derived)?;
        Ok(drbg)
    }

    pub(in crate::library::tpm2) fn additional_data(
        &mut self,
        data: &[u8],
    ) -> Result<(), TpmResult> {
        let derived = super::df::df_buffer(data).ok_or(TPM_FAIL)?;
        self.reseed(&derived)
    }

    pub(in crate::library::tpm2) fn restore(
        seed: &[u8],
        reseed_counter: u64,
        last_value: [u32; 4],
        continuous_test: bool,
    ) -> Result<Self, TpmResult> {
        let seed: [u8; DRBG_SEED_SIZE] = seed.try_into().map_err(|_| TPM_FAIL)?;
        Ok(Self {
            reseed_counter,
            seed,
            last_value,
            continuous_test,
        })
    }

    pub(in crate::library::tpm2) fn reseed_from_entropy(
        &mut self,
        entropy: EntropySource,
    ) -> Result<(), ReseedError> {
        let mut seed_material = [0u8; DRBG_SEED_SIZE];
        entropy(&mut seed_material).map_err(|_| ReseedError::Entropy)?;
        self.reseed(&seed_material)
            .map_err(|_| ReseedError::ContinuousTest)
    }

    pub(in crate::library::tpm2) fn stir(
        &mut self,
        entropy: EntropySource,
        additional_data: Option<&[u8; DRBG_SEED_SIZE]>,
    ) -> Result<(), StirError> {
        let mut seed_material = [0u8; DRBG_SEED_SIZE];
        entropy(&mut seed_material).map_err(|_| StirError::Entropy)?;
        if let Some(data) = additional_data {
            for (byte, data_byte) in seed_material.iter_mut().zip(data) {
                *byte ^= data_byte;
            }
        }
        self.reseed(&seed_material)
            .map_err(|_| StirError::ContinuousTest)
    }

    fn reseed(&mut self, provided_entropy: &[u8; DRBG_SEED_SIZE]) -> Result<(), TpmResult> {
        let key = self.key_schedule();
        self.update(&key, Some(provided_entropy))?;
        self.reseed_counter = 1;
        Ok(())
    }

    pub(in crate::library::tpm2) fn generate(
        &mut self,
        output: &mut [u8],
    ) -> Result<(), TpmResult> {
        let key = self.key_schedule();
        let mut iv = self.iv();
        self.encrypt_drbg(&key, &mut iv, output)?;
        self.seed[DRBG_KEY_SIZE..].copy_from_slice(&iv);
        self.update(&key, None)?;
        self.reseed_counter += 1;
        Ok(())
    }

    fn update(
        &mut self,
        key: &aes::Aes256,
        provided_data: Option<&[u8; DRBG_SEED_SIZE]>,
    ) -> Result<(), TpmResult> {
        let mut iv = self.iv();
        let mut new_seed = [0u8; DRBG_SEED_SIZE];
        self.encrypt_drbg(key, &mut iv, &mut new_seed)?;
        if let Some(data) = provided_data {
            for (byte, data_byte) in new_seed.iter_mut().zip(data) {
                *byte ^= data_byte;
            }
        }
        self.seed = new_seed;
        Ok(())
    }

    fn encrypt_drbg(
        &mut self,
        key: &aes::Aes256,
        iv: &mut [u8; DRBG_IV_SIZE],
        output: &mut [u8],
    ) -> Result<(), TpmResult> {
        for chunk in output.chunks_mut(DRBG_IV_SIZE) {
            increment_iv(iv);
            let block = encrypt_block(key, *iv);
            if self.continuous_test {
                let words = block_words(&block);
                if words == self.last_value {
                    return Err(TPM_FAIL);
                }
                self.last_value = words;
            }
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }

    fn key_schedule(&self) -> aes::Aes256 {
        let key: &[u8; DRBG_KEY_SIZE] = self.seed[..DRBG_KEY_SIZE].try_into().unwrap();
        aes::Aes256::new(key.into())
    }

    fn iv(&self) -> [u8; DRBG_IV_SIZE] {
        self.seed[DRBG_KEY_SIZE..].try_into().unwrap()
    }

    pub(in crate::library::tpm2) fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    pub(in crate::library::tpm2) fn needs_reseed(&self) -> bool {
        self.reseed_counter >= CTR_DRBG_MAX_REQUESTS_PER_RESEED
    }

    pub(in crate::library::tpm2) fn seed(&self) -> &[u8; DRBG_SEED_SIZE] {
        &self.seed
    }

    pub(in crate::library::tpm2) fn last_value(&self) -> [u32; 4] {
        self.last_value
    }
}

#[cfg(test)]
mod tests {
    use super::super::drbg_vectors::{DrbgVectorRecord, vector_record};
    use super::*;

    fn oracle_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        assert_eq!(buffer.len(), DRBG_SEED_SIZE, "one full-seed request");
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(DRBG_SEED_SIZE as u8) ^ 0xa5;
        }
        Ok(())
    }

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn assert_instantiate_matches(record: &DrbgVectorRecord, continuous: bool) -> Drbg {
        let drbg = Drbg::instantiate(oracle_entropy, continuous).expect("instantiate");
        assert_eq!(drbg.seed(), &record.seed_after_instantiate);
        assert_eq!(drbg.last_value(), record.last_value_after_instantiate);
        assert_eq!(
            drbg.reseed_counter(),
            record.reseed_counter_after_instantiate
        );
        assert_eq!(drbg.reseed_counter(), 1, "DRBG_Reseed's final assignment");
        drbg
    }

    #[test]
    fn instantiate_vendored_oracle_parity() {
        assert_instantiate_matches(&vector_record(false), false);
        assert_instantiate_matches(&vector_record(true), true);
    }

    #[test]
    fn generate_sequence_vendored_oracle_parity() {
        for continuous in [false, true] {
            let record = vector_record(continuous);
            let mut drbg = assert_instantiate_matches(&record, continuous);
            let mut output = [0u8; 64];
            let draws = [
                &record.commit_nonce,
                &record.ep_seed,
                &record.sp_seed,
                &record.pp_seed,
                &record.ph_proof,
                &record.sh_proof,
                &record.eh_proof,
            ];
            for (index, expected) in draws.into_iter().enumerate() {
                drbg.generate(&mut output).expect("generate");
                assert_eq!(&output, expected, "continuous {continuous}, draw {index}");
                assert_eq!(drbg.reseed_counter(), 2 + index as u64);
            }
            assert_eq!(drbg.seed(), &record.final_seed);
            assert_eq!(drbg.reseed_counter(), record.final_reseed_counter);
            assert_eq!(drbg.last_value(), record.final_last_value);
        }
    }

    #[test]
    fn continuous_test_last_value_tracking_mode_distinction() {
        let plain = vector_record(false);
        let continuous = vector_record(true);
        assert_eq!(plain.final_seed, continuous.final_seed);
        assert_eq!(plain.ep_seed, continuous.ep_seed);
        assert_eq!(plain.final_last_value, [0; 4], "plain mode never writes");
        assert_ne!(continuous.final_last_value, [0; 4]);
    }

    #[test]
    fn partial_block_request_last_block_truncation() {
        let mut long_drbg = Drbg::instantiate(oracle_entropy, false).unwrap();
        let mut short_drbg = Drbg::instantiate(oracle_entropy, false).unwrap();
        let mut long = [0u8; 64];
        let mut short = [0u8; 20];
        long_drbg.generate(&mut long).unwrap();
        short_drbg.generate(&mut short).unwrap();
        assert_eq!(short, long[..20]);
    }

    #[test]
    fn instantiate_entropy_failure_propagation() {
        assert_eq!(
            Drbg::instantiate(failing_entropy, false).map(|_| ()),
            Err(ReseedError::Entropy)
        );
    }

    fn snapshot(drbg: &Drbg) -> ([u8; DRBG_SEED_SIZE], u64, [u32; 4]) {
        (*drbg.seed(), drbg.reseed_counter(), drbg.last_value())
    }

    fn colliding_last_value(drbg: &Drbg) -> [u32; 4] {
        let key: [u8; DRBG_KEY_SIZE] = drbg.seed()[..DRBG_KEY_SIZE].try_into().unwrap();
        let mut iv: [u8; DRBG_IV_SIZE] = drbg.seed()[DRBG_KEY_SIZE..].try_into().unwrap();
        increment_iv(&mut iv);
        let cipher = aes::Aes256::new(&key.into());
        block_words(&encrypt_block(&cipher, iv))
    }

    #[test]
    fn entropy_failure_classification_state_unchanged() {
        let mut drbg = Drbg::instantiate(oracle_entropy, true).expect("instantiate");
        let before = snapshot(&drbg);
        assert_eq!(
            drbg.reseed_from_entropy(failing_entropy),
            Err(ReseedError::Entropy)
        );
        assert_eq!(
            snapshot(&drbg),
            before,
            "DRBG_Reseed bails before the update"
        );
        assert_eq!(drbg.stir(failing_entropy, None), Err(StirError::Entropy));
        assert_eq!(snapshot(&drbg), before);
    }

    #[test]
    fn reseed_repeated_block_continuous_test_failure() {
        let drbg = Drbg::instantiate(oracle_entropy, true).expect("instantiate");
        let collision = colliding_last_value(&drbg);
        let mut drbg =
            Drbg::restore(drbg.seed(), drbg.reseed_counter(), collision, true).expect("restores");
        let before = snapshot(&drbg);
        assert_eq!(
            drbg.reseed_from_entropy(oracle_entropy),
            Err(ReseedError::ContinuousTest)
        );
        assert_eq!(snapshot(&drbg), before, "the failed update is not stored");
        assert_eq!(
            drbg.stir(oracle_entropy, None),
            Err(StirError::ContinuousTest)
        );
    }

    #[test]
    fn generation_repeated_block_continuous_test_failure() {
        let source = Drbg::instantiate(oracle_entropy, true).expect("instantiate");
        let collision = colliding_last_value(&source);
        let mut drbg = Drbg::restore(source.seed(), source.reseed_counter(), collision, true)
            .expect("restores");
        let before = snapshot(&drbg);
        let mut out = [0u8; 16];
        assert_eq!(drbg.generate(&mut out), Err(TPM_FAIL));
        assert_eq!(
            (*drbg.seed(), drbg.reseed_counter()),
            (before.0, before.1),
            "the failed generation neither stores a new seed nor advances the counter"
        );

        let mut plain = Drbg::restore(source.seed(), source.reseed_counter(), collision, false)
            .expect("restores");
        assert!(
            plain.generate(&mut out).is_ok(),
            "without the attribute the same state generates"
        );
    }

    #[test]
    fn fips_197_appendix_c3_known_answer() {
        let key: [u8; DRBG_KEY_SIZE] = core::array::from_fn(|index| index as u8);
        let plaintext: [u8; DRBG_IV_SIZE] = core::array::from_fn(|index| (index * 0x11) as u8);
        let expected = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        let cipher = aes::Aes256::new(&key.into());
        assert_eq!(encrypt_block(&cipher, plaintext), expected);
    }

    #[test]
    fn iv_increment_cross_byte_carry() {
        let mut iv = [0xff; DRBG_IV_SIZE];
        increment_iv(&mut iv);
        assert_eq!(iv, [0; DRBG_IV_SIZE], "full wrap");
        let mut iv = [0u8; DRBG_IV_SIZE];
        iv[15] = 0xff;
        increment_iv(&mut iv);
        let mut expected = [0u8; DRBG_IV_SIZE];
        expected[14] = 0x01;
        assert_eq!(iv, expected, "single carry");
    }
}
