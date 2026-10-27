#[allow(deprecated)]
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymKey {
    Aes128,
    Aes192,
    Aes256,
    Camellia128,
    Camellia192,
    Camellia256,
    Tdes128,
    Tdes192,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymMode {
    Ctr,
    Ofb,
    Cbc,
    Cfb,
    Ecb,
}

impl SymKey {
    pub const ALL: [SymKey; 8] = [
        Self::Aes128,
        Self::Aes192,
        Self::Aes256,
        Self::Camellia128,
        Self::Camellia192,
        Self::Camellia256,
        Self::Tdes128,
        Self::Tdes192,
    ];

    pub fn alg_id(self) -> u16 {
        match self {
            Self::Aes128 | Self::Aes192 | Self::Aes256 => 0x0006,
            Self::Camellia128 | Self::Camellia192 | Self::Camellia256 => 0x0026,
            Self::Tdes128 | Self::Tdes192 => 0x0003,
        }
    }

    pub fn bits(self) -> u16 {
        match self {
            Self::Aes128 | Self::Camellia128 | Self::Tdes128 => 128,
            Self::Aes192 | Self::Camellia192 | Self::Tdes192 => 192,
            Self::Aes256 | Self::Camellia256 => 256,
        }
    }

    pub fn key_bytes(self) -> usize {
        self.bits() as usize / 8
    }

    pub fn block(self) -> usize {
        match self {
            Self::Tdes128 | Self::Tdes192 => 8,
            _ => 16,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128",
            Self::Aes192 => "aes192",
            Self::Aes256 => "aes256",
            Self::Camellia128 => "camellia128",
            Self::Camellia192 => "camellia192",
            Self::Camellia256 => "camellia256",
            Self::Tdes128 => "tdes128",
            Self::Tdes192 => "tdes192",
        }
    }

    pub fn is_tdes(self) -> bool {
        matches!(self, Self::Tdes128 | Self::Tdes192)
    }

    pub fn valid_key(self, key: &[u8]) -> bool {
        key.len() == self.key_bytes() && (!self.is_tdes() || tdes_key_valid(key))
    }

    #[allow(deprecated)]
    pub fn encrypt_block(self, key: &[u8], block: &mut [u8]) {
        macro_rules! enc {
            ($t:ty) => {{
                let cipher = <$t>::new_from_slice(key).expect("key length checked");
                cipher.encrypt_block(GenericArray::from_mut_slice(block));
            }};
        }
        match self {
            Self::Aes128 => enc!(aes::Aes128),
            Self::Aes192 => enc!(aes::Aes192),
            Self::Aes256 => enc!(aes::Aes256),
            Self::Camellia128 => enc!(camellia::Camellia128),
            Self::Camellia192 => enc!(camellia::Camellia192),
            Self::Camellia256 => enc!(camellia::Camellia256),
            Self::Tdes128 => enc!(des::TdesEde2),
            Self::Tdes192 => enc!(des::TdesEde3),
        }
    }

    #[allow(deprecated)]
    pub fn decrypt_block(self, key: &[u8], block: &mut [u8]) {
        macro_rules! dec {
            ($t:ty) => {{
                let cipher = <$t>::new_from_slice(key).expect("key length checked");
                cipher.decrypt_block(GenericArray::from_mut_slice(block));
            }};
        }
        match self {
            Self::Aes128 => dec!(aes::Aes128),
            Self::Aes192 => dec!(aes::Aes192),
            Self::Aes256 => dec!(aes::Aes256),
            Self::Camellia128 => dec!(camellia::Camellia128),
            Self::Camellia192 => dec!(camellia::Camellia192),
            Self::Camellia256 => dec!(camellia::Camellia256),
            Self::Tdes128 => dec!(des::TdesEde2),
            Self::Tdes192 => dec!(des::TdesEde3),
        }
    }

    pub fn encrypt_block_copy(self, key: &[u8], block: &[u8]) -> Vec<u8> {
        let mut out = block.to_vec();
        self.encrypt_block(key, &mut out);
        out
    }
}

impl SymMode {
    pub const ALL: [SymMode; 5] = [Self::Ctr, Self::Ofb, Self::Cbc, Self::Cfb, Self::Ecb];

    pub fn alg_id(self) -> u16 {
        match self {
            Self::Ctr => 0x0040,
            Self::Ofb => 0x0041,
            Self::Cbc => 0x0042,
            Self::Cfb => 0x0043,
            Self::Ecb => 0x0044,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ctr => "ctr",
            Self::Ofb => "ofb",
            Self::Cbc => "cbc",
            Self::Cfb => "cfb",
            Self::Ecb => "ecb",
        }
    }

    pub fn uses_iv(self) -> bool {
        self != Self::Ecb
    }
}

fn increment(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

/// The chaining value (ivOut) returned after a partial final CFB block.
///
/// The two supported backends disagree on this confirmed, independently
/// reproducible difference, so the exact contract is recorded per backend:
///
/// - [`ChainingContract::RetainedSuffix`]: the OpenSSL-backed C reference keeps
///   the unused suffix of the encrypted feedback block in the chaining value.
/// - [`ChainingContract::ZeroSuffix`]: this repository's Rust port zeroes the
///   unused suffix and keeps only the produced ciphertext (or plaintext) prefix.
///
/// The data output itself is identical under both contracts; only the chaining
/// value differs. Never mask or hash the differing bytes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChainingContract {
    RetainedSuffix,
    ZeroSuffix,
}

pub const DEFAULT_CHAINING_CONTRACT: ChainingContract = ChainingContract::RetainedSuffix;

pub fn crypt(
    key_spec: SymKey,
    mode: SymMode,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> (Vec<u8>, Vec<u8>) {
    crypt_contract(
        key_spec,
        mode,
        key,
        iv,
        data,
        encrypt,
        DEFAULT_CHAINING_CONTRACT,
    )
}

pub fn crypt_contract(
    key_spec: SymKey,
    mode: SymMode,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
    contract: ChainingContract,
) -> (Vec<u8>, Vec<u8>) {
    let n = key_spec.block();
    if matches!(mode, SymMode::Cbc | SymMode::Ecb) {
        assert_eq!(data.len() % n, 0, "block mode requires whole blocks");
    }
    let mut state = if mode.uses_iv() {
        assert_eq!(iv.len(), n);
        iv.to_vec()
    } else {
        Vec::new()
    };
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(n) {
        match mode {
            SymMode::Ecb => {
                let mut block = chunk.to_vec();
                if encrypt {
                    key_spec.encrypt_block(key, &mut block);
                } else {
                    key_spec.decrypt_block(key, &mut block);
                }
                out.extend(block);
            }
            SymMode::Cbc => {
                if encrypt {
                    let mut block: Vec<u8> = chunk.iter().zip(&state).map(|(a, b)| a ^ b).collect();
                    key_spec.encrypt_block(key, &mut block);
                    state = block.clone();
                    out.extend(block);
                } else {
                    let mut block = chunk.to_vec();
                    key_spec.decrypt_block(key, &mut block);
                    out.extend(block.iter().zip(&state).map(|(a, b)| a ^ b));
                    state = chunk.to_vec();
                }
            }
            SymMode::Cfb => {
                let mut keystream = state.clone();
                key_spec.encrypt_block(key, &mut keystream);
                let produced: Vec<u8> = chunk.iter().zip(&keystream).map(|(a, b)| a ^ b).collect();
                // The prefix of the chaining value always holds the partial
                // ciphertext (encrypt) or plaintext (decrypt); only the unused
                // suffix is governed by the backend's chaining contract.
                state = keystream;
                state[..chunk.len()].copy_from_slice(if encrypt { &produced } else { chunk });
                if contract == ChainingContract::ZeroSuffix {
                    state[chunk.len()..].fill(0);
                }
                out.extend(produced);
            }
            SymMode::Ofb => {
                key_spec.encrypt_block(key, &mut state);
                out.extend(chunk.iter().zip(&state).map(|(a, b)| a ^ b));
            }
            SymMode::Ctr => {
                let mut keystream = state.clone();
                key_spec.encrypt_block(key, &mut keystream);
                increment(&mut state);
                out.extend(chunk.iter().zip(&keystream).map(|(a, b)| a ^ b));
            }
        }
    }
    (out, state)
}

fn dbl(block: &[u8], rb: u8) -> Vec<u8> {
    let mut out = vec![0u8; block.len()];
    let mut carry = 0u8;
    for i in (0..block.len()).rev() {
        out[i] = (block[i] << 1) | carry;
        carry = block[i] >> 7;
    }
    if carry == 1 {
        *out.last_mut().unwrap() ^= rb;
    }
    out
}

pub fn cmac(key_spec: SymKey, key: &[u8], data: &[u8]) -> Vec<u8> {
    let rb = if key_spec.block() == 16 { 0x87 } else { 0x1b };
    cmac_with_rb(key_spec, key, data, rb)
}

pub const TPM_CMAC_RB: u8 = 0x87;

pub fn tpm_cmac(key_spec: SymKey, key: &[u8], data: &[u8]) -> Vec<u8> {
    cmac_with_rb(key_spec, key, data, TPM_CMAC_RB)
}

pub fn cmac_with_rb(key_spec: SymKey, key: &[u8], data: &[u8], rb: u8) -> Vec<u8> {
    let n = key_spec.block();
    let mut l = vec![0u8; n];
    key_spec.encrypt_block(key, &mut l);
    let k1 = dbl(&l, rb);
    let k2 = dbl(&k1, rb);
    let blocks = data.len().div_ceil(n).max(1);
    let complete = !data.is_empty() && data.len().is_multiple_of(n);
    let mut state = vec![0u8; n];
    for i in 0..blocks {
        let mut block = data[i * n..data.len().min((i + 1) * n)].to_vec();
        if i == blocks - 1 {
            if complete {
                block.iter_mut().zip(&k1).for_each(|(a, b)| *a ^= b);
            } else {
                block.push(0x80);
                block.resize(n, 0);
                block.iter_mut().zip(&k2).for_each(|(a, b)| *a ^= b);
            }
        }
        state.iter_mut().zip(&block).for_each(|(a, b)| *a ^= b);
        key_spec.encrypt_block(key, &mut state);
    }
    state
}

const DES_WEAK_KEYS: [u64; 64] = [
    0x0101010101010101,
    0xFEFEFEFEFEFEFEFE,
    0xE0E0E0E0F1F1F1F1,
    0x1F1F1F1F0E0E0E0E,
    0x011F011F010E010E,
    0x1F011F010E010E01,
    0x01E001E001F101F1,
    0xE001E001F101F101,
    0x01FE01FE01FE01FE,
    0xFE01FE01FE01FE01,
    0x1FE01FE00EF10EF1,
    0xE01FE01FF10EF10E,
    0x1FFE1FFE0EFE0EFE,
    0xFE1FFE1FFE0EFE0E,
    0xE0FEE0FEF1FEF1FE,
    0xFEE0FEE0FEF1FEF1,
    0x01011F1F01010E0E,
    0x1F1F01010E0E0101,
    0xE0E01F1FF1F10E0E,
    0x0101E0E00101F1F1,
    0x1F1FE0E00E0EF1F1,
    0xE0E0FEFEF1F1FEFE,
    0x0101FEFE0101FEFE,
    0x1F1FFEFE0E0EFEFE,
    0xE0FE011FF1FE010E,
    0x011F1F01010E0E01,
    0x1FE001FE0EF101FE,
    0xE0FE1F01F1FE0E01,
    0x011FE0FE010EF1FE,
    0x1FE0E01F0EF1F10E,
    0xE0FEFEE0F1FEFEF1,
    0x011FFEE0010EFEF1,
    0x1FE0FE010EF1FE01,
    0xFE0101FEFE0101FE,
    0x01E01FFE01F10EFE,
    0x1FFE01E00EFE01F1,
    0xFE011FE0FE010EF1,
    0xFE01E01FFE01F10E,
    0x1FFEE0010EFEF101,
    0xFE1F01E0FE0E01F1,
    0x01E0E00101F1F101,
    0x1FFEFE1F0EFEFE0E,
    0xFE1FE001FE0EF101,
    0x01E0FE1F01F1FE0E,
    0xE00101E0F10101F1,
    0xFE1F1FFEFE0E0EFE,
    0x01FE1FE001FE0EF1,
    0xE0011FFEF1010EFE,
    0xFEE0011FFEF1010E,
    0x01FEE01F01FEF10E,
    0xE001FE1FF101FE0E,
    0xFEE01F01FEF10E01,
    0x01FEFE0101FEFE01,
    0xE01F01FEF10E01FE,
    0xFEE0E0FEFEF1F1FE,
    0x1F01011F0E01010E,
    0xE01F1FE0F10E0EF1,
    0xFEFE0101FEFE0101,
    0x1F01E0FE0E01F1FE,
    0xE01FFE01F10EFE01,
    0xFEFE1F1FFEFE0E0E,
    0x1F01FEE00E01FEF1,
    0xE0E00101F1F10101,
    0xFEFEE0E0FEFEF1F1,
];

fn odd_parity(k: u64) -> u64 {
    const PMASK: u64 = 0x0101_0101_0101_0101;
    let mut k = k | PMASK;
    let mut out = k;
    k ^= k >> 4;
    k ^= k >> 2;
    k ^= k >> 1;
    k &= PMASK;
    out ^= k;
    out ^ PMASK
}

pub fn tdes_key_valid(key: &[u8]) -> bool {
    if key.len() != 16 && key.len() != 24 {
        return false;
    }
    let parts: Vec<u64> = key
        .chunks(8)
        .map(|c| odd_parity(u64::from_be_bytes(c.try_into().unwrap())))
        .collect();
    if parts.iter().any(|k| DES_WEAK_KEYS.contains(k)) || parts[0] == parts[1] {
        return false;
    }
    parts.len() == 2 || parts[1] != parts[2]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_known_answer_and_mode_round_trips() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let mut block = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        SymKey::Aes128.encrypt_block(&key, &mut block);
        assert_eq!(hex::encode(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
        for spec in SymKey::ALL {
            let key: Vec<u8> = (0..spec.key_bytes() as u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            assert!(spec.valid_key(&key), "{spec:?} test key");
            let iv = vec![0x5au8; spec.block()];
            let data: Vec<u8> = (0..4 * spec.block() as u8).collect();
            for mode in SymMode::ALL {
                let iv_in = if mode.uses_iv() {
                    iv.clone()
                } else {
                    Vec::new()
                };
                let (ct, iv_e) = crypt(spec, mode, &key, &iv_in, &data, true);
                let (pt, iv_d) = crypt(spec, mode, &key, &iv_in, &ct, false);
                assert_eq!(pt, data, "{spec:?} {mode:?}");
                assert_eq!(iv_e, iv_d, "{spec:?} {mode:?} chaining value");
                assert_ne!(ct, data);
            }
        }
    }

    #[test]
    fn cfb_partial_final_block_matches_nist_sp800_38a() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
            .unwrap();
        let cipher =
            hex::decode("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b")
                .unwrap();
        for len in [0, 1, 15, 16, 17, 31, 32] {
            let (actual, _) = crypt(SymKey::Aes128, SymMode::Cfb, &key, &iv, &plain[..len], true);
            assert_eq!(actual, cipher[..len], "NIST CFB128 prefix length {len}");
            assert_eq!(
                crypt(SymKey::Aes128, SymMode::Cfb, &key, &iv, &actual, false).0,
                plain[..len]
            );
        }
    }

    #[test]
    fn cfb_partial_chaining_contracts_share_the_data_output_and_split_only_the_suffix() {
        let data: Vec<u8> = (0..21u8).collect();
        for (spec, mode) in [
            (SymKey::Aes128, SymMode::Cfb),
            (SymKey::Camellia256, SymMode::Cfb),
            (SymKey::Tdes128, SymMode::Cfb),
        ] {
            let key: Vec<u8> = (0..spec.key_bytes() as u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            assert!(spec.valid_key(&key), "{spec:?} test key");
            let iv_in = vec![0x5a; spec.block()];
            for encrypt in [true, false] {
                let (retained_out, retained_chain) = crypt_contract(
                    spec,
                    mode,
                    &key[..spec.key_bytes()],
                    &iv_in,
                    &data,
                    encrypt,
                    ChainingContract::RetainedSuffix,
                );
                let (zero_out, zero_chain) = crypt_contract(
                    spec,
                    mode,
                    &key[..spec.key_bytes()],
                    &iv_in,
                    &data,
                    encrypt,
                    ChainingContract::ZeroSuffix,
                );
                assert_eq!(
                    retained_out, zero_out,
                    "{spec:?} encrypt {encrypt}: the data output is contract-independent"
                );
                let used = data.len() % spec.block();
                assert_eq!(retained_chain[..used], zero_chain[..used]);
                // The retained suffix is the unused part of the keystream block
                // that produced the final partial block, i.e. E(previous
                // ciphertext block) — never zeroed. On decrypt the ciphertext
                // block is the input block; on encrypt it is the output block.
                let start = data.len() - used - spec.block();
                let previous_ct = if encrypt {
                    &retained_out[start..data.len() - used]
                } else {
                    &data[start..data.len() - used]
                };
                let keystream_tail = spec.encrypt_block_copy(&key[..spec.key_bytes()], previous_ct);
                let expected_retained: Vec<u8> = retained_chain[..used]
                    .iter()
                    .chain(keystream_tail[used..].iter())
                    .copied()
                    .collect();
                assert_eq!(retained_chain, expected_retained, "retained suffix");
                assert!(
                    zero_chain[used..].iter().all(|b| *b == 0),
                    "{spec:?} encrypt {encrypt}: zeroed suffix"
                );
                // Whole blocks leave no suffix to differ on.
                let full: Vec<u8> = (0..spec.block() as u16 * 2)
                    .map(|i| (i as u8).wrapping_mul(13).wrapping_add(5))
                    .collect();
                let whole = crypt_contract(
                    spec,
                    mode,
                    &key[..spec.key_bytes()],
                    &iv_in,
                    &full,
                    encrypt,
                    ChainingContract::ZeroSuffix,
                );
                let whole_retained = crypt_contract(
                    spec,
                    mode,
                    &key[..spec.key_bytes()],
                    &iv_in,
                    &full,
                    encrypt,
                    ChainingContract::RetainedSuffix,
                );
                assert_eq!(whole, whole_retained, "{spec:?} whole blocks contract-free");
            }
        }
    }

    #[test]
    fn cmac_matches_sp800_38b_examples() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        assert_eq!(
            hex::encode(cmac(SymKey::Aes128, &key, b"")),
            "bb1d6929e95937287fa37d129b756746"
        );
        let m = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        assert_eq!(
            hex::encode(cmac(SymKey::Aes128, &key, &m)),
            "070a16b46b4d4144f79bdd9dd04a287c"
        );
        let m40 = hex::decode(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        )
        .unwrap();
        assert_eq!(
            hex::encode(cmac(SymKey::Aes128, &key, &m40)),
            "dfa66747de9ae63030ca32611497c827"
        );
        assert_eq!(
            tpm_cmac(SymKey::Aes128, &key, &m40),
            cmac(SymKey::Aes128, &key, &m40)
        );
        let tdes = hex::decode("8aa83bf8cbda10620bc1bf19fbb6cd58bc313d4a371ca8b5").unwrap();
        let m = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        assert_eq!(
            hex::encode(cmac(SymKey::Tdes192, &tdes, &m)),
            "286d394673448197"
        );
        assert_ne!(
            tpm_cmac(SymKey::Tdes192, &tdes, &m),
            cmac(SymKey::Tdes192, &tdes, &m)
        );
    }

    #[test]
    fn weak_tdes_keys_are_rejected() {
        let mut key = [0x01u8; 16];
        assert!(!tdes_key_valid(&key));
        key[8..].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
        assert!(!tdes_key_valid(&key));
        key[..8].copy_from_slice(&0x1334_5779_9bbc_dff1u64.to_be_bytes());
        assert!(tdes_key_valid(&key));
        let same = [0x13u8, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1].repeat(2);
        assert!(!tdes_key_valid(&same));
    }
}
