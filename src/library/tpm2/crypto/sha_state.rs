// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/NVMarshal.c
// - libtpms/src/tpm2/crypto/openssl/CryptHash.c
//
// Original upstream authors and copyright notices:
// Written by Stefan Berger
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corporation 2017,2018.
// Written by Ken Goldman
// (c) Copyright IBM Corp. and others, 2016 - 2024
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use sha1::compress as compress_sha1;
use sha2::{compress256, compress512};

use super::super::algorithm::{TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512};

pub(in crate::library::tpm2) const SHA1_BLOCK: usize = 64;
pub(in crate::library::tpm2) const SHA256_BLOCK: usize = 64;
pub(in crate::library::tpm2) const SHA512_BLOCK: usize = 128;

const SHA1_INIT: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

const SHA256_INIT: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA384_INIT: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

const SHA512_INIT: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

#[derive(Clone)]
enum Words {
    W32 { h: Vec<u32>, nl: u32, nh: u32 },
    W64 { h: [u64; 8], nl: u64, nh: u64 },
}

#[derive(Clone)]
pub(in crate::library::tpm2) struct ShaState {
    hash_alg: u16,
    words: Words,
    data: Vec<u8>,
    num: u32,
    md_len: u32,
}

fn hash_block_size(hash_alg: u16) -> Option<usize> {
    Some(match hash_alg {
        TPM_ALG_SHA1 => SHA1_BLOCK,
        TPM_ALG_SHA256 => SHA256_BLOCK,
        TPM_ALG_SHA384 | TPM_ALG_SHA512 => SHA512_BLOCK,
        _ => return None,
    })
}

fn hash_digest_size(hash_alg: u16) -> Option<usize> {
    Some(match hash_alg {
        TPM_ALG_SHA1 => 20,
        TPM_ALG_SHA256 => 32,
        TPM_ALG_SHA384 => 48,
        TPM_ALG_SHA512 => 64,
        _ => return None,
    })
}

impl ShaState {
    pub(in crate::library::tpm2) fn new(hash_alg: u16) -> Option<Self> {
        let (words, block, md_len) = match hash_alg {
            TPM_ALG_SHA1 => (
                Words::W32 {
                    h: SHA1_INIT.to_vec(),
                    nl: 0,
                    nh: 0,
                },
                SHA1_BLOCK,
                0,
            ),
            TPM_ALG_SHA256 => (
                Words::W32 {
                    h: SHA256_INIT.to_vec(),
                    nl: 0,
                    nh: 0,
                },
                SHA256_BLOCK,
                32,
            ),
            TPM_ALG_SHA384 => (
                Words::W64 {
                    h: SHA384_INIT,
                    nl: 0,
                    nh: 0,
                },
                SHA512_BLOCK,
                48,
            ),
            TPM_ALG_SHA512 => (
                Words::W64 {
                    h: SHA512_INIT,
                    nl: 0,
                    nh: 0,
                },
                SHA512_BLOCK,
                64,
            ),
            _ => return None,
        };
        Some(Self {
            hash_alg,
            words,
            data: vec![0u8; block],
            num: 0,
            md_len,
        })
    }

    pub(in crate::library::tpm2) fn hash_alg(&self) -> u16 {
        self.hash_alg
    }

    fn block_size(&self) -> usize {
        self.data.len()
    }

    fn compress(&mut self, blocks: &[u8]) {
        match &mut self.words {
            Words::W32 { h, .. } if self.hash_alg == TPM_ALG_SHA1 => {
                let mut state = [h[0], h[1], h[2], h[3], h[4]];
                for chunk in blocks.chunks_exact(SHA1_BLOCK) {
                    let block: [u8; SHA1_BLOCK] = chunk.try_into().expect("a full block");
                    compress_sha1(&mut state, &[block.into()]);
                }
                h.copy_from_slice(&state);
            }
            Words::W32 { h, .. } => {
                let mut state: [u32; 8] = h[..].try_into().expect("eight words");
                for chunk in blocks.chunks_exact(SHA256_BLOCK) {
                    let block: [u8; SHA256_BLOCK] = chunk.try_into().expect("a full block");
                    compress256(&mut state, &[block.into()]);
                }
                h.copy_from_slice(&state);
            }
            Words::W64 { h, .. } => {
                for chunk in blocks.chunks_exact(SHA512_BLOCK) {
                    let block: [u8; SHA512_BLOCK] = chunk.try_into().expect("a full block");
                    compress512(h, &[block.into()]);
                }
            }
        }
    }

    fn add_bits(&mut self, len: usize) {
        let bits = (len as u128) << 3;
        match &mut self.words {
            Words::W32 { nl, nh, .. } => {
                let low = (bits & 0xffff_ffff) as u32;
                let updated = nl.wrapping_add(low);
                if updated < *nl {
                    *nh = nh.wrapping_add(1);
                }
                *nh = nh.wrapping_add((bits >> 32) as u32);
                *nl = updated;
            }
            Words::W64 { nl, nh, .. } => {
                let low = (bits & 0xffff_ffff_ffff_ffff) as u64;
                let updated = nl.wrapping_add(low);
                if updated < *nl {
                    *nh = nh.wrapping_add(1);
                }
                *nh = nh.wrapping_add((bits >> 64) as u64);
                *nl = updated;
            }
        }
    }

    pub(in crate::library::tpm2) fn update(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }
        self.add_bits(input.len());

        let block = self.block_size();
        let mut data = input;
        let buffered = self.num as usize;
        if buffered != 0 {
            let free = block - buffered;
            if data.len() < free {
                self.data[buffered..buffered + data.len()].copy_from_slice(data);
                self.num += data.len() as u32;
                return;
            }
            self.data[buffered..block].copy_from_slice(&data[..free]);
            data = &data[free..];
            let pending = core::mem::take(&mut self.data);
            self.compress(&pending);
            self.data = pending;
            self.data.fill(0);
            self.num = 0;
        }

        let whole = (data.len() / block) * block;
        if whole != 0 {
            self.compress(&data[..whole]);
            data = &data[whole..];
        }

        if !data.is_empty() {
            self.data[..data.len()].copy_from_slice(data);
            self.num = data.len() as u32;
        }
    }

    pub(in crate::library::tpm2) fn finalize(mut self) -> Vec<u8> {
        let block = self.block_size();
        let length_bytes = if block == SHA512_BLOCK { 16 } else { 8 };
        let bit_count = match &self.words {
            Words::W32 { nl, nh, .. } => {
                let mut out = vec![0u8; length_bytes];
                out[..4].copy_from_slice(&nh.to_be_bytes());
                out[4..].copy_from_slice(&nl.to_be_bytes());
                out
            }
            Words::W64 { nl, nh, .. } => {
                let mut out = vec![0u8; length_bytes];
                out[..8].copy_from_slice(&nh.to_be_bytes());
                out[8..].copy_from_slice(&nl.to_be_bytes());
                out
            }
        };

        let mut tail = Vec::with_capacity(2 * block);
        tail.push(0x80u8);
        let filled = self.num as usize + 1;
        let remainder = filled % block;
        let padding = if remainder > block - length_bytes {
            block - remainder + block - length_bytes
        } else {
            block - length_bytes - remainder
        };
        tail.extend(core::iter::repeat_n(0u8, padding));
        tail.extend_from_slice(&bit_count);

        let buffered = self.num as usize;
        let mut blocks = Vec::with_capacity(buffered + tail.len());
        blocks.extend_from_slice(&self.data[..buffered]);
        blocks.extend_from_slice(&tail);
        self.compress(&blocks);

        let digest_size = hash_digest_size(self.hash_alg).expect("a compiled algorithm");
        let mut out = Vec::with_capacity(digest_size);
        match &self.words {
            Words::W32 { h, .. } => {
                for word in h {
                    out.extend_from_slice(&word.to_be_bytes());
                }
            }
            Words::W64 { h, .. } => {
                for word in h {
                    out.extend_from_slice(&word.to_be_bytes());
                }
            }
        }
        out.truncate(digest_size);
        out
    }

    pub(in crate::library::tpm2) fn export(&self) -> ShaStatePayload {
        match &self.words {
            Words::W32 { h, nl, nh } if self.hash_alg == TPM_ALG_SHA1 => ShaStatePayload::Sha1 {
                h: h[..].try_into().expect("five words"),
                nl: *nl,
                nh: *nh,
                data: self.data.clone(),
                num: self.num,
            },
            Words::W32 { h, nl, nh } => ShaStatePayload::Sha256 {
                h: h[..].try_into().expect("eight words"),
                nl: *nl,
                nh: *nh,
                data: self.data.clone(),
                num: self.num,
                md_len: self.md_len,
            },
            Words::W64 { h, nl, nh } => ShaStatePayload::Sha512 {
                h: *h,
                nl: *nl,
                nh: *nh,
                data: self.data.clone(),
                num: self.num,
                md_len: self.md_len,
            },
        }
    }

    pub(in crate::library::tpm2) fn import(
        hash_alg: u16,
        payload: ShaStatePayload,
    ) -> Option<Self> {
        let block = hash_block_size(hash_alg)?;
        let (words, data, num, md_len) = match (hash_alg, payload) {
            (
                TPM_ALG_SHA1,
                ShaStatePayload::Sha1 {
                    h,
                    nl,
                    nh,
                    data,
                    num,
                },
            ) => (
                Words::W32 {
                    h: h.to_vec(),
                    nl,
                    nh,
                },
                data,
                num,
                0,
            ),
            (
                TPM_ALG_SHA256,
                ShaStatePayload::Sha256 {
                    h,
                    nl,
                    nh,
                    data,
                    num,
                    md_len,
                },
            ) => (
                Words::W32 {
                    h: h.to_vec(),
                    nl,
                    nh,
                },
                data,
                num,
                md_len,
            ),
            (
                TPM_ALG_SHA384 | TPM_ALG_SHA512,
                ShaStatePayload::Sha512 {
                    h,
                    nl,
                    nh,
                    data,
                    num,
                    md_len,
                },
            ) => (Words::W64 { h, nl, nh }, data, num, md_len),
            _ => return None,
        };
        if data.len() != block || num as usize > block {
            return None;
        }
        Some(Self {
            hash_alg,
            words,
            data,
            num,
            md_len,
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(in crate::library::tpm2) enum ShaStatePayload {
    Sha1 {
        h: [u32; 5],
        nl: u32,
        nh: u32,
        data: Vec<u8>,
        num: u32,
    },
    Sha256 {
        h: [u32; 8],
        nl: u32,
        nh: u32,
        data: Vec<u8>,
        num: u32,
        md_len: u32,
    },
    Sha512 {
        h: [u64; 8],
        nl: u64,
        nh: u64,
        data: Vec<u8>,
        num: u32,
        md_len: u32,
    },
}

pub(in crate::library::tpm2) struct SequenceHmac {
    pub(in crate::library::tpm2) state: ShaState,
    pub(in crate::library::tpm2) opad_key: Vec<u8>,
}

impl SequenceHmac {
    pub(in crate::library::tpm2) fn start(hash_alg: u16, key: &[u8]) -> Option<Self> {
        let block = hash_block_size(hash_alg)?;
        let mut pad = if key.len() > block {
            let mut digest = ShaState::new(hash_alg)?;
            digest.update(key);
            digest.finalize()
        } else {
            key.to_vec()
        };
        for byte in &mut pad {
            *byte ^= 0x36;
        }
        pad.resize(block, 0x36);

        let mut state = ShaState::new(hash_alg)?;
        state.update(&pad);
        for byte in &mut pad {
            *byte ^= 0x5c ^ 0x36;
        }
        Some(Self {
            state,
            opad_key: pad,
        })
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn update(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    pub(in crate::library::tpm2) fn finalize(self) -> Option<Vec<u8>> {
        let hash_alg = self.state.hash_alg();
        let inner = self.state.finalize();
        let mut outer = ShaState::new(hash_alg)?;
        outer.update(&self.opad_key);
        outer.update(&inner);
        Some(outer.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::super::hash::{COMPILED_HASHES, Hasher};
    use super::super::hmac::HmacState;
    use super::*;

    fn digest_of(hash_alg: u16, chunks: &[&[u8]]) -> Vec<u8> {
        let mut state = ShaState::new(hash_alg).expect("a compiled algorithm");
        for chunk in chunks {
            state.update(chunk);
        }
        state.finalize()
    }

    fn reference(hash_alg: u16, chunks: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Hasher::new(hash_alg).expect("a compiled algorithm");
        for chunk in chunks {
            hasher.update(chunk);
        }
        hasher.finalize()
    }

    #[test]
    fn compiled_algorithm_state_construction() {
        for (hash_alg, size) in COMPILED_HASHES {
            let state = ShaState::new(hash_alg).expect("a compiled algorithm");
            assert_eq!(state.hash_alg(), hash_alg);
            assert_eq!(state.finalize().len(), size, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn uncompiled_algorithm_no_state_construction() {
        for hash_alg in [0x0000u16, 0x0005, 0x0010, 0x0012, 0xffff] {
            assert!(ShaState::new(hash_alg).is_none(), "alg {hash_alg:#06x}");
            assert!(hash_block_size(hash_alg).is_none());
            assert!(hash_digest_size(hash_alg).is_none());
        }
    }

    #[test]
    fn split_pattern_shared_hasher_digest_match() {
        let message: Vec<u8> = (0..1000u32).map(|index| (index * 7) as u8).collect();
        for (hash_alg, _) in COMPILED_HASHES {
            for length in [0usize, 1, 3, 55, 56, 63, 64, 65, 111, 127, 128, 129, 1000] {
                let data = &message[..length];
                assert_eq!(
                    digest_of(hash_alg, &[data]),
                    reference(hash_alg, &[data]),
                    "alg {hash_alg:#06x} length {length}"
                );
                for chunk in [1usize, 5, 17, 64, 100] {
                    let pieces: Vec<&[u8]> = data.chunks(chunk).collect();
                    assert_eq!(
                        digest_of(hash_alg, &pieces),
                        reference(hash_alg, &pieces),
                        "alg {hash_alg:#06x} length {length} chunk {chunk}"
                    );
                }
            }
        }
    }

    #[test]
    fn empty_update_digest_preservation() {
        for (hash_alg, _) in COMPILED_HASHES {
            assert_eq!(
                digest_of(hash_alg, &[&[], b"abc", &[]]),
                digest_of(hash_alg, &[b"abc"]),
                "alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn buffer_beyond_pending_zero_preservation() {
        let message: Vec<u8> = (0..500u32).map(|index| index as u8).collect();
        for (hash_alg, _) in COMPILED_HASHES {
            let block = hash_block_size(hash_alg).expect("a compiled algorithm");
            for chunk in [1usize, 7, 63, 64, 65, 127, 128, 130] {
                let mut state = ShaState::new(hash_alg).expect("a compiled algorithm");
                for piece in message.chunks(chunk) {
                    state.update(piece);
                    let num = state.num as usize;
                    assert!(num < block);
                    assert!(
                        state.data[num..].iter().all(|&byte| byte == 0),
                        "alg {hash_alg:#06x} chunk {chunk}: stale bytes past num"
                    );
                }
            }
        }
    }

    #[test]
    fn export_import_round_trip() {
        let message: Vec<u8> = (0..300u32).map(|index| (index * 3) as u8).collect();
        for (hash_alg, _) in COMPILED_HASHES {
            for split in [0usize, 1, 63, 64, 100, 200, 300] {
                let mut state = ShaState::new(hash_alg).expect("a compiled algorithm");
                state.update(&message[..split]);
                let payload = state.export();
                let mut restored =
                    ShaState::import(hash_alg, payload).expect("the payload imports");
                restored.update(&message[split..]);
                state.update(&message[split..]);
                assert_eq!(
                    restored.finalize(),
                    state.finalize(),
                    "alg {hash_alg:#06x} split {split}"
                );
            }
        }
    }

    #[test]
    fn mismatched_payload_import_rejection() {
        let sha1 = ShaState::new(TPM_ALG_SHA1).expect("a compiled algorithm");
        assert!(ShaState::import(TPM_ALG_SHA256, sha1.export()).is_none());
        let sha512 = ShaState::new(TPM_ALG_SHA512).expect("a compiled algorithm");
        assert!(ShaState::import(TPM_ALG_SHA1, sha512.export()).is_none());
        assert!(ShaState::import(TPM_ALG_SHA384, sha512.export()).is_some());
    }

    #[test]
    fn out_of_range_buffer_import_rejection() {
        let state = ShaState::new(TPM_ALG_SHA256).expect("a compiled algorithm");
        let ShaStatePayload::Sha256 {
            h,
            nl,
            nh,
            data,
            md_len,
            ..
        } = state.export()
        else {
            panic!("a sha256 payload");
        };
        let oversized = ShaStatePayload::Sha256 {
            h,
            nl,
            nh,
            data: data.clone(),
            num: 64,
            md_len,
        };
        assert!(ShaState::import(TPM_ALG_SHA256, oversized).is_some());
        let beyond = ShaStatePayload::Sha256 {
            h,
            nl,
            nh,
            data: data.clone(),
            num: 65,
            md_len,
        };
        assert!(ShaState::import(TPM_ALG_SHA256, beyond).is_none());
        let short = ShaStatePayload::Sha256 {
            h,
            nl,
            nh,
            data: vec![0u8; 8],
            num: 0,
            md_len,
        };
        assert!(ShaState::import(TPM_ALG_SHA256, short).is_none());
    }

    #[test]
    fn md_len_algorithm_match() {
        for (hash_alg, size) in COMPILED_HASHES {
            let state = ShaState::new(hash_alg).expect("a compiled algorithm");
            let md_len = match state.export() {
                ShaStatePayload::Sha1 { .. } => 0,
                ShaStatePayload::Sha256 { md_len, .. } | ShaStatePayload::Sha512 { md_len, .. } => {
                    md_len
                }
            };
            let expected = if hash_alg == TPM_ALG_SHA1 {
                0
            } else {
                size as u32
            };
            assert_eq!(md_len, expected, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn hmac_shared_implementation_match() {
        let message: Vec<u8> = (0..400u32).map(|index| (index * 5) as u8).collect();
        for (hash_alg, _) in COMPILED_HASHES {
            for key_len in [0usize, 1, 20, 63, 64, 65, 127, 128, 129, 200] {
                let key: Vec<u8> = (0..key_len).map(|index| (index as u8) ^ 0x5a).collect();
                let mut ours = SequenceHmac::start(hash_alg, &key).expect("a compiled algorithm");
                for piece in message.chunks(37) {
                    ours.update(piece);
                }
                let mut theirs = HmacState::new(hash_alg, &key).expect("a compiled algorithm");
                theirs.update(&message);
                assert_eq!(
                    ours.finalize().expect("a compiled algorithm"),
                    theirs.finalize(),
                    "alg {hash_alg:#06x} key {key_len}"
                );
            }
        }
    }

    #[test]
    fn stored_hmac_key_opad_block() {
        for (hash_alg, _) in COMPILED_HASHES {
            let block = hash_block_size(hash_alg).expect("a compiled algorithm");
            let hmac = SequenceHmac::start(hash_alg, b"Jefe").expect("a compiled algorithm");
            assert_eq!(hmac.opad_key.len(), block);
            let mut expected = b"Jefe".to_vec();
            expected.resize(block, 0);
            for byte in &mut expected {
                *byte ^= 0x5c;
            }
            assert_eq!(hmac.opad_key, expected, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn long_hmac_key_digest_reduction() {
        for (hash_alg, digest_size) in COMPILED_HASHES {
            let block = hash_block_size(hash_alg).expect("a compiled algorithm");
            let key = vec![0xaa; block + 1];
            let hmac = SequenceHmac::start(hash_alg, &key).expect("a compiled algorithm");
            let mut reduced = ShaState::new(hash_alg).expect("a compiled algorithm");
            reduced.update(&key);
            let mut expected = reduced.finalize();
            assert_eq!(expected.len(), digest_size);
            expected.resize(block, 0);
            for byte in &mut expected {
                *byte ^= 0x5c;
            }
            assert_eq!(hmac.opad_key, expected, "alg {hash_alg:#06x}");
        }
    }
}
