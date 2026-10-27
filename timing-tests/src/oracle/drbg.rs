//! Independent AES-256 CTR_DRBG model for the isolated timing adapter.
//! Uses a big-endian u128 counter and complete AES blocks; no production DRBG
//! code is linked. C-generated fixtures anchor output, state and entropy counts.
use aes::cipher::{BlockEncrypt, KeyInit};

pub const MAGIC: &[u8; 4] = b"\xffDR1";
pub const INPUT_BYTES: usize = 123;
pub const RESEED_INTERVAL: u64 = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Input {
    pub seed: [u8; 48],
    pub counter: u64,
    /// Raw little-endian words, matching the hook wire representation.
    pub last_value: [u8; 16],
    pub entropy: [u8; 48],
    pub continuous: bool,
    pub requested: u16,
}

impl Input {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != INPUT_BYTES {
            return Err(format!("DRBG payload must be {INPUT_BYTES} bytes"));
        }
        let counter = u64::from_be_bytes(bytes[48..56].try_into().unwrap());
        let requested = u16::from_be_bytes(bytes[121..123].try_into().unwrap());
        if !(1..=RESEED_INTERVAL + 7).contains(&counter) || bytes[120] > 1 || requested > 64 {
            return Err("invalid DRBG counter, continuous flag or requested length".into());
        }
        Ok(Self {
            seed: bytes[..48].try_into().unwrap(),
            counter,
            last_value: bytes[56..72].try_into().unwrap(),
            entropy: bytes[72..120].try_into().unwrap(),
            continuous: bytes[120] == 1,
            requested,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(INPUT_BYTES);
        out.extend(self.seed);
        out.extend(self.counter.to_be_bytes());
        out.extend(self.last_value);
        out.extend(self.entropy);
        out.push(u8::from(self.continuous));
        out.extend(self.requested.to_be_bytes());
        out
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    pub bytes: Vec<u8>,
    pub seed: [u8; 48],
    pub counter: u64,
    pub last_value: [u8; 16],
    pub entropy_draws: u32,
}

impl Output {
    pub fn response(&self) -> Vec<u8> {
        let mut parameters = (self.bytes.len() as u16).to_be_bytes().to_vec();
        parameters.extend(&self.bytes);
        parameters.extend(self.seed);
        parameters.extend(self.counter.to_be_bytes());
        parameters.extend(self.last_value);
        parameters.extend(self.entropy_draws.to_be_bytes());
        crate::tpm::success_response(&[], &parameters, 0)
    }
}

/// Full first AES block, useful for continuous-test prefix boundary fixtures.
pub fn first_block(seed: &[u8; 48]) -> [u8; 16] {
    let cipher = aes::Aes256::new_from_slice(&seed[..32]).unwrap();
    let v = u128::from_be_bytes(seed[32..].try_into().unwrap()).wrapping_add(1);
    let mut block = aes::Block::from(v.to_be_bytes());
    cipher.encrypt_block(&mut block);
    block.into()
}

fn stream(seed: &[u8; 48], blocks: usize) -> Vec<[u8; 16]> {
    let cipher = aes::Aes256::new_from_slice(&seed[..32]).unwrap();
    let v = u128::from_be_bytes(seed[32..].try_into().unwrap());
    let mut blocks: Vec<aes::Block> = (1..=blocks)
        .map(|i| aes::Block::from(v.wrapping_add(i as u128).to_be_bytes()))
        .collect();
    cipher.encrypt_blocks(&mut blocks);
    blocks.into_iter().map(Into::into).collect()
}

fn accept(last: &mut [u8; 16], blocks: &[[u8; 16]], continuous: bool) -> Result<(), String> {
    if continuous {
        for block in blocks {
            if block == last {
                return Err("continuous DRBG test would reject a repeated block".into());
            }
            *last = *block;
        }
    }
    Ok(())
}

pub fn generate(input: &Input) -> Result<Output, String> {
    Input::decode(&input.encode())?;
    let mut seed = input.seed;
    let mut last = input.last_value;
    let reseed = input.counter >= RESEED_INTERVAL;
    if reseed {
        let blocks = stream(&seed, 3);
        accept(&mut last, &blocks, input.continuous)?;
        for (index, byte) in blocks.iter().flatten().enumerate() {
            seed[index] = byte ^ input.entropy[index];
        }
    }
    let count = usize::from(input.requested).div_ceil(16);
    // Generate and post-generation update use the same expanded key and
    // consecutive V values; the three update blocks replace key and V.
    let blocks = stream(&seed, count + 3);
    accept(&mut last, &blocks, input.continuous)?;
    let bytes = blocks[..count]
        .iter()
        .flatten()
        .copied()
        .take(usize::from(input.requested))
        .collect();
    for (target, byte) in seed.iter_mut().zip(blocks[count..].iter().flatten()) {
        *target = *byte;
    }
    Ok(Output {
        bytes,
        seed,
        counter: if reseed { 2 } else { input.counter + 1 },
        last_value: last,
        entropy_draws: u32::from(reseed),
    })
}
