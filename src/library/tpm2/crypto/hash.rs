use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384, Sha512};

use super::super::algorithm::{TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512};

pub(in crate::library::tpm2) const COMPILED_HASHES: [(u16, usize); 4] = [
    (TPM_ALG_SHA1, 20),
    (TPM_ALG_SHA256, 32),
    (TPM_ALG_SHA384, 48),
    (TPM_ALG_SHA512, 64),
];

pub(in crate::library::tpm2) enum Hasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub(in crate::library::tpm2) fn new(hash_alg: u16) -> Option<Self> {
        Some(match hash_alg {
            TPM_ALG_SHA1 => Self::Sha1(Sha1::new()),
            TPM_ALG_SHA256 => Self::Sha256(Sha256::new()),
            TPM_ALG_SHA384 => Self::Sha384(Sha384::new()),
            TPM_ALG_SHA512 => Self::Sha512(Sha512::new()),
            _ => return None,
        })
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn hash_alg(&self) -> u16 {
        match self {
            Self::Sha1(_) => TPM_ALG_SHA1,
            Self::Sha256(_) => TPM_ALG_SHA256,
            Self::Sha384(_) => TPM_ALG_SHA384,
            Self::Sha512(_) => TPM_ALG_SHA512,
        }
    }

    pub(in crate::library::tpm2) fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(context) => context.update(data),
            Self::Sha256(context) => context.update(data),
            Self::Sha384(context) => context.update(data),
            Self::Sha512(context) => context.update(data),
        }
    }

    pub(in crate::library::tpm2) fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha1(context) => context.finalize().to_vec(),
            Self::Sha256(context) => context.finalize().to_vec(),
            Self::Sha384(context) => context.finalize().to_vec(),
            Self::Sha512(context) => context.finalize().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::algorithm::{TPM_ALG_AES, TPM_ALG_HMAC, TPM_ALG_NULL};

    fn hex(digest: &[u8]) -> String {
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn compiled_algorithm_hasher_selection() {
        for (hash_alg, _) in COMPILED_HASHES {
            assert!(Hasher::new(hash_alg).is_some(), "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn hasher_algorithm_report() {
        for (hash_alg, _) in COMPILED_HASHES {
            let hasher = Hasher::new(hash_alg).expect("a compiled algorithm");
            assert_eq!(hasher.hash_alg(), hash_alg);
        }
    }

    #[test]
    fn uncompiled_algorithm_no_hasher_selection() {
        for hash_alg in [
            TPM_ALG_NULL,
            TPM_ALG_AES,
            TPM_ALG_HMAC,
            0x0000,
            0x0005,
            0x0012,
            0x0027,
            0xffff,
        ] {
            assert!(Hasher::new(hash_alg).is_none(), "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn digest_size_algorithm_match() {
        for (hash_alg, size) in COMPILED_HASHES {
            let hasher = Hasher::new(hash_alg).expect("a compiled algorithm");
            assert_eq!(hasher.finalize().len(), size, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn empty_message_digest_published_vector_match() {
        const EMPTY: [(u16, &str); 4] = [
            (TPM_ALG_SHA1, "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            (
                TPM_ALG_SHA256,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                TPM_ALG_SHA384,
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                 274edebfe76f65fbd51ad2f14898b95b",
            ),
            (
                TPM_ALG_SHA512,
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
        ];

        for (hash_alg, expected) in EMPTY {
            let hasher = Hasher::new(hash_alg).expect("a compiled algorithm");
            let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            assert_eq!(hex(&hasher.finalize()), expected, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn abc_digest_published_vector_match() {
        const ABC: [(u16, &str); 4] = [
            (TPM_ALG_SHA1, "a9993e364706816aba3e25717850c26c9cd0d89d"),
            (
                TPM_ALG_SHA256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                TPM_ALG_SHA384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                TPM_ALG_SHA512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ];

        for (hash_alg, expected) in ABC {
            let mut hasher = Hasher::new(hash_alg).expect("a compiled algorithm");
            hasher.update(b"abc");
            let expected: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
            assert_eq!(hex(&hasher.finalize()), expected, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn incremental_update_concatenation_equivalence() {
        let message: Vec<u8> = (0..300u32).map(|index| index as u8).collect();
        for (hash_alg, _) in COMPILED_HASHES {
            let mut whole = Hasher::new(hash_alg).expect("a compiled algorithm");
            whole.update(&message);

            let mut split = Hasher::new(hash_alg).expect("a compiled algorithm");
            for chunk in message.chunks(7) {
                split.update(chunk);
            }

            assert_eq!(split.finalize(), whole.finalize(), "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn empty_update_digest_preservation() {
        for (hash_alg, _) in COMPILED_HASHES {
            let mut padded = Hasher::new(hash_alg).expect("a compiled algorithm");
            padded.update(&[]);
            padded.update(b"abc");
            padded.update(&[]);

            let mut plain = Hasher::new(hash_alg).expect("a compiled algorithm");
            plain.update(b"abc");

            assert_eq!(padded.finalize(), plain.finalize(), "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn compiled_table_no_duplicates() {
        for (index, &(hash_alg, _)) in COMPILED_HASHES.iter().enumerate() {
            assert!(
                !COMPILED_HASHES[index + 1..]
                    .iter()
                    .any(|&(other, _)| other == hash_alg),
                "duplicate alg {hash_alg:#06x}"
            );
        }
    }
}
