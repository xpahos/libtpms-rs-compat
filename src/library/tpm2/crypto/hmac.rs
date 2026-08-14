use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use super::super::algorithm::{TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512};

pub(in crate::library::tpm2) enum HmacState {
    Sha1(Box<Hmac<Sha1>>),
    Sha256(Box<Hmac<Sha256>>),
    Sha384(Box<Hmac<Sha384>>),
    Sha512(Box<Hmac<Sha512>>),
}

impl HmacState {
    pub(in crate::library::tpm2) fn new(hash_alg: u16, key: &[u8]) -> Option<Self> {
        Some(match hash_alg {
            TPM_ALG_SHA1 => Self::Sha1(Box::new(Hmac::new_from_slice(key).ok()?)),
            TPM_ALG_SHA256 => Self::Sha256(Box::new(Hmac::new_from_slice(key).ok()?)),
            TPM_ALG_SHA384 => Self::Sha384(Box::new(Hmac::new_from_slice(key).ok()?)),
            TPM_ALG_SHA512 => Self::Sha512(Box::new(Hmac::new_from_slice(key).ok()?)),
            _ => return None,
        })
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
            Self::Sha1(context) => context.finalize().into_bytes().to_vec(),
            Self::Sha256(context) => context.finalize().into_bytes().to_vec(),
            Self::Sha384(context) => context.finalize().into_bytes().to_vec(),
            Self::Sha512(context) => context.finalize().into_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::hash::COMPILED_HASHES;
    use super::*;
    use crate::library::tpm2::algorithm::{TPM_ALG_AES, TPM_ALG_NULL};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&cleaned[index..index + 2], 16).unwrap())
            .collect()
    }

    fn mac_of(hash_alg: u16, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut state = HmacState::new(hash_alg, key).expect("a compiled algorithm");
        state.update(data);
        state.finalize()
    }

    #[test]
    fn every_compiled_algorithm_selects_a_state() {
        for (hash_alg, size) in COMPILED_HASHES {
            let state = HmacState::new(hash_alg, b"key").expect("a compiled algorithm");
            assert_eq!(state.finalize().len(), size, "alg {hash_alg:#06x}");
        }
    }

    #[test]
    fn uncompiled_algorithms_select_no_state() {
        for hash_alg in [TPM_ALG_NULL, TPM_ALG_AES, 0x0000, 0x0012, 0xffff] {
            assert!(
                HmacState::new(hash_alg, b"key").is_none(),
                "alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn the_rfc_4231_test_case_2_vectors_are_reproduced() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(
            hex(&mac_of(TPM_ALG_SHA256, key, data)),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&mac_of(TPM_ALG_SHA384, key, data)),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        );
        assert_eq!(
            hex(&mac_of(TPM_ALG_SHA512, key, data)),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        );
    }

    #[test]
    fn the_rfc_2202_sha1_test_case_2_vector_is_reproduced() {
        assert_eq!(
            hex(&mac_of(
                TPM_ALG_SHA1,
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn a_key_longer_than_the_block_size_is_reduced_like_rfc_4231_test_case_6() {
        assert_eq!(
            hex(&mac_of(
                TPM_ALG_SHA256,
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn an_empty_key_is_accepted() {
        for (hash_alg, size) in COMPILED_HASHES {
            assert_eq!(
                mac_of(hash_alg, &[], b"message").len(),
                size,
                "alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn incremental_updates_authenticate_the_concatenation() {
        let message: Vec<u8> = (0..300u32).map(|index| index as u8).collect();
        for (hash_alg, _) in COMPILED_HASHES {
            let mut split = HmacState::new(hash_alg, b"secret").expect("a compiled algorithm");
            for chunk in message.chunks(11) {
                split.update(chunk);
            }
            assert_eq!(
                split.finalize(),
                mac_of(hash_alg, b"secret", &message),
                "alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn a_different_key_changes_the_mac() {
        for (hash_alg, _) in COMPILED_HASHES {
            assert_ne!(
                mac_of(hash_alg, &[0x11; 64], b"message"),
                mac_of(hash_alg, &[0x12; 64], b"message"),
                "alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn the_sha512_vector_matches_an_independently_fixed_value() {
        assert_eq!(
            mac_of(TPM_ALG_SHA512, &[0x0b; 20], b"Hi There"),
            unhex(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                 daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            )
        );
    }
}
