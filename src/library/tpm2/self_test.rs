use aes::cipher::{BlockEncrypt, KeyInit};

use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_RC_FAILURE;

use super::algorithm::{
    TPM_ALG_AES, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, algorithm_enabled,
    hash_profile_name,
};
use super::capability::algorithms::enabled_algorithms;
use super::pcr::BankHasher;
use super::profile::ValidatedProfile;

const AES_BLOCK_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;
const AES_PROFILE_NAME: &[u8] = b"aes";

const fn hex_nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("known-answer vectors are written in lowercase hexadecimal"),
    }
}

const fn hex_bytes<const N: usize>(text: &[u8]) -> [u8; N] {
    assert!(text.len() == N * 2);
    let mut out = [0u8; N];
    let mut index = 0;
    while index < N {
        out[index] = (hex_nibble(text[index * 2]) << 4) | hex_nibble(text[index * 2 + 1]);
        index += 1;
    }
    out
}

struct HashVector<const N: usize> {
    message: &'static [u8],
    digest: [u8; N],
}

struct BlockCipherVector {
    key: [u8; AES256_KEY_SIZE],
    plaintext: [u8; AES_BLOCK_SIZE],
    ciphertext: [u8; AES_BLOCK_SIZE],
}

const SHA1_VECTORS: [HashVector<20>; 3] = [
    HashVector {
        message: b"",
        digest: hex_bytes(b"da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    },
    HashVector {
        message: b"abc",
        digest: hex_bytes(b"a9993e364706816aba3e25717850c26c9cd0d89d"),
    },
    HashVector {
        message: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        digest: hex_bytes(b"84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    },
];

const SHA256_VECTORS: [HashVector<32>; 3] = [
    HashVector {
        message: b"",
        digest: hex_bytes(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    },
    HashVector {
        message: b"abc",
        digest: hex_bytes(b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    },
    HashVector {
        message: b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        digest: hex_bytes(b"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    },
];

const SHA384_MULTI_BLOCK_MESSAGE: &[u8] =
    b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
      ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

const SHA384_VECTORS: [HashVector<48>; 3] = [
    HashVector {
        message: b"",
        digest: hex_bytes(
            b"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
              274edebfe76f65fbd51ad2f14898b95b",
        ),
    },
    HashVector {
        message: b"abc",
        digest: hex_bytes(
            b"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
              8086072ba1e7cc2358baeca134c825a7",
        ),
    },
    HashVector {
        message: SHA384_MULTI_BLOCK_MESSAGE,
        digest: hex_bytes(
            b"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
              fcc7c71a557e2db966c3e9fa91746039",
        ),
    },
];

const SHA512_VECTORS: [HashVector<64>; 3] = [
    HashVector {
        message: b"",
        digest: hex_bytes(
            b"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
              47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ),
    },
    HashVector {
        message: b"abc",
        digest: hex_bytes(
            b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
              2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    },
    HashVector {
        message: SHA384_MULTI_BLOCK_MESSAGE,
        digest: hex_bytes(
            b"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
              501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        ),
    },
];

const AES256_VECTORS: [BlockCipherVector; 3] = [
    BlockCipherVector {
        key: hex_bytes(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        plaintext: hex_bytes(b"00112233445566778899aabbccddeeff"),
        ciphertext: hex_bytes(b"8ea2b7ca516745bfeafc49904b496089"),
    },
    BlockCipherVector {
        key: hex_bytes(b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        plaintext: hex_bytes(b"6bc1bee22e409f96e93d7e117393172a"),
        ciphertext: hex_bytes(b"f3eed1bdb5d2a03c064b5a7e3db181f8"),
    },
    BlockCipherVector {
        key: hex_bytes(b"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
        plaintext: hex_bytes(b"ae2d8a571e03ac9c9eb76fac45af8e51"),
        ciphertext: hex_bytes(b"591ccb10d410ed26dc5ba74a31362870"),
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum PrimitiveTest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Aes256,
}

impl PrimitiveTest {
    pub(in crate::library::tpm2) const ALL: [Self; 5] = [
        Self::Sha1,
        Self::Aes256,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
    ];

    const fn bit(self) -> u8 {
        1 << self as u8
    }

    const fn algorithm(self) -> u16 {
        match self {
            Self::Sha1 => TPM_ALG_SHA1,
            Self::Sha256 => TPM_ALG_SHA256,
            Self::Sha384 => TPM_ALG_SHA384,
            Self::Sha512 => TPM_ALG_SHA512,
            Self::Aes256 => TPM_ALG_AES,
        }
    }

    fn for_algorithm(algorithm: u16) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|test| test.algorithm() == algorithm)
    }

    const fn profile_name(self) -> &'static [u8] {
        let name = match self {
            Self::Sha1 => hash_profile_name(TPM_ALG_SHA1),
            Self::Sha256 => hash_profile_name(TPM_ALG_SHA256),
            Self::Sha384 => hash_profile_name(TPM_ALG_SHA384),
            Self::Sha512 => hash_profile_name(TPM_ALG_SHA512),
            Self::Aes256 => Some(AES_PROFILE_NAME),
        };
        match name {
            Some(name) => name,
            None => panic!("every self-test primitive maps to a profile token"),
        }
    }

    fn run(self) -> bool {
        match self {
            Self::Sha1 => run_hash_vectors(0, &SHA1_VECTORS),
            Self::Sha256 => run_hash_vectors(1, &SHA256_VECTORS),
            Self::Sha384 => run_hash_vectors(2, &SHA384_VECTORS),
            Self::Sha512 => run_hash_vectors(3, &SHA512_VECTORS),
            Self::Aes256 => run_block_cipher_vectors(&AES256_VECTORS),
        }
    }
}

fn run_hash_vectors<const N: usize>(slot: usize, vectors: &[HashVector<N>]) -> bool {
    vectors.iter().all(|vector| {
        BankHasher::new(slot).is_some_and(|mut hasher| {
            hasher.update(vector.message);
            hasher.finalize() == vector.digest
        })
    })
}

fn run_block_cipher_vectors(vectors: &[BlockCipherVector]) -> bool {
    vectors.iter().all(|vector| {
        let cipher = aes::Aes256::new(&vector.key.into());
        let mut block = aes::Block::from(vector.plaintext);
        cipher.encrypt_block(&mut block);
        block.as_slice() == vector.ciphertext
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::library::tpm2) struct PrimitiveTestSet(u8);

impl PrimitiveTestSet {
    pub(in crate::library::tpm2) fn for_algorithms(profile_algorithms: &[u8]) -> Self {
        let mut set = Self(0);
        for test in PrimitiveTest::ALL {
            if algorithm_enabled(profile_algorithms, test.profile_name()) {
                set.insert(test);
            }
        }
        set
    }

    pub(in crate::library::tpm2) fn contains(self, test: PrimitiveTest) -> bool {
        self.0 & test.bit() != 0
    }

    fn insert(&mut self, test: PrimitiveTest) {
        self.0 |= test.bit();
    }

    fn remove(&mut self, test: PrimitiveTest) {
        self.0 &= !test.bit();
    }

    pub(in crate::library::tpm2) fn is_empty(self) -> bool {
        self.0 == 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct SelfTestFailure {
    pub(in crate::library::tpm2) primitive: PrimitiveTest,
}

type PrimitiveRunner = fn(PrimitiveTest) -> bool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum SelectedTestError {
    UnsupportedAlgorithm(u16),
    TestFailed,
}

pub(in crate::library::tpm2) struct SelfTestState {
    pub(in crate::library::tpm2) implemented: PrimitiveTestSet,
    pub(in crate::library::tpm2) pending: PrimitiveTestSet,
    pub(in crate::library::tpm2) failure: Option<SelfTestFailure>,
    enabled: Box<[u16]>,
    runner: PrimitiveRunner,
}

impl SelfTestState {
    pub(in crate::library::tpm2) fn for_algorithms(profile_algorithms: &[u8]) -> Self {
        let implemented = PrimitiveTestSet::for_algorithms(profile_algorithms);
        Self {
            implemented,
            pending: implemented,
            failure: None,
            enabled: enabled_algorithms(profile_algorithms).collect(),
            runner: PrimitiveTest::run,
        }
    }

    pub(in crate::library::tpm2) fn for_profile(profile: &ValidatedProfile) -> Self {
        Self::for_algorithms(&profile.algorithms)
    }

    pub(in crate::library::tpm2) fn restarted(&self) -> Self {
        Self {
            implemented: self.implemented,
            pending: self.implemented,
            failure: None,
            enabled: self.enabled.clone(),
            runner: PrimitiveTest::run,
        }
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn set_runner(&mut self, runner: PrimitiveRunner) {
        self.runner = runner;
    }

    pub(in crate::library::tpm2) fn run(&mut self, full_test: bool) -> Result<(), TpmResult> {
        if full_test {
            self.pending = self.implemented;
        }
        self.failure = None;
        for test in PrimitiveTest::ALL {
            if !self.pending.contains(test) {
                continue;
            }
            if !(self.runner)(test) {
                self.failure = Some(SelfTestFailure { primitive: test });
                return Err(TPM_RC_FAILURE);
            }
            self.pending.remove(test);
        }
        Ok(())
    }

    pub(in crate::library::tpm2) fn run_pending_algorithm(
        &mut self,
        algorithm: u16,
    ) -> Result<(), TpmResult> {
        let Some(test) = PrimitiveTest::for_algorithm(algorithm) else {
            return Ok(());
        };
        if !self.pending.contains(test) {
            return Ok(());
        }
        if !(self.runner)(test) {
            self.failure = Some(SelfTestFailure { primitive: test });
            return Err(TPM_RC_FAILURE);
        }
        self.pending.remove(test);
        Ok(())
    }

    pub(in crate::library::tpm2) fn run_selected(
        &mut self,
        requested: &[u16],
    ) -> Result<(), SelectedTestError> {
        let selected = self.select(requested)?;
        if selected.is_empty() {
            return Ok(());
        }
        self.failure = None;
        for test in PrimitiveTest::ALL {
            if !selected.contains(test) {
                continue;
            }
            if !(self.runner)(test) {
                self.failure = Some(SelfTestFailure { primitive: test });
                return Err(SelectedTestError::TestFailed);
            }
            self.pending.remove(test);
        }
        Ok(())
    }

    fn select(&self, requested: &[u16]) -> Result<PrimitiveTestSet, SelectedTestError> {
        let mut selected = PrimitiveTestSet::default();
        for &algorithm in requested {
            if !self.enabled.contains(&algorithm) {
                return Err(SelectedTestError::UnsupportedAlgorithm(algorithm));
            }
            if let Some(test) = PrimitiveTest::for_algorithm(algorithm) {
                selected.insert(test);
            }
        }
        Ok(selected)
    }

    pub(in crate::library::tpm2) fn pending_algorithms(&self) -> Vec<u16> {
        let mut algorithms: Vec<u16> = PrimitiveTest::ALL
            .into_iter()
            .filter(|&test| self.pending.contains(test))
            .map(PrimitiveTest::algorithm)
            .collect();
        algorithms.sort_unstable();
        algorithms
    }
}

impl core::fmt::Debug for SelfTestState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SelfTestState")
            .field("implemented", &self.implemented)
            .field("pending", &self.pending)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) fn always_fails(_test: PrimitiveTest) -> bool {
    false
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fails_on_sha384(test: PrimitiveTest) -> bool {
    test != PrimitiveTest::Sha384
}

#[cfg(test)]
mod tests {
    use super::super::algorithm::{TPM_ALG_ERROR, TPM_ALG_HMAC, TPM_ALG_RSA};
    use super::*;
    use crate::library::tpm2::pcr::PCR_SLOT_BANKS;
    use crate::library::tpm2::profile::{DEFAULT_ALGORITHMS_PROFILE, validate_user_profile};
    use core::cell::Cell;

    fn always_passes(_test: PrimitiveTest) -> bool {
        true
    }

    fn default_state() -> SelfTestState {
        SelfTestState::for_algorithms(DEFAULT_ALGORITHMS_PROFILE)
    }

    fn without(algorithms: &[u8], removed: &[u8]) -> Vec<u8> {
        let kept: Vec<&[u8]> = algorithms
            .split(|&byte| byte == b',')
            .filter(|token| *token != removed)
            .collect();
        kept.join(&b',')
    }

    thread_local! {
        static RUN_COUNT: Cell<usize> = const { Cell::new(0) };
    }

    fn counting_runner(_test: PrimitiveTest) -> bool {
        RUN_COUNT.with(|count| count.set(count.get() + 1));
        true
    }

    fn rejects_sha512(test: PrimitiveTest) -> bool {
        assert_ne!(
            test,
            PrimitiveTest::Sha512,
            "a disabled primitive must never reach the runner"
        );
        true
    }

    #[test]
    fn every_implemented_primitive_test_passes_its_own_vectors() {
        for test in PrimitiveTest::ALL {
            assert!(test.run(), "{test:?}");
        }
    }

    #[test]
    fn sha1_known_answer_vectors_match() {
        assert_eq!(SHA1_VECTORS.len(), 3);
        assert!(run_hash_vectors(0, &SHA1_VECTORS));
    }

    #[test]
    fn sha256_known_answer_vectors_match() {
        assert_eq!(SHA256_VECTORS.len(), 3);
        assert!(run_hash_vectors(1, &SHA256_VECTORS));
    }

    #[test]
    fn sha384_known_answer_vectors_match() {
        assert_eq!(SHA384_VECTORS.len(), 3);
        assert!(run_hash_vectors(2, &SHA384_VECTORS));
    }

    #[test]
    fn sha512_known_answer_vectors_match() {
        assert_eq!(SHA512_VECTORS.len(), 3);
        assert!(run_hash_vectors(3, &SHA512_VECTORS));
    }

    #[test]
    fn aes256_known_answer_vectors_match() {
        assert_eq!(AES256_VECTORS.len(), 3);
        assert!(run_block_cipher_vectors(&AES256_VECTORS));
    }

    #[test]
    fn the_multi_block_message_is_reassembled_without_the_source_indentation() {
        assert_eq!(SHA384_MULTI_BLOCK_MESSAGE.len(), 112);
        assert!(!SHA384_MULTI_BLOCK_MESSAGE.contains(&b' '));
        assert_eq!(SHA1_VECTORS[2].message.len(), 56);
    }

    #[test]
    fn each_hash_vector_binds_to_the_bank_the_pcr_code_uses() {
        assert_eq!(PCR_SLOT_BANKS[0].0, TPM_ALG_SHA1);
        assert_eq!(PCR_SLOT_BANKS[1].0, TPM_ALG_SHA256);
        assert_eq!(PCR_SLOT_BANKS[2].0, TPM_ALG_SHA384);
        assert_eq!(PCR_SLOT_BANKS[3].0, TPM_ALG_SHA512);
        assert_eq!(SHA1_VECTORS[0].digest.len(), PCR_SLOT_BANKS[0].1);
        assert_eq!(SHA256_VECTORS[0].digest.len(), PCR_SLOT_BANKS[1].1);
        assert_eq!(SHA384_VECTORS[0].digest.len(), PCR_SLOT_BANKS[2].1);
        assert_eq!(SHA512_VECTORS[0].digest.len(), PCR_SLOT_BANKS[3].1);
    }

    #[test]
    fn a_single_wrong_digest_bit_is_rejected() {
        let corrupted = [HashVector {
            message: b"abc",
            digest: hex_bytes::<20>(b"a9993e364706816aba3e25717850c26c9cd0d89c"),
        }];
        assert!(!run_hash_vectors(0, &corrupted));
    }

    #[test]
    fn a_digest_from_another_bank_is_rejected() {
        let mismatched = [HashVector {
            message: b"abc",
            digest: hex_bytes::<20>(b"a9993e364706816aba3e25717850c26c9cd0d89d"),
        }];
        assert!(!run_hash_vectors(1, &mismatched));
    }

    #[test]
    fn a_single_wrong_ciphertext_bit_is_rejected() {
        let corrupted = [BlockCipherVector {
            key: hex_bytes(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            plaintext: hex_bytes(b"00112233445566778899aabbccddeeff"),
            ciphertext: hex_bytes(b"8ea2b7ca516745bfeafc49904b496088"),
        }];
        assert!(!run_block_cipher_vectors(&corrupted));
    }

    #[test]
    fn an_unimplemented_bank_slot_fails_instead_of_reporting_success() {
        assert!(!run_hash_vectors(PCR_SLOT_BANKS.len(), &SHA1_VECTORS));
    }

    #[test]
    fn hex_bytes_decodes_digits_and_letters() {
        assert_eq!(hex_bytes::<4>(b"00ff107f"), [0x00, 0xff, 0x10, 0x7f]);
        assert_eq!(hex_bytes::<3>(b"0123ab"), [0x01, 0x23, 0xab]);
    }

    #[test]
    fn the_default_profile_makes_every_compiled_test_pending() {
        let state = default_state();
        for test in PrimitiveTest::ALL {
            assert!(state.pending.contains(test), "{test:?}");
            assert!(state.implemented.contains(test), "{test:?}");
        }
        assert!(state.failure.is_none());
    }

    #[test]
    fn each_primitive_maps_to_its_exact_profile_token() {
        assert_eq!(PrimitiveTest::Sha1.profile_name(), b"sha1");
        assert_eq!(PrimitiveTest::Sha256.profile_name(), b"sha256");
        assert_eq!(PrimitiveTest::Sha384.profile_name(), b"sha384");
        assert_eq!(PrimitiveTest::Sha512.profile_name(), b"sha512");
        assert_eq!(PrimitiveTest::Aes256.profile_name(), b"aes");
        for test in PrimitiveTest::ALL {
            assert!(algorithm_enabled(
                DEFAULT_ALGORITHMS_PROFILE,
                test.profile_name()
            ));
        }
    }

    #[test]
    fn a_profile_without_sha1_excludes_the_sha1_self_test() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha1");
        let state = SelfTestState::for_algorithms(&algorithms);
        assert!(!state.implemented.contains(PrimitiveTest::Sha1));
        assert!(!state.pending.contains(PrimitiveTest::Sha1));
        for test in [
            PrimitiveTest::Sha256,
            PrimitiveTest::Sha384,
            PrimitiveTest::Sha512,
            PrimitiveTest::Aes256,
        ] {
            assert!(state.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn a_profile_without_sha512_excludes_the_sha512_self_test() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha512");
        let state = SelfTestState::for_algorithms(&algorithms);
        assert!(!state.implemented.contains(PrimitiveTest::Sha512));
        assert!(!state.pending.contains(PrimitiveTest::Sha512));
        for test in [
            PrimitiveTest::Sha1,
            PrimitiveTest::Sha256,
            PrimitiveTest::Sha384,
            PrimitiveTest::Aes256,
        ] {
            assert!(state.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn a_profile_without_aes_excludes_the_aes_self_test() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"aes");
        let state = SelfTestState::for_algorithms(&algorithms);
        assert!(!state.implemented.contains(PrimitiveTest::Aes256));
        assert!(state.pending.contains(PrimitiveTest::Sha256));
    }

    #[test]
    fn the_mandatory_algorithms_stay_included_when_optional_ones_are_dropped() {
        let algorithms = without(&without(DEFAULT_ALGORITHMS_PROFILE, b"sha1"), b"sha512");
        let state = SelfTestState::for_algorithms(&algorithms);
        assert!(state.implemented.contains(PrimitiveTest::Sha256));
        assert!(state.implemented.contains(PrimitiveTest::Sha384));
        assert!(state.implemented.contains(PrimitiveTest::Aes256));
        assert!(!state.implemented.contains(PrimitiveTest::Sha1));
        assert!(!state.implemented.contains(PrimitiveTest::Sha512));
    }

    const MINIMAL_ALGORITHMS: &str = "rsa,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,null,oaep,\
ecdsa,ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,symcipher,cfb,ecc-nist-p256,ecc-nist-p384";

    #[test]
    fn a_validated_custom_profile_drives_the_pending_set() {
        let json = format!(r#"{{"Name":"custom","Algorithms":"{MINIMAL_ALGORITHMS}"}}"#);
        let profile = validate_user_profile(Some(json.as_bytes()))
            .expect("the minimal algorithm set validates");
        let state = SelfTestState::for_profile(&profile);
        assert!(!state.implemented.contains(PrimitiveTest::Sha1));
        assert!(!state.implemented.contains(PrimitiveTest::Sha512));
        assert!(state.implemented.contains(PrimitiveTest::Sha256));
        assert!(state.implemented.contains(PrimitiveTest::Sha384));
        assert!(state.implemented.contains(PrimitiveTest::Aes256));
        assert_eq!(state.pending, state.implemented);
    }

    #[test]
    fn the_null_profile_enables_every_primitive_test() {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = SelfTestState::for_profile(&profile);
        for test in PrimitiveTest::ALL {
            assert!(state.implemented.contains(test), "{test:?}");
        }
    }

    #[test]
    fn an_empty_algorithm_profile_leaves_nothing_pending() {
        let mut state = SelfTestState::for_algorithms(b"");
        assert!(state.implemented.is_empty());
        assert!(state.pending.is_empty());
        assert_eq!(state.run(true), Ok(()));
        assert!(state.failure.is_none());
    }

    #[test]
    fn profile_matching_rejects_substrings_and_prefixes() {
        for algorithms in [&b"sha"[..], b"sha5121", b"1sha512", b"xsha512,sha51"] {
            let state = SelfTestState::for_algorithms(algorithms);
            assert!(
                !state.implemented.contains(PrimitiveTest::Sha512),
                "{:?}",
                core::str::from_utf8(algorithms)
            );
            assert!(!state.implemented.contains(PrimitiveTest::Sha1));
        }
        let state = SelfTestState::for_algorithms(b"a,sha512,b");
        assert!(state.implemented.contains(PrimitiveTest::Sha512));
    }

    #[test]
    fn a_disabled_primitive_is_never_passed_to_the_runner() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha512");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        state.set_runner(rejects_sha512);
        assert_eq!(state.run(false), Ok(()));
        assert_eq!(state.run(true), Ok(()));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn a_non_full_test_runs_only_the_profile_enabled_pending_primitives() {
        let algorithms = without(&without(DEFAULT_ALGORITHMS_PROFILE, b"sha1"), b"sha512");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));
        assert_eq!(state.run(false), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 3);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn a_full_test_resets_only_the_profile_enabled_primitive_set() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha1");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        assert_eq!(state.run(false), Ok(()));
        assert!(state.pending.is_empty());
        state.set_runner(always_fails);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        assert!(!state.pending.contains(PrimitiveTest::Sha1));
        assert!(state.pending.contains(PrimitiveTest::Sha256));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Aes256
            }),
            "the first enabled primitive in upstream order is the one that failed"
        );
    }

    #[test]
    fn the_debug_output_exposes_no_vector_material() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        let rendered = format!("{state:?}");
        assert!(rendered.contains("Sha384"), "{rendered}");
        for vector in &SHA1_VECTORS {
            assert!(
                !rendered.contains(&format!("{:?}", vector.digest)),
                "{rendered}"
            );
        }
        for vector in &AES256_VECTORS {
            assert!(
                !rendered.contains(&format!("{:?}", vector.key)),
                "{rendered}"
            );
        }
    }

    #[test]
    fn every_test_owns_a_distinct_bit() {
        for (index, test) in PrimitiveTest::ALL.iter().enumerate() {
            for other in &PrimitiveTest::ALL[index + 1..] {
                assert_ne!(test.bit(), other.bit(), "{test:?} and {other:?}");
            }
        }
    }

    #[test]
    fn a_successful_run_clears_every_pending_test() {
        let mut state = default_state();
        assert_eq!(state.run(false), Ok(()));
        assert!(state.pending.is_empty());
        assert!(state.failure.is_none());
    }

    #[test]
    fn a_second_run_without_full_test_reruns_nothing() {
        let mut state = default_state();
        assert_eq!(state.run(false), Ok(()));
        state.set_runner(always_fails);
        assert_eq!(
            state.run(false),
            Ok(()),
            "a runner that always fails is never reached when nothing is pending"
        );
        assert!(state.pending.is_empty());
    }

    #[test]
    fn a_full_test_marks_every_test_pending_again() {
        let mut state = default_state();
        assert_eq!(state.run(false), Ok(()));
        state.set_runner(always_fails);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        for test in PrimitiveTest::ALL {
            assert!(state.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn a_failure_keeps_the_failed_and_unreached_tests_pending() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(false), Err(TPM_RC_FAILURE));
        assert!(!state.pending.contains(PrimitiveTest::Sha1));
        assert!(!state.pending.contains(PrimitiveTest::Aes256));
        assert!(!state.pending.contains(PrimitiveTest::Sha256));
        assert!(state.pending.contains(PrimitiveTest::Sha384));
        assert!(state.pending.contains(PrimitiveTest::Sha512));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha384
            })
        );
    }

    #[test]
    fn a_run_after_a_failure_retries_only_the_tests_left_pending() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(false), Err(TPM_RC_FAILURE));
        state.set_runner(always_passes);
        assert_eq!(state.run(false), Ok(()));
        assert!(state.pending.is_empty());
        assert!(state.failure.is_none(), "a successful retry clears it");
    }

    #[test]
    fn a_full_test_clears_the_previous_failure_before_executing() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(false), Err(TPM_RC_FAILURE));
        state.set_runner(always_passes);
        assert_eq!(state.run(true), Ok(()));
        assert!(state.failure.is_none());
        assert!(state.pending.is_empty());
    }

    #[test]
    fn a_later_failure_replaces_the_recorded_primitive() {
        let mut state = default_state();
        state.set_runner(always_fails);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha1
            })
        );
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha384
            })
        );
    }

    fn never_runs(test: PrimitiveTest) -> bool {
        panic!("an invalid request must never reach the runner, got {test:?}");
    }

    fn fails_on_aes256(test: PrimitiveTest) -> bool {
        test != PrimitiveTest::Aes256
    }

    fn fails_on_aes256_and_sha256(test: PrimitiveTest) -> bool {
        !matches!(test, PrimitiveTest::Aes256 | PrimitiveTest::Sha256)
    }

    #[test]
    fn the_canonical_order_follows_ascending_tpm_algorithm_ids() {
        let algorithms: Vec<u16> = PrimitiveTest::ALL
            .into_iter()
            .map(PrimitiveTest::algorithm)
            .collect();
        assert_eq!(
            algorithms,
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512
            ],
            "upstream CryptRunSelfTests walks the algorithm IDs in numeric order"
        );
        assert!(algorithms.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn a_selection_runs_aes_before_sha256() {
        let mut state = default_state();
        state.set_runner(fails_on_aes256_and_sha256);
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA256, TPM_ALG_AES]),
            Err(SelectedTestError::TestFailed)
        );
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Aes256
            }),
            "AES has the lower algorithm ID, so it runs and fails first"
        );
        assert!(state.pending.contains(PrimitiveTest::Aes256));
        assert!(
            state.pending.contains(PrimitiveTest::Sha256),
            "SHA-256 was never reached"
        );
    }

    #[test]
    fn a_full_test_runs_sha1_before_the_failing_aes_test() {
        let mut state = default_state();
        state.set_runner(fails_on_aes256);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        assert!(!state.pending.contains(PrimitiveTest::Sha1));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Aes256
            })
        );
        assert!(state.pending.contains(PrimitiveTest::Aes256));
        assert!(state.pending.contains(PrimitiveTest::Sha256));
        assert!(state.pending.contains(PrimitiveTest::Sha384));
        assert!(state.pending.contains(PrimitiveTest::Sha512));
        assert_eq!(
            state.pending_algorithms(),
            [TPM_ALG_AES, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512],
            "the reported list stays numerically sorted"
        );
    }

    #[test]
    fn every_primitive_maps_to_its_tpm_algorithm_id() {
        assert_eq!(PrimitiveTest::Sha1.algorithm(), TPM_ALG_SHA1);
        assert_eq!(PrimitiveTest::Sha256.algorithm(), TPM_ALG_SHA256);
        assert_eq!(PrimitiveTest::Sha384.algorithm(), TPM_ALG_SHA384);
        assert_eq!(PrimitiveTest::Sha512.algorithm(), TPM_ALG_SHA512);
        assert_eq!(PrimitiveTest::Aes256.algorithm(), TPM_ALG_AES);
        for test in PrimitiveTest::ALL {
            assert_eq!(PrimitiveTest::for_algorithm(test.algorithm()), Some(test));
        }
        for algorithm in [TPM_ALG_ERROR, TPM_ALG_RSA, TPM_ALG_HMAC, 0x0027, 0xffff] {
            assert_eq!(PrimitiveTest::for_algorithm(algorithm), None);
        }
    }

    #[test]
    fn an_empty_selection_runs_nothing_and_keeps_the_pending_set() {
        let mut state = default_state();
        state.set_runner(never_runs);
        assert_eq!(state.run_selected(&[]), Ok(()));
        assert_eq!(state.pending, state.implemented);
        assert!(state.failure.is_none());
    }

    #[test]
    fn a_selection_runs_only_the_requested_primitives() {
        let mut state = default_state();
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));
        assert_eq!(state.run_selected(&[TPM_ALG_SHA384, TPM_ALG_AES]), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 2);
        assert!(!state.pending.contains(PrimitiveTest::Sha384));
        assert!(!state.pending.contains(PrimitiveTest::Aes256));
        assert!(state.pending.contains(PrimitiveTest::Sha1));
        assert!(state.pending.contains(PrimitiveTest::Sha256));
        assert!(state.pending.contains(PrimitiveTest::Sha512));
    }

    #[test]
    fn a_duplicated_algorithm_runs_its_primitive_once() {
        let mut state = default_state();
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA1, TPM_ALG_SHA1, TPM_ALG_SHA1]),
            Ok(())
        );
        assert_eq!(RUN_COUNT.with(Cell::get), 1);
    }

    #[test]
    fn a_completed_primitive_runs_again_when_it_is_requested_explicitly() {
        let mut state = default_state();
        assert_eq!(state.run(true), Ok(()));
        assert!(state.pending.is_empty());
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));
        assert_eq!(state.run_selected(&[TPM_ALG_SHA256]), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 1);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn an_algorithm_outside_the_registry_is_rejected_before_anything_runs() {
        let mut state = default_state();
        state.set_runner(never_runs);
        for algorithm in [0x0002u16, 0x0009, 0x0027, 0x0045, 0xffff] {
            assert_eq!(
                state.run_selected(&[TPM_ALG_SHA256, algorithm]),
                Err(SelectedTestError::UnsupportedAlgorithm(algorithm)),
                "algorithm {algorithm:#06x}"
            );
        }
        assert_eq!(state.pending, state.implemented);
        assert!(state.failure.is_none());
    }

    #[test]
    fn a_profile_disabled_algorithm_is_rejected_before_anything_runs() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha512");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        state.set_runner(never_runs);
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA256, TPM_ALG_SHA512]),
            Err(SelectedTestError::UnsupportedAlgorithm(TPM_ALG_SHA512))
        );
        assert_eq!(state.pending, state.implemented);
    }

    #[test]
    fn an_enabled_algorithm_without_a_rust_test_runs_nothing() {
        let mut state = default_state();
        state.set_runner(never_runs);
        assert_eq!(state.run_selected(&[TPM_ALG_RSA, TPM_ALG_HMAC]), Ok(()));
        assert_eq!(state.pending, state.implemented);
        assert!(!state.pending_algorithms().contains(&TPM_ALG_RSA));
    }

    #[test]
    fn a_selected_failure_records_the_primitive_and_keeps_the_rest_pending() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA1, TPM_ALG_SHA384, TPM_ALG_SHA512]),
            Err(SelectedTestError::TestFailed)
        );
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha384
            })
        );
        assert!(!state.pending.contains(PrimitiveTest::Sha1));
        assert!(state.pending.contains(PrimitiveTest::Sha384));
        assert!(state.pending.contains(PrimitiveTest::Sha512));
        assert!(state.pending.contains(PrimitiveTest::Sha256));
        assert!(state.pending.contains(PrimitiveTest::Aes256));
    }

    #[test]
    fn a_successful_retry_clears_the_recorded_failure() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA384]),
            Err(SelectedTestError::TestFailed)
        );
        assert!(state.failure.is_some());
        state.set_runner(always_passes);
        assert_eq!(state.run_selected(&[TPM_ALG_SHA384]), Ok(()));
        assert!(state.failure.is_none());
        assert!(!state.pending.contains(PrimitiveTest::Sha384));
    }

    #[test]
    fn a_rejected_selection_leaves_a_recorded_failure_untouched() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA384]),
            Err(SelectedTestError::TestFailed)
        );
        let recorded = state.failure;
        let pending = state.pending;
        assert_eq!(
            state.run_selected(&[0xffff]),
            Err(SelectedTestError::UnsupportedAlgorithm(0xffff))
        );
        assert_eq!(state.failure, recorded);
        assert_eq!(state.pending, pending);
    }

    #[test]
    fn the_pending_algorithms_are_reported_in_ascending_order() {
        let mut state = default_state();
        assert_eq!(
            state.pending_algorithms(),
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512
            ]
        );
        assert_eq!(state.run_selected(&[TPM_ALG_SHA1, TPM_ALG_SHA384]), Ok(()));
        assert_eq!(
            state.pending_algorithms(),
            [TPM_ALG_AES, TPM_ALG_SHA256, TPM_ALG_SHA512]
        );
        assert_eq!(state.run(true), Ok(()));
        assert_eq!(state.pending_algorithms(), Vec::new());
    }

    #[test]
    fn a_profile_without_sha1_never_reports_or_accepts_it() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha1");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        assert_eq!(
            state.pending_algorithms(),
            [TPM_ALG_AES, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512]
        );
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA1]),
            Err(SelectedTestError::UnsupportedAlgorithm(TPM_ALG_SHA1))
        );
    }

    #[test]
    fn a_restarted_state_keeps_the_profile_for_validation() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha512");
        let mut source = SelfTestState::for_algorithms(&algorithms);
        assert_eq!(source.run(true), Ok(()));
        let mut restarted = source.restarted();
        assert_eq!(restarted.implemented, source.implemented);
        assert_eq!(restarted.pending, source.implemented);
        assert!(restarted.failure.is_none());
        assert_eq!(
            restarted.run_selected(&[TPM_ALG_SHA512]),
            Err(SelectedTestError::UnsupportedAlgorithm(TPM_ALG_SHA512))
        );
        assert_eq!(restarted.run_selected(&[TPM_ALG_SHA256]), Ok(()));
    }

    #[test]
    fn a_pending_algorithm_runs_once_and_stops_being_pending() {
        let mut state = default_state();
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));

        assert_eq!(state.run_pending_algorithm(TPM_ALG_SHA384), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 1);
        assert!(!state.pending.contains(PrimitiveTest::Sha384));

        assert_eq!(state.run_pending_algorithm(TPM_ALG_SHA384), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 1, "an already tested primitive");
        assert!(state.failure.is_none());
    }

    #[test]
    fn a_pending_algorithm_leaves_the_other_primitives_pending() {
        let mut state = default_state();
        assert_eq!(state.run_pending_algorithm(TPM_ALG_SHA256), Ok(()));
        assert_eq!(
            state.pending_algorithms(),
            [TPM_ALG_SHA1, TPM_ALG_AES, TPM_ALG_SHA384, TPM_ALG_SHA512]
        );
    }

    #[test]
    fn an_algorithm_without_a_primitive_test_runs_nothing() {
        let mut state = default_state();
        state.set_runner(never_runs);
        for algorithm in [TPM_ALG_RSA, TPM_ALG_HMAC, TPM_ALG_ERROR, 0x0027, 0xffff] {
            assert_eq!(
                state.run_pending_algorithm(algorithm),
                Ok(()),
                "algorithm {algorithm:#06x}"
            );
        }
        assert_eq!(state.pending, state.implemented);
        assert!(state.failure.is_none());
    }

    #[test]
    fn an_algorithm_outside_the_profile_runs_nothing_and_is_not_an_error() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha512");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        state.set_runner(never_runs);
        assert_eq!(
            state.run_pending_algorithm(TPM_ALG_SHA512),
            Ok(()),
            "internal use never reports the unsupported-algorithm error TPM2_IncrementalSelfTest \
             answers with"
        );
        assert_eq!(state.pending, state.implemented);
        assert!(state.failure.is_none());
    }

    #[test]
    fn a_failed_pending_algorithm_stays_pending_and_records_the_primitive() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(
            state.run_pending_algorithm(TPM_ALG_SHA384),
            Err(TPM_RC_FAILURE)
        );
        assert!(state.pending.contains(PrimitiveTest::Sha384));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha384
            })
        );
        assert_eq!(state.pending, state.implemented, "nothing else ran");
    }

    #[test]
    fn a_retry_after_a_failed_pending_algorithm_can_succeed() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(
            state.run_pending_algorithm(TPM_ALG_SHA384),
            Err(TPM_RC_FAILURE)
        );
        state.set_runner(always_passes);
        assert_eq!(state.run_pending_algorithm(TPM_ALG_SHA384), Ok(()));
        assert!(!state.pending.contains(PrimitiveTest::Sha384));
    }

    #[test]
    fn the_first_failing_test_stops_the_run() {
        let mut state = default_state();
        state.set_runner(always_fails);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        for test in PrimitiveTest::ALL {
            assert!(state.pending.contains(test), "{test:?}");
        }
    }
}
