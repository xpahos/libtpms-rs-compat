use aes::cipher::{BlockEncrypt, KeyInit};

use crate::library::constants::TPM_RC_FAILURE;
use crate::types::TpmResult;

use super::algorithm::{
    TPM_ALG_AES, TPM_ALG_ECDH, TPM_ALG_NULL, TPM_ALG_OAEP, TPM_ALG_RSA, TPM_ALG_RSAES,
    TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, algorithm_enabled,
    hash_profile_name,
};
use super::capability::algorithms::enabled_algorithms;
use super::ecc::{EccPoint, point_multiply};
use super::pcr::BankHasher;
use super::profile::ValidatedProfile;

const AES_BLOCK_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;
const AES_PROFILE_NAME: &[u8] = b"aes";
const ECDH_PROFILE_NAME: &[u8] = b"ecdh";
const ECDH_TEST_CURVE: u16 = 0x0003;

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
    Ecdh,
}

impl PrimitiveTest {
    pub(in crate::library::tpm2) const ALL: [Self; 6] = [
        Self::Sha1,
        Self::Aes256,
        Self::Sha256,
        Self::Sha384,
        Self::Sha512,
        Self::Ecdh,
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
            Self::Ecdh => TPM_ALG_ECDH,
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
            Self::Ecdh => Some(ECDH_PROFILE_NAME),
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
            Self::Ecdh => run_ecdh_vector(&ECDH_VECTOR),
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

struct EcdhVector {
    private: [u8; 32],
    peer_x: [u8; 32],
    peer_y: [u8; 32],
    shared_x: [u8; 32],
    shared_y: [u8; 32],
}

const ECDH_VECTOR: EcdhVector = EcdhVector {
    private: hex_bytes(b"df8da4a388f6769689fc2f2da1b4397a78c47f718ca69185c0bff35420912f73"),
    peer_x: hex_bytes(b"a51e80d1763e8b96cecc2182c9a2a2ed4721895344e9c792e7314838e6ea9347"),
    peer_y: hex_bytes(b"30e64f9703a1cb3b322a703994eb4eea5588813fb500b85425abd4dafd537a18"),
    shared_x: hex_bytes(b"6402689278db3352ed3bfa3b74a33d2c2f9c590307f82290ede345f82a0ad81d"),
    shared_y: hex_bytes(b"58940582be5f330225903a339089e3e5104abc78a5c50764af91bce6ff851140"),
};

fn run_ecdh_vector(vector: &EcdhVector) -> bool {
    let peer = EccPoint {
        x: vector.peer_x.to_vec(),
        y: vector.peer_y.to_vec(),
    };
    point_multiply(ECDH_TEST_CURVE, Some(&peer), &vector.private)
        .is_ok_and(|shared| shared.x == vector.shared_x && shared.y == vector.shared_y)
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

pub(in crate::library::tpm2) use super::rsa_vectors::{
    OAEP_TEST_SEED_SIZE, PaddedRsaSelfTestStage, RSAES_TEST_PADDING_SIZE, RawRsaSelfTestStage,
};

pub(in crate::library::tpm2) type PaddedRsaRunner = fn(&[u8]) -> Result<(), PaddedRsaSelfTestStage>;
pub(in crate::library::tpm2) type RawRsaRunner = fn() -> Result<(), RawRsaSelfTestStage>;

pub(in crate::library::tpm2) struct SelfTestState {
    pub(in crate::library::tpm2) implemented: PrimitiveTestSet,
    pub(in crate::library::tpm2) pending: PrimitiveTestSet,
    pub(in crate::library::tpm2) failure: Option<SelfTestFailure>,
    pub(in crate::library::tpm2) oaep_pending: bool,
    pub(in crate::library::tpm2) rsaes_pending: bool,
    pub(in crate::library::tpm2) raw_rsa_pending: bool,
    oaep_runner: PaddedRsaRunner,
    rsaes_runner: PaddedRsaRunner,
    raw_rsa_runner: RawRsaRunner,
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
            oaep_pending: true,
            rsaes_pending: true,
            raw_rsa_pending: true,
            oaep_runner: super::rsa_vectors::run_oaep_known_answer,
            rsaes_runner: super::rsa_vectors::run_rsaes_known_answer,
            raw_rsa_runner: super::rsa_vectors::run_rsaep_known_answer,
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
            oaep_pending: true,
            rsaes_pending: true,
            raw_rsa_pending: true,
            oaep_runner: super::rsa_vectors::run_oaep_known_answer,
            rsaes_runner: super::rsa_vectors::run_rsaes_known_answer,
            raw_rsa_runner: super::rsa_vectors::run_rsaep_known_answer,
            enabled: self.enabled.clone(),
            runner: PrimitiveTest::run,
        }
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn set_runner(&mut self, runner: PrimitiveRunner) {
        self.runner = runner;
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn set_oaep_runner(&mut self, runner: PaddedRsaRunner) {
        self.oaep_runner = runner;
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn set_rsaes_runner(&mut self, runner: PaddedRsaRunner) {
        self.rsaes_runner = runner;
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn set_raw_rsa_runner(&mut self, runner: RawRsaRunner) {
        self.raw_rsa_runner = runner;
    }

    #[cfg(test)]
    pub(in crate::library) fn park_on_gate(&mut self) {
        self.runner = parks_on_the_gate_once;
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

    pub(in crate::library::tpm2) fn check_selection(
        &self,
        requested: &[u16],
    ) -> Result<(), SelectedTestError> {
        self.select(requested).map(|_| ())
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
            .chain(self.oaep_pending.then_some(TPM_ALG_OAEP))
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
pub(in crate::library) struct SelfTestGate {
    entered: std::sync::mpsc::Receiver<()>,
    release: std::sync::mpsc::SyncSender<()>,
}

#[cfg(test)]
const GATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(test)]
static GATE_ENTERED: std::sync::Mutex<Option<std::sync::mpsc::SyncSender<()>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static GATE_RELEASE: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(in crate::library) fn arm_self_test_gate() -> SelfTestGate {
    use std::sync::PoisonError;
    use std::sync::mpsc::sync_channel;

    let (entered_tx, entered_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    *GATE_ENTERED.lock().unwrap_or_else(PoisonError::into_inner) = Some(entered_tx);
    *GATE_RELEASE.lock().unwrap_or_else(PoisonError::into_inner) = Some(release_rx);
    SelfTestGate {
        entered: entered_rx,
        release: release_tx,
    }
}

#[cfg(test)]
impl SelfTestGate {
    pub(in crate::library) fn wait_until_entered(&self) {
        self.entered
            .recv_timeout(GATE_TIMEOUT)
            .expect("the command reached the gated self-test primitive");
    }

    pub(in crate::library) fn release(&self) {
        self.release
            .send(())
            .expect("the command is parked on the gate");
    }
}

#[cfg(test)]
impl Drop for SelfTestGate {
    fn drop(&mut self) {
        use std::sync::PoisonError;
        GATE_ENTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        GATE_RELEASE
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

#[cfg(test)]
fn parks_on_the_gate_once(_test: PrimitiveTest) -> bool {
    use std::sync::PoisonError;

    let entered = GATE_ENTERED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    let Some(entered) = entered else {
        return true;
    };
    entered.send(()).expect("the test thread is waiting");
    let release = GATE_RELEASE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take()
        .expect("the gate was armed with both ends");
    release
        .recv_timeout(GATE_TIMEOUT)
        .expect("the test thread released the parked command");
    true
}

pub(in crate::library::tpm2) struct LazySelfTest<'a>(
    Option<&'a mut dyn FnMut(u16) -> Result<(), TpmResult>>,
);

impl<'a> LazySelfTest<'a> {
    // TODO: Give the duplication and private-blob outer-wrap paths a
    // runtime-backed gate; they do not model the lazy hash and symmetric
    // known-answer tests they reach yet. The known-answer runners themselves
    // stay ungated, because the reference suppresses nested tests while one is
    // running.
    pub(in crate::library::tpm2) fn untested() -> Self {
        Self(None)
    }

    pub(in crate::library::tpm2) fn runtime(
        run: &'a mut dyn FnMut(u16) -> Result<(), TpmResult>,
    ) -> Self {
        Self(Some(run))
    }

    pub(in crate::library::tpm2) fn algorithm(&mut self, algorithm: u16) -> Result<(), TpmResult> {
        match &mut self.0 {
            Some(run) => run(algorithm),
            None => Ok(()),
        }
    }
}

pub(in crate::library::tpm2) fn self_test_reached(
    runtime: &mut super::runtime::Tpm2Runtime,
    algorithm: u16,
) -> Result<(), TpmResult> {
    match algorithm {
        TPM_ALG_OAEP => self_test_rsa_oaep(runtime),
        TPM_ALG_RSAES => run_rsaes_test_if_pending(runtime),
        _ => self_test_algorithm(runtime, algorithm),
    }
}

pub(in crate::library::tpm2) fn self_test_rsa_oaep(
    runtime: &mut super::runtime::Tpm2Runtime,
) -> Result<(), TpmResult> {
    if !runtime.self_test.oaep_pending {
        return Ok(());
    }
    run_oaep_test(runtime)
}

pub(in crate::library::tpm2) fn self_test_rsa_scheme(
    runtime: &mut super::runtime::Tpm2Runtime,
    scheme: u16,
) -> Result<(), TpmResult> {
    match scheme {
        TPM_ALG_OAEP => self_test_rsa_oaep(runtime),
        TPM_ALG_RSAES => run_rsaes_test_if_pending(runtime),
        TPM_ALG_NULL => run_raw_rsa_test_if_pending(runtime),
        _ => Ok(()),
    }
}

fn run_oaep_test(runtime: &mut super::runtime::Tpm2Runtime) -> Result<(), TpmResult> {
    self_test_algorithm(runtime, TPM_ALG_SHA512)?;
    let seed = super::random::generate_random(runtime, OAEP_TEST_SEED_SIZE)?;
    match (runtime.self_test.oaep_runner)(&seed) {
        Ok(()) => {
            runtime.self_test.oaep_pending = false;
            runtime.self_test.raw_rsa_pending = false;
            Ok(())
        }
        Err(stage) => {
            super::failure_mode::enter_failure_mode(runtime, padded_failure_location(stage));
            Err(TPM_RC_FAILURE)
        }
    }
}

fn run_rsaes_test_if_pending(runtime: &mut super::runtime::Tpm2Runtime) -> Result<(), TpmResult> {
    if !runtime.self_test.rsaes_pending {
        return Ok(());
    }
    run_rsaes_test(runtime)
}

fn run_rsaes_test(runtime: &mut super::runtime::Tpm2Runtime) -> Result<(), TpmResult> {
    let padding = super::random::generate_random(runtime, RSAES_TEST_PADDING_SIZE)?;
    match (runtime.self_test.rsaes_runner)(&padding) {
        Ok(()) => {
            runtime.self_test.rsaes_pending = false;
            runtime.self_test.raw_rsa_pending = false;
            Ok(())
        }
        Err(stage) => {
            super::failure_mode::enter_failure_mode(runtime, padded_failure_location(stage));
            Err(TPM_RC_FAILURE)
        }
    }
}

fn run_raw_rsa_test_if_pending(runtime: &mut super::runtime::Tpm2Runtime) -> Result<(), TpmResult> {
    if !runtime.self_test.raw_rsa_pending {
        return Ok(());
    }
    run_raw_rsa_test(runtime)
}

fn run_raw_rsa_test(runtime: &mut super::runtime::Tpm2Runtime) -> Result<(), TpmResult> {
    match (runtime.self_test.raw_rsa_runner)() {
        Ok(()) => {
            runtime.self_test.raw_rsa_pending = false;
            Ok(())
        }
        Err(stage) => {
            super::failure_mode::enter_failure_mode(runtime, raw_failure_location(stage));
            Err(TPM_RC_FAILURE)
        }
    }
}

pub(in crate::library::tpm2) fn run_self_test(
    runtime: &mut super::runtime::Tpm2Runtime,
    full_test: bool,
) -> Result<(), TpmResult> {
    if full_test {
        runtime.self_test.oaep_pending = true;
        runtime.self_test.rsaes_pending = true;
        runtime.self_test.raw_rsa_pending = true;
        run_raw_rsa_test_if_pending(runtime)?;
    }
    if let Err(code) = runtime.self_test.run(full_test) {
        enter_self_test_failure_mode(runtime);
        return Err(code);
    }
    if !full_test {
        run_raw_rsa_test_if_pending(runtime)?;
    }
    run_rsaes_test_if_pending(runtime)?;
    self_test_rsa_oaep(runtime)
}

fn raw_rsa_test_is_covered_by(requested: &[u16]) -> bool {
    requested
        .iter()
        .any(|algorithm| matches!(*algorithm, TPM_ALG_RSAES | TPM_ALG_OAEP))
}

pub(in crate::library::tpm2) fn run_incremental_self_test(
    runtime: &mut super::runtime::Tpm2Runtime,
    requested: &[u16],
) -> Result<(), SelectedTestError> {
    runtime.self_test.check_selection(requested)?;
    if requested.contains(&TPM_ALG_RSA) && !raw_rsa_test_is_covered_by(requested) {
        run_raw_rsa_test(runtime).map_err(|_| SelectedTestError::TestFailed)?;
    }
    if let Err(error) = runtime.self_test.run_selected(requested) {
        if error == SelectedTestError::TestFailed {
            enter_self_test_failure_mode(runtime);
        }
        return Err(error);
    }
    if requested.contains(&TPM_ALG_RSAES) {
        run_rsaes_test(runtime).map_err(|_| SelectedTestError::TestFailed)?;
    }
    if requested.contains(&TPM_ALG_OAEP) {
        run_oaep_test(runtime).map_err(|_| SelectedTestError::TestFailed)?;
    }
    Ok(())
}

fn enter_self_test_failure_mode(runtime: &mut super::runtime::Tpm2Runtime) {
    let location = super::failure_mode::FailureLocation::for_self_test(&runtime.self_test);
    super::failure_mode::enter_failure_mode(runtime, location);
}

const fn padded_failure_location(
    stage: PaddedRsaSelfTestStage,
) -> super::failure_mode::FailureLocation {
    use super::failure_mode::FailureLocation;
    match stage {
        PaddedRsaSelfTestStage::Encrypt => FailureLocation::RsaOaepEncrypt,
        PaddedRsaSelfTestStage::RoundTripDecrypt => FailureLocation::RsaOaepRoundTripDecrypt,
        PaddedRsaSelfTestStage::RoundTripCompare => FailureLocation::RsaOaepRoundTripCompare,
        PaddedRsaSelfTestStage::KnownAnswerDecrypt => FailureLocation::RsaOaepKnownAnswerDecrypt,
        PaddedRsaSelfTestStage::KnownAnswerCompare => FailureLocation::RsaOaepKnownAnswerCompare,
    }
}

const fn raw_failure_location(stage: RawRsaSelfTestStage) -> super::failure_mode::FailureLocation {
    use super::failure_mode::FailureLocation;
    match stage {
        RawRsaSelfTestStage::Encrypt => FailureLocation::RsaRawEncrypt,
        RawRsaSelfTestStage::EncryptCompare => FailureLocation::RsaRawEncryptCompare,
        RawRsaSelfTestStage::Decrypt => FailureLocation::RsaRawDecrypt,
        RawRsaSelfTestStage::DecryptCompare => FailureLocation::RsaRawDecryptCompare,
    }
}

pub(in crate::library::tpm2) fn self_test_algorithm(
    runtime: &mut super::runtime::Tpm2Runtime,
    algorithm: u16,
) -> Result<(), TpmResult> {
    match runtime.self_test.run_pending_algorithm(algorithm) {
        Ok(()) => Ok(()),
        Err(code) => {
            let location = super::failure_mode::FailureLocation::for_self_test(&runtime.self_test);
            super::failure_mode::enter_failure_mode(runtime, location);
            Err(code)
        }
    }
}

#[cfg(test)]
pub(in crate::library::tpm2) fn always_fails(_test: PrimitiveTest) -> bool {
    false
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fails_on_sha256(test: PrimitiveTest) -> bool {
    test != PrimitiveTest::Sha256
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fails_on_sha384(test: PrimitiveTest) -> bool {
    test != PrimitiveTest::Sha384
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fails_on_aes(test: PrimitiveTest) -> bool {
    test != PrimitiveTest::Aes256
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fails_on_sha512(test: PrimitiveTest) -> bool {
    test != PrimitiveTest::Sha512
}

#[cfg(test)]
pub(in crate::library::tpm2) fn fails_on_ecdh(test: PrimitiveTest) -> bool {
    test != PrimitiveTest::Ecdh
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
    fn implemented_primitive_vector_success() {
        for test in PrimitiveTest::ALL {
            assert!(test.run(), "{test:?}");
        }
    }

    #[test]
    fn sha1_known_answer_vector_match() {
        assert_eq!(SHA1_VECTORS.len(), 3);
        assert!(run_hash_vectors(0, &SHA1_VECTORS));
    }

    #[test]
    fn sha256_known_answer_vector_match() {
        assert_eq!(SHA256_VECTORS.len(), 3);
        assert!(run_hash_vectors(1, &SHA256_VECTORS));
    }

    #[test]
    fn sha384_known_answer_vector_match() {
        assert_eq!(SHA384_VECTORS.len(), 3);
        assert!(run_hash_vectors(2, &SHA384_VECTORS));
    }

    #[test]
    fn sha512_known_answer_vector_match() {
        assert_eq!(SHA512_VECTORS.len(), 3);
        assert!(run_hash_vectors(3, &SHA512_VECTORS));
    }

    #[test]
    fn aes256_known_answer_vector_match() {
        assert_eq!(AES256_VECTORS.len(), 3);
        assert!(run_block_cipher_vectors(&AES256_VECTORS));
    }

    #[test]
    fn multi_block_message_reassembly_without_indentation() {
        assert_eq!(SHA384_MULTI_BLOCK_MESSAGE.len(), 112);
        assert!(!SHA384_MULTI_BLOCK_MESSAGE.contains(&b' '));
        assert_eq!(SHA1_VECTORS[2].message.len(), 56);
    }

    #[test]
    fn hash_vector_pcr_bank_binding() {
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
    fn wrong_digest_bit_rejection() {
        let corrupted = [HashVector {
            message: b"abc",
            digest: hex_bytes::<20>(b"a9993e364706816aba3e25717850c26c9cd0d89c"),
        }];
        assert!(!run_hash_vectors(0, &corrupted));
    }

    #[test]
    fn cross_bank_digest_rejection() {
        let mismatched = [HashVector {
            message: b"abc",
            digest: hex_bytes::<20>(b"a9993e364706816aba3e25717850c26c9cd0d89d"),
        }];
        assert!(!run_hash_vectors(1, &mismatched));
    }

    #[test]
    fn wrong_ciphertext_bit_rejection() {
        let corrupted = [BlockCipherVector {
            key: hex_bytes(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            plaintext: hex_bytes(b"00112233445566778899aabbccddeeff"),
            ciphertext: hex_bytes(b"8ea2b7ca516745bfeafc49904b496088"),
        }];
        assert!(!run_block_cipher_vectors(&corrupted));
    }

    #[test]
    fn unimplemented_bank_slot_failure() {
        assert!(!run_hash_vectors(PCR_SLOT_BANKS.len(), &SHA1_VECTORS));
    }

    #[test]
    fn hex_bytes_digit_letter_decoding() {
        assert_eq!(hex_bytes::<4>(b"00ff107f"), [0x00, 0xff, 0x10, 0x7f]);
        assert_eq!(hex_bytes::<3>(b"0123ab"), [0x01, 0x23, 0xab]);
    }

    #[test]
    fn default_profile_all_tests_pending() {
        let state = default_state();
        for test in PrimitiveTest::ALL {
            assert!(state.pending.contains(test), "{test:?}");
            assert!(state.implemented.contains(test), "{test:?}");
        }
        assert!(state.failure.is_none());
    }

    #[test]
    fn primitive_exact_profile_token_mapping() {
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
    fn sha1_disabled_profile_exclusion() {
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
    fn sha512_disabled_profile_exclusion() {
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
    fn aes_disabled_profile_exclusion() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"aes");
        let state = SelfTestState::for_algorithms(&algorithms);
        assert!(!state.implemented.contains(PrimitiveTest::Aes256));
        assert!(state.pending.contains(PrimitiveTest::Sha256));
    }

    #[test]
    fn mandatory_algorithm_retention_without_optional() {
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
    fn custom_profile_pending_set() {
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
    fn null_profile_full_enablement() {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = SelfTestState::for_profile(&profile);
        for test in PrimitiveTest::ALL {
            assert!(state.implemented.contains(test), "{test:?}");
        }
    }

    #[test]
    fn empty_profile_empty_pending_set() {
        let mut state = SelfTestState::for_algorithms(b"");
        assert!(state.implemented.is_empty());
        assert!(state.pending.is_empty());
        assert_eq!(state.run(true), Ok(()));
        assert!(state.failure.is_none());
    }

    #[test]
    fn profile_matching_substring_prefix_rejection() {
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
    fn disabled_primitive_runner_exclusion() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha512");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        state.set_runner(rejects_sha512);
        assert_eq!(state.run(false), Ok(()));
        assert_eq!(state.run(true), Ok(()));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn non_full_test_pending_enabled_only() {
        let algorithms = without(&without(DEFAULT_ALGORITHMS_PROFILE, b"sha1"), b"sha512");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));
        assert_eq!(state.run(false), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 4);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn full_test_profile_scoped_reset() {
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
    fn debug_output_no_vector_material() {
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
    fn test_bit_distinctness() {
        for (index, test) in PrimitiveTest::ALL.iter().enumerate() {
            for other in &PrimitiveTest::ALL[index + 1..] {
                assert_ne!(test.bit(), other.bit(), "{test:?} and {other:?}");
            }
        }
    }

    #[test]
    fn successful_run_pending_clearance() {
        let mut state = default_state();
        assert_eq!(state.run(false), Ok(()));
        assert!(state.pending.is_empty());
        assert!(state.failure.is_none());
    }

    #[test]
    fn second_non_full_run_no_reruns() {
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
    fn full_test_pending_reset() {
        let mut state = default_state();
        assert_eq!(state.run(false), Ok(()));
        state.set_runner(always_fails);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        for test in PrimitiveTest::ALL {
            assert!(state.pending.contains(test), "{test:?}");
        }
    }

    #[test]
    fn failed_and_unreached_pending_retention() {
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
    fn post_failure_retry_pending_only() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(false), Err(TPM_RC_FAILURE));
        state.set_runner(always_passes);
        assert_eq!(state.run(false), Ok(()));
        assert!(state.pending.is_empty());
        assert!(state.failure.is_none(), "a successful retry clears it");
    }

    #[test]
    fn full_test_prior_failure_clearance() {
        let mut state = default_state();
        state.set_runner(fails_on_sha384);
        assert_eq!(state.run(false), Err(TPM_RC_FAILURE));
        state.set_runner(always_passes);
        assert_eq!(state.run(true), Ok(()));
        assert!(state.failure.is_none());
        assert!(state.pending.is_empty());
    }

    #[test]
    fn later_failure_record_replacement() {
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
    fn canonical_order_ascending_algorithm_ids() {
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
                TPM_ALG_SHA512,
                TPM_ALG_ECDH
            ],
            "upstream CryptRunSelfTests walks the algorithm IDs in numeric order"
        );
        assert!(algorithms.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn selection_aes_before_sha256_order() {
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
    fn full_test_sha1_before_failing_aes_order() {
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
            [
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512,
                TPM_ALG_OAEP,
                TPM_ALG_ECDH
            ],
            "the reported list stays numerically sorted"
        );
    }

    #[test]
    fn primitive_tpm_algorithm_id_mapping() {
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
    fn empty_selection_no_run_pending_preservation() {
        let mut state = default_state();
        state.set_runner(never_runs);
        assert_eq!(state.run_selected(&[]), Ok(()));
        assert_eq!(state.pending, state.implemented);
        assert!(state.failure.is_none());
    }

    #[test]
    fn selection_requested_primitives_only() {
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
    fn duplicated_algorithm_single_run() {
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
    fn completed_primitive_explicit_rerun() {
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
    fn unregistered_algorithm_pre_run_rejection() {
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
    fn profile_disabled_algorithm_pre_run_rejection() {
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
    fn enabled_algorithm_without_rust_test_no_run() {
        let mut state = default_state();
        state.set_runner(never_runs);
        assert_eq!(state.run_selected(&[TPM_ALG_RSA, TPM_ALG_HMAC]), Ok(()));
        assert_eq!(state.pending, state.implemented);
        assert!(!state.pending_algorithms().contains(&TPM_ALG_RSA));
    }

    #[test]
    fn selected_failure_record_and_pending_retention() {
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
    fn successful_retry_failure_clearance() {
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
    fn rejected_selection_recorded_failure_unchanged() {
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
    fn pending_algorithms_ascending_order() {
        let mut state = default_state();
        assert_eq!(
            state.pending_algorithms(),
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512,
                TPM_ALG_OAEP,
                TPM_ALG_ECDH
            ]
        );
        assert_eq!(state.run_selected(&[TPM_ALG_SHA1, TPM_ALG_SHA384]), Ok(()));
        assert_eq!(
            state.pending_algorithms(),
            [
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA512,
                TPM_ALG_OAEP,
                TPM_ALG_ECDH
            ]
        );
        assert_eq!(state.run(true), Ok(()));
        assert_eq!(
            state.pending_algorithms(),
            [TPM_ALG_OAEP],
            "the primitive engine never clears the OAEP known-answer test"
        );
    }

    #[test]
    fn sha1_disabled_report_and_selection_rejection() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"sha1");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        assert_eq!(
            state.pending_algorithms(),
            [
                TPM_ALG_AES,
                TPM_ALG_SHA256,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512,
                TPM_ALG_OAEP,
                TPM_ALG_ECDH
            ]
        );
        assert_eq!(
            state.run_selected(&[TPM_ALG_SHA1]),
            Err(SelectedTestError::UnsupportedAlgorithm(TPM_ALG_SHA1))
        );
    }

    #[test]
    fn restarted_state_profile_retention() {
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

    use super::super::command::{TPM_CC_COMMIT, find_command};

    const CANCEL_CHECKPOINTS: &str = include_str!("testdata/cancel_checkpoints.txt");

    #[derive(Debug, Eq, PartialEq)]
    struct Checkpoint<'a> {
        file: &'a str,
        line: u32,
        function: &'a str,
        form: &'a str,
    }

    fn vendored_checkpoints() -> Vec<Checkpoint<'static>> {
        CANCEL_CHECKPOINTS
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let mut fields = line.split('\t');
                let mut next = |what: &str| {
                    fields
                        .next()
                        .unwrap_or_else(|| panic!("every record carries a {what}"))
                };
                let checkpoint = Checkpoint {
                    file: next("file"),
                    line: next("line").parse().expect("a decimal line number"),
                    function: next("function"),
                    form: next("form"),
                };
                assert_eq!(fields.next(), None, "records have exactly four fields");
                checkpoint
            })
            .collect()
    }

    #[test]
    fn ecdh_known_answer_vendored_vector_match() {
        assert!(
            PrimitiveTest::Ecdh.run(),
            "the vendored TestECDH vector reproduces"
        );
        assert_eq!(PrimitiveTest::Ecdh.algorithm(), TPM_ALG_ECDH);
        assert_eq!(PrimitiveTest::Ecdh.profile_name(), b"ecdh");
        let mut broken = ECDH_VECTOR;
        broken.shared_x[31] ^= 0x01;
        assert!(!run_ecdh_vector(&broken), "a wrong answer is refused");
        let mut off_curve = ECDH_VECTOR;
        off_curve.peer_y[31] ^= 0x01;
        assert!(!run_ecdh_vector(&off_curve), "an off-curve peer is refused");
    }

    #[test]
    fn ecdh_disabled_report_and_selection_rejection() {
        let algorithms = without(DEFAULT_ALGORITHMS_PROFILE, b"ecdh");
        let mut state = SelfTestState::for_algorithms(&algorithms);
        assert!(!state.pending_algorithms().contains(&TPM_ALG_ECDH));
        assert_eq!(
            state.run_selected(&[TPM_ALG_ECDH]),
            Err(SelectedTestError::UnsupportedAlgorithm(TPM_ALG_ECDH))
        );
        assert_eq!(state.run(true), Ok(()));
    }

    #[test]
    fn ecdh_failure_record_and_retry_until_pass() {
        let mut state = default_state();
        state.set_runner(fails_on_ecdh);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        assert_eq!(
            state.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Ecdh
            })
        );
        assert!(state.pending.contains(PrimitiveTest::Ecdh));

        let mut state = default_state();
        state.set_runner(counting_runner);
        RUN_COUNT.with(|count| count.set(0));
        assert_eq!(state.run_pending_algorithm(TPM_ALG_ECDH), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 1);
        assert!(!state.pending.contains(PrimitiveTest::Ecdh));
        assert_eq!(state.run_pending_algorithm(TPM_ALG_ECDH), Ok(()));
        assert_eq!(RUN_COUNT.with(Cell::get), 1, "a cleared test never reruns");
    }

    #[test]
    fn restart_ecdh_pending_reset() {
        let mut state = default_state();
        assert_eq!(state.run(true), Ok(()));
        assert!(!state.pending.contains(PrimitiveTest::Ecdh));
        let restarted = state.restarted();
        assert!(restarted.pending.contains(PrimitiveTest::Ecdh));
    }

    #[test]
    fn vendored_cancellation_checkpoints_fixture_match() {
        let checkpoints = vendored_checkpoints();
        assert_eq!(
            checkpoints,
            vec![
                Checkpoint {
                    file: "libtpms/src/tpm2/AlgorithmTests.c",
                    line: 107,
                    function: "<macro>",
                    form: "CHECK_CANCELED: _plat__IsCanceled() && toTest != &g_toTest",
                },
                Checkpoint {
                    file: "libtpms/src/tpm2/AlgorithmTests.c",
                    line: 733,
                    function: "TestEccSignAndVerify",
                    form: "CHECK_CANCELED",
                },
                Checkpoint {
                    file: "libtpms/src/tpm2/AlgorithmTests.c",
                    line: 741,
                    function: "TestEccSignAndVerify",
                    form: "CHECK_CANCELED",
                },
                Checkpoint {
                    file: "libtpms/src/tpm2/AlgorithmTests.c",
                    line: 748,
                    function: "TestEccSignAndVerify",
                    form: "CHECK_CANCELED",
                },
                Checkpoint {
                    file: "libtpms/src/tpm2/crypto/openssl/CryptEccSignature.c",
                    line: 305,
                    function: "CryptEccCommitCompute",
                    form: "_plat__IsCanceled",
                },
                Checkpoint {
                    file: "libtpms/src/tpm2/crypto/openssl/CryptEccSignature.c",
                    line: 325,
                    function: "CryptEccCommitCompute",
                    form: "_plat__IsCanceled",
                },
                Checkpoint {
                    file: "libtpms/src/tpm2/crypto/openssl/CryptRsa.c",
                    line: 1490,
                    function: "CryptRsaGenerateKey",
                    form: "_plat__IsCanceled",
                },
            ],
            "the vendored cancellation checkpoints moved; \
             rerun scripts/generate_cancel_checkpoints_fixture.py and \
             re-derive which Rust operations are cancelable"
        );
    }

    #[test]
    fn vendored_checkpoint_self_test_path_absence() {
        const IMPLEMENTED_SELF_TEST_PATHS: [&str; 8] = [
            "CryptSelfTest",
            "CryptIncrementalSelfTest",
            "CryptRunSelfTests",
            "CryptTestAlgorithm",
            "TestAlgorithm",
            "TestHash",
            "TestSymmetricAlgorithm",
            "TestKDFa",
        ];

        for checkpoint in vendored_checkpoints() {
            assert!(
                !IMPLEMENTED_SELF_TEST_PATHS.contains(&checkpoint.function),
                "{}:{} polls the cancel flag from {}, which this port implements",
                checkpoint.file,
                checkpoint.line,
                checkpoint.function
            );
        }
    }

    #[test]
    fn commit_and_rsa_keygen_cancelability() {
        const POLLED_BY_THIS_PORT: [&str; 2] = ["CryptEccCommitCompute", "CryptRsaGenerateKey"];
        const STILL_UNIMPLEMENTED: [&str; 2] = ["<macro>", "TestEccSignAndVerify"];

        let checkpoints = vendored_checkpoints();
        let polled: Vec<u32> = checkpoints
            .iter()
            .filter(|checkpoint| POLLED_BY_THIS_PORT.contains(&checkpoint.function))
            .map(|checkpoint| checkpoint.line)
            .collect();
        assert_eq!(
            polled,
            [305, 325, 1490],
            "TPM2_Commit polls both CryptEccCommitCompute checkpoints and \
             RSA key generation polls the CryptRsaGenerateKey checkpoint"
        );
        for checkpoint in &checkpoints {
            assert!(
                POLLED_BY_THIS_PORT.contains(&checkpoint.function)
                    || STILL_UNIMPLEMENTED.contains(&checkpoint.function),
                "{}:{} sits in {}, which is neither polled nor known to be unimplemented",
                checkpoint.file,
                checkpoint.line,
                checkpoint.function
            );
        }
        assert!(
            find_command(TPM_CC_COMMIT).is_some(),
            "the polled checkpoints belong to a registered command"
        );
    }

    #[test]
    fn self_test_checkpoint_caller_list_gating() {
        let macros: Vec<_> = vendored_checkpoints()
            .into_iter()
            .filter(|checkpoint| checkpoint.function == "<macro>")
            .map(|checkpoint| checkpoint.form.to_owned())
            .collect();
        assert_eq!(
            macros,
            ["CHECK_CANCELED: _plat__IsCanceled() && toTest != &g_toTest"],
            "TPM2_SelfTest passes &g_toTest, so the self-test checkpoint is \
             inert for it whatever the flag says"
        );
    }

    #[test]
    fn pending_algorithm_single_run_and_clearance() {
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
    fn pending_algorithm_other_primitives_unchanged() {
        let mut state = default_state();
        assert_eq!(state.run_pending_algorithm(TPM_ALG_SHA256), Ok(()));
        assert_eq!(
            state.pending_algorithms(),
            [
                TPM_ALG_SHA1,
                TPM_ALG_AES,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512,
                TPM_ALG_OAEP,
                TPM_ALG_ECDH
            ]
        );
    }

    #[test]
    fn algorithm_without_primitive_test_no_run() {
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
    fn out_of_profile_algorithm_no_run_no_error() {
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
    fn failed_pending_algorithm_retention_and_record() {
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
    fn failed_pending_algorithm_retry_success() {
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
    fn first_failure_run_termination() {
        let mut state = default_state();
        state.set_runner(always_fails);
        assert_eq!(state.run(true), Err(TPM_RC_FAILURE));
        for test in PrimitiveTest::ALL {
            assert!(state.pending.contains(test), "{test:?}");
        }
    }
}
