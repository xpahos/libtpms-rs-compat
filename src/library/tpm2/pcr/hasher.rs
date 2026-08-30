use super::super::crypto::Hasher;
use super::PCR_SLOT_BANKS;

pub(in crate::library::tpm2) struct BankHasher(Hasher);

impl BankHasher {
    pub(in crate::library::tpm2) fn all() -> [Self; PCR_SLOT_BANKS.len()] {
        core::array::from_fn(|slot| Self::new(slot).expect("every bank slot is compiled"))
    }

    pub(in crate::library::tpm2) fn new(slot: usize) -> Option<Self> {
        let &(hash_alg, _) = PCR_SLOT_BANKS.get(slot)?;
        Hasher::new(hash_alg).map(Self)
    }

    #[cfg(test)]
    pub(in crate::library::tpm2) fn hash_alg(&self) -> u16 {
        self.0.hash_alg()
    }

    pub(in crate::library::tpm2) fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub(in crate::library::tpm2) fn finalize(self) -> Vec<u8> {
        self.0.finalize()
    }

    pub(in crate::library::tpm2) fn extend(
        slot: usize,
        old: &[u8],
        input: &[u8],
    ) -> Option<Vec<u8>> {
        let mut context = Self::new(slot)?;
        context.update(old);
        context.update(input);
        Some(context.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{PCR_SLOT_BANKS, bank_slot};
    use super::*;

    fn digest_of(slot: usize, data: &[u8]) -> Option<Vec<u8>> {
        let mut context = BankHasher::new(slot)?;
        context.update(data);
        Some(context.finalize())
    }

    #[test]
    fn per_slot_compiled_algorithm_selection() {
        for (slot, &(hash_alg, _)) in PCR_SLOT_BANKS.iter().enumerate() {
            let hasher = BankHasher::new(slot).expect("a compiled bank slot");
            assert_eq!(hasher.hash_alg(), hash_alg, "slot {slot}");
        }
    }

    #[test]
    fn out_of_range_slot_rejection() {
        for slot in [PCR_SLOT_BANKS.len(), 4, 5, 100, usize::MAX] {
            assert!(
                BankHasher::new(slot).is_none(),
                "slot {slot} must not select an algorithm"
            );
            assert!(
                BankHasher::extend(slot, &[0u8; 32], &[0u8; 32]).is_none(),
                "slot {slot} must not extend"
            );
        }
    }

    #[test]
    fn per_slot_compiled_digest_size() {
        for (slot, &(_, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
            let hasher = BankHasher::new(slot).expect("a compiled bank slot");
            assert_eq!(hasher.finalize().len(), digest_size, "slot {slot}");
        }
    }

    #[test]
    fn extend_digest_slot_size() {
        for (slot, &(_, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
            let extended =
                BankHasher::extend(slot, &vec![0u8; digest_size], &vec![0xaa; digest_size])
                    .expect("a compiled bank slot");
            assert_eq!(extended.len(), digest_size, "slot {slot}");
        }
    }

    #[test]
    fn extend_old_value_input_concatenation_order() {
        for (slot, &(_, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
            let old = vec![0u8; digest_size];
            let mut input = b"1234".to_vec();
            input.resize(digest_size, 0);

            let split = BankHasher::extend(slot, &old, &input).expect("a compiled bank slot");
            let mut joined = old.clone();
            joined.extend_from_slice(&input);
            assert_eq!(
                Some(split),
                digest_of(slot, &joined),
                "slot {slot} computes Hash(oldPCR || inputDigest)"
            );
        }
    }

    #[test]
    fn infallible_set_bank_coverage() {
        assert_eq!(BankHasher::all().len(), PCR_SLOT_BANKS.len());
    }

    #[test]
    fn infallible_fallible_constructor_match() {
        for (slot, hasher) in BankHasher::all().into_iter().enumerate() {
            let expected = BankHasher::new(slot).expect("a compiled bank slot");
            assert_eq!(hasher.hash_alg(), expected.hash_alg(), "slot {slot}");
        }
    }

    #[test]
    fn hasher_set_bank_algorithm_and_digest_size_match() {
        const EMPTY_DIGESTS: [&str; PCR_SLOT_BANKS.len()] = [
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b",
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        ];

        for ((slot, hasher), &(hash_alg, digest_size)) in BankHasher::all()
            .into_iter()
            .enumerate()
            .zip(&PCR_SLOT_BANKS)
        {
            let digest = hasher.finalize();
            assert_eq!(digest.len(), digest_size, "slot {slot}");
            let expected: String = EMPTY_DIGESTS[slot]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(
                actual, expected,
                "slot {slot} must hash with alg {hash_alg:#06x}"
            );
        }
    }

    #[test]
    fn hash_algorithm_slot_hasher_coverage() {
        for (slot, &(hash_alg, digest_size)) in PCR_SLOT_BANKS.iter().enumerate() {
            assert_eq!(
                bank_slot(hash_alg),
                Some((slot, digest_size)),
                "alg {hash_alg:#06x}"
            );
            assert!(
                BankHasher::new(slot).is_some(),
                "slot {slot} is reachable from the wire and needs a hasher"
            );
        }
    }

    #[test]
    fn sha256_extend_upstream_vector_match() {
        let mut input = b"1234".to_vec();
        input.resize(32, 0);
        let extended = BankHasher::extend(1, &[0u8; 32], &input).expect("the SHA-256 slot");
        assert_eq!(
            extended,
            [
                0x1f, 0x7f, 0xb1, 0x00, 0xe1, 0xb2, 0xd1, 0x95, 0x19, 0x4b, 0x58, 0xe7, 0xc3, 0x09,
                0xa5, 0x86, 0x30, 0x7c, 0x34, 0x64, 0x19, 0xdc, 0xb2, 0xd5, 0x9f, 0x52, 0x2b, 0xe7,
                0xf0, 0x94, 0x51, 0x01
            ]
        );
    }
}
