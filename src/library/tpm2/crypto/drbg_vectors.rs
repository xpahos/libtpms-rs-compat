pub(in crate::library::tpm2) struct DrbgVectorRecord {
    pub(in crate::library::tpm2) seed_after_instantiate: [u8; 48],
    pub(in crate::library::tpm2) last_value_after_instantiate: [u32; 4],
    pub(in crate::library::tpm2) reseed_counter_after_instantiate: u64,
    pub(in crate::library::tpm2) commit_nonce: [u8; 64],
    pub(in crate::library::tpm2) ep_seed: [u8; 64],
    pub(in crate::library::tpm2) sp_seed: [u8; 64],
    pub(in crate::library::tpm2) pp_seed: [u8; 64],
    pub(in crate::library::tpm2) ph_proof: [u8; 64],
    pub(in crate::library::tpm2) sh_proof: [u8; 64],
    pub(in crate::library::tpm2) eh_proof: [u8; 64],
    pub(in crate::library::tpm2) final_seed: [u8; 48],
    pub(in crate::library::tpm2) final_reseed_counter: u64,
    pub(in crate::library::tpm2) final_last_value: [u32; 4],
}

const RECORD_SIZE: usize = 48 + 16 + 8 + 64 + 6 * 64 + 48 + 8 + 16;

const FIXTURE: &[u8] = include_bytes!("../testdata/drbg_manufacture_vectors.bin");

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> [u8; N] {
        let (head, tail) = self.0.split_at(N);
        self.0 = tail;
        head.try_into().unwrap()
    }

    fn last_value(&mut self) -> [u32; 4] {
        let bytes: [u8; 16] = self.array();
        core::array::from_fn(|word| {
            u32::from_be_bytes(bytes[word * 4..word * 4 + 4].try_into().unwrap())
        })
    }
}

pub(in crate::library::tpm2) fn vector_record(continuous_test: bool) -> DrbgVectorRecord {
    assert_eq!(FIXTURE.len(), 2 * RECORD_SIZE, "stale fixture layout");
    let offset = usize::from(continuous_test) * RECORD_SIZE;
    let mut reader = Reader(&FIXTURE[offset..offset + RECORD_SIZE]);
    DrbgVectorRecord {
        seed_after_instantiate: reader.array(),
        last_value_after_instantiate: reader.last_value(),
        reseed_counter_after_instantiate: u64::from_be_bytes(reader.array()),
        commit_nonce: reader.array(),
        ep_seed: reader.array(),
        sp_seed: reader.array(),
        pp_seed: reader.array(),
        ph_proof: reader.array(),
        sh_proof: reader.array(),
        eh_proof: reader.array(),
        final_seed: reader.array(),
        final_reseed_counter: u64::from_be_bytes(reader.array()),
        final_last_value: reader.last_value(),
    }
}
