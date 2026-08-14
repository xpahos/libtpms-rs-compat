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

pub(in crate::library::tpm2) struct DrbgGenerateStep {
    pub(in crate::library::tpm2) requested: u16,
    output: [u8; 64],
    pub(in crate::library::tpm2) seed_after: [u8; 48],
    pub(in crate::library::tpm2) reseed_counter_after: u64,
    pub(in crate::library::tpm2) last_value_after: [u32; 4],
}

impl DrbgGenerateStep {
    pub(in crate::library::tpm2) fn output(&self) -> &[u8] {
        &self.output[..usize::from(self.requested)]
    }
}

pub(in crate::library::tpm2) const GENERATE_STEPS: usize = 6;

pub(in crate::library::tpm2) struct DrbgGenerateRecord {
    pub(in crate::library::tpm2) initial_seed: [u8; 48],
    pub(in crate::library::tpm2) initial_reseed_counter: u64,
    pub(in crate::library::tpm2) initial_last_value: [u32; 4],
    pub(in crate::library::tpm2) steps: [DrbgGenerateStep; GENERATE_STEPS],
}

pub(in crate::library::tpm2) struct DrbgBoundaryCase {
    pub(in crate::library::tpm2) initial_reseed_counter: u64,
    pub(in crate::library::tpm2) requested: u16,
    pub(in crate::library::tpm2) entropy_draws: u8,
    output: [u8; 64],
    pub(in crate::library::tpm2) seed_after: [u8; 48],
    pub(in crate::library::tpm2) reseed_counter_after: u64,
    pub(in crate::library::tpm2) last_value_after: [u32; 4],
}

impl DrbgBoundaryCase {
    pub(in crate::library::tpm2) fn output(&self) -> &[u8] {
        &self.output[..usize::from(self.requested)]
    }
}

pub(in crate::library::tpm2) const BOUNDARY_CASES: usize = 4;

pub(in crate::library::tpm2) struct DrbgBoundaryRecord {
    pub(in crate::library::tpm2) initial_seed: [u8; 48],
    pub(in crate::library::tpm2) initial_last_value: [u32; 4],
    pub(in crate::library::tpm2) cases: [DrbgBoundaryCase; BOUNDARY_CASES],
}

pub(in crate::library::tpm2) struct DrbgStirCase {
    pub(in crate::library::tpm2) initial_seed: [u8; 48],
    pub(in crate::library::tpm2) initial_reseed_counter: u64,
    pub(in crate::library::tpm2) initial_last_value: [u32; 4],
    pub(in crate::library::tpm2) entropy: [u8; 48],
    additional_size: u16,
    additional: [u8; 128],
    pub(in crate::library::tpm2) derived: [u8; 48],
    pub(in crate::library::tpm2) seed_after: [u8; 48],
    pub(in crate::library::tpm2) reseed_counter_after: u64,
    pub(in crate::library::tpm2) last_value_after: [u32; 4],
    pub(in crate::library::tpm2) next_output: [u8; 64],
}

impl DrbgStirCase {
    pub(in crate::library::tpm2) fn additional(&self) -> &[u8] {
        &self.additional[..usize::from(self.additional_size)]
    }
}

pub(in crate::library::tpm2) const STIR_CASES: usize = 6;

pub(in crate::library::tpm2) struct DrbgStirRecord {
    pub(in crate::library::tpm2) cases: [DrbgStirCase; STIR_CASES],
}

const RECORD_SIZE: usize = 48 + 16 + 8 + 64 + 6 * 64 + 48 + 8 + 16;

const GENERATE_STEP_SIZE: usize = 2 + 64 + 48 + 8 + 16;
const GENERATE_RECORD_SIZE: usize = 48 + 8 + 16 + GENERATE_STEPS * GENERATE_STEP_SIZE;

const BOUNDARY_CASE_SIZE: usize = 8 + 2 + 1 + 64 + 48 + 8 + 16;
const BOUNDARY_RECORD_SIZE: usize = 48 + 16 + BOUNDARY_CASES * BOUNDARY_CASE_SIZE;

const GENERATE_FIXTURE_SIZE: usize = 2 * GENERATE_RECORD_SIZE + 2 * BOUNDARY_RECORD_SIZE;

const STIR_CASE_SIZE: usize = 48 + 8 + 16 + 48 + 2 + 128 + 48 + 48 + 8 + 16 + 64;
const STIR_RECORD_SIZE: usize = STIR_CASES * STIR_CASE_SIZE;
const STIR_FIXTURE_SIZE: usize = 2 * STIR_RECORD_SIZE;

const FIXTURE: &[u8] = include_bytes!("../testdata/drbg_manufacture_vectors.bin");

const GENERATE_FIXTURE: &[u8] = include_bytes!("../testdata/drbg_generate_vectors.bin");

const STIR_FIXTURE: &[u8] = include_bytes!("../testdata/drbg_stir_vectors.bin");

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

    fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
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

pub(in crate::library::tpm2) fn generate_record(continuous_test: bool) -> DrbgGenerateRecord {
    assert_eq!(
        GENERATE_FIXTURE.len(),
        GENERATE_FIXTURE_SIZE,
        "stale fixture layout"
    );
    let offset = usize::from(continuous_test) * GENERATE_RECORD_SIZE;
    let record = &GENERATE_FIXTURE[offset..offset + GENERATE_RECORD_SIZE];
    let mut reader = Reader(record);
    let initial_seed = reader.array();
    let initial_reseed_counter = reader.u64();
    let initial_last_value = reader.last_value();
    let steps_at = GENERATE_RECORD_SIZE - GENERATE_STEPS * GENERATE_STEP_SIZE;
    DrbgGenerateRecord {
        initial_seed,
        initial_reseed_counter,
        initial_last_value,
        steps: core::array::from_fn(|index| {
            let start = steps_at + index * GENERATE_STEP_SIZE;
            let mut reader = Reader(&record[start..start + GENERATE_STEP_SIZE]);
            DrbgGenerateStep {
                requested: reader.u16(),
                output: reader.array(),
                seed_after: reader.array(),
                reseed_counter_after: reader.u64(),
                last_value_after: reader.last_value(),
            }
        }),
    }
}

pub(in crate::library::tpm2) fn stir_record(continuous_test: bool) -> DrbgStirRecord {
    assert_eq!(
        STIR_FIXTURE.len(),
        STIR_FIXTURE_SIZE,
        "stale fixture layout"
    );
    let offset = usize::from(continuous_test) * STIR_RECORD_SIZE;
    let record = &STIR_FIXTURE[offset..offset + STIR_RECORD_SIZE];
    DrbgStirRecord {
        cases: core::array::from_fn(|index| {
            let start = index * STIR_CASE_SIZE;
            let mut reader = Reader(&record[start..start + STIR_CASE_SIZE]);
            DrbgStirCase {
                initial_seed: reader.array(),
                initial_reseed_counter: reader.u64(),
                initial_last_value: reader.last_value(),
                entropy: reader.array(),
                additional_size: reader.u16(),
                additional: reader.array(),
                derived: reader.array(),
                seed_after: reader.array(),
                reseed_counter_after: reader.u64(),
                last_value_after: reader.last_value(),
                next_output: reader.array(),
            }
        }),
    }
}

pub(in crate::library::tpm2) fn boundary_record(continuous_test: bool) -> DrbgBoundaryRecord {
    assert_eq!(
        GENERATE_FIXTURE.len(),
        GENERATE_FIXTURE_SIZE,
        "stale fixture layout"
    );
    let offset = 2 * GENERATE_RECORD_SIZE + usize::from(continuous_test) * BOUNDARY_RECORD_SIZE;
    let record = &GENERATE_FIXTURE[offset..offset + BOUNDARY_RECORD_SIZE];
    let mut reader = Reader(record);
    let initial_seed = reader.array();
    let initial_last_value = reader.last_value();
    let cases_at = BOUNDARY_RECORD_SIZE - BOUNDARY_CASES * BOUNDARY_CASE_SIZE;
    DrbgBoundaryRecord {
        initial_seed,
        initial_last_value,
        cases: core::array::from_fn(|index| {
            let start = cases_at + index * BOUNDARY_CASE_SIZE;
            let mut reader = Reader(&record[start..start + BOUNDARY_CASE_SIZE]);
            DrbgBoundaryCase {
                initial_reseed_counter: reader.u64(),
                requested: reader.u16(),
                entropy_draws: reader.u8(),
                output: reader.array(),
                seed_after: reader.array(),
                reseed_counter_after: reader.u64(),
                last_value_after: reader.last_value(),
            }
        }),
    }
}
