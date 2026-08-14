mod drbg;
#[cfg(test)]
mod drbg_vectors;
mod entropy;

pub(super) use drbg::{DRBG_MAGIC, Drbg};
pub(in crate::library) use entropy::{EntropySource, os_entropy};

#[cfg(test)]
pub(super) use drbg::{CTR_DRBG_MAX_REQUESTS_PER_RESEED, DRBG_SEED_SIZE};

#[cfg(test)]
pub(super) use drbg_vectors::{
    DrbgBoundaryCase, DrbgBoundaryRecord, DrbgGenerateRecord, DrbgVectorRecord, boundary_record,
    generate_record, vector_record,
};
