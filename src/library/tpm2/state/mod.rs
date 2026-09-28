// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

mod clear;
mod reset;

pub(super) use clear::{
    NUM_AUTHVALUE_PCR_GROUP, NUM_STATIC_PCR, PCR_AUTHVALUE_MAGIC, PCR_AUTHVALUE_VERSION, PCR_BANKS,
    PCR_SAVE_MAGIC, PCR_SAVE_VERSION, PcrBank, STATE_CLEAR_DATA_MAGIC, STATE_CLEAR_DATA_VERSION,
    StateClearData, algs_active, parse_state_clear_data,
};
pub(super) use reset::{
    COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS, PROOF_SIZE, STATE_RESET_DATA_MAGIC,
    STATE_RESET_DATA_VERSION, StateResetData, WIDE_CONTEXT_SLOTS_SINCE_VERSION,
    parse_state_reset_data,
};

#[cfg(test)]
pub(super) use clear::{PcrSaveFixture, StateClearFixture};
#[cfg(test)]
pub(super) use reset::StateResetFixture;
