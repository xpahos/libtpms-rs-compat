// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::tpm2::command::core::test_support::{
    counter_entropy, manufactured_runtime_with,
};
use crate::library::tpm2::runtime::Tpm2Runtime;

pub(super) fn started_runtime() -> Tpm2Runtime {
    let mut runtime = manufactured_runtime_with(None, counter_entropy::<0x27>);
    runtime.startup_received = true;
    runtime
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct RuntimeSnapshot {
    nv_memory: Vec<u8>,
    nv_update_pending: bool,
    manufactured: bool,
    startup_received: bool,
    tpm_established: bool,
    locality: u8,
    power_on: bool,
    nv_available: bool,
}

pub(super) fn snapshot(runtime: &Tpm2Runtime) -> RuntimeSnapshot {
    RuntimeSnapshot {
        nv_memory: runtime.nv_memory.to_vec(),
        nv_update_pending: runtime.nv_update_pending,
        manufactured: runtime.manufactured,
        startup_received: runtime.startup_received,
        tpm_established: runtime.tpm_established,
        locality: runtime.locality,
        power_on: runtime.power_on,
        nv_available: runtime.nv_available,
    }
}
