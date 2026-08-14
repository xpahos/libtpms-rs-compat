use crate::ffi_types::TpmResult;

use super::buffer_size::DEFAULT_BUFFER_SIZE;
use super::clock::RuntimeClock;
use super::crypto::{EntropySource, os_entropy};
use super::live::{LiveState, RestoredVolatile, split_restored_volatile};
use super::nv::build_nv_image;
use super::persistent::{OwnedPcrAllocation, OwnedPersistentState};
use super::profile::{DEFAULT_ALGORITHMS_PROFILE, ValidatedProfile};
use super::self_test::SelfTestState;
use super::tis::DrtmSequence;
use super::volatile::OwnedVolatileState;

pub const NV_MEMORY_SIZE: usize = 128 * 1024 + 65 * 704;

pub struct Tpm2Runtime {
    pub(super) state: Option<OwnedPersistentState>,

    pub(super) shadow_pcr_allocated: OwnedPcrAllocation,

    pub(super) shadow_pcr_pending: bool,

    pub(super) live_pcr_allocated: Option<OwnedPcrAllocation>,

    pub(super) live: LiveState,

    pub(super) restored_volatile: Option<RestoredVolatile>,

    pub(super) entropy: EntropySource,

    pub(super) nv_update_pending: bool,

    #[allow(dead_code)]
    pub(super) clock: RuntimeClock,

    pub(super) active_profile_json: String,

    pub(super) drtm_sequence: Option<DrtmSequence>,

    pub(super) self_test: SelfTestState,

    pub manufactured: bool,
    pub was_manufactured: bool,
    pub startup_received: bool,
    pub tpm_established: bool,
    pub failure_mode: bool,
    #[allow(dead_code)]
    pub reported_failure: bool,

    pub power_on: bool,
    pub nv_available: bool,
    pub locality: u8,
    pub buffer_size: u32,
    pub nv_memory: Box<[u8]>,
}

impl Tpm2Runtime {
    #[cfg(test)]
    pub(super) fn state(&self) -> &OwnedPersistentState {
        self.state
            .as_ref()
            .expect("this runtime carries decoded state")
    }

    pub(super) fn effective_pcr_allocated(&self) -> Option<&OwnedPcrAllocation> {
        self.live_pcr_allocated.as_ref().or_else(|| {
            self.state
                .as_ref()
                .map(|state| &state.persistent.pcr_allocated)
        })
    }
}

pub(super) fn merge_volatile_state(runtime: &mut Tpm2Runtime, volatile: OwnedVolatileState) {
    let (live, flags, carry) = split_restored_volatile(volatile);
    runtime.manufactured = flags.manufactured;
    runtime.startup_received = flags.initialized;
    runtime.tpm_established = flags.tpm_established;
    runtime.failure_mode = flags.in_failure_mode;
    runtime.clock = flags.resume_clock;
    runtime.live = live;
    runtime.restored_volatile = Some(carry);
}

pub(super) fn nv_shadow_restore(runtime: &mut Tpm2Runtime) {
    if runtime.shadow_pcr_pending {
        runtime.live_pcr_allocated = Some(runtime.shadow_pcr_allocated.clone());
        runtime.shadow_pcr_pending = false;
    }
}

impl core::fmt::Debug for Tpm2Runtime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tpm2Runtime")
            .field("manufactured", &self.manufactured)
            .field("was_manufactured", &self.was_manufactured)
            .field("startup_received", &self.startup_received)
            .field("failure_mode", &self.failure_mode)
            .field("power_on", &self.power_on)
            .field("nv_available", &self.nv_available)
            .finish_non_exhaustive()
    }
}

pub(super) fn format_active_profile(profile: &ValidatedProfile) -> String {
    let mut json = format!(
        "{{\"Name\":\"{}\",\"StateFormatLevel\":{}",
        String::from_utf8_lossy(&profile.name),
        profile.state_format_level,
    );
    json.push_str(&format!(
        ",\"Commands\":\"{}\"",
        String::from_utf8_lossy(&profile.commands)
    ));
    json.push_str(&format!(
        ",\"Algorithms\":\"{}\"",
        String::from_utf8_lossy(&profile.algorithms)
    ));
    if let Some(attributes) = &profile.attributes {
        json.push_str(&format!(
            ",\"Attributes\":\"{}\"",
            String::from_utf8_lossy(attributes)
        ));
    }
    json.push_str(&format!(
        ",\"Description\":\"{}\"",
        String::from_utf8_lossy(&profile.description)
    ));
    json.push('}');
    json
}

pub(super) fn commit_restored_state(
    candidate: OwnedPersistentState,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    let live = LiveState::power_on_with_state_reset(candidate.state_reset.as_ref());
    commit_state(candidate, false, live, true)
}

pub(super) fn commit_manufactured_state(
    candidate: OwnedPersistentState,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    commit_state(candidate, true, LiveState::power_on(), false)
}

pub(super) fn commit_first_boot_reloaded_state(
    candidate: OwnedPersistentState,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    let live = LiveState::power_on_with_state_reset(candidate.state_reset.as_ref());
    commit_state(candidate, true, live, true)
}

fn commit_state(
    candidate: OwnedPersistentState,
    was_manufactured: bool,
    mut live: LiveState,
    shadow_pcr_pending: bool,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    let nv_memory = build_nv_image(&candidate)?;

    live.orderly = candidate.orderly.clone();

    let shadow_pcr_allocated = candidate
        .persistent
        .shadow_pcr_allocated
        .clone()
        .unwrap_or_else(|| candidate.persistent.pcr_allocated.clone());

    let active_profile_json = format_active_profile(&candidate.profile);
    let self_test = SelfTestState::for_profile(&candidate.profile);

    Ok(Box::new(Tpm2Runtime {
        state: Some(candidate),
        shadow_pcr_allocated,
        shadow_pcr_pending,
        live_pcr_allocated: None,
        live,
        restored_volatile: None,
        entropy: os_entropy,
        nv_update_pending: false,
        clock: RuntimeClock::POWER_ON_RESET,
        active_profile_json,
        drtm_sequence: None,
        self_test,
        manufactured: true,
        was_manufactured,
        startup_received: false,
        tpm_established: false,
        failure_mode: false,
        reported_failure: false,
        power_on: true,
        nv_available: true,
        locality: 0,
        buffer_size: DEFAULT_BUFFER_SIZE,
        nv_memory,
    }))
}

pub(super) fn empty_state_runtime() -> Box<Tpm2Runtime> {
    Box::new(Tpm2Runtime {
        state: None,
        shadow_pcr_allocated: OwnedPcrAllocation {
            selections: Vec::new(),
        },
        shadow_pcr_pending: false,
        live_pcr_allocated: None,
        live: LiveState::power_on(),
        restored_volatile: None,
        entropy: os_entropy,
        nv_update_pending: false,
        clock: RuntimeClock::POWER_ON_RESET,
        active_profile_json: String::new(),
        drtm_sequence: None,
        self_test: SelfTestState::for_algorithms(DEFAULT_ALGORITHMS_PROFILE),
        manufactured: false,
        was_manufactured: false,
        startup_received: false,
        tpm_established: false,
        failure_mode: false,
        reported_failure: false,
        power_on: true,
        nv_available: true,
        locality: 0,
        buffer_size: DEFAULT_BUFFER_SIZE,
        nv_memory: vec![0u8; NV_MEMORY_SIZE].into_boxed_slice(),
    })
}

pub(super) fn manufactured_zeroed_nv_runtime(manufactured: &Tpm2Runtime) -> Box<Tpm2Runtime> {
    let mut runtime = empty_state_runtime();
    runtime.manufactured = true;
    runtime.was_manufactured = true;
    runtime.buffer_size = manufactured.buffer_size;
    runtime.active_profile_json = manufactured.active_profile_json.clone();
    runtime.self_test = manufactured.self_test.restarted();
    runtime
}
