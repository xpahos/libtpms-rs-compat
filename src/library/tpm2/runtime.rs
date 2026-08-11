use crate::ffi_types::TpmResult;

use super::clock::RuntimeClock;
use super::nv::build_nv_image;
use super::persistent::{OwnedPcrAllocation, OwnedPersistentState};
use super::profile::ValidatedProfile;
use super::volatile::OwnedVolatileState;

pub const NV_MEMORY_SIZE: usize = 128 * 1024 + 65 * 704;

pub struct Tpm2Runtime {
    pub(super) state: Option<OwnedPersistentState>,

    pub(super) shadow_pcr_allocated: OwnedPcrAllocation,

    pub(super) shadow_pcr_pending: bool,

    pub(super) live_pcr_allocated: Option<OwnedPcrAllocation>,

    pub(super) volatile: Option<OwnedVolatileState>,

    #[allow(dead_code)]
    pub(super) clock: RuntimeClock,

    #[allow(dead_code)]
    pub(super) context_slot_mask: Option<u16>,
    #[allow(dead_code)]
    pub(super) null_seed_compat_level: Option<u8>,

    pub(super) active_profile_json: String,

    pub manufactured: bool,
    pub was_manufactured: bool,
    pub startup_received: bool,
    pub failure_mode: bool,
    #[allow(dead_code)]
    pub reported_failure: bool,

    pub power_on: bool,
    pub nv_available: bool,
    #[allow(dead_code)]
    pub nv_memory: Box<[u8]>,
}

impl Tpm2Runtime {
    #[cfg(test)]
    pub(super) fn state(&self) -> &OwnedPersistentState {
        self.state
            .as_ref()
            .expect("this runtime carries decoded state")
    }

    #[cfg(test)]
    pub(super) fn effective_pcr_allocated(&self) -> Option<&OwnedPcrAllocation> {
        self.live_pcr_allocated.as_ref().or_else(|| {
            self.state
                .as_ref()
                .map(|state| &state.persistent.pcr_allocated)
        })
    }
}

pub(super) fn merge_volatile_state(runtime: &mut Tpm2Runtime, volatile: OwnedVolatileState) {
    runtime.manufactured = volatile.manufactured;
    runtime.startup_received = volatile.initialized;
    runtime.failure_mode = volatile.in_failure_mode;
    runtime.context_slot_mask = Some(volatile.state_reset.context_slot_mask);
    runtime.null_seed_compat_level = Some(volatile.state_reset.null_seed_compat_level);
    runtime.clock = volatile.resume_clock;
    runtime.volatile = Some(volatile);
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
    let context_slot_mask = candidate
        .state_reset
        .as_ref()
        .map(|reset| reset.context_slot_mask);
    let null_seed_compat_level = candidate
        .state_reset
        .as_ref()
        .map(|reset| reset.null_seed_compat_level);
    commit_state(
        candidate,
        false,
        context_slot_mask,
        null_seed_compat_level,
        true,
    )
}

pub(super) fn commit_manufactured_state(
    candidate: OwnedPersistentState,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    commit_state(candidate, true, Some(0xffff), None, false)
}

pub(super) fn commit_first_boot_reloaded_state(
    candidate: OwnedPersistentState,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    let context_slot_mask = candidate
        .state_reset
        .as_ref()
        .map_or(0xffff, |reset| reset.context_slot_mask);
    let null_seed_compat_level = candidate
        .state_reset
        .as_ref()
        .map(|reset| reset.null_seed_compat_level);
    commit_state(
        candidate,
        true,
        Some(context_slot_mask),
        null_seed_compat_level,
        true,
    )
}

fn commit_state(
    candidate: OwnedPersistentState,
    was_manufactured: bool,
    context_slot_mask: Option<u16>,
    null_seed_compat_level: Option<u8>,
    shadow_pcr_pending: bool,
) -> Result<Box<Tpm2Runtime>, TpmResult> {
    let nv_memory = build_nv_image(&candidate)?;

    let shadow_pcr_allocated = candidate
        .persistent
        .shadow_pcr_allocated
        .clone()
        .unwrap_or_else(|| candidate.persistent.pcr_allocated.clone());

    let active_profile_json = format_active_profile(&candidate.profile);

    Ok(Box::new(Tpm2Runtime {
        state: Some(candidate),
        shadow_pcr_allocated,
        shadow_pcr_pending,
        live_pcr_allocated: None,
        volatile: None,
        clock: RuntimeClock::POWER_ON_RESET,
        context_slot_mask,
        null_seed_compat_level,
        active_profile_json,
        manufactured: true,
        was_manufactured,
        startup_received: false,
        failure_mode: false,
        reported_failure: false,
        power_on: true,
        nv_available: true,
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
        volatile: None,
        clock: RuntimeClock::POWER_ON_RESET,
        context_slot_mask: None,
        null_seed_compat_level: None,
        active_profile_json: String::new(),
        manufactured: false,
        was_manufactured: false,
        startup_received: false,
        failure_mode: false,
        reported_failure: false,
        power_on: true,
        nv_available: true,
        nv_memory: vec![0u8; NV_MEMORY_SIZE].into_boxed_slice(),
    })
}

pub(super) fn manufactured_zeroed_nv_runtime(active_profile_json: String) -> Box<Tpm2Runtime> {
    let mut runtime = empty_state_runtime();
    runtime.manufactured = true;
    runtime.was_manufactured = true;
    runtime.context_slot_mask = Some(0xffff);
    runtime.active_profile_json = active_profile_json;
    runtime
}
