use core::ffi::c_int;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

use crate::ffi::types::{
    LibtpmsCallbacks, TpmResult, TpmlibInfoFlags, TpmlibTpmProperty, TpmlibTpmVersion,
};

use super::cancel::CancelGate;
#[cfg(feature = "tpm2")]
use super::constants::TPM_BAD_TYPE;
use super::constants::{
    TPM_BUFFER_MAX, TPM_FAIL, TPM_INVALID_POSTINIT, TPM_SUCCESS, TPMLIB_TPM_VERSION_1_2,
    TPMLIB_TPM_VERSION_2, TPMPROP_TPM_BUFFER_MAX,
};
#[cfg(feature = "tpm2")]
use super::preloaded_state::PreloadedBlob;
use super::preloaded_state::PreloadedState;
use super::state_blob::{StateBlobKind, StateInput, StateOutput, StateValidationMask};

#[cfg(feature = "tpm2")]
use super::tpm2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TpmVersion {
    V1_2,
    V2_0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferSizeLimits {
    pub current: u32,
    pub minimum: u32,
    pub maximum: u32,
}

#[cfg(feature = "tpm2")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Lifecycle {
    generation: u64,
    selected: TpmVersion,
    initializing: Option<u64>,
}

struct LibraryState {
    selected: TpmVersion,
    version_locked: bool,
    lifecycle_generation: u64,
    initializing: Option<u64>,
    preloaded_state: PreloadedState,
    callbacks: LibtpmsCallbacks,
    #[cfg(feature = "tpm2")]
    tpm2_buffer_size: u32,
    #[cfg(feature = "tpm2")]
    configured_profile: Option<Vec<u8>>,
    #[cfg(feature = "tpm2")]
    tpm2_runtime: Option<Box<tpm2::Tpm2Runtime>>,
    #[cfg(feature = "tpm2")]
    installed_permanent: Option<tpm2::VolatileValidationContext>,
    #[cfg(all(test, feature = "tpm2"))]
    entropy_override: Option<tpm2::EntropySource>,
}

impl LibraryState {
    const fn new() -> Self {
        Self {
            selected: TpmVersion::V1_2,
            version_locked: false,
            lifecycle_generation: 0,
            initializing: None,
            preloaded_state: PreloadedState::new(),
            callbacks: LibtpmsCallbacks::empty(),
            #[cfg(feature = "tpm2")]
            tpm2_buffer_size: tpm2::DEFAULT_BUFFER_SIZE,
            #[cfg(feature = "tpm2")]
            configured_profile: None,
            #[cfg(feature = "tpm2")]
            tpm2_runtime: None,
            #[cfg(feature = "tpm2")]
            installed_permanent: None,
            #[cfg(all(test, feature = "tpm2"))]
            entropy_override: None,
        }
    }

    fn choose_tpm_version(&mut self, version: TpmlibTpmVersion) -> TpmResult {
        if self.version_locked {
            return TPM_FAIL;
        }
        let requested = match version {
            TPMLIB_TPM_VERSION_1_2 if cfg!(feature = "tpm1") => TpmVersion::V1_2,
            TPMLIB_TPM_VERSION_2 if cfg!(feature = "tpm2") => TpmVersion::V2_0,
            _ => return TPM_FAIL,
        };
        if self.selected != requested {
            self.clear_preloaded_state();
            self.advance_lifecycle();
        }
        self.selected = requested;
        TPM_SUCCESS
    }

    fn clear_preloaded_state(&mut self) {
        self.preloaded_state.clear_all();
        #[cfg(feature = "tpm2")]
        self.clear_installed_permanent();
    }

    #[cfg(feature = "tpm2")]
    fn clear_installed_permanent(&mut self) {
        self.installed_permanent = None;
    }

    fn advance_lifecycle(&mut self) {
        self.lifecycle_generation = self.lifecycle_generation.wrapping_add(1);
    }

    #[cfg(feature = "tpm2")]
    fn lifecycle(&self) -> Lifecycle {
        Lifecycle {
            generation: self.lifecycle_generation,
            selected: self.selected,
            initializing: self.initializing,
        }
    }
}

pub struct Library {
    state: Mutex<LibraryState>,
    cancel: CancelGate,
}

struct InitializingGuard<'a> {
    library: &'a Library,
    epoch: u64,
}

impl Drop for InitializingGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.library.lock_state();
        if state.initializing != Some(self.epoch) {
            return;
        }
        state.initializing = None;
        state.advance_lifecycle();
    }
}

impl Library {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LibraryState::new()),
            cancel: CancelGate::new(),
        }
    }

    pub fn global() -> &'static Self {
        &LIBRARY
    }

    fn lock_state(&self) -> MutexGuard<'_, LibraryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn choose_tpm_version(&self, version: TpmlibTpmVersion) -> TpmResult {
        let mut state = self.lock_state();
        let result = state.choose_tpm_version(version);
        self.cancel
            .set_cancelable(state.selected == TpmVersion::V2_0);
        result
    }

    pub fn cancel_command(&self) -> TpmResult {
        if self.cancel.request() {
            TPM_SUCCESS
        } else {
            TPM_FAIL
        }
    }

    pub fn main_init(&self) -> TpmResult {
        let mut state = self.lock_state();
        if state.initializing.is_some() {
            return TPM_INVALID_POSTINIT;
        }
        state.version_locked = true;
        state.advance_lifecycle();
        let epoch = state.lifecycle_generation;
        state.initializing = Some(epoch);
        let selected = state.selected;
        #[cfg(feature = "tpm2")]
        let token = state.lifecycle();
        #[cfg(feature = "tpm2")]
        let context = tpm2::Tpm2InitContext {
            callbacks: state.callbacks,
            preloaded_permanent: state.preloaded_state.get(StateBlobKind::Permanent).clone(),
            preloaded_volatile: state.preloaded_state.get(StateBlobKind::Volatile).clone(),
            configured_profile: state.configured_profile.clone(),
            #[cfg(not(test))]
            entropy: tpm2::os_entropy,
            #[cfg(test)]
            entropy: state.entropy_override.unwrap_or(tpm2::os_entropy),
            clock: &tpm2::OsClock,
        };
        drop(state);
        let initializing = InitializingGuard {
            library: self,
            epoch,
        };

        let result = match selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                let outcome = tpm2::main_init(context);
                let mut state = self.lock_state();
                if state.lifecycle() != token {
                    TPM_INVALID_POSTINIT
                } else {
                    match outcome {
                        Ok(mut runtime) => {
                            state.preloaded_state.take(StateBlobKind::Permanent);
                            state.preloaded_state.take(StateBlobKind::Volatile);
                            runtime.buffer_size = state.tpm2_buffer_size;
                            runtime.cancel = self.cancel.power_on();
                            state.tpm2_runtime = Some(runtime);
                            TPM_SUCCESS
                        }
                        Err(code) => {
                            state.tpm2_runtime = None;
                            self.cancel.power_off();
                            code
                        }
                    }
                }
            }
            _ => TPM_FAIL,
        };

        drop(initializing);
        result
    }

    #[cfg(feature = "tpm2")]
    pub(crate) fn prepare_process(&self) -> ProcessPreparation<'_> {
        let state = self.lock_state();
        match state.selected {
            TpmVersion::V2_0 => {
                let callbacks = state.callbacks;
                drop(state);
                ProcessPreparation::Tpm2(Tpm2ProcessContext {
                    library: self,
                    platform: host_platform_inputs(&callbacks),
                })
            }
            _ => ProcessPreparation::Disabled,
        }
    }

    #[cfg(not(feature = "tpm2"))]
    pub(crate) fn prepare_process(&self) -> ProcessPreparation {
        let _ = self.lock_state().selected;
        ProcessPreparation::Disabled
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_runtime_locality(&self) -> Option<u8> {
        self.lock_state()
            .tpm2_runtime
            .as_ref()
            .map(|runtime| runtime.locality)
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_require_physical_presence(&self, code: u32) {
        let mut state = self.lock_state();
        let runtime = state
            .tpm2_runtime
            .as_deref_mut()
            .expect("a running TPM 2 runtime");
        tpm2::require_physical_presence(runtime, code);
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_runtime_physical_presence(&self) -> Option<bool> {
        self.lock_state()
            .tpm2_runtime
            .as_ref()
            .map(|runtime| runtime.physical_presence)
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn stage_empty_state(&self, kind: StateBlobKind) {
        self.lock_state().preloaded_state.set_empty(kind);
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn stage_state_data(&self, kind: StateBlobKind, bytes: Vec<u8>) {
        self.lock_state().preloaded_state.set_data(kind, bytes);
    }

    #[cfg(test)]
    pub(in crate::library) fn cancel_is_signaled(&self) -> bool {
        self.cancel.is_signaled()
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn arm_cancel_request_park(&self) -> super::cancel::RequestPark {
        self.cancel.arm_request_park()
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn park_self_test_on_gate(&self) {
        let mut state = self.lock_state();
        let runtime = state
            .tpm2_runtime
            .as_deref_mut()
            .expect("a live TPM 2.0 runtime");
        tpm2::park_self_test_on_gate(runtime);
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn pending_self_test_algorithms(&self) -> Vec<u16> {
        let state = self.lock_state();
        let runtime = state
            .tpm2_runtime
            .as_deref()
            .expect("a live TPM 2.0 runtime");
        tpm2::pending_self_test_algorithms(runtime)
    }

    pub fn terminate(&self) {
        let selected = self.lock_state().selected;
        match selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                tpm2::terminate();
                self.cancel.power_off();
            }
            _ => {}
        }
        let mut state = self.lock_state();

        #[cfg(feature = "tpm2")]
        {
            state.tpm2_runtime = None;
            state.clear_installed_permanent();
            if selected == TpmVersion::V2_0 {
                state.configured_profile = None;
            }
        }
        state.version_locked = false;
        state.advance_lifecycle();
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn set_profile(&self, profile: Option<&[u8]>) -> TpmResult {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                let mut state = state;
                if state.tpm2_runtime.is_some() {
                    return TPM_INVALID_POSTINIT;
                }
                match profile {
                    None => {
                        state.configured_profile = None;
                        TPM_SUCCESS
                    }
                    Some(bytes) => {
                        if tpm2::user_profile_is_valid(bytes) {
                            state.configured_profile = Some(bytes.to_vec());
                            TPM_SUCCESS
                        } else {
                            TPM_FAIL
                        }
                    }
                }
            }
            _ => TPM_FAIL,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn set_buffer_size(&self, wanted_size: u32) -> Option<BufferSizeLimits> {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                let mut state = state;
                if wanted_size != 0 {
                    state.tpm2_buffer_size = tpm2::clamp_buffer_size(wanted_size);
                }
                let current = state.tpm2_buffer_size;
                if let Some(runtime) = state.tpm2_runtime.as_deref_mut() {
                    runtime.buffer_size = current;
                }
                Some(BufferSizeLimits {
                    current,
                    minimum: tpm2::MIN_BUFFER_SIZE,
                    maximum: tpm2::MAX_BUFFER_SIZE,
                })
            }
            _ => None,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn validate_state(&self, mask: StateValidationMask) -> TpmResult {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                let callbacks = state.callbacks;
                let lifecycle = state.lifecycle();
                let cached_volatile = state.preloaded_state.get(StateBlobKind::Volatile).clone();
                drop(state);
                let loaded = tpm2::load_state_for_validation(callbacks, mask, cached_volatile);
                let mut state = self.lock_state();
                if state.selected != lifecycle.selected {
                    return TPM_FAIL;
                }
                if state.lifecycle() != lifecycle {
                    return TPM_INVALID_POSTINIT;
                }
                let outcome = tpm2::finish_validation(
                    loaded,
                    state.tpm2_runtime.as_deref(),
                    state.installed_permanent.as_ref(),
                );
                if let Some(installed) = outcome.installed {
                    state.installed_permanent = Some(installed);
                }
                outcome.result
            }
            _ => TPM_FAIL,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn set_state(&self, kind: StateBlobKind, input: StateInput) -> TpmResult {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                let mut state = state;
                let bytes = match input {
                    StateInput::Empty => {
                        state.preloaded_state.set_empty(kind);
                        return TPM_SUCCESS;
                    }
                    StateInput::Data(bytes) => bytes,
                };
                if state.tpm2_runtime.is_some() || state.initializing.is_some() {
                    return TPM_INVALID_POSTINIT;
                }
                let callbacks = state.callbacks;
                let lifecycle = state.lifecycle();
                drop(state);
                self.cache_validated_state(kind, bytes, callbacks, lifecycle)
            }
            _ => TPM_FAIL,
        }
    }

    #[cfg(feature = "tpm2")]
    fn cache_validated_state(
        &self,
        kind: StateBlobKind,
        bytes: Vec<u8>,
        callbacks: LibtpmsCallbacks,
        lifecycle: Lifecycle,
    ) -> TpmResult {
        let outcome = self.validate_state_blob(kind, &bytes, callbacks);
        let mut state = self.lock_state();
        if state.selected != lifecycle.selected {
            return TPM_FAIL;
        }
        if state.lifecycle() != lifecycle || state.tpm2_runtime.is_some() {
            return TPM_INVALID_POSTINIT;
        }
        if let Some(installed) = outcome.installed {
            state.installed_permanent = Some(installed);
        }
        if outcome.result != TPM_SUCCESS {
            state.preloaded_state.clear_all();
            return outcome.result;
        }
        state.preloaded_state.set_data(kind, bytes);
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    fn validate_state_blob(
        &self,
        kind: StateBlobKind,
        bytes: &[u8],
        callbacks: LibtpmsCallbacks,
    ) -> tpm2::ValidationOutcome {
        match kind {
            StateBlobKind::Permanent => match tpm2::permanent_validation_context(bytes) {
                Ok(context) => tpm2::ValidationOutcome {
                    result: TPM_SUCCESS,
                    installed: Some(context),
                },
                Err(code) => tpm2::ValidationOutcome::rejected(code),
            },
            StateBlobKind::Volatile => {
                let permanent = match self.permanent_state_for_validation(callbacks) {
                    Ok(permanent) => permanent,
                    Err(code) => return tpm2::ValidationOutcome::rejected(code),
                };
                match tpm2::permanent_validation_context(&permanent) {
                    Ok(context) => tpm2::ValidationOutcome {
                        result: tpm2::validate_volatile_in_context(&context, bytes),
                        installed: Some(context),
                    },
                    Err(code) => tpm2::ValidationOutcome::rejected(code),
                }
            }
            StateBlobKind::SaveState => tpm2::ValidationOutcome::rejected(TPM_BAD_TYPE),
        }
    }

    #[cfg(feature = "tpm2")]
    fn permanent_state_for_validation(
        &self,
        callbacks: LibtpmsCallbacks,
    ) -> Result<Vec<u8>, TpmResult> {
        let cached = self
            .lock_state()
            .preloaded_state
            .get(StateBlobKind::Permanent)
            .clone();
        match cached {
            PreloadedBlob::Data(blob) => Ok(blob),
            PreloadedBlob::Empty => Ok(Vec::new()),
            PreloadedBlob::Missing => {
                tpm2::load_state_from_backend(callbacks, StateBlobKind::Permanent)
            }
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn get_state(&self, kind: StateBlobKind) -> Result<StateOutput, TpmResult> {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                if let Some(runtime) = state.tpm2_runtime.as_deref() {
                    return match kind {
                        StateBlobKind::Permanent => {
                            tpm2::persistent_all_store(runtime).map(StateOutput::Data)
                        }
                        StateBlobKind::Volatile => {
                            tpm2::volatile_all_store(runtime).map(StateOutput::Data)
                        }
                        StateBlobKind::SaveState => Ok(StateOutput::Data(Vec::new())),
                    };
                }
                match state.preloaded_state.get(kind).clone() {
                    PreloadedBlob::Data(blob) => Ok(StateOutput::Data(blob)),
                    PreloadedBlob::Empty => Ok(StateOutput::Empty),
                    PreloadedBlob::Missing => {
                        let callbacks = state.callbacks;
                        drop(state);
                        tpm2::load_state_from_backend(callbacks, kind).map(StateOutput::Data)
                    }
                }
            }
            _ => Err(TPM_FAIL),
        }
    }

    pub fn was_manufactured(&self) -> bool {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => state
                .tpm2_runtime
                .as_ref()
                .is_some_and(|runtime| runtime.was_manufactured),
            _ => false,
        }
    }

    pub fn volatile_all_store(&self) -> Result<Vec<u8>, TpmResult> {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => state
                .tpm2_runtime
                .as_deref()
                .ok_or(TPM_FAIL)
                .and_then(tpm2::volatile_all_store),
            _ => Err(TPM_FAIL),
        }
    }

    pub fn register_callbacks(&self, table: LibtpmsCallbacks) {
        self.lock_state().callbacks = table;
    }

    pub fn tis_established_get(&self) -> Result<bool, TpmResult> {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => state
                .tpm2_runtime
                .as_deref()
                .map(|runtime| runtime.tpm_established)
                .ok_or(TPM_FAIL),
            _ => Err(TPM_FAIL),
        }
    }

    pub fn tis_established_reset(&self) -> TpmResult {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => {
                if state.tpm2_runtime.is_none() {
                    return TPM_FAIL;
                }
                let callbacks = state.callbacks;
                drop(state);
                let locality = host_locality_raw(&callbacks);
                let mut state = self.lock_state();
                match state.tpm2_runtime.as_deref_mut() {
                    Some(runtime) => tpm2::tis_established_reset(runtime, locality),
                    None => TPM_FAIL,
                }
            }
            _ => TPM_FAIL,
        }
    }

    pub fn tis_hash_start(&self) -> TpmResult {
        #[cfg(feature = "tpm2")]
        return self.with_tpm2_runtime(tpm2::tis_hash_start);
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn tis_hash_data(&self, data: &[u8]) -> TpmResult {
        #[cfg(feature = "tpm2")]
        return self.with_tpm2_runtime(|runtime| tpm2::tis_hash_data(runtime, data));
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
    }

    pub fn tis_hash_end(&self) -> TpmResult {
        #[cfg(feature = "tpm2")]
        return self.with_tpm2_runtime(tpm2::tis_hash_end);
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
    }

    #[cfg(feature = "tpm2")]
    fn with_tpm2_runtime(
        &self,
        operation: impl FnOnce(&mut tpm2::Tpm2Runtime) -> TpmResult,
    ) -> TpmResult {
        let mut state = self.lock_state();
        match state.selected {
            TpmVersion::V2_0 => match state.tpm2_runtime.as_deref_mut() {
                Some(runtime) => operation(runtime),
                _ => TPM_FAIL,
            },
            _ => TPM_FAIL,
        }
    }

    pub fn get_tpm_property(&self, prop: TpmlibTpmProperty) -> Option<c_int> {
        if prop == TPMPROP_TPM_BUFFER_MAX {
            return Some(TPM_BUFFER_MAX);
        }
        match self.lock_state().selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => tpm2::get_tpm_property(prop),
            _ => None,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn get_info(&self, flags: TpmlibInfoFlags) -> Option<String> {
        let state = self.lock_state();
        match state.selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => Some(tpm2::get_info(flags, state.tpm2_runtime.as_deref())),
            _ => None,
        }
    }
}

#[cfg(feature = "tpm2")]
pub(crate) enum ProcessPreparation<'a> {
    Disabled,
    Tpm2(Tpm2ProcessContext<'a>),
}

#[cfg(not(feature = "tpm2"))]
pub(crate) enum ProcessPreparation {
    Disabled,
}

#[cfg(feature = "tpm2")]
pub(crate) struct Tpm2ProcessContext<'a> {
    library: &'a Library,
    platform: tpm2::PlatformInputs,
}

#[cfg(feature = "tpm2")]
impl Tpm2ProcessContext<'_> {
    pub(crate) fn execute(self, command: &super::CommandInput) -> Result<Vec<u8>, TpmResult> {
        let mut state = self.library.lock_state();
        let host_nvram = tpm2::HostNvram::new(state.callbacks);
        match state.tpm2_runtime.as_deref_mut() {
            Some(runtime) => {
                tpm2::process(runtime, self.platform, command, &tpm2::OsClock, |runtime| {
                    tpm2::host_nv_commit(&host_nvram, runtime)
                })
            }
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(feature = "tpm2")]
fn host_locality_raw(callbacks: &LibtpmsCallbacks) -> u32 {
    let Some(callback) = callbacks.tpm_io_getlocality else {
        return 0;
    };
    let mut locality: crate::ffi::types::TpmModifierIndicator = 0;
    // SAFETY: the registered callback has the exact C ABI signature and must
    // not unwind, and the out-pointer references a live local for the
    // duration of the call.
    let _ = unsafe { callback(&mut locality, 0) };
    locality
}

#[cfg(feature = "tpm2")]
fn host_locality(callbacks: &LibtpmsCallbacks) -> u8 {
    host_locality_raw(callbacks) as u8
}

#[cfg(feature = "tpm2")]
fn host_physical_presence(callbacks: &LibtpmsCallbacks) -> bool {
    let Some(callback) = callbacks.tpm_io_getphysicalpresence else {
        return false;
    };
    let mut asserted: crate::ffi::types::TpmBool = 0;
    // SAFETY: the registered callback has the exact C ABI signature and must
    // not unwind, and the out-pointer references a live local for the
    // duration of the call.
    let result = unsafe { callback(&mut asserted, 0) };
    result == crate::library::constants::TPM_SUCCESS && asserted != 0
}

#[cfg(feature = "tpm2")]
fn host_platform_inputs(callbacks: &LibtpmsCallbacks) -> tpm2::PlatformInputs {
    tpm2::PlatformInputs {
        locality: host_locality(callbacks),
        physical_presence: host_physical_presence(callbacks),
    }
}

impl Default for Library {
    fn default() -> Self {
        Self::new()
    }
}

static LIBRARY: LazyLock<Library> = LazyLock::new(Library::new);

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "tpm2")]
    use crate::library::preloaded_state::PreloadedBlob;
    use crate::library::state_blob::StateBlobKind;
    #[cfg(feature = "tpm2")]
    use std::sync::Arc;

    #[test]
    fn unknown_version_fails() {
        let library = Library::new();
        assert_eq!(library.choose_tpm_version(2), TPM_FAIL);
        assert_eq!(library.choose_tpm_version(-1), TPM_FAIL);
        assert_eq!(library.lock_state().selected, TpmVersion::V1_2);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_is_selectable() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(library.lock_state().selected, TpmVersion::V2_0);
    }

    #[cfg(not(feature = "tpm1"))]
    #[test]
    fn tpm12_fails_when_not_compiled_in() {
        let library = Library::new();
        assert_eq!(library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2), TPM_FAIL);
        assert_eq!(library.lock_state().selected, TpmVersion::V1_2);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn reselecting_same_version_keeps_preloaded_state() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, vec![1, 2, 3]);
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert!(
            library
                .lock_state()
                .preloaded_state
                .is_present(StateBlobKind::Permanent)
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failed_main_init_still_locks_until_terminate() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(library.main_init(), TPM_FAIL);
        assert_eq!(library.choose_tpm_version(TPMLIB_TPM_VERSION_2), TPM_FAIL);
        library.terminate();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
    }

    #[test]
    fn repeated_main_init_is_allowed() {
        let library = Library::new();
        assert_eq!(library.main_init(), TPM_FAIL);
        assert_eq!(library.main_init(), TPM_FAIL);
    }

    #[test]
    fn terminate_without_init_is_harmless_and_keeps_preloaded_state() {
        let library = Library::new();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, vec![1, 2, 3]);
        library.terminate();
        assert!(!library.lock_state().version_locked);
        assert!(
            library
                .lock_state()
                .preloaded_state
                .is_present(StateBlobKind::Permanent),
            "C does not clear blobs"
        );
    }

    #[test]
    fn buffer_max_is_answered_before_version_dispatch() {
        let library = Library::new();
        assert_eq!(library.get_tpm_property(TPMPROP_TPM_BUFFER_MAX), Some(4096));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_properties_match_reference_build() {
        use crate::library::constants::{TPMPROP_TPM_KEY_HANDLES, TPMPROP_TPM_RSA_KEY_LENGTH_MAX};

        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(
            library.get_tpm_property(TPMPROP_TPM_RSA_KEY_LENGTH_MAX),
            Some(3072)
        );
        assert_eq!(library.get_tpm_property(TPMPROP_TPM_KEY_HANDLES), Some(3));
        for prop in 4..=15 {
            assert_eq!(library.get_tpm_property(prop), None, "prop {prop}");
        }
    }

    #[cfg(not(feature = "tpm1"))]
    #[test]
    fn disabled_version_answers_no_properties_or_info() {
        use crate::library::constants::TPMPROP_TPM_RSA_KEY_LENGTH_MAX;

        let library = Library::new();
        assert_eq!(
            library.get_tpm_property(TPMPROP_TPM_RSA_KEY_LENGTH_MAX),
            None
        );
        assert!(library.get_info(0).is_none());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn get_info_dispatches_to_tpm2() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(library.get_info(0).as_deref(), Some("{}"));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failed_main_init_leaves_no_runtime() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(library.main_init(), TPM_FAIL);
        assert!(library.lock_state().tpm2_runtime.is_none());
        assert!(!library.was_manufactured());
        library.terminate();
    }

    #[test]
    fn volatile_store_without_a_running_tpm_fails() {
        let library = Library::new();
        assert_eq!(library.volatile_all_store(), Err(TPM_FAIL));

        #[cfg(feature = "tpm2")]
        {
            assert_eq!(
                library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
                TPM_SUCCESS
            );
            assert_eq!(library.volatile_all_store(), Err(TPM_FAIL));
        }
    }

    #[cfg(feature = "tpm2")]
    fn tpm2_library() -> Library {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
    }

    #[cfg(feature = "tpm2")]
    #[track_caller]
    fn buffer_size(library: &Library, wanted_size: u32) -> u32 {
        let limits = library
            .set_buffer_size(wanted_size)
            .expect("TPM 2 is selected");
        assert_eq!(limits.minimum, 2808);
        assert_eq!(limits.maximum, 4096);
        limits.current
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn the_buffer_size_starts_at_the_compile_time_maximum_and_queries_leave_it() {
        let library = tpm2_library();
        assert_eq!(buffer_size(&library, 0), 4096);
        assert_eq!(buffer_size(&library, 0), 4096, "a query changes nothing");
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn wanted_buffer_sizes_clamp_into_the_supported_range() {
        let library = tpm2_library();
        assert_eq!(buffer_size(&library, 2808), 2808);
        assert_eq!(buffer_size(&library, 4096), 4096);
        assert_eq!(buffer_size(&library, 2807), 2808, "below the minimum");
        assert_eq!(buffer_size(&library, 1), 2808);
        assert_eq!(buffer_size(&library, 4097), 4096, "above the maximum");
        assert_eq!(buffer_size(&library, u32::MAX), 4096);
        assert_eq!(buffer_size(&library, 3000), 3000, "in range");
        assert_eq!(buffer_size(&library, 0), 3000, "a query keeps the value");
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn the_buffer_size_is_per_library_and_survives_terminate() {
        let library = tpm2_library();
        let untouched = tpm2_library();
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            library
                .lock_state()
                .tpm2_runtime
                .as_ref()
                .unwrap()
                .buffer_size,
            4096
        );

        assert_eq!(buffer_size(&library, 3000), 3000);
        assert_eq!(
            library
                .lock_state()
                .tpm2_runtime
                .as_ref()
                .unwrap()
                .buffer_size,
            3000,
            "a live runtime sees the change immediately"
        );
        assert_eq!(
            buffer_size(&untouched, 0),
            4096,
            "another library instance keeps its own value"
        );

        library.terminate();
        assert_eq!(buffer_size(&library, 0), 3000, "terminate keeps the value");
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            library
                .lock_state()
                .tpm2_runtime
                .as_ref()
                .unwrap()
                .buffer_size,
            3000,
            "the re-initialized runtime starts from the configured value"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn the_buffer_size_bounds_the_accepted_command_size() {
        use crate::library::constants::TPM_RC_COMMAND_SIZE;

        fn unsupported_command(size: u32) -> crate::library::CommandInput {
            let mut bytes = vec![0u8; size as usize];
            bytes[..2].copy_from_slice(&[0x80, 0x01]);
            bytes[2..6].copy_from_slice(&size.to_be_bytes());
            bytes[6..10].copy_from_slice(&[0x20, 0x00, 0x00, 0x00]);
            crate::library::CommandInput::new(size, bytes)
        }

        #[track_caller]
        fn response_code(library: &Library, size: u32) -> u32 {
            let ProcessPreparation::Tpm2(context) = library.prepare_process() else {
                panic!("TPM 2 must be selected");
            };
            let response = context.execute(&unsupported_command(size)).unwrap();
            u32::from_be_bytes(response[6..10].try_into().unwrap())
        }

        const COMMAND_CODE: u32 = 0x143;

        let library = tpm2_library();
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);

        assert_eq!(response_code(&library, 4096), COMMAND_CODE);
        assert_eq!(buffer_size(&library, 2808), 2808);
        assert_eq!(response_code(&library, 2808), COMMAND_CODE);
        assert_eq!(response_code(&library, 2809), TPM_RC_COMMAND_SIZE);
        assert_eq!(response_code(&library, 4096), TPM_RC_COMMAND_SIZE);

        assert_eq!(buffer_size(&library, 4096), 4096);
        assert_eq!(
            response_code(&library, 4096),
            COMMAND_CODE,
            "restoring the maximum restores the original behavior"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn the_configured_buffer_size_is_reported_by_get_capability() {
        const MAX_COMMAND_SIZE: u32 = 0x11e;
        const MAX_RESPONSE_SIZE: u32 = 0x11f;

        #[track_caller]
        fn reported(library: &Library, property: u32) -> u32 {
            let mut bytes = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
            bytes.extend_from_slice(&0x0000_017au32.to_be_bytes());
            bytes.extend_from_slice(&6u32.to_be_bytes());
            bytes.extend_from_slice(&property.to_be_bytes());
            bytes.extend_from_slice(&1u32.to_be_bytes());
            let input = crate::library::CommandInput::new(bytes.len() as u32, bytes);
            let ProcessPreparation::Tpm2(context) = library.prepare_process() else {
                panic!("TPM 2 must be selected");
            };
            let response = context.execute(&input).unwrap();
            assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
            assert_eq!(&response[19..23], &property.to_be_bytes());
            u32::from_be_bytes(response[23..27].try_into().unwrap())
        }

        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.main_init(), TPM_SUCCESS);
        let startup = crate::library::CommandInput::new(
            12,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ],
        );
        let ProcessPreparation::Tpm2(context) = library.prepare_process() else {
            panic!("TPM 2 must be selected");
        };
        context.execute(&startup).unwrap();

        assert_eq!(reported(&library, MAX_COMMAND_SIZE), 4096);
        assert_eq!(reported(&library, MAX_RESPONSE_SIZE), 4096);
        assert_eq!(buffer_size(&library, 2808), 2808);
        assert_eq!(reported(&library, MAX_COMMAND_SIZE), 2808);
        assert_eq!(reported(&library, MAX_RESPONSE_SIZE), 2808);
        assert_eq!(
            library.get_tpm_property(TPMPROP_TPM_BUFFER_MAX),
            Some(4096),
            "TPMPROP_TPM_BUFFER_MAX stays the compile-time maximum"
        );
        library.terminate();
    }

    #[test]
    fn set_buffer_size_without_a_tpm2_selection_reports_nothing() {
        let library = Library::new();
        for wanted_size in [0u32, 1, 2808, 4096, u32::MAX] {
            assert_eq!(library.set_buffer_size(wanted_size), None);
        }
    }

    #[test]
    fn register_callbacks_stores_table() {
        unsafe extern "C" fn dummy_init() -> TpmResult {
            TPM_SUCCESS
        }
        let library = Library::new();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(dummy_init),
            ..LibtpmsCallbacks::empty()
        });
        assert!(library.lock_state().callbacks.tpm_nvram_init.is_some());
    }

    #[cfg(all(feature = "tpm1", feature = "tpm2"))]
    #[test]
    fn switching_versions_clears_preloaded_state() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, vec![1, 2, 3]);
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Volatile);
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2),
            TPM_SUCCESS
        );
        let state = library.lock_state();
        assert!(!state.preloaded_state.is_present(StateBlobKind::Permanent));
        assert!(!state.preloaded_state.is_present(StateBlobKind::Volatile));
        assert!(!state.preloaded_state.is_present(StateBlobKind::SaveState));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn preloaded_empty_initializes_without_manufacture_and_is_consumed() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Missing,
            "the staged entry is consumed on success"
        );
        assert!(library.lock_state().tpm2_runtime.is_some());
        assert!(!library.was_manufactured(), "no Manufacture ran");
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failed_preloaded_empty_init_preserves_the_staged_entry() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Permanent);
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, vec![0xd0, 0x0d]);
        assert_eq!(
            library.main_init(),
            crate::library::constants::TPM_RC_FAILURE
        );
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Empty,
            "the staged entry must survive a failed MainInit"
        );
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Volatile),
            PreloadedBlob::Data(vec![0xd0, 0x0d])
        );
        assert!(library.lock_state().tpm2_runtime.is_none());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_permanent_state_initializes_and_consumes_the_staged_blob() {
        const INFO_ACTIVE_PROFILE: crate::ffi::types::TpmlibInfoFlags = 32;

        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::valid_permanent_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, blob.clone());
        assert_eq!(
            library.get_info(INFO_ACTIVE_PROFILE).as_deref(),
            Some("{}"),
            "no active profile before a successful MainInit"
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Missing,
            "the staged blob is consumed on success"
        );
        assert!(library.lock_state().tpm2_runtime.is_some());
        assert!(
            !library.was_manufactured(),
            "a restore never reports TPMLIB_WasManufactured"
        );
        let info = library.get_info(INFO_ACTIVE_PROFILE).unwrap();
        assert!(
            info.contains(r#""ActiveProfile":{"Name":"null","StateFormatLevel":1"#),
            "{info}"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    static BACKEND_BLOB: std::sync::LazyLock<Vec<u8>> =
        std::sync::LazyLock::new(crate::library::tpm2::valid_permanent_state_fixture);

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn loaddata_backend_fixture(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        use crate::library::constants::TPM_RETRY;
        if unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes() != b"permall" {
            return TPM_RETRY;
        }
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&BACKEND_BLOB);
            *length = BACKEND_BLOB.len() as u32;
        }
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn backend_loaded_permanent_state_initializes() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_backend_fixture),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(library.lock_state().tpm2_runtime.is_some());
        assert!(!library.was_manufactured());
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn commit_phase_failure_preserves_preloaded_state_and_publishes_nothing() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::commit_failing_permanent_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, blob.clone());
        for attempt in 0..2 {
            assert_eq!(library.main_init(), TPM_FAIL, "attempt {attempt}");
            assert_eq!(
                *library
                    .lock_state()
                    .preloaded_state
                    .get(StateBlobKind::Permanent),
                PreloadedBlob::Data(blob.clone()),
                "attempt {attempt}: the staged blob survives a commit failure"
            );
            assert!(library.lock_state().tpm2_runtime.is_none());
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn repeated_main_init_after_success_follows_library_semantics() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::valid_permanent_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, blob);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(library.lock_state().tpm2_runtime.is_some());
        assert_eq!(
            library.main_init(),
            TPM_FAIL,
            "no staged state and no backend: the manufacture boundary"
        );
        assert!(
            library.lock_state().tpm2_runtime.is_none(),
            "a failed re-init publishes no stale runtime"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn successful_main_init_consumes_both_staged_entries() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::valid_permanent_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, blob);
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Volatile);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        let state = library.lock_state();
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Missing
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Missing,
            "the preloaded-empty volatile entry is consumed on success"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_boundary_failure_preserves_both_staged_blobs() {
        const INFO_ACTIVE_PROFILE: crate::ffi::types::TpmlibInfoFlags = 32;

        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = vec![0xd0, 0x0d];
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, permanent.clone());
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, volatile.clone());
        for attempt in 0..2 {
            assert_eq!(
                library.main_init(),
                crate::library::constants::TPM_RC_FAILURE,
                "attempt {attempt}"
            );
            let state = library.lock_state();
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Permanent),
                PreloadedBlob::Data(permanent.clone()),
                "attempt {attempt}: the staged permanent blob survives"
            );
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Volatile),
                PreloadedBlob::Data(volatile.clone()),
                "attempt {attempt}: the staged volatile blob survives"
            );
            assert!(state.tpm2_runtime.is_none());
            drop(state);
            assert_eq!(
                library.get_info(INFO_ACTIVE_PROFILE).as_deref(),
                Some("{}"),
                "attempt {attempt}: no ActiveProfile without a published runtime"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn bad_volatile_digest_preserves_both_staged_blobs() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let mut volatile = crate::library::tpm2::valid_volatile_state_fixture();
        let last = volatile.len() - 1;
        volatile[last] ^= 0xff;
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, permanent.clone());
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, volatile.clone());
        for attempt in 0..2 {
            assert_eq!(
                library.main_init(),
                crate::library::constants::TPM_RC_FAILURE,
                "attempt {attempt}"
            );
            let state = library.lock_state();
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Permanent),
                PreloadedBlob::Data(permanent.clone()),
                "attempt {attempt}: the staged permanent blob survives"
            );
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Volatile),
                PreloadedBlob::Data(volatile.clone()),
                "attempt {attempt}: the staged volatile blob survives"
            );
            assert!(state.tpm2_runtime.is_none());
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_volatile_state_restores_and_consumes_both_entries() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();
        for round in 0..2 {
            library
                .lock_state()
                .preloaded_state
                .set_data(StateBlobKind::Permanent, permanent.clone());
            library
                .lock_state()
                .preloaded_state
                .set_data(StateBlobKind::Volatile, volatile.clone());
            assert_eq!(library.main_init(), TPM_SUCCESS, "round {round}");
            let state = library.lock_state();
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Permanent),
                PreloadedBlob::Missing,
                "round {round}: the permanent entry is consumed"
            );
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Volatile),
                PreloadedBlob::Missing,
                "round {round}: the volatile entry is consumed"
            );
            assert!(state.tpm2_runtime.is_some(), "round {round}");
            drop(state);
            library.terminate();
            assert!(library.lock_state().tpm2_runtime.is_none());
        }
    }

    #[cfg(feature = "tpm2")]
    static MANUFACTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(feature = "tpm2")]
    static BACKEND_PERMALL: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
    #[cfg(feature = "tpm2")]
    static BACKEND_STORES: std::sync::Mutex<u32> = std::sync::Mutex::new(0);

    #[cfg(feature = "tpm2")]
    fn requested_name(name: *const core::ffi::c_char) -> String {
        // SAFETY: the library passes a NUL-terminated state name.
        unsafe { core::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned()
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn loaddata_backend(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        use crate::library::constants::TPM_RETRY;
        if requested_name(name) != "permall" {
            return TPM_RETRY;
        }
        let Some(blob) = BACKEND_PERMALL.lock().unwrap().clone() else {
            return TPM_RETRY;
        };
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&blob);
            *length = blob.len() as u32;
        }
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn storedata_backend(
        data: *const core::ffi::c_uchar,
        length: u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        assert_eq!(requested_name(name), "permall");
        // SAFETY: the host may read `length` bytes per the contract.
        let bytes = unsafe { core::slice::from_raw_parts(data, length as usize) }.to_vec();
        *BACKEND_PERMALL.lock().unwrap() = Some(bytes);
        *BACKEND_STORES.lock().unwrap() += 1;
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x3c;
        }
        Ok(())
    }

    #[cfg(feature = "tpm2")]
    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    #[cfg(feature = "tpm2")]
    fn manufacture_library() -> Library {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_backend),
            tpm_nvram_storedata: Some(storedata_backend),
            ..LibtpmsCallbacks::empty()
        });
        library.lock_state().entropy_override = Some(deterministic_entropy);
        library
    }

    #[cfg(feature = "tpm2")]
    const INFO_ACTIVE_PROFILE: crate::ffi::types::TpmlibInfoFlags = 32;

    #[cfg(feature = "tpm2")]
    #[test]
    fn first_boot_manufactures_then_restarts_without_remanufacturing() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();

        assert!(!library.was_manufactured(), "nothing ran yet");
        assert_eq!(
            library.get_info(INFO_ACTIVE_PROFILE).as_deref(),
            Some("{}"),
            "no ActiveProfile before a successful MainInit"
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(
            library.was_manufactured(),
            "TPMLIB_WasManufactured after a first-boot Manufacture"
        );
        assert_eq!(*BACKEND_STORES.lock().unwrap(), 1, "one permall store");
        let stored = BACKEND_PERMALL.lock().unwrap().clone().unwrap();
        assert!(!stored.is_empty());
        let info = library.get_info(INFO_ACTIVE_PROFILE).unwrap();
        assert!(
            info.contains(r#""ActiveProfile":{"Name":"null","StateFormatLevel":1"#),
            "{info}"
        );

        library.terminate();
        assert!(
            !library.was_manufactured(),
            "termination drops the manufactured runtime"
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(
            !library.was_manufactured(),
            "a restored-state MainInit never reports was_manufactured"
        );
        assert_eq!(
            *BACKEND_STORES.lock().unwrap(),
            1,
            "the backend restore performs no NvCommit"
        );
        assert_eq!(
            *BACKEND_PERMALL.lock().unwrap(),
            Some(stored),
            "the stored blob is untouched by the restart"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn manufactured_tpm_accepts_exactly_one_startup_clear() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.main_init(), TPM_SUCCESS);

        let startup = crate::library::CommandInput::new(
            12,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ],
        );
        let stores_before = *BACKEND_STORES.lock().unwrap();
        let ProcessPreparation::Tpm2(context) = library.prepare_process() else {
            panic!("TPM 2 must be selected");
        };
        let response = context.execute(&startup).unwrap();
        assert_eq!(
            response,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00],
            "TPM2_Startup(TPM_SU_CLEAR) succeeds after a first-boot manufacture"
        );
        assert_eq!(
            *BACKEND_STORES.lock().unwrap(),
            stores_before + 1,
            "the abstract commit reaches tpm_nvram_storedata"
        );
        assert!(BACKEND_PERMALL.lock().unwrap().is_some());

        let ProcessPreparation::Tpm2(context) = library.prepare_process() else {
            panic!("TPM 2 must be selected");
        };
        let response = context.execute(&startup).unwrap();
        assert_eq!(
            response,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x00],
            "a repeated startup answers TPM_RC_INITIALIZE"
        );
        assert_eq!(
            *BACKEND_STORES.lock().unwrap(),
            stores_before + 1,
            "TPM_RC_INITIALIZE performs no host commit"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn terminate_allows_a_clean_remanufacture() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(library.was_manufactured());
        library.terminate();
        *BACKEND_PERMALL.lock().unwrap() = None;
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library.lock_state().entropy_override = Some(deterministic_entropy);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(library.was_manufactured(), "a clean re-manufacture");
        assert_eq!(*BACKEND_STORES.lock().unwrap(), 2);
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn set_profile_configures_validates_and_locks_after_power_on() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();

        assert_eq!(library.set_profile(Some(b"not json")), TPM_FAIL);
        assert!(library.lock_state().configured_profile.is_none());

        let profile = br#"{"Name":"default-v1"}"#;
        assert_eq!(library.set_profile(Some(profile)), TPM_SUCCESS);
        assert_eq!(
            library.lock_state().configured_profile.as_deref(),
            Some(&profile[..])
        );

        assert_eq!(
            library.set_profile(Some(br#"{"Name":"unknown-profile"}"#)),
            TPM_FAIL
        );
        assert_eq!(
            library.set_profile(Some(br#"{"Name":"default-v1","Commands":"0x11f"}"#)),
            TPM_FAIL,
            "non-modifiable profiles reject customization"
        );
        assert_eq!(
            library.lock_state().configured_profile.as_deref(),
            Some(&profile[..])
        );

        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(library.was_manufactured());
        let info = library.get_info(INFO_ACTIVE_PROFILE).unwrap();
        assert!(
            info.contains(r#""ActiveProfile":{"Name":"default-v1","StateFormatLevel":7"#),
            "{info}"
        );

        assert_eq!(
            library.set_profile(Some(br#"{"Name":"null"}"#)),
            crate::library::constants::TPM_INVALID_POSTINIT
        );
        assert_eq!(
            library.set_profile(None),
            crate::library::constants::TPM_INVALID_POSTINIT
        );
        assert_eq!(
            library.lock_state().configured_profile.as_deref(),
            Some(&profile[..])
        );

        library.terminate();
        assert!(library.lock_state().configured_profile.is_none());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn set_profile_null_clears_the_configuration() {
        let library = manufacture_library();
        assert_eq!(
            library.set_profile(Some(br#"{"Name":"default-v1"}"#)),
            TPM_SUCCESS
        );
        assert_eq!(library.set_profile(None), TPM_SUCCESS);
        assert!(library.lock_state().configured_profile.is_none());
    }

    #[test]
    fn set_profile_without_tpm2_selection_fails() {
        let library = Library::new();
        assert_eq!(library.set_profile(Some(br#"{"Name":"null"}"#)), TPM_FAIL);
        assert_eq!(library.set_profile(None), TPM_FAIL);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn entropy_failure_is_transactional_and_retryable() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        library.lock_state().entropy_override = Some(failing_entropy);
        let profile = br#"{"Name":"default-v1"}"#;
        assert_eq!(library.set_profile(Some(profile)), TPM_SUCCESS);
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, vec![0xd0, 0x0d]);

        for attempt in 0..2 {
            assert_eq!(library.main_init(), TPM_FAIL, "attempt {attempt}");
            let state = library.lock_state();
            assert!(state.tpm2_runtime.is_none(), "attempt {attempt}");
            assert_eq!(
                *state.preloaded_state.get(StateBlobKind::Volatile),
                PreloadedBlob::Data(vec![0xd0, 0x0d]),
                "attempt {attempt}: the staged volatile entry survives"
            );
            assert_eq!(
                state.configured_profile.as_deref(),
                Some(&profile[..]),
                "attempt {attempt}: the configured profile survives"
            );
            drop(state);
            assert!(!library.was_manufactured(), "attempt {attempt}");
            assert_eq!(
                library.get_info(INFO_ACTIVE_PROFILE).as_deref(),
                Some("{}"),
                "attempt {attempt}: no ActiveProfile"
            );
            assert!(
                BACKEND_PERMALL.lock().unwrap().is_none(),
                "attempt {attempt}: nothing was stored"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failed_main_init_does_not_consume_preloaded_data() {
        use crate::library::constants::TPM_RC_INSUFFICIENT;

        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, vec![4, 5, 6]);
        assert_eq!(library.main_init(), TPM_RC_INSUFFICIENT);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Data(vec![4, 5, 6]),
            "the staged bytes must survive a failed MainInit unmodified"
        );
        assert!(!library.was_manufactured());
        assert!(library.lock_state().tpm2_runtime.is_none());
    }

    #[test]
    fn tis_calls_without_a_selected_tpm2_fail() {
        let library = Library::new();
        assert_eq!(library.tis_established_get(), Err(TPM_FAIL));
        assert_eq!(library.tis_established_reset(), TPM_FAIL);
        assert_eq!(library.tis_hash_start(), TPM_FAIL);
        assert_eq!(library.tis_hash_data(&[1, 2]), TPM_FAIL);
        assert_eq!(library.tis_hash_end(), TPM_FAIL);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tis_calls_without_an_initialized_runtime_fail() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(library.tis_established_get(), Err(TPM_FAIL));
        assert_eq!(library.tis_established_reset(), TPM_FAIL);
        assert_eq!(library.tis_hash_start(), TPM_FAIL);
        assert_eq!(library.tis_hash_data(&[]), TPM_FAIL);
        assert_eq!(library.tis_hash_end(), TPM_FAIL);
    }

    #[cfg(feature = "tpm2")]
    static TIS_LOCALITY: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn tis_locality_callback(
        locality: *mut crate::ffi::types::TpmModifierIndicator,
        _tpm_number: u32,
    ) -> TpmResult {
        // SAFETY: the library passes a live out-pointer per the contract.
        unsafe { *locality = TIS_LOCALITY.load(std::sync::atomic::Ordering::SeqCst) };
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tis_established_lifecycle_through_the_library() {
        use std::sync::atomic::Ordering;

        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.main_init(), TPM_SUCCESS);

        assert_eq!(library.tis_established_get(), Ok(false));
        assert_eq!(library.tis_hash_data(&[1]), TPM_SUCCESS, "no-op data");
        assert_eq!(library.tis_hash_end(), TPM_SUCCESS, "no-op end");
        assert_eq!(library.tis_hash_start(), TPM_SUCCESS);
        assert_eq!(library.tis_established_get(), Ok(true));

        assert_eq!(
            library.tis_established_reset(),
            crate::library::constants::TPM_BAD_LOCALITY,
            "no locality callback: the host locality defaults to 0"
        );
        assert_eq!(library.tis_established_get(), Ok(true));

        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_backend),
            tpm_nvram_storedata: Some(storedata_backend),
            tpm_io_getlocality: Some(tis_locality_callback),
            ..LibtpmsCallbacks::empty()
        });
        for locality in [0u32, 1, 2, 5] {
            TIS_LOCALITY.store(locality, Ordering::SeqCst);
            assert_eq!(
                library.tis_established_reset(),
                crate::library::constants::TPM_BAD_LOCALITY,
                "locality {locality}"
            );
            assert_eq!(library.tis_established_get(), Ok(true));
        }
        TIS_LOCALITY.store(3, Ordering::SeqCst);
        assert_eq!(library.tis_established_reset(), TPM_SUCCESS);
        assert_eq!(library.tis_established_get(), Ok(false));

        assert_eq!(library.tis_hash_start(), TPM_SUCCESS);
        TIS_LOCALITY.store(4, Ordering::SeqCst);
        assert_eq!(library.tis_established_reset(), TPM_SUCCESS);
        assert_eq!(library.tis_established_get(), Ok(false));

        library.terminate();
        assert_eq!(library.tis_established_get(), Err(TPM_FAIL));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn restored_volatile_state_preserves_the_established_flag() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Volatile,
            crate::library::tpm2::valid_volatile_state_fixture(),
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            library.tis_established_get(),
            Ok(true),
            "the fixture's tpmEstablished bit reaches the active runtime"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    const ALL_KINDS: [StateBlobKind; 3] = [
        StateBlobKind::Permanent,
        StateBlobKind::Volatile,
        StateBlobKind::SaveState,
    ];

    #[test]
    fn state_transfer_without_a_tpm2_selection_fails() {
        let library = Library::new();
        for kind in [
            StateBlobKind::Permanent,
            StateBlobKind::Volatile,
            StateBlobKind::SaveState,
        ] {
            assert_eq!(library.set_state(kind, StateInput::Empty), TPM_FAIL);
            assert_eq!(
                library.set_state(kind, StateInput::Data(vec![1, 2, 3])),
                TPM_FAIL
            );
            assert_eq!(library.get_state(kind), Err(TPM_FAIL));
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn an_empty_input_stages_an_empty_cached_state_for_every_kind() {
        let library = tpm2_library();
        for kind in ALL_KINDS {
            assert_eq!(library.set_state(kind, StateInput::Empty), TPM_SUCCESS);
            assert_eq!(
                *library.lock_state().preloaded_state.get(kind),
                PreloadedBlob::Empty
            );
            assert_eq!(library.get_state(kind), Ok(StateOutput::Empty));
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_nonempty_save_state_is_rejected_with_the_upstream_code() {
        use crate::library::constants::TPM_BAD_TYPE;

        let library = tpm2_library();
        assert_eq!(
            library.set_state(StateBlobKind::SaveState, StateInput::Data(vec![1])),
            TPM_BAD_TYPE
        );
        assert_eq!(
            library.set_state(StateBlobKind::SaveState, StateInput::Data(Vec::new())),
            TPM_BAD_TYPE,
            "a zero-length blob is still not an explicitly empty state"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_permanent_state_is_cached_byte_for_byte() {
        let library = tpm2_library();
        let blob = crate::library::tpm2::valid_permanent_state_fixture();
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Data(blob.clone())),
            TPM_SUCCESS
        );
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Data(blob.clone()),
            "the original bytes are cached, not a reserialized form"
        );
        assert_eq!(
            library.get_state(StateBlobKind::Permanent),
            Ok(StateOutput::Data(blob))
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn malformed_permanent_state_is_rejected_and_clears_every_cached_entry() {
        use crate::library::constants::TPM_RC_INSUFFICIENT;

        let library = tpm2_library();
        assert_eq!(
            library.set_state(StateBlobKind::SaveState, StateInput::Empty),
            TPM_SUCCESS
        );
        assert_eq!(
            library.set_state(StateBlobKind::Volatile, StateInput::Empty),
            TPM_SUCCESS
        );
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Data(vec![4, 5, 6])),
            TPM_RC_INSUFFICIENT
        );
        let state = library.lock_state();
        for kind in ALL_KINDS {
            assert_eq!(
                *state.preloaded_state.get(kind),
                PreloadedBlob::Missing,
                "upstream clears all cached state on a validation failure"
            );
        }
        assert!(state.tpm2_runtime.is_none(), "nothing was published");
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_volatile_state_validates_against_the_staged_permanent_state() {
        let library = tpm2_library();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();
        assert_eq!(
            library.set_state(
                StateBlobKind::Permanent,
                StateInput::Data(permanent.clone())
            ),
            TPM_SUCCESS
        );
        assert_eq!(
            library.set_state(StateBlobKind::Volatile, StateInput::Data(volatile.clone())),
            TPM_SUCCESS
        );
        let state = library.lock_state();
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Data(permanent)
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Data(volatile)
        );
        assert!(state.tpm2_runtime.is_none());
        drop(state);
        assert_eq!(library.main_init(), TPM_SUCCESS, "the pair really restores");
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_mismatched_volatile_seed_tie_is_rejected_and_clears_the_cache() {
        use crate::library::constants::TPM_RC_VALUE;

        let library = tpm2_library();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Data(permanent)),
            TPM_SUCCESS
        );
        assert_eq!(
            library.set_state(
                StateBlobKind::Volatile,
                StateInput::Data(crate::library::tpm2::seed_mismatched_volatile_state_fixture()),
            ),
            TPM_RC_VALUE
        );
        let state = library.lock_state();
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Missing,
            "the previously accepted permanent blob goes too"
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Missing
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_state_without_any_permanent_state_fails() {
        let library = tpm2_library();
        assert_eq!(
            library.set_state(
                StateBlobKind::Volatile,
                StateInput::Data(crate::library::tpm2::valid_volatile_state_fixture()),
            ),
            TPM_FAIL,
            "no cached permanent state and no NVRAM backend"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_state_against_an_empty_cached_permanent_state_fails() {
        use crate::library::constants::TPM_RC_INSUFFICIENT;

        let library = tpm2_library();
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Empty),
            TPM_SUCCESS
        );
        assert_eq!(
            library.set_state(
                StateBlobKind::Volatile,
                StateInput::Data(crate::library::tpm2::valid_volatile_state_fixture()),
            ),
            TPM_RC_INSUFFICIENT,
            "upstream unmarshals the empty cached state and runs out of bytes"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_state_falls_back_to_the_permanent_state_in_the_backend() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = tpm2_library();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_backend_fixture),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            library.set_state(
                StateBlobKind::Volatile,
                StateInput::Data(crate::library::tpm2::valid_volatile_state_fixture()),
            ),
            TPM_SUCCESS
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn state_data_is_refused_while_a_runtime_is_active_but_an_empty_state_is_not() {
        let library = tpm2_library();
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);

        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Data(permanent)),
            TPM_INVALID_POSTINIT
        );
        assert_eq!(
            library.set_state(StateBlobKind::Volatile, StateInput::Data(vec![1])),
            TPM_INVALID_POSTINIT
        );
        assert_eq!(
            library.set_state(StateBlobKind::SaveState, StateInput::Data(vec![1])),
            TPM_INVALID_POSTINIT,
            "the lifecycle check comes before the state-type check"
        );
        for kind in ALL_KINDS {
            assert_eq!(
                *library.lock_state().preloaded_state.get(kind),
                PreloadedBlob::Missing
            );
        }

        for kind in ALL_KINDS {
            assert_eq!(
                library.set_state(kind, StateInput::Empty),
                TPM_SUCCESS,
                "upstream caches an empty state before its powered-on check"
            );
            assert_eq!(
                *library.lock_state().preloaded_state.get(kind),
                PreloadedBlob::Empty
            );
        }

        library.terminate();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Data(permanent)),
            TPM_SUCCESS,
            "state is accepted again after Terminate"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_running_tpm_snapshots_each_state_kind() {
        let library = tpm2_library();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);

        let permanent = library
            .get_state(StateBlobKind::Permanent)
            .expect("a running TPM stores its permanent state");
        assert!(matches!(&permanent, StateOutput::Data(blob) if !blob.is_empty()));
        assert_eq!(
            library.get_state(StateBlobKind::Permanent),
            Ok(permanent),
            "the snapshot is stable across calls"
        );

        let StateOutput::Data(volatile) = library
            .get_state(StateBlobKind::Volatile)
            .expect("a running TPM stores its volatile state")
        else {
            panic!("a running TPM never answers an empty cached state");
        };
        let direct = library.volatile_all_store().expect("the same store");
        assert_eq!(
            (volatile.len(), &volatile[..6]),
            (direct.len(), &direct[..6]),
            "VOLATILE goes through the same store as TPMLIB_VolatileAll_Store; \
             only the resumed clock differs between two snapshots"
        );

        assert_eq!(
            library.get_state(StateBlobKind::SaveState),
            Ok(StateOutput::Data(Vec::new())),
            "a running TPM answers SAVE_STATE with a null buffer of length zero"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_stopped_tpm_copies_its_cached_state_without_consuming_it() {
        let library = tpm2_library();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, permanent.clone());
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, volatile.clone());

        for round in 0..3 {
            assert_eq!(
                library.get_state(StateBlobKind::Permanent),
                Ok(StateOutput::Data(permanent.clone())),
                "round {round}"
            );
            assert_eq!(
                library.get_state(StateBlobKind::Volatile),
                Ok(StateOutput::Data(volatile.clone())),
                "round {round}"
            );
        }
        let state = library.lock_state();
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Data(permanent)
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Data(volatile)
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_stopped_tpm_without_cache_or_backend_fails() {
        let library = tpm2_library();
        for kind in ALL_KINDS {
            assert_eq!(library.get_state(kind), Err(TPM_FAIL));
        }
    }

    #[cfg(feature = "tpm2")]
    static NVRAM_EVENTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn nvram_init_ok() -> TpmResult {
        NVRAM_EVENTS.lock().unwrap().push("init".to_owned());
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn nvram_init_error() -> TpmResult {
        NVRAM_EVENTS.lock().unwrap().push("init".to_owned());
        0x4242
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn loaddata_recording(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        NVRAM_EVENTS
            .lock()
            .unwrap()
            .push(format!("load:{}", requested_name(name)));
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&[0xa5, 0x5a]);
            *length = 2;
        }
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn loaddata_error(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        NVRAM_EVENTS
            .lock()
            .unwrap()
            .push(format!("load:{}", requested_name(name)));
        0x1357
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_missing_cache_falls_back_to_the_backend_in_upstream_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        NVRAM_EVENTS.lock().unwrap().clear();
        let library = tpm2_library();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_recording),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            library.get_state(StateBlobKind::Volatile),
            Ok(StateOutput::Data(vec![0xa5, 0x5a]))
        );
        assert_eq!(
            *NVRAM_EVENTS.lock().unwrap(),
            ["init".to_owned(), "load:volatilestate".to_owned()],
            "NVRAM initialization runs before the load"
        );

        NVRAM_EVENTS.lock().unwrap().clear();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, vec![7]);
        assert_eq!(
            library.get_state(StateBlobKind::Volatile),
            Ok(StateOutput::Data(vec![7]))
        );
        assert!(
            NVRAM_EVENTS.lock().unwrap().is_empty(),
            "a cached blob never reaches the backend"
        );

        NVRAM_EVENTS.lock().unwrap().clear();
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Volatile);
        assert_eq!(
            library.get_state(StateBlobKind::Volatile),
            Ok(StateOutput::Empty)
        );
        assert!(
            NVRAM_EVENTS.lock().unwrap().is_empty(),
            "an empty cached state never reaches the backend either"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn backend_error_codes_propagate_unchanged() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        NVRAM_EVENTS.lock().unwrap().clear();
        let library = tpm2_library();

        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_error),
            tpm_nvram_loaddata: Some(loaddata_recording),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(library.get_state(StateBlobKind::Permanent), Err(0x4242));
        assert_eq!(
            *NVRAM_EVENTS.lock().unwrap(),
            ["init".to_owned()],
            "a failed initialization stops before the load"
        );

        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_error),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(library.get_state(StateBlobKind::Permanent), Err(0x1357));

        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_backend),
            ..LibtpmsCallbacks::empty()
        });
        *BACKEND_PERMALL.lock().unwrap() = None;
        assert_eq!(
            library.get_state(StateBlobKind::Permanent),
            Err(crate::library::constants::TPM_RETRY),
            "an absent blob is reported with the callback's own code"
        );

        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            library.get_state(StateBlobKind::Permanent),
            Err(TPM_FAIL),
            "no load callback: nothing can be read back"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_validation_reports_the_upstream_parser_result() {
        use crate::library::constants::{
            TPM_RC_BAD_TAG, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_VALUE,
        };

        let valid = crate::library::tpm2::valid_volatile_state_fixture();

        let truncated = valid[..valid.len() / 2].to_vec();
        let mut bad_digest = valid.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0xff;

        for (blob, expected, what) in [
            (Vec::new(), TPM_RC_INSUFFICIENT, "an empty blob"),
            (truncated, TPM_RC_INSUFFICIENT, "a truncated blob"),
            (
                crate::library::tpm2::bad_tag_volatile_state_fixture(),
                TPM_RC_BAD_TAG,
                "a bad trailing magic",
            ),
            (bad_digest, TPM_RC_HASH, "a bad checksum"),
            (
                crate::library::tpm2::seed_mismatched_volatile_state_fixture(),
                TPM_RC_VALUE,
                "a seed tie mismatch",
            ),
        ] {
            let library = tpm2_library();
            library.lock_state().preloaded_state.set_data(
                StateBlobKind::Permanent,
                crate::library::tpm2::valid_permanent_state_fixture(),
            );
            assert_eq!(
                library.set_state(StateBlobKind::Volatile, StateInput::Data(blob)),
                expected,
                "{what}"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_restore_still_collapses_every_volatile_error_into_one_code() {
        use crate::library::constants::TPM_RC_FAILURE;

        let valid = crate::library::tpm2::valid_volatile_state_fixture();
        for blob in [
            valid[..valid.len() / 2].to_vec(),
            crate::library::tpm2::bad_tag_volatile_state_fixture(),
            crate::library::tpm2::seed_mismatched_volatile_state_fixture(),
        ] {
            let library = tpm2_library();
            library.lock_state().preloaded_state.set_data(
                StateBlobKind::Permanent,
                crate::library::tpm2::valid_permanent_state_fixture(),
            );
            library
                .lock_state()
                .preloaded_state
                .set_data(StateBlobKind::Volatile, blob);
            assert_eq!(library.main_init(), TPM_RC_FAILURE);
        }
    }

    const VALIDATE_PERMANENT: c_int = 1;
    const VALIDATE_VOLATILE: c_int = 2;
    const VALIDATE_SAVE_STATE: c_int = 4;

    fn validation_mask(bits: c_int) -> StateValidationMask {
        StateValidationMask::from_c(bits)
    }

    #[test]
    fn validation_without_a_tpm2_selection_fails() {
        let library = Library::new();
        for bits in [
            0,
            VALIDATE_PERMANENT,
            VALIDATE_VOLATILE,
            VALIDATE_SAVE_STATE,
            VALIDATE_PERMANENT | VALIDATE_VOLATILE | VALIDATE_SAVE_STATE,
            -1,
        ] {
            assert_eq!(
                library.validate_state(validation_mask(bits)),
                TPM_FAIL,
                "mask {bits}"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    static BACKEND_VOLATILESTATE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn loaddata_state_backend(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        use crate::library::constants::TPM_RETRY;
        let name = requested_name(name);
        NVRAM_EVENTS.lock().unwrap().push(format!("load:{name}"));
        let blob = match name.as_str() {
            "permall" => BACKEND_PERMALL.lock().unwrap().clone(),
            "volatilestate" => BACKEND_VOLATILESTATE.lock().unwrap().clone(),
            _ => None,
        };
        let Some(blob) = blob else {
            return TPM_RETRY;
        };
        // SAFETY: out-pointers are valid per the callback contract; the
        // buffer is malloc'ed and ownership transfers to the caller.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&blob);
            *length = blob.len() as u32;
        }
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn loaddata_zero_length_blob(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        NVRAM_EVENTS
            .lock()
            .unwrap()
            .push(format!("load:{}", requested_name(name)));
        // SAFETY: out-pointers are valid per the callback contract; the
        // one-byte allocation is handed over with a declared length of zero.
        unsafe {
            *data = crate::ffi::memory::malloc_bytes(&[0]);
            *length = 0;
        }
        TPM_SUCCESS
    }

    #[cfg(feature = "tpm2")]
    struct ValidationFixture {
        library: Library,
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    #[cfg(feature = "tpm2")]
    impl ValidationFixture {
        fn new() -> Self {
            let serial = MANUFACTURE_LOCK
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let fixture = Self {
                library: tpm2_library(),
                _serial: serial,
            };
            fixture.clear_backend();
            fixture
        }

        fn clear_backend(&self) {
            NVRAM_EVENTS.lock().unwrap().clear();
            *BACKEND_PERMALL.lock().unwrap() = None;
            *BACKEND_VOLATILESTATE.lock().unwrap() = None;
            *BACKEND_STORES.lock().unwrap() = 0;
        }

        fn restart(&mut self) {
            self.library = tpm2_library();
            self.clear_backend();
        }

        fn with_backend(&self) {
            self.library.register_callbacks(LibtpmsCallbacks {
                tpm_nvram_init: Some(nvram_init_ok),
                tpm_nvram_loaddata: Some(loaddata_state_backend),
                ..LibtpmsCallbacks::empty()
            });
        }

        fn cache(&self, kind: StateBlobKind, blob: Vec<u8>) {
            self.library
                .lock_state()
                .preloaded_state
                .set_data(kind, blob);
        }

        fn accept(&self, kind: StateBlobKind, blob: Vec<u8>) {
            assert_eq!(
                self.library.set_state(kind, StateInput::Data(blob)),
                TPM_SUCCESS,
                "the fixture blob must be accepted by SetState"
            );
        }

        fn events(&self) -> Vec<String> {
            NVRAM_EVENTS.lock().unwrap().clone()
        }

        fn forget_events(&self) {
            NVRAM_EVENTS.lock().unwrap().clear();
        }

        fn validate(&self, bits: c_int) -> TpmResult {
            self.library.validate_state(validation_mask(bits))
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn an_empty_mask_still_runs_the_nvram_initialization() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        assert_eq!(fixture.validate(0), TPM_SUCCESS);
        assert_eq!(
            fixture.events(),
            ["init".to_owned()],
            "upstream calls tpm_nvram_init before it looks at any bit"
        );

        fixture.forget_events();
        fixture.library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_error),
            tpm_nvram_loaddata: Some(loaddata_state_backend),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(fixture.validate(0), 0x4242);
        assert_eq!(fixture.events(), ["init".to_owned()]);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn unknown_bits_validate_nothing_at_all() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        for bits in [8, 16, 1 << 30, i32::MIN] {
            fixture.forget_events();
            assert_eq!(fixture.validate(bits), TPM_SUCCESS, "mask {bits}");
            assert_eq!(fixture.events(), ["init".to_owned()], "mask {bits}");
        }

        *BACKEND_PERMALL.lock().unwrap() = Some(vec![1, 2, 3]);
        fixture.forget_events();
        assert_eq!(
            fixture.validate(8 | VALIDATE_PERMANENT),
            crate::library::constants::TPM_RC_INSUFFICIENT,
            "a known bit still selects its state next to an unknown one"
        );
        assert_eq!(
            fixture.events(),
            ["init".to_owned(), "load:permall".to_owned()]
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn permanent_validation_reads_the_backend_blob_and_never_the_cache() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() =
            Some(crate::library::tpm2::valid_permanent_state_fixture());

        for bits in [
            VALIDATE_PERMANENT,
            VALIDATE_SAVE_STATE,
            VALIDATE_PERMANENT | VALIDATE_SAVE_STATE,
        ] {
            fixture.forget_events();
            assert_eq!(fixture.validate(bits), TPM_SUCCESS, "mask {bits}");
            assert_eq!(
                fixture.events(),
                ["init".to_owned(), "load:permall".to_owned()],
                "mask {bits} reads permall exactly once and nothing else"
            );
        }

        fixture.cache(StateBlobKind::Permanent, vec![1, 2, 3]);
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            TPM_SUCCESS,
            "TPM2_ValidateState calls tpm_nvram_loaddata(TPM_PERMANENT_ALL_NAME) itself \
             instead of consulting the cached state the way VolatileLoad does"
        );

        *BACKEND_PERMALL.lock().unwrap() = None;
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            crate::library::constants::TPM_RETRY,
            "a cached blob cannot stand in for a missing backend blob"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn malformed_permanent_state_reports_the_exact_parser_code() {
        use crate::library::constants::{TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT};

        let valid = crate::library::tpm2::valid_permanent_state_fixture();

        let mut cut_payload = valid[..valid.len() / 2].to_vec();
        cut_payload.extend_from_slice(&valid[valid.len() - 4..]);
        let cut_footer = valid[..valid.len() / 2].to_vec();
        let mut bad_footer = valid.clone();
        let last = bad_footer.len() - 1;
        bad_footer[last] ^= 0xff;
        let mut bad_version = valid.clone();
        bad_version[6] = 0x00;
        bad_version[7] = 0x63;

        let fixture = ValidationFixture::new();
        fixture.with_backend();
        for (blob, expected, what) in [
            (cut_payload, TPM_RC_INSUFFICIENT, "a truncated payload"),
            (cut_footer, TPM_RC_BAD_TAG, "a blob cut before its footer"),
            (bad_footer, TPM_RC_BAD_TAG, "a bad trailing magic"),
            (bad_version, TPM_RC_BAD_VERSION, "an unsupported version"),
            (
                valid[..3].to_vec(),
                TPM_RC_INSUFFICIENT,
                "a stub of a header",
            ),
            (vec![1, 2, 3], TPM_RC_INSUFFICIENT, "a stray blob"),
        ] {
            *BACKEND_PERMALL.lock().unwrap() = Some(blob);
            assert_eq!(fixture.validate(VALIDATE_PERMANENT), expected, "{what}");
            assert_eq!(
                fixture.validate(VALIDATE_SAVE_STATE),
                expected,
                "{what}, through the save-state bit"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_permanent_blob_the_backend_cannot_produce_is_told_apart_from_a_zero_length_one() {
        use crate::library::constants::{TPM_RC_INSUFFICIENT, TPM_RETRY};

        let fixture = ValidationFixture::new();
        fixture.with_backend();
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            TPM_RETRY,
            "no permall at the backend"
        );

        *BACKEND_PERMALL.lock().unwrap() = Some(Vec::new());
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            TPM_FAIL,
            "success without a buffer is upstream's `if (!data) return TPM_FAIL`"
        );

        fixture.library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_zero_length_blob),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            TPM_RC_INSUFFICIENT,
            "a real buffer of zero length reaches the parser"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_validation_runs_against_the_permanent_state() {
        let mut fixture = ValidationFixture::new();
        fixture.with_backend();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();

        fixture.accept(StateBlobKind::Permanent, permanent.clone());
        fixture.accept(StateBlobKind::Volatile, volatile.clone());
        fixture.forget_events();
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_SUCCESS);
        assert_eq!(
            fixture.events(),
            ["init".to_owned()],
            "the cached blob is decoded against the permanent state SetState installed"
        );

        fixture.restart();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(permanent.clone());
        fixture.cache(StateBlobKind::Volatile, volatile.clone());
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE),
            TPM_SUCCESS
        );
        assert_eq!(
            fixture.events(),
            ["init".to_owned(), "load:permall".to_owned()],
            "the permanent blob loaded for its own bit is reused as the context"
        );

        fixture.restart();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(permanent);
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatile);
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE | VALIDATE_SAVE_STATE),
            TPM_SUCCESS
        );
        assert_eq!(
            fixture.events(),
            [
                "init".to_owned(),
                "load:permall".to_owned(),
                "load:volatilestate".to_owned()
            ],
            "permanent state is validated before volatile state"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_malformed_permanent_blob_stops_the_volatile_step() {
        use crate::library::constants::TPM_RC_INSUFFICIENT;

        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(vec![1, 2, 3]);
        *BACKEND_VOLATILESTATE.lock().unwrap() =
            Some(crate::library::tpm2::valid_volatile_state_fixture());
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE),
            TPM_RC_INSUFFICIENT
        );
        assert_eq!(
            fixture.events(),
            ["init".to_owned(), "load:permall".to_owned()],
            "the volatile blob is never fetched once the permanent one failed"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn malformed_volatile_state_reports_the_exact_parser_codes() {
        use crate::library::constants::{
            TPM_RC_BAD_TAG, TPM_RC_HASH, TPM_RC_INSUFFICIENT, TPM_RC_VALUE,
        };

        let valid = crate::library::tpm2::valid_volatile_state_fixture();
        let truncated = valid[..valid.len() / 2].to_vec();
        let mut bad_digest = valid.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0xff;

        for (blob, expected, what) in [
            (truncated, TPM_RC_INSUFFICIENT, "a truncated blob"),
            (
                crate::library::tpm2::bad_tag_volatile_state_fixture(),
                TPM_RC_BAD_TAG,
                "a bad trailing magic",
            ),
            (bad_digest, TPM_RC_HASH, "a bad checksum"),
            (
                crate::library::tpm2::seed_mismatched_volatile_state_fixture(),
                TPM_RC_VALUE,
                "a seed tie mismatch",
            ),
        ] {
            let mut fixture = ValidationFixture::new();
            fixture.with_backend();
            fixture.accept(
                StateBlobKind::Permanent,
                crate::library::tpm2::valid_permanent_state_fixture(),
            );
            fixture.cache(StateBlobKind::Volatile, blob.clone());
            assert_eq!(fixture.validate(VALIDATE_VOLATILE), expected, "{what}");

            fixture.restart();
            fixture.with_backend();
            *BACKEND_PERMALL.lock().unwrap() =
                Some(crate::library::tpm2::valid_permanent_state_fixture());
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(blob);
            assert_eq!(
                fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE),
                expected,
                "{what}, from the backend"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_failure_mode_volatile_blob_validates_but_never_restores() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        fixture.accept(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        fixture.cache(
            StateBlobKind::Volatile,
            crate::library::tpm2::failure_mode_volatile_state_fixture(),
        );
        assert_eq!(
            fixture.validate(VALIDATE_VOLATILE),
            TPM_SUCCESS,
            "validation reports the parser result, not the restore boundary"
        );
        assert!(fixture.library.lock_state().tpm2_runtime.is_none());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn an_explicitly_empty_cached_volatile_state_validates_successfully() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(vec![1, 2, 3]);
        fixture
            .library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Volatile);
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_SUCCESS);
        assert_eq!(
            fixture.events(),
            ["init".to_owned()],
            "an empty cached state never reaches the backend"
        );

        fixture.forget_events();
        *BACKEND_PERMALL.lock().unwrap() =
            Some(crate::library::tpm2::valid_permanent_state_fixture());
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE),
            TPM_SUCCESS
        );
        assert_eq!(
            fixture.events(),
            ["init".to_owned(), "load:permall".to_owned()]
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_volatile_load_failure_is_swallowed_but_a_permanent_one_propagates() {
        let mut fixture = ValidationFixture::new();
        fixture.library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_error),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(fixture.validate(VALIDATE_PERMANENT), 0x1357);
        assert_eq!(fixture.validate(VALIDATE_SAVE_STATE), 0x1357);

        fixture.cache(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(
            fixture.validate(VALIDATE_VOLATILE),
            TPM_SUCCESS,
            "upstream VolatileLoad drops the load result and leaves rc untouched"
        );

        fixture.restart();
        fixture.with_backend();
        fixture.cache(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(
            fixture.validate(VALIDATE_VOLATILE),
            TPM_SUCCESS,
            "a missing volatile blob is not an error either"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn validation_without_backend_callbacks_follows_upstream() {
        let fixture = ValidationFixture::new();
        assert_eq!(fixture.validate(0), TPM_SUCCESS);
        assert_eq!(fixture.validate(VALIDATE_PERMANENT), TPM_FAIL);
        assert_eq!(fixture.validate(VALIDATE_SAVE_STATE), TPM_FAIL);
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE | VALIDATE_SAVE_STATE),
            TPM_FAIL,
            "the permanent step fails before the volatile one runs"
        );
        assert_eq!(
            fixture.validate(VALIDATE_VOLATILE),
            TPM_SUCCESS,
            "with nothing to load there is nothing to reject"
        );
        assert!(
            fixture.events().is_empty(),
            "an unregistered tpm_nvram_init is skipped, exactly as upstream does"
        );

        fixture.library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_state_backend),
            ..LibtpmsCallbacks::empty()
        });
        *BACKEND_PERMALL.lock().unwrap() =
            Some(crate::library::tpm2::valid_permanent_state_fixture());
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            TPM_SUCCESS,
            "a load callback alone is enough"
        );
        assert_eq!(fixture.events(), ["load:permall".to_owned()]);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn validation_leaves_every_piece_of_library_state_alone() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();
        *BACKEND_PERMALL.lock().unwrap() = Some(permanent.clone());
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatile.clone());

        fixture.library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_ok),
            tpm_nvram_loaddata: Some(loaddata_state_backend),
            tpm_nvram_storedata: Some(storedata_backend),
            ..LibtpmsCallbacks::empty()
        });
        assert_eq!(
            fixture.library.set_state(
                StateBlobKind::Permanent,
                StateInput::Data(permanent.clone())
            ),
            TPM_SUCCESS
        );
        assert_eq!(
            fixture
                .library
                .set_state(StateBlobKind::Volatile, StateInput::Data(volatile.clone())),
            TPM_SUCCESS
        );
        let profile = br#"{"Name":"default-v1"}"#;
        assert_eq!(
            fixture.library.set_profile(Some(profile)),
            TPM_SUCCESS,
            "the profile stays configured across the validation"
        );
        fixture.library.set_buffer_size(3000);
        let before = fixture.library.lock_state().lifecycle();
        *BACKEND_STORES.lock().unwrap() = 0;

        for _ in 0..2 {
            assert_eq!(
                fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE | VALIDATE_SAVE_STATE),
                TPM_SUCCESS,
                "the cached state is validated, not consumed"
            );
        }

        let state = fixture.library.lock_state();
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Data(permanent)
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Data(volatile)
        );
        assert!(state.tpm2_runtime.is_none(), "no runtime is ever published");
        assert_eq!(state.selected, TpmVersion::V2_0);
        assert_eq!(state.tpm2_buffer_size, 3000);
        assert_eq!(state.configured_profile.as_deref(), Some(&profile[..]));
        assert!(!state.version_locked);
        assert_eq!(state.lifecycle(), before, "the lifecycle never moves");
        assert!(state.callbacks.tpm_nvram_storedata.is_some());
        assert!(
            state.installed_permanent.is_some(),
            "the decoded permanent state is installed, as upstream unmarshals it into its NV image"
        );
        drop(state);
        assert_eq!(
            *BACKEND_STORES.lock().unwrap(),
            0,
            "nothing is committed to host NVRAM"
        );
    }

    #[cfg(feature = "tpm2")]
    const VALIDATE_STATE_ORACLE: &str = include_str!("tpm2/testdata/validate_state_oracle.txt");

    #[cfg(feature = "tpm2")]
    fn oracle(scenario: &str) -> (TpmResult, Vec<String>) {
        for line in VALIDATE_STATE_ORACLE.lines() {
            let mut fields = line.split('\t');
            let (Some(name), Some(result)) = (fields.next(), fields.next()) else {
                continue;
            };
            if name != scenario {
                continue;
            }
            let result = TpmResult::from_str_radix(result.trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("{scenario}: unparsable oracle result {result}"));
            let events = match fields.next().unwrap_or("") {
                "" => Vec::new(),
                events => events.split(',').map(str::to_owned).collect(),
            };
            return (result, events);
        }
        panic!("{scenario} is missing from the oracle fixture");
    }

    #[cfg(feature = "tpm2")]
    impl ValidationFixture {
        fn assert_oracle(&self, scenario: &str, result: TpmResult) {
            let (expected, events) = oracle(scenario);
            assert_eq!(result, expected, "{scenario}: vendored C result");
            assert_eq!(self.events(), events, "{scenario}: vendored C callbacks");
        }

        fn permall(&self) -> Vec<u8> {
            crate::library::tpm2::valid_permanent_state_fixture()
        }

        fn volatilestate(&self) -> Vec<u8> {
            crate::library::tpm2::valid_volatile_state_fixture()
        }

        fn malformed_volatile_matrix(&self) -> Vec<(&'static str, Vec<u8>)> {
            let valid = self.volatilestate();
            let mut bad_digest = valid.clone();
            let last = bad_digest.len() - 1;
            bad_digest[last] ^= 0xff;
            let mut bad_header_magic = valid.clone();
            bad_header_magic[3] ^= 0xff;
            vec![
                ("valid_volatile", valid.clone()),
                ("truncated_volatile", valid[..valid.len() / 2].to_vec()),
                ("bad_digest_volatile", bad_digest),
                (
                    "bad_trailing_magic_volatile",
                    crate::library::tpm2::bad_tag_volatile_state_fixture(),
                ),
                (
                    "seed_mismatch_volatile",
                    crate::library::tpm2::seed_mismatched_volatile_state_fixture(),
                ),
                ("bad_header_magic_volatile", bad_header_magic),
            ]
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn every_c_oracle_scenario_is_replayed() {
        let replayed = [
            "permanent_only",
            "save_state_only",
            "combined_permanent_volatile",
            "permanent_then_volatile_only.permanent",
            "permanent_then_volatile_only.volatile",
            "save_state_then_volatile_only.save_state",
            "save_state_then_volatile_only.volatile",
            "failed_permanent_then_volatile_only.permanent",
            "failed_permanent_then_volatile_only.volatile",
            "combined_seed_mismatch_then_volatile_only.combined",
            "combined_seed_mismatch_then_volatile_only.volatile",
            "cached_volatile_no_backend_permall",
            "backend_volatile_no_backend_permall",
            "backend_truncated_volatile_no_backend_permall",
            "backend_bad_digest_volatile_no_backend_permall",
            "no_volatile_anywhere",
            "empty_cached_volatile",
            "installed_then_empty_cached_permanent",
            "empty_cached_permanent_nothing_installed",
            "changed_backend_permall",
            "failed_set_state_volatile_then_volatile_only.set_state",
            "failed_set_state_volatile_then_volatile_only.volatile",
            "installed_bad_trailing_magic_volatile",
            "installed_seed_mismatch_volatile",
            "installed_bad_header_magic_volatile",
            "nothing_installed_valid_volatile",
            "nothing_installed_truncated_volatile",
            "nothing_installed_bad_digest_volatile",
            "nothing_installed_bad_trailing_magic_volatile",
            "nothing_installed_seed_mismatch_volatile",
            "nothing_installed_bad_header_magic_volatile",
            "installed_object_rsa",
            "installed_object_ecc",
            "installed_object_aes128",
            "installed_object_aes192",
            "nothing_installed_object_rsa",
            "nothing_installed_object_ecc",
            "nothing_installed_object_aes128",
            "nothing_installed_object_aes192",
            "running_tpm",
        ];
        let recorded: Vec<&str> = VALIDATE_STATE_ORACLE
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split('\t').next())
            .collect();
        assert_eq!(recorded, replayed);
        for scenario in replayed {
            let _ = oracle(scenario);
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn permanent_selecting_masks_match_the_c_oracle() {
        let mut fixture = ValidationFixture::new();
        for (scenario, bits) in [
            ("permanent_only", VALIDATE_PERMANENT),
            ("save_state_only", VALIDATE_SAVE_STATE),
            (
                "combined_permanent_volatile",
                VALIDATE_PERMANENT | VALIDATE_VOLATILE,
            ),
        ] {
            fixture.restart();
            fixture.with_backend();
            *BACKEND_PERMALL.lock().unwrap() = Some(fixture.permall());
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(fixture.volatilestate());
            fixture.forget_events();
            let result = fixture.validate(bits);
            fixture.assert_oracle(scenario, result);
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_only_validation_matches_the_c_oracle() {
        let mut fixture = ValidationFixture::new();
        let permall = fixture.permall();
        let volatilestate = fixture.volatilestate();

        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        fixture.accept(StateBlobKind::Volatile, volatilestate.clone());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("cached_volatile_no_backend_permall", result);

        fixture.restart();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatilestate.clone());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("backend_volatile_no_backend_permall", result);

        fixture.restart();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        *BACKEND_VOLATILESTATE.lock().unwrap() =
            Some(volatilestate[..volatilestate.len() / 2].to_vec());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("backend_truncated_volatile_no_backend_permall", result);

        let mut bad_digest = volatilestate.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0xff;
        fixture.restart();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(bad_digest);
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("backend_bad_digest_volatile_no_backend_permall", result);

        fixture.restart();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("no_volatile_anywhere", result);

        fixture.restart();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        assert_eq!(
            fixture
                .library
                .set_state(StateBlobKind::Volatile, StateInput::Empty),
            TPM_SUCCESS
        );
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatilestate.clone());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("empty_cached_volatile", result);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_volatile_only_mask_never_consults_the_permanent_backend() {
        let mut fixture = ValidationFixture::new();
        let permall = fixture.permall();
        let volatilestate = fixture.volatilestate();

        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall.clone());
        fixture.accept(StateBlobKind::Volatile, volatilestate.clone());
        assert_eq!(
            fixture
                .library
                .set_state(StateBlobKind::Permanent, StateInput::Empty),
            TPM_SUCCESS
        );
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("installed_then_empty_cached_permanent", result);

        fixture.restart();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, permall);
        fixture.accept(StateBlobKind::Volatile, volatilestate.clone());
        *BACKEND_PERMALL.lock().unwrap() = Some(vec![1, 2, 3]);
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("changed_backend_permall", result);

        fixture.restart();
        fixture.with_backend();
        assert_eq!(
            fixture
                .library
                .set_state(StateBlobKind::Permanent, StateInput::Empty),
            TPM_SUCCESS
        );
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatilestate);
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("empty_cached_permanent_nothing_installed", result);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_volatile_blob_without_any_installed_permanent_state_matches_the_c_oracle() {
        let mut fixture = ValidationFixture::new();
        for (scenario, blob) in fixture.malformed_volatile_matrix() {
            fixture.restart();
            fixture.with_backend();
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(blob);
            fixture.forget_events();
            let result = fixture.validate(VALIDATE_VOLATILE);
            fixture.assert_oracle(&format!("nothing_installed_{scenario}"), result);
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_volatile_blob_against_installed_permanent_state_matches_the_c_oracle() {
        let mut fixture = ValidationFixture::new();
        let permall = fixture.permall();
        const INSTALLED: [&str; 3] = [
            "bad_trailing_magic_volatile",
            "seed_mismatch_volatile",
            "bad_header_magic_volatile",
        ];
        for (scenario, blob) in fixture.malformed_volatile_matrix() {
            if !INSTALLED.contains(&scenario) {
                continue;
            }
            fixture.restart();
            fixture.with_backend();
            fixture.accept(StateBlobKind::Permanent, permall.clone());
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(blob);
            fixture.forget_events();
            let result = fixture.validate(VALIDATE_VOLATILE);
            fixture.assert_oracle(&format!("installed_{scenario}"), result);
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_permanent_validation_installs_the_state_it_decoded() {
        let mut fixture = ValidationFixture::new();
        let permall = fixture.permall();
        let volatilestate = fixture.volatilestate();

        for (scenario, bits) in [
            ("permanent_then_volatile_only", VALIDATE_PERMANENT),
            ("save_state_then_volatile_only", VALIDATE_SAVE_STATE),
        ] {
            let step = if bits == VALIDATE_PERMANENT {
                "permanent"
            } else {
                "save_state"
            };
            fixture.restart();
            fixture.with_backend();
            *BACKEND_PERMALL.lock().unwrap() = Some(permall.clone());
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatilestate.clone());
            fixture.forget_events();
            let result = fixture.validate(bits);
            fixture.assert_oracle(&format!("{scenario}.{step}"), result);

            *BACKEND_PERMALL.lock().unwrap() = None;
            fixture.forget_events();
            let result = fixture.validate(VALIDATE_VOLATILE);
            fixture.assert_oracle(&format!("{scenario}.volatile"), result);
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_failed_permanent_validation_installs_nothing() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(vec![1, 2, 3]);
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(fixture.volatilestate());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_PERMANENT);
        fixture.assert_oracle("failed_permanent_then_volatile_only.permanent", result);
        assert!(fixture.library.lock_state().installed_permanent.is_none());

        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("failed_permanent_then_volatile_only.volatile", result);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_failed_volatile_step_keeps_the_permanent_state_it_installed() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(fixture.permall());
        *BACKEND_VOLATILESTATE.lock().unwrap() =
            Some(crate::library::tpm2::seed_mismatched_volatile_state_fixture());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_PERMANENT | VALIDATE_VOLATILE);
        fixture.assert_oracle("combined_seed_mismatch_then_volatile_only.combined", result);

        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(fixture.volatilestate());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("combined_seed_mismatch_then_volatile_only.volatile", result);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_failed_volatile_set_state_installs_the_permanent_state_it_loaded() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(fixture.permall());
        fixture.forget_events();
        let result = fixture.library.set_state(
            StateBlobKind::Volatile,
            StateInput::Data(crate::library::tpm2::seed_mismatched_volatile_state_fixture()),
        );
        fixture.assert_oracle(
            "failed_set_state_volatile_then_volatile_only.set_state",
            result,
        );
        assert!(
            fixture.library.lock_state().installed_permanent.is_some(),
            "the permanent state the rejected blob was validated against stays installed"
        );

        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(fixture.volatilestate());
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle(
            "failed_set_state_volatile_then_volatile_only.volatile",
            result,
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_objects_follow_the_installed_state_format_level() {
        let mut fixture = ValidationFixture::new();
        let permall = fixture.permall();
        let objects = [
            (
                "rsa",
                crate::library::tpm2::rsa_object_volatile_state_fixture(),
            ),
            (
                "ecc",
                crate::library::tpm2::ecc_object_volatile_state_fixture(),
            ),
            (
                "aes128",
                crate::library::tpm2::symmetric_object_volatile_state_fixture(128),
            ),
            (
                "aes192",
                crate::library::tpm2::symmetric_object_volatile_state_fixture(192),
            ),
        ];
        for (kind, blob) in objects {
            fixture.restart();
            fixture.with_backend();
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(blob.clone());
            fixture.forget_events();
            let result = fixture.validate(VALIDATE_VOLATILE);
            fixture.assert_oracle(&format!("nothing_installed_object_{kind}"), result);

            fixture.restart();
            fixture.with_backend();
            fixture.accept(StateBlobKind::Permanent, permall.clone());
            *BACKEND_VOLATILESTATE.lock().unwrap() = Some(blob);
            fixture.forget_events();
            let result = fixture.validate(VALIDATE_VOLATILE);
            fixture.assert_oracle(&format!("installed_object_{kind}"), result);
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_running_tpm_validates_volatile_state_against_its_own_runtime() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(fixture.permall());
        assert_eq!(fixture.library.main_init(), TPM_SUCCESS);
        let running = fixture
            .library
            .volatile_all_store()
            .expect("a running TPM snapshots its volatile state");
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(running);
        *BACKEND_PERMALL.lock().unwrap() = None;
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("running_tpm", result);
        assert!(fixture.library.lock_state().tpm2_runtime.is_some());
        fixture.library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn terminate_clears_the_installed_permanent_context() {
        use crate::library::constants::TPM_RC_VALUE;

        let fixture = ValidationFixture::new();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, fixture.permall());
        fixture.accept(StateBlobKind::Volatile, fixture.volatilestate());
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_SUCCESS);

        fixture.library.terminate();
        assert!(fixture.library.lock_state().installed_permanent.is_none());
        assert_eq!(
            fixture.validate(VALIDATE_VOLATILE),
            TPM_RC_VALUE,
            "the superseded lifecycle takes its permanent context with it"
        );
    }

    #[cfg(all(feature = "tpm1", feature = "tpm2"))]
    #[test]
    fn a_version_switch_clears_the_installed_permanent_context() {
        use crate::library::constants::TPM_RC_VALUE;

        let fixture = ValidationFixture::new();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, fixture.permall());
        let volatilestate = fixture.volatilestate();
        fixture.accept(StateBlobKind::Volatile, volatilestate.clone());
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_SUCCESS);

        assert_eq!(
            fixture.library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2),
            TPM_SUCCESS
        );
        assert_eq!(
            fixture.library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert!(fixture.library.lock_state().installed_permanent.is_none());
        fixture.cache(StateBlobKind::Volatile, volatilestate);
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_RC_VALUE);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_cached_malformed_volatile_blob_reports_the_same_code_as_the_backend() {
        let mut fixture = ValidationFixture::new();
        let permall = fixture.permall();
        let volatilestate = fixture.volatilestate();
        let truncated = volatilestate[..volatilestate.len() / 2].to_vec();
        let mut bad_digest = volatilestate;
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0xff;

        for (blob, scenario) in [
            (truncated, "backend_truncated_volatile_no_backend_permall"),
            (bad_digest, "backend_bad_digest_volatile_no_backend_permall"),
        ] {
            fixture.restart();
            fixture.with_backend();
            fixture.accept(StateBlobKind::Permanent, permall.clone());
            fixture.cache(StateBlobKind::Volatile, blob);
            fixture.forget_events();
            let result = fixture.validate(VALIDATE_VOLATILE);
            let (expected, _) = oracle(scenario);
            assert_eq!(
                result, expected,
                "{scenario}: upstream VolatileLoad decodes cached and backend \
                 blobs through the same VolatileState_Load"
            );
            assert!(
                fixture.events() == ["init".to_owned()],
                "a cached blob reaches no backend at all"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn validation_alongside_a_running_tpm_reports_the_blob_it_was_given() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() =
            Some(crate::library::tpm2::valid_permanent_state_fixture());
        assert_eq!(fixture.library.main_init(), TPM_SUCCESS);
        let locality = fixture.library.tpm2_runtime_locality();

        assert_eq!(fixture.validate(VALIDATE_PERMANENT), TPM_SUCCESS);
        *BACKEND_PERMALL.lock().unwrap() = Some(vec![1, 2, 3]);
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            crate::library::constants::TPM_RC_INSUFFICIENT
        );

        assert!(
            fixture.library.lock_state().tpm2_runtime.is_some(),
            "the running TPM is untouched by either validation"
        );
        assert_eq!(fixture.library.tpm2_runtime_locality(), locality);
        fixture.library.terminate();
    }

    #[cfg(feature = "tpm2")]
    mod gate {
        use std::sync::{Condvar, Mutex, PoisonError};
        use std::time::Duration;

        const TIMEOUT: Duration = Duration::from_secs(30);

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Phase {
            Idle,
            Parked,
            Released,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(super) enum Park {
            Parked,
            PassedThrough,
            TimedOut,
        }

        static PHASE: Mutex<Phase> = Mutex::new(Phase::Idle);
        static SIGNAL: Condvar = Condvar::new();
        static TIMED_OUT: Mutex<bool> = Mutex::new(false);

        pub(super) static SERIAL: Mutex<()> = Mutex::new(());

        pub(super) fn reset() {
            *PHASE.lock().unwrap_or_else(PoisonError::into_inner) = Phase::Idle;
            *TIMED_OUT.lock().unwrap_or_else(PoisonError::into_inner) = false;
        }

        pub(super) fn park() -> Park {
            let mut phase = PHASE.lock().unwrap_or_else(PoisonError::into_inner);
            if *phase != Phase::Idle {
                return Park::PassedThrough;
            }
            *phase = Phase::Parked;
            SIGNAL.notify_all();
            let (guard, wait) = SIGNAL
                .wait_timeout_while(phase, TIMEOUT, |phase| *phase != Phase::Released)
                .unwrap_or_else(PoisonError::into_inner);
            drop(guard);
            if wait.timed_out() {
                *TIMED_OUT.lock().unwrap_or_else(PoisonError::into_inner) = true;
                return Park::TimedOut;
            }
            Park::Parked
        }

        #[must_use]
        pub(super) fn wait_until_parked() -> bool {
            let phase = PHASE.lock().unwrap_or_else(PoisonError::into_inner);
            let (phase, wait) = SIGNAL
                .wait_timeout_while(phase, TIMEOUT, |phase| *phase == Phase::Idle)
                .unwrap_or_else(PoisonError::into_inner);
            !wait.timed_out() && *phase == Phase::Parked
        }

        pub(super) fn timed_out() -> bool {
            *TIMED_OUT.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub(super) struct Release;

        impl Drop for Release {
            fn drop(&mut self) {
                *PHASE.lock().unwrap_or_else(PoisonError::into_inner) = Phase::Released;
                SIGNAL.notify_all();
            }
        }
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn nvram_init_gate() -> TpmResult {
        match gate::park() {
            gate::Park::Parked | gate::Park::PassedThrough => TPM_SUCCESS,
            gate::Park::TimedOut => TPM_FAIL,
        }
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn io_init_gate() -> TpmResult {
        match gate::park() {
            gate::Park::Parked | gate::Park::PassedThrough => TPM_SUCCESS,
            gate::Park::TimedOut => TPM_FAIL,
        }
    }

    #[cfg(feature = "tpm2")]
    unsafe extern "C" fn io_init_gate_failing_passthrough() -> TpmResult {
        match gate::park() {
            gate::Park::Parked => TPM_SUCCESS,
            gate::Park::PassedThrough | gate::Park::TimedOut => TPM_FAIL,
        }
    }

    #[cfg(feature = "tpm2")]
    fn gated_library() -> Library {
        let library = tpm2_library();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_nvram_init: Some(nvram_init_gate),
            tpm_nvram_loaddata: Some(loaddata_backend_fixture),
            ..LibtpmsCallbacks::empty()
        });
        library
    }

    #[cfg(feature = "tpm2")]
    fn stage_volatile_while(library: &Library, interfere: impl FnOnce(&Library)) -> TpmResult {
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();
        let result = std::thread::scope(|scope| {
            let staging = scope
                .spawn(|| library.set_state(StateBlobKind::Volatile, StateInput::Data(volatile)));
            let release = gate::Release;
            assert!(
                gate::wait_until_parked(),
                "timed out waiting for the staging thread to reach the gate"
            );
            interfere(library);
            drop(release);
            staging.join().expect("the staging thread never panics")
        });
        assert!(!gate::timed_out(), "the gated callback timed out");
        result
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn an_undisturbed_gated_validation_still_caches_the_blob() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        assert_eq!(stage_volatile_while(&library, |_| {}), TPM_SUCCESS);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Volatile),
            PreloadedBlob::Data(crate::library::tpm2::valid_volatile_state_fixture())
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_main_init_in_flight_rejects_a_blob_staged_behind_its_back() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = tpm2_library();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_io_init: Some(io_init_gate),
            ..LibtpmsCallbacks::empty()
        });
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();

        let staged = std::thread::scope(|scope| {
            let init = scope.spawn(|| library.main_init());
            let release = gate::Release;
            assert!(
                gate::wait_until_parked(),
                "timed out waiting for the MainInit to reach the gate"
            );
            let staged =
                library.set_state(StateBlobKind::Volatile, StateInput::Data(volatile.clone()));
            drop(release);
            assert_eq!(
                init.join().expect("the init thread never panics"),
                TPM_SUCCESS
            );
            staged
        });
        assert!(!gate::timed_out(), "the gated callback timed out");
        assert_eq!(
            staged, TPM_INVALID_POSTINIT,
            "the MainInit already copied the state this blob would have joined, \
             and would silently drop it when it finishes"
        );
        let state = library.lock_state();
        assert!(state.tpm2_runtime.is_some());
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Missing
        );
        drop(state);
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_main_init_never_loses_the_state_it_published() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = stage_volatile_while(&library, |library| {
            library.stage_empty_state(StateBlobKind::Permanent);
            assert_eq!(library.main_init(), TPM_SUCCESS);
        });
        assert_eq!(
            result, TPM_INVALID_POSTINIT,
            "a blob validated for a superseded lifecycle is never published"
        );
        let state = library.lock_state();
        assert!(
            state.tpm2_runtime.is_some(),
            "the runtime the concurrent MainInit published survives"
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Missing,
            "the late blob does not reappear behind the running TPM"
        );
        drop(state);
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_failing_main_init_also_discards_the_blob() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = stage_volatile_while(&library, |library| {
            library
                .lock_state()
                .preloaded_state
                .set_data(StateBlobKind::Permanent, vec![4, 5, 6]);
            assert_eq!(
                library.main_init(),
                crate::library::constants::TPM_RC_INSUFFICIENT
            );
        });
        assert_eq!(result, TPM_INVALID_POSTINIT);
        let state = library.lock_state();
        assert!(state.tpm2_runtime.is_none());
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Missing
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Data(vec![4, 5, 6]),
            "the failed MainInit keeps its own staged blob"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_terminate_discards_the_blob() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = stage_volatile_while(&library, Library::terminate);
        assert_eq!(result, TPM_INVALID_POSTINIT);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Volatile),
            PreloadedBlob::Missing
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_version_switch_discards_the_blob() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = stage_volatile_while(&library, |library| {
            library.lock_state().selected = TpmVersion::V1_2;
        });
        assert_eq!(result, TPM_FAIL);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Volatile),
            PreloadedBlob::Missing
        );
    }

    #[cfg(feature = "tpm2")]
    fn validate_state_while(library: &Library, interfere: impl FnOnce(&Library)) -> TpmResult {
        let result = std::thread::scope(|scope| {
            let validation =
                scope.spawn(|| library.validate_state(validation_mask(VALIDATE_PERMANENT)));
            let release = gate::Release;
            assert!(
                gate::wait_until_parked(),
                "timed out waiting for the validation thread to reach the gate"
            );
            interfere(library);
            drop(release);
            validation
                .join()
                .expect("the validation thread never panics")
        });
        assert!(!gate::timed_out(), "the gated callback timed out");
        result
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn an_undisturbed_gated_validation_reports_its_own_result() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, vec![1, 2, 3]);
        assert_eq!(validate_state_while(&library, |_| {}), TPM_SUCCESS);
        let state = library.lock_state();
        assert!(state.tpm2_runtime.is_none());
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Volatile),
            PreloadedBlob::Data(vec![1, 2, 3])
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_main_init_supersedes_a_validation_in_flight() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = validate_state_while(&library, |library| {
            assert_eq!(library.main_init(), TPM_SUCCESS);
        });
        assert_eq!(
            result, TPM_INVALID_POSTINIT,
            "a result computed for a superseded lifecycle is never reported as current"
        );
        assert!(
            library.lock_state().tpm2_runtime.is_some(),
            "the runtime the concurrent MainInit published survives"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_terminate_supersedes_a_validation_in_flight() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        assert_eq!(
            validate_state_while(&library, Library::terminate),
            TPM_INVALID_POSTINIT
        );
        assert!(library.lock_state().tpm2_runtime.is_none());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_concurrent_version_switch_supersedes_a_validation_in_flight() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = validate_state_while(&library, |library| {
            library.lock_state().selected = TpmVersion::V1_2;
        });
        assert_eq!(
            result, TPM_FAIL,
            "a TPM2 validation is never reported against a TPM 1.2 selection"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_second_main_init_cannot_take_over_the_first_ones_lifecycle() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = tpm2_library();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_io_init: Some(io_init_gate_failing_passthrough),
            ..LibtpmsCallbacks::empty()
        });
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();

        let (second_init, staged, first_init) = std::thread::scope(|scope| {
            let first = scope.spawn(|| library.main_init());
            let release = gate::Release;
            assert!(
                gate::wait_until_parked(),
                "timed out waiting for the first MainInit to reach the gate"
            );
            let second_init = library.main_init();
            let staged =
                library.set_state(StateBlobKind::Volatile, StateInput::Data(volatile.clone()));
            drop(release);
            let first_init = first.join().expect("the init thread never panics");
            (second_init, staged, first_init)
        });
        assert!(!gate::timed_out(), "the gated callback timed out");

        let state = library.lock_state();
        let cached = state.preloaded_state.get(StateBlobKind::Volatile).clone();
        drop(state);
        if staged == TPM_SUCCESS {
            assert_eq!(
                cached,
                PreloadedBlob::Data(volatile),
                "a SetState that reported success must never be discarded by a MainInit"
            );
        }

        assert_eq!(
            second_init, TPM_INVALID_POSTINIT,
            "a MainInit already in flight owns the lifecycle until it finishes"
        );
        assert_eq!(first_init, TPM_SUCCESS);
        assert_eq!(staged, TPM_INVALID_POSTINIT);
        assert_eq!(cached, PreloadedBlob::Missing);
        assert!(library.lock_state().tpm2_runtime.is_some());
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn sequential_main_init_calls_are_still_accepted() {
        let library = tpm2_library();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);
        library.terminate();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(
            library.main_init(),
            TPM_SUCCESS,
            "the lifecycle is released by every attempt"
        );
        library.terminate();
        assert_eq!(
            library.main_init(),
            TPM_FAIL,
            "no staged state and no backend, not a lifecycle rejection"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    fn init_while(library: &Library, interfere: impl FnOnce(&Library)) -> TpmResult {
        let result = std::thread::scope(|scope| {
            let init = scope.spawn(|| library.main_init());
            let release = gate::Release;
            assert!(
                gate::wait_until_parked(),
                "timed out waiting for the MainInit to reach the gate"
            );
            interfere(library);
            drop(release);
            init.join().expect("the init thread never panics")
        });
        assert!(!gate::timed_out(), "the gated callback timed out");
        result
    }

    #[cfg(feature = "tpm2")]
    fn gated_init_library() -> Library {
        let library = tpm2_library();
        library.register_callbacks(LibtpmsCallbacks {
            tpm_io_init: Some(io_init_gate),
            ..LibtpmsCallbacks::empty()
        });
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        library
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_terminate_during_main_init_discards_the_stale_runtime() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_init_library();
        let restaged = crate::library::tpm2::valid_permanent_state_fixture();

        let result = init_while(&library, |library| {
            library.terminate();
            library
                .lock_state()
                .preloaded_state
                .set_data(StateBlobKind::Permanent, restaged.clone());
        });

        let state = library.lock_state();
        assert!(
            state.tpm2_runtime.is_none(),
            "the stale runtime is dropped, never published over a completed Terminate"
        );
        assert_eq!(
            *state.preloaded_state.get(StateBlobKind::Permanent),
            PreloadedBlob::Data(restaged),
            "the newer lifecycle keeps the state staged for it"
        );
        assert!(
            !state.version_locked,
            "the completed Terminate stays effective"
        );
        assert!(
            state.initializing.is_none(),
            "the superseded attempt still releases the lifecycle it owned"
        );
        drop(state);
        assert_eq!(
            result, TPM_INVALID_POSTINIT,
            "a MainInit superseded by Terminate reports the lifecycle break"
        );
    }

    #[cfg(all(feature = "tpm1", feature = "tpm2"))]
    #[test]
    fn a_stale_main_init_cannot_overwrite_a_newer_tpm12_lifecycle() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_init_library();

        let result = init_while(&library, |library| {
            library.terminate();
            assert_eq!(
                library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2),
                TPM_SUCCESS
            );
        });

        let state = library.lock_state();
        assert_eq!(
            state.selected,
            TpmVersion::V1_2,
            "the newer selection survives the stale MainInit"
        );
        assert!(
            state.tpm2_runtime.is_none(),
            "a TPM 1.2 selection can never carry a published TPM2 runtime"
        );
        assert!(state.initializing.is_none());
        drop(state);
        assert_eq!(result, TPM_INVALID_POSTINIT);

        assert_eq!(library.volatile_all_store(), Err(TPM_FAIL));
        assert!(library.get_info(0).is_none());
        assert!(!library.was_manufactured());
        assert_eq!(
            library.set_state(StateBlobKind::Permanent, StateInput::Empty),
            TPM_FAIL,
            "state transfer dispatches to TPM 1.2 too"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_failure_mode_volatile_blob_validates_but_does_not_restore() {
        use crate::library::constants::TPM_RC_FAILURE;

        let blob = crate::library::tpm2::failure_mode_volatile_state_fixture();

        let library = tpm2_library();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(
            library.set_state(StateBlobKind::Volatile, StateInput::Data(blob.clone())),
            TPM_SUCCESS,
            "a structurally valid blob is accepted whatever its failure-mode flag says"
        );
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Volatile),
            PreloadedBlob::Data(blob.clone())
        );

        assert_eq!(
            library.main_init(),
            TPM_RC_FAILURE,
            "restoring the same blob still reaches the failure boundary"
        );
        assert!(library.lock_state().tpm2_runtime.is_none());
    }

    #[test]
    fn cancel_command_without_a_tpm2_selection_fails() {
        let library = Library::new();
        assert_eq!(
            library.cancel_command(),
            TPM_FAIL,
            "TPM 1.2 and the disabled interface answer TPM_FAIL"
        );
        assert!(!library.cancel_is_signaled());
    }

    #[cfg(feature = "tpm1")]
    #[test]
    fn cancel_command_after_selecting_tpm1_fails() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2),
            TPM_SUCCESS
        );
        assert_eq!(library.cancel_command(), TPM_FAIL);
        assert!(!library.cancel_is_signaled());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cancel_command_before_main_init_succeeds_without_raising_the_pin() {
        let library = tpm2_library();
        assert_eq!(
            library.cancel_command(),
            TPM_SUCCESS,
            "upstream returns success even with no command in flight"
        );
        assert!(
            !library.cancel_is_signaled(),
            "_rpc__Signal_CancelOn only sets the flag once power is on"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn selecting_tpm2_after_another_version_starts_answering_cancel() {
        let library = Library::new();
        assert_eq!(library.cancel_command(), TPM_FAIL);
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert_eq!(library.cancel_command(), TPM_SUCCESS);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cancel_command_is_idempotent_across_the_whole_lifecycle() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();

        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(!library.cancel_is_signaled(), "power-on clears the pin");
        for round in 0..4 {
            assert_eq!(library.cancel_command(), TPM_SUCCESS, "round {round}");
            assert!(library.cancel_is_signaled(), "round {round}");
        }

        library.terminate();
        assert!(
            library.cancel_is_signaled(),
            "_rpc__Signal_PowerOff leaves s_isCanceled alone"
        );
        for round in 0..4 {
            assert_eq!(
                library.cancel_command(),
                TPM_SUCCESS,
                "still dispatched to TPM 2.0, round {round}"
            );
        }

        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert!(
            !library.cancel_is_signaled(),
            "a request from the previous lifecycle cannot reach the new one"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cancel_command_does_not_wait_for_the_library_mutex() {
        let library = tpm2_library();
        let held = library.lock_state();
        assert_eq!(
            library.cancel_command(),
            TPM_SUCCESS,
            "the call completes while the command mutex is held elsewhere"
        );
        drop(held);
    }

    #[cfg(feature = "tpm2")]
    fn startup_clear() -> crate::library::CommandInput {
        crate::library::CommandInput::new(
            12,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ],
        )
    }

    #[cfg(feature = "tpm2")]
    fn incremental_self_test(algorithms: &[u16]) -> crate::library::CommandInput {
        let mut bytes = vec![0x80, 0x01];
        let size = 14 + 2 * algorithms.len() as u32;
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&0x0000_0142u32.to_be_bytes());
        bytes.extend_from_slice(&(algorithms.len() as u32).to_be_bytes());
        for &algorithm in algorithms {
            bytes.extend_from_slice(&algorithm.to_be_bytes());
        }
        crate::library::CommandInput::new(size, bytes)
    }

    #[cfg(feature = "tpm2")]
    #[track_caller]
    fn execute(library: &Library, command: &crate::library::CommandInput) -> Vec<u8> {
        let ProcessPreparation::Tpm2(context) = library.prepare_process() else {
            panic!("TPM 2 must be selected");
        };
        context.execute(command).expect("the response fits")
    }

    #[cfg(feature = "tpm2")]
    #[track_caller]
    fn response_code(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("a complete header"))
    }

    #[cfg(feature = "tpm2")]
    const TPM_ALG_SHA1: u16 = 0x0004;
    #[cfg(feature = "tpm2")]
    const TPM_ALG_SHA256: u16 = 0x000b;
    #[cfg(feature = "tpm2")]
    const TPM_ALG_AES: u16 = 0x0006;
    #[cfg(feature = "tpm2")]
    const TPM_ALG_ECDH: u16 = 0x0019;
    #[cfg(feature = "tpm2")]
    const TPM_ALG_SHA384: u16 = 0x000c;
    #[cfg(feature = "tpm2")]
    const TPM_ALG_SHA512: u16 = 0x000d;
    #[cfg(feature = "tpm2")]
    const TPM_ALG_OAEP: u16 = 0x0017;

    #[cfg(feature = "tpm2")]
    fn started_library() -> Library {
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        library
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_request_raised_before_a_command_starts_never_cancels_it() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = started_library();

        assert_eq!(library.cancel_command(), TPM_SUCCESS);
        assert!(library.cancel_is_signaled());
        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA1]));
        assert_eq!(response_code(&response), 0, "{response:02x?}");
        assert!(
            !library.cancel_is_signaled(),
            "the command start cleared it"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_request_raised_while_a_command_runs_is_visible_but_cancels_nothing() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let gate = tpm2::arm_self_test_gate();
        library.park_self_test_on_gate();
        let worker_library = Arc::clone(&library);
        let worker = std::thread::spawn(move || {
            let ProcessPreparation::Tpm2(context) = worker_library.prepare_process() else {
                panic!("TPM 2 must be selected");
            };
            context.execute(&incremental_self_test(&[TPM_ALG_SHA1, TPM_ALG_SHA256]))
        });

        gate.wait_until_entered();
        assert!(
            !library.cancel_is_signaled(),
            "the command start cleared the pin"
        );
        assert_eq!(
            library.cancel_command(),
            TPM_SUCCESS,
            "cancellation does not block on the command's mutex"
        );
        assert!(
            library.cancel_is_signaled(),
            "the request is published into the running lifecycle"
        );
        gate.release();

        let response = worker
            .join()
            .expect("the command thread finished")
            .expect("the response fits");
        assert_eq!(
            response_code(&response),
            0,
            "TPM2_IncrementalSelfTest reaches no upstream cancellation checkpoint"
        );
        assert_eq!(
            library.pending_self_test_algorithms(),
            [
                TPM_ALG_AES,
                TPM_ALG_SHA384,
                TPM_ALG_SHA512,
                TPM_ALG_OAEP,
                TPM_ALG_ECDH
            ],
            "both selected primitives ran to completion"
        );
        assert!(
            library.cancel_is_signaled(),
            "nothing clears the pin at command completion"
        );

        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA384]));
        assert_eq!(response_code(&response), 0);
        assert!(
            !library.cancel_is_signaled(),
            "the stale request is dropped by the next command start"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_request_delayed_across_terminate_publishes_nothing() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let park = library.arm_cancel_request_park();
        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || canceller_library.cancel_command());

        park.wait_until_entered();
        library.terminate();
        park.release();
        assert_eq!(
            canceller.join().expect("the request thread finished"),
            TPM_SUCCESS
        );
        assert!(
            !library.cancel_is_signaled(),
            "the lifecycle was powered off before the request published"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_request_delayed_across_a_restart_cannot_cancel_the_new_lifecycle() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let park = library.arm_cancel_request_park();
        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || canceller_library.cancel_command());
        park.wait_until_entered();

        library.terminate();
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);

        let gate = tpm2::arm_self_test_gate();
        library.park_self_test_on_gate();
        let worker_library = Arc::clone(&library);
        let worker = std::thread::spawn(move || {
            let ProcessPreparation::Tpm2(context) = worker_library.prepare_process() else {
                panic!("TPM 2 must be selected");
            };
            context.execute(&incremental_self_test(&[TPM_ALG_SHA1]))
        });
        gate.wait_until_entered();
        assert!(!library.cancel_is_signaled());

        park.release();
        assert_eq!(
            canceller.join().expect("the request thread finished"),
            TPM_SUCCESS
        );
        assert!(
            !library.cancel_is_signaled(),
            "an obsolete request must not reach a command of the new lifecycle"
        );

        assert_eq!(library.cancel_command(), TPM_SUCCESS);
        assert!(
            library.cancel_is_signaled(),
            "a fresh request for the live lifecycle still publishes"
        );

        gate.release();
        let response = worker
            .join()
            .expect("the command thread finished")
            .expect("the response fits");
        assert_eq!(response_code(&response), 0);
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn a_request_delayed_across_many_restarts_cannot_reach_the_newest_lifecycle() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let park = library.arm_cancel_request_park();
        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || canceller_library.cancel_command());
        park.wait_until_entered();

        for round in 0..6 {
            library.terminate();
            assert_eq!(library.main_init(), TPM_SUCCESS, "round {round}");
        }
        park.release();
        assert_eq!(
            canceller.join().expect("the request thread finished"),
            TPM_SUCCESS
        );
        assert!(!library.cancel_is_signaled());

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA1]));
        assert_eq!(response_code(&response), 0, "{response:02x?}");
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cancellation_racing_termination_leaves_the_library_usable() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || {
            for _ in 0..4096 {
                assert_eq!(canceller_library.cancel_command(), TPM_SUCCESS);
            }
        });

        for _ in 0..8 {
            library.terminate();
            assert_eq!(library.main_init(), TPM_SUCCESS);
        }
        canceller.join().expect("the canceller thread finished");

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA1]));
        assert_eq!(response_code(&response), 0, "{response:02x?}");
        library.terminate();
    }

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    #[test]
    fn cancellation_racing_version_selection_stays_consistent() {
        let library = Arc::new(tpm2_library());
        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || {
            for _ in 0..4096 {
                let code = canceller_library.cancel_command();
                assert!(code == TPM_SUCCESS || code == TPM_FAIL, "{code}");
            }
        });

        for _ in 0..256 {
            assert_eq!(
                library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2),
                TPM_SUCCESS
            );
            assert_eq!(
                library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
                TPM_SUCCESS
            );
        }
        canceller.join().expect("the canceller finished");
        assert!(
            !library.cancel_is_signaled(),
            "no lifecycle was ever powered on"
        );
    }
}
