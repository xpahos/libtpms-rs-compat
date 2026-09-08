use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::types::TpmResult;

use super::cancel::CommandCancellation;
#[cfg(feature = "tpm2")]
use super::constants::TPM_SIZE;
#[cfg(feature = "tpm2")]
use super::constants::{TPM_BAD_TYPE, TPM_INVALID_POSTINIT};
use super::constants::{TPM_BUFFER_MAX, TPM_FAIL, TPM_SUCCESS};
use super::platform::Platform;
#[cfg(feature = "tpm2")]
use super::preloaded_state::PreloadedBlob;
use super::preloaded_state::PreloadedState;
use super::services::ExternalServices;
use super::state_blob::{StateBlobKind, StateInput, StateOutput, StateValidationMask};
use super::storage::Storage;

#[cfg(feature = "tpm2")]
use super::tpm2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TpmVersion {
    V1_2,
    V2_0,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TpmProperty {
    RsaKeyLengthMax,
    BufferMax,
    KeyHandles,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InformationFlags(u32);

impl InformationFlags {
    pub const TPM_SPECIFICATION: Self = Self(1);
    pub const TPM_ATTRIBUTES: Self = Self(2);
    pub const TPM_FEATURES: Self = Self(4);
    pub const RUNTIME_ALGORITHMS: Self = Self(8);
    pub const RUNTIME_COMMANDS: Self = Self(16);
    pub const ACTIVE_PROFILE: Self = Self(32);
    pub const AVAILABLE_PROFILES: Self = Self(64);
    pub const RUNTIME_ATTRIBUTES: Self = Self(128);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[cfg(feature = "tpm2")]
    pub(crate) const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }
}

impl core::ops::BitOr for InformationFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BufferSizeLimits {
    pub current: u32,
    pub minimum: u32,
    pub maximum: u32,
}

struct TpmState {
    selected: TpmVersion,
    version_locked: bool,
    preloaded_state: PreloadedState,
    services: ExternalServices,
    #[cfg(feature = "tpm2")]
    tpm2_buffer_size: u32,
    #[cfg(feature = "tpm2")]
    configured_profile: Option<Vec<u8>>,
    #[cfg(feature = "tpm2")]
    installed_permanent: Option<tpm2::VolatileValidationContext>,
    #[cfg(all(test, feature = "tpm2"))]
    entropy_override: Option<tpm2::EntropySource>,
}

impl TpmState {
    fn new(services: ExternalServices) -> Self {
        Self {
            selected: crate::library::TpmVersion::V1_2,
            version_locked: false,
            preloaded_state: PreloadedState::new(),
            services,
            #[cfg(feature = "tpm2")]
            tpm2_buffer_size: tpm2::DEFAULT_BUFFER_SIZE,
            #[cfg(feature = "tpm2")]
            configured_profile: None,
            #[cfg(feature = "tpm2")]
            installed_permanent: None,
            #[cfg(all(test, feature = "tpm2"))]
            entropy_override: None,
        }
    }

    fn set_version(&mut self, version: TpmVersion) -> TpmResult {
        if self.version_locked {
            return TPM_FAIL;
        }
        let requested = match version {
            crate::library::TpmVersion::V1_2 if cfg!(feature = "tpm1") => {
                crate::library::TpmVersion::V1_2
            }
            crate::library::TpmVersion::V2_0 if cfg!(feature = "tpm2") => {
                crate::library::TpmVersion::V2_0
            }
            _ => return TPM_FAIL,
        };
        if self.selected != requested {
            self.clear_preloaded_state();
        }
        self.selected = requested;
        TPM_SUCCESS
    }

    fn clear_preloaded_state(&mut self) {
        self.preloaded_state.clear_all();
        #[cfg(feature = "tpm2")]
        {
            self.installed_permanent = None;
        }
    }
}

pub struct Tpm {
    state: Mutex<TpmState>,
    #[cfg(feature = "tpm2")]
    runtime: Mutex<Option<tpm2::Tpm2Runtime>>,
    cancellation: CommandCancellation,
    #[cfg(all(test, feature = "tpm2"))]
    empty_state_gate: Mutex<Option<EmptyStateGate>>,
}

#[cfg(all(test, feature = "tpm2"))]
type EmptyStateGate = Arc<dyn Fn(EmptyStatePhase) + Send + Sync>;

#[cfg(all(test, feature = "tpm2"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library) enum EmptyStatePhase {
    BeforeRuntimeLock,
    AfterRuntimeLock,
}

#[cfg(feature = "tpm2")]
struct Tpm2Access<'a> {
    runtime: MutexGuard<'a, Option<tpm2::Tpm2Runtime>>,
    services: ExternalServices,
}

impl Tpm {
    pub fn new(services: ExternalServices) -> Self {
        Self {
            state: Mutex::new(TpmState::new(services)),
            #[cfg(feature = "tpm2")]
            runtime: Mutex::new(None),
            cancellation: CommandCancellation::new(),
            #[cfg(all(test, feature = "tpm2"))]
            empty_state_gate: Mutex::new(None),
        }
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn set_empty_state_gate(&self, gate: EmptyStateGate) {
        *self
            .empty_state_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(gate);
    }

    #[cfg(all(test, feature = "tpm2"))]
    fn fire_empty_state_gate(&self, phase: EmptyStatePhase) {
        let gate = self
            .empty_state_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(gate) = gate {
            gate(phase);
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, TpmState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(feature = "tpm2")]
    fn lock_runtime(&self) -> MutexGuard<'_, Option<tpm2::Tpm2Runtime>> {
        self.runtime.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(feature = "tpm2")]
    fn acquire_tpm2(&self) -> Result<Tpm2Access<'_>, TpmResult> {
        let runtime = self.lock_runtime();
        let state = self.lock_state();
        if state.selected != crate::library::TpmVersion::V2_0 {
            return Err(TPM_FAIL);
        }
        let services = state.services.clone();
        drop(state);
        Ok(Tpm2Access { runtime, services })
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn state_is_unlocked(&self) -> bool {
        !matches!(
            self.state.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn runtime_is_unlocked(&self) -> bool {
        !matches!(
            self.runtime.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    }

    pub fn set_version(&self, version: TpmVersion) -> TpmResult {
        self.lock_state().set_version(version)
    }

    #[cfg(feature = "tpm2")]
    pub(crate) fn tpm2_selected(&self) -> bool {
        self.lock_state().selected == crate::library::TpmVersion::V2_0
    }

    pub fn cancel(&self) -> TpmResult {
        match self.lock_state().selected {
            crate::library::TpmVersion::V2_0 => {
                self.cancellation.cancel();
                TPM_SUCCESS
            }
            crate::library::TpmVersion::V1_2 => TPM_FAIL,
        }
    }

    pub fn initialize(&self) -> TpmResult {
        #[cfg(feature = "tpm2")]
        {
            let runtime = self.lock_runtime();
            let mut state = self.lock_state();
            state.version_locked = true;
            if state.selected != crate::library::TpmVersion::V2_0 {
                return TPM_FAIL;
            }
            let mut op = Tpm2Access {
                runtime,
                services: state.services.clone(),
            };
            let context = tpm2::Tpm2InitContext {
                platform: op.services.platform_ref(),
                storage: op.services.storage_ref(),
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
            let displaced = op.runtime.take();
            let result = match tpm2::main_init(context) {
                Ok(mut runtime) => {
                    let mut state = self.lock_state();
                    state.preloaded_state.take(StateBlobKind::Permanent);
                    state.preloaded_state.take(StateBlobKind::Volatile);
                    runtime.buffer_size = state.tpm2_buffer_size;
                    drop(state);
                    *op.runtime = Some(runtime);
                    TPM_SUCCESS
                }
                Err(code) => code,
            };
            drop(op);
            drop(displaced);
            result
        }
        #[cfg(not(feature = "tpm2"))]
        {
            self.lock_state().version_locked = true;
            TPM_FAIL
        }
    }

    #[cfg(feature = "tpm2")]
    pub fn process(&self, command: &[u8]) -> Result<Vec<u8>, TpmResult> {
        let size = u32::try_from(command.len()).map_err(|_| TPM_SIZE)?;
        let prefix_len = super::CommandInput::required_prefix_len(size);
        self.process_input(&super::CommandInput::new(
            size,
            command[..prefix_len].to_vec(),
        ))
    }

    #[cfg(feature = "tpm2")]
    pub(crate) fn process_input(
        &self,
        command: &super::CommandInput,
    ) -> Result<Vec<u8>, TpmResult> {
        let mut op = self.acquire_tpm2()?;
        match op.runtime.as_mut() {
            None => Ok(Vec::new()),
            Some(runtime) => {
                let inputs = host_platform_inputs(op.services.platform_ref());
                self.cancellation.run(|cancellation| {
                    tpm2::process(
                        runtime,
                        inputs,
                        command,
                        &tpm2::OsClock,
                        |runtime| tpm2::host_nv_commit(op.services.storage_ref(), runtime),
                        cancellation,
                    )
                })
            }
        }
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_runtime_locality(&self) -> Option<u8> {
        self.lock_runtime().as_ref().map(|runtime| runtime.locality)
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_require_physical_presence(&self, code: u32) {
        let mut runtime_slot = self.lock_runtime();
        let runtime = runtime_slot.as_mut().expect("a running TPM 2 runtime");
        tpm2::require_physical_presence(runtime, code);
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_runtime_physical_presence(&self) -> Option<bool> {
        self.lock_runtime()
            .as_ref()
            .map(|runtime| runtime.physical_presence)
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn runtime_is_initialized(&self) -> bool {
        self.lock_runtime().is_some()
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn tpm2_runtime_buffer_size(&self) -> Option<u32> {
        self.lock_runtime()
            .as_ref()
            .map(|runtime| runtime.buffer_size)
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(crate) fn stage_empty_state(&self, kind: StateBlobKind) {
        self.lock_state().preloaded_state.set_empty(kind);
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn stage_state_data(&self, kind: StateBlobKind, bytes: Vec<u8>) {
        self.lock_state().preloaded_state.set_data(kind, bytes);
    }

    #[cfg(test)]
    pub(in crate::library) fn cancel_is_requested(&self) -> bool {
        self.cancellation.is_requested()
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn park_self_test_on_gate(&self) {
        let mut runtime_slot = self.lock_runtime();
        let runtime = runtime_slot.as_mut().expect("a live TPM 2.0 runtime");
        tpm2::park_self_test_on_gate(runtime);
    }

    #[cfg(all(test, feature = "tpm2"))]
    pub(in crate::library) fn pending_self_test_algorithms(&self) -> Vec<u16> {
        let runtime_slot = self.lock_runtime();
        let runtime = runtime_slot.as_ref().expect("a live TPM 2.0 runtime");
        tpm2::pending_self_test_algorithms(runtime)
    }

    pub fn terminate(&self) {
        #[cfg(feature = "tpm2")]
        {
            let mut runtime_slot = self.lock_runtime();
            let displaced = runtime_slot.take();
            let mut state = self.lock_state();
            if state.selected == crate::library::TpmVersion::V2_0 {
                tpm2::terminate();
                state.configured_profile = None;
            }
            state.installed_permanent = None;
            state.version_locked = false;
            drop(state);
            drop(runtime_slot);
            drop(displaced);
        }
        #[cfg(not(feature = "tpm2"))]
        {
            self.lock_state().version_locked = false;
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn set_profile(&self, profile: Option<&[u8]>) -> TpmResult {
        #[cfg(feature = "tpm2")]
        {
            let runtime_slot = self.lock_runtime();
            let mut state = self.lock_state();
            if state.selected != crate::library::TpmVersion::V2_0 {
                return TPM_FAIL;
            }
            if runtime_slot.is_some() {
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
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn set_buffer_size(&self, wanted_size: u32) -> Option<BufferSizeLimits> {
        #[cfg(feature = "tpm2")]
        {
            let mut runtime_slot = self.lock_runtime();
            let mut state = self.lock_state();
            if state.selected != crate::library::TpmVersion::V2_0 {
                return None;
            }
            if wanted_size != 0 {
                state.tpm2_buffer_size = tpm2::clamp_buffer_size(wanted_size);
            }
            let current = state.tpm2_buffer_size;
            if let Some(runtime) = runtime_slot.as_mut() {
                runtime.buffer_size = current;
            }
            Some(BufferSizeLimits {
                current,
                minimum: tpm2::MIN_BUFFER_SIZE,
                maximum: tpm2::MAX_BUFFER_SIZE,
            })
        }
        #[cfg(not(feature = "tpm2"))]
        {
            let _ = self.lock_state().selected;
            None
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn validate_state(&self, mask: StateValidationMask) -> TpmResult {
        #[cfg(feature = "tpm2")]
        return self.validate_tpm2_state(mask);
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
    }

    #[cfg(feature = "tpm2")]
    fn validate_tpm2_state(&self, mask: StateValidationMask) -> TpmResult {
        let op = match self.acquire_tpm2() {
            Ok(op) => op,
            Err(code) => return code,
        };
        let cached_volatile = self
            .lock_state()
            .preloaded_state
            .get(StateBlobKind::Volatile)
            .clone();
        let loaded =
            tpm2::load_state_for_validation(op.services.storage_ref(), mask, cached_volatile);
        let mut state = self.lock_state();
        let result = if state.selected != crate::library::TpmVersion::V2_0 {
            TPM_FAIL
        } else {
            let outcome = tpm2::finish_validation(
                loaded,
                op.runtime.as_ref(),
                state.installed_permanent.as_ref(),
            );
            if let Some(installed) = outcome.installed {
                state.installed_permanent = Some(installed);
            }
            outcome.result
        };
        drop(state);
        result
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn set_state(&self, kind: StateBlobKind, input: StateInput) -> TpmResult {
        #[cfg(feature = "tpm2")]
        {
            let bytes = match input {
                StateInput::Empty => {
                    #[cfg(test)]
                    self.fire_empty_state_gate(EmptyStatePhase::BeforeRuntimeLock);
                    let _runtime_slot = self.lock_runtime();
                    #[cfg(test)]
                    self.fire_empty_state_gate(EmptyStatePhase::AfterRuntimeLock);
                    let mut state = self.lock_state();
                    if state.selected != crate::library::TpmVersion::V2_0 {
                        return TPM_FAIL;
                    }
                    state.preloaded_state.set_empty(kind);
                    return TPM_SUCCESS;
                }
                StateInput::Data(bytes) => bytes,
            };
            let op = match self.acquire_tpm2() {
                Ok(op) => op,
                Err(code) => return code,
            };
            if op.runtime.is_some() {
                return TPM_INVALID_POSTINIT;
            }
            let outcome = self.validate_state_blob(kind, &bytes, op.services.storage_ref());
            let mut state = self.lock_state();
            let result = if state.selected != crate::library::TpmVersion::V2_0 {
                TPM_FAIL
            } else {
                if let Some(installed) = outcome.installed {
                    state.installed_permanent = Some(installed);
                }
                if outcome.result != TPM_SUCCESS {
                    state.preloaded_state.clear_all();
                    outcome.result
                } else {
                    state.preloaded_state.set_data(kind, bytes);
                    TPM_SUCCESS
                }
            };
            drop(state);
            result
        }
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
    }

    #[cfg(feature = "tpm2")]
    fn validate_state_blob(
        &self,
        kind: StateBlobKind,
        bytes: &[u8],
        storage: &dyn Storage,
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
                let permanent = match self.permanent_state_for_validation(storage) {
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
    fn permanent_state_for_validation(&self, storage: &dyn Storage) -> Result<Vec<u8>, TpmResult> {
        let cached = self
            .lock_state()
            .preloaded_state
            .get(StateBlobKind::Permanent)
            .clone();
        match cached {
            PreloadedBlob::Data(blob) => Ok(blob),
            PreloadedBlob::Empty => Ok(Vec::new()),
            PreloadedBlob::Missing => {
                tpm2::load_state_from_backend(storage, StateBlobKind::Permanent)
            }
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn get_state(&self, kind: StateBlobKind) -> Result<StateOutput, TpmResult> {
        #[cfg(feature = "tpm2")]
        {
            let op = self.acquire_tpm2()?;
            if let Some(runtime) = op.runtime.as_ref() {
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
            let cached = self.lock_state().preloaded_state.get(kind).clone();
            match cached {
                PreloadedBlob::Data(blob) => Ok(StateOutput::Data(blob)),
                PreloadedBlob::Empty => Ok(StateOutput::Empty),
                PreloadedBlob::Missing => {
                    tpm2::load_state_from_backend(op.services.storage_ref(), kind)
                        .map(StateOutput::Data)
                }
            }
        }
        #[cfg(not(feature = "tpm2"))]
        Err(TPM_FAIL)
    }

    pub fn was_manufactured(&self) -> bool {
        #[cfg(feature = "tpm2")]
        {
            let runtime_slot = self.lock_runtime();
            if self.lock_state().selected != crate::library::TpmVersion::V2_0 {
                return false;
            }
            runtime_slot
                .as_ref()
                .is_some_and(|runtime| runtime.was_manufactured)
        }
        #[cfg(not(feature = "tpm2"))]
        false
    }

    pub fn volatile_all_store(&self) -> Result<Vec<u8>, TpmResult> {
        #[cfg(feature = "tpm2")]
        {
            let runtime_slot = self.lock_runtime();
            if self.lock_state().selected != crate::library::TpmVersion::V2_0 {
                return Err(TPM_FAIL);
            }
            runtime_slot
                .as_ref()
                .ok_or(TPM_FAIL)
                .and_then(tpm2::volatile_all_store)
        }
        #[cfg(not(feature = "tpm2"))]
        Err(TPM_FAIL)
    }

    pub fn register_storage(&self, storage: Arc<dyn Storage>) {
        let displaced = {
            let mut state = self.lock_state();
            state.services.replace_storage(storage)
        };
        drop(displaced);
    }

    pub fn register_platform(&self, platform: Arc<dyn Platform>) {
        let displaced = {
            let mut state = self.lock_state();
            state.services.replace_platform(platform)
        };
        drop(displaced);
    }

    pub fn register_external_services(&self, services: ExternalServices) {
        let displaced = {
            let mut state = self.lock_state();
            core::mem::replace(&mut state.services, services)
        };
        drop(displaced);
    }

    pub fn tis_established_get(&self) -> Result<bool, TpmResult> {
        #[cfg(feature = "tpm2")]
        {
            let runtime_slot = self.lock_runtime();
            if self.lock_state().selected != crate::library::TpmVersion::V2_0 {
                return Err(TPM_FAIL);
            }
            runtime_slot
                .as_ref()
                .map(|runtime| runtime.tpm_established)
                .ok_or(TPM_FAIL)
        }
        #[cfg(not(feature = "tpm2"))]
        Err(TPM_FAIL)
    }

    pub fn tis_established_reset(&self) -> TpmResult {
        #[cfg(feature = "tpm2")]
        {
            let mut op = match self.acquire_tpm2() {
                Ok(op) => op,
                Err(code) => return code,
            };
            match op.runtime.as_mut() {
                Some(runtime) => {
                    let locality = op.services.platform_ref().locality();
                    tpm2::tis_established_reset(runtime, locality)
                }
                None => TPM_FAIL,
            }
        }
        #[cfg(not(feature = "tpm2"))]
        TPM_FAIL
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
        let mut runtime_slot = self.lock_runtime();
        if self.lock_state().selected != crate::library::TpmVersion::V2_0 {
            return TPM_FAIL;
        }
        match runtime_slot.as_mut() {
            Some(runtime) => operation(runtime),
            None => TPM_FAIL,
        }
    }

    pub fn get_tpm_property(&self, prop: TpmProperty) -> Option<u32> {
        if prop == TpmProperty::BufferMax {
            return Some(TPM_BUFFER_MAX);
        }
        match self.lock_state().selected {
            #[cfg(feature = "tpm2")]
            crate::library::TpmVersion::V2_0 => tpm2::get_tpm_property(prop),
            _ => None,
        }
    }

    #[cfg_attr(not(feature = "tpm2"), allow(unused_variables))]
    pub fn get_info(&self, flags: InformationFlags) -> Option<String> {
        #[cfg(feature = "tpm2")]
        {
            let runtime_slot = self.lock_runtime();
            if self.lock_state().selected != crate::library::TpmVersion::V2_0 {
                return None;
            }
            Some(tpm2::get_info(flags, runtime_slot.as_ref()))
        }
        #[cfg(not(feature = "tpm2"))]
        None
    }
}

#[cfg(feature = "tpm2")]
fn host_platform_inputs(platform: &dyn Platform) -> tpm2::PlatformInputs {
    tpm2::PlatformInputs {
        locality: platform.locality() as u8,
        physical_presence: platform.physical_presence(),
    }
}

impl Default for Tpm {
    fn default() -> Self {
        Self::new(ExternalServices::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "tpm2")]
    use crate::library::platform::test_support::TestPlatform;
    #[cfg(feature = "tpm2")]
    use crate::library::preloaded_state::PreloadedBlob;
    use crate::library::state_blob::StateBlobKind;
    #[cfg(feature = "tpm2")]
    use crate::library::storage::StorageLoad;
    #[cfg(feature = "tpm2")]
    use crate::library::storage::test_support::TestStorage;

    #[cfg(feature = "tpm2")]
    #[test]
    fn independent_instances() {
        let first = Tpm::default();
        let second = Tpm::default();
        assert_eq!(
            first.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert!(first.tpm2_selected());
        assert!(!second.tpm2_selected());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn explicit_instance_process() {
        let tpm = Tpm::default();
        assert_eq!(
            tpm.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        tpm.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(tpm.initialize(), TPM_SUCCESS);
        let response = tpm
            .process(&[0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x44, 0, 0])
            .expect("the response fits");
        assert_eq!(response.len(), 10);
        assert_eq!(&response[2..6], &10_u32.to_be_bytes());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn oversized_explicit_instance_process() {
        const COMMAND_SIZE_RESPONSE: [u8; 10] =
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x42];

        let tpm = Tpm::default();
        assert_eq!(tpm.set_version(TpmVersion::V2_0), TPM_SUCCESS);
        tpm.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(tpm.initialize(), TPM_SUCCESS);

        let mut command = vec![0u8; crate::library::constants::TPM_BUFFER_MAX as usize + 1];
        let size = command.len() as u32;
        command[..2].copy_from_slice(&[0x80, 0x01]);
        command[2..6].copy_from_slice(&size.to_be_bytes());

        assert_eq!(tpm.process(&command), Ok(COMMAND_SIZE_RESPONSE.to_vec()));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_selection_success() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert_eq!(
            library.lock_state().selected,
            crate::library::TpmVersion::V2_0
        );
    }

    #[cfg(not(feature = "tpm1"))]
    #[test]
    fn tpm12_not_compiled_in_failure() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V1_2),
            TPM_FAIL
        );
        assert_eq!(
            library.lock_state().selected,
            crate::library::TpmVersion::V1_2
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn same_version_reselection_preload_preservation() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, vec![1, 2, 3]);
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
    fn failed_main_init_lock_until_terminate() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert_eq!(library.initialize(), TPM_FAIL);
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_FAIL
        );
        library.terminate();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
    }

    #[test]
    fn repeated_main_init_acceptance() {
        let library = Tpm::default();
        assert_eq!(library.initialize(), TPM_FAIL);
        assert_eq!(library.initialize(), TPM_FAIL);
    }

    #[test]
    fn terminate_without_init_preload_preservation() {
        let library = Tpm::default();
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
    fn buffer_max_query_before_version_dispatch() {
        let library = Tpm::default();
        assert_eq!(library.get_tpm_property(TpmProperty::BufferMax), Some(4096));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_property_reference_build_parity() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert_eq!(
            library.get_tpm_property(TpmProperty::RsaKeyLengthMax),
            Some(3072)
        );
        assert_eq!(library.get_tpm_property(TpmProperty::KeyHandles), Some(3));
    }

    #[cfg(not(feature = "tpm1"))]
    #[test]
    fn disabled_version_no_properties_or_info() {
        let library = Tpm::default();
        assert_eq!(library.get_tpm_property(TpmProperty::RsaKeyLengthMax), None);
        assert!(library.get_info(InformationFlags::default()).is_none());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn get_info_tpm2_dispatch() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert_eq!(
            library.get_info(InformationFlags::default()).as_deref(),
            Some("{}")
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn main_init_failure_no_runtime() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert_eq!(library.initialize(), TPM_FAIL);
        assert!(!library.runtime_is_initialized());
        assert!(!library.was_manufactured());
        library.terminate();
    }

    #[test]
    fn volatile_store_no_running_tpm_failure() {
        let library = Tpm::default();
        assert_eq!(library.volatile_all_store(), Err(TPM_FAIL));

        #[cfg(feature = "tpm2")]
        {
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );
            assert_eq!(library.volatile_all_store(), Err(TPM_FAIL));
        }
    }

    #[cfg(feature = "tpm2")]
    fn tpm2_library() -> Tpm {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library
    }

    #[cfg(feature = "tpm2")]
    #[track_caller]
    fn buffer_size(library: &Tpm, wanted_size: u32) -> u32 {
        let limits = library
            .set_buffer_size(wanted_size)
            .expect("TPM 2 is selected");
        assert_eq!(limits.minimum, 2808);
        assert_eq!(limits.maximum, 4096);
        limits.current
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn buffer_size_compile_time_default_query_unchanged() {
        let library = tpm2_library();
        assert_eq!(buffer_size(&library, 0), 4096);
        assert_eq!(buffer_size(&library, 0), 4096, "a query changes nothing");
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn wanted_buffer_size_supported_range_clamp() {
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
    fn buffer_size_per_library_terminate_persistence() {
        let library = tpm2_library();
        let untouched = tpm2_library();
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(library.tpm2_runtime_buffer_size(), Some(4096));

        assert_eq!(buffer_size(&library, 3000), 3000);
        assert_eq!(
            library.tpm2_runtime_buffer_size(),
            Some(3000),
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(
            library.tpm2_runtime_buffer_size(),
            Some(3000),
            "the re-initialized runtime starts from the configured value"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn command_buffer_limit() {
        use crate::library::constants::TPM_RC_COMMAND_SIZE;

        fn unsupported_command(size: u32) -> crate::library::CommandInput {
            let mut bytes = vec![0u8; size as usize];
            bytes[..2].copy_from_slice(&[0x80, 0x01]);
            bytes[2..6].copy_from_slice(&size.to_be_bytes());
            bytes[6..10].copy_from_slice(&[0x20, 0x00, 0x00, 0x00]);
            crate::library::CommandInput::new(size, bytes)
        }

        #[track_caller]
        fn response_code(library: &Tpm, size: u32) -> u32 {
            let response = library.process_input(&unsupported_command(size)).unwrap();
            u32::from_be_bytes(response[6..10].try_into().unwrap())
        }

        const COMMAND_CODE: u32 = 0x143;

        let library = tpm2_library();
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);

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
    fn buffer_size_get_capability_report() {
        const MAX_COMMAND_SIZE: u32 = 0x11e;
        const MAX_RESPONSE_SIZE: u32 = 0x11f;

        #[track_caller]
        fn reported(library: &Tpm, property: u32) -> u32 {
            let mut bytes = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
            bytes.extend_from_slice(&0x0000_017au32.to_be_bytes());
            bytes.extend_from_slice(&6u32.to_be_bytes());
            bytes.extend_from_slice(&property.to_be_bytes());
            bytes.extend_from_slice(&1u32.to_be_bytes());
            let input = crate::library::CommandInput::new(bytes.len() as u32, bytes);
            let response = library.process_input(&input).unwrap();
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
        let startup = crate::library::CommandInput::new(
            12,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ],
        );
        library.process_input(&startup).unwrap();

        assert_eq!(reported(&library, MAX_COMMAND_SIZE), 4096);
        assert_eq!(reported(&library, MAX_RESPONSE_SIZE), 4096);
        assert_eq!(buffer_size(&library, 2808), 2808);
        assert_eq!(reported(&library, MAX_COMMAND_SIZE), 2808);
        assert_eq!(reported(&library, MAX_RESPONSE_SIZE), 2808);
        assert_eq!(
            library.get_tpm_property(TpmProperty::BufferMax),
            Some(4096),
            "TpmProperty::BufferMax stays the compile-time maximum"
        );
        library.terminate();
    }

    #[test]
    fn set_buffer_size_no_tpm2_selection_empty_report() {
        let library = Tpm::default();
        for wanted_size in [0u32, 1, 2808, 4096, u32::MAX] {
            assert_eq!(library.set_buffer_size(wanted_size), None);
        }
    }

    #[cfg(feature = "tpm2")]
    fn locality_platform(locality: u32) -> Arc<dyn Platform> {
        TestPlatform::at_locality(locality).arc()
    }

    #[cfg(feature = "tpm2")]
    fn no_services() -> ExternalServices {
        ExternalServices::default()
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn native_storage_independence() {
        let library = Tpm::default();
        library.register_storage(TestStorage::new().on_can_store(|| true).arc());
        assert!(library.lock_state().services.storage_ref().supports_store());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn native_storage_platform_preservation() {
        let library = Tpm::default();
        library.register_external_services(ExternalServices::new(
            locality_platform(3),
            Arc::new(crate::library::storage::NoStorage),
        ));
        library.register_storage(TestStorage::new().on_can_store(|| true).arc());
        let state = library.lock_state();
        assert_eq!(state.services.platform_ref().locality(), 3);
        assert!(state.services.storage_ref().supports_store());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn native_platform_storage_preservation() {
        let library = Tpm::default();
        library.register_storage(TestStorage::new().on_can_store(|| true).arc());
        library.register_platform(locality_platform(4));
        let state = library.lock_state();
        assert_eq!(state.services.platform_ref().locality(), 4);
        assert!(
            state.services.storage_ref().supports_store(),
            "the storage survives"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn platform_execution_outside_state_lock() {
        let library = Arc::new(tpm2_library());
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);

        let seen: Arc<Mutex<Vec<(&'static str, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let locality_seen = Arc::clone(&seen);
        let locality_library = Arc::clone(&library);
        let presence_seen = Arc::clone(&seen);
        let presence_library = Arc::clone(&library);
        library.register_platform(
            TestPlatform::new()
                .on_locality(move || {
                    locality_seen
                        .lock()
                        .unwrap()
                        .push(("locality", locality_library.state_is_unlocked()));
                    locality_library.register_storage(Arc::new(crate::library::storage::NoStorage));
                    2
                })
                .on_physical_presence(move || {
                    presence_seen
                        .lock()
                        .unwrap()
                        .push(("presence", presence_library.state_is_unlocked()));
                    true
                })
                .arc(),
        );

        library
            .process_input(&startup_clear())
            .expect("the response fits");
        assert_eq!(
            *seen.lock().unwrap(),
            [("locality", true), ("presence", true)],
            "a reentrant platform never meets the state mutex"
        );
        assert_eq!(library.tpm2_runtime_locality(), Some(2));
        assert_eq!(library.tpm2_runtime_physical_presence(), Some(true));
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn platform_init_failure_rollback() {
        let library = tpm2_library();
        library.register_platform(TestPlatform::new().on_initialize(|| Err(42)).arc());
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Permanent);

        for attempt in 0..2 {
            assert_eq!(library.initialize(), 42, "attempt {attempt}");
            assert!(!library.runtime_is_initialized(), "attempt {attempt}");
            assert_eq!(
                *library
                    .lock_state()
                    .preloaded_state
                    .get(StateBlobKind::Permanent),
                PreloadedBlob::Empty,
                "attempt {attempt}: the staged entry survives"
            );
        }

        library.register_platform(Arc::new(crate::library::platform::DefaultPlatform));
        assert_eq!(
            library.initialize(),
            TPM_SUCCESS,
            "a working platform initializes the same library"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn external_service_replacement() {
        let library = Tpm::default();
        library.register_external_services(ExternalServices::new(
            locality_platform(3),
            TestStorage::new().on_can_store(|| true).arc(),
        ));
        library.register_external_services(no_services());
        let state = library.lock_state();
        assert_eq!(state.services.platform_ref().locality(), 0);
        assert!(!state.services.storage_ref().supports_store());
    }

    #[cfg(all(feature = "tpm1", feature = "tpm2"))]
    #[test]
    fn version_switch_preloaded_state_clear() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
            library.set_version(crate::library::TpmVersion::V1_2),
            TPM_SUCCESS
        );
        let state = library.lock_state();
        assert!(!state.preloaded_state.is_present(StateBlobKind::Permanent));
        assert!(!state.preloaded_state.is_present(StateBlobKind::Volatile));
        assert!(!state.preloaded_state.is_present(StateBlobKind::SaveState));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn preloaded_empty_no_manufacture_init_and_consumption() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_empty(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Missing,
            "the staged entry is consumed on success"
        );
        assert!(library.runtime_is_initialized());
        assert!(!library.was_manufactured(), "no Manufacture ran");
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failed_preloaded_empty_init_staged_entry_preservation() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
            library.initialize(),
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
        assert!(!library.runtime_is_initialized());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_permanent_state_init_staged_blob_consumption() {
        const INFO_ACTIVE_PROFILE: InformationFlags = InformationFlags::ACTIVE_PROFILE;

        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Missing,
            "the staged blob is consumed on success"
        );
        assert!(library.runtime_is_initialized());
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
    fn fixture_backend_storage() -> TestStorage {
        TestStorage::new().on_load(|kind| match kind {
            StateBlobKind::Permanent => Ok(StorageLoad::Data(BACKEND_BLOB.clone())),
            _ => Ok(StorageLoad::Missing),
        })
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn backend_loaded_permanent_state_initialization() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library.register_storage(fixture_backend_storage().arc());
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert!(library.runtime_is_initialized());
        assert!(!library.was_manufactured());
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn commit_phase_failure_preloaded_state_preservation() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::commit_failing_permanent_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, blob.clone());
        for attempt in 0..2 {
            assert_eq!(library.initialize(), TPM_FAIL, "attempt {attempt}");
            assert_eq!(
                *library
                    .lock_state()
                    .preloaded_state
                    .get(StateBlobKind::Permanent),
                PreloadedBlob::Data(blob.clone()),
                "attempt {attempt}: the staged blob survives a commit failure"
            );
            assert!(!library.runtime_is_initialized());
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn repeated_main_init_after_success_library_semantics() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::valid_permanent_state_fixture();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, blob);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert!(library.runtime_is_initialized());
        assert_eq!(
            library.initialize(),
            TPM_FAIL,
            "no staged state and no backend: the manufacture boundary"
        );
        assert!(
            !library.runtime_is_initialized(),
            "a failed re-init publishes no stale runtime"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn successful_main_init_staged_entry_consumption() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
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
    fn volatile_boundary_failure_staged_blob_preservation() {
        const INFO_ACTIVE_PROFILE: InformationFlags = InformationFlags::ACTIVE_PROFILE;

        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
                library.initialize(),
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
            drop(state);
            assert!(!library.runtime_is_initialized());
            assert_eq!(
                library.get_info(INFO_ACTIVE_PROFILE).as_deref(),
                Some("{}"),
                "attempt {attempt}: no ActiveProfile without a published runtime"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn bad_volatile_digest_staged_blob_preservation() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
                library.initialize(),
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
            drop(state);
            assert!(!library.runtime_is_initialized());
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_volatile_state_restore_and_consumption() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
            assert_eq!(library.initialize(), TPM_SUCCESS, "round {round}");
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
            drop(state);
            assert!(library.runtime_is_initialized(), "round {round}");
            library.terminate();
            assert!(!library.runtime_is_initialized());
        }
    }

    #[cfg(feature = "tpm2")]
    static MANUFACTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    #[cfg(feature = "tpm2")]
    static BACKEND_PERMALL: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
    #[cfg(feature = "tpm2")]
    static BACKEND_STORES: std::sync::Mutex<u32> = std::sync::Mutex::new(0);

    #[cfg(feature = "tpm2")]
    fn backend_blob(blob: Option<Vec<u8>>) -> StorageLoad {
        match blob {
            None => StorageLoad::Missing,
            Some(blob) if blob.is_empty() => StorageLoad::Empty,
            Some(blob) => StorageLoad::Data(blob),
        }
    }

    #[cfg(feature = "tpm2")]
    fn backend_load(kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        match kind {
            StateBlobKind::Permanent => Ok(backend_blob(BACKEND_PERMALL.lock().unwrap().clone())),
            _ => Ok(StorageLoad::Missing),
        }
    }

    #[cfg(feature = "tpm2")]
    fn backend_store(kind: StateBlobKind, data: &[u8]) -> Result<(), TpmResult> {
        assert_eq!(kind, StateBlobKind::Permanent);
        *BACKEND_PERMALL.lock().unwrap() = Some(data.to_vec());
        *BACKEND_STORES.lock().unwrap() += 1;
        Ok(())
    }

    #[cfg(feature = "tpm2")]
    fn manufacture_storage() -> TestStorage {
        TestStorage::new()
            .on_load(backend_load)
            .on_store(backend_store)
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
    fn manufacture_library() -> Tpm {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library.register_storage(manufacture_storage().arc());
        library.lock_state().entropy_override = Some(deterministic_entropy);
        library
    }

    #[cfg(feature = "tpm2")]
    const INFO_ACTIVE_PROFILE: InformationFlags = InformationFlags::ACTIVE_PROFILE;

    #[cfg(feature = "tpm2")]
    #[test]
    fn first_boot_manufacture_restart_no_remanufacture() {
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
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
    fn manufactured_tpm_single_startup_clear_acceptance() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.initialize(), TPM_SUCCESS);

        let startup = crate::library::CommandInput::new(
            12,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
            ],
        );
        let stores_before = *BACKEND_STORES.lock().unwrap();
        let response = library.process_input(&startup).unwrap();
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

        let response = library.process_input(&startup).unwrap();
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
    struct DropProbe {
        library: Arc<Tpm>,
        seen: Arc<Mutex<Vec<(bool, bool)>>>,
    }

    #[cfg(feature = "tpm2")]
    impl Drop for DropProbe {
        fn drop(&mut self) {
            let unlocked = (
                self.library.state_is_unlocked(),
                self.library.runtime_is_unlocked(),
            );
            self.library
                .register_platform(Arc::new(crate::library::platform::DefaultPlatform));
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(unlocked);
        }
    }

    #[cfg(feature = "tpm2")]
    impl Platform for DropProbe {
        fn initialize(&self) -> Result<(), TpmResult> {
            Ok(())
        }

        fn locality(&self) -> u32 {
            0
        }

        fn physical_presence(&self) -> bool {
            false
        }
    }

    #[cfg(feature = "tpm2")]
    fn probe_platform(
        library: &Arc<Tpm>,
        seen: &Arc<Mutex<Vec<(bool, bool)>>>,
    ) -> Arc<dyn Platform> {
        Arc::new(DropProbe {
            library: Arc::clone(library),
            seen: Arc::clone(seen),
        })
    }

    #[cfg(feature = "tpm2")]
    fn probe_storage(library: &Arc<Tpm>, seen: &Arc<Mutex<Vec<(bool, bool)>>>) -> Arc<dyn Storage> {
        let probe = DropProbe {
            library: Arc::clone(library),
            seen: Arc::clone(seen),
        };
        TestStorage::new()
            .on_can_store(move || {
                let _ = &probe;
                false
            })
            .arc()
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn displaced_platform_drop_order() {
        let library = Arc::new(Tpm::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        library.register_platform(probe_platform(&library, &seen));
        assert!(seen.lock().unwrap().is_empty(), "still registered");

        library.register_platform(Arc::new(crate::library::platform::DefaultPlatform));
        assert_eq!(*seen.lock().unwrap(), [(true, true)]);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn displaced_storage_drop_order() {
        let library = Arc::new(Tpm::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        library.register_storage(probe_storage(&library, &seen));
        assert!(seen.lock().unwrap().is_empty(), "still registered");

        library.register_storage(Arc::new(crate::library::storage::NoStorage));
        assert_eq!(*seen.lock().unwrap(), [(true, true)]);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn displaced_services_drop_order() {
        let library = Arc::new(Tpm::default());
        let seen = Arc::new(Mutex::new(Vec::new()));
        library.register_external_services(ExternalServices::new(
            probe_platform(&library, &seen),
            probe_storage(&library, &seen),
        ));
        assert!(seen.lock().unwrap().is_empty(), "still registered");

        library.register_external_services(ExternalServices::default());
        assert_eq!(*seen.lock().unwrap(), [(true, true), (true, true)]);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn commit_failure_mode() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();
        library.register_storage(TestStorage::new().on_store(|_, _| Err(TPM_FAIL)).arc());

        assert_eq!(
            execute(&library, &startup_clear()),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "a failed commit answers TPM_RC_FAILURE"
        );
        assert_eq!(
            execute(&library, &startup_clear()),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "the runtime stays in failure mode after the commit failure"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    fn running_library() -> Arc<Tpm> {
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = Arc::new(manufacture_library());
        assert_eq!(library.initialize(), TPM_SUCCESS);
        library
    }

    #[cfg(feature = "tpm2")]
    struct ParkedCommand {
        library: Arc<Tpm>,
        entered: std::sync::mpsc::Receiver<()>,
        release: std::sync::mpsc::SyncSender<()>,
        commit_done: Arc<std::sync::atomic::AtomicBool>,
        stored: Arc<Mutex<Vec<Vec<u8>>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[cfg(feature = "tpm2")]
    const PARK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    #[cfg(feature = "tpm2")]
    impl ParkedCommand {
        fn await_parked(&self) {
            self.entered
                .recv_timeout(PARK_TIMEOUT)
                .expect("timed out waiting for the command to reach its platform callback");
        }

        fn release(&self) {
            self.release.send(()).expect("the parked command resumes");
        }
    }

    #[cfg(feature = "tpm2")]
    fn parked_command_library() -> ParkedCommand {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::sync_channel;

        let library = running_library();
        let events: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
        let (entered_tx, entered_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel::<()>(1);
        let armed = Arc::new(AtomicBool::new(true));
        let release_rx = Mutex::new(release_rx);
        let locality_events = Arc::clone(&events);
        library.register_platform(
            TestPlatform::new()
                .on_locality(move || {
                    locality_events.lock().unwrap().push("enter");
                    if armed.swap(false, Ordering::SeqCst) {
                        entered_tx.send(()).expect("the test awaits the park");
                        release_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(PARK_TIMEOUT)
                            .expect("timed out waiting for the test to release the park");
                    }
                    0
                })
                .arc(),
        );
        let commit_done = Arc::new(AtomicBool::new(false));
        let stored = Arc::new(Mutex::new(Vec::new()));
        let commit_flag = Arc::clone(&commit_done);
        let recorder = Arc::clone(&stored);
        let store_events = Arc::clone(&events);
        library.register_storage(
            TestStorage::new()
                .on_load(backend_load)
                .on_store(move |kind, data| {
                    store_events.lock().unwrap().push("commit");
                    recorder.lock().unwrap().push(data.to_vec());
                    commit_flag.store(true, Ordering::SeqCst);
                    backend_store(kind, data)
                })
                .arc(),
        );
        ParkedCommand {
            library,
            entered: entered_rx,
            release: release_tx,
            commit_done,
            stored,
            events,
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn process_serialization() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let parked = parked_command_library();
        let library = &parked.library;

        let (first, second_saw_commit, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| library.process_input(&startup_clear()));
            parked.await_parked();
            let commit_done = Arc::clone(&parked.commit_done);
            let second = scope.spawn(move || {
                let response = library.process_input(&shutdown_state());
                (
                    commit_done.load(std::sync::atomic::Ordering::SeqCst),
                    response,
                )
            });
            parked.release();
            let first = first.join().expect("the first command never panics");
            let (second_saw_commit, second) =
                second.join().expect("the second command never panics");
            (first, second_saw_commit, second)
        });

        let first = first.expect("the first response fits");
        assert_eq!(response_code(&first), 0, "TPM2_Startup(CLEAR) succeeds");
        let second = second.expect("the second command returns its own response");
        assert!(
            !second.is_empty(),
            "a busy runtime never produces an empty TPM_SUCCESS"
        );
        assert_eq!(
            response_code(&second),
            0,
            "TPM2_Shutdown(STATE) observes the state the first command left"
        );
        assert!(
            second_saw_commit,
            "the second command completed only after the first one committed"
        );
        assert_eq!(
            *parked.events.lock().unwrap(),
            ["enter", "commit", "enter", "commit"],
            "the commands never interleave"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn terminate_serialization() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let parked = parked_command_library();
        let library = &parked.library;

        let (response, terminated_after_commit) = std::thread::scope(|scope| {
            let command = scope.spawn(|| library.process_input(&startup_clear()));
            parked.await_parked();
            let commit_done = Arc::clone(&parked.commit_done);
            let terminator = scope.spawn(move || {
                library.terminate();
                commit_done.load(std::sync::atomic::Ordering::SeqCst)
            });
            parked.release();
            (
                command.join().expect("the command never panics"),
                terminator.join().expect("the terminator never panics"),
            )
        });

        let response = response.expect("the response fits");
        assert_eq!(
            response_code(&response),
            0,
            "Terminate never yanks the runtime out of a running command"
        );
        assert!(
            terminated_after_commit,
            "Terminate returned only after the command committed"
        );
        assert!(!library.runtime_is_initialized());
        assert_eq!(
            library.process_input(&startup_clear()),
            Ok(Vec::new()),
            "the terminated library answers like a stopped TPM"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn get_state_serialization() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let parked = parked_command_library();
        let library = &parked.library;

        let (response, read_after_commit, read) = std::thread::scope(|scope| {
            let command = scope.spawn(|| library.process_input(&startup_clear()));
            parked.await_parked();
            let commit_done = Arc::clone(&parked.commit_done);
            let reader = scope.spawn(move || {
                let read = library.get_state(StateBlobKind::Permanent);
                (commit_done.load(std::sync::atomic::Ordering::SeqCst), read)
            });
            parked.release();
            let response = command.join().expect("the command never panics");
            let (read_after_commit, read) = reader.join().expect("the reader never panics");
            (response, read_after_commit, read)
        });

        assert_eq!(response_code(&response.expect("the response fits")), 0);
        assert!(
            read_after_commit,
            "GetState returned only after the command committed"
        );
        let StateOutput::Data(blob) = read.expect("a running TPM snapshots its state") else {
            panic!("a running TPM never answers an empty cached state");
        };
        assert_eq!(
            blob,
            *parked
                .stored
                .lock()
                .unwrap()
                .last()
                .expect("the command committed"),
            "the snapshot reflects the completed command, not the state it started from"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn validation_serialization() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let parked = parked_command_library();
        let library = &parked.library;

        let (response, validated_after_commit, result) = std::thread::scope(|scope| {
            let command = scope.spawn(|| library.process_input(&startup_clear()));
            parked.await_parked();
            let commit_done = Arc::clone(&parked.commit_done);
            let validator = scope.spawn(move || {
                let result = library.validate_state(validation_mask(VALIDATE_PERMANENT));
                (
                    commit_done.load(std::sync::atomic::Ordering::SeqCst),
                    result,
                )
            });
            parked.release();
            let response = command.join().expect("the command never panics");
            let (validated_after_commit, result) =
                validator.join().expect("the validator never panics");
            (response, validated_after_commit, result)
        });

        assert_eq!(response_code(&response.expect("the response fits")), 0);
        assert!(
            validated_after_commit,
            "ValidateState returned only after the command committed"
        );
        assert_eq!(
            result, TPM_SUCCESS,
            "the validation ran against the committed state"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn empty_state_serialization() {
        use std::sync::atomic::Ordering;
        use std::sync::mpsc::sync_channel;

        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let parked = parked_command_library();
        let library = &parked.library;

        let (started_tx, started_rx) = sync_channel(1);
        let (acquired_tx, acquired_rx) = sync_channel(1);
        let gate_commit = Arc::clone(&parked.commit_done);
        library.set_empty_state_gate(Arc::new(move |phase| match phase {
            EmptyStatePhase::BeforeRuntimeLock => started_tx
                .send(())
                .expect("the test observes the empty-state update"),
            EmptyStatePhase::AfterRuntimeLock => acquired_tx
                .send(gate_commit.load(Ordering::SeqCst))
                .expect("the test observes the runtime acquisition"),
        }));

        let (response, staged_after_commit, staged) = std::thread::scope(|scope| {
            let command = scope.spawn(|| library.process_input(&startup_clear()));
            parked.await_parked();
            let commit_done = Arc::clone(&parked.commit_done);
            let stager = scope.spawn(move || {
                let staged = library.set_state(StateBlobKind::SaveState, StateInput::Empty);
                (commit_done.load(Ordering::SeqCst), staged)
            });
            started_rx
                .recv_timeout(PARK_TIMEOUT)
                .expect("timed out waiting for the empty-state update to start");
            parked.release();
            let response = command.join().expect("the command never panics");
            let acquired_after_commit = acquired_rx
                .recv_timeout(PARK_TIMEOUT)
                .expect("timed out waiting for the empty-state update to acquire the runtime");
            assert!(
                acquired_after_commit,
                "the empty path acquires the runtime only after the command commits"
            );
            let (staged_after_commit, staged) = stager.join().expect("the stager never panics");
            (response, staged_after_commit, staged)
        });

        assert_eq!(response_code(&response.expect("the response fits")), 0);
        assert!(
            staged_after_commit,
            "the marker is applied only after the running command finishes"
        );
        assert_eq!(staged, TPM_SUCCESS, "staging an empty marker stays allowed");
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::SaveState),
            PreloadedBlob::Empty
        );
        library.terminate();
    }

    #[cfg(all(feature = "tpm1", feature = "tpm2"))]
    #[test]
    fn empty_state_version_switch() {
        use std::sync::mpsc::sync_channel;

        let library = tpm2_library();

        let (held_tx, held_rx) = sync_channel(1);
        let (release_tx, release_rx) = sync_channel::<()>(1);
        let release_rx = Mutex::new(release_rx);
        library.set_empty_state_gate(Arc::new(move |phase| {
            if phase == EmptyStatePhase::AfterRuntimeLock {
                held_tx
                    .send(())
                    .expect("the test observes the held runtime");
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(PARK_TIMEOUT)
                    .expect("timed out waiting for the version switch");
            }
        }));

        let staged = std::thread::scope(|scope| {
            let stager =
                scope.spawn(|| library.set_state(StateBlobKind::SaveState, StateInput::Empty));
            held_rx
                .recv_timeout(PARK_TIMEOUT)
                .expect("timed out waiting for the empty-state update to hold the runtime");
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V1_2),
                TPM_SUCCESS
            );
            release_tx.send(()).expect("the stager resumes");
            stager.join().expect("the stager never panics")
        });

        assert_eq!(
            staged, TPM_FAIL,
            "a marker validated for TPM 2.0 is never installed for TPM 1.2"
        );
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::SaveState),
            PreloadedBlob::Missing,
            "the switched selection keeps its cleared preloaded state"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cancel_nonblocking() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let parked = parked_command_library();
        let library = &parked.library;

        let response = std::thread::scope(|scope| {
            let command = scope.spawn(|| library.process_input(&startup_clear()));
            parked.await_parked();
            assert_eq!(
                library.cancel(),
                TPM_SUCCESS,
                "CancelCommand never touches the runtime mutex"
            );
            assert!(library.cancel_is_requested());
            parked.release();
            command.join().expect("the command never panics")
        });

        assert_eq!(
            response_code(&response.expect("the response fits")),
            0,
            "TPM2_Startup reaches no upstream cancellation checkpoint"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn storage_drop_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();
        let seen: Arc<Mutex<Vec<(bool, bool)>>> = Arc::new(Mutex::new(Vec::new()));

        let probe = DropProbe {
            library: Arc::clone(&library),
            seen: Arc::clone(&seen),
        };
        let swap = Arc::clone(&library);
        library.register_storage(
            TestStorage::new()
                .on_store(move |kind, data| {
                    let _ = &probe;
                    swap.register_storage(manufacture_storage().arc());
                    backend_store(kind, data)
                })
                .arc(),
        );

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        assert_eq!(
            *seen.lock().unwrap(),
            [(true, true)],
            "the command's storage clone is destroyed after every library mutex"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn platform_drop_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();
        let seen: Arc<Mutex<Vec<(bool, bool)>>> = Arc::new(Mutex::new(Vec::new()));

        let probe = DropProbe {
            library: Arc::clone(&library),
            seen: Arc::clone(&seen),
        };
        let swap = Arc::clone(&library);
        library.register_platform(
            TestPlatform::new()
                .on_locality(move || {
                    let _ = &probe;
                    swap.register_platform(TestPlatform::at_locality(0).arc());
                    0
                })
                .arc(),
        );

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        assert_eq!(
            *seen.lock().unwrap(),
            [(true, true)],
            "the command's platform clone is destroyed after every library mutex"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn storage_panic_drop_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();
        let seen: Arc<Mutex<Vec<(bool, bool)>>> = Arc::new(Mutex::new(Vec::new()));

        let probe = DropProbe {
            library: Arc::clone(&library),
            seen: Arc::clone(&seen),
        };
        let swap = Arc::clone(&library);
        library.register_storage(
            TestStorage::new()
                .on_store(move |_, _| {
                    let _ = &probe;
                    swap.register_storage(manufacture_storage().arc());
                    panic!("the storage callback panics");
                })
                .arc(),
        );

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            library.process_input(&startup_clear())
        }));
        assert!(outcome.is_err(), "the callback panic reaches the caller");
        assert_eq!(
            *seen.lock().unwrap(),
            [(true, true)],
            "the unwinding command destroys its storage clone after every library mutex"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn platform_panic_drop_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();
        let seen: Arc<Mutex<Vec<(bool, bool)>>> = Arc::new(Mutex::new(Vec::new()));

        let probe = DropProbe {
            library: Arc::clone(&library),
            seen: Arc::clone(&seen),
        };
        let swap = Arc::clone(&library);
        library.register_platform(
            TestPlatform::new()
                .on_locality(move || {
                    let _ = &probe;
                    swap.register_platform(TestPlatform::at_locality(0).arc());
                    panic!("the platform callback panics");
                })
                .arc(),
        );

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            library.process_input(&startup_clear())
        }));
        assert!(outcome.is_err(), "the callback panic reaches the caller");
        assert_eq!(
            *seen.lock().unwrap(),
            [(true, true)],
            "the unwinding command destroys its platform clone after every library mutex"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn init_panic_drop_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = Arc::new(manufacture_library());
        let seen: Arc<Mutex<Vec<(bool, bool)>>> = Arc::new(Mutex::new(Vec::new()));

        let probe = DropProbe {
            library: Arc::clone(&library),
            seen: Arc::clone(&seen),
        };
        let swap = Arc::clone(&library);
        library.register_storage(
            manufacture_storage()
                .on_init(move || {
                    let _ = &probe;
                    swap.register_storage(manufacture_storage().arc());
                    panic!("the storage init callback panics");
                })
                .arc(),
        );

        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| library.initialize()));
        assert!(outcome.is_err(), "the callback panic reaches the caller");
        assert_eq!(
            *seen.lock().unwrap(),
            [(true, true)],
            "the unwinding MainInit destroys its storage clone after every library mutex"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn init_storage_drop_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = Arc::new(manufacture_library());
        let seen: Arc<Mutex<Vec<(bool, bool)>>> = Arc::new(Mutex::new(Vec::new()));

        let probe = DropProbe {
            library: Arc::clone(&library),
            seen: Arc::clone(&seen),
        };
        let swap = Arc::clone(&library);
        library.register_storage(
            manufacture_storage()
                .on_init(move || {
                    let _ = &probe;
                    swap.register_storage(manufacture_storage().arc());
                    Ok(())
                })
                .arc(),
        );

        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(
            *seen.lock().unwrap(),
            [(true, true)],
            "MainInit's storage clone is destroyed after every library mutex"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn command_single_service_snapshot() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();

        let used: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let services = |name: &'static str, presence: bool| {
            let recorder = Arc::clone(&used);
            let platform = TestPlatform::new()
                .on_physical_presence(move || {
                    recorder.lock().unwrap().push(format!("platform:{name}"));
                    presence
                })
                .arc();
            let recorder = Arc::clone(&used);
            let storage = TestStorage::new()
                .on_store(move |kind, _| {
                    assert_eq!(kind, StateBlobKind::Permanent);
                    recorder.lock().unwrap().push(format!("storage:{name}"));
                    Ok(())
                })
                .arc();
            ExternalServices::new(platform, storage)
        };

        let register_b = Arc::clone(&library);
        let b_services = services("b", true);
        let a_recorder = Arc::clone(&used);
        let a_storage = {
            let recorder = Arc::clone(&used);
            TestStorage::new()
                .on_store(move |_, _| {
                    recorder.lock().unwrap().push("storage:a".to_owned());
                    Ok(())
                })
                .arc()
        };
        library.register_external_services(ExternalServices::new(
            TestPlatform::new()
                .on_physical_presence(move || {
                    a_recorder.lock().unwrap().push("platform:a".to_owned());
                    register_b.register_external_services(b_services.clone());
                    false
                })
                .arc(),
            a_storage,
        ));

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        assert_eq!(
            *used.lock().unwrap(),
            ["platform:a", "storage:a"],
            "the running command never mixes service generations"
        );
        assert_eq!(library.tpm2_runtime_physical_presence(), Some(false));

        used.lock().unwrap().clear();
        assert_eq!(response_code(&execute(&library, &shutdown_state())), 0);
        assert_eq!(
            *used.lock().unwrap(),
            ["platform:b", "storage:b"],
            "the next command uses the newly registered pair"
        );
        assert_eq!(library.tpm2_runtime_physical_presence(), Some(true));
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn stale_request_drop() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = started_library();

        assert_eq!(library.cancel(), TPM_SUCCESS);
        assert!(library.cancel_is_requested());
        library.terminate();
        assert_eq!(
            library.cancel(),
            TPM_SUCCESS,
            "still dispatched to TPM 2.0 after Terminate"
        );
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(
            response_code(&execute(&library, &startup_clear())),
            0,
            "the next command drops the stale request before dispatch"
        );
        assert!(!library.cancel_is_requested());
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn storage_execution_outside_state_lock() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();

        let seen: Arc<Mutex<Vec<(&'static str, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let observed = |what: &'static str,
                        seen: &Arc<Mutex<Vec<(&'static str, bool)>>>,
                        library: &Arc<Tpm>| {
            let entry = (what, library.state_is_unlocked());
            seen.lock().unwrap().push(entry);
        };
        let can_store_seen = Arc::clone(&seen);
        let can_store_library = Arc::clone(&library);
        let store_seen = Arc::clone(&seen);
        let store_library = Arc::clone(&library);
        library.register_storage(
            TestStorage::new()
                .on_can_store(move || {
                    observed("supports_store", &can_store_seen, &can_store_library);
                    true
                })
                .on_store(move |_, _| {
                    observed("store", &store_seen, &store_library);
                    Ok(())
                })
                .arc(),
        );

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        assert_eq!(
            *seen.lock().unwrap(),
            [("supports_store", true), ("store", true)],
            "the commit calls storage with the state mutex free"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn validation_failure_storage_release() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = tpm2_library();
        library.register_storage(TestStorage::new().on_init(|| Err(0x4242)).arc());

        assert_eq!(
            library.validate_state(validation_mask(VALIDATE_PERMANENT)),
            0x4242
        );
        assert_eq!(
            library.validate_state(validation_mask(VALIDATE_PERMANENT)),
            0x4242,
            "the next validation still acquires storage"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn unchanged_state_no_commit() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();
        let stores = Arc::new(Mutex::new(0u32));
        let counter = Arc::clone(&stores);
        library.register_storage(
            TestStorage::new()
                .on_store(move |_, _| {
                    *counter.lock().unwrap() += 1;
                    Ok(())
                })
                .arc(),
        );

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        assert_eq!(*stores.lock().unwrap(), 1, "TPM2_Startup commits once");

        assert_eq!(
            response_code(&execute(&library, &startup_clear())),
            0x100,
            "a repeated TPM2_Startup answers TPM_RC_INITIALIZE"
        );
        assert_eq!(
            response_code(&execute(&library, &unknown_command())),
            0x143,
            "an unsupported command answers TPM_RC_COMMAND_CODE"
        );
        assert_eq!(
            *stores.lock().unwrap(),
            1,
            "neither reaches the storage backend"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn reentrant_storage_registration() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = running_library();

        let first_stores = Arc::new(Mutex::new(0u32));
        let second_stores = Arc::new(Mutex::new(0u32));
        let first_counter = Arc::clone(&first_stores);
        let second_counter = Arc::clone(&second_stores);
        let reentrant = Arc::clone(&library);
        library.register_storage(
            TestStorage::new()
                .on_store(move |_, _| {
                    *first_counter.lock().unwrap() += 1;
                    let counter = Arc::clone(&second_counter);
                    reentrant.register_storage(
                        TestStorage::new()
                            .on_store(move |_, _| {
                                *counter.lock().unwrap() += 1;
                                Ok(())
                            })
                            .arc(),
                    );
                    Ok(())
                })
                .arc(),
        );

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        assert_eq!(
            (
                *first_stores.lock().unwrap(),
                *second_stores.lock().unwrap()
            ),
            (1, 0),
            "the running commit completes through the backend execute captured"
        );

        assert_eq!(response_code(&execute(&library, &shutdown_state())), 0);
        assert_eq!(
            (
                *first_stores.lock().unwrap(),
                *second_stores.lock().unwrap()
            ),
            (1, 1),
            "the next command commits through the backend registered from inside store"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn terminate_clean_remanufacture() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert!(library.was_manufactured());
        library.terminate();
        *BACKEND_PERMALL.lock().unwrap() = None;
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library.lock_state().entropy_override = Some(deterministic_entropy);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert!(library.was_manufactured(), "a clean re-manufacture");
        assert_eq!(*BACKEND_STORES.lock().unwrap(), 2);
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn set_profile_configure_validate_lock_after_power_on() {
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

        assert_eq!(library.initialize(), TPM_SUCCESS);
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
    fn accepted_reversed_command_range_state_round_trip() {
        const PROFILE: &[u8] = br#"{"Name":"custom","StateFormatLevel":2,"Commands":"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x140-0x130"}"#;

        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.set_profile(Some(PROFILE)), TPM_SUCCESS);
        assert_eq!(library.initialize(), TPM_SUCCESS);
        let StateOutput::Data(blob) = library
            .get_state(StateBlobKind::Permanent)
            .expect("the accepted profile can be serialized")
        else {
            panic!("a manufactured TPM has permanent state");
        };
        assert_eq!(*BACKEND_PERMALL.lock().unwrap(), Some(blob.clone()));
        let active_profile = library.get_info(INFO_ACTIVE_PROFILE);
        library.terminate();

        let restored = tpm2_library();
        assert_eq!(
            restored.set_state(StateBlobKind::Permanent, StateInput::Data(blob.clone())),
            TPM_SUCCESS
        );
        assert_eq!(restored.initialize(), TPM_SUCCESS);
        assert!(!restored.was_manufactured());
        assert_eq!(
            restored.get_state(StateBlobKind::Permanent),
            Ok(StateOutput::Data(blob)),
            "the compressed command bitmaps survive serialization and restore"
        );
        assert_eq!(restored.get_info(INFO_ACTIVE_PROFILE), active_profile);
        restored.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn set_profile_null_configuration_clear() {
        let library = manufacture_library();
        assert_eq!(
            library.set_profile(Some(br#"{"Name":"default-v1"}"#)),
            TPM_SUCCESS
        );
        assert_eq!(library.set_profile(None), TPM_SUCCESS);
        assert!(library.lock_state().configured_profile.is_none());
    }

    #[test]
    fn set_profile_no_tpm2_selection_failure() {
        let library = Tpm::default();
        assert_eq!(library.set_profile(Some(br#"{"Name":"null"}"#)), TPM_FAIL);
        assert_eq!(library.set_profile(None), TPM_FAIL);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn entropy_failure_rollback_and_retry() {
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
            assert_eq!(library.initialize(), TPM_FAIL, "attempt {attempt}");
            assert!(!library.runtime_is_initialized(), "attempt {attempt}");
            let state = library.lock_state();
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
    fn main_init_failure_preload_preservation() {
        use crate::library::constants::TPM_RC_INSUFFICIENT;

        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Permanent, vec![4, 5, 6]);
        assert_eq!(library.initialize(), TPM_RC_INSUFFICIENT);
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Permanent),
            PreloadedBlob::Data(vec![4, 5, 6]),
            "the staged bytes must survive a failed MainInit unmodified"
        );
        assert!(!library.was_manufactured());
        assert!(!library.runtime_is_initialized());
    }

    #[test]
    fn tis_call_no_tpm2_selection_failure() {
        let library = Tpm::default();
        assert_eq!(library.tis_established_get(), Err(TPM_FAIL));
        assert_eq!(library.tis_established_reset(), TPM_FAIL);
        assert_eq!(library.tis_hash_start(), TPM_FAIL);
        assert_eq!(library.tis_hash_data(&[1, 2]), TPM_FAIL);
        assert_eq!(library.tis_hash_end(), TPM_FAIL);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tis_call_uninitialized_runtime_failure() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
    fn tis_locality_platform() -> Arc<dyn Platform> {
        TestPlatform::new()
            .on_locality(|| TIS_LOCALITY.load(std::sync::atomic::Ordering::SeqCst))
            .arc()
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tis_established_library_lifecycle() {
        use std::sync::atomic::Ordering;

        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.initialize(), TPM_SUCCESS);

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

        library.register_external_services(ExternalServices::new(
            tis_locality_platform(),
            manufacture_storage().arc(),
        ));
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
    fn restored_volatile_state_established_flag_preservation() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
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
        assert_eq!(library.initialize(), TPM_SUCCESS);
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
    fn state_transfer_no_tpm2_selection_failure() {
        let library = Tpm::default();
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
    fn empty_input_empty_cached_state_all_kinds() {
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
    fn nonempty_save_state_upstream_rejection() {
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
    fn valid_permanent_state_byte_exact_cache() {
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
    fn malformed_permanent_state_rejection_cache_clear() {
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
        drop(state);
        assert!(!library.runtime_is_initialized(), "nothing was published");
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn valid_volatile_state_staged_permanent_validation() {
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
        drop(state);
        assert!(!library.runtime_is_initialized());
        assert_eq!(
            library.initialize(),
            TPM_SUCCESS,
            "the pair really restores"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn mismatched_volatile_seed_tie_rejection_cache_clear() {
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
    fn volatile_state_missing_permanent_failure() {
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
    fn volatile_state_empty_cached_permanent_failure() {
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
    fn volatile_state_backend_permanent_fallback() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = tpm2_library();
        library.register_storage(
            fixture_backend_storage()
                .on_init(|| {
                    record_event("init".to_owned());
                    Ok(())
                })
                .arc(),
        );
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
    fn active_runtime_state_rejection_empty_state_acceptance() {
        let library = tpm2_library();
        library.stage_empty_state(StateBlobKind::Permanent);
        assert_eq!(library.initialize(), TPM_SUCCESS);

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
    fn running_tpm_state_kind_snapshot() {
        let library = tpm2_library();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(library.initialize(), TPM_SUCCESS);

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
    fn stopped_tpm_cached_state_copy_no_consumption() {
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
    fn stopped_tpm_no_cache_no_backend_failure() {
        let library = tpm2_library();
        for kind in ALL_KINDS {
            assert_eq!(library.get_state(kind), Err(TPM_FAIL));
        }
    }

    #[cfg(feature = "tpm2")]
    static NVRAM_EVENTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    #[cfg(feature = "tpm2")]
    fn oracle_name(kind: StateBlobKind) -> &'static str {
        match kind {
            StateBlobKind::Permanent => "permall",
            StateBlobKind::Volatile => "volatilestate",
            StateBlobKind::SaveState => "savestate",
        }
    }

    #[cfg(feature = "tpm2")]
    fn record_event(event: String) {
        NVRAM_EVENTS.lock().unwrap().push(event);
    }

    #[cfg(feature = "tpm2")]
    fn recording_init(outcome: Result<(), TpmResult>) -> TestStorage {
        TestStorage::new().on_init(move || {
            record_event("init".to_owned());
            outcome
        })
    }

    #[cfg(feature = "tpm2")]
    fn recording_load(
        storage: TestStorage,
        outcome: fn(StateBlobKind) -> Result<StorageLoad, TpmResult>,
    ) -> TestStorage {
        storage.on_load(move |kind| {
            record_event(format!("load:{}", oracle_name(kind)));
            outcome(kind)
        })
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn get_state_storage_init_reentry() {
        let library = Arc::new(tpm2_library());
        let reentrant = Arc::downgrade(&library);
        library.register_storage(
            TestStorage::new()
                .on_init(move || {
                    let library = reentrant.upgrade().expect("the caller owns the TPM");
                    assert!(
                        library.state_is_unlocked(),
                        "storage initialization must run outside the state lock"
                    );
                    assert_eq!(library.get_tpm_property(TpmProperty::KeyHandles), Some(3));
                    Ok(())
                })
                .on_load(|_| Ok(StorageLoad::Data(vec![0xa5, 0x5a])))
                .arc(),
        );

        for kind in ALL_KINDS {
            assert_eq!(
                library.get_state(kind),
                Ok(StateOutput::Data(vec![0xa5, 0x5a])),
                "{kind:?}"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn get_state_storage_load_reentry() {
        let library = Arc::new(tpm2_library());
        let reentrant = Arc::downgrade(&library);
        library.register_storage(
            TestStorage::new()
                .on_load(move |_| {
                    let library = reentrant.upgrade().expect("the caller owns the TPM");
                    assert!(
                        library.state_is_unlocked(),
                        "storage loading must run outside the state lock"
                    );
                    assert_eq!(library.get_tpm_property(TpmProperty::KeyHandles), Some(3));
                    Ok(StorageLoad::Data(vec![0xa5, 0x5a]))
                })
                .arc(),
        );

        for kind in ALL_KINDS {
            assert_eq!(
                library.get_state(kind),
                Ok(StateOutput::Data(vec![0xa5, 0x5a])),
                "{kind:?}"
            );
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn missing_cache_backend_fallback_order() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        NVRAM_EVENTS.lock().unwrap().clear();
        let library = tpm2_library();
        library.register_storage(
            recording_load(recording_init(Ok(())), |_| {
                Ok(StorageLoad::Data(vec![0xa5, 0x5a]))
            })
            .arc(),
        );
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
    fn backend_error_code_propagation() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        NVRAM_EVENTS.lock().unwrap().clear();
        let library = tpm2_library();

        library.register_storage(
            recording_load(recording_init(Err(0x4242)), |_| {
                Ok(StorageLoad::Data(vec![0xa5, 0x5a]))
            })
            .arc(),
        );
        assert_eq!(library.get_state(StateBlobKind::Permanent), Err(0x4242));
        assert_eq!(
            *NVRAM_EVENTS.lock().unwrap(),
            ["init".to_owned()],
            "a failed initialization stops before the load"
        );

        library.register_storage(recording_load(recording_init(Ok(())), |_| Err(0x1357)).arc());
        assert_eq!(library.get_state(StateBlobKind::Permanent), Err(0x1357));

        library.register_storage(recording_init(Ok(())).on_load(backend_load).arc());
        *BACKEND_PERMALL.lock().unwrap() = None;
        assert_eq!(
            library.get_state(StateBlobKind::Permanent),
            Err(crate::library::constants::TPM_RETRY),
            "an absent blob is reported with the callback's own code"
        );

        library.register_storage(recording_init(Ok(())).arc());
        assert_eq!(
            library.get_state(StateBlobKind::Permanent),
            Err(TPM_FAIL),
            "no load callback: nothing can be read back"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_validation_upstream_parser_result() {
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
    fn restore_volatile_error_code_collapse() {
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
            assert_eq!(library.initialize(), TPM_RC_FAILURE);
        }
    }

    const VALIDATE_PERMANENT: u32 = 1;
    const VALIDATE_VOLATILE: u32 = 2;
    const VALIDATE_SAVE_STATE: u32 = 4;

    fn validation_mask(bits: u32) -> StateValidationMask {
        StateValidationMask::from_bits(bits)
    }

    #[test]
    fn validation_no_tpm2_selection_failure() {
        let library = Tpm::default();
        for bits in [
            0,
            VALIDATE_PERMANENT,
            VALIDATE_VOLATILE,
            VALIDATE_SAVE_STATE,
            VALIDATE_PERMANENT | VALIDATE_VOLATILE | VALIDATE_SAVE_STATE,
            u32::MAX,
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
    fn state_backend_load(kind: StateBlobKind) -> Result<StorageLoad, TpmResult> {
        let blob = match kind {
            StateBlobKind::Permanent => BACKEND_PERMALL.lock().unwrap().clone(),
            StateBlobKind::Volatile => BACKEND_VOLATILESTATE.lock().unwrap().clone(),
            StateBlobKind::SaveState => None,
        };
        Ok(backend_blob(blob))
    }

    #[cfg(feature = "tpm2")]
    fn state_backend_storage() -> TestStorage {
        recording_load(recording_init(Ok(())), state_backend_load)
    }

    #[cfg(feature = "tpm2")]
    struct ValidationFixture {
        library: Tpm,
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
            self.library.register_storage(state_backend_storage().arc());
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

        fn validate(&self, bits: u32) -> TpmResult {
            self.library.validate_state(validation_mask(bits))
        }
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn empty_mask_nvram_initialization() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        assert_eq!(fixture.validate(0), TPM_SUCCESS);
        assert_eq!(
            fixture.events(),
            ["init".to_owned()],
            "upstream calls tpm_nvram_init before it looks at any bit"
        );

        fixture.forget_events();
        fixture.library.register_storage(
            recording_load(recording_init(Err(0x4242)), state_backend_load).arc(),
        );
        assert_eq!(fixture.validate(0), 0x4242);
        assert_eq!(fixture.events(), ["init".to_owned()]);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn unknown_bits_no_validation() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        for bits in [8, 16, 1 << 30, 1 << 31] {
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
    fn permanent_validation_backend_only_read() {
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
    fn malformed_permanent_state_exact_parser_code() {
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
    fn unavailable_permanent_blob_zero_length_distinction() {
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

        fixture.library.register_storage(
            recording_load(recording_init(Ok(())), |_| {
                Ok(StorageLoad::Data(Vec::new()))
            })
            .arc(),
        );
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            TPM_RC_INSUFFICIENT,
            "a real buffer of zero length reaches the parser"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn volatile_validation_against_permanent_state() {
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
    fn malformed_permanent_blob_volatile_step_abort() {
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
    fn malformed_volatile_state_exact_parser_codes() {
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
    fn failure_mode_volatile_validation_no_restore() {
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
        assert!(!fixture.library.runtime_is_initialized());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn explicit_empty_cached_volatile_validation_success() {
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
    fn volatile_load_failure_swallow_permanent_propagation() {
        let mut fixture = ValidationFixture::new();
        fixture
            .library
            .register_storage(recording_load(recording_init(Ok(())), |_| Err(0x1357)).arc());
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
    fn validation_missing_backend_callbacks_upstream_parity() {
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

        fixture
            .library
            .register_storage(recording_load(TestStorage::new(), state_backend_load).arc());
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
    fn validation_library_state_unchanged() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        let permanent = crate::library::tpm2::valid_permanent_state_fixture();
        let volatile = crate::library::tpm2::valid_volatile_state_fixture();
        *BACKEND_PERMALL.lock().unwrap() = Some(permanent.clone());
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(volatile.clone());

        fixture
            .library
            .register_storage(state_backend_storage().on_store(backend_store).arc());
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
        assert_eq!(state.selected, crate::library::TpmVersion::V2_0);
        assert_eq!(state.tpm2_buffer_size, 3000);
        assert_eq!(state.configured_profile.as_deref(), Some(&profile[..]));
        assert!(!state.version_locked);
        assert!(state.services.storage_ref().supports_store());
        assert!(
            state.installed_permanent.is_some(),
            "the decoded permanent state is installed, as upstream unmarshals it into its NV image"
        );
        drop(state);
        assert!(
            !fixture.library.runtime_is_initialized(),
            "no runtime is ever published"
        );
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
    fn c_oracle_scenario_replay() {
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
    fn permanent_selecting_mask_c_oracle_parity() {
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
    fn volatile_only_validation_c_oracle_parity() {
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
    fn volatile_only_mask_no_permanent_backend_access() {
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
    fn volatile_blob_no_installed_permanent_oracle_match() {
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
    fn volatile_blob_installed_permanent_oracle_match() {
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
    fn permanent_validation_decoded_state_install() {
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
    fn failed_permanent_validation_no_install() {
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
    fn failed_volatile_step_permanent_state_retention() {
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
    fn failed_volatile_set_state_permanent_install() {
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
    fn volatile_object_state_format_level_conformance() {
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
    fn running_tpm_volatile_validation_against_runtime() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() = Some(fixture.permall());
        assert_eq!(fixture.library.initialize(), TPM_SUCCESS);
        let running = fixture
            .library
            .volatile_all_store()
            .expect("a running TPM snapshots its volatile state");
        *BACKEND_VOLATILESTATE.lock().unwrap() = Some(running);
        *BACKEND_PERMALL.lock().unwrap() = None;
        fixture.forget_events();
        let result = fixture.validate(VALIDATE_VOLATILE);
        fixture.assert_oracle("running_tpm", result);
        assert!(fixture.library.runtime_is_initialized());
        fixture.library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn terminate_installed_permanent_context_clear() {
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
    fn version_switch_permanent_context_clear() {
        use crate::library::constants::TPM_RC_VALUE;

        let fixture = ValidationFixture::new();
        fixture.with_backend();
        fixture.accept(StateBlobKind::Permanent, fixture.permall());
        let volatilestate = fixture.volatilestate();
        fixture.accept(StateBlobKind::Volatile, volatilestate.clone());
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_SUCCESS);

        assert_eq!(
            fixture
                .library
                .set_version(crate::library::TpmVersion::V1_2),
            TPM_SUCCESS
        );
        assert_eq!(
            fixture
                .library
                .set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert!(fixture.library.lock_state().installed_permanent.is_none());
        fixture.cache(StateBlobKind::Volatile, volatilestate);
        assert_eq!(fixture.validate(VALIDATE_VOLATILE), TPM_RC_VALUE);
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cached_malformed_volatile_backend_code_match() {
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
    fn running_tpm_validation_given_blob_report() {
        let fixture = ValidationFixture::new();
        fixture.with_backend();
        *BACKEND_PERMALL.lock().unwrap() =
            Some(crate::library::tpm2::valid_permanent_state_fixture());
        assert_eq!(fixture.library.initialize(), TPM_SUCCESS);
        let locality = fixture.library.tpm2_runtime_locality();

        assert_eq!(fixture.validate(VALIDATE_PERMANENT), TPM_SUCCESS);
        *BACKEND_PERMALL.lock().unwrap() = Some(vec![1, 2, 3]);
        assert_eq!(
            fixture.validate(VALIDATE_PERMANENT),
            crate::library::constants::TPM_RC_INSUFFICIENT
        );

        assert!(
            fixture.library.runtime_is_initialized(),
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
    fn gated_init(storage: TestStorage) -> TestStorage {
        storage.on_init(|| match gate::park() {
            gate::Park::Parked | gate::Park::PassedThrough => Ok(()),
            gate::Park::TimedOut => Err(TPM_FAIL),
        })
    }

    #[cfg(feature = "tpm2")]
    fn gated_library() -> Tpm {
        let library = tpm2_library();
        library.register_storage(gated_init(fixture_backend_storage()).arc());
        library
    }

    #[cfg(feature = "tpm2")]
    fn stage_volatile_while(library: &Tpm, interfere: impl FnOnce(&Tpm)) -> TpmResult {
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
    fn undisturbed_gated_validation_blob_caching() {
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
    fn concurrent_version_switch_blob_discard() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = stage_volatile_while(&library, |library| {
            library.lock_state().selected = crate::library::TpmVersion::V1_2;
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
    fn validate_state_while(library: &Tpm, interfere: impl FnOnce(&Tpm)) -> TpmResult {
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
    fn undisturbed_gated_validation_own_result() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        library
            .lock_state()
            .preloaded_state
            .set_data(StateBlobKind::Volatile, vec![1, 2, 3]);
        assert_eq!(validate_state_while(&library, |_| {}), TPM_SUCCESS);
        assert!(!library.runtime_is_initialized());
        assert_eq!(
            *library
                .lock_state()
                .preloaded_state
                .get(StateBlobKind::Volatile),
            PreloadedBlob::Data(vec![1, 2, 3])
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn concurrent_version_switch_validation_supersession() {
        let _serial = gate::SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        gate::reset();
        let library = gated_library();
        let result = validate_state_while(&library, |library| {
            library.lock_state().selected = crate::library::TpmVersion::V1_2;
        });
        assert_eq!(
            result, TPM_FAIL,
            "a TPM2 validation is never reported against a TPM 1.2 selection"
        );
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn sequential_main_init_acceptance() {
        let library = tpm2_library();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(library.initialize(), TPM_SUCCESS);
        library.terminate();
        library.lock_state().preloaded_state.set_data(
            StateBlobKind::Permanent,
            crate::library::tpm2::valid_permanent_state_fixture(),
        );
        assert_eq!(
            library.initialize(),
            TPM_SUCCESS,
            "the lifecycle is released by every attempt"
        );
        library.terminate();
        assert_eq!(
            library.initialize(),
            TPM_FAIL,
            "no staged state and no backend, not a lifecycle rejection"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failure_mode_volatile_set_state_failure_boundary() {
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
            library.initialize(),
            TPM_RC_FAILURE,
            "restoring the same blob still reaches the failure boundary"
        );
        assert!(!library.runtime_is_initialized());
    }

    #[test]
    fn cancel_no_tpm2_selection_failure() {
        let library = Tpm::default();
        assert_eq!(
            library.cancel(),
            TPM_FAIL,
            "TPM 1.2 and the disabled interface answer TPM_FAIL"
        );
        assert!(!library.cancel_is_requested());
    }

    #[cfg(feature = "tpm1")]
    #[test]
    fn cancel_tpm1_selection_failure() {
        let library = Tpm::default();
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V1_2),
            TPM_SUCCESS
        );
        assert_eq!(library.cancel(), TPM_FAIL);
        assert!(!library.cancel_is_requested());
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn tpm2_reselection_cancel_availability() {
        let library = Tpm::default();
        assert_eq!(library.cancel(), TPM_FAIL);
        assert_eq!(
            library.set_version(crate::library::TpmVersion::V2_0),
            TPM_SUCCESS
        );
        assert_eq!(library.cancel(), TPM_SUCCESS);
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
    fn unknown_command() -> crate::library::CommandInput {
        crate::library::CommandInput::new(
            10,
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x00, 0x00, 0x00],
        )
    }

    #[cfg(feature = "tpm2")]
    fn shutdown_state() -> crate::library::CommandInput {
        crate::library::CommandInput::new(
            12,
            vec![
                0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x01,
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
    fn execute(library: &Tpm, command: &crate::library::CommandInput) -> Vec<u8> {
        library.process_input(command).expect("the response fits")
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
    fn started_library() -> Tpm {
        *BACKEND_PERMALL.lock().unwrap() = None;
        *BACKEND_STORES.lock().unwrap() = 0;
        let library = manufacture_library();
        assert_eq!(library.initialize(), TPM_SUCCESS);
        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        library
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn pre_command_request_no_cancellation() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = started_library();

        assert_eq!(library.cancel(), TPM_SUCCESS);
        assert!(library.cancel_is_requested());
        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA1]));
        assert_eq!(response_code(&response), 0, "{response:02x?}");
        assert!(
            !library.cancel_is_requested(),
            "the command start cleared it"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn mid_command_request_visibility_no_cancellation() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let gate = tpm2::arm_self_test_gate();
        library.park_self_test_on_gate();
        let worker_library = Arc::clone(&library);
        let worker = std::thread::spawn(move || {
            worker_library.process_input(&incremental_self_test(&[TPM_ALG_SHA1, TPM_ALG_SHA256]))
        });

        gate.wait_until_entered();
        assert!(
            !library.cancel_is_requested(),
            "the command start cleared the pin"
        );
        assert_eq!(
            library.cancel(),
            TPM_SUCCESS,
            "cancellation does not block on the command's mutex"
        );
        assert!(
            library.cancel_is_requested(),
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
            library.cancel_is_requested(),
            "nothing clears the pin at command completion"
        );

        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA384]));
        assert_eq!(response_code(&response), 0);
        assert!(
            !library.cancel_is_requested(),
            "the stale request is dropped by the next command start"
        );
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cancellation_termination_race_usability() {
        let _serial = MANUFACTURE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let library = Arc::new(started_library());

        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || {
            for _ in 0..4096 {
                assert_eq!(canceller_library.cancel(), TPM_SUCCESS);
            }
        });

        for _ in 0..8 {
            library.terminate();
            assert_eq!(library.initialize(), TPM_SUCCESS);
        }
        canceller.join().expect("the canceller thread finished");

        assert_eq!(response_code(&execute(&library, &startup_clear())), 0);
        let response = execute(&library, &incremental_self_test(&[TPM_ALG_SHA1]));
        assert_eq!(response_code(&response), 0, "{response:02x?}");
        library.terminate();
    }

    #[cfg(all(feature = "tpm2", feature = "tpm1"))]
    #[test]
    fn cancellation_version_selection_race_consistency() {
        let library = Arc::new(tpm2_library());
        let canceller_library = Arc::clone(&library);
        let canceller = std::thread::spawn(move || {
            for _ in 0..4096 {
                let code = canceller_library.cancel();
                assert!(code == TPM_SUCCESS || code == TPM_FAIL, "{code}");
            }
        });

        for _ in 0..256 {
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V1_2),
                TPM_SUCCESS
            );
            assert_eq!(
                library.set_version(crate::library::TpmVersion::V2_0),
                TPM_SUCCESS
            );
        }
        canceller.join().expect("the canceller finished");
        assert_eq!(
            library.cancel(),
            TPM_SUCCESS,
            "the racing selections leave a consistent TPM 2.0 selection"
        );
    }
}
