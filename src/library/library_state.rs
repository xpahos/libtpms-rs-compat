use core::ffi::c_int;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::ffi_types::{
    LibtpmsCallbacks, TpmResult, TpmlibInfoFlags, TpmlibTpmProperty, TpmlibTpmVersion,
};

#[cfg(feature = "tpm2")]
use super::constants::TPM_INVALID_POSTINIT;
use super::constants::{
    TPM_BUFFER_MAX, TPM_FAIL, TPM_SUCCESS, TPMLIB_TPM_VERSION_1_2, TPMLIB_TPM_VERSION_2,
    TPMPROP_TPM_BUFFER_MAX,
};
use super::preloaded_state::PreloadedState;
#[cfg(feature = "tpm2")]
use super::state_blob::StateBlobKind;

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

struct LibraryState {
    selected: TpmVersion,
    version_locked: bool,
    preloaded_state: PreloadedState,
    callbacks: LibtpmsCallbacks,
    #[cfg(feature = "tpm2")]
    tpm2_buffer_size: u32,
    #[cfg(feature = "tpm2")]
    configured_profile: Option<Vec<u8>>,
    #[cfg(feature = "tpm2")]
    tpm2_runtime: Option<Box<tpm2::Tpm2Runtime>>,
    #[cfg(all(test, feature = "tpm2"))]
    entropy_override: Option<tpm2::EntropySource>,
}

impl LibraryState {
    const fn new() -> Self {
        Self {
            selected: TpmVersion::V1_2,
            version_locked: false,
            preloaded_state: PreloadedState::new(),
            callbacks: LibtpmsCallbacks::empty(),
            #[cfg(feature = "tpm2")]
            tpm2_buffer_size: tpm2::DEFAULT_BUFFER_SIZE,
            #[cfg(feature = "tpm2")]
            configured_profile: None,
            #[cfg(feature = "tpm2")]
            tpm2_runtime: None,
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
        }
        self.selected = requested;
        TPM_SUCCESS
    }

    fn clear_preloaded_state(&mut self) {
        self.preloaded_state.clear_all();
    }
}

pub struct Library {
    state: Mutex<LibraryState>,
}

impl Library {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(LibraryState::new()),
        }
    }

    pub fn global() -> &'static Self {
        &LIBRARY
    }

    fn lock_state(&self) -> MutexGuard<'_, LibraryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn choose_tpm_version(&self, version: TpmlibTpmVersion) -> TpmResult {
        self.lock_state().choose_tpm_version(version)
    }

    pub fn main_init(&self) -> TpmResult {
        let mut state = self.lock_state();
        state.version_locked = true;
        let selected = state.selected;
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

        match selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => match tpm2::main_init(context) {
                Ok(mut runtime) => {
                    let mut state = self.lock_state();
                    state.preloaded_state.take(StateBlobKind::Permanent);
                    state.preloaded_state.take(StateBlobKind::Volatile);
                    runtime.buffer_size = state.tpm2_buffer_size;
                    state.tpm2_runtime = Some(runtime);
                    TPM_SUCCESS
                }
                Err(code) => {
                    self.lock_state().tpm2_runtime = None;
                    code
                }
            },
            _ => TPM_FAIL,
        }
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
                    locality: host_locality(&callbacks),
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
    pub(in crate::library) fn stage_empty_state(&self, kind: StateBlobKind) {
        self.lock_state().preloaded_state.set_empty(kind);
    }

    pub fn terminate(&self) {
        let selected = self.lock_state().selected;
        match selected {
            #[cfg(feature = "tpm2")]
            TpmVersion::V2_0 => tpm2::terminate(),
            _ => {}
        }
        let mut state = self.lock_state();

        #[cfg(feature = "tpm2")]
        {
            state.tpm2_runtime = None;
            if selected == TpmVersion::V2_0 {
                state.configured_profile = None;
            }
        }
        state.version_locked = false;
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
    locality: u8,
}

#[cfg(feature = "tpm2")]
impl Tpm2ProcessContext<'_> {
    pub(crate) fn execute(self, command: &super::CommandInput) -> Result<Vec<u8>, TpmResult> {
        let mut state = self.library.lock_state();
        let host_nvram = tpm2::HostNvram::new(state.callbacks);
        match state.tpm2_runtime.as_deref_mut() {
            Some(runtime) => tpm2::process(runtime, self.locality, command, |runtime| {
                tpm2::host_nv_commit(&host_nvram, runtime)
            }),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(feature = "tpm2")]
fn host_locality_raw(callbacks: &LibtpmsCallbacks) -> u32 {
    let Some(callback) = callbacks.tpm_io_getlocality else {
        return 0;
    };
    let mut locality: crate::ffi_types::TpmModifierIndicator = 0;
    // SAFETY: the copied callback has the exact C ABI signature, and the
    // out-pointer references a live local for the duration of the call.
    let _ = unsafe { callback(&mut locality, 0) };
    locality
}

#[cfg(feature = "tpm2")]
fn host_locality(callbacks: &LibtpmsCallbacks) -> u8 {
    host_locality_raw(callbacks) as u8
}

static LIBRARY: Library = Library::new();

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "tpm2")]
    use crate::library::preloaded_state::PreloadedBlob;
    use crate::library::state_blob::StateBlobKind;

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
        const INFO_ACTIVE_PROFILE: crate::ffi_types::TpmlibInfoFlags = 32;

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
            *data = crate::ffi_support::malloc_bytes(&BACKEND_BLOB);
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
        const INFO_ACTIVE_PROFILE: crate::ffi_types::TpmlibInfoFlags = 32;

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
            *data = crate::ffi_support::malloc_bytes(&blob);
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
    const INFO_ACTIVE_PROFILE: crate::ffi_types::TpmlibInfoFlags = 32;

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
        locality: *mut crate::ffi_types::TpmModifierIndicator,
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
}
