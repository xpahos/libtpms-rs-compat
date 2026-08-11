use core::ffi::c_int;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::ffi_types::{
    LibtpmsCallbacks, TpmResult, TpmlibInfoFlags, TpmlibTpmProperty, TpmlibTpmVersion,
};

use super::cached_state::CachedState;
#[cfg(feature = "tpm2")]
use super::cached_state::StateKind;
#[cfg(feature = "tpm2")]
use super::constants::TPM_INVALID_POSTINIT;
use super::constants::{
    TPM_BUFFER_MAX, TPM_FAIL, TPM_SUCCESS, TPMLIB_TPM_VERSION_1_2, TPMLIB_TPM_VERSION_2,
    TPMPROP_TPM_BUFFER_MAX,
};

#[cfg(feature = "tpm2")]
use super::tpm2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TpmVersion {
    V1_2,
    V2_0,
}

struct LibraryState {
    selected: TpmVersion,
    version_locked: bool,
    cached_state: CachedState,
    callbacks: LibtpmsCallbacks,
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
            cached_state: CachedState::new(),
            callbacks: LibtpmsCallbacks::empty(),
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
            self.clear_cached_state();
        }
        self.selected = requested;
        TPM_SUCCESS
    }

    fn clear_cached_state(&mut self) {
        self.cached_state.clear_all();
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

    pub fn global() -> &'static Library {
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
            cached_permanent: state.cached_state.get(StateKind::Permanent).clone(),
            cached_volatile: state.cached_state.get(StateKind::Volatile).clone(),
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
                Ok(runtime) => {
                    let mut state = self.lock_state();
                    state.cached_state.take(StateKind::Permanent);
                    state.cached_state.take(StateKind::Volatile);
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

    pub fn register_callbacks(&self, table: LibtpmsCallbacks) {
        self.lock_state().callbacks = table;
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

impl Default for Library {
    fn default() -> Self {
        Self::new()
    }
}

static LIBRARY: Library = Library::new();

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "tpm2")]
    use crate::library::cached_state::CachedBlob;
    use crate::library::cached_state::StateKind;

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
    fn reselecting_same_version_keeps_cached_state() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Permanent, vec![1, 2, 3]);
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        assert!(
            library
                .lock_state()
                .cached_state
                .is_present(StateKind::Permanent)
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
    fn terminate_without_init_is_harmless_and_keeps_cached_state() {
        let library = Library::new();
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Permanent, vec![1, 2, 3]);
        library.terminate();
        assert!(!library.lock_state().version_locked);
        assert!(
            library
                .lock_state()
                .cached_state
                .is_present(StateKind::Permanent),
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
    fn switching_versions_clears_cached_state() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Permanent, vec![1, 2, 3]);
        library
            .lock_state()
            .cached_state
            .set_empty(StateKind::Volatile);
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_1_2),
            TPM_SUCCESS
        );
        let state = library.lock_state();
        assert!(!state.cached_state.is_present(StateKind::Permanent));
        assert!(!state.cached_state.is_present(StateKind::Volatile));
        assert!(!state.cached_state.is_present(StateKind::SaveState));
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn cached_empty_initializes_without_manufacture_and_is_consumed() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .cached_state
            .set_empty(StateKind::Permanent);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            *library.lock_state().cached_state.get(StateKind::Permanent),
            CachedBlob::Missing,
            "the staged entry is consumed on success"
        );
        assert!(library.lock_state().tpm2_runtime.is_some());
        assert!(!library.was_manufactured(), "no Manufacture ran");
        library.terminate();
    }

    #[cfg(feature = "tpm2")]
    #[test]
    fn failed_cached_empty_init_preserves_the_staged_entry() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .cached_state
            .set_empty(StateKind::Permanent);
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Volatile, vec![0xd0, 0x0d]);
        assert_eq!(
            library.main_init(),
            crate::library::constants::TPM_RC_FAILURE
        );
        assert_eq!(
            *library.lock_state().cached_state.get(StateKind::Permanent),
            CachedBlob::Empty,
            "the staged entry must survive a failed MainInit"
        );
        assert_eq!(
            *library.lock_state().cached_state.get(StateKind::Volatile),
            CachedBlob::Data(vec![0xd0, 0x0d])
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
            .cached_state
            .set_data(StateKind::Permanent, blob.clone());
        assert_eq!(
            library.get_info(INFO_ACTIVE_PROFILE).as_deref(),
            Some("{}"),
            "no active profile before a successful MainInit"
        );
        assert_eq!(library.main_init(), TPM_SUCCESS);
        assert_eq!(
            *library.lock_state().cached_state.get(StateKind::Permanent),
            CachedBlob::Missing,
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
    fn commit_phase_failure_preserves_cached_state_and_publishes_nothing() {
        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        let blob = crate::library::tpm2::commit_failing_permanent_state_fixture();
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Permanent, blob.clone());
        for attempt in 0..2 {
            assert_eq!(library.main_init(), TPM_FAIL, "attempt {attempt}");
            assert_eq!(
                *library.lock_state().cached_state.get(StateKind::Permanent),
                CachedBlob::Data(blob.clone()),
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
            .cached_state
            .set_data(StateKind::Permanent, blob);
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
            .cached_state
            .set_data(StateKind::Permanent, blob);
        library
            .lock_state()
            .cached_state
            .set_empty(StateKind::Volatile);
        assert_eq!(library.main_init(), TPM_SUCCESS);
        let state = library.lock_state();
        assert_eq!(
            *state.cached_state.get(StateKind::Permanent),
            CachedBlob::Missing
        );
        assert_eq!(
            *state.cached_state.get(StateKind::Volatile),
            CachedBlob::Missing,
            "the cached-empty volatile entry is consumed on success"
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
            .cached_state
            .set_data(StateKind::Permanent, permanent.clone());
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Volatile, volatile.clone());
        for attempt in 0..2 {
            assert_eq!(
                library.main_init(),
                crate::library::constants::TPM_RC_FAILURE,
                "attempt {attempt}"
            );
            let state = library.lock_state();
            assert_eq!(
                *state.cached_state.get(StateKind::Permanent),
                CachedBlob::Data(permanent.clone()),
                "attempt {attempt}: the staged permanent blob survives"
            );
            assert_eq!(
                *state.cached_state.get(StateKind::Volatile),
                CachedBlob::Data(volatile.clone()),
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
            .cached_state
            .set_data(StateKind::Permanent, permanent.clone());
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Volatile, volatile.clone());
        for attempt in 0..2 {
            assert_eq!(
                library.main_init(),
                crate::library::constants::TPM_RC_FAILURE,
                "attempt {attempt}"
            );
            let state = library.lock_state();
            assert_eq!(
                *state.cached_state.get(StateKind::Permanent),
                CachedBlob::Data(permanent.clone()),
                "attempt {attempt}: the staged permanent blob survives"
            );
            assert_eq!(
                *state.cached_state.get(StateKind::Volatile),
                CachedBlob::Data(volatile.clone()),
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
                .cached_state
                .set_data(StateKind::Permanent, permanent.clone());
            library
                .lock_state()
                .cached_state
                .set_data(StateKind::Volatile, volatile.clone());
            assert_eq!(library.main_init(), TPM_SUCCESS, "round {round}");
            let state = library.lock_state();
            assert_eq!(
                *state.cached_state.get(StateKind::Permanent),
                CachedBlob::Missing,
                "round {round}: the permanent entry is consumed"
            );
            assert_eq!(
                *state.cached_state.get(StateKind::Volatile),
                CachedBlob::Missing,
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
            .cached_state
            .set_data(StateKind::Volatile, vec![0xd0, 0x0d]);

        for attempt in 0..2 {
            assert_eq!(library.main_init(), TPM_FAIL, "attempt {attempt}");
            let state = library.lock_state();
            assert!(state.tpm2_runtime.is_none(), "attempt {attempt}");
            assert_eq!(
                *state.cached_state.get(StateKind::Volatile),
                CachedBlob::Data(vec![0xd0, 0x0d]),
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
    fn failed_main_init_does_not_consume_cached_data() {
        use crate::library::constants::TPM_RC_INSUFFICIENT;

        let library = Library::new();
        assert_eq!(
            library.choose_tpm_version(TPMLIB_TPM_VERSION_2),
            TPM_SUCCESS
        );
        library
            .lock_state()
            .cached_state
            .set_data(StateKind::Permanent, vec![4, 5, 6]);
        assert_eq!(library.main_init(), TPM_RC_INSUFFICIENT);
        assert_eq!(
            *library.lock_state().cached_state.get(StateKind::Permanent),
            CachedBlob::Data(vec![4, 5, 6]),
            "the staged bytes must survive a failed MainInit unmodified"
        );
        assert!(!library.was_manufactured());
        assert!(library.lock_state().tpm2_runtime.is_none());
    }
}
