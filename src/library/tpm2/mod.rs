// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/NVMarshal.c
// - libtpms/src/tpm2/StateMarshal.c
// - libtpms/src/tpm_tpm2_interface.c
//
// Original upstream authors and copyright notices:
// Written by Stefan Berger
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corporation 2017,2018.
// (c) Copyright IBM Corporation 2015.
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

mod algorithm;
mod audit;
mod buffer_size;
mod capability;
mod clock;
mod command;
mod command_bitmap;
mod commit;
mod compile_constants;
mod context;
mod crypto;
mod dictionary_attack;
mod ecc;
mod entity;
mod failure_mode;
#[cfg(test)]
mod golden_responses;
#[cfg(test)]
mod hash_vectors;
mod hierarchy;
mod info;
mod live;
mod lockout;
mod manufacture;
mod marshal;
mod nv;
mod object;
mod object_create;
mod object_load;
mod object_wrap;
mod orderly;
mod pcr;
mod persistent;
mod pp_list;
mod process;
mod profile;
mod public;
mod random;
mod rsa_encryption;
mod rsa_vectors;
mod runtime;
mod secret;
mod self_test;
mod sequence;
mod session;
mod signature;
mod state;
mod template;
#[cfg(test)]
pub(in crate::library) mod test_support;
mod ticket;
mod tis;
mod volatile;

use crate::types::TpmResult;
#[cfg(test)]
use std::sync::Arc;

use super::constants::{TPM_FAIL, TPM_RC_FAILURE, TPM_RETRY, TPM_SUCCESS};
use super::library_state::{InformationFlags, TpmProperty};
use super::platform::Platform;
use super::preloaded_state::PreloadedBlob;
use super::state_blob::{StateBlobKind, StateValidationMask};
use super::storage::{Storage, StorageLoad, StorageProbe};
use marshal::{BlobReader, BlockSkipError, skip_optional_block};
use pcr::PcrSelection;
use persistent::{PersistentAllEnvelope, PersistentAllError, StateSection};
use public::StateFormatLimit;

pub(super) use buffer_size::{
    DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE, MIN_BUFFER_SIZE, clamp_buffer_size,
};
pub(super) use clock::{HostClock, OsClock};
pub(super) use crypto::{EntropySource, os_entropy};
#[cfg(test)]
pub(in crate::library) use pp_list::require_physical_presence;
pub(super) use process::{PlatformInputs, process};
pub(super) use runtime::FailureDiagnostics;
pub use runtime::Tpm2Runtime;
pub(super) use tis::{
    established_reset as tis_established_reset, hash_data as tis_hash_data,
    hash_end as tis_hash_end, hash_start as tis_hash_start,
};

#[cfg(test)]
pub(super) use self_test::arm_self_test_gate;

pub(super) fn volatile_all_store(runtime: &Tpm2Runtime) -> Result<Vec<u8>, TpmResult> {
    volatile::volatile_all_store(runtime, &OsClock)
}

#[cfg(test)]
pub(super) fn park_self_test_on_gate(runtime: &mut Tpm2Runtime) {
    runtime.self_test.park_on_gate();
}

#[cfg(test)]
pub(super) fn pending_self_test_algorithms(runtime: &Tpm2Runtime) -> Vec<u16> {
    runtime.self_test.pending_algorithms()
}

pub fn get_info(flags: InformationFlags, runtime: Option<&Tpm2Runtime>) -> String {
    info::get_info(
        flags,
        runtime.and_then(|runtime| {
            (!runtime.active_profile_json.is_empty())
                .then_some(runtime.active_profile_json.as_str())
        }),
        runtime.and_then(|runtime| {
            (!runtime.active_profile_algorithms.is_empty())
                .then_some(runtime.active_profile_algorithms.as_slice())
        }),
    )
}

pub(super) fn user_profile_is_valid(profile: &[u8]) -> bool {
    profile::validate_user_profile(Some(profile)).is_ok()
}

pub const MAX_RSA_KEY_BITS: u32 = 3072;

pub const MAX_HANDLE_NUM: u32 = 3;

pub fn get_tpm_property(prop: TpmProperty) -> Option<u32> {
    match prop {
        TpmProperty::RsaKeyLengthMax => Some(MAX_RSA_KEY_BITS),
        TpmProperty::KeyHandles => Some(MAX_HANDLE_NUM),
        _ => None,
    }
}

pub(super) struct Tpm2InitContext<'a> {
    pub(super) platform: &'a dyn Platform,
    pub(super) storage: &'a dyn Storage,
    pub(super) preloaded_permanent: PreloadedBlob,
    pub(super) preloaded_volatile: PreloadedBlob,
    pub(super) configured_profile: Option<Vec<u8>>,
    pub(super) entropy: EntropySource,
    pub(super) clock: &'a dyn HostClock,
    pub(super) failure_diagnostics: FailureDiagnostics,
}

pub(super) fn failure_diagnostics(runtime: &Tpm2Runtime) -> FailureDiagnostics {
    runtime.failure_diagnostics
}

#[derive(Debug, Eq, PartialEq)]
enum PermanentStateSource {
    Manufacture,
    PreloadedEmpty,
    PreloadedData(Vec<u8>),
    Backend,
}

fn select_permanent_state_source(
    preloaded: PreloadedBlob,
    probe: StorageProbe,
) -> PermanentStateSource {
    match preloaded {
        PreloadedBlob::Empty => PermanentStateSource::PreloadedEmpty,
        PreloadedBlob::Data(blob) => PermanentStateSource::PreloadedData(blob),
        PreloadedBlob::Missing => match probe {
            StorageProbe::Present => PermanentStateSource::Backend,
            StorageProbe::Missing | StorageProbe::Unsupported => PermanentStateSource::Manufacture,
        },
    }
}

enum VolatileResolution {
    NotPresent,
    Nonempty(Vec<u8>),
}

fn resolve_volatile_state(
    storage: &dyn Storage,
    preloaded_volatile: PreloadedBlob,
) -> VolatileResolution {
    match preloaded_volatile {
        PreloadedBlob::Empty => VolatileResolution::NotPresent,
        PreloadedBlob::Data(blob) => VolatileResolution::Nonempty(blob),
        PreloadedBlob::Missing => match storage.load(StateBlobKind::Volatile) {
            Ok(StorageLoad::Data(blob)) => VolatileResolution::Nonempty(blob),
            Ok(StorageLoad::Unsupported | StorageLoad::Missing | StorageLoad::Empty) | Err(_) => {
                VolatileResolution::NotPresent
            }
        },
    }
}

enum VolatileRestore {
    Absent,
    Restored,
    Rejected,
}

fn volatile_phase(
    storage: &dyn Storage,
    preloaded_volatile: PreloadedBlob,
    clock: &dyn HostClock,
    runtime: &mut Tpm2Runtime,
) -> VolatileRestore {
    match resolve_volatile_state(storage, preloaded_volatile) {
        VolatileResolution::Nonempty(blob) => load_volatile_blob(runtime, &blob, clock),
        VolatileResolution::NotPresent => VolatileRestore::Absent,
    }
}

fn load_volatile_blob(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
    clock: &dyn HostClock,
) -> VolatileRestore {
    if blob.len() < volatile::SHA1_DIGEST_SIZE {
        return VolatileRestore::Absent;
    }
    match unmarshal_for_restore(runtime, blob, clock) {
        Ok(LoadedVolatile::Verified(state)) => {
            runtime::merge_volatile_state(runtime, state);
            runtime::nv_shadow_restore(runtime);
            VolatileRestore::Restored
        }
        Ok(LoadedVolatile::Unverified(state)) => {
            runtime::merge_volatile_state(runtime, state);
            runtime.failure_mode = true;
            VolatileRestore::Restored
        }
        Err(_) => {
            clock::time_power_on(runtime, clock);
            restore_until_defect(runtime, blob, clock);
            runtime.failure_mode = true;
            VolatileRestore::Rejected
        }
    }
}

fn restore_until_defect(runtime: &mut Tpm2Runtime, blob: &[u8], clock: &dyn HostClock) {
    let Ok(context) = volatile_validation_context(runtime) else {
        return;
    };
    let shadow: Vec<PcrSelection<'_>> = context
        .shadow_pcr_allocated
        .iter()
        .map(|selection| PcrSelection {
            hash_alg: selection.hash_alg,
            select: &selection.select,
        })
        .collect();
    volatile::restore_until_defect(
        runtime,
        blob,
        volatile::RestoreContext {
            shadow: &shadow,
            seeds: context.seed_tie(),
            state_format: context.state_format,
        },
        clock,
    );
}

enum LoadedVolatile {
    Verified(volatile::OwnedVolatileState),
    Unverified(volatile::OwnedVolatileState),
}

fn unmarshal_for_restore(
    runtime: &Tpm2Runtime,
    blob: &[u8],
    clock: &dyn HostClock,
) -> Result<LoadedVolatile, TpmResult> {
    let context = volatile_validation_context(runtime)?;
    match unmarshal_volatile_blob(&context, blob, clock)? {
        volatile::UnmarshalledBlob::Verified(decoded) => {
            materialize_volatile(&context, &decoded).map(LoadedVolatile::Verified)
        }
        volatile::UnmarshalledBlob::Unverified(decoded, _) => {
            materialize_volatile(&context, &decoded).map(LoadedVolatile::Unverified)
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct VolatileValidationContext {
    ep_seed: persistent::OwnedSecret,
    sp_seed: persistent::OwnedSecret,
    pp_seed: persistent::OwnedSecret,
    shadow_pcr_allocated: Vec<persistent::OwnedPcrSelection>,
    object_version: u16,
    state_format: StateFormatLimit,
}

impl VolatileValidationContext {
    fn without_permanent_state() -> Self {
        Self {
            ep_seed: persistent::OwnedSecret::copy_of(&[]),
            sp_seed: persistent::OwnedSecret::copy_of(&[]),
            pp_seed: persistent::OwnedSecret::copy_of(&[]),
            shadow_pcr_allocated: Vec::new(),
            object_version: volatile::CURRENT_OBJECT_VERSION,
            state_format: StateFormatLimit::NONE,
        }
    }

    fn seed_tie(&self) -> volatile::SeedTie<'_> {
        volatile::SeedTie {
            ep_seed: self.ep_seed.as_bytes(),
            sp_seed: self.sp_seed.as_bytes(),
            pp_seed: self.pp_seed.as_bytes(),
        }
    }
}

fn volatile_validation_context(
    runtime: &Tpm2Runtime,
) -> Result<VolatileValidationContext, TpmResult> {
    let Some(state) = runtime.state.as_ref() else {
        return Ok(VolatileValidationContext {
            shadow_pcr_allocated: runtime.shadow_pcr_allocated.selections.clone(),
            state_format: StateFormatLimit::CURRENT,
            ..VolatileValidationContext::without_permanent_state()
        });
    };
    Ok(VolatileValidationContext {
        ep_seed: persistent::OwnedSecret::copy_of(state.persistent.ep_seed.as_bytes()),
        sp_seed: persistent::OwnedSecret::copy_of(state.persistent.sp_seed.as_bytes()),
        pp_seed: persistent::OwnedSecret::copy_of(state.persistent.pp_seed.as_bytes()),
        shadow_pcr_allocated: runtime.shadow_pcr_allocated.selections.clone(),
        object_version: volatile::volatile_object_version(state.profile.state_format_level)
            .map_err(|_| TPM_RC_FAILURE)?,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    })
}

fn unmarshal_volatile_blob<'a>(
    context: &VolatileValidationContext,
    blob: &'a [u8],
    clock: &dyn HostClock,
) -> Result<volatile::UnmarshalledBlob<'a>, TpmResult> {
    let shadow_views: Vec<PcrSelection<'_>> = context
        .shadow_pcr_allocated
        .iter()
        .map(|selection| PcrSelection {
            hash_alg: selection.hash_alg,
            select: &selection.select,
        })
        .collect();
    volatile::unmarshal_volatile_state_blob(
        blob,
        &shadow_views,
        context.seed_tie(),
        clock,
        context.state_format,
    )
    .map_err(PersistentAllError::tpm_result)
}

fn materialize_volatile(
    context: &VolatileValidationContext,
    decoded: &volatile::DecodedVolatileState<'_>,
) -> Result<volatile::OwnedVolatileState, TpmResult> {
    volatile::materialize_volatile_state(decoded, context.seed_tie(), context.object_version)
}

fn decode_volatile_blob(
    context: &VolatileValidationContext,
    blob: &[u8],
    clock: &dyn HostClock,
) -> Result<volatile::OwnedVolatileState, TpmResult> {
    match unmarshal_volatile_blob(context, blob, clock)? {
        volatile::UnmarshalledBlob::Verified(decoded) => materialize_volatile(context, &decoded),
        volatile::UnmarshalledBlob::Unverified(_, error) => Err(error.tpm_result()),
    }
}

#[cfg(test)]
pub(super) fn restore_permanent_blob_for_test(blob: &[u8]) -> Result<Tpm2Runtime, TpmResult> {
    initialize_from_permanent_blob(blob, PermanentCommit::Restore)
}

#[cfg(test)]
pub(super) fn attach_volatile_blob_for_test(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
) -> Result<(), TpmResult> {
    attach_volatile_blob(runtime, blob, &OsClock)
}

#[cfg(test)]
pub(super) fn attach_volatile_blob_for_replay(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
    clock: &dyn HostClock,
) -> Result<(), TpmResult> {
    attach_volatile_blob(runtime, blob, clock)
}

#[cfg(test)]
pub(super) fn attach_volatile_blob(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
    clock: &dyn HostClock,
) -> Result<(), TpmResult> {
    let LoadedVolatile::Verified(state) =
        unmarshal_for_restore(runtime, blob, clock).map_err(|_| TPM_RC_FAILURE)?
    else {
        return Err(TPM_RC_FAILURE);
    };
    runtime::merge_volatile_state(runtime, state);
    runtime::nv_shadow_restore(runtime);
    if runtime.failure_mode {
        return Err(TPM_RC_FAILURE);
    }
    Ok(())
}

pub(super) fn host_nv_commit(
    storage: &dyn Storage,
    runtime: &Tpm2Runtime,
) -> Result<(), TpmResult> {
    if !storage.supports_store() {
        return Ok(());
    }
    let Some(state) = runtime.state.as_ref() else {
        return Ok(());
    };
    let blob = persistent::persistent_all_store(state)?;
    storage.store(StateBlobKind::Permanent, &blob).map(|_| ())
}

fn nv_commit(storage: &dyn Storage, runtime: &Tpm2Runtime) {
    let _ = host_nv_commit(storage, runtime);
}

#[derive(Debug)]
pub(super) enum InitFailure {
    Callback(TpmResult),
    FailureMode {
        runtime: Box<Tpm2Runtime>,
        volatile_loaded: bool,
    },
    NoRuntime(TpmResult),
}

impl InitFailure {
    pub(super) fn code(&self) -> TpmResult {
        match self {
            Self::Callback(code) | Self::NoRuntime(code) => *code,
            Self::FailureMode { .. } => TPM_RC_FAILURE,
        }
    }
}

impl From<TpmResult> for InitFailure {
    fn from(code: TpmResult) -> Self {
        Self::NoRuntime(code)
    }
}

#[cfg(test)]
impl PartialEq<TpmResult> for InitFailure {
    fn eq(&self, code: &TpmResult) -> bool {
        self.code() == *code
    }
}

pub(super) fn main_init_prologue(running: &mut Tpm2Runtime) {
    running.failure_mode = false;
    running.reported_failure = false;
    running.was_manufactured = false;
}

fn permanent_state_failure(was_manufactured: bool, entropy: EntropySource) -> InitFailure {
    let mut runtime = runtime::empty_state_runtime();
    runtime.manufactured = was_manufactured;
    runtime.was_manufactured = was_manufactured;
    runtime.entropy = entropy;
    failure_mode::enter_failure_mode(&mut runtime, failure_mode::FailureLocation::NvPowerOn);
    InitFailure::FailureMode {
        runtime: Box::new(runtime),
        volatile_loaded: false,
    }
}

pub(super) fn main_init(context: Tpm2InitContext<'_>) -> Result<Tpm2Runtime, InitFailure> {
    let entropy = context.entropy;
    let storage = context.storage;

    context
        .platform
        .initialize()
        .map_err(InitFailure::Callback)?;
    storage.initialize().map_err(InitFailure::Callback)?;

    let probe = storage.probe_permanent();
    let load_supported = probe != StorageProbe::Unsupported;

    let source = select_permanent_state_source(context.preloaded_permanent, probe);
    let staged = matches!(
        source,
        PermanentStateSource::PreloadedEmpty | PermanentStateSource::PreloadedData(_)
    );
    let mut runtime = match source {
        PermanentStateSource::Manufacture => {
            if !load_supported {
                return Err(TPM_FAIL.into());
            }
            match storage.load(StateBlobKind::Permanent)? {
                StorageLoad::Missing => {
                    if !storage.supports_store() {
                        return Err(TPM_FAIL.into());
                    }
                }
                StorageLoad::Unsupported | StorageLoad::Data(_) | StorageLoad::Empty => {
                    return Err(TPM_FAIL.into());
                }
            }
            let profile = profile::validate_user_profile(context.configured_profile.as_deref())
                .map_err(|_| TPM_FAIL)?;
            let candidate = manufacture::manufacture_state(profile, context.entropy)?;
            let manufactured = runtime::commit_manufactured_state(candidate)?;
            nv_commit(storage, &manufactured);
            match storage.load(StateBlobKind::Permanent) {
                Ok(StorageLoad::Data(blob)) => {
                    drop(manufactured);
                    initialize_from_permanent_blob(&blob, PermanentCommit::FirstBootReload)
                        .map_err(|_| permanent_state_failure(true, entropy))?
                }
                Ok(StorageLoad::Missing) => {
                    if !storage.supports_store() {
                        return Err(TPM_FAIL.into());
                    }
                    runtime::manufactured_zeroed_nv_runtime(&manufactured)
                }
                Ok(StorageLoad::Empty | StorageLoad::Unsupported) => {
                    return Err(TPM_FAIL.into());
                }
                Err(_) => return Err(permanent_state_failure(true, entropy)),
            }
        }
        PermanentStateSource::PreloadedEmpty => runtime::empty_state_runtime(),
        PermanentStateSource::PreloadedData(blob) => {
            initialize_from_permanent_blob(&blob, PermanentCommit::Restore)?
        }
        PermanentStateSource::Backend => match storage.load(StateBlobKind::Permanent) {
            Ok(StorageLoad::Data(blob)) => {
                initialize_from_permanent_blob(&blob, PermanentCommit::Restore)
                    .map_err(|_| permanent_state_failure(false, entropy))?
            }
            Ok(StorageLoad::Unsupported | StorageLoad::Missing | StorageLoad::Empty) => {
                return Err(TPM_FAIL.into());
            }
            Err(_) => return Err(permanent_state_failure(false, entropy)),
        },
    };
    runtime.failure_diagnostics = context.failure_diagnostics;
    if let VolatileRestore::Absent = volatile_phase(
        storage,
        context.preloaded_volatile,
        context.clock,
        &mut runtime,
    ) {
        clock::time_power_on(&mut runtime, context.clock);
    }
    runtime.entropy = entropy;
    if runtime.failure_mode {
        return Err(InitFailure::FailureMode {
            runtime: Box::new(runtime),
            volatile_loaded: true,
        });
    }
    if staged {
        nv_commit(storage, &runtime);
    }
    Ok(runtime)
}

pub(super) fn persistent_all_store(runtime: &Tpm2Runtime) -> Result<Vec<u8>, TpmResult> {
    match runtime.state.as_ref() {
        Some(state) => persistent::persistent_all_store(state),
        None => Err(TPM_FAIL),
    }
}

pub(super) fn load_state_from_backend(
    storage: &dyn Storage,
    kind: StateBlobKind,
) -> Result<Vec<u8>, TpmResult> {
    storage.initialize()?;
    match storage.load(kind)? {
        StorageLoad::Data(blob) => Ok(blob),
        StorageLoad::Empty => Ok(Vec::new()),
        StorageLoad::Missing => Err(TPM_RETRY),
        StorageLoad::Unsupported => Err(TPM_FAIL),
    }
}

pub(super) fn permanent_validation_context(
    blob: &[u8],
) -> Result<VolatileValidationContext, TpmResult> {
    let runtime = initialize_from_permanent_blob(blob, PermanentCommit::Restore)?;
    volatile_validation_context(&runtime)
}

pub(super) fn validate_volatile_in_context(
    context: &VolatileValidationContext,
    volatile: &[u8],
) -> TpmResult {
    match decode_volatile_blob(context, volatile, &OsClock) {
        Ok(_) => TPM_SUCCESS,
        Err(code) => code,
    }
}

enum ValidationStage {
    Complete(TpmResult),
    Volatile(Vec<u8>),
}

pub(super) struct ValidationLoad {
    permanent: Option<VolatileValidationContext>,
    stage: ValidationStage,
}

impl ValidationLoad {
    fn complete(result: TpmResult) -> Self {
        Self {
            permanent: None,
            stage: ValidationStage::Complete(result),
        }
    }
}

pub(super) struct ValidationOutcome {
    pub(super) result: TpmResult,
    pub(super) installed: Option<VolatileValidationContext>,
}

impl ValidationOutcome {
    pub(super) fn rejected(result: TpmResult) -> Self {
        Self {
            result,
            installed: None,
        }
    }
}

pub(super) fn load_state_for_validation(
    storage: &dyn Storage,
    mask: StateValidationMask,
    cached_volatile: PreloadedBlob,
) -> ValidationLoad {
    if let Err(code) = storage.initialize() {
        return ValidationLoad::complete(code);
    }

    let permanent = if mask.selects_permanent_blob() {
        let blob = match load_permanent_for_validation(storage) {
            Ok(blob) => blob,
            Err(code) => return ValidationLoad::complete(code),
        };
        match permanent_validation_context(&blob) {
            Ok(context) => Some(context),
            Err(code) => return ValidationLoad::complete(code),
        }
    } else {
        None
    };

    let stage = if mask.volatile() {
        match resolve_volatile_for_validation(storage, cached_volatile) {
            Some(blob) => ValidationStage::Volatile(blob),
            None => ValidationStage::Complete(TPM_SUCCESS),
        }
    } else {
        ValidationStage::Complete(TPM_SUCCESS)
    };

    ValidationLoad { permanent, stage }
}

fn resolve_volatile_for_validation(
    storage: &dyn Storage,
    cached_volatile: PreloadedBlob,
) -> Option<Vec<u8>> {
    match cached_volatile {
        PreloadedBlob::Empty => None,
        PreloadedBlob::Data(blob) => Some(blob),
        PreloadedBlob::Missing => match storage.load(StateBlobKind::Volatile) {
            Ok(StorageLoad::Data(blob)) => Some(blob),
            Ok(StorageLoad::Unsupported | StorageLoad::Missing | StorageLoad::Empty) | Err(_) => {
                None
            }
        },
    }
}

pub(super) fn finish_validation(
    load: ValidationLoad,
    runtime: Option<&Tpm2Runtime>,
    installed: Option<&VolatileValidationContext>,
) -> ValidationOutcome {
    let blob = match load.stage {
        ValidationStage::Complete(result) => {
            return ValidationOutcome {
                result,
                installed: load.permanent,
            };
        }
        ValidationStage::Volatile(blob) => blob,
    };
    let result = match (load.permanent.as_ref(), runtime, installed) {
        (Some(context), _, _) => validate_volatile_in_context(context, &blob),
        (None, Some(runtime), _) => match volatile_validation_context(runtime) {
            Ok(context) => validate_volatile_in_context(&context, &blob),
            Err(code) => code,
        },
        (None, None, Some(context)) => validate_volatile_in_context(context, &blob),
        (None, None, None) => validate_volatile_in_context(
            &VolatileValidationContext::without_permanent_state(),
            &blob,
        ),
    };
    ValidationOutcome {
        result,
        installed: load.permanent,
    }
}

fn load_permanent_for_validation(storage: &dyn Storage) -> Result<Vec<u8>, TpmResult> {
    match storage.load(StateBlobKind::Permanent)? {
        StorageLoad::Data(blob) => Ok(blob),
        StorageLoad::Missing => Err(TPM_RETRY),
        StorageLoad::Unsupported | StorageLoad::Empty => Err(TPM_FAIL),
    }
}

const TPM_SU_STATE: u16 = 0x0001;
const TPM_SU_STATE_MASK: u16 = !(0x8000 | 0x4000);

struct DecodedPersistentData<'a> {
    prefix: persistent::PersistentDataPrefix<'a>,
    pcr_policies: pcr::ParsedPcrPolicies<'a>,
    pcr_allocated: pcr::PcrAllocation<'a>,
    pp_list: pp_list::PpList<'a>,
    lockout: lockout::LockoutState<'a>,
    audit: audit::AuditState<'a>,
    compat: persistent::CompatTail<'a>,
}

struct DecodedPersistentAll<'a> {
    envelope_version: u16,
    profile: profile::ValidatedProfile,
    persistent_data: DecodedPersistentData<'a>,
    orderly_data: persistent::OrderlyData<'a>,
    read_su_state: bool,
    state_reset_data: Option<state::StateResetData<'a>>,
    state_clear_data: Option<state::StateClearData<'a>>,
    index_orderly_ram: nv::IndexOrderlyRam<'a>,
    user_nvram: nv::UserNvram<'a>,
}

fn parse_persistent_all_payload<'a>(
    envelope: &PersistentAllEnvelope<'a>,
) -> Result<DecodedPersistentAll<'a>, PersistentAllError> {
    let validated_profile = profile::validate_profile(envelope.profile)?;
    let validated = compile_constants::parse_and_validate_pa_compile_constants(envelope.payload)?;
    let prefix = persistent::parse_persistent_data_prefix(validated.remaining)?;
    let pcr_policies = pcr::parse_pcr_policies(prefix.remaining)?;
    let pcr_allocated = pcr::parse_pcr_allocation(pcr_policies.remaining)?;
    let pp_list = pp_list::parse_pp_list(pcr_allocated.remaining, prefix.header.version)?;
    let lockout = lockout::parse_lockout_state(pp_list.remaining)?;
    let audit = audit::parse_audit_state(lockout.remaining, prefix.header.version)?;
    let compat = persistent::parse_compat_tail(audit.remaining, prefix.header.version)?;

    let orderly_data = persistent::parse_orderly_data(compat.remaining)?;

    let read_su_state = if envelope.header.version < 3 {
        true
    } else {
        (lockout.orderly_state & TPM_SU_STATE_MASK) == TPM_SU_STATE
    };

    let mut remaining = orderly_data.remaining;
    let (state_reset_data, state_clear_data) = if read_su_state {
        let state_reset = state::parse_state_reset_data(remaining)?;
        let shadow: &[PcrSelection<'_>] = match &compat.shadow_pcr_allocated {
            Some(allocation) => &allocation.selections[..allocation.declared_count as usize],
            None => &pcr_allocated.selections[..pcr_allocated.declared_count as usize],
        };
        let state_clear = state::parse_state_clear_data(state_reset.remaining, shadow)?;
        remaining = state_clear.remaining;
        (Some(state_reset), Some(state_clear))
    } else {
        (None, None)
    };

    let index_ram = nv::parse_index_orderly_ram(remaining)?;

    let user = nv::parse_user_nvram(
        index_ram.remaining,
        validated_profile.object_format(),
        StateFormatLimit::new(validated_profile.state_format_level),
    )?;

    const TAIL: StateSection = StateSection::PersistentAllTail;
    let mut reader = BlobReader::new(user.remaining);
    if envelope.header.version >= 2 {
        skip_optional_block(&mut reader, false).map_err(|error| match error {
            BlockSkipError::Truncated => PersistentAllError::Truncated { section: TAIL },
            BlockSkipError::MissingRequiredBlock => {
                PersistentAllError::MissingRequiredBlock { section: TAIL }
            }
        })?;
    }
    if !reader.remaining().is_empty() {
        return Err(PersistentAllError::TrailingPayloadBytes {
            remaining: reader.remaining().len(),
        });
    }

    Ok(DecodedPersistentAll {
        envelope_version: envelope.header.version,
        profile: validated_profile,
        persistent_data: DecodedPersistentData {
            prefix,
            pcr_policies,
            pcr_allocated,
            pp_list,
            lockout,
            audit,
            compat,
        },
        orderly_data,
        read_su_state,
        state_reset_data,
        state_clear_data,
        index_orderly_ram: index_ram,
        user_nvram: user,
    })
}

enum PermanentCommit {
    Restore,
    FirstBootReload,
}

fn initialize_from_permanent_blob(
    blob: &[u8],
    commit: PermanentCommit,
) -> Result<Tpm2Runtime, TpmResult> {
    let envelope = PersistentAllEnvelope::parse(blob).map_err(PersistentAllError::tpm_result)?;
    let decoded =
        parse_persistent_all_payload(&envelope).map_err(PersistentAllError::tpm_result)?;
    let candidate = persistent::materialize_persistent_state(decoded)?;
    match commit {
        PermanentCommit::Restore => runtime::commit_restored_state(candidate),
        PermanentCommit::FirstBootReload => runtime::commit_first_boot_reloaded_state(candidate),
    }
}

pub fn terminate() {}

#[cfg(test)]
fn remaining_sections() -> Vec<u8> {
    let mut out = persistent::OrderlyFixture::default().bytes();
    out.extend_from_slice(&nv::IndexOrderlyRamFixture::default().bytes());
    out.extend_from_slice(&nv::UserNvramFixture::default().bytes());
    out.extend_from_slice(&[0x01, 0x00, 0x00]);
    out
}

#[cfg(test)]
fn remaining_sections_with_su_state() -> Vec<u8> {
    let mut out = persistent::OrderlyFixture::default().bytes();
    out.extend_from_slice(&state::StateResetFixture::default().bytes());
    out.extend_from_slice(&state::StateClearFixture::default().bytes());
    out.extend_from_slice(&nv::IndexOrderlyRamFixture::default().bytes());
    out.extend_from_slice(&nv::UserNvramFixture::default().bytes());
    out.extend_from_slice(&[0x01, 0x00, 0x00]);
    out
}

#[cfg(test)]
fn persistent_data_tail() -> Vec<u8> {
    lockout::LockoutFixture {
        tail: audit::AuditFixture {
            tail: persistent::CompatTailFixture {
                tail: remaining_sections(),
                ..persistent::CompatTailFixture::default()
            }
            .bytes(),
            ..audit::AuditFixture::default()
        }
        .bytes(),
        ..lockout::LockoutFixture::default()
    }
    .bytes()
}

#[cfg(test)]
pub(in crate::library) fn valid_permanent_state_fixture() -> Vec<u8> {
    let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
    blob.extend_from_slice(&compile_constants::marshalled_section(3));
    blob.extend_from_slice(
        &persistent::PrefixFixture {
            tail: pcr::PcrPoliciesFixture {
                tail: pcr::PcrAllocationFixture {
                    tail: pp_list::PpListFixture {
                        tail: persistent_data_tail(),
                        ..pp_list::PpListFixture::default()
                    }
                    .bytes(),
                    ..pcr::PcrAllocationFixture::default()
                }
                .bytes(),
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes(),
            ..persistent::PrefixFixture::default()
        }
        .bytes(),
    );
    blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
    blob
}

#[cfg(test)]
pub(in crate::library) fn valid_volatile_state_fixture() -> Vec<u8> {
    volatile::VolatileFixture {
        ep_seed: Vec::new(),
        sp_seed: Vec::new(),
        pp_seed: Vec::new(),
        ..volatile::VolatileFixture::default()
    }
    .bytes()
}

#[cfg(test)]
pub(in crate::library) fn seed_mismatched_volatile_state_fixture() -> Vec<u8> {
    volatile::VolatileFixture::default().bytes()
}

#[cfg(test)]
pub(in crate::library) fn failure_mode_volatile_state_fixture() -> Vec<u8> {
    volatile::VolatileFixture {
        in_failure_mode: 1,
        ep_seed: Vec::new(),
        sp_seed: Vec::new(),
        pp_seed: Vec::new(),
        ..volatile::VolatileFixture::default()
    }
    .bytes()
}

#[cfg(test)]
pub(in crate::library) fn diagnosed_failure_mode_volatile_state_fixture() -> Vec<u8> {
    let diagnostics = failure_mode::FailureLocation::NvCommit.diagnostics();
    volatile::VolatileFixture {
        in_failure_mode: 1,
        fail_function: diagnostics.function,
        fail_line: diagnostics.line,
        fail_code: diagnostics.code,
        ep_seed: Vec::new(),
        sp_seed: Vec::new(),
        pp_seed: Vec::new(),
        ..volatile::VolatileFixture::default()
    }
    .bytes()
}

#[cfg(test)]
pub(in crate::library) fn bad_tag_volatile_state_fixture() -> Vec<u8> {
    volatile::VolatileFixture {
        trailing_magic: 0,
        ep_seed: Vec::new(),
        sp_seed: Vec::new(),
        pp_seed: Vec::new(),
        ..volatile::VolatileFixture::default()
    }
    .bytes()
}

#[cfg(test)]
pub(in crate::library) fn object_volatile_state_fixture(public: &[u8]) -> Vec<u8> {
    let mut objects = vec![object::fixtures::any_unoccupied_object(); volatile::MAX_LOADED_OBJECTS];
    objects[0] = object::fixtures::any_public_only_object(public);
    volatile::VolatileFixture {
        objects,
        ep_seed: Vec::new(),
        sp_seed: Vec::new(),
        pp_seed: Vec::new(),
        ..volatile::VolatileFixture::default()
    }
    .bytes()
}

#[cfg(test)]
pub(in crate::library) fn rsa_object_volatile_state_fixture() -> Vec<u8> {
    object_volatile_state_fixture(&public::fixtures::rsa_public(256))
}

#[cfg(test)]
pub(in crate::library) fn ecc_object_volatile_state_fixture() -> Vec<u8> {
    object_volatile_state_fixture(&public::fixtures::ecc_public())
}

#[cfg(test)]
pub(in crate::library) fn symmetric_object_volatile_state_fixture(key_bits: u16) -> Vec<u8> {
    object_volatile_state_fixture(&public::fixtures::symcipher_public(key_bits))
}

#[cfg(test)]
pub(in crate::library) fn commit_failing_permanent_state_fixture() -> Vec<u8> {
    permanent_state_fixture_with_user_object(
        &object::fixtures::any_sequence_object(object::fixtures::SEQ_HASH),
        1,
    )
}

#[cfg(test)]
pub(in crate::library) fn permanent_state_fixture_with_user_object(
    object_bytes: &[u8],
    state_format_level: u32,
) -> Vec<u8> {
    let mut sections = persistent::OrderlyFixture::default().bytes();
    sections.extend_from_slice(&nv::IndexOrderlyRamFixture::default().bytes());
    sections.extend_from_slice(
        &nv::UserNvramFixture {
            entries: vec![nv::UserNvramFixture::persistent_entry(
                0x8100_0001,
                object_bytes,
            )],
            ..nv::UserNvramFixture::default()
        }
        .bytes(),
    );
    sections.extend_from_slice(&[0x01, 0x00, 0x00]);

    let mut payload = compile_constants::marshalled_section(3);
    payload.extend_from_slice(
        &persistent::PrefixFixture {
            tail: pcr::PcrPoliciesFixture {
                tail: pcr::PcrAllocationFixture {
                    tail: pp_list::PpListFixture {
                        tail: lockout::LockoutFixture {
                            tail: audit::AuditFixture {
                                tail: persistent::CompatTailFixture {
                                    tail: sections,
                                    ..persistent::CompatTailFixture::default()
                                }
                                .bytes(),
                                ..audit::AuditFixture::default()
                            }
                            .bytes(),
                            ..lockout::LockoutFixture::default()
                        }
                        .bytes(),
                        ..pp_list::PpListFixture::default()
                    }
                    .bytes(),
                    ..pcr::PcrAllocationFixture::default()
                }
                .bytes(),
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes(),
            ..persistent::PrefixFixture::default()
        }
        .bytes(),
    );

    let profile = format!(r#"{{"Name":"null","StateFormatLevel":{state_format_level}}}"#);
    let profile = profile.as_bytes();
    let mut blob = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
    blob.extend_from_slice(&u16::try_from(profile.len() + 1).unwrap().to_be_bytes());
    blob.extend_from_slice(profile);
    blob.push(0);
    blob.extend_from_slice(&payload);
    blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT,
    };
    use crate::library::platform::DefaultPlatform;
    use crate::library::platform::test_support::TestPlatform;
    use crate::library::storage::NoStorage;
    use crate::library::storage::test_support::TestStorage;
    use crate::library::tpm2::test_support::{envelope_v4_with_profile, envelope_with_payload};
    use std::sync::{LazyLock, Mutex};

    fn pp_list_tail() -> Vec<u8> {
        pp_list::PpListFixture {
            tail: persistent_data_tail(),
            ..pp_list::PpListFixture::default()
        }
        .bytes()
    }

    fn pcr_allocated_tail() -> Vec<u8> {
        pcr::PcrAllocationFixture {
            tail: pp_list_tail(),
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes()
    }

    fn valid_payload() -> Vec<u8> {
        payload_with_pcr_policies(
            pcr::PcrPoliciesFixture {
                tail: pcr_allocated_tail(),
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes(),
        )
    }

    fn payload_with_pcr_policies(pcr_policies: Vec<u8>) -> Vec<u8> {
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &persistent::PrefixFixture {
                tail: pcr_policies,
                ..persistent::PrefixFixture::default()
            }
            .bytes(),
        );
        payload
    }

    fn payload_with_pcr_allocated(pcr_allocated: Vec<u8>) -> Vec<u8> {
        payload_with_pcr_policies(
            pcr::PcrPoliciesFixture {
                tail: pcr_allocated,
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes(),
        )
    }

    fn payload_with_pp_list(pp_list: Vec<u8>) -> Vec<u8> {
        payload_with_pcr_allocated(
            pcr::PcrAllocationFixture {
                tail: pp_list,
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes(),
        )
    }

    fn payload_with_lockout(lockout: Vec<u8>) -> Vec<u8> {
        payload_with_pp_list(
            pp_list::PpListFixture {
                tail: lockout,
                ..pp_list::PpListFixture::default()
            }
            .bytes(),
        )
    }

    fn payload_with_audit(audit: Vec<u8>) -> Vec<u8> {
        payload_with_lockout(
            lockout::LockoutFixture {
                tail: audit,
                ..lockout::LockoutFixture::default()
            }
            .bytes(),
        )
    }

    fn payload_with_compat_tail(compat: Vec<u8>) -> Vec<u8> {
        payload_with_audit(
            audit::AuditFixture {
                tail: compat,
                ..audit::AuditFixture::default()
            }
            .bytes(),
        )
    }

    static VALID_ENVELOPE: LazyLock<Vec<u8>> =
        LazyLock::new(|| envelope_with_payload(&valid_payload()));

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn push_event(event: String) {
        EVENTS.lock().unwrap().push(event);
    }

    fn events() -> Vec<String> {
        EVENTS.lock().unwrap().clone()
    }

    fn io_platform() -> Arc<dyn Platform> {
        TestPlatform::new()
            .on_initialize(|| {
                push_event("io".into());
                Ok(())
            })
            .arc()
    }

    fn failing_io_platform() -> Arc<dyn Platform> {
        TestPlatform::new()
            .on_initialize(|| {
                push_event("io-fail".into());
                Err(42)
            })
            .arc()
    }

    fn no_platform() -> Arc<dyn Platform> {
        Arc::new(DefaultPlatform)
    }

    fn recording_init(storage: TestStorage) -> TestStorage {
        storage.on_init(|| {
            push_event("nvram".into());
            Ok(())
        })
    }

    fn failing_init(storage: TestStorage) -> TestStorage {
        storage.on_init(|| {
            push_event("nvram-fail".into());
            Err(43)
        })
    }

    fn no_storage() -> Arc<dyn Storage> {
        Arc::new(NoStorage)
    }

    const ENTROPY: crate::library::tpm2::crypto::EntropySource =
        crate::library::tpm2::test_support::counter_entropy::<0xa5>;

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn context(
        storage: Arc<dyn Storage>,
        preloaded_permanent: PreloadedBlob,
    ) -> Tpm2InitContext<'static> {
        context_with_volatile(storage, preloaded_permanent, PreloadedBlob::Missing)
    }

    fn context_with_volatile(
        storage: Arc<dyn Storage>,
        preloaded_permanent: PreloadedBlob,
        preloaded_volatile: PreloadedBlob,
    ) -> Tpm2InitContext<'static> {
        context_with_profile(storage, preloaded_permanent, preloaded_volatile, None)
    }

    fn context_with_profile(
        storage: Arc<dyn Storage>,
        preloaded_permanent: PreloadedBlob,
        preloaded_volatile: PreloadedBlob,
        configured_profile: Option<&[u8]>,
    ) -> Tpm2InitContext<'static> {
        context_with_platform(
            no_platform(),
            storage,
            preloaded_permanent,
            preloaded_volatile,
            configured_profile,
        )
    }

    fn context_with_platform(
        platform: Arc<dyn Platform>,
        storage: Arc<dyn Storage>,
        preloaded_permanent: PreloadedBlob,
        preloaded_volatile: PreloadedBlob,
        configured_profile: Option<&[u8]>,
    ) -> Tpm2InitContext<'static> {
        let platform: &'static Arc<dyn Platform> = Box::leak(Box::new(platform));
        let storage: &'static Arc<dyn Storage> = Box::leak(Box::new(storage));
        Tpm2InitContext {
            platform: platform.as_ref(),
            storage: storage.as_ref(),
            preloaded_permanent,
            preloaded_volatile,
            configured_profile: configured_profile.map(<[u8]>::to_vec),
            entropy: ENTROPY,
            clock: &TEST_HOST_CLOCK,
            failure_diagnostics: FailureDiagnostics::default(),
        }
    }

    const TEST_REALTIME_MS: u64 = 1_600_000_500_000;
    const TEST_MONOTONIC_MS: u64 = 7_000_000;

    struct TestClock;

    impl clock::HostClock for TestClock {
        fn realtime_ms(&self) -> u64 {
            TEST_REALTIME_MS
        }

        fn monotonic_ms(&self) -> u64 {
            TEST_MONOTONIC_MS
        }
    }

    static TEST_HOST_CLOCK: TestClock = TestClock;

    fn recording_clock() -> clock::RecordingClock {
        clock::RecordingClock::new(TEST_REALTIME_MS, TEST_MONOTONIC_MS)
    }

    #[track_caller]
    fn failure_mode_runtime(outcome: Result<Tpm2Runtime, InitFailure>) -> (Tpm2Runtime, bool) {
        match outcome {
            Err(InitFailure::FailureMode {
                runtime,
                volatile_loaded,
            }) => {
                assert!(runtime.failure_mode, "the published TPM is in failure mode");
                (*runtime, volatile_loaded)
            }
            other => panic!("expected a TPM in failure mode, got {other:?}"),
        }
    }

    const NV_POWER_ON: failure_mode::FailureLocation = failure_mode::FailureLocation::NvPowerOn;

    fn probe(exists: bool, load_supported: bool) -> StorageProbe {
        match (exists, load_supported) {
            (true, _) => StorageProbe::Present,
            (false, true) => StorageProbe::Missing,
            (false, false) => StorageProbe::Unsupported,
        }
    }

    fn load_retry() -> TestStorage {
        TestStorage::new().on_load(|kind| {
            push_event(format!("load-retry:{kind:?}"));
            Ok(StorageLoad::Missing)
        })
    }

    fn load_permanent_envelope() -> TestStorage {
        TestStorage::new().on_load(|kind| {
            push_event(format!("load:{kind:?}"));
            match kind {
                StateBlobKind::Permanent => Ok(StorageLoad::Data(VALID_ENVELOPE.to_vec())),
                _ => Ok(StorageLoad::Missing),
            }
        })
    }

    fn load_permanent_and_junk_volatile() -> TestStorage {
        TestStorage::new().on_load(|kind| {
            push_event(format!("load-found:{kind:?}"));
            match kind {
                StateBlobKind::Permanent => Ok(StorageLoad::Data(VALID_ENVELOPE.to_vec())),
                StateBlobKind::Volatile => Ok(StorageLoad::Data(vec![0xd0, 0x0d])),
                StateBlobKind::SaveState => Ok(StorageLoad::Missing),
            }
        })
    }

    fn load_volatile_only(outcome: fn() -> Result<StorageLoad, TpmResult>) -> TestStorage {
        TestStorage::new().on_load(move |kind| {
            push_event(format!("load:{kind:?}"));
            match kind {
                StateBlobKind::Volatile => outcome(),
                _ => Ok(StorageLoad::Missing),
            }
        })
    }

    fn load_permanent_truncated() -> TestStorage {
        TestStorage::new().on_load(|kind| {
            push_event(format!("load-truncated:{kind:?}"));
            match kind {
                StateBlobKind::Permanent => Ok(StorageLoad::Data(vec![0x00, 0x03])),
                _ => Ok(StorageLoad::Missing),
            }
        })
    }

    fn load_permanent_outcome(outcome: fn() -> Result<StorageLoad, TpmResult>) -> TestStorage {
        TestStorage::new().on_load(move |kind| match kind {
            StateBlobKind::Permanent => outcome(),
            _ => Ok(StorageLoad::Missing),
        })
    }

    static VANISH_CALLS: Mutex<u32> = Mutex::new(0);

    fn load_permanent_then_vanishing() -> TestStorage {
        TestStorage::new().on_load(|kind| {
            if kind != StateBlobKind::Permanent {
                return Ok(StorageLoad::Missing);
            }
            let mut calls = VANISH_CALLS.lock().unwrap();
            *calls += 1;
            if *calls == 1 {
                Ok(StorageLoad::Data(VALID_ENVELOPE.to_vec()))
            } else {
                Ok(StorageLoad::Missing)
            }
        })
    }

    static STORED_BLOBS: Mutex<Vec<(String, Vec<u8>)>> = Mutex::new(Vec::new());

    fn recording_store(storage: TestStorage) -> TestStorage {
        storage.on_store(|kind, data| {
            push_event(format!("store:{kind:?}"));
            STORED_BLOBS
                .lock()
                .unwrap()
                .push((format!("{kind:?}"), data.to_vec()));
            Ok(())
        })
    }

    fn failing_store(storage: TestStorage) -> TestStorage {
        storage.on_store(|kind, _| {
            push_event(format!("store-error:{kind:?}"));
            Err(88)
        })
    }

    #[test]
    fn manufacture_selection_missing_preloaded_absent_backend() {
        assert_eq!(
            select_permanent_state_source(PreloadedBlob::Missing, probe(false, true)),
            PermanentStateSource::Manufacture
        );
        assert_eq!(
            select_permanent_state_source(PreloadedBlob::Missing, probe(false, false)),
            PermanentStateSource::Manufacture
        );
    }

    #[test]
    fn backend_selection_missing_preloaded_existing_backend() {
        assert_eq!(
            select_permanent_state_source(PreloadedBlob::Missing, probe(true, true)),
            PermanentStateSource::Backend
        );
        assert_eq!(
            select_permanent_state_source(PreloadedBlob::Missing, probe(true, false)),
            PermanentStateSource::Backend
        );
    }

    #[test]
    fn preloaded_empty_selection_backend_independence() {
        for exists in [false, true] {
            assert_eq!(
                select_permanent_state_source(PreloadedBlob::Empty, probe(exists, true)),
                PermanentStateSource::PreloadedEmpty,
                "backend exists = {exists}"
            );
        }
    }

    #[test]
    fn preloaded_data_selection_blob_preservation() {
        for exists in [false, true] {
            assert_eq!(
                select_permanent_state_source(
                    PreloadedBlob::Data(vec![7, 8, 9]),
                    probe(exists, true)
                ),
                PermanentStateSource::PreloadedData(vec![7, 8, 9]),
                "backend exists = {exists}"
            );
        }
    }

    #[test]
    fn missing_permanent_backend_post_init_failure() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context_with_platform(
            io_platform(),
            recording_init(TestStorage::new()).arc(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
            None,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "no permanent-state backend is available");
        assert_eq!(*EVENTS.lock().unwrap(), ["io", "nvram"]);
    }

    #[test]
    fn io_init_failure_nvram_init_probe_prevention() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context_with_platform(
            failing_io_platform(),
            recording_init(load_retry()).arc(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
            None,
        ))
        .unwrap_err();
        assert_eq!(error, 42);
        assert_eq!(*EVENTS.lock().unwrap(), ["io-fail"]);
    }

    #[test]
    fn nvram_init_failure_backend_probe_prevention() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context_with_platform(
            io_platform(),
            failing_init(load_retry()).arc(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
            None,
        ))
        .unwrap_err();
        assert_eq!(error, 43);
        assert_eq!(*EVENTS.lock().unwrap(), ["io", "nvram-fail"]);
    }

    #[test]
    fn first_boot_missing_storedata_nv_enable_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context(load_retry().arc(), PreloadedBlob::Missing)).unwrap_err();
        assert_eq!(error, TPM_FAIL, "no storedata: NV cannot be enabled");
        assert_eq!(events(), ["load-retry:Permanent", "load-retry:Permanent"]);
    }

    #[test]
    fn existing_backend_state_runtime_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            load_permanent_envelope().arc(),
            PreloadedBlob::Missing,
        ))
        .expect("a valid backend blob restores");
        assert_eq!(
            events(),
            ["load:Permanent", "load:Permanent", "load:Volatile"],
            "the probe, the real backend load, and the volatile load \
             each hit the callback, with TPM number 0 and the exact \
             upstream state names"
        );
        assert!(
            !runtime.manufactured,
            "neither a manufacture nor a volatile state set it"
        );
        assert!(!runtime.was_manufactured, "no manufacture ran this init");
        assert!(!runtime.startup_received, "TPM2_Startup is still pending");
        assert!(!runtime.failure_mode);
        assert!(runtime.power_on && runtime.nv_available);
        assert_eq!(runtime.nv_memory.len(), runtime::NV_MEMORY_SIZE);
    }

    #[test]
    fn backend_preloaded_shared_restore_path() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let storage = load_permanent_envelope().arc();
        let preloaded = main_init(context(
            Arc::clone(&storage),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("preloaded data restores");
        assert_eq!(
            events(),
            ["load:Permanent", "load:Volatile"],
            "preloaded data skips the backend permanent load but not the \
             probe or the volatile load"
        );
        let backend =
            main_init(context(storage, PreloadedBlob::Missing)).expect("backend data restores");
        assert_eq!(preloaded.nv_memory, backend.nv_memory);
        assert_eq!(preloaded.active_profile_json, backend.active_profile_json);
    }

    #[test]
    fn backend_load_error_nv_power_on_failure_mode() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let outcome = main_init(context(
            load_permanent_outcome(|| Err(77)).arc(),
            PreloadedBlob::Missing,
        ));
        assert_eq!(outcome.as_ref().unwrap_err(), &TPM_RC_FAILURE);
        let (runtime, volatile_loaded) = failure_mode_runtime(outcome);
        assert!(
            !volatile_loaded,
            "NvPowerOn failed, so _TPM_Init never reached VolatileLoad"
        );
        assert_eq!(runtime.failure_diagnostics, NV_POWER_ON.diagnostics());
        assert!(!runtime.was_manufactured);
    }

    #[test]
    fn backend_success_without_data_explicit_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let error = main_init(context(
            load_permanent_outcome(|| Ok(StorageLoad::Empty)).arc(),
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "a success without a buffer has no blob");
    }

    #[test]
    fn vanished_backend_state_probe_load_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *VANISH_CALLS.lock().unwrap() = 0;
        let error = main_init(context(
            load_permanent_then_vanishing().arc(),
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "TPM_RETRY on the real load has no blob");
        assert_eq!(*VANISH_CALLS.lock().unwrap(), 2, "probe plus real load");
    }

    #[test]
    fn backend_probe_with_preloaded_empty_state() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(load_retry().arc(), PreloadedBlob::Empty))
            .expect("preloaded-empty powers on over a zeroed NV image");
        assert_eq!(
            events(),
            ["load-retry:Permanent", "load-retry:Volatile"],
            "upstream probes the backend even with preloaded state, and \
             the volatile load still runs at its normal point"
        );
        assert!(!runtime.manufactured, "no Manufacture ran");
        assert!(!runtime.was_manufactured);
    }

    #[test]
    fn backend_probe_with_preloaded_data_state() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("preloaded data restores");
        assert_eq!(
            events(),
            ["load-retry:Permanent", "load-retry:Volatile"],
            "upstream probes the backend even with preloaded state, and \
             still asks for the volatile state afterwards"
        );
    }

    #[test]
    fn malformed_preloaded_header_upstream_code() {
        let truncated =
            main_init(context(no_storage(), PreloadedBlob::Data(vec![0x00, 0x03]))).unwrap_err();
        assert_eq!(truncated, TPM_RC_INSUFFICIENT);

        let bad_magic = main_init(context(
            no_storage(),
            PreloadedBlob::Data(vec![0x00, 0x03, 0xde, 0xad, 0xbe, 0xef]),
        ))
        .unwrap_err();
        assert_eq!(bad_magic, TPM_RC_BAD_TAG);
    }

    #[test]
    fn malformed_backend_header_nv_power_on_failure_mode() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let outcome = main_init(context(
            load_permanent_truncated().arc(),
            PreloadedBlob::Missing,
        ));
        assert_eq!(
            outcome.as_ref().unwrap_err(),
            &TPM_RC_FAILURE,
            "PERSISTENT_ALL_Unmarshal's own code stays inside NvPowerOn"
        );
        let (runtime, volatile_loaded) = failure_mode_runtime(outcome);
        assert!(!volatile_loaded);
        assert_eq!(runtime.failure_diagnostics, NV_POWER_ON.diagnostics());
        assert_eq!(
            events(),
            ["load-truncated:Permanent", "load-truncated:Permanent"],
            "no volatile load after NvPowerOn failed"
        );
    }

    #[test]
    fn valid_envelope_upstream_fixture_section_restore() {
        let mut payload = include_bytes!("testdata/pa_compile_constants_v3.bin").to_vec();
        payload.extend_from_slice(
            &persistent::PrefixFixture {
                tail: pcr::PcrPoliciesFixture {
                    tail: pcr_allocated_tail(),
                    ..pcr::PcrPoliciesFixture::default()
                }
                .bytes(),
                ..persistent::PrefixFixture::default()
            }
            .bytes(),
        );
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the upstream fixture section restores");
        assert!(runtime.state.is_some());
        assert!(!runtime.manufactured);
    }

    #[test]
    fn missing_compile_constants_section_pre_boundary_rejection() {
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&[])),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn invalid_compile_constants_magic_bad_tag() {
        let mut section = compile_constants::marshalled_section(3);
        section[2] = 0xde;
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn unsupported_compile_constants_version_bad_version() {
        let mut section = compile_constants::marshalled_section(3);
        section[0..2].copy_from_slice(&4u16.to_be_bytes());
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_VERSION);
    }

    #[test]
    fn incompatible_compile_constant_bad_parameter() {
        let mut section = compile_constants::marshalled_section(3);
        section[12..16].copy_from_slice(&0u32.to_be_bytes());
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn truncated_compile_constant_array_insufficient() {
        let mut section = compile_constants::marshalled_section(3);
        section.truncate(section.len() / 2);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn invalid_persistent_data_magic_bad_tag() {
        let mut payload = compile_constants::marshalled_section(3);
        let mut prefix = persistent::PrefixFixture::default().bytes();
        prefix[2] = 0xff;
        payload.extend_from_slice(&prefix);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn oversized_persistent_data_tpm2b_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        for index in [0usize, 3, 6, 9] {
            let mut payload = compile_constants::marshalled_section(3);
            let fixture = persistent::PrefixFixture::with_tpm2b(index, vec![0x2a; 65]);
            payload.extend_from_slice(&fixture.bytes());
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_SIZE, "tpm2b index {index}");
        }
    }

    #[test]
    fn truncated_persistent_data_reset_counter_insufficient() {
        let mut payload = compile_constants::marshalled_section(3);
        let prefix = persistent::PrefixFixture::default().bytes();
        payload.extend_from_slice(&prefix[..prefix.len() - 8]);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn absent_required_pcr_policies_block_bad_parameter() {
        let payload = payload_with_pcr_policies(vec![0x00, 0x00, 0x00]);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn invalid_pcr_policy_magic_bad_tag() {
        let mut block = pcr::PcrPoliciesFixture::default().bytes();
        block[6] = 0xff;
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn invalid_pcr_policy_group_count_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        let block = pcr::PcrPoliciesFixture {
            array_size: 2,
            ..pcr::PcrPoliciesFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_SIZE);
    }

    #[test]
    fn raw_pcr_policy_hash_id_restoration() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for hash_alg in [0x0012u16, 0x0000, 0xffff] {
            EVENTS.lock().unwrap().clear();
            let block = pcr::PcrPoliciesFixture {
                hash_alg,
                tail: pcr_allocated_tail(),
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes();
            main_init(context(
                load_retry().arc(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
            ))
            .unwrap_or_else(|error| panic!("alg {hash_alg:#06x}: {:#x}", error.code()));
            assert_eq!(
                events(),
                ["load-retry:Permanent", "load-retry:Volatile"],
                "alg {hash_alg:#06x}: only the probe and the volatile load ran"
            );
        }
    }

    #[test]
    fn zero_count_pcr_allocation_restoration() {
        let allocation = pcr::PcrAllocationFixture {
            selections: Vec::new(),
            tail: pp_list_tail(),
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .expect("a zero-count allocation restores");
    }

    #[test]
    fn oversized_pcr_allocation_count_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        for count in [5u32, u32::MAX] {
            let allocation = pcr::PcrAllocationFixture {
                count: Some(count),
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes();
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                    allocation,
                ))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_SIZE, "count {count}");
        }
    }

    #[test]
    fn invalid_pcr_allocation_hash_error() {
        use crate::library::constants::TPM_RC_HASH;

        for hash in [0x0000u16, 0x0010, 0x0012, 0xffff] {
            let allocation = pcr::PcrAllocationFixture {
                selections: vec![(hash, 3, vec![0x00; 3])],
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes();
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                    allocation,
                ))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_HASH, "hash {hash:#06x}");
        }
    }

    #[test]
    fn invalid_pcr_select_size_value_error() {
        use crate::library::constants::TPM_RC_VALUE;

        let allocation = pcr::PcrAllocationFixture {
            selections: vec![(0x000b, 4, vec![0x00; 4])],
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_VALUE);
    }

    #[test]
    fn truncated_pcr_allocation_bitmap_insufficient() {
        let allocation = pcr::PcrAllocationFixture {
            selections: vec![(0x000b, 3, vec![0x00; 2])],
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn pcr_allocation_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let allocation = pcr::PcrAllocationFixture {
            count: Some(5),
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_SIZE);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the pcrAllocated failure"
        );
    }

    #[test]
    fn oversized_pp_list_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        for size in [18usize, 100] {
            let pp_list = pp_list::PpListFixture {
                array: vec![0x00; size],
                ..pp_list::PpListFixture::default()
            }
            .bytes();
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pp_list(pp_list))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_SIZE, "size {size}");
        }
    }

    #[test]
    fn truncated_pp_list_insufficient() {
        let pp_list = pp_list::PpListFixture {
            size: Some(17),
            array: vec![0x00; 2],
            ..pp_list::PpListFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pp_list(pp_list))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn version_4_blob_compressed_pp_list_path() {
        use crate::library::constants::TPM_RC_SIZE;

        let results: Vec<Result<Tpm2Runtime, InitFailure>> = [4u16, 5]
            .into_iter()
            .map(|version| {
                let mut payload = compile_constants::marshalled_section(3);
                payload.extend_from_slice(
                    &persistent::PrefixFixture {
                        version,
                        tail: pcr::PcrPoliciesFixture {
                            tail: pcr::PcrAllocationFixture {
                                tail: pp_list::PpListFixture {
                                    array: vec![0xff; 60],
                                    tail: persistent_data_tail(),
                                    ..pp_list::PpListFixture::default()
                                }
                                .bytes(),
                                ..pcr::PcrAllocationFixture::default()
                            }
                            .bytes(),
                            ..pcr::PcrPoliciesFixture::default()
                        }
                        .bytes(),
                        ..persistent::PrefixFixture::default()
                    }
                    .bytes(),
                );
                main_init(context(
                    no_storage(),
                    PreloadedBlob::Data(envelope_with_payload(&payload)),
                ))
            })
            .collect();
        assert!(
            results[0].is_ok(),
            "version 4: compressed arrays of any size restore"
        );
        assert_eq!(
            *results[1].as_ref().unwrap_err(),
            TPM_RC_SIZE,
            "version 5: the raw path caps at 17"
        );
    }

    #[test]
    fn pp_list_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let pp_list = pp_list::PpListFixture {
            array: vec![0x00; 18],
            ..pp_list::PpListFixture::default()
        }
        .bytes();
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pp_list(pp_list))),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_SIZE);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the ppList failure"
        );
    }

    #[test]
    fn persistent_data_remainder_orderly_data_boundary() {
        let section = persistent::PrefixFixture {
            tail: pcr::PcrPoliciesFixture {
                tail: pcr_allocated_tail(),
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes(),
            ..persistent::PrefixFixture::default()
        }
        .bytes();
        let prefix = persistent::parse_persistent_data_prefix(&section).unwrap();
        let policies = pcr::parse_pcr_policies(prefix.remaining).unwrap();
        let allocation = pcr::parse_pcr_allocation(policies.remaining).unwrap();
        let pp = pp_list::parse_pp_list(allocation.remaining, prefix.header.version).unwrap();
        let lockout_state = lockout::parse_lockout_state(pp.remaining).unwrap();
        let audit_state =
            audit::parse_audit_state(lockout_state.remaining, prefix.header.version).unwrap();
        let compat =
            persistent::parse_compat_tail(audit_state.remaining, prefix.header.version).unwrap();
        let sections = remaining_sections();
        assert_eq!(compat.remaining, &sections[..]);
        assert!(core::ptr::eq(
            compat.remaining.as_ptr(),
            section[section.len() - sections.len()..].as_ptr()
        ));
    }

    #[test]
    fn truncated_lockout_state_insufficient() {
        let lockout_bytes = lockout::LockoutFixture::default().bytes()[..10].to_vec();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_lockout(lockout_bytes))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn oversized_audit_commands_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        let audit_bytes = audit::AuditFixture {
            commands: vec![0x00; 18],
            ..audit::AuditFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_audit(audit_bytes))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_SIZE);
    }

    #[test]
    fn invalid_clocksize_bad_parameter() {
        let audit_bytes = audit::AuditFixture {
            clocksize: 8,
            ..audit::AuditFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_audit(audit_bytes))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn missing_required_compat_blocks_bad_parameter() {
        for compat in [
            persistent::CompatTailFixture {
                outer_has_block: Some(0),
                ..persistent::CompatTailFixture::default()
            },
            persistent::CompatTailFixture {
                seed_has_block: Some(0),
                ..persistent::CompatTailFixture::default()
            },
        ] {
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                    compat.bytes(),
                ))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn invalid_shadow_pcr_allocation_hash_error() {
        use crate::library::constants::TPM_RC_HASH;

        let compat = persistent::CompatTailFixture {
            shadow: pcr::PcrAllocationFixture {
                selections: vec![(0x0010, 3, vec![0x00; 3])],
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes(),
            ..persistent::CompatTailFixture::default()
        };
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                compat.bytes(),
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_HASH);
    }

    #[test]
    fn maximum_seed_compat_level_commit_survival() {
        let compat = persistent::CompatTailFixture {
            seed_levels: [1, 1, 1],
            tail: remaining_sections(),
            ..persistent::CompatTailFixture::default()
        };
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                compat.bytes(),
            ))),
        ))
        .expect("maximum seed levels restore");
        assert_eq!(runtime.state().persistent.ep_seed_compat_level, 1);
        assert_eq!(runtime.state().persistent.sp_seed_compat_level, 1);
        assert_eq!(runtime.state().persistent.pp_seed_compat_level, 1);
    }

    #[test]
    fn seed_compat_level_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let compat = persistent::CompatTailFixture {
            seed_levels: [2, 0, 0],
            ..persistent::CompatTailFixture::default()
        };
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                compat.bytes(),
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_VERSION);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the seed-level failure"
        );
    }

    #[test]
    fn oversized_pcr_policy_digest_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        let block = pcr::PcrPoliciesFixture {
            policy: vec![0x2a; 65],
            ..pcr::PcrPoliciesFixture::default()
        }
        .bytes();
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_SIZE);
    }

    #[test]
    fn truncated_pcr_policies_insufficient() {
        let mut block = pcr::PcrPoliciesFixture::default().bytes();
        block.truncate(block.len() - 2);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn pcr_policies_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let payload = payload_with_pcr_policies(vec![0x00, 0x00, 0x00]);
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the pcrPolicies failure"
        );
    }

    #[test]
    fn persistent_data_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let mut payload = compile_constants::marshalled_section(3);
        let mut prefix = persistent::PrefixFixture::default().bytes();
        prefix[2] = 0xff;
        payload.extend_from_slice(&prefix);
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the prefix failure"
        );
    }

    #[test]
    fn section_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let mut section = compile_constants::marshalled_section(3);
        section[2] = 0xde;
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the section failure"
        );
    }

    #[test]
    fn parse_failure_no_further_callbacks_preload_priority() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error =
            main_init(context(load_retry().arc(), PreloadedBlob::Data(vec![0x00]))).unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the parse failure"
        );
    }

    #[test]
    fn preloaded_empty_no_load_callback_power_on() {
        let runtime = main_init(context(no_storage(), PreloadedBlob::Empty))
            .expect("preloaded-empty powers on without any callback");
        assert!(!runtime.manufactured);
        assert!(!runtime.was_manufactured);
        assert!(runtime.power_on && runtime.nv_available);
        assert!(runtime.state.is_none(), "no decoded state exists");
        assert_eq!(runtime.nv_memory.len(), runtime::NV_MEMORY_SIZE);
        assert!(
            runtime.nv_memory.iter().all(|&byte| byte == 0),
            "the NV image is fully zeroed"
        );
        assert_eq!(
            runtime.active_profile_json, "",
            "no profile is ever activated on this path"
        );
    }

    fn payload_with_orderly_state(orderly_state: u16, sections: Vec<u8>) -> Vec<u8> {
        payload_with_lockout(
            lockout::LockoutFixture {
                orderly_state,
                tail: audit::AuditFixture {
                    tail: persistent::CompatTailFixture {
                        tail: sections,
                        ..persistent::CompatTailFixture::default()
                    }
                    .bytes(),
                    ..audit::AuditFixture::default()
                }
                .bytes(),
                ..lockout::LockoutFixture::default()
            }
            .bytes(),
        )
    }

    fn envelope_v2_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x02, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    fn envelope_v1_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x01, 0xab, 0x36, 0x47, 0x23];
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    #[test]
    fn su_state_blob_conditional_section_reads() {
        for orderly_state in [0x0001u16, 0x8001, 0x4001, 0xc001] {
            let payload =
                payload_with_orderly_state(orderly_state, remaining_sections_with_su_state());
            let runtime = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_or_else(|error| {
                panic!("orderlyState {orderly_state:#06x}: {:#x}", error.code())
            });
            assert!(
                runtime.state().state_reset.is_some() && runtime.state().state_clear.is_some(),
                "orderlyState {orderly_state:#06x}: both sections restored"
            );
        }
    }

    #[test]
    fn non_su_state_blob_conditional_section_omission() {
        for orderly_state in [0x0000u16, 0x0002, 0x8000] {
            let payload = payload_with_orderly_state(orderly_state, remaining_sections());
            let runtime = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_or_else(|error| {
                panic!("orderlyState {orderly_state:#06x}: {:#x}", error.code())
            });
            assert!(
                runtime.state().state_reset.is_none() && runtime.state().state_clear.is_none(),
                "orderlyState {orderly_state:#06x}: no startup sections"
            );
        }
    }

    #[test]
    fn su_state_blob_missing_conditional_sections_rejection() {
        let payload = payload_with_orderly_state(0x0001, remaining_sections());
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn non_su_state_blob_conditional_sections_rejection() {
        let payload = payload_with_orderly_state(0x0000, remaining_sections_with_su_state());
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn outer_version_below_3_conditional_section_reads() {
        let payload = payload_with_orderly_state(0x0000, remaining_sections_with_su_state());
        main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v2_with_payload(&payload)),
        ))
        .expect("version 2 always carries the sections");

        let payload = payload_with_orderly_state(0x0000, remaining_sections());
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v2_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn pre_footer_extra_bytes_rejection() {
        let mut payload = valid_payload();
        payload.push(0xee);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn absent_final_future_block_insufficiency() {
        let mut payload = valid_payload();
        payload.truncate(payload.len() - 3);
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn nonempty_final_future_block_skip() {
        let mut payload = valid_payload();
        payload.truncate(payload.len() - 3);
        payload.extend_from_slice(&[0x01, 0x00, 0x04, 0xf1, 0xf2, 0xf3, 0xf4]);
        main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("a nonempty final future block restores");
    }

    #[test]
    fn late_section_truncation_insufficiency() {
        let sections = remaining_sections();
        for len in 0..sections.len() {
            let payload = payload_with_orderly_state(0, sections[..len].to_vec());
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_err();
            assert_eq!(
                error,
                TPM_RC_INSUFFICIENT,
                "prefix length {len} of {}",
                sections.len()
            );
        }
    }

    #[test]
    fn conditional_section_truncation_insufficiency() {
        let sections = remaining_sections_with_su_state();
        let orderly_len = persistent::OrderlyFixture::default().bytes().len();
        let reset_len = state::StateResetFixture::default().bytes().len();
        let clear_len = state::StateClearFixture::default().bytes().len();
        for len in [
            orderly_len + 1,
            orderly_len + reset_len - 1,
            orderly_len + reset_len + 1,
            orderly_len + reset_len + clear_len - 1,
        ] {
            let payload = payload_with_orderly_state(0x0001, sections[..len].to_vec());
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_INSUFFICIENT, "truncated at {len}");
        }
    }

    #[test]
    fn late_section_failure_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let mut bad_entry = Vec::new();
        bad_entry.extend_from_slice(&10u32.to_be_bytes());
        bad_entry.extend_from_slice(&0x4000_0001u32.to_be_bytes());
        let mut sections = persistent::OrderlyFixture::default().bytes();
        sections.extend_from_slice(&nv::IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(
            &nv::UserNvramFixture {
                entries: vec![bad_entry],
                ..nv::UserNvramFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        let payload = payload_with_orderly_state(0, sections);
        let error = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_HANDLE);
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "only the probe ran; no extra callback after the USER_NVRAM failure"
        );
    }

    const NULL_PROFILE_LEVEL_1: &[u8] = br#"{"Name":"null","StateFormatLevel":1}"#;
    const DEFAULT_PROFILE_LEVEL_7: &[u8] = br#"{"Name":"default-v1","StateFormatLevel":7}"#;

    #[test]
    fn version_1_envelope_complete_payload_decode() {
        let mut sections = remaining_sections_with_su_state();
        sections.truncate(sections.len() - 3);
        let payload = payload_with_orderly_state(0, sections);
        main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v1_with_payload(&payload)),
        ))
        .expect("a version-1 envelope restores");
    }

    #[test]
    fn version_4_serialized_profile_envelope_restoration() {
        for (profile, level) in [(NULL_PROFILE_LEVEL_1, 1), (DEFAULT_PROFILE_LEVEL_7, 7)] {
            let runtime = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_v4_with_profile(profile, &valid_payload())),
            ))
            .unwrap_or_else(|error| {
                panic!(
                    "profile {:?}: {:#x}",
                    String::from_utf8_lossy(profile),
                    error.code()
                )
            });
            assert_eq!(runtime.state().profile.state_format_level, level);
        }
    }

    #[test]
    fn profile_rejection_upstream_codes() {
        use crate::library::constants::{TPM_RC_NO_RESULT, TPM_RC_VALUE};

        for (profile, expected) in [
            (&b"garbage"[..], TPM_RC_NO_RESULT),
            (br#"{"StateFormatLevel":1}"#, TPM_RC_NO_RESULT),
            (br#"{"Name":"null"}"#, TPM_RC_NO_RESULT),
            (br#"{"Name":"nosuch","StateFormatLevel":1}"#, TPM_RC_VALUE),
            (br#"{"Name":"null","StateFormatLevel":8}"#, TPM_RC_VALUE),
        ] {
            let error = main_init(context(
                no_storage(),
                PreloadedBlob::Data(envelope_v4_with_profile(profile, &valid_payload())),
            ))
            .unwrap_err();
            assert_eq!(
                error,
                expected,
                "profile {:?}",
                String::from_utf8_lossy(profile)
            );
        }
    }

    #[test]
    fn profile_validation_compile_constant_precedence() {
        let mut payload = valid_payload();
        payload[2] = 0xde;
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v4_with_profile(b"garbage", &payload)),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_NO_RESULT);
    }

    fn payload_with_persistent_objects(count: usize) -> Vec<u8> {
        let object = object::fixtures::any_rsa_object(4);
        let entries = (0..count)
            .map(|_| nv::UserNvramFixture::persistent_entry(0x8100_0001, &object))
            .collect();
        let mut sections = persistent::OrderlyFixture::default().bytes();
        sections.extend_from_slice(&nv::IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(
            &nv::UserNvramFixture {
                entries,
                ..nv::UserNvramFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);
        payload_with_orderly_state(0, sections)
    }

    #[test]
    fn serialized_level_1_profile_legacy_object_size() {
        let payload = payload_with_persistent_objects(66);

        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v4_with_profile(NULL_PROFILE_LEVEL_1, &payload)),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            crate::library::constants::TPM_RC_SIZE,
            "level 1 must charge 2600 bytes per object"
        );

        main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v4_with_profile(DEFAULT_PROFILE_LEVEL_7, &payload)),
        ))
        .expect("level 7 charges the re-marshalled size and fits");
    }

    #[test]
    fn legacy_capacity_boundary_65_objects() {
        let payload = payload_with_persistent_objects(65);
        main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_v4_with_profile(NULL_PROFILE_LEVEL_1, &payload)),
        ))
        .expect("65 legacy objects fit exactly");
    }

    #[test]
    fn repeated_main_init_determinism() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for attempt in 0..3 {
            EVENTS.lock().unwrap().clear();
            let runtime = main_init(context(
                load_retry().arc(),
                PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            ))
            .unwrap_or_else(|error| panic!("attempt {attempt}: {:#x}", error.code()));
            assert!(!runtime.manufactured, "attempt {attempt}");
            assert_eq!(
                events(),
                ["load-retry:Permanent", "load-retry:Volatile"],
                "attempt {attempt}: the probe and the volatile load ran"
            );
        }

        let payload = payload_with_orderly_state(0x0001, remaining_sections());
        let blob = envelope_with_payload(&payload);
        for attempt in 0..3 {
            EVENTS.lock().unwrap().clear();
            let error = main_init(context(
                load_retry().arc(),
                PreloadedBlob::Data(blob.clone()),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_BAD_TAG, "attempt {attempt}");
            assert_eq!(
                events(),
                ["load-retry:Permanent"],
                "attempt {attempt}: only the probe ran"
            );
        }
    }

    #[test]
    fn runtime_state_ownership_after_blob_drop() {
        let runtime = {
            let blob = VALID_ENVELOPE.to_vec();
            main_init(context(no_storage(), PreloadedBlob::Data(blob)))
                .expect("the valid envelope restores")
        };
        assert_eq!(runtime.nv_memory.len(), runtime::NV_MEMORY_SIZE);
        assert_eq!(
            runtime.state().orderly.drbg_state.seed.expose(),
            &[0x5a; 48][..]
        );
        assert_eq!(runtime.state().user_nvram.required_capacity, 12);
    }

    #[test]
    fn su_state_runtime_live_global_values() {
        let payload = payload_with_orderly_state(0x0001, remaining_sections_with_su_state());
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the SU-state blob restores");
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, 0);

        let payload = payload_with_orderly_state(0, remaining_sections());
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the non-SU blob restores");
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, 0);
    }

    #[test]
    fn shadow_allocation_runtime_distinction() {
        let compat = persistent::CompatTailFixture {
            shadow: pcr::PcrAllocationFixture {
                selections: vec![(0x0004, 3, vec![0x00, 0x00, 0x02])],
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes(),
            tail: remaining_sections(),
            ..persistent::CompatTailFixture::default()
        };
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                compat.bytes(),
            ))),
        ))
        .expect("the shadow-carrying blob restores");
        assert_ne!(
            runtime.shadow_pcr_allocated,
            runtime.state().persistent.pcr_allocated
        );
        assert_eq!(runtime.shadow_pcr_allocated.selections[0].hash_alg, 0x0004);
        assert_eq!(
            runtime.state().persistent.pcr_allocated.selections[0].hash_alg,
            0x000b
        );
    }

    #[test]
    fn runtime_debug_output_no_secret_bytes() {
        let auth = b"auth-secret-mark".to_vec();
        let seed = b"seed-secret-mark".to_vec();
        let proof = b"proof-secret-mrk".to_vec();
        let mut prefix = persistent::PrefixFixture {
            tail: pcr::PcrPoliciesFixture {
                tail: pcr_allocated_tail(),
                ..pcr::PcrPoliciesFixture::default()
            }
            .bytes(),
            ..persistent::PrefixFixture::default()
        };
        prefix.tpm2bs[3] = auth;
        prefix.tpm2bs[6] = seed;
        prefix.tpm2bs[9] = proof;
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(&prefix.bytes());
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the marked blob restores");
        let formatted = format!("{runtime:?} {:?}", runtime.state());
        for secret in ["auth-secret-mark", "seed-secret-mark", "proof-secret-mrk"] {
            assert!(
                !formatted.contains(secret),
                "Debug output must not contain {secret:?}"
            );
        }
    }

    fn tailless_v2_payload_with_active_sha256(pcr_save: Vec<u8>) -> Vec<u8> {
        let mut sections = persistent::OrderlyFixture::default().bytes();
        sections.extend_from_slice(&state::StateResetFixture::default().bytes());
        sections.extend_from_slice(
            &state::StateClearFixture {
                pcr_save,
                ..state::StateClearFixture::default()
            }
            .bytes(),
        );
        sections.extend_from_slice(&nv::IndexOrderlyRamFixture::default().bytes());
        sections.extend_from_slice(&nv::UserNvramFixture::default().bytes());
        sections.extend_from_slice(&[0x01, 0x00, 0x00]);

        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &persistent::PrefixFixture {
                version: 2,
                tail: pcr::PcrPoliciesFixture {
                    tail: pcr::PcrAllocationFixture {
                        selections: vec![(0x000b, 3, vec![0x01, 0x00, 0x00])],
                        tail: pp_list::PpListFixture {
                            tail: lockout::LockoutFixture {
                                orderly_state: 0x0001,
                                tail: audit::AuditFixture {
                                    tail: persistent::CompatTailFixture {
                                        outer_has_block: Some(0),
                                        tail: sections,
                                        ..persistent::CompatTailFixture::default()
                                    }
                                    .bytes(),
                                    ..audit::AuditFixture::default()
                                }
                                .bytes(),
                                ..lockout::LockoutFixture::default()
                            }
                            .bytes(),
                            ..pp_list::PpListFixture::default()
                        }
                        .bytes(),
                        ..pcr::PcrAllocationFixture::default()
                    }
                    .bytes(),
                    ..pcr::PcrPoliciesFixture::default()
                }
                .bytes(),
                ..persistent::PrefixFixture::default()
            }
            .bytes(),
        );
        payload
    }

    #[test]
    fn absent_compat_tail_pcr_save_validation() {
        let payload =
            tailless_v2_payload_with_active_sha256(state::PcrSaveFixture::default().bytes());
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("all banks present restores");
        assert!(runtime.state().persistent.shadow_pcr_allocated.is_none());
        assert_eq!(
            runtime.shadow_pcr_allocated,
            runtime.state().persistent.pcr_allocated,
            "missing shadow falls back to the normal pcrAllocated"
        );

        let mut pcr_save = state::PcrSaveFixture::default();
        pcr_save.banks.retain(|&(alg, _, _)| alg != 0x000b);
        let payload = tailless_v2_payload_with_active_sha256(pcr_save.bytes());
        let error = main_init(context(
            no_storage(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn preloaded_permanent_missing_volatile_upstream_callback_sequence() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let runtime = main_init(context_with_platform(
            io_platform(),
            recording_store(recording_init(load_retry())).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Missing,
            None,
        ))
        .expect("preloaded permanent state with no volatile state restores");
        assert_eq!(
            events(),
            [
                "io",
                "nvram",
                "load-retry:Permanent",
                "load-retry:Volatile",
                "store:Permanent",
            ]
        );
        let stored = STORED_BLOBS.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "Permanent");
        assert_eq!(
            stored[0].1,
            persistent::persistent_all_store(runtime.state()).unwrap()
        );
        let envelope = persistent::PersistentAllEnvelope::parse(&stored[0].1).unwrap();
        parse_persistent_all_payload(&envelope).expect("the committed blob round-trips");
    }

    #[test]
    fn backend_permanent_no_preloaded_state_commit() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        main_init(context_with_platform(
            io_platform(),
            recording_store(recording_init(load_permanent_envelope())).arc(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
            None,
        ))
        .expect("backend permanent state restores");
        assert_eq!(
            events(),
            [
                "io",
                "nvram",
                "load:Permanent",
                "load:Permanent",
                "load:Volatile",
            ]
        );
        assert!(
            STORED_BLOBS.lock().unwrap().is_empty(),
            "no preloaded-state NvCommit for backend-loaded permanent state"
        );
    }

    #[test]
    fn preloaded_empty_volatile_backend_load_skip() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context_with_volatile(
            load_retry().arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Empty,
        ))
        .expect("preloaded-empty volatile state restores permanent-only");
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "an explicitly empty preloaded volatile entry suppresses the \
             backend volatile load"
        );
    }

    #[test]
    fn backend_retry_volatile_state_no_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            load_retry().arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("TPM_RETRY for volatilestate restores permanent-only");
        assert_eq!(events(), ["load-retry:Permanent", "load-retry:Volatile"]);
        assert!(!runtime.startup_received);
    }

    #[test]
    fn short_preloaded_volatile_blob_ignored() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let runtime = main_init(context_with_volatile(
            recording_store(load_retry()).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(vec![0xd0, 0x0d]),
        ))
        .expect("VolatileState_Load refuses a blob without room for its trailer untouched");
        assert!(!runtime.failure_mode);
        assert!(runtime.restored_volatile.is_none());
        assert_eq!(
            events(),
            ["load-retry:Permanent", "store:Permanent"],
            "preloaded volatile data needs no backend load, and the \
             preloaded-state commit follows the successful power-on"
        );
    }

    #[test]
    fn undecodable_preloaded_volatile_blob_failure_mode() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let outcome = main_init(context_with_volatile(
            recording_store(load_retry()).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(vec![0xd0; 64]),
        ));
        assert_eq!(outcome.as_ref().unwrap_err(), &TPM_RC_FAILURE);
        let (runtime, volatile_loaded) = failure_mode_runtime(outcome);
        assert!(volatile_loaded);
        assert_eq!(
            runtime.failure_diagnostics,
            runtime::FailureDiagnostics::default(),
            "the header already failed, before any diagnostics"
        );
        assert!(
            runtime.state.is_some(),
            "the permanent state stays restored"
        );
        assert_eq!(
            events(),
            ["load-retry:Permanent"],
            "no preloaded-state commit for a TPM in failure mode"
        );
        assert!(STORED_BLOBS.lock().unwrap().is_empty());
    }

    #[test]
    fn short_backend_volatile_blob_ignored() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            load_volatile_only(|| Ok(StorageLoad::Data(vec![0xd0, 0x0d]))).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a two-byte volatile blob is not restored");
        assert!(!runtime.failure_mode);
        assert_eq!(events(), ["load:Permanent", "load:Volatile"]);

        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            load_permanent_and_junk_volatile().arc(),
            PreloadedBlob::Missing,
        ))
        .expect("the backend's two junk bytes are not restored either");
        assert!(!runtime.failure_mode);
        assert_eq!(
            events(),
            [
                "load-found:Permanent",
                "load-found:Permanent",
                "load-found:Volatile",
            ]
        );
    }

    #[test]
    fn undecodable_backend_volatile_blob_failure_mode() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let outcome = main_init(context(
            load_volatile_only(|| Ok(StorageLoad::Data(vec![0xd0; 64]))).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ));
        let (runtime, volatile_loaded) = failure_mode_runtime(outcome);
        assert!(volatile_loaded);
        assert!(runtime.restored_volatile.is_none());
        assert_eq!(events(), ["load:Permanent", "load:Volatile"]);
    }

    #[test]
    fn volatile_callback_error_upstream_ignore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            load_volatile_only(|| Err(77)).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a volatile load error restores permanent-only, like upstream");
        assert_eq!(events(), ["load:Permanent", "load:Volatile"]);
    }

    #[test]
    fn volatile_success_without_buffer_no_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            load_volatile_only(|| Ok(StorageLoad::Empty)).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a bufferless volatile success restores permanent-only");
        assert_eq!(events(), ["load:Permanent", "load:Volatile"]);
    }

    #[test]
    fn storedata_error_maininit_result_unchanged() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            failing_store(load_retry()).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a failed preloaded-state commit is ignored, like upstream");
        assert_eq!(
            events(),
            [
                "load-retry:Permanent",
                "load-retry:Volatile",
                "store-error:Permanent",
            ]
        );
    }

    #[test]
    fn pcr_shadow_pending_without_volatile_restore() {
        let shadow_tail = persistent::CompatTailFixture {
            shadow: pcr::PcrAllocationFixture {
                selections: vec![(0x0004, 3, vec![0x00, 0x00, 0x02])],
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes(),
            tail: remaining_sections(),
            ..persistent::CompatTailFixture::default()
        };
        let blob = envelope_with_payload(&payload_with_compat_tail(shadow_tail.bytes()));

        for preloaded_volatile in [PreloadedBlob::Missing, PreloadedBlob::Empty] {
            let runtime = main_init(context_with_volatile(
                no_storage(),
                PreloadedBlob::Data(blob.clone()),
                preloaded_volatile,
            ))
            .expect("permanent-only initialization succeeds");
            let expected_shadow = persistent::OwnedPcrAllocation {
                selections: vec![persistent::OwnedPcrSelection {
                    hash_alg: 0x0004,
                    select: vec![0x00, 0x00, 0x02],
                }],
            };
            assert_eq!(
                runtime.shadow_pcr_allocated, expected_shadow,
                "the shadow is retained as pending state"
            );
            assert_ne!(
                runtime.state().persistent.pcr_allocated,
                expected_shadow,
                "the committed allocation was not overwritten prematurely"
            );
            assert!(
                runtime.shadow_pcr_pending,
                "the pending marker survives when NVShadowRestore never ran"
            );
            assert!(runtime.live_pcr_allocated.is_none());
        }
    }

    static VALID_VOLATILE: LazyLock<Vec<u8>> = LazyLock::new(valid_volatile_state_fixture);

    fn load_permanent_and_valid_volatile() -> TestStorage {
        TestStorage::new().on_load(|kind| {
            push_event(format!("load-valid:{kind:?}"));
            match kind {
                StateBlobKind::Permanent => Ok(StorageLoad::Data(VALID_ENVELOPE.to_vec())),
                StateBlobKind::Volatile => Ok(StorageLoad::Data(VALID_VOLATILE.to_vec())),
                StateBlobKind::SaveState => Ok(StorageLoad::Missing),
            }
        })
    }

    #[test]
    fn valid_preloaded_volatile_blob_restore_merge_commit() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let runtime = main_init(context_with_volatile(
            recording_store(load_retry()).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(valid_volatile_state_fixture()),
        ))
        .expect("a valid volatile blob restores");
        assert_eq!(
            events(),
            ["load-retry:Permanent", "store:Permanent"],
            "preloaded volatile data needs no backend load and the \
             preloaded-state commit still runs"
        );

        let volatile_state = runtime
            .restored_volatile
            .as_ref()
            .expect("volatile state merged");
        assert_eq!(volatile_state.time, 987_654);
        assert_eq!(volatile_state.max_counter, 42);
        assert!(runtime.tpm_established, "tpmEstablished from the blob");
        assert!(runtime.manufactured, "g_manufactured from the blob");
        assert!(runtime.startup_received, "g_initialized from the blob");
        assert!(!runtime.failure_mode);
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, 0);

        assert!(!runtime.shadow_pcr_pending);
        assert_eq!(
            runtime.live_pcr_allocated.as_ref(),
            Some(&runtime.shadow_pcr_allocated)
        );
        assert_eq!(
            runtime.effective_pcr_allocated(),
            Some(&runtime.shadow_pcr_allocated)
        );

        let stored = STORED_BLOBS.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].1,
            persistent::persistent_all_store(runtime.state()).unwrap()
        );
    }

    #[test]
    fn c_generated_volatile_fixture_end_to_end_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let blob = include_bytes!("testdata/volatile_state_v4.bin").to_vec();
        let runtime = main_init(context_with_volatile(
            no_storage(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(blob),
        ))
        .expect("the C-generated volatile fixture restores");
        let volatile_state = runtime
            .restored_volatile
            .as_ref()
            .expect("volatile state merged");
        assert_eq!(volatile_state.time, 0x123456);
        assert_eq!(runtime.failure_diagnostics.function, 0xa1);
        assert!(runtime.manufactured);
        assert!(runtime.startup_received);
        assert!(!runtime.shadow_pcr_pending);
    }

    #[test]
    fn v4_restore_init_time_rebased_clock() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let host = recording_clock();
        let runtime = main_init(Tpm2InitContext {
            platform: Box::leak(Box::new(no_platform())).as_ref(),
            storage: Box::leak(Box::new(no_storage())).as_ref(),
            preloaded_permanent: PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            preloaded_volatile: PreloadedBlob::Data(valid_volatile_state_fixture()),
            configured_profile: None,
            entropy: ENTROPY,
            clock: &host,
            failure_diagnostics: FailureDiagnostics::default(),
        })
        .expect("the v4 volatile fixture restores");
        assert_eq!(
            host.calls(),
            [clock::ClockCall::Monotonic, clock::ClockCall::Realtime]
        );
        assert_eq!(
            runtime.clock,
            clock::RuntimeClock {
                host_monotonic_adjust_ms: -2_000_000,
                suspended_elapsed_ms: 560_000,
                last_system_time_ms: 1_600_000_000_500,
                last_reported_time_ms: 1_600_000_000_400,
            }
        );
    }

    #[test]
    fn pre_v4_restore_realtime_clock_rebase() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let blob = volatile::VolatileFixture {
            version: 3,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
        .bytes();
        let host = recording_clock();
        let runtime = main_init(Tpm2InitContext {
            platform: Box::leak(Box::new(no_platform())).as_ref(),
            storage: Box::leak(Box::new(no_storage())).as_ref(),
            preloaded_permanent: PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            preloaded_volatile: PreloadedBlob::Data(blob),
            configured_profile: None,
            entropy: ENTROPY,
            clock: &host,
            failure_diagnostics: FailureDiagnostics::default(),
        })
        .expect("the v3 volatile fixture restores");
        assert_eq!(
            host.calls(),
            [clock::ClockCall::Realtime, clock::ClockCall::Monotonic]
        );
        assert_eq!(
            runtime.clock,
            clock::RuntimeClock {
                host_monotonic_adjust_ms: -7_000_000,
                suspended_elapsed_ms: 1_600_000_500_000,
                last_system_time_ms: 1_600_000_500_000,
                last_reported_time_ms: 1_600_000_500_000,
            }
        );
    }

    #[test]
    fn init_without_volatile_restore_power_on_baseline() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runtime = main_init(context(
            no_storage(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("the permanent fixture restores without volatile state");
        assert_eq!(
            runtime.clock,
            clock::RuntimeClock {
                host_monotonic_adjust_ms: 0,
                suspended_elapsed_ms: 0,
                last_system_time_ms: TEST_MONOTONIC_MS,
                last_reported_time_ms: 0,
            },
            "TimePowerOn samples the host timer like _TPM_Init"
        );
        assert_eq!(runtime.timer, clock::TpmTimer::POWER_ON_RESET);
    }

    #[test]
    fn short_volatile_blob_left_unrestored() {
        let storage = NoStorage;
        for length in [0, 2, volatile::SHA1_DIGEST_SIZE - 1] {
            let mut candidate = runtime::empty_state_runtime();
            let host = recording_clock();
            volatile_phase(
                &storage,
                PreloadedBlob::Data(valid_volatile_state_fixture()[..length].to_vec()),
                &host,
                &mut candidate,
            );
            assert!(
                host.calls().is_empty(),
                "{length} bytes: VolatileState_Load stops before the unmarshal"
            );
            assert_eq!(candidate.clock, clock::RuntimeClock::POWER_ON_RESET);
            assert!(candidate.restored_volatile.is_none(), "{length} bytes");
            assert!(
                !candidate.failure_mode,
                "{length} bytes: _TPM_Init ignores the TPM_RC_INSUFFICIENT"
            );
        }
    }

    fn diagnosed_volatile_fixture() -> volatile::VolatileFixture {
        volatile::VolatileFixture {
            tpm_established: 1,
            fail_function: 0x0102_0304,
            fail_line: 0x0506_0708,
            fail_code: 0x090a_0b0c,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
    }

    const FIXTURE_DIAGNOSTICS: runtime::FailureDiagnostics = runtime::FailureDiagnostics {
        function: 0x0102_0304,
        line: 0x0506_0708,
        code: 0x090a_0b0c,
    };

    #[test]
    fn early_rejected_volatile_blob_keeps_only_the_fields_before_its_defect() {
        let storage = NoStorage;
        let blob = diagnosed_volatile_fixture().bytes();
        for (length, ph_enable, drtm_handle) in [
            (
                volatile::SHA1_DIGEST_SIZE,
                false,
                hierarchy::TPM_RH_UNASSIGNED,
            ),
            (64, true, 0x4000_0007),
        ] {
            let mut candidate = runtime::empty_state_runtime();
            let host = recording_clock();
            volatile_phase(
                &storage,
                PreloadedBlob::Data(blob[..length].to_vec()),
                &host,
                &mut candidate,
            );
            assert!(candidate.failure_mode, "{length} bytes");
            let carried = candidate
                .restored_volatile
                .as_ref()
                .unwrap_or_else(|| panic!("{length} bytes: the leading fields are restored"));
            assert_eq!(
                carried.exclusive_audit_session, 0x0300_0000,
                "{length} bytes"
            );
            assert_eq!(carried.drtm_handle, drtm_handle, "{length} bytes");
            assert_eq!(candidate.timer.time_ms, 987_654, "{length} bytes");
            assert_eq!(candidate.live.ph_enable, ph_enable, "{length} bytes");
            assert_eq!(
                candidate.failure_diagnostics,
                runtime::FailureDiagnostics::default(),
                "{length} bytes: the unmarshal never reached s_failFunction"
            );
            assert!(!candidate.tpm_established, "{length} bytes");
            assert_eq!(
                candidate.clock.last_system_time_ms, TEST_MONOTONIC_MS,
                "{length} bytes: TimePowerOn ran before the load"
            );
            assert_eq!(
                candidate.clock.host_monotonic_adjust_ms, 0,
                "{length} bytes"
            );
        }
    }

    #[test]
    fn tail_truncated_volatile_failure_mode_with_unmarshalled_fields() {
        let payload = diagnosed_volatile_fixture().payload();
        let cut = payload.len() - 4 - 3 - 32 + 8;
        let storage = NoStorage;
        for attempt in 0..2 {
            let mut candidate = runtime::empty_state_runtime();
            let host = recording_clock();
            volatile_phase(
                &storage,
                PreloadedBlob::Data(payload[..cut].to_vec()),
                &host,
                &mut candidate,
            );
            assert_eq!(
                host.calls(),
                [
                    clock::ClockCall::Monotonic,
                    clock::ClockCall::Monotonic,
                    clock::ClockCall::Monotonic
                ],
                "attempt {attempt}: the decoder's tail sample, TimePowerOn, then the restore's"
            );
            assert!(candidate.failure_mode, "attempt {attempt}");
            assert_eq!(
                candidate.failure_diagnostics, FIXTURE_DIAGNOSTICS,
                "attempt {attempt}: the diagnostics precede the tail"
            );
            assert!(candidate.tpm_established, "attempt {attempt}");
            assert_eq!(
                (
                    candidate.timer.real_time_previous,
                    candidate.timer.tpm_time,
                    candidate.timer.adjust_rate,
                    candidate.timer.timer_reset,
                    candidate.timer.timer_stopped,
                ),
                (111_222, 111_000, 30_000, false, false),
                "attempt {attempt}: the timer block precedes the tail"
            );
            assert_eq!(
                candidate.clock,
                clock::RuntimeClock {
                    host_monotonic_adjust_ms: 5_000_000 - TEST_MONOTONIC_MS as i64,
                    suspended_elapsed_ms: 0,
                    last_system_time_ms: TEST_MONOTONIC_MS,
                    last_reported_time_ms: 0,
                },
                "attempt {attempt}: only the tail's first sample was restored"
            );
            let carried = candidate
                .restored_volatile
                .as_ref()
                .unwrap_or_else(|| panic!("attempt {attempt}: the leading fields are restored"));
            assert_eq!(carried.tail_v4, None, "attempt {attempt}");
        }
    }

    #[test]
    fn bad_volatile_digest_full_unmarshal_failure_mode() {
        let mut blob = diagnosed_volatile_fixture().bytes();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        let storage = NoStorage;
        let reference = {
            let mut runtime = runtime::empty_state_runtime();
            let valid = diagnosed_volatile_fixture().bytes();
            volatile_phase(
                &storage,
                PreloadedBlob::Data(valid),
                &recording_clock(),
                &mut runtime,
            );
            runtime
        };
        for attempt in 0..2 {
            let mut candidate = runtime::empty_state_runtime();
            candidate.shadow_pcr_pending = true;
            let host = recording_clock();
            volatile_phase(
                &storage,
                PreloadedBlob::Data(blob.clone()),
                &host,
                &mut candidate,
            );
            assert_eq!(
                host.calls(),
                [clock::ClockCall::Monotonic, clock::ClockCall::Realtime],
                "attempt {attempt}: the v4 unmarshal reads run before the digest check"
            );
            assert!(candidate.failure_mode, "attempt {attempt}");
            assert_eq!(candidate.failure_diagnostics, FIXTURE_DIAGNOSTICS);
            assert!(
                candidate.restored_volatile.is_some(),
                "attempt {attempt}: every field was unmarshalled before the check"
            );
            assert_eq!(candidate.clock, reference.clock, "attempt {attempt}");
            assert!(
                candidate.shadow_pcr_pending,
                "attempt {attempt}: no NVShadowRestore for a failed load"
            );
        }
    }

    #[test]
    fn controlled_clock_repeated_init_determinism() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let run = |host: &clock::RecordingClock| {
            main_init(Tpm2InitContext {
                platform: Box::leak(Box::new(no_platform())).as_ref(),
                storage: Box::leak(Box::new(no_storage())).as_ref(),
                preloaded_permanent: PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
                preloaded_volatile: PreloadedBlob::Data(valid_volatile_state_fixture()),
                configured_profile: None,
                entropy: ENTROPY,
                clock: host,
                failure_diagnostics: FailureDiagnostics::default(),
            })
            .expect("the restore succeeds")
        };
        let first_host = recording_clock();
        let first = run(&first_host);
        let second_host = recording_clock();
        let second = run(&second_host);
        assert_eq!(first.clock, second.clock);
        assert_eq!(first.clock.suspended_elapsed_ms, 560_000);
        assert_eq!(first_host.calls(), second_host.calls());
        assert_eq!(
            first_host.calls(),
            [clock::ClockCall::Monotonic, clock::ClockCall::Realtime]
        );
    }

    #[test]
    fn valid_backend_volatile_blob_restoration() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            load_permanent_and_valid_volatile().arc(),
            PreloadedBlob::Missing,
        ))
        .expect("backend permanent and volatile state restore");
        assert_eq!(
            events(),
            [
                "load-valid:Permanent",
                "load-valid:Permanent",
                "load-valid:Volatile",
            ]
        );
        assert!(runtime.restored_volatile.is_some());
        assert!(!runtime.shadow_pcr_pending);
    }

    #[test]
    fn preloaded_volatile_over_backend_precedence() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context_with_volatile(
            load_permanent_and_junk_volatile().arc(),
            PreloadedBlob::Missing,
            PreloadedBlob::Data(valid_volatile_state_fixture()),
        ))
        .expect("the preloaded volatile blob wins over the backend's junk");
        assert_eq!(
            events(),
            ["load-found:Permanent", "load-found:Permanent"],
            "no volatilestate load for preloaded volatile data"
        );
        assert!(runtime.restored_volatile.is_some());
    }

    #[test]
    fn successful_restore_distinct_shadow_allocation() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let shadow_tail = persistent::CompatTailFixture {
            shadow: pcr::PcrAllocationFixture {
                selections: vec![(0x0004, 3, vec![0x00, 0x00, 0x02])],
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes(),
            tail: remaining_sections(),
            ..persistent::CompatTailFixture::default()
        };
        let blob = envelope_with_payload(&payload_with_compat_tail(shadow_tail.bytes()));

        let runtime = main_init(context_with_volatile(
            no_storage(),
            PreloadedBlob::Data(blob),
            PreloadedBlob::Data(valid_volatile_state_fixture()),
        ))
        .expect("the volatile restore succeeds under the shadow allocation");
        let expected_shadow = persistent::OwnedPcrAllocation {
            selections: vec![persistent::OwnedPcrSelection {
                hash_alg: 0x0004,
                select: vec![0x00, 0x00, 0x02],
            }],
        };
        assert!(
            !runtime.shadow_pcr_pending,
            "the pending shadow was consumed"
        );
        assert_eq!(runtime.effective_pcr_allocated(), Some(&expected_shadow));
        assert_ne!(
            runtime.state().persistent.pcr_allocated,
            expected_shadow,
            "the NV-backed allocation keeps the decoded value"
        );
    }

    #[test]
    fn nv_shadow_restore_boundary_exactness() {
        let runtime = initialize_from_permanent_blob(
            &valid_permanent_state_fixture(),
            PermanentCommit::Restore,
        )
        .expect("the permanent fixture restores");
        let mut runtime = runtime;
        assert!(runtime.shadow_pcr_pending);
        assert!(runtime.live_pcr_allocated.is_none());
        let shadow = runtime.shadow_pcr_allocated.clone();

        runtime::nv_shadow_restore(&mut runtime);
        assert!(!runtime.shadow_pcr_pending);
        assert_eq!(runtime.live_pcr_allocated.as_ref(), Some(&shadow));

        runtime.shadow_pcr_allocated.selections.clear();
        runtime::nv_shadow_restore(&mut runtime);
        assert_eq!(runtime.live_pcr_allocated.as_ref(), Some(&shadow));
    }

    #[test]
    fn restored_failure_mode_retained_runtime() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let blob = volatile::VolatileFixture {
            in_failure_mode: 1,
            fail_function: 0x6365_7845,
            fail_line: 318,
            fail_code: 3,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
        .bytes();
        let outcome = main_init(context_with_volatile(
            recording_store(TestStorage::new()).arc(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(blob),
        ));
        assert_eq!(outcome.as_ref().unwrap_err(), &TPM_RC_FAILURE);
        let (runtime, volatile_loaded) = failure_mode_runtime(outcome);
        assert!(volatile_loaded);
        assert_eq!(
            runtime.failure_diagnostics,
            failure_mode::FailureLocation::NvCommit.diagnostics(),
            "the restored diagnostics, not a fresh runtime's"
        );
        let restored = runtime
            .restored_volatile
            .as_ref()
            .expect("the whole volatile state was restored");
        assert_eq!(restored.time, 987_654);
        assert!(runtime.startup_received, "g_initialized from the blob");
        assert!(!runtime.shadow_pcr_pending, "NVShadowRestore ran");
        assert!(
            STORED_BLOBS.lock().unwrap().is_empty(),
            "no preloaded-state commit for a TPM in failure mode"
        );
    }

    #[test]
    fn corrupt_volatile_blob_failure_mode_no_store() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let valid = valid_volatile_state_fixture();

        let bad_magic = volatile::VolatileFixture {
            trailing_magic: 0,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
        .bytes();
        let mut bad_digest = valid.clone();
        let last = bad_digest.len() - 1;
        bad_digest[last] ^= 0x01;
        let truncated = valid[..valid.len() / 2].to_vec();

        for blob in [bad_magic, bad_digest, truncated] {
            EVENTS.lock().unwrap().clear();
            STORED_BLOBS.lock().unwrap().clear();
            let (runtime, volatile_loaded) =
                failure_mode_runtime(main_init(context_with_volatile(
                    recording_store(TestStorage::new()).arc(),
                    PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
                    PreloadedBlob::Data(blob),
                )));
            assert!(volatile_loaded);
            assert!(
                runtime.shadow_pcr_pending,
                "a failed VolatileState_Load skips NVShadowRestore"
            );
            assert!(STORED_BLOBS.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn profile_disabled_algorithm_volatile_decode_acceptance() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let algorithms = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,\
                          aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,\
                          rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,\
                          kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,\
                          ecc-bn,ecc-sm2-p256,symcipher,cmac,ctr,ofb,cbc,cfb,ecb"
            .replace([' ', '\n'], "");
        let profile =
            format!(r#"{{"Name":"custom","StateFormatLevel":7,"Algorithms":"{algorithms}"}}"#);
        let permanent = envelope_v4_with_profile(profile.as_bytes(), &valid_payload());

        let mut slots = vec![
            session::SessionSlotFixture {
                occupied: 1,
                session: session::SessionFixture {
                    symmetric: vec![0x00, 0x26, 0x00, 0x80, 0x00, 0x43],
                    ..session::SessionFixture::default()
                }
                .bytes(),
                ..session::SessionSlotFixture::default()
            }
            .bytes(),
        ];
        slots.extend(
            (1..volatile::MAX_LOADED_SESSIONS)
                .map(|_| session::SessionSlotFixture::default().bytes()),
        );
        let volatile_blob = volatile::VolatileFixture {
            session_slots: slots,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
        .bytes();

        let runtime = main_init(context_with_volatile(
            no_storage(),
            PreloadedBlob::Data(permanent),
            PreloadedBlob::Data(volatile_blob),
        ))
        .expect("the profile-disabled Camellia session still decodes");
        assert!(
            !runtime.active_profile_json.contains("camellia"),
            "the active profile survives unchanged: {}",
            runtime.active_profile_json
        );
        let session = runtime.live.sessions[0].session.as_ref().unwrap();
        assert_eq!(session.symmetric.algorithm, 0x0026);
    }

    #[test]
    fn seed_tie_foreign_volatile_blob_failure_mode() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let blob = volatile::VolatileFixture {
            fail_function: 0x0102_0304,
            ..volatile::VolatileFixture::default()
        }
        .bytes();
        let (runtime, _) = failure_mode_runtime(main_init(context_with_volatile(
            no_storage(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(blob),
        )));
        assert_eq!(
            runtime.failure_diagnostics.function, 0x0102_0304,
            "the seeds follow the diagnostics, which stay in effect"
        );
        assert!(runtime.tpm_established, "and so does tpmEstablished");
        assert_eq!(
            (runtime.timer.real_time_previous, runtime.timer.tpm_time),
            (111_222, 111_000),
            "the timer block precedes the seeds"
        );
        let carried = runtime
            .restored_volatile
            .as_ref()
            .expect("the fields before the seeds are restored");
        assert_eq!(carried.tail_v4, None, "the tail after the seeds is not");
    }

    static BACKEND_PERMALL: Mutex<Option<Vec<u8>>> = Mutex::new(None);

    fn manufacture_platform() -> Arc<dyn Platform> {
        io_platform()
    }

    fn manufacture_context(preloaded_permanent: PreloadedBlob) -> Tpm2InitContext<'static> {
        context_with_platform(
            manufacture_platform(),
            manufacture_storage(),
            preloaded_permanent,
            PreloadedBlob::Missing,
            None,
        )
    }

    fn manufacture_storage() -> Arc<dyn Storage> {
        recording_init(TestStorage::new())
            .on_load(|kind| {
                push_event(format!("load:{kind:?}"));
                if kind != StateBlobKind::Permanent {
                    return Ok(StorageLoad::Missing);
                }
                match BACKEND_PERMALL.lock().unwrap().clone() {
                    Some(blob) => Ok(StorageLoad::Data(blob)),
                    None => Ok(StorageLoad::Missing),
                }
            })
            .on_store(|kind, data| {
                push_event(format!("store:{kind:?}"));
                *BACKEND_PERMALL.lock().unwrap() = Some(data.to_vec());
                STORED_BLOBS
                    .lock()
                    .unwrap()
                    .push((format!("{kind:?}"), data.to_vec()));
                Ok(())
            })
            .arc()
    }

    fn reset_manufacture_backend() {
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *BACKEND_PERMALL.lock().unwrap() = None;
    }

    const FIRST_BOOT_EVENTS: [&str; 7] = [
        "io",
        "nvram",
        "load:Permanent",
        "load:Permanent",
        "store:Permanent",
        "load:Permanent",
        "load:Volatile",
    ];

    fn oracle_record() -> crypto::DrbgVectorRecord {
        crypto::vector_record(false)
    }

    fn compressed_command_bitmap(command_codes: &[u32]) -> Vec<u8> {
        let table = &nv::COMPRESSED_COMMAND_BITS;
        let mut bytes = vec![0u8; table.len().div_ceil(8)];
        for &code in command_codes {
            let raw_bit = u16::try_from(code - 0x11f).unwrap();
            let index = table
                .iter()
                .position(|&bit| bit == raw_bit)
                .expect("command present in the v0.9 table");
            bytes[index / 8] |= 1 << (index % 8);
        }
        bytes
    }

    fn le_u16(bytes: &[u8]) -> u16 {
        u16::from_le_bytes(bytes[..2].try_into().unwrap())
    }

    fn le_u32(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    fn le_u64(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    #[test]
    fn first_boot_permall_manufacture_and_store_order() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(manufacture_context(PreloadedBlob::Missing))
            .expect("first boot manufactures");
        assert_eq!(
            events(),
            FIRST_BOOT_EVENTS,
            "the exact upstream callback order -- probe, NV enable \
             load, Manufacture store, `_TPM_Init` permanent reload, \
             volatile load -- with TPM number 0 and the exact upstream \
             state names"
        );
        assert!(runtime.manufactured);
        assert!(runtime.was_manufactured, "this init WAS a manufacture");
        assert!(!runtime.startup_received, "TPM2_Startup is still pending");
        assert!(!runtime.failure_mode && !runtime.reported_failure);
        assert!(runtime.power_on && runtime.nv_available);
        assert_eq!(runtime.nv_memory.len(), runtime::NV_MEMORY_SIZE);
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(
            runtime.live.null_seed_compat_level, 0,
            "gr.nullSeedCompatLevel keeps the power-on default until Startup"
        );
        let stored = STORED_BLOBS.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "Permanent");
        assert_eq!(
            stored[0].1,
            persistent::persistent_all_store(runtime.state()).unwrap()
        );
    }

    #[test]
    fn manufactured_state_upstream_defaults() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(manufacture_context(PreloadedBlob::Missing))
            .expect("first boot manufactures");
        let state = runtime.state();
        let persistent = &state.persistent;
        let record = oracle_record();

        assert!(!persistent.disable_clear);
        for alg in [
            persistent.owner_alg,
            persistent.endorsement_alg,
            persistent.lockout_alg,
        ] {
            assert_eq!(alg, 0x0010, "TPM_ALG_NULL hierarchy algorithms");
        }
        for empty in [
            persistent.owner_auth.expose(),
            persistent.endorsement_auth.expose(),
            persistent.lockout_auth.expose(),
        ] {
            assert!(empty.is_empty(), "empty initial auth values");
        }
        assert!(persistent.owner_policy.is_empty());
        for (secret, expected) in [
            (persistent.ep_seed.expose(), &record.ep_seed),
            (persistent.sp_seed.expose(), &record.sp_seed),
            (persistent.pp_seed.expose(), &record.pp_seed),
            (persistent.ph_proof.expose(), &record.ph_proof),
            (persistent.sh_proof.expose(), &record.sh_proof),
            (persistent.eh_proof.expose(), &record.eh_proof),
        ] {
            assert_eq!(secret, expected);
        }
        for level in [
            persistent.ep_seed_compat_level,
            persistent.sp_seed_compat_level,
            persistent.pp_seed_compat_level,
        ] {
            assert_eq!(level, 1, "SEED_COMPAT_LEVEL_LAST");
        }

        assert_eq!(persistent.failed_tries, 0);
        assert_eq!(persistent.max_tries, 3);
        assert_eq!(persistent.recovery_time, 1000);
        assert_eq!(persistent.lockout_recovery, 1000);
        assert!(persistent.lockout_auth_enabled);

        let banks: Vec<u16> = persistent
            .pcr_allocated
            .selections
            .iter()
            .map(|selection| selection.hash_alg)
            .collect();
        assert_eq!(banks, [0x0004, 0x000b, 0x000c, 0x000d]);
        for selection in &persistent.pcr_allocated.selections {
            assert_eq!(selection.select, [0xff, 0xff, 0xff]);
        }
        assert_eq!(persistent.pcr_policies[0].hash_alg, 0x0010);
        assert!(persistent.pcr_policies[0].policy.is_empty());
        assert_eq!(
            persistent.shadow_pcr_allocated.as_ref(),
            Some(&persistent.pcr_allocated)
        );

        assert_eq!(
            persistent.pp_list.bytes,
            compressed_command_bitmap(&[0x0000_012d])
        );
        assert!(persistent.pp_list.compressed);
        assert_eq!(
            persistent.audit_commands.bytes,
            compressed_command_bitmap(&[0x0000_0140])
        );
        assert!(persistent.audit_commands.compressed);
        assert_eq!(persistent.audit_hash_alg, 0x000d, "SHA512");
        assert_eq!(persistent.audit_counter, 0);

        assert_eq!(persistent.orderly_state, 0x0000, "TPM_SU_CLEAR");
        assert_eq!(persistent.firmware_v1, 0x2024_0125);
        assert_eq!(persistent.firmware_v2, 0x0012_0000);
        assert_eq!(persistent.total_reset_count, 0);
        assert_eq!(persistent.reset_count, 0);
        assert_eq!(persistent.algorithm_set, 0);
        assert_eq!(persistent.time_epoch, 0);

        assert_eq!(state.orderly.clock, 0);
        assert_eq!(state.orderly.clock_safe, 1, "clockSafe == YES");
        assert_eq!(state.orderly.drbg_state.seed.expose(), record.final_seed);
        assert_eq!(
            state.orderly.drbg_state.reseed_counter,
            record.final_reseed_counter
        );
        assert_eq!(state.orderly.drbg_state.reseed_counter, 8);
        assert_eq!(state.orderly.drbg_state.drbg_magic, 0x4742_5244);
        assert_eq!(state.orderly.drbg_state.last_value, [0; 4]);
        assert_eq!(state.orderly.self_heal_timer, 0);

        assert!(state.state_reset.is_none() && state.state_clear.is_none());
        assert!(!state.read_su_state);

        assert!(state.index_orderly_ram.views().is_empty());
        assert_eq!(state.index_orderly_ram.used_bytes(), 0);
        assert!(state.user_nvram.entries.is_empty());
        assert_eq!(state.user_nvram.max_count, 0);
        assert_eq!(state.user_nvram.required_capacity, 12);

        assert!(state.profile.was_null_profile);
        assert_eq!(state.profile.state_format_level, 1);
        assert!(
            runtime
                .active_profile_json
                .contains(r#""Name":"null","StateFormatLevel":1"#),
            "{}",
            runtime.active_profile_json
        );
    }

    #[test]
    fn manufactured_nv_image_upstream_reserved_fields() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let record = oracle_record();
        let runtime = main_init(manufacture_context(PreloadedBlob::Missing))
            .expect("first boot manufactures");
        let nv = &runtime.nv_memory;
        assert_eq!(nv.len(), nv::NV_MEMORY_SIZE);

        assert_eq!(le_u32(&nv[nv::PD_MAX_TRIES..]), 3);
        assert_eq!(le_u32(&nv[nv::PD_RECOVERY_TIME..]), 1000);
        assert_eq!(le_u32(&nv[nv::PD_LOCKOUT_RECOVERY..]), 1000);
        assert_eq!(le_u32(&nv[nv::PD_LOCKOUT_AUTH_ENABLED..]), 1);
        assert_eq!(le_u16(&nv[nv::PD_ORDERLY_STATE..]), 0x0000);
        assert_eq!(le_u16(&nv[nv::PD_AUDIT_HASH_ALG..]), 0x000d);
        assert_eq!(le_u32(&nv[nv::PD_FIRMWARE_V1..]), 0x2024_0125);
        assert_eq!(le_u32(&nv[nv::PD_FIRMWARE_V2..]), 0x0012_0000);
        assert_eq!(le_u64(&nv[nv::PD_TOTAL_RESET_COUNT..]), 0);
        assert_eq!(le_u32(&nv[nv::PD_RESET_COUNT..]), 0);
        assert_eq!(nv[nv::PD_PP_LIST + 1], 0x40, "PP_Commands bit");
        assert_eq!(nv[nv::PD_AUDIT_COMMANDS + 4], 0x02, "audit bit");
        assert_eq!(le_u32(&nv[nv::PD_PCR_ALLOCATED..]), 4, "bank count");
        assert_eq!(le_u16(&nv[nv::PD_EP_SEED..]), 64, "EPSeed size");
        assert_eq!(
            &nv[nv::PD_EP_SEED + 2..nv::PD_EP_SEED + 2 + 64],
            &record.ep_seed
        );
        assert_eq!(nv[nv::PD_EP_SEED_COMPAT_LEVEL], 1);

        assert!(
            nv[nv::NV_STATE_RESET_DATA..nv::NV_ORDERLY_DATA]
                .iter()
                .all(|&byte| byte == 0)
        );

        let od = nv::NV_ORDERLY_DATA;
        assert_eq!(le_u64(&nv[od + nv::OD_CLOCK..]), 0);
        assert_eq!(nv[od + nv::OD_CLOCK_SAFE], 1);
        let drbg = od + nv::OD_DRBG_STATE;
        assert_eq!(le_u64(&nv[drbg + nv::DRBG_RESEED_COUNTER..]), 8);
        assert_eq!(le_u32(&nv[drbg + nv::DRBG_MAGIC_FIELD..]), 0x4742_5244);
        assert_eq!(
            &nv[drbg + nv::DRBG_SEED_FIELD..drbg + nv::DRBG_SEED_FIELD + 48],
            &record.final_seed
        );

        assert!(nv[nv::NV_INDEX_RAM_DATA..].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn configured_profile_manufacture_activation() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(context_with_platform(
            manufacture_platform(),
            manufacture_storage(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
            Some(br#"{"Name":"default-v1"}"#),
        ))
        .expect("first boot manufactures with the configured profile");
        assert!(
            runtime
                .active_profile_json
                .contains(r#""Name":"default-v1","StateFormatLevel":7"#),
            "{}",
            runtime.active_profile_json
        );
        assert!(!runtime.state().profile.was_null_profile);
        let stored = STORED_BLOBS.lock().unwrap();
        assert_eq!(stored[0].1[..2], [0x00, 0x04]);
    }

    #[test]
    fn deterministic_entropy_manufacture_determinism() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut images = Vec::new();
        let mut blobs = Vec::new();
        for _ in 0..2 {
            reset_manufacture_backend();
            let runtime = main_init(manufacture_context(PreloadedBlob::Missing))
                .expect("first boot manufactures");
            images.push(runtime.nv_memory.clone());
            blobs.push(STORED_BLOBS.lock().unwrap()[0].1.clone());
        }
        assert_eq!(images[0], images[1], "identical NV images");
        assert_eq!(blobs[0], blobs[1], "identical stored permall blobs");
    }

    #[test]
    fn entropy_failure_no_publication_and_determinism() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for attempt in 0..2 {
            reset_manufacture_backend();
            let error = main_init(Tpm2InitContext {
                platform: Box::leak(Box::new(manufacture_platform())).as_ref(),
                storage: Box::leak(Box::new(manufacture_storage())).as_ref(),
                preloaded_permanent: PreloadedBlob::Missing,
                preloaded_volatile: PreloadedBlob::Missing,
                configured_profile: None,
                entropy: failing_entropy,
                clock: &TEST_HOST_CLOCK,
                failure_diagnostics: FailureDiagnostics::default(),
            })
            .unwrap_err();
            assert_eq!(error, TPM_FAIL, "attempt {attempt}");
            assert_eq!(
                events(),
                ["io", "nvram", "load:Permanent", "load:Permanent"],
                "attempt {attempt}: the entropy/DRBG failure surfaces \
                 before any store, reload, or volatile callback"
            );
            assert!(STORED_BLOBS.lock().unwrap().is_empty());
            assert!(BACKEND_PERMALL.lock().unwrap().is_none());
        }
    }

    #[test]
    fn stored_manufactured_blob_restore_path() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let manufactured = main_init(manufacture_context(PreloadedBlob::Missing))
            .expect("first boot manufactures");
        let blob = STORED_BLOBS.lock().unwrap()[0].1.clone();

        let restored = main_init(context(no_storage(), PreloadedBlob::Data(blob.clone())))
            .expect("the stored blob restores");
        assert!(manufactured.manufactured);
        assert!(!restored.manufactured);
        assert!(
            !restored.was_manufactured,
            "a restore never reports TPMLIB_WasManufactured"
        );
        assert_eq!(restored.nv_memory, manufactured.nv_memory);
        assert_eq!(
            restored.active_profile_json,
            manufactured.active_profile_json
        );
        assert_eq!(
            persistent::persistent_all_store(restored.state()).unwrap(),
            blob
        );
    }

    #[test]
    fn ignored_storedata_failure_retry_zeroed_nv_power_on() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            failing_store(load_retry()).arc(),
            PreloadedBlob::Missing,
        ))
        .expect("a failed manufacture commit is ignored, like upstream");
        assert_eq!(
            events(),
            [
                "load-retry:Permanent",
                "load-retry:Permanent",
                "store-error:Permanent",
                "load-retry:Permanent",
                "load-retry:Volatile",
            ]
        );
        assert!(runtime.manufactured, "g_manufactured survives the reload");
        assert!(runtime.was_manufactured, "this init WAS a manufacture");
        assert!(
            runtime.state.is_none(),
            "the zeroed NV carries no decoded state"
        );
        assert!(
            runtime.nv_memory.iter().all(|&byte| byte == 0),
            "the NV image was zeroed by the failed reload"
        );
        assert_eq!(
            runtime.live.context_slot_mask, 0xffff,
            "s_ContextSlotMask keeps the manufacture-time value"
        );
        assert!(
            runtime
                .active_profile_json
                .contains(r#""Name":"null","StateFormatLevel":1"#),
            "g_RuntimeProfile keeps the activated profile: {}",
            runtime.active_profile_json
        );
    }

    #[test]
    fn stale_volatile_state_after_manufacture_failure_mode() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let outcome = main_init(context_with_platform(
            manufacture_platform(),
            manufacture_storage(),
            PreloadedBlob::Missing,
            PreloadedBlob::Data(volatile::VolatileFixture::default().bytes()),
            None,
        ));
        let (runtime, volatile_loaded) = failure_mode_runtime(outcome);
        assert!(volatile_loaded);
        assert!(
            runtime.was_manufactured,
            "g_wasManufactured is set before the power-on that fails"
        );
        assert!(
            runtime.state.is_some(),
            "the manufactured state stays loaded"
        );
        assert_eq!(
            events(),
            &FIRST_BOOT_EVENTS[..6],
            "the manufacture NvCommit and the permanent reload precede \
             the volatile phase, exactly like upstream; the preloaded \
             volatile blob needs no backend load"
        );
    }

    #[test]
    fn first_boot_then_later_volatile_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();

        let first = main_init(context_with_platform(
            manufacture_platform(),
            manufacture_storage(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
            None,
        ))
        .expect("first boot manufactures");
        assert!(first.was_manufactured);
        assert!(first.restored_volatile.is_none());

        let persistent = &first.state().persistent;
        let volatile_blob = volatile::VolatileFixture {
            ep_seed: persistent.ep_seed.expose().to_vec(),
            sp_seed: persistent.sp_seed.expose().to_vec(),
            pp_seed: persistent.pp_seed.expose().to_vec(),
            ..volatile::VolatileFixture::default()
        }
        .bytes();
        drop(first);

        let runtime = main_init(context_with_platform(
            manufacture_platform(),
            manufacture_storage(),
            PreloadedBlob::Missing,
            PreloadedBlob::Data(volatile_blob),
            None,
        ))
        .expect("the later boot restores permanent and volatile state");
        assert!(!runtime.was_manufactured, "no re-manufacture");
        assert!(
            runtime.restored_volatile.is_some(),
            "the volatile state merged"
        );
        assert!(
            !runtime.shadow_pcr_pending,
            "NVShadowRestore consumed the pending shadow"
        );
        assert!(runtime.startup_received, "g_initialized from the blob");
    }

    static PERMALL_CALLS: Mutex<u32> = Mutex::new(0);

    fn scripted_permall_call() -> u32 {
        let mut calls = PERMALL_CALLS.lock().unwrap();
        *calls += 1;
        *calls
    }

    fn load_after_store(outcome: fn() -> Result<StorageLoad, TpmResult>) -> TestStorage {
        TestStorage::new().on_load(move |kind| {
            push_event(format!("load:{kind:?}"));
            if kind != StateBlobKind::Permanent || scripted_permall_call() <= 2 {
                return Ok(StorageLoad::Missing);
            }
            outcome()
        })
    }

    fn load_swapped_after_store() -> TestStorage {
        load_after_store(|| Ok(StorageLoad::Data(VALID_ENVELOPE.to_vec())))
    }

    fn load_malformed_after_store() -> TestStorage {
        load_after_store(|| Ok(StorageLoad::Data(vec![0x00, 0x03])))
    }

    fn load_error_after_store() -> TestStorage {
        load_after_store(|| Err(77))
    }

    #[test]
    fn first_boot_runtime_backend_blob_parity() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *PERMALL_CALLS.lock().unwrap() = 0;
        let runtime = main_init(context(
            recording_store(load_swapped_after_store()).arc(),
            PreloadedBlob::Missing,
        ))
        .expect("the swapped reload blob restores");
        assert_eq!(
            events(),
            [
                "load:Permanent",
                "load:Permanent",
                "store:Permanent",
                "load:Permanent",
                "load:Volatile",
            ]
        );
        assert!(runtime.manufactured);
        assert!(runtime.was_manufactured, "this init WAS a manufacture");
        assert_eq!(
            runtime.state().orderly.drbg_state.seed.expose(),
            &[0x5a; 48][..]
        );
        assert_ne!(
            persistent::persistent_all_store(runtime.state()).unwrap(),
            STORED_BLOBS.lock().unwrap()[0].1,
            "the runtime no longer matches the stored bytes"
        );
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, 0);
    }

    #[test]
    fn malformed_reload_blob_after_manufacture_no_publication() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *PERMALL_CALLS.lock().unwrap() = 0;
        let error = main_init(context(
            recording_store(load_malformed_after_store()).arc(),
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert_eq!(
            events(),
            [
                "load:Permanent",
                "load:Permanent",
                "store:Permanent",
                "load:Permanent",
            ],
            "initialization stops at the failed reload"
        );
    }

    #[test]
    fn reload_callback_error_after_manufacture_rc_failure() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *PERMALL_CALLS.lock().unwrap() = 0;
        let error = main_init(context(
            recording_store(load_error_after_store()).arc(),
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert_eq!(
            events(),
            [
                "load:Permanent",
                "load:Permanent",
                "store:Permanent",
                "load:Permanent",
            ],
            "no volatile phase after the failed reload"
        );
    }

    #[test]
    fn preloaded_empty_storedata_callback_no_store() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(manufacture_context(PreloadedBlob::Empty))
            .expect("preloaded-empty powers on");
        assert!(!runtime.manufactured && !runtime.was_manufactured);
        assert_eq!(
            events(),
            ["io", "nvram", "load:Permanent", "load:Volatile"],
            "no NVEnable permall ask, no store: the empty preloaded state \
             wins before the backend is consulted again"
        );
        assert!(STORED_BLOBS.lock().unwrap().is_empty());
    }

    #[test]
    fn manufactured_runtime_active_profile_self_test_derivation() {
        use self_test::PrimitiveTestSet;

        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(manufacture_context(PreloadedBlob::Missing))
            .expect("first boot manufactures");
        assert_eq!(
            runtime.self_test.implemented,
            PrimitiveTestSet::for_algorithms(&runtime.state().profile.algorithms)
        );
        assert_eq!(runtime.self_test.pending, runtime.self_test.implemented);
        assert!(runtime.self_test.failure.is_none());
    }

    #[test]
    fn manufactured_runtime_debug_output_no_secret_bytes() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let record = oracle_record();
        let runtime = main_init(manufacture_context(PreloadedBlob::Missing))
            .expect("first boot manufactures");
        let formatted = format!("{runtime:?} {:?}", runtime.state());
        for (label, secret) in [
            ("EPSeed", &record.ep_seed[..4]),
            ("ehProof", &record.eh_proof[..4]),
            ("DRBG seed", &record.final_seed[..4]),
        ] {
            let needle = secret
                .iter()
                .map(|byte| byte.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            assert!(
                !formatted.contains(needle.as_str()),
                "Debug output must not contain the {label} bytes {needle}"
            );
        }
    }

    #[test]
    fn permanent_blob_state_format_level_user_object_gating() {
        use crate::library::constants::{TPM_RC_CURVE, TPM_RC_VALUE};

        for (what, public, required_level, rejection) in [
            (
                "aes-128",
                public::fixtures::symcipher_public(128),
                1,
                TPM_RC_VALUE,
            ),
            (
                "aes-192",
                public::fixtures::symcipher_public(192),
                4,
                TPM_RC_VALUE,
            ),
            (
                "rsa-2048",
                public::fixtures::rsa_public(256),
                1,
                TPM_RC_VALUE,
            ),
            ("ecc-p256", public::fixtures::ecc_public(), 1, TPM_RC_CURVE),
        ] {
            let object = object::fixtures::any_public_only_object(&public);
            for level in [1u32, 4] {
                let blob = permanent_state_fixture_with_user_object(&object, level);
                let result = permanent_validation_context(&blob);
                if level >= required_level {
                    assert!(result.is_ok(), "{what} in a level {level} blob");
                } else {
                    assert_eq!(
                        result.unwrap_err(),
                        rejection,
                        "{what} in a level {level} blob"
                    );
                }
            }
        }
    }

    #[test]
    fn validation_context_no_hierarchy_seed_formatting() {
        const EP_SEED: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        const SP_SEED: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
        const PP_SEED: [u8; 4] = [0xd0, 0xd1, 0xd2, 0xd3];

        let context = VolatileValidationContext {
            ep_seed: persistent::OwnedSecret::copy_of(&EP_SEED),
            sp_seed: persistent::OwnedSecret::copy_of(&SP_SEED),
            pp_seed: persistent::OwnedSecret::copy_of(&PP_SEED),
            ..VolatileValidationContext::without_permanent_state()
        };
        let rendered = format!("{context:?} {:?}", context.clone());

        for seed in [EP_SEED, SP_SEED, PP_SEED] {
            let decimals: Vec<String> = seed.iter().map(|byte| format!("{byte}")).collect();
            let shapes = [
                seed.iter().map(|byte| format!("{byte:02x}")).collect(),
                seed.iter().map(|byte| format!("{byte:02X}")).collect(),
                decimals.join(", "),
                decimals.join(","),
            ];
            for shape in shapes.iter().chain(&decimals) {
                assert!(
                    !rendered.contains(shape),
                    "seed {seed:02x?} rendered as {shape} in {rendered}"
                );
            }
        }
        assert!(rendered.contains("OwnedSecret { len: 4 }"));
        assert_eq!(
            context.ep_seed.as_bytes(),
            EP_SEED,
            "the seed is still owned"
        );
    }

    #[test]
    #[ignore = "manual helper for the swtpm restored-state integration check"]
    fn dump_permall_fixture() {
        if let Ok(path) = std::env::var("PERMALL_DUMP_PATH") {
            std::fs::write(path, valid_permanent_state_fixture()).unwrap();
        }
    }

    #[test]
    #[ignore = "manual helper for the ValidateState C oracle"]
    fn dump_volatilestate_fixture() {
        let Ok(prefix) = std::env::var("VOLATILESTATE_DUMP_PREFIX") else {
            return;
        };
        for (suffix, blob) in [
            ("valid.bin", valid_volatile_state_fixture()),
            ("bad_tag.bin", bad_tag_volatile_state_fixture()),
            (
                "seed_mismatch.bin",
                seed_mismatched_volatile_state_fixture(),
            ),
            ("rsa_object.bin", rsa_object_volatile_state_fixture()),
            ("ecc_object.bin", ecc_object_volatile_state_fixture()),
            (
                "aes128_object.bin",
                symmetric_object_volatile_state_fixture(128),
            ),
            (
                "aes192_object.bin",
                symmetric_object_volatile_state_fixture(192),
            ),
        ] {
            std::fs::write(format!("{prefix}{suffix}"), blob).unwrap();
        }
    }
}
