mod algorithm;
mod audit;
mod buffer_size;
mod capability;
mod clock;
mod command;
mod command_bitmap;
mod compile_constants;
mod crypto;
mod dictionary_attack;
mod failure_mode;
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
#[cfg(test)]
mod oracles;
mod orderly;
mod pcr;
mod persistent;
mod pp_list;
mod process;
mod profile;
mod public;
mod random;
mod runtime;
mod self_test;
mod session;
mod signature;
mod state;
mod template;
mod ticket;
mod tis;
mod volatile;

use core::ffi::c_int;

use crate::ffi_types::{LibtpmsCallbacks, TpmResult, TpmlibInfoFlags, TpmlibTpmProperty};

use super::constants::{
    TPM_FAIL, TPM_RC_FAILURE, TPM_RETRY, TPM_SUCCESS, TPMPROP_TPM_KEY_HANDLES,
    TPMPROP_TPM_RSA_KEY_LENGTH_MAX,
};
use super::preloaded_state::PreloadedBlob;
use super::state_blob::{StateBlobKind, StateValidationMask};
use marshal::{BlobReader, BlockSkipError, skip_optional_block};
pub(super) use nv::HostNvram;
use nv::{NvramLoad, NvramWrite, PermanentStateProbe};
use pcr::PcrSelection;
use persistent::{PersistentAllEnvelope, PersistentAllError, StateSection};
use public::StateFormatLimit;

pub(super) use buffer_size::{
    DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE, MIN_BUFFER_SIZE, clamp_buffer_size,
};
pub(super) use clock::{HostClock, OsClock};
pub(super) use crypto::{EntropySource, os_entropy};
pub(super) use process::process;
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

/// Makes the next self-test run park on the armed [`SelfTestGate`].
#[cfg(test)]
pub(super) fn park_self_test_on_gate(runtime: &mut Tpm2Runtime) {
    runtime.self_test.park_on_gate();
}

/// The algorithms whose self-test is still pending, as `TPM2_IncrementalSelfTest`
/// would report them.
#[cfg(test)]
pub(super) fn pending_self_test_algorithms(runtime: &Tpm2Runtime) -> Vec<u16> {
    runtime.self_test.pending_algorithms()
}

pub fn get_info(flags: TpmlibInfoFlags, runtime: Option<&Tpm2Runtime>) -> String {
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

pub const MAX_RSA_KEY_BITS: c_int = 3072;

pub const MAX_HANDLE_NUM: c_int = 3;

pub fn get_tpm_property(prop: TpmlibTpmProperty) -> Option<c_int> {
    match prop {
        TPMPROP_TPM_RSA_KEY_LENGTH_MAX => Some(MAX_RSA_KEY_BITS),
        TPMPROP_TPM_KEY_HANDLES => Some(MAX_HANDLE_NUM),
        _ => None,
    }
}

pub(super) struct Tpm2InitContext<'a> {
    pub(super) callbacks: LibtpmsCallbacks,
    pub(super) preloaded_permanent: PreloadedBlob,
    pub(super) preloaded_volatile: PreloadedBlob,
    pub(super) configured_profile: Option<Vec<u8>>,
    pub(super) entropy: EntropySource,
    pub(super) clock: &'a dyn HostClock,
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
    probe: PermanentStateProbe,
) -> PermanentStateSource {
    match preloaded {
        PreloadedBlob::Empty => PermanentStateSource::PreloadedEmpty,
        PreloadedBlob::Data(blob) => PermanentStateSource::PreloadedData(blob),
        PreloadedBlob::Missing if probe.exists => PermanentStateSource::Backend,
        PreloadedBlob::Missing => PermanentStateSource::Manufacture,
    }
}

enum VolatileResolution {
    NotPresent,
    Nonempty(Vec<u8>),
}

fn resolve_volatile_state(
    host_nvram: &HostNvram,
    preloaded_volatile: PreloadedBlob,
) -> VolatileResolution {
    match preloaded_volatile {
        PreloadedBlob::Empty => VolatileResolution::NotPresent,
        PreloadedBlob::Data(blob) => VolatileResolution::Nonempty(blob),
        PreloadedBlob::Missing => match host_nvram.load(StateBlobKind::Volatile) {
            Ok(NvramLoad::Data(blob)) => VolatileResolution::Nonempty(blob),
            Ok(NvramLoad::NotRegistered | NvramLoad::Missing | NvramLoad::SuccessWithoutData)
            | Err(_) => VolatileResolution::NotPresent,
        },
    }
}

fn volatile_phase(
    host_nvram: &HostNvram,
    preloaded_volatile: PreloadedBlob,
    clock: &dyn HostClock,
    runtime: &mut Tpm2Runtime,
) -> Result<(), TpmResult> {
    let blob = match resolve_volatile_state(host_nvram, preloaded_volatile) {
        VolatileResolution::NotPresent => return Ok(()),
        VolatileResolution::Nonempty(blob) => blob,
    };
    attach_volatile_blob(runtime, &blob, clock, VolatileDecodeBoundary::Restore)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VolatileDecodeBoundary {
    Restore,
    Validate,
}

impl VolatileDecodeBoundary {
    fn map_parse(self, error: PersistentAllError) -> TpmResult {
        self.map_result(error.tpm_result())
    }

    fn map_result(self, code: TpmResult) -> TpmResult {
        match self {
            Self::Restore => TPM_RC_FAILURE,
            Self::Validate => code,
        }
    }

    fn rejects_restored_failure_mode(self) -> bool {
        self == Self::Restore
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

fn decode_volatile_blob(
    context: &VolatileValidationContext,
    blob: &[u8],
    clock: &dyn HostClock,
    boundary: VolatileDecodeBoundary,
) -> Result<volatile::OwnedVolatileState, TpmResult> {
    let shadow_views: Vec<PcrSelection<'_>> = context
        .shadow_pcr_allocated
        .iter()
        .map(|selection| PcrSelection {
            hash_alg: selection.hash_alg,
            select: &selection.select,
        })
        .collect();
    let seed_tie = volatile::SeedTie {
        ep_seed: context.ep_seed.as_bytes(),
        sp_seed: context.sp_seed.as_bytes(),
        pp_seed: context.pp_seed.as_bytes(),
    };
    let decoded = volatile::parse_volatile_state_blob(
        blob,
        &shadow_views,
        seed_tie,
        clock,
        context.state_format,
    )
    .map_err(|error| boundary.map_parse(error))?;
    volatile::materialize_volatile_state(&decoded, seed_tie, context.object_version)
        .map_err(|code| boundary.map_result(code))
}

#[cfg(test)]
pub(super) fn restore_permanent_blob_for_test(blob: &[u8]) -> Result<Box<Tpm2Runtime>, TpmResult> {
    initialize_from_permanent_blob(blob, PermanentCommit::Restore)
}

#[cfg(test)]
pub(super) fn attach_volatile_blob_for_test(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
) -> Result<(), TpmResult> {
    attach_volatile_blob(runtime, blob, &OsClock, VolatileDecodeBoundary::Restore)
}

fn attach_volatile_blob(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
    clock: &dyn HostClock,
    boundary: VolatileDecodeBoundary,
) -> Result<(), TpmResult> {
    let context = volatile_validation_context(runtime)?;
    let owned = decode_volatile_blob(&context, blob, clock, boundary)?;

    runtime::merge_volatile_state(runtime, owned);
    runtime::nv_shadow_restore(runtime);

    if boundary.rejects_restored_failure_mode() && runtime.failure_mode {
        return Err(TPM_RC_FAILURE);
    }
    Ok(())
}

pub(super) fn host_nv_commit(
    host_nvram: &HostNvram,
    runtime: &Tpm2Runtime,
) -> Result<(), TpmResult> {
    // TODO: Implement the NVChip fallback after command processing and host
    // persistence are complete.
    if !host_nvram.can_store() {
        return Ok(());
    }
    let Some(state) = runtime.state.as_ref() else {
        return Ok(());
    };
    let blob = persistent::persistent_all_store(state)?;
    host_nvram
        .store(StateBlobKind::Permanent, &blob)
        .map(|_| ())
}

fn nv_commit(host_nvram: &HostNvram, runtime: &Tpm2Runtime) {
    let _ = host_nv_commit(host_nvram, runtime);
}

pub(super) fn main_init(context: Tpm2InitContext<'_>) -> Result<Box<Tpm2Runtime>, TpmResult> {
    let entropy = context.entropy;
    let callbacks = context.callbacks;
    let host_nvram = HostNvram::new(callbacks);

    if let Some(callback) = callbacks.tpm_io_init {
        // SAFETY: TPMLIB_RegisterCallbacks copied a function pointer with the
        // exact C ABI signature. The host must keep its code loaded while the
        // callback is registered.
        let result = unsafe { callback() };
        if result != TPM_SUCCESS {
            return Err(result);
        }
    }

    host_nvram.init()?;

    let probe = host_nvram.probe_permanent();
    let has_load_callback = probe.has_load_callback;

    let mut runtime = match select_permanent_state_source(context.preloaded_permanent, probe) {
        PermanentStateSource::Manufacture => {
            // TODO: Implement the legacy NVChip fallback after TPMLIB_Process
            // and the command-time NVRAM mutation/commit path are complete.
            if !has_load_callback {
                return Err(TPM_FAIL);
            }
            match host_nvram.load(StateBlobKind::Permanent)? {
                NvramLoad::Missing => {
                    if !host_nvram.can_store() {
                        return Err(TPM_FAIL);
                    }
                }
                NvramLoad::NotRegistered | NvramLoad::Data(_) | NvramLoad::SuccessWithoutData => {
                    return Err(TPM_FAIL);
                }
            }
            let profile = profile::validate_user_profile(context.configured_profile.as_deref())
                .map_err(|_| TPM_FAIL)?;
            let candidate = manufacture::manufacture_state(profile, context.entropy)?;
            let manufactured = runtime::commit_manufactured_state(candidate)?;
            nv_commit(&host_nvram, &manufactured);
            let mut runtime = match host_nvram
                .load(StateBlobKind::Permanent)
                .map_err(|_| TPM_RC_FAILURE)?
            {
                NvramLoad::Data(blob) => {
                    drop(manufactured);
                    initialize_from_permanent_blob(&blob, PermanentCommit::FirstBootReload)
                        .map_err(|_| TPM_RC_FAILURE)?
                }
                NvramLoad::Missing => {
                    if !host_nvram.can_store() {
                        return Err(TPM_FAIL);
                    }
                    runtime::manufactured_zeroed_nv_runtime(&manufactured)
                }
                NvramLoad::SuccessWithoutData | NvramLoad::NotRegistered => {
                    return Err(TPM_FAIL);
                }
            };
            volatile_phase(
                &host_nvram,
                context.preloaded_volatile,
                context.clock,
                &mut runtime,
            )?;
            Ok(runtime)
        }
        PermanentStateSource::PreloadedEmpty => {
            let mut runtime = runtime::empty_state_runtime();
            volatile_phase(
                &host_nvram,
                context.preloaded_volatile,
                context.clock,
                &mut runtime,
            )?;
            nv_commit(&host_nvram, &runtime);
            Ok(runtime)
        }
        PermanentStateSource::PreloadedData(blob) => {
            let mut runtime = initialize_from_permanent_blob(&blob, PermanentCommit::Restore)?;
            volatile_phase(
                &host_nvram,
                context.preloaded_volatile,
                context.clock,
                &mut runtime,
            )?;
            nv_commit(&host_nvram, &runtime);
            Ok(runtime)
        }
        PermanentStateSource::Backend => match host_nvram.load(StateBlobKind::Permanent)? {
            NvramLoad::Data(blob) => {
                let mut runtime = initialize_from_permanent_blob(&blob, PermanentCommit::Restore)?;
                volatile_phase(
                    &host_nvram,
                    context.preloaded_volatile,
                    context.clock,
                    &mut runtime,
                )?;
                Ok(runtime)
            }
            NvramLoad::NotRegistered | NvramLoad::Missing | NvramLoad::SuccessWithoutData => {
                Err(TPM_FAIL)
            }
        },
    }?;
    runtime.entropy = entropy;
    Ok(runtime)
}

pub(super) fn persistent_all_store(runtime: &Tpm2Runtime) -> Result<Vec<u8>, TpmResult> {
    match runtime.state.as_ref() {
        Some(state) => persistent::persistent_all_store(state),
        None => Err(TPM_FAIL),
    }
}

pub(super) fn load_state_from_backend(
    callbacks: LibtpmsCallbacks,
    kind: StateBlobKind,
) -> Result<Vec<u8>, TpmResult> {
    let host_nvram = HostNvram::new(callbacks);
    if host_nvram.init()? == NvramWrite::NotRegistered {
        return Err(TPM_FAIL);
    }
    match host_nvram.load(kind)? {
        NvramLoad::Data(blob) => Ok(blob),
        NvramLoad::SuccessWithoutData => Ok(Vec::new()),
        NvramLoad::Missing => Err(TPM_RETRY),
        // TODO: Implement the NVChip file fallback for hosts that register
        // no tpm_nvram_loaddata callback.
        NvramLoad::NotRegistered => Err(TPM_FAIL),
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
    match decode_volatile_blob(
        context,
        volatile,
        &OsClock,
        VolatileDecodeBoundary::Validate,
    ) {
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
    callbacks: LibtpmsCallbacks,
    mask: StateValidationMask,
    cached_volatile: PreloadedBlob,
) -> ValidationLoad {
    let host_nvram = HostNvram::new(callbacks);
    if let Err(code) = host_nvram.init() {
        return ValidationLoad::complete(code);
    }

    let permanent = if mask.selects_permanent_blob() {
        let blob = match load_permanent_for_validation(&host_nvram) {
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
        match resolve_volatile_for_validation(&host_nvram, cached_volatile) {
            Some(blob) => ValidationStage::Volatile(blob),
            None => ValidationStage::Complete(TPM_SUCCESS),
        }
    } else {
        ValidationStage::Complete(TPM_SUCCESS)
    };

    ValidationLoad { permanent, stage }
}

fn resolve_volatile_for_validation(
    host_nvram: &HostNvram,
    cached_volatile: PreloadedBlob,
) -> Option<Vec<u8>> {
    match cached_volatile {
        PreloadedBlob::Empty => None,
        PreloadedBlob::Data(blob) => Some(blob),
        PreloadedBlob::Missing => match host_nvram.load(StateBlobKind::Volatile) {
            Ok(NvramLoad::Data(blob)) => Some(blob),
            Ok(NvramLoad::NotRegistered | NvramLoad::Missing | NvramLoad::SuccessWithoutData)
            | Err(_) => None,
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

fn load_permanent_for_validation(host_nvram: &HostNvram) -> Result<Vec<u8>, TpmResult> {
    // TODO: Implement the NVChip file fallback for hosts that register no
    // tpm_nvram_loaddata callback.
    match host_nvram.load(StateBlobKind::Permanent)? {
        NvramLoad::Data(blob) => Ok(blob),
        NvramLoad::Missing => Err(TPM_RETRY),
        NvramLoad::NotRegistered | NvramLoad::SuccessWithoutData => Err(TPM_FAIL),
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
) -> Result<Box<Tpm2Runtime>, TpmResult> {
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
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT, TPM_RETRY,
    };
    use std::sync::{LazyLock, Mutex};

    fn envelope_with_payload(payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

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

    unsafe extern "C" fn io_init() -> TpmResult {
        push_event("io".into());
        TPM_SUCCESS
    }

    unsafe extern "C" fn nvram_init() -> TpmResult {
        push_event("nvram".into());
        TPM_SUCCESS
    }

    unsafe extern "C" fn failing_io_init() -> TpmResult {
        push_event("io-fail".into());
        42
    }

    unsafe extern "C" fn failing_nvram_init() -> TpmResult {
        push_event("nvram-fail".into());
        43
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0xa5;
        }
        Ok(())
    }

    fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        Err(TPM_FAIL)
    }

    fn context(
        callbacks: LibtpmsCallbacks,
        preloaded_permanent: PreloadedBlob,
    ) -> Tpm2InitContext<'static> {
        context_with_volatile(callbacks, preloaded_permanent, PreloadedBlob::Missing)
    }

    fn context_with_volatile(
        callbacks: LibtpmsCallbacks,
        preloaded_permanent: PreloadedBlob,
        preloaded_volatile: PreloadedBlob,
    ) -> Tpm2InitContext<'static> {
        context_with_profile(callbacks, preloaded_permanent, preloaded_volatile, None)
    }

    fn context_with_profile(
        callbacks: LibtpmsCallbacks,
        preloaded_permanent: PreloadedBlob,
        preloaded_volatile: PreloadedBlob,
        configured_profile: Option<&[u8]>,
    ) -> Tpm2InitContext<'static> {
        Tpm2InitContext {
            callbacks,
            preloaded_permanent,
            preloaded_volatile,
            configured_profile: configured_profile.map(<[u8]>::to_vec),
            entropy: deterministic_entropy,
            clock: &TEST_HOST_CLOCK,
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

    fn probe(exists: bool, has_load_callback: bool) -> PermanentStateProbe {
        PermanentStateProbe {
            exists,
            has_load_callback,
        }
    }

    fn requested_name(name: *const core::ffi::c_char) -> String {
        // SAFETY: the library passes a NUL-terminated state name.
        unsafe { core::ffi::CStr::from_ptr(name) }
            .to_string_lossy()
            .into_owned()
    }

    // SAFETY of every fixture below: out-pointers are valid per the
    // callback contract; buffers are malloc'ed and ownership transfers
    // to the caller.

    unsafe fn hand_out(data: *mut *mut core::ffi::c_uchar, length: *mut u32, bytes: &[u8]) {
        // SAFETY: forwarded from the fixture's caller.
        unsafe {
            *data = crate::ffi_support::malloc_bytes(bytes);
            *length = bytes.len() as u32;
        }
    }

    unsafe extern "C" fn loaddata_retry(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        push_event(format!("load-retry:{}", requested_name(name)));
        TPM_RETRY
    }

    unsafe extern "C" fn loaddata_found(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}:{tpm_number}"));
        if name == "permall" {
            // SAFETY: forwarded.
            unsafe { hand_out(data, length, &VALID_ENVELOPE) };
            TPM_SUCCESS
        } else {
            TPM_RETRY
        }
    }

    unsafe extern "C" fn loaddata_found_with_volatile(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load-found:{name}"));
        match name.as_str() {
            // SAFETY: forwarded.
            "permall" => unsafe {
                hand_out(data, length, &VALID_ENVELOPE);
                TPM_SUCCESS
            },
            // SAFETY: forwarded.
            "volatilestate" => unsafe {
                hand_out(data, length, &[0xd0, 0x0d]);
                TPM_SUCCESS
            },
            _ => TPM_RETRY,
        }
    }

    unsafe extern "C" fn loaddata_volatile_only(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}"));
        if name == "volatilestate" {
            // SAFETY: forwarded.
            unsafe { hand_out(data, length, &[0xd0, 0x0d]) };
            TPM_SUCCESS
        } else {
            TPM_RETRY
        }
    }

    unsafe extern "C" fn loaddata_volatile_error(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}"));
        if name == "volatilestate" {
            77
        } else {
            TPM_RETRY
        }
    }

    unsafe extern "C" fn loaddata_volatile_success_null(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}"));
        if name == "volatilestate" {
            TPM_SUCCESS
        } else {
            TPM_RETRY
        }
    }

    unsafe extern "C" fn loaddata_found_truncated(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        push_event(format!("load-truncated:{}", requested_name(name)));
        if requested_name(name) == "permall" {
            // SAFETY: forwarded.
            unsafe { hand_out(data, length, &[0x00, 0x03]) };
            TPM_SUCCESS
        } else {
            TPM_RETRY
        }
    }

    unsafe extern "C" fn loaddata_error(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        if requested_name(name) == "permall" {
            77
        } else {
            TPM_RETRY
        }
    }

    unsafe extern "C" fn loaddata_success_null(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        if requested_name(name) == "permall" {
            TPM_SUCCESS
        } else {
            TPM_RETRY
        }
    }

    static VANISH_CALLS: Mutex<u32> = Mutex::new(0);

    unsafe extern "C" fn loaddata_found_then_retry(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        if requested_name(name) != "permall" {
            return TPM_RETRY;
        }
        let mut calls = VANISH_CALLS.lock().unwrap();
        *calls += 1;
        if *calls == 1 { TPM_SUCCESS } else { TPM_RETRY }
    }

    static STORED_BLOBS: Mutex<Vec<(String, Vec<u8>)>> = Mutex::new(Vec::new());

    unsafe extern "C" fn storedata_recording(
        data: *const core::ffi::c_uchar,
        length: u32,
        tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("store:{name}:{tpm_number}"));
        // SAFETY: the host may read `length` bytes per the contract.
        let bytes = unsafe { core::slice::from_raw_parts(data, length as usize) }.to_vec();
        STORED_BLOBS.lock().unwrap().push((name, bytes));
        TPM_SUCCESS
    }

    unsafe extern "C" fn storedata_error(
        _data: *const core::ffi::c_uchar,
        _length: u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        push_event(format!("store-error:{}", requested_name(name)));
        88
    }

    #[test]
    fn selects_manufacture_for_missing_preloaded_state_and_absent_backend() {
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
    fn selects_backend_for_missing_preloaded_state_and_existing_backend() {
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
    fn selects_preloaded_empty_regardless_of_backend() {
        for exists in [false, true] {
            assert_eq!(
                select_permanent_state_source(PreloadedBlob::Empty, probe(exists, true)),
                PermanentStateSource::PreloadedEmpty,
                "backend exists = {exists}"
            );
        }
    }

    #[test]
    fn selects_preloaded_data_and_preserves_blob_regardless_of_backend() {
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
    fn missing_permanent_backend_fails_after_platform_initialization() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_io_init: Some(io_init),
                tpm_nvram_init: Some(nvram_init),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "no permanent-state backend is available");
        assert_eq!(*EVENTS.lock().unwrap(), ["io", "nvram"]);
    }

    #[test]
    fn failing_io_init_prevents_nvram_init_and_backend_probe() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_io_init: Some(failing_io_init),
                tpm_nvram_init: Some(nvram_init),
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, 42);
        assert_eq!(*EVENTS.lock().unwrap(), ["io-fail"]);
    }

    #[test]
    fn failing_nvram_init_prevents_backend_probe() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_io_init: Some(io_init),
                tpm_nvram_init: Some(failing_nvram_init),
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, 43);
        assert_eq!(*EVENTS.lock().unwrap(), ["io", "nvram-fail"]);
    }

    #[test]
    fn first_boot_without_storedata_stops_at_the_nv_enable_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "no storedata: NV cannot be enabled");
        assert_eq!(events(), ["load-retry:permall", "load-retry:permall"]);
    }

    #[test]
    fn existing_backend_state_restores_a_runtime() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_found),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .expect("a valid backend blob restores");
        assert_eq!(
            events(),
            ["load:permall:0", "load:permall:0", "load:volatilestate:0"],
            "the probe, the real backend load, and the volatile load \
             each hit the callback, with TPM number 0 and the exact \
             upstream state names"
        );
        assert!(runtime.manufactured, "restored state was manufactured");
        assert!(!runtime.was_manufactured, "no manufacture ran this init");
        assert!(!runtime.startup_received, "TPM2_Startup is still pending");
        assert!(!runtime.failure_mode);
        assert!(runtime.power_on && runtime.nv_available);
        assert_eq!(runtime.nv_memory.len(), runtime::NV_MEMORY_SIZE);
    }

    #[test]
    fn backend_and_preloaded_data_share_the_restore_path() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let callbacks = LibtpmsCallbacks {
            tpm_nvram_loaddata: Some(loaddata_found),
            ..LibtpmsCallbacks::empty()
        };
        let preloaded = main_init(context(
            callbacks,
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("preloaded data restores");
        assert_eq!(
            events(),
            ["load:permall:0", "load:volatilestate:0"],
            "preloaded data skips the backend permanent load but not the \
             probe or the volatile load"
        );
        let backend =
            main_init(context(callbacks, PreloadedBlob::Missing)).expect("backend data restores");
        assert_eq!(preloaded.nv_memory, backend.nv_memory);
        assert_eq!(preloaded.active_profile_json, backend.active_profile_json);
    }

    #[test]
    fn backend_load_error_propagates_the_host_code() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_error),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, 77);
    }

    #[test]
    fn backend_success_without_data_stops_at_the_explicit_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_success_null),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "a success without a buffer has no blob");
    }

    #[test]
    fn backend_state_vanishing_between_probe_and_load_stops_at_the_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *VANISH_CALLS.lock().unwrap() = 0;
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_found_then_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_FAIL, "TPM_RETRY on the real load has no blob");
        assert_eq!(*VANISH_CALLS.lock().unwrap(), 2, "probe plus real load");
    }

    #[test]
    fn backend_probe_still_runs_with_preloaded_empty_state() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Empty,
        ))
        .expect("preloaded-empty powers on over a zeroed NV image");
        assert_eq!(
            events(),
            ["load-retry:permall", "load-retry:volatilestate"],
            "upstream probes the backend even with preloaded state, and \
             the volatile load still runs at its normal point"
        );
        assert!(!runtime.manufactured, "no Manufacture ran");
        assert!(!runtime.was_manufactured);
    }

    #[test]
    fn backend_probe_still_runs_with_preloaded_data_state() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("preloaded data restores");
        assert_eq!(
            events(),
            ["load-retry:permall", "load-retry:volatilestate"],
            "upstream probes the backend even with preloaded state, and \
             still asks for the volatile state afterwards"
        );
    }

    #[test]
    fn malformed_preloaded_header_returns_the_upstream_code() {
        let truncated = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(vec![0x00, 0x03]),
        ))
        .unwrap_err();
        assert_eq!(truncated, TPM_RC_INSUFFICIENT);

        let bad_magic = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(vec![0x00, 0x03, 0xde, 0xad, 0xbe, 0xef]),
        ))
        .unwrap_err();
        assert_eq!(bad_magic, TPM_RC_BAD_TAG);
    }

    #[test]
    fn malformed_backend_header_returns_the_upstream_code() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_found_truncated),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn valid_envelope_with_upstream_fixture_section_restores() {
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
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the upstream fixture section restores");
        assert!(runtime.manufactured);
    }

    #[test]
    fn missing_compile_constants_section_no_longer_reaches_the_boundary() {
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&[])),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn invalid_compile_constants_magic_returns_bad_tag() {
        let mut section = compile_constants::marshalled_section(3);
        section[2] = 0xde;
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn unsupported_compile_constants_version_returns_bad_version() {
        let mut section = compile_constants::marshalled_section(3);
        section[0..2].copy_from_slice(&4u16.to_be_bytes());
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_VERSION);
    }

    #[test]
    fn incompatible_compile_constant_returns_bad_parameter() {
        let mut section = compile_constants::marshalled_section(3);
        section[12..16].copy_from_slice(&0u32.to_be_bytes());
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn truncated_compile_constant_array_returns_insufficient() {
        let mut section = compile_constants::marshalled_section(3);
        section.truncate(section.len() / 2);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn invalid_persistent_data_magic_returns_bad_tag() {
        let mut payload = compile_constants::marshalled_section(3);
        let mut prefix = persistent::PrefixFixture::default().bytes();
        prefix[2] = 0xff;
        payload.extend_from_slice(&prefix);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn oversized_persistent_data_tpm2b_returns_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        for index in [0usize, 3, 6, 9] {
            let mut payload = compile_constants::marshalled_section(3);
            let fixture = persistent::PrefixFixture::with_tpm2b(index, vec![0x2a; 65]);
            payload.extend_from_slice(&fixture.bytes());
            let error = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_SIZE, "tpm2b index {index}");
        }
    }

    #[test]
    fn truncated_persistent_data_reset_counter_returns_insufficient() {
        let mut payload = compile_constants::marshalled_section(3);
        let prefix = persistent::PrefixFixture::default().bytes();
        payload.extend_from_slice(&prefix[..prefix.len() - 8]);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn absent_required_pcr_policies_block_returns_bad_parameter() {
        let payload = payload_with_pcr_policies(vec![0x00, 0x00, 0x00]);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn invalid_pcr_policy_magic_returns_bad_tag() {
        let mut block = pcr::PcrPoliciesFixture::default().bytes();
        block[6] = 0xff;
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn invalid_pcr_policy_group_count_returns_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        let block = pcr::PcrPoliciesFixture {
            array_size: 2,
            ..pcr::PcrPoliciesFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_SIZE);
    }

    #[test]
    fn raw_pcr_policy_hash_ids_restore() {
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
                LibtpmsCallbacks {
                    tpm_nvram_loaddata: Some(loaddata_retry),
                    ..LibtpmsCallbacks::empty()
                },
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
            ))
            .unwrap_or_else(|error| panic!("alg {hash_alg:#06x}: {error:#x}"));
            assert_eq!(
                events(),
                ["load-retry:permall", "load-retry:volatilestate"],
                "alg {hash_alg:#06x}: only the probe and the volatile load ran"
            );
        }
    }

    #[test]
    fn zero_count_pcr_allocation_restores() {
        let allocation = pcr::PcrAllocationFixture {
            selections: Vec::new(),
            tail: pp_list_tail(),
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .expect("a zero-count allocation restores");
    }

    #[test]
    fn oversized_pcr_allocation_count_returns_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        for count in [5u32, u32::MAX] {
            let allocation = pcr::PcrAllocationFixture {
                count: Some(count),
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes();
            let error = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                    allocation,
                ))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_SIZE, "count {count}");
        }
    }

    #[test]
    fn invalid_pcr_allocation_hash_returns_hash_error() {
        use crate::library::constants::TPM_RC_HASH;

        for hash in [0x0000u16, 0x0010, 0x0012, 0xffff] {
            let allocation = pcr::PcrAllocationFixture {
                selections: vec![(hash, 3, vec![0x00; 3])],
                ..pcr::PcrAllocationFixture::default()
            }
            .bytes();
            let error = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                    allocation,
                ))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_HASH, "hash {hash:#06x}");
        }
    }

    #[test]
    fn invalid_pcr_select_size_returns_value_error() {
        use crate::library::constants::TPM_RC_VALUE;

        let allocation = pcr::PcrAllocationFixture {
            selections: vec![(0x000b, 4, vec![0x00; 4])],
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_VALUE);
    }

    #[test]
    fn truncated_pcr_allocation_bitmap_returns_insufficient() {
        let allocation = pcr::PcrAllocationFixture {
            selections: vec![(0x000b, 3, vec![0x00; 2])],
            ..pcr::PcrAllocationFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn pcr_allocation_failure_invokes_no_further_callbacks() {
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
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_allocated(
                allocation,
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_SIZE);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the pcrAllocated failure"
        );
    }

    #[test]
    fn oversized_pp_list_returns_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        for size in [18usize, 100] {
            let pp_list = pp_list::PpListFixture {
                array: vec![0x00; size],
                ..pp_list::PpListFixture::default()
            }
            .bytes();
            let error = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_pp_list(pp_list))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_SIZE, "size {size}");
        }
    }

    #[test]
    fn truncated_pp_list_returns_insufficient() {
        let pp_list = pp_list::PpListFixture {
            size: Some(17),
            array: vec![0x00; 2],
            ..pp_list::PpListFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pp_list(pp_list))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn version_4_blob_takes_the_compressed_pp_list_path() {
        use crate::library::constants::TPM_RC_SIZE;

        let results: Vec<Result<Box<Tpm2Runtime>, TpmResult>> = [4u16, 5]
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
                    LibtpmsCallbacks::empty(),
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
    fn pp_list_failure_invokes_no_further_callbacks() {
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
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pp_list(pp_list))),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_SIZE);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the ppList failure"
        );
    }

    #[test]
    fn persistent_data_remainder_begins_exactly_at_orderly_data() {
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
    fn truncated_lockout_state_returns_insufficient() {
        let lockout_bytes = lockout::LockoutFixture::default().bytes()[..10].to_vec();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_lockout(lockout_bytes))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn oversized_audit_commands_returns_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        let audit_bytes = audit::AuditFixture {
            commands: vec![0x00; 18],
            ..audit::AuditFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_audit(audit_bytes))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_SIZE);
    }

    #[test]
    fn invalid_clocksize_returns_bad_parameter() {
        let audit_bytes = audit::AuditFixture {
            clocksize: 8,
            ..audit::AuditFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_audit(audit_bytes))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn missing_required_compat_blocks_return_bad_parameter() {
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
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                    compat.bytes(),
                ))),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn invalid_shadow_pcr_allocation_returns_hash_error() {
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
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                compat.bytes(),
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_HASH);
    }

    #[test]
    fn maximum_seed_compat_levels_survive_the_commit() {
        let compat = persistent::CompatTailFixture {
            seed_levels: [1, 1, 1],
            tail: remaining_sections(),
            ..persistent::CompatTailFixture::default()
        };
        let runtime = main_init(context(
            LibtpmsCallbacks::empty(),
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
    fn seed_compat_level_failure_invokes_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let compat = persistent::CompatTailFixture {
            seed_levels: [2, 0, 0],
            ..persistent::CompatTailFixture::default()
        };
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&payload_with_compat_tail(
                compat.bytes(),
            ))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_VERSION);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the seed-level failure"
        );
    }

    #[test]
    fn oversized_pcr_policy_digest_returns_size_error() {
        use crate::library::constants::TPM_RC_SIZE;

        let block = pcr::PcrPoliciesFixture {
            policy: vec![0x2a; 65],
            ..pcr::PcrPoliciesFixture::default()
        }
        .bytes();
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_SIZE);
    }

    #[test]
    fn truncated_pcr_policies_returns_insufficient() {
        let mut block = pcr::PcrPoliciesFixture::default().bytes();
        block.truncate(block.len() - 2);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload_with_pcr_policies(block))),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn pcr_policies_failure_invokes_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let payload = payload_with_pcr_policies(vec![0x00, 0x00, 0x00]);
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the pcrPolicies failure"
        );
    }

    #[test]
    fn persistent_data_failure_invokes_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let mut payload = compile_constants::marshalled_section(3);
        let mut prefix = persistent::PrefixFixture::default().bytes();
        prefix[2] = 0xff;
        payload.extend_from_slice(&prefix);
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the prefix failure"
        );
    }

    #[test]
    fn section_failure_invokes_no_further_callbacks() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let mut section = compile_constants::marshalled_section(3);
        section[2] = 0xde;
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&section)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the section failure"
        );
    }

    #[test]
    fn parse_failure_invokes_no_further_callbacks_and_keeps_preloaded_priority() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(vec![0x00]),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the parse failure"
        );
    }

    #[test]
    fn preloaded_empty_without_load_callback_powers_on_an_empty_image() {
        let runtime = main_init(context(LibtpmsCallbacks::empty(), PreloadedBlob::Empty))
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

    fn envelope_v4_with_profile(profile: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut blob = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
        blob.extend_from_slice(&u16::try_from(profile.len() + 1).unwrap().to_be_bytes());
        blob.extend_from_slice(profile);
        blob.push(0);
        blob.extend_from_slice(payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        blob
    }

    #[test]
    fn su_state_blobs_read_both_conditional_sections() {
        for orderly_state in [0x0001u16, 0x8001, 0x4001, 0xc001] {
            let payload =
                payload_with_orderly_state(orderly_state, remaining_sections_with_su_state());
            let runtime = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_or_else(|error| panic!("orderlyState {orderly_state:#06x}: {error:#x}"));
            assert!(
                runtime.state().state_reset.is_some() && runtime.state().state_clear.is_some(),
                "orderlyState {orderly_state:#06x}: both sections restored"
            );
        }
    }

    #[test]
    fn non_su_state_blobs_omit_the_conditional_sections() {
        for orderly_state in [0x0000u16, 0x0002, 0x8000] {
            let payload = payload_with_orderly_state(orderly_state, remaining_sections());
            let runtime = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_or_else(|error| panic!("orderlyState {orderly_state:#06x}: {error:#x}"));
            assert!(
                runtime.state().state_reset.is_none() && runtime.state().state_clear.is_none(),
                "orderlyState {orderly_state:#06x}: no startup sections"
            );
        }
    }

    #[test]
    fn su_state_blob_without_the_sections_is_rejected() {
        let payload = payload_with_orderly_state(0x0001, remaining_sections());
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn non_su_state_blob_with_the_sections_is_rejected() {
        let payload = payload_with_orderly_state(0x0000, remaining_sections_with_su_state());
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn outer_versions_below_3_always_read_the_conditional_sections() {
        let payload = payload_with_orderly_state(0x0000, remaining_sections_with_su_state());
        main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_v2_with_payload(&payload)),
        ))
        .expect("version 2 always carries the sections");

        let payload = payload_with_orderly_state(0x0000, remaining_sections());
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_v2_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn extra_bytes_before_the_footer_are_rejected() {
        let mut payload = valid_payload();
        payload.push(0xee);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_TAG);
    }

    #[test]
    fn absent_final_future_block_is_insufficient() {
        let mut payload = valid_payload();
        payload.truncate(payload.len() - 3);
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_INSUFFICIENT);
    }

    #[test]
    fn nonempty_final_future_block_is_skipped() {
        let mut payload = valid_payload();
        payload.truncate(payload.len() - 3);
        payload.extend_from_slice(&[0x01, 0x00, 0x04, 0xf1, 0xf2, 0xf3, 0xf4]);
        main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("a nonempty final future block restores");
    }

    #[test]
    fn truncation_inside_the_late_sections_is_insufficient() {
        let sections = remaining_sections();
        for len in 0..sections.len() {
            let payload = payload_with_orderly_state(0, sections[..len].to_vec());
            let error = main_init(context(
                LibtpmsCallbacks::empty(),
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
    fn truncation_inside_the_conditional_sections_is_insufficient() {
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
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_with_payload(&payload)),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_INSUFFICIENT, "truncated at {len}");
        }
    }

    #[test]
    fn late_section_failure_invokes_no_further_callbacks() {
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
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, crate::library::constants::TPM_RC_HANDLE);
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "only the probe ran; no extra callback after the USER_NVRAM failure"
        );
    }

    const NULL_PROFILE_LEVEL_1: &[u8] = br#"{"Name":"null","StateFormatLevel":1}"#;
    const DEFAULT_PROFILE_LEVEL_7: &[u8] = br#"{"Name":"default-v1","StateFormatLevel":7}"#;

    #[test]
    fn version_1_envelope_decodes_the_complete_payload() {
        let mut sections = remaining_sections_with_su_state();
        sections.truncate(sections.len() - 3);
        let payload = payload_with_orderly_state(0, sections);
        main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_v1_with_payload(&payload)),
        ))
        .expect("a version-1 envelope restores");
    }

    #[test]
    fn version_4_envelopes_with_serialized_profiles_restore() {
        for (profile, level) in [(NULL_PROFILE_LEVEL_1, 1), (DEFAULT_PROFILE_LEVEL_7, 7)] {
            let runtime = main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(envelope_v4_with_profile(profile, &valid_payload())),
            ))
            .unwrap_or_else(|error| {
                panic!("profile {:?}: {error:#x}", String::from_utf8_lossy(profile))
            });
            assert_eq!(runtime.state().profile.state_format_level, level);
        }
    }

    #[test]
    fn profile_rejections_surface_the_upstream_codes() {
        use crate::library::constants::{TPM_RC_NO_RESULT, TPM_RC_VALUE};

        for (profile, expected) in [
            (&b"garbage"[..], TPM_RC_NO_RESULT),
            (br#"{"StateFormatLevel":1}"#, TPM_RC_NO_RESULT),
            (br#"{"Name":"null"}"#, TPM_RC_NO_RESULT),
            (br#"{"Name":"nosuch","StateFormatLevel":1}"#, TPM_RC_VALUE),
            (br#"{"Name":"null","StateFormatLevel":8}"#, TPM_RC_VALUE),
        ] {
            let error = main_init(context(
                LibtpmsCallbacks::empty(),
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
    fn profile_validation_precedes_the_compile_constant_check() {
        let mut payload = valid_payload();
        payload[2] = 0xde;
        let error = main_init(context(
            LibtpmsCallbacks::empty(),
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
    fn serialized_level_1_profile_charges_the_legacy_object_size() {
        let payload = payload_with_persistent_objects(66);

        let error = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_v4_with_profile(NULL_PROFILE_LEVEL_1, &payload)),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            crate::library::constants::TPM_RC_SIZE,
            "level 1 must charge 2600 bytes per object"
        );

        main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_v4_with_profile(DEFAULT_PROFILE_LEVEL_7, &payload)),
        ))
        .expect("level 7 charges the re-marshalled size and fits");
    }

    #[test]
    fn legacy_capacity_boundary_sits_at_65_objects() {
        let payload = payload_with_persistent_objects(65);
        main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_v4_with_profile(NULL_PROFILE_LEVEL_1, &payload)),
        ))
        .expect("65 legacy objects fit exactly");
    }

    #[test]
    fn repeated_main_init_attempts_are_deterministic() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for attempt in 0..3 {
            EVENTS.lock().unwrap().clear();
            let runtime = main_init(context(
                LibtpmsCallbacks {
                    tpm_nvram_loaddata: Some(loaddata_retry),
                    ..LibtpmsCallbacks::empty()
                },
                PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            ))
            .unwrap_or_else(|error| panic!("attempt {attempt}: {error:#x}"));
            assert!(runtime.manufactured, "attempt {attempt}");
            assert_eq!(
                events(),
                ["load-retry:permall", "load-retry:volatilestate"],
                "attempt {attempt}: the probe and the volatile load ran"
            );
        }

        let payload = payload_with_orderly_state(0x0001, remaining_sections());
        let blob = envelope_with_payload(&payload);
        for attempt in 0..3 {
            EVENTS.lock().unwrap().clear();
            let error = main_init(context(
                LibtpmsCallbacks {
                    tpm_nvram_loaddata: Some(loaddata_retry),
                    ..LibtpmsCallbacks::empty()
                },
                PreloadedBlob::Data(blob.clone()),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_BAD_TAG, "attempt {attempt}");
            assert_eq!(
                events(),
                ["load-retry:permall"],
                "attempt {attempt}: only the probe ran"
            );
        }
    }

    #[test]
    fn runtime_owns_all_state_after_the_blob_is_dropped() {
        let runtime = {
            let blob = VALID_ENVELOPE.to_vec();
            main_init(context(
                LibtpmsCallbacks::empty(),
                PreloadedBlob::Data(blob),
            ))
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
    fn su_state_runtime_carries_the_live_global_values() {
        let payload = payload_with_orderly_state(0x0001, remaining_sections_with_su_state());
        let runtime = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the SU-state blob restores");
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, 0);

        let payload = payload_with_orderly_state(0, remaining_sections());
        let runtime = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .expect("the non-SU blob restores");
        assert_eq!(runtime.live.context_slot_mask, 0xffff);
        assert_eq!(runtime.live.null_seed_compat_level, 0);
    }

    #[test]
    fn distinct_shadow_allocation_stays_distinct_in_the_runtime() {
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
            LibtpmsCallbacks::empty(),
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
    fn runtime_debug_output_contains_no_secret_bytes() {
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
            LibtpmsCallbacks::empty(),
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
    fn absent_compat_tail_validates_pcr_save_against_pcr_allocated() {
        let payload =
            tailless_v2_payload_with_active_sha256(state::PcrSaveFixture::default().bytes());
        let runtime = main_init(context(
            LibtpmsCallbacks::empty(),
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
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(envelope_with_payload(&payload)),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_BAD_PARAMETER);
    }

    #[test]
    fn preloaded_permanent_missing_volatile_runs_the_upstream_callback_sequence() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_io_init: Some(io_init),
                tpm_nvram_init: Some(nvram_init),
                tpm_nvram_loaddata: Some(loaddata_retry),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("preloaded permanent state with no volatile state restores");
        assert_eq!(
            events(),
            [
                "io",
                "nvram",
                "load-retry:permall",
                "load-retry:volatilestate",
                "store:permall:0",
            ]
        );
        let stored = STORED_BLOBS.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "permall");
        assert_eq!(
            stored[0].1,
            persistent::persistent_all_store(runtime.state()).unwrap()
        );
        let envelope = persistent::PersistentAllEnvelope::parse(&stored[0].1).unwrap();
        parse_persistent_all_payload(&envelope).expect("the committed blob round-trips");
    }

    #[test]
    fn backend_permanent_performs_no_preloaded_state_commit() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        main_init(context(
            LibtpmsCallbacks {
                tpm_io_init: Some(io_init),
                tpm_nvram_init: Some(nvram_init),
                tpm_nvram_loaddata: Some(loaddata_found),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .expect("backend permanent state restores");
        assert_eq!(
            events(),
            [
                "io",
                "nvram",
                "load:permall:0",
                "load:permall:0",
                "load:volatilestate:0",
            ]
        );
        assert!(
            STORED_BLOBS.lock().unwrap().is_empty(),
            "no preloaded-state NvCommit for backend-loaded permanent state"
        );
    }

    #[test]
    fn preloaded_empty_volatile_skips_the_backend_volatile_load() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context_with_volatile(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Empty,
        ))
        .expect("preloaded-empty volatile state restores permanent-only");
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "an explicitly empty preloaded volatile entry suppresses the \
             backend volatile load"
        );
    }

    #[test]
    fn backend_retry_for_volatile_state_means_no_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("TPM_RETRY for volatilestate restores permanent-only");
        assert_eq!(events(), ["load-retry:permall", "load-retry:volatilestate"]);
        assert!(!runtime.startup_received);
    }

    #[test]
    fn undecodable_preloaded_volatile_blob_fails_with_the_failure_mode_result() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let error = main_init(context_with_volatile(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(vec![0xd0, 0x0d]),
        ))
        .unwrap_err();
        assert_eq!(
            error, TPM_RC_FAILURE,
            "an undecodable volatile blob fails the restore"
        );
        assert_eq!(
            events(),
            ["load-retry:permall"],
            "preloaded volatile data needs no backend load, and the failed \
             volatile phase suppresses the preloaded-state commit"
        );
        assert!(STORED_BLOBS.lock().unwrap().is_empty());
    }

    #[test]
    fn undecodable_backend_volatile_blob_fails_with_the_failure_mode_result() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_volatile_only),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert_eq!(events(), ["load:permall", "load:volatilestate"]);

        EVENTS.lock().unwrap().clear();
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_found_with_volatile),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert_eq!(
            events(),
            [
                "load-found:permall",
                "load-found:permall",
                "load-found:volatilestate",
            ]
        );
    }

    #[test]
    fn volatile_callback_error_is_ignored_like_upstream() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_volatile_error),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a volatile load error restores permanent-only, like upstream");
        assert_eq!(events(), ["load:permall", "load:volatilestate"]);
    }

    #[test]
    fn volatile_success_without_buffer_means_no_restore() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_volatile_success_null),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a bufferless volatile success restores permanent-only");
        assert_eq!(events(), ["load:permall", "load:volatilestate"]);
    }

    #[test]
    fn storedata_error_does_not_change_the_maininit_result() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                tpm_nvram_storedata: Some(storedata_error),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("a failed preloaded-state commit is ignored, like upstream");
        assert_eq!(
            events(),
            [
                "load-retry:permall",
                "load-retry:volatilestate",
                "store-error:permall",
            ]
        );
    }

    #[test]
    fn pcr_shadow_stays_pending_while_no_volatile_state_was_restored() {
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
                LibtpmsCallbacks::empty(),
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

    unsafe extern "C" fn loaddata_found_with_valid_volatile(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load-valid:{name}:{tpm_number}"));
        match name.as_str() {
            // SAFETY: forwarded.
            "permall" => unsafe {
                hand_out(data, length, &VALID_ENVELOPE);
                TPM_SUCCESS
            },
            // SAFETY: forwarded.
            "volatilestate" => unsafe {
                hand_out(data, length, &VALID_VOLATILE);
                TPM_SUCCESS
            },
            _ => TPM_RETRY,
        }
    }

    #[test]
    fn valid_preloaded_volatile_blob_restores_merges_and_commits() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let runtime = main_init(context_with_volatile(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(valid_volatile_state_fixture()),
        ))
        .expect("a valid volatile blob restores");
        assert_eq!(
            events(),
            ["load-retry:permall", "store:permall:0"],
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
    fn c_generated_volatile_fixture_restores_end_to_end() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let blob = include_bytes!("testdata/volatile_state_v4.bin").to_vec();
        let runtime = main_init(context_with_volatile(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(blob),
        ))
        .expect("the C-generated volatile fixture restores");
        let volatile_state = runtime
            .restored_volatile
            .as_ref()
            .expect("volatile state merged");
        assert_eq!(volatile_state.time, 0x123456);
        assert_eq!(volatile_state.fail_function, 0xa1);
        assert!(runtime.manufactured);
        assert!(runtime.startup_received);
        assert!(!runtime.shadow_pcr_pending);
    }

    #[test]
    fn v4_restore_derives_the_rebased_clock_at_init_time() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let host = recording_clock();
        let runtime = main_init(Tpm2InitContext {
            callbacks: LibtpmsCallbacks::empty(),
            preloaded_permanent: PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            preloaded_volatile: PreloadedBlob::Data(valid_volatile_state_fixture()),
            configured_profile: None,
            entropy: deterministic_entropy,
            clock: &host,
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
    fn pre_v4_restore_rebases_every_clock_value_to_realtime_now() {
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
            callbacks: LibtpmsCallbacks::empty(),
            preloaded_permanent: PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            preloaded_volatile: PreloadedBlob::Data(blob),
            configured_profile: None,
            entropy: deterministic_entropy,
            clock: &host,
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
    fn initialization_without_a_volatile_restore_keeps_the_reset_clock() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runtime = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
        ))
        .expect("the permanent fixture restores without volatile state");
        assert_eq!(runtime.clock, clock::RuntimeClock::POWER_ON_RESET);
    }

    #[test]
    fn failed_volatile_phase_publishes_no_partial_clock_state() {
        let host_nvram = HostNvram::new(LibtpmsCallbacks::empty());
        let mut candidate = runtime::empty_state_runtime();
        for attempt in 0..2 {
            let host = recording_clock();
            let result = volatile_phase(
                &host_nvram,
                PreloadedBlob::Data(vec![0xd0, 0x0d]),
                &host,
                &mut candidate,
            );
            assert_eq!(result.unwrap_err(), TPM_RC_FAILURE, "attempt {attempt}");
            assert!(
                host.calls().is_empty(),
                "attempt {attempt}: an invalid header reads no host clock"
            );
            assert_eq!(
                candidate.clock,
                clock::RuntimeClock::POWER_ON_RESET,
                "attempt {attempt}: no partial clock state"
            );
            assert!(candidate.restored_volatile.is_none(), "attempt {attempt}");
            assert!(!candidate.failure_mode, "attempt {attempt}");
        }
    }

    #[test]
    fn tail_truncated_volatile_phase_reads_monotonic_once_and_publishes_nothing() {
        let payload = volatile::VolatileFixture {
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
        .payload();
        let cut = payload.len() - 4 - 3 - 32 + 8;
        let host_nvram = HostNvram::new(LibtpmsCallbacks::empty());
        let mut candidate = runtime::empty_state_runtime();
        for attempt in 0..2 {
            let host = recording_clock();
            let result = volatile_phase(
                &host_nvram,
                PreloadedBlob::Data(payload[..cut].to_vec()),
                &host,
                &mut candidate,
            );
            assert_eq!(result.unwrap_err(), TPM_RC_FAILURE, "attempt {attempt}");
            assert_eq!(
                host.calls(),
                [clock::ClockCall::Monotonic],
                "attempt {attempt}: exactly the one tail monotonic read"
            );
            assert_eq!(
                candidate.clock,
                clock::RuntimeClock::POWER_ON_RESET,
                "attempt {attempt}: no partial clock state"
            );
            assert!(candidate.restored_volatile.is_none(), "attempt {attempt}");
            assert!(!candidate.failure_mode, "attempt {attempt}");
        }
    }

    #[test]
    fn bad_volatile_digest_publishes_no_partial_clock_state() {
        let mut blob = valid_volatile_state_fixture();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        let host_nvram = HostNvram::new(LibtpmsCallbacks::empty());
        let mut candidate = runtime::empty_state_runtime();
        for attempt in 0..2 {
            let host = recording_clock();
            let result = volatile_phase(
                &host_nvram,
                PreloadedBlob::Data(blob.clone()),
                &host,
                &mut candidate,
            );
            assert_eq!(result.unwrap_err(), TPM_RC_FAILURE, "attempt {attempt}");
            assert_eq!(
                host.calls(),
                [clock::ClockCall::Monotonic, clock::ClockCall::Realtime],
                "attempt {attempt}: the v4 unmarshal reads run before the digest check"
            );
            assert_eq!(
                candidate.clock,
                clock::RuntimeClock::POWER_ON_RESET,
                "attempt {attempt}: no partial clock state"
            );
            assert!(candidate.restored_volatile.is_none(), "attempt {attempt}");
            assert!(!candidate.failure_mode, "attempt {attempt}");
        }
    }

    #[test]
    fn repeated_initialization_with_controlled_clocks_is_identical() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let run = |host: &clock::RecordingClock| {
            main_init(Tpm2InitContext {
                callbacks: LibtpmsCallbacks::empty(),
                preloaded_permanent: PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
                preloaded_volatile: PreloadedBlob::Data(valid_volatile_state_fixture()),
                configured_profile: None,
                entropy: deterministic_entropy,
                clock: host,
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
    fn valid_backend_volatile_blob_restores() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_found_with_valid_volatile),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .expect("backend permanent and volatile state restore");
        assert_eq!(
            events(),
            [
                "load-valid:permall:0",
                "load-valid:permall:0",
                "load-valid:volatilestate:0",
            ]
        );
        assert!(runtime.restored_volatile.is_some());
        assert!(!runtime.shadow_pcr_pending);
    }

    #[test]
    fn preloaded_volatile_data_wins_over_backend_volatile() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context_with_volatile(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_found_with_volatile),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
            PreloadedBlob::Data(valid_volatile_state_fixture()),
        ))
        .expect("the preloaded volatile blob wins over the backend's junk");
        assert_eq!(
            events(),
            ["load-found:permall", "load-found:permall"],
            "no volatilestate load for preloaded volatile data"
        );
        assert!(runtime.restored_volatile.is_some());
    }

    #[test]
    fn successful_restore_applies_a_distinct_shadow_allocation() {
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
            LibtpmsCallbacks::empty(),
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
    fn nv_shadow_restore_boundary_is_exact() {
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
    fn restored_failure_mode_reaches_the_failure_boundary() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        let blob = volatile::VolatileFixture {
            in_failure_mode: 1,
            ep_seed: Vec::new(),
            sp_seed: Vec::new(),
            pp_seed: Vec::new(),
            ..volatile::VolatileFixture::default()
        }
        .bytes();
        let error = main_init(context_with_volatile(
            LibtpmsCallbacks {
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(blob),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert!(STORED_BLOBS.lock().unwrap().is_empty());
    }

    #[test]
    fn corrupt_volatile_blobs_publish_nothing_and_store_nothing() {
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
            let error = main_init(context_with_volatile(
                LibtpmsCallbacks {
                    tpm_nvram_storedata: Some(storedata_recording),
                    ..LibtpmsCallbacks::empty()
                },
                PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
                PreloadedBlob::Data(blob),
            ))
            .unwrap_err();
            assert_eq!(error, TPM_RC_FAILURE);
            assert!(STORED_BLOBS.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn profile_disabled_algorithm_is_accepted_during_volatile_decode() {
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
            LibtpmsCallbacks::empty(),
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
    fn seed_tie_rejects_a_volatile_blob_from_another_tpm() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let error = main_init(context_with_volatile(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(VALID_ENVELOPE.to_vec()),
            PreloadedBlob::Data(volatile::VolatileFixture::default().bytes()),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
    }

    static BACKEND_PERMALL: Mutex<Option<Vec<u8>>> = Mutex::new(None);

    unsafe extern "C" fn loaddata_backend(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}:{tpm_number}"));
        if name != "permall" {
            return TPM_RETRY;
        }
        let Some(blob) = BACKEND_PERMALL.lock().unwrap().clone() else {
            return TPM_RETRY;
        };
        // SAFETY: forwarded.
        unsafe { hand_out(data, length, &blob) };
        TPM_SUCCESS
    }

    unsafe extern "C" fn storedata_backend(
        data: *const core::ffi::c_uchar,
        length: u32,
        tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("store:{name}:{tpm_number}"));
        // SAFETY: the host may read `length` bytes per the contract.
        let bytes = unsafe { core::slice::from_raw_parts(data, length as usize) }.to_vec();
        *BACKEND_PERMALL.lock().unwrap() = Some(bytes.clone());
        STORED_BLOBS.lock().unwrap().push((name, bytes));
        TPM_SUCCESS
    }

    fn manufacture_callbacks() -> LibtpmsCallbacks {
        LibtpmsCallbacks {
            tpm_io_init: Some(io_init),
            tpm_nvram_init: Some(nvram_init),
            tpm_nvram_loaddata: Some(loaddata_backend),
            tpm_nvram_storedata: Some(storedata_backend),
            ..LibtpmsCallbacks::empty()
        }
    }

    fn reset_manufacture_backend() {
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *BACKEND_PERMALL.lock().unwrap() = None;
    }

    const FIRST_BOOT_EVENTS: [&str; 7] = [
        "io",
        "nvram",
        "load:permall:0",
        "load:permall:0",
        "store:permall:0",
        "load:permall:0",
        "load:volatilestate:0",
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
    fn first_boot_manufactures_and_stores_permall_in_upstream_order() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
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
        assert_eq!(stored[0].0, "permall");
        assert_eq!(
            stored[0].1,
            persistent::persistent_all_store(runtime.state()).unwrap()
        );
    }

    #[test]
    fn manufactured_state_owns_the_upstream_defaults() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
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

        assert!(state.index_orderly_ram.entries.is_empty());
        assert_eq!(state.index_orderly_ram.used_bytes, 0);
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
    fn manufactured_nv_image_carries_the_upstream_reserved_fields() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let record = oracle_record();
        let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
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
    fn configured_profile_is_activated_by_manufacture() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(context_with_profile(
            manufacture_callbacks(),
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
    fn deterministic_entropy_manufactures_deterministic_state() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut images = Vec::new();
        let mut blobs = Vec::new();
        for _ in 0..2 {
            reset_manufacture_backend();
            let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
                .expect("first boot manufactures");
            images.push(runtime.nv_memory.clone());
            blobs.push(STORED_BLOBS.lock().unwrap()[0].1.clone());
        }
        assert_eq!(images[0], images[1], "identical NV images");
        assert_eq!(blobs[0], blobs[1], "identical stored permall blobs");
    }

    #[test]
    fn entropy_failure_publishes_nothing_and_is_deterministic() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for attempt in 0..2 {
            reset_manufacture_backend();
            let error = main_init(Tpm2InitContext {
                callbacks: manufacture_callbacks(),
                preloaded_permanent: PreloadedBlob::Missing,
                preloaded_volatile: PreloadedBlob::Missing,
                configured_profile: None,
                entropy: failing_entropy,
                clock: &TEST_HOST_CLOCK,
            })
            .unwrap_err();
            assert_eq!(error, TPM_FAIL, "attempt {attempt}");
            assert_eq!(
                events(),
                ["io", "nvram", "load:permall:0", "load:permall:0"],
                "attempt {attempt}: the entropy/DRBG failure surfaces \
                 before any store, reload, or volatile callback"
            );
            assert!(STORED_BLOBS.lock().unwrap().is_empty());
            assert!(BACKEND_PERMALL.lock().unwrap().is_none());
        }
    }

    #[test]
    fn stored_manufactured_blob_restores_through_the_restore_path() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let manufactured = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
            .expect("first boot manufactures");
        let blob = STORED_BLOBS.lock().unwrap()[0].1.clone();

        let restored = main_init(context(
            LibtpmsCallbacks::empty(),
            PreloadedBlob::Data(blob.clone()),
        ))
        .expect("the stored blob restores");
        assert!(restored.manufactured);
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
    fn ignored_storedata_failure_then_retry_powers_on_over_zeroed_nv() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_retry),
                tpm_nvram_storedata: Some(storedata_error),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .expect("a failed manufacture commit is ignored, like upstream");
        assert_eq!(
            events(),
            [
                "load-retry:permall",
                "load-retry:permall",
                "store-error:permall",
                "load-retry:permall",
                "load-retry:volatilestate",
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
    fn nonempty_volatile_state_prevents_publication_after_manufacture() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let error = main_init(context_with_volatile(
            manufacture_callbacks(),
            PreloadedBlob::Missing,
            PreloadedBlob::Data(vec![0xd0, 0x0d]),
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
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

        let first = main_init(context_with_volatile(
            manufacture_callbacks(),
            PreloadedBlob::Missing,
            PreloadedBlob::Missing,
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

        let runtime = main_init(context_with_volatile(
            manufacture_callbacks(),
            PreloadedBlob::Missing,
            PreloadedBlob::Data(volatile_blob),
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

    unsafe extern "C" fn loaddata_swapped_after_store(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}"));
        if name != "permall" || scripted_permall_call() <= 2 {
            return TPM_RETRY;
        }
        // SAFETY: forwarded.
        unsafe { hand_out(data, length, &VALID_ENVELOPE) };
        TPM_SUCCESS
    }

    unsafe extern "C" fn loaddata_malformed_after_store(
        data: *mut *mut core::ffi::c_uchar,
        length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}"));
        if name != "permall" || scripted_permall_call() <= 2 {
            return TPM_RETRY;
        }
        // SAFETY: forwarded.
        unsafe { hand_out(data, length, &[0x00, 0x03]) };
        TPM_SUCCESS
    }

    unsafe extern "C" fn loaddata_error_after_store(
        _data: *mut *mut core::ffi::c_uchar,
        _length: *mut u32,
        _tpm_number: u32,
        name: *const core::ffi::c_char,
    ) -> TpmResult {
        let name = requested_name(name);
        push_event(format!("load:{name}"));
        if name != "permall" || scripted_permall_call() <= 2 {
            return TPM_RETRY;
        }
        77
    }

    #[test]
    fn first_boot_runtime_reflects_the_backend_returned_blob() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *PERMALL_CALLS.lock().unwrap() = 0;
        let runtime = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_swapped_after_store),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .expect("the swapped reload blob restores");
        assert_eq!(
            events(),
            [
                "load:permall",
                "load:permall",
                "store:permall:0",
                "load:permall",
                "load:volatilestate",
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
    fn malformed_reload_blob_after_manufacture_publishes_nothing() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *PERMALL_CALLS.lock().unwrap() = 0;
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_malformed_after_store),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert_eq!(
            events(),
            [
                "load:permall",
                "load:permall",
                "store:permall:0",
                "load:permall",
            ],
            "initialization stops at the failed reload"
        );
    }

    #[test]
    fn reload_callback_error_after_manufacture_collapses_to_rc_failure() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        EVENTS.lock().unwrap().clear();
        STORED_BLOBS.lock().unwrap().clear();
        *PERMALL_CALLS.lock().unwrap() = 0;
        let error = main_init(context(
            LibtpmsCallbacks {
                tpm_nvram_loaddata: Some(loaddata_error_after_store),
                tpm_nvram_storedata: Some(storedata_recording),
                ..LibtpmsCallbacks::empty()
            },
            PreloadedBlob::Missing,
        ))
        .unwrap_err();
        assert_eq!(error, TPM_RC_FAILURE);
        assert_eq!(
            events(),
            [
                "load:permall",
                "load:permall",
                "store:permall:0",
                "load:permall",
            ],
            "no volatile phase after the failed reload"
        );
    }

    #[test]
    fn preloaded_empty_stores_nothing_even_with_a_storedata_callback() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Empty))
            .expect("preloaded-empty powers on");
        assert!(!runtime.manufactured && !runtime.was_manufactured);
        assert_eq!(
            events(),
            ["io", "nvram", "load:permall:0", "load:volatilestate:0"],
            "no NVEnable permall ask, no store: the empty preloaded state \
             wins before the backend is consulted again"
        );
        assert!(STORED_BLOBS.lock().unwrap().is_empty());
    }

    #[test]
    fn a_manufactured_runtime_derives_its_self_tests_from_the_active_profile() {
        use self_test::PrimitiveTestSet;

        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
            .expect("first boot manufactures");
        assert_eq!(
            runtime.self_test.implemented,
            PrimitiveTestSet::for_algorithms(&runtime.state().profile.algorithms)
        );
        assert_eq!(runtime.self_test.pending, runtime.self_test.implemented);
        assert!(runtime.self_test.failure.is_none());
    }

    #[test]
    fn manufactured_runtime_debug_output_contains_no_secret_bytes() {
        let _serial = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_manufacture_backend();
        let record = oracle_record();
        let runtime = main_init(context(manufacture_callbacks(), PreloadedBlob::Missing))
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
    fn a_permanent_blob_gates_its_user_objects_on_its_own_state_format_level() {
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
    fn a_validation_context_never_formats_hierarchy_seeds() {
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
