mod attach;
mod store;

#[cfg(test)]
pub(super) use attach::OwnedSession;
pub(super) use attach::{
    OwnedPcr, OwnedSessionProcess, OwnedSessionSlot, OwnedVolatileState, materialize_volatile_state,
};
pub(super) use store::{CURRENT_OBJECT_VERSION, volatile_all_store, volatile_object_version};
#[cfg(test)]
pub(super) use store::{capture_volatile_state, marshal_volatile_state};

use sha1::{Digest, Sha1};

use super::clock::{
    HostClock, RuntimeClock, adjust_post_resume, apply_tail_v4, tail_v4_monotonic_adjust,
};
use super::marshal::{BlobReader, BlockDisposition, BlockSkipError, skip_optional_block};
use super::object::{AnyObject, parse_any_object};
use super::pcr::{Pcr, PcrSelection, parse_pcr};
use super::persistent::{
    OrderlyData, PersistentAllError, PersistentField, StateSection, parse_nv_header,
    parse_orderly_data,
};
use super::public::{DIGEST_SIZE, StateFormatLimit};
use super::session::{SessionSlot, parse_session_slot};
use super::state::{
    StateClearData, StateResetData, parse_state_clear_data, parse_state_reset_data,
};

pub(super) const VOLATILE_STATE_VERSION: u16 = 4;
pub(super) const VOLATILE_STATE_MAGIC: u32 = 0x4563_7889;

pub(super) const SHA1_DIGEST_SIZE: usize = 20;

pub(super) const MAX_SESSION_NUM: usize = 3;
pub(super) const MAX_LOADED_SESSIONS: usize = 3;
pub(super) const MAX_LOADED_OBJECTS: usize = 3;
pub(super) const IMPLEMENTATION_PCR: usize = 24;
pub(super) const RAM_INDEX_SPACE: usize = 512;

const PRIMARY_SEED_SIZE: usize = 64;

const TPMA_SESSION_RESERVED: u8 = 0x18;

const TAIL_SINCE_VERSION: u16 = 2;

const SECTION: StateSection = StateSection::VolatileState;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

fn read_block(
    reader: &mut BlobReader<'_>,
    needs_block: bool,
) -> Result<BlockDisposition, PersistentAllError> {
    skip_optional_block(reader, needs_block).map_err(|error| match error {
        BlockSkipError::Truncated => truncated(),
        BlockSkipError::MissingRequiredBlock => {
            PersistentAllError::MissingRequiredBlock { section: SECTION }
        }
    })
}

fn read_tpm2b<'a>(
    reader: &mut BlobReader<'a>,
    field: PersistentField,
    maximum: usize,
) -> Result<&'a [u8], PersistentAllError> {
    super::public::read_tpm2b(reader, SECTION, field, maximum)
}

#[derive(Clone, Copy)]
pub(super) struct SeedTie<'a> {
    pub(super) ep_seed: &'a [u8],
    pub(super) sp_seed: &'a [u8],
    pub(super) pp_seed: &'a [u8],
}

impl SeedTie<'_> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) const EMPTY: SeedTie<'static> = SeedTie {
        ep_seed: &[],
        sp_seed: &[],
        pp_seed: &[],
    };
}

pub(super) struct SessionProcess<'a> {
    pub(super) session_handles: [u32; MAX_SESSION_NUM],
    pub(super) attributes: [u8; MAX_SESSION_NUM],
    pub(super) associated_handles: [u32; MAX_SESSION_NUM],
    pub(super) nonce_callers: [&'a [u8]; MAX_SESSION_NUM],
    pub(super) input_auth_values: [&'a [u8]; MAX_SESSION_NUM],
    pub(super) encrypt_session_index: u32,
    pub(super) decrypt_session_index: u32,
    pub(super) audit_session_index: u32,
    pub(super) cp_hash_for_command_audit: &'a [u8],
    pub(super) da_pending_on_nv: bool,
}

impl core::fmt::Debug for SessionProcess<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionProcess")
            .field("session_handles", &self.session_handles)
            .field(
                "input_auth_value_lens",
                &self.input_auth_values.map(<[u8]>::len),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TailV4 {
    pub(super) host_monotonic_sample: u64,
    pub(super) suspended_elapsed_time: u64,
    pub(super) last_system_time: u64,
    pub(super) last_reported_time: u64,
}

#[derive(Debug)]
pub(super) struct DecodedVolatileState<'a> {
    pub(super) header_version: u16,
    pub(super) exclusive_audit_session: u32,
    pub(super) time: u64,
    pub(super) ph_enable: bool,
    pub(super) pcr_reconfig: bool,
    pub(super) drtm_handle: u32,
    pub(super) drtm_pre_startup: bool,
    pub(super) startup_locality3: bool,
    pub(super) da_used: bool,
    pub(super) power_was_lost: bool,
    pub(super) prev_orderly_state: u16,
    pub(super) nv_ok: bool,
    pub(super) orderly: OrderlyData<'a>,
    pub(super) state_clear: StateClearData<'a>,
    pub(super) state_reset: StateResetData<'a>,
    pub(super) manufactured: bool,
    pub(super) initialized: bool,
    pub(super) session_process: SessionProcess<'a>,
    pub(super) evict_nv_end: u32,
    pub(super) index_orderly_ram: &'a [u8],
    pub(super) max_counter: u64,
    pub(super) objects: Vec<AnyObject<'a>>,
    pub(super) pcrs: Vec<Pcr<'a>>,
    pub(super) sessions: Vec<SessionSlot<'a>>,
    pub(super) oldest_saved_session: u32,
    pub(super) free_session_slots: u32,
    pub(super) in_failure_mode: bool,
    pub(super) tpm_established: bool,
    pub(super) fail_function: u32,
    pub(super) fail_line: u32,
    pub(super) fail_code: u32,
    pub(super) real_time_previous: u64,
    pub(super) tpm_time: u64,
    pub(super) timer_reset: bool,
    pub(super) timer_stopped: bool,
    pub(super) adjust_rate: u32,
    pub(super) backthen: u64,
    pub(super) times_are_realtime: bool,
    pub(super) tail_v4: Option<TailV4>,
    pub(super) resume_clock: RuntimeClock,
}

fn parse_tail_v3(
    reader: &mut BlobReader<'_>,
    seed_tie: SeedTie<'_>,
) -> Result<(), PersistentAllError> {
    for (field, expected) in [
        (PersistentField::EpSeed, seed_tie.ep_seed),
        (PersistentField::SpSeed, seed_tie.sp_seed),
        (PersistentField::PpSeed, seed_tie.pp_seed),
    ] {
        let seed = read_tpm2b(reader, field, PRIMARY_SEED_SIZE)?;
        if seed != expected {
            return Err(PersistentAllError::SeedTieMismatch { field });
        }
    }
    Ok(())
}

fn parse_tail_v4(
    reader: &mut BlobReader<'_>,
    host_clock: &dyn HostClock,
) -> Result<(TailV4, i64), PersistentAllError> {
    let host_monotonic_sample = reader.read_u64().map_err(|_| truncated())?;
    let host_monotonic_adjust_ms = tail_v4_monotonic_adjust(host_monotonic_sample, host_clock);
    let tail = TailV4 {
        host_monotonic_sample,
        suspended_elapsed_time: reader.read_u64().map_err(|_| truncated())?,
        last_system_time: reader.read_u64().map_err(|_| truncated())?,
        last_reported_time: reader.read_u64().map_err(|_| truncated())?,
    };
    Ok((tail, host_monotonic_adjust_ms))
}

fn advance_over<'a>(
    reader: &mut BlobReader<'a>,
    input_len: usize,
    remaining_len: usize,
) -> Result<&'a [u8], PersistentAllError> {
    reader
        .take(input_len - remaining_len)
        .map_err(|_| truncated())
}

fn read_exact_array_size(
    reader: &mut BlobReader<'_>,
    expected: usize,
) -> Result<(), PersistentAllError> {
    let declared = reader.read_u16().map_err(|_| truncated())?;
    if usize::from(declared) != expected {
        return Err(PersistentAllError::ArraySizeInvalid {
            section: SECTION,
            declared,
            expected,
        });
    }
    Ok(())
}

fn unmarshal_volatile_state<'a>(
    reader: &mut BlobReader<'a>,
    shadow: &[PcrSelection<'_>],
    seed_tie: SeedTie<'_>,
    host_clock: &dyn HostClock,
    state_format: StateFormatLimit,
) -> Result<DecodedVolatileState<'a>, PersistentAllError> {
    let header = parse_nv_header(
        reader,
        SECTION,
        VOLATILE_STATE_MAGIC,
        VOLATILE_STATE_VERSION,
    )?;

    let exclusive_audit_session = reader.read_u32().map_err(|_| truncated())?;
    let time = reader.read_u64().map_err(|_| truncated())?;
    let ph_enable = reader.read_bool().map_err(|_| truncated())?;
    let pcr_reconfig = reader.read_bool().map_err(|_| truncated())?;
    let drtm_handle = reader.read_u32().map_err(|_| truncated())?;
    let drtm_pre_startup = reader.read_bool().map_err(|_| truncated())?;
    let startup_locality3 = reader.read_bool().map_err(|_| truncated())?;

    read_block(reader, true)?;
    let da_used = reader.read_bool().map_err(|_| truncated())?;

    let power_was_lost = reader.read_bool().map_err(|_| truncated())?;
    let prev_orderly_state = reader.read_u16().map_err(|_| truncated())?;
    let nv_ok = reader.read_bool().map_err(|_| truncated())?;
    let _ = read_tpm2b(reader, PersistentField::PlatformUniqueDetails, DIGEST_SIZE)?;

    let input = reader.remaining();
    let orderly = parse_orderly_data(input)?;
    let remaining_len = orderly.remaining.len();
    advance_over(reader, input.len(), remaining_len)?;

    let input = reader.remaining();
    let state_clear = parse_state_clear_data(input, shadow)?;
    let remaining_len = state_clear.remaining.len();
    advance_over(reader, input.len(), remaining_len)?;

    let input = reader.remaining();
    let state_reset = parse_state_reset_data(input)?;
    let remaining_len = state_reset.remaining.len();
    advance_over(reader, input.len(), remaining_len)?;

    let manufactured = reader.read_bool().map_err(|_| truncated())?;
    let initialized = reader.read_bool().map_err(|_| truncated())?;

    read_block(reader, true)?;
    read_exact_array_size(reader, MAX_SESSION_NUM)?;
    let mut session_handles = [0u32; MAX_SESSION_NUM];
    let mut attributes = [0u8; MAX_SESSION_NUM];
    let mut associated_handles = [0u32; MAX_SESSION_NUM];
    let mut nonce_callers: [&[u8]; MAX_SESSION_NUM] = [&[]; MAX_SESSION_NUM];
    let mut input_auth_values: [&[u8]; MAX_SESSION_NUM] = [&[]; MAX_SESSION_NUM];
    for index in 0..MAX_SESSION_NUM {
        session_handles[index] = reader.read_u32().map_err(|_| truncated())?;
        let session_attributes = reader.read_u8().map_err(|_| truncated())?;
        if session_attributes & TPMA_SESSION_RESERVED != 0 {
            return Err(PersistentAllError::ReservedBitsSet {
                section: SECTION,
                actual: u32::from(session_attributes),
            });
        }
        attributes[index] = session_attributes;
        associated_handles[index] = reader.read_u32().map_err(|_| truncated())?;
        nonce_callers[index] = read_tpm2b(reader, PersistentField::NonceCaller, DIGEST_SIZE)?;
        input_auth_values[index] =
            read_tpm2b(reader, PersistentField::InputAuthValue, DIGEST_SIZE)?;
    }
    let encrypt_session_index = reader.read_u32().map_err(|_| truncated())?;
    let decrypt_session_index = reader.read_u32().map_err(|_| truncated())?;
    let audit_session_index = reader.read_u32().map_err(|_| truncated())?;

    read_block(reader, true)?;
    let cp_hash_for_command_audit =
        read_tpm2b(reader, PersistentField::CpHashForCommandAudit, DIGEST_SIZE)?;

    let da_pending_on_nv = reader.read_bool().map_err(|_| truncated())?;

    let session_process = SessionProcess {
        session_handles,
        attributes,
        associated_handles,
        nonce_callers,
        input_auth_values,
        encrypt_session_index,
        decrypt_session_index,
        audit_session_index,
        cp_hash_for_command_audit,
        da_pending_on_nv,
    };

    read_block(reader, false)?;

    read_block(reader, true)?;
    let evict_nv_end = reader.read_u32().map_err(|_| truncated())?;
    read_exact_array_size(reader, RAM_INDEX_SPACE)?;
    let index_orderly_ram = reader.take(RAM_INDEX_SPACE).map_err(|_| truncated())?;
    let max_counter = reader.read_u64().map_err(|_| truncated())?;

    read_block(reader, true)?;
    read_exact_array_size(reader, MAX_LOADED_OBJECTS)?;
    let mut objects = Vec::with_capacity(MAX_LOADED_OBJECTS);
    for _ in 0..MAX_LOADED_OBJECTS {
        objects.push(parse_any_object(reader, state_format)?);
    }

    read_block(reader, true)?;
    read_exact_array_size(reader, IMPLEMENTATION_PCR)?;
    let mut pcrs = Vec::with_capacity(IMPLEMENTATION_PCR);
    for _ in 0..IMPLEMENTATION_PCR {
        pcrs.push(parse_pcr(reader, shadow)?);
    }

    read_block(reader, true)?;
    read_exact_array_size(reader, MAX_LOADED_SESSIONS)?;
    let mut sessions = Vec::with_capacity(MAX_LOADED_SESSIONS);
    for _ in 0..MAX_LOADED_SESSIONS {
        sessions.push(parse_session_slot(reader, state_format)?);
    }
    let oldest_saved_session = reader.read_u32().map_err(|_| truncated())?;
    let free_session_slots = reader.read_u32().map_err(|_| truncated())?;

    let in_failure_mode = reader.read_bool().map_err(|_| truncated())?;
    let tpm_established = reader.read_bool().map_err(|_| truncated())?;

    read_block(reader, true)?;
    let fail_function = reader.read_u32().map_err(|_| truncated())?;
    let fail_line = reader.read_u32().map_err(|_| truncated())?;
    let fail_code = reader.read_u32().map_err(|_| truncated())?;

    read_block(reader, true)?;
    let real_time_previous = reader.read_u64().map_err(|_| truncated())?;
    let tpm_time = reader.read_u64().map_err(|_| truncated())?;

    let timer_reset = reader.read_bool().map_err(|_| truncated())?;
    let timer_stopped = reader.read_bool().map_err(|_| truncated())?;
    let adjust_rate = reader.read_u32().map_err(|_| truncated())?;
    let backthen = reader.read_u64().map_err(|_| truncated())?;

    let mut resume_clock = RuntimeClock::POWER_ON_RESET;
    let mut tail_v4 = None;
    if header.version >= TAIL_SINCE_VERSION
        && matches!(
            read_block(reader, header.version >= 3)?,
            BlockDisposition::Present { .. }
        )
    {
        parse_tail_v3(reader, seed_tie)?;
        if matches!(
            read_block(reader, header.version >= 4)?,
            BlockDisposition::Present { .. }
        ) {
            let (tail, host_monotonic_adjust_ms) = parse_tail_v4(reader, host_clock)?;
            apply_tail_v4(&mut resume_clock, &tail, host_monotonic_adjust_ms);
            tail_v4 = Some(tail);
            read_block(reader, false)?;
        }
    }

    let trailing_magic = reader.read_u32().map_err(|_| truncated())?;
    if trailing_magic != VOLATILE_STATE_MAGIC {
        return Err(PersistentAllError::InvalidTrailingMagic {
            section: SECTION,
            actual: trailing_magic,
        });
    }

    let times_are_realtime = header.version <= 3;
    adjust_post_resume(&mut resume_clock, backthen, times_are_realtime, host_clock);

    Ok(DecodedVolatileState {
        header_version: header.version,
        exclusive_audit_session,
        time,
        ph_enable,
        pcr_reconfig,
        drtm_handle,
        drtm_pre_startup,
        startup_locality3,
        da_used,
        power_was_lost,
        prev_orderly_state,
        nv_ok,
        orderly,
        state_clear,
        state_reset,
        manufactured,
        initialized,
        session_process,
        evict_nv_end,
        index_orderly_ram,
        max_counter,
        objects,
        pcrs,
        sessions,
        oldest_saved_session,
        free_session_slots,
        in_failure_mode,
        tpm_established,
        fail_function,
        fail_line,
        fail_code,
        real_time_previous,
        tpm_time,
        timer_reset,
        timer_stopped,
        adjust_rate,
        backthen,
        times_are_realtime,
        tail_v4,
        resume_clock,
    })
}

pub(super) fn parse_volatile_state_blob<'a>(
    blob: &'a [u8],
    shadow: &[PcrSelection<'_>],
    seed_tie: SeedTie<'_>,
    host_clock: &dyn HostClock,
    state_format: StateFormatLimit,
) -> Result<DecodedVolatileState<'a>, PersistentAllError> {
    let Some(payload_len) = blob.len().checked_sub(SHA1_DIGEST_SIZE) else {
        return Err(truncated());
    };
    let computed = Sha1::digest(&blob[..payload_len]);

    let mut reader = BlobReader::new(blob);
    let decoded =
        unmarshal_volatile_state(&mut reader, shadow, seed_tie, host_clock, state_format)?;

    let remaining = reader.remaining();
    if remaining.len() < SHA1_DIGEST_SIZE {
        return Err(truncated());
    }
    let digest = &remaining[remaining.len() - SHA1_DIGEST_SIZE..];

    if digest != computed.as_slice() {
        return Err(PersistentAllError::IntegrityDigestMismatch);
    }
    Ok(decoded)
}

#[cfg(test)]
pub(super) type SessionEntryFixture = (u32, u8, u32, Vec<u8>, Vec<u8>);

#[cfg(test)]
pub(super) struct VolatileFixture {
    pub(super) version: u16,
    pub(super) magic: u32,
    pub(super) min_version: Option<u16>,
    pub(super) exclusive_audit_session: u32,
    pub(super) time: u64,
    pub(super) ph_enable: u8,
    pub(super) pcr_reconfig: u8,
    pub(super) drtm_handle: u32,
    pub(super) drtm_pre_startup: u8,
    pub(super) startup_locality3: u8,
    pub(super) da_used: u8,
    pub(super) power_was_lost: u8,
    pub(super) prev_orderly_state: u16,
    pub(super) nv_ok: u8,
    pub(super) platform_unique: Vec<u8>,
    pub(super) orderly: Vec<u8>,
    pub(super) state_clear: Vec<u8>,
    pub(super) state_reset: Vec<u8>,
    pub(super) manufactured: u8,
    pub(super) initialized: u8,
    pub(super) session_array_size: u16,
    pub(super) session_entries: Vec<SessionEntryFixture>,
    pub(super) encrypt_session_index: u32,
    pub(super) decrypt_session_index: u32,
    pub(super) audit_session_index: u32,
    pub(super) cp_hash: Vec<u8>,
    pub(super) da_pending_on_nv: u8,
    pub(super) evict_nv_end: u32,
    pub(super) orderly_ram_size: u16,
    pub(super) orderly_ram: Vec<u8>,
    pub(super) max_counter: u64,
    pub(super) object_array_size: u16,
    pub(super) objects: Vec<Vec<u8>>,
    pub(super) pcr_array_size: u16,
    pub(super) pcrs: Vec<Vec<u8>>,
    pub(super) session_slot_array_size: u16,
    pub(super) session_slots: Vec<Vec<u8>>,
    pub(super) oldest_saved_session: u32,
    pub(super) free_session_slots: u32,
    pub(super) in_failure_mode: u8,
    pub(super) tpm_established: u8,
    pub(super) fail_function: u32,
    pub(super) fail_line: u32,
    pub(super) fail_code: u32,
    pub(super) real_time_previous: u64,
    pub(super) tpm_time: u64,
    pub(super) timer_reset: u8,
    pub(super) timer_stopped: u8,
    pub(super) adjust_rate: u32,
    pub(super) backthen: u64,
    pub(super) ep_seed: Vec<u8>,
    pub(super) sp_seed: Vec<u8>,
    pub(super) pp_seed: Vec<u8>,
    pub(super) tail_v4: [u64; 4],
    pub(super) post_magic: Vec<u8>,
    pub(super) trailing_magic: u32,
}

#[cfg(test)]
pub(super) const FIXTURE_EP_SEED: [u8; 32] = [0xe5; 32];
#[cfg(test)]
pub(super) const FIXTURE_SP_SEED: [u8; 32] = [0x51; 32];
#[cfg(test)]
pub(super) const FIXTURE_PP_SEED: [u8; 32] = [0xb5; 32];

#[cfg(test)]
impl Default for VolatileFixture {
    fn default() -> Self {
        use super::object::fixtures as object_fixtures;
        use super::pcr::PcrFixture;
        use super::session::SessionSlotFixture;

        Self {
            version: VOLATILE_STATE_VERSION,
            magic: VOLATILE_STATE_MAGIC,
            min_version: Some(1),
            exclusive_audit_session: 0x0300_0000,
            time: 987_654,
            ph_enable: 1,
            pcr_reconfig: 0,
            drtm_handle: 0x4000_0007,
            drtm_pre_startup: 0,
            startup_locality3: 0,
            da_used: 1,
            power_was_lost: 0,
            prev_orderly_state: 0x0001,
            nv_ok: 1,
            platform_unique: Vec::new(),
            orderly: super::persistent::OrderlyFixture::default().bytes(),
            state_clear: super::state::StateClearFixture::default().bytes(),
            state_reset: super::state::StateResetFixture::default().bytes(),
            manufactured: 1,
            initialized: 1,
            session_array_size: MAX_SESSION_NUM as u16,
            session_entries: vec![
                (
                    0x0300_0000,
                    0x01,
                    0x4000_0001,
                    vec![0x21; 16],
                    vec![0x22; 16],
                ),
                (0xffff_ffff, 0x00, 0xffff_ffff, Vec::new(), Vec::new()),
                (0xffff_ffff, 0x00, 0xffff_ffff, Vec::new(), Vec::new()),
            ],
            encrypt_session_index: 0xffff_ffff,
            decrypt_session_index: 0xffff_ffff,
            audit_session_index: 0xffff_ffff,
            cp_hash: vec![0x77; 32],
            da_pending_on_nv: 0,
            evict_nv_end: 0x0002_4000,
            orderly_ram_size: RAM_INDEX_SPACE as u16,
            orderly_ram: (0..RAM_INDEX_SPACE).map(|i| i as u8).collect(),
            max_counter: 42,
            object_array_size: MAX_LOADED_OBJECTS as u16,
            objects: vec![object_fixtures::any_unoccupied_object(); MAX_LOADED_OBJECTS],
            pcr_array_size: IMPLEMENTATION_PCR as u16,
            pcrs: (0..IMPLEMENTATION_PCR)
                .map(|_| PcrFixture::default().bytes())
                .collect(),
            session_slot_array_size: MAX_LOADED_SESSIONS as u16,
            session_slots: {
                let mut slots = vec![SessionSlotFixture::occupied().bytes()];
                slots.extend(
                    (1..MAX_LOADED_SESSIONS).map(|_| SessionSlotFixture::default().bytes()),
                );
                slots
            },
            oldest_saved_session: 0x0100_0000,
            free_session_slots: 2,
            in_failure_mode: 0,
            tpm_established: 1,
            fail_function: 0,
            fail_line: 0,
            fail_code: 0,
            real_time_previous: 111_222,
            tpm_time: 111_000,
            timer_reset: 0,
            timer_stopped: 0,
            adjust_rate: 30_000,
            backthen: 1_600_000_000_000,
            ep_seed: FIXTURE_EP_SEED.to_vec(),
            sp_seed: FIXTURE_SP_SEED.to_vec(),
            pp_seed: FIXTURE_PP_SEED.to_vec(),
            tail_v4: [5_000_000, 60_000, 1_600_000_000_500, 1_600_000_000_400],
            post_magic: Vec::new(),
            trailing_magic: VOLATILE_STATE_MAGIC,
        }
    }
}

#[cfg(test)]
impl VolatileFixture {
    pub(super) fn seed_tie() -> SeedTie<'static> {
        SeedTie {
            ep_seed: &FIXTURE_EP_SEED,
            sp_seed: &FIXTURE_SP_SEED,
            pp_seed: &FIXTURE_PP_SEED,
        }
    }

    fn push_block(out: &mut Vec<u8>, has_block: u8, payload: &[u8]) {
        out.push(has_block);
        out.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        out.extend_from_slice(payload);
    }

    fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
        out.extend_from_slice(bytes);
    }

    pub(super) fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.magic.to_be_bytes());
        if self.version >= 2
            && let Some(min_version) = self.min_version
        {
            out.extend_from_slice(&min_version.to_be_bytes());
        }
        out.extend_from_slice(&self.exclusive_audit_session.to_be_bytes());
        out.extend_from_slice(&self.time.to_be_bytes());
        out.push(self.ph_enable);
        out.push(self.pcr_reconfig);
        out.extend_from_slice(&self.drtm_handle.to_be_bytes());
        out.push(self.drtm_pre_startup);
        out.push(self.startup_locality3);
        Self::push_block(&mut out, 1, &[self.da_used]);
        out.push(self.power_was_lost);
        out.extend_from_slice(&self.prev_orderly_state.to_be_bytes());
        out.push(self.nv_ok);
        Self::push_tpm2b(&mut out, &self.platform_unique);
        out.extend_from_slice(&self.orderly);
        out.extend_from_slice(&self.state_clear);
        out.extend_from_slice(&self.state_reset);
        out.push(self.manufactured);
        out.push(self.initialized);

        let mut session_process = Vec::new();
        session_process.extend_from_slice(&self.session_array_size.to_be_bytes());
        for (handle, attributes, associated, nonce, auth) in &self.session_entries {
            session_process.extend_from_slice(&handle.to_be_bytes());
            session_process.push(*attributes);
            session_process.extend_from_slice(&associated.to_be_bytes());
            Self::push_tpm2b(&mut session_process, nonce);
            Self::push_tpm2b(&mut session_process, auth);
        }
        session_process.extend_from_slice(&self.encrypt_session_index.to_be_bytes());
        session_process.extend_from_slice(&self.decrypt_session_index.to_be_bytes());
        session_process.extend_from_slice(&self.audit_session_index.to_be_bytes());
        let mut cp_hash_block = Vec::new();
        Self::push_tpm2b(&mut cp_hash_block, &self.cp_hash);
        Self::push_block(&mut session_process, 1, &cp_hash_block);
        session_process.push(self.da_pending_on_nv);
        Self::push_block(&mut out, 1, &session_process);

        Self::push_block(&mut out, 0, &[]);

        let mut nv = Vec::new();
        nv.extend_from_slice(&self.evict_nv_end.to_be_bytes());
        nv.extend_from_slice(&self.orderly_ram_size.to_be_bytes());
        nv.extend_from_slice(&self.orderly_ram);
        nv.extend_from_slice(&self.max_counter.to_be_bytes());
        Self::push_block(&mut out, 1, &nv);

        let mut object_block = Vec::new();
        object_block.extend_from_slice(&self.object_array_size.to_be_bytes());
        for object in &self.objects {
            object_block.extend_from_slice(object);
        }
        Self::push_block_truncating(&mut out, 1, &object_block);

        let mut pcr_block = Vec::new();
        pcr_block.extend_from_slice(&self.pcr_array_size.to_be_bytes());
        for pcr in &self.pcrs {
            pcr_block.extend_from_slice(pcr);
        }
        Self::push_block_truncating(&mut out, 1, &pcr_block);

        let mut session_block = Vec::new();
        session_block.extend_from_slice(&self.session_slot_array_size.to_be_bytes());
        for slot in &self.session_slots {
            session_block.extend_from_slice(slot);
        }
        session_block.extend_from_slice(&self.oldest_saved_session.to_be_bytes());
        session_block.extend_from_slice(&self.free_session_slots.to_be_bytes());
        Self::push_block_truncating(&mut out, 1, &session_block);

        out.push(self.in_failure_mode);
        out.push(self.tpm_established);

        let mut fail = Vec::new();
        fail.extend_from_slice(&self.fail_function.to_be_bytes());
        fail.extend_from_slice(&self.fail_line.to_be_bytes());
        fail.extend_from_slice(&self.fail_code.to_be_bytes());
        Self::push_block(&mut out, 1, &fail);

        let mut clock = Vec::new();
        clock.extend_from_slice(&self.real_time_previous.to_be_bytes());
        clock.extend_from_slice(&self.tpm_time.to_be_bytes());
        Self::push_block(&mut out, 1, &clock);

        out.push(self.timer_reset);
        out.push(self.timer_stopped);
        out.extend_from_slice(&self.adjust_rate.to_be_bytes());
        out.extend_from_slice(&self.backthen.to_be_bytes());

        if self.version >= 2 {
            let mut v3 = Vec::new();
            if self.version >= 3 {
                Self::push_tpm2b(&mut v3, &self.ep_seed);
                Self::push_tpm2b(&mut v3, &self.sp_seed);
                Self::push_tpm2b(&mut v3, &self.pp_seed);
                let mut v4 = Vec::new();
                if self.version >= 4 {
                    for value in self.tail_v4 {
                        v4.extend_from_slice(&value.to_be_bytes());
                    }
                    Self::push_block(&mut v4, 1, &[]);
                }
                Self::push_block(&mut v3, 1, &v4);
            }
            Self::push_block(&mut out, 1, &v3);
        }

        out.extend_from_slice(&self.trailing_magic.to_be_bytes());
        out.extend_from_slice(&self.post_magic);
        out
    }

    fn push_block_truncating(out: &mut Vec<u8>, has_block: u8, payload: &[u8]) {
        out.push(has_block);
        out.extend_from_slice(&((payload.len() as u16).to_be_bytes()));
        out.extend_from_slice(payload);
    }

    pub(super) fn bytes(&self) -> Vec<u8> {
        let mut out = self.payload();
        let digest = Sha1::digest(&out);
        out.extend_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::clock::{ClockCall, RecordingClock};
    use super::super::state::MAX_ACTIVE_SESSIONS;
    use super::*;
    use crate::library::constants::{
        TPM_RC_BAD_PARAMETER, TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_HASH, TPM_RC_INSUFFICIENT,
        TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_VALUE,
    };

    const HOST_REALTIME: u64 = 1_600_000_500_000;
    const HOST_MONOTONIC: u64 = 7_000_000;

    fn scripted_clock() -> RecordingClock {
        RecordingClock::new(HOST_REALTIME, HOST_MONOTONIC)
    }

    fn parse(blob: &[u8]) -> Result<DecodedVolatileState<'_>, PersistentAllError> {
        parse_volatile_state_blob(
            blob,
            &[],
            VolatileFixture::seed_tie(),
            &scripted_clock(),
            StateFormatLimit::CURRENT,
        )
    }

    fn parse_recording<'a>(
        blob: &'a [u8],
        host: &RecordingClock,
    ) -> Result<DecodedVolatileState<'a>, PersistentAllError> {
        parse_volatile_state_blob(
            blob,
            &[],
            VolatileFixture::seed_tie(),
            host,
            StateFormatLimit::CURRENT,
        )
    }

    #[test]
    fn every_supported_writer_version_decodes() {
        for version in [1u16, 2, 3, 4] {
            let fixture = VolatileFixture {
                version,
                min_version: Some(1),
                ..VolatileFixture::default()
            };
            let blob = fixture.bytes();
            let decoded =
                parse(&blob).unwrap_or_else(|error| panic!("version {version}: {error:?}"));
            assert_eq!(decoded.header_version, version);
            assert_eq!(decoded.times_are_realtime, version <= 3);
            assert_eq!(decoded.tail_v4.is_some(), version >= 4);
        }
    }

    #[test]
    fn version_1_has_no_min_version_and_no_tail_chain() {
        let fixture = VolatileFixture {
            version: 1,
            min_version: None,
            ..VolatileFixture::default()
        };
        let blob = fixture.bytes();
        let decoded = parse(&blob).unwrap();
        assert_eq!(decoded.header_version, 1);
        assert!(decoded.tail_v4.is_none());
        assert!(decoded.times_are_realtime);
    }

    #[test]
    fn bad_magic_is_bad_tag() {
        let fixture = VolatileFixture {
            magic: 0xdead_beef,
            ..VolatileFixture::default()
        };
        let error = parse(&fixture.bytes()).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidHeaderMagic {
                section: StateSection::VolatileState,
                actual: 0xdead_beef,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);
    }

    #[test]
    fn version_zero_decodes_like_a_pre_tail_stream() {
        let fixture = VolatileFixture {
            version: 0,
            min_version: None,
            ..VolatileFixture::default()
        };
        let blob = fixture.bytes();
        let decoded = parse(&blob).unwrap();
        assert_eq!(decoded.header_version, 0);
        assert!(decoded.tail_v4.is_none());
    }

    #[test]
    fn newer_version_with_supported_min_version_decodes() {
        let fixture = VolatileFixture {
            version: 5,
            min_version: Some(1),
            ..VolatileFixture::default()
        };
        let blob = fixture.bytes();
        let decoded = parse(&blob).unwrap();
        assert_eq!(decoded.header_version, 5);
        assert!(decoded.tail_v4.is_some());
    }

    #[test]
    fn min_version_newer_than_supported_is_rejected() {
        let fixture = VolatileFixture {
            min_version: Some(VOLATILE_STATE_VERSION + 1),
            ..VolatileFixture::default()
        };
        let error = parse(&fixture.bytes()).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MinimumVersionTooNew {
                section: StateSection::VolatileState,
                minimum: VOLATILE_STATE_VERSION + 1,
                supported: VOLATILE_STATE_VERSION,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_VERSION);
    }

    #[test]
    fn every_truncated_header_prefix_fails_safely() {
        let full = VolatileFixture::default().bytes();
        for len in 0..12 {
            let error = parse(&full[..len]).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT, "prefix {len}");
        }
    }

    #[test]
    fn scalars_decode_exactly() {
        let blob = VolatileFixture::default().bytes();
        let decoded = parse(&blob).unwrap();
        assert_eq!(decoded.exclusive_audit_session, 0x0300_0000);
        assert_eq!(decoded.time, 987_654);
        assert!(decoded.ph_enable);
        assert!(!decoded.pcr_reconfig);
        assert_eq!(decoded.drtm_handle, 0x4000_0007);
        assert!(!decoded.drtm_pre_startup);
        assert!(!decoded.startup_locality3);
        assert!(decoded.da_used);
        assert!(!decoded.power_was_lost);
        assert_eq!(decoded.prev_orderly_state, 0x0001);
        assert!(decoded.nv_ok);
        assert!(decoded.manufactured);
        assert!(decoded.initialized);
        assert_eq!(decoded.evict_nv_end, 0x0002_4000);
        assert_eq!(decoded.max_counter, 42);
        assert_eq!(decoded.oldest_saved_session, 0x0100_0000);
        assert_eq!(decoded.free_session_slots, 2);
        assert!(!decoded.in_failure_mode);
        assert!(decoded.tpm_established);
        assert_eq!(decoded.fail_function, 0);
        assert_eq!(decoded.real_time_previous, 111_222);
        assert_eq!(decoded.tpm_time, 111_000);
        assert_eq!(decoded.adjust_rate, 30_000);
        assert_eq!(decoded.backthen, 1_600_000_000_000);
        assert_eq!(
            decoded.tail_v4,
            Some(TailV4 {
                host_monotonic_sample: 5_000_000,
                suspended_elapsed_time: 60_000,
                last_system_time: 1_600_000_000_500,
                last_reported_time: 1_600_000_000_400,
            })
        );
        assert_eq!(decoded.orderly.clock_safe, 1);
        assert_eq!(decoded.state_reset.context_array.len(), MAX_ACTIVE_SESSIONS);
        assert_eq!(decoded.index_orderly_ram.len(), RAM_INDEX_SPACE);
        assert_eq!(decoded.index_orderly_ram[3], 3);
        assert_eq!(decoded.objects.len(), MAX_LOADED_OBJECTS);
        assert_eq!(decoded.pcrs.len(), IMPLEMENTATION_PCR);
        assert_eq!(decoded.sessions.len(), MAX_LOADED_SESSIONS);
        assert!(decoded.sessions[0].occupied);
        assert!(!decoded.sessions[1].occupied);
        assert_eq!(decoded.session_process.session_handles[0], 0x0300_0000);
        assert_eq!(decoded.session_process.attributes[0], 0x01);
        assert_eq!(decoded.session_process.nonce_callers[0], &[0x21; 16][..]);
        assert_eq!(
            decoded.session_process.input_auth_values[0],
            &[0x22; 16][..]
        );
        assert_eq!(
            decoded.session_process.cp_hash_for_command_audit,
            &[0x77; 32][..]
        );
        assert!(!decoded.session_process.da_pending_on_nv);
    }

    #[test]
    fn wrong_session_process_array_size_is_bad_parameter() {
        for declared in [0u16, 2, 4, 64] {
            let mut fixture = VolatileFixture {
                session_array_size: declared,
                ..VolatileFixture::default()
            };
            fixture
                .session_entries
                .truncate(usize::from(declared).min(3));
            let error = parse(&fixture.bytes()).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::VolatileState,
                    declared,
                    expected: MAX_SESSION_NUM,
                },
                "declared {declared}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_BAD_PARAMETER);
        }
    }

    #[test]
    fn reserved_session_attribute_bits_are_rejected() {
        let mut fixture = VolatileFixture::default();
        fixture.session_entries[1].1 = 0x18;
        let error = parse(&fixture.bytes()).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ReservedBitsSet {
                section: StateSection::VolatileState,
                actual: 0x18,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_RESERVED_BITS);
    }

    #[test]
    fn oversized_volatile_tpm2bs_are_size_errors() {
        let oversized = vec![0u8; 65];
        let fixtures = [
            VolatileFixture {
                platform_unique: oversized.clone(),
                ..VolatileFixture::default()
            },
            {
                let mut fixture = VolatileFixture::default();
                fixture.session_entries[0].3 = oversized.clone();
                fixture
            },
            VolatileFixture {
                cp_hash: oversized,
                ..VolatileFixture::default()
            },
        ];
        for fixture in fixtures {
            let error = parse(&fixture.bytes()).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_SIZE);
        }
    }

    #[test]
    fn wrong_orderly_ram_size_is_bad_parameter() {
        for declared in [0u16, 511, 513] {
            let fixture = VolatileFixture {
                orderly_ram_size: declared,
                orderly_ram: vec![0; usize::from(declared)],
                ..VolatileFixture::default()
            };
            let error = parse(&fixture.bytes()).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ArraySizeInvalid {
                    section: StateSection::VolatileState,
                    declared,
                    expected: RAM_INDEX_SPACE,
                },
                "declared {declared}"
            );
        }
    }

    #[test]
    fn wrong_object_pcr_and_session_slot_counts_are_bad_parameter() {
        for (fixture, expected) in [
            (
                VolatileFixture {
                    object_array_size: 4,
                    ..VolatileFixture::default()
                },
                MAX_LOADED_OBJECTS,
            ),
            (
                VolatileFixture {
                    pcr_array_size: 23,
                    ..VolatileFixture::default()
                },
                IMPLEMENTATION_PCR,
            ),
            (
                VolatileFixture {
                    session_slot_array_size: 0,
                    ..VolatileFixture::default()
                },
                MAX_LOADED_SESSIONS,
            ),
        ] {
            let error = parse(&fixture.bytes()).unwrap_err();
            assert!(
                matches!(
                    error,
                    PersistentAllError::ArraySizeInvalid { expected: e, .. } if e == expected
                ),
                "{error:?}"
            );
        }
    }

    #[test]
    fn missing_required_block_is_bad_parameter() {
        let mut payload = VolatileFixture::default().payload();
        assert_eq!(payload[28], 1, "fixture layout: DA block flag");
        payload[28] = 0;
        let digest = Sha1::digest(&payload);
        payload.extend_from_slice(&digest);
        let error = parse(&payload).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingRequiredBlock {
                section: StateSection::VolatileState,
            }
        );
    }

    #[test]
    fn seed_tie_mismatch_identifies_the_hierarchy() {
        for (field, wrong) in [
            (PersistentField::EpSeed, 0usize),
            (PersistentField::SpSeed, 1),
            (PersistentField::PpSeed, 2),
        ] {
            let mut fixture = VolatileFixture::default();
            match wrong {
                0 => fixture.ep_seed = vec![0xff; 32],
                1 => fixture.sp_seed = vec![0xff; 32],
                _ => fixture.pp_seed = vec![0xff; 32],
            }
            let error = parse(&fixture.bytes()).unwrap_err();
            assert_eq!(error, PersistentAllError::SeedTieMismatch { field });
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn seed_length_mismatch_is_a_tie_mismatch_and_oversize_is_size() {
        let fixture = VolatileFixture {
            ep_seed: FIXTURE_EP_SEED[..16].to_vec(),
            ..VolatileFixture::default()
        };
        assert_eq!(
            parse(&fixture.bytes()).unwrap_err(),
            PersistentAllError::SeedTieMismatch {
                field: PersistentField::EpSeed,
            }
        );
        let fixture = VolatileFixture {
            ep_seed: vec![0xe5; 65],
            ..VolatileFixture::default()
        };
        assert_eq!(
            parse(&fixture.bytes()).unwrap_err().tpm_result(),
            TPM_RC_SIZE
        );
    }

    #[test]
    fn version_2_stream_skips_the_tail_chain_entirely() {
        let mut payload = VolatileFixture {
            version: 2,
            ..VolatileFixture::default()
        }
        .payload();
        let magic_at = payload.len() - 4;
        payload.truncate(magic_at - 3);
        payload.push(1);
        payload.extend_from_slice(&4u16.to_be_bytes());
        payload.extend_from_slice(&[0xaa; 4]);
        payload.extend_from_slice(&VOLATILE_STATE_MAGIC.to_be_bytes());
        let digest = Sha1::digest(&payload);
        payload.extend_from_slice(&digest);
        let decoded = parse(&payload).unwrap();
        assert_eq!(decoded.header_version, 2);
        assert!(decoded.tail_v4.is_none());
        assert!(decoded.times_are_realtime);
    }

    #[test]
    fn bad_trailing_magic_is_bad_tag() {
        let fixture = VolatileFixture {
            trailing_magic: 0x1234_5678,
            ..VolatileFixture::default()
        };
        let error = parse(&fixture.bytes()).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::InvalidTrailingMagic {
                section: StateSection::VolatileState,
                actual: 0x1234_5678,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);
    }

    #[test]
    fn blob_shorter_than_the_digest_is_insufficient() {
        for len in 0..SHA1_DIGEST_SIZE {
            let error = parse(&vec![0u8; len]).unwrap_err();
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT, "length {len}");
        }
    }

    #[test]
    fn corrupted_payload_fails_the_digest_when_the_decode_cannot_see_it() {
        let mut blob = VolatileFixture::default().bytes();
        let ramp: Vec<u8> = (0..RAM_INDEX_SPACE).map(|i| i as u8).collect();
        let at = blob
            .windows(RAM_INDEX_SPACE)
            .position(|window| window == ramp)
            .expect("the fixture orderly-RAM ramp is present");
        blob[at + 200] ^= 0x01;
        let error = parse(&blob).unwrap_err();
        assert_eq!(error, PersistentAllError::IntegrityDigestMismatch);
    }

    #[test]
    fn corrupted_digest_is_a_hash_error() {
        let mut blob = VolatileFixture::default().bytes();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        let error = parse(&blob).unwrap_err();
        assert_eq!(error, PersistentAllError::IntegrityDigestMismatch);
        assert_eq!(error.tpm_result(), TPM_RC_HASH);
    }

    #[test]
    fn future_bytes_before_the_digest_are_skipped_and_hash_covered() {
        let fixture = VolatileFixture {
            post_magic: vec![0xf0, 0xf1, 0xf2, 0xf3, 0xf4],
            ..VolatileFixture::default()
        };
        let blob = fixture.bytes();
        assert!(parse(&blob).is_ok());

        let mut corrupted = blob;
        let index = corrupted.len() - SHA1_DIGEST_SIZE - 2;
        corrupted[index] ^= 0xff;
        assert_eq!(
            parse(&corrupted).unwrap_err(),
            PersistentAllError::IntegrityDigestMismatch
        );
    }

    #[test]
    fn digest_over_wrong_range_is_rejected() {
        let payload = VolatileFixture::default().payload();
        let mut blob = payload.clone();
        let digest = Sha1::digest(&payload[..payload.len() - 4]);
        blob.extend_from_slice(&digest);
        assert_eq!(
            parse(&blob).unwrap_err(),
            PersistentAllError::IntegrityDigestMismatch
        );
    }

    #[test]
    fn occupied_objects_in_the_volatile_stream_decode() {
        let mut fixture = VolatileFixture::default();
        fixture.objects[0] = super::super::object::fixtures::any_rsa_object(4);
        let blob = fixture.bytes();
        let decoded = parse(&blob).unwrap();
        assert!(decoded.objects[0].occupied());
        assert!(!decoded.objects[1].occupied());
        assert!(!decoded.objects[2].occupied());
    }

    const C_FIXTURE_V1: &[u8] = include_bytes!("../testdata/volatile_state_v1_synthetic.bin");
    const C_FIXTURE_V2: &[u8] = include_bytes!("../testdata/volatile_state_v2_synthetic.bin");
    const C_FIXTURE_V3: &[u8] = include_bytes!("../testdata/volatile_state_v3_synthetic.bin");
    const C_FIXTURE_V4: &[u8] = include_bytes!("../testdata/volatile_state_v4.bin");
    const C_FIXTURE_V4_FUTURE: &[u8] = include_bytes!("../testdata/volatile_state_v4_future.bin");

    fn parse_c_fixture(blob: &[u8]) -> DecodedVolatileState<'_> {
        parse_volatile_state_blob(
            blob,
            &[],
            SeedTie::EMPTY,
            &scripted_clock(),
            StateFormatLimit::CURRENT,
        )
        .expect("the C fixture decodes")
    }

    #[test]
    fn c_fixtures_decode_for_every_layout_version() {
        for (blob, version) in [
            (C_FIXTURE_V1, 1u16),
            (C_FIXTURE_V2, 2),
            (C_FIXTURE_V3, 3),
            (C_FIXTURE_V4, 4),
        ] {
            let decoded = parse_c_fixture(blob);
            assert_eq!(decoded.header_version, version);
            assert_eq!(decoded.times_are_realtime, version <= 3);
            assert_eq!(decoded.tail_v4.is_some(), version >= 4);
            assert_eq!(decoded.time, 0x123456, "version {version}");
        }
    }

    #[test]
    fn c_v4_fixture_carries_the_expected_values_in_every_section() {
        let decoded = parse_c_fixture(C_FIXTURE_V4);

        assert_eq!(decoded.exclusive_audit_session, 0x0300_0abc);
        assert_eq!(decoded.time, 0x123456);
        assert!(decoded.ph_enable);
        assert!(decoded.pcr_reconfig);
        assert_eq!(decoded.drtm_handle, 0x4000_0007);
        assert!(!decoded.drtm_pre_startup);
        assert!(decoded.startup_locality3);
        assert!(decoded.da_used);
        assert!(decoded.power_was_lost);
        assert_eq!(decoded.prev_orderly_state, 0x8001);
        assert!(decoded.nv_ok);

        assert_eq!(decoded.orderly.clock, 0x0011_2233_4455_6677);
        assert_eq!(decoded.orderly.clock_safe, 0);
        assert_eq!(decoded.orderly.drbg_state.reseed_counter, 0x99);
        assert_eq!(decoded.orderly.drbg_state.drbg_magic, 0x4452_4247);
        let seed: Vec<u8> = (0..48u16).map(|i| (0x30 + i) as u8).collect();
        assert_eq!(decoded.orderly.drbg_state.seed, &seed[..]);
        assert_eq!(decoded.orderly.drbg_state.last_value, [1, 2, 3, 4]);
        assert_eq!(decoded.orderly.self_heal_timer, 1000);
        assert_eq!(decoded.orderly.lockout_timer, 2000);
        assert_eq!(decoded.orderly.time, 3000);

        assert!(decoded.state_clear.sh_enable);
        assert!(!decoded.state_clear.eh_enable);
        assert!(decoded.state_clear.ph_enable_nv);
        assert_eq!(decoded.state_clear.platform_alg, 0x000b);
        assert_eq!(decoded.state_clear.platform_policy, &[0x7c; 32][..]);
        assert_eq!(decoded.state_clear.platform_auth, &[0x7d; 12][..]);
        for (index, fill) in [0x41u8, 0x42, 0x43, 0x44].iter().enumerate() {
            let bank = decoded.state_clear.pcr_save.banks[index].expect("bank present");
            assert!(bank.pcrs.iter().all(|&byte| byte == *fill));
        }
        assert_eq!(decoded.state_clear.pcr_auth_values[0], &[0x7e; 20][..]);

        assert_eq!(decoded.state_reset.null_proof, &[0x6a; 16][..]);
        assert_eq!(decoded.state_reset.null_seed, &[0x6b; 16][..]);
        assert_eq!(decoded.state_reset.clear_count, 5);
        assert_eq!(decoded.state_reset.object_context_id, 0x77);
        assert_eq!(decoded.state_reset.context_array[63], 63);
        assert_eq!(decoded.state_reset.context_slot_mask, 0xffff);
        assert_eq!(decoded.state_reset.context_counter, 0x88);
        assert_eq!(decoded.state_reset.command_audit_digest, &[0x6c; 32][..]);
        assert_eq!(decoded.state_reset.restart_count, 9);
        assert_eq!(decoded.state_reset.pcr_counter, 11);
        assert_eq!(decoded.state_reset.commit_counter, 0x99);
        assert_eq!(decoded.state_reset.commit_nonce, &[0x6d; 16][..]);
        assert_eq!(decoded.state_reset.commit_array, [0x6e; 16]);
        assert_eq!(decoded.state_reset.null_seed_compat_level, 0);

        assert!(decoded.manufactured);
        assert!(decoded.initialized);
        assert_eq!(decoded.session_process.session_handles[0], 0x0200_0000);
        assert_eq!(decoded.session_process.attributes[0], 0x01);
        assert_eq!(decoded.session_process.associated_handles[0], 0x4000_0001);
        assert_eq!(decoded.session_process.nonce_callers[0], &[0x21; 16][..]);
        assert_eq!(
            decoded.session_process.input_auth_values[0],
            &[0x22; 16][..]
        );
        assert_eq!(decoded.session_process.session_handles[1], 0xffff_ffff);
        assert_eq!(decoded.session_process.encrypt_session_index, 7);
        assert_eq!(decoded.session_process.decrypt_session_index, 8);
        assert_eq!(decoded.session_process.audit_session_index, 9);
        assert_eq!(
            decoded.session_process.cp_hash_for_command_audit,
            &[0x23; 32][..]
        );
        assert!(decoded.session_process.da_pending_on_nv);

        assert_eq!(decoded.evict_nv_end, 0x0002_4000);
        assert_eq!(decoded.index_orderly_ram.len(), RAM_INDEX_SPACE);
        assert_eq!(decoded.index_orderly_ram[511], 255);
        assert_eq!(decoded.max_counter, 0x2a);
        assert_eq!(decoded.objects.len(), MAX_LOADED_OBJECTS);
        assert!(decoded.objects.iter().all(|object| !object.occupied()));
        assert_eq!(decoded.pcrs.len(), IMPLEMENTATION_PCR);
        assert_eq!(decoded.pcrs[5].banks[0], Some(&[0x55u8; 20][..]));
        assert_eq!(decoded.pcrs[5].banks[1], Some(&[0x65u8; 32][..]));
        assert!(decoded.sessions[0].occupied);
        let session = decoded.sessions[0].session.as_ref().unwrap();
        assert_eq!(session.attributes, 0x0101_0101);
        assert_eq!(session.pcr_counter, 3);
        assert_eq!(session.start_time, 100);
        assert_eq!(session.timeout, 5000);
        assert_eq!(session.epoch, 12);
        assert_eq!(session.command_code, 0x176);
        assert_eq!(session.auth_hash_alg, 0x000b);
        assert_eq!(session.symmetric.algorithm, 0x0006);
        assert_eq!(session.symmetric.key_bits, Some(128));
        assert_eq!(session.symmetric.mode, Some(0x0043));
        assert_eq!(session.session_key, &[0x33; 32][..]);
        assert_eq!(session.nonce_tpm, &[0x34; 20][..]);
        assert_eq!(session.bound_entity, &[0x35; 34][..]);
        assert!(!decoded.sessions[1].occupied);
        assert!(!decoded.sessions[2].occupied);
        assert_eq!(decoded.oldest_saved_session, 1);
        assert_eq!(decoded.free_session_slots, 2);

        assert!(!decoded.in_failure_mode);
        assert!(decoded.tpm_established);
        assert_eq!(decoded.fail_function, 0xa1);
        assert_eq!(decoded.fail_line, 0xa2);
        assert_eq!(decoded.fail_code, 0xa3);
        assert_eq!(decoded.real_time_previous, 111_222);
        assert_eq!(decoded.tpm_time, 111_000);
        assert!(decoded.timer_reset);
        assert!(!decoded.timer_stopped);
        assert_eq!(decoded.adjust_rate, 30_000);
        assert_eq!(decoded.backthen, 100_000_000_000);
        assert_eq!(
            decoded.tail_v4,
            Some(TailV4 {
                host_monotonic_sample: 5_000_000,
                suspended_elapsed_time: 60_000,
                last_system_time: 1_600_000_000_500,
                last_reported_time: 1_600_000_000_400,
            })
        );
    }

    #[test]
    fn c_future_fixture_pins_the_exact_hash_coverage() {
        let decoded = parse_c_fixture(C_FIXTURE_V4_FUTURE);
        assert_eq!(decoded.header_version, 4);
        assert_eq!(
            C_FIXTURE_V4_FUTURE.len(),
            C_FIXTURE_V4.len() + 6,
            "six forward-compatible bytes precede the digest"
        );
        let mut corrupted = C_FIXTURE_V4_FUTURE.to_vec();
        let index = corrupted.len() - SHA1_DIGEST_SIZE - 1;
        corrupted[index] ^= 0xff;
        assert_eq!(
            parse_volatile_state_blob(
                &corrupted,
                &[],
                SeedTie::EMPTY,
                &scripted_clock(),
                StateFormatLimit::CURRENT
            )
            .unwrap_err(),
            PersistentAllError::IntegrityDigestMismatch
        );
    }

    #[test]
    fn c_fixture_strict_prefixes_fail_safely() {
        let payload = &C_FIXTURE_V4[..C_FIXTURE_V4.len() - SHA1_DIGEST_SIZE];
        for len in (0..payload.len()).step_by(13) {
            let mut blob = payload[..len].to_vec();
            let digest = Sha1::digest(&blob);
            blob.extend_from_slice(&digest);
            assert!(
                parse_volatile_state_blob(
                    &blob,
                    &[],
                    SeedTie::EMPTY,
                    &scripted_clock(),
                    StateFormatLimit::CURRENT
                )
                .is_err(),
                "prefix length {len} decoded"
            );
        }
    }

    #[test]
    fn v4_stream_reads_monotonic_then_realtime_exactly_once() {
        let blob = VolatileFixture::default().bytes();
        let host = scripted_clock();
        let decoded = parse_recording(&blob, &host).expect("the v4 fixture decodes");
        assert_eq!(host.calls(), [ClockCall::Monotonic, ClockCall::Realtime]);
        assert_eq!(
            decoded.resume_clock,
            RuntimeClock {
                host_monotonic_adjust_ms: -2_000_000,
                suspended_elapsed_ms: 560_000,
                last_system_time_ms: 1_600_000_000_500,
                last_reported_time_ms: 1_600_000_000_400,
            }
        );
    }

    #[test]
    fn pre_v4_streams_read_realtime_then_monotonic_exactly_once() {
        for version in [1u16, 2, 3] {
            let fixture = VolatileFixture {
                version,
                min_version: (version >= 2).then_some(1),
                ..VolatileFixture::default()
            };
            let blob = fixture.bytes();
            let host = scripted_clock();
            let decoded = parse_recording(&blob, &host)
                .unwrap_or_else(|error| panic!("version {version}: {error:?}"));
            assert_eq!(
                host.calls(),
                [ClockCall::Realtime, ClockCall::Monotonic],
                "version {version}"
            );
            assert_eq!(
                decoded.resume_clock,
                RuntimeClock {
                    host_monotonic_adjust_ms: -(HOST_MONOTONIC as i64),
                    suspended_elapsed_ms: HOST_REALTIME,
                    last_system_time_ms: HOST_REALTIME,
                    last_reported_time_ms: HOST_REALTIME,
                },
                "version {version}"
            );
        }
    }

    #[test]
    fn invalid_header_performs_no_clock_reads() {
        let fixture = VolatileFixture {
            magic: 0xdead_beef,
            ..VolatileFixture::default()
        };
        let host = scripted_clock();
        assert!(parse_recording(&fixture.bytes(), &host).is_err());
        assert!(host.calls().is_empty());

        let host = scripted_clock();
        assert!(parse_recording(&[0xd0, 0x0d], &host).is_err());
        assert!(host.calls().is_empty());
    }

    #[test]
    fn failure_before_the_versioned_tail_performs_no_clock_reads() {
        let fixture = VolatileFixture {
            ep_seed: vec![0xaa; 32],
            ..VolatileFixture::default()
        };
        let host = scripted_clock();
        assert_eq!(
            parse_recording(&fixture.bytes(), &host).unwrap_err(),
            PersistentAllError::SeedTieMismatch {
                field: PersistentField::EpSeed,
            }
        );
        assert!(host.calls().is_empty());
    }

    fn tail_v4_offset(payload: &[u8]) -> usize {
        payload.len() - 4 - 3 - 32
    }

    #[test]
    fn tail_v4_truncated_inside_the_first_sample_performs_no_clock_reads() {
        let payload = VolatileFixture::default().payload();
        let tail_at = tail_v4_offset(&payload);
        for available in [0usize, 1, 7] {
            let host = scripted_clock();
            let error = parse_recording(&payload[..tail_at + available], &host).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "available {available}"
            );
            assert!(host.calls().is_empty(), "available {available}");
        }
    }

    #[test]
    fn tail_v4_truncated_after_the_sample_has_already_read_monotonic() {
        let payload = VolatileFixture::default().payload();
        let tail_at = tail_v4_offset(&payload);
        for available in [8usize, 15, 16, 24, 31] {
            let host = scripted_clock();
            let error = parse_recording(&payload[..tail_at + available], &host).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "available {available}"
            );
            assert_eq!(
                host.calls(),
                [ClockCall::Monotonic],
                "available {available}"
            );
        }
    }

    #[test]
    fn complete_tail_v4_with_a_malformed_future_block_reads_monotonic_only() {
        let payload = VolatileFixture::default().payload();
        let tail_at = tail_v4_offset(&payload);
        for available in [32usize, 33, 34] {
            let host = scripted_clock();
            let error = parse_recording(&payload[..tail_at + available], &host).unwrap_err();
            assert_eq!(
                error.tpm_result(),
                TPM_RC_INSUFFICIENT,
                "available {available}"
            );
            assert_eq!(
                host.calls(),
                [ClockCall::Monotonic],
                "available {available}"
            );
        }
    }

    #[test]
    fn failure_before_the_trailing_magic_skips_the_realtime_read() {
        let fixture = VolatileFixture {
            trailing_magic: 0x0bad_0bad,
            ..VolatileFixture::default()
        };
        let host = scripted_clock();
        let error = parse_recording(&fixture.bytes(), &host).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_BAD_TAG);
        assert_eq!(host.calls(), [ClockCall::Monotonic]);

        let fixture = VolatileFixture {
            version: 1,
            min_version: None,
            trailing_magic: 0x0bad_0bad,
            ..VolatileFixture::default()
        };
        let host = scripted_clock();
        assert!(parse_recording(&fixture.bytes(), &host).is_err());
        assert!(host.calls().is_empty());
    }

    #[test]
    fn bad_digest_fails_after_the_upstream_reads() {
        let mut blob = VolatileFixture::default().bytes();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        let host = scripted_clock();
        assert_eq!(
            parse_recording(&blob, &host).unwrap_err(),
            PersistentAllError::IntegrityDigestMismatch
        );
        assert_eq!(host.calls(), [ClockCall::Monotonic, ClockCall::Realtime]);
    }

    #[test]
    fn repeated_parses_with_the_same_script_are_deterministic() {
        let blob = VolatileFixture::default().bytes();
        let run = || {
            let host = scripted_clock();
            let clock = parse_recording(&blob, &host).expect("decodes").resume_clock;
            (clock, host.calls())
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn every_strict_prefix_of_the_payload_fails_safely() {
        let payload = VolatileFixture::default().payload();
        for len in (0..payload.len()).step_by(7) {
            let mut blob = payload[..len].to_vec();
            let digest = Sha1::digest(&blob);
            blob.extend_from_slice(&digest);
            assert!(parse(&blob).is_err(), "prefix length {len} decoded");
        }
    }

    #[test]
    fn malformed_single_byte_corruption_never_panics() {
        let blob = VolatileFixture::default().bytes();
        for index in (0..blob.len()).step_by(3) {
            for byte in [0x00u8, 0x01, 0xff] {
                let mut corrupted = blob.clone();
                corrupted[index] = byte;
                let _ = parse(&corrupted);
            }
        }
    }
}
