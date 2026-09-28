// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/NVMarshal.c
// - libtpms/src/tpm2/Volatile.c
//
// Original upstream authors and copyright notices:
// Written by Stefan Berger
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corporation 2017,2018.
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use super::super::clock::{HostClock, adjust_post_resume, tail_v4_monotonic_adjust};
use super::super::live::{RestoredVolatile, power_on_state_clear, power_on_state_reset};
use super::super::marshal::{BlobReader, BlockDisposition, skip_optional_block};
use super::super::nv::OrderlyRamImage;
use super::super::pcr::{PCR_MAGIC, PCR_SLOT_BANKS, PCR_VERSION, PcrSelection};
use super::super::persistent::{
    DRBG_LAST_VALUE_COUNT, DRBG_SEED_SIZE, DRBG_STATE_MAGIC, DRBG_STATE_VERSION,
    ORDERLY_DATA_MAGIC, ORDERLY_DATA_VERSION, OwnedPcrBank, OwnedSecret, OwnedStateClearData,
    OwnedStateResetData, SEED_COMPAT_LEVEL_LAST, SEED_COMPAT_LEVEL_ORIGINAL, StateSection,
    parse_nv_header,
};
use super::super::public::{DIGEST_SIZE, NAME_SIZE, StateFormatLimit, SymDefObject, TPM_ALG_NULL};
use super::super::runtime::Tpm2Runtime;
use super::super::session::{
    EPOCH_CLOCK_SIZE, SESSION_MAGIC, SESSION_SLOT_MAGIC, SESSION_SLOT_VERSION, SESSION_VERSION,
};
use super::super::state::{
    COMMIT_ARRAY_SIZE, MAX_ACTIVE_SESSIONS, NUM_AUTHVALUE_PCR_GROUP, NUM_STATIC_PCR,
    PCR_AUTHVALUE_MAGIC, PCR_AUTHVALUE_VERSION, PCR_BANKS, PCR_SAVE_MAGIC, PCR_SAVE_VERSION,
    PROOF_SIZE, STATE_CLEAR_DATA_MAGIC, STATE_CLEAR_DATA_VERSION, STATE_RESET_DATA_MAGIC,
    STATE_RESET_DATA_VERSION, WIDE_CONTEXT_SLOTS_SINCE_VERSION, algs_active,
};
use super::attach::OwnedSession;
use super::{
    IMPLEMENTATION_PCR, MAX_LOADED_OBJECTS, MAX_LOADED_SESSIONS, MAX_SESSION_NUM,
    PRIMARY_SEED_SIZE, RAM_INDEX_SPACE, SeedTie, TAIL_SINCE_VERSION, TPMA_SESSION_RESERVED, TailV4,
    VOLATILE_STATE_MAGIC, VOLATILE_STATE_VERSION,
};

mod object;

const BLOCK_SKIP_SINCE_VERSION: u16 = 2;
const TAIL_V3_REQUIRED_SINCE_VERSION: u16 = 3;
const TAIL_V4_REQUIRED_SINCE_VERSION: u16 = 4;
const SEED_COMPAT_REQUIRED_SINCE_VERSION: u16 = 3;
const TIMES_ARE_REALTIME_UNTIL_VERSION: u16 = 3;
const NARROW_CONTEXT_SLOT_MASK: u16 = 0x00ff;
const WIDE_CONTEXT_SLOT_MASK: u16 = 0xffff;

#[derive(Clone, Copy)]
pub(in crate::library::tpm2) struct RestoreContext<'a> {
    pub(in crate::library::tpm2) shadow: &'a [PcrSelection<'a>],
    pub(in crate::library::tpm2) seeds: SeedTie<'a>,
    pub(in crate::library::tpm2) state_format: StateFormatLimit,
}

struct Defect;

type Step<T = ()> = Result<T, Defect>;

pub(in crate::library::tpm2) fn restore_until_defect(
    runtime: &mut Tpm2Runtime,
    blob: &[u8],
    context: RestoreContext<'_>,
    clock: &dyn HostClock,
) -> bool {
    let mut walker = Walker {
        reader: BlobReader::new(blob),
        runtime,
        context,
        clock,
    };
    walker.volatile_state().is_ok()
}

struct Walker<'b, 'r, 'c> {
    reader: BlobReader<'b>,
    runtime: &'r mut Tpm2Runtime,
    context: RestoreContext<'c>,
    clock: &'c dyn HostClock,
}

fn header(
    reader: &mut BlobReader<'_>,
    section: StateSection,
    magic: u32,
    version: u16,
) -> Step<u16> {
    parse_nv_header(reader, section, magic, version)
        .map(|header| header.version)
        .map_err(|_| Defect)
}

fn block(reader: &mut BlobReader<'_>, needed: bool) -> Step<bool> {
    match skip_optional_block(reader, needed) {
        Ok(BlockDisposition::Present { .. }) => Ok(true),
        Ok(_) => Ok(false),
        Err(_) => Err(Defect),
    }
}

fn tpm2b_into(reader: &mut BlobReader<'_>, maximum: usize, target: &mut Vec<u8>) -> Step {
    let size = usize::from(reader.read_u16().map_err(|_| Defect)?);
    if size > maximum {
        target.clear();
        return Err(Defect);
    }
    match reader.take(size) {
        Ok(bytes) => {
            *target = bytes.to_vec();
            Ok(())
        }
        Err(_) => {
            target.resize(size, 0);
            Err(Defect)
        }
    }
}

fn secret_into(reader: &mut BlobReader<'_>, maximum: usize, target: &mut OwnedSecret) -> Step {
    let mut bytes = target.as_bytes().to_vec();
    let outcome = tpm2b_into(reader, maximum, &mut bytes);
    *target = OwnedSecret::from_vec(bytes);
    outcome
}

fn carry(runtime: &mut Tpm2Runtime) -> &mut RestoredVolatile {
    runtime
        .restored_volatile
        .get_or_insert_with(RestoredVolatile::power_on)
}

fn clear(runtime: &mut Tpm2Runtime) -> &mut OwnedStateClearData {
    runtime
        .live
        .state_clear
        .get_or_insert_with(power_on_state_clear)
}

fn reset(runtime: &mut Tpm2Runtime) -> &mut OwnedStateResetData {
    let live = &mut runtime.live;
    let (context_slot_mask, null_seed_compat_level) =
        (live.context_slot_mask, live.null_seed_compat_level);
    live.state_reset.get_or_insert_with(|| OwnedStateResetData {
        context_slot_mask,
        null_seed_compat_level,
        ..power_on_state_reset()
    })
}

fn session(runtime: &mut Tpm2Runtime, index: usize) -> &mut OwnedSession {
    runtime.live.sessions[index]
        .session
        .get_or_insert_with(|| OwnedSession {
            attributes: 0,
            pcr_counter: 0,
            start_time: 0,
            timeout: 0,
            epoch: 0,
            command_code: 0,
            auth_hash_alg: 0,
            command_locality: 0,
            symmetric: SymDefObject {
                algorithm: 0,
                key_bits: None,
                mode: None,
            },
            session_key: OwnedSecret::from_vec(Vec::new()),
            nonce_tpm: OwnedSecret::from_vec(Vec::new()),
            bound_entity: Vec::new(),
            audit_digest: Vec::new(),
        })
}

impl Walker<'_, '_, '_> {
    fn u8(&mut self) -> Step<u8> {
        self.reader.read_u8().map_err(|_| Defect)
    }

    fn u16(&mut self) -> Step<u16> {
        self.reader.read_u16().map_err(|_| Defect)
    }

    fn u32(&mut self) -> Step<u32> {
        self.reader.read_u32().map_err(|_| Defect)
    }

    fn u64(&mut self) -> Step<u64> {
        self.reader.read_u64().map_err(|_| Defect)
    }

    fn bool(&mut self) -> Step<bool> {
        self.reader.read_bool().map_err(|_| Defect)
    }

    fn take(&mut self, length: usize) -> Step<Vec<u8>> {
        self.reader
            .take(length)
            .map(<[u8]>::to_vec)
            .map_err(|_| Defect)
    }

    fn header(&mut self, section: StateSection, magic: u32, version: u16) -> Step<u16> {
        header(&mut self.reader, section, magic, version)
    }

    fn block(&mut self, needed: bool) -> Step<bool> {
        block(&mut self.reader, needed)
    }

    fn array_size(&mut self, expected: usize) -> Step {
        if usize::from(self.u16()?) == expected {
            Ok(())
        } else {
            Err(Defect)
        }
    }

    fn volatile_state(&mut self) -> Step {
        let version = self.header(
            StateSection::VolatileState,
            VOLATILE_STATE_MAGIC,
            VOLATILE_STATE_VERSION,
        )?;
        let exclusive_audit_session = self.u32()?;
        carry(self.runtime).exclusive_audit_session = exclusive_audit_session;
        let time = self.u64()?;
        carry(self.runtime).time = time;
        self.runtime.timer.time_ms = time;
        self.runtime.live.ph_enable = self.bool()?;
        self.runtime.live.pcr_reconfig = self.bool()?;
        let drtm_handle = self.u32()?;
        carry(self.runtime).drtm_handle = drtm_handle;
        self.runtime.live.drtm_pre_startup = self.bool()?;
        self.runtime.live.startup_locality3 = self.bool()?;
        self.block(true)?;
        self.runtime.live.da_used = self.bool()?;
        self.runtime.live.power_was_lost = self.bool()?;
        self.runtime.live.prev_orderly_state = self.u16()?;
        self.runtime.live.nv_ok = self.bool()?;
        tpm2b_into(&mut self.reader, DIGEST_SIZE, &mut Vec::new())?;

        self.orderly_data()?;
        self.state_clear_data()?;
        self.state_reset_data()?;

        self.runtime.manufactured = self.bool()?;
        self.runtime.startup_received = self.bool()?;

        self.session_process()?;
        self.block(false)?;
        self.nv()?;
        self.objects()?;
        self.pcrs()?;
        self.sessions()?;

        self.bool()?;
        self.runtime.tpm_established = self.bool()?;

        self.block(true)?;
        self.runtime.failure_diagnostics.function = self.u32()?;
        self.runtime.failure_diagnostics.line = self.u32()?;
        self.runtime.failure_diagnostics.code = self.u32()?;

        self.block(true)?;
        let real_time_previous = self.u64()?;
        self.runtime.timer.real_time_previous = real_time_previous;
        carry(self.runtime).real_time_previous = real_time_previous;
        let tpm_time = self.u64()?;
        self.runtime.timer.tpm_time = tpm_time;
        carry(self.runtime).tpm_time = tpm_time;
        let timer_reset = self.bool()?;
        self.runtime.timer.timer_reset = timer_reset;
        carry(self.runtime).timer_reset = timer_reset;
        let timer_stopped = self.bool()?;
        self.runtime.timer.timer_stopped = timer_stopped;
        carry(self.runtime).timer_stopped = timer_stopped;
        let adjust_rate = self.u32()?;
        self.runtime.timer.adjust_rate = adjust_rate;
        carry(self.runtime).adjust_rate = adjust_rate;
        let backthen = self.u64()?;

        if version >= TAIL_SINCE_VERSION && self.block(version >= TAIL_V3_REQUIRED_SINCE_VERSION)? {
            self.tail_v3()?;
            if self.block(version >= TAIL_V4_REQUIRED_SINCE_VERSION)? {
                self.tail_v4()?;
                self.block(false)?;
            }
        }

        if self.u32()? != VOLATILE_STATE_MAGIC {
            return Err(Defect);
        }
        let times_are_realtime = version <= TIMES_ARE_REALTIME_UNTIL_VERSION;
        adjust_post_resume(
            &mut self.runtime.clock,
            backthen,
            times_are_realtime,
            self.clock,
        );
        let carried = carry(self.runtime);
        carried.header_version = version;
        carried.backthen = backthen;
        carried.times_are_realtime = times_are_realtime;
        Ok(())
    }

    fn orderly_data(&mut self) -> Step {
        let version = self.header(
            StateSection::OrderlyData,
            ORDERLY_DATA_MAGIC,
            ORDERLY_DATA_VERSION,
        )?;
        self.runtime.live.orderly.clock = self.u64()?;
        self.runtime.live.orderly.clock_safe = self.u8()?;
        self.drbg_state()?;
        self.block(true)?;
        self.runtime.live.orderly.self_heal_timer = self.u64()?;
        self.runtime.live.orderly.lockout_timer = self.u64()?;
        self.runtime.live.orderly.time = self.u64()?;
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn drbg_state(&mut self) -> Step {
        let version = self.header(
            StateSection::DrbgState,
            DRBG_STATE_MAGIC,
            DRBG_STATE_VERSION,
        )?;
        self.runtime.live.orderly.drbg_state.reseed_counter = self.u64()?;
        self.runtime.live.orderly.drbg_state.drbg_magic = self.u32()?;
        self.array_size(DRBG_SEED_SIZE)?;
        let seed = self.take(DRBG_SEED_SIZE)?;
        self.runtime.live.orderly.drbg_state.seed = OwnedSecret::from_vec(seed);
        self.array_size(DRBG_LAST_VALUE_COUNT)?;
        for index in 0..DRBG_LAST_VALUE_COUNT {
            self.runtime.live.orderly.drbg_state.last_value[index] = self.u32()?;
        }
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn state_clear_data(&mut self) -> Step {
        let version = self.header(
            StateSection::StateClearData,
            STATE_CLEAR_DATA_MAGIC,
            STATE_CLEAR_DATA_VERSION,
        )?;
        clear(self.runtime).sh_enable = self.bool()?;
        clear(self.runtime).eh_enable = self.bool()?;
        clear(self.runtime).ph_enable_nv = self.bool()?;
        clear(self.runtime).platform_alg = self.u16()?;
        tpm2b_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut clear(self.runtime).platform_policy,
        )?;
        secret_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut clear(self.runtime).platform_auth,
        )?;
        self.pcr_save()?;
        self.pcr_auth_values()?;
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn pcr_save(&mut self) -> Step {
        let version = self.header(StateSection::PcrSave, PCR_SAVE_MAGIC, PCR_SAVE_VERSION)?;
        self.array_size(NUM_STATIC_PCR)?;
        let mut algs_needed = algs_active(self.context.shadow);
        loop {
            let alg = self.u16()?;
            if alg == TPM_ALG_NULL {
                break;
            }
            let Some(bank) = PCR_BANKS.iter().position(|&(bank_alg, _)| bank_alg == alg) else {
                return Err(Defect);
            };
            algs_needed &= !(1u64 << alg);
            let expected = PCR_BANKS[bank].1;
            self.array_size(expected)?;
            let pcrs = self.take(expected)?;
            clear(self.runtime).pcr_save[bank] = Some(OwnedPcrBank {
                hash_alg: alg,
                pcrs,
            });
        }
        if algs_needed != 0 {
            return Err(Defect);
        }
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn pcr_auth_values(&mut self) -> Step {
        let version = self.header(
            StateSection::PcrAuthValue,
            PCR_AUTHVALUE_MAGIC,
            PCR_AUTHVALUE_VERSION,
        )?;
        self.array_size(NUM_AUTHVALUE_PCR_GROUP)?;
        for index in 0..NUM_AUTHVALUE_PCR_GROUP {
            secret_into(
                &mut self.reader,
                DIGEST_SIZE,
                &mut clear(self.runtime).pcr_auth_values[index],
            )?;
        }
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn set_context_slot_mask(&mut self, mask: u16) {
        self.runtime.live.context_slot_mask = mask;
        if let Some(reset) = self.runtime.live.state_reset.as_mut() {
            reset.context_slot_mask = mask;
        }
    }

    fn set_null_seed_compat_level(&mut self, level: u8) {
        self.runtime.live.null_seed_compat_level = level;
        if let Some(reset) = self.runtime.live.state_reset.as_mut() {
            reset.null_seed_compat_level = level;
        }
    }

    fn state_reset_data(&mut self) -> Step {
        let before_compat_level = self.state_reset_fields();
        self.set_null_seed_compat_level(SEED_COMPAT_LEVEL_ORIGINAL);
        let version = before_compat_level?;
        if version >= BLOCK_SKIP_SINCE_VERSION
            && self.block(version >= SEED_COMPAT_REQUIRED_SINCE_VERSION)?
        {
            let level = self.u8()?;
            self.set_null_seed_compat_level(level);
            if level > SEED_COMPAT_LEVEL_LAST {
                return Err(Defect);
            }
            self.block(false)?;
        }
        Ok(())
    }

    fn state_reset_fields(&mut self) -> Step<u16> {
        let version = self.header(
            StateSection::StateResetData,
            STATE_RESET_DATA_MAGIC,
            STATE_RESET_DATA_VERSION,
        )?;
        secret_into(
            &mut self.reader,
            PROOF_SIZE,
            &mut reset(self.runtime).null_proof,
        )?;
        secret_into(
            &mut self.reader,
            PRIMARY_SEED_SIZE,
            &mut reset(self.runtime).null_seed,
        )?;
        reset(self.runtime).clear_count = self.u32()?;
        reset(self.runtime).object_context_id = self.u64()?;
        self.array_size(MAX_ACTIVE_SESSIONS)?;
        if version < WIDE_CONTEXT_SLOTS_SINCE_VERSION {
            let elements = self.narrow_context_array();
            self.set_context_slot_mask(NARROW_CONTEXT_SLOT_MASK);
            elements?;
        } else {
            for index in 0..MAX_ACTIVE_SESSIONS {
                reset(self.runtime).context_array[index] = self.u16()?;
            }
            let mask = self.u16()?;
            self.set_context_slot_mask(mask);
            if mask != WIDE_CONTEXT_SLOT_MASK && mask != NARROW_CONTEXT_SLOT_MASK {
                return Err(Defect);
            }
        }
        reset(self.runtime).context_counter = self.u64()?;
        tpm2b_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut reset(self.runtime).command_audit_digest,
        )?;
        reset(self.runtime).restart_count = self.u32()?;
        reset(self.runtime).pcr_counter = self.u32()?;
        self.block(true)?;
        reset(self.runtime).commit_counter = self.u64()?;
        secret_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut reset(self.runtime).commit_nonce,
        )?;
        self.array_size(COMMIT_ARRAY_SIZE)?;
        let commit_array = self.take(COMMIT_ARRAY_SIZE)?;
        reset(self.runtime)
            .commit_array
            .copy_from_slice(&commit_array);
        Ok(version)
    }

    fn narrow_context_array(&mut self) -> Step {
        for index in 0..MAX_ACTIVE_SESSIONS {
            reset(self.runtime).context_array[index] = u16::from(self.u8()?);
        }
        Ok(())
    }

    fn session_process(&mut self) -> Step {
        self.block(true)?;
        self.array_size(MAX_SESSION_NUM)?;
        for index in 0..MAX_SESSION_NUM {
            let handle = self.u32()?;
            carry(self.runtime).session_process.session_handles[index] = handle;
            let attributes = self.u8()?;
            if attributes & TPMA_SESSION_RESERVED != 0 {
                return Err(Defect);
            }
            carry(self.runtime).session_process.attributes[index] = attributes;
            let associated = self.u32()?;
            carry(self.runtime).session_process.associated_handles[index] = associated;
            secret_into(
                &mut self.reader,
                DIGEST_SIZE,
                &mut carry(self.runtime).session_process.nonce_callers[index],
            )?;
            secret_into(
                &mut self.reader,
                DIGEST_SIZE,
                &mut carry(self.runtime).session_process.input_auth_values[index],
            )?;
        }
        let encrypt = self.u32()?;
        carry(self.runtime).session_process.encrypt_session_index = encrypt;
        let decrypt = self.u32()?;
        carry(self.runtime).session_process.decrypt_session_index = decrypt;
        let audit = self.u32()?;
        carry(self.runtime).session_process.audit_session_index = audit;
        self.block(true)?;
        tpm2b_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut carry(self.runtime)
                .session_process
                .cp_hash_for_command_audit,
        )?;
        let da_pending_on_nv = self.bool()?;
        self.runtime.live.da_pending_on_nv = da_pending_on_nv;
        carry(self.runtime).session_process.da_pending_on_nv = da_pending_on_nv;
        Ok(())
    }

    fn nv(&mut self) -> Step {
        self.block(true)?;
        let evict_nv_end = self.u32()?;
        carry(self.runtime).evict_nv_end = evict_nv_end;
        self.array_size(RAM_INDEX_SPACE)?;
        let index_orderly_ram = self.take(RAM_INDEX_SPACE)?;
        self.runtime.live.index_orderly_ram =
            OrderlyRamImage::from_bytes(&index_orderly_ram).ok_or(Defect)?;
        let max_counter = self.u64()?;
        carry(self.runtime).max_counter = max_counter;
        self.runtime.live.max_nv_counter = max_counter;
        Ok(())
    }

    fn objects(&mut self) -> Step {
        self.block(true)?;
        self.array_size(MAX_LOADED_OBJECTS)?;
        for index in 0..MAX_LOADED_OBJECTS {
            object::any_object_into(
                &mut self.reader,
                &mut self.runtime.live.objects[index],
                self.context.state_format,
            )?;
        }
        Ok(())
    }

    fn pcrs(&mut self) -> Step {
        self.block(true)?;
        self.array_size(IMPLEMENTATION_PCR)?;
        for index in 0..IMPLEMENTATION_PCR {
            self.pcr(index)?;
        }
        Ok(())
    }

    fn pcr(&mut self, index: usize) -> Step {
        let version = self.header(StateSection::Pcr, PCR_MAGIC, PCR_VERSION)?;
        let mut algs_needed = algs_active(self.context.shadow);
        loop {
            let alg = self.u16()?;
            if alg == TPM_ALG_NULL {
                break;
            }
            let Some(bank) = PCR_SLOT_BANKS
                .iter()
                .position(|&(bank_alg, _)| bank_alg == alg)
            else {
                return Err(Defect);
            };
            algs_needed &= !(1u64 << alg);
            let expected = PCR_SLOT_BANKS[bank].1;
            self.array_size(expected)?;
            let digest = self.take(expected)?;
            self.runtime.live.pcrs[index].banks[bank] = Some(digest);
        }
        if algs_needed != 0 {
            return Err(Defect);
        }
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn sessions(&mut self) -> Step {
        self.block(true)?;
        self.array_size(MAX_LOADED_SESSIONS)?;
        for index in 0..MAX_LOADED_SESSIONS {
            self.session_slot(index)?;
        }
        self.runtime.live.oldest_saved_session = self.u32()?;
        self.runtime.live.free_session_slots = self.u32()?;
        Ok(())
    }

    fn session_slot(&mut self, index: usize) -> Step {
        let version = self.header(
            StateSection::SessionSlot,
            SESSION_SLOT_MAGIC,
            SESSION_SLOT_VERSION,
        )?;
        let occupied = self.bool()?;
        self.runtime.live.sessions[index].occupied = occupied;
        if !occupied {
            self.runtime.live.sessions[index].session = None;
            return Ok(());
        }
        session(self.runtime, index);
        self.session(index)?;
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn session(&mut self, index: usize) -> Step {
        let version = self.header(StateSection::Session, SESSION_MAGIC, SESSION_VERSION)?;
        session(self.runtime, index).attributes = self.u32()?;
        session(self.runtime, index).pcr_counter = self.u32()?;
        session(self.runtime, index).start_time = self.u64()?;
        session(self.runtime, index).timeout = self.u64()?;
        if self.u8()? != EPOCH_CLOCK_SIZE {
            return Err(Defect);
        }
        session(self.runtime, index).epoch = self.u32()?;
        session(self.runtime, index).command_code = self.u32()?;
        session(self.runtime, index).auth_hash_alg = self.u16()?;
        session(self.runtime, index).command_locality = self.u8()?;
        object::sym_def_into(
            &mut self.reader,
            &mut session(self.runtime, index).symmetric,
            true,
            true,
            self.context.state_format,
        )?;
        secret_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut session(self.runtime, index).session_key,
        )?;
        secret_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut session(self.runtime, index).nonce_tpm,
        )?;
        tpm2b_into(
            &mut self.reader,
            NAME_SIZE,
            &mut session(self.runtime, index).bound_entity,
        )?;
        tpm2b_into(
            &mut self.reader,
            DIGEST_SIZE,
            &mut session(self.runtime, index).audit_digest,
        )?;
        if version >= BLOCK_SKIP_SINCE_VERSION {
            self.block(false)?;
        }
        Ok(())
    }

    fn tail_v3(&mut self) -> Step {
        let seeds = self.context.seeds;
        for expected in [seeds.ep_seed, seeds.sp_seed, seeds.pp_seed] {
            let mut seed = Vec::new();
            tpm2b_into(&mut self.reader, PRIMARY_SEED_SIZE, &mut seed)?;
            if seed != expected {
                return Err(Defect);
            }
        }
        Ok(())
    }

    fn tail_v4(&mut self) -> Step {
        let host_monotonic_sample = self.u64()?;
        self.runtime.clock.host_monotonic_adjust_ms =
            tail_v4_monotonic_adjust(host_monotonic_sample, self.clock);
        self.runtime.clock.suspended_elapsed_ms = self.u64()?;
        self.runtime.clock.last_system_time_ms = self.u64()?;
        self.runtime.clock.last_reported_time_ms = self.u64()?;
        let tail = TailV4 {
            host_monotonic_sample,
            suspended_elapsed_time: self.runtime.clock.suspended_elapsed_ms,
            last_system_time: self.runtime.clock.last_system_time_ms,
            last_reported_time: self.runtime.clock.last_reported_time_ms,
        };
        carry(self.runtime).tail_v4 = Some(tail);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::clock::{RecordingClock, time_power_on};
    use crate::library::tpm2::golden_responses::get_test_result::vector;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::object::fixtures::any_rsa_object;
    use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody, OwnedPublicId};
    use crate::library::tpm2::public::{PublicParms, TPM_ALG_ECC, TPM_ALG_RSA};
    use crate::library::tpm2::runtime::empty_state_runtime;
    use crate::library::tpm2::state::StateResetFixture;
    use crate::library::tpm2::volatile::attach::resumable_sequence;
    use crate::library::tpm2::volatile::{
        SHA1_DIGEST_SIZE, UnmarshalledBlob, VolatileFixture, unmarshal_volatile_state_blob,
        volatile_all_store,
    };
    use crate::library::tpm2::{load_volatile_blob, restore_permanent_blob_for_test};

    fn host() -> RecordingClock {
        RecordingClock::new(1_767_225_600_000, 1_000_000)
    }

    struct Boundary {
        seeds: [Vec<u8>; 3],
        shadow: Vec<(u16, Vec<u8>)>,
        state_format: StateFormatLimit,
    }

    impl Boundary {
        fn of(runtime: &Tpm2Runtime) -> Self {
            let state = runtime.state();
            Self {
                seeds: [
                    state.persistent.ep_seed.as_bytes().to_vec(),
                    state.persistent.sp_seed.as_bytes().to_vec(),
                    state.persistent.pp_seed.as_bytes().to_vec(),
                ],
                shadow: runtime
                    .shadow_pcr_allocated
                    .selections
                    .iter()
                    .map(|selection| (selection.hash_alg, selection.select.clone()))
                    .collect(),
                state_format: StateFormatLimit::new(state.profile.state_format_level),
            }
        }

        fn fixture() -> Self {
            let seeds = VolatileFixture::seed_tie();
            Self {
                seeds: [
                    seeds.ep_seed.to_vec(),
                    seeds.sp_seed.to_vec(),
                    seeds.pp_seed.to_vec(),
                ],
                shadow: Vec::new(),
                state_format: StateFormatLimit::CURRENT,
            }
        }

        fn walk(&self, runtime: &mut Tpm2Runtime, blob: &[u8], clock: &RecordingClock) -> bool {
            let shadow: Vec<PcrSelection<'_>> = self
                .shadow
                .iter()
                .map(|(hash_alg, select)| PcrSelection {
                    hash_alg: *hash_alg,
                    select,
                })
                .collect();
            restore_until_defect(
                runtime,
                blob,
                RestoreContext {
                    shadow: &shadow,
                    seeds: SeedTie {
                        ep_seed: &self.seeds[0],
                        sp_seed: &self.seeds[1],
                        pp_seed: &self.seeds[2],
                    },
                    state_format: self.state_format,
                },
                clock,
            )
        }

        fn decodes(&self, blob: &[u8], clock: &RecordingClock) -> bool {
            let shadow: Vec<PcrSelection<'_>> = self
                .shadow
                .iter()
                .map(|(hash_alg, select)| PcrSelection {
                    hash_alg: *hash_alg,
                    select,
                })
                .collect();
            let seeds = SeedTie {
                ep_seed: &self.seeds[0],
                sp_seed: &self.seeds[1],
                pp_seed: &self.seeds[2],
            };
            match unmarshal_volatile_state_blob(blob, &shadow, seeds, clock, self.state_format) {
                Ok(
                    UnmarshalledBlob::Verified(decoded) | UnmarshalledBlob::Unverified(decoded, _),
                ) => decoded
                    .objects
                    .iter()
                    .all(|object| resumable_sequence(object.attributes, &object.body)),
                Err(_) => false,
            }
        }
    }

    const GOLDEN_STATES: [(&str, &str); 5] = [
        ("PERMALL_BUSY", "VOLATILE_BUSY"),
        ("PERMALL_FAILURE_ENTRY", "VOLATILE_FAILURE_ENTRY"),
        ("PERMALL_ORDERLY", "VOLATILE_ORDERLY"),
        ("PERMALL_PARTS", "VOLATILE_PARTS"),
        ("PERMALL_SEQUENCES", "VOLATILE_SEQUENCES"),
    ];

    #[test]
    fn walking_a_complete_blob_restores_what_the_merge_restores() {
        for (permanent, volatile) in GOLDEN_STATES {
            let clock = host();
            let mut merged = restore_permanent_blob_for_test(vector(permanent)).unwrap();
            load_volatile_blob(&mut merged, vector(volatile), &clock);

            let mut walked = restore_permanent_blob_for_test(vector(permanent)).unwrap();
            let boundary = Boundary::of(&walked);
            time_power_on(&mut walked, &clock);
            assert!(
                boundary.walk(&mut walked, vector(volatile), &clock),
                "{volatile}"
            );
            walked.failure_mode = merged.failure_mode;

            assert_eq!(
                volatile_all_store(&walked, &clock).unwrap(),
                volatile_all_store(&merged, &clock).unwrap(),
                "{volatile}"
            );
            assert_eq!(walked.manufactured, merged.manufactured, "{volatile}");
            assert_eq!(
                walked.startup_received, merged.startup_received,
                "{volatile}"
            );
        }
    }

    #[test]
    fn the_walk_stops_wherever_the_decoder_rejects_a_blob() {
        for (permanent, volatile) in GOLDEN_STATES {
            let clock = host();
            let base = restore_permanent_blob_for_test(vector(permanent)).unwrap();
            let boundary = Boundary::of(&base);
            let blob = vector(volatile);
            let mut runtime = empty_state_runtime();
            for at in 0..blob.len() - SHA1_DIGEST_SIZE {
                let mut corrupted = blob.to_vec();
                corrupted[at] ^= 0xff;
                assert_eq!(
                    boundary.walk(&mut runtime, &corrupted, &clock),
                    boundary.decodes(&corrupted, &clock),
                    "{volatile}: byte {at} flipped"
                );
            }
        }
    }

    #[test]
    fn a_newer_hash_state_header_only_stops_the_walk_without_a_sha_state() {
        let clock = host();
        let base = restore_permanent_blob_for_test(vector("PERMALL_SEQUENCES")).unwrap();
        let boundary = Boundary::of(&base);
        for (min_version, walks) in [(4183, true), (4591, false)] {
            let mut blob = vector("VOLATILE_SEQUENCES").to_vec();
            blob[min_version..min_version + 2].copy_from_slice(&3u16.to_be_bytes());
            let payload = blob.len() - SHA1_DIGEST_SIZE;
            let digest = <sha1::Sha1 as sha1::Digest>::digest(&blob[..payload]);
            blob[payload..].copy_from_slice(&digest);
            let mut runtime = empty_state_runtime();
            assert_eq!(
                boundary.walk(&mut runtime, &blob, &clock),
                walks,
                "{min_version}"
            );
            assert_eq!(boundary.decodes(&blob, &clock), walks, "{min_version}");
        }
    }

    #[test]
    fn a_truncated_blob_never_walks_to_its_end() {
        let clock = host();
        let base = restore_permanent_blob_for_test(vector("PERMALL_BUSY")).unwrap();
        let boundary = Boundary::of(&base);
        let blob = vector("VOLATILE_BUSY");
        let mut runtime = empty_state_runtime();
        for length in (0..blob.len() - SHA1_DIGEST_SIZE).step_by(7) {
            assert!(
                !boundary.walk(&mut runtime, &blob[..length], &clock),
                "{length}"
            );
        }
    }

    fn fixture_with_reset(reset: StateResetFixture) -> Vec<u8> {
        VolatileFixture {
            state_reset: reset.bytes(),
            ..VolatileFixture::default()
        }
        .payload()
    }

    fn state_reset_offset(payload: &[u8]) -> usize {
        let marker = STATE_RESET_DATA_MAGIC.to_be_bytes();
        payload
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("the payload carries STATE_RESET_DATA")
            - 2
    }

    #[test]
    fn the_context_slot_mask_is_stored_before_it_is_checked() {
        let payload = fixture_with_reset(StateResetFixture {
            context_slot_mask: 0x1234,
            context_counter: 0x77,
            ..StateResetFixture::default()
        });
        let mut runtime = empty_state_runtime();
        assert!(!Boundary::fixture().walk(&mut runtime, &payload, &host()));
        assert_eq!(runtime.live.context_slot_mask, 0x1234);
        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.context_slot_mask, 0x1234);
        assert_eq!(
            reset.context_counter, 0,
            "nothing after the mask is restored"
        );
    }

    #[test]
    fn any_defect_in_state_reset_data_clears_the_null_seed_compat_level() {
        let payload = fixture_with_reset(StateResetFixture {
            null_proof: vec![0x0f; 16],
            null_seed_compat_level: 1,
            ..StateResetFixture::default()
        });
        let cut = state_reset_offset(&payload) + 8 + 2 + 5;
        let mut runtime = empty_state_runtime();
        runtime.live.null_seed_compat_level = 1;
        assert!(!Boundary::fixture().walk(&mut runtime, &payload[..cut], &host()));
        assert_eq!(runtime.live.null_seed_compat_level, 0);
        let reset = runtime.live.state_reset.as_ref().unwrap();
        assert_eq!(reset.null_seed_compat_level, 0);
        assert_eq!(
            reset.null_proof.expose(),
            &[0u8; 16][..],
            "the size is stored before the bytes it announces"
        );
    }

    #[test]
    fn a_complete_state_reset_data_restores_its_compat_level() {
        let payload = fixture_with_reset(StateResetFixture {
            null_seed_compat_level: 1,
            ..StateResetFixture::default()
        });
        let mut runtime = empty_state_runtime();
        assert!(Boundary::fixture().walk(&mut runtime, &payload, &host()));
        assert_eq!(runtime.live.null_seed_compat_level, 1);
    }

    #[test]
    fn session_attributes_with_reserved_bits_are_never_stored() {
        let mut fixture = VolatileFixture::default();
        fixture.session_entries[0].1 = TPMA_SESSION_RESERVED;
        let mut runtime = empty_state_runtime();
        assert!(!Boundary::fixture().walk(&mut runtime, &fixture.payload(), &host()));
        let process = &runtime.restored_volatile.as_ref().unwrap().session_process;
        assert_eq!(process.session_handles[0], fixture.session_entries[0].0);
        assert_eq!(process.attributes[0], 0);
        assert_eq!(process.associated_handles[0], 0);
    }

    fn walk_objects(objects: Vec<Vec<u8>>, cut: impl Fn(&[u8], usize) -> usize) -> Tpm2Runtime {
        let fixture = VolatileFixture {
            objects,
            ..VolatileFixture::default()
        };
        let payload = fixture.payload();
        let object = &fixture.objects[0];
        let at = payload
            .windows(object.len())
            .position(|window| window == object.as_slice())
            .expect("the payload carries the object");
        let mut runtime = empty_state_runtime();
        assert!(!Boundary::fixture().walk(&mut runtime, &payload[..cut(object, at)], &host()));
        runtime
    }

    fn unoccupied() -> Vec<u8> {
        crate::library::tpm2::object::fixtures::any_unoccupied_object()
    }

    fn object_in(runtime: &Tpm2Runtime, slot: usize) -> &OwnedObjectBody {
        match &runtime.live.objects[slot].body {
            OwnedAnyObjectBody::Object(body) => body,
            _ => panic!("slot {slot} holds no object body"),
        }
    }

    const OBJECT_START: usize = 8 + 4 + 8;
    const RSA_PUBLIC_LEN: usize = 282;

    #[test]
    fn a_loaded_object_cut_short_keeps_the_fields_it_wrote() {
        let runtime = walk_objects(
            vec![any_rsa_object(4), unoccupied(), unoccupied()],
            |_, at| at + OBJECT_START + RSA_PUBLIC_LEN + 2 + 2 + 1,
        );
        assert_eq!(runtime.live.max_nv_counter, 42, "the NV block precedes it");
        assert_eq!(runtime.live.objects[0].attributes, ATTR_OCCUPIED);
        let body = object_in(&runtime, 0);
        assert_eq!(body.public.object_type, TPM_ALG_RSA);
        assert!(matches!(
            body.public.parameters,
            PublicParms::Rsa {
                key_bits: 2048,
                exponent: 65537,
                ..
            }
        ));
        assert_eq!(body.public.unique, OwnedPublicId::Rsa(vec![0xab; 256]));
        assert_eq!(body.sensitive.sensitive_type, TPM_ALG_RSA);
        assert_eq!(
            body.sensitive.auth_value.expose(),
            &[0u8; 4][..],
            "the size is stored before the bytes it announces"
        );
        assert!(body.sensitive.seed_value.expose().is_empty());
        assert_eq!(
            body.sensitive
                .sensitive
                .as_ref()
                .map(|key| key.expose().len()),
            Some(0)
        );
        assert!(body.private_exponent.is_none());
        assert!(body.qualified_name.is_empty() && body.name.is_empty());
        assert_eq!(body.seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(
            body.hierarchy, None,
            "the hierarchy defaults to the attributes"
        );
        assert_eq!(runtime.live.objects[1].attributes, 0);
    }

    #[test]
    fn an_object_cut_after_its_attributes_is_occupied_with_defaults() {
        let runtime = walk_objects(
            vec![any_rsa_object(4), unoccupied(), unoccupied()],
            |_, at| at + 8 + 4,
        );
        assert_eq!(runtime.live.objects[0].attributes, ATTR_OCCUPIED);
        let body = object_in(&runtime, 0);
        assert_eq!(body.public.object_type, 0);
        assert_eq!(body.public.parameters, PublicParms::Unselected);
        assert_eq!(body.public.unique, OwnedPublicId::Unselected);
        assert_eq!(body.seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);
        assert_eq!(body.hierarchy, None);
    }

    #[test]
    fn an_object_seed_compat_level_is_stored_before_it_is_checked() {
        let runtime = walk_objects(
            vec![any_rsa_object(4), unoccupied(), unoccupied()],
            |object, at| at + object.len() - 3 - 4 - 3 - 1,
        );
        let body = object_in(&runtime, 0);
        assert_eq!(body.name, vec![0x52; 34]);
        assert_eq!(body.seed_compat_level, SEED_COMPAT_LEVEL_ORIGINAL);

        let mut object = any_rsa_object(4);
        let level = object.len() - 3 - 4 - 3 - 1;
        object[level] = 7;
        let fixture = VolatileFixture {
            objects: vec![object, unoccupied(), unoccupied()],
            ..VolatileFixture::default()
        };
        let mut runtime = empty_state_runtime();
        assert!(!Boundary::fixture().walk(&mut runtime, &fixture.payload(), &host()));
        let body = object_in(&runtime, 0);
        assert_eq!(body.seed_compat_level, 7);
        assert_eq!(body.hierarchy, None);
    }

    #[test]
    fn an_ecc_parameter_defect_restores_every_ecc_parameter() {
        use crate::library::tpm2::object::fixtures::any_public_only_object;
        use crate::library::tpm2::public::fixtures::ecc_public;

        let mut public = ecc_public();
        let curve = 2 + 2 + 4 + 2 + 2 + 4;
        public[curve..curve + 2].copy_from_slice(&0x00fcu16.to_be_bytes());
        let fixture = VolatileFixture {
            objects: vec![any_public_only_object(&public), unoccupied(), unoccupied()],
            ..VolatileFixture::default()
        };
        let mut runtime = empty_state_runtime();
        assert!(!Boundary::fixture().walk(&mut runtime, &fixture.payload(), &host()));
        let body = object_in(&runtime, 0);
        assert_eq!(body.public.object_type, TPM_ALG_ECC);
        assert_eq!(
            body.public.parameters,
            PublicParms::selected_by(TPM_ALG_ECC)
        );
    }

    #[test]
    fn a_prime_cut_between_words_repeats_the_last_word_read() {
        use crate::library::tpm2::object::{BN_PRIME_T_MAGIC, BN_PRIME_T_VERSION};

        let mut object = any_rsa_object(4);
        let prime = object
            .windows(4)
            .position(|window| window == BN_PRIME_T_MAGIC.to_be_bytes())
            .expect("the object carries a prime")
            - 2;
        assert_eq!(object[prime..prime + 2], BN_PRIME_T_VERSION.to_be_bytes());
        let words = prime + 8 + 2;
        for (index, word) in [0x1111_1111u32, 0x2222_2222, 0x3333_3333]
            .iter()
            .enumerate()
        {
            object[words + 4 * index..words + 4 * index + 4].copy_from_slice(&word.to_be_bytes());
        }
        let cut = words + 12;
        let runtime = walk_objects(vec![object, unoccupied(), unoccupied()], move |_, at| {
            at + cut
        });
        let body = object_in(&runtime, 0);
        let q = &body
            .private_exponent
            .as_ref()
            .expect("the block was entered")
            .primes[0];
        assert_eq!(q.numbytes, 96);
        assert_eq!(q.data.expose().len(), 96);
        let data: Vec<u64> = q
            .data
            .expose()
            .chunks(8)
            .map(|word| u64::from_be_bytes(word.try_into().unwrap()))
            .collect();
        assert_eq!(data[0], 0x1111_1111_2222_2222);
        assert_eq!(data[1], 0x3333_3333_3333_3333);
        assert!(data[2..].iter().all(|&word| word == 0));
    }

    #[test]
    fn session_symmetric_fields_are_stored_as_they_are_read() {
        use crate::library::tpm2::session::{SessionFixture, SessionSlotFixture};

        for (symmetric, cut_after, expected) in [
            (
                vec![0x00, 0x06, 0x00, 0x80, 0x00, 0x43],
                Some(2),
                SymDefObject {
                    algorithm: 0x0006,
                    key_bits: Some(0),
                    mode: Some(0),
                },
            ),
            (
                vec![0x00, 0x06, 0x00, 0x7f, 0x00, 0x43],
                None,
                SymDefObject {
                    algorithm: 0x0006,
                    key_bits: Some(0),
                    mode: Some(0),
                },
            ),
            (
                vec![0x00, 0x06, 0x00, 0x80, 0x00, 0xbc],
                None,
                SymDefObject {
                    algorithm: 0x0006,
                    key_bits: Some(128),
                    mode: Some(0),
                },
            ),
            (
                vec![0x00, 0x0a, 0x00, 0xf4],
                None,
                SymDefObject {
                    algorithm: 0x000a,
                    key_bits: Some(0),
                    mode: None,
                },
            ),
            (
                vec![0x00, 0xf9, 0x00, 0x80, 0x00, 0x43],
                None,
                SymDefObject::UNSELECTED,
            ),
        ] {
            let session = SessionFixture {
                symmetric: symmetric.clone(),
                ..SessionFixture::default()
            };
            let mut fixture = VolatileFixture::default();
            fixture.session_slots[0] = SessionSlotFixture {
                occupied: 1,
                session: session.bytes(),
                ..SessionSlotFixture::default()
            }
            .bytes();
            let payload = fixture.payload();
            let at = payload
                .windows(symmetric.len() + 2)
                .position(|window| {
                    window[..symmetric.len()] == symmetric[..]
                        && window[symmetric.len()..] == [0x00, 0x20]
                })
                .expect("the payload carries the symmetric definition");
            let end = cut_after.map_or(payload.len(), |cut| at + cut);
            let mut runtime = empty_state_runtime();
            assert!(!Boundary::fixture().walk(&mut runtime, &payload[..end], &host()));
            let restored = runtime.live.sessions[0]
                .session
                .as_ref()
                .expect("the slot is occupied");
            assert_eq!(restored.symmetric, expected, "{symmetric:02x?}");
        }
    }
}
