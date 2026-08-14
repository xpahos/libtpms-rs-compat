use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::PERSISTENT_ALL_MAGIC;
use super::attach::{
    OwnedCommandBitmap, OwnedIndexOrderlyRam, OwnedOrderlyData, OwnedPcrAllocation,
    OwnedPersistentData, OwnedPersistentState, OwnedStateClearData, OwnedStateResetData,
    OwnedUserNvram, OwnedUserNvramEntry,
};
use super::compat_tail::SEED_COMPAT_LEVEL_ORIGINAL;
use super::data::PERSISTENT_DATA_MAGIC;
use super::orderly::{DRBG_STATE_MAGIC, ORDERLY_DATA_MAGIC};
use crate::library::tpm2::compile_constants;
use crate::library::tpm2::nv::{
    COMPRESSED_COMMAND_BITS, INDEX_ORDERLY_RAM_MAGIC, NATIVE_SIZEOF_NV_INDEX, NV_INDEX_MAGIC,
    NV_RAM_HEADER_SIZE, RAM_INDEX_SPACE, USER_NVRAM_CAPACITY, USER_NVRAM_MAGIC, WireWriter,
    any_object_image, command_bitmap_image,
};
use crate::library::tpm2::pcr::{NUM_POLICY_PCR_GROUP, PCR_POLICY_MAGIC};
use crate::library::tpm2::profile::enabled_command_count;
use crate::library::tpm2::runtime::format_active_profile;
use crate::library::tpm2::state::{
    MAX_ACTIVE_SESSIONS, NUM_AUTHVALUE_PCR_GROUP, NUM_STATIC_PCR, PCR_AUTHVALUE_MAGIC, PCR_BANKS,
    PCR_SAVE_MAGIC, STATE_CLEAR_DATA_MAGIC, STATE_RESET_DATA_MAGIC,
};
use crate::library::tpm2::{TPM_SU_STATE, TPM_SU_STATE_MASK};

const PCR_POLICY_VERSION: u16 = 2;
const ORDERLY_DATA_VERSION: u16 = 2;
const DRBG_STATE_VERSION: u16 = 2;
const STATE_RESET_DATA_VERSION: u16 = 4;
const STATE_CLEAR_DATA_VERSION: u16 = 2;
const PCR_SAVE_VERSION: u16 = 2;
const PCR_AUTHVALUE_VERSION: u16 = 2;
const INDEX_ORDERLY_RAM_VERSION: u16 = 2;
const USER_NVRAM_VERSION: u16 = 2;
const NV_INDEX_VERSION: u16 = 2;
const PA_COMPILE_CONSTANTS_VERSION: u16 = 3;

const TPM_ALG_NULL: u16 = 0x0010;

const COMPRESSED_LIST_COMMANDS: u32 = 110;

fn marshal_pcr_allocation(w: &mut WireWriter, allocation: &OwnedPcrAllocation) {
    w.u32(allocation.selections.len() as u32);
    for selection in &allocation.selections {
        w.u16(selection.hash_alg);
        w.u8(selection.select.len() as u8);
        w.bytes(&selection.select);
    }
}

fn compress_command_bitmap(image: &[u8], array_size: usize) -> Result<Vec<u8>, TpmResult> {
    let mut out = vec![0u8; array_size];
    for bit in 0..image.len() * 8 {
        if image[bit / 8] & (1 << (bit % 8)) == 0 {
            continue;
        }
        let compressed = COMPRESSED_COMMAND_BITS
            .iter()
            .position(|&build_bit| usize::from(build_bit) == bit)
            .ok_or(TPM_FAIL)?;
        if compressed >= array_size * 8 {
            return Err(TPM_FAIL);
        }
        out[compressed / 8] |= 1 << (compressed % 8);
    }
    Ok(out)
}

fn marshal_command_bitmap(
    w: &mut WireWriter,
    bitmap: &OwnedCommandBitmap,
    capacity: usize,
    section_version: u16,
    command_count: u32,
) -> Result<(), TpmResult> {
    let image = command_bitmap_image(bitmap, capacity)?;
    if section_version <= 4 {
        let array_size = (command_count as usize).div_ceil(8);
        let compressed = compress_command_bitmap(&image, array_size)?;
        w.u16(array_size as u16);
        w.bytes(&compressed);
    } else {
        w.u16(capacity as u16);
        w.bytes(&image);
    }
    Ok(())
}

fn marshal_persistent_data(
    w: &mut WireWriter,
    data: &OwnedPersistentData,
    section_version: u16,
    command_count: u32,
) -> Result<(), TpmResult> {
    w.nv_header(section_version, PERSISTENT_DATA_MAGIC, section_version);
    w.u8(u8::from(data.disable_clear));
    w.u16(data.owner_alg);
    w.u16(data.endorsement_alg);
    w.u16(data.lockout_alg);
    w.tpm2b(&data.owner_policy)?;
    w.tpm2b(&data.endorsement_policy)?;
    w.tpm2b(&data.lockout_policy)?;
    w.tpm2b(data.owner_auth.as_bytes())?;
    w.tpm2b(data.endorsement_auth.as_bytes())?;
    w.tpm2b(data.lockout_auth.as_bytes())?;
    w.tpm2b(data.ep_seed.as_bytes())?;
    w.tpm2b(data.sp_seed.as_bytes())?;
    w.tpm2b(data.pp_seed.as_bytes())?;
    w.tpm2b(data.ph_proof.as_bytes())?;
    w.tpm2b(data.sh_proof.as_bytes())?;
    w.tpm2b(data.eh_proof.as_bytes())?;
    w.u64(data.total_reset_count);
    w.u32(data.reset_count);

    w.block(true, |w| {
        w.nv_header(PCR_POLICY_VERSION, PCR_POLICY_MAGIC, 1);
        w.u16(NUM_POLICY_PCR_GROUP as u16);
        for policy in &data.pcr_policies {
            w.u16(policy.hash_alg);
            w.tpm2b(&policy.policy)?;
        }
        w.block(true, |_| Ok(()))
    })?;

    marshal_pcr_allocation(w, &data.pcr_allocated);
    marshal_command_bitmap(w, &data.pp_list, 17, section_version, command_count)?;

    w.u32(data.failed_tries);
    w.u32(data.max_tries);
    w.u32(data.recovery_time);
    w.u32(data.lockout_recovery);
    w.u8(u8::from(data.lockout_auth_enabled));
    w.u16(data.orderly_state);

    marshal_command_bitmap(w, &data.audit_commands, 17, section_version, command_count)?;
    w.u16(data.audit_hash_alg);
    w.u64(data.audit_counter);
    w.u32(data.algorithm_set);
    w.u32(data.firmware_v1);
    w.u32(data.firmware_v2);
    w.u8(4);
    w.u32(data.time_epoch);

    w.block(true, |w| {
        marshal_pcr_allocation(w, &data.pcr_allocated);
        w.block(true, |w| {
            w.u8(data.ep_seed_compat_level);
            w.u8(data.sp_seed_compat_level);
            w.u8(data.pp_seed_compat_level);
            w.block(true, |_| Ok(()))
        })
    })
}

pub(in crate::library::tpm2) fn marshal_orderly_data(
    w: &mut WireWriter,
    data: &OwnedOrderlyData,
) -> Result<(), TpmResult> {
    w.nv_header(ORDERLY_DATA_VERSION, ORDERLY_DATA_MAGIC, 1);
    w.u64(data.clock);
    w.u8(data.clock_safe);

    w.nv_header(DRBG_STATE_VERSION, DRBG_STATE_MAGIC, 1);
    w.u64(data.drbg_state.reseed_counter);
    w.u32(data.drbg_state.drbg_magic);
    w.u16(data.drbg_state.seed.as_bytes().len() as u16);
    w.bytes(data.drbg_state.seed.as_bytes());
    w.u16(data.drbg_state.last_value.len() as u16);
    for value in data.drbg_state.last_value {
        w.u32(value);
    }
    w.block(true, |_| Ok(()))?;

    w.block(true, |w| {
        w.u64(data.self_heal_timer);
        w.u64(data.lockout_timer);
        w.u64(data.time);
        Ok(())
    })?;
    w.block(true, |_| Ok(()))
}

pub(in crate::library::tpm2) fn marshal_state_reset(
    w: &mut WireWriter,
    data: &OwnedStateResetData,
    null_seed_compat_level: u8,
) -> Result<(), TpmResult> {
    w.nv_header(STATE_RESET_DATA_VERSION, STATE_RESET_DATA_MAGIC, 4);
    w.tpm2b(data.null_proof.as_bytes())?;
    w.tpm2b(data.null_seed.as_bytes())?;
    w.u32(data.clear_count);
    w.u64(data.object_context_id);
    w.u16(MAX_ACTIVE_SESSIONS as u16);
    for slot in data.context_array.iter() {
        w.u16(*slot);
    }
    let mask = match data.context_slot_mask {
        0x00ff | 0xffff => data.context_slot_mask,
        _ => 0xffff,
    };
    w.u16(mask);
    w.u64(data.context_counter);
    w.tpm2b(&data.command_audit_digest)?;
    w.u32(data.restart_count);
    w.u32(data.pcr_counter);
    w.block(true, |w| {
        w.u64(data.commit_counter);
        w.tpm2b(data.commit_nonce.as_bytes())?;
        w.u16(data.commit_array.len() as u16);
        w.bytes(&data.commit_array);
        Ok(())
    })?;
    w.block(true, |w| {
        w.u8(null_seed_compat_level);
        w.block(true, |_| Ok(()))
    })
}

pub(in crate::library::tpm2) fn marshal_state_clear(
    w: &mut WireWriter,
    data: &OwnedStateClearData,
) -> Result<(), TpmResult> {
    w.nv_header(STATE_CLEAR_DATA_VERSION, STATE_CLEAR_DATA_MAGIC, 1);
    w.u8(u8::from(data.sh_enable));
    w.u8(u8::from(data.eh_enable));
    w.u8(u8::from(data.ph_enable_nv));
    w.u16(data.platform_alg);
    w.tpm2b(&data.platform_policy)?;
    w.tpm2b(data.platform_auth.as_bytes())?;

    w.nv_header(PCR_SAVE_VERSION, PCR_SAVE_MAGIC, 1);
    w.u16(NUM_STATIC_PCR as u16);
    for (index, &(alg, size)) in PCR_BANKS.iter().enumerate() {
        w.u16(alg);
        w.u16(size as u16);
        match &data.pcr_save[index] {
            Some(bank) => {
                if bank.pcrs.len() != size {
                    return Err(TPM_FAIL);
                }
                w.bytes(&bank.pcrs);
            }
            None => w.bytes(&vec![0u8; size]),
        }
    }
    w.u16(TPM_ALG_NULL);
    w.block(true, |_| Ok(()))?;

    w.nv_header(PCR_AUTHVALUE_VERSION, PCR_AUTHVALUE_MAGIC, 1);
    w.u16(NUM_AUTHVALUE_PCR_GROUP as u16);
    for auth in &data.pcr_auth_values {
        w.tpm2b(auth.as_bytes())?;
    }
    w.block(true, |_| Ok(()))?;

    w.block(true, |_| Ok(()))
}

fn marshal_index_orderly_ram(
    w: &mut WireWriter,
    ram: &OwnedIndexOrderlyRam,
) -> Result<(), TpmResult> {
    w.nv_header(INDEX_ORDERLY_RAM_VERSION, INDEX_ORDERLY_RAM_MAGIC, 1);
    w.u32(RAM_INDEX_SPACE as u32);
    let mut offset: u64 = 0;
    for entry in &ram.entries {
        let size = NV_RAM_HEADER_SIZE + entry.data.len() as u64;
        w.u32(u32::try_from(size).map_err(|_| TPM_FAIL)?);
        w.u32(entry.handle);
        w.u32(entry.attributes);
        w.u16(u16::try_from(entry.data.len()).map_err(|_| TPM_FAIL)?);
        w.bytes(&entry.data);
        offset += size;
    }
    if offset + NV_RAM_HEADER_SIZE <= RAM_INDEX_SPACE {
        w.u32(0);
    }
    w.block(true, |_| Ok(()))
}

fn marshal_user_nvram(
    w: &mut WireWriter,
    user: &OwnedUserNvram,
    object_version: u16,
) -> Result<(), TpmResult> {
    w.nv_header(USER_NVRAM_VERSION, USER_NVRAM_MAGIC, 1);
    w.u64(USER_NVRAM_CAPACITY);
    for entry in user.entries.iter() {
        match entry {
            OwnedUserNvramEntry::NvIndex {
                handle,
                index,
                data,
                ..
            } => {
                let entrysize = 4 + NATIVE_SIZEOF_NV_INDEX as u64 + data.len() as u64;
                w.u32(u32::try_from(entrysize).map_err(|_| TPM_FAIL)?);
                w.u32(*handle);
                w.nv_header(NV_INDEX_VERSION, NV_INDEX_MAGIC, 1);
                w.u32(index.nv_index);
                w.u16(index.name_alg);
                w.u32(index.attributes);
                w.tpm2b(&index.auth_policy)?;
                w.u16(index.data_size);
                w.tpm2b(index.auth_value.as_bytes())?;
                w.block(true, |_| Ok(()))?;
                w.u32(u32::try_from(data.len()).map_err(|_| TPM_FAIL)?);
                w.bytes(data);
            }
            OwnedUserNvramEntry::Persistent {
                handle,
                object,
                object_destination_size,
                ..
            } => {
                let entrysize = 4 + 4 + *object_destination_size;
                w.u32(u32::try_from(entrysize).map_err(|_| TPM_FAIL)?);
                w.u32(*handle);
                w.bytes(&any_object_image(object, object_version)?);
            }
        }
    }
    w.u32(0);
    w.u64(user.max_count);
    w.block(true, |_| Ok(()))
}

pub(in crate::library::tpm2) fn persistent_all_store(
    state: &OwnedPersistentState,
) -> Result<Vec<u8>, TpmResult> {
    let level = state.profile.state_format_level;
    let blob_version: u16 = if level == 1 { 3 } else { 4 };
    if state.profile.was_null_profile != (blob_version == 3) {
        return Err(TPM_FAIL);
    }
    let pd_version: u16 = if level <= 2 { 4 } else { 5 };
    let object_version: u16 = if level <= 5 { 3 } else { 4 };
    let command_count = enabled_command_count(&state.profile.commands)?;
    if pd_version <= 4 && command_count > COMPRESSED_LIST_COMMANDS {
        return Err(TPM_FAIL);
    }

    let mut w = WireWriter::new();
    w.nv_header(blob_version, PERSISTENT_ALL_MAGIC, blob_version);

    if blob_version >= 4 {
        let json = format_active_profile(&state.profile);
        let len = u16::try_from(json.len() + 1).map_err(|_| TPM_FAIL)?;
        w.u16(len);
        w.bytes(json.as_bytes());
        w.u8(0);
    }

    w.bytes(&compile_constants::marshalled_section(
        PA_COMPILE_CONSTANTS_VERSION,
    ));

    marshal_persistent_data(&mut w, &state.persistent, pd_version, command_count)?;
    marshal_orderly_data(&mut w, &state.orderly)?;

    let write_su_state = (state.persistent.orderly_state & TPM_SU_STATE_MASK) == TPM_SU_STATE;
    if write_su_state {
        let (Some(reset), Some(clear)) = (&state.state_reset, &state.state_clear) else {
            return Err(TPM_FAIL);
        };
        marshal_state_reset(&mut w, reset, SEED_COMPAT_LEVEL_ORIGINAL)?;
        marshal_state_clear(&mut w, clear)?;
    }

    marshal_index_orderly_ram(&mut w, &state.index_orderly_ram)?;
    marshal_user_nvram(&mut w, &state.user_nvram, object_version)?;

    w.block(true, |_| Ok(()))?;
    w.u32(PERSISTENT_ALL_MAGIC);

    Ok(w.out)
}

#[cfg(test)]
mod tests {
    use super::super::PersistentAllEnvelope;
    use super::super::attach::{OwnedPersistentState, materialize_persistent_state};
    use super::super::{compat_tail, data};
    use super::*;
    use crate::library::tpm2::nv::{IndexOrderlyRamFixture, UserNvramFixture};
    use crate::library::tpm2::pcr::{PcrAllocationFixture, PcrPoliciesFixture};
    use crate::library::tpm2::profile::validate_profile;
    use crate::library::tpm2::state::{StateClearFixture, StateResetFixture};
    use crate::library::tpm2::{audit, lockout, parse_persistent_all_payload, pp_list};

    fn materialize(blob: &[u8]) -> OwnedPersistentState {
        let envelope = PersistentAllEnvelope::parse(blob).unwrap();
        materialize_persistent_state(parse_persistent_all_payload(&envelope).unwrap()).unwrap()
    }

    #[test]
    fn null_profile_store_emits_the_upstream_v3_shape() {
        let state = materialize(&crate::library::tpm2::valid_permanent_state_fixture());
        let blob = persistent_all_store(&state).expect("the null-profile state serializes");

        assert_eq!(
            &blob[..8],
            &[0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x03]
        );
        let constants = compile_constants::marshalled_section(3);
        assert_eq!(&blob[8..8 + constants.len()], &constants[..]);
        let pd = &blob[8 + constants.len()..];
        assert_eq!(&pd[..8], &[0x00, 0x04, 0x12, 0x21, 0x34, 0x43, 0x00, 0x04]);
        assert_eq!(*blob.last().unwrap(), 0x23, "footer magic");

        let state2 = materialize(&blob);
        assert!(state2.persistent.pp_list.compressed);
        assert_eq!(state2.persistent.pp_list.bytes.len(), 14, "(110 + 7) / 8");
        assert_eq!(
            command_bitmap_image(&state2.persistent.pp_list, 17).unwrap(),
            command_bitmap_image(&state.persistent.pp_list, 17).unwrap(),
        );
        assert_eq!(
            command_bitmap_image(&state2.persistent.audit_commands, 17).unwrap(),
            command_bitmap_image(&state.persistent.audit_commands, 17).unwrap(),
        );
        assert_eq!(
            state2.persistent.orderly_state,
            state.persistent.orderly_state
        );
        assert_eq!(state2.orderly.clock_safe, state.orderly.clock_safe);
        assert!(state2.profile.was_null_profile);

        assert_eq!(persistent_all_store(&state2).unwrap(), blob);
    }

    #[test]
    fn compressed_bitmap_remaps_bits_through_the_v09_table() {
        let mut pp = vec![0u8; 17];
        pp[0] = 1 << 5;
        let payload = {
            let mut payload = compile_constants::marshalled_section(3);
            payload.extend_from_slice(
                &data::PrefixFixture {
                    tail: PcrPoliciesFixture {
                        tail: PcrAllocationFixture {
                            tail: pp_list::PpListFixture {
                                array: pp.clone(),
                                tail: crate::library::tpm2::persistent_data_tail(),
                                ..pp_list::PpListFixture::default()
                            }
                            .bytes(),
                            ..PcrAllocationFixture::default()
                        }
                        .bytes(),
                        ..PcrPoliciesFixture::default()
                    }
                    .bytes(),
                    ..data::PrefixFixture::default()
                }
                .bytes(),
            );
            payload
        };
        let blob = {
            let mut out = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
            out.extend_from_slice(&payload);
            out.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
            out
        };
        let state = materialize(&blob);
        let stored = persistent_all_store(&state).unwrap();
        let state2 = materialize(&stored);
        assert!(state2.persistent.pp_list.compressed);
        assert_eq!(
            state2.persistent.pp_list.bytes[0] & (1 << 4),
            1 << 4,
            "build bit 5 lands on compressed bit 4"
        );
        assert_eq!(
            command_bitmap_image(&state2.persistent.pp_list, 17).unwrap(),
            command_bitmap_image(&state.persistent.pp_list, 17).unwrap(),
        );
    }

    #[test]
    fn default_v1_store_round_trips_byte_identically() {
        let canonical = format_active_profile(
            &validate_profile(super::super::ProfileField::Bytes(
                br#"{"Name":"default-v1","StateFormatLevel":7}"#,
            ))
            .unwrap(),
        );

        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &data::PrefixFixture {
                min_version: 5,
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: crate::library::tpm2::persistent_data_tail(),
                            ..pp_list::PpListFixture::default()
                        }
                        .bytes(),
                        ..PcrAllocationFixture::default()
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..data::PrefixFixture::default()
            }
            .bytes(),
        );

        let mut blob = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
        blob.extend_from_slice(&u16::try_from(canonical.len() + 1).unwrap().to_be_bytes());
        blob.extend_from_slice(canonical.as_bytes());
        blob.push(0);
        blob.extend_from_slice(&payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);

        let state = materialize(&blob);
        assert_eq!(state.profile.state_format_level, 7);
        assert_eq!(persistent_all_store(&state).unwrap(), blob);
    }

    #[test]
    fn su_state_store_round_trips_and_drops_the_null_seed_level() {
        let sections = {
            let mut out = super::super::orderly::OrderlyFixture::default().bytes();
            out.extend_from_slice(
                &StateResetFixture {
                    null_seed_compat_level: 1,
                    ..StateResetFixture::default()
                }
                .bytes(),
            );
            out.extend_from_slice(&StateClearFixture::default().bytes());
            out.extend_from_slice(&IndexOrderlyRamFixture::default().bytes());
            out.extend_from_slice(&UserNvramFixture::default().bytes());
            out.extend_from_slice(&[0x01, 0x00, 0x00]);
            out
        };
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &data::PrefixFixture {
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: lockout::LockoutFixture {
                                orderly_state: 0x0001,
                                tail: audit::AuditFixture {
                                    tail: compat_tail::CompatTailFixture {
                                        tail: sections,
                                        ..compat_tail::CompatTailFixture::default()
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
                        ..PcrAllocationFixture::default()
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..data::PrefixFixture::default()
            }
            .bytes(),
        );
        let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
        blob.extend_from_slice(&payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);

        let state = materialize(&blob);
        assert_eq!(
            state.state_reset.as_ref().unwrap().null_seed_compat_level,
            1
        );

        let stored = persistent_all_store(&state).unwrap();
        let state2 = materialize(&stored);
        let reset = state2.state_reset.as_ref().expect("SU sections survive");
        assert_eq!(
            reset.null_seed_compat_level, 0,
            "the NV image default, not the decoded live-global value"
        );
        assert_eq!(
            reset.null_proof.expose(),
            state.state_reset.as_ref().unwrap().null_proof.expose()
        );
        assert!(state2.state_clear.is_some());
        assert_eq!(persistent_all_store(&state2).unwrap(), stored);
    }

    #[test]
    fn stored_compat_tail_carries_the_active_allocation_not_the_input_shadow() {
        let allocated = PcrAllocationFixture {
            selections: vec![(0x000b, 3, vec![0x01, 0x00, 0x00])],
            ..PcrAllocationFixture::default()
        };
        let compat = compat_tail::CompatTailFixture {
            shadow: PcrAllocationFixture {
                selections: vec![(0x0004, 3, vec![0x00, 0x00, 0x02])],
                ..PcrAllocationFixture::default()
            }
            .bytes(),
            ..compat_tail::CompatTailFixture::default()
        };
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &data::PrefixFixture {
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: lockout::LockoutFixture {
                                tail: audit::AuditFixture {
                                    tail: compat_tail::CompatTailFixture {
                                        tail: crate::library::tpm2::remaining_sections(),
                                        ..compat
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
                        ..allocated
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..data::PrefixFixture::default()
            }
            .bytes(),
        );
        let mut blob = vec![0x00, 0x03, 0xab, 0x36, 0x47, 0x23, 0x00, 0x01];
        blob.extend_from_slice(&payload);
        blob.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);

        let state = materialize(&blob);
        assert!(state.persistent.shadow_pcr_allocated.is_some());

        let state2 = materialize(&persistent_all_store(&state).unwrap());
        let shadow = state2
            .persistent
            .shadow_pcr_allocated
            .as_ref()
            .expect("the tail always carries a list in current-writer shape");
        assert_eq!(
            shadow, &state2.persistent.pcr_allocated,
            "the stored shadow slot holds the active allocation"
        );
        assert_eq!(
            state2.persistent.pcr_allocated.selections[0].hash_alg,
            0x000b
        );
    }

    #[test]
    fn serialized_profile_with_level_one_is_the_upstream_abort_boundary() {
        let blob = crate::library::tpm2::commit_failing_permanent_state_fixture();
        let profile = br#"{"Name":"null","StateFormatLevel":1}"#;
        let mut payload = compile_constants::marshalled_section(3);
        payload.extend_from_slice(
            &data::PrefixFixture {
                tail: PcrPoliciesFixture {
                    tail: PcrAllocationFixture {
                        tail: pp_list::PpListFixture {
                            tail: crate::library::tpm2::persistent_data_tail(),
                            ..pp_list::PpListFixture::default()
                        }
                        .bytes(),
                        ..PcrAllocationFixture::default()
                    }
                    .bytes(),
                    ..PcrPoliciesFixture::default()
                }
                .bytes(),
                ..data::PrefixFixture::default()
            }
            .bytes(),
        );
        let mut v4 = vec![0x00, 0x04, 0xab, 0x36, 0x47, 0x23, 0x00, 0x04];
        v4.extend_from_slice(&u16::try_from(profile.len() + 1).unwrap().to_be_bytes());
        v4.extend_from_slice(profile);
        v4.push(0);
        v4.extend_from_slice(&payload);
        v4.extend_from_slice(&[0xab, 0x36, 0x47, 0x23]);
        drop(blob);

        let state = materialize(&v4);
        assert!(!state.profile.was_null_profile);
        assert_eq!(state.profile.state_format_level, 1);
        assert_eq!(persistent_all_store(&state).unwrap_err(), TPM_FAIL);
    }

    #[test]
    fn stored_blob_never_leaks_secret_lengths_through_debug() {
        let state = materialize(&crate::library::tpm2::valid_permanent_state_fixture());
        let _ = persistent_all_store(&state).unwrap();
        let formatted = format!("{state:?}");
        assert!(formatted.contains("OwnedSecret { len:"), "{formatted}");
    }
}
