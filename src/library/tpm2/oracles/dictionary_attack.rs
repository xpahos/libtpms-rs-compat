use super::{Fixture, OracleVector};

const MAGIC: &[u8; 8] = b"DAORACLE";

const FIXTURE: Fixture = Fixture::new(
    "dictionary attack",
    MAGIC,
    include_bytes!("../testdata/oracles/dictionary_attack.bin"),
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum RecordKind {
    Response,
    Permanent,
    Volatile,
}

pub(in crate::library::tpm2) fn record_kind(name: &str) -> RecordKind {
    if name.starts_with("PERMALL_") {
        RecordKind::Permanent
    } else if name.starts_with("VOLATILE_") {
        RecordKind::Volatile
    } else {
        RecordKind::Response
    }
}

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

#[track_caller]
pub(in crate::library::tpm2) fn vectors() -> Vec<OracleVector<'static>> {
    FIXTURE.vectors()
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::*;
    use crate::ffi_types::TpmResult;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_FAIL;
    use crate::library::tpm2::clock::{SteppingClock, time_power_on};
    use crate::library::tpm2::oracles;
    use crate::library::tpm2::persistent::{OwnedPersistentState, OwnedSecret};
    use crate::library::tpm2::persistent::{
        PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
    };
    use crate::library::tpm2::process::process;
    use crate::library::tpm2::runtime::{Tpm2Runtime, commit_restored_state};
    use crate::library::tpm2::volatile::{
        OwnedVolatileState, marshal_volatile_state, volatile_all_store,
    };
    use crate::library::tpm2::{
        VolatileDecodeBoundary, attach_volatile_blob, decode_volatile_blob,
        parse_persistent_all_payload, volatile_validation_context,
    };

    const TPM_RH_OWNER: u32 = 0x4000_0001;
    const TPM_RH_LOCKOUT: u32 = 0x4000_000a;
    const DA_INDEX: u32 = 0x0100_0000;
    const NODA_INDEX: u32 = 0x0100_0001;
    const TPMA_NV_NO_DA: u32 = 0x0200_0000;
    const AUTH_READ_WRITE: u32 = 0x0004_0004;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x3d;
        }
        Ok(())
    }

    fn no_sessions_command(code: u32, params: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x01];
        out.extend_from_slice(&(10 + params.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(params);
        out
    }

    fn password_command(code: u32, handles: &[u32], password: &[u8], params: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x02, 0, 0, 0, 0];
        out.extend_from_slice(&code.to_be_bytes());
        for &handle in handles {
            out.extend_from_slice(&handle.to_be_bytes());
        }
        out.extend_from_slice(&(9 + password.len() as u32).to_be_bytes());
        out.extend_from_slice(&0x4000_0009u32.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        out.extend_from_slice(&(password.len() as u16).to_be_bytes());
        out.extend_from_slice(password);
        out.extend_from_slice(params);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    fn startup_clear() -> Vec<u8> {
        no_sessions_command(0x0000_0144, &[0x00, 0x00])
    }

    fn shutdown_clear() -> Vec<u8> {
        no_sessions_command(0x0000_0145, &[0x00, 0x00])
    }

    fn cap_da_props() -> Vec<u8> {
        let mut params = 6u32.to_be_bytes().to_vec();
        params.extend_from_slice(&0x0000_020eu32.to_be_bytes());
        params.extend_from_slice(&4u32.to_be_bytes());
        no_sessions_command(0x0000_017a, &params)
    }

    fn cap_cc_dap() -> Vec<u8> {
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&0x0000_013au32.to_be_bytes());
        params.extend_from_slice(&1u32.to_be_bytes());
        no_sessions_command(0x0000_017a, &params)
    }

    fn define_index(index: u32, password: &[u8], attributes: u32) -> Vec<u8> {
        let mut params = (password.len() as u16).to_be_bytes().to_vec();
        params.extend_from_slice(password);
        params.extend_from_slice(&0x000eu16.to_be_bytes());
        params.extend_from_slice(&index.to_be_bytes());
        params.extend_from_slice(&0x000bu16.to_be_bytes());
        params.extend_from_slice(&attributes.to_be_bytes());
        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&1u16.to_be_bytes());
        password_command(0x0000_012a, &[TPM_RH_OWNER], &[], &params)
    }

    fn nv_write(index: u32, password: &[u8]) -> Vec<u8> {
        let params = [0x00, 0x01, b'A', 0x00, 0x00];
        password_command(0x0000_0137, &[index, index], password, &params)
    }

    fn dap(password: &[u8], max_tries: u32, recovery: u32, lockout_recovery: u32) -> Vec<u8> {
        let mut params = max_tries.to_be_bytes().to_vec();
        params.extend_from_slice(&recovery.to_be_bytes());
        params.extend_from_slice(&lockout_recovery.to_be_bytes());
        password_command(0x0000_013a, &[TPM_RH_LOCKOUT], password, &params)
    }

    fn dap_raw(handle: u32, params: &[u8]) -> Vec<u8> {
        password_command(0x0000_013a, &[handle], &[], params)
    }

    fn dap_no_sessions() -> Vec<u8> {
        let mut params = TPM_RH_LOCKOUT.to_be_bytes().to_vec();
        params.extend_from_slice(&1u32.to_be_bytes());
        params.extend_from_slice(&6u32.to_be_bytes());
        params.extend_from_slice(&6u32.to_be_bytes());
        no_sessions_command(0x0000_013a, &params)
    }

    fn materialize_permanent(bytes: &[u8]) -> Result<OwnedPersistentState, String> {
        let envelope =
            PersistentAllEnvelope::parse(bytes).map_err(|error| format!("envelope: {error:?}"))?;
        let decoded = parse_persistent_all_payload(&envelope)
            .map_err(|error| format!("payload: {error:?}"))?;
        materialize_persistent_state(decoded).map_err(|code| format!("materialize: {code:#x}"))
    }

    #[track_caller]
    fn permanent_record(label: &str) -> OwnedPersistentState {
        materialize_permanent(vector(&format!("PERMALL_{label}")))
            .unwrap_or_else(|error| panic!("PERMALL_{label}: {error}"))
    }

    fn decode_volatile(permall: &[u8], bytes: &[u8]) -> Result<OwnedVolatileState, String> {
        let state = materialize_permanent(permall)?;
        let runtime =
            commit_restored_state(state).map_err(|code| format!("restored commit: {code:#x}"))?;
        let context =
            volatile_validation_context(&runtime).map_err(|code| format!("context: {code:#x}"))?;
        let clock = SteppingClock::new(1_600_000_000_000, 5_000_000);
        decode_volatile_blob(&context, bytes, &clock, VolatileDecodeBoundary::Validate)
            .map_err(|code| format!("decode: {code:#x}"))
    }

    #[track_caller]
    fn volatile_record(label: &str) -> OwnedVolatileState {
        decode_volatile(
            vector(&format!("PERMALL_{label}")),
            vector(&format!("VOLATILE_{label}")),
        )
        .unwrap_or_else(|error| panic!("VOLATILE_{label}: {error}"))
    }

    fn state_partner(name: &str) -> String {
        name.replacen("VOLATILE_", "PERMALL_", 1)
    }

    fn validate_record(name: &str, bytes: &[u8]) -> Result<(), String> {
        match record_kind(name) {
            RecordKind::Response => {
                if bytes.len() < 10 {
                    return Err("a response carries at least a header".into());
                }
                let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
                if tag != 0x8001 && tag != 0x8002 {
                    return Err(format!("not a response tag: {tag:#06x}"));
                }
                let size = u32::from_be_bytes(bytes[2..6].try_into().expect("four bytes")) as usize;
                if size != bytes.len() {
                    return Err(format!("declared {size}, found {}", bytes.len()));
                }
                Ok(())
            }
            RecordKind::Permanent => {
                let state = materialize_permanent(bytes)?;
                let stored =
                    persistent_all_store(&state).map_err(|code| format!("store: {code:#x}"))?;
                if stored != bytes {
                    return Err("the permanent state does not round-trip".into());
                }
                Ok(())
            }
            RecordKind::Volatile => {
                let permall = FIXTURE
                    .find(&state_partner(name))
                    .ok_or_else(|| format!("no {} partner", state_partner(name)))?;
                let owned = decode_volatile(permall, bytes)?;
                let stored =
                    marshal_volatile_state(&owned).map_err(|code| format!("marshal: {code:#x}"))?;
                if stored != bytes {
                    return Err("the volatile state does not round-trip".into());
                }
                Ok(())
            }
        }
    }

    const STATE_BOUNDARIES: [&str; 13] = [
        "FRESH_STARTUP",
        "AFTER_RETRY",
        "AFTER_AUTH_FAIL",
        "AFTER_DAP",
        "AT_LOCKOUT",
        "AFTER_SELF_HEAL",
        "AFTER_BAD_LOCKOUT",
        "AFTER_LOCKOUT_RECOVERY",
        "AFTER_ORDERLY",
        "AFTER_UNORDERLY",
        "BEFORE_SAVE",
        "AFTER_RESTORE",
        "AFTER_RESTORE_RECOVERY",
    ];

    const LIVE_ORDERLY_BOUNDARIES: [&str; 6] = [
        "AFTER_LOCKOUT_RECOVERY",
        "AFTER_ORDERLY",
        "AFTER_UNORDERLY",
        "BEFORE_SAVE",
        "AFTER_RESTORE",
        "AFTER_RESTORE_RECOVERY",
    ];

    fn changed_offsets(baseline: &[u8], mutated: &[u8]) -> Vec<usize> {
        if baseline.len() != mutated.len() {
            return Vec::new();
        }
        (0..baseline.len())
            .filter(|&index| baseline[index] != mutated[index])
            .collect()
    }

    fn flipped_secret(secret: &OwnedSecret) -> OwnedSecret {
        OwnedSecret::from_vec(secret.as_bytes().iter().map(|byte| !byte).collect())
    }

    type PermanentMutator = fn(&mut OwnedPersistentState);
    type VolatileMutator = fn(&mut OwnedVolatileState);

    const PERMANENT_MUTATORS: [(&str, PermanentMutator); 14] = [
        ("persistent.failed_tries", |state| {
            state.persistent.failed_tries = !state.persistent.failed_tries;
        }),
        ("persistent.max_tries", |state| {
            state.persistent.max_tries = !state.persistent.max_tries;
        }),
        ("persistent.recovery_time", |state| {
            state.persistent.recovery_time = !state.persistent.recovery_time;
        }),
        ("persistent.lockout_recovery", |state| {
            state.persistent.lockout_recovery = !state.persistent.lockout_recovery;
        }),
        ("persistent.lockout_auth_enabled", |state| {
            state.persistent.lockout_auth_enabled = !state.persistent.lockout_auth_enabled;
        }),
        ("persistent.orderly_state", |state| {
            state.persistent.orderly_state ^= 1;
        }),
        ("persistent.time_epoch", |state| {
            state.persistent.time_epoch = !state.persistent.time_epoch;
        }),
        ("orderly.clock", |state| {
            state.orderly.clock = !state.orderly.clock
        }),
        ("orderly.clock_safe", |state| state.orderly.clock_safe ^= 1),
        ("orderly.self_heal_timer", |state| {
            state.orderly.self_heal_timer = !state.orderly.self_heal_timer;
        }),
        ("orderly.lockout_timer", |state| {
            state.orderly.lockout_timer = !state.orderly.lockout_timer;
        }),
        ("orderly.time", |state| {
            state.orderly.time = !state.orderly.time
        }),
        ("orderly.drbg_state.seed", |state| {
            state.orderly.drbg_state.seed = flipped_secret(&state.orderly.drbg_state.seed);
        }),
        ("orderly.drbg_state.last_value", |state| {
            for word in &mut state.orderly.drbg_state.last_value {
                *word = !*word;
            }
        }),
    ];

    const VOLATILE_MUTATORS: [(&str, VolatileMutator); 32] = [
        ("time", |state| state.time = !state.time),
        ("tpm_time", |state| state.tpm_time = !state.tpm_time),
        ("real_time_previous", |state| {
            state.real_time_previous = !state.real_time_previous;
        }),
        ("adjust_rate", |state| {
            state.adjust_rate = !state.adjust_rate
        }),
        ("timer_reset", |state| {
            state.timer_reset = !state.timer_reset
        }),
        ("timer_stopped", |state| {
            state.timer_stopped = !state.timer_stopped
        }),
        ("backthen", |state| state.backthen = !state.backthen),
        ("da_used", |state| state.da_used = !state.da_used),
        ("session_process.da_pending_on_nv", |state| {
            state.session_process.da_pending_on_nv = !state.session_process.da_pending_on_nv;
        }),
        ("prev_orderly_state", |state| {
            state.prev_orderly_state ^= 0xffff
        }),
        ("exclusive_audit_session", |state| {
            state.exclusive_audit_session = !state.exclusive_audit_session;
        }),
        ("ph_enable", |state| state.ph_enable = !state.ph_enable),
        ("orderly.clock", |state| {
            state.orderly.clock = !state.orderly.clock
        }),
        ("orderly.clock_safe", |state| state.orderly.clock_safe ^= 1),
        ("orderly.self_heal_timer", |state| {
            state.orderly.self_heal_timer = !state.orderly.self_heal_timer;
        }),
        ("orderly.lockout_timer", |state| {
            state.orderly.lockout_timer = !state.orderly.lockout_timer;
        }),
        ("orderly.time", |state| {
            state.orderly.time = !state.orderly.time
        }),
        ("tail_v4.host_monotonic_sample", |state| {
            if let Some(tail) = state.tail_v4.as_mut() {
                tail.host_monotonic_sample = !tail.host_monotonic_sample;
            }
        }),
        ("tail_v4.last_system_time", |state| {
            if let Some(tail) = state.tail_v4.as_mut() {
                tail.last_system_time = !tail.last_system_time;
            }
        }),
        ("tail_v4.last_reported_time", |state| {
            if let Some(tail) = state.tail_v4.as_mut() {
                tail.last_reported_time = !tail.last_reported_time;
            }
        }),
        ("orderly.drbg_state.seed", |state| {
            state.orderly.drbg_state.seed = flipped_secret(&state.orderly.drbg_state.seed);
        }),
        ("orderly.drbg_state.last_value", |state| {
            for word in &mut state.orderly.drbg_state.last_value {
                *word = !*word;
            }
        }),
        ("state_reset.null_proof", |state| {
            state.state_reset.null_proof = flipped_secret(&state.state_reset.null_proof);
        }),
        ("state_reset.null_seed", |state| {
            state.state_reset.null_seed = flipped_secret(&state.state_reset.null_seed);
        }),
        ("session_process.session_handles", |state| {
            for handle in &mut state.session_process.session_handles {
                *handle = !*handle;
            }
        }),
        ("session_process.attributes", |state| {
            for attributes in &mut state.session_process.attributes {
                *attributes = !*attributes;
            }
        }),
        ("session_process.associated_handles", |state| {
            for handle in &mut state.session_process.associated_handles {
                *handle = !*handle;
            }
        }),
        ("session_process.input_auth_values", |state| {
            for value in &mut state.session_process.input_auth_values {
                *value = OwnedSecret::from_vec(vec![0xa5; 4]);
            }
        }),
        ("session_process.nonce_callers", |state| {
            for value in &mut state.session_process.nonce_callers {
                *value = OwnedSecret::from_vec(vec![0x5a; 4]);
            }
        }),
        ("session_process.decrypt_session_index", |state| {
            state.session_process.decrypt_session_index =
                !state.session_process.decrypt_session_index;
        }),
        ("session_process.encrypt_session_index", |state| {
            state.session_process.encrypt_session_index =
                !state.session_process.encrypt_session_index;
        }),
        ("session_process.audit_session_index", |state| {
            state.session_process.audit_session_index = !state.session_process.audit_session_index;
        }),
    ];

    const VOLATILE_ENTROPY_FIELDS: [&str; 5] = [
        "orderly.drbg_state.seed",
        "orderly.drbg_state.last_value",
        "state_reset.null_proof",
        "state_reset.null_seed",
        "state_reset.commit_nonce",
    ];

    const PERMANENT_ENTROPY_FIELDS: [&str; 2] =
        ["orderly.drbg_state.seed", "orderly.drbg_state.last_value"];

    struct FieldMap {
        fields: Vec<(&'static str, Vec<usize>)>,
        integrity: Vec<usize>,
    }

    impl FieldMap {
        fn from_offsets(mut fields: Vec<(&'static str, Vec<usize>)>) -> FieldMap {
            let mut integrity: Vec<usize> = Vec::new();
            if let Some((_, first)) = fields.first() {
                integrity = first
                    .iter()
                    .copied()
                    .filter(|offset| fields.iter().all(|(_, set)| set.contains(offset)))
                    .collect();
            }
            for (_, set) in &mut fields {
                set.retain(|offset| !integrity.contains(offset));
            }
            FieldMap { fields, integrity }
        }

        fn describe(&self, offset: usize) -> String {
            if self.integrity.contains(&offset) {
                return " (integrity digest)".into();
            }
            self.fields
                .iter()
                .find(|(_, set)| set.contains(&offset))
                .map(|(name, _)| format!(" ({name})"))
                .unwrap_or_default()
        }

        fn allowed(&self, entropy_fields: &[&str]) -> Vec<usize> {
            let mut allowed = self.integrity.clone();
            for (name, set) in &self.fields {
                if entropy_fields.contains(name) {
                    allowed.extend_from_slice(set);
                }
            }
            allowed.sort_unstable();
            allowed
        }
    }

    fn permanent_field_map(expected: &[u8]) -> FieldMap {
        let mut fields = Vec::new();
        for (name, mutate) in PERMANENT_MUTATORS {
            let Ok(mut state) = materialize_permanent(expected) else {
                continue;
            };
            mutate(&mut state);
            let Ok(mutated) = persistent_all_store(&state) else {
                continue;
            };
            let offsets = changed_offsets(expected, &mutated);
            if !offsets.is_empty() {
                fields.push((name, offsets));
            }
        }
        FieldMap::from_offsets(fields)
    }

    fn volatile_field_map(partner_permall: &[u8], expected: &[u8]) -> FieldMap {
        let mut fields = Vec::new();
        for (name, mutate) in VOLATILE_MUTATORS {
            let Ok(mut state) = decode_volatile(partner_permall, expected) else {
                continue;
            };
            mutate(&mut state);
            let Ok(mutated) = marshal_volatile_state(&state) else {
                continue;
            };
            let offsets = changed_offsets(expected, &mutated);
            if !offsets.is_empty() {
                fields.push((name, offsets));
            }
        }
        if let Ok(mut state) = decode_volatile(partner_permall, expected) {
            state.state_reset.commit_nonce = flipped_secret(&state.state_reset.commit_nonce);
            if let Ok(mutated) = marshal_volatile_state(&state) {
                let offsets = changed_offsets(expected, &mutated);
                if !offsets.is_empty() {
                    fields.push(("state_reset.commit_nonce", offsets));
                }
            }
        }
        FieldMap::from_offsets(fields)
    }

    fn compare_state_bytes(
        kind: &str,
        label: &str,
        expected: &[u8],
        actual: &[u8],
        map: &FieldMap,
        entropy_fields: &[&str],
    ) -> Result<(), String> {
        if expected == actual {
            return Ok(());
        }
        if expected.len() != actual.len() {
            return Err(format!(
                "{label} {kind} state length diverges: expected {}, found {}",
                expected.len(),
                actual.len()
            ));
        }
        let allowed = map.allowed(entropy_fields);
        for offset in 0..expected.len() {
            if expected[offset] == actual[offset] || allowed.binary_search(&offset).is_ok() {
                continue;
            }
            return Err(format!(
                "{label} {kind} state diverges at offset {offset}{field}: \
                 expected {expected_byte:#04x}, found {actual_byte:#04x}",
                field = map.describe(offset),
                expected_byte = expected[offset],
                actual_byte = actual[offset],
            ));
        }
        Ok(())
    }

    fn compare_permanent(label: &str, expected: &[u8], actual: &[u8]) -> Result<(), String> {
        let entropy: &[&str] = if LIVE_ORDERLY_BOUNDARIES.contains(&label) {
            &PERMANENT_ENTROPY_FIELDS
        } else {
            &[]
        };
        let map = permanent_field_map(expected);
        compare_state_bytes("permanent", label, expected, actual, &map, entropy)?;
        if expected != actual {
            let expected_state = materialize_permanent(expected)?;
            let actual_state = materialize_permanent(actual)?;
            if expected_state.orderly.drbg_state.seed.as_bytes().len()
                != actual_state.orderly.drbg_state.seed.as_bytes().len()
            {
                return Err(format!("{label} permanent DRBG seed lengths diverge"));
            }
        }
        Ok(())
    }

    fn compare_volatile(label: &str, expected: &[u8], actual: &[u8]) -> Result<(), String> {
        let partner = state_partner(&format!("VOLATILE_{label}"));
        let permall_bytes = FIXTURE
            .find(&partner)
            .ok_or_else(|| format!("{label}: no {partner} partner"))?;
        let map = volatile_field_map(permall_bytes, expected);
        compare_state_bytes(
            "volatile",
            label,
            expected,
            actual,
            &map,
            &VOLATILE_ENTROPY_FIELDS,
        )?;
        if expected != actual {
            let expected_state = decode_volatile(permall_bytes, expected)?;
            let actual_state = decode_volatile(permall_bytes, actual)?;
            for (name, lhs, rhs) in [
                (
                    "DRBG seed",
                    expected_state.orderly.drbg_state.seed.as_bytes().len(),
                    actual_state.orderly.drbg_state.seed.as_bytes().len(),
                ),
                (
                    "null proof",
                    expected_state.state_reset.null_proof.as_bytes().len(),
                    actual_state.state_reset.null_proof.as_bytes().len(),
                ),
                (
                    "null seed",
                    expected_state.state_reset.null_seed.as_bytes().len(),
                    actual_state.state_reset.null_seed.as_bytes().len(),
                ),
                (
                    "commit nonce",
                    expected_state.state_reset.commit_nonce.as_bytes().len(),
                    actual_state.state_reset.commit_nonce.as_bytes().len(),
                ),
            ] {
                if lhs != rhs {
                    return Err(format!("{label} volatile {name} lengths diverge"));
                }
            }
        }
        Ok(())
    }

    fn seek_plat_real(clock: &SteppingClock, runtime: &Tpm2Runtime, plat_real: u64) {
        clock.set_monotonic(
            plat_real
                .wrapping_sub(runtime.clock.host_monotonic_adjust_ms as u64)
                .wrapping_sub(runtime.clock.suspended_elapsed_ms),
        );
    }

    fn seek(clock: &SteppingClock, runtime: &Tpm2Runtime, tpm_time: u64) {
        let plat_real = runtime
            .clock
            .last_system_time_ms
            .wrapping_add(tpm_time.wrapping_sub(runtime.clock.last_reported_time_ms));
        seek_plat_real(clock, runtime, plat_real);
    }

    #[track_caller]
    fn assert_boundary(
        runtime: &Tpm2Runtime,
        clock: &SteppingClock,
        permall: &RefCell<Vec<u8>>,
        label: &str,
    ) -> Vec<u8> {
        let record = volatile_record(label);
        let tail = record.tail_v4.expect("the capture carries a tail");
        clock.set_monotonic(
            tail.host_monotonic_sample
                .wrapping_sub(runtime.clock.host_monotonic_adjust_ms as u64),
        );
        clock.set_realtime(record.backthen);
        let captured = volatile_all_store(runtime, clock).expect("the volatile state captures");
        compare_volatile(label, vector(&format!("VOLATILE_{label}")), &captured)
            .unwrap_or_else(|error| panic!("{error}"));
        compare_permanent(
            label,
            vector(&format!("PERMALL_{label}")),
            &permall.borrow(),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        captured
    }

    #[track_caller]
    fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        permall: &RefCell<Vec<u8>>,
        label: &str,
        bytes: Vec<u8>,
    ) {
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(runtime, 0, &input, clock, |runtime| {
            *permall.borrow_mut() = persistent_all_store(runtime.state.as_ref().ok_or(TPM_FAIL)?)
                .map_err(|_| TPM_FAIL)?;
            Ok(())
        })
        .unwrap_or_else(|code| panic!("{label} failed with {code:#x}"));
        assert_eq!(response, vector(label), "{label}");
    }

    fn reboot(
        previous: &Tpm2Runtime,
        permall: &[u8],
        clock: &SteppingClock,
        first_boundary: &str,
    ) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::live::RestoredVolatile;

        let envelope = PersistentAllEnvelope::parse(permall).expect("the stored envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload decodes");
        let state = materialize_persistent_state(decoded).expect("the state materializes");
        let mut runtime = commit_restored_state(state).expect("the restored state commits");
        runtime.entropy = deterministic_entropy;
        if let Some(carried) = previous.restored_volatile.as_ref() {
            let restored = runtime
                .restored_volatile
                .get_or_insert_with(RestoredVolatile::power_on);
            restored.session_process = carried.session_process.clone();
            restored.exclusive_audit_session = carried.exclusive_audit_session;
        }
        let tail = volatile_record(first_boundary)
            .tail_v4
            .expect("the capture carries a tail");
        seek_plat_real(clock, &runtime, tail.last_system_time);
        time_power_on(&mut runtime, clock);
        runtime
    }

    fn restore(permall: &[u8], volatile: &[u8], clock: &SteppingClock) -> Box<Tpm2Runtime> {
        let envelope = PersistentAllEnvelope::parse(permall).expect("the stored envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload decodes");
        let state = materialize_persistent_state(decoded).expect("the state materializes");
        let mut runtime = commit_restored_state(state).expect("the restored state commits");
        runtime.entropy = deterministic_entropy;
        attach_volatile_blob(
            &mut runtime,
            volatile,
            clock,
            VolatileDecodeBoundary::Restore,
        )
        .expect("the volatile state attaches");
        runtime
    }

    fn index_data(runtime: &Tpm2Runtime, handle: u32) -> Vec<u8> {
        use crate::library::tpm2::persistent::OwnedUserNvramEntry;
        for entry in &runtime.state.as_ref().expect("state").user_nvram.entries {
            if let OwnedUserNvramEntry::NvIndex {
                handle: entry_handle,
                data,
                ..
            } = entry
                && *entry_handle == handle
            {
                return data.clone();
            }
        }
        panic!("index {handle:#010x} is not defined");
    }

    #[test]
    fn the_full_oracle_sequence_replays_byte_for_byte() {
        let permall = RefCell::new(Vec::new());
        let boot_state = materialize_permanent(vector("PERMALL_MANUFACTURED"))
            .expect("the manufactured permall decodes");
        let mut runtime = commit_restored_state(boot_state).expect("the manufactured state boots");
        runtime.entropy = deterministic_entropy;
        runtime.was_manufactured = true;

        let fresh = volatile_record("FRESH_STARTUP");
        let fresh_tail = fresh.tail_v4.expect("the capture carries a tail");
        let clock = SteppingClock::new(fresh.backthen, fresh_tail.last_system_time);
        time_power_on(&mut runtime, &clock);

        exec(
            &mut runtime,
            &clock,
            &permall,
            "STARTUP_FRESH",
            startup_clear(),
        );
        assert_boundary(&runtime, &clock, &permall, "FRESH_STARTUP");
        exec(&mut runtime, &clock, &permall, "CAP_CC_DAP", cap_cc_dap());
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DEFINE_DA_INDEX",
            define_index(DA_INDEX, b"test", AUTH_READ_WRITE),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DEFINE_NODA_INDEX",
            define_index(NODA_INDEX, b"test", AUTH_READ_WRITE | TPMA_NV_NO_DA),
        );

        let untouched = index_data(&runtime, DA_INDEX);
        seek(&clock, &runtime, volatile_record("AFTER_RETRY").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "RETRY_FIRST_DA_AUTH",
            nv_write(DA_INDEX, &[]),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_RETRY");
        assert!(runtime.live.da_used, "the retry records the DA-used marker");
        assert_eq!(
            runtime.state.as_ref().unwrap().persistent.orderly_state,
            0xfffe,
            "the retry commits the SU_DA_USED orderly marker"
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_RETRY",
            cap_da_props(),
        );
        seek(&clock, &runtime, volatile_record("AFTER_AUTH_FAIL").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "AUTH_FAIL_AFTER_RETRY",
            nv_write(DA_INDEX, &[]),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_AUTH_FAIL");
        assert_eq!(
            index_data(&runtime, DA_INDEX),
            untouched,
            "failed authorizations leave the protected index untouched"
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_FAIL",
            cap_da_props(),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "WRITE_GOOD_AFTER_FAIL",
            nv_write(DA_INDEX, b"test"),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_GOOD",
            cap_da_props(),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "NODA_BAD_AUTH",
            nv_write(NODA_INDEX, b"nope"),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_NODA",
            cap_da_props(),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_TRUNC_P1",
            dap_raw(TPM_RH_LOCKOUT, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_TRUNC_P2",
            dap_raw(TPM_RH_LOCKOUT, &1u32.to_be_bytes()),
        );
        let mut eight = 1u32.to_be_bytes().to_vec();
        eight.extend_from_slice(&6u32.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_TRUNC_P3",
            dap_raw(TPM_RH_LOCKOUT, &eight),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_TRAILING",
            dap_raw(TPM_RH_LOCKOUT, &[0u8; 13]),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_WRONG_HANDLE",
            dap_raw(TPM_RH_OWNER, &{
                let mut params = 1u32.to_be_bytes().to_vec();
                params.extend_from_slice(&6u32.to_be_bytes());
                params.extend_from_slice(&6u32.to_be_bytes());
                params
            }),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_NO_SESSIONS",
            dap_no_sessions(),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_ERRORS",
            cap_da_props(),
        );

        seek(&clock, &runtime, volatile_record("AFTER_DAP").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_SUCCESS",
            dap(&[], 2, 1, 1),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_DAP");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_DAP",
            cap_da_props(),
        );

        seek(&clock, &runtime, volatile_record("AT_LOCKOUT").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "AUTH_FAIL_TO_LOCKOUT",
            nv_write(DA_INDEX, &[]),
        );
        assert_boundary(&runtime, &clock, &permall, "AT_LOCKOUT");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_LOCKED",
            cap_da_props(),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "WRITE_GOOD_LOCKED",
            nv_write(DA_INDEX, b"test"),
        );

        seek(&clock, &runtime, volatile_record("AFTER_SELF_HEAL").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_HEALED_ONE",
            cap_da_props(),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_SELF_HEAL");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "WRITE_GOOD_HEALED",
            nv_write(DA_INDEX, b"test"),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_RAISE_MAX",
            dap(&[], 5, 1, 1),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "FAIL_ONE_OF_TWO",
            nv_write(DA_INDEX, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "FAIL_TWO_OF_TWO",
            nv_write(DA_INDEX, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_TWO_FAILURES",
            cap_da_props(),
        );
        seek(
            &clock,
            &runtime,
            volatile_record("AFTER_SELF_HEAL").time + 2_000,
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_HEALED_TWO",
            cap_da_props(),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_BEFORE_ZERO",
            dap(&[], 2, 1000, 1000),
        );
        seek(
            &clock,
            &runtime,
            volatile_record("AFTER_BAD_LOCKOUT").orderly.self_heal_timer,
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "FAIL_BEFORE_ZERO",
            nv_write(DA_INDEX, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_BEFORE_ZERO",
            cap_da_props(),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_RECOVERY_ZERO",
            dap(&[], 2, 0, 1),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_ZERO",
            cap_da_props(),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_BEFORE_BAD_LOCKOUT",
            dap(&[], 2, 1, 1),
        );
        seek(&clock, &runtime, volatile_record("AFTER_BAD_LOCKOUT").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_BAD_LOCKOUT_AUTH",
            dap(b"x", 2, 1, 1),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_BAD_LOCKOUT");
        assert!(
            !runtime
                .state
                .as_ref()
                .unwrap()
                .persistent
                .lockout_auth_enabled,
            "a failed lockout authorization disables lockoutAuth"
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_WHILE_DISABLED",
            dap(&[], 2, 1, 1),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_LOCKOUT_DISABLED",
            cap_da_props(),
        );
        seek(
            &clock,
            &runtime,
            volatile_record("AFTER_LOCKOUT_RECOVERY").time,
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_AFTER_REENABLE",
            dap(&[], 3, 1000, 1000),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_LOCKOUT_RECOVERY");
        assert!(
            runtime
                .state
                .as_ref()
                .unwrap()
                .persistent
                .lockout_auth_enabled,
            "the lockout interval re-enables lockoutAuth"
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_REENABLED",
            cap_da_props(),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "WRITE_GOOD_BEFORE_ORDERLY",
            nv_write(DA_INDEX, b"test"),
        );
        seek(
            &clock,
            &runtime,
            permanent_record("AFTER_ORDERLY").orderly.time,
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "SHUTDOWN_ORDERLY",
            shutdown_clear(),
        );
        let mut runtime = reboot(&runtime, &permall.borrow().clone(), &clock, "AFTER_ORDERLY");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "STARTUP_AFTER_ORDERLY",
            startup_clear(),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_ORDERLY");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_ORDERLY",
            cap_da_props(),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "RETRY_BEFORE_UNORDERLY",
            nv_write(DA_INDEX, &[]),
        );
        let mut runtime = reboot(
            &runtime,
            &permall.borrow().clone(),
            &clock,
            "AFTER_UNORDERLY",
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "STARTUP_AFTER_UNORDERLY",
            startup_clear(),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_UNORDERLY");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_AFTER_UNORDERLY",
            cap_da_props(),
        );

        exec(
            &mut runtime,
            &clock,
            &permall,
            "DAP_FOR_RESTORE",
            dap(&[], 2, 1, 1),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "RETRY_BEFORE_RESTORE",
            nv_write(DA_INDEX, &[]),
        );
        seek(
            &clock,
            &runtime,
            volatile_record("BEFORE_SAVE").orderly.self_heal_timer,
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "FAIL_TO_LOCK_BEFORE_SAVE",
            nv_write(DA_INDEX, &[]),
        );
        seek(&clock, &runtime, volatile_record("BEFORE_SAVE").time);
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_LOCKED_BEFORE_SAVE",
            cap_da_props(),
        );
        let saved_volatile = assert_boundary(&runtime, &clock, &permall, "BEFORE_SAVE");
        let saved_permall = permall.borrow().clone();

        clock.set_realtime(volatile_record("AFTER_RESTORE").backthen);
        let mut runtime = restore(&saved_permall, &saved_volatile, &clock);
        assert_boundary(&runtime, &clock, &permall, "AFTER_RESTORE");
        exec(
            &mut runtime,
            &clock,
            &permall,
            "WRITE_GOOD_LOCKED_AFTER_RESTORE",
            nv_write(DA_INDEX, b"test"),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_LOCKED_AFTER_RESTORE",
            cap_da_props(),
        );
        seek(
            &clock,
            &runtime,
            volatile_record("AFTER_RESTORE_RECOVERY").time,
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "WRITE_GOOD_RECOVERED_AFTER_RESTORE",
            nv_write(DA_INDEX, b"test"),
        );
        exec(
            &mut runtime,
            &clock,
            &permall,
            "CAP_DA_RECOVERED_AFTER_RESTORE",
            cap_da_props(),
        );
        assert_boundary(&runtime, &clock, &permall, "AFTER_RESTORE_RECOVERY");
    }

    #[test]
    fn permanent_field_mutations_are_detected() {
        let expected = vector("PERMALL_AT_LOCKOUT");
        for (name, mutate) in PERMANENT_MUTATORS {
            let mut state = materialize_permanent(expected).expect("the record decodes");
            mutate(&mut state);
            let mutated = persistent_all_store(&state).expect("the mutation serializes");
            let error = compare_permanent("AT_LOCKOUT", expected, &mutated)
                .expect_err(&format!("a {name} mutation must be detected"));
            assert!(
                error.contains(name),
                "{name}: the report names the field: {error}"
            );
        }
    }

    #[test]
    fn volatile_field_mutations_are_detected() {
        let expected = vector("VOLATILE_AT_LOCKOUT");
        let permall = vector("PERMALL_AT_LOCKOUT");
        for (name, mutate) in VOLATILE_MUTATORS {
            if VOLATILE_ENTROPY_FIELDS.contains(&name) {
                continue;
            }
            let mut state = decode_volatile(permall, expected).expect("the record decodes");
            mutate(&mut state);
            let mutated = marshal_volatile_state(&state).expect("the mutation serializes");
            let error = compare_volatile("AT_LOCKOUT", expected, &mutated)
                .expect_err(&format!("a {name} mutation must be detected"));
            assert!(
                error.contains(name) || error.contains("length diverges"),
                "{name}: the report identifies the mismatch: {error}"
            );
        }
    }

    #[test]
    fn an_unrelated_persistent_mutation_is_detected() {
        let expected = vector("PERMALL_AT_LOCKOUT");
        let mut state = materialize_permanent(expected).expect("the record decodes");
        state.persistent.owner_auth = OwnedSecret::from_vec(vec![0x42; 8]);
        let mutated = persistent_all_store(&state).expect("the mutation serializes");
        assert!(
            compare_permanent("AT_LOCKOUT", expected, &mutated).is_err(),
            "an owner-auth change must be detected"
        );
    }

    #[test]
    fn an_unrelated_volatile_mutation_is_detected() {
        let expected = vector("VOLATILE_AT_LOCKOUT");
        let permall = vector("PERMALL_AT_LOCKOUT");
        let mut state = decode_volatile(permall, expected).expect("the record decodes");
        state.free_session_slots = state.free_session_slots.wrapping_sub(1);
        let mutated = marshal_volatile_state(&state).expect("the mutation serializes");
        assert!(
            compare_volatile("AT_LOCKOUT", expected, &mutated).is_err(),
            "a session-slot change must be detected"
        );
    }

    #[test]
    fn only_the_entropy_reseeded_fields_are_normalized() {
        let expected = vector("VOLATILE_BEFORE_SAVE");
        let permall = vector("PERMALL_BEFORE_SAVE");
        let mut state = decode_volatile(permall, expected).expect("the record decodes");
        state.orderly.drbg_state.seed = flipped_secret(&state.orderly.drbg_state.seed);
        state.state_reset.null_proof = flipped_secret(&state.state_reset.null_proof);
        state.state_reset.null_seed = flipped_secret(&state.state_reset.null_seed);
        state.state_reset.commit_nonce = flipped_secret(&state.state_reset.commit_nonce);
        let mutated = marshal_volatile_state(&state).expect("the mutation serializes");
        assert_eq!(
            compare_volatile("BEFORE_SAVE", expected, &mutated),
            Ok(()),
            "the host-entropy reseeded secrets have no injectable oracle value"
        );

        let mut state = decode_volatile(permall, expected).expect("the record decodes");
        state.orderly.drbg_state.reseed_counter =
            state.orderly.drbg_state.reseed_counter.wrapping_add(1);
        let mutated = marshal_volatile_state(&state).expect("the mutation serializes");
        assert!(
            compare_volatile("BEFORE_SAVE", expected, &mutated).is_err(),
            "the reseed counter right next to the seed stays byte-compared"
        );

        let expected = vector("PERMALL_AFTER_RETRY");
        let mut state = materialize_permanent(expected).expect("the record decodes");
        state.orderly.drbg_state.seed = flipped_secret(&state.orderly.drbg_state.seed);
        let mutated = persistent_all_store(&state).expect("the mutation serializes");
        assert!(
            compare_permanent("AFTER_RETRY", expected, &mutated).is_err(),
            "the shared manufacture-time DRBG stays byte-compared before any live copy"
        );

        let expected = vector("PERMALL_BEFORE_SAVE");
        let mut state = materialize_permanent(expected).expect("the record decodes");
        state.orderly.drbg_state.seed = flipped_secret(&state.orderly.drbg_state.seed);
        let mutated = persistent_all_store(&state).expect("the mutation serializes");
        assert_eq!(
            compare_permanent("BEFORE_SAVE", expected, &mutated),
            Ok(()),
            "the reseeded live DRBG copied into NV is the only permanent allowance"
        );
    }

    #[test]
    fn a_missing_state_partner_fails_the_comparison() {
        let volatile = vector("VOLATILE_BEFORE_SAVE");
        assert!(
            compare_volatile("WITHOUT_PARTNER", volatile, volatile).is_err(),
            "a volatile comparison requires the paired permanent record"
        );
    }

    #[test]
    fn the_fixture_parses_into_the_expected_records() {
        let all = vectors();
        assert_eq!(all.len(), 84);
        let responses = all
            .iter()
            .filter(|vector| record_kind(vector.name) == RecordKind::Response)
            .count();
        let permanent = all
            .iter()
            .filter(|vector| record_kind(vector.name) == RecordKind::Permanent)
            .count();
        let volatile = all
            .iter()
            .filter(|vector| record_kind(vector.name) == RecordKind::Volatile)
            .count();
        assert_eq!((responses, permanent, volatile), (57, 14, 13));
        for boundary in STATE_BOUNDARIES {
            assert!(
                FIXTURE.find(&format!("PERMALL_{boundary}")).is_some(),
                "PERMALL_{boundary}"
            );
            assert!(
                FIXTURE.find(&format!("VOLATILE_{boundary}")).is_some(),
                "VOLATILE_{boundary}"
            );
        }
    }

    #[test]
    fn every_record_validates_against_its_declared_kind() {
        for vector in vectors() {
            validate_record(vector.name, vector.bytes)
                .unwrap_or_else(|error| panic!("{}: {error}", vector.name));
        }
    }

    #[test]
    fn state_records_round_trip_through_the_production_codecs() {
        for boundary in STATE_BOUNDARIES {
            let permall = vector(&format!("PERMALL_{boundary}"));
            let state = materialize_permanent(permall)
                .unwrap_or_else(|error| panic!("PERMALL_{boundary}: {error}"));
            assert_eq!(
                persistent_all_store(&state).expect("the state serializes"),
                permall,
                "PERMALL_{boundary} round-trips through the production store"
            );

            let blob = vector(&format!("VOLATILE_{boundary}"));
            let owned = decode_volatile(permall, blob)
                .unwrap_or_else(|error| panic!("VOLATILE_{boundary}: {error}"));
            assert_eq!(
                marshal_volatile_state(&owned).expect("the volatile state serializes"),
                blob,
                "VOLATILE_{boundary} round-trips through the production store"
            );
        }
    }

    #[test]
    fn state_records_are_not_interpreted_as_responses() {
        for vector in vectors() {
            if record_kind(vector.name) == RecordKind::Response {
                continue;
            }
            let renamed =
                vector
                    .name
                    .replacen("PERMALL_", "R1_", 1)
                    .replacen("VOLATILE_", "R2_", 1);
            assert_eq!(record_kind(&renamed), RecordKind::Response);
            assert!(
                validate_record(&renamed, vector.bytes).is_err(),
                "{} must not validate as a response",
                vector.name
            );
        }
    }

    #[test]
    fn response_records_are_not_valid_state_records() {
        let response = vector("RETRY_FIRST_DA_AUTH");
        assert!(validate_record("PERMALL_RETRY_FIRST_DA_AUTH", response).is_err());
        assert!(validate_record("VOLATILE_FRESH_STARTUP", response).is_err());
    }

    #[test]
    fn a_mislabelled_state_record_is_rejected() {
        let permall = vector("PERMALL_FRESH_STARTUP");
        let volatile = vector("VOLATILE_FRESH_STARTUP");
        assert!(
            validate_record("VOLATILE_FRESH_STARTUP", permall).is_err(),
            "a permanent payload must not validate as a volatile record"
        );
        assert!(
            validate_record("PERMALL_FRESH_STARTUP", volatile).is_err(),
            "a volatile payload must not validate as a permanent record"
        );
        assert!(
            validate_record("VOLATILE_WITHOUT_PARTNER", volatile).is_err(),
            "a volatile record requires its permanent partner"
        );
    }

    #[test]
    fn a_corrupted_state_record_is_rejected() {
        for name in ["PERMALL_FRESH_STARTUP", "VOLATILE_FRESH_STARTUP"] {
            let bytes = vector(name);
            let mut truncated = bytes.to_vec();
            truncated.pop();
            assert!(
                validate_record(name, &truncated).is_err(),
                "{name} truncated"
            );
            let mut extended = bytes.to_vec();
            extended.push(0x00);
            assert!(validate_record(name, &extended).is_err(), "{name} extended");
            let mut corrupted = bytes.to_vec();
            corrupted[0] ^= 0xff;
            assert!(
                validate_record(name, &corrupted).is_err(),
                "{name} corrupted"
            );
        }
    }

    #[test]
    fn fixture_regeneration_is_deterministic() {
        let records: Vec<(&str, &[u8])> = vectors()
            .into_iter()
            .map(|vector| (vector.name, vector.bytes))
            .collect();
        let packed = oracles::synthesize(
            FIXTURE.magic(),
            oracles::VERSION,
            records.len() as u16,
            &records,
        );
        assert_eq!(
            packed,
            FIXTURE.bytes(),
            "packing the parsed records is stable"
        );
    }

    #[test]
    fn the_captured_state_relations_match_the_upstream_da_arithmetic() {
        let fresh = volatile_record("FRESH_STARTUP");
        let fresh_permanent = permanent_record("FRESH_STARTUP");
        assert_eq!(
            fresh_permanent.persistent.time_epoch, 1,
            "the first startup rolls the epoch"
        );
        assert!(!fresh.timer_stopped, "startup consumes the stopped timer");
        assert!(!fresh.timer_reset, "startup consumes the reset timer");
        assert!(!fresh.da_used);
        assert_eq!(fresh_permanent.persistent.failed_tries, 0);

        let after_retry = permanent_record("AFTER_RETRY");
        assert_eq!(after_retry.persistent.orderly_state, 0xfffe);
        assert_eq!(
            after_retry.persistent.failed_tries, 0,
            "a retry is not a failure"
        );
        assert!(volatile_record("AFTER_RETRY").da_used);

        let failed = volatile_record("AFTER_AUTH_FAIL");
        assert_eq!(
            failed.orderly.self_heal_timer, failed.time,
            "a failure rewinds the self-heal timer to the current TPM time"
        );
        assert_eq!(
            permanent_record("AFTER_AUTH_FAIL").persistent.failed_tries,
            1
        );

        let after_dap = permanent_record("AFTER_DAP");
        assert_eq!(
            (
                after_dap.persistent.failed_tries,
                after_dap.persistent.max_tries,
                after_dap.persistent.recovery_time,
                after_dap.persistent.lockout_recovery,
            ),
            (1, 2, 1, 1),
            "DictionaryAttackParameters preserves failedTries"
        );

        let locked = volatile_record("AT_LOCKOUT");
        let locked_permanent = permanent_record("AT_LOCKOUT");
        assert_eq!(
            locked_permanent.persistent.failed_tries, locked_permanent.persistent.max_tries,
            "the boundary failure reaches maxTries"
        );
        assert_eq!(locked.orderly.self_heal_timer, locked.time);

        let healed = volatile_record("AFTER_SELF_HEAL");
        assert_eq!(
            permanent_record("AFTER_SELF_HEAL").persistent.failed_tries,
            1
        );
        assert_eq!(
            healed.orderly.self_heal_timer,
            locked.orderly.self_heal_timer + 1_000,
            "one consumed interval advances the timer by exactly recoveryTime"
        );
        assert!(healed.time - healed.orderly.self_heal_timer < 1_000);

        let bad_lockout = volatile_record("AFTER_BAD_LOCKOUT");
        assert!(
            !permanent_record("AFTER_BAD_LOCKOUT")
                .persistent
                .lockout_auth_enabled
        );
        assert_eq!(
            bad_lockout.orderly.lockout_timer, bad_lockout.time,
            "a lockout failure rewinds the lockout timer to the current TPM time"
        );

        let reenabled = volatile_record("AFTER_LOCKOUT_RECOVERY");
        assert!(
            permanent_record("AFTER_LOCKOUT_RECOVERY")
                .persistent
                .lockout_auth_enabled
        );
        assert!(
            (reenabled.time - reenabled.orderly.lockout_timer) / 1_000 >= 1,
            "re-enabling waited out the configured lockout interval"
        );

        let orderly = permanent_record("AFTER_ORDERLY");
        assert_eq!(orderly.persistent.failed_tries, 0, "no synthetic failure");
        assert_eq!(
            orderly.persistent.time_epoch, 2,
            "each power cycle rolls one epoch"
        );
        assert!(!volatile_record("AFTER_ORDERLY").da_used);

        let unorderly = permanent_record("AFTER_UNORDERLY");
        let unorderly_volatile = volatile_record("AFTER_UNORDERLY");
        assert_eq!(
            unorderly.persistent.failed_tries, 1,
            "daUsed adds one failure"
        );
        assert_eq!(unorderly.persistent.time_epoch, 3);
        assert_eq!(unorderly_volatile.orderly.self_heal_timer, 0);
        assert_eq!(unorderly_volatile.orderly.lockout_timer, 0);
        assert!(!unorderly_volatile.da_used);

        let before = volatile_record("BEFORE_SAVE");
        let before_permanent = permanent_record("BEFORE_SAVE");
        assert_eq!(
            before_permanent.persistent.failed_tries, before_permanent.persistent.max_tries,
            "the save happens while locked out"
        );
        assert!(before.time - before.orderly.self_heal_timer < 1_000);
        assert!(!before.timer_stopped);

        let restored = volatile_record("AFTER_RESTORE");
        let restored_permanent = permanent_record("AFTER_RESTORE");
        assert_eq!(
            restored_permanent.persistent.failed_tries,
            before_permanent.persistent.failed_tries
        );
        assert_eq!(
            restored_permanent.persistent.time_epoch, before_permanent.persistent.time_epoch,
            "restoring a running timer does not roll a new epoch"
        );
        assert_eq!(
            restored.time, before.time,
            "the restored TPM time continues from the save"
        );
        assert_eq!(restored.tpm_time, before.tpm_time);
        assert_eq!(
            restored.orderly.self_heal_timer,
            before.orderly.self_heal_timer
        );
        assert_eq!(restored.orderly.lockout_timer, before.orderly.lockout_timer);
        assert!(
            !restored.timer_stopped,
            "the restored timer is still running"
        );
        assert_eq!(restored.da_used, before.da_used);

        let recovered = volatile_record("AFTER_RESTORE_RECOVERY");
        let recovered_permanent = permanent_record("AFTER_RESTORE_RECOVERY");
        assert_eq!(recovered_permanent.persistent.failed_tries, 1);
        assert_eq!(
            recovered_permanent.persistent.time_epoch, before_permanent.persistent.time_epoch,
            "recovery after restore rolls no epoch"
        );
        assert_eq!(
            recovered.orderly.self_heal_timer,
            before.orderly.self_heal_timer + 1_000,
            "the interval elapsed across the restore is consumed exactly once"
        );
        assert!(recovered.time - before.time >= 1_000);
    }

    #[test]
    fn the_retry_and_lockout_vectors_carry_the_upstream_warning_codes() {
        for (name, code) in [
            ("RETRY_FIRST_DA_AUTH", 0x0000_0922u32),
            ("RETRY_BEFORE_UNORDERLY", 0x0000_0922),
            ("RETRY_BEFORE_RESTORE", 0x0000_0922),
            ("AUTH_FAIL_AFTER_RETRY", 0x0000_098e),
            ("AUTH_FAIL_TO_LOCKOUT", 0x0000_098e),
            ("DAP_BAD_LOCKOUT_AUTH", 0x0000_098e),
            ("NODA_BAD_AUTH", 0x0000_09a2),
            ("WRITE_GOOD_LOCKED", 0x0000_0921),
            ("DAP_WHILE_DISABLED", 0x0000_0921),
            ("WRITE_GOOD_LOCKED_AFTER_RESTORE", 0x0000_0921),
            ("DAP_TRUNC_P1", 0x0000_01da),
            ("DAP_TRUNC_P2", 0x0000_02da),
            ("DAP_TRUNC_P3", 0x0000_03da),
            ("DAP_TRAILING", 0x0000_0095),
            ("DAP_WRONG_HANDLE", 0x0000_0184),
            ("DAP_NO_SESSIONS", 0x0000_0125),
        ] {
            let bytes = vector(name);
            assert_eq!(
                u32::from_be_bytes(bytes[6..10].try_into().expect("four bytes")),
                code,
                "{name}"
            );
        }
    }

    #[test]
    fn the_records_are_sorted_and_unique() {
        oracles::assert_names_are_sorted_and_unique(&FIXTURE);
    }

    #[test]
    fn a_truncated_or_extended_fixture_is_rejected_without_panicking() {
        oracles::assert_rejects_truncation_and_trailing_bytes(&FIXTURE);
    }

    #[test]
    fn a_corrupted_header_is_rejected() {
        oracles::assert_rejects_a_corrupted_header(&FIXTURE);
    }

    #[test]
    fn a_corrupted_record_is_rejected() {
        oracles::assert_rejects_a_corrupted_record(&FIXTURE);
    }

    #[test]
    fn foreign_magics_do_not_open_the_fixture() {
        for magic in [b"NVORACLE", b"FCORACLE"] {
            let foreign = oracles::synthesize(magic, oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
            assert!(FIXTURE.parse(&foreign).is_none());
        }
    }
}
