use crate::ffi::types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::crypto::{DRBG_MAGIC, Drbg, EntropySource};
use super::nv::RAM_INDEX_SPACE;
use super::persistent::{
    OwnedCommandBitmap, OwnedDrbgState, OwnedIndexOrderlyRam, OwnedOrderlyData, OwnedPcrAllocation,
    OwnedPcrPolicyEntry, OwnedPcrSelection, OwnedPersistentData, OwnedPersistentState, OwnedSecret,
    OwnedUserNvram,
};
use super::profile::{ATTRIBUTE_DRBG_CONTINUOUS_TEST, ValidatedProfile, command_enabled};

const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_SHA384: u16 = 0x000c;
const TPM_ALG_SHA512: u16 = 0x000d;

const PRIMARY_SEED_SIZE: usize = 64;
const PROOF_SIZE: usize = 64;

const COMMIT_NONCE_SIZE: usize = 64;

use super::capability::properties::{
    PLATFORM_FIRMWARE_V1 as FIRMWARE_V1, PLATFORM_FIRMWARE_V2 as FIRMWARE_V2,
};

const TPM_SU_CLEAR: u16 = 0x0000;

const SEED_COMPAT_LEVEL_LAST: u8 = 1;

const COMMAND_FIRST: u32 = 0x11f;
const COMMAND_BITMAP_BYTES: usize = 17;
const CC_PP_COMMANDS: u32 = 0x0000_012d;
const CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0000_0140;

const DA_MAX_TRIES: u32 = 3;
const DA_RECOVERY_TIME: u32 = 1000;
const DA_LOCKOUT_RECOVERY: u32 = 1000;

const PCR_BANK_ALGS: [u16; 4] = [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512];
const PCR_SELECT_ALL: [u8; 3] = [0xff, 0xff, 0xff];

fn generate_secret(drbg: &mut Drbg, len: usize) -> Result<OwnedSecret, TpmResult> {
    let mut bytes = vec![0u8; len];
    drbg.generate(&mut bytes)?;
    Ok(OwnedSecret::from_vec(bytes))
}

fn empty_secret() -> OwnedSecret {
    OwnedSecret::from_vec(Vec::new())
}

fn command_bitmap(command_codes: &[u32]) -> OwnedCommandBitmap {
    let mut bytes = vec![0u8; COMMAND_BITMAP_BYTES];
    for &code in command_codes {
        let bit = (code - COMMAND_FIRST) as usize;
        bytes[bit / 8] |= 1 << (bit % 8);
    }
    OwnedCommandBitmap {
        compressed: false,
        bytes,
    }
}

pub(super) fn manufacture_state(
    profile: ValidatedProfile,
    entropy: EntropySource,
) -> Result<OwnedPersistentState, TpmResult> {
    let _ = entropy(&mut []);
    let continuous_test = profile.attribute_enabled(ATTRIBUTE_DRBG_CONTINUOUS_TEST);
    let mut drbg = Drbg::instantiate(entropy, continuous_test).map_err(|_| TPM_FAIL)?;
    generate_secret(&mut drbg, COMMIT_NONCE_SIZE)?;
    let ep_seed = generate_secret(&mut drbg, PRIMARY_SEED_SIZE)?;
    let sp_seed = generate_secret(&mut drbg, PRIMARY_SEED_SIZE)?;
    let pp_seed = generate_secret(&mut drbg, PRIMARY_SEED_SIZE)?;
    let ph_proof = generate_secret(&mut drbg, PROOF_SIZE)?;
    let sh_proof = generate_secret(&mut drbg, PROOF_SIZE)?;
    let eh_proof = generate_secret(&mut drbg, PROOF_SIZE)?;

    let level = profile.state_format_level;
    let section_version: u16 = if level <= 2 { 4 } else { 5 };
    let envelope_version: u16 = if level == 1 { 3 } else { 4 };

    let audit_commands = if command_enabled(&profile.commands, CC_SET_COMMAND_CODE_AUDIT_STATUS) {
        command_bitmap(&[CC_SET_COMMAND_CODE_AUDIT_STATUS])
    } else {
        command_bitmap(&[])
    };

    let persistent = OwnedPersistentData {
        section_version,
        disable_clear: false,
        owner_alg: TPM_ALG_NULL,
        endorsement_alg: TPM_ALG_NULL,
        lockout_alg: TPM_ALG_NULL,
        owner_policy: Vec::new(),
        endorsement_policy: Vec::new(),
        lockout_policy: Vec::new(),
        owner_auth: empty_secret(),
        endorsement_auth: empty_secret(),
        lockout_auth: empty_secret(),
        ep_seed,
        sp_seed,
        pp_seed,
        ph_proof,
        sh_proof,
        eh_proof,
        total_reset_count: 0,
        reset_count: 0,
        pcr_policies: core::array::from_fn(|_| OwnedPcrPolicyEntry {
            hash_alg: TPM_ALG_NULL,
            policy: Vec::new(),
        }),
        pcr_allocated: OwnedPcrAllocation {
            selections: PCR_BANK_ALGS
                .iter()
                .map(|&hash_alg| OwnedPcrSelection {
                    hash_alg,
                    select: PCR_SELECT_ALL.to_vec(),
                })
                .collect(),
        },
        pp_list: command_bitmap(&[CC_PP_COMMANDS]),
        failed_tries: 0,
        max_tries: DA_MAX_TRIES,
        recovery_time: DA_RECOVERY_TIME,
        lockout_recovery: DA_LOCKOUT_RECOVERY,
        lockout_auth_enabled: true,
        orderly_state: TPM_SU_CLEAR,
        audit_commands,
        audit_hash_alg: TPM_ALG_SHA512,
        audit_counter: 0,
        algorithm_set: 0,
        firmware_v1: FIRMWARE_V1,
        firmware_v2: FIRMWARE_V2,
        time_epoch: 0,
        shadow_pcr_allocated: None,
        ep_seed_compat_level: SEED_COMPAT_LEVEL_LAST,
        sp_seed_compat_level: SEED_COMPAT_LEVEL_LAST,
        pp_seed_compat_level: SEED_COMPAT_LEVEL_LAST,
    };

    let orderly = OwnedOrderlyData {
        clock: 0,
        clock_safe: 1,
        drbg_state: OwnedDrbgState {
            reseed_counter: drbg.reseed_counter(),
            drbg_magic: DRBG_MAGIC,
            seed: OwnedSecret::from_vec(drbg.seed().to_vec()),
            last_value: drbg.last_value(),
        },
        self_heal_timer: 0,
        lockout_timer: 0,
        time: 0,
    };

    Ok(OwnedPersistentState {
        profile,
        persistent,
        orderly,
        state_reset: None,
        state_clear: None,
        index_orderly_ram: OwnedIndexOrderlyRam {
            sourceside_size: RAM_INDEX_SPACE as u32,
            entries: Vec::new(),
            terminated: true,
            used_bytes: 0,
        },
        user_nvram: OwnedUserNvram {
            entries: Vec::new(),
            max_count: 0,
            required_capacity: 12,
        },
        envelope_version,
        read_su_state: false,
    })
}

#[cfg(test)]
mod tests {
    use super::super::crypto::vector_record;
    use super::super::profile::validate_user_profile;
    use super::*;
    use crate::library::constants::TPM_FAIL;
    use std::sync::Mutex;

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

    fn zero_length_failing_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        if buffer.is_empty() {
            return Err(TPM_FAIL);
        }
        deterministic_entropy(buffer)
    }

    static ENTROPY_REQUESTS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

    fn recording_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        ENTROPY_REQUESTS.lock().unwrap().push(buffer.len());
        deterministic_entropy(buffer)
    }

    fn null_profile() -> ValidatedProfile {
        validate_user_profile(None).expect("the null profile validates")
    }

    fn continuous_test_profile() -> ValidatedProfile {
        validate_user_profile(Some(
            br#"{"Name":"custom","Attributes":"drbg-continous-test"}"#,
        ))
        .expect("the custom profile with the attribute validates")
    }

    #[test]
    fn entropy_request_pattern_matches_upstream() {
        ENTROPY_REQUESTS.lock().unwrap().clear();
        manufacture_state(null_profile(), recording_entropy).expect("manufacture succeeds");
        assert_eq!(*ENTROPY_REQUESTS.lock().unwrap(), [0, 48]);
    }

    #[test]
    fn secrets_and_drbg_state_match_the_vendored_oracle() {
        let record = vector_record(false);
        let state =
            manufacture_state(null_profile(), deterministic_entropy).expect("manufacture succeeds");
        let persistent = &state.persistent;
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
        let drbg = &state.orderly.drbg_state;
        assert_eq!(drbg.seed.expose(), record.final_seed);
        assert_eq!(&drbg.seed.expose()[..32], &record.final_seed[..32], "key");
        assert_eq!(&drbg.seed.expose()[32..], &record.final_seed[32..], "IV");
        assert_eq!(drbg.reseed_counter, record.final_reseed_counter);
        assert_eq!(drbg.reseed_counter, 8);
        assert_eq!(drbg.last_value, [0; 4]);
        assert_eq!(drbg.drbg_magic, DRBG_MAGIC);
    }

    #[test]
    fn commit_nonce_draw_advances_the_drbg_before_hierarchy_generation() {
        let record = vector_record(false);
        assert_ne!(record.ep_seed, record.commit_nonce);
        let state =
            manufacture_state(null_profile(), deterministic_entropy).expect("manufacture succeeds");
        assert_eq!(state.persistent.ep_seed.expose(), record.ep_seed);
        assert_ne!(state.persistent.ep_seed.expose(), record.commit_nonce);
    }

    #[test]
    fn continuous_test_profile_preserves_the_oracle_last_value() {
        let record = vector_record(true);
        let state = manufacture_state(continuous_test_profile(), deterministic_entropy)
            .expect("manufacture succeeds");
        assert_eq!(state.persistent.ep_seed.expose(), record.ep_seed);
        let drbg = &state.orderly.drbg_state;
        assert_eq!(drbg.seed.expose(), record.final_seed);
        assert_eq!(drbg.last_value, record.final_last_value);
        assert_ne!(drbg.last_value, [0; 4]);
    }

    #[test]
    fn zero_length_reset_failure_is_ignored() {
        let state = manufacture_state(null_profile(), zero_length_failing_entropy)
            .expect("manufacture succeeds despite the failed reset");
        assert_eq!(
            state.persistent.ep_seed.expose(),
            vector_record(false).ep_seed
        );
    }

    #[test]
    fn entropy_failure_is_transactional_and_retryable() {
        assert_eq!(
            manufacture_state(null_profile(), failing_entropy)
                .map(|_| ())
                .unwrap_err(),
            TPM_FAIL
        );
        manufacture_state(null_profile(), deterministic_entropy).expect("a later attempt succeeds");
    }

    #[test]
    fn manufactured_debug_output_contains_no_secret_bytes() {
        let record = vector_record(false);
        let state =
            manufacture_state(null_profile(), deterministic_entropy).expect("manufacture succeeds");
        let formatted = format!("{state:?}");
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
}
