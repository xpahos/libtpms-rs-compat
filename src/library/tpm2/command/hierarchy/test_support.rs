// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::CommandInput;
use crate::library::cancel::CancellationToken;
use crate::library::tpm2::clock::SteppingClock;
use crate::library::tpm2::command::core::test_support::tpm2b;
pub(super) use crate::library::tpm2::command::core::test_support::{
    command, framed, get_capability, shutdown, startup,
};
pub(super) use crate::library::tpm2::command::core::test_support::{occupied_slots, reload};
pub(super) use crate::library::tpm2::command::nv::test_support::nvram_handles;
use crate::library::tpm2::crypto::EntropySource;
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::golden_responses::hierarchy_management::vector;
use crate::library::tpm2::hierarchy::TPM_RH_LOCKOUT;
use crate::library::tpm2::nv::build_nv_image;
use crate::library::tpm2::persistent::{OwnedSecret, persistent_all_store};
use crate::library::tpm2::process::process;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::test_support::counter_entropy;
use crate::library::tpm2::{attach_volatile_blob_for_replay, restore_permanent_blob_for_test};
use crate::types::TpmResult;
pub(super) const TPM_ALG_NULL: u16 = 0x0010;
pub(super) const TPM_ALG_SHA256: u16 = 0x000b;

pub(super) const RC_SUCCESS: u32 = 0x000;
pub(super) const RC_VALUE_H1: u32 = 0x184;
pub(super) const RC_INSUFFICIENT_H1: u32 = 0x19a;
pub(super) const RC_HIERARCHY_H1: u32 = 0x185;
pub(super) const RC_AUTH_TYPE: u32 = 0x124;
pub(super) const RC_AUTH_MISSING: u32 = 0x125;
pub(super) const RC_DISABLED: u32 = 0x120;
pub(super) const RC_AUTH_FAIL: u32 = 0x08e;
pub(super) const RC_SIZE: u32 = 0x095;
pub(super) const RC_NV_UNAVAILABLE: u32 = 0x923;
pub(super) const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
pub(super) const RC_LOCKOUT: u32 = 0x921;

pub(super) fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("SHA-256 is compiled in");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().try_into().expect("a 32-byte digest")
}

fn secret_fingerprint(secret: &OwnedSecret) -> [u8; 32] {
    fingerprint(secret.expose())
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Secrets {
    pub(in crate::library::tpm2::command) ep_seed: [u8; 32],
    pub(in crate::library::tpm2::command) sp_seed: [u8; 32],
    pub(in crate::library::tpm2::command) pp_seed: [u8; 32],
    pub(in crate::library::tpm2::command) eh_proof: [u8; 32],
    pub(in crate::library::tpm2::command) sh_proof: [u8; 32],
    pub(in crate::library::tpm2::command) ph_proof: [u8; 32],
    pub(in crate::library::tpm2::command) ep_seed_compat_level: u8,
    pub(in crate::library::tpm2::command) sp_seed_compat_level: u8,
    pub(in crate::library::tpm2::command) pp_seed_compat_level: u8,
    pub(in crate::library::tpm2::command) owner_auth: [u8; 32],
    pub(in crate::library::tpm2::command) endorsement_auth: [u8; 32],
    pub(in crate::library::tpm2::command) lockout_auth: [u8; 32],
    pub(in crate::library::tpm2::command) platform_auth: [u8; 32],
}

pub(super) fn secrets(runtime: &Tpm2Runtime) -> Secrets {
    let persistent = &runtime.state().persistent;
    Secrets {
        ep_seed: secret_fingerprint(&persistent.ep_seed),
        sp_seed: secret_fingerprint(&persistent.sp_seed),
        pp_seed: secret_fingerprint(&persistent.pp_seed),
        eh_proof: secret_fingerprint(&persistent.eh_proof),
        sh_proof: secret_fingerprint(&persistent.sh_proof),
        ph_proof: secret_fingerprint(&persistent.ph_proof),
        ep_seed_compat_level: persistent.ep_seed_compat_level,
        sp_seed_compat_level: persistent.sp_seed_compat_level,
        pp_seed_compat_level: persistent.pp_seed_compat_level,
        owner_auth: secret_fingerprint(&persistent.owner_auth),
        endorsement_auth: secret_fingerprint(&persistent.endorsement_auth),
        lockout_auth: secret_fingerprint(&persistent.lockout_auth),
        platform_auth: runtime
            .live
            .state_clear
            .as_ref()
            .map_or([0; 32], |clear| secret_fingerprint(&clear.platform_auth)),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Policies {
    pub(in crate::library::tpm2::command) owner: (u16, Vec<u8>),
    pub(in crate::library::tpm2::command) endorsement: (u16, Vec<u8>),
    pub(in crate::library::tpm2::command) lockout: (u16, Vec<u8>),
    pub(in crate::library::tpm2::command) platform: (u16, Vec<u8>),
    pub(in crate::library::tpm2::command) pcr: Vec<(u16, Vec<u8>)>,
}

pub(super) fn policies(runtime: &Tpm2Runtime) -> Policies {
    let persistent = &runtime.state().persistent;
    let clear = runtime.live.state_clear.as_ref().expect("started runtime");
    Policies {
        owner: (persistent.owner_alg, persistent.owner_policy.clone()),
        endorsement: (
            persistent.endorsement_alg,
            persistent.endorsement_policy.clone(),
        ),
        lockout: (persistent.lockout_alg, persistent.lockout_policy.clone()),
        platform: (clear.platform_alg, clear.platform_policy.clone()),
        pcr: persistent
            .pcr_policies
            .iter()
            .map(|entry| (entry.hash_alg, entry.policy.clone()))
            .collect(),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DictionaryAttackState {
    pub(in crate::library::tpm2::command) failed_tries: u32,
    pub(in crate::library::tpm2::command) max_tries: u32,
    pub(in crate::library::tpm2::command) recovery_time: u32,
    pub(in crate::library::tpm2::command) lockout_recovery: u32,
    pub(in crate::library::tpm2::command) lockout_auth_enabled: bool,
    pub(in crate::library::tpm2::command) self_heal_timer: u64,
    pub(in crate::library::tpm2::command) lockout_timer: u64,
}

pub(super) fn dictionary_attack_state(runtime: &Tpm2Runtime) -> DictionaryAttackState {
    let persistent = &runtime.state().persistent;
    DictionaryAttackState {
        failed_tries: persistent.failed_tries,
        max_tries: persistent.max_tries,
        recovery_time: persistent.recovery_time,
        lockout_recovery: persistent.lockout_recovery,
        lockout_auth_enabled: persistent.lockout_auth_enabled,
        self_heal_timer: runtime.live.orderly.self_heal_timer,
        lockout_timer: runtime.live.orderly.lockout_timer,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Enables {
    pub(in crate::library::tpm2::command) ph_enable: bool,
    pub(in crate::library::tpm2::command) sh_enable: bool,
    pub(in crate::library::tpm2::command) eh_enable: bool,
    pub(in crate::library::tpm2::command) ph_enable_nv: bool,
}

pub(super) fn enables(runtime: &Tpm2Runtime) -> Enables {
    let clear = runtime.live.state_clear.as_ref().expect("started runtime");
    Enables {
        ph_enable: runtime.live.ph_enable,
        sh_enable: clear.sh_enable,
        eh_enable: clear.eh_enable,
        ph_enable_nv: clear.ph_enable_nv,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Counters {
    pub(in crate::library::tpm2::command) reset_count: u32,
    pub(in crate::library::tpm2::command) total_reset_count: u64,
    pub(in crate::library::tpm2::command) restart_count: u32,
    pub(in crate::library::tpm2::command) clear_count: u32,
    pub(in crate::library::tpm2::command) pcr_counter: u32,
    pub(in crate::library::tpm2::command) audit_counter: u64,
}

pub(super) fn counters(runtime: &Tpm2Runtime) -> Counters {
    let persistent = &runtime.state().persistent;
    let reset = runtime.live.state_reset.as_ref().expect("started runtime");
    Counters {
        reset_count: persistent.reset_count,
        total_reset_count: persistent.total_reset_count,
        restart_count: reset.restart_count,
        clear_count: reset.clear_count,
        pcr_counter: reset.pcr_counter,
        audit_counter: persistent.audit_counter,
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(in crate::library::tpm2::command) failure_mode: bool,
    pub(in crate::library::tpm2::command) nv_update_pending: bool,
    pub(in crate::library::tpm2::command) disable_clear: bool,
    pub(in crate::library::tpm2::command) orderly_state: u16,
    pub(in crate::library::tpm2::command) clock: u64,
    pub(in crate::library::tpm2::command) clock_safe: u8,
    pub(in crate::library::tpm2::command) secrets: Secrets,
    pub(in crate::library::tpm2::command) policies: Policies,
    pub(in crate::library::tpm2::command) dictionary_attack: DictionaryAttackState,
    pub(in crate::library::tpm2::command) enables: Enables,
    pub(in crate::library::tpm2::command) counters: Counters,
    pub(in crate::library::tpm2::command) nvram_handles: Vec<u32>,
    pub(in crate::library::tpm2::command) occupied_slots: Vec<usize>,
    pub(in crate::library::tpm2::command) nv_memory: [u8; 32],
    pub(in crate::library::tpm2::command) pcr_auth_values: Vec<[u8; 32]>,
}

pub(super) fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
    let clear = runtime.live.state_clear.as_ref().expect("started runtime");
    Snapshot {
        failure_mode: runtime.failure_mode,
        nv_update_pending: runtime.nv_update_pending,
        disable_clear: runtime.state().persistent.disable_clear,
        orderly_state: runtime.state().persistent.orderly_state,
        clock: runtime.live.orderly.clock,
        clock_safe: runtime.live.orderly.clock_safe,
        secrets: secrets(runtime),
        policies: policies(runtime),
        dictionary_attack: dictionary_attack_state(runtime),
        enables: enables(runtime),
        counters: counters(runtime),
        nvram_handles: nvram_handles(runtime),
        occupied_slots: occupied_slots(runtime),
        nv_memory: fingerprint(&runtime.nv_memory),
        pcr_auth_values: clear
            .pcr_auth_values
            .iter()
            .map(secret_fingerprint)
            .collect(),
    }
}

#[track_caller]
pub(super) fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
    assert_eq!(&snapshot(runtime), before);
}

#[track_caller]
pub(super) fn assert_nv_image_is_current(runtime: &Tpm2Runtime) {
    assert_eq!(
        runtime.nv_memory,
        build_nv_image(runtime.state()).expect("the state serializes"),
        "the published NV image must follow the decoded state"
    );
}

pub(super) const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
pub(super) const TPM_CC_HIERARCHY_CONTROL: u32 = 0x0000_0121;
pub(super) const TPM_CC_CHANGE_PPS: u32 = 0x0000_0125;
pub(super) const TPM_CC_CLEAR: u32 = 0x0000_0126;
pub(super) const TPM_CC_CLEAR_CONTROL: u32 = 0x0000_0127;
pub(super) const TPM_CC_HIERARCHY_CHANGE_AUTH: u32 = 0x0000_0129;
pub(super) const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012a;
pub(super) const TPM_CC_PCR_SET_AUTH_POLICY: u32 = 0x0000_012c;
pub(super) const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x0000_012e;
pub(super) const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub(super) const TPM_CC_DA_LOCK_RESET: u32 = 0x0000_0139;
pub(super) const TPM_CC_DA_PARAMETERS: u32 = 0x0000_013a;
pub(super) const TPM_CC_NV_READ: u32 = 0x0000_014e;
pub(super) const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
pub(super) const TPM_CC_NV_READ_PUBLIC: u32 = 0x0000_0169;
pub(super) const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
pub(super) const TPM_CC_PCR_READ: u32 = 0x0000_017e;

pub(super) const TRANSIENT_FIRST: u32 = 0x8000_0000;
pub(super) const OWNER_INDEX: u32 = 0x0100_0001;
pub(super) const PLATFORM_INDEX: u32 = 0x0180_0001;
pub(super) const OWNER_PERSISTENT: u32 = 0x8100_0001;
pub(super) const PLATFORM_PERSISTENT: u32 = 0x8180_0001;

pub(super) const NV_OWNER_ATTRIBUTES: u32 = 0x0004_0004;
pub(super) const NV_PLATFORM_ATTRIBUTES: u32 = 0x4001_0001;

pub(super) const DIGEST: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

const AES_PRIMARY_PUBLIC: [u8; 18] = [
    0x00, 0x25, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43,
    0x00, 0x00,
];

pub(super) fn hierarchy_control(auth: u32, enable: u32, state: u8, password: &[u8]) -> Vec<u8> {
    let mut parameters = enable.to_be_bytes().to_vec();
    parameters.push(state);
    command(TPM_CC_HIERARCHY_CONTROL, &[auth], &[password], &parameters)
}

pub(super) fn change_pps(auth: u32, password: &[u8]) -> Vec<u8> {
    command(TPM_CC_CHANGE_PPS, &[auth], &[password], &[])
}

pub(super) fn clear(auth: u32, password: &[u8]) -> Vec<u8> {
    command(TPM_CC_CLEAR, &[auth], &[password], &[])
}

pub(super) fn clear_control(auth: u32, disable: u8, password: &[u8]) -> Vec<u8> {
    command(TPM_CC_CLEAR_CONTROL, &[auth], &[password], &[disable])
}

pub(super) fn da_lock_reset(auth: u32, password: &[u8]) -> Vec<u8> {
    command(TPM_CC_DA_LOCK_RESET, &[auth], &[password], &[])
}

pub(super) fn da_parameters(
    max_tries: u32,
    recovery_time: u32,
    lockout_recovery: u32,
    password: &[u8],
) -> Vec<u8> {
    let mut parameters = max_tries.to_be_bytes().to_vec();
    parameters.extend_from_slice(&recovery_time.to_be_bytes());
    parameters.extend_from_slice(&lockout_recovery.to_be_bytes());
    command(
        TPM_CC_DA_PARAMETERS,
        &[TPM_RH_LOCKOUT],
        &[password],
        &parameters,
    )
}

pub(super) fn set_primary_policy(
    auth: u32,
    policy: &[u8],
    hash_alg: u16,
    password: &[u8],
) -> Vec<u8> {
    let mut parameters = tpm2b(policy);
    parameters.extend_from_slice(&hash_alg.to_be_bytes());
    command(TPM_CC_SET_PRIMARY_POLICY, &[auth], &[password], &parameters)
}

pub(super) fn pcr_set_auth_policy(
    auth: u32,
    policy: &[u8],
    hash_alg: u16,
    pcr: u32,
    password: &[u8],
) -> Vec<u8> {
    let mut parameters = tpm2b(policy);
    parameters.extend_from_slice(&hash_alg.to_be_bytes());
    parameters.extend_from_slice(&pcr.to_be_bytes());
    command(
        TPM_CC_PCR_SET_AUTH_POLICY,
        &[auth],
        &[password],
        &parameters,
    )
}

pub(super) fn create_primary(hierarchy: u32) -> Vec<u8> {
    let mut sensitive = tpm2b(&[]);
    sensitive.extend_from_slice(&tpm2b(&[]));
    let mut parameters = tpm2b(&sensitive);
    parameters.extend_from_slice(&tpm2b(&AES_PRIMARY_PUBLIC));
    parameters.extend_from_slice(&tpm2b(&[]));
    parameters.extend_from_slice(&0u32.to_be_bytes());
    command(TPM_CC_CREATE_PRIMARY, &[hierarchy], &[&[]], &parameters)
}

pub(super) fn evict_control(auth: u32, object: u32, persistent: u32) -> Vec<u8> {
    command(
        TPM_CC_EVICT_CONTROL,
        &[auth, object],
        &[&[]],
        &persistent.to_be_bytes(),
    )
}

pub(super) fn nv_define(auth: u32, index: u32, attributes: u32, size: u16) -> Vec<u8> {
    let mut public = index.to_be_bytes().to_vec();
    public.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    public.extend_from_slice(&attributes.to_be_bytes());
    public.extend_from_slice(&tpm2b(&[]));
    public.extend_from_slice(&size.to_be_bytes());
    let mut parameters = tpm2b(&[]);
    parameters.extend_from_slice(&tpm2b(&public));
    command(TPM_CC_NV_DEFINE_SPACE, &[auth], &[&[]], &parameters)
}

pub(super) fn nv_read(index: u32, password: &[u8]) -> Vec<u8> {
    let mut parameters = 8u16.to_be_bytes().to_vec();
    parameters.extend_from_slice(&0u16.to_be_bytes());
    command(TPM_CC_NV_READ, &[index, index], &[password], &parameters)
}

pub(super) fn nv_read_public(index: u32) -> Vec<u8> {
    framed(TPM_CC_NV_READ_PUBLIC, &index.to_be_bytes(), false)
}

pub(super) fn read_public(handle: u32) -> Vec<u8> {
    framed(TPM_CC_READ_PUBLIC, &handle.to_be_bytes(), false)
}

pub(super) fn cap_transient() -> Vec<u8> {
    get_capability(1, TRANSIENT_FIRST, 8)
}

pub(super) fn cap_persistent() -> Vec<u8> {
    get_capability(1, 0x8100_0000, 8)
}

pub(super) fn cap_nv() -> Vec<u8> {
    get_capability(1, 0x0100_0000, 8)
}

pub(super) fn cap_permanent_flags() -> Vec<u8> {
    get_capability(6, 0x200, 1)
}

pub(super) fn cap_startup_clear() -> Vec<u8> {
    get_capability(6, 0x201, 1)
}

pub(super) fn cap_lockout() -> Vec<u8> {
    get_capability(6, 0x20e, 4)
}

pub(super) fn pcr_read_all() -> Vec<u8> {
    let mut payload = 4u32.to_be_bytes().to_vec();
    for alg in [0x0004u16, 0x000b, 0x000c, 0x000d] {
        payload.extend_from_slice(&alg.to_be_bytes());
        payload.extend_from_slice(&[0x03, 0x00, 0x04, 0x00]);
    }
    framed(TPM_CC_PCR_READ, &payload, false)
}

pub(super) fn flush(handle: u32) -> Vec<u8> {
    framed(TPM_CC_FLUSH_CONTEXT, &handle.to_be_bytes(), false)
}

pub(super) fn change_auth_command(hierarchy: u32, password: &[u8], new_auth: &[u8]) -> Vec<u8> {
    command(
        TPM_CC_HIERARCHY_CHANGE_AUTH,
        &[hierarchy],
        &[password],
        &tpm2b(new_auth),
    )
}

const ENTROPY: EntropySource = counter_entropy::<0x55>;

fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
    panic!("the replayed reference state never reseeds from host entropy");
}

pub(super) fn replay_clock() -> SteppingClock {
    SteppingClock::new(1_700_000_000_000, 4_000_000)
}

pub(super) fn oracle_runtime(clock: &SteppingClock) -> Tpm2Runtime {
    let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_READY"))
        .expect("the reference permanent state restores");
    attach_volatile_blob_for_replay(&mut runtime, vector("VOLATILE_READY"), clock)
        .expect("the reference volatile state attaches");
    runtime.entropy = unreachable_entropy;
    runtime
}

pub(super) fn try_exec(
    runtime: &mut Tpm2Runtime,
    clock: &SteppingClock,
    bytes: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
    process(
        runtime,
        crate::library::tpm2::PlatformInputs::at_locality(0),
        &input,
        clock,
        |_| Ok(()),
        CancellationToken::disabled(),
    )
}

#[track_caller]
pub(super) fn exec(runtime: &mut Tpm2Runtime, clock: &SteppingClock, bytes: &[u8]) -> Vec<u8> {
    try_exec(runtime, clock, bytes).expect("the command processes")
}

#[track_caller]
pub(super) fn exec_counting(
    runtime: &mut Tpm2Runtime,
    clock: &SteppingClock,
    bytes: &[u8],
    commits: &core::cell::Cell<u32>,
) -> Vec<u8> {
    let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
    process(
        runtime,
        crate::library::tpm2::PlatformInputs::at_locality(0),
        &input,
        clock,
        |_| {
            commits.set(commits.get() + 1);
            Ok(())
        },
        CancellationToken::disabled(),
    )
    .expect("the command processes")
}

#[track_caller]
pub(super) fn commits_for(bytes: &[u8]) -> u32 {
    let clock = replay_clock();
    let mut runtime = oracle_runtime(&clock);
    let commits = core::cell::Cell::new(0u32);
    exec_counting(&mut runtime, &clock, bytes, &commits);
    commits.get()
}

#[track_caller]
pub(super) fn expect(runtime: &mut Tpm2Runtime, clock: &SteppingClock, label: &str, bytes: &[u8]) {
    assert_eq!(exec(runtime, clock, bytes), vector(label), "{label}");
}

#[track_caller]
pub(super) fn replay(steps: &[(&str, Vec<u8>)]) -> Tpm2Runtime {
    let clock = replay_clock();
    let mut runtime = oracle_runtime(&clock);
    for (label, bytes) in steps {
        expect(&mut runtime, &clock, label, bytes);
    }
    runtime
}

#[track_caller]
pub(super) fn reboot(runtime: &Tpm2Runtime, clock: &SteppingClock) -> Tpm2Runtime {
    let blob = persistent_all_store(runtime.state()).expect("the permanent state serializes");
    let _ = clock;
    let mut rebooted =
        restore_permanent_blob_for_test(&blob).expect("the permanent state restores");
    rebooted.entropy = ENTROPY;
    rebooted
}
