use crate::ffi::types::TpmResult;
use crate::library::CommandInput;
use crate::library::tpm2::clock::SteppingClock;
pub(super) use crate::library::tpm2::command::core::test_support::{command, framed};
use crate::library::tpm2::crypto::Hasher;
pub(super) use crate::library::tpm2::golden_responses::platform_state::vector;
use crate::library::tpm2::nv::command_bitmap_image;
use crate::library::tpm2::persistent::{
    OwnedPersistentState, PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
};
use crate::library::tpm2::pp_list::PP_LIST_SIZE;
use crate::library::tpm2::process::process;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::{attach_volatile_blob_for_replay, restore_permanent_blob_for_test};
pub(super) const TPM_RH_OWNER: u32 = 0x4000_0001;
pub(super) const TPM_RH_NULL: u32 = 0x4000_0007;
pub(super) const TPM_RH_LOCKOUT: u32 = 0x4000_000a;
pub(super) const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
pub(super) const TPM_RH_PLATFORM: u32 = 0x4000_000c;
pub(super) const TPM_RH_ACT_0: u32 = 0x4000_0110;

pub(super) const TPM_CC_HIERARCHY_CONTROL: u32 = 0x0000_0121;
pub(super) const TPM_CC_CLEAR_CONTROL: u32 = 0x0000_0127;
pub(super) const TPM_CC_CLOCK_SET: u32 = 0x0000_0128;
pub(super) const TPM_CC_PP_COMMANDS: u32 = 0x0000_012d;
pub(super) const TPM_CC_CLOCK_RATE_ADJUST: u32 = 0x0000_0130;
pub(super) const TPM_CC_CREATE_PRIMARY: u32 = 0x0000_0131;
pub(super) const TPM_CC_SET_ALGORITHM_SET: u32 = 0x0000_013f;
pub(super) const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub(super) const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub(super) const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017a;
pub(super) const TPM_CC_PCR_READ: u32 = 0x0000_017e;
pub(super) const TPM_CC_READ_CLOCK: u32 = 0x0000_0181;
pub(super) const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub(super) const TPM_CC_PCR_SET_AUTH_VALUE: u32 = 0x0000_0183;
pub(super) const TPM_CC_ACT_SET_TIMEOUT: u32 = 0x0000_0198;

pub(super) const TPM_CAP_COMMANDS: u32 = 2;
pub(super) const TPM_CAP_PP_COMMANDS: u32 = 3;
pub(super) const TPM_CAP_TPM_PROPERTIES: u32 = 6;
pub(super) const TPM_CAP_ACT: u32 = 10;

pub(super) const TPM_PT_ALGORITHM_SET: u32 = 0x0000_020c;

pub(super) const RC_SUCCESS: u32 = 0x000;
pub(super) const RC_VALUE: u32 = 0x084;
pub(super) const RC_SIZE: u32 = 0x095;
pub(super) const RC_INITIALIZE: u32 = 0x100;
pub(super) const RC_COMMAND_CODE: u32 = 0x143;
pub(super) const RC_AUTH_MISSING: u32 = 0x125;
pub(super) const RC_VALUE_H1: u32 = 0x184;
pub(super) const RC_INSUFFICIENT_H1: u32 = 0x19a;
pub(super) const RC_VALUE_P1: u32 = 0x1c4;
pub(super) const RC_SIZE_P1: u32 = 0x1d5;
pub(super) const RC_INSUFFICIENT_P1: u32 = 0x1da;
pub(super) const RC_VALUE_P2: u32 = 0x2c4;
pub(super) const RC_INSUFFICIENT_P2: u32 = 0x2da;
pub(super) const RC_NV_UNAVAILABLE: u32 = 0x923;
pub(super) const RC_SESSION1_HANDLE: u32 = 0x98b;
pub(super) const RC_SESSION1_BAD_AUTH: u32 = 0x9a2;
pub(super) const RC_SESSION1_PP: u32 = 0x990;

pub(super) const DIGEST32: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
    panic!("the replayed reference state never reseeds from host entropy");
}

fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
    let len = buffer.len() as u8;
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(len) ^ 0x55;
    }
    Ok(())
}

pub(super) fn replay_clock() -> SteppingClock {
    SteppingClock::new(1_700_000_000_000, 4_000_000)
}

#[track_caller]
pub(super) fn restored(checkpoint: &str, clock: &SteppingClock) -> Box<Tpm2Runtime> {
    let mut runtime = restore_permanent_blob_for_test(vector(&format!("PERMALL_{checkpoint}")))
        .expect("the reference permanent state restores");
    attach_volatile_blob_for_replay(
        &mut runtime,
        vector(&format!("VOLATILE_{checkpoint}")),
        clock,
    )
    .expect("the reference volatile state attaches");
    runtime.entropy = unreachable_entropy;
    runtime
}

#[track_caller]
pub(super) fn ready(clock: &SteppingClock) -> Box<Tpm2Runtime> {
    restored("READY", clock)
}

#[track_caller]
pub(super) fn manufactured(_clock: &SteppingClock) -> Box<Tpm2Runtime> {
    restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
        .expect("the reference manufactured state restores")
}

#[track_caller]
pub(super) fn assert_matches_permall(runtime: &Tpm2Runtime, checkpoint: &str) {
    crate::library::tpm2::command::nv::test_support::assert_matches_oracle(
        runtime,
        vector(&format!("PERMALL_{checkpoint}")),
        &format!("PERMALL_{checkpoint}"),
    );
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct DurableState {
    pub(in crate::library::tpm2::command) orderly_state: u16,
    pub(in crate::library::tpm2::command) clock: u64,
    pub(in crate::library::tpm2::command) clock_safe: u8,
    pub(in crate::library::tpm2::command) algorithm_set: u32,
    pub(in crate::library::tpm2::command) pp_list: Vec<u8>,
    pub(in crate::library::tpm2::command) reset_count: u32,
    pub(in crate::library::tpm2::command) total_reset_count: u64,
}

fn durable_of(state: &OwnedPersistentState) -> DurableState {
    DurableState {
        orderly_state: state.persistent.orderly_state,
        clock: state.orderly.clock,
        clock_safe: state.orderly.clock_safe,
        algorithm_set: state.persistent.algorithm_set,
        pp_list: command_bitmap_image(&state.persistent.pp_list, PP_LIST_SIZE)
            .expect("the pp-list image builds"),
        reset_count: state.persistent.reset_count,
        total_reset_count: state.persistent.total_reset_count,
    }
}

#[track_caller]
pub(super) fn permall_durable(checkpoint: &str) -> DurableState {
    let blob = vector(&format!("PERMALL_{checkpoint}"));
    let envelope = PersistentAllEnvelope::parse(blob).expect("the stored envelope parses");
    let decoded = crate::library::tpm2::parse_persistent_all_payload(&envelope)
        .expect("the stored payload decodes");
    durable_of(&materialize_persistent_state(decoded).expect("the payload materializes"))
}

#[track_caller]
pub(super) fn assert_durable_state(runtime: &Tpm2Runtime, checkpoint: &str) {
    assert_eq!(
        durable_of(runtime.state()),
        permall_durable(checkpoint),
        "PERMALL_{checkpoint}"
    );
}

#[track_caller]
pub(super) fn exec(runtime: &mut Tpm2Runtime, clock: &SteppingClock, bytes: &[u8]) -> Vec<u8> {
    let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
    process(
        runtime,
        crate::library::tpm2::PlatformInputs::at_locality(0),
        &input,
        clock,
        |_| Ok(()),
    )
    .expect("the command processes")
}

pub(super) struct Host {
    stored: core::cell::RefCell<Vec<u8>>,
    presence: core::cell::Cell<bool>,
}

impl Host {
    #[track_caller]
    pub(in crate::library::tpm2::command) fn at(checkpoint: &str) -> Self {
        Host {
            stored: core::cell::RefCell::new(vector(&format!("PERMALL_{checkpoint}")).to_vec()),
            presence: core::cell::Cell::new(false),
        }
    }

    pub(in crate::library::tpm2::command) fn set_physical_presence(&self, asserted: bool) {
        self.presence.set(asserted);
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn run(
        &self,
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        bytes: &[u8],
    ) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        process(
            runtime,
            crate::library::tpm2::PlatformInputs::with_physical_presence(0, self.presence.get()),
            &input,
            clock,
            |committed| {
                *self.stored.borrow_mut() = persistent_all_store(committed.state())?;
                Ok(())
            },
        )
        .expect("the command processes")
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn expect(
        &self,
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: &[u8],
    ) {
        assert_eq!(self.run(runtime, clock, bytes), vector(label), "{label}");
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn reboot(&self) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(&self.stored.borrow())
            .expect("the stored permanent state restores");
        runtime.entropy = deterministic_entropy;
        runtime
    }
}

#[track_caller]
pub(super) fn expect(runtime: &mut Tpm2Runtime, clock: &SteppingClock, label: &str, bytes: &[u8]) {
    assert_eq!(exec(runtime, clock, bytes), vector(label), "{label}");
}

pub(super) fn fingerprint(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new(0x000b).expect("SHA-256 is compiled in");
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().try_into().expect("a 32-byte digest")
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Snapshot {
    pub(in crate::library::tpm2::command) failure_mode: bool,
    pub(in crate::library::tpm2::command) nv_update_pending: bool,
    pub(in crate::library::tpm2::command) orderly_state: u16,
    pub(in crate::library::tpm2::command) clock: u64,
    pub(in crate::library::tpm2::command) clock_safe: u8,
    pub(in crate::library::tpm2::command) time_ms: u64,
    pub(in crate::library::tpm2::command) adjust_rate: u32,
    pub(in crate::library::tpm2::command) algorithm_set: u32,
    pub(in crate::library::tpm2::command) pp_list: Vec<u8>,
    pub(in crate::library::tpm2::command) pcr_auth_values: Vec<[u8; 32]>,
    pub(in crate::library::tpm2::command) nv_memory: [u8; 32],
}

pub(super) fn pp_list_bytes(runtime: &Tpm2Runtime) -> Vec<u8> {
    command_bitmap_image(&runtime.state().persistent.pp_list, PP_LIST_SIZE)
        .expect("the pp-list image builds")
}

pub(super) fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
    Snapshot {
        failure_mode: runtime.failure_mode,
        nv_update_pending: runtime.nv_update_pending,
        orderly_state: runtime.state().persistent.orderly_state,
        clock: runtime.live.orderly.clock,
        clock_safe: runtime.live.orderly.clock_safe,
        time_ms: runtime.timer.time_ms,
        adjust_rate: runtime.timer.adjust_rate,
        algorithm_set: runtime.state().persistent.algorithm_set,
        pp_list: pp_list_bytes(runtime),
        pcr_auth_values: runtime
            .live
            .state_clear
            .as_ref()
            .expect("a started runtime")
            .pcr_auth_values
            .iter()
            .map(|secret| fingerprint(secret.expose()))
            .collect(),
        nv_memory: fingerprint(&runtime.nv_memory),
    }
}

#[track_caller]
pub(super) fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
    assert_eq!(&snapshot(runtime), before);
}

fn tpm2b(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

pub(super) fn read_clock() -> Vec<u8> {
    framed(TPM_CC_READ_CLOCK, &[], false)
}

pub(super) fn clock_set(auth: u32, new_time: u64, password: &[u8]) -> Vec<u8> {
    command(
        TPM_CC_CLOCK_SET,
        &[auth],
        &[password],
        &new_time.to_be_bytes(),
    )
}

pub(super) fn clock_rate_adjust(auth: u32, adjust: u8, password: &[u8]) -> Vec<u8> {
    command(TPM_CC_CLOCK_RATE_ADJUST, &[auth], &[password], &[adjust])
}

pub(super) fn command_list(codes: &[u32]) -> Vec<u8> {
    let mut out = (codes.len() as u32).to_be_bytes().to_vec();
    for code in codes {
        out.extend_from_slice(&code.to_be_bytes());
    }
    out
}

pub(super) fn pp_commands(
    auth: u32,
    set_list: &[u32],
    clear_list: &[u32],
    password: &[u8],
) -> Vec<u8> {
    let mut parameters = command_list(set_list);
    parameters.extend_from_slice(&command_list(clear_list));
    command(TPM_CC_PP_COMMANDS, &[auth], &[password], &parameters)
}

pub(super) fn set_algorithm_set(auth: u32, algorithm_set: u32, password: &[u8]) -> Vec<u8> {
    command(
        TPM_CC_SET_ALGORITHM_SET,
        &[auth],
        &[password],
        &algorithm_set.to_be_bytes(),
    )
}

pub(super) fn pcr_set_auth_value(pcr: u32, auth: &[u8], password: &[u8]) -> Vec<u8> {
    command(TPM_CC_PCR_SET_AUTH_VALUE, &[pcr], &[password], &tpm2b(auth))
}

pub(super) fn act_set_timeout(handle: u32, timeout: u32) -> Vec<u8> {
    command(
        TPM_CC_ACT_SET_TIMEOUT,
        &[handle],
        &[&[]],
        &timeout.to_be_bytes(),
    )
}

pub(super) fn clear_control(auth: u32, disable: u8) -> Vec<u8> {
    command(TPM_CC_CLEAR_CONTROL, &[auth], &[&[]], &[disable])
}

pub(super) fn hierarchy_control(auth: u32, enable: u32, state: u8) -> Vec<u8> {
    let mut parameters = enable.to_be_bytes().to_vec();
    parameters.push(state);
    command(TPM_CC_HIERARCHY_CONTROL, &[auth], &[&[]], &parameters)
}

pub(super) fn get_capability(capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut payload = capability.to_be_bytes().to_vec();
    payload.extend_from_slice(&property.to_be_bytes());
    payload.extend_from_slice(&count.to_be_bytes());
    framed(TPM_CC_GET_CAPABILITY, &payload, false)
}

pub(super) fn cap_pp_commands(property: u32, count: u32) -> Vec<u8> {
    get_capability(TPM_CAP_PP_COMMANDS, property, count)
}

pub(super) fn startup(kind: u16) -> Vec<u8> {
    framed(TPM_CC_STARTUP, &kind.to_be_bytes(), false)
}

pub(super) fn shutdown(kind: u16) -> Vec<u8> {
    framed(TPM_CC_SHUTDOWN, &kind.to_be_bytes(), false)
}

pub(super) fn time_info(response: &[u8]) -> (u64, u64, u32, u32, u8) {
    let body = &response[10..];
    assert_eq!(body.len(), 25, "a marshaled TPMS_TIME_INFO");
    (
        u64::from_be_bytes(body[..8].try_into().expect("eight bytes")),
        u64::from_be_bytes(body[8..16].try_into().expect("eight bytes")),
        u32::from_be_bytes(body[16..20].try_into().expect("four bytes")),
        u32::from_be_bytes(body[20..24].try_into().expect("four bytes")),
        body[24],
    )
}

pub(super) fn capability_codes(response: &[u8]) -> Vec<u32> {
    let count = u32::from_be_bytes(response[15..19].try_into().expect("a count"));
    (0..count as usize)
        .map(|index| {
            let at = 19 + index * 4;
            u32::from_be_bytes(response[at..at + 4].try_into().expect("a command code"))
        })
        .collect()
}

pub(super) fn capability_property(response: &[u8]) -> u32 {
    u32::from_be_bytes(response[23..27].try_into().expect("a property value"))
}
