use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};

use super::super::capability::{
    TPM_CAP_ALGS, TPM_CAP_COMMANDS, TPM_CAP_TPM_PROPERTIES, algorithms, commands, properties,
};
use super::super::runtime::Tpm2Runtime;
use super::dispatcher::CommandFrame;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const TPM_RC_3: TpmResult = 0x300;
const RC_GET_CAPABILITY_CAPABILITY: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_GET_CAPABILITY_PROPERTY: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_GET_CAPABILITY_PROPERTY_COUNT: TpmResult = TPM_RC_P + TPM_RC_3;

struct GetCapabilityIn {
    capability: u32,
    property: u32,
    property_count: u32,
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<Vec<u8>, TpmResult> {
    let input = parse_parameters(frame.parameters)?;
    collect_capability(runtime, &input)
}

fn read_parameter(input: &[u8], parameter_index: TpmResult) -> Result<(u32, &[u8]), TpmResult> {
    let (bytes, rest) = input
        .split_first_chunk::<4>()
        .ok_or(TPM_RC_INSUFFICIENT + parameter_index)?;
    Ok((u32::from_be_bytes(*bytes), rest))
}

fn parse_parameters(parameters: &[u8]) -> Result<GetCapabilityIn, TpmResult> {
    let (capability, rest) = read_parameter(parameters, RC_GET_CAPABILITY_CAPABILITY)?;
    let (property, rest) = read_parameter(rest, RC_GET_CAPABILITY_PROPERTY)?;
    let (property_count, rest) = read_parameter(rest, RC_GET_CAPABILITY_PROPERTY_COUNT)?;
    if !rest.is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(GetCapabilityIn {
        capability,
        property,
        property_count,
    })
}

fn response_prefix(more_data: bool, capability: u32, count: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 4);
    out.push(u8::from(more_data));
    out.extend_from_slice(&capability.to_be_bytes());
    out.extend_from_slice(&(count as u32).to_be_bytes());
    out
}

fn collect_capability(
    runtime: &Tpm2Runtime,
    input: &GetCapabilityIn,
) -> Result<Vec<u8>, TpmResult> {
    match input.capability {
        TPM_CAP_ALGS => {
            // TODO: Support runtimes without decoded state after the NVChip
            // fallback is implemented.
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            let page = algorithms::implemented(
                &state.profile.algorithms,
                input.property as u16,
                input.property_count,
            );
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for property in &page.entries {
                out.extend_from_slice(&property.algorithm.to_be_bytes());
                out.extend_from_slice(&property.attributes.to_be_bytes());
            }
            Ok(out)
        }
        TPM_CAP_COMMANDS => {
            let page = commands::implemented(input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for attributes in &page.entries {
                out.extend_from_slice(&attributes.to_be_bytes());
            }
            Ok(out)
        }
        TPM_CAP_TPM_PROPERTIES => {
            // TODO: Support runtimes without decoded state after the NVChip
            // fallback is implemented.
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            let page = properties::collect(runtime, state, input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for property in &page.entries {
                out.extend_from_slice(&property.property.to_be_bytes());
                out.extend_from_slice(&property.value.to_be_bytes());
            }
            Ok(out)
        }
        _ => Err(TPM_RC_VALUE + RC_GET_CAPABILITY_CAPABILITY),
    }
}

#[cfg(test)]
mod tests {
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::TPM_CC_GET_CAPABILITY;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::process;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    const RC_INSUFFICIENT_PARAM1: u32 = 0x1da;
    const RC_INSUFFICIENT_PARAM2: u32 = 0x2da;
    const RC_INSUFFICIENT_PARAM3: u32 = 0x3da;
    const RC_VALUE_PARAM1: u32 = 0x1c4;
    const RC_SIZE: u32 = 0x095;
    const RC_SESSION1_HANDLE: u32 = 0x98b;
    const RC_INSUFFICIENT: u32 = 0x09a;

    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(cleaned.len().is_multiple_of(2));
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x63;
        }
        Ok(())
    }

    fn manufactured_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        runtime
    }

    #[track_caller]
    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        serialize_response(&dispatch(runtime, &parsed)).expect("the response serializes")
    }

    #[track_caller]
    fn started_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = manufactured_runtime();
        let startup = hex("80010000000c0000014400 00");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn get_capability_command(capability: u32, property: u32, count: u32) -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
        out.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
        out.extend_from_slice(&capability.to_be_bytes());
        out.extend_from_slice(&property.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    fn error_response(code: u32) -> Vec<u8> {
        let mut out = hex("80010000000a");
        out.extend_from_slice(&code.to_be_bytes());
        out
    }

    #[track_caller]
    fn query(runtime: &mut Tpm2Runtime, capability: u32, property: u32, count: u32) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &get_capability_command(capability, property, count),
        )
    }

    struct Snapshot {
        startup_received: bool,
        failure_mode: bool,
        nv_update_pending: bool,
        orderly_state: u16,
        failed_tries: u32,
        nv_memory: Box<[u8]>,
        live_free_session_slots: u32,
        live_prev_orderly_state: u16,
        live_drbg_counter: u64,
    }

    fn snapshot(runtime: &Tpm2Runtime) -> Snapshot {
        let state = runtime.state.as_ref().expect("state present");
        Snapshot {
            startup_received: runtime.startup_received,
            failure_mode: runtime.failure_mode,
            nv_update_pending: runtime.nv_update_pending,
            orderly_state: state.persistent.orderly_state,
            failed_tries: state.persistent.failed_tries,
            nv_memory: runtime.nv_memory.clone(),
            live_free_session_slots: runtime.live.free_session_slots,
            live_prev_orderly_state: runtime.live.prev_orderly_state,
            live_drbg_counter: runtime.live.orderly.drbg_state.reseed_counter,
        }
    }

    #[track_caller]
    fn assert_unchanged(runtime: &Tpm2Runtime, before: &Snapshot) {
        let state = runtime.state.as_ref().expect("state present");
        assert_eq!(runtime.startup_received, before.startup_received);
        assert_eq!(runtime.failure_mode, before.failure_mode);
        assert_eq!(runtime.nv_update_pending, before.nv_update_pending);
        assert_eq!(state.persistent.orderly_state, before.orderly_state);
        assert_eq!(state.persistent.failed_tries, before.failed_tries);
        assert_eq!(runtime.nv_memory, before.nv_memory);
        assert_eq!(
            runtime.live.free_session_slots,
            before.live_free_session_slots
        );
        assert_eq!(
            runtime.live.prev_orderly_state,
            before.live_prev_orderly_state
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            before.live_drbg_counter
        );
    }

    #[test]
    fn get_capability_is_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            query(&mut runtime, 6, 0x100, 10),
            error_response(TPM_RC_INITIALIZE)
        );
        let mut truncated = hex("80010000000a");
        truncated.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
        assert_eq!(
            dispatch_bytes(&mut runtime, &truncated),
            error_response(TPM_RC_INITIALIZE),
            "the lifecycle check precedes parameter parsing"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn get_capability_is_dispatched_after_startup() {
        let mut runtime = started_runtime();
        let response = query(&mut runtime, 2, 0, 1000);
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
    }

    #[test]
    fn every_truncated_parameter_returns_its_indexed_error() {
        let full_params = [0u8; 12];
        for len in 0..12usize {
            let expected = match len {
                0..=3 => RC_INSUFFICIENT_PARAM1,
                4..=7 => RC_INSUFFICIENT_PARAM2,
                _ => RC_INSUFFICIENT_PARAM3,
            };
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            let mut command = vec![0x80, 0x01];
            command.extend_from_slice(&(10 + len as u32).to_be_bytes());
            command.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
            command.extend_from_slice(&full_params[..len]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "parameter length {len}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn trailing_parameter_bytes_return_size() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let mut command = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x17];
        command.extend_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
        command.extend_from_slice(&[0; 12]);
        command.push(0xee);
        assert_eq!(
            dispatch_bytes(&mut runtime, &command),
            error_response(RC_SIZE)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn unsupported_capability_selectors_return_value_for_parameter_one() {
        for capability in [1u32, 3, 4, 5, 7, 8, 9, 0xa, 0x100, 0x7fff_ffff, u32::MAX] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                query(&mut runtime, capability, 0, 10),
                error_response(RC_VALUE_PARAM1),
                "capability {capability:#x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn session_tagged_requests_match_the_oracle() {
        let pw_auth =
            hex("80020000002300 00017a 00000009 40000009 0000 00 0000 00000006 00000100 0000000a");
        let no_authsize = hex("80020000000a0000017a");
        let authsize_zero = hex("80020000001a0000017a 00000000 00000006 00000100 0000000a");

        for (label, command, expected) in [
            ("pw_auth", pw_auth, RC_SESSION1_HANDLE),
            ("no_authsize", no_authsize, RC_INSUFFICIENT),
            ("authsize_zero", authsize_zero, RC_SIZE),
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "{label}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        let valid = get_capability_command(6, 0x100, 10);
        for len in 10..=valid.len() {
            for index in 6..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
                    mutated[index] ^= flip;
                    let mut runtime = started_runtime();
                    let input = CommandInput::new(mutated.len() as u32, mutated);
                    let parsed = parse_command(&input).expect("the header parses");
                    let _ = serialize_response(&dispatch(&mut runtime, &parsed));
                }
            }
        }
    }

    #[test]
    fn the_full_algorithm_list_matches_the_oracle_bytes() {
        let mut runtime = started_runtime();
        let expected = hex(
            "8001000000d90000000000000000000000002100010000000900030000000200040000000400050000\
010400060000000200070000040400080000030c000a00000006000b00000004000c00000004000d000000040014000\
00101001500000201001600000101001700000201001800000101001900000401001a00000101001b00000501001c00\
000101001d00000401002000000404002100000404002200000404002300000009002500000008002600000002003f0\
0000102004000000202004100000202004200000202004300000202004400000202",
        );
        assert_eq!(query(&mut runtime, 0, 0, 1000), expected);
        assert_eq!(query(&mut runtime, 0, 0, 36), expected, "oversized count");
    }

    #[test]
    fn algorithm_boundary_queries_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 0, 0, 0),
            hex("80010000001300000000010000000000000000"),
            "count zero"
        );
        assert_eq!(
            query(&mut runtime, 0, 0x0001, 1),
            hex("80010000001900000000010000000000000001000100000009"),
            "inclusive start with more data"
        );
        assert_eq!(
            query(&mut runtime, 0, 0x0002, 2),
            hex("80010000001f00000000010000000000000002000300000002000400000004"),
            "start inside a gap"
        );
        assert_eq!(
            query(&mut runtime, 0, 0x0044, 10),
            hex("80010000001900000000000000000000000001004400000202"),
            "last algorithm"
        );
        assert_eq!(
            query(&mut runtime, 0, 0x0045, 10),
            hex("80010000001300000000000000000000000000"),
            "past the last algorithm"
        );
        assert_eq!(
            query(&mut runtime, 0, 0x0045, 0),
            hex("80010000001300000000000000000000000000"),
            "count zero past the end"
        );
        assert_eq!(
            query(&mut runtime, 0, 0x0001_0001, 2),
            hex("80010000001f00000000010000000000000002000100000009000300000002"),
            "the property is truncated to TPM_ALG_ID like upstream"
        );
    }

    #[test]
    fn the_command_list_is_generated_from_the_registry() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 2, 0, 1000),
            hex(
                "800100000033000000000000000002000000080200013d 00400142 00400143 00400144 \
                 00400145 0000017a 0000017e 02000182"
            )
        );
    }

    #[test]
    fn command_boundary_queries_page_through_the_registry() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 2, 0, 0),
            hex("80010000001300000000010000000200000000"),
            "count zero matches the oracle bytes"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013d, 1),
            hex("80010000001700000000010000000200000001 0200013d"),
            "PCR_Reset advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013e, 1),
            hex("80010000001700000000010000000200000001 00400142"),
            "just above PCR_Reset"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0142, 1),
            hex("80010000001700000000010000000200000001 00400142"),
            "IncrementalSelfTest advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0143, 1),
            hex("80010000001700000000010000000200000001 00400143"),
            "SelfTest advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0144, 1),
            hex("80010000001700000000010000000200000001 00400144"),
            "just above SelfTest"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0145, 1),
            hex("8001000000170000000001000000020000000100400145"),
            "start at Shutdown matches the oracle bytes"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0146, 3),
            hex("80010000001f000000000000000002000000030000017a 0000017e 02000182"),
            "between Shutdown and GetCapability"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017a, 3),
            hex("80010000001f000000000000000002000000030000017a 0000017e 02000182"),
            "GetCapability advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017e, 2),
            hex("80010000001b000000000000000002000000020000017e 02000182"),
            "PCR_Read advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0182, 2),
            hex("80010000001700000000000000000200000001 02000182"),
            "PCR_Extend advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x2000_0000, 10),
            hex("80010000001300000000000000000200000000"),
            "above the last command matches the oracle bytes"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 3),
            hex("80010000001f00000000010000000200000003 0200013d 00400142 00400143"),
            "an exhausted count leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 8),
            hex(
                "800100000033000000000000000002000000080200013d 00400142 00400143 00400144 \
                 00400145 0000017a 0000017e 02000182"
            ),
            "an exact count consumes the registry"
        );
    }

    const ORACLE_PROPS_FIXED_ALL: &str = "800100000183000000000000000006 0000002e\
00000100322e3000000001010000000000000102000000b7000001030000001900000104000007e8000\
0010549424d000000010653572020000001072054504d0000010800000000000001090000000000000\
10a000000010000010b202401250000010c001200000000010d000004000000010e000000030000010\
f000000070000011000000003000001110000004000000112000000180000011300000003000001140\
000ffff00000116000000000000011700000800000001180000000600000119000010000000011a000\
0000d0000011b000000060000011c000001000000011d000000ff0000011e000010000000011f00001\
00000000120000000400000012100000a8c00000122000001940000012300000001000001240000000\
00000012500000106000001260000001900000127000007e8000001280000008000000129000000080\
000012a000000080000012b000000000000012c000004000000012d000000000000012e00000400";

    #[test]
    fn the_fixed_property_group_matches_the_oracle_with_registry_command_counts() {
        let mut runtime = started_runtime();
        let expected = hex(ORACLE_PROPS_FIXED_ALL);
        assert_eq!(query(&mut runtime, 6, 0, 1000), expected, "clamped start");
        assert_eq!(query(&mut runtime, 6, 0x100, 1000), expected);
    }

    #[test]
    fn the_variable_property_group_matches_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 6, 0x200, 1000),
            hex(
                "8001000000bb000000000000000006000000150000020000000400000002018000000f000002020000000000000203000000000000020400000003000002050000000000000206000000400000020700000003000002080000000000000209000000400000020a000000000000020b000000190000020c000000000000020d000000080000020e000000000000020f0000000300000210000003e800000211000003e8000002120000000000000213000000000000021400000000"
            )
        );
    }

    #[test]
    fn property_boundary_queries_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 6, 0x50, 2),
            hex("8001000000230000000001000000060000000200000100322e30000000010100000000"),
            "a start below PT_FIXED clamps"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x100, 0),
            hex("80010000001300000000010000000600000000"),
            "count zero"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x100, 1),
            hex("80010000001b0000000001000000060000000100000100322e3000"),
            "count one"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x115, 2),
            hex("8001000000230000000001000000060000000200000116000000000000011700000800"),
            "the undefined property 0x115 is skipped"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x12e, 5),
            hex("80010000001b000000000000000006000000010000012e00000400"),
            "the last fixed property"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x12f, 5),
            hex("80010000001300000000000000000600000000"),
            "past the last fixed property stays inside the group"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x1ff, 5),
            hex("80010000001300000000000000000600000000")
        );
        assert_eq!(
            query(&mut runtime, 6, 0x214, 5),
            hex("80010000001b000000000000000006000000010000021400000000"),
            "the last variable property"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x215, 5),
            hex("80010000001300000000000000000600000000")
        );
        for start in [0x2ffu32, 0x300, 0xffff_ffff] {
            assert_eq!(
                query(&mut runtime, 6, start, 5),
                hex("80010000001300000000000000000600000000"),
                "start {start:#x}"
            );
        }
        assert_eq!(
            query(&mut runtime, 6, 0x200, 3),
            hex(
                "80010000002b000000000100000006000000030000020000000400000002018000000f0000020200000000"
            ),
            "variable pagination with more data"
        );
        assert_eq!(
            query(&mut runtime, 6, 0x2f0, 0),
            hex("80010000001300000000000000000600000000"),
            "count zero with nothing eligible"
        );
    }

    #[test]
    fn successful_queries_do_not_mutate_the_runtime() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        for (capability, property) in [(0u32, 0u32), (2, 0), (6, 0x100), (6, 0x200)] {
            let response = query(&mut runtime, capability, property, 1000);
            assert_eq!(&response[6..10], &[0, 0, 0, 0]);
            assert_unchanged(&runtime, &before);
        }
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn get_capability_never_invokes_the_nv_commit_callback() {
        let mut runtime = started_runtime();
        let command = get_capability_command(6, 0x100, 1000);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("GetCapability must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);

        let failing = get_capability_command(0x7fff_ffff, 0, 0);
        let input = CommandInput::new(failing.len() as u32, failing);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failing GetCapability must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(&response, &error_response(RC_VALUE_PARAM1));
    }

    #[test]
    fn responses_echo_the_capability_selector() {
        let mut runtime = started_runtime();
        for capability in [0u32, 2, 6] {
            let response = query(&mut runtime, capability, 0x100, 1);
            assert_eq!(
                &response[11..15],
                &capability.to_be_bytes(),
                "capability {capability}"
            );
        }
    }
}
