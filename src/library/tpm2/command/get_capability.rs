use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::capability::{
    TPM_CAP_ALGS, TPM_CAP_COMMANDS, TPM_CAP_HANDLES, TPM_CAP_PCRS, TPM_CAP_TPM_PROPERTIES,
    algorithms, commands, handles, pcrs, properties,
};
use super::super::runtime::Tpm2Runtime;
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

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
) -> Result<CommandOutput, TpmResult> {
    let input = parse_parameters(frame.parameters)?;
    let parameters = collect_capability(runtime, &input)?;
    Ok(CommandOutput::from_parameters(parameters))
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
        TPM_CAP_HANDLES => {
            // TODO: Support runtimes without decoded state after the NVChip
            // fallback is implemented.
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            let page = handles::collect(&runtime.live, state, input.property, input.property_count)
                .ok_or(TPM_RC_HANDLE + RC_GET_CAPABILITY_PROPERTY)?;
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for handle in &page.entries {
                out.extend_from_slice(&handle.to_be_bytes());
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
        TPM_CAP_PCRS => {
            // Upstream rejects a non-zero property inside the selector arm, so
            // the lifecycle and parameter checks still run first.
            if input.property != 0 {
                return Err(TPM_RC_VALUE + RC_GET_CAPABILITY_PROPERTY);
            }
            // TODO: Support runtimes without decoded state after the NVChip
            // fallback is implemented.
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            let allocation = runtime.effective_pcr_allocated().ok_or(TPM_RC_FAILURE)?;
            let page = pcrs::collect(allocation, &state.profile.algorithms, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for selection in &page.entries {
                out.extend_from_slice(&selection.hash_alg.to_be_bytes());
                out.push(u8::try_from(selection.select.len()).map_err(|_| TPM_RC_FAILURE)?);
                out.extend_from_slice(&selection.select);
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
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::ffi_types::TpmResult>,
    ) -> Result<Vec<u8>, crate::ffi_types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            locality,
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
        )
    }
    use super::super::dispatcher::dispatch;
    use super::super::header::{parse_command, serialize_response};
    use super::super::registry::TPM_CC_GET_CAPABILITY;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::capability::handles::test_state::{
        load_session, nv_index_entry, occupy_object, persistent_entry, push_nvram, save_session,
    };
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::persistent::{OwnedPcrAllocation, OwnedPcrSelection};
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::runtime::commit_manufactured_state;

    const RC_INSUFFICIENT_PARAM1: u32 = 0x1da;
    const RC_INSUFFICIENT_PARAM2: u32 = 0x2da;
    const RC_INSUFFICIENT_PARAM3: u32 = 0x3da;
    const RC_VALUE_PARAM1: u32 = 0x1c4;
    const RC_HANDLE_PARAM2: u32 = 0x2cb;
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
        for capability in [3u32, 4, 7, 8, 9, 0xa, 0x100, 0x7fff_ffff, u32::MAX] {
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
                "8001000000a700000000000000000200000025 0440011f 04400120 04400122 02c00124 02400129 0240012a 0240012b 12000131 02400132 04400134 04400135 04400136 04400137 04400138 0240013a 0240013b 0200013c 0200013d 00400142 00400143 00400144 00400145 00400146 0400014e 0440014f 02000153 0200015d 00000165 02000169 0000017a 0000017b 0000017c 0000017d 0000017e 02000182 06000184 12000191"
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
            query(&mut runtime, 2, 0, 1),
            hex("80010000001700000000010000000200000001 0440011f"),
            "NV_UndefineSpaceSpecial leads the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0125, 1),
            hex("80010000001700000000010000000200000001 02400129"),
            "HierarchyChangeAuth follows ChangeEPS"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0129, 1),
            hex("80010000001700000000010000000200000001 02400129"),
            "HierarchyChangeAuth advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x012a, 1),
            hex("80010000001700000000010000000200000001 0240012a"),
            "NV_DefineSpace follows HierarchyChangeAuth"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x012b, 1),
            hex("80010000001700000000010000000200000001 0240012b"),
            "PCR_Allocate advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x012c, 1),
            hex("80010000001700000000010000000200000001 12000131"),
            "just above PCR_Allocate"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0131, 1),
            hex("80010000001700000000010000000200000001 12000131"),
            "CreatePrimary advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0132, 1),
            hex("80010000001700000000010000000200000001 02400132"),
            "NV_GlobalWriteLock follows CreatePrimary"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013d, 1),
            hex("80010000001700000000010000000200000001 0200013d"),
            "PCR_Reset advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0121, 1),
            hex("80010000001700000000010000000200000001 04400122"),
            "NV_UndefineSpace follows EvictControl"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0133, 1),
            hex("80010000001700000000010000000200000001 04400134"),
            "NV_Increment follows NV_GlobalWriteLock"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0139, 1),
            hex("80010000001700000000010000000200000001 0240013a"),
            "DictionaryAttackParameters follows NV_WriteLock"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013a, 1),
            hex("80010000001700000000010000000200000001 0240013a"),
            "DictionaryAttackParameters advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013b, 1),
            hex("80010000001700000000010000000200000001 0240013b"),
            "NV_ChangeAuth follows DictionaryAttackParameters"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013c, 1),
            hex("80010000001700000000010000000200000001 0200013c"),
            "PCR_Event advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013c, 2),
            hex("80010000001b00000000010000000200000002 0200013c 0200013d"),
            "PCR_Reset follows PCR_Event"
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
            query(&mut runtime, 2, 0x0146, 1),
            hex("80010000001700000000010000000200000001 00400146"),
            "StirRandom advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0147, 10),
            hex(
                "80010000003b0000000001000000020000000a 0400014e 0440014f 02000153 0200015d \
                 00000165 02000169 0000017a 0000017b 0000017c 0000017d"
            ),
            "between StirRandom and NV_Read"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017a, 3),
            hex("80010000001f00000000010000000200000003 0000017a 0000017b 0000017c"),
            "GetCapability advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017b, 1),
            hex("80010000001700000000010000000200000001 0000017b"),
            "GetRandom advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017c, 2),
            hex("80010000001b00000000010000000200000002 0000017c 0000017d"),
            "GetTestResult advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017d, 1),
            hex("80010000001700000000010000000200000001 0000017d"),
            "Hash advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x017e, 3),
            hex("80010000001f000000000100000002000000030000017e 02000182 06000184"),
            "PCR_Read advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0182, 2),
            hex("80010000001b00000000010000000200000002 02000182 06000184"),
            "PCR_Extend advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0184, 1),
            hex("80010000001700000000010000000200000001 06000184"),
            "TPM2_CreateLoaded still follows NV_Certify"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0191, 1),
            hex("80010000001700000000000000000200000001 12000191"),
            "CreateLoaded closes the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x2000_0000, 10),
            hex("80010000001300000000000000000200000000"),
            "above the last command matches the oracle bytes"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 3),
            hex("80010000001f000000000100000002000000030440011f0440012004400122"),
            "an exhausted count leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 35),
            hex(
                "80010000009f00000000010000000200000023 0440011f 04400120 04400122 02c00124 02400129 0240012a 0240012b 12000131 02400132 04400134 04400135 04400136 04400137 04400138 0240013a 0240013b 0200013c 0200013d 00400142 00400143 00400144 00400145 00400146 0400014e 0440014f 02000153 0200015d 00000165 02000169 0000017a 0000017b 0000017c 0000017d 0000017e 02000182"
            ),
            "two short of the registry still leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 36),
            hex(
                "8001000000a300000000010000000200000024 0440011f 04400120 04400122 02c00124 02400129 0240012a 0240012b 12000131 02400132 04400134 04400135 04400136 04400137 04400138 0240013a 0240013b 0200013c 0200013d 00400142 00400143 00400144 00400145 00400146 0400014e 0440014f 02000153 0200015d 00000165 02000169 0000017a 0000017b 0000017c 0000017d 0000017e 02000182 06000184"
            ),
            "one short of the registry still leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 37),
            hex(
                "8001000000a700000000000000000200000025 0440011f 04400120 04400122 02c00124 02400129 0240012a 0240012b 12000131 02400132 04400134 04400135 04400136 04400137 04400138 0240013a 0240013b 0200013c 0200013d 00400142 00400143 00400144 00400145 00400146 0400014e 0440014f 02000153 0200015d 00000165 02000169 0000017a 0000017b 0000017c 0000017d 0000017e 02000182 06000184 12000191"
            ),
            "an exact count consumes the registry"
        );
    }

    const ORACLE_PROPS_FIXED_ALL: &str = "8001000001830000000000000000060000002e0000010\
0322e3000000001010000000000000102000000b7000001030000001900000104000007e800000105\
49424d000000010653572020000001072054504d000001080000000000000109000000000000010a0\
00000010000010b202401250000010c001200000000010d000004000000010e000000030000010f00\
000007000001100000000300000111000000400000011200000018000001130000000300000114000\
0ffff00000116000000000000011700000800000001180000000600000119000010000000011a0000\
000d0000011b000000060000011c000001000000011d000000ff0000011e000010000000011f00001\
00000000120000000400000012100000a8c0000012200000194000001230000000100000124000000\
00000001250000010600000126000000190000012700000\
7e800000128000000800000012900000025\
0000012a000000250000012b000000000000012c000004000000012d000000000000012e00000400";

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
        for (capability, property) in [(0u32, 0x100u32), (1, 0x100), (2, 0x100), (5, 0), (6, 0x100)]
        {
            let response = query(&mut runtime, capability, property, 1);
            assert_eq!(
                &response[11..15],
                &capability.to_be_bytes(),
                "capability {capability}"
            );
        }
    }

    const EMPTY_HANDLE_LIST: &str = "80010000001300000000000000000100000000";

    #[track_caller]
    fn handles(runtime: &mut Tpm2Runtime, property: u32, count: u32) -> Vec<u8> {
        query(runtime, TPM_CAP_HANDLES, property, count)
    }

    #[test]
    fn the_permanent_handle_list_matches_the_oracle_bytes() {
        let mut runtime = started_runtime();
        let expected = hex(
            "80010000002f000000000000000001000000074000000140000007400000094000000a4000000b\
             4000000c4000000d",
        );
        assert_eq!(handles(&mut runtime, 0x4000_0000, 1000), expected);
        assert_eq!(
            handles(&mut runtime, 0x4000_0000, 7),
            expected,
            "an exact count consumes the list"
        );
    }

    #[test]
    fn permanent_handle_boundary_queries_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            handles(&mut runtime, 0x4000_0000, 0),
            hex("80010000001300000000010000000100000000"),
            "count zero"
        );
        assert_eq!(
            handles(&mut runtime, 0x4000_0000, 1),
            hex("8001000000170000000001000000010000000140000001"),
            "count one"
        );
        assert_eq!(
            handles(&mut runtime, 0x4000_0000, 2),
            hex("80010000001b000000000100000001000000024000000140000007")
        );
        assert_eq!(
            handles(&mut runtime, 0x4000_0001, 3),
            hex("80010000001f00000000010000000100000003400000014000000740000009"),
            "inclusive start"
        );
        assert_eq!(
            handles(&mut runtime, 0x4000_0002, 3),
            hex("80010000001f0000000001000000010000000340000007400000094000000a"),
            "a start inside the gap below TPM_RH_NULL"
        );
        assert_eq!(
            handles(&mut runtime, 0x4000_0009, 2),
            hex("80010000001b00000000010000000100000002400000094000000a"),
            "TPM_RS_PW is enumerated"
        );
        assert_eq!(
            handles(&mut runtime, 0x4000_000d, 5),
            hex("800100000017000000000000000001000000014000000d"),
            "TPM_RH_PLATFORM_NV is the last permanent handle"
        );
        for start in [
            0x4000_000eu32,
            0x4000_0110,
            0x4000_0120,
            0x4000_ffff,
            0x40ff_ffff,
        ] {
            assert_eq!(
                handles(&mut runtime, start, 5),
                hex(EMPTY_HANDLE_LIST),
                "start {start:#010x}"
            );
        }
        assert_eq!(
            handles(&mut runtime, 0x40ff_ffff, 0),
            hex(EMPTY_HANDLE_LIST),
            "count zero past the last permanent handle"
        );
    }

    #[test]
    fn the_pcr_handle_list_matches_the_oracle_bytes() {
        let mut runtime = started_runtime();
        let expected = hex(
            "8001000000730000000000000000010000001800000000000000010000000200000003000000040000\
             0005000000060000000700000008000000090000000a0000000b0000000c0000000d0000000e0000000f\
             0000001000000011000000120000001300000014000000150000001600000017",
        );
        assert_eq!(handles(&mut runtime, 0x0000_0000, 1000), expected);
        assert_eq!(handles(&mut runtime, 0x0000_0000, 24), expected);
    }

    #[test]
    fn pcr_handle_boundary_queries_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        assert_eq!(
            handles(&mut runtime, 0x0000_0000, 0),
            hex("80010000001300000000010000000100000000"),
            "count zero"
        );
        assert_eq!(
            handles(&mut runtime, 0x0000_0000, 1),
            hex("8001000000170000000001000000010000000100000000"),
            "count one"
        );
        assert_eq!(
            handles(&mut runtime, 0x0000_0000, 23),
            hex(
                "80010000006f000000000100000001000000170000000000000001000000020000000300000004000\
                 00005000000060000000700000008000000090000000a0000000b0000000c0000000d0000000e0000\
                 000f00000010000000110000001200000013000000140000001500000016"
            ),
            "one short of the whole bank"
        );
        assert_eq!(
            handles(&mut runtime, 0x0000_000a, 3),
            hex("80010000001f000000000100000001000000030000000a0000000b0000000c"),
            "a start in the middle of the range"
        );
        assert_eq!(
            handles(&mut runtime, 0x0000_0017, 5),
            hex("8001000000170000000000000000010000000100000017"),
            "the last PCR"
        );
        for start in [0x0000_0018u32, 0x00ff_ffff] {
            assert_eq!(
                handles(&mut runtime, start, 5),
                hex(EMPTY_HANDLE_LIST),
                "start {start:#010x}"
            );
        }
        assert_eq!(
            handles(&mut runtime, 0x0000_0018, 0),
            hex(EMPTY_HANDLE_LIST),
            "count zero past the last PCR"
        );
    }

    #[test]
    fn the_dynamic_handle_ranges_are_empty_on_a_freshly_started_tpm() {
        let mut runtime = started_runtime();
        for start in [
            0x0100_0000u32,
            0x01ff_ffff,
            0x0200_0000,
            0x0300_0000,
            0x8000_0000,
            0x8100_0000,
        ] {
            assert_eq!(
                handles(&mut runtime, start, 10),
                hex(EMPTY_HANDLE_LIST),
                "start {start:#010x}"
            );
            assert_eq!(
                handles(&mut runtime, start, 0),
                hex(EMPTY_HANDLE_LIST),
                "start {start:#010x} with count zero"
            );
        }
    }

    #[test]
    fn unimplemented_handle_types_return_handle_for_parameter_two() {
        for handle_type in [
            0x04u32, 0x05, 0x0f, 0x10, 0x11, 0x12, 0x3f, 0x41, 0x7f, 0x82, 0x90, 0xff,
        ] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            assert_eq!(
                handles(&mut runtime, handle_type << 24, 1000),
                error_response(RC_HANDLE_PARAM2),
                "handle type {handle_type:#04x}"
            );
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn nv_index_handles_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [
                nv_index_entry(0x0100_0005),
                nv_index_entry(0x0100_0001),
                nv_index_entry(0x0100_0003),
                nv_index_entry(0x0100_000a),
            ],
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0000, 10),
            hex("800100000023000000000000000001000000040100000101000003010000050100000a"),
            "storage order is discarded for ascending handles"
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0000, 0),
            hex("80010000001300000000010000000100000000"),
            "count zero with eligible handles reports more data"
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0000, 1),
            hex("8001000000170000000001000000010000000101000001")
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0000, 2),
            hex("80010000001b000000000100000001000000020100000101000003")
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0000, 4),
            hex("800100000023000000000000000001000000040100000101000003010000050100000a"),
            "an exact count leaves no more data"
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0002, 10),
            hex("80010000001f0000000000000000010000000301000003010000050100000a"),
            "a start between two defined indexes"
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0005, 1),
            hex("8001000000170000000001000000010000000101000005")
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_000b, 10),
            hex(EMPTY_HANDLE_LIST),
            "past the highest index"
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_000b, 0),
            hex(EMPTY_HANDLE_LIST)
        );
        assert_eq!(
            handles(&mut runtime, 0x8100_0000, 10),
            hex(EMPTY_HANDLE_LIST),
            "NV indexes never appear in the persistent range"
        );
    }

    #[test]
    fn persistent_object_handles_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [persistent_entry(0x8100_0005), persistent_entry(0x8100_0001)],
        );
        assert_eq!(
            handles(&mut runtime, 0x8100_0000, 10),
            hex("80010000001b000000000000000001000000028100000181000005")
        );
        assert_eq!(
            handles(&mut runtime, 0x8100_0000, 0),
            hex("80010000001300000000010000000100000000")
        );
        assert_eq!(
            handles(&mut runtime, 0x8100_0000, 1),
            hex("8001000000170000000001000000010000000181000001")
        );
        assert_eq!(
            handles(&mut runtime, 0x8100_0002, 10),
            hex("8001000000170000000000000000010000000181000005")
        );
        assert_eq!(
            handles(&mut runtime, 0x8100_0006, 10),
            hex(EMPTY_HANDLE_LIST)
        );
        assert_eq!(
            handles(&mut runtime, 0x0100_0000, 10),
            hex(EMPTY_HANDLE_LIST),
            "persistent objects never appear in the NV index range"
        );
    }

    #[test]
    fn transient_object_handles_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        for slot in 0..3 {
            occupy_object(&mut runtime, slot);
        }
        assert_eq!(
            handles(&mut runtime, 0x8000_0000, 10),
            hex("80010000001f00000000000000000100000003800000008000000180000002")
        );
        assert_eq!(
            handles(&mut runtime, 0x8000_0000, 1),
            hex("8001000000170000000001000000010000000180000000")
        );
        assert_eq!(
            handles(&mut runtime, 0x8000_0000, 2),
            hex("80010000001b000000000100000001000000028000000080000001")
        );
        assert_eq!(
            handles(&mut runtime, 0x8000_0001, 10),
            hex("80010000001b000000000000000001000000028000000180000002")
        );
        assert_eq!(
            handles(&mut runtime, 0x8000_0003, 10),
            hex(EMPTY_HANDLE_LIST)
        );

        runtime.live.objects[0].attributes &= !(1 << 15);
        assert_eq!(
            handles(&mut runtime, 0x8000_0000, 10),
            hex("80010000001b000000000000000001000000028000000180000002")
        );
    }

    #[test]
    fn session_handles_match_the_oracle_bytes() {
        let mut runtime = started_runtime();
        load_session(&mut runtime, 0, 0, false);
        load_session(&mut runtime, 1, 1, true);
        assert_eq!(
            handles(&mut runtime, 0x0200_0000, 10),
            hex("80010000001b000000000000000001000000020200000003000001"),
            "the policy session is reported in the policy range"
        );
        assert_eq!(
            handles(&mut runtime, 0x0200_0000, 1),
            hex("8001000000170000000001000000010000000102000000")
        );
        assert_eq!(
            handles(&mut runtime, 0x0200_0001, 10),
            hex("8001000000170000000000000000010000000103000001"),
            "the start handle selects on the context slot"
        );
        assert_eq!(
            handles(&mut runtime, 0x0200_0002, 10),
            hex(EMPTY_HANDLE_LIST)
        );
        assert_eq!(
            handles(&mut runtime, 0x0300_0000, 10),
            hex(EMPTY_HANDLE_LIST),
            "the policy range only reports context-saved sessions"
        );

        save_session(&mut runtime, 0, 4);
        assert_eq!(
            handles(&mut runtime, 0x0200_0000, 10),
            hex("8001000000170000000000000000010000000103000001"),
            "only the policy session is still loaded"
        );
        assert_eq!(
            handles(&mut runtime, 0x0300_0000, 10),
            hex("8001000000170000000000000000010000000102000000"),
            "saved sessions are reported in the HMAC range"
        );
        assert_eq!(
            handles(&mut runtime, 0x0300_0000, 0),
            hex("80010000001300000000010000000100000000")
        );
        assert_eq!(
            handles(&mut runtime, 0x0300_0001, 10),
            hex(EMPTY_HANDLE_LIST)
        );
    }

    #[test]
    fn the_response_size_limit_truncates_the_handle_list() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [
                nv_index_entry(0x0100_0005),
                nv_index_entry(0x0100_0001),
                nv_index_entry(0x0100_0003),
                nv_index_entry(0x0100_000a),
            ],
        );
        push_nvram(
            &mut runtime,
            (0..300u32).map(|index| nv_index_entry(0x0100_1000 + index)),
        );
        // `oracle16 nv_bulk_count1000`: 254 handles, more data, 1035 bytes.
        for count in [254u32, 255, 300, 1000] {
            let response = handles(&mut runtime, 0x0100_0000, count);
            assert_eq!(response.len(), 0x40b, "count {count}");
            assert_eq!(&response[..6], &hex("80010000040b")[..], "count {count}");
            assert_eq!(&response[6..10], &[0, 0, 0, 0], "count {count}");
            assert_eq!(response[10], 1, "more data, count {count}");
            assert_eq!(&response[11..15], &hex("00000001")[..], "count {count}");
            assert_eq!(&response[15..19], &hex("000000fe")[..], "count {count}");
            assert_eq!(
                &response[19..35],
                &hex("01000001 01000003 01000005 0100000a")[..],
                "count {count}"
            );
            assert_eq!(
                &response[response.len() - 4..],
                &hex("010010f9")[..],
                "count {count}"
            );
        }
    }

    #[test]
    fn handle_queries_are_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        for (property, label) in [
            (0x4000_0000u32, "a supported handle type"),
            (0x0400_0000, "an unsupported handle type"),
        ] {
            assert_eq!(
                handles(&mut runtime, property, 10),
                error_response(TPM_RC_INITIALIZE),
                "{label}"
            );
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn handle_queries_do_not_mutate_the_runtime() {
        let mut runtime = started_runtime();
        push_nvram(
            &mut runtime,
            [nv_index_entry(0x0100_0001), persistent_entry(0x8100_0001)],
        );
        occupy_object(&mut runtime, 0);
        load_session(&mut runtime, 0, 0, false);
        let before = snapshot(&runtime);
        for property in [
            0x0000_0000u32,
            0x0100_0000,
            0x0200_0000,
            0x0300_0000,
            0x4000_0000,
            0x8000_0000,
            0x8100_0000,
        ] {
            let response = handles(&mut runtime, property, 1000);
            assert_eq!(
                &response[6..10],
                &[0, 0, 0, 0],
                "property {property:#010x} succeeds"
            );
            assert_unchanged(&runtime, &before);
        }
        assert!(!runtime.nv_update_pending);
        assert_eq!(
            runtime
                .state
                .as_ref()
                .expect("state present")
                .user_nvram
                .entries
                .len(),
            2,
            "the user NVRAM is untouched"
        );
    }

    #[test]
    fn a_handle_query_never_invokes_the_nv_commit_callback() {
        let mut runtime = started_runtime();
        let command = get_capability_command(TPM_CAP_HANDLES, 0x4000_0000, 1000);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a handle query must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);

        let failing = get_capability_command(TPM_CAP_HANDLES, 0x0400_0000, 1000);
        let input = CommandInput::new(failing.len() as u32, failing);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failing handle query must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(&response, &error_response(RC_HANDLE_PARAM2));
    }

    #[test]
    fn malformed_handle_requests_never_panic() {
        let valid = get_capability_command(TPM_CAP_HANDLES, 0x4000_0000, 10);
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

    const SWTPM_SETUP_GET_CAPABILITY: &str = "80010000001600000 17a 00000005 00000000 00000040";

    const ORACLE_PCRS_ALL_BANKS: &str = "80010000002b000000000000000005000000 04 \
         000403ffffff 000b03ffffff 000c03ffffff 000d03ffffff";
    const ORACLE_PCRS_COUNT_ZERO: &str = "80010000001300000000010000000500000000";
    const ORACLE_PCRS_EMPTY: &str = "80010000001300000000000000000500000000";

    const RC_VALUE_PARAM2: u32 = 0x2c4;

    #[track_caller]
    fn pcr_banks(runtime: &mut Tpm2Runtime, property: u32, count: u32) -> Vec<u8> {
        query(runtime, TPM_CAP_PCRS, property, count)
    }

    fn started_runtime_with_algorithms(algorithms: &str) -> Box<Tpm2Runtime> {
        let json = format!(r#"{{"Name":"custom","Algorithms":"{algorithms}"}}"#);
        let profile = validate_user_profile(Some(json.as_bytes())).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let startup = hex("80010000000c0000014400 00");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn restored_runtime_with_allocation(selections: Vec<OwnedPcrSelection>) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::parse_persistent_all_payload;
        use crate::library::tpm2::persistent::{
            PersistentAllEnvelope, materialize_persistent_state, persistent_all_store,
        };
        use crate::library::tpm2::runtime::commit_restored_state;

        let profile = validate_user_profile(None).expect("the null profile validates");
        let mut state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        state.persistent.pcr_allocated = OwnedPcrAllocation { selections };
        let blob = persistent_all_store(&state).expect("the state serializes");
        let envelope = PersistentAllEnvelope::parse(&blob).expect("the envelope parses");
        let decoded = parse_persistent_all_payload(&envelope).expect("the payload parses");
        let candidate = materialize_persistent_state(decoded).expect("materializes");
        let mut runtime = commit_restored_state(candidate).expect("commits");
        runtime.entropy = deterministic_entropy;
        let startup = hex("80010000000c0000014400 00");
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            hex("80010000000a00000000")
        );
        runtime.nv_update_pending = false;
        runtime
    }

    fn bank(hash_alg: u16, select: [u8; 3]) -> OwnedPcrSelection {
        OwnedPcrSelection {
            hash_alg,
            select: select.to_vec(),
        }
    }

    #[test]
    fn the_swtpm_setup_capability_request_matches_the_oracle_bytes() {
        let request = hex(SWTPM_SETUP_GET_CAPABILITY);
        assert_eq!(
            request,
            get_capability_command(TPM_CAP_PCRS, 0, 64),
            "the fixture is the exact request swtpm_setup builds"
        );

        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        assert_eq!(
            dispatch_bytes(&mut runtime, &request),
            hex(ORACLE_PCRS_ALL_BANKS)
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn the_default_profile_reports_every_compiled_pcr_bank() {
        let mut runtime = started_runtime();
        let expected = hex(ORACLE_PCRS_ALL_BANKS);
        for count in [1u32, 2, 3, 4, 5, 64, 1000, u32::MAX] {
            assert_eq!(pcr_banks(&mut runtime, 0, count), expected, "count {count}");
        }
    }

    #[test]
    fn a_zero_property_count_reports_more_data_and_no_banks() {
        let mut runtime = started_runtime();
        assert_eq!(pcr_banks(&mut runtime, 0, 0), hex(ORACLE_PCRS_COUNT_ZERO));
    }

    #[test]
    fn a_zero_property_count_reports_more_data_even_with_nothing_allocated() {
        let mut runtime = restored_runtime_with_allocation(Vec::new());
        assert_eq!(
            pcr_banks(&mut runtime, 0, 0),
            hex(ORACLE_PCRS_COUNT_ZERO),
            "upstream returns YES for a zero count without consulting the allocation"
        );
    }

    #[test]
    fn a_non_zero_property_returns_value_for_parameter_two() {
        for property in [1u32, 2, 0x0b, 0x100, 0x4000_0000, 0x7fff_ffff, u32::MAX] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            for count in [0u32, 1, 64] {
                assert_eq!(
                    pcr_banks(&mut runtime, property, count),
                    error_response(RC_VALUE_PARAM2),
                    "property {property:#010x}, count {count}"
                );
            }
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn a_restricted_profile_drops_its_disabled_banks() {
        const ALL: &str = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,\
aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,\
ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,\
ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb";

        let drop_tokens = |dropped: &[&str]| -> String {
            ALL.split(',')
                .filter(|token| !dropped.contains(token))
                .collect::<Vec<_>>()
                .join(",")
        };

        for (label, dropped, expected) in [
            ("all banks", &[][..], ORACLE_PCRS_ALL_BANKS),
            (
                "no sha1",
                &["sha1"][..],
                "80010000002500000000000000000500000003 000b03ffffff 000c03ffffff 000d03ffffff",
            ),
            (
                "no sha512",
                &["sha512"][..],
                "80010000002500000000000000000500000003 000403ffffff 000b03ffffff 000c03ffffff",
            ),
            (
                "no sha1 and no sha512",
                &["sha1", "sha512"][..],
                "80010000001f00000000000000000500000002 000b03ffffff 000c03ffffff",
            ),
        ] {
            let mut runtime = started_runtime_with_algorithms(&drop_tokens(dropped));
            assert_eq!(pcr_banks(&mut runtime, 0, 64), hex(expected), "{label}");
            assert_eq!(
                pcr_banks(&mut runtime, 0, 0),
                hex(ORACLE_PCRS_COUNT_ZERO),
                "{label} with a zero count"
            );
        }
    }

    #[test]
    fn a_restored_allocation_is_reported_instead_of_the_manufactured_one() {
        let mut runtime = restored_runtime_with_allocation(vec![
            bank(0x000b, [0x0f, 0x00, 0x00]),
            bank(0x000c, [0xff, 0x01, 0x00]),
        ]);
        assert_eq!(
            pcr_banks(&mut runtime, 0, 64),
            hex("80010000001f00000000000000000500000002 000b030f0000 000c03ff0100"),
            "the blob's allocation, bitmaps included"
        );
    }

    #[test]
    fn an_empty_restored_allocation_reports_no_banks() {
        let mut runtime = restored_runtime_with_allocation(Vec::new());
        assert_eq!(pcr_banks(&mut runtime, 0, 64), hex(ORACLE_PCRS_EMPTY));
    }

    #[test]
    fn the_restored_shadow_allocation_wins_once_it_has_been_applied() {
        let mut runtime = restored_runtime_with_allocation(vec![bank(0x000b, [0xff, 0xff, 0xff])]);
        runtime.shadow_pcr_allocated = OwnedPcrAllocation {
            selections: vec![bank(0x0004, [0x01, 0x00, 0x00]), bank(0x000d, [0x02, 0, 0])],
        };
        runtime.shadow_pcr_pending = true;
        crate::library::tpm2::runtime::nv_shadow_restore(&mut runtime);
        assert_eq!(
            pcr_banks(&mut runtime, 0, 64),
            hex("80010000001f00000000000000000500000002 000403010000 000d03020000")
        );
    }

    #[test]
    fn pcr_bank_queries_are_rejected_before_startup() {
        let mut runtime = manufactured_runtime();
        let before = snapshot(&runtime);
        for (property, label) in [(0u32, "a valid property"), (1, "a rejected property")] {
            assert_eq!(
                pcr_banks(&mut runtime, property, 64),
                error_response(TPM_RC_INITIALIZE),
                "{label}: the lifecycle check precedes the property check"
            );
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn truncated_and_trailing_pcr_bank_parameters_match_the_oracle() {
        let full = hex("00000005 00000000 00000040");
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
            command.extend_from_slice(&full[..len]);
            assert_eq!(
                dispatch_bytes(&mut runtime, &command),
                error_response(expected),
                "parameter length {len}"
            );
            assert_unchanged(&runtime, &before);
        }

        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let mut command = hex("80010000001700 00017a");
        command.extend_from_slice(&full);
        command.push(0xee);
        assert_eq!(
            dispatch_bytes(&mut runtime, &command),
            error_response(RC_SIZE),
            "trailing parameter bytes"
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn session_tagged_pcr_bank_requests_match_the_oracle() {
        let pw_auth =
            hex("80020000002300 00017a 00000009 40000009 0000 00 0000 00000005 00000000 00000040");
        let no_authsize = hex("80020000000a0000017a");
        let authsize_zero = hex("80020000001a0000017a 00000000 00000005 00000000 00000040");

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
    fn pcr_bank_queries_do_not_mutate_the_runtime() {
        let mut runtime = started_runtime();
        let before = snapshot(&runtime);
        let allocation = runtime.effective_pcr_allocated().cloned();
        for count in [0u32, 1, 64, u32::MAX] {
            let response = pcr_banks(&mut runtime, 0, count);
            assert_eq!(&response[6..10], &[0, 0, 0, 0], "count {count}");
            assert_unchanged(&runtime, &before);
        }
        assert_eq!(
            runtime.effective_pcr_allocated(),
            allocation.as_ref(),
            "the collector filters a copy, never the runtime allocation"
        );
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_pcr_bank_query_never_invokes_the_nv_commit_callback() {
        let mut runtime = started_runtime();
        let command = get_capability_command(TPM_CAP_PCRS, 0, 64);
        let input = CommandInput::new(command.len() as u32, command);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a PCR bank query must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, hex(ORACLE_PCRS_ALL_BANKS));

        let failing = get_capability_command(TPM_CAP_PCRS, 1, 64);
        let input = CommandInput::new(failing.len() as u32, failing);
        let response = process(&mut runtime, 0, &input, |_| {
            panic!("a failing PCR bank query must not schedule an NV commit")
        })
        .expect("the command processes");
        assert_eq!(response, error_response(RC_VALUE_PARAM2));
    }

    #[test]
    fn malformed_pcr_bank_requests_never_panic() {
        let valid = get_capability_command(TPM_CAP_PCRS, 0, 64);
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
}
