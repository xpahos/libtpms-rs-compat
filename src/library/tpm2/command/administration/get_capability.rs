use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::capability::{
    TPM_CAP_ACT, TPM_CAP_ALGS, TPM_CAP_AUDIT_COMMANDS, TPM_CAP_AUTH_POLICIES, TPM_CAP_COMMANDS,
    TPM_CAP_ECC_CURVES, TPM_CAP_HANDLES, TPM_CAP_PCR_PROPERTIES, TPM_CAP_PCRS, TPM_CAP_PP_COMMANDS,
    TPM_CAP_TPM_PROPERTIES, algorithms, audit_commands, auth_policies, commands, ecc_curves,
    handles, pcr_properties, pcrs, properties,
};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::hierarchy::{TPM_RH_ACT_0, TPM_RH_ACT_F};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const TPM_RC_3: TpmResult = 0x300;
const RC_GET_CAPABILITY_CAPABILITY: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_GET_CAPABILITY_PROPERTY: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_GET_CAPABILITY_PROPERTY_COUNT: TpmResult = TPM_RC_P + TPM_RC_3;

const HR_SHIFT: u32 = 24;
const TPM_HT_PERMANENT: u32 = 0x40;

struct GetCapabilityIn {
    capability: u32,
    property: u32,
    property_count: u32,
}

pub(in crate::library::tpm2::command) fn execute(
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
        TPM_CAP_PP_COMMANDS => {
            let page = commands::physical_presence(runtime, input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for code in &page.entries {
                out.extend_from_slice(&code.to_be_bytes());
            }
            Ok(out)
        }
        TPM_CAP_AUDIT_COMMANDS => {
            let page = audit_commands::collect(runtime, input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for code in &page.entries {
                out.extend_from_slice(&code.to_be_bytes());
            }
            Ok(out)
        }
        TPM_CAP_PCR_PROPERTIES => {
            let page = pcr_properties::collect(input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for selection in &page.entries {
                out.extend_from_slice(&selection.marshal());
            }
            Ok(out)
        }
        TPM_CAP_ECC_CURVES => {
            // TODO: Support runtimes without decoded state after the NVChip
            // fallback is implemented.
            let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
            let page = ecc_curves::collect(state, input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for curve in &page.entries {
                out.extend_from_slice(&curve.to_be_bytes());
            }
            Ok(out)
        }
        TPM_CAP_AUTH_POLICIES => {
            if input.property >> HR_SHIFT != TPM_HT_PERMANENT {
                return Err(TPM_RC_VALUE + RC_GET_CAPABILITY_PROPERTY);
            }
            let page = auth_policies::collect(runtime, input.property, input.property_count);
            let mut out = response_prefix(page.more_data, input.capability, page.entries.len());
            for policy in &page.entries {
                out.extend_from_slice(&policy.marshal());
            }
            Ok(out)
        }
        TPM_CAP_ACT => {
            if !(TPM_RH_ACT_0..=TPM_RH_ACT_F).contains(&input.property) {
                return Err(TPM_RC_VALUE + RC_GET_CAPABILITY_PROPERTY);
            }
            Ok(response_prefix(false, input.capability, 0))
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
    use crate::library::cancel::Cancellation;
    fn process(
        runtime: &mut crate::library::tpm2::runtime::Tpm2Runtime,
        locality: u8,
        command: &crate::library::CommandInput,
        commit_nv: impl FnOnce(
            &crate::library::tpm2::runtime::Tpm2Runtime,
        ) -> Result<(), crate::types::TpmResult>,
    ) -> Result<Vec<u8>, crate::types::TpmResult> {
        crate::library::tpm2::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(locality),
            command,
            &crate::library::tpm2::clock::RecordingClock::new(1_600_000_000_000, 5_000_000),
            commit_nv,
            Cancellation::disabled(),
        )
    }
    use super::*;
    use crate::library::CommandInput;
    use crate::library::constants::TPM_RC_INITIALIZE;
    use crate::library::tpm2::capability::handles::test_state::{
        load_session, nv_index_entry, occupy_object, persistent_entry, push_nvram, save_session,
    };
    use crate::library::tpm2::command::core::dispatcher::dispatch;
    use crate::library::tpm2::command::core::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::core::registry::TPM_CC_GET_CAPABILITY;
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

    fn registry_count() -> u32 {
        crate::library::tpm2::command::implemented_commands().count() as u32
    }

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

    fn manufactured_runtime() -> Tpm2Runtime {
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
        serialize_response(&dispatch(runtime, &parsed, Cancellation::disabled()))
            .expect("the response serializes")
    }

    #[track_caller]
    fn started_runtime() -> Tpm2Runtime {
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
    fn capability_query_pre_startup_rejection() {
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
    fn capability_query_post_startup_dispatch() {
        let mut runtime = started_runtime();
        let response = query(&mut runtime, 2, 0, 1000);
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "TPM_RC_SUCCESS");
    }

    #[test]
    fn truncated_parameter_indexed_error_coverage() {
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
    fn trailing_parameter_byte_size_error() {
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
    fn unsupported_capability_selector_parameter_one_value_error() {
        for capability in [0x100u32, 0x101, 0x7fff_ffff, u32::MAX] {
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

    fn capability_page(response: &[u8], capability: u32) -> (bool, Vec<u8>) {
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "the query succeeds");
        assert_eq!(&response[11..15], &capability.to_be_bytes());
        (response[10] != 0, response[19..].to_vec())
    }

    fn capability_count(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[15..19].try_into().expect("four bytes"))
    }

    #[test]
    fn audit_command_list_command_code_serialization() {
        let mut runtime = started_runtime();
        let response = query(&mut runtime, TPM_CAP_AUDIT_COMMANDS, 0, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_AUDIT_COMMANDS);
        assert!(!more);
        assert_eq!(capability_count(&response), 1);
        assert_eq!(entries, 0x0000_0140u32.to_be_bytes());

        let response = query(&mut runtime, TPM_CAP_AUDIT_COMMANDS, 0x0000_0141, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_AUDIT_COMMANDS);
        assert!(!more);
        assert_eq!(capability_count(&response), 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn pcr_property_list_tagged_selection_serialization() {
        let mut runtime = started_runtime();
        let response = query(&mut runtime, TPM_CAP_PCR_PROPERTIES, 0, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_PCR_PROPERTIES);
        assert!(!more);
        assert_eq!(capability_count(&response), 15);
        assert_eq!(entries.len(), 15 * (4 + 1 + 3));
        assert_eq!(&entries[..8], &[0, 0, 0, 0, 3, 0xff, 0xff, 0x00]);

        let response = query(&mut runtime, TPM_CAP_PCR_PROPERTIES, 0, 2);
        let (more, entries) = capability_page(&response, TPM_CAP_PCR_PROPERTIES);
        assert!(more, "a truncated page still has properties left");
        assert_eq!(capability_count(&response), 2);
        assert_eq!(entries.len(), 2 * 8);

        let response = query(&mut runtime, TPM_CAP_PCR_PROPERTIES, 0x0000_0015, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_PCR_PROPERTIES);
        assert!(!more, "a start past the last property leaves nothing");
        assert!(entries.is_empty());
    }

    #[test]
    fn ecc_curve_list_curve_id_serialization() {
        let mut runtime = started_runtime();
        let response = query(&mut runtime, TPM_CAP_ECC_CURVES, 0, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_ECC_CURVES);
        assert!(!more);
        assert_eq!(capability_count(&response), 8);
        assert_eq!(entries, hex("0001 0002 0003 0004 0005 0010 0011 0020"));

        let response = query(&mut runtime, TPM_CAP_ECC_CURVES, 0x0004, 2);
        let (more, entries) = capability_page(&response, TPM_CAP_ECC_CURVES);
        assert!(more);
        assert_eq!(entries, hex("0004 0005"));

        let response = query(&mut runtime, TPM_CAP_ECC_CURVES, 0x0021, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_ECC_CURVES);
        assert!(!more);
        assert!(entries.is_empty());
    }

    #[test]
    fn auth_policy_list_tagged_policy_serialization() {
        let mut runtime = started_runtime();
        let response = query(&mut runtime, TPM_CAP_AUTH_POLICIES, 0x4000_0000, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_AUTH_POLICIES);
        assert!(!more);
        assert_eq!(capability_count(&response), 4);
        assert_eq!(
            entries,
            hex("40000001 0010 4000000a 0010 4000000b 0010 4000000c 0010"),
            "an unset hierarchy policy carries a null hash and no digest"
        );

        let response = query(&mut runtime, TPM_CAP_AUTH_POLICIES, 0x4000_000b, 1);
        let (more, entries) = capability_page(&response, TPM_CAP_AUTH_POLICIES);
        assert!(more);
        assert_eq!(entries, hex("4000000b 0010"));

        let response = query(&mut runtime, TPM_CAP_AUTH_POLICIES, 0x4000_000d, 64);
        let (more, entries) = capability_page(&response, TPM_CAP_AUTH_POLICIES);
        assert!(!more);
        assert!(entries.is_empty());
    }

    #[test]
    fn auth_policy_property_range_value_error() {
        for property in [0u32, 0x0000_0001, 0x8000_0000, 0x0100_0000, u32::MAX] {
            let mut runtime = started_runtime();
            let before = snapshot(&runtime);
            for count in [0u32, 1, 64] {
                assert_eq!(
                    query(&mut runtime, TPM_CAP_AUTH_POLICIES, property, count),
                    error_response(RC_VALUE_PARAM2),
                    "property {property:#010x}, count {count}"
                );
            }
            assert_unchanged(&runtime, &before);
        }
    }

    #[test]
    fn zero_property_count_more_data_all_selectors() {
        let mut runtime = started_runtime();
        for (capability, property, expected) in [
            (TPM_CAP_AUDIT_COMMANDS, 0u32, true),
            (TPM_CAP_AUDIT_COMMANDS, 0x0000_0141, false),
            (TPM_CAP_PCR_PROPERTIES, 0, true),
            (TPM_CAP_PCR_PROPERTIES, 0x0000_0015, false),
            (TPM_CAP_ECC_CURVES, 0, true),
            (TPM_CAP_ECC_CURVES, 0x0021, false),
            (TPM_CAP_AUTH_POLICIES, 0x4000_0000, true),
            (TPM_CAP_AUTH_POLICIES, 0x4000_000d, false),
        ] {
            let response = query(&mut runtime, capability, property, 0);
            let (more, entries) = capability_page(&response, capability);
            assert!(entries.is_empty(), "{capability:#x}/{property:#x}");
            assert_eq!(capability_count(&response), 0);
            assert_eq!(more, expected, "{capability:#x}/{property:#x}");
        }
    }

    #[test]
    fn session_tagged_request_oracle_parity() {
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
    fn capability_request_mutation_panic_safety() {
        for valid in [
            get_capability_command(6, 0x100, 10),
            get_capability_command(TPM_CAP_HANDLES, 0x4000_0000, 10),
            get_capability_command(TPM_CAP_PCRS, 0, 64),
        ] {
            for len in 10..=valid.len() {
                for index in 6..len {
                    for flip in [0x01u8, 0x80, 0xff] {
                        let mut mutated = valid[..len].to_vec();
                        mutated[2..6].copy_from_slice(&(len as u32).to_be_bytes());
                        mutated[index] ^= flip;
                        let mut runtime = started_runtime();
                        let input = CommandInput::new(mutated.len() as u32, mutated);
                        let parsed = parse_command(&input).expect("the header parses");
                        let _ = serialize_response(&dispatch(
                            &mut runtime,
                            &parsed,
                            Cancellation::disabled(),
                        ));
                    }
                }
            }
        }
    }

    #[test]
    fn full_algorithm_list_oracle_match() {
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
    fn algorithm_boundary_query_oracle_byte_parity() {
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
    fn profile_disabled_command_code_skipping_oracle_match() {
        use crate::library::tpm2::golden_responses::disabled_commands::vector;
        let mut runtime = started_runtime();
        for (record, capability, property, count) in [
            ("DC_CCATTR_012E", 2u32, 0x0000_012eu32, 1u32),
            ("DC_CCATTR_012F", 2, 0x0000_012f, 1),
            ("DC_CCATTR_0130", 2, 0x0000_0130, 1),
            ("DC_CCATTR_0140", 2, 0x0000_0140, 1),
            ("DC_CCATTR_0141", 2, 0x0000_0141, 1),
            ("DC_CCATTR_0142", 2, 0x0000_0142, 1),
            ("DC_CCATTR_0178", 2, 0x0000_0178, 1),
            ("DC_CCATTR_0179", 2, 0x0000_0179, 1),
            ("DC_CCATTR_017A", 2, 0x0000_017a, 1),
            ("DC_CCATTR_0193", 2, 0x0000_0193, 1),
            ("DC_CCATTR_0194", 2, 0x0000_0194, 1),
            ("DC_CCATTR_0195", 2, 0x0000_0195, 1),
            ("DC_CCATTR_0196", 2, 0x0000_0196, 1),
            ("DC_CCATTR_0197", 2, 0x0000_0197, 1),
            ("DC_CCATTR_0198", 2, 0x0000_0198, 1),
            ("DC_CCATTR_0199", 2, 0x0000_0199, 1),
            ("DC_CCATTR_019C", 2, 0x0000_019c, 1),
            ("DC_CCATTR_019D", 2, 0x0000_019d, 1),
            ("DC_CCATTR_019E", 2, 0x0000_019e, 1),
            ("DC_CCATTR_019F", 2, 0x0000_019f, 1),
            ("DC_CCATTR_01A0", 2, 0x0000_01a0, 1),
            ("DC_CCLIST_0000012C_6", 2, 0x0000_012c, 6),
            ("DC_CCLIST_0000013E_6", 2, 0x0000_013e, 6),
            ("DC_CCLIST_00000176_6", 2, 0x0000_0176, 6),
            ("DC_CCLIST_00000191_8", 2, 0x0000_0191, 8),
            ("DC_CCLIST_0000019A_8", 2, 0x0000_019a, 8),
            ("DC_CCLIST_0000019C_4", 2, 0x0000_019c, 4),
            ("DC_CCLIST_000001FF_4", 2, 0x0000_01ff, 4),
            ("DC_CCLIST_20000000_4", 2, 0x2000_0000, 4),
            ("DC_CCLIST_FFFFFFFF_4", 2, 0xffff_ffff, 4),
            ("DC_PROP_0129", 6, 0x0000_0129, 1),
            ("DC_PROP_012A", 6, 0x0000_012a, 1),
            ("DC_PROP_012B", 6, 0x0000_012b, 1),
            ("DC_PPLIST_0000012C_8", 3, 0x0000_012c, 8),
            ("DC_PPLIST_00000191_12", 3, 0x0000_0191, 12),
            ("DC_AUDITCC_0000012C_16", 4, 0x0000_012c, 16),
            ("DC_AUDITCC_00000197_4", 4, 0x0000_0197, 4),
            ("DC_AUDITCC_0000019D_4", 4, 0x0000_019d, 4),
            ("DC_AUDITCC_20000000_4", 4, 0x2000_0000, 4),
        ] {
            assert_eq!(
                query(&mut runtime, capability, property, count),
                vector(record),
                "{record}"
            );
        }
    }

    #[test]
    fn fixed_command_count_property_oracle_match() {
        use crate::library::tpm2::golden_responses::disabled_commands::vector;
        for (record, expected) in [
            ("DC_PROP_0129", registry_count()),
            ("DC_PROP_012A", registry_count()),
            ("DC_PROP_012B", 0),
        ] {
            let bytes = vector(record);
            let value = u32::from_be_bytes(bytes[23..27].try_into().expect("four bytes"));
            assert_eq!(value, expected, "{record}");
        }
        assert_eq!(registry_count(), 114);
    }

    #[test]
    fn registry_generated_command_list() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 2, 0, 1000),
            hex(
                "8001 000001db 00000000 00 00000002 00000072 0440011f 04400120 02c00121 04400122 02c00124 02c00125 02c00126 02400127 02400128 02400129 0240012a 0240012b 0240012c 0240012d 0240012e 02000130 12000131 02400132 04400133 04400134 04400135 04400136 04400137 04400138 02400139 0240013a 0240013b 0200013c 0200013d 0300013e 0240013f 02400140 00400142 00400143 00400144 00400145 00400146 04000147 04000148 06000149 0400014a 0400014b 0400014c 0600014d 0400014e 0440014f 04000150 04000151 04000152 02000153 02000154 02000155 02000156 12000157 02000158 02000159 1200015b 0200015c 0200015d 0200015e 04000160 10000161 02000162 02000163 02000164 00000165 10000167 02000168 02000169 0200016a 0200016b 0200016c 0200016d 0200016e 0200016f 02000170 02000171 02000172 02000173 02000174 14000176 02000177 00000178 0000017a 0000017b 0000017c 0000017d 0000017e 0200017f 02000180 00000181 02000182 02000183 06000184 05400185 10000186 02000187 02000188 02000189 0000018a 0200018b 0200018c 0200018d 0000018e 0200018f 02000190 12000191 06000192 02000193 04000197 02000199 0200019a 0200019b 0200019c"
            )
        );
    }

    #[test]
    fn command_boundary_query_registry_pagination() {
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
            hex("80010000001700000000010000000200000001 02c00125"),
            "ChangePPS follows ChangeEPS"
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
            hex("80010000001700000000010000000200000001 0240012c"),
            "PCR_SetAuthPolicy follows PCR_Allocate"
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
            hex("80010000001700000000010000000200000001 02c00121"),
            "HierarchyControl follows EvictControl"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0133, 1),
            hex("80010000001700000000010000000200000001 04400133"),
            "GetCommandAuditDigest follows NV_GlobalWriteLock"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0139, 1),
            hex("80010000001700000000010000000200000001 02400139"),
            "DictionaryAttackLockReset follows NV_WriteLock"
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
            hex("80010000001700000000010000000200000001 0300013e"),
            "SequenceComplete advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x013f, 1),
            hex("80010000001700000000010000000200000001 0240013f"),
            "SetAlgorithmSet follows SequenceComplete"
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
                "80010000003b0000000001000000020000000a 04000147 04000148 06000149 0400014a 0400014b 0400014c 0600014d 0400014e 0440014f 04000150"
            ),
            "ActivateCredential leads the page that starts at its own command code"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0173, 2),
            hex("80010000001b00000000010000000200000002 02000173 02000174"),
            "ReadPublic and RSA_Encrypt page together"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0174, 3),
            hex("80010000001f00000000010000000200000003 02000174 14000176 02000177"),
            "the unimplemented codes between them are skipped"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0178, 1),
            hex("80010000001700000000010000000200000001 00000178"),
            "TPM2_ECC_Parameters follows VerifySignature"
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
            hex("80010000001f00000000010000000200000003 0000017e 0200017f 02000180"),
            "PCR_Read advertises itself through the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0182, 2),
            hex("80010000001b00000000010000000200000002 02000182 02000183"),
            "PCR_SetAuthValue follows PCR_Extend"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x0184, 1),
            hex("80010000001700000000010000000200000001 06000184"),
            "EventSequenceComplete now follows NV_Certify"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x019c, 1),
            hex("80010000001700000000000000000200000001 0200019c"),
            "PolicyParameters closes the registry"
        );
        assert_eq!(
            query(&mut runtime, 2, 0x2000_0000, 10),
            hex("80010000001300000000000000000200000000"),
            "above the last command matches the oracle bytes"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, 3),
            hex("80010000001f000000000100000002000000030440011f0440012002c00121"),
            "an exhausted count leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, registry_count() - 2),
            hex(
                "8001 000001d3 00000000 01 00000002 00000070 0440011f 04400120 02c00121 04400122 02c00124 02c00125 02c00126 02400127 02400128 02400129 0240012a 0240012b 0240012c 0240012d 0240012e 02000130 12000131 02400132 04400133 04400134 04400135 04400136 04400137 04400138 02400139 0240013a 0240013b 0200013c 0200013d 0300013e 0240013f 02400140 00400142 00400143 00400144 00400145 00400146 04000147 04000148 06000149 0400014a 0400014b 0400014c 0600014d 0400014e 0440014f 04000150 04000151 04000152 02000153 02000154 02000155 02000156 12000157 02000158 02000159 1200015b 0200015c 0200015d 0200015e 04000160 10000161 02000162 02000163 02000164 00000165 10000167 02000168 02000169 0200016a 0200016b 0200016c 0200016d 0200016e 0200016f 02000170 02000171 02000172 02000173 02000174 14000176 02000177 00000178 0000017a 0000017b 0000017c 0000017d 0000017e 0200017f 02000180 00000181 02000182 02000183 06000184 05400185 10000186 02000187 02000188 02000189 0000018a 0200018b 0200018c 0200018d 0000018e 0200018f 02000190 12000191 06000192 02000193 04000197 02000199 0200019a"
            ),
            "two short of the registry still leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, registry_count() - 1),
            hex(
                "8001 000001d7 00000000 01 00000002 00000071 0440011f 04400120 02c00121 04400122 02c00124 02c00125 02c00126 02400127 02400128 02400129 0240012a 0240012b 0240012c 0240012d 0240012e 02000130 12000131 02400132 04400133 04400134 04400135 04400136 04400137 04400138 02400139 0240013a 0240013b 0200013c 0200013d 0300013e 0240013f 02400140 00400142 00400143 00400144 00400145 00400146 04000147 04000148 06000149 0400014a 0400014b 0400014c 0600014d 0400014e 0440014f 04000150 04000151 04000152 02000153 02000154 02000155 02000156 12000157 02000158 02000159 1200015b 0200015c 0200015d 0200015e 04000160 10000161 02000162 02000163 02000164 00000165 10000167 02000168 02000169 0200016a 0200016b 0200016c 0200016d 0200016e 0200016f 02000170 02000171 02000172 02000173 02000174 14000176 02000177 00000178 0000017a 0000017b 0000017c 0000017d 0000017e 0200017f 02000180 00000181 02000182 02000183 06000184 05400185 10000186 02000187 02000188 02000189 0000018a 0200018b 0200018c 0200018d 0000018e 0200018f 02000190 12000191 06000192 02000193 04000197 02000199 0200019a 0200019b"
            ),
            "one short of the registry still leaves more data"
        );
        assert_eq!(
            query(&mut runtime, 2, 0, registry_count()),
            hex(
                "8001 000001db 00000000 00 00000002 00000072 0440011f 04400120 02c00121 04400122 02c00124 02c00125 02c00126 02400127 02400128 02400129 0240012a 0240012b 0240012c 0240012d 0240012e 02000130 12000131 02400132 04400133 04400134 04400135 04400136 04400137 04400138 02400139 0240013a 0240013b 0200013c 0200013d 0300013e 0240013f 02400140 00400142 00400143 00400144 00400145 00400146 04000147 04000148 06000149 0400014a 0400014b 0400014c 0600014d 0400014e 0440014f 04000150 04000151 04000152 02000153 02000154 02000155 02000156 12000157 02000158 02000159 1200015b 0200015c 0200015d 0200015e 04000160 10000161 02000162 02000163 02000164 00000165 10000167 02000168 02000169 0200016a 0200016b 0200016c 0200016d 0200016e 0200016f 02000170 02000171 02000172 02000173 02000174 14000176 02000177 00000178 0000017a 0000017b 0000017c 0000017d 0000017e 0200017f 02000180 00000181 02000182 02000183 06000184 05400185 10000186 02000187 02000188 02000189 0000018a 0200018b 0200018c 0200018d 0000018e 0200018f 02000190 12000191 06000192 02000193 04000197 02000199 0200019a 0200019b 0200019c"
            ),
            "an exact count consumes the registry"
        );
    }

    const ORACLE_PROPS_FIXED_HEAD: &str = "8001000001830000000000000000060000002e00000100322e300000000101000000000000010200\
0000b7000001030000001900000104000007e80000010549424d0000000106535720200000010720\
54504d000001080000000000000109000000000000010a000000010000010b202401250000010c00\
1200000000010d000004000000010e000000030000010f0000000700000110000000030000011100\
00004000000112000000180000011300000003000001140000ffff00000116000000000000011700\
000800000001180000000600000119000010000000011a0000000d0000011b000000060000011c00\
0001000000011d000000ff0000011e000010000000011f0000100000000120000000400000012100\
000a8c00000122000001940000012300000001000001240000000000000125000001060000012600\
00001900000127000007e80000012800000080";

    const ORACLE_PROPS_FIXED_TAIL: &str =
        "0000012b000000000000012c000004000000012d000000000000012e00000400";

    fn oracle_props_fixed_all() -> Vec<u8> {
        let count = registry_count();
        hex(&format!(
            "{ORACLE_PROPS_FIXED_HEAD}00000129{count:08x}0000012a{count:08x}\
             {ORACLE_PROPS_FIXED_TAIL}"
        ))
    }

    #[test]
    fn fixed_property_group_oracle_match_registry_counts() {
        let mut runtime = started_runtime();
        let expected = oracle_props_fixed_all();
        assert_eq!(query(&mut runtime, 6, 0, 1000), expected, "clamped start");
        assert_eq!(query(&mut runtime, 6, 0x100, 1000), expected);
    }

    #[test]
    fn variable_property_group_oracle_match() {
        let mut runtime = started_runtime();
        assert_eq!(
            query(&mut runtime, 6, 0x200, 1000),
            hex(
                "8001000000bb000000000000000006000000150000020000000400000002018000000f000002020000000000000203000000000000020400000003000002050000000000000206000000400000020700000003000002080000000000000209000000400000020a000000000000020b000000190000020c000000000000020d000000080000020e000000000000020f0000000300000210000003e800000211000003e8000002120000000000000213000000000000021400000000"
            )
        );
    }

    #[test]
    fn property_boundary_query_oracle_byte_parity() {
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
    fn successful_query_runtime_preservation() {
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
    fn get_capability_no_nv_commit_callback() {
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
    fn response_capability_selector_echo() {
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
    fn permanent_handle_list_oracle_match() {
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
    fn permanent_handle_boundary_query_oracle_byte_parity() {
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
    fn pcr_handle_list_oracle_match() {
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
    fn pcr_handle_boundary_query_oracle_byte_parity() {
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
    fn fresh_start_empty_dynamic_handle_ranges() {
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
    fn unimplemented_handle_type_parameter_two_handle_error() {
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
    fn nv_index_handle_oracle_byte_parity() {
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
    fn persistent_object_handle_oracle_byte_parity() {
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
    fn transient_object_handle_oracle_byte_parity() {
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
    fn session_handle_oracle_byte_parity() {
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
    fn response_size_limit_handle_list_truncation() {
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
    fn handle_query_pre_startup_rejection() {
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
    fn handle_query_runtime_preservation() {
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
    fn handle_query_no_nv_commit_callback() {
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

    fn started_runtime_with_algorithms(algorithms: &str) -> Tpm2Runtime {
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

    fn restored_runtime_with_allocation(selections: Vec<OwnedPcrSelection>) -> Tpm2Runtime {
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
    fn swtpm_setup_capability_request_oracle_match() {
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
    fn default_profile_all_compiled_pcr_banks() {
        let mut runtime = started_runtime();
        let expected = hex(ORACLE_PCRS_ALL_BANKS);
        for count in [1u32, 2, 3, 4, 5, 64, 1000, u32::MAX] {
            assert_eq!(pcr_banks(&mut runtime, 0, count), expected, "count {count}");
        }
    }

    #[test]
    fn zero_property_count_more_data_no_banks() {
        let mut runtime = started_runtime();
        assert_eq!(pcr_banks(&mut runtime, 0, 0), hex(ORACLE_PCRS_COUNT_ZERO));
    }

    #[test]
    fn zero_property_count_more_data_unallocated() {
        let mut runtime = restored_runtime_with_allocation(Vec::new());
        assert_eq!(
            pcr_banks(&mut runtime, 0, 0),
            hex(ORACLE_PCRS_COUNT_ZERO),
            "upstream returns YES for a zero count without consulting the allocation"
        );
    }

    #[test]
    fn nonzero_property_value_error_parameter_two() {
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
    fn restricted_profile_disabled_bank_omission() {
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
    fn restored_allocation_precedence_over_manufactured() {
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
    fn empty_restored_allocation_no_banks() {
        let mut runtime = restored_runtime_with_allocation(Vec::new());
        assert_eq!(pcr_banks(&mut runtime, 0, 64), hex(ORACLE_PCRS_EMPTY));
    }

    #[test]
    fn applied_shadow_allocation_precedence() {
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
    fn pcr_bank_query_pre_startup_rejection() {
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
    fn pcr_bank_truncated_trailing_parameter_oracle_parity() {
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
    fn session_tagged_pcr_bank_request_oracle_parity() {
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
    fn pcr_bank_query_runtime_preservation() {
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
    fn pcr_bank_query_no_nv_commit_callback() {
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
}

#[cfg(test)]
mod oracle {
    use crate::library::tpm2::capability::{
        TPM_CAP_AUDIT_COMMANDS, TPM_CAP_AUTH_POLICIES, TPM_CAP_ECC_CURVES, TPM_CAP_PCR_PROPERTIES,
    };
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::command::core::registry::TPM_CC_GET_CAPABILITY;
    use crate::library::tpm2::golden_responses::{
        attestation, ecc_commands, hierarchy_management, platform_state,
    };
    use crate::library::tpm2::object_load::replay::{clock, exec_raw, plain, runtime_from};
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const TPM_RH_OWNER: u32 = 0x4000_0001;
    const RS_PW: u32 = 0x4000_0009;
    const TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS: u32 = 0x0000_0140;
    const TPM_CC_SET_PRIMARY_POLICY: u32 = 0x0000_012e;
    const ALG_NULL: u16 = 0x0010;
    const ALG_SHA256: u16 = 0x000b;

    fn ready(vector: fn(&str) -> &'static [u8], clock: &SteppingClock) -> Tpm2Runtime {
        runtime_from(vector("PERMALL_READY"), vector("VOLATILE_READY"), clock)
    }

    fn capability(capability: u32, property: u32, count: u32) -> Vec<u8> {
        let mut payload = capability.to_be_bytes().to_vec();
        payload.extend_from_slice(&property.to_be_bytes());
        payload.extend_from_slice(&count.to_be_bytes());
        plain(TPM_CC_GET_CAPABILITY, &payload)
    }

    fn password_area() -> Vec<u8> {
        let mut area = RS_PW.to_be_bytes().to_vec();
        area.extend_from_slice(&0u16.to_be_bytes());
        area.push(0x00);
        area.extend_from_slice(&0u16.to_be_bytes());
        let mut out = (area.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&area);
        out
    }

    fn owner_command(code: u32, parameters: &[u8]) -> Vec<u8> {
        let mut payload = TPM_RH_OWNER.to_be_bytes().to_vec();
        payload.extend_from_slice(&password_area());
        payload.extend_from_slice(parameters);
        let mut out = 0x8002u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(&payload);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    #[track_caller]
    fn expect(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        vector: fn(&str) -> &'static [u8],
        label: &str,
        bytes: Vec<u8>,
    ) {
        assert_eq!(exec_raw(runtime, clock, bytes), vector(label), "{label}");
    }

    #[test]
    fn audit_command_list_oracle_match() {
        let clock = clock();
        let vector = attestation::vector;
        let mut runtime = ready(vector, &clock);
        let mut set_list = ALG_NULL.to_be_bytes().to_vec();
        set_list.extend_from_slice(&2u32.to_be_bytes());
        set_list.extend_from_slice(&0x0000_014eu32.to_be_bytes());
        set_list.extend_from_slice(&0x0000_017bu32.to_be_bytes());
        set_list.extend_from_slice(&0u32.to_be_bytes());

        for (label, bytes) in [
            ("AUDITCC_INITIAL", capability(TPM_CAP_AUDIT_COMMANDS, 0, 64)),
            (
                "AUDITCC_SET",
                owner_command(TPM_CC_SET_COMMAND_CODE_AUDIT_STATUS, &set_list),
            ),
            (
                "AUDITCC_AFTER_SET",
                capability(TPM_CAP_AUDIT_COMMANDS, 0, 64),
            ),
            (
                "AUDITCC_FROM_NV_READ",
                capability(TPM_CAP_AUDIT_COMMANDS, 0x0000_014e, 64),
            ),
            (
                "AUDITCC_AFTER_NV_READ",
                capability(TPM_CAP_AUDIT_COMMANDS, 0x0000_014f, 64),
            ),
            ("AUDITCC_ONE", capability(TPM_CAP_AUDIT_COMMANDS, 0, 1)),
            (
                "AUDITCC_COUNT_ZERO",
                capability(TPM_CAP_AUDIT_COMMANDS, 0, 0),
            ),
            (
                "AUDITCC_PAST_END",
                capability(TPM_CAP_AUDIT_COMMANDS, 0x0000_017c, 64),
            ),
            (
                "AUDITCC_COUNT_ZERO_PAST_END",
                capability(TPM_CAP_AUDIT_COMMANDS, 0x0000_017c, 0),
            ),
            (
                "AUDITCC_VENDOR_START",
                capability(TPM_CAP_AUDIT_COMMANDS, 0x2000_0000, 64),
            ),
        ] {
            expect(&mut runtime, &clock, vector, label, bytes);
        }
    }

    #[test]
    fn pcr_property_list_oracle_match() {
        let clock = clock();
        let vector = platform_state::vector;
        let mut runtime = ready(vector, &clock);
        for (label, property, count) in [
            ("PCRPROP_ALL", 0u32, 64u32),
            ("PCRPROP_FROM_MIDDLE", 6, 64),
            ("PCRPROP_FROM_HOLE", 0x0b, 64),
            ("PCRPROP_ONE", 0, 1),
            ("PCRPROP_TRUNCATED", 0, 14),
            ("PCRPROP_EXACT", 0, 15),
            ("PCRPROP_COUNT_ZERO", 0, 0),
            ("PCRPROP_PAST_END", 0x15, 64),
            ("PCRPROP_COUNT_ZERO_PAST_END", 0x15, 0),
        ] {
            let bytes = capability(TPM_CAP_PCR_PROPERTIES, property, count);
            expect(&mut runtime, &clock, vector, label, bytes);
        }
    }

    #[test]
    fn ecc_curve_list_oracle_match() {
        let clock = clock();
        let vector = ecc_commands::vector;
        let mut runtime = ready(vector, &clock);
        for (label, property, count) in [
            ("CURVES_ALL", 0u32, 64u32),
            ("CURVES_FROM_P384", 0x0004, 64),
            ("CURVES_BETWEEN", 0x0006, 64),
            ("CURVES_ONE", 0, 1),
            ("CURVES_TRUNCATED", 0, 7),
            ("CURVES_EXACT", 0, 8),
            ("CURVES_COUNT_ZERO", 0, 0),
            ("CURVES_PAST_END", 0x0021, 64),
            ("CURVES_COUNT_ZERO_PAST_END", 0x0021, 0),
        ] {
            let bytes = capability(TPM_CAP_ECC_CURVES, property, count);
            expect(&mut runtime, &clock, vector, label, bytes);
        }
    }

    #[test]
    fn auth_policy_list_oracle_match() {
        let clock = clock();
        let vector = hierarchy_management::vector;
        let mut runtime = ready(vector, &clock);
        let mut policy = (32u16).to_be_bytes().to_vec();
        policy.extend((0u8..32).collect::<Vec<u8>>());
        policy.extend_from_slice(&ALG_SHA256.to_be_bytes());

        expect(
            &mut runtime,
            &clock,
            vector,
            "AUTHPOL_INITIAL",
            capability(TPM_CAP_AUTH_POLICIES, 0x4000_0000, 64),
        );
        expect(
            &mut runtime,
            &clock,
            vector,
            "AUTHPOL_SET_OWNER",
            owner_command(TPM_CC_SET_PRIMARY_POLICY, &policy),
        );
        for (label, property, count) in [
            ("AUTHPOL_AFTER_OWNER", 0x4000_0000u32, 64u32),
            ("AUTHPOL_FROM_ENDORSEMENT", 0x4000_000b, 64),
            ("AUTHPOL_FROM_NULL_HANDLE", 0x4000_0007, 64),
            ("AUTHPOL_ONE", 0x4000_0000, 1),
            ("AUTHPOL_TRUNCATED", 0x4000_0000, 3),
            ("AUTHPOL_EXACT", 0x4000_0000, 4),
            ("AUTHPOL_COUNT_ZERO", 0x4000_0000, 0),
            ("AUTHPOL_PAST_END", 0x4000_000d, 64),
            ("AUTHPOL_COUNT_ZERO_PAST_END", 0x4000_000d, 0),
            ("AUTHPOL_BAD_HANDLE_TYPE", 0x8000_0000, 64),
            ("AUTHPOL_TRANSIENT_HANDLE_TYPE", 0x0000_0000, 64),
        ] {
            let bytes = capability(TPM_CAP_AUTH_POLICIES, property, count);
            expect(&mut runtime, &clock, vector, label, bytes);
        }
    }
}
