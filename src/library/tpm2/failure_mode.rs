use crate::ffi_types::TpmResult;
use crate::library::CommandInput;
use crate::library::constants::{TPM_FAIL, TPM_RC_FAILURE};

use super::capability::TPM_CAP_TPM_PROPERTIES;
use super::command::{
    HEADER_SIZE, Response, TPM_CC_GET_CAPABILITY, TPM_ST_NO_SESSIONS, serialize_response,
};
use super::runtime::Tpm2Runtime;

pub(super) const TPM_CC_GET_TEST_RESULT: u32 = 0x0000_017c;

const GET_CAPABILITY_COMMAND_SIZE: u32 = HEADER_SIZE as u32 + 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureModeRoute {
    BareFailure,
    GetTestResult,
    RestrictedGetCapability,
}

struct FailureModeHeader {
    tag: u16,
    size: u32,
    code: u32,
}

fn peek_header(command: &CommandInput) -> Option<FailureModeHeader> {
    let (tag_bytes, rest) = command.bytes().split_first_chunk::<2>()?;
    let (size_bytes, rest) = rest.split_first_chunk::<4>()?;
    let (code_bytes, _) = rest.split_first_chunk::<4>()?;
    Some(FailureModeHeader {
        tag: u16::from_be_bytes(*tag_bytes),
        size: u32::from_be_bytes(*size_bytes),
        code: u32::from_be_bytes(*code_bytes),
    })
}

fn peek_capability(command: &CommandInput) -> Option<u32> {
    let payload = command.bytes().get(HEADER_SIZE..)?;
    let (capability_bytes, _) = payload.split_first_chunk::<4>()?;
    Some(u32::from_be_bytes(*capability_bytes))
}

pub(super) fn route(command: &CommandInput) -> FailureModeRoute {
    let Some(header) = peek_header(command) else {
        return FailureModeRoute::BareFailure;
    };
    if header.tag != TPM_ST_NO_SESSIONS
        || header.size < HEADER_SIZE as u32
        || header.size != command.received_size()
    {
        return FailureModeRoute::BareFailure;
    }
    match header.code {
        TPM_CC_GET_TEST_RESULT if header.size == HEADER_SIZE as u32 => {
            FailureModeRoute::GetTestResult
        }
        TPM_CC_GET_CAPABILITY
            if header.size == GET_CAPABILITY_COMMAND_SIZE
                && peek_capability(command) == Some(TPM_CAP_TPM_PROPERTIES) =>
        {
            FailureModeRoute::RestrictedGetCapability
        }
        _ => FailureModeRoute::BareFailure,
    }
}

// TODO: Answer TPM2_GetTestResult from `runtime.self_test.failure` and the
// restricted TPM2_GetCapability property query once those commands exist; both
// already reach this boundary through `route`.
pub(in crate::library::tpm2) fn process(
    _runtime: &mut Tpm2Runtime,
    command: &CommandInput,
) -> Result<Vec<u8>, TpmResult> {
    match route(command) {
        FailureModeRoute::BareFailure
        | FailureModeRoute::GetTestResult
        | FailureModeRoute::RestrictedGetCapability => bare_failure(),
    }
}

fn bare_failure() -> Result<Vec<u8>, TpmResult> {
    serialize_response(&Response::error(TPM_RC_FAILURE)).map_err(|_| TPM_FAIL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::capability::{TPM_CAP_ALGS, TPM_CAP_COMMANDS};
    use crate::library::tpm2::command::implemented_commands;
    use crate::library::tpm2::runtime::empty_state_runtime;

    const BARE_FAILURE: [u8; 10] = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01];

    fn input(bytes: &[u8]) -> CommandInput {
        CommandInput::new(bytes.len() as u32, bytes.to_vec())
    }

    fn framed(tag: u16, code: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn get_capability(capability: u32, property: u32, property_count: u32) -> Vec<u8> {
        let mut payload = capability.to_be_bytes().to_vec();
        payload.extend_from_slice(&property.to_be_bytes());
        payload.extend_from_slice(&property_count.to_be_bytes());
        framed(0x8001, TPM_CC_GET_CAPABILITY, &payload)
    }

    #[test]
    fn every_implemented_command_answers_the_bare_failure_response() {
        for descriptor in implemented_commands() {
            let mut runtime = empty_state_runtime();
            runtime.failure_mode = true;
            for payload in [&[][..], &[0x00][..], &[0x00; 12][..]] {
                let bytes = framed(0x8001, descriptor.code, payload);
                assert_eq!(
                    process(&mut runtime, &input(&bytes)).unwrap(),
                    BARE_FAILURE,
                    "code {:#x}",
                    descriptor.code
                );
            }
        }
    }

    #[test]
    fn the_future_special_command_codes_are_identified_without_executing() {
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        assert_eq!(route(&input(&bytes)), FailureModeRoute::GetTestResult);

        let bytes = get_capability(TPM_CAP_TPM_PROPERTIES, 0x0000_0100, 1);
        assert_eq!(
            route(&input(&bytes)),
            FailureModeRoute::RestrictedGetCapability
        );

        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            BARE_FAILURE,
            "routing does not yet change the answer"
        );
    }

    #[test]
    fn only_the_tpm_properties_group_takes_the_restricted_capability_route() {
        assert_eq!(
            route(&input(&get_capability(TPM_CAP_TPM_PROPERTIES, 0x100, 1))),
            FailureModeRoute::RestrictedGetCapability
        );
        for capability in [
            TPM_CAP_ALGS,
            TPM_CAP_COMMANDS,
            0x0000_0001,
            0x0000_0003,
            0x0000_0005,
            0x0000_0007,
            0x0000_0009,
            0x0000_0100,
            0x7fff_ffff,
            u32::MAX,
        ] {
            assert_eq!(
                route(&input(&get_capability(capability, 0x100, 1))),
                FailureModeRoute::BareFailure,
                "capability {capability:#x}"
            );
        }
    }

    #[test]
    fn the_property_and_count_fields_are_not_restricted() {
        for property in [0u32, 1, 0x100, 0x12e, 0x200, 0x7fff_ffff, u32::MAX] {
            for property_count in [0u32, 1, 2, 1000, 0x8000_0000, u32::MAX] {
                assert_eq!(
                    route(&input(&get_capability(
                        TPM_CAP_TPM_PROPERTIES,
                        property,
                        property_count
                    ))),
                    FailureModeRoute::RestrictedGetCapability,
                    "property {property:#x} count {property_count:#x}"
                );
            }
        }
    }

    #[test]
    fn a_capability_request_of_the_wrong_length_is_a_bare_failure() {
        for extra in [&[][..], &[0x00; 4][..], &[0x00; 7][..], &[0x00; 16][..]] {
            let mut payload = TPM_CAP_TPM_PROPERTIES.to_be_bytes().to_vec();
            payload.extend_from_slice(extra);
            let bytes = framed(0x8001, TPM_CC_GET_CAPABILITY, &payload);
            assert_eq!(
                route(&input(&bytes)),
                FailureModeRoute::BareFailure,
                "{} payload bytes",
                payload.len()
            );
        }
    }

    #[test]
    fn a_session_tagged_capability_request_is_a_bare_failure() {
        let mut bytes = get_capability(TPM_CAP_TPM_PROPERTIES, 0x100, 1);
        bytes[..2].copy_from_slice(&0x8002u16.to_be_bytes());
        assert_eq!(route(&input(&bytes)), FailureModeRoute::BareFailure);
    }

    #[test]
    fn get_test_result_is_not_registered_or_advertised() {
        assert!(
            implemented_commands().all(|descriptor| descriptor.code != TPM_CC_GET_TEST_RESULT),
            "GetTestResult must not be registered before it is implemented"
        );
    }

    #[test]
    fn session_tagged_and_wrong_sized_requests_fall_back_to_bare_failure() {
        for tag in [0x8002u16, 0x0000, 0xffff] {
            let bytes = framed(tag, TPM_CC_GET_TEST_RESULT, &[]);
            assert_eq!(route(&input(&bytes)), FailureModeRoute::BareFailure);
        }
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[0x00]);
        assert_eq!(route(&input(&bytes)), FailureModeRoute::BareFailure);
        let bytes = framed(0x8001, TPM_CC_GET_CAPABILITY, &[0x00; 8]);
        assert_eq!(route(&input(&bytes)), FailureModeRoute::BareFailure);
    }

    #[test]
    fn a_declared_size_that_disagrees_with_the_request_is_a_bare_failure() {
        let mut bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        bytes[5] = 0x0b;
        assert_eq!(route(&input(&bytes[..10])), FailureModeRoute::BareFailure);
    }

    #[test]
    fn an_oversized_declared_size_never_drives_an_allocation() {
        let mut bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        bytes[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        let command = CommandInput::new(u32::MAX, bytes[..6].to_vec());
        assert_eq!(route(&command), FailureModeRoute::BareFailure);
        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        assert_eq!(process(&mut runtime, &command).unwrap(), BARE_FAILURE);
    }

    #[test]
    fn truncated_and_malformed_requests_never_panic() {
        let valid = get_capability(TPM_CAP_TPM_PROPERTIES, 0x0000_0100, 1);
        for length in 0..=valid.len() {
            let truncated = &valid[..length];
            assert_eq!(
                route(&input(truncated)),
                if length == valid.len() {
                    FailureModeRoute::RestrictedGetCapability
                } else {
                    FailureModeRoute::BareFailure
                },
                "length {length}"
            );
            for index in 0..length {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = truncated.to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = empty_state_runtime();
                    runtime.failure_mode = true;
                    assert_eq!(
                        process(&mut runtime, &input(&mutated)).unwrap(),
                        BARE_FAILURE
                    );
                }
            }
        }
    }

    #[test]
    fn an_empty_request_is_a_bare_failure() {
        let mut runtime = empty_state_runtime();
        runtime.failure_mode = true;
        assert_eq!(route(&input(&[])), FailureModeRoute::BareFailure);
        assert_eq!(process(&mut runtime, &input(&[])).unwrap(), BARE_FAILURE);
    }
}
