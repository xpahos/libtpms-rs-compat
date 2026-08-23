use crate::ffi_types::TpmResult;
use crate::library::CommandInput;
use crate::library::constants::{TPM_FAIL, TPM_RC_FAILURE, TPM_RC_NV_UNINITIALIZED};

use super::capability::TPM_CAP_TPM_PROPERTIES;
use super::capability::properties::{
    TPM_PT_FIRMWARE_VERSION_2, TPM_PT_MANUFACTURER, failure_mode_property_value,
};
use super::command::{
    HEADER_SIZE, Response, TPM_CC_GET_CAPABILITY, TPM_CC_GET_TEST_RESULT, TPM_ST_NO_SESSIONS,
    serialize_response_within,
};
use super::runtime::{FailureDiagnostics, Tpm2Runtime};
use super::self_test::{PrimitiveTest, SelfTestState};

const GET_CAPABILITY_COMMAND_SIZE: u32 = HEADER_SIZE as u32 + 12;

const FATAL_ERROR_INTERNAL: u32 = 3;
const FATAL_ERROR_ENTROPY: u32 = 5;
const FATAL_ERROR_SELF_TEST: u32 = 6;
pub(super) const FATAL_ERROR_NV_UNRECOVERABLE: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) enum FailureLocation {
    NvCommit,
    HashSelfTest,
    SymmetricSelfTest,
    RsaOaepEncrypt,
    RsaOaepRoundTripDecrypt,
    RsaOaepRoundTripCompare,
    RsaOaepKnownAnswerDecrypt,
    RsaOaepKnownAnswerCompare,
    DrbgInvalidState,
    DrbgEntropy,
}

const fn function_word(name: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*name)
}

impl FailureLocation {
    #[cfg(test)]
    pub(in crate::library::tpm2) const ALL: [Self; 10] = [
        Self::NvCommit,
        Self::HashSelfTest,
        Self::SymmetricSelfTest,
        Self::RsaOaepEncrypt,
        Self::RsaOaepRoundTripDecrypt,
        Self::RsaOaepRoundTripCompare,
        Self::RsaOaepKnownAnswerDecrypt,
        Self::RsaOaepKnownAnswerCompare,
        Self::DrbgInvalidState,
        Self::DrbgEntropy,
    ];

    #[cfg(test)]
    const fn position(self) -> usize {
        match self {
            Self::NvCommit => 0,
            Self::HashSelfTest => 1,
            Self::SymmetricSelfTest => 2,
            Self::RsaOaepEncrypt => 3,
            Self::RsaOaepRoundTripDecrypt => 4,
            Self::RsaOaepRoundTripCompare => 5,
            Self::RsaOaepKnownAnswerDecrypt => 6,
            Self::RsaOaepKnownAnswerCompare => 7,
            Self::DrbgInvalidState => 8,
            Self::DrbgEntropy => 9,
        }
    }

    pub(in crate::library::tpm2) const fn diagnostics(self) -> FailureDiagnostics {
        let (name, line, code) = match self {
            Self::NvCommit => (b"Exec", 318, FATAL_ERROR_INTERNAL),
            Self::HashSelfTest => (b"Test", 155, FATAL_ERROR_SELF_TEST),
            Self::SymmetricSelfTest => (b"Test", 259, FATAL_ERROR_SELF_TEST),
            Self::RsaOaepEncrypt => (b"Test", 491, FATAL_ERROR_SELF_TEST),
            Self::RsaOaepRoundTripDecrypt => (b"Test", 497, FATAL_ERROR_SELF_TEST),
            Self::RsaOaepRoundTripCompare => (b"Test", 502, FATAL_ERROR_SELF_TEST),
            Self::RsaOaepKnownAnswerDecrypt => (b"Test", 508, FATAL_ERROR_SELF_TEST),
            Self::RsaOaepKnownAnswerCompare => (b"Test", 512, FATAL_ERROR_SELF_TEST),
            Self::DrbgInvalidState => (b"DRBG", 940, FATAL_ERROR_INTERNAL),
            Self::DrbgEntropy => (b"Encr", 387, FATAL_ERROR_ENTROPY),
        };
        FailureDiagnostics {
            function: function_word(name),
            line,
            code,
        }
    }

    pub(in crate::library::tpm2) fn for_self_test(state: &SelfTestState) -> Self {
        match state.failure {
            Some(failure) if failure.primitive == PrimitiveTest::Aes256 => Self::SymmetricSelfTest,
            _ => Self::HashSelfTest,
        }
    }
}

pub(in crate::library::tpm2) fn enter_failure_mode(
    runtime: &mut Tpm2Runtime,
    location: FailureLocation,
) {
    runtime.failure_mode = true;
    runtime.failure_diagnostics = location.diagnostics();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FailureModeRoute {
    BareFailure,
    GetTestResult,
    RestrictedGetCapability { property: u32, property_count: u32 },
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

fn peek_u32(command: &CommandInput, at: usize) -> Option<u32> {
    let bytes = command.bytes().get(at..at.checked_add(4)?)?;
    let bytes: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

pub(super) fn route(command: &CommandInput) -> FailureModeRoute {
    let Some(header) = peek_header(command) else {
        return FailureModeRoute::BareFailure;
    };
    if header.tag != TPM_ST_NO_SESSIONS || header.size < HEADER_SIZE as u32 {
        return FailureModeRoute::BareFailure;
    }
    match header.code {
        TPM_CC_GET_TEST_RESULT if header.size == HEADER_SIZE as u32 => {
            FailureModeRoute::GetTestResult
        }
        TPM_CC_GET_CAPABILITY if header.size == GET_CAPABILITY_COMMAND_SIZE => {
            let (Some(capability), Some(property), Some(property_count)) = (
                peek_u32(command, HEADER_SIZE),
                peek_u32(command, HEADER_SIZE + 4),
                peek_u32(command, HEADER_SIZE + 8),
            ) else {
                return FailureModeRoute::BareFailure;
            };
            if capability != TPM_CAP_TPM_PROPERTIES {
                return FailureModeRoute::BareFailure;
            }
            FailureModeRoute::RestrictedGetCapability {
                property,
                property_count,
            }
        }
        _ => FailureModeRoute::BareFailure,
    }
}

pub(in crate::library::tpm2) fn process(
    runtime: &mut Tpm2Runtime,
    command: &CommandInput,
) -> Result<Vec<u8>, TpmResult> {
    match route(command) {
        FailureModeRoute::BareFailure => bare_failure(runtime.buffer_size),
        FailureModeRoute::GetTestResult => success(
            test_result_parameters(runtime.failure_diagnostics),
            runtime.buffer_size,
        ),
        FailureModeRoute::RestrictedGetCapability {
            property,
            property_count,
        } => success(
            restricted_capability_parameters(property, property_count),
            runtime.buffer_size,
        ),
    }
}

fn test_result_parameters(diagnostics: FailureDiagnostics) -> Vec<u8> {
    let test_result = if diagnostics.code == FATAL_ERROR_NV_UNRECOVERABLE {
        TPM_RC_NV_UNINITIALIZED
    } else {
        TPM_RC_FAILURE
    };
    let mut out = Vec::with_capacity(2 + 12 + 4);
    out.extend_from_slice(&12u16.to_be_bytes());
    out.extend_from_slice(&diagnostics.function.to_be_bytes());
    out.extend_from_slice(&diagnostics.line.to_be_bytes());
    out.extend_from_slice(&diagnostics.code.to_be_bytes());
    out.extend_from_slice(&test_result.to_be_bytes());
    out
}

fn restricted_capability_parameters(property: u32, property_count: u32) -> Vec<u8> {
    let count: u32 = if property_count > 0 { 1 } else { 0 };
    let property = property.max(TPM_PT_MANUFACTURER);
    let more_data = property < TPM_PT_FIRMWARE_VERSION_2;
    let value = if count > 0 {
        failure_mode_property_value(property)
    } else {
        property
    };
    let mut out = Vec::with_capacity(1 + 4 * 4);
    out.push(u8::from(more_data));
    out.extend_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&property.to_be_bytes());
    out.extend_from_slice(&value.to_be_bytes());
    out
}

fn success(parameters: Vec<u8>, buffer_size: u32) -> Result<Vec<u8>, TpmResult> {
    let response = Response::success_with_handles(TPM_ST_NO_SESSIONS, Vec::new(), parameters);
    serialize_response_within(&response, buffer_size).map_err(|_| TPM_FAIL)
}

fn bare_failure(buffer_size: u32) -> Result<Vec<u8>, TpmResult> {
    serialize_response_within(&Response::error(TPM_RC_FAILURE), buffer_size).map_err(|_| TPM_FAIL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::capability::{TPM_CAP_ALGS, TPM_CAP_COMMANDS};
    use crate::library::tpm2::command::implemented_commands;
    use crate::library::tpm2::golden_responses::get_test_result::vector;
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

    fn failed_runtime(location: FailureLocation) -> Box<Tpm2Runtime> {
        let mut runtime = empty_state_runtime();
        enter_failure_mode(&mut runtime, location);
        runtime
    }

    #[test]
    fn every_implemented_command_answers_the_bare_failure_response() {
        for descriptor in implemented_commands() {
            let mut runtime = failed_runtime(FailureLocation::NvCommit);
            for payload in [&[][..], &[0x00][..], &[0x00; 12][..]] {
                if descriptor.code == TPM_CC_GET_TEST_RESULT && payload.is_empty() {
                    continue;
                }
                let bytes = framed(0x8001, descriptor.code, payload);
                assert_eq!(
                    process(&mut runtime, &input(&bytes)).unwrap(),
                    BARE_FAILURE,
                    "code {:#x} payload {payload:02x?}",
                    descriptor.code
                );
            }
        }
    }

    #[test]
    fn the_special_command_codes_are_identified() {
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        assert_eq!(route(&input(&bytes)), FailureModeRoute::GetTestResult);

        let bytes = get_capability(TPM_CAP_TPM_PROPERTIES, 0x0000_0100, 1);
        assert_eq!(
            route(&input(&bytes)),
            FailureModeRoute::RestrictedGetCapability {
                property: 0x100,
                property_count: 1,
            }
        );
    }

    #[test]
    fn only_the_tpm_properties_group_takes_the_restricted_capability_route() {
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
    fn the_property_and_count_fields_are_not_restricted_by_the_router() {
        for property in [0u32, 1, 0x100, 0x12e, 0x200, 0x7fff_ffff, u32::MAX] {
            for property_count in [0u32, 1, 2, 1000, 0x8000_0000, u32::MAX] {
                assert_eq!(
                    route(&input(&get_capability(
                        TPM_CAP_TPM_PROPERTIES,
                        property,
                        property_count
                    ))),
                    FailureModeRoute::RestrictedGetCapability {
                        property,
                        property_count,
                    },
                    "property {property:#x} count {property_count:#x}"
                );
            }
        }
    }

    #[test]
    fn a_capability_request_of_the_wrong_declared_length_is_a_bare_failure() {
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
    fn session_tagged_and_undersized_requests_fall_back_to_bare_failure() {
        for tag in [0x8002u16, 0x0000, 0xffff] {
            let bytes = framed(tag, TPM_CC_GET_TEST_RESULT, &[]);
            assert_eq!(route(&input(&bytes)), FailureModeRoute::BareFailure);
        }
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[0x00]);
        assert_eq!(
            route(&input(&bytes)),
            FailureModeRoute::BareFailure,
            "a declared size of eleven is not the special request"
        );
        let bytes = framed(0x8001, TPM_CC_GET_CAPABILITY, &[0x00; 8]);
        assert_eq!(route(&input(&bytes)), FailureModeRoute::BareFailure);
    }

    #[test]
    fn undeclared_trailing_bytes_are_ignored_like_the_c_boundary() {
        let mut bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        bytes.extend_from_slice(&[0x00; 4]);
        assert_eq!(route(&input(&bytes)), FailureModeRoute::GetTestResult);

        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_GTR_TRAILING_UNDECLARED")
        );

        let mut bytes = get_capability(TPM_CAP_TPM_PROPERTIES, 0x105, 1);
        bytes.extend_from_slice(&[0x00; 4]);
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_CAP_TRAILING_UNDECLARED")
        );
    }

    #[test]
    fn a_declared_size_beyond_the_received_bytes_is_a_bare_failure() {
        let mut bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        bytes[5] = 0x0b;
        assert_eq!(route(&input(&bytes[..10])), FailureModeRoute::BareFailure);
        let capability = get_capability(TPM_CAP_TPM_PROPERTIES, 0x105, 1);
        assert_eq!(
            route(&input(&capability[..18])),
            FailureModeRoute::BareFailure,
            "the twelve parameter bytes must actually arrive"
        );
    }

    #[test]
    fn an_oversized_declared_size_never_drives_an_allocation() {
        let mut bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        bytes[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
        let command = CommandInput::new(u32::MAX, bytes[..6].to_vec());
        assert_eq!(route(&command), FailureModeRoute::BareFailure);
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        assert_eq!(process(&mut runtime, &command).unwrap(), BARE_FAILURE);
    }

    #[test]
    fn get_test_result_reports_the_nv_commit_diagnostics() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_GTR_OK"),
            "the oracle entered failure mode through the very same NvCommit path"
        );
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_GTR_REPEAT"),
            "a repeated query answers identically"
        );
        assert!(
            runtime.failure_mode,
            "the query must not leave failure mode"
        );
    }

    #[test]
    fn the_nv_unrecoverable_code_answers_nv_uninitialized() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        runtime.failure_diagnostics.code = FATAL_ERROR_NV_UNRECOVERABLE;
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_GTR_NV_UNRECOVERABLE")
        );
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_GTR_NV_UNRECOVERABLE_REPEAT")
        );
    }

    #[test]
    fn every_other_fatal_code_answers_plain_failure() {
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        for code in [0u32, 1, 2, 3, 4, 5, 6, 7, 9, 500, 600, 1000, u32::MAX] {
            let mut runtime = failed_runtime(FailureLocation::NvCommit);
            runtime.failure_diagnostics.code = code;
            let response = process(&mut runtime, &input(&bytes)).unwrap();
            assert_eq!(response.len(), 28, "code {code}");
            assert_eq!(&response[20..24], &code.to_be_bytes(), "code {code}");
            assert_eq!(
                &response[24..],
                &TPM_RC_FAILURE.to_be_bytes(),
                "code {code}"
            );
        }
    }

    #[test]
    fn the_diagnostic_fields_encode_big_endian_after_the_twelve_byte_size() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        runtime.failure_diagnostics = FailureDiagnostics {
            function: 0x0102_0304,
            line: 0x0506_0708,
            code: 0x090a_0b0c,
        };
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            [
                0x80, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x01, 0x02,
                0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x00, 0x01, 0x01
            ]
        );
    }

    #[test]
    fn the_restricted_capability_matrix_matches_the_oracle() {
        let cases: [(&str, u32, u32); 19] = [
            ("FM_CAP_PT000_C1", 0x000, 1),
            ("FM_CAP_PT104_C1", 0x104, 1),
            ("FM_CAP_PT105_C1", 0x105, 1),
            ("FM_CAP_PT106_C1", 0x106, 1),
            ("FM_CAP_PT107_C1", 0x107, 1),
            ("FM_CAP_PT108_C1", 0x108, 1),
            ("FM_CAP_PT109_C1", 0x109, 1),
            ("FM_CAP_PT10A_C1", 0x10a, 1),
            ("FM_CAP_PT10B_C1", 0x10b, 1),
            ("FM_CAP_PT10C_C1", 0x10c, 1),
            ("FM_CAP_PT10D_C1", 0x10d, 1),
            ("FM_CAP_PT200_C1", 0x200, 1),
            ("FM_CAP_PTMAX_C1", u32::MAX, 1),
            ("FM_CAP_PT000_C0", 0x000, 0),
            ("FM_CAP_PT105_C0", 0x105, 0),
            ("FM_CAP_PT10C_C0", 0x10c, 0),
            ("FM_CAP_PT10D_C0", 0x10d, 0),
            ("FM_CAP_PT105_C2", 0x105, 2),
            ("FM_CAP_PT105_CMAX", 0x105, u32::MAX),
        ];
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        for (name, property, count) in cases {
            let bytes = get_capability(TPM_CAP_TPM_PROPERTIES, property, count);
            assert_eq!(
                process(&mut runtime, &input(&bytes)).unwrap(),
                vector(name),
                "{name}"
            );
        }
    }

    #[test]
    fn the_more_data_byte_tracks_only_the_clamped_property() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        for (property, count, more_data) in [
            (0u32, 1u32, 1u8),
            (0x10b, 1, 1),
            (0x10b, 0, 1),
            (0x10c, 1, 0),
            (0x10c, 0, 0),
            (0x10d, 1, 0),
            (u32::MAX, 1, 0),
        ] {
            let bytes = get_capability(TPM_CAP_TPM_PROPERTIES, property, count);
            let response = process(&mut runtime, &input(&bytes)).unwrap();
            assert_eq!(
                response[10], more_data,
                "property {property:#x} count {count}"
            );
        }
    }

    #[test]
    fn malformed_capability_variants_stay_bare_failures_like_the_oracle() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        for name in [
            "FM_CAP_ALGS",
            "FM_CAP_HANDLES",
            "FM_CAP_COMMANDS",
            "FM_CAP_CAPMAX",
            "FM_CAP_SESSIONS",
            "FM_GTR_SESSIONS",
            "FM_GTR_DECLARED_11",
            "FM_GTR_TRUNC9",
            "FM_STARTUP",
            "FM_UNKNOWN",
            "FM_GETRANDOM",
        ] {
            assert_eq!(vector(name), BARE_FAILURE, "{name}");
        }
        for (bytes, label) in [
            (get_capability(TPM_CAP_ALGS, 0x105, 1), "algs"),
            (get_capability(1, 0x105, 1), "handles"),
            (get_capability(TPM_CAP_COMMANDS, 0x105, 1), "commands"),
            (get_capability(u32::MAX, 0x105, 1), "capmax"),
            (
                framed(0x8001, TPM_CC_GET_TEST_RESULT, &[0x00]),
                "declared 11",
            ),
            (framed(0x8002, TPM_CC_GET_TEST_RESULT, &[]), "sessions"),
            (framed(0x8001, 0x2000_0000, &[]), "unknown"),
            (framed(0x8001, 0x0000_017b, &[0x00, 0x08]), "get random"),
        ] {
            assert_eq!(
                process(&mut runtime, &input(&bytes)).unwrap(),
                BARE_FAILURE,
                "{label}"
            );
        }
        let mut session = get_capability(TPM_CAP_TPM_PROPERTIES, 0x105, 1);
        session[..2].copy_from_slice(&0x8002u16.to_be_bytes());
        assert_eq!(
            process(&mut runtime, &input(&session)).unwrap(),
            BARE_FAILURE
        );
    }

    #[test]
    fn failure_mode_queries_do_not_mutate_the_runtime() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        let diagnostics = runtime.failure_diagnostics;
        let nv_before = runtime.nv_memory.clone();
        for bytes in [
            framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]),
            get_capability(TPM_CAP_TPM_PROPERTIES, 0x105, 1),
            get_capability(TPM_CAP_TPM_PROPERTIES, 0x10d, 0),
            framed(0x8001, 0x2000_0000, &[]),
        ] {
            let _ = process(&mut runtime, &input(&bytes)).unwrap();
            assert!(runtime.failure_mode);
            assert_eq!(runtime.failure_diagnostics, diagnostics);
            assert!(!runtime.nv_update_pending);
            assert_eq!(runtime.nv_memory, nv_before);
            assert!(runtime.live.orderly.drbg_state.seed.as_bytes().is_empty());
        }
    }

    #[test]
    fn the_oracle_volatile_record_restores_the_diagnostics() {
        use crate::library::tpm2::{
            attach_volatile_blob_for_test, restore_permanent_blob_for_test,
        };

        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_FAILURE_ENTRY"))
            .expect("the oracle permanent state restores");
        assert_eq!(
            attach_volatile_blob_for_test(&mut runtime, vector("VOLATILE_FAILURE_ENTRY")),
            Err(TPM_RC_FAILURE),
            "a failure-mode volatile restore reports the failure like TPM2_MainInit (257)"
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::NvCommit.diagnostics(),
            "the C-recorded diagnostics survive the restore"
        );
        let bytes = framed(0x8001, TPM_CC_GET_TEST_RESULT, &[]);
        assert_eq!(
            process(&mut runtime, &input(&bytes)).unwrap(),
            vector("FM_GTR_AFTER_RESTORE")
        );
        let capability = get_capability(TPM_CAP_TPM_PROPERTIES, 0x105, 1);
        assert_eq!(
            process(&mut runtime, &input(&capability)).unwrap(),
            vector("FM_CAP_AFTER_RESTORE")
        );
    }

    #[test]
    fn the_after_queries_volatile_record_carries_identical_diagnostics() {
        use crate::library::tpm2::{
            attach_volatile_blob_for_test, restore_permanent_blob_for_test,
        };

        let mut before = restore_permanent_blob_for_test(vector("PERMALL_FAILURE_ENTRY"))
            .expect("the oracle permanent state restores");
        let _ = attach_volatile_blob_for_test(&mut before, vector("VOLATILE_FAILURE_ENTRY"));
        let mut after = restore_permanent_blob_for_test(vector("PERMALL_AFTER_QUERIES"))
            .expect("the oracle permanent state restores");
        let _ = attach_volatile_blob_for_test(&mut after, vector("VOLATILE_AFTER_QUERIES"));
        assert!(before.failure_mode && after.failure_mode);
        assert_eq!(
            before.failure_diagnostics, after.failure_diagnostics,
            "the failure-mode queries left the recorded diagnostics untouched"
        );
        assert_eq!(
            vector("PERMALL_FAILURE_ENTRY"),
            vector("PERMALL_AFTER_QUERIES"),
            "the queries never reached the permanent state"
        );
    }

    #[test]
    fn truncated_and_malformed_requests_never_panic() {
        let valid = get_capability(TPM_CAP_TPM_PROPERTIES, 0x0000_0100, 1);
        for length in 0..=valid.len() {
            let truncated = &valid[..length];
            let expected = if length == valid.len() {
                FailureModeRoute::RestrictedGetCapability {
                    property: 0x100,
                    property_count: 1,
                }
            } else {
                FailureModeRoute::BareFailure
            };
            assert_eq!(route(&input(truncated)), expected, "length {length}");
            for index in 0..length {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = truncated.to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = failed_runtime(FailureLocation::NvCommit);
                    let _ = process(&mut runtime, &input(&mutated)).unwrap();
                    assert!(runtime.failure_mode);
                }
            }
        }
    }

    #[test]
    fn an_empty_request_is_a_bare_failure() {
        let mut runtime = failed_runtime(FailureLocation::NvCommit);
        assert_eq!(route(&input(&[])), FailureModeRoute::BareFailure);
        assert_eq!(process(&mut runtime, &input(&[])).unwrap(), BARE_FAILURE);
    }

    mod locations {
        use super::*;

        const FAILURE_LOCATIONS: &str = include_str!("testdata/failure_locations.txt");

        fn records() -> Vec<(String, u32, String, String)> {
            FAILURE_LOCATIONS
                .lines()
                .filter(|line| !line.starts_with('#') && !line.is_empty())
                .map(|line| {
                    let mut fields = line.split('\t');
                    let mut next = |what: &str| {
                        fields
                            .next()
                            .unwrap_or_else(|| panic!("every record carries a {what}"))
                            .to_owned()
                    };
                    let record = (
                        next("file"),
                        next("line").parse().expect("a decimal line number"),
                        next("function"),
                        next("form"),
                    );
                    assert_eq!(fields.next(), None, "records have exactly four fields");
                    record
                })
                .collect()
        }

        fn fatal_error_code(form: &str) -> u32 {
            if form == "SELF_TEST_FAILURE" {
                return FATAL_ERROR_SELF_TEST;
            }
            let arguments = form
                .split_once('(')
                .and_then(|(_, rest)| rest.split_once(')'))
                .map(|(inside, _)| inside)
                .unwrap_or_else(|| panic!("{form} carries no fatal error code"));
            match arguments.split(',').next().map(str::trim) {
                Some("FATAL_ERROR_INTERNAL") => FATAL_ERROR_INTERNAL,
                Some("FATAL_ERROR_ENTROPY") => FATAL_ERROR_ENTROPY,
                Some("FATAL_ERROR_SELF_TEST") => FATAL_ERROR_SELF_TEST,
                other => panic!("unexpected fatal error code {other:?}"),
            }
        }

        fn diagnostics_for(function: &str, line: u32, form: &str) -> FailureDiagnostics {
            let word: [u8; 4] = function.as_bytes()[..4].try_into().expect("four bytes");
            FailureDiagnostics {
                function: u32::from_le_bytes(word),
                line,
                code: fatal_error_code(form),
            }
        }

        fn vendored_site(location: FailureLocation) -> (&'static str, u32) {
            match location {
                FailureLocation::NvCommit => ("ExecuteCommand", 318),
                FailureLocation::HashSelfTest => ("TestHash", 155),
                FailureLocation::SymmetricSelfTest => ("TestSymmetricAlgorithm", 259),
                FailureLocation::RsaOaepEncrypt => ("TestRsaEncryptDecrypt", 491),
                FailureLocation::RsaOaepRoundTripDecrypt => ("TestRsaEncryptDecrypt", 497),
                FailureLocation::RsaOaepRoundTripCompare => ("TestRsaEncryptDecrypt", 502),
                FailureLocation::RsaOaepKnownAnswerDecrypt => ("TestRsaEncryptDecrypt", 508),
                FailureLocation::RsaOaepKnownAnswerCompare => ("TestRsaEncryptDecrypt", 512),
                FailureLocation::DrbgInvalidState => ("DRBG_Generate", 940),
                FailureLocation::DrbgEntropy => ("EncryptDRBG", 387),
            }
        }

        #[test]
        fn every_mapped_location_matches_a_pinned_vendored_fail_site() {
            let records = records();
            let find = |function: &str, line: u32| {
                records
                    .iter()
                    .find(|(_, l, f, _)| f == function && *l == line)
                    .unwrap_or_else(|| {
                        panic!(
                            "{function}:{line} is no longer a vendored FAIL site; \
                             rerun scripts/generate_failure_locations_fixture.py and \
                             re-derive the FailureLocation mapping"
                        )
                    })
                    .clone()
            };
            for (index, location) in FailureLocation::ALL.into_iter().enumerate() {
                assert_eq!(
                    location.position(),
                    index,
                    "{location:?} is missing from FailureLocation::ALL"
                );
                let (function, line) = vendored_site(location);
                let (_, _, _, form) = find(function, line);
                assert_eq!(
                    location.diagnostics(),
                    diagnostics_for(function, line, &form),
                    "{function}:{line}"
                );
            }
        }

        #[test]
        fn the_symmetric_site_is_the_encrypt_comparison() {
            let first = records()
                .into_iter()
                .filter(|(_, _, f, _)| f == "TestSymmetricAlgorithm")
                .map(|(_, line, _, _)| line)
                .min()
                .expect("the symmetric test sites are pinned");
            assert_eq!(first, 259);
        }

        #[test]
        fn the_oracle_wire_bytes_agree_with_the_nv_commit_mapping() {
            let response = vector("FM_GTR_OK");
            let diagnostics = FailureLocation::NvCommit.diagnostics();
            assert_eq!(&response[12..16], &diagnostics.function.to_be_bytes());
            assert_eq!(&response[16..20], &diagnostics.line.to_be_bytes());
            assert_eq!(&response[20..24], &diagnostics.code.to_be_bytes());
        }
    }
}
