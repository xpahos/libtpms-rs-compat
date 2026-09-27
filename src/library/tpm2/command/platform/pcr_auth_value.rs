use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE, TPM_RC_VALUE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_P};
use crate::library::tpm2::command::core::transaction::with_rollback;
use crate::library::tpm2::entity::strip_trailing_zeros;
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::pcr::pcr_auth_value_group;
use crate::library::tpm2::persistent::OwnedSecret;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;

const RC_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;
const MAX_DIGEST_SIZE: usize = 64;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let pcr_handle = handle_at(frame, 0)?;
    let auth = parse_auth(frame.parameters)?;
    let Some(group) = pcr_auth_value_group(pcr_handle as usize) else {
        return Err(TPM_RC_VALUE);
    };
    let orderly_state = prepare_clear_orderly(runtime)?;
    let auth = strip_trailing_zeros(auth).to_vec();
    with_rollback(runtime, |runtime| {
        let slot = runtime
            .live
            .state_clear
            .as_mut()
            .ok_or(TPM_RC_FAILURE)?
            .pcr_auth_values
            .get_mut(group)
            .ok_or(TPM_RC_FAILURE)?;
        *slot = OwnedSecret::from_vec(auth);
        commit_clear_orderly(runtime, orderly_state)
    })?;
    Ok(CommandOutput::empty())
}

fn parse_auth(parameters: &[u8]) -> Result<&[u8], TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let auth = reader
        .read_tpm2b(MAX_DIGEST_SIZE)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_AUTH,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_AUTH,
        })?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(auth)
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::core::registry::TPM_CC_PCR_SET_AUTH_VALUE;
    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, command, for_each_mutation, framed, prefix_bit_flips,
        response_code,
    };
    use crate::library::tpm2::command::platform::test_support::{
        DIGEST32, RC_AUTH_MISSING, RC_INITIALIZE, RC_INSUFFICIENT_H1, RC_INSUFFICIENT_P1,
        RC_SESSION1_BAD_AUTH, RC_SIZE, RC_SIZE_P1, RC_VALUE, RC_VALUE_H1, TPM_CC_PCR_EXTEND,
        TPM_CC_PCR_READ, TPM_RH_NULL, TPM_RH_PLATFORM, assert_matches_permall, assert_unchanged,
        exec, expect, manufactured, pcr_set_auth_value, ready, replay_clock, snapshot,
    };
    use crate::library::tpm2::entity::strip_trailing_zeros;
    use crate::library::tpm2::golden_responses::platform_state::vector;
    use crate::library::tpm2::pcr::pcr_auth_value_group;
    use crate::library::tpm2::volatile::IMPLEMENTATION_PCR;

    const DIGEST64: [u8; 64] = {
        let mut out = [0u8; 64];
        let mut index = 0;
        while index < 64 {
            out[index] = index as u8;
            index += 1;
        }
        out
    };

    #[test]
    fn unstarted_tpm_rejection() {
        let clock = replay_clock();
        let mut runtime = manufactured(&clock);
        assert_scenario_response(
            "TPM2_PCR_SetAuthValue before TPM2_Startup: platform-state LIFECYCLE_PCR_SET_AUTH_VALUE",
            vector("LIFECYCLE_PCR_SET_AUTH_VALUE"),
            || {
                exec(
                    &mut runtime,
                    &clock,
                    &pcr_set_auth_value(20, &DIGEST32, &[]),
                )
            },
        );
        assert_eq!(
            response_code(vector("LIFECYCLE_PCR_SET_AUTH_VALUE")),
            RC_INITIALIZE,
            "platform-state LIFECYCLE_PCR_SET_AUTH_VALUE"
        );
    }

    #[test]
    fn implemented_pcr_authorization_group_absence() {
        for pcr in 0..IMPLEMENTATION_PCR {
            assert_eq!(
                pcr_auth_value_group(pcr),
                None,
                "the vendored platform table puts PCR {pcr} in group zero"
            );
        }
    }

    #[test]
    fn full_pcr_range_rejection_reference_match() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        let before = snapshot(&runtime);
        for pcr in [0u32, 1, 16, 17, 19, 20, 21, 22, 23] {
            let label = format!("PSAV_PCR_{pcr:02}");
            expect(
                &mut runtime,
                &clock,
                &label,
                &pcr_set_auth_value(pcr, &DIGEST32, &[]),
            );
            assert_eq!(
                response_code(vector(&label)),
                RC_VALUE,
                "the reference answers a bare TPM_RC_VALUE"
            );
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn auth_value_shape_reference_match() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("PSAV_EMPTY_AUTH", pcr_set_auth_value(20, &[], &[])),
            ("PSAV_MAX_AUTH", pcr_set_auth_value(20, &DIGEST64, &[])),
            (
                "PSAV_OVERSIZED_AUTH",
                pcr_set_auth_value(20, &[&DIGEST64[..], &[0x40][..]].concat(), &[]),
            ),
            (
                "PSAV_TRAILING_ZEROS",
                pcr_set_auth_value(20, &[0x01, 0x02, 0x00, 0x00], &[]),
            ),
            (
                "PSAV_ALL_ZEROS",
                pcr_set_auth_value(20, &[0x00, 0x00, 0x00, 0x00], &[]),
            ),
            (
                "PSAV_TRUNCATED_AUTH",
                command(
                    TPM_CC_PCR_SET_AUTH_VALUE,
                    &[20],
                    &[&[]],
                    &[0x00, 0x08, 0x01, 0x02],
                ),
            ),
            (
                "PSAV_MISSING_AUTH",
                command(TPM_CC_PCR_SET_AUTH_VALUE, &[20], &[&[]], &[]),
            ),
            (
                "PSAV_TRAILING",
                command(
                    TPM_CC_PCR_SET_AUTH_VALUE,
                    &[20],
                    &[&[]],
                    &[0x00, 0x00, 0xee],
                ),
            ),
            (
                "PSAV_WRONG_PASSWORD",
                pcr_set_auth_value(20, &DIGEST32, b"wrong"),
            ),
            (
                "PSAV_NO_SESSIONS",
                framed(
                    TPM_CC_PCR_SET_AUTH_VALUE,
                    &[
                        &20u32.to_be_bytes()[..],
                        &(DIGEST32.len() as u16).to_be_bytes()[..],
                        &DIGEST32[..],
                    ]
                    .concat(),
                    false,
                ),
            ),
            (
                "PSAV_TRUNCATED_HANDLE",
                framed(TPM_CC_PCR_SET_AUTH_VALUE, &20u32.to_be_bytes()[..2], true),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
        }
        assert_unchanged(&runtime, &before);

        for (label, code) in [
            ("PSAV_EMPTY_AUTH", RC_VALUE),
            ("PSAV_MAX_AUTH", RC_VALUE),
            ("PSAV_OVERSIZED_AUTH", RC_SIZE_P1),
            ("PSAV_TRAILING_ZEROS", RC_VALUE),
            ("PSAV_ALL_ZEROS", RC_VALUE),
            ("PSAV_TRUNCATED_AUTH", RC_INSUFFICIENT_P1),
            ("PSAV_MISSING_AUTH", RC_INSUFFICIENT_P1),
            ("PSAV_TRAILING", RC_SIZE),
            ("PSAV_WRONG_PASSWORD", RC_SESSION1_BAD_AUTH),
            ("PSAV_NO_SESSIONS", RC_AUTH_MISSING),
            ("PSAV_TRUNCATED_HANDLE", RC_INSUFFICIENT_H1),
        ] {
            assert_eq!(response_code(vector(label)), code, "{label}");
        }
    }

    #[test]
    fn out_of_range_handle_interface_rejection() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        let before = snapshot(&runtime);
        for (label, bytes) in [
            ("PSAV_PCR_24", pcr_set_auth_value(24, &DIGEST32, &[])),
            (
                "PSAV_NULL_HANDLE",
                pcr_set_auth_value(TPM_RH_NULL, &DIGEST32, &[]),
            ),
            (
                "PSAV_PLATFORM_HANDLE",
                pcr_set_auth_value(TPM_RH_PLATFORM, &DIGEST32, &[]),
            ),
        ] {
            expect(&mut runtime, &clock, label, &bytes);
            assert_eq!(response_code(vector(label)), RC_VALUE_H1, "{label}");
        }
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn rejected_command_bank_locality_unchanged() {
        let clock = replay_clock();
        let mut runtime = ready(&clock);
        expect(
            &mut runtime,
            &clock,
            "PSAV_PCR_READ_AFTER",
            &framed(
                TPM_CC_PCR_READ,
                &[
                    &1u32.to_be_bytes()[..],
                    &0x000bu16.to_be_bytes()[..],
                    &[0x03, 0x03, 0x00, 0x00][..],
                ]
                .concat(),
                false,
            ),
        );
        expect(
            &mut runtime,
            &clock,
            "PSAV_EXTEND_PCR_20",
            &command(
                TPM_CC_PCR_EXTEND,
                &[20],
                &[&[]],
                &[
                    &1u32.to_be_bytes()[..],
                    &0x000bu16.to_be_bytes()[..],
                    &DIGEST32[..],
                ]
                .concat(),
            ),
        );
        assert_matches_permall(&runtime, "AFTER_PCR_SET_AUTH_VALUE");
    }

    #[test]
    fn group_auth_value_trailing_zero_trim() {
        let clock = replay_clock();
        let runtime = ready(&clock);
        let stored = runtime
            .live
            .state_clear
            .as_ref()
            .expect("a started runtime")
            .pcr_auth_values[0]
            .as_bytes()
            .to_vec();
        assert!(stored.is_empty(), "no group has an authorization value yet");
        assert_eq!(
            strip_trailing_zeros(&[0x01, 0x02, 0x00, 0x00]),
            [0x01, 0x02]
        );
        assert_eq!(strip_trailing_zeros(&[0x00, 0x00]), [] as [u8; 0]);
        assert_eq!(strip_trailing_zeros(&DIGEST32), DIGEST32);
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = replay_clock();
        let valid = pcr_set_auth_value(20, &DIGEST32, &[]);
        for_each_mutation(
            "TPM2_PCR_SetAuthValue",
            prefix_bit_flips(&valid, 0, 0, false),
            |bytes| {
                let _ = exec(&mut ready(&clock), &clock, &bytes);
            },
        );
    }
}
