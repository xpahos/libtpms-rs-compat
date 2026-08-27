use crate::ffi_types::TpmResult;
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
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_PCR_SET_AUTH_VALUE, find,
    };
    use crate::library::tpm2::command::core::test_support::{command, framed, response_code};
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
    fn the_command_is_registered_with_the_reference_attributes() {
        let descriptor = find(TPM_CC_PCR_SET_AUTH_VALUE).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0200_0183);
        assert_eq!(
            descriptor.attributes,
            u32::from_be_bytes(
                vector("CCATTR_0183")[19..23]
                    .try_into()
                    .expect("four bytes")
            )
        );
        assert_eq!(descriptor.handles.len(), 1);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Pcr));
        assert!(descriptor.handles[0].user_auth);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert!(!descriptor.physical_presence);
        assert!(!descriptor.physical_presence_required);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "TPM2_PCR_SetAuthValue does not update NV"
        );
    }

    #[test]
    fn the_command_needs_a_started_tpm() {
        let clock = replay_clock();
        let mut runtime = manufactured(&clock);
        expect(
            &mut runtime,
            &clock,
            "LIFECYCLE_PCR_SET_AUTH_VALUE",
            &pcr_set_auth_value(20, &DIGEST32, &[]),
        );
        assert_eq!(
            response_code(vector("LIFECYCLE_PCR_SET_AUTH_VALUE")),
            RC_INITIALIZE
        );
    }

    #[test]
    fn no_implemented_pcr_belongs_to_an_authorization_group() {
        for pcr in 0..IMPLEMENTATION_PCR {
            assert_eq!(
                pcr_auth_value_group(pcr),
                None,
                "the vendored platform table puts PCR {pcr} in group zero"
            );
        }
    }

    #[test]
    fn every_pcr_is_rejected_like_the_reference() {
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
    fn the_authorization_value_shapes_match_the_reference() {
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
    fn handles_outside_the_pcr_range_are_rejected_by_the_interface() {
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
    fn the_pcr_bank_and_locality_rules_are_untouched_by_the_rejected_commands() {
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
    fn a_group_authorization_value_is_stored_without_its_trailing_zeros() {
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
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = replay_clock();
        let valid = pcr_set_auth_value(20, &DIGEST32, &[]);
        for len in 0..=valid.len() {
            for index in 0..len {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..len].to_vec();
                    mutated[index] ^= flip;
                    let mut runtime = ready(&clock);
                    let _ = exec(&mut runtime, &clock, &mutated);
                }
            }
        }
    }
}
