use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_CURVE, TPM_RC_FAILURE, TPM_RC_SIZE};

use super::super::crypto::is_compiled_curve;
use super::super::ecc::algorithm_detail;
use super::super::runtime::Tpm2Runtime;
use super::super::template::TemplateReader;
use super::dispatcher::CommandFrame;
use super::load::algorithm_policy;
use super::nv_common::{TPM_RC_1, TPM_RC_P};
use super::output::CommandOutput;

const RC_CURVE_ID: TpmResult = TPM_RC_P + TPM_RC_1;

pub(super) fn parse_curve_id(
    runtime: &Tpm2Runtime,
    reader: &mut TemplateReader<'_>,
) -> Result<u16, TpmResult> {
    let curve_id = reader.u16().map_err(|code| code + RC_CURVE_ID)?;
    let policy = algorithm_policy(runtime)?;
    if !is_compiled_curve(curve_id) || !policy.curve_allowed(curve_id) {
        return Err(TPM_RC_CURVE + RC_CURVE_ID);
    }
    Ok(curve_id)
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let mut reader = TemplateReader::new(frame.parameters);
    let curve_id = parse_curve_id(runtime, &mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    let detail = algorithm_detail(curve_id).ok_or(TPM_RC_FAILURE)?;
    Ok(CommandOutput::from_parameters(detail))
}

#[cfg(test)]
mod tests {
    use super::super::ecc_common::harness::*;
    use super::super::registry::{
        CommandLifecycle, NvAccess, TPM_CC_EC_EPHEMERAL, TPM_CC_ECC_PARAMETERS, find,
    };
    use crate::library::tpm2::ecc::algorithm_detail;

    const ALL_CURVES: [(&str, u16); 8] = [
        ("P192", 0x0001),
        ("P224", 0x0002),
        ("P256", 0x0003),
        ("P384", 0x0004),
        ("P521", 0x0005),
        ("BN256", 0x0010),
        ("BN638", 0x0011),
        ("SM2", 0x0020),
    ];

    fn parameters(curve: u16) -> Vec<u8> {
        cmd(CC_ECC_PARAMETERS, &[], None, &curve.to_be_bytes())
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = find(TPM_CC_ECC_PARAMETERS).expect("TPM2_ECC_Parameters is registered");
        assert_eq!(descriptor.attributes, 0x0000_0178);
        assert_eq!(descriptor.decrypt_size, 0);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert!(descriptor.handles.is_empty(), "no command handles");
        assert_eq!(
            find(TPM_CC_EC_EPHEMERAL).expect("registered").attributes,
            0x0000_018e
        );
    }

    #[test]
    fn every_profile_enabled_curve_answers_the_reference_detail() {
        let mut runtime = ready();
        for (name, curve) in ALL_CURVES {
            expect(&mut runtime, &format!("PARM_{name}"), &parameters(curve));
        }
    }

    #[test]
    fn the_response_parameters_are_the_marshalled_algorithm_detail() {
        let mut runtime = ready();
        for (name, curve) in ALL_CURVES {
            let response = expect(&mut runtime, &format!("PARM_{name}"), &parameters(curve));
            assert_eq!(
                response_parameters(&response),
                algorithm_detail(curve).expect("a compiled curve"),
                "curve {name}"
            );
        }
    }

    #[test]
    fn an_unusable_curve_identifier_is_a_curve_error() {
        let mut runtime = ready();
        for (record, curve) in [
            ("PARM_NONE", 0x0000u16),
            ("PARM_UNKNOWN", 0x0006),
            ("PARM_MAX", 0xffff),
        ] {
            expect(&mut runtime, record, &parameters(curve));
        }
    }

    #[test]
    fn malformed_framing_matches_the_reference() {
        let mut runtime = ready();
        expect(
            &mut runtime,
            "PARM_TRUNCATED",
            &cmd(CC_ECC_PARAMETERS, &[], None, &[0x00]),
        );
        expect(
            &mut runtime,
            "PARM_MISSING",
            &cmd(CC_ECC_PARAMETERS, &[], None, &[]),
        );
        let mut trailing = CURVE_P256.to_be_bytes().to_vec();
        trailing.push(0x00);
        expect(
            &mut runtime,
            "PARM_TRAILING",
            &cmd(CC_ECC_PARAMETERS, &[], None, &trailing),
        );
    }

    #[test]
    fn a_session_on_a_handleless_command_is_refused_like_the_reference() {
        let mut runtime = ready();
        expect(
            &mut runtime,
            "PARM_WITH_SESSION",
            &cmd(
                CC_ECC_PARAMETERS,
                &[],
                Some(&pw(&[])),
                &CURVE_P256.to_be_bytes(),
            ),
        );
        expect(
            &mut runtime,
            "PARM_SESSION_TAG_NO_AREA",
            &framed(0x8002, CC_ECC_PARAMETERS, &CURVE_P256.to_be_bytes()),
        );
    }

    #[test]
    fn a_curve_query_leaves_the_tpm_state_alone() {
        let mut runtime = ready();
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let nv_before = runtime.nv_memory.clone();
        for (_, curve) in ALL_CURVES {
            dispatch_bytes(&mut runtime, &parameters(curve));
        }
        dispatch_bytes(&mut runtime, &parameters(0x0006));
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the state serializes"),
            before
        );
        assert_eq!(runtime.nv_memory, nv_before);
        assert!(!runtime.nv_update_pending);
    }
}
