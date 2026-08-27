use super::builder::{
    Attested, check_signing_object, fill_in_attest_info, parse_qualifying_data, parse_scheme,
    sign_and_respond,
};
use crate::ffi::types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_NV_RANGE, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_P,
};
use crate::library::tpm2::command::crypto::signing_state::{RC_SIGN_HANDLE, signing_object};
use crate::library::tpm2::command::nv::access::{MAX_NV_BUFFER_SIZE, read_access_checks, resolve};
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::nv::{nv_index_name, read_index_data};
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::signature::{SigScheme, select_sign_scheme};
use crate::library::tpm2::template::TemplateReader;

const RC_QUALIFYING_DATA: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_SIZE_PARAM: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_OFFSET_PARAM: TpmResult = TPM_RC_P + TPM_RC_4;

struct Parameters {
    qualifying_data: Vec<u8>,
    scheme: SigScheme,
    size: u16,
    offset: u16,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let sign_handle = handle_at(frame, 0)?;
    let auth_handle = handle_at(frame, 1)?;
    let nv_handle = handle_at(frame, 2)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    let sign_object = signing_object(runtime, sign_handle)?;
    check_signing_object(sign_object.as_deref(), RC_SIGN_HANDLE)?;
    let scheme = select_sign_scheme(sign_object.as_deref(), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    let resolved = resolve(runtime, nv_handle)?;
    read_access_checks(auth_handle, nv_handle, resolved.attributes())?;

    let data_size = u32::from(resolved.public.data_size);
    if u32::from(parameters.size) + u32::from(parameters.offset) > data_size {
        return Err(TPM_RC_NV_RANGE);
    }
    if usize::from(parameters.size) > MAX_NV_BUFFER_SIZE {
        return Err(TPM_RC_VALUE + RC_SIZE_PARAM);
    }

    let index_name = nv_index_name(&resolved.public)?;
    let attested = if parameters.size != 0 || parameters.offset != 0 {
        let contents = read_index_data(
            runtime,
            &resolved,
            usize::from(parameters.offset),
            usize::from(parameters.size),
        )?;
        Attested::Nv {
            index_name,
            offset: parameters.offset,
            contents,
        }
    } else {
        let mut hasher = Hasher::new(scheme.hash_alg).ok_or(TPM_RC_HASH)?;
        hasher.update(&read_index_data(
            runtime,
            &resolved,
            0,
            usize::from(resolved.public.data_size),
        )?);
        Attested::NvDigest {
            index_name,
            digest: hasher.finalize(),
        }
    };

    let attest = fill_in_attest_info(
        runtime,
        sign_object.as_deref(),
        &scheme,
        &parameters.qualifying_data,
        attested,
    )?;
    sign_and_respond(runtime, sign_object.as_deref(), &scheme, &attest)
}

fn parse_parameters(
    parameters: &[u8],
    profile: &ValidatedProfile,
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let qualifying_data = parse_qualifying_data(&mut reader, RC_QUALIFYING_DATA)?;
    let scheme = parse_scheme(&mut reader, profile, RC_IN_SCHEME)?;
    let size = reader.u16().map_err(|code| code + RC_SIZE_PARAM)?;
    let offset = reader.u16().map_err(|code| code + RC_OFFSET_PARAM)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        qualifying_data,
        scheme,
        size,
        offset,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_NV_CERTIFY, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, TPM_ALG_SHA1, TPM_ALG_SHA256, command, dispatch_bytes, framed, response_code,
        response_parameters, started_runtime,
    };
    use crate::library::tpm2::command::crypto::signing_state::{
        load_signing_state, publish_signing_outcome,
    };
    use crate::library::tpm2::command::nv::test_support::{
        assert_matches_oracle, assert_matches_oracle_except, assert_unchanged, nv_public, snapshot,
    };
    use crate::library::tpm2::golden_responses::nv::certify_vector;
    use crate::library::tpm2::hierarchy::{
        TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    };
    use crate::library::tpm2::nv::{
        NvPublic, TPMA_NV_AUTHREAD, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE, TPMA_NV_READ_STCLEAR,
        marshal_sized_nv_public,
    };
    use crate::library::tpm2::object_create::occupied_object_slot;
    use crate::library::tpm2::persistent::OwnedSecret;
    use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
    use crate::library::tpm2::restore_permanent_blob_for_test;
    use crate::library::tpm2::state::COMMIT_ARRAY_SIZE;

    const RC_SIZE: u32 = 0x095;
    const RC_HANDLE1_KEY: u32 = 0x19c;
    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE3_HANDLE: u32 = 0x38b;
    const RC_PARAM2_SCHEME: u32 = 0x2d2;
    const RC_PARAM3_VALUE: u32 = 0x3c4;
    const RC_NV_RANGE: u32 = 0x146;
    const RC_NV_LOCKED: u32 = 0x148;
    const RC_NV_AUTHORIZATION: u32 = 0x149;
    const RC_NV_UNINITIALIZED: u32 = 0x14a;
    const RC_AUTH_MISSING: u32 = 0x125;

    const INDEX: u32 = 0x0100_0001;

    const TPM_ALG_RSASSA: u16 = 0x0014;
    const TPM_ALG_RSAPSS: u16 = 0x0016;
    const SIGN_KEY_ATTRS: u32 = 0x0004_0072;
    const DECRYPT_KEY_ATTRS: u32 = 0x0002_0072;

    fn all_algorithms() -> String {
        String::from_utf8(crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE.to_vec())
            .expect("an ascii algorithm list")
    }

    fn without(algorithm: &str) -> String {
        all_algorithms()
            .split(',')
            .filter(|token| *token != algorithm)
            .collect::<Vec<_>>()
            .join(",")
    }

    #[track_caller]
    fn profile_runtime(algorithms: &str, attributes: &str) -> Box<Tpm2Runtime> {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let json = format!(
            r#"{{"Name":"custom","Algorithms":"{algorithms}","Attributes":"{attributes}"}}"#
        );
        let profile =
            validate_user_profile(Some(json.as_bytes())).expect("the custom profile validates");
        let state = manufacture_state(profile, |buffer| {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x55;
            }
            Ok(())
        })
        .expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );
        mark_da_cycle_used(&mut runtime);
        runtime.nv_update_pending = false;
        runtime
    }

    fn rsa_template(scheme: u16, scheme_hash: u16, attributes: u32) -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme != 0x0010 {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
        }
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    #[track_caller]
    fn create_primary(
        runtime: &mut Tpm2Runtime,
        hierarchy: u32,
        template: &[u8],
    ) -> (u32, Vec<u8>) {
        let mut parameters = 4u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&(template.len() as u16).to_be_bytes());
        parameters.extend_from_slice(template);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        parameters.extend_from_slice(&0u32.to_be_bytes());
        let response = dispatch_bytes(
            runtime,
            &command(0x0000_0131, &[hierarchy], &[&[]], &parameters),
        );
        assert_eq!(
            response_code(&response),
            RC_SUCCESS,
            "the primary is created"
        );
        let handle = u32::from_be_bytes(response[10..14].try_into().expect("a response handle"));
        (handle, response)
    }

    #[track_caller]
    fn define(runtime: &mut Tpm2Runtime, public: &NvPublic) {
        let mut parameters = 0u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&marshal_sized_nv_public(public));
        assert_eq!(
            response_code(&dispatch_bytes(
                runtime,
                &command(0x0000_012a, &[TPM_RH_OWNER], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
    }

    #[track_caller]
    fn write(runtime: &mut Tpm2Runtime, index: u32, data: &[u8]) {
        let mut parameters = (data.len() as u16).to_be_bytes().to_vec();
        parameters.extend_from_slice(data);
        parameters.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            response_code(&dispatch_bytes(
                runtime,
                &command(0x0000_0137, &[TPM_RH_OWNER, index], &[&[]], &parameters),
            )),
            RC_SUCCESS
        );
    }

    fn certify_parameters(
        qualifying: &[u8],
        scheme: u16,
        scheme_hash: u16,
        size: u16,
        offset: u16,
    ) -> Vec<u8> {
        let mut out = (qualifying.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(qualifying);
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme != 0x0010 {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
        }
        out.extend_from_slice(&size.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out
    }

    #[track_caller]
    #[allow(clippy::too_many_arguments)]
    fn certify(
        runtime: &mut Tpm2Runtime,
        sign_handle: u32,
        auth_handle: u32,
        index: u32,
        qualifying: &[u8],
        scheme: u16,
        scheme_hash: u16,
        size: u16,
        offset: u16,
    ) -> Vec<u8> {
        dispatch_bytes(
            runtime,
            &command(
                TPM_CC_NV_CERTIFY,
                &[sign_handle, auth_handle, index],
                &[&[], &[]],
                &certify_parameters(qualifying, scheme, scheme_hash, size, offset),
            ),
        )
    }

    const DATA32: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const QUALIFY: [u8; 8] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];

    #[track_caller]
    fn oracle_runtime() -> (Box<Tpm2Runtime>, u32) {
        let (runtime, endorsement, _) = oracle_runtime_with_owner(false);
        (runtime, endorsement)
    }

    #[track_caller]
    fn oracle_runtime_with_owner(with_owner: bool) -> (Box<Tpm2Runtime>, u32, u32) {
        oracle_runtime_before_da_transition(with_owner)
    }

    #[track_caller]
    fn oracle_runtime_before_da_transition(with_owner: bool) -> (Box<Tpm2Runtime>, u32, u32) {
        let mut runtime = restore_permanent_blob_for_test(&certify_vector("PERMALL_BASE"))
            .expect("the oracle permanent state restores");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x0000_0144, &[0x00, 0x00], false)
            )),
            RC_SUCCESS
        );
        let (endorsement, response) = create_primary(
            &mut runtime,
            TPM_RH_ENDORSEMENT,
            &rsa_template(TPM_ALG_RSASSA, TPM_ALG_SHA256, SIGN_KEY_ATTRS),
        );
        assert_eq!(
            response,
            certify_vector("CREATE_ENDORSEMENT_SIGNER"),
            "the endorsement signing key matches the oracle byte for byte"
        );
        let owner = if with_owner {
            let (owner, response) = create_primary(
                &mut runtime,
                TPM_RH_OWNER,
                &rsa_template(TPM_ALG_RSASSA, TPM_ALG_SHA256, SIGN_KEY_ATTRS),
            );
            assert_eq!(response, certify_vector("CREATE_OWNER_SIGNER"));
            owner
        } else {
            0
        };

        define(
            &mut runtime,
            &nv_public(
                INDEX,
                TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | TPMA_NV_AUTHREAD | TPMA_NV_READ_STCLEAR,
                32,
            ),
        );
        write(&mut runtime, INDEX, &DATA32);
        (runtime, endorsement, owner)
    }

    fn mark_da_cycle_used(runtime: &mut Tpm2Runtime) {
        use crate::library::tpm2::dictionary_attack::record_da_used;
        record_da_used(runtime).expect(
            "the certify fixtures expect the post-transition DA state, so the \
             test support performs that production transition before replaying them",
        );
    }

    fn certify_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = started_runtime();
        mark_da_cycle_used(&mut runtime);
        runtime.nv_update_pending = false;
        runtime
    }

    #[test]
    fn the_test_support_enters_the_complete_post_transition_state() {
        use crate::library::tpm2::nv::build_nv_image;

        let (mut oracle, endorsement) = oracle_runtime();
        assert!(!oracle.live.da_used, "the transition has not happened yet");
        assert_eq!(
            response_code(&certify(
                &mut oracle,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_SUCCESS
        );
        assert!(oracle.live.da_used);
        assert_eq!(oracle.state().persistent.orderly_state, 0xfffe);
        assert_eq!(
            oracle.nv_memory,
            build_nv_image(oracle.state()).expect("the state serializes"),
            "the committed NV image carries the DA-used marker"
        );
    }

    struct ClockInfo {
        clock: u64,
        reset_count: u32,
        restart_count: u32,
        safe: u8,
        firmware_version: u64,
    }

    fn attest_clock_info(response: &[u8]) -> ClockInfo {
        let parameters = response_parameters(response);
        let mut offset = 2 + 4 + 2;
        let name_size = u16::from_be_bytes([parameters[offset], parameters[offset + 1]]) as usize;
        offset += 2 + name_size;
        let extra_size = u16::from_be_bytes([parameters[offset], parameters[offset + 1]]) as usize;
        offset += 2 + extra_size;
        let word =
            |at: usize| u32::from_be_bytes(parameters[at..at + 4].try_into().expect("four bytes"));
        let long =
            |at: usize| u64::from_be_bytes(parameters[at..at + 8].try_into().expect("eight bytes"));
        ClockInfo {
            clock: long(offset),
            reset_count: word(offset + 8),
            restart_count: word(offset + 12),
            safe: parameters[offset + 16],
            firmware_version: long(offset + 17),
        }
    }

    #[track_caller]
    fn replay_clock(runtime: &mut Tpm2Runtime, expected: &[u8]) {
        runtime.live.orderly.clock = attest_clock_info(expected).clock;
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = certify_vector("CCATTR_0184");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        assert_eq!(TPM_CC_NV_CERTIFY, 0x0000_0184);
        let descriptor = find(TPM_CC_NV_CERTIFY).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0600_0184);
        assert_eq!(
            descriptor.attributes & (1 << 22),
            0,
            "TPM2_NV_Certify does not write NV"
        );
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!(
            (descriptor.attributes >> 25) & 0x7,
            3,
            "three command handles"
        );
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Read));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
    }

    #[test]
    fn the_handles_carry_the_upstream_roles() {
        let descriptor = find(TPM_CC_NV_CERTIFY).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 3);
        assert!(descriptor.handles[0].user_auth);
        assert!(descriptor.handles[1].user_auth);
        assert!(!descriptor.handles[2].user_auth);
        assert!(descriptor.handles.iter().all(|spec| !spec.admin_role()));
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::ObjectAllowNull
        ));
        assert!(matches!(descriptor.handles[1].kind, HandleKind::NvAuth));
        assert!(matches!(descriptor.handles[2].kind, HandleKind::NvIndex));

        let kind = descriptor.handles[0].kind;
        assert!(kind.accepts(0x8000_0000));
        assert!(kind.accepts(0x8100_0000));
        assert!(
            kind.accepts(TPM_RH_NULL),
            "signHandle unmarshals with allowNull"
        );
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT, 0x0100_0001, 0x0200_0000] {
            assert!(!kind.accepts(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn the_capability_list_advertises_nv_certify() {
        use crate::library::tpm2::capability::commands::implemented;
        let page = implemented(TPM_CC_NV_CERTIFY, 1);
        assert_eq!(page.entries, [0x0600_0184]);
        let all = implemented(0, 1000);
        assert!(all.entries.contains(&0x0600_0184));
        assert_eq!(
            all.entries.last(),
            Some(&0x0200_019c),
            "TPM2_PolicyParameters has the highest command code in the registry"
        );
    }

    #[test]
    fn direct_content_certification_matches_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_ENDORSEMENT"));
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_ENDORSEMENT")
        );
    }

    #[test]
    fn a_certified_window_matches_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_WINDOW"));
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_SUCCESS
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                8,
                4
            ),
            certify_vector("CERTIFY_NV_WINDOW")
        );
    }

    #[test]
    fn certification_without_qualifying_data_matches_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_NO_QUALIFYING"));
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &[],
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_NO_QUALIFYING")
        );
    }

    #[test]
    fn digest_certification_matches_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_DIGEST"));
        let response = certify(
            &mut runtime,
            endorsement,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            0x0010,
            0,
            0,
            0,
        );
        assert_eq!(response, certify_vector("CERTIFY_NV_DIGEST"));
        let parameters = response_parameters(&response);
        assert_eq!(
            &parameters[2 + 4..2 + 6],
            &[0x80, 0x1c],
            "a zero size and offset select TPM_ST_ATTEST_NV_DIGEST"
        );
    }

    #[test]
    fn digest_certification_without_qualifying_data_matches_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(
            &mut runtime,
            &certify_vector("CERTIFY_NV_DIGEST_NO_QUALIFYING"),
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &[],
                0x0010,
                0,
                0,
                0
            ),
            certify_vector("CERTIFY_NV_DIGEST_NO_QUALIFYING")
        );
    }

    #[test]
    fn a_storage_hierarchy_signer_obfuscates_the_clock_and_firmware_values() {
        let (mut runtime, endorsement, owner) = oracle_runtime_with_owner(true);
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_OWNER_SIGNER"));
        let response = certify(
            &mut runtime,
            owner,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            0x0010,
            0,
            32,
            0,
        );
        assert_eq!(response, certify_vector("CERTIFY_NV_OWNER_SIGNER"));

        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_ENDORSEMENT"));
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_ENDORSEMENT"),
            "an endorsement-hierarchy signer reports the values unmasked"
        );

        let plain = attest_clock_info(&certify_vector("CERTIFY_NV_ENDORSEMENT"));
        let masked = attest_clock_info(&response);
        assert_eq!(plain.reset_count, 1);
        assert_eq!(plain.restart_count, 0);
        assert_eq!(plain.firmware_version, 0x2024_0125_0012_0000);
        assert_ne!(
            masked.reset_count, plain.reset_count,
            "a storage-hierarchy signer masks resetCount"
        );
        assert_ne!(
            masked.restart_count, plain.restart_count,
            "a storage-hierarchy signer masks restartCount"
        );
        assert_ne!(
            masked.firmware_version, plain.firmware_version,
            "a storage-hierarchy signer masks firmwareVersion"
        );
        assert_eq!(masked.safe, plain.safe, "the safe flag is never masked");
    }

    #[test]
    fn the_index_may_authorize_its_own_certification() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_INDEX_AUTH"));
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                INDEX,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_INDEX_AUTH")
        );
    }

    #[test]
    fn an_explicit_scheme_that_matches_the_key_is_accepted() {
        let (mut runtime, endorsement) = oracle_runtime();
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_EXPLICIT_SCHEME"));
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_RSASSA,
                TPM_ALG_SHA256,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_EXPLICIT_SCHEME")
        );
    }

    #[test]
    fn a_scheme_that_disagrees_with_the_key_is_a_scheme_error() {
        let (mut runtime, endorsement) = oracle_runtime();
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_RSAPSS,
                TPM_ALG_SHA256,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_WRONG_SCHEME")
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_RSASSA,
                TPM_ALG_SHA1,
                32,
                0
            ),
            certify_vector("CERTIFY_NV_WRONG_HASH")
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_RSAPSS,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_PARAM2_SCHEME
        );
    }

    #[test]
    fn the_range_and_size_errors_match_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                0,
                33
            ),
            certify_vector("CERTIFY_OFFSET_PAST_END")
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                8,
                28
            ),
            certify_vector("CERTIFY_RANGE")
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                1025,
                0
            ),
            certify_vector("CERTIFY_SIZE_ABOVE_BUFFER")
        );
        for (size, offset) in [(0u16, 33u16), (8, 28), (1025, 0), (33, 0)] {
            assert_eq!(
                response_code(&certify(
                    &mut runtime,
                    endorsement,
                    TPM_RH_OWNER,
                    INDEX,
                    &QUALIFY,
                    0x0010,
                    0,
                    size,
                    offset
                )),
                RC_NV_RANGE,
                "size {size} offset {offset}"
            );
        }
    }

    #[test]
    fn an_oversized_size_within_a_large_index_is_a_value_error() {
        let (mut runtime, endorsement) = oracle_runtime();
        define(
            &mut runtime,
            &nv_public(0x0100_0009, TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD, 2048),
        );
        write(&mut runtime, 0x0100_0009, &[0xcc; 1024]);
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                0x0100_0009,
                &QUALIFY,
                0x0010,
                0,
                1025,
                0
            )),
            RC_PARAM3_VALUE,
            "the buffer limit is reported once the range check passes"
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                0x0100_0009,
                &QUALIFY,
                0x0010,
                0,
                1024,
                0
            )),
            RC_SUCCESS
        );
    }

    #[test]
    fn the_authorization_errors_match_the_oracle() {
        let (mut runtime, endorsement) = oracle_runtime();
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_PLATFORM,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_PLATFORM_WITHOUT_PPREAD")
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_PLATFORM,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_NV_AUTHORIZATION
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                0x0100_0002,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_UNDEFINED_INDEX")
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                0x0100_0002,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_HANDLE3_HANDLE
        );
    }

    #[test]
    fn an_uninitialized_index_cannot_be_certified() {
        let (mut runtime, endorsement) = oracle_runtime();
        define(
            &mut runtime,
            &nv_public(0x0100_0003, TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD, 32),
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                0x0100_0003,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_UNINITIALIZED")
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                0x0100_0003,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_NV_UNINITIALIZED
        );
    }

    #[test]
    fn a_read_locked_index_cannot_be_certified() {
        let (mut runtime, endorsement) = oracle_runtime();
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(0x0000_014f, &[TPM_RH_OWNER, INDEX], &[&[]], &[]),
            )),
            RC_SUCCESS
        );
        assert_eq!(
            certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_READLOCKED")
        );
        assert_eq!(
            certify(
                &mut runtime,
                TPM_RH_NULL,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            ),
            certify_vector("CERTIFY_NULL_SIGNER"),
            "the lock is reported before the null signing key is considered"
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_NV_LOCKED
        );
    }

    #[test]
    fn the_permanent_state_around_certification_matches_the_oracle() {
        let (mut runtime, endorsement, _) = oracle_runtime_before_da_transition(false);
        assert_matches_oracle(
            &runtime,
            certify_vector("PERMALL_READY"),
            "before certification",
        );
        replay_clock(&mut runtime, &certify_vector("CERTIFY_NV_ENDORSEMENT"));
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_SUCCESS,
            "the first DA-protected signer authorization records the DA-used \
             marker and proceeds, exactly as the capture's first certification did"
        );
        assert_matches_oracle_except(
            &runtime,
            certify_vector("PERMALL_AFTER_CERTIFY"),
            "after certification",
            &[],
        );
    }

    #[test]
    fn a_null_signing_key_produces_a_null_signature() {
        let (mut runtime, _) = oracle_runtime();
        let response = certify(
            &mut runtime,
            TPM_RH_NULL,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            0x0010,
            0,
            32,
            0,
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        let parameters = response_parameters(&response);
        let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        assert_eq!(
            &parameters[2 + attest_size..],
            &[0x00, 0x10],
            "a null signing key answers with a TPM_ALG_NULL signature"
        );
        assert_eq!(
            &parameters[2 + 6..2 + 12],
            &[0x00, 0x04, 0x40, 0x00, 0x00, 0x07],
            "the qualified signer of a null key is the TPM_RH_NULL handle"
        );
    }

    #[test]
    fn a_key_that_cannot_sign_is_a_key_error() {
        let mut runtime = certify_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD, 32),
        );
        write(&mut runtime, INDEX, &DATA32);
        let (decrypt, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_template(0x0010, 0, DECRYPT_KEY_ATTRS),
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                decrypt,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_RSASSA,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_HANDLE1_KEY
        );
    }

    #[test]
    fn a_key_without_a_default_scheme_needs_an_explicit_one() {
        let mut runtime = certify_runtime();
        define(
            &mut runtime,
            &nv_public(INDEX, TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD, 32),
        );
        write(&mut runtime, INDEX, &DATA32);
        let (signer, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_template(0x0010, 0, SIGN_KEY_ATTRS),
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                signer,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_PARAM2_SCHEME
        );
        for scheme in [TPM_ALG_RSASSA, TPM_ALG_RSAPSS] {
            let response = certify(
                &mut runtime,
                signer,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                scheme,
                TPM_ALG_SHA256,
                32,
                0,
            );
            assert_eq!(response_code(&response), RC_SUCCESS, "scheme {scheme:#06x}");
            let parameters = response_parameters(&response);
            let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
            assert_eq!(
                &parameters[2 + attest_size..2 + attest_size + 2],
                &scheme.to_be_bytes(),
                "the response carries the selected scheme"
            );
            assert_eq!(
                parameters.len(),
                2 + attest_size + 4 + 2 + 256,
                "an RSA-2048 signature is a 256-byte sized buffer"
            );
        }
    }

    #[test]
    fn an_rsassa_signature_verifies_against_the_public_key() {
        use crate::library::tpm2::crypto::BigUint;
        let (mut runtime, endorsement) = oracle_runtime();
        let modulus = {
            let create = certify_vector("CREATE_ENDORSEMENT_SIGNER");
            let public_size = usize::from(u16::from_be_bytes([create[18], create[19]]));
            let public_area = &create[20..20 + public_size];
            public_area[public_area.len() - 256..].to_vec()
        };
        let response = certify(
            &mut runtime,
            endorsement,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            0x0010,
            0,
            32,
            0,
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        let parameters = response_parameters(&response);
        let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let certify_info = &parameters[2..2 + attest_size];
        let signature = &parameters[2 + attest_size + 6..];
        assert_eq!(signature.len(), 256);

        let n = BigUint::from_be_bytes(&modulus);
        let e = BigUint::from_u64(65537);
        let recovered = BigUint::from_be_bytes(signature)
            .mod_exp(&e, &n)
            .expect("the public operation succeeds")
            .to_be_bytes(256)
            .expect("the recovered block fits the modulus");

        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(certify_info);
        let digest = hasher.finalize();
        assert_eq!(
            &recovered[256 - 32..],
            &digest[..],
            "the PKCS#1 v1.5 block carries the attestation digest"
        );
        assert_eq!(&recovered[..2], &[0x00, 0x01]);
    }

    const TPM_ALG_ECDSA: u16 = 0x0018;
    const TPM_ALG_ECDAA: u16 = 0x001a;
    const TPM_ALG_SM2: u16 = 0x001b;
    const TPM_ALG_ECSCHNORR: u16 = 0x001c;
    const TPM_ALG_HMAC: u16 = 0x0005;
    const TPM_ECC_NIST_P256: u16 = 0x0003;
    const TPM_ECC_SM2_P256: u16 = 0x0020;
    const RC_PARAM2_HASH: u32 = 0x2c3;
    const RC_HASH: u32 = 0x083;
    const RC_VALUE: u32 = 0x084;

    fn ecc_template(scheme: u16, scheme_hash: u16, curve_id: u16, attributes: u32) -> Vec<u8> {
        let mut out = 0x0023u16.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme != 0x0010 {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
        }
        out.extend_from_slice(&curve_id.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    fn keyedhash_template(scheme: u16, scheme_hash: u16, attributes: u32) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme != 0x0010 {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
        }
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    #[track_caller]
    fn certify_split(
        runtime: &mut Tpm2Runtime,
        sign_handle: u32,
        index: u32,
        scheme: u16,
        scheme_hash: u16,
        count: u16,
    ) -> Vec<u8> {
        let mut parameters = 0u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&scheme.to_be_bytes());
        parameters.extend_from_slice(&scheme_hash.to_be_bytes());
        parameters.extend_from_slice(&count.to_be_bytes());
        parameters.extend_from_slice(&32u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        dispatch_bytes(
            runtime,
            &command(
                TPM_CC_NV_CERTIFY,
                &[sign_handle, TPM_RH_OWNER, index],
                &[&[], &[]],
                &parameters,
            ),
        )
    }

    #[track_caller]
    fn ready_index(runtime: &mut Tpm2Runtime) {
        define(
            runtime,
            &nv_public(INDEX, TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD, 32),
        );
        write(runtime, INDEX, &DATA32);
    }

    #[track_caller]
    fn loaded_body(runtime: &Tpm2Runtime, handle: u32) -> Box<OwnedObjectBody> {
        let slot = occupied_object_slot(runtime, handle).expect("a loaded object");
        match &runtime.live.objects[slot].body {
            OwnedAnyObjectBody::Object(body) => body.clone(),
            _ => panic!("the handle names a key"),
        }
    }

    #[track_caller]
    fn ecc_signature(response: &[u8]) -> (u16, Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(response);
        let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let signature = &parameters[2 + attest_size..];
        let hash_alg = u16::from_be_bytes([signature[2], signature[3]]);
        let r_size = u16::from_be_bytes([signature[4], signature[5]]) as usize;
        let r = signature[6..6 + r_size].to_vec();
        let s_at = 6 + r_size;
        let s_size = u16::from_be_bytes([signature[s_at], signature[s_at + 1]]) as usize;
        let s = signature[s_at + 2..s_at + 2 + s_size].to_vec();
        assert_eq!(signature.len(), s_at + 2 + s_size, "the signature is exact");
        (hash_alg, r, s)
    }

    #[track_caller]
    fn attested_digest(response: &[u8], hash_alg: u16) -> Vec<u8> {
        let parameters = response_parameters(response);
        let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
        hasher.update(&parameters[2..2 + attest_size]);
        hasher.finalize()
    }

    #[test]
    fn every_ecc_scheme_reaches_the_oracle_return_code() {
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        for (scheme, hash_alg, expected) in [
            (TPM_ALG_ECDSA, TPM_ALG_SHA256, RC_SUCCESS),
            (TPM_ALG_ECDSA, TPM_ALG_SHA1, RC_SUCCESS),
            (TPM_ALG_ECDSA, 0x000c, RC_SUCCESS),
            (TPM_ALG_ECDSA, 0x000d, RC_SUCCESS),
            (TPM_ALG_ECSCHNORR, TPM_ALG_SHA256, RC_SUCCESS),
            (TPM_ALG_SM2, TPM_ALG_SHA256, RC_SUCCESS),
        ] {
            assert_eq!(
                response_code(&certify(
                    &mut runtime,
                    key,
                    TPM_RH_OWNER,
                    INDEX,
                    &QUALIFY,
                    scheme,
                    hash_alg,
                    32,
                    0
                )),
                expected,
                "scheme {scheme:#06x} hash {hash_alg:#06x}"
            );
        }
        for count in [0u16, 7] {
            assert_eq!(
                response_code(&certify_split(
                    &mut runtime,
                    key,
                    INDEX,
                    TPM_ALG_ECDAA,
                    TPM_ALG_SHA256,
                    count
                )),
                RC_VALUE,
                "ECDAA without a commitment is a value error, count {count}"
            );
        }
    }

    #[test]
    fn an_sm2_curve_key_signs_with_the_sm2_scheme() {
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_SM2_P256, SIGN_KEY_ATTRS),
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_SM2,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_SUCCESS
        );
    }

    #[test]
    fn a_keyed_hash_key_signs_with_hmac() {
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &keyedhash_template(TPM_ALG_HMAC, TPM_ALG_SHA256, SIGN_KEY_ATTRS),
        );
        let response = certify(
            &mut runtime,
            key,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            0x0010,
            0,
            32,
            0,
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        let parameters = response_parameters(&response);
        let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let signature = &parameters[2 + attest_size..];
        assert_eq!(&signature[..4], &[0x00, 0x05, 0x00, 0x0b]);
        assert_eq!(signature.len(), 4 + 32, "TPMT_HA carries a bare digest");
    }

    #[test]
    fn the_ecc_signatures_satisfy_their_signing_equations() {
        use crate::library::tpm2::crypto::{BigUint, curve_parameters};
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        let body = loaded_body(&runtime, key);
        let d = BigUint::from_be_bytes(body.sensitive.sensitive.as_ref().unwrap().as_bytes());
        let curve = curve_parameters(TPM_ECC_NIST_P256).expect("a compiled curve");
        let order = &curve.order;

        for scheme in [TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_SM2] {
            let response = certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                scheme,
                TPM_ALG_SHA256,
                32,
                0,
            );
            assert_eq!(response_code(&response), RC_SUCCESS, "{scheme:#06x}");
            let (hash_alg, r_bytes, s_bytes) = ecc_signature(&response);
            assert_eq!(hash_alg, TPM_ALG_SHA256);
            assert_eq!(r_bytes.len(), 32, "an order-sized r");
            assert_eq!(s_bytes.len(), 32, "an order-sized s");
            let r = BigUint::from_be_bytes(&r_bytes);
            let s = BigUint::from_be_bytes(&s_bytes);
            let digest = attested_digest(&response, TPM_ALG_SHA256);

            let k = match scheme {
                TPM_ALG_ECDSA => {
                    let z = BigUint::from_be_bytes(&digest).rem(order).unwrap();
                    let rd = r.mod_mul(&d, order).unwrap();
                    s.mod_inverse(order)
                        .unwrap()
                        .mod_mul(&z.mod_add(&rd, order).unwrap(), order)
                        .unwrap()
                }
                TPM_ALG_ECSCHNORR => s.mod_sub(&r.mod_mul(&d, order).unwrap(), order).unwrap(),
                _ => {
                    let one_plus_d = d.add_u64(1).rem(order).unwrap();
                    s.mod_mul(&one_plus_d, order)
                        .unwrap()
                        .mod_add(&r.mod_mul(&d, order).unwrap(), order)
                        .unwrap()
                }
            };
            let (x, _) = curve.multiply_generator(&k).expect("a valid nonce point");

            let recovered = match scheme {
                TPM_ALG_ECDSA => x.rem(order).unwrap(),
                TPM_ALG_ECSCHNORR => {
                    let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
                    hasher.update(&x.to_be_bytes(32).unwrap());
                    hasher.update(&digest);
                    BigUint::from_be_bytes(&hasher.finalize())
                }
                _ => BigUint::from_be_bytes(&digest).mod_add(&x, order).unwrap(),
            };
            assert_eq!(recovered, r, "scheme {scheme:#06x} reproduces r");
        }
    }

    #[test]
    fn a_committed_ecdaa_signature_consumes_its_commitment() {
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        {
            let reset = runtime.live.state_reset.as_mut().unwrap();
            reset.commit_nonce = OwnedSecret::copy_of(&[0x5a; 32]);
            reset.commit_counter = 1;
            reset.commit_array[0] = 0x01;
        }
        let response = certify_split(&mut runtime, key, INDEX, TPM_ALG_ECDAA, TPM_ALG_SHA256, 0);
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            runtime.live.state_reset.as_ref().unwrap().commit_array[0],
            0x00,
            "a completed split signature releases its commit slot"
        );
        let (_, nonce, s) = ecc_signature(&response);
        assert!(!nonce.is_empty(), "the r component carries nonceK");
        assert_eq!(s.len(), 32);
        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_VALUE,
            "the commitment cannot be reused"
        );
    }

    #[test]
    fn an_anonymous_scheme_drops_the_signer_and_qualifying_data() {
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        {
            let reset = runtime.live.state_reset.as_mut().unwrap();
            reset.commit_nonce = OwnedSecret::copy_of(&[0x33; 32]);
            reset.commit_counter = 1;
            reset.commit_array[0] = 0x01;
        }
        let response = certify_split(&mut runtime, key, INDEX, TPM_ALG_ECDAA, TPM_ALG_SHA256, 0);
        assert_eq!(response_code(&response), RC_SUCCESS);
        let parameters = response_parameters(&response);
        assert_eq!(
            &parameters[2 + 6..2 + 10],
            &[0x00, 0x00, 0x00, 0x00],
            "an anonymous signature has an empty signer and extraData"
        );
    }

    #[test]
    fn a_profile_disabled_scheme_or_hash_is_reported_against_the_scheme_parameter() {
        for (dropped, scheme, hash_alg, expected) in [
            (
                "ecschnorr",
                TPM_ALG_ECSCHNORR,
                TPM_ALG_SHA256,
                RC_PARAM2_SCHEME,
            ),
            ("sha512", TPM_ALG_RSASSA, 0x000d, RC_PARAM2_HASH),
        ] {
            let mut runtime = profile_runtime(&without(dropped), "");
            ready_index(&mut runtime);
            let (key, _) = create_primary(
                &mut runtime,
                TPM_RH_OWNER,
                &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
            );
            assert_eq!(
                response_code(&certify(
                    &mut runtime,
                    key,
                    TPM_RH_OWNER,
                    INDEX,
                    &QUALIFY,
                    scheme,
                    hash_alg,
                    32,
                    0
                )),
                expected,
                "{dropped} disabled"
            );
        }
    }

    #[test]
    fn an_enabled_scheme_and_hash_still_certify() {
        let mut runtime = profile_runtime(&all_algorithms(), "");
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECSCHNORR,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_SUCCESS
        );
    }

    #[test]
    fn the_sha1_signing_restriction_matches_the_oracle() {
        let mut runtime = profile_runtime(&all_algorithms(), "no-sha1-signing");
        ready_index(&mut runtime);
        let (ecc, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        let (keyed, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &keyedhash_template(TPM_ALG_HMAC, TPM_ALG_SHA1, SIGN_KEY_ATTRS),
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                ecc,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA1,
                32,
                0
            )),
            RC_HASH,
            "an ECC key cannot sign a SHA-1 digest"
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                ecc,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_SUCCESS
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                keyed,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_SUCCESS,
            "keyed-hash signing is not covered by no-sha1-signing"
        );
    }

    #[test]
    fn the_sha1_hmac_creation_restriction_matches_the_oracle() {
        let mut runtime = profile_runtime(&all_algorithms(), "no-sha1-hmac-creation");
        ready_index(&mut runtime);
        let (ecc, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        let (keyed, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &keyedhash_template(TPM_ALG_HMAC, TPM_ALG_SHA1, SIGN_KEY_ATTRS),
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                keyed,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_HASH,
            "a keyed-hash key cannot create a SHA-1 HMAC"
        );
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                ecc,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA1,
                32,
                0
            )),
            RC_SUCCESS,
            "signing keys are not covered by no-sha1-hmac-creation"
        );
    }

    #[test]
    fn a_rejected_signature_leaves_the_signing_state_untouched() {
        let mut runtime = profile_runtime(&without("ecschnorr"), "no-sha1-signing");
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        {
            let reset = runtime.live.state_reset.as_mut().unwrap();
            reset.commit_nonce = OwnedSecret::copy_of(&[0x77; 32]);
            reset.commit_counter = 1;
            reset.commit_array[0] = 0x01;
        }
        runtime.nv_update_pending = false;
        let before = snapshot(&runtime);
        let drbg_before = runtime.live.orderly.drbg_state.clone();
        let orderly_before = runtime.state().persistent.orderly_state;

        let rejections: [(u16, u16, Option<u16>, u32); 3] = [
            (TPM_ALG_ECSCHNORR, TPM_ALG_SHA256, None, RC_PARAM2_SCHEME),
            (TPM_ALG_ECDSA, TPM_ALG_SHA1, None, RC_HASH),
            (TPM_ALG_ECDAA, TPM_ALG_SHA256, Some(5), RC_VALUE),
        ];
        for (scheme, hash_alg, count, expected) in rejections {
            let response = match count {
                Some(count) => certify_split(&mut runtime, key, INDEX, scheme, hash_alg, count),
                None => certify(
                    &mut runtime,
                    key,
                    TPM_RH_OWNER,
                    INDEX,
                    &QUALIFY,
                    scheme,
                    hash_alg,
                    32,
                    0,
                ),
            };
            assert_eq!(
                response_code(&response),
                expected,
                "scheme {scheme:#06x} hash {hash_alg:#06x}"
            );
            assert_unchanged(&runtime, &before);
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter, drbg_before.reseed_counter,
                "a rejected signature draws no randomness"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.as_bytes(),
                drbg_before.seed.as_bytes()
            );
            assert_eq!(
                runtime.live.state_reset.as_ref().unwrap().commit_array[0],
                0x01,
                "a rejected signature keeps its commitment"
            );
            assert_eq!(
                runtime.state().persistent.orderly_state,
                orderly_before,
                "a rejected signature does not disturb the orderly state"
            );
        }
    }

    #[test]
    fn an_rsapss_signature_verifies_against_the_public_key() {
        use crate::library::tpm2::crypto::{BigUint, mgf1};
        let mut runtime = certify_runtime();
        ready_index(&mut runtime);
        let (key, create) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_template(TPM_ALG_RSAPSS, TPM_ALG_SHA256, SIGN_KEY_ATTRS),
        );
        let modulus = match &loaded_body(&runtime, key).public.unique {
            crate::library::tpm2::persistent::OwnedPublicId::Rsa(modulus) => modulus.clone(),
            _ => panic!("an RSA key"),
        };
        assert!(
            create
                .windows(modulus.len())
                .any(|window| window == modulus),
            "the response carries the modulus"
        );

        let response = certify(
            &mut runtime,
            key,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            0x0010,
            0,
            32,
            0,
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        let parameters = response_parameters(&response);
        let attest_size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let signature = &parameters[2 + attest_size + 6..];
        assert_eq!(signature.len(), 256);

        let n = BigUint::from_be_bytes(&modulus);
        let recovered = BigUint::from_be_bytes(signature)
            .mod_exp(&BigUint::from_u64(65537), &n)
            .expect("the public operation succeeds")
            .to_be_bytes(256)
            .expect("the recovered block fits the modulus");

        assert_eq!(recovered[255], 0xbc, "the PSS trailer is present");
        assert_eq!(recovered[0] & 0x80, 0, "the leading bit is cleared");
        let mask_len = 256 - 32 - 1;
        let h = &recovered[mask_len..mask_len + 32];
        let mask = mgf1(TPM_ALG_SHA256, h, mask_len).expect("a mask");
        let mut db: Vec<u8> = recovered[..mask_len]
            .iter()
            .zip(&mask)
            .map(|(left, right)| left ^ right)
            .collect();
        db[0] &= 0x7f;
        assert_eq!(db[mask_len - 33], 0x01, "the salt separator is recovered");
        let salt = &db[mask_len - 32..];
        assert!(
            db[..mask_len - 33].iter().all(|&byte| byte == 0),
            "the padding is zero"
        );

        let digest = attested_digest(&response, TPM_ALG_SHA256);
        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(&[0u8; 8]);
        hasher.update(&digest);
        hasher.update(salt);
        assert_eq!(
            h,
            &hasher.finalize()[..],
            "the PSS hash commits to the attestation digest and the recovered salt"
        );
    }

    const RC_NV_UNAVAILABLE: u32 = 0x923;
    const RC_FAILURE: u32 = 0x101;

    #[derive(Debug, Eq, PartialEq)]
    struct SigningSnapshot {
        drbg_magic: u32,
        reseed_counter: u64,
        seed: Vec<u8>,
        last_value: [u32; 4],
        commit_counter: u64,
        commit_array: [u8; COMMIT_ARRAY_SIZE],
    }

    fn signing_snapshot(runtime: &Tpm2Runtime) -> SigningSnapshot {
        let drbg = &runtime.live.orderly.drbg_state;
        let reset = runtime.live.state_reset.as_ref().expect("a reset section");
        SigningSnapshot {
            drbg_magic: drbg.drbg_magic,
            reseed_counter: drbg.reseed_counter,
            seed: drbg.seed.as_bytes().to_vec(),
            last_value: drbg.last_value,
            commit_counter: reset.commit_counter,
            commit_array: reset.commit_array,
        }
    }

    #[track_caller]
    fn commitable_ecc_runtime(attributes: &str) -> (Box<Tpm2Runtime>, u32) {
        let mut runtime = profile_runtime(&all_algorithms(), attributes);
        ready_index(&mut runtime);
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, SIGN_KEY_ATTRS),
        );
        {
            let reset = runtime.live.state_reset.as_mut().unwrap();
            reset.commit_nonce = OwnedSecret::copy_of(&[0x21; 32]);
            reset.commit_counter = 1;
            reset.commit_array[0] = 0x01;
        }
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0;
        runtime.nv_update_pending = false;
        (runtime, key)
    }

    #[test]
    fn a_certification_that_cannot_clear_the_orderly_state_leaves_no_trace() {
        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        let before = snapshot(&runtime);
        let signing_before = signing_snapshot(&runtime);
        runtime.nv_available = false;

        for scheme in [TPM_ALG_ECDSA, TPM_ALG_ECSCHNORR, TPM_ALG_SM2] {
            assert_eq!(
                response_code(&certify(
                    &mut runtime,
                    key,
                    TPM_RH_OWNER,
                    INDEX,
                    &QUALIFY,
                    scheme,
                    TPM_ALG_SHA256,
                    32,
                    0
                )),
                RC_NV_UNAVAILABLE,
                "an orderly TPM without NV cannot clear its orderly state, scheme {scheme:#06x}"
            );
            assert_unchanged(&runtime, &before);
            assert_eq!(
                signing_snapshot(&runtime),
                signing_before,
                "the DRBG and the commit array survive the failure, scheme {scheme:#06x}"
            );
        }

        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_NV_UNAVAILABLE,
            "a split signature fails the same way"
        );
        assert_unchanged(&runtime, &before);
        assert_eq!(
            signing_snapshot(&runtime),
            signing_before,
            "a failed split signature keeps its commitment"
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0,
            "the TPM is still orderly"
        );
        assert!(!runtime.nv_update_pending, "no NV update was queued");
    }

    #[test]
    fn a_reseed_due_signature_draw_follows_the_live_drbg_policy() {
        use crate::library::tpm2::crypto::CTR_DRBG_MAX_REQUESTS_PER_RESEED;

        fn failing_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
            Err(crate::library::constants::TPM_FAIL)
        }
        fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
            panic!("the entropy-bad latch must short-circuit the platform callback");
        }
        fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x1d;
            }
            Ok(())
        }

        const RC_NO_RESULT: u32 = 0x154;

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.entropy = failing_entropy;
        let before = signing_snapshot(&runtime);
        let certify_ecdsa = |runtime: &mut Tpm2Runtime| {
            certify(
                runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
                32,
                0,
            )
        };
        assert_eq!(response_code(&certify_ecdsa(&mut runtime)), RC_NO_RESULT);
        assert!(runtime.entropy_bad, "the failed fetch latches g_entropyBad");
        assert!(!runtime.failure_mode);
        assert_eq!(signing_snapshot(&runtime), before, "nothing was published");

        runtime.entropy = unreachable_entropy;
        assert_eq!(response_code(&certify_ecdsa(&mut runtime)), RC_NO_RESULT);
        assert_eq!(signing_snapshot(&runtime), before);

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
        runtime.entropy = deterministic_entropy;
        let response = certify(
            &mut runtime,
            key,
            TPM_RH_OWNER,
            INDEX,
            &QUALIFY,
            TPM_ALG_ECDSA,
            TPM_ALG_SHA256,
            32,
            0,
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, 2,
            "one automatic reseed and one nonce draw"
        );
        assert!(!runtime.entropy_bad);
    }

    #[test]
    fn the_production_outcome_publication_precedes_an_ordinary_signing_error() {
        const INJECTED_SIGNING_ERROR: TpmResult = 0x0195;

        let mut runtime = profile_runtime(&all_algorithms(), "drbg-continous-test");
        let before = signing_snapshot(&runtime);
        let orderly_before = runtime.state().persistent.orderly_state;
        let nv_memory_before = runtime.nv_memory.clone();

        let mut signing = load_signing_state(&mut runtime).expect("the signing state loads");
        let mut scratch = [0u8; 64];
        signing.rand.generate(&mut scratch).expect("randomness");
        signing.commit.array[3] = 0xa5;

        let outcome = publish_signing_outcome(&mut runtime, signing, Err(INJECTED_SIGNING_ERROR));
        assert_eq!(
            outcome.map(|_| ()),
            Err(INJECTED_SIGNING_ERROR),
            "the injected ordinary error is returned"
        );

        let published = signing_snapshot(&runtime);
        assert_ne!(published.seed, before.seed, "the DRBG seed moved");
        assert_eq!(
            published.reseed_counter,
            before.reseed_counter + 1,
            "the single draw advanced the reseed counter"
        );
        assert_ne!(
            published.last_value, before.last_value,
            "the continuous-test value moved"
        );
        assert_eq!(published.commit_array[3], 0xa5);
        assert!(!runtime.entropy_bad);
        assert!(!runtime.failure_mode);
        assert_eq!(runtime.state().persistent.orderly_state, orderly_before);
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn an_unavailable_nv_after_signing_keeps_the_published_signing_state() {
        const NO_DA_SIGN_KEY_ATTRS: u32 = SIGN_KEY_ATTRS | 0x0400;

        let (mut runtime, _) = commitable_ecc_runtime("drbg-continous-test");
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, NO_DA_SIGN_KEY_ATTRS),
        );
        runtime.nv_available = false;
        let before = signing_snapshot(&runtime);
        let nv_memory_before = runtime.nv_memory.clone();

        assert_eq!(
            response_code(&certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_NV_UNAVAILABLE
        );

        let after = signing_snapshot(&runtime);
        assert_ne!(after.seed, before.seed, "the nonce draw remains consumed");
        assert_ne!(after.reseed_counter, before.reseed_counter);
        assert_eq!(after.commit_array, before.commit_array);
        assert_eq!(runtime.state().persistent.orderly_state, 0);
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_failed_orderly_commit_keeps_the_signing_state_and_rolls_back_nv() {
        use crate::library::tpm2::nv::build_nv_image;

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        runtime.state.as_mut().unwrap().persistent.owner_policy = vec![0x5a; 4096];
        assert!(build_nv_image(runtime.state()).is_err());
        let before = signing_snapshot(&runtime);
        let nv_memory_before = runtime.nv_memory.clone();

        assert_eq!(
            response_code(&certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_FAILURE
        );

        let after = signing_snapshot(&runtime);
        assert_ne!(after.seed, before.seed, "the nonce draw remains consumed");
        assert_ne!(after.reseed_counter, before.reseed_counter);
        assert_eq!(after.commit_array, before.commit_array);
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0,
            "the tentative orderly mutation is rolled back"
        );
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn an_unavailable_nv_after_a_split_signature_keeps_the_consumed_commitment() {
        const NO_DA_SIGN_KEY_ATTRS: u32 = SIGN_KEY_ATTRS | 0x0400;

        let (mut runtime, _) = commitable_ecc_runtime("drbg-continous-test");
        let (key, _) = create_primary(
            &mut runtime,
            TPM_RH_OWNER,
            &ecc_template(0x0010, 0, TPM_ECC_NIST_P256, NO_DA_SIGN_KEY_ATTRS),
        );
        runtime.nv_available = false;
        let before = signing_snapshot(&runtime);
        let nv_memory_before = runtime.nv_memory.clone();
        assert_eq!(before.commit_array[0], 0x01, "the commitment is active");

        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_NV_UNAVAILABLE
        );

        let after = signing_snapshot(&runtime);
        assert_ne!(after.seed, before.seed, "the nonce draw remains consumed");
        assert_ne!(after.reseed_counter, before.reseed_counter);
        assert_eq!(
            after.commit_array[0], 0x00,
            "the split signature released its commit slot"
        );
        assert_eq!(runtime.state().persistent.orderly_state, 0);
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
        assert!(!runtime.failure_mode);

        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_VALUE,
            "the commitment cannot be reused"
        );
    }

    #[test]
    fn a_failed_orderly_commit_after_a_split_signature_keeps_the_consumed_commitment() {
        use crate::library::tpm2::nv::build_nv_image;

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        runtime.state.as_mut().unwrap().persistent.owner_policy = vec![0x5a; 4096];
        assert!(build_nv_image(runtime.state()).is_err());
        let before = signing_snapshot(&runtime);
        let nv_memory_before = runtime.nv_memory.clone();
        assert_eq!(before.commit_array[0], 0x01, "the commitment is active");

        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_FAILURE
        );

        let after = signing_snapshot(&runtime);
        assert_ne!(after.seed, before.seed, "the nonce draw remains consumed");
        assert_ne!(after.reseed_counter, before.reseed_counter);
        assert_eq!(
            after.commit_array[0], 0x00,
            "the split signature released its commit slot"
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0,
            "the tentative orderly mutation is rolled back"
        );
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
        assert!(!runtime.failure_mode);

        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_VALUE,
            "the commitment cannot be reused"
        );
    }

    #[test]
    fn a_continuous_test_failure_during_signing_is_fatal_and_publishes_nothing() {
        use crate::library::tpm2::crypto::Drbg;
        use crate::library::tpm2::failure_mode::FailureLocation;

        fn colliding_last_value(seed: &[u8]) -> [u32; 4] {
            let mut probe = Drbg::restore(seed, 1, [0; 4], false).expect("the probe restores");
            let mut block = [0u8; 16];
            probe.generate(&mut block).expect("the probe generates");
            core::array::from_fn(|word| {
                u32::from_le_bytes(block[word * 4..word * 4 + 4].try_into().unwrap())
            })
        }

        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        let seed = runtime.live.orderly.drbg_state.seed.as_bytes().to_vec();
        runtime.live.orderly.drbg_state.last_value = colliding_last_value(&seed);
        let before = signing_snapshot(&runtime);
        let nv_memory_before = runtime.nv_memory.clone();

        assert_eq!(
            response_code(&certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_FAILURE
        );

        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::DrbgEntropy.diagnostics()
        );
        assert!(!runtime.entropy_bad);
        assert_eq!(
            signing_snapshot(&runtime),
            before,
            "no partially advanced state is published"
        );
        assert_eq!(runtime.state().persistent.orderly_state, 0);
        assert_eq!(runtime.nv_memory, nv_memory_before);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn a_successful_certification_publishes_the_signing_state() {
        let (mut runtime, key) = commitable_ecc_runtime("drbg-continous-test");
        let before = signing_snapshot(&runtime);
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                key,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_ECDSA,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_SUCCESS
        );
        let after = signing_snapshot(&runtime);
        assert_ne!(after.seed, before.seed, "signing advanced the DRBG");
        assert_ne!(after.reseed_counter, before.reseed_counter);
        assert_ne!(
            after.last_value, before.last_value,
            "the continuous-test value advanced"
        );
        assert_eq!(
            after.commit_array, before.commit_array,
            "a non-split scheme keeps every commitment"
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0xfffe,
            "a successful certification records the DA-used orderly marker"
        );
        assert!(runtime.nv_update_pending, "the NV image was queued");

        runtime.state.as_mut().unwrap().persistent.orderly_state = 0;
        assert_eq!(
            response_code(&certify_split(
                &mut runtime,
                key,
                INDEX,
                TPM_ALG_ECDAA,
                TPM_ALG_SHA256,
                0
            )),
            RC_SUCCESS
        );
        assert_eq!(
            runtime.live.state_reset.as_ref().unwrap().commit_array[0],
            0x00,
            "a successful split signature consumes its commitment"
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0xfffe,
            "the DA-used orderly marker is recorded again"
        );
    }

    #[test]
    fn certification_clears_the_orderly_state() {
        let (mut runtime, endorsement) = oracle_runtime();
        runtime.state.as_mut().unwrap().persistent.orderly_state = 0;
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_SUCCESS
        );
        assert_eq!(
            runtime.state().persistent.orderly_state,
            0xfffe,
            "the attestation uses the clock, so the TPM is no longer orderly"
        );
    }

    #[test]
    fn a_failed_certification_leaves_no_trace() {
        let (mut runtime, endorsement) = oracle_runtime();
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_SUCCESS,
            "the first authorization performs the DA-used transition"
        );
        runtime.nv_update_pending = false;
        let before = snapshot(&runtime);
        for (size, offset) in [(0u16, 33u16), (8, 28)] {
            assert_ne!(
                response_code(&certify(
                    &mut runtime,
                    endorsement,
                    TPM_RH_OWNER,
                    INDEX,
                    &QUALIFY,
                    0x0010,
                    0,
                    size,
                    offset
                )),
                RC_SUCCESS
            );
            assert_unchanged(&runtime, &before);
        }
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                endorsement,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                TPM_ALG_RSAPSS,
                TPM_ALG_SHA256,
                32,
                0
            )),
            RC_PARAM2_SCHEME
        );
        assert_unchanged(&runtime, &before);
    }

    #[test]
    fn a_missing_authorization_area_is_auth_missing() {
        let (mut runtime, endorsement) = oracle_runtime();
        let mut payload = endorsement.to_be_bytes().to_vec();
        payload.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        payload.extend_from_slice(&INDEX.to_be_bytes());
        payload.extend_from_slice(&certify_parameters(&QUALIFY, 0x0010, 0, 32, 0));
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(TPM_CC_NV_CERTIFY, &payload, false)
            )),
            RC_AUTH_MISSING
        );
    }

    #[test]
    fn an_invalid_sign_handle_is_reported_against_its_own_index() {
        let (mut runtime, _) = oracle_runtime();
        assert_eq!(
            response_code(&certify(
                &mut runtime,
                TPM_RH_OWNER,
                TPM_RH_OWNER,
                INDEX,
                &QUALIFY,
                0x0010,
                0,
                32,
                0
            )),
            RC_HANDLE1_VALUE
        );
    }

    #[test]
    fn trailing_parameter_bytes_are_a_size_error() {
        let (mut runtime, endorsement) = oracle_runtime();
        let mut parameters = certify_parameters(&QUALIFY, 0x0010, 0, 32, 0);
        parameters.push(0x00);
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &command(
                    TPM_CC_NV_CERTIFY,
                    &[endorsement, TPM_RH_OWNER, INDEX],
                    &[&[], &[]],
                    &parameters,
                ),
            )),
            RC_SIZE
        );
    }

    #[test]
    fn certify_parameter_mutations_do_not_panic() {
        let full = certify_parameters(&QUALIFY, TPM_ALG_RSASSA, TPM_ALG_SHA256, 32, 0);
        let (mut runtime, endorsement) = oracle_runtime();
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let response = dispatch_bytes(
                    &mut runtime,
                    &command(
                        TPM_CC_NV_CERTIFY,
                        &[endorsement, TPM_RH_OWNER, INDEX],
                        &[&[], &[]],
                        &parameters,
                    ),
                );
                assert!(response.len() >= 10, "index {index} byte {byte:#04x}");
            }
        }
    }
}
