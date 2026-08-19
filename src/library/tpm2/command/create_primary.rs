use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_OBJECT_MEMORY, TPM_RC_SIZE, TPM_RC_VALUE,
};

use super::super::crypto::{HmacState, SeededRand};
use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, hierarchy_proof};
use super::super::marshal::BlobWriter;
use super::super::object_create::{
    ObjectSecrets, PRIMARY_OBJECT_CREATION, create_object, find_empty_object_slot, primary_seed,
    store_created_object,
};
use super::super::pcr::{HASH_COUNT, PCR_SELECT_MAX, PCR_SELECT_MIN, compute_current_digest};
use super::super::persistent::OwnedPcrSelection;
use super::super::profile::ATTRIBUTE_DRBG_CONTINUOUS_TEST;
use super::super::public::{StateFormatLimit, TPM_ALG_NULL};
use super::super::runtime::Tpm2Runtime;
use super::super::template::{
    AlgorithmPolicy, TemplateReader, adjusted_auth_value, create_checks, digest_size,
    marshal_public_area, object_name, parse_public_area, parse_sensitive_create,
};
use super::super::ticket::CONTEXT_INTEGRITY_HASH_ALG;
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const RC_FMT1: TpmResult = 0x080;
const RC_MODIFIER_MASK: TpmResult = 0xf40;

const RC_IN_SENSITIVE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_PUBLIC: TpmResult = TPM_RC_P + TPM_RC_1 * 2;
const RC_OUTSIDE_INFO: TpmResult = TPM_RC_P + TPM_RC_1 * 3;
const RC_CREATION_PCR: TpmResult = TPM_RC_P + TPM_RC_1 * 4;

const MAX_OUTSIDE_INFO: usize = 2 + 64;

pub(super) const TPM_ST_CREATION: u16 = 0x8021;

pub(super) fn add_modifier(code: TpmResult, modifier: TpmResult) -> TpmResult {
    if code & RC_FMT1 != 0 && code & RC_MODIFIER_MASK == 0 {
        code + modifier
    } else {
        code
    }
}

pub(super) struct Parameters {
    pub(super) user_auth: Vec<u8>,
    pub(super) sensitive_data: Vec<u8>,
    pub(super) public: super::super::persistent::OwnedTpmtPublic,
    pub(super) outside_info: Vec<u8>,
    pub(super) creation_pcr: Vec<OwnedPcrSelection>,
}

pub(super) fn parse_parameters(
    policy: &AlgorithmPolicy<'_>,
    parameters: &[u8],
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);

    let sensitive = parse_sized_sensitive_create(&mut reader)
        .map_err(|code| add_modifier(code, RC_IN_SENSITIVE))?;
    let public =
        parse_sized_public(&mut reader, policy).map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
    let outside_info = reader
        .tpm2b(MAX_OUTSIDE_INFO)
        .map_err(|code| add_modifier(code, RC_OUTSIDE_INFO))?
        .to_vec();
    let creation_pcr =
        parse_pcr_selection(&mut reader).map_err(|code| add_modifier(code, RC_CREATION_PCR))?;

    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    Ok(Parameters {
        user_auth: sensitive.0,
        sensitive_data: sensitive.1,
        public,
        outside_info,
        creation_pcr,
    })
}

pub(super) fn parse_sized_sensitive_create(
    reader: &mut TemplateReader<'_>,
) -> Result<(Vec<u8>, Vec<u8>), TpmResult> {
    let declared = usize::from(reader.u16()?);
    if declared == 0 {
        return Err(TPM_RC_SIZE);
    }
    let start = reader.consumed();
    let sensitive = parse_sensitive_create(reader)?;
    if reader.consumed() - start != declared {
        return Err(TPM_RC_SIZE);
    }
    Ok((sensitive.user_auth, sensitive.data))
}

fn parse_sized_public(
    reader: &mut TemplateReader<'_>,
    policy: &AlgorithmPolicy<'_>,
) -> Result<super::super::persistent::OwnedTpmtPublic, TpmResult> {
    let declared = usize::from(reader.u16()?);
    if declared == 0 {
        return Err(TPM_RC_SIZE);
    }
    let start = reader.consumed();
    let public = parse_public_area(reader, policy, false)?;
    if reader.consumed() - start != declared {
        return Err(TPM_RC_SIZE);
    }
    Ok(public)
}

fn parse_pcr_selection(
    reader: &mut TemplateReader<'_>,
) -> Result<Vec<OwnedPcrSelection>, TpmResult> {
    let count = reader.u32()?;
    if count > HASH_COUNT as u32 {
        return Err(TPM_RC_SIZE);
    }
    let mut selections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let hash_alg = reader.u16()?;
        if digest_size(hash_alg).is_none() {
            return Err(TPM_RC_HASH);
        }
        let sizeof_select = usize::from(reader.u8()?);
        if !(PCR_SELECT_MIN..=PCR_SELECT_MAX).contains(&sizeof_select) {
            return Err(TPM_RC_VALUE);
        }
        let mut select = vec![0u8; sizeof_select];
        for byte in &mut select {
            *byte = reader.u8()?;
        }
        selections.push(OwnedPcrSelection { hash_alg, select });
    }
    Ok(selections)
}

fn marshal_pcr_selection(writer: &mut BlobWriter, selections: &[OwnedPcrSelection]) {
    writer.write_u32(selections.len() as u32);
    for selection in selections {
        writer.write_u16(selection.hash_alg);
        writer.write_u8(selection.select.len() as u8);
        writer.write_bytes(&selection.select);
    }
}

fn locality_attributes(locality: u8) -> u8 {
    if locality < 5 {
        1 << locality
    } else {
        locality
    }
}

pub(super) fn creation_data_bytes(
    parent_name_alg: u16,
    parent_name: &[u8],
    parent_qualified_name: &[u8],
    locality: u8,
    creation_pcr: &[OwnedPcrSelection],
    pcr_digest: &[u8],
    outside_info: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let mut writer = BlobWriter::new();
    marshal_pcr_selection(&mut writer, creation_pcr);
    writer.write_tpm2b(pcr_digest).map_err(|_| TPM_RC_SIZE)?;
    writer.write_u8(locality_attributes(locality));
    writer.write_u16(parent_name_alg);
    writer.write_tpm2b(parent_name).map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(parent_qualified_name)
        .map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(outside_info).map_err(|_| TPM_RC_SIZE)?;
    Ok(writer.into_bytes())
}

pub(super) fn compute_creation_ticket(
    runtime: &Tpm2Runtime,
    hierarchy: u32,
    name: &[u8],
    creation_hash: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let proof: Vec<u8> = if hierarchy == TPM_RH_NULL {
        runtime
            .live
            .state_reset
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .null_proof
            .as_bytes()
            .to_vec()
    } else {
        let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
        hierarchy_proof(persistent, hierarchy)
            .ok_or(TPM_RC_FAILURE)?
            .to_vec()
    };
    let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, &proof).ok_or(TPM_RC_FAILURE)?;
    hmac.update(&TPM_ST_CREATION.to_be_bytes());
    hmac.update(name);
    hmac.update(creation_hash);
    Ok(hmac.finalize())
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let primary_handle = *frame.handles.first().ok_or(TPM_RC_FAILURE)?;
    // TODO: Support runtimes without decoded state after the NVChip fallback
    // is implemented.
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let policy = AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    };
    let continuous_test = state
        .profile
        .attribute_enabled(ATTRIBUTE_DRBG_CONTINUOUS_TEST);
    let parsed = parse_parameters(&policy, frame.parameters)?;

    let (slot, object_handle) = find_empty_object_slot(runtime).ok_or(TPM_RC_OBJECT_MEMORY)?;

    let mut public = parsed.public;
    create_checks(None, &public, parsed.sensitive_data.len())
        .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
    let user_auth = adjusted_auth_value(&parsed.user_auth, public.name_alg)
        .map_err(|_| TPM_RC_SIZE + RC_IN_SENSITIVE)?;

    let (seed, seed_compat_level) = primary_seed(runtime, primary_handle)?;
    let template_name = object_name(&public)?;
    let mut rand = SeededRand::instantiate(
        seed,
        PRIMARY_OBJECT_CREATION,
        &template_name,
        &parsed.sensitive_data,
        seed_compat_level,
        continuous_test,
    )?;

    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    let sh_proof = persistent.sh_proof.as_bytes().to_vec();
    let eh_proof = persistent.eh_proof.as_bytes().to_vec();
    let secrets = ObjectSecrets {
        sh_proof: &sh_proof,
        eh_proof: &eh_proof,
    };

    let created = create_object(
        &mut public,
        user_auth,
        &parsed.sensitive_data,
        primary_handle == TPM_RH_ENDORSEMENT,
        &secrets,
        &mut rand,
    )?;

    let out_public = marshal_public_area(&created.public)?;
    let name = created.name.clone();

    let mut creation_pcr = parsed.creation_pcr;
    let pcr_digest = compute_current_digest(runtime, public.name_alg, &mut creation_pcr)?;
    let creation_data = creation_data_bytes(
        TPM_ALG_NULL,
        &primary_handle.to_be_bytes(),
        &primary_handle.to_be_bytes(),
        runtime.locality,
        &creation_pcr,
        &pcr_digest,
        &parsed.outside_info,
    )?;
    let mut hasher = super::super::crypto::Hasher::new(public.name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&creation_data);
    let creation_hash = hasher.finalize();

    let ticket = compute_creation_ticket(runtime, primary_handle, &name, &creation_hash)?;

    store_created_object(runtime, slot, primary_handle, seed_compat_level, created)?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&out_public).map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&creation_data)
        .map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&creation_hash)
        .map_err(|_| TPM_RC_SIZE)?;
    writer.write_u16(TPM_ST_CREATION);
    writer.write_u32(primary_handle);
    writer.write_tpm2b(&ticket).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&name).map_err(|_| TPM_RC_SIZE)?;

    Ok(CommandOutput::with_handle(
        object_handle,
        writer.into_bytes(),
    ))
}

#[cfg(test)]
pub(in crate::library::tpm2) mod fixtures {
    use super::super::super::public::{
        TPM_ALG_AES, TPM_ALG_CFB, TPM_ALG_ECC, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SHA256,
        TPM_ALG_SHA384,
    };
    use super::super::super::template::{
        TPMA_OBJECT_ADMIN_WITH_POLICY, TPMA_OBJECT_DECRYPT, TPMA_OBJECT_FIXED_PARENT,
        TPMA_OBJECT_FIXED_TPM, TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN,
        TPMA_OBJECT_SIGN, TPMA_OBJECT_USER_WITH_AUTH,
    };

    pub(in crate::library::tpm2) const EK_POLICY_SHA256: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa,
    ];

    pub(in crate::library::tpm2) fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    pub(in crate::library::tpm2) fn storage_attributes() -> u32 {
        TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_RESTRICTED
            | TPMA_OBJECT_DECRYPT
    }

    pub(in crate::library::tpm2) fn endorsement_attributes() -> u32 {
        TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_ADMIN_WITH_POLICY
            | TPMA_OBJECT_RESTRICTED
            | TPMA_OBJECT_DECRYPT
    }

    pub(in crate::library::tpm2) fn signing_attributes() -> u32 {
        TPMA_OBJECT_FIXED_TPM
            | TPMA_OBJECT_FIXED_PARENT
            | TPMA_OBJECT_SENSITIVE_DATA_ORIGIN
            | TPMA_OBJECT_USER_WITH_AUTH
            | TPMA_OBJECT_SIGN
    }

    pub(in crate::library::tpm2) fn rsa_template(
        key_bits: u16,
        name_alg: u16,
        attributes: u32,
        auth_policy: &[u8],
    ) -> Vec<u8> {
        let restricted_parent = attributes & (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT)
            == (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT);
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_RSA.to_be_bytes());
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        push_tpm2b(&mut out, auth_policy);
        if restricted_parent {
            out.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
            out.extend_from_slice(&128u16.to_be_bytes());
            out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        } else {
            out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        }
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2) fn ecc_template(
        curve_id: u16,
        name_alg: u16,
        attributes: u32,
        auth_policy: &[u8],
    ) -> Vec<u8> {
        let restricted_parent = attributes & (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT)
            == (TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT);
        let mut out = Vec::new();
        out.extend_from_slice(&TPM_ALG_ECC.to_be_bytes());
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        push_tpm2b(&mut out, auth_policy);
        if restricted_parent {
            out.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
            out.extend_from_slice(&128u16.to_be_bytes());
            out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        } else {
            out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        }
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&curve_id.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2) fn ek_policy(name_alg: u16) -> Vec<u8> {
        match name_alg {
            TPM_ALG_SHA256 => EK_POLICY_SHA256.to_vec(),
            TPM_ALG_SHA384 => vec![0xb2; 48],
            _ => Vec::new(),
        }
    }

    pub(in crate::library::tpm2) fn rsa_ek_template(key_bits: u16, name_alg: u16) -> Vec<u8> {
        rsa_template(
            key_bits,
            name_alg,
            endorsement_attributes(),
            &ek_policy(name_alg),
        )
    }

    pub(in crate::library::tpm2) fn ecc_ek_template() -> Vec<u8> {
        ecc_template(
            0x0004,
            TPM_ALG_SHA384,
            endorsement_attributes(),
            &ek_policy(TPM_ALG_SHA384),
        )
    }

    pub(in crate::library::tpm2) fn rsa_storage_template(key_bits: u16) -> Vec<u8> {
        rsa_template(key_bits, TPM_ALG_SHA256, storage_attributes(), &[])
    }

    pub(in crate::library::tpm2) fn parameters(
        in_sensitive: &[u8],
        in_public: &[u8],
        outside_info: &[u8],
        creation_pcr: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        push_tpm2b(&mut out, in_sensitive);
        push_tpm2b(&mut out, in_public);
        push_tpm2b(&mut out, outside_info);
        out.extend_from_slice(creation_pcr);
        out
    }

    pub(in crate::library::tpm2) fn empty_sensitive() -> Vec<u8> {
        let mut out = Vec::new();
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2) fn no_creation_pcr() -> Vec<u8> {
        0u32.to_be_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::command::header::{parse_command, serialize_response};
    use crate::library::tpm2::command::registry::TPM_CC_CREATE_PRIMARY;
    use crate::library::tpm2::hierarchy::{TPM_RH_OWNER, TPM_RH_PLATFORM};
    use crate::library::tpm2::manufacture::manufacture_state;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::persistent::OwnedAnyObjectBody;
    use crate::library::tpm2::profile::validate_user_profile;
    use crate::library::tpm2::public::{TPM_ALG_ECC, TPM_ALG_RSA, TPM_ALG_SHA256, TPM_ALG_SHA384};
    use crate::library::tpm2::runtime::commit_manufactured_state;

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE1_HIERARCHY: u32 = 0x185;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_BAD_AUTH_SESSION1: u32 = 0x9a2;
    const RC_SIZE: u32 = 0x095;
    const RC_OBJECT_MEMORY: u32 = 0x902;

    fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
        let len = buffer.len() as u8;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(len) ^ 0x63;
        }
        Ok(())
    }

    fn dispatch_bytes(runtime: &mut Tpm2Runtime, bytes: &[u8]) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes.to_vec());
        let parsed = parse_command(&input).expect("the header parses");
        let response = super::super::dispatcher::dispatch(runtime, &parsed);
        serialize_response(&response).expect("the response fits")
    }

    fn started_runtime() -> Box<Tpm2Runtime> {
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let startup = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
        runtime
    }

    fn password_session(password: &[u8]) -> Vec<u8> {
        let mut session = Vec::new();
        session.extend_from_slice(&0x4000_0009u32.to_be_bytes());
        push_tpm2b(&mut session, &[]);
        session.push(0x00);
        push_tpm2b(&mut session, password);
        session
    }

    fn command(handle: u32, password: &[u8], parameters: &[u8]) -> Vec<u8> {
        let session = password_session(password);
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&(session.len() as u32).to_be_bytes());
        payload.extend_from_slice(&session);
        payload.extend_from_slice(parameters);
        let mut out = 0x8002u16.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_CREATE_PRIMARY.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn create(runtime: &mut Tpm2Runtime, handle: u32, in_public: &[u8]) -> Vec<u8> {
        let parameters = parameters(&empty_sensitive(), in_public, &[], &no_creation_pcr());
        dispatch_bytes(runtime, &command(handle, &[], &parameters))
    }

    fn response_code(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("a response code"))
    }

    struct Decoded {
        object_handle: u32,
        out_public: Vec<u8>,
        creation_data: Vec<u8>,
        creation_hash: Vec<u8>,
        ticket: Vec<u8>,
        name: Vec<u8>,
    }

    #[track_caller]
    fn decode(response: &[u8]) -> Decoded {
        assert_eq!(response_code(response), 0, "the command succeeded");
        assert_eq!(&response[..2], &0x8002u16.to_be_bytes());
        let object_handle = u32::from_be_bytes(response[10..14].try_into().unwrap());
        let parameter_size = u32::from_be_bytes(response[14..18].try_into().unwrap()) as usize;
        let parameters = &response[18..18 + parameter_size];
        let mut reader = TemplateReader::new(parameters);
        let out_public = reader.tpm2b(0xffff).unwrap().to_vec();
        let creation_data = reader.tpm2b(0xffff).unwrap().to_vec();
        let creation_hash = reader.tpm2b(0xffff).unwrap().to_vec();
        assert_eq!(reader.u16().unwrap(), TPM_ST_CREATION);
        let _hierarchy = reader.u32().unwrap();
        let ticket = reader.tpm2b(0xffff).unwrap().to_vec();
        let name = reader.tpm2b(0xffff).unwrap().to_vec();
        assert!(reader.remaining().is_empty(), "no trailing parameters");
        Decoded {
            object_handle,
            out_public,
            creation_data,
            creation_hash,
            ticket,
            name,
        }
    }

    #[test]
    fn the_command_code_and_attributes_match_upstream() {
        use crate::library::tpm2::command::registry::find;
        assert_eq!(TPM_CC_CREATE_PRIMARY, 0x0000_0131);
        let descriptor = find(TPM_CC_CREATE_PRIMARY).expect("a registered command");
        assert_eq!(descriptor.attributes, 0x1200_0131);
        assert_ne!(descriptor.attributes & (1 << 28), 0, "a response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NVRAM update");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
    }

    #[test]
    fn the_command_declares_one_user_authorized_hierarchy_handle() {
        use crate::library::tpm2::command::registry::{HandleKind, find};
        let descriptor = find(TPM_CC_CREATE_PRIMARY).expect("a registered command");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Hierarchy));
        assert!(descriptor.sessions_allowed);
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_PLATFORM,
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
        ] {
            assert!(descriptor.handles[0].kind.accepts(handle));
        }
        for handle in [0x4000_000au32, 0x4000_0009, 0, 23, 0x8000_0000, u32::MAX] {
            assert!(!descriptor.handles[0].kind.accepts(handle));
        }
    }

    #[test]
    fn every_supported_hierarchy_creates_a_primary_with_a_password_session() {
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_PLATFORM,
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
        ] {
            let mut runtime = started_runtime();
            let response = create(&mut runtime, handle, &rsa_storage_template(1024));
            let decoded = decode(&response);
            assert_eq!(decoded.object_handle, 0x8000_0000, "handle {handle:#010x}");
            assert_eq!(decoded.name.len(), 2 + 32);
        }
    }

    #[test]
    fn a_handle_outside_the_hierarchy_range_is_a_value_error() {
        let mut runtime = started_runtime();
        for handle in [0x4000_000au32, 0x4000_0009, 0x8000_0000, 0, u32::MAX] {
            let response = create(&mut runtime, handle, &rsa_storage_template(1024));
            assert_eq!(response_code(&response), RC_HANDLE1_VALUE, "{handle:#010x}");
        }
    }

    #[test]
    fn a_disabled_hierarchy_is_reported_before_the_parameters_are_parsed() {
        let mut runtime = started_runtime();
        runtime.live.ph_enable = false;
        let response = create(&mut runtime, TPM_RH_PLATFORM, &[]);
        assert_eq!(response_code(&response), RC_HANDLE1_HIERARCHY);

        if let Some(clear) = runtime.live.state_clear.as_mut() {
            clear.sh_enable = false;
            clear.eh_enable = false;
        }
        for handle in [TPM_RH_OWNER, TPM_RH_ENDORSEMENT] {
            let response = create(&mut runtime, handle, &rsa_storage_template(1024));
            assert_eq!(response_code(&response), RC_HANDLE1_HIERARCHY);
        }
        let response = create(&mut runtime, TPM_RH_NULL, &rsa_storage_template(1024));
        assert_eq!(
            response_code(&response),
            0,
            "the null hierarchy never disables"
        );
    }

    #[test]
    fn a_command_without_an_authorization_area_is_auth_missing() {
        let mut runtime = started_runtime();
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &no_creation_pcr(),
        );
        let mut payload = TPM_RH_OWNER.to_be_bytes().to_vec();
        payload.extend_from_slice(&parameters);
        let mut out = 0x8001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&TPM_CC_CREATE_PRIMARY.to_be_bytes());
        out.extend_from_slice(&payload);
        assert_eq!(
            response_code(&dispatch_bytes(&mut runtime, &out)),
            RC_AUTH_MISSING
        );
    }

    #[test]
    fn a_wrong_hierarchy_password_is_rejected_before_any_key_is_generated() {
        let mut runtime = started_runtime();
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &no_creation_pcr(),
        );
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, b"wrong", &parameters));
        assert_eq!(response_code(&response), RC_BAD_AUTH_SESSION1);
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes == 0)
        );
    }

    #[test]
    fn trailing_parameter_bytes_are_a_bare_size_error() {
        let mut runtime = started_runtime();
        let mut parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &no_creation_pcr(),
        );
        parameters.push(0x00);
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
        assert_eq!(response_code(&response), RC_SIZE);
    }

    #[test]
    fn every_strict_prefix_of_the_parameters_fails_without_creating_an_object() {
        let mut runtime = started_runtime();
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &no_creation_pcr(),
        );
        for length in 0..parameters.len() {
            let response = dispatch_bytes(
                &mut runtime,
                &command(TPM_RH_OWNER, &[], &parameters[..length]),
            );
            assert_ne!(response_code(&response), 0, "prefix {length}");
            assert!(
                runtime
                    .live
                    .objects
                    .iter()
                    .all(|object| object.attributes == 0),
                "prefix {length} left an object behind"
            );
        }
    }

    #[test]
    fn an_empty_sized_input_is_a_size_error_on_its_own_parameter() {
        let mut runtime = started_runtime();
        let mut parameters = Vec::new();
        push_tpm2b(&mut parameters, &[]);
        push_tpm2b(&mut parameters, &rsa_storage_template(1024));
        push_tpm2b(&mut parameters, &[]);
        parameters.extend_from_slice(&no_creation_pcr());
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
        assert_eq!(response_code(&response), RC_SIZE + RC_IN_SENSITIVE);

        let mut parameters = Vec::new();
        push_tpm2b(&mut parameters, &empty_sensitive());
        push_tpm2b(&mut parameters, &[]);
        push_tpm2b(&mut parameters, &[]);
        parameters.extend_from_slice(&no_creation_pcr());
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
        assert_eq!(response_code(&response), RC_SIZE + RC_IN_PUBLIC);
    }

    #[test]
    fn a_declared_size_that_disagrees_with_the_structure_is_a_size_error() {
        let mut runtime = started_runtime();
        let template = rsa_storage_template(1024);
        let mut parameters = Vec::new();
        push_tpm2b(&mut parameters, &empty_sensitive());
        parameters.extend_from_slice(&((template.len() - 1) as u16).to_be_bytes());
        parameters.extend_from_slice(&template);
        push_tpm2b(&mut parameters, &[]);
        parameters.extend_from_slice(&no_creation_pcr());
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
        assert_eq!(response_code(&response), RC_SIZE + RC_IN_PUBLIC);
    }

    #[test]
    fn template_errors_are_decorated_with_the_public_parameter_number() {
        let mut runtime = started_runtime();
        let cases: [(Vec<u8>, u32); 4] = [
            (
                rsa_template(512, TPM_ALG_SHA256, storage_attributes(), &[]),
                0x084,
            ),
            (rsa_template(2048, 0x0012, storage_attributes(), &[]), 0x083),
            (
                ecc_template(0x0099, TPM_ALG_SHA256, storage_attributes(), &[]),
                0x0a6,
            ),
            (
                rsa_template(2048, TPM_ALG_SHA256, storage_attributes() | (1 << 3), &[]),
                0x0a1,
            ),
        ];
        for (template, code) in cases {
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_eq!(response_code(&response), code + RC_IN_PUBLIC);
        }
    }

    #[test]
    fn attribute_errors_are_decorated_with_the_public_parameter_number() {
        let mut runtime = started_runtime();
        let template = rsa_template(
            2048,
            TPM_ALG_SHA256,
            storage_attributes() & !TPMA_OBJECT_SENSITIVE_DATA_ORIGIN_BIT,
            &[],
        );
        let response = create(&mut runtime, TPM_RH_OWNER, &template);
        assert_eq!(response_code(&response), 0x082 + RC_IN_PUBLIC);
    }

    const TPMA_OBJECT_SENSITIVE_DATA_ORIGIN_BIT: u32 = 1 << 5;

    #[test]
    fn an_oversized_user_auth_is_a_size_error_on_the_sensitive_parameter() {
        let mut runtime = started_runtime();
        let mut sensitive = Vec::new();
        push_tpm2b(&mut sensitive, &[0xaa; 33]);
        push_tpm2b(&mut sensitive, &[]);
        let parameters = parameters(
            &sensitive,
            &rsa_storage_template(1024),
            &[],
            &no_creation_pcr(),
        );
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
        assert_eq!(response_code(&response), RC_SIZE + RC_IN_SENSITIVE);
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes == 0)
        );
    }

    #[test]
    fn an_rsa_two_thousand_forty_eight_bit_endorsement_key_is_created() {
        let mut runtime = started_runtime();
        let response = create(
            &mut runtime,
            TPM_RH_ENDORSEMENT,
            &rsa_ek_template(2048, TPM_ALG_SHA256),
        );
        let decoded = decode(&response);
        let mut reader = TemplateReader::new(&decoded.out_public);
        assert_eq!(reader.u16().unwrap(), TPM_ALG_RSA);
        assert_eq!(reader.u16().unwrap(), TPM_ALG_SHA256);
        let public = &decoded.out_public;
        let modulus = &public[public.len() - 256..];
        assert_ne!(modulus[0] & 0x80, 0, "a full-length modulus");
        assert_eq!(decoded.name.len(), 2 + 32);
        assert_eq!(decoded.creation_hash.len(), 32);
        assert_eq!(decoded.ticket.len(), 64);
    }

    #[test]
    fn an_rsa_three_thousand_seventy_two_bit_endorsement_key_is_created() {
        let mut runtime = started_runtime();
        let response = create(
            &mut runtime,
            TPM_RH_ENDORSEMENT,
            &rsa_ek_template(3072, TPM_ALG_SHA384),
        );
        let decoded = decode(&response);
        let public = &decoded.out_public;
        let modulus = &public[public.len() - 384..];
        assert_ne!(modulus[0] & 0x80, 0, "a full-length modulus");
        assert_eq!(decoded.name.len(), 2 + 48);
        assert_eq!(decoded.creation_hash.len(), 48);
    }

    #[test]
    fn an_ecc_nist_p384_endorsement_key_is_created() {
        let mut runtime = started_runtime();
        let response = create(&mut runtime, TPM_RH_ENDORSEMENT, &ecc_ek_template());
        let decoded = decode(&response);
        let mut reader = TemplateReader::new(&decoded.out_public);
        assert_eq!(reader.u16().unwrap(), TPM_ALG_ECC);
        assert_eq!(reader.u16().unwrap(), TPM_ALG_SHA384);
        let public = &decoded.out_public;
        let coordinates = &public[public.len() - (2 + 48) * 2..];
        assert_eq!(&coordinates[..2], &48u16.to_be_bytes());
        assert_eq!(&coordinates[50..52], &48u16.to_be_bytes());
        assert_eq!(decoded.name.len(), 2 + 48);
    }

    #[test]
    fn the_same_seed_and_template_derive_the_same_key_twice() {
        let mut first = started_runtime();
        let mut second = started_runtime();
        let template = rsa_storage_template(1024);
        let left = decode(&create(&mut first, TPM_RH_OWNER, &template));
        let right = decode(&create(&mut second, TPM_RH_OWNER, &template));
        assert_eq!(left.out_public, right.out_public);
        assert_eq!(left.name, right.name);
    }

    #[test]
    fn a_second_creation_in_the_same_boot_reproduces_the_first_key() {
        let mut runtime = started_runtime();
        let template = rsa_storage_template(1024);
        let first = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
        let second = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
        assert_eq!(first.out_public, second.out_public);
        assert_eq!(first.name, second.name);
        assert_ne!(first.object_handle, second.object_handle);
    }

    #[test]
    fn each_hierarchy_derives_its_own_key_from_its_own_seed() {
        let mut runtime = started_runtime();
        let template = rsa_storage_template(1024);
        let owner = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
        let platform = decode(&create(&mut runtime, TPM_RH_PLATFORM, &template));
        assert_ne!(owner.out_public, platform.out_public);
        assert_ne!(owner.name, platform.name);
    }

    #[test]
    fn a_changed_hierarchy_seed_changes_the_derived_key() {
        let mut runtime = started_runtime();
        let template = rsa_storage_template(1024);
        let before = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
        if let Some(state) = runtime.state.as_mut() {
            state.persistent.sp_seed =
                crate::library::tpm2::persistent::OwnedSecret::copy_of(&[0x5a; 64]);
        }
        let mut runtime = runtime;
        runtime.live.objects[0].attributes = 0;
        runtime.live.objects[1].attributes = 0;
        let after = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
        assert_ne!(before.out_public, after.out_public);
    }

    #[test]
    fn a_different_template_derives_a_different_key() {
        let mut runtime = started_runtime();
        let first = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let second = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_template(1024, TPM_ALG_SHA384, storage_attributes(), &[]),
        ));
        assert_ne!(first.out_public, second.out_public);
    }

    #[test]
    fn the_sensitive_data_field_changes_the_derived_key() {
        let mut runtime = started_runtime();
        let template = rsa_storage_template(1024);
        let plain = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
        let mut sensitive = Vec::new();
        push_tpm2b(&mut sensitive, &[]);
        push_tpm2b(&mut sensitive, b"salt");
        let parameters = parameters(&sensitive, &template, &[], &no_creation_pcr());
        let seasoned = decode(&dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_OWNER, &[], &parameters),
        ));
        assert_ne!(plain.out_public, seasoned.out_public);
    }

    #[test]
    fn transient_handles_are_allocated_in_order_until_the_slots_run_out() {
        let mut runtime = started_runtime();
        let template = rsa_storage_template(1024);
        for expected in [0x8000_0000u32, 0x8000_0001, 0x8000_0002] {
            let decoded = decode(&create(&mut runtime, TPM_RH_OWNER, &template));
            assert_eq!(decoded.object_handle, expected);
        }
        let response = create(&mut runtime, TPM_RH_OWNER, &template);
        assert_eq!(response_code(&response), RC_OBJECT_MEMORY);
    }

    #[test]
    fn the_object_memory_error_is_reported_before_the_template_is_validated() {
        let mut runtime = started_runtime();
        for object in &mut runtime.live.objects {
            object.attributes = ATTR_OCCUPIED;
        }
        let response = create(&mut runtime, TPM_RH_OWNER, &rsa_storage_template(1024));
        assert_eq!(response_code(&response), RC_OBJECT_MEMORY);
    }

    #[test]
    fn the_created_object_occupies_its_slot_with_a_matching_name() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let object = &runtime.live.objects[0];
        assert_ne!(object.attributes & ATTR_OCCUPIED, 0);
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("an object body");
        };
        assert_eq!(body.name, decoded.name);
        assert_eq!(body.hierarchy, Some(TPM_RH_OWNER));
        assert_eq!(body.qualified_name.len(), 2 + 32);
        assert!(body.sensitive.sensitive.is_some());
    }

    #[test]
    fn a_failed_creation_leaves_every_slot_free() {
        let mut runtime = started_runtime();
        for template in [
            rsa_template(512, TPM_ALG_SHA256, storage_attributes(), &[]),
            ecc_template(0x0099, TPM_ALG_SHA256, storage_attributes(), &[]),
            rsa_template(2048, TPM_ALG_SHA256, storage_attributes() | (1 << 18), &[]),
        ] {
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_ne!(response_code(&response), 0);
            assert!(
                runtime
                    .live
                    .objects
                    .iter()
                    .all(|object| object.attributes == 0),
                "a failed creation occupied a slot"
            );
        }
    }

    #[test]
    fn the_creation_data_carries_the_hierarchy_handle_as_both_parent_names() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let mut reader = TemplateReader::new(&decoded.creation_data);
        assert_eq!(reader.u32().unwrap(), 0, "no creation PCR selection");
        assert_eq!(reader.tpm2b(64).unwrap().len(), 32, "an empty PCR digest");
        assert_eq!(reader.u8().unwrap(), 0x01, "locality zero");
        assert_eq!(reader.u16().unwrap(), TPM_ALG_NULL);
        assert_eq!(reader.tpm2b(68).unwrap(), &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(reader.tpm2b(68).unwrap(), &TPM_RH_OWNER.to_be_bytes());
        assert_eq!(reader.tpm2b(66).unwrap(), b"");
        assert!(reader.remaining().is_empty());
    }

    #[test]
    fn the_creation_hash_digests_the_creation_data() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let mut hasher =
            crate::library::tpm2::crypto::Hasher::new(TPM_ALG_SHA256).expect("a compiled hash");
        hasher.update(&decoded.creation_data);
        assert_eq!(decoded.creation_hash, hasher.finalize());
    }

    #[test]
    fn the_outside_info_travels_into_the_creation_data() {
        let mut runtime = started_runtime();
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            b"outside",
            &no_creation_pcr(),
        );
        let decoded = decode(&dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_OWNER, &[], &parameters),
        ));
        assert!(
            decoded.creation_data.ends_with(b"\x00\x07outside"),
            "the outside info closes the creation data"
        );
    }

    #[test]
    fn a_creation_pcr_selection_is_filtered_against_the_allocation() {
        let mut runtime = started_runtime();
        let mut creation_pcr = 1u32.to_be_bytes().to_vec();
        creation_pcr.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        creation_pcr.push(3);
        creation_pcr.extend_from_slice(&[0xff, 0xff, 0xff]);
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &creation_pcr,
        );
        let decoded = decode(&dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_OWNER, &[], &parameters),
        ));
        let mut reader = TemplateReader::new(&decoded.creation_data);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u16().unwrap(), TPM_ALG_SHA256);
        assert_eq!(reader.u8().unwrap(), 3);
        assert_eq!(reader.remaining()[..3], [0xff, 0xff, 0xff]);
    }

    #[test]
    fn an_unselectable_creation_pcr_bank_is_cleared() {
        let mut runtime = started_runtime();
        if let Some(state) = runtime.state.as_mut() {
            state.persistent.pcr_allocated.selections.clear();
        }
        runtime.live_pcr_allocated = None;
        let mut creation_pcr = 1u32.to_be_bytes().to_vec();
        creation_pcr.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        creation_pcr.push(3);
        creation_pcr.extend_from_slice(&[0xff, 0xff, 0xff]);
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &creation_pcr,
        );
        let decoded = decode(&dispatch_bytes(
            &mut runtime,
            &command(TPM_RH_OWNER, &[], &parameters),
        ));
        let mut reader = TemplateReader::new(&decoded.creation_data);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.u16().unwrap(), TPM_ALG_SHA256);
        assert_eq!(reader.u8().unwrap(), 3);
        assert_eq!(reader.remaining()[..3], [0x00, 0x00, 0x00]);
    }

    #[test]
    fn too_many_creation_pcr_banks_are_a_size_error_on_the_fourth_parameter() {
        let mut runtime = started_runtime();
        let creation_pcr = 5u32.to_be_bytes().to_vec();
        let parameters = parameters(
            &empty_sensitive(),
            &rsa_storage_template(1024),
            &[],
            &creation_pcr,
        );
        let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
        assert_eq!(response_code(&response), RC_SIZE + RC_CREATION_PCR);
    }

    #[test]
    fn a_creation_pcr_selection_size_outside_the_bounds_is_a_value_error() {
        let mut runtime = started_runtime();
        for sizeof_select in [0u8, 1, 2, 4, 255] {
            let mut creation_pcr = 1u32.to_be_bytes().to_vec();
            creation_pcr.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
            creation_pcr.push(sizeof_select);
            creation_pcr.extend_from_slice(&[0x00; 8]);
            let parameters = parameters(
                &empty_sensitive(),
                &rsa_storage_template(1024),
                &[],
                &creation_pcr,
            );
            let response = dispatch_bytes(&mut runtime, &command(TPM_RH_OWNER, &[], &parameters));
            assert_eq!(
                response_code(&response),
                0x084 + RC_CREATION_PCR,
                "sizeofSelect {sizeof_select}"
            );
        }
    }

    #[test]
    fn the_creation_ticket_is_a_full_length_hierarchy_mac() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        assert_eq!(decoded.ticket.len(), 64);
        let proof = runtime
            .state
            .as_ref()
            .unwrap()
            .persistent
            .sh_proof
            .as_bytes()
            .to_vec();
        let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, &proof).unwrap();
        hmac.update(&TPM_ST_CREATION.to_be_bytes());
        hmac.update(&decoded.name);
        hmac.update(&decoded.creation_hash);
        assert_eq!(decoded.ticket, hmac.finalize());
    }

    #[test]
    fn the_null_hierarchy_ticket_uses_the_null_proof() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_NULL,
            &rsa_storage_template(1024),
        ));
        let proof = runtime
            .live
            .state_reset
            .as_ref()
            .unwrap()
            .null_proof
            .as_bytes()
            .to_vec();
        let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, &proof).unwrap();
        hmac.update(&TPM_ST_CREATION.to_be_bytes());
        hmac.update(&decoded.name);
        hmac.update(&decoded.creation_hash);
        assert_eq!(decoded.ticket, hmac.finalize());
    }

    #[test]
    fn the_returned_name_is_the_digest_of_the_returned_public_area() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let mut hasher =
            crate::library::tpm2::crypto::Hasher::new(TPM_ALG_SHA256).expect("a compiled hash");
        hasher.update(&decoded.out_public);
        let mut expected = TPM_ALG_SHA256.to_be_bytes().to_vec();
        expected.extend_from_slice(&hasher.finalize());
        assert_eq!(decoded.name, expected);
    }

    #[test]
    fn the_locality_travels_into_the_creation_data() {
        let mut runtime = started_runtime();
        runtime.locality = 3;
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        assert_eq!(decoded.creation_data[4 + 2 + 32], 0x08);
    }

    #[test]
    fn the_locality_attribute_matches_the_upstream_encoding() {
        for locality in 0..5u8 {
            assert_eq!(locality_attributes(locality), 1 << locality);
        }
        for locality in [32u8, 200, 255] {
            assert_eq!(locality_attributes(locality), locality);
        }
    }

    #[track_caller]
    fn round_trip_object(runtime: &Tpm2Runtime) -> Box<Tpm2Runtime> {
        let blob = crate::library::tpm2::volatile_all_store(runtime)
            .expect("the volatile state serializes");
        let profile = validate_user_profile(None).expect("the null profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut restored = commit_manufactured_state(state).expect("commits");
        crate::library::tpm2::attach_volatile_blob_for_test(&mut restored, &blob)
            .expect("the volatile state restores");
        restored
    }

    #[track_caller]
    fn restored_object_body(
        runtime: &Tpm2Runtime,
        slot: usize,
    ) -> (Vec<u8>, Vec<u8>, Option<u32>, u8) {
        let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[slot].body else {
            panic!("an object body");
        };
        (
            body.name.clone(),
            body.qualified_name.clone(),
            body.hierarchy,
            body.seed_compat_level,
        )
    }

    #[test]
    fn the_created_object_survives_a_volatile_state_round_trip() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let before = restored_object_body(&runtime, 0);
        let restored = round_trip_object(&runtime);
        assert_eq!(before.0, decoded.name);
        let after = restored_object_body(&restored, 0);
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1);
        assert_eq!(after.3, before.3);
        assert_eq!(
            after.2, None,
            "the null profile writes objects at version three, which carries no hierarchy"
        );
        assert_ne!(restored.live.objects[0].attributes & ATTR_OCCUPIED, 0);
        assert_eq!(
            restored.live.objects[0].attributes,
            runtime.live.objects[0].attributes
        );
    }

    fn started_default_profile_runtime() -> Box<Tpm2Runtime> {
        let json = br#"{"Name":"default-v1"}"#;
        let profile = validate_user_profile(Some(json)).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let startup = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
        runtime
    }

    #[test]
    fn the_current_state_format_carries_the_hierarchy_through_a_round_trip() {
        let mut runtime = started_default_profile_runtime();
        decode(&create(
            &mut runtime,
            TPM_RH_ENDORSEMENT,
            &rsa_storage_template(1024),
        ));
        let before = restored_object_body(&runtime, 0);
        assert_eq!(before.2, Some(TPM_RH_ENDORSEMENT));
        let blob = crate::library::tpm2::volatile_all_store(&runtime)
            .expect("the volatile state serializes");
        let json = br#"{"Name":"default-v1"}"#;
        let profile = validate_user_profile(Some(json)).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut restored = commit_manufactured_state(state).expect("commits");
        crate::library::tpm2::attach_volatile_blob_for_test(&mut restored, &blob)
            .expect("the volatile state restores");
        assert_eq!(restored_object_body(&restored, 0), before);
    }

    #[test]
    fn a_stored_ecc_object_survives_a_volatile_state_round_trip() {
        let mut runtime = started_runtime();
        let decoded = decode(&create(
            &mut runtime,
            TPM_RH_ENDORSEMENT,
            &ecc_ek_template(),
        ));
        let before = restored_object_body(&runtime, 0);
        let restored = round_trip_object(&runtime);
        assert_eq!(before.0, decoded.name);
        let after = restored_object_body(&restored, 0);
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1);
        assert_eq!(after.3, before.3);
    }

    #[test]
    fn the_restored_object_keeps_its_public_and_sensitive_areas() {
        let mut runtime = started_runtime();
        decode(&create(
            &mut runtime,
            TPM_RH_OWNER,
            &rsa_storage_template(1024),
        ));
        let restored = round_trip_object(&runtime);
        let (OwnedAnyObjectBody::Object(before), OwnedAnyObjectBody::Object(after)) = (
            &runtime.live.objects[0].body,
            &restored.live.objects[0].body,
        ) else {
            panic!("two object bodies");
        };
        assert_eq!(before.public.unique, after.public.unique);
        assert_eq!(
            before
                .sensitive
                .sensitive
                .as_ref()
                .map(|s| s.as_bytes().to_vec()),
            after
                .sensitive
                .sensitive
                .as_ref()
                .map(|s| s.as_bytes().to_vec())
        );
        assert_eq!(
            before.sensitive.seed_value.as_bytes(),
            after.sensitive.seed_value.as_bytes()
        );
        assert_eq!(
            before.private_exponent.as_ref().map(|e| e
                .primes
                .iter()
                .map(|p| (p.numbytes, p.data.as_bytes().to_vec()))
                .collect::<Vec<_>>()),
            after.private_exponent.as_ref().map(|e| e
                .primes
                .iter()
                .map(|p| (p.numbytes, p.data.as_bytes().to_vec()))
                .collect::<Vec<_>>())
        );
    }

    fn oracle_runtime() -> Box<Tpm2Runtime> {
        use crate::library::tpm2::oracles::create_primary::vector;
        let mut runtime = crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL"))
            .expect("the oracle permanent state restores");
        let startup = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
        runtime
    }

    #[test]
    fn every_swtpm_setup_template_matches_the_libtpms_oracle_byte_for_byte() {
        use crate::library::tpm2::oracles::create_primary::oracle_cases;
        for (label, hierarchy, template, expected) in oracle_cases() {
            let mut runtime = oracle_runtime();
            let response = create(&mut runtime, hierarchy, &template);
            assert_eq!(response, expected, "{label}");
        }
    }

    #[test]
    fn an_unrestricted_signing_primary_is_created_in_every_hierarchy() {
        for handle in [
            TPM_RH_OWNER,
            TPM_RH_PLATFORM,
            TPM_RH_ENDORSEMENT,
            TPM_RH_NULL,
        ] {
            let mut runtime = started_runtime();
            let template = rsa_template(1024, TPM_ALG_SHA256, signing_attributes(), &[]);
            let decoded = decode(&create(&mut runtime, handle, &template));
            assert_eq!(decoded.object_handle, 0x8000_0000, "handle {handle:#010x}");
            let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[0].body else {
                panic!("an object body");
            };
            assert!(
                body.sensitive.seed_value.as_bytes().is_empty(),
                "a signing key keeps no protection seed"
            );
        }
    }

    #[test]
    fn the_null_hierarchy_key_has_the_oracle_shape_but_a_per_boot_value() {
        use crate::library::tpm2::oracles::create_primary::{null_hierarchy_template, vector};
        let expected = vector("NULL_RSA1024");
        let mut runtime = oracle_runtime();
        let response = create(&mut runtime, TPM_RH_NULL, &null_hierarchy_template());
        assert_eq!(response.len(), expected.len());
        assert_eq!(
            response[..46],
            expected[..46],
            "the template travels through"
        );
        assert_ne!(
            response, expected,
            "the null seed is drawn afresh on every startup"
        );
        let creation_data_start = 46 + 128;
        assert_eq!(
            response[creation_data_start..creation_data_start + 57],
            expected[creation_data_start..creation_data_start + 57],
            "the creation data does not depend on the seed"
        );
    }

    #[test]
    fn the_oracle_permanent_state_restores_with_the_default_profile() {
        let runtime = oracle_runtime();
        let state = runtime.state.as_ref().expect("decoded state");
        assert_eq!(state.profile.state_format_level, 7);
        assert_eq!(state.persistent.ep_seed.as_bytes().len(), 64);
        assert_eq!(state.persistent.sp_seed.as_bytes().len(), 64);
        assert_eq!(state.persistent.pp_seed.as_bytes().len(), 64);
        assert_eq!(state.persistent.ep_seed_compat_level, 1);
    }

    fn sym_permall_runtime() -> Box<Tpm2Runtime> {
        use crate::library::tpm2::oracles::create_primary::vector;
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("SYM_PERMALL"))
                .expect("the oracle permanent state restores");
        let startup = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
        runtime
    }

    fn profile_runtime(algorithms: &str) -> Box<Tpm2Runtime> {
        let json = format!(r#"{{"Name":"custom","Algorithms":"{algorithms}"}}"#);
        let profile = validate_user_profile(Some(json.as_bytes())).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let startup = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        assert_eq!(
            dispatch_bytes(&mut runtime, &startup),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00]
        );
        runtime
    }

    fn create_with_sensitive(
        runtime: &mut Tpm2Runtime,
        hierarchy: u32,
        in_public: &[u8],
        key: &[u8],
    ) -> Vec<u8> {
        let mut sensitive = Vec::new();
        push_tpm2b(&mut sensitive, &[]);
        push_tpm2b(&mut sensitive, key);
        let parameters = parameters(&sensitive, in_public, &[], &no_creation_pcr());
        dispatch_bytes(runtime, &command(hierarchy, &[], &parameters))
    }

    #[test]
    fn the_profile_minimum_key_sizes_match_the_libtpms_oracle_codes() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let cases: [(&str, Vec<u8>, u32); 9] = [
            (
                "rsa1024",
                vectors::asym_rsa_template(1024, 256),
                vectors::RC_MIN_RSA1024,
            ),
            (
                "rsa2048",
                vectors::asym_rsa_template(2048, 256),
                vectors::RC_MIN_RSA2048,
            ),
            (
                "ecc_p192",
                vectors::asym_ecc_template(0x0001, 256),
                vectors::RC_MIN_ECC_P192,
            ),
            (
                "ecc_p224",
                vectors::asym_ecc_template(0x0002, 256),
                vectors::RC_MIN_ECC_P224,
            ),
            (
                "ecc_p256",
                vectors::asym_ecc_template(0x0003, 256),
                vectors::RC_MIN_ECC_P256,
            ),
            (
                "aes128",
                vectors::symcipher_template(0x0006, 128, vectors::SYM_GENERATED_ATTRIBUTES),
                vectors::RC_MIN_AES128,
            ),
            (
                "aes192",
                vectors::symcipher_template(0x0006, 192, vectors::SYM_GENERATED_ATTRIBUTES),
                vectors::RC_MIN_AES192,
            ),
            (
                "camellia128",
                vectors::symcipher_template(0x0026, 128, vectors::SYM_GENERATED_ATTRIBUTES),
                vectors::RC_MIN_CAMELLIA128,
            ),
            (
                "tdes128",
                vectors::symcipher_template(0x0003, 128, vectors::SYM_GENERATED_ATTRIBUTES),
                vectors::RC_MIN_TDES128,
            ),
        ];
        for (label, template, expected) in cases {
            let mut runtime = profile_runtime(vectors::MIN_SIZE_PROFILE);
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_eq!(response_code(&response), expected, "{label}");
            assert!(
                runtime
                    .live
                    .objects
                    .iter()
                    .all(|object| object.attributes == 0),
                "{label} occupied a slot"
            );
        }
    }

    #[test]
    fn a_template_at_or_above_the_profile_minimum_is_accepted() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let cases: [(&str, Vec<u8>); 3] = [
            ("rsa3072", vectors::asym_rsa_template(3072, 256)),
            ("ecc_p384", vectors::asym_ecc_template(0x0004, 256)),
            (
                "tdes192",
                vectors::symcipher_template(0x0003, 192, vectors::SYM_GENERATED_ATTRIBUTES),
            ),
        ];
        for (label, template) in cases {
            let mut runtime = profile_runtime(vectors::MIN_SIZE_PROFILE);
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_eq!(response_code(&response), 0, "{label}");
        }
    }

    #[test]
    fn the_symmetric_parameter_of_a_storage_key_is_checked_against_the_profile() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let mut runtime = profile_runtime(vectors::MIN_SIZE_PROFILE);
        let template = vectors::asym_rsa_template(3072, 128);
        let response = create(&mut runtime, TPM_RH_OWNER, &template);
        assert_eq!(
            response_code(&response),
            vectors::RC_MIN_RSA3072_AES128_PARM
        );
    }

    #[test]
    fn a_disabled_curve_family_is_rejected_with_the_oracle_code() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        for (label, curve, expected) in [
            ("bn_p256", 0x0010u16, vectors::RC_NOBN_ECC_BN_P256),
            ("sm2_p256", 0x0020, vectors::RC_NOBN_ECC_SM2_P256),
        ] {
            let mut runtime = profile_runtime(vectors::NO_BN_CURVE_PROFILE);
            let template = vectors::asym_ecc_template(curve, 128);
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_eq!(response_code(&response), expected, "{label}");
        }
        let mut runtime = profile_runtime(vectors::NO_BN_CURVE_PROFILE);
        let template = vectors::asym_ecc_template(0x0004, 128);
        assert_eq!(
            response_code(&create(&mut runtime, TPM_RH_OWNER, &template)),
            0,
            "the enabled family still works"
        );
    }

    #[test]
    fn an_individually_disabled_curve_is_rejected_with_the_oracle_code() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        for (label, curve, expected) in [
            ("p192", 0x0001u16, vectors::RC_ONECURVE_ECC_P192),
            ("p521", 0x0005, vectors::RC_ONECURVE_ECC_P521),
        ] {
            let mut runtime = profile_runtime(vectors::TWO_CURVE_PROFILE);
            let template = vectors::asym_ecc_template(curve, 128);
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_eq!(response_code(&response), expected, "{label}");
        }
        for curve in [0x0003u16, 0x0004] {
            let mut runtime = profile_runtime(vectors::TWO_CURVE_PROFILE);
            let template = vectors::asym_ecc_template(curve, 128);
            assert_eq!(
                response_code(&create(&mut runtime, TPM_RH_OWNER, &template)),
                0,
                "curve {curve:#06x}"
            );
        }
    }

    #[test]
    fn a_disabled_symmetric_algorithm_is_rejected_before_its_key_size() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let mut runtime = profile_runtime(vectors::NO_TDES_PROFILE);
        let template = vectors::symcipher_template(0x0003, 128, vectors::SYM_GENERATED_ATTRIBUTES);
        let response = create(&mut runtime, TPM_RH_OWNER, &template);
        assert_eq!(response_code(&response), vectors::RC_NOTDES_TDES128);
    }

    #[test]
    fn generated_symmetric_primaries_match_the_libtpms_oracle_byte_for_byte() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let cases: [(&str, u16, u16, &[u8]); 3] = [
            ("tdes128", 0x0003, 128, vectors::vector("TDES128_GENERATED")),
            ("tdes192", 0x0003, 192, vectors::vector("TDES192_GENERATED")),
            ("aes128", 0x0006, 128, vectors::vector("AES128_GENERATED")),
        ];
        for (label, symmetric, key_bits, expected) in cases {
            let mut runtime = sym_permall_runtime();
            let template =
                vectors::symcipher_template(symmetric, key_bits, vectors::SYM_GENERATED_ATTRIBUTES);
            let response = create(&mut runtime, TPM_RH_OWNER, &template);
            assert_eq!(response, expected, "{label}");
        }
    }

    #[test]
    fn supplied_symmetric_primaries_match_the_libtpms_oracle_byte_for_byte() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let cases: [(&str, u16, u16, &[u8], &[u8]); 5] = [
            (
                "tdes128",
                0x0003,
                128,
                &vectors::TDES_TWO_KEY,
                vectors::vector("TDES128_SUPPLIED_OK"),
            ),
            (
                "tdes192",
                0x0003,
                192,
                &vectors::TDES_THREE_KEY,
                vectors::vector("TDES192_SUPPLIED_OK"),
            ),
            (
                "tdes128_no_parity",
                0x0003,
                128,
                &vectors::TDES_TWO_KEY_NO_PARITY,
                vectors::vector("TDES128_SUPPLIED_BAD_PARITY"),
            ),
            (
                "tdes192_repeated_ends",
                0x0003,
                192,
                &vectors::TDES_THREE_KEY_REPEATED_ENDS,
                vectors::vector("TDES192_SUPPLIED_SAME13"),
            ),
            (
                "aes128",
                0x0006,
                128,
                &vectors::AES_SUPPLIED_KEY,
                vectors::vector("AES128_SUPPLIED_OK"),
            ),
        ];
        for (label, symmetric, key_bits, key, expected) in cases {
            let mut runtime = sym_permall_runtime();
            let template =
                vectors::symcipher_template(symmetric, key_bits, vectors::SYM_SUPPLIED_ATTRIBUTES);
            let response = create_with_sensitive(&mut runtime, TPM_RH_OWNER, &template, key);
            assert_eq!(response, expected, "{label}");
        }
    }

    #[test]
    fn a_rejected_supplied_tdes_key_matches_the_libtpms_oracle_code() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let cases: [(&str, u16, &[u8], u32); 5] = [
            (
                "wrong_size_long",
                128,
                &vectors::TDES_THREE_KEY,
                vectors::RC_TDES128_SUPPLIED_SHORT,
            ),
            (
                "wrong_size_short",
                192,
                &vectors::TDES_TWO_KEY,
                vectors::RC_TDES192_SUPPLIED_SHORT,
            ),
            (
                "weak_component",
                128,
                &vectors::TDES_TWO_KEY_WEAK,
                vectors::RC_TDES128_SUPPLIED_WEAK,
            ),
            (
                "repeated_components",
                128,
                &vectors::TDES_TWO_KEY_REPEATED,
                vectors::RC_TDES128_SUPPLIED_SAME,
            ),
            (
                "repeated_tail",
                192,
                &vectors::TDES_THREE_KEY_REPEATED_TAIL,
                vectors::RC_TDES192_SUPPLIED_SAME23,
            ),
        ];
        for (label, key_bits, key, expected) in cases {
            let mut runtime = sym_permall_runtime();
            let template =
                vectors::symcipher_template(0x0003, key_bits, vectors::SYM_SUPPLIED_ATTRIBUTES);
            let response = create_with_sensitive(&mut runtime, TPM_RH_OWNER, &template, key);
            assert_eq!(response_code(&response), expected, "{label}");
            assert!(
                runtime
                    .live
                    .objects
                    .iter()
                    .all(|object| object.attributes == 0),
                "{label} occupied a slot"
            );
        }
    }

    #[test]
    fn a_generated_tdes_primary_derives_deterministically_from_the_hierarchy_seed() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        let template = vectors::symcipher_template(0x0003, 192, vectors::SYM_GENERATED_ATTRIBUTES);
        let mut first = started_runtime();
        let mut second = started_runtime();
        let left = decode(&create(&mut first, TPM_RH_OWNER, &template));
        let right = decode(&create(&mut second, TPM_RH_OWNER, &template));
        assert_eq!(left.out_public, right.out_public);

        let mut changed = started_runtime();
        if let Some(state) = changed.state.as_mut() {
            state.persistent.sp_seed =
                crate::library::tpm2::persistent::OwnedSecret::copy_of(&[0x3c; 64]);
        }
        let other = decode(&create(&mut changed, TPM_RH_OWNER, &template));
        assert_ne!(left.out_public, other.out_public);
    }

    #[test]
    fn a_generated_tdes_key_carries_odd_parity_and_distinct_components() {
        use crate::library::tpm2::oracles::create_primary as vectors;
        for key_bits in [128u16, 192] {
            let mut runtime = started_runtime();
            let template =
                vectors::symcipher_template(0x0003, key_bits, vectors::SYM_GENERATED_ATTRIBUTES);
            assert_eq!(
                response_code(&create(&mut runtime, TPM_RH_OWNER, &template)),
                0
            );
            let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[0].body else {
                panic!("an object body");
            };
            let key = body
                .sensitive
                .sensitive
                .as_ref()
                .expect("a symmetric key")
                .as_bytes()
                .to_vec();
            assert_eq!(key.len(), usize::from(key_bits) / 8);
            for byte in &key {
                assert_eq!(byte.count_ones() % 2, 1, "bits {key_bits} byte {byte:#04x}");
            }
            assert!(crate::library::tpm2::crypto::validate_tdes_key(&key));
        }
    }

    #[test]
    fn the_modifier_helper_only_decorates_undecorated_format_one_codes() {
        assert_eq!(add_modifier(0x082, RC_IN_PUBLIC), 0x2c2);
        assert_eq!(add_modifier(0x095, RC_IN_SENSITIVE), 0x1d5);
        assert_eq!(add_modifier(0x095, RC_CREATION_PCR), 0x4d5);
        assert_eq!(add_modifier(0x101, RC_IN_PUBLIC), 0x101, "format zero");
        assert_eq!(add_modifier(0x902, RC_IN_PUBLIC), 0x902, "format zero");
        assert_eq!(
            add_modifier(0x184, RC_IN_PUBLIC),
            0x184,
            "already decorated"
        );
    }
}
