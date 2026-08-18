use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_OBJECT_MEMORY, TPM_RC_SIZE, TPM_RC_TYPE,
};

use super::super::crypto::SeededRand;
use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_NULL, TPM_RH_OWNER, TPM_RH_PLATFORM};
use super::super::marshal::BlobWriter;
use super::super::object::{
    ATTR_DERIVATION, ATTR_EPS_HIERARCHY, ATTR_IS_PARENT, ATTR_PPS_HIERARCHY, ATTR_SPS_HIERARCHY,
};
use super::super::object_create::{
    ObjectSecrets, PRIMARY_OBJECT_CREATION, ParentSnapshot, create_object, empty_object_slots,
    is_object_handle, is_persistent_object_handle, primary_seed, resolve_any_object,
    sensitive_to_private, store_created_object, store_loaded_child_object,
};
use super::super::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use super::super::profile::{ATTRIBUTE_DRBG_CONTINUOUS_TEST, ATTRIBUTE_NO_ECC_KEY_DERIVATION};
use super::super::public::{PublicParms, StateFormatLimit, TPM_ALG_ECC, TPM_ALG_NULL, TPM_ALG_RSA};
use super::super::random::{store_live_drbg, take_live_drbg};
use super::super::runtime::Tpm2Runtime;
use super::super::template::{
    AlgorithmPolicy, TPMA_OBJECT_SENSITIVE_DATA_ORIGIN, TemplateReader, adjusted_auth_value,
    create_checks, marshal_public_area, object_name, parent_public_info, parse_template_to_public,
    public_attributes_validation, set_label_and_context,
};
use super::create_primary::{add_modifier, parse_sized_sensitive_create};
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_PARENT_HANDLE: TpmResult = TPM_RC_1;
const RC_IN_SENSITIVE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_PUBLIC: TpmResult = TPM_RC_P + TPM_RC_1 * 2;

const TPMT_PUBLIC_MARSHALED_LIMIT: usize = 484;
const TPM_MAX_DERIVATION_BITS: u32 = 8192;

struct ResolvedParent {
    slot_attributes: u32,
    body: Option<Box<OwnedObjectBody>>,
    persistent: bool,
}

fn resolve_parent(runtime: &Tpm2Runtime, handle: u32) -> Result<Option<ResolvedParent>, TpmResult> {
    if !is_object_handle(handle) {
        return Ok(None);
    }
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    let body = match &object.body {
        OwnedAnyObjectBody::Object(body) => Some(body.clone()),
        _ => None,
    };
    Ok(Some(ResolvedParent {
        slot_attributes: object.attributes,
        body,
        persistent: is_persistent_object_handle(handle),
    }))
}

fn object_hierarchy(body: &OwnedObjectBody, slot_attributes: u32) -> u32 {
    body.hierarchy.unwrap_or({
        if slot_attributes & ATTR_SPS_HIERARCHY != 0 {
            TPM_RH_OWNER
        } else if slot_attributes & ATTR_EPS_HIERARCHY != 0 {
            TPM_RH_ENDORSEMENT
        } else if slot_attributes & ATTR_PPS_HIERARCHY != 0 {
            TPM_RH_PLATFORM
        } else {
            TPM_RH_NULL
        }
    })
}

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parent_handle = *frame.handles.first().ok_or(TPM_RC_FAILURE)?;
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let policy = AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    };
    let continuous_test = state
        .profile
        .attribute_enabled(ATTRIBUTE_DRBG_CONTINUOUS_TEST);
    let no_ecc_derivation = state
        .profile
        .attribute_enabled(ATTRIBUTE_NO_ECC_KEY_DERIVATION);
    let profile_seed_compat_level = state.profile.seed_compat_level();

    let mut reader = TemplateReader::new(frame.parameters);
    let (user_auth_input, sensitive_data_input) = parse_sized_sensitive_create(&mut reader)
        .map_err(|code| add_modifier(code, RC_IN_SENSITIVE))?;
    let template = reader
        .tpm2b(TPMT_PUBLIC_MARSHALED_LIMIT)
        .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let parent = resolve_parent(runtime, parent_handle)?;
    let derivation = parent
        .as_ref()
        .is_some_and(|parent| parent.slot_attributes & ATTR_DERIVATION != 0);
    if let Some(parent) = &parent
        && parent.slot_attributes & (ATTR_IS_PARENT | ATTR_DERIVATION) == 0
    {
        return Err(TPM_RC_TYPE + RC_PARENT_HANDLE);
    }

    let (slot, object_handle) = {
        let mut free_slots = empty_object_slots(runtime);
        if parent.as_ref().is_some_and(|parent| parent.persistent) {
            free_slots.next();
        }
        free_slots.next().ok_or(TPM_RC_OBJECT_MEMORY)?
    };

    let (mut public, mut label_context) = parse_template_to_public(&template, &policy, derivation)
        .map_err(|code| code + RC_IN_PUBLIC)?;

    let user_auth = adjusted_auth_value(&user_auth_input, public.name_alg)
        .map_err(|_| TPM_RC_SIZE + RC_IN_SENSITIVE)?;

    let mut sensitive_data = sensitive_data_input;
    let seed_compat_level;
    let mut rand;
    if derivation {
        let parent_body = parent
            .as_ref()
            .and_then(|parent| parent.body.as_deref())
            .ok_or(TPM_RC_FAILURE)?;
        let PublicParms::KeyedHash(scheme) = &parent_body.public.parameters else {
            return Err(TPM_RC_FAILURE);
        };
        if public.object_type == TPM_ALG_RSA {
            return Err(TPM_RC_TYPE + RC_IN_PUBLIC);
        }
        if public.object_type == TPM_ALG_ECC && no_ecc_derivation {
            return Err(TPM_RC_TYPE + RC_IN_PUBLIC);
        }
        if public.object_attributes & TPMA_OBJECT_SENSITIVE_DATA_ORIGIN != 0 {
            return Err(TPM_RC_ATTRIBUTES);
        }
        let parent_info = parent_public_info(&parent_body.public, true);
        public_attributes_validation(Some(&parent_info), &public)
            .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
        set_label_and_context(&mut label_context, &sensitive_data)?;
        seed_compat_level = parent_body.seed_compat_level;
        rand = SeededRand::instantiate_seeded_kdf(
            scheme.hash_alg.unwrap_or(TPM_ALG_NULL),
            parent_body
                .sensitive
                .sensitive
                .as_ref()
                .map_or(&[][..], |secret| secret.as_bytes()),
            &label_context.label,
            &label_context.context,
            TPM_MAX_DERIVATION_BITS,
            seed_compat_level,
        )?;
        sensitive_data.clear();
    } else {
        let parent_info = parent
            .as_ref()
            .and_then(|parent| parent.body.as_deref())
            .map(|body| parent_public_info(&body.public, false));
        create_checks(parent_info.as_ref(), &public, sensitive_data.len())
            .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
        if parent.is_none() {
            let (seed, level) = primary_seed(runtime, parent_handle)?;
            seed_compat_level = level;
            let template_name = object_name(&public)?;
            rand = SeededRand::instantiate(
                seed,
                PRIMARY_OBJECT_CREATION,
                &template_name,
                &sensitive_data,
                seed_compat_level,
                continuous_test,
            )?;
        } else {
            seed_compat_level = profile_seed_compat_level;
            rand = SeededRand::from_live_drbg(take_live_drbg(runtime)?, runtime.entropy);
        }
    }

    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    let sh_proof = persistent.sh_proof.as_bytes().to_vec();
    let eh_proof = persistent.eh_proof.as_bytes().to_vec();
    let secrets = ObjectSecrets {
        sh_proof: &sh_proof,
        eh_proof: &eh_proof,
    };
    let eps_primary = parent.is_none() && parent_handle == TPM_RH_ENDORSEMENT;

    let created = create_object(
        &mut public,
        user_auth,
        &sensitive_data,
        eps_primary,
        &secrets,
        &mut rand,
    );
    let (created, out_private) = created.and_then(|created| {
        let out_private = match parent.as_ref().filter(|_| !derivation) {
            Some(parent) => {
                let body = parent.body.as_deref().ok_or(TPM_RC_FAILURE)?;
                sensitive_to_private(
                    &created.sensitive,
                    &created.name,
                    &body.public,
                    body.sensitive.seed_value.as_bytes(),
                    created.public.name_alg,
                    &mut rand,
                )?
            }
            None => Vec::new(),
        };
        Ok((created, out_private))
    })?;
    if let Some(drbg) = rand.into_live_drbg() {
        store_live_drbg(runtime, &drbg);
    }

    let out_public = marshal_public_area(&created.public)?;
    let name = created.name.clone();

    match &parent {
        Some(parent) => {
            let body = parent.body.as_deref().ok_or(TPM_RC_FAILURE)?;
            let snapshot = ParentSnapshot {
                slot_attributes: parent.slot_attributes,
                hierarchy: object_hierarchy(body, parent.slot_attributes),
                qualified_name: body.qualified_name.clone(),
            };
            store_loaded_child_object(runtime, slot, &snapshot, seed_compat_level, created)?;
        }
        None => {
            store_created_object(runtime, slot, parent_handle, seed_compat_level, created)?;
        }
    }

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&out_private).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&out_public).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&name).map_err(|_| TPM_RC_SIZE)?;

    Ok(CommandOutput::with_handle(
        object_handle,
        writer.into_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::registry::{self, TPM_CC_CREATE_LOADED};
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::oracles::create_loaded::vector;
    use crate::library::tpm2::process::process;
    use crate::library::tpm2::{VolatileDecodeBoundary, restore_permanent_blob_for_test};

    const TPM_RH_OWNER_H: u32 = 0x4000_0001;
    const TPM_RH_NULL_H: u32 = 0x4000_0007;
    const TPM_RH_ENDORSEMENT_H: u32 = 0x4000_000b;

    const AES_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];
    const TDES_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x60, 0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];
    const AES_PROVIDED_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];
    const TDES_PROVIDED_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];
    const SRK_TEMPLATE: [u8; 26] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const SRK_NODA_CLEAR_TEMPLATE: [u8; 26] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x00, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const RSA_SIGN_TEMPLATE: [u8; 24] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x04, 0x04, 0x72, 0x00, 0x00, 0x00, 0x10, 0x00, 0x14, 0x00,
        0x0b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const DERIVATION_PARENT_TEMPLATE: [u8; 18] = [
        0x00, 0x08, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
        0x22, 0x00, 0x00,
    ];
    const TDES_SRK_TEMPLATE: [u8; 26] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const CAMELLIA_SRK_TEMPLATE: [u8; 26] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x26, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const TDES_SRK_BAD_KEYBITS_TEMPLATE: [u8; 26] = [
        0x00, 0x01, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x03, 0x00, 0x40, 0x00,
        0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    const SYMCIPHER_CMAC_MODE_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x3f, 0x00, 0x00,
    ];
    const CAMELLIA_SYMCIPHER_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x60, 0x00, 0x00, 0x00, 0x26, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];

    fn push_tpm2b(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn build(command_code: u32, handles: &[u32], password: &[u8], params: &[u8]) -> Vec<u8> {
        let mut out = vec![0x80, 0x02, 0, 0, 0, 0];
        out.extend_from_slice(&command_code.to_be_bytes());
        for handle in handles {
            out.extend_from_slice(&handle.to_be_bytes());
        }
        out.extend_from_slice(&(9 + password.len() as u32).to_be_bytes());
        out.extend_from_slice(&0x4000_0009u32.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        push_tpm2b(&mut out, password);
        out.extend_from_slice(params);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    fn cl_params(user_auth: &[u8], data: &[u8], template: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(4 + user_auth.len() as u16 + data.len() as u16).to_be_bytes());
        push_tpm2b(&mut out, user_auth);
        push_tpm2b(&mut out, data);
        push_tpm2b(&mut out, template);
        out
    }

    fn cl_command(
        parent: u32,
        password: &[u8],
        user_auth: &[u8],
        data: &[u8],
        template: &[u8],
    ) -> Vec<u8> {
        build(
            TPM_CC_CREATE_LOADED,
            &[parent],
            password,
            &cl_params(user_auth, data, template),
        )
    }

    fn cp_command(hierarchy: u32, user_auth: &[u8], template: &[u8]) -> Vec<u8> {
        let mut params = Vec::new();
        params.extend_from_slice(&(4 + user_auth.len() as u16).to_be_bytes());
        push_tpm2b(&mut params, user_auth);
        push_tpm2b(&mut params, &[]);
        push_tpm2b(&mut params, template);
        params.extend_from_slice(&0u16.to_be_bytes());
        params.extend_from_slice(&0u32.to_be_bytes());
        build(0x0000_0131, &[hierarchy], &[], &params)
    }

    fn flush_command(handle: u32) -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0e];
        out.extend_from_slice(&0x0000_0165u32.to_be_bytes());
        out.extend_from_slice(&handle.to_be_bytes());
        out
    }

    fn ecc_derive_template(label: &[u8], context: &[u8], attributes: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0023u16.to_be_bytes());
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        push_tpm2b(&mut out, label);
        push_tpm2b(&mut out, context);
        out
    }

    fn rsa_derive_template() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0001u16.to_be_bytes());
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&0x0002_0452u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0010u16.to_be_bytes());
        out.extend_from_slice(&0x0800u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }

    fn derive_sensitive(label: &[u8], context: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_tpm2b(&mut out, label);
        push_tpm2b(&mut out, context);
        out
    }

    fn cap_cc_command() -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
        out.extend_from_slice(&0x0000_017au32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&0x191u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out
    }

    fn cap_da_command() -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
        out.extend_from_slice(&0x0000_017au32.to_be_bytes());
        out.extend_from_slice(&6u32.to_be_bytes());
        out.extend_from_slice(&0x20eu32.to_be_bytes());
        out.extend_from_slice(&4u32.to_be_bytes());
        out
    }

    fn define_da_index_command() -> Vec<u8> {
        let mut params = Vec::new();
        push_tpm2b(&mut params, b"test");
        let mut public = Vec::new();
        public.extend_from_slice(&0x0100_0000u32.to_be_bytes());
        public.extend_from_slice(&0x000bu16.to_be_bytes());
        public.extend_from_slice(&0x0004_0004u32.to_be_bytes());
        public.extend_from_slice(&0u16.to_be_bytes());
        public.extend_from_slice(&1u16.to_be_bytes());
        push_tpm2b(&mut params, &public);
        build(0x0000_012a, &[TPM_RH_OWNER_H], &[], &params)
    }

    fn nv_write_empty_command(index: u32, password: &[u8]) -> Vec<u8> {
        let mut params = Vec::new();
        push_tpm2b(&mut params, &[]);
        params.extend_from_slice(&0u16.to_be_bytes());
        build(0x0000_0137, &[index, index], password, &params)
    }

    fn evict_command(object: u32, persistent: u32) -> Vec<u8> {
        build(
            0x0000_0120,
            &[TPM_RH_OWNER_H, object],
            &[],
            &persistent.to_be_bytes(),
        )
    }

    fn unreachable_entropy(_buffer: &mut [u8]) -> Result<(), TpmResult> {
        panic!("the replay must not draw host entropy");
    }

    fn restored_runtime(clock: &SteppingClock) -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_BASE"))
            .expect("the oracle permanent state restores");
        crate::library::tpm2::attach_volatile_blob(
            &mut runtime,
            vector("VOLATILE_BASE"),
            clock,
            VolatileDecodeBoundary::Restore,
        )
        .expect("the oracle volatile state attaches");
        runtime.entropy = unreachable_entropy;
        runtime
    }

    #[track_caller]
    fn exec(runtime: &mut Tpm2Runtime, clock: &SteppingClock, label: &str, bytes: Vec<u8>) {
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response = process(runtime, 0, &input, clock, |_| Ok(()))
            .unwrap_or_else(|code| panic!("{label} failed with {code:#x}"));
        assert_eq!(response, vector(label), "{label}");
    }

    fn replay_case(steps: &[(&str, Vec<u8>)]) -> Box<Tpm2Runtime> {
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        for (label, bytes) in steps {
            exec(&mut runtime, &clock, label, bytes.clone());
        }
        runtime
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = registry::find(TPM_CC_CREATE_LOADED).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x1200_0191);
        assert!(descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role);
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let oracle = vector("CAP_CC_CREATE_LOADED");
        assert_eq!(
            &oracle[oracle.len() - 4..],
            0x1200_0191u32.to_be_bytes(),
            "the vendored TPM reports TPMA_CC 0x12000191"
        );
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        let bytes = cap_cc_command();
        let input = CommandInput::new(bytes.len() as u32, bytes);
        let response =
            process(&mut runtime, 0, &input, &clock, |_| Ok(())).expect("the query succeeds");
        assert_eq!(
            &response[response.len() - 4..],
            0x1200_0191u32.to_be_bytes(),
            "this registry reports the same attributes"
        );
        assert_eq!(&response[..10], &oracle[..10], "header and response code");
        assert_eq!(&response[11..], &oracle[11..], "capability payload");
        assert_eq!(
            response[10], 0,
            "the vendored TPM implements commands beyond 0x191, so only its moreData flag differs"
        );
        assert_eq!(oracle[10], 1);
    }

    #[test]
    fn primary_symmetric_objects_match_the_oracle() {
        replay_case(&[
            (
                "AES_PRIMARY_OWNER",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            ),
            ("FLUSH_AES", flush_command(0x8000_0000)),
        ]);
        replay_case(&[(
            "TDES_PRIMARY_OWNER",
            cl_command(TPM_RH_OWNER_H, &[], &[], &[], &TDES_TEMPLATE),
        )]);
        replay_case(&[(
            "AES_PRIMARY_ENDORSEMENT",
            cl_command(TPM_RH_ENDORSEMENT_H, &[], &[], &[], &AES_TEMPLATE),
        )]);
        replay_case(&[(
            "AES_PRIMARY_NULL",
            cl_command(TPM_RH_NULL_H, &[], &[], &[], &AES_TEMPLATE),
        )]);
    }

    #[test]
    fn provided_symmetric_keys_match_the_oracle() {
        replay_case(&[(
            "AES_PROVIDED_KEY",
            cl_command(
                TPM_RH_OWNER_H,
                &[],
                &[],
                b"0123456789abcdef",
                &AES_PROVIDED_TEMPLATE,
            ),
        )]);
        replay_case(&[(
            "TDES_WEAK_PROVIDED_KEY",
            cl_command(
                TPM_RH_OWNER_H,
                &[],
                &[],
                &[0x01; 16],
                &TDES_PROVIDED_TEMPLATE,
            ),
        )]);
        replay_case(&[(
            "AES_PROVIDED_KEY_WRONG_SIZE",
            cl_command(
                TPM_RH_OWNER_H,
                &[],
                &[],
                b"0123456789",
                &AES_PROVIDED_TEMPLATE,
            ),
        )]);
    }

    #[test]
    fn an_ordinary_child_under_a_storage_parent_matches_the_oracle() {
        replay_case(&[
            (
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            (
                "CHILD_AES_UNDER_PARENT",
                cl_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE),
            ),
            ("FLUSH_CHILD", flush_command(0x8000_0001)),
            (
                "CHILD_AES_AGAIN",
                cl_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn derived_ecc_children_match_the_oracle() {
        let child = |label: &[u8], context: &[u8]| ecc_derive_template(label, context, 0x0002_0452);
        replay_case(&[
            (
                "CP_DERIVATION_PARENT",
                cp_command(TPM_RH_ENDORSEMENT_H, &[], &DERIVATION_PARENT_TEMPLATE),
            ),
            (
                "DERIVED_ECC_EMPTY",
                cl_command(0x8000_0000, &[], &[], &[], &child(&[], &[])),
            ),
            ("FLUSH_DERIVED_1", flush_command(0x8000_0001)),
            (
                "DERIVED_ECC_TEMPLATE_LABEL",
                cl_command(0x8000_0000, &[], &[], &[], &child(b"L1", &[])),
            ),
            ("FLUSH_DERIVED_2", flush_command(0x8000_0001)),
            (
                "DERIVED_ECC_TEMPLATE_CONTEXT",
                cl_command(0x8000_0000, &[], &[], &[], &child(&[], b"C1")),
            ),
            ("FLUSH_DERIVED_3", flush_command(0x8000_0001)),
            (
                "DERIVED_ECC_SENSITIVE_LABEL",
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &derive_sensitive(b"L2", &[]),
                    &child(&[], &[]),
                ),
            ),
            ("FLUSH_DERIVED_4", flush_command(0x8000_0001)),
            (
                "DERIVED_ECC_SENSITIVE_CONTEXT",
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &derive_sensitive(&[], b"C2"),
                    &child(&[], &[]),
                ),
            ),
            ("FLUSH_DERIVED_5", flush_command(0x8000_0001)),
            (
                "DERIVED_ECC_TEMPLATE_WINS",
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &derive_sensitive(b"L2", b"C2"),
                    &child(b"L1", b"C1"),
                ),
            ),
            ("FLUSH_DERIVED_6", flush_command(0x8000_0001)),
            (
                "DERIVED_ECC_MIXED_SOURCES",
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &derive_sensitive(b"L2", b"C2"),
                    &child(b"L1", &[]),
                ),
            ),
            ("FLUSH_DERIVED_7", flush_command(0x8000_0001)),
            (
                "DERIVED_RSA_REJECTED",
                cl_command(0x8000_0000, &[], &[], &[], &rsa_derive_template()),
            ),
            (
                "DERIVED_SDO_SET",
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &[],
                    &ecc_derive_template(&[], &[], 0x0002_0472),
                ),
            ),
            (
                "DERIVED_SENSITIVE_TRUNCATED",
                cl_command(0x8000_0000, &[], &[], &[0x00], &child(&[], &[])),
            ),
            ("DERIVED_SENSITIVE_OVERSIZED_LABEL", {
                let mut bad = Vec::new();
                push_tpm2b(&mut bad, &[0x41; 33]);
                push_tpm2b(&mut bad, &[]);
                cl_command(0x8000_0000, &[], &[], &bad, &child(&[], &[]))
            }),
        ]);
    }

    #[test]
    fn parent_type_and_availability_errors_match_the_oracle() {
        replay_case(&[
            (
                "CP_SIGNING_KEY",
                cp_command(TPM_RH_OWNER_H, &[], &RSA_SIGN_TEMPLATE),
            ),
            (
                "PARENT_NOT_A_PARENT",
                cl_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE),
            ),
        ]);
        replay_case(&[
            (
                "UNLOADED_TRANSIENT_PARENT",
                cl_command(0x8000_0002, &[], &[], &[], &AES_TEMPLATE),
            ),
            (
                "UNDEFINED_PERSISTENT_PARENT",
                cl_command(0x8100_0000, &[], &[], &[], &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn a_full_object_table_matches_the_oracle() {
        replay_case(&[
            (
                "SLOT_FILL_1",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            ),
            (
                "SLOT_FILL_2",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            ),
            (
                "SLOT_FILL_3",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            ),
            (
                "NO_FREE_SLOT",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn malformed_parameters_match_the_oracle() {
        replay_case(&[(
            "OVERSIZED_USERAUTH",
            cl_command(TPM_RH_OWNER_H, &[], &[0x61; 33], &[], &AES_TEMPLATE),
        )]);
        replay_case(&[
            (
                "TEMPLATE_TRUNCATED_BODY",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE[..14]),
            ),
            ("TEMPLATE_TRAILING_BYTE", {
                let mut template = AES_TEMPLATE.to_vec();
                template.push(0x00);
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &template)
            }),
            (
                "TEMPLATE_EMPTY",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &[]),
            ),
            ("TEMPLATE_BAD_TYPE", {
                let mut template = AES_TEMPLATE.to_vec();
                template[0..2].copy_from_slice(&0x0010u16.to_be_bytes());
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &template)
            }),
        ]);
    }

    #[test]
    fn truncated_commands_match_the_oracle() {
        let full = cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE);
        assert_eq!(full.len(), 0x35);
        let mut steps: Vec<(String, Vec<u8>)> = Vec::new();
        for cut in [12usize, 16, 20, 27, 29, 31, 33, 35, 45, 52] {
            let mut shortened = full[..cut].to_vec();
            shortened[2..6].copy_from_slice(&(cut as u32).to_be_bytes());
            steps.push((format!("TRUNCATED_AT_{cut:02}"), shortened));
        }
        let mut extended = full.clone();
        extended.extend_from_slice(&[0x00, 0x00]);
        let size = (extended.len() as u32).to_be_bytes();
        extended[2..6].copy_from_slice(&size);
        steps.push(("TRAILING_COMMAND_BYTES".into(), extended));

        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        for (label, bytes) in &steps {
            exec(&mut runtime, &clock, label, bytes.clone());
        }
    }

    #[test]
    fn authorization_behaviour_matches_the_oracle() {
        replay_case(&[("NO_SESSIONS_AUTH_MISSING", {
            let mut out = vec![0x80, 0x01, 0, 0, 0, 0];
            out.extend_from_slice(&TPM_CC_CREATE_LOADED.to_be_bytes());
            out.extend_from_slice(&TPM_RH_OWNER_H.to_be_bytes());
            out.extend_from_slice(&cl_params(&[], &[], &AES_TEMPLATE));
            let size = (out.len() as u32).to_be_bytes();
            out[2..6].copy_from_slice(&size);
            out
        })]);
        let runtime = replay_case(&[
            (
                "CP_AUTHED_PARENT",
                cp_command(TPM_RH_OWNER_H, b"parent", &SRK_TEMPLATE),
            ),
            (
                "CHILD_WRONG_AUTH",
                cl_command(0x8000_0000, b"wrong", &[], &[], &AES_TEMPLATE),
            ),
            (
                "CHILD_RIGHT_AUTH",
                cl_command(0x8000_0000, b"parent", &[], &[], &AES_TEMPLATE),
            ),
        ]);
        assert!(
            !runtime.live.da_used,
            "the noDA parent's authorizations never perform the first-use \
             DA transition, even on a fresh cycle"
        );
        assert_ne!(
            runtime
                .state
                .as_ref()
                .expect("state")
                .persistent
                .orderly_state,
            0xfffe,
            "no SU_DA_USED marker was recorded for the exempt parent"
        );
    }

    #[test]
    fn dictionary_attack_protection_matches_the_oracle() {
        replay_case(&[
            (
                "CP_DA_PARENT",
                cp_command(TPM_RH_OWNER_H, b"parent", &SRK_NODA_CLEAR_TEMPLATE),
            ),
            ("DEFINE_DA_INDEX", define_da_index_command()),
            ("NVWRITE_DA_RETRY", nv_write_empty_command(0x0100_0000, &[])),
            ("CAP_DA_BEFORE_FAIL", cap_da_command()),
            (
                "DA_CHILD_WRONG_AUTH",
                cl_command(0x8000_0000, b"wrong", &[], &[], &AES_TEMPLATE),
            ),
            ("CAP_DA_AFTER_FAIL", cap_da_command()),
            (
                "DA_CHILD_RIGHT_AUTH",
                cl_command(0x8000_0000, b"parent", &[], &[], &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn parent_template_parameter_errors_match_the_oracle() {
        replay_case(&[
            (
                "CL_TDES_PARENT_BAD_KEYBITS",
                cl_command(
                    TPM_RH_OWNER_H,
                    &[],
                    &[],
                    &[],
                    &TDES_SRK_BAD_KEYBITS_TEMPLATE,
                ),
            ),
            (
                "CL_SYMCIPHER_CMAC_MODE",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &SYMCIPHER_CMAC_MODE_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn the_first_da_protected_use_is_uniform_across_entity_types() {
        let nv = replay_case(&[
            ("DA2_DEFINE_INDEX", define_da_index_command()),
            (
                "DA2_NV_FIRST_USE",
                nv_write_empty_command(0x0100_0000, b"test"),
            ),
            (
                "DA2_NV_AFTER_USED_OK",
                nv_write_empty_command(0x0100_0000, b"test"),
            ),
            (
                "DA2_NV_WRONG_AFTER_USED",
                nv_write_empty_command(0x0100_0000, b"nope"),
            ),
            ("CAP_DA2_NV", cap_da_command()),
        ]);
        let transient = replay_case(&[
            (
                "CP_DA2_TRANSIENT_PARENT",
                cp_command(TPM_RH_OWNER_H, b"parent", &SRK_NODA_CLEAR_TEMPLATE),
            ),
            (
                "DA2_TRANSIENT_FIRST_USE",
                cl_command(0x8000_0000, b"parent", &[], &[], &AES_TEMPLATE),
            ),
            (
                "DA2_TRANSIENT_AFTER_USED_OK",
                cl_command(0x8000_0000, b"parent", &[], &[], &AES_TEMPLATE),
            ),
            ("CAP_DA2_TRANSIENT", cap_da_command()),
        ]);
        let persistent = replay_case(&[
            (
                "CP_DA2_PERSISTENT_PARENT",
                cp_command(TPM_RH_OWNER_H, b"parent", &SRK_NODA_CLEAR_TEMPLATE),
            ),
            ("DA2_EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
            ("DA2_FLUSH_TRANSIENT", flush_command(0x8000_0000)),
            (
                "DA2_PERSISTENT_FIRST_USE",
                cl_command(0x8100_0100, b"parent", &[], &[], &AES_TEMPLATE),
            ),
            (
                "DA2_PERSISTENT_AFTER_USED_OK",
                cl_command(0x8100_0100, b"parent", &[], &[], &AES_TEMPLATE),
            ),
            (
                "DA2_PERSISTENT_WRONG_AFTER_USED",
                cl_command(0x8100_0100, b"wrong", &[], &[], &AES_TEMPLATE),
            ),
            ("CAP_DA2_PERSISTENT", cap_da_command()),
        ]);

        assert_eq!(
            vector("DA2_NV_FIRST_USE"),
            vector("DA2_TRANSIENT_FIRST_USE"),
            "the first-use retry is identical for NV and transient-object auth"
        );
        assert_eq!(
            vector("DA2_TRANSIENT_FIRST_USE"),
            vector("DA2_PERSISTENT_FIRST_USE"),
            "the first-use retry is identical for transient and persistent auth"
        );
        assert_eq!(
            vector("DA2_TRANSIENT_AFTER_USED_OK"),
            vector("DA2_PERSISTENT_AFTER_USED_OK"),
            "the same parent secret yields the same child either way"
        );
        for runtime in [&nv, &transient, &persistent] {
            assert!(runtime.live.da_used, "the first use records the marker");
            assert_eq!(
                runtime
                    .state
                    .as_ref()
                    .expect("state")
                    .persistent
                    .orderly_state,
                0xfffe,
                "the first use commits the SU_DA_USED orderly marker"
            );
        }
        assert_eq!(
            nv.state.as_ref().expect("state").persistent.failed_tries,
            1,
            "only the actual wrong password increments failedTries"
        );
        assert_eq!(
            transient
                .state
                .as_ref()
                .expect("state")
                .persistent
                .failed_tries,
            0,
            "a retried then successful authorization never fails a try"
        );
        assert_eq!(
            persistent
                .state
                .as_ref()
                .expect("state")
                .persistent
                .failed_tries,
            1
        );
        use crate::library::tpm2::object::ATTR_OCCUPIED;
        assert_eq!(
            persistent
                .live
                .objects
                .iter()
                .map(|object| object.attributes & ATTR_OCCUPIED != 0)
                .collect::<Vec<bool>>(),
            [false, true, false],
            "only the successful child occupies a slot, one past the \
             persistent parent's temporary load slot"
        );
    }

    #[test]
    fn a_profile_without_camellia_matches_the_oracle_error() {
        const NO_CAMELLIA_PROFILE: &[u8] = br#"{"Name":"custom","Algorithms":"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,cmac,ctr,ofb,cbc,cfb,ecb"}"#;
        let responses = dispatch_with_profile(
            NO_CAMELLIA_PROFILE,
            &[cl_command(
                TPM_RH_OWNER_H,
                &[],
                &[],
                &[],
                &CAMELLIA_SYMCIPHER_TEMPLATE,
            )],
        );
        assert_eq!(responses[0], vector("PROFILE_NO_CAMELLIA_CREATE"));
    }

    #[test]
    fn the_command_is_rejected_before_startup() {
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_BASE"))
            .expect("the oracle permanent state restores");
        exec(
            &mut runtime,
            &clock,
            "BEFORE_STARTUP",
            cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
        );
    }

    fn dispatch_with_profile(profile: &[u8], commands: &[Vec<u8>]) -> Vec<Vec<u8>> {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        fn deterministic_entropy(buffer: &mut [u8]) -> Result<(), TpmResult> {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x29;
            }
            Ok(())
        }

        let profile = validate_user_profile(Some(profile)).expect("the profile validates");
        let state = manufacture_state(profile, deterministic_entropy).expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        runtime.entropy = deterministic_entropy;
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let startup = vec![
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
        ];
        let input = CommandInput::new(startup.len() as u32, startup);
        let response = process(&mut runtime, 0, &input, &clock, |_| Ok(())).expect("startup runs");
        assert_eq!(response[6..], [0, 0, 0, 0], "startup succeeds");
        commands
            .iter()
            .map(|bytes| {
                let input = CommandInput::new(bytes.len() as u32, bytes.clone());
                process(&mut runtime, 0, &input, &clock, |_| Ok(())).expect("the command runs")
            })
            .collect()
    }

    #[test]
    fn a_profile_without_tdes_matches_the_oracle_error() {
        const NO_TDES_PROFILE: &[u8] = br#"{"Name":"custom","Algorithms":"rsa,rsa-min-size=1024,sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb"}"#;
        let responses = dispatch_with_profile(
            NO_TDES_PROFILE,
            &[cl_command(TPM_RH_OWNER_H, &[], &[], &[], &TDES_TEMPLATE)],
        );
        assert_eq!(responses[0], vector("PROFILE_NO_TDES_CREATE"));
    }

    #[test]
    fn a_profile_without_ecc_derivation_matches_the_oracle_error() {
        const NO_ECC_DERIVE_PROFILE: &[u8] =
            br#"{"Name":"custom","Attributes":"no-ecc-key-derivation"}"#;
        let responses = dispatch_with_profile(
            NO_ECC_DERIVE_PROFILE,
            &[
                cp_command(TPM_RH_ENDORSEMENT_H, &[], &DERIVATION_PARENT_TEMPLATE),
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &[],
                    &ecc_derive_template(&[], &[], 0x0002_0452),
                ),
            ],
        );
        assert_eq!(responses[0][6..10], [0, 0, 0, 0], "the parent is created");
        assert_eq!(responses[1], vector("PROFILE_NO_ECC_DERIVE_CREATE"));
    }

    mod state {
        use super::*;
        use crate::library::tpm2::nv::any_object_image;
        use crate::library::tpm2::persistent::{
            OwnedAnyObject, PersistentAllEnvelope, materialize_persistent_state,
            persistent_all_store,
        };
        use crate::library::tpm2::runtime::commit_restored_state;
        use crate::library::tpm2::volatile::{CURRENT_OBJECT_VERSION, OwnedVolatileState};
        use crate::library::tpm2::{
            decode_volatile_blob, parse_persistent_all_payload, volatile_validation_context,
        };

        fn decode_oracle_volatile(label: &str) -> OwnedVolatileState {
            let permall = vector(&format!("PERMALL_{label}"));
            let envelope = PersistentAllEnvelope::parse(permall).expect("the envelope parses");
            let decoded = parse_persistent_all_payload(&envelope).expect("the payload decodes");
            let state = materialize_persistent_state(decoded).expect("the state materializes");
            let runtime = commit_restored_state(state).expect("the state commits");
            let context = volatile_validation_context(&runtime).expect("the context builds");
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            decode_volatile_blob(
                &context,
                vector(&format!("VOLATILE_{label}")),
                &clock,
                VolatileDecodeBoundary::Validate,
            )
            .expect("the volatile record decodes")
        }

        fn object_images(objects: &[OwnedAnyObject]) -> Vec<Vec<u8>> {
            objects
                .iter()
                .map(|object| {
                    any_object_image(object, CURRENT_OBJECT_VERSION).expect("the object serializes")
                })
                .collect()
        }

        #[track_caller]
        fn assert_permall_matches(runtime: &Tpm2Runtime, label: &str) {
            let stored = persistent_all_store(runtime.state.as_ref().expect("state"))
                .expect("the state serializes");
            assert_eq!(stored, vector(label), "{label}");
        }

        #[test]
        fn a_created_primary_matches_the_oracle_volatile_object_slots() {
            let runtime = replay_case(&[(
                "AES_PRIMARY_OWNER",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            )]);
            let oracle = decode_oracle_volatile("AFTER_AES");
            assert_eq!(
                object_images(&runtime.live.objects),
                object_images(&oracle.objects),
                "the loaded object slots serialize to the oracle bytes"
            );
            assert_permall_matches(&runtime, "PERMALL_AFTER_AES");
        }

        #[test]
        fn tdes_and_camellia_storage_parents_match_the_oracle() {
            for (parent_label, parent_template, child_label, boundary, flush_label) in [
                (
                    "CP_TDES_PARENT",
                    &TDES_SRK_TEMPLATE,
                    "CHILD_AES_UNDER_TDES_PARENT",
                    "AFTER_TDES_CHILD",
                    "FLUSH_TDES_CHILD_AFTER_RESUME",
                ),
                (
                    "CP_CAMELLIA_PARENT",
                    &CAMELLIA_SRK_TEMPLATE,
                    "CHILD_AES_UNDER_CAMELLIA_PARENT",
                    "AFTER_CAMELLIA_CHILD",
                    "FLUSH_CAMELLIA_CHILD_AFTER_RESUME",
                ),
            ] {
                let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
                let mut runtime = restored_runtime(&clock);
                exec(
                    &mut runtime,
                    &clock,
                    parent_label,
                    cp_command(TPM_RH_OWNER_H, &[], parent_template),
                );
                let parent_before =
                    any_object_image(&runtime.live.objects[0], CURRENT_OBJECT_VERSION).unwrap();
                exec(
                    &mut runtime,
                    &clock,
                    child_label,
                    cl_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE),
                );
                assert_eq!(
                    any_object_image(&runtime.live.objects[0], CURRENT_OBJECT_VERSION).unwrap(),
                    parent_before,
                    "{parent_label} is unchanged by child creation"
                );
                let oracle = decode_oracle_volatile(boundary);
                assert_eq!(
                    object_images(&runtime.live.objects),
                    object_images(&oracle.objects),
                    "{boundary} object slots"
                );
                assert_eq!(
                    runtime.live.orderly.drbg_state.seed.as_bytes(),
                    oracle.orderly.drbg_state.seed.as_bytes(),
                    "{boundary} live DRBG"
                );
                assert_eq!(
                    runtime.live.orderly.drbg_state.reseed_counter,
                    oracle.orderly.drbg_state.reseed_counter
                );

                use crate::library::tpm2::volatile::volatile_all_store;
                let blob = volatile_all_store(&runtime, &clock).expect("the volatile state saves");
                let mut resumed = restore_permanent_blob_for_test(vector("PERMALL_BASE"))
                    .expect("the permanent state restores");
                crate::library::tpm2::attach_volatile_blob(
                    &mut resumed,
                    &blob,
                    &clock,
                    VolatileDecodeBoundary::Restore,
                )
                .expect("the saved volatile state attaches");
                exec(
                    &mut resumed,
                    &clock,
                    flush_label,
                    flush_command(0x8000_0001),
                );
            }
        }

        #[test]
        fn the_da_used_transition_survives_volatile_serialization() {
            for boundary in [
                "AFTER_DA2_NV_FIRST",
                "AFTER_DA2_TRANSIENT_FIRST",
                "AFTER_DA2_PERSISTENT_FIRST",
            ] {
                let oracle = decode_oracle_volatile(boundary);
                assert!(oracle.da_used, "{boundary} carries the DA-used marker");
            }
        }

        #[test]
        fn an_ordinary_child_matches_the_oracle_volatile_object_slots_and_drbg() {
            let runtime = replay_case(&[
                (
                    "CP_STORAGE_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                (
                    "CHILD_AES_UNDER_PARENT",
                    cl_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE),
                ),
            ]);
            let oracle = decode_oracle_volatile("AFTER_CHILD");
            assert_eq!(
                object_images(&runtime.live.objects),
                object_images(&oracle.objects)
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.as_bytes(),
                oracle.orderly.drbg_state.seed.as_bytes(),
                "the live DRBG advanced exactly as far as the vendored TPM"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter,
                oracle.orderly.drbg_state.reseed_counter
            );
            assert_permall_matches(&runtime, "PERMALL_AFTER_CHILD");
        }

        #[test]
        fn a_derived_child_matches_the_oracle_volatile_object_slots_without_live_drbg_use() {
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            let mut runtime = restored_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "CP_DERIVATION_PARENT",
                cp_command(TPM_RH_ENDORSEMENT_H, &[], &DERIVATION_PARENT_TEMPLATE),
            );
            let drbg_before = runtime.live.orderly.drbg_state.clone();
            exec(
                &mut runtime,
                &clock,
                "DERIVED_ECC_EMPTY",
                cl_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &[],
                    &ecc_derive_template(&[], &[], 0x0002_0452),
                ),
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.as_bytes(),
                drbg_before.seed.as_bytes(),
                "derivation never consumes the live DRBG"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter,
                drbg_before.reseed_counter
            );
            let oracle = decode_oracle_volatile("AFTER_DERIVED");
            assert_eq!(
                object_images(&runtime.live.objects),
                object_images(&oracle.objects)
            );
            assert_permall_matches(&runtime, "PERMALL_AFTER_DERIVED");
        }

        #[test]
        fn failed_commands_leave_no_slot_or_state_behind() {
            use crate::library::tpm2::object_create::find_empty_object_slot;
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            let mut runtime = restored_runtime(&clock);
            let drbg_before = runtime.live.orderly.drbg_state.clone();
            for (label, bytes) in [
                (
                    "TEMPLATE_TRUNCATED_BODY",
                    cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE[..14]),
                ),
                (
                    "OVERSIZED_USERAUTH",
                    cl_command(TPM_RH_OWNER_H, &[], &[0x61; 33], &[], &AES_TEMPLATE),
                ),
                (
                    "UNLOADED_TRANSIENT_PARENT",
                    cl_command(0x8000_0002, &[], &[], &[], &AES_TEMPLATE),
                ),
            ] {
                let input = CommandInput::new(bytes.len() as u32, bytes);
                let response =
                    process(&mut runtime, 0, &input, &clock, |_| Ok(())).expect("processes");
                assert_eq!(response, vector(label), "{label}");
                assert_eq!(
                    find_empty_object_slot(&runtime),
                    Some((0, 0x8000_0000)),
                    "{label} leaves every slot free"
                );
                assert_eq!(
                    runtime.live.orderly.drbg_state.seed.as_bytes(),
                    drbg_before.seed.as_bytes(),
                    "{label} leaves the live DRBG untouched"
                );
            }
            assert_permall_matches(&runtime, "PERMALL_AFTER_MALFORMED");
        }

        #[test]
        fn the_parent_object_is_unchanged_by_child_creation() {
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            let mut runtime = restored_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            );
            let parent_before =
                any_object_image(&runtime.live.objects[0], CURRENT_OBJECT_VERSION).unwrap();
            exec(
                &mut runtime,
                &clock,
                "CHILD_AES_UNDER_PARENT",
                cl_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE),
            );
            let parent_after =
                any_object_image(&runtime.live.objects[0], CURRENT_OBJECT_VERSION).unwrap();
            assert_eq!(parent_before, parent_after);
        }

        #[test]
        fn the_created_object_survives_a_volatile_round_trip() {
            use crate::library::tpm2::volatile::volatile_all_store;
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            let mut runtime = replay_case(&[(
                "AES_PRIMARY_OWNER",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            )]);
            let images_before = object_images(&runtime.live.objects);
            let blob = volatile_all_store(&runtime, &clock).expect("the volatile state saves");

            let mut restored = restore_permanent_blob_for_test(vector("PERMALL_BASE"))
                .expect("the permanent state restores");
            crate::library::tpm2::attach_volatile_blob(
                &mut restored,
                &blob,
                &clock,
                VolatileDecodeBoundary::Restore,
            )
            .expect("the saved volatile state attaches");
            assert_eq!(object_images(&restored.live.objects), images_before);

            exec(
                &mut runtime,
                &clock,
                "FLUSH_AES",
                flush_command(0x8000_0000),
            );
            exec(
                &mut restored,
                &clock,
                "FLUSH_AES",
                flush_command(0x8000_0000),
            );
            assert_eq!(
                object_images(&restored.live.objects),
                object_images(&runtime.live.objects),
                "the restored object flushes exactly like the original"
            );
        }

        #[test]
        fn the_new_object_appears_in_the_transient_capability_list() {
            use crate::library::tpm2::capability::handles::collect;
            let runtime = replay_case(&[(
                "AES_PRIMARY_OWNER",
                cl_command(TPM_RH_OWNER_H, &[], &[], &[], &AES_TEMPLATE),
            )]);
            let page = collect(
                &runtime.live,
                runtime.state.as_ref().expect("state"),
                0x8000_0000,
                8,
            )
            .expect("the transient handle type enumerates");
            assert_eq!(page.entries, [0x8000_0000]);
        }

        #[test]
        fn different_derivation_inputs_produce_different_keys() {
            let labels = [
                "DERIVED_ECC_EMPTY",
                "DERIVED_ECC_TEMPLATE_LABEL",
                "DERIVED_ECC_TEMPLATE_CONTEXT",
                "DERIVED_ECC_SENSITIVE_LABEL",
                "DERIVED_ECC_SENSITIVE_CONTEXT",
                "DERIVED_ECC_TEMPLATE_WINS",
                "DERIVED_ECC_MIXED_SOURCES",
            ];
            for (index, left) in labels.iter().enumerate() {
                for right in &labels[index + 1..] {
                    assert_ne!(vector(left), vector(right), "{left} vs {right}");
                }
            }
        }

        #[test]
        fn a_different_parent_secret_changes_the_derived_key() {
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            let mut runtime = restored_runtime(&clock);
            let parent = cp_command(TPM_RH_OWNER_H, &[], &DERIVATION_PARENT_TEMPLATE);
            let input = CommandInput::new(parent.len() as u32, parent);
            let response = process(&mut runtime, 0, &input, &clock, |_| Ok(())).expect("processes");
            assert_eq!(response[6..10], [0, 0, 0, 0], "the owner parent is created");
            let child = cl_command(
                0x8000_0000,
                &[],
                &[],
                &[],
                &ecc_derive_template(&[], &[], 0x0002_0452),
            );
            let input = CommandInput::new(child.len() as u32, child);
            let response = process(&mut runtime, 0, &input, &clock, |_| Ok(())).expect("processes");
            assert_eq!(
                response[6..10],
                [0, 0, 0, 0],
                "the derived child is created"
            );
            assert_ne!(
                response,
                vector("DERIVED_ECC_EMPTY"),
                "an owner-hierarchy parent derives a different child than the endorsement one"
            );
        }
    }
}
