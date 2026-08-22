use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_OBJECT_MEMORY, TPM_RC_SIZE, TPM_RC_TYPE,
};

use super::super::marshal::BlobWriter;
use super::super::object::{ATTR_IS_PARENT, ATTR_OCCUPIED};
use super::super::object_create::{
    ObjectSecrets, create_object, empty_object_slots, find_empty_object_slot, sensitive_to_private,
};
use super::super::pcr::compute_current_digest;
use super::super::public::StateFormatLimit;
use super::super::random::{finish_live_rand, take_live_rand};
use super::super::runtime::Tpm2Runtime;
use super::super::template::{
    AlgorithmPolicy, adjusted_auth_value, create_checks, marshal_public_area, parent_public_info,
};
use super::create_loaded::{object_hierarchy, resolve_parent};
use super::create_primary::{
    TPM_ST_CREATION, add_modifier, compute_creation_ticket, creation_data_bytes, parse_parameters,
};
use super::dispatcher::CommandFrame;
use super::output::CommandOutput;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_PARENT_HANDLE: TpmResult = TPM_RC_1;
const RC_IN_SENSITIVE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_PUBLIC: TpmResult = TPM_RC_P + TPM_RC_1 * 2;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parent_handle = *frame.handles.first().ok_or(TPM_RC_FAILURE)?;
    let parent = resolve_parent(runtime, parent_handle)?.ok_or(TPM_RC_FAILURE)?;
    if parent.persistent
        && let Some((slot, _)) = find_empty_object_slot(runtime)
        && let Some(entry) = runtime.live.objects.get_mut(slot)
    {
        entry.attributes = parent.slot_attributes & !ATTR_OCCUPIED;
    }

    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let policy = AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    };
    let parsed = parse_parameters(&policy, frame.parameters)?;

    if parent.slot_attributes & ATTR_IS_PARENT == 0 {
        return Err(TPM_RC_TYPE + RC_PARENT_HANDLE);
    }
    {
        let mut free_slots = empty_object_slots(runtime);
        if parent.persistent {
            free_slots.next();
        }
        free_slots.next().ok_or(TPM_RC_OBJECT_MEMORY)?;
    }
    let body = parent.body.as_deref().ok_or(TPM_RC_FAILURE)?;

    let mut public = parsed.public;
    let parent_info = parent_public_info(&body.public, false);
    create_checks(Some(&parent_info), &public, parsed.sensitive_data.len())
        .map_err(|code| add_modifier(code, RC_IN_PUBLIC))?;
    let user_auth = adjusted_auth_value(&parsed.user_auth, public.name_alg)
        .map_err(|_| TPM_RC_SIZE + RC_IN_SENSITIVE)?;

    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    let sh_proof = persistent.sh_proof.as_bytes().to_vec();
    let eh_proof = persistent.eh_proof.as_bytes().to_vec();
    let secrets = ObjectSecrets {
        sh_proof: &sh_proof,
        eh_proof: &eh_proof,
    };

    let mut rand = take_live_rand(runtime)?;
    let created = create_object(
        &mut public,
        user_auth,
        &parsed.sensitive_data,
        false,
        &secrets,
        &mut rand,
    );
    let created = created.and_then(|created| {
        let out_private = sensitive_to_private(
            &created.sensitive,
            &created.name,
            &body.public,
            body.sensitive.seed_value.as_bytes(),
            created.public.name_alg,
            &mut rand,
        )?;
        Ok((created, out_private))
    });
    finish_live_rand(runtime, rand)?;
    let (created, out_private) = created?;

    let out_public = marshal_public_area(&created.public)?;

    let mut creation_pcr = parsed.creation_pcr;
    let pcr_digest = compute_current_digest(runtime, public.name_alg, &mut creation_pcr)?;
    let creation_data = creation_data_bytes(
        body.public.name_alg,
        &body.name,
        &body.qualified_name,
        runtime.locality,
        &creation_pcr,
        &pcr_digest,
        &parsed.outside_info,
    )?;
    let mut hasher = super::super::crypto::Hasher::new(public.name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&creation_data);
    let creation_hash = hasher.finalize();

    let hierarchy = object_hierarchy(body, parent.slot_attributes);
    let ticket = compute_creation_ticket(runtime, hierarchy, &created.name, &creation_hash)?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&out_private).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&out_public).map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&creation_data)
        .map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&creation_hash)
        .map_err(|_| TPM_RC_SIZE)?;
    writer.write_u16(TPM_ST_CREATION);
    writer.write_u32(hierarchy);
    writer.write_tpm2b(&ticket).map_err(|_| TPM_RC_SIZE)?;

    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::super::registry::{self, HandleKind, TPM_CC_CREATE};
    use super::*;
    use crate::library::CommandInput;
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::golden_responses::create::vector;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::process::process;
    use crate::library::tpm2::template::TemplateReader;
    use crate::library::tpm2::{VolatileDecodeBoundary, restore_permanent_blob_for_test};

    const TPM_RH_OWNER_H: u32 = 0x4000_0001;
    const TPM_RH_NULL_H: u32 = 0x4000_0007;
    const TPM_RH_ENDORSEMENT_H: u32 = 0x4000_000b;

    const AES_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x60, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];
    const AES_PROVIDED_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
        0x43, 0x00, 0x00,
    ];
    const AES_FIXEDTPM_ONLY_TEMPLATE: [u8; 18] = [
        0x00, 0x25, 0x00, 0x0b, 0x00, 0x06, 0x04, 0x62, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00,
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
    const SEALED_DATA_TEMPLATE: [u8; 14] = [
        0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    ];
    const HMAC_SIGN_TEMPLATE: [u8; 16] = [
        0x00, 0x08, 0x00, 0x0b, 0x00, 0x04, 0x04, 0x72, 0x00, 0x00, 0x00, 0x05, 0x00, 0x0b, 0x00,
        0x00,
    ];
    const DERIVATION_PARENT_TEMPLATE: [u8; 18] = [
        0x00, 0x08, 0x00, 0x0b, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
        0x22, 0x00, 0x00,
    ];

    const PCR_SHA256_LOW: [u8; 10] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x03, 0xff, 0x00, 0x00];
    const PCR_TOO_MANY: [u8; 10] = [0x00, 0x00, 0x00, 0x08, 0x00, 0x0b, 0x03, 0xff, 0x00, 0x00];
    const PCR_BAD_ALG: [u8; 10] = [0x00, 0x00, 0x00, 0x01, 0x07, 0x77, 0x03, 0xff, 0x00, 0x00];
    const PCR_BAD_SELECT_SIZE: [u8; 7] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x00];

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

    fn cr_params(
        user_auth: &[u8],
        data: &[u8],
        template: &[u8],
        outside_info: &[u8],
        creation_pcr: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(4 + user_auth.len() as u16 + data.len() as u16).to_be_bytes());
        push_tpm2b(&mut out, user_auth);
        push_tpm2b(&mut out, data);
        push_tpm2b(&mut out, template);
        push_tpm2b(&mut out, outside_info);
        if creation_pcr.is_empty() {
            out.extend_from_slice(&0u32.to_be_bytes());
        } else {
            out.extend_from_slice(creation_pcr);
        }
        out
    }

    fn cr_command(
        parent: u32,
        password: &[u8],
        user_auth: &[u8],
        data: &[u8],
        template: &[u8],
        outside_info: &[u8],
        creation_pcr: &[u8],
    ) -> Vec<u8> {
        build(
            TPM_CC_CREATE,
            &[parent],
            password,
            &cr_params(user_auth, data, template, outside_info, creation_pcr),
        )
    }

    fn create_command(parent: u32, password: &[u8], template: &[u8]) -> Vec<u8> {
        cr_command(parent, password, &[], &[], template, &[], &[])
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

    fn cl_command(parent: u32, template: &[u8]) -> Vec<u8> {
        let mut params = Vec::new();
        params.extend_from_slice(&4u16.to_be_bytes());
        push_tpm2b(&mut params, &[]);
        push_tpm2b(&mut params, &[]);
        push_tpm2b(&mut params, template);
        build(0x0000_0191, &[parent], &[], &params)
    }

    fn flush_command(handle: u32) -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0e];
        out.extend_from_slice(&0x0000_0165u32.to_be_bytes());
        out.extend_from_slice(&handle.to_be_bytes());
        out
    }

    fn evict_command(object: u32, persistent: u32) -> Vec<u8> {
        build(
            0x0000_0120,
            &[TPM_RH_OWNER_H, object],
            &[],
            &persistent.to_be_bytes(),
        )
    }

    fn cap_cc_command(property: u32, count: u32) -> Vec<u8> {
        let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
        out.extend_from_slice(&0x0000_017au32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&property.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
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
    fn exec_raw(runtime: &mut Tpm2Runtime, clock: &SteppingClock, bytes: Vec<u8>) -> Vec<u8> {
        let input = CommandInput::new(bytes.len() as u32, bytes);
        process(runtime, 0, &input, clock, |_| Ok(())).expect("the command processes")
    }

    #[track_caller]
    fn exec(runtime: &mut Tpm2Runtime, clock: &SteppingClock, label: &str, bytes: Vec<u8>) {
        let response = exec_raw(runtime, clock, bytes);
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
        assert_eq!(TPM_CC_CREATE, 0x0000_0153);
        let descriptor = registry::find(TPM_CC_CREATE).expect("the command is registered");
        assert_eq!(descriptor.attributes, 0x0200_0153);
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NVRAM update");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role);
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_object_handle_kind_accepts_only_transient_and_persistent_handles() {
        let kind = registry::find(TPM_CC_CREATE).unwrap().handles[0].kind;
        for handle in [
            0x8000_0000u32,
            0x8000_0001,
            0x8000_0002,
            0x8100_0000,
            0x81ff_ffff,
        ] {
            assert!(kind.accepts(handle), "handle {handle:#x}");
        }
        for handle in [
            0u32,
            23,
            0x0100_0000,
            TPM_RH_OWNER_H,
            TPM_RH_NULL_H,
            TPM_RH_ENDORSEMENT_H,
            0x4000_0009,
            0x8000_0003,
            0x8200_0000,
            u32::MAX,
        ] {
            assert!(!kind.accepts(handle), "handle {handle:#x}");
        }
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let oracle = vector("CAP_CC_CREATE");
        assert_eq!(
            &oracle[oracle.len() - 4..],
            0x0200_0153u32.to_be_bytes(),
            "the vendored TPM reports TPMA_CC 0x02000153"
        );
        replay_case(&[("CAP_CC_CREATE", cap_cc_command(0x153, 1))]);
    }

    #[test]
    fn the_capability_pagination_keeps_the_sorted_neighbours() {
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        let response = exec_raw(&mut runtime, &clock, cap_cc_command(0x14f, 3));
        assert_eq!(response[6..10], [0, 0, 0, 0], "the query succeeds");
        assert_eq!(response[10], 1, "moreData is set");
        assert_eq!(&response[11..15], &2u32.to_be_bytes(), "TPM_CAP_COMMANDS");
        assert_eq!(&response[15..19], &3u32.to_be_bytes(), "three entries");
        let entries: Vec<u32> = response[19..]
            .chunks(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .collect();
        assert_eq!(entries, [0x0440_014f, 0x0200_0153, 0x0200_015d]);
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
            create_command(0x8000_0000, &[], &AES_TEMPLATE),
        );
    }

    #[test]
    fn children_under_a_storage_parent_match_the_oracle() {
        let runtime = replay_case(&[
            (
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            (
                "CREATE_AES_CHILD",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
            (
                "CREATE_HMAC_CHILD",
                create_command(0x8000_0000, &[], &HMAC_SIGN_TEMPLATE),
            ),
            (
                "CREATE_AES_PROVIDED_KEY",
                cr_command(
                    0x8000_0000,
                    &[],
                    &[],
                    b"0123456789abcdef",
                    &AES_PROVIDED_TEMPLATE,
                    &[],
                    &[],
                ),
            ),
            (
                "CREATE_SEALED_DATA",
                cr_command(
                    0x8000_0000,
                    &[],
                    b"seal-auth",
                    b"sealed secret bytes",
                    &SEALED_DATA_TEMPLATE,
                    &[],
                    &[],
                ),
            ),
            (
                "CREATE_OUTSIDE_INFO",
                cr_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE, b"outside!", &[]),
            ),
            (
                "CREATE_WITH_PCR",
                cr_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &[],
                    &AES_TEMPLATE,
                    &[],
                    &PCR_SHA256_LOW,
                ),
            ),
            (
                "CREATE_OUTSIDE_INFO_MAX",
                cr_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE, &[0x5a; 66], &[]),
            ),
        ]);
        assert_eq!(
            runtime
                .live
                .objects
                .iter()
                .map(|object| object.attributes & ATTR_OCCUPIED != 0)
                .collect::<Vec<bool>>(),
            [true, false, false],
            "only the parent occupies a slot after eight creations"
        );
    }

    #[test]
    fn an_rsa_child_under_a_storage_parent_is_created_deterministically() {
        let decode = |response: &[u8]| {
            assert_eq!(response[6..10], [0, 0, 0, 0], "the creation succeeds");
            let parameter_size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
            let mut reader = TemplateReader::new(&response[14..14 + parameter_size]);
            let out_private = reader.tpm2b(0xffff).unwrap().to_vec();
            let out_public = reader.tpm2b(0xffff).unwrap().to_vec();
            let creation_data = reader.tpm2b(0xffff).unwrap().to_vec();
            let creation_hash = reader.tpm2b(0xffff).unwrap().to_vec();
            assert_eq!(reader.u16().unwrap(), TPM_ST_CREATION);
            assert_eq!(reader.u32().unwrap(), TPM_RH_OWNER_H);
            let ticket = reader.tpm2b(0xffff).unwrap().to_vec();
            assert!(reader.remaining().is_empty());
            (
                out_private,
                out_public,
                creation_data,
                creation_hash,
                ticket,
            )
        };
        let run = || {
            let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
            let mut runtime = restored_runtime(&clock);
            exec(
                &mut runtime,
                &clock,
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            );
            let response = exec_raw(
                &mut runtime,
                &clock,
                create_command(0x8000_0000, &[], &RSA_SIGN_TEMPLATE),
            );
            assert_eq!(
                runtime
                    .live
                    .objects
                    .iter()
                    .map(|object| object.attributes & ATTR_OCCUPIED != 0)
                    .collect::<Vec<bool>>(),
                [true, false, false],
                "the child is not loaded"
            );
            response
        };
        let first = run();
        assert_eq!(first, run(), "the same state yields the same child");
        let (out_private, out_public, _creation_data, creation_hash, ticket) = decode(&first);
        assert!(!out_private.is_empty());
        let mut public = TemplateReader::new(&out_public);
        assert_eq!(public.u16().unwrap(), 0x0001, "an RSA object");
        assert_eq!(public.u16().unwrap(), 0x000b);
        assert_eq!(public.u32().unwrap(), 0x0004_0472);
        assert_eq!(public.tpm2b(0xffff).unwrap(), []);
        assert_eq!(public.u16().unwrap(), 0x0010, "no symmetric algorithm");
        assert_eq!(public.u16().unwrap(), 0x0014, "the RSASSA scheme");
        assert_eq!(public.u16().unwrap(), 0x000b);
        assert_eq!(public.u16().unwrap(), 2048);
        assert_eq!(public.u32().unwrap(), 0);
        let modulus = public.tpm2b(0xffff).unwrap();
        assert_eq!(modulus.len(), 256);
        assert_ne!(modulus[0] & 0x80, 0);
        assert!(public.remaining().is_empty());
        assert_eq!(creation_hash.len(), 32);
        assert_eq!(ticket.len(), 64);
    }

    #[test]
    fn the_response_is_framed_without_a_handle_or_name() {
        let oracle = vector("CREATE_AES_CHILD");
        assert_eq!(&oracle[..2], &0x8002u16.to_be_bytes());
        assert_eq!(&oracle[6..10], &[0, 0, 0, 0], "the command succeeded");
        let parameter_size = u32::from_be_bytes(oracle[10..14].try_into().unwrap()) as usize;
        let parameters = &oracle[14..14 + parameter_size];
        let mut reader = TemplateReader::new(parameters);
        let out_private = reader.tpm2b(0xffff).unwrap().to_vec();
        let out_public = reader.tpm2b(0xffff).unwrap().to_vec();
        let creation_data = reader.tpm2b(0xffff).unwrap().to_vec();
        let creation_hash = reader.tpm2b(0xffff).unwrap().to_vec();
        assert_eq!(reader.u16().unwrap(), TPM_ST_CREATION);
        assert_eq!(reader.u32().unwrap(), 0x4000_0001, "the owner hierarchy");
        let ticket = reader.tpm2b(0xffff).unwrap().to_vec();
        assert!(reader.remaining().is_empty(), "no trailing name");
        assert!(!out_private.is_empty(), "a wrapped private area");
        assert_eq!(&out_public[..2], &AES_TEMPLATE[..2]);
        assert!(!creation_data.is_empty());
        assert_eq!(creation_hash.len(), 32);
        assert_eq!(ticket.len(), 64);
        assert_eq!(
            oracle[14 + parameter_size..],
            [0x00, 0x00, 0x01, 0x00, 0x00],
            "the password session acknowledgement follows the parameters"
        );
    }

    #[test]
    fn the_creation_data_carries_the_parent_name_and_qualified_name() {
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "CP_STORAGE_PARENT",
            cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
        );
        let (parent_name, parent_qualified_name) = {
            use crate::library::tpm2::persistent::OwnedAnyObjectBody;
            let OwnedAnyObjectBody::Object(body) = &runtime.live.objects[0].body else {
                panic!("an object body");
            };
            (body.name.clone(), body.qualified_name.clone())
        };
        let response = exec_raw(
            &mut runtime,
            &clock,
            create_command(0x8000_0000, &[], &AES_TEMPLATE),
        );
        assert_eq!(response, vector("CREATE_AES_CHILD"));
        let parameter_size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
        let mut reader = TemplateReader::new(&response[14..14 + parameter_size]);
        let _out_private = reader.tpm2b(0xffff).unwrap();
        let _out_public = reader.tpm2b(0xffff).unwrap();
        let creation_data = reader.tpm2b(0xffff).unwrap().to_vec();
        let mut data = TemplateReader::new(&creation_data);
        assert_eq!(data.u32().unwrap(), 0, "no PCR selection");
        assert_eq!(
            data.tpm2b(0xffff).unwrap().len(),
            32,
            "the empty PCR digest"
        );
        assert_eq!(data.u8().unwrap(), 0x01, "locality zero");
        assert_eq!(data.u16().unwrap(), 0x000b, "the parent name algorithm");
        assert_eq!(data.tpm2b(0xffff).unwrap(), parent_name);
        assert_eq!(data.tpm2b(0xffff).unwrap(), parent_qualified_name);
        assert_eq!(data.tpm2b(0xffff).unwrap(), []);
        assert!(data.remaining().is_empty());
    }

    #[test]
    fn parameter_errors_match_the_oracle() {
        replay_case(&[
            (
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            (
                "CREATE_SDO_WITH_DATA",
                cr_command(
                    0x8000_0000,
                    &[],
                    &[],
                    b"0123456789abcdef",
                    &AES_TEMPLATE,
                    &[],
                    &[],
                ),
            ),
            (
                "CREATE_NO_DATA_NO_SDO",
                create_command(0x8000_0000, &[], &AES_PROVIDED_TEMPLATE),
            ),
            (
                "CREATE_FIXEDTPM_MISMATCH",
                create_command(0x8000_0000, &[], &AES_FIXEDTPM_ONLY_TEMPLATE),
            ),
            (
                "CREATE_OVERSIZED_USERAUTH",
                cr_command(0x8000_0000, &[], &[0x61; 33], &[], &AES_TEMPLATE, &[], &[]),
            ),
            (
                "CREATE_OUTSIDE_INFO_OVERSIZED",
                cr_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE, &[0x5a; 67], &[]),
            ),
            (
                "CREATE_PCR_TOO_MANY",
                cr_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &[],
                    &AES_TEMPLATE,
                    &[],
                    &PCR_TOO_MANY,
                ),
            ),
            (
                "CREATE_PCR_BAD_ALG",
                cr_command(0x8000_0000, &[], &[], &[], &AES_TEMPLATE, &[], &PCR_BAD_ALG),
            ),
            (
                "CREATE_PCR_BAD_SELECT_SIZE",
                cr_command(
                    0x8000_0000,
                    &[],
                    &[],
                    &[],
                    &AES_TEMPLATE,
                    &[],
                    &PCR_BAD_SELECT_SIZE,
                ),
            ),
            (
                "TEMPLATE_TRUNCATED_BODY",
                create_command(0x8000_0000, &[], &AES_TEMPLATE[..14]),
            ),
            ("TEMPLATE_TRAILING_BYTE", {
                let mut template = AES_TEMPLATE.to_vec();
                template.push(0x00);
                create_command(0x8000_0000, &[], &template)
            }),
            ("TEMPLATE_EMPTY", create_command(0x8000_0000, &[], &[])),
            ("TEMPLATE_BAD_TYPE", {
                let mut template = AES_TEMPLATE.to_vec();
                template[0..2].copy_from_slice(&0x0010u16.to_be_bytes());
                create_command(0x8000_0000, &[], &template)
            }),
            ("TRAILING_PARAMETER_BYTES", {
                let mut extended = create_command(0x8000_0000, &[], &AES_TEMPLATE);
                extended.extend_from_slice(&[0x00, 0x00]);
                let size = (extended.len() as u32).to_be_bytes();
                extended[2..6].copy_from_slice(&size);
                extended
            }),
        ]);
    }

    #[test]
    fn truncated_commands_match_the_oracle() {
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "CP_STORAGE_PARENT",
            cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
        );
        let full = create_command(0x8000_0000, &[], &AES_TEMPLATE);
        assert_eq!(full.len(), 0x3b);
        for cut in [12usize, 16, 20, 27, 29, 31, 33, 43, 53, 55, 57] {
            let mut shortened = full[..cut].to_vec();
            shortened[2..6].copy_from_slice(&(cut as u32).to_be_bytes());
            exec(
                &mut runtime,
                &clock,
                &format!("TRUNCATED_AT_{cut:02}"),
                shortened,
            );
        }
    }

    #[test]
    fn unsuitable_parents_match_the_oracle() {
        replay_case(&[
            (
                "CP_SIGNING_KEY",
                cp_command(TPM_RH_OWNER_H, &[], &RSA_SIGN_TEMPLATE),
            ),
            (
                "CREATE_UNDER_SIGNING_KEY",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
        ]);
        replay_case(&[
            (
                "CP_DERIVATION_PARENT",
                cp_command(TPM_RH_ENDORSEMENT_H, &[], &DERIVATION_PARENT_TEMPLATE),
            ),
            (
                "CREATE_UNDER_DERIVATION_PARENT",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn handle_validation_matches_the_oracle() {
        replay_case(&[
            (
                "CREATE_UNDER_OWNER_HIERARCHY",
                create_command(TPM_RH_OWNER_H, &[], &AES_TEMPLATE),
            ),
            (
                "CREATE_UNDER_NULL_HIERARCHY",
                create_command(TPM_RH_NULL_H, &[], &AES_TEMPLATE),
            ),
            (
                "CREATE_UNLOADED_TRANSIENT",
                create_command(0x8000_0002, &[], &AES_TEMPLATE),
            ),
            (
                "CREATE_UNDEFINED_PERSISTENT",
                create_command(0x8100_0000, &[], &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn a_persistent_parent_matches_the_oracle() {
        let runtime = replay_case(&[
            (
                "CP_PERSISTENT_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            ("EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
            ("FLUSH_TRANSIENT_PARENT", flush_command(0x8000_0000)),
            (
                "CREATE_UNDER_PERSISTENT_PARENT",
                create_command(0x8100_0100, &[], &AES_TEMPLATE),
            ),
        ]);
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes & ATTR_OCCUPIED == 0),
            "no transient slot stays occupied"
        );
    }

    #[test]
    fn a_null_hierarchy_parent_matches_the_oracle() {
        let oracle = vector("CREATE_UNDER_NULL_PARENT");
        replay_case(&[
            (
                "CP_NULL_PARENT",
                cp_command(TPM_RH_NULL_H, &[], &SRK_TEMPLATE),
            ),
            (
                "CREATE_UNDER_NULL_PARENT",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
        ]);
        let parameter_size = u32::from_be_bytes(oracle[10..14].try_into().unwrap()) as usize;
        let mut reader = TemplateReader::new(&oracle[14..14 + parameter_size]);
        let _out_private = reader.tpm2b(0xffff).unwrap();
        let _out_public = reader.tpm2b(0xffff).unwrap();
        let _creation_data = reader.tpm2b(0xffff).unwrap();
        let _creation_hash = reader.tpm2b(0xffff).unwrap();
        assert_eq!(reader.u16().unwrap(), TPM_ST_CREATION);
        assert_eq!(
            reader.u32().unwrap(),
            TPM_RH_NULL_H,
            "the ticket names the null hierarchy"
        );
    }

    #[test]
    fn authorization_behaviour_matches_the_oracle() {
        let clock = SteppingClock::new(1_700_000_000_000, 4_000_000);
        let mut runtime = restored_runtime(&clock);
        let response = exec_raw(
            &mut runtime,
            &clock,
            cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
        );
        assert_eq!(response, vector("CP_STORAGE_PARENT"));
        exec(&mut runtime, &clock, "NO_SESSIONS_AUTH_MISSING", {
            let mut out = vec![0x80, 0x01, 0, 0, 0, 0];
            out.extend_from_slice(&TPM_CC_CREATE.to_be_bytes());
            out.extend_from_slice(&0x8000_0000u32.to_be_bytes());
            out.extend_from_slice(&cr_params(&[], &[], &AES_TEMPLATE, &[], &[]));
            let size = (out.len() as u32).to_be_bytes();
            out[2..6].copy_from_slice(&size);
            out
        });

        replay_case(&[
            (
                "CP_AUTHED_PARENT",
                cp_command(TPM_RH_OWNER_H, b"parent", &SRK_TEMPLATE),
            ),
            (
                "CHILD_WRONG_AUTH",
                create_command(0x8000_0000, b"wrong", &AES_TEMPLATE),
            ),
            (
                "CHILD_RIGHT_AUTH",
                create_command(0x8000_0000, b"parent", &AES_TEMPLATE),
            ),
        ]);
    }

    #[test]
    fn dictionary_attack_protection_matches_the_oracle() {
        replay_case(&[
            (
                "CP_DA_PARENT",
                cp_command(TPM_RH_OWNER_H, b"parent", &SRK_NODA_CLEAR_TEMPLATE),
            ),
            (
                "DA_CHILD_FIRST_USE",
                create_command(0x8000_0000, b"parent", &AES_TEMPLATE),
            ),
            (
                "DA_CHILD_SECOND_USE",
                create_command(0x8000_0000, b"parent", &AES_TEMPLATE),
            ),
            (
                "DA_CHILD_WRONG_AUTH",
                create_command(0x8000_0000, b"wrong", &AES_TEMPLATE),
            ),
            ("CAP_DA_AFTER_WRONG", cap_da_command()),
        ]);
    }

    fn occupied_slots(runtime: &Tpm2Runtime) -> Vec<bool> {
        runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect()
    }

    #[test]
    fn a_full_object_table_matches_the_oracle() {
        let full_table = vector("CREATE_FULL_TABLE");
        assert_eq!(full_table[6..10], [0, 0, 0x09, 0x02]);
        let runtime = replay_case(&[
            (
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
            ("SLOT_FILL_3", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
            (
                "CREATE_FULL_TABLE",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
        ]);
        assert_eq!(occupied_slots(&runtime), [true, true, true]);
    }

    #[test]
    fn one_free_slot_still_creates_a_child_and_leaves_it_free() {
        assert_eq!(
            vector("CREATE_ONE_FREE_SLOT"),
            vector("CREATE_AES_CHILD"),
            "the primary slot fill draws nothing from the live DRBG"
        );
        let runtime = replay_case(&[
            (
                "CP_STORAGE_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
            (
                "CREATE_ONE_FREE_SLOT",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
        ]);
        assert_eq!(occupied_slots(&runtime), [true, true, false]);
        assert_eq!(runtime.live.objects[2].attributes, 0);
    }

    #[test]
    fn a_persistent_parent_with_one_free_slot_matches_the_oracle() {
        let one_free = vector("CREATE_PERSISTENT_ONE_FREE");
        assert_eq!(one_free[6..10], [0, 0, 0x09, 0x02]);
        let runtime = replay_case(&[
            (
                "CP_PERSISTENT_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            ("EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
            ("FLUSH_TRANSIENT_PARENT", flush_command(0x8000_0000)),
            (
                "FILL_AFTER_FLUSH",
                cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE),
            ),
            ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
            (
                "CREATE_PERSISTENT_ONE_FREE",
                create_command(0x8100_0100, &[], &AES_TEMPLATE),
            ),
        ]);
        assert_eq!(occupied_slots(&runtime), [true, true, false]);
        assert_ne!(
            runtime.live.objects[2].attributes, 0,
            "the temporary parent load leaves its residue in the last free slot"
        );
    }

    #[test]
    fn a_persistent_parent_with_two_free_slots_matches_the_oracle() {
        assert_eq!(
            vector("CREATE_PERSISTENT_TWO_FREE"),
            vector("CREATE_UNDER_PERSISTENT_PARENT")
        );
        let runtime = replay_case(&[
            (
                "CP_PERSISTENT_PARENT",
                cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
            ),
            ("EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
            ("FLUSH_TRANSIENT_PARENT", flush_command(0x8000_0000)),
            (
                "FILL_AFTER_FLUSH",
                cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE),
            ),
            (
                "CREATE_PERSISTENT_TWO_FREE",
                create_command(0x8100_0100, &[], &AES_TEMPLATE),
            ),
        ]);
        assert_eq!(occupied_slots(&runtime), [true, false, false]);
        assert_ne!(
            runtime.live.objects[1].attributes, 0,
            "the temporary parent load leaves its residue"
        );
        assert_eq!(
            runtime.live.objects[2].attributes, 0,
            "the child workspace slot stays untouched"
        );
    }

    #[test]
    fn the_parent_type_error_precedes_the_full_table_error() {
        let non_parent = vector("CREATE_NONPARENT_FULL_TABLE");
        assert_eq!(non_parent[6..10], [0, 0, 0x01, 0x8a]);
        replay_case(&[
            (
                "CP_SIGNING_KEY",
                cp_command(TPM_RH_OWNER_H, &[], &RSA_SIGN_TEMPLATE),
            ),
            ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
            ("SLOT_FILL_3", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
            (
                "CREATE_NONPARENT_FULL_TABLE",
                create_command(0x8000_0000, &[], &AES_TEMPLATE),
            ),
        ]);
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

        #[test]
        fn a_created_child_leaves_the_object_slots_untouched() {
            let runtime = replay_case(&[
                (
                    "CP_STORAGE_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                (
                    "CREATE_AES_CHILD",
                    create_command(0x8000_0000, &[], &AES_TEMPLATE),
                ),
            ]);
            let after_parent = decode_oracle_volatile("AFTER_PARENT");
            let after_create = decode_oracle_volatile("AFTER_CREATE");
            assert_eq!(
                object_images(&after_parent.objects),
                object_images(&after_create.objects),
                "the vendored TPM keeps its object slots unchanged across TPM2_Create"
            );
            assert_eq!(
                object_images(&runtime.live.objects),
                object_images(&after_create.objects),
                "this implementation serializes the same object slots"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.as_bytes(),
                after_create.orderly.drbg_state.seed.as_bytes(),
                "the live DRBG advanced exactly as far as the oracle's"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter,
                after_create.orderly.drbg_state.reseed_counter
            );
            let stored = persistent_all_store(runtime.state.as_ref().expect("state"))
                .expect("the state serializes");
            assert_eq!(stored, vector("PERMALL_AFTER_CREATE"));
        }

        #[test]
        fn a_persistent_parent_creation_matches_the_oracle_state() {
            let runtime = replay_case(&[
                (
                    "CP_PERSISTENT_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                ("EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
                ("FLUSH_TRANSIENT_PARENT", flush_command(0x8000_0000)),
                (
                    "CREATE_UNDER_PERSISTENT_PARENT",
                    create_command(0x8100_0100, &[], &AES_TEMPLATE),
                ),
            ]);
            let oracle = decode_oracle_volatile("AFTER_PERSISTENT_CREATE");
            assert_eq!(
                object_images(&runtime.live.objects),
                object_images(&oracle.objects),
                "no slot keeps the temporarily loaded persistent parent"
            );
            assert_eq!(
                oracle.objects[0].attributes & ATTR_OCCUPIED,
                0,
                "the vendored TPM leaves the load slot unoccupied with residual attributes"
            );
            assert_ne!(oracle.objects[0].attributes, 0);
        }

        #[test]
        fn failed_creations_leave_the_oracle_state() {
            let runtime = replay_case(&[
                (
                    "CP_STORAGE_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                (
                    "CREATE_SDO_WITH_DATA",
                    cr_command(
                        0x8000_0000,
                        &[],
                        &[],
                        b"0123456789abcdef",
                        &AES_TEMPLATE,
                        &[],
                        &[],
                    ),
                ),
                ("TEMPLATE_EMPTY", create_command(0x8000_0000, &[], &[])),
            ]);
            let oracle = decode_oracle_volatile("AFTER_PARENT");
            assert_eq!(
                object_images(&runtime.live.objects),
                object_images(&oracle.objects),
                "failed creations mutate no object slot"
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.seed.as_bytes(),
                oracle.orderly.drbg_state.seed.as_bytes(),
                "failed creations draw nothing from the live DRBG"
            );
        }

        #[test]
        fn slot_exhaustion_boundaries_match_the_oracle_state() {
            let full = replay_case(&[
                (
                    "CP_STORAGE_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
                ("SLOT_FILL_3", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
                (
                    "CREATE_FULL_TABLE",
                    create_command(0x8000_0000, &[], &AES_TEMPLATE),
                ),
            ]);
            let oracle = decode_oracle_volatile("AFTER_FULL_TABLE");
            assert_eq!(
                object_images(&full.live.objects),
                object_images(&oracle.objects),
                "the failed creation leaves every occupied slot untouched"
            );
            assert_eq!(
                full.live.orderly.drbg_state.seed.as_bytes(),
                oracle.orderly.drbg_state.seed.as_bytes()
            );

            let one_free = replay_case(&[
                (
                    "CP_STORAGE_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
                (
                    "CREATE_ONE_FREE_SLOT",
                    create_command(0x8000_0000, &[], &AES_TEMPLATE),
                ),
            ]);
            let oracle = decode_oracle_volatile("AFTER_ONE_FREE_SLOT");
            assert_eq!(
                object_images(&one_free.live.objects),
                object_images(&oracle.objects),
                "the workspace slot stays free after the successful creation"
            );
            assert_eq!(
                oracle.objects[2].attributes & ATTR_OCCUPIED,
                0,
                "the vendored TPM does not retain the created child"
            );
        }

        #[test]
        fn persistent_parent_slot_exhaustion_matches_the_oracle_state() {
            let one_free = replay_case(&[
                (
                    "CP_PERSISTENT_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                ("EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
                ("FLUSH_TRANSIENT_PARENT", flush_command(0x8000_0000)),
                (
                    "FILL_AFTER_FLUSH",
                    cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE),
                ),
                ("SLOT_FILL_2", cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE)),
                (
                    "CREATE_PERSISTENT_ONE_FREE",
                    create_command(0x8100_0100, &[], &AES_TEMPLATE),
                ),
            ]);
            let oracle = decode_oracle_volatile("AFTER_PERSISTENT_ONE_FREE");
            assert_eq!(
                object_images(&one_free.live.objects),
                object_images(&oracle.objects),
                "the failed creation still leaves the temporary parent load residue"
            );
            assert_eq!(oracle.objects[2].attributes & ATTR_OCCUPIED, 0);
            assert_ne!(oracle.objects[2].attributes, 0);

            let two_free = replay_case(&[
                (
                    "CP_PERSISTENT_PARENT",
                    cp_command(TPM_RH_OWNER_H, &[], &SRK_TEMPLATE),
                ),
                ("EVICT_PARENT", evict_command(0x8000_0000, 0x8100_0100)),
                ("FLUSH_TRANSIENT_PARENT", flush_command(0x8000_0000)),
                (
                    "FILL_AFTER_FLUSH",
                    cl_command(TPM_RH_OWNER_H, &AES_TEMPLATE),
                ),
                (
                    "CREATE_PERSISTENT_TWO_FREE",
                    create_command(0x8100_0100, &[], &AES_TEMPLATE),
                ),
            ]);
            let oracle = decode_oracle_volatile("AFTER_PERSISTENT_TWO_FREE");
            assert_eq!(
                object_images(&two_free.live.objects),
                object_images(&oracle.objects),
                "the successful creation leaves neither the parent nor the child loaded"
            );
            assert_eq!(oracle.objects[1].attributes & ATTR_OCCUPIED, 0);
            assert_ne!(oracle.objects[1].attributes, 0);
            assert_eq!(oracle.objects[2].attributes, 0);
        }
    }
}
