use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_HASH, TPM_RC_HIERARCHY, TPM_RC_SIZE,
    TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_VALUE,
};

use super::super::hierarchy::TPM_RH_NULL;
use super::super::marshal::BlobWriter;
use super::super::object::ATTR_IS_PARENT;
use super::super::object_create::{object_is_storage, resolve_any_object};
use super::super::object_load::{add_modifier, object_load, public_marshal_and_compute_name};
use super::super::object_wrap::{
    MAX_PRIVATE, Protector, duplicate_to_sensitive, produce_outer_wrap, sensitive_to_duplicate,
    sensitive_to_private, unwrap_outer,
};
use super::super::persistent::{OwnedAnyObjectBody, OwnedObjectBody, OwnedTpmtPublic};
use super::super::public::{NAME_SIZE, SymDefObject, TPM_ALG_NULL, TPM_ALG_RSA, TPM_ALG_SYMCIPHER};
use super::super::random::{finish_live_rand, take_live_rand};
use super::super::runtime::Tpm2Runtime;
use super::super::secret::{
    DUPLICATE_LABEL, MAX_ENCRYPTED_SECRET, rsa_secret_reaches_self_test, secret_decrypt,
    secret_encrypt,
};
use super::super::self_test::self_test_rsa_oaep;
use super::super::template::{
    TPMA_OBJECT_ENCRYPTED_DUPLICATION, TPMA_OBJECT_FIXED_PARENT, TPMA_OBJECT_FIXED_TPM,
    TemplateReader, digest_size,
};
use super::dispatcher::CommandFrame;
use super::load::{algorithm_policy, parse_sized_public};
use super::nv_common::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_5, TPM_RC_H, TPM_RC_P, handle_at,
};
use super::output::CommandOutput;

const RC_DUPLICATE_OBJECT_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_DUPLICATE_NEW_PARENT_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_DUPLICATE_ENCRYPTION_KEY_IN: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_DUPLICATE_SYMMETRIC_ALG: TpmResult = TPM_RC_P + TPM_RC_2;

const RC_REWRAP_OLD_PARENT: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_REWRAP_NEW_PARENT: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_REWRAP_IN_DUPLICATE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_REWRAP_NAME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_REWRAP_IN_SYM_SEED: TpmResult = TPM_RC_P + TPM_RC_3;

const RC_IMPORT_PARENT_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_IMPORT_ENCRYPTION_KEY: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IMPORT_OBJECT_PUBLIC: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_IMPORT_DUPLICATE: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_IMPORT_IN_SYM_SEED: TpmResult = TPM_RC_P + TPM_RC_4;
const RC_IMPORT_SYMMETRIC_ALG: TpmResult = TPM_RC_P + TPM_RC_5;

const MAX_DATA: usize = 66;

fn object_body(
    runtime: &Tpm2Runtime,
    handle: u32,
    blame: TpmResult,
) -> Result<Box<OwnedObjectBody>, TpmResult> {
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    match &object.body {
        OwnedAnyObjectBody::Object(body) => Ok(body.clone()),
        _ => Err(TPM_RC_TYPE + blame),
    }
}

fn slot_attributes(runtime: &Tpm2Runtime, handle: u32) -> Result<u32, TpmResult> {
    Ok(resolve_any_object(runtime, handle)
        .ok_or(TPM_RC_FAILURE)?
        .attributes)
}

fn inner_key_bytes(symmetric: &SymDefObject) -> usize {
    usize::from(symmetric.key_bits.unwrap_or(0)).div_ceil(8)
}

fn duplication_protector(public: &OwnedTpmtPublic) -> Protector<'_> {
    Protector {
        public,
        seed_value: &[],
    }
}

fn read_data(reader: &mut TemplateReader<'_>, blame: TpmResult) -> Result<Vec<u8>, TpmResult> {
    Ok(reader
        .tpm2b(MAX_DATA)
        .map_err(|code| add_modifier(code, blame))?
        .to_vec())
}

fn read_private(reader: &mut TemplateReader<'_>, blame: TpmResult) -> Result<Vec<u8>, TpmResult> {
    Ok(reader
        .tpm2b(MAX_PRIVATE)
        .map_err(|code| add_modifier(code, blame))?
        .to_vec())
}

fn read_encrypted_secret(
    reader: &mut TemplateReader<'_>,
    blame: TpmResult,
) -> Result<Vec<u8>, TpmResult> {
    Ok(reader
        .tpm2b(MAX_ENCRYPTED_SECRET)
        .map_err(|code| add_modifier(code, blame))?
        .to_vec())
}

pub(super) fn execute_duplicate(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let object_handle = handle_at(frame, 0)?;
    let new_parent_handle = handle_at(frame, 1)?;

    let symmetric;
    let encryption_key_in;
    {
        let policy = algorithm_policy(runtime)?;
        let mut reader = TemplateReader::new(frame.parameters);
        encryption_key_in = read_data(&mut reader, RC_DUPLICATE_ENCRYPTION_KEY_IN)?;
        symmetric = policy
            .sym_object(&mut reader, true)
            .map_err(|code| add_modifier(code, RC_DUPLICATE_SYMMETRIC_ALG))?;
        if !reader.remaining().is_empty() {
            return Err(TPM_RC_SIZE);
        }
    }

    let object = object_body(runtime, object_handle, RC_DUPLICATE_OBJECT_HANDLE)?;
    let attributes = object.public.object_attributes;
    if attributes & TPMA_OBJECT_FIXED_PARENT != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_DUPLICATE_OBJECT_HANDLE);
    }
    if object.public.name_alg == TPM_ALG_NULL {
        return Err(TPM_RC_TYPE + RC_DUPLICATE_OBJECT_HANDLE);
    }
    if new_parent_handle != TPM_RH_NULL && !object_is_storage(runtime, new_parent_handle) {
        return Err(TPM_RC_TYPE + RC_DUPLICATE_NEW_PARENT_HANDLE);
    }
    if attributes & TPMA_OBJECT_ENCRYPTED_DUPLICATION != 0 {
        if symmetric.algorithm == TPM_ALG_NULL {
            return Err(TPM_RC_SYMMETRIC + RC_DUPLICATE_SYMMETRIC_ALG);
        }
        if new_parent_handle == TPM_RH_NULL {
            return Err(TPM_RC_HIERARCHY + RC_DUPLICATE_NEW_PARENT_HANDLE);
        }
    }
    if symmetric.algorithm == TPM_ALG_NULL {
        if !encryption_key_in.is_empty() {
            return Err(TPM_RC_SIZE + RC_DUPLICATE_ENCRYPTION_KEY_IN);
        }
    } else if !encryption_key_in.is_empty()
        && encryption_key_in.len() != inner_key_bytes(&symmetric)
    {
        return Err(TPM_RC_SIZE + RC_DUPLICATE_ENCRYPTION_KEY_IN);
    }

    let new_parent = if new_parent_handle == TPM_RH_NULL {
        None
    } else {
        Some(object_body(
            runtime,
            new_parent_handle,
            RC_DUPLICATE_NEW_PARENT_HANDLE,
        )?)
    };

    let (data, out_sym_seed) = match &new_parent {
        Some(parent) => {
            let encrypted = secret_encrypt(runtime, &parent.public, DUPLICATE_LABEL)?;
            (encrypted.data, encrypted.secret)
        }
        None => (Vec::new(), Vec::new()),
    };

    let protector = new_parent
        .as_ref()
        .map(|parent| duplication_protector(&parent.public));
    let mut rand = take_live_rand(runtime)?;
    let produced = sensitive_to_duplicate(
        &object.sensitive,
        &object.name,
        protector.as_ref(),
        object.public.name_alg,
        &data,
        &symmetric,
        &encryption_key_in,
        &mut rand,
    );
    finish_live_rand(runtime, rand)?;
    let produced = produced?;

    let mut writer = BlobWriter::new();
    writer
        .write_tpm2b(produced.generated_inner_key.as_deref().unwrap_or_default())
        .map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&produced.blob)
        .map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&out_sym_seed).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(super) fn execute_rewrap(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let old_parent_handle = handle_at(frame, 0)?;
    let new_parent_handle = handle_at(frame, 1)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let in_duplicate = read_private(&mut reader, RC_REWRAP_IN_DUPLICATE)?;
    let name = reader
        .tpm2b(NAME_SIZE)
        .map_err(|code| add_modifier(code, RC_REWRAP_NAME))?
        .to_vec();
    let in_sym_seed = read_encrypted_secret(&mut reader, RC_REWRAP_IN_SYM_SEED)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    if (in_sym_seed.is_empty() && old_parent_handle != TPM_RH_NULL)
        || (!in_sym_seed.is_empty() && old_parent_handle == TPM_RH_NULL)
    {
        return Err(TPM_RC_HANDLE + RC_REWRAP_OLD_PARENT);
    }

    let private_blob = if old_parent_handle == TPM_RH_NULL {
        in_duplicate
    } else {
        if !object_is_storage(runtime, old_parent_handle) {
            return Err(TPM_RC_TYPE + RC_REWRAP_OLD_PARENT);
        }
        let old_parent = object_body(runtime, old_parent_handle, RC_REWRAP_OLD_PARENT)?;
        if old_parent.public.object_type == TPM_ALG_RSA
            && rsa_secret_reaches_self_test(&old_parent, &in_sym_seed)
        {
            self_test_rsa_oaep(runtime)?;
        }
        let data = secret_decrypt(&old_parent, DUPLICATE_LABEL, &in_sym_seed)
            .map_err(|_| TPM_RC_VALUE + RC_REWRAP_IN_SYM_SEED)?;
        let protector = duplication_protector(&old_parent.public);
        unwrap_outer(
            &protector,
            &name,
            old_parent.public.name_alg,
            Some(&data),
            false,
            &in_duplicate,
            TPM_RC_FAILURE,
        )
        .map_err(|code| add_modifier(code, RC_REWRAP_IN_DUPLICATE))?
    };

    if new_parent_handle == TPM_RH_NULL {
        return rewrap_output(&private_blob, &[]);
    }

    if !object_is_storage(runtime, new_parent_handle) {
        return Err(TPM_RC_TYPE + RC_REWRAP_NEW_PARENT);
    }
    let new_parent = object_body(runtime, new_parent_handle, RC_REWRAP_NEW_PARENT)?;
    let encrypted = secret_encrypt(runtime, &new_parent.public, DUPLICATE_LABEL)?;
    let hash_size = 2 + digest_size(new_parent.public.name_alg).ok_or(TPM_RC_FAILURE)?;
    if private_blob.len() + hash_size > MAX_PRIVATE {
        return Err(TPM_RC_VALUE + RC_REWRAP_IN_DUPLICATE);
    }
    let protector = duplication_protector(&new_parent.public);
    let mut rand = take_live_rand(runtime)?;
    let wrapped = produce_outer_wrap(
        &protector,
        &name,
        new_parent.public.name_alg,
        Some(&encrypted.data),
        false,
        &private_blob,
        &mut rand,
    );
    finish_live_rand(runtime, rand)?;
    rewrap_output(&wrapped?, &encrypted.secret)
}

fn rewrap_output(duplicate: &[u8], sym_seed: &[u8]) -> Result<CommandOutput, TpmResult> {
    let mut writer = BlobWriter::new();
    writer.write_tpm2b(duplicate).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(sym_seed).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(super) fn execute_import(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let parent_handle = handle_at(frame, 0)?;

    let encryption_key;
    let object_public;
    let duplicate;
    let in_sym_seed;
    let symmetric;
    {
        let policy = algorithm_policy(runtime)?;
        let mut reader = TemplateReader::new(frame.parameters);
        encryption_key = read_data(&mut reader, RC_IMPORT_ENCRYPTION_KEY)?;
        object_public = parse_sized_public(&mut reader, &policy, false)
            .map_err(|code| add_modifier(code, RC_IMPORT_OBJECT_PUBLIC))?;
        duplicate = read_private(&mut reader, RC_IMPORT_DUPLICATE)?;
        in_sym_seed = read_encrypted_secret(&mut reader, RC_IMPORT_IN_SYM_SEED)?;
        symmetric = policy
            .sym_object(&mut reader, true)
            .map_err(|code| add_modifier(code, RC_IMPORT_SYMMETRIC_ALG))?;
        if !reader.remaining().is_empty() {
            return Err(TPM_RC_SIZE);
        }
    }

    let attributes = object_public.object_attributes;
    if attributes & (TPMA_OBJECT_FIXED_TPM | TPMA_OBJECT_FIXED_PARENT) != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_IMPORT_OBJECT_PUBLIC);
    }
    if slot_attributes(runtime, parent_handle)? & ATTR_IS_PARENT == 0 {
        return Err(TPM_RC_TYPE + RC_IMPORT_PARENT_HANDLE);
    }
    let parent = object_body(runtime, parent_handle, RC_IMPORT_PARENT_HANDLE)?;

    if symmetric.algorithm != TPM_ALG_NULL {
        if encryption_key.len() != inner_key_bytes(&symmetric) {
            return Err(TPM_RC_SIZE + RC_IMPORT_ENCRYPTION_KEY);
        }
    } else {
        if !encryption_key.is_empty() {
            return Err(TPM_RC_SIZE + RC_IMPORT_ENCRYPTION_KEY);
        }
        if attributes & TPMA_OBJECT_ENCRYPTED_DUPLICATION != 0 {
            return Err(TPM_RC_ATTRIBUTES + RC_IMPORT_ENCRYPTION_KEY);
        }
    }

    let data = if in_sym_seed.is_empty() {
        if attributes & TPMA_OBJECT_ENCRYPTED_DUPLICATION != 0 {
            return Err(TPM_RC_ATTRIBUTES + RC_IMPORT_IN_SYM_SEED);
        }
        Vec::new()
    } else {
        if parent.public.object_type == TPM_ALG_SYMCIPHER {
            return Err(TPM_RC_TYPE + RC_IMPORT_PARENT_HANDLE);
        }
        if parent.public.object_type == TPM_ALG_RSA
            && rsa_secret_reaches_self_test(&parent, &in_sym_seed)
        {
            self_test_rsa_oaep(runtime)?;
        }
        secret_decrypt(&parent, DUPLICATE_LABEL, &in_sym_seed)
            .map_err(|code| add_modifier(code, RC_IMPORT_IN_SYM_SEED))?
    };

    let name = public_marshal_and_compute_name(&object_public)?;
    if name.is_empty() {
        return Err(TPM_RC_HASH + RC_IMPORT_OBJECT_PUBLIC);
    }

    let name_alg = object_public.name_alg;
    let protector = duplication_protector(&parent.public);
    let sensitive = duplicate_to_sensitive(
        &duplicate,
        &name,
        Some(&protector),
        name_alg,
        &data,
        &symmetric,
        &encryption_key,
    )
    .map_err(|code| add_modifier(code, RC_IMPORT_DUPLICATE))?;

    if parent.public.object_attributes & TPMA_OBJECT_FIXED_TPM != 0 {
        object_load(
            None,
            object_public,
            Some(sensitive.clone()),
            RC_IMPORT_OBJECT_PUBLIC,
            RC_IMPORT_DUPLICATE,
            name.clone(),
        )?;
    }

    let mut rand = take_live_rand(runtime)?;
    let out_private = sensitive_to_private(
        &sensitive,
        &name,
        &Protector {
            public: &parent.public,
            seed_value: parent.sensitive.seed_value.as_bytes(),
        },
        name_alg,
        &mut rand,
    );
    finish_live_rand(runtime, rand)?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&out_private?).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod harness {
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::crypto::Hasher;
    use crate::library::tpm2::golden_responses::object_transfer::vector;
    use crate::library::tpm2::object_load::replay::{
        exec_raw, framed, handles, plain, push_tpm2b, response_parameters, runtime_from, tpm2b,
    };
    use crate::library::tpm2::runtime::Tpm2Runtime;

    pub(super) const RH_OWNER: u32 = 0x4000_0001;
    pub(super) const RH_NULL: u32 = 0x4000_0007;
    pub(super) const RH_PLATFORM: u32 = 0x4000_000c;
    pub(super) const RS_PW: u32 = 0x4000_0009;
    pub(super) const SESSION: u32 = 0x0300_0000;

    pub(super) const H0: u32 = 0x8000_0000;
    pub(super) const H1: u32 = 0x8000_0001;
    pub(super) const H2: u32 = 0x8000_0002;

    pub(super) const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
    pub(super) const CC_CREATE: u32 = 0x0000_0153;
    pub(super) const CC_LOAD: u32 = 0x0000_0157;
    pub(super) const CC_DUPLICATE: u32 = 0x0000_014b;
    pub(super) const CC_REWRAP: u32 = 0x0000_0152;
    pub(super) const CC_IMPORT: u32 = 0x0000_0156;
    pub(super) const CC_UNSEAL: u32 = 0x0000_015e;
    pub(super) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    pub(super) const CC_POLICY_COMMAND_CODE: u32 = 0x0000_016c;
    pub(super) const CC_POLICY_DUPLICATION_SELECT: u32 = 0x0000_0188;
    pub(super) const CC_POLICY_GET_DIGEST: u32 = 0x0000_0189;
    pub(super) const CC_READ_PUBLIC: u32 = 0x0000_0173;
    pub(super) const CC_GET_CAPABILITY: u32 = 0x0000_017a;
    pub(super) const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

    pub(super) const ALG_NULL: u16 = 0x0010;
    pub(super) const ALG_AES: u16 = 0x0006;
    pub(super) const ALG_CFB: u16 = 0x0043;
    pub(super) const ALG_SHA256: u16 = 0x000b;

    pub(super) const SEAL_AUTH: &[u8] = b"dup-auth";
    pub(super) const SEAL_DATA: &[u8] = b"duplicable payload";
    pub(super) const INNER_KEY: [u8; 16] = [0xa5; 16];
    pub(super) const WRONG_INNER_KEY: [u8; 16] = [0x5a; 16];

    pub(super) const ATTR_USER_NODA: u32 = 0x0000_0440;
    pub(super) const ATTR_USER_NODA_ENCDUP: u32 = 0x0000_0c40;
    pub(super) const ATTR_FIXED: u32 = 0x0000_0452;
    pub(super) const STORAGE_ATTRS: u32 = 0x0003_0472;

    pub(super) fn clock() -> SteppingClock {
        crate::library::tpm2::object_load::replay::clock()
    }

    pub(super) fn runtime_at(snapshot: &str, clock: &SteppingClock) -> Box<Tpm2Runtime> {
        runtime_from(
            vector(&format!("PERMALL_{snapshot}")),
            vector(&format!("VOLATILE_{snapshot}")),
            clock,
        )
    }

    #[track_caller]
    pub(super) fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: Vec<u8>,
    ) {
        assert_eq!(exec_raw(runtime, clock, bytes), vector(label), "{label}");
    }

    #[track_caller]
    pub(super) fn run(runtime: &mut Tpm2Runtime, clock: &SteppingClock, bytes: Vec<u8>) {
        exec_raw(runtime, clock, bytes);
    }

    pub(super) fn password_area(password: &[u8]) -> Vec<u8> {
        let mut area = RS_PW.to_be_bytes().to_vec();
        push_tpm2b(&mut area, &[]);
        area.push(0x00);
        push_tpm2b(&mut area, password);
        let mut out = (area.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&area);
        out
    }

    pub(super) fn policy_area() -> Vec<u8> {
        let mut area = SESSION.to_be_bytes().to_vec();
        push_tpm2b(&mut area, &[0x5a; 16]);
        area.push(0x01);
        push_tpm2b(&mut area, &[]);
        let mut out = (area.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&area);
        out
    }

    pub(super) fn sessioned(
        code: u32,
        handle_list: &[u32],
        auth: &[u8],
        parameters: &[u8],
    ) -> Vec<u8> {
        let mut payload = handles(handle_list);
        payload.extend_from_slice(auth);
        payload.extend_from_slice(parameters);
        framed(0x8002, code, &payload)
    }

    pub(super) fn sym_aes128_cfb() -> Vec<u8> {
        let mut out = ALG_AES.to_be_bytes().to_vec();
        out.extend_from_slice(&128u16.to_be_bytes());
        out.extend_from_slice(&ALG_CFB.to_be_bytes());
        out
    }

    pub(super) fn sym_null() -> Vec<u8> {
        ALG_NULL.to_be_bytes().to_vec()
    }

    pub(super) fn rsa_storage_template() -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&STORAGE_ATTRS.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&sym_aes128_cfb());
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(super) fn ecc_storage_template() -> Vec<u8> {
        let mut out = 0x0023u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&STORAGE_ATTRS.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&sym_aes128_cfb());
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        out.extend_from_slice(&0x0003u16.to_be_bytes());
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(super) fn sym_storage_template() -> Vec<u8> {
        let mut out = 0x0025u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&STORAGE_ATTRS.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out.extend_from_slice(&sym_aes128_cfb());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(super) fn sealed_template(attributes: u32, policy: &[u8]) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        push_tpm2b(&mut out, policy);
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out
    }

    fn sensitive_create(auth: &[u8], data: &[u8]) -> Vec<u8> {
        let mut inner = tpm2b(auth);
        inner.extend_from_slice(&tpm2b(data));
        tpm2b(&inner)
    }

    pub(super) fn create_primary(hierarchy: u32, template: &[u8]) -> Vec<u8> {
        let mut parameters = sensitive_create(&[], &[]);
        parameters.extend_from_slice(&tpm2b(template));
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&0u32.to_be_bytes());
        sessioned(
            CC_CREATE_PRIMARY,
            &[hierarchy],
            &password_area(&[]),
            &parameters,
        )
    }

    pub(super) fn create(parent: u32, auth: &[u8], data: &[u8], template: &[u8]) -> Vec<u8> {
        let mut parameters = sensitive_create(auth, data);
        parameters.extend_from_slice(&tpm2b(template));
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&0u32.to_be_bytes());
        sessioned(CC_CREATE, &[parent], &password_area(&[]), &parameters)
    }

    pub(super) fn load(parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
        let mut parameters = tpm2b(private);
        parameters.extend_from_slice(&tpm2b(public));
        sessioned(CC_LOAD, &[parent], &password_area(&[]), &parameters)
    }

    pub(super) fn start_policy_session() -> Vec<u8> {
        let mut payload = handles(&[RH_NULL, RH_NULL]);
        push_tpm2b(&mut payload, &[0x5a; 32]);
        push_tpm2b(&mut payload, &[]);
        payload.push(0x01);
        payload.extend_from_slice(&ALG_NULL.to_be_bytes());
        payload.extend_from_slice(&ALG_SHA256.to_be_bytes());
        plain(CC_START_AUTH_SESSION, &payload)
    }

    pub(super) fn policy_command_code(code: u32) -> Vec<u8> {
        let mut payload = SESSION.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        plain(CC_POLICY_COMMAND_CODE, &payload)
    }

    pub(super) fn policy_duplication_select(
        object_name: &[u8],
        parent_name: &[u8],
        include: u8,
    ) -> Vec<u8> {
        let mut payload = SESSION.to_be_bytes().to_vec();
        push_tpm2b(&mut payload, object_name);
        push_tpm2b(&mut payload, parent_name);
        payload.push(include);
        plain(CC_POLICY_DUPLICATION_SELECT, &payload)
    }

    pub(super) fn policy_get_digest() -> Vec<u8> {
        plain(CC_POLICY_GET_DIGEST, &SESSION.to_be_bytes())
    }

    pub(super) fn duplicate(object: u32, new_parent: u32) -> Vec<u8> {
        duplicate_with(object, new_parent, &[], &sym_null(), &policy_area())
    }

    pub(super) fn duplicate_with(
        object: u32,
        new_parent: u32,
        key_in: &[u8],
        symmetric: &[u8],
        auth: &[u8],
    ) -> Vec<u8> {
        let mut parameters = tpm2b(key_in);
        parameters.extend_from_slice(symmetric);
        sessioned(CC_DUPLICATE, &[object, new_parent], auth, &parameters)
    }

    pub(super) fn rewrap(
        old_parent: u32,
        new_parent: u32,
        in_duplicate: &[u8],
        name: &[u8],
        in_sym_seed: &[u8],
    ) -> Vec<u8> {
        let mut parameters = tpm2b(in_duplicate);
        parameters.extend_from_slice(&tpm2b(name));
        parameters.extend_from_slice(&tpm2b(in_sym_seed));
        sessioned(
            CC_REWRAP,
            &[old_parent, new_parent],
            &password_area(&[]),
            &parameters,
        )
    }

    pub(super) fn import(
        parent: u32,
        key: &[u8],
        public: &[u8],
        blob: &[u8],
        seed: &[u8],
    ) -> Vec<u8> {
        import_with(parent, key, public, blob, seed, &sym_null())
    }

    pub(super) fn import_with(
        parent: u32,
        key: &[u8],
        public: &[u8],
        blob: &[u8],
        seed: &[u8],
        symmetric: &[u8],
    ) -> Vec<u8> {
        let mut parameters = tpm2b(key);
        parameters.extend_from_slice(&tpm2b(public));
        parameters.extend_from_slice(&tpm2b(blob));
        parameters.extend_from_slice(&tpm2b(seed));
        parameters.extend_from_slice(symmetric);
        sessioned(CC_IMPORT, &[parent], &password_area(&[]), &parameters)
    }

    pub(super) fn unseal(handle: u32, auth: &[u8]) -> Vec<u8> {
        sessioned(CC_UNSEAL, &[handle], &password_area(auth), &[])
    }

    pub(super) fn read_public(handle: u32) -> Vec<u8> {
        plain(CC_READ_PUBLIC, &handle.to_be_bytes())
    }

    pub(super) fn cap_cc(code: u32) -> Vec<u8> {
        cap_cc_page(code, 1)
    }

    pub(super) fn cap_cc_page(code: u32, count: u32) -> Vec<u8> {
        let mut payload = 2u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(&count.to_be_bytes());
        plain(CC_GET_CAPABILITY, &payload)
    }

    pub(super) fn command_page(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        code: u32,
        count: u32,
    ) -> (bool, Vec<u32>) {
        let response = exec_raw(runtime, clock, cap_cc_page(code, count));
        assert_eq!(&response[6..10], &[0, 0, 0, 0], "the query succeeds");
        let more = response[10] != 0;
        let entries = u32::from_be_bytes(response[15..19].try_into().expect("four bytes"));
        let mut out = Vec::with_capacity(entries as usize);
        for index in 0..entries as usize {
            let at = 19 + index * 4;
            out.push(u32::from_be_bytes(
                response[at..at + 4].try_into().expect("four bytes"),
            ));
        }
        (more, out)
    }

    #[track_caller]
    pub(super) fn exec_counting_nv(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        bytes: Vec<u8>,
        commits: &std::cell::Cell<usize>,
    ) -> Vec<u8> {
        let input = crate::library::CommandInput::new(bytes.len() as u32, bytes);
        crate::library::tpm2::process::process(
            runtime,
            crate::library::tpm2::PlatformInputs::at_locality(0),
            &input,
            clock,
            |_| {
                commits.set(commits.get() + 1);
                Ok(())
            },
        )
        .expect("the command processes")
    }

    pub(super) fn generator_state(runtime: &Tpm2Runtime) -> (u64, [u32; 4], Vec<u8>) {
        let drbg = &runtime.live.orderly.drbg_state;
        (
            drbg.reseed_counter,
            drbg.last_value,
            drbg.seed.as_bytes().to_vec(),
        )
    }

    pub(super) fn object_images(runtime: &Tpm2Runtime) -> Vec<Vec<u8>> {
        use crate::library::tpm2::nv::any_object_image;
        use crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION;
        runtime
            .live
            .objects
            .iter()
            .map(|object| {
                any_object_image(object, CURRENT_OBJECT_VERSION).expect("the object serializes")
            })
            .collect()
    }

    pub(super) fn cap_transient() -> Vec<u8> {
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&H0.to_be_bytes());
        payload.extend_from_slice(&8u32.to_be_bytes());
        plain(CC_GET_CAPABILITY, &payload)
    }

    pub(super) fn flush(handle: u32) -> Vec<u8> {
        plain(CC_FLUSH_CONTEXT, &handle.to_be_bytes())
    }

    pub(super) fn with_trailing(command: Vec<u8>) -> Vec<u8> {
        let mut out = command;
        out.push(0x00);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    pub(super) fn truncated(command: Vec<u8>, drop: usize) -> Vec<u8> {
        let mut out = command;
        out.truncate(out.len() - drop);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    pub(super) fn flipped(data: &[u8], index: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        out[index] ^= 0x01;
        out
    }

    pub(super) fn sha256(parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Hasher::new(ALG_SHA256).expect("sha256");
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    pub(super) fn object_name(public: &[u8]) -> Vec<u8> {
        let mut name = ALG_SHA256.to_be_bytes().to_vec();
        name.extend_from_slice(&sha256(&[public]));
        name
    }

    pub(super) fn dup_policy() -> Vec<u8> {
        sha256(&[
            &[0u8; 32],
            &CC_POLICY_COMMAND_CODE.to_be_bytes(),
            &CC_DUPLICATE.to_be_bytes(),
        ])
    }

    pub(super) fn duplication_select_policy(parent_name: &[u8]) -> Vec<u8> {
        sha256(&[
            &[0u8; 32],
            &CC_POLICY_DUPLICATION_SELECT.to_be_bytes(),
            parent_name,
            &[0u8],
        ])
    }

    fn split_tpm2b(blob: &[u8], at: usize) -> (Vec<u8>, usize) {
        let size = u16::from_be_bytes(blob[at..at + 2].try_into().expect("two bytes")) as usize;
        (blob[at + 2..at + 2 + size].to_vec(), at + 2 + size)
    }

    pub(super) fn created(label: &str) -> (Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(vector(label));
        let (private, at) = split_tpm2b(&parameters, 0);
        let (public, _) = split_tpm2b(&parameters, at);
        (private, public)
    }

    pub(super) fn primary_public(label: &str) -> Vec<u8> {
        let response = vector(label);
        let size = u32::from_be_bytes(response[14..18].try_into().expect("four bytes")) as usize;
        let (public, _) = split_tpm2b(&response[18..18 + size], 0);
        public
    }

    pub(super) fn duplicated(label: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(vector(label));
        let (key, at) = split_tpm2b(&parameters, 0);
        let (blob, at) = split_tpm2b(&parameters, at);
        let (seed, _) = split_tpm2b(&parameters, at);
        (key, blob, seed)
    }

    pub(super) fn rewrapped(label: &str) -> (Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(vector(label));
        let (blob, at) = split_tpm2b(&parameters, 0);
        let (seed, _) = split_tpm2b(&parameters, at);
        (blob, seed)
    }

    pub(super) fn imported(label: &str) -> Vec<u8> {
        let parameters = response_parameters(vector(label));
        split_tpm2b(&parameters, 0).0
    }
}

#[cfg(test)]
mod tests {
    use super::super::registry::{self, AuthRole, CommandLifecycle, HandleKind, NvAccess};
    use super::harness::*;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::object_load::replay::{exec_raw, handles, plain, tpm2b};
    use crate::library::tpm2::runtime::Tpm2Runtime;

    fn occupied(runtime: &Tpm2Runtime) -> Vec<bool> {
        runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect()
    }

    fn child() -> (Vec<u8>, Vec<u8>) {
        created("CREATE_DUP_CHILD")
    }

    fn child_public() -> Vec<u8> {
        child().1
    }

    fn child_name() -> Vec<u8> {
        object_name(&child_public())
    }

    fn open_dup_policy(
        runtime: &mut Tpm2Runtime,
        clock: &crate::library::tpm2::clock::SteppingClock,
    ) {
        run(runtime, clock, start_policy_session());
        run(runtime, clock, policy_command_code(CC_DUPLICATE));
    }

    #[test]
    fn the_commands_are_registered_with_the_upstream_attributes() {
        let duplicate = registry::find(CC_DUPLICATE).expect("TPM2_Duplicate is registered");
        assert_eq!(duplicate.attributes, 0x0400_014b);
        assert_eq!(duplicate.decrypt_size, 2);
        assert_eq!(duplicate.encrypt_size, 2);
        assert!(duplicate.sessions_allowed);
        assert!(!duplicate.physical_presence);
        assert!(matches!(duplicate.nv_access, NvAccess::Neither));
        assert!(matches!(
            duplicate.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(duplicate.handles.len(), 2);
        assert!(duplicate.handles[0].user_auth);
        assert!(duplicate.handles[0].dup_role());
        assert!(!duplicate.handles[0].admin_role());
        assert!(matches!(duplicate.handles[0].kind, HandleKind::Object));
        assert!(!duplicate.handles[1].user_auth);
        assert!(duplicate.handles[1].role == AuthRole::User);
        assert!(matches!(
            duplicate.handles[1].kind,
            HandleKind::ObjectAllowNull
        ));

        let rewrap = registry::find(CC_REWRAP).expect("TPM2_Rewrap is registered");
        assert_eq!(rewrap.attributes, 0x0400_0152);
        assert_eq!(rewrap.decrypt_size, 2);
        assert_eq!(rewrap.encrypt_size, 2);
        assert!(rewrap.sessions_allowed);
        assert!(!rewrap.physical_presence);
        assert!(matches!(rewrap.nv_access, NvAccess::Neither));
        assert_eq!(rewrap.handles.len(), 2);
        assert!(rewrap.handles[0].user_auth);
        assert!(
            rewrap
                .handles
                .iter()
                .all(|spec| spec.role == AuthRole::User)
        );
        assert!(
            rewrap
                .handles
                .iter()
                .all(|spec| matches!(spec.kind, HandleKind::ObjectAllowNull))
        );
        assert!(!rewrap.handles[1].user_auth);

        let import = registry::find(CC_IMPORT).expect("TPM2_Import is registered");
        assert_eq!(import.attributes, 0x0200_0156);
        assert_eq!(import.decrypt_size, 2);
        assert_eq!(import.encrypt_size, 2);
        assert!(import.sessions_allowed);
        assert!(!import.physical_presence);
        assert!(matches!(import.nv_access, NvAccess::Neither));
        assert_eq!(import.handles.len(), 1);
        assert!(import.handles[0].user_auth);
        assert!(import.handles[0].role == AuthRole::User);
        assert!(matches!(import.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(&mut runtime, &clock, "CCATTR_014B", cap_cc(0x014b));
        exec(&mut runtime, &clock, "CCATTR_0152", cap_cc(0x0152));
        exec(&mut runtime, &clock, "CCATTR_0156", cap_cc(0x0156));
    }

    #[test]
    fn unloaded_and_mistyped_handles_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "DUP_UNLOADED_OBJECT",
            duplicate(H0, H1),
        );
        exec(
            &mut runtime,
            &clock,
            "DUP_BAD_OBJECT_HANDLE",
            duplicate(RH_OWNER, H1),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_UNLOADED_PARENT",
            rewrap(H1, H0, &[0x11; 70], &[0x22; 34], &[0x33; 256]),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_BAD_PARENT_HANDLE",
            rewrap(RH_OWNER, RH_NULL, &[0x11; 70], &[0x22; 34], &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_UNLOADED_PARENT",
            import(H0, &[], &[0x44; 46], &[0x11; 70], &[0x33; 256]),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_BAD_PARENT_HANDLE",
            import(RH_OWNER, &[], &[0x44; 46], &[0x11; 70], &[0x33; 256]),
        );
        assert_eq!(occupied(&runtime), [false, false, false]);
    }

    #[test]
    fn the_transfer_objects_are_created_like_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_SRK",
            create_primary(RH_OWNER, &rsa_storage_template()),
        );
        exec(
            &mut runtime,
            &clock,
            "CREATE_DUP_CHILD",
            create(
                H0,
                SEAL_AUTH,
                SEAL_DATA,
                &sealed_template(ATTR_USER_NODA, &dup_policy()),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "CREATE_ENCDUP_CHILD",
            create(
                H0,
                SEAL_AUTH,
                SEAL_DATA,
                &sealed_template(ATTR_USER_NODA_ENCDUP, &dup_policy()),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "CREATE_FIXED_CHILD",
            create(
                H0,
                SEAL_AUTH,
                SEAL_DATA,
                &sealed_template(ATTR_FIXED, &dup_policy()),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "CREATE_SYM_PARENT",
            create(H0, &[], &[], &sym_storage_template()),
        );
        exec(
            &mut runtime,
            &clock,
            "CREATE_PLAIN_CHILD",
            create(H0, &[], SEAL_DATA, &sealed_template(ATTR_USER_NODA, &[])),
        );
    }

    #[test]
    fn the_transfer_parents_are_loaded_like_the_oracle() {
        let clock = clock();
        let (private, public) = child();

        let mut runtime = runtime_at("SRK_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_TARGET",
            create_primary(RH_PLATFORM, &rsa_storage_template()),
        );
        exec(
            &mut runtime,
            &clock,
            "LOAD_DUP_CHILD",
            load(H0, &private, &public),
        );

        let mut runtime = runtime_at("SRK_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_ECC",
            create_primary(RH_OWNER, &ecc_storage_template()),
        );
        exec(
            &mut runtime,
            &clock,
            "LOAD_DUP_CHILD_UNDER_ECC",
            load(H0, &private, &public),
        );
    }

    #[test]
    fn the_rsa_duplicate_import_load_round_trip_matches_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        exec(&mut runtime, &clock, "SAS_DUP", start_policy_session());
        exec(
            &mut runtime,
            &clock,
            "PCC_DUP",
            policy_command_code(CC_DUPLICATE),
        );
        exec(&mut runtime, &clock, "PGD_DUP", policy_get_digest());
        exec(&mut runtime, &clock, "DUP_RSA", duplicate(H2, H1));
        assert_eq!(
            occupied(&runtime),
            [true, true, true],
            "a successful duplication keeps the source object loaded"
        );

        let (key, blob, seed) = duplicated("DUP_RSA");
        assert!(key.is_empty(), "no inner wrapper means no key is returned");
        exec(
            &mut runtime,
            &clock,
            "IMPORT_RSA",
            import(H1, &[], &child_public(), &blob, &seed),
        );
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_IMPORTED_RSA",
            load(H1, &imported("IMPORT_RSA"), &child_public()),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_IMPORTED_RSA",
            read_public(H2),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_IMPORTED_RSA",
            unseal(H2, SEAL_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_IMPORTED_WRONG_AUTH",
            unseal(H2, b"wrong-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "CAP_TRANSIENT_AFTER_IMPORT",
            cap_transient(),
        );
    }

    #[test]
    fn a_tpm_generated_inner_wrapper_matches_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        exec(
            &mut runtime,
            &clock,
            "DUP_RSA_INNER_TPM",
            duplicate_with(H2, H1, &[], &sym_aes128_cfb(), &policy_area()),
        );
        let (key, blob, seed) = duplicated("DUP_RSA_INNER_TPM");
        assert_eq!(key.len(), 16, "the TPM returns the key it generated");
        exec(
            &mut runtime,
            &clock,
            "IMPORT_RSA_INNER_TPM",
            import_with(H1, &key, &child_public(), &blob, &seed, &sym_aes128_cfb()),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_INNER_WRONG_KEY",
            import_with(
                H1,
                &WRONG_INNER_KEY,
                &child_public(),
                &blob,
                &seed,
                &sym_aes128_cfb(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_INNER_CORRUPT",
            import_with(
                H1,
                &key,
                &child_public(),
                &flipped(&blob, blob.len() - 1),
                &seed,
                &sym_aes128_cfb(),
            ),
        );
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_INNER_TPM",
            load(H1, &imported("IMPORT_RSA_INNER_TPM"), &child_public()),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_INNER_TPM",
            unseal(H2, SEAL_AUTH),
        );
    }

    #[test]
    fn a_caller_supplied_inner_wrapper_matches_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        exec(
            &mut runtime,
            &clock,
            "DUP_RSA_INNER_CALLER",
            duplicate_with(H2, H1, &INNER_KEY, &sym_aes128_cfb(), &policy_area()),
        );
        let (key, blob, seed) = duplicated("DUP_RSA_INNER_CALLER");
        assert!(
            key.is_empty(),
            "a caller-supplied key is not echoed back to the caller"
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_RSA_INNER_CALLER",
            import_with(
                H1,
                &INNER_KEY,
                &child_public(),
                &blob,
                &seed,
                &sym_aes128_cfb(),
            ),
        );
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_INNER_CALLER",
            load(H1, &imported("IMPORT_RSA_INNER_CALLER"), &child_public()),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_INNER_CALLER",
            unseal(H2, SEAL_AUTH),
        );
    }

    #[test]
    fn the_ecc_seed_encryption_stays_byte_compatible_with_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("ECC_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        exec(&mut runtime, &clock, "DUP_ECC", duplicate(H2, H1));
        let (_key, _blob, seed) = duplicated("DUP_ECC");
        assert_eq!(seed.len(), 2 + 32 + 2 + 32, "a marshalled P-256 point");
    }

    #[test]
    fn the_ecc_parent_and_rewrap_paths_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("ECC_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        exec(&mut runtime, &clock, "DUP_ECC", duplicate(H2, H1));
        let (_key, blob, seed) = duplicated("DUP_ECC");
        exec(
            &mut runtime,
            &clock,
            "REWRAP_ECC_TO_SRK",
            rewrap(H1, H0, &blob, &child_name(), &seed),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_ECC_DIRECT",
            import(H1, &[], &child_public(), &blob, &seed),
        );
        let (new_blob, new_seed) = rewrapped("REWRAP_ECC_TO_SRK");
        exec(
            &mut runtime,
            &clock,
            "IMPORT_FROM_REWRAP_SRK",
            import(H0, &[], &child_public(), &new_blob, &new_seed),
        );
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_FROM_REWRAP_SRK",
            load(H0, &imported("IMPORT_FROM_REWRAP_SRK"), &child_public()),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_FROM_REWRAP_SRK",
            unseal(H2, SEAL_AUTH),
        );
    }

    #[test]
    fn the_null_parent_path_matches_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        exec(
            &mut runtime,
            &clock,
            "DUP_NULL_PARENT",
            duplicate(H2, RH_NULL),
        );
        let (key, blob, seed) = duplicated("DUP_NULL_PARENT");
        assert!(key.is_empty());
        assert!(seed.is_empty(), "a null parent produces no seed");
        exec(
            &mut runtime,
            &clock,
            "REWRAP_NULL_TO_NULL",
            rewrap(RH_NULL, RH_NULL, &blob, &child_name(), &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_NULL_TO_RSA",
            rewrap(RH_NULL, H1, &blob, &child_name(), &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_WRONG_NEW_PARENT_TYPE",
            rewrap(RH_NULL, H2, &blob, &child_name(), &[]),
        );
        let (new_blob, new_seed) = rewrapped("REWRAP_NULL_TO_RSA");
        exec(
            &mut runtime,
            &clock,
            "IMPORT_FROM_NULL_REWRAP",
            import(H1, &[], &child_public(), &new_blob, &new_seed),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_RSA_BACK_TO_NULL",
            rewrap(H1, RH_NULL, &new_blob, &child_name(), &new_seed),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_WRONG_NAME",
            rewrap(
                H1,
                H0,
                &new_blob,
                &object_name(&created("CREATE_PLAIN_CHILD").1),
                &new_seed,
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_CORRUPT_OUTER",
            rewrap(H1, H0, &flipped(&new_blob, 3), &child_name(), &new_seed),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_BAD_SEED",
            rewrap(H1, H0, &new_blob, &child_name(), &flipped(&new_seed, 5)),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_WRONG_OLD_PARENT",
            rewrap(H0, H1, &new_blob, &child_name(), &new_seed),
        );
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_FROM_NULL_REWRAP",
            load(H1, &imported("IMPORT_FROM_NULL_REWRAP"), &child_public()),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_FROM_NULL_REWRAP",
            unseal(H2, SEAL_AUTH),
        );
    }

    #[test]
    fn encrypted_duplication_requires_both_wrappers_like_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let (private, public) = created("CREATE_ENCDUP_CHILD");
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_ENCDUP_CHILD",
            load(H0, &private, &public),
        );
        open_dup_policy(&mut runtime, &clock);
        exec(
            &mut runtime,
            &clock,
            "DUP_ENCDUP_WITHOUT_INNER",
            duplicate(H2, H1),
        );
        exec(
            &mut runtime,
            &clock,
            "DUP_ENCDUP_NULL_PARENT",
            duplicate_with(H2, RH_NULL, &[], &sym_aes128_cfb(), &policy_area()),
        );
        exec(
            &mut runtime,
            &clock,
            "DUP_ENCDUP",
            duplicate_with(H2, H1, &[], &sym_aes128_cfb(), &policy_area()),
        );
        let (key, blob, seed) = duplicated("DUP_ENCDUP");
        exec(
            &mut runtime,
            &clock,
            "IMPORT_ENCDUP_WITHOUT_INNER",
            import(H1, &[], &public, &blob, &seed),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_ENCDUP_WITHOUT_SEED",
            import_with(H1, &key, &public, &blob, &[], &sym_aes128_cfb()),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_ENCDUP",
            import_with(H1, &key, &public, &blob, &seed, &sym_aes128_cfb()),
        );
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_ENCDUP_IMPORTED",
            load(H1, &imported("IMPORT_ENCDUP"), &public),
        );
        exec(
            &mut runtime,
            &clock,
            "UNSEAL_ENCDUP_IMPORTED",
            unseal(H2, SEAL_AUTH),
        );
    }

    #[test]
    fn policy_duplication_select_authorizes_one_new_parent() {
        let clock = clock();
        let mut runtime = runtime_at("SRK_READY", &clock);
        let target_name = object_name(&primary_public("CP_TARGET"));
        exec(
            &mut runtime,
            &clock,
            "CREATE_PDS_CHILD",
            create(
                H0,
                SEAL_AUTH,
                SEAL_DATA,
                &sealed_template(ATTR_USER_NODA, &duplication_select_policy(&target_name)),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_TARGET_FOR_PDS",
            create_primary(RH_PLATFORM, &rsa_storage_template()),
        );
        let (private, public) = created("CREATE_PDS_CHILD");
        exec(
            &mut runtime,
            &clock,
            "LOAD_PDS_CHILD",
            load(H0, &private, &public),
        );
        exec(&mut runtime, &clock, "SAS_PDS", start_policy_session());
        exec(
            &mut runtime,
            &clock,
            "PDS_SELECT",
            policy_duplication_select(&object_name(&public), &target_name, 0),
        );
        exec(&mut runtime, &clock, "PGD_PDS", policy_get_digest());
        exec(
            &mut runtime,
            &clock,
            "DUP_PDS_WRONG_PARENT",
            duplicate(H2, H0),
        );
        exec(&mut runtime, &clock, "DUP_PDS", duplicate(H2, H1));
    }

    #[test]
    fn duplicate_authorization_failures_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "SAS_NO_POLICY",
            start_policy_session(),
        );
        exec(
            &mut runtime,
            &clock,
            "DUP_POLICY_NOT_SET",
            duplicate(H2, H1),
        );
        run(&mut runtime, &clock, policy_command_code(CC_LOAD));
        exec(
            &mut runtime,
            &clock,
            "DUP_POLICY_MISMATCH",
            duplicate(H2, H1),
        );
        exec(
            &mut runtime,
            &clock,
            "DUP_PASSWORD_SESSION",
            duplicate_with(H2, H1, &[], &sym_null(), &password_area(SEAL_AUTH)),
        );
        let mut payload = handles(&[H2, H1]);
        payload.extend_from_slice(&tpm2b(&[]));
        payload.extend_from_slice(&sym_null());
        exec(
            &mut runtime,
            &clock,
            "DUP_NO_SESSIONS",
            plain(CC_DUPLICATE, &payload),
        );
    }

    #[test]
    fn duplicate_rejections_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        for (label, command) in [
            ("DUP_OBJECT_WITHOUT_POLICY", duplicate(H0, H1)),
            (
                "DUP_KEY_WITHOUT_SYM",
                duplicate_with(H2, H1, &INNER_KEY, &sym_null(), &policy_area()),
            ),
            (
                "DUP_KEY_WRONG_SIZE",
                duplicate_with(H2, H1, &INNER_KEY[..8], &sym_aes128_cfb(), &policy_area()),
            ),
            ("DUP_NEW_PARENT_NOT_STORAGE", duplicate(H2, H2)),
            (
                "DUP_UNKNOWN_SYM_ALG",
                duplicate_with(
                    H2,
                    H1,
                    &[],
                    &sym_definition(0x0005, 128, ALG_CFB),
                    &policy_area(),
                ),
            ),
            (
                "DUP_BAD_SYM_KEY_BITS",
                duplicate_with(
                    H2,
                    H1,
                    &[],
                    &sym_definition(ALG_AES, 7, ALG_CFB),
                    &policy_area(),
                ),
            ),
            (
                "DUP_BAD_SYM_MODE",
                duplicate_with(
                    H2,
                    H1,
                    &[],
                    &sym_definition(ALG_AES, 128, 0x0099),
                    &policy_area(),
                ),
            ),
            ("DUP_TRAILING", with_trailing(duplicate(H2, H1))),
            ("DUP_TRUNCATED", truncated(duplicate(H2, H1), 3)),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn a_fixed_parent_object_cannot_be_duplicated() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let (private, public) = created("CREATE_FIXED_CHILD");
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_FIXED_CHILD",
            load(H0, &private, &public),
        );
        open_dup_policy(&mut runtime, &clock);
        exec(&mut runtime, &clock, "DUP_FIXED_PARENT", duplicate(H2, H1));
    }

    #[test]
    fn import_rejections_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let public = child_public();
        let other = created("CREATE_PLAIN_CHILD").1;
        let fixed = created("CREATE_FIXED_CHILD").1;
        for (label, command) in [
            (
                "IMPORT_FIXED_TPM_PUBLIC",
                import(H1, &[], &fixed, &blob, &seed),
            ),
            (
                "IMPORT_KEY_WITHOUT_SYM",
                import(H1, &INNER_KEY, &public, &blob, &seed),
            ),
            (
                "IMPORT_KEY_WRONG_SIZE",
                import_with(
                    H1,
                    &INNER_KEY[..8],
                    &public,
                    &blob,
                    &seed,
                    &sym_aes128_cfb(),
                ),
            ),
            (
                "IMPORT_WRONG_PARENT",
                import(H0, &[], &public, &blob, &seed),
            ),
            (
                "IMPORT_CORRUPT_OUTER",
                import(H1, &[], &public, &flipped(&blob, 4), &seed),
            ),
            ("IMPORT_WRONG_NAME", import(H1, &[], &other, &blob, &seed)),
            (
                "IMPORT_CORRUPT_SEED",
                import(H1, &[], &public, &blob, &flipped(&seed, 7)),
            ),
            ("IMPORT_EMPTY_PUBLIC", import(H1, &[], &[], &blob, &seed)),
            (
                "IMPORT_EMPTY_DUPLICATE",
                import(H1, &[], &public, &[], &seed),
            ),
            (
                "IMPORT_OVERSIZED_DUPLICATE",
                import(H1, &[], &public, &[0u8; 1231], &seed),
            ),
            (
                "IMPORT_MAX_DUPLICATE",
                import(H1, &[], &public, &[0u8; 1230], &seed),
            ),
            (
                "IMPORT_TRAILING",
                with_trailing(import(H1, &[], &public, &blob, &seed)),
            ),
            (
                "IMPORT_TRUNCATED",
                truncated(import(H1, &[], &public, &blob, &seed), 5),
            ),
            ("IMPORT_NO_SESSIONS", {
                let mut payload = handles(&[H1]);
                payload.extend_from_slice(&tpm2b(&[]));
                payload.extend_from_slice(&tpm2b(&public));
                payload.extend_from_slice(&tpm2b(&blob));
                payload.extend_from_slice(&tpm2b(&seed));
                payload.extend_from_slice(&sym_null());
                plain(CC_IMPORT, &payload)
            }),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn a_non_parent_and_a_symmetric_parent_are_rejected_like_the_oracle() {
        let clock = clock();
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let public = child_public();

        let mut runtime = runtime_at("RSA_READY", &clock);
        let (private, plain_public) = created("CREATE_PLAIN_CHILD");
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_PLAIN_CHILD",
            load(H0, &private, &plain_public),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_PARENT_NOT_PARENT",
            import(H2, &[], &public, &blob, &seed),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_OLD_NOT_A_STORAGE_KEY",
            rewrap(H2, H1, &blob, &child_name(), &seed),
        );
        exec(
            &mut runtime,
            &clock,
            "REWRAP_NEW_NOT_A_STORAGE_KEY",
            rewrap(RH_NULL, H2, &blob, &child_name(), &[]),
        );

        let mut runtime = runtime_at("RSA_READY", &clock);
        let (private, sym_public) = created("CREATE_SYM_PARENT");
        run(&mut runtime, &clock, flush(H2));
        exec(
            &mut runtime,
            &clock,
            "LOAD_SYM_PARENT",
            load(H0, &private, &sym_public),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_SYM_PARENT_WITH_SEED",
            import(H2, &[], &public, &blob, &seed),
        );
        exec(
            &mut runtime,
            &clock,
            "IMPORT_SYM_PARENT_NO_SEED",
            import(H2, &[], &public, &blob, &[]),
        );
    }

    #[test]
    fn rewrap_rejections_match_the_oracle() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let name = child_name();
        for (label, command) in [
            (
                "REWRAP_SEED_WITHOUT_PARENT",
                rewrap(RH_NULL, H1, &blob, &name, &seed),
            ),
            (
                "REWRAP_PARENT_WITHOUT_SEED",
                rewrap(H1, H0, &blob, &name, &[]),
            ),
            (
                "REWRAP_OVERSIZED",
                rewrap(RH_NULL, H1, &[0u8; 1230], &name, &[]),
            ),
            (
                "REWRAP_TRAILING",
                with_trailing(rewrap(H1, H0, &blob, &name, &seed)),
            ),
            (
                "REWRAP_TRUNCATED",
                truncated(rewrap(H1, H0, &blob, &name, &seed), 9),
            ),
            ("REWRAP_NO_SESSIONS", {
                let mut payload = handles(&[H1, H0]);
                payload.extend_from_slice(&tpm2b(&blob));
                payload.extend_from_slice(&tpm2b(&name));
                payload.extend_from_slice(&tpm2b(&seed));
                plain(CC_REWRAP, &payload)
            }),
        ] {
            exec(&mut runtime, &clock, label, command);
        }
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn the_transfer_commands_page_through_the_capability_listing() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        assert_eq!(
            command_page(&mut runtime, &clock, 0x014a, 3),
            (true, vec![0x0400_014a, 0x0400_014b, 0x0400_014c])
        );
        assert_eq!(
            command_page(&mut runtime, &clock, 0x014b, 1),
            (true, vec![0x0400_014b])
        );
        assert_eq!(
            command_page(&mut runtime, &clock, 0x014c, 1),
            (true, vec![0x0400_014c]),
            "the next command after TPM2_Duplicate is TPM2_GetTime"
        );
        assert_eq!(
            command_page(&mut runtime, &clock, 0x0151, 3),
            (true, vec![0x0400_0151, 0x0400_0152, 0x0200_0153])
        );
        assert_eq!(
            command_page(&mut runtime, &clock, 0x0154, 2),
            (true, vec![0x0200_0155, 0x0200_0156]),
            "TPM2_HMAC is the first command at or after TPM2_ECDH_ZGen"
        );
        let (_more, all) = command_page(&mut runtime, &clock, 0, 1000);
        for attributes in [0x0400_014bu32, 0x0400_0152, 0x0200_0156] {
            assert!(
                all.contains(&attributes),
                "{attributes:#010x} is advertised"
            );
        }
        assert!(
            all.windows(2)
                .all(|pair| pair[0] & 0xffff < pair[1] & 0xffff),
            "the listing stays in command-code order"
        );
    }

    #[test]
    fn the_response_framing_follows_the_session_tag() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        let response = exec_raw(&mut runtime, &clock, duplicate(H2, H1));
        assert_eq!(&response[..2], &[0x80, 0x02], "a sessioned response");
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        let size = u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize;
        assert_eq!(size, response.len());
        let parameter_size = u32::from_be_bytes(response[10..14].try_into().unwrap()) as usize;
        assert_eq!(
            size,
            10 + 4 + parameter_size + 2 + 32 + 1 + 2,
            "the response carries one acknowledgement area with a fresh nonce"
        );
        let area = &response[10 + 4 + parameter_size..];
        assert_eq!(&area[..2], &32u16.to_be_bytes());
        assert_eq!(area[34], 0x01, "the session continues");
        assert_eq!(
            &area[35..],
            &0u16.to_be_bytes(),
            "the response HMAC is empty"
        );

        let mut payload = handles(&[H2, H1]);
        payload.extend_from_slice(&tpm2b(&[]));
        payload.extend_from_slice(&sym_null());
        let response = exec_raw(&mut runtime, &clock, plain(CC_DUPLICATE, &payload));
        assert_eq!(
            &response[..2],
            &[0x80, 0x01],
            "an unsessioned error response"
        );
        assert_eq!(response.len(), 10);
    }

    #[test]
    fn no_transfer_command_commits_nv_state() {
        let clock = clock();
        let commits = std::cell::Cell::new(0usize);
        let mut runtime = runtime_at("RSA_READY", &clock);
        for command in [start_policy_session(), policy_command_code(CC_DUPLICATE)] {
            exec_counting_nv(&mut runtime, &clock, command, &commits);
        }
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let public = child_public();
        commits.set(0);
        for command in [
            duplicate(H2, H1),
            import(H1, &[], &public, &blob, &seed),
            rewrap(H1, H0, &blob, &child_name(), &seed),
            import(H0, &[], &public, &blob, &seed),
            rewrap(RH_NULL, RH_NULL, &blob, &child_name(), &[]),
        ] {
            exec_counting_nv(&mut runtime, &clock, command, &commits);
        }
        assert_eq!(commits.get(), 0, "object transfer never writes NV");
    }

    #[test]
    fn the_first_asymmetric_seed_operation_runs_the_lazy_self_test() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let corrupt = import(H1, &[], &child_public(), &flipped(&blob, 4), &seed);

        let before = generator_state(&runtime);
        exec_raw(&mut runtime, &clock, corrupt.clone());
        let after_first = generator_state(&runtime);
        assert!(
            after_first != before,
            "the first RSA seed decryption runs the pending self test"
        );
        exec_raw(&mut runtime, &clock, corrupt);
        assert!(
            generator_state(&runtime) == after_first,
            "a second rejected import draws nothing more"
        );
    }

    #[test]
    fn a_rejected_transfer_leaves_the_generator_and_the_object_slots_untouched() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let public = child_public();
        exec_raw(
            &mut runtime,
            &clock,
            import(H1, &[], &public, &flipped(&blob, 4), &seed),
        );
        let before_state = generator_state(&runtime);
        let before_objects = object_images(&runtime);
        for command in [
            duplicate_with(H2, H1, &INNER_KEY, &sym_null(), &policy_area()),
            duplicate(H2, H2),
            duplicate(H0, H1),
            import(H0, &[], &public, &blob, &seed),
            import(H1, &[], &public, &flipped(&blob, 4), &seed),
            rewrap(H1, H0, &blob, &[0x11; 34], &seed),
            rewrap(RH_NULL, H1, &blob, &child_name(), &seed),
        ] {
            let response = exec_raw(&mut runtime, &clock, command);
            assert_ne!(&response[6..10], &[0, 0, 0, 0], "the command is rejected");
        }
        assert!(
            generator_state(&runtime) == before_state,
            "a rejected transfer draws no randomness"
        );
        assert_eq!(object_images(&runtime), before_objects);
    }

    #[test]
    fn a_successful_duplicate_advances_the_generator_and_keeps_its_source() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        let before_state = generator_state(&runtime);
        let before_objects = object_images(&runtime);
        let response = exec_raw(&mut runtime, &clock, duplicate(H2, H1));
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);
        assert!(
            generator_state(&runtime) != before_state,
            "the seed encryption draws randomness"
        );
        assert_eq!(
            object_images(&runtime),
            before_objects,
            "the duplicated object is left exactly as it was"
        );
    }

    #[test]
    fn a_null_parent_duplicate_draws_only_the_response_nonce() {
        use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        let response = exec_raw(&mut runtime, &clock, duplicate(H2, RH_NULL));
        assert_eq!(&response[6..10], &[0, 0, 0, 0]);

        let mut control = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut control, &clock);
        let mut rand = take_live_rand(&mut control).expect("the generator is available");
        rand.random_bytes(32).expect("the nonce is drawn");
        finish_live_rand(&mut control, rand).expect("the generator is stored");
        assert!(
            generator_state(&runtime) == generator_state(&control),
            "a null parent has neither a seed nor an inner key to generate"
        );
    }

    #[test]
    fn malformed_transfer_commands_never_panic() {
        let clock = clock();
        let (_key, blob, seed) = duplicated("DUP_RSA");
        let public = child_public();
        let name = child_name();
        let originals = [
            duplicate(H2, H1),
            duplicate_with(H2, H1, &INNER_KEY, &sym_aes128_cfb(), &policy_area()),
            rewrap(H1, H0, &blob, &name, &seed),
            rewrap(RH_NULL, RH_NULL, &blob, &name, &[]),
            import(H1, &[], &public, &blob, &seed),
            import_with(H1, &INNER_KEY, &public, &blob, &seed, &sym_aes128_cfb()),
        ];
        let mut runtime = runtime_at("RSA_READY", &clock);
        open_dup_policy(&mut runtime, &clock);
        for original in &originals {
            for drop in 1..original.len().saturating_sub(10).min(48) {
                exec_raw(&mut runtime, &clock, truncated(original.clone(), drop));
            }
            for position in (10..original.len()).step_by(7) {
                let mut corrupt = original.clone();
                corrupt[position] ^= 0xff;
                let size = (corrupt.len() as u32).to_be_bytes();
                corrupt[2..6].copy_from_slice(&size);
                exec_raw(&mut runtime, &clock, corrupt);
            }
            exec_raw(&mut runtime, &clock, with_trailing(original.clone()));
        }
    }

    fn sym_definition(algorithm: u16, key_bits: u16, mode: u16) -> Vec<u8> {
        let mut out = algorithm.to_be_bytes().to_vec();
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
        out
    }
}
