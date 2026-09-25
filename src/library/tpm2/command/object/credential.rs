use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_SIZE, TPM_RC_TYPE};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_2, TPM_RC_H, TPM_RC_P};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::object_load::add_modifier;
use crate::library::tpm2::object_wrap::{
    MAX_ID_OBJECT, Protector, credential_to_secret, secret_to_credential,
};
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use crate::library::tpm2::public::{DIGEST_SIZE, NAME_SIZE};
use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::secret::{
    IDENTITY_LABEL, MAX_ENCRYPTED_SECRET, is_asymmetric, secret_decrypt_with_runtime,
    secret_encrypt,
};
use crate::library::tpm2::self_test::{LazySelfTest, self_test_reached};
use crate::library::tpm2::template::{
    TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TemplateReader, digest_size,
};
use crate::types::TpmResult;

const RC_MAKE_CREDENTIAL_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_MAKE_CREDENTIAL_CREDENTIAL: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_MAKE_CREDENTIAL_OBJECT_NAME: TpmResult = TPM_RC_P + TPM_RC_2;

const RC_ACTIVATE_CREDENTIAL_KEY_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_ACTIVATE_CREDENTIAL_CREDENTIAL_BLOB: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_ACTIVATE_CREDENTIAL_SECRET: TpmResult = TPM_RC_P + TPM_RC_2;

fn protector_object(
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

fn activation_name(runtime: &Tpm2Runtime, handle: u32) -> Result<Vec<u8>, TpmResult> {
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    match &object.body {
        OwnedAnyObjectBody::Object(body) => Ok(body.name.clone()),
        _ => Ok(Vec::new()),
    }
}

fn restricted_decryption_key(
    public: &crate::library::tpm2::persistent::OwnedTpmtPublic,
    blame: TpmResult,
) -> Result<(), TpmResult> {
    let attributes = public.object_attributes;
    if !is_asymmetric(public.object_type)
        || attributes & TPMA_OBJECT_DECRYPT == 0
        || attributes & TPMA_OBJECT_RESTRICTED == 0
    {
        return Err(TPM_RC_TYPE + blame);
    }
    Ok(())
}

fn credential_protector(
    public: &crate::library::tpm2::persistent::OwnedTpmtPublic,
) -> Protector<'_> {
    Protector {
        public,
        seed_value: &[],
    }
}

pub(in crate::library::tpm2::command) fn execute_make_credential(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let handle = handle_at(frame, 0)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let credential = reader
        .tpm2b(DIGEST_SIZE)
        .map_err(|code| add_modifier(code, RC_MAKE_CREDENTIAL_CREDENTIAL))?
        .to_vec();
    let object_name = reader
        .tpm2b(NAME_SIZE)
        .map_err(|code| add_modifier(code, RC_MAKE_CREDENTIAL_OBJECT_NAME))?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let object = protector_object(runtime, handle, RC_MAKE_CREDENTIAL_HANDLE)?;
    restricted_decryption_key(&object.public, RC_MAKE_CREDENTIAL_HANDLE)?;
    if credential.len() > digest_size(object.public.name_alg).unwrap_or(0) {
        return Err(TPM_RC_SIZE + RC_MAKE_CREDENTIAL_CREDENTIAL);
    }

    let encrypted = secret_encrypt(runtime, &object.public, IDENTITY_LABEL)?;

    let protector = credential_protector(&object.public);
    let mut rand = take_live_rand(runtime)?;
    let blob = {
        let mut run = |algorithm: u16| self_test_reached(runtime, algorithm);
        secret_to_credential(
            &credential,
            &object_name,
            &encrypted.data,
            &protector,
            &mut LazySelfTest::runtime(&mut run),
            &mut rand,
        )
    };
    finish_live_rand(runtime, rand)?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&blob?).map_err(|_| TPM_RC_SIZE)?;
    writer
        .write_tpm2b(&encrypted.secret)
        .map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(in crate::library::tpm2::command) fn execute_activate_credential(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let activate_handle = handle_at(frame, 0)?;
    let key_handle = handle_at(frame, 1)?;

    let mut reader = TemplateReader::new(frame.parameters);
    let credential_blob = reader
        .tpm2b(MAX_ID_OBJECT)
        .map_err(|code| add_modifier(code, RC_ACTIVATE_CREDENTIAL_CREDENTIAL_BLOB))?
        .to_vec();
    let secret = reader
        .tpm2b(MAX_ENCRYPTED_SECRET)
        .map_err(|code| add_modifier(code, RC_ACTIVATE_CREDENTIAL_SECRET))?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }

    let object = protector_object(runtime, key_handle, RC_ACTIVATE_CREDENTIAL_KEY_HANDLE)?;
    restricted_decryption_key(&object.public, RC_ACTIVATE_CREDENTIAL_KEY_HANDLE)?;
    let activate_name = activation_name(runtime, activate_handle)?;

    let data =
        secret_decrypt_with_runtime(runtime, &object, IDENTITY_LABEL, &secret).map_err(|code| {
            if code == TPM_RC_KEY {
                TPM_RC_FAILURE
            } else {
                add_modifier(code, RC_ACTIVATE_CREDENTIAL_SECRET)
            }
        })?;

    let protector = credential_protector(&object.public);
    let mut run = |algorithm: u16| self_test_reached(runtime, algorithm);
    let cert_info = credential_to_secret(
        &credential_blob,
        &activate_name,
        &data,
        &protector,
        &mut LazySelfTest::runtime(&mut run),
    )
    .map_err(|code| add_modifier(code, RC_ACTIVATE_CREDENTIAL_CREDENTIAL_BLOB))?;

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&cert_info).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
mod test_support {
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::crypto::{HmacState, kdfa, sym_cfb_encrypt};
    pub(in crate::library::tpm2::command) use crate::library::tpm2::golden_responses::credential_activation::vector;
    use crate::library::tpm2::object_load::replay::{
        exec_raw, framed, handles, plain, push_tpm2b, response_parameters, runtime_from, tpm2b,
    };
    use crate::library::tpm2::runtime::Tpm2Runtime;

    pub(in crate::library::tpm2::command) const RH_OWNER: u32 = 0x4000_0001;
    pub(in crate::library::tpm2::command) const RH_NULL: u32 = 0x4000_0007;
    pub(in crate::library::tpm2::command) const RH_PLATFORM: u32 = 0x4000_000c;
    pub(in crate::library::tpm2::command) const RS_PW: u32 = 0x4000_0009;
    pub(in crate::library::tpm2::command) const HMAC_SESSION: u32 = 0x0200_0000;
    pub(in crate::library::tpm2::command) const POLICY_SESSION: u32 = 0x0300_0000;

    pub(in crate::library::tpm2::command) const H0: u32 = 0x8000_0000;
    pub(in crate::library::tpm2::command) const H1: u32 = 0x8000_0001;
    pub(in crate::library::tpm2::command) const H2: u32 = 0x8000_0002;

    pub(in crate::library::tpm2::command) const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
    pub(in crate::library::tpm2::command) const CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
    pub(in crate::library::tpm2::command) const CC_MAKE_CREDENTIAL: u32 = 0x0000_0168;
    pub(in crate::library::tpm2::command) const CC_READ_PUBLIC: u32 = 0x0000_0173;
    pub(in crate::library::tpm2::command) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    pub(in crate::library::tpm2::command) const CC_GET_CAPABILITY: u32 = 0x0000_017a;
    pub(in crate::library::tpm2::command) const CC_POLICY_COMMAND_CODE: u32 = 0x0000_016c;

    pub(in crate::library::tpm2::command) const ALG_RSA: u16 = 0x0001;
    pub(in crate::library::tpm2::command) const ALG_HMAC: u16 = 0x0005;
    pub(in crate::library::tpm2::command) const ALG_AES: u16 = 0x0006;
    pub(in crate::library::tpm2::command) const ALG_KEYEDHASH: u16 = 0x0008;
    pub(in crate::library::tpm2::command) const ALG_SHA256: u16 = 0x000b;
    pub(in crate::library::tpm2::command) const ALG_SHA384: u16 = 0x000c;
    pub(in crate::library::tpm2::command) const ALG_NULL: u16 = 0x0010;
    pub(in crate::library::tpm2::command) const ALG_RSASSA: u16 = 0x0014;
    pub(in crate::library::tpm2::command) const ALG_RSAES: u16 = 0x0015;
    pub(in crate::library::tpm2::command) const ALG_ECC: u16 = 0x0023;
    pub(in crate::library::tpm2::command) const ALG_SYMCIPHER: u16 = 0x0025;
    pub(in crate::library::tpm2::command) const ALG_CFB: u16 = 0x0043;

    const COMMON_ATTRS: u32 = 0x0000_0472;
    pub(in crate::library::tpm2::command) const STORAGE_ATTRS: u32 = COMMON_ATTRS | 0x0003_0000;
    pub(in crate::library::tpm2::command) const SIGNER_ATTRS: u32 = COMMON_ATTRS | 0x0005_0000;
    pub(in crate::library::tpm2::command) const DECRYPT_ONLY_ATTRS: u32 =
        COMMON_ATTRS | 0x0002_0000;

    pub(in crate::library::tpm2::command) const SRK_AUTH: &[u8] = b"srk";
    pub(in crate::library::tpm2::command) const AK_AUTH: &[u8] = b"ak";
    pub(in crate::library::tpm2::command) const NONCE_CALLER: [u8; 32] = [0x5a; 32];

    pub(in crate::library::tpm2::command) const CONTINUE_SESSION: u8 = 0x01;
    pub(in crate::library::tpm2::command) const SESSION_DECRYPT: u8 = 0x20;
    pub(in crate::library::tpm2::command) const SESSION_ENCRYPT: u8 = 0x40;

    pub(in crate::library::tpm2::command) fn credential() -> Vec<u8> {
        (0x40u8..0x60).collect()
    }

    pub(in crate::library::tpm2::command) fn clock() -> SteppingClock {
        crate::library::tpm2::object_load::replay::clock()
    }

    pub(in crate::library::tpm2::command) fn runtime_at(
        snapshot: &str,
        clock: &SteppingClock,
    ) -> Tpm2Runtime {
        runtime_from(
            vector(&format!("PERMALL_{snapshot}")),
            vector(&format!("VOLATILE_{snapshot}")),
            clock,
        )
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: Vec<u8>,
    ) {
        assert_eq!(exec_raw(runtime, clock, bytes), vector(label), "{label}");
    }

    pub(in crate::library::tpm2::command) fn password_area(password: &[u8]) -> Vec<u8> {
        let mut area = RS_PW.to_be_bytes().to_vec();
        push_tpm2b(&mut area, &[]);
        area.push(CONTINUE_SESSION);
        push_tpm2b(&mut area, password);
        area
    }

    pub(in crate::library::tpm2::command) fn session_area(
        handle: u32,
        attributes: u8,
        authorization: &[u8],
    ) -> Vec<u8> {
        let mut area = handle.to_be_bytes().to_vec();
        push_tpm2b(&mut area, &NONCE_CALLER);
        area.push(attributes);
        push_tpm2b(&mut area, authorization);
        area
    }

    pub(in crate::library::tpm2::command) fn sessioned(
        code: u32,
        handle_list: &[u32],
        areas: &[Vec<u8>],
        parameters: &[u8],
    ) -> Vec<u8> {
        let blob: Vec<u8> = areas.concat();
        let mut payload = handles(handle_list);
        payload.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        payload.extend_from_slice(&blob);
        payload.extend_from_slice(parameters);
        framed(0x8002, code, &payload)
    }

    fn sym_aes128_cfb() -> Vec<u8> {
        let mut out = ALG_AES.to_be_bytes().to_vec();
        out.extend_from_slice(&128u16.to_be_bytes());
        out.extend_from_slice(&ALG_CFB.to_be_bytes());
        out
    }

    fn sym_null() -> Vec<u8> {
        ALG_NULL.to_be_bytes().to_vec()
    }

    fn public_head(object_type: u16, name_alg: u16, attributes: u32, policy: &[u8]) -> Vec<u8> {
        let mut out = object_type.to_be_bytes().to_vec();
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        push_tpm2b(&mut out, policy);
        out
    }

    pub(in crate::library::tpm2::command) fn rsa_template(
        name_alg: u16,
        attributes: u32,
        symmetric: &[u8],
        scheme: &[u8],
        policy: &[u8],
    ) -> Vec<u8> {
        let mut out = public_head(ALG_RSA, name_alg, attributes, policy);
        out.extend_from_slice(symmetric);
        out.extend_from_slice(scheme);
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2::command) fn rsa_storage(name_alg: u16) -> Vec<u8> {
        rsa_template(name_alg, STORAGE_ATTRS, &sym_aes128_cfb(), &sym_null(), &[])
    }

    pub(in crate::library::tpm2::command) fn rsa_signer(name_alg: u16, policy: &[u8]) -> Vec<u8> {
        let mut scheme = ALG_RSASSA.to_be_bytes().to_vec();
        scheme.extend_from_slice(&name_alg.to_be_bytes());
        rsa_template(name_alg, SIGNER_ATTRS, &sym_null(), &scheme, policy)
    }

    pub(in crate::library::tpm2::command) fn rsa_unrestricted(scheme: &[u8]) -> Vec<u8> {
        rsa_template(ALG_SHA256, DECRYPT_ONLY_ATTRS, &sym_null(), scheme, &[])
    }

    pub(in crate::library::tpm2::command) fn rsaes_scheme() -> Vec<u8> {
        ALG_RSAES.to_be_bytes().to_vec()
    }

    pub(in crate::library::tpm2::command) fn null_scheme() -> Vec<u8> {
        sym_null()
    }

    pub(in crate::library::tpm2::command) fn ecc_storage() -> Vec<u8> {
        let mut out = public_head(ALG_ECC, ALG_SHA256, STORAGE_ATTRS, &[]);
        out.extend_from_slice(&sym_aes128_cfb());
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        out.extend_from_slice(&0x0003u16.to_be_bytes());
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2::command) fn sym_storage() -> Vec<u8> {
        let mut out = public_head(ALG_SYMCIPHER, ALG_SHA256, STORAGE_ATTRS, &[]);
        out.extend_from_slice(&sym_aes128_cfb());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2::command) fn keyedhash_signer() -> Vec<u8> {
        let mut out = public_head(ALG_KEYEDHASH, ALG_SHA256, COMMON_ATTRS | 0x0004_0000, &[]);
        out.extend_from_slice(&ALG_HMAC.to_be_bytes());
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        push_tpm2b(&mut out, &[]);
        out
    }

    pub(in crate::library::tpm2::command) fn create_primary(
        hierarchy: u32,
        template: &[u8],
        auth: &[u8],
    ) -> Vec<u8> {
        let mut inner = tpm2b(auth);
        inner.extend_from_slice(&tpm2b(&[]));
        let mut parameters = tpm2b(&inner);
        parameters.extend_from_slice(&tpm2b(template));
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&0u32.to_be_bytes());
        sessioned(
            CC_CREATE_PRIMARY,
            &[hierarchy],
            &[password_area(&[])],
            &parameters,
        )
    }

    pub(in crate::library::tpm2::command) fn read_public(handle: u32) -> Vec<u8> {
        plain(CC_READ_PUBLIC, &handle.to_be_bytes())
    }

    pub(in crate::library::tpm2::command) fn make_credential(
        handle: u32,
        credential: &[u8],
        name: &[u8],
    ) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&tpm2b(credential));
        payload.extend_from_slice(&tpm2b(name));
        plain(CC_MAKE_CREDENTIAL, &payload)
    }

    pub(in crate::library::tpm2::command) fn activate_parameters(
        blob: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        let mut parameters = tpm2b(blob);
        parameters.extend_from_slice(&tpm2b(secret));
        parameters
    }

    pub(in crate::library::tpm2::command) fn activate_credential(
        activate: u32,
        key: u32,
        blob: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        activate_with(
            activate,
            key,
            &activate_parameters(blob, secret),
            &[password_area(AK_AUTH), password_area(SRK_AUTH)],
        )
    }

    pub(in crate::library::tpm2::command) fn activate_with(
        activate: u32,
        key: u32,
        parameters: &[u8],
        areas: &[Vec<u8>],
    ) -> Vec<u8> {
        sessioned(CC_ACTIVATE_CREDENTIAL, &[activate, key], areas, parameters)
    }

    pub(in crate::library::tpm2::command) fn cap_cc_page(code: u32, count: u32) -> Vec<u8> {
        let mut payload = 2u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(&count.to_be_bytes());
        plain(CC_GET_CAPABILITY, &payload)
    }

    pub(in crate::library::tpm2::command) fn start_session(kind: u8, symmetric: &[u8]) -> Vec<u8> {
        let mut payload = handles(&[RH_NULL, RH_NULL]);
        push_tpm2b(&mut payload, &NONCE_CALLER);
        push_tpm2b(&mut payload, &[]);
        payload.push(kind);
        payload.extend_from_slice(symmetric);
        payload.extend_from_slice(&ALG_SHA256.to_be_bytes());
        plain(CC_START_AUTH_SESSION, &payload)
    }

    pub(in crate::library::tpm2::command) fn start_hmac_session() -> Vec<u8> {
        start_session(0x00, &sym_null())
    }

    pub(in crate::library::tpm2::command) fn start_hmac_session_aes() -> Vec<u8> {
        start_session(0x00, &sym_aes128_cfb())
    }

    pub(in crate::library::tpm2::command) fn start_policy_session() -> Vec<u8> {
        start_session(0x01, &sym_null())
    }

    pub(in crate::library::tpm2::command) fn policy_command_code(code: u32) -> Vec<u8> {
        let mut payload = POLICY_SESSION.to_be_bytes().to_vec();
        payload.extend_from_slice(&code.to_be_bytes());
        plain(CC_POLICY_COMMAND_CODE, &payload)
    }

    pub(in crate::library::tpm2::command) fn with_trailing(command: Vec<u8>) -> Vec<u8> {
        let mut out = command;
        out.push(0x00);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    pub(in crate::library::tpm2::command) fn truncated(command: Vec<u8>, drop: usize) -> Vec<u8> {
        let mut out = command;
        out.truncate(out.len() - drop);
        let size = (out.len() as u32).to_be_bytes();
        out[2..6].copy_from_slice(&size);
        out
    }

    pub(in crate::library::tpm2::command) fn flipped(data: &[u8], index: usize) -> Vec<u8> {
        let mut out = data.to_vec();
        out[index] ^= 0x01;
        out
    }

    fn split_tpm2b(blob: &[u8], at: usize) -> (Vec<u8>, usize) {
        let size = u16::from_be_bytes(blob[at..at + 2].try_into().expect("two bytes")) as usize;
        (blob[at + 2..at + 2 + size].to_vec(), at + 2 + size)
    }

    pub(in crate::library::tpm2::command) fn object_name(label: &str) -> Vec<u8> {
        let parameters = response_parameters(vector(label));
        let (_, at) = split_tpm2b(&parameters, 0);
        split_tpm2b(&parameters, at).0
    }

    pub(in crate::library::tpm2::command) fn made_credential(label: &str) -> (Vec<u8>, Vec<u8>) {
        let parameters = response_parameters(vector(label));
        let (blob, at) = split_tpm2b(&parameters, 0);
        (blob, split_tpm2b(&parameters, at).0)
    }

    pub(in crate::library::tpm2::command) fn session_nonce(label: &str) -> Vec<u8> {
        let parameters = response_parameters(vector(label));
        split_tpm2b(&parameters, 4).0
    }

    pub(in crate::library::tpm2::command) fn sha256(parts: &[&[u8]]) -> Vec<u8> {
        let mut hasher =
            crate::library::tpm2::crypto::Hasher::new(ALG_SHA256).expect("sha256 is compiled");
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }

    pub(in crate::library::tpm2::command) fn cp_hash(
        code: u32,
        names: &[&[u8]],
        parameters: &[u8],
    ) -> Vec<u8> {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(names.len() + 2);
        let code_bytes = code.to_be_bytes();
        parts.push(&code_bytes);
        parts.extend_from_slice(names);
        parts.push(parameters);
        sha256(&parts)
    }

    pub(in crate::library::tpm2::command) fn command_hmac(
        key: &[u8],
        nonce_tpm: &[u8],
        attributes: u8,
        code: u32,
        names: &[&[u8]],
        parameters: &[u8],
    ) -> Vec<u8> {
        let mut hmac = HmacState::new(ALG_SHA256, key).expect("sha256 hmac");
        hmac.update(&cp_hash(code, names, parameters));
        hmac.update(&NONCE_CALLER);
        hmac.update(nonce_tpm);
        hmac.update(&[attributes]);
        hmac.finalize()
    }

    pub(in crate::library::tpm2::command) fn parameter_encrypt(
        extra_key: &[u8],
        nonce_tpm: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let material = kdfa(
            ALG_SHA256,
            extra_key,
            b"CFB\0",
            &NONCE_CALLER,
            nonce_tpm,
            256,
        )
        .expect("the parameter key derives");
        let mut out = data.to_vec();
        sym_cfb_encrypt(ALG_AES, &material[..16], &material[16..32], &mut out)
            .expect("the parameter encrypts");
        out
    }

    pub(in crate::library::tpm2::command) fn activate_policy() -> Vec<u8> {
        sha256(&[
            &[0u8; 32],
            &CC_POLICY_COMMAND_CODE.to_be_bytes(),
            &CC_ACTIVATE_CREDENTIAL.to_be_bytes(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        AK_AUTH, ALG_SHA256, ALG_SHA384, CC_ACTIVATE_CREDENTIAL, CC_MAKE_CREDENTIAL,
        CONTINUE_SESSION, H0, H1, H2, HMAC_SESSION, POLICY_SESSION, RH_OWNER, RH_PLATFORM,
        SESSION_DECRYPT, SESSION_ENCRYPT, SRK_AUTH, activate_credential, activate_parameters,
        activate_policy, activate_with, cap_cc_page, clock, command_hmac, create_primary,
        credential, ecc_storage, exec, flipped, keyedhash_signer, made_credential, make_credential,
        null_scheme, object_name, parameter_encrypt, password_area, policy_command_code,
        read_public, rsa_signer, rsa_storage, rsa_unrestricted, rsaes_scheme, runtime_at,
        session_area, session_nonce, sessioned, start_hmac_session, start_hmac_session_aes,
        start_policy_session, sym_storage, truncated, with_trailing,
    };
    use crate::library::tpm2::command::core::registry::{
        self, AuthRole, CommandLifecycle, HandleKind, NvAccess,
    };

    #[test]
    fn command_registration_upstream_attributes() {
        let make = registry::find(CC_MAKE_CREDENTIAL).expect("TPM2_MakeCredential is registered");
        assert_eq!(make.attributes, 0x0200_0168);
        assert_eq!(make.decrypt_size, 2);
        assert_eq!(make.encrypt_size, 2);
        assert!(make.sessions_allowed);
        assert!(!make.physical_presence);
        assert!(!make.physical_presence_required);
        assert!(matches!(make.nv_access, NvAccess::Neither));
        assert!(matches!(make.lifecycle, CommandLifecycle::RequiresStarted));
        assert_eq!(make.handles.len(), 1);
        assert!(!make.handles[0].user_auth);
        assert!(make.handles[0].role == AuthRole::User);
        assert!(matches!(make.handles[0].kind, HandleKind::Object));

        let activate =
            registry::find(CC_ACTIVATE_CREDENTIAL).expect("TPM2_ActivateCredential is registered");
        assert_eq!(activate.attributes, 0x0400_0147);
        assert_eq!(activate.decrypt_size, 2);
        assert_eq!(activate.encrypt_size, 2);
        assert!(activate.sessions_allowed);
        assert!(!activate.physical_presence);
        assert!(matches!(activate.nv_access, NvAccess::Neither));
        assert_eq!(activate.handles.len(), 2);
        assert!(activate.handles[0].user_auth);
        assert!(activate.handles[0].admin_role());
        assert!(matches!(activate.handles[0].kind, HandleKind::Object));
        assert!(activate.handles[1].user_auth);
        assert!(activate.handles[1].role == AuthRole::User);
        assert!(matches!(activate.handles[1].kind, HandleKind::Object));
    }

    #[test]
    fn command_attributes_oracle_match() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CCATTR_0147",
            cap_cc_page(CC_ACTIVATE_CREDENTIAL, 1),
        );
        exec(
            &mut runtime,
            &clock,
            "CCATTR_0168",
            cap_cc_page(CC_MAKE_CREDENTIAL, 1),
        );
        exec(
            &mut runtime,
            &clock,
            "CCLIST_FROM_ACTIVATE",
            cap_cc_page(CC_ACTIVATE_CREDENTIAL, 4),
        );
        exec(
            &mut runtime,
            &clock,
            "CCLIST_FROM_MAKE",
            cap_cc_page(CC_MAKE_CREDENTIAL, 4),
        );
    }

    #[test]
    fn pre_execution_handle_resolution() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        let name = object_name("READPUBLIC_RSA_AK");
        exec(
            &mut runtime,
            &clock,
            "MC_UNLOADED_TRANSIENT",
            make_credential(H0, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_HIERARCHY_HANDLE",
            make_credential(RH_OWNER, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_TRUNCATED_HANDLE",
            truncated(make_credential(H0, &[], &[]), 6),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_UNLOADED_TRANSIENT",
            activate_credential(H0, H1, &[0x11; 68], &[0x22; 256]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_TRUNCATED_HANDLE",
            truncated(
                activate_with(H0, H1, &[], &[password_area(&[]), password_area(&[])]),
                activate_with(H0, H1, &[], &[password_area(&[]), password_area(&[])]).len() - 14,
            ),
        );
    }

    #[test]
    fn rsa_key_reference_template_creation() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_RSA_SRK",
            create_primary(RH_OWNER, &rsa_storage(ALG_SHA256), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_RSA_AK",
            create_primary(RH_OWNER, &rsa_signer(ALG_SHA256, &[]), AK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_OTHER_AK",
            create_primary(RH_PLATFORM, &rsa_signer(ALG_SHA256, &[]), AK_AUTH),
        );
        exec(&mut runtime, &clock, "READPUBLIC_RSA_SRK", read_public(H0));
        exec(&mut runtime, &clock, "READPUBLIC_RSA_AK", read_public(H1));
        exec(&mut runtime, &clock, "READPUBLIC_OTHER_AK", read_public(H2));
    }

    #[test]
    fn rsa_make_credential_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let name = object_name("READPUBLIC_RSA_AK");
        let other = object_name("READPUBLIC_OTHER_AK");
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_SHA256",
            make_credential(H0, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_EMPTY_CREDENTIAL",
            make_credential(H0, &[], &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_SHORT_CREDENTIAL",
            make_credential(H0, &[0xc0, 0xc1, 0xc2, 0xc3], &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_AT_LIMIT",
            make_credential(H0, &[0x5a; 32], &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_OVER_LIMIT",
            make_credential(H0, &[0x5a; 33], &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_EMPTY_NAME",
            make_credential(H0, &credential(), &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_OTHER_NAME",
            make_credential(H0, &credential(), &other),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_OVERSIZE_NAME",
            make_credential(H0, &credential(), &[0x11; 69]),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_TRAILING",
            with_trailing(make_credential(H0, &credential(), &name)),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_TRUNCATED_NAME",
            truncated(make_credential(H0, &credential(), &[0x22; 2]), 2),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_SIGN_ONLY_KEY",
            make_credential(H1, &credential(), &name),
        );
    }

    #[test]
    fn rsa_activate_credential_oracle_parity() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        let (blob, secret) = made_credential("MC_RSA_SHA256");
        let (empty_blob, empty_secret) = made_credential("MC_RSA_EMPTY_CREDENTIAL");
        let (other_blob, other_secret) = made_credential("MC_RSA_OTHER_NAME");

        exec(
            &mut runtime,
            &clock,
            "AC_RSA_SHA256",
            activate_credential(H1, H0, &blob, &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_EMPTY_CREDENTIAL",
            activate_credential(H1, H0, &empty_blob, &empty_secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_WRONG_ACTIVATE_OBJECT",
            activate_credential(H2, H0, &blob, &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_BOUND_TO_OTHER_NAME",
            activate_credential(H1, H0, &other_blob, &other_secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_OTHER_NAME_ON_OTHER_OBJECT",
            activate_credential(H2, H0, &other_blob, &other_secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_CORRUPT_INTEGRITY",
            activate_credential(H1, H0, &flipped(&blob, 2), &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_CORRUPT_PAYLOAD",
            activate_credential(H1, H0, &flipped(&blob, blob.len() - 1), &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_CORRUPT_SECRET",
            activate_credential(H1, H0, &blob, &flipped(&secret, secret.len() - 1)),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_EMPTY_BLOB",
            activate_credential(H1, H0, &[], &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_TRUNCATED_BLOB",
            activate_credential(H1, H0, &blob[..33], &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_SHORT_BLOB",
            activate_credential(H1, H0, &blob[..2], &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_OVERSIZE_BLOB",
            activate_credential(H1, H0, &[0x33; 133], &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_EMPTY_SECRET",
            activate_credential(H1, H0, &blob, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_TRUNCATED_SECRET",
            activate_credential(H1, H0, &blob, &secret[..255]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_ZERO_SECRET",
            activate_credential(H1, H0, &blob, &[0u8; 256]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_OVERSIZE_SECRET",
            activate_credential(H1, H0, &blob, &[0x44; 385]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_TRAILING",
            with_trailing(activate_credential(H1, H0, &blob, &secret)),
        );
        let mut short = activate_parameters(&blob, &secret);
        short.truncate(2 + blob.len() + 1);
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_TRUNCATED_PARAMETERS",
            activate_with(
                H1,
                H0,
                &short,
                &[password_area(AK_AUTH), password_area(SRK_AUTH)],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_NO_SESSIONS",
            crate::library::tpm2::object_load::replay::plain(CC_ACTIVATE_CREDENTIAL, &{
                let mut payload = H1.to_be_bytes().to_vec();
                payload.extend_from_slice(&H0.to_be_bytes());
                payload.extend_from_slice(&activate_parameters(&blob, &secret));
                payload
            }),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_WRONG_ACTIVATE_AUTH",
            activate_with(
                H1,
                H0,
                &activate_parameters(&blob, &secret),
                &[password_area(b"wrong"), password_area(SRK_AUTH)],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_WRONG_KEY_AUTH",
            activate_with(
                H1,
                H0,
                &activate_parameters(&blob, &secret),
                &[password_area(AK_AUTH), password_area(b"wrong")],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_ONE_SESSION",
            activate_with(
                H1,
                H0,
                &activate_parameters(&blob, &secret),
                &[password_area(AK_AUTH)],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_SIGN_ONLY_KEY",
            activate_with(
                H1,
                H1,
                &activate_parameters(&blob, &secret),
                &[password_area(AK_AUTH), password_area(AK_AUTH)],
            ),
        );
    }

    #[test]
    fn ecc_protector_round_trip() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_ECC_SRK",
            create_primary(RH_OWNER, &ecc_storage(), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_ECC_AK",
            create_primary(RH_OWNER, &rsa_signer(ALG_SHA256, &[]), AK_AUTH),
        );
        exec(&mut runtime, &clock, "READPUBLIC_ECC_AK", read_public(H1));

        let mut runtime = runtime_at("ECC_READY", &clock);
        let name = object_name("READPUBLIC_ECC_AK");
        exec(
            &mut runtime,
            &clock,
            "MC_ECC_SHA256",
            make_credential(H0, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_ECC_AT_LIMIT",
            make_credential(H0, &[0x5a; 32], &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_ECC_OVER_LIMIT",
            make_credential(H0, &[0x5a; 33], &name),
        );

        let mut runtime = runtime_at("ECC_READY", &clock);
        let (blob, secret) = made_credential("MC_ECC_SHA256");
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_SHA256",
            activate_credential(H1, H0, &blob, &secret),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_EMPTY_SECRET",
            activate_credential(H1, H0, &blob, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_TRUNCATED_SECRET",
            activate_credential(H1, H0, &blob, &secret[..35]),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_OFF_CURVE_SECRET",
            activate_credential(H1, H0, &blob, &ecc_point(&[0x07; 32], &[0x08; 32])),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_EMPTY_POINT_SECRET",
            activate_credential(H1, H0, &blob, &ecc_point(&[], &[])),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_OVERSIZE_COORDINATE",
            activate_credential(H1, H0, &blob, &ecc_point(&[0x07; 81], &[0x08; 32])),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_ECC_CORRUPT_SECRET",
            activate_credential(H1, H0, &blob, &flipped(&secret, secret.len() - 1)),
        );
    }

    fn ecc_point(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut out = (x.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(x);
        out.extend_from_slice(&(y.len() as u16).to_be_bytes());
        out.extend_from_slice(y);
        out
    }

    #[test]
    fn sha384_protector_credential_digest_bound() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_RSA_SRK_SHA384",
            create_primary(RH_OWNER, &rsa_storage(ALG_SHA384), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_AK_SHA384",
            create_primary(RH_OWNER, &rsa_signer(ALG_SHA384, &[]), AK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_AK_SHA384",
            read_public(H1),
        );

        let mut runtime = runtime_at("SHA384_READY", &clock);
        let name = object_name("READPUBLIC_AK_SHA384");
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_SHA384",
            make_credential(H0, &[0x5a; 48], &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_SHA384_AT_LIMIT",
            make_credential(H0, &(0u8..48).collect::<Vec<u8>>(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_RSA_SHA384_OVER_LIMIT",
            make_credential(H0, &[0x5a; 49], &name),
        );

        let mut runtime = runtime_at("SHA384_READY", &clock);
        let (blob, secret) = made_credential("MC_RSA_SHA384");
        exec(
            &mut runtime,
            &clock,
            "AC_RSA_SHA384",
            activate_credential(H1, H0, &blob, &secret),
        );
    }

    #[test]
    fn credential_protection_restricted_decrypt_key_only() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_SYM_PARENT",
            create_primary(RH_OWNER, &sym_storage(), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_UNRESTRICTED_RSAES",
            create_primary(RH_OWNER, &rsa_unrestricted(&rsaes_scheme()), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_UNRESTRICTED_NULL",
            create_primary(RH_OWNER, &rsa_unrestricted(&null_scheme()), SRK_AUTH),
        );

        let mut runtime = runtime_at("SHAPES_READY", &clock);
        let name = object_name("READPUBLIC_RSA_AK");
        let (blob, secret) = made_credential("MC_RSA_SHA256");
        exec(
            &mut runtime,
            &clock,
            "MC_SYM_PARENT",
            make_credential(H0, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_UNRESTRICTED_RSAES",
            make_credential(H1, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_UNRESTRICTED_NULL",
            make_credential(H2, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_SYM_PARENT",
            activate_with(
                H1,
                H0,
                &activate_parameters(&blob, &secret),
                &[password_area(SRK_AUTH), password_area(SRK_AUTH)],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_UNRESTRICTED_RSAES",
            activate_with(
                H2,
                H1,
                &activate_parameters(&blob, &secret),
                &[password_area(SRK_AUTH), password_area(SRK_AUTH)],
            ),
        );

        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_KEYEDHASH",
            create_primary(RH_OWNER, &keyedhash_signer(), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "MC_KEYEDHASH",
            make_credential(H0, &credential(), &name),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_KEYEDHASH",
            activate_with(
                H0,
                H0,
                &activate_parameters(&blob, &secret),
                &[password_area(SRK_AUTH), password_area(SRK_AUTH)],
            ),
        );
    }

    #[test]
    fn hmac_session_activation_authorization() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        exec(&mut runtime, &clock, "SAS_PLAIN", start_hmac_session());

        let nonce = session_nonce("SAS_PLAIN");
        let (blob, secret) = made_credential("MC_RSA_SHA256");
        let parameters = activate_parameters(&blob, &secret);
        let names: [&[u8]; 2] = [
            &object_name("READPUBLIC_RSA_AK"),
            &object_name("READPUBLIC_RSA_SRK"),
        ];

        for (label, key) in [
            ("AC_RSA_HMAC_AUTH", AK_AUTH),
            ("AC_RSA_HMAC_WRONG", &b"nope"[..]),
        ] {
            let mut runtime = runtime_at("SESSION_READY", &clock);
            let authorization = command_hmac(
                key,
                &nonce,
                CONTINUE_SESSION,
                CC_ACTIVATE_CREDENTIAL,
                &names,
                &parameters,
            );
            exec(
                &mut runtime,
                &clock,
                label,
                activate_with(
                    H1,
                    H0,
                    &parameters,
                    &[
                        session_area(HMAC_SESSION, CONTINUE_SESSION, &authorization),
                        password_area(SRK_AUTH),
                    ],
                ),
            );
        }
    }

    #[test]
    fn session_parameter_encryption() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        exec(&mut runtime, &clock, "SAS_AES", start_hmac_session_aes());

        let nonce = session_nonce("SAS_AES");
        let name = object_name("READPUBLIC_RSA_AK");
        let srk_name = object_name("READPUBLIC_RSA_SRK");
        let clear = {
            let mut out = (credential().len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&credential());
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(&name);
            out
        };
        let hidden = {
            let cipher = parameter_encrypt(&[], &nonce, &credential());
            let mut out = (cipher.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&cipher);
            out.extend_from_slice(&(name.len() as u16).to_be_bytes());
            out.extend_from_slice(&name);
            out
        };

        for (label, parameters, attributes) in [
            (
                "MC_RSA_ENCRYPTED_REQUEST",
                &hidden,
                CONTINUE_SESSION | SESSION_DECRYPT,
            ),
            (
                "MC_RSA_ENCRYPTED_RESPONSE",
                &clear,
                CONTINUE_SESSION | SESSION_ENCRYPT,
            ),
            (
                "MC_RSA_ENCRYPTED_BOTH",
                &hidden,
                CONTINUE_SESSION | SESSION_DECRYPT | SESSION_ENCRYPT,
            ),
        ] {
            let mut runtime = runtime_at("SESSION_AES_READY", &clock);
            exec(
                &mut runtime,
                &clock,
                label,
                sessioned(
                    CC_MAKE_CREDENTIAL,
                    &[H0],
                    &[session_area(HMAC_SESSION, attributes, &[])],
                    parameters,
                ),
            );
        }

        let (blob, secret) = made_credential("MC_RSA_SHA256");
        let names: [&[u8]; 2] = [&name, &srk_name];
        let plain_parameters = activate_parameters(&blob, &secret);
        let hidden_parameters =
            activate_parameters(&parameter_encrypt(AK_AUTH, &nonce, &blob), &secret);

        for (label, parameters, attributes) in [
            (
                "AC_RSA_ENCRYPTED_REQUEST",
                &hidden_parameters,
                CONTINUE_SESSION | SESSION_DECRYPT,
            ),
            (
                "AC_RSA_ENCRYPTED_RESPONSE",
                &plain_parameters,
                CONTINUE_SESSION | SESSION_ENCRYPT,
            ),
        ] {
            let mut runtime = runtime_at("SESSION_AES_READY", &clock);
            let authorization = command_hmac(
                AK_AUTH,
                &nonce,
                attributes,
                CC_ACTIVATE_CREDENTIAL,
                &names,
                parameters,
            );
            exec(
                &mut runtime,
                &clock,
                label,
                activate_with(
                    H1,
                    H0,
                    parameters,
                    &[
                        session_area(HMAC_SESSION, attributes, &authorization),
                        password_area(SRK_AUTH),
                    ],
                ),
            );
        }
    }

    #[test]
    fn policy_session_admin_role_authorization() {
        let clock = clock();
        let mut runtime = runtime_at("READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "CP_POLICY_SRK",
            create_primary(RH_OWNER, &rsa_storage(ALG_SHA256), SRK_AUTH),
        );
        exec(
            &mut runtime,
            &clock,
            "CP_POLICY_AK",
            create_primary(
                RH_OWNER,
                &rsa_signer(ALG_SHA256, &activate_policy()),
                AK_AUTH,
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "READPUBLIC_POLICY_AK",
            read_public(H1),
        );

        let mut runtime = runtime_at("POLICY_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "MC_POLICY_AK",
            make_credential(H0, &credential(), &object_name("READPUBLIC_POLICY_AK")),
        );

        let (blob, secret) = made_credential("MC_POLICY_AK");
        let parameters = activate_parameters(&blob, &secret);
        let policy_session = || session_area(POLICY_SESSION, CONTINUE_SESSION, &[]);

        let mut runtime = runtime_at("POLICY_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "PSESSION_NO_CODE",
            start_policy_session(),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_POLICY_WITHOUT_COMMAND_CODE",
            activate_with(
                H1,
                H0,
                &parameters,
                &[policy_session(), password_area(SRK_AUTH)],
            ),
        );

        let mut runtime = runtime_at("POLICY_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "PSESSION_ADMIN",
            start_policy_session(),
        );
        exec(
            &mut runtime,
            &clock,
            "PCC_ACTIVATE",
            policy_command_code(CC_ACTIVATE_CREDENTIAL),
        );
        exec(
            &mut runtime,
            &clock,
            "AC_POLICY_ADMIN",
            activate_with(
                H1,
                H0,
                &parameters,
                &[policy_session(), password_area(SRK_AUTH)],
            ),
        );

        let mut runtime = runtime_at("POLICY_READY", &clock);
        exec(
            &mut runtime,
            &clock,
            "AC_POLICY_AK_PASSWORD",
            activate_with(
                H1,
                H0,
                &parameters,
                &[password_area(AK_AUTH), password_area(SRK_AUTH)],
            ),
        );
    }
}

#[cfg(test)]
mod behaviour {
    use super::test_support::{
        ALG_AES, ALG_SHA256, ALG_SHA384, H0, H1, activate_credential, clock, credential, flipped,
        made_credential, make_credential, object_name, runtime_at,
    };
    use crate::library::tpm2::crypto::CTR_DRBG_MAX_REQUESTS_PER_RESEED;
    use crate::library::tpm2::golden_responses::credential_activation::vector;
    use crate::library::tpm2::object_load::replay::exec_raw;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::self_test::PrimitiveTest;

    const ALG_OAEP: u16 = 0x0017;
    const ALG_ECDH: u16 = 0x0019;
    const ALG_SHA512: u16 = 0x000d;

    fn response_code(response: &[u8]) -> u32 {
        u32::from_be_bytes(response[6..10].try_into().expect("four bytes"))
    }

    fn generator_state(runtime: &Tpm2Runtime) -> (u64, [u32; 4], Vec<u8>) {
        let drbg = &runtime.live.orderly.drbg_state;
        (
            drbg.reseed_counter,
            drbg.last_value,
            drbg.seed.as_bytes().to_vec(),
        )
    }

    fn starve_the_generator(runtime: &mut Tpm2Runtime) {
        runtime.entropy_bad = true;
        runtime.live.orderly.drbg_state.reseed_counter = CTR_DRBG_MAX_REQUESTS_PER_RESEED;
    }

    #[test]
    fn response_code_reference_decorations() {
        const HANDLE_1_TYPE: u32 = 0x018a;
        const HANDLE_2_TYPE: u32 = 0x028a;
        const HANDLE_1_VALUE: u32 = 0x0184;
        const HANDLE_1_INSUFFICIENT: u32 = 0x019a;
        const HANDLE_2_INSUFFICIENT: u32 = 0x029a;
        const PARAM_1_SIZE: u32 = 0x01d5;
        const PARAM_2_SIZE: u32 = 0x02d5;
        const PARAM_1_INSUFFICIENT: u32 = 0x01da;
        const PARAM_2_INSUFFICIENT: u32 = 0x02da;
        const PARAM_1_INTEGRITY: u32 = 0x01df;
        const PARAM_2_VALUE: u32 = 0x02c4;
        const PARAM_2_ECC_POINT: u32 = 0x02e7;
        const SIZE: u32 = 0x0095;
        const AUTH_MISSING: u32 = 0x0125;
        const REFERENCE_H0: u32 = 0x0910;
        const SESSION_1_BAD_AUTH: u32 = 0x09a2;
        const SESSION_2_BAD_AUTH: u32 = 0x0aa2;
        const SESSION_1_POLICY_FAIL: u32 = 0x099d;

        for (label, expected) in [
            ("MC_SIGN_ONLY_KEY", HANDLE_1_TYPE),
            ("MC_SYM_PARENT", HANDLE_1_TYPE),
            ("MC_KEYEDHASH", HANDLE_1_TYPE),
            ("MC_UNRESTRICTED_RSAES", HANDLE_1_TYPE),
            ("MC_UNRESTRICTED_NULL", HANDLE_1_TYPE),
            ("MC_HIERARCHY_HANDLE", HANDLE_1_VALUE),
            ("MC_TRUNCATED_HANDLE", HANDLE_1_INSUFFICIENT),
            ("MC_UNLOADED_TRANSIENT", REFERENCE_H0),
            ("MC_RSA_OVER_LIMIT", PARAM_1_SIZE),
            ("MC_ECC_OVER_LIMIT", PARAM_1_SIZE),
            ("MC_RSA_SHA384_OVER_LIMIT", PARAM_1_SIZE),
            ("MC_RSA_OVERSIZE_NAME", PARAM_2_SIZE),
            ("MC_RSA_TRUNCATED_NAME", PARAM_2_INSUFFICIENT),
            ("MC_RSA_TRAILING", SIZE),
            ("AC_SYM_PARENT", HANDLE_2_TYPE),
            ("AC_KEYEDHASH", HANDLE_2_TYPE),
            ("AC_UNRESTRICTED_RSAES", HANDLE_2_TYPE),
            ("AC_RSA_SIGN_ONLY_KEY", HANDLE_2_TYPE),
            ("AC_TRUNCATED_HANDLE", HANDLE_2_INSUFFICIENT),
            ("AC_UNLOADED_TRANSIENT", REFERENCE_H0),
            ("AC_RSA_CORRUPT_INTEGRITY", PARAM_1_INTEGRITY),
            ("AC_RSA_CORRUPT_PAYLOAD", PARAM_1_INTEGRITY),
            ("AC_RSA_BOUND_TO_OTHER_NAME", PARAM_1_INTEGRITY),
            ("AC_RSA_WRONG_ACTIVATE_OBJECT", PARAM_1_INTEGRITY),
            ("AC_RSA_EMPTY_BLOB", PARAM_1_INSUFFICIENT),
            ("AC_RSA_SHORT_BLOB", PARAM_1_INSUFFICIENT),
            ("AC_RSA_TRUNCATED_BLOB", PARAM_1_INSUFFICIENT),
            ("AC_RSA_OVERSIZE_BLOB", PARAM_1_SIZE),
            ("AC_RSA_EMPTY_SECRET", PARAM_2_SIZE),
            ("AC_RSA_TRUNCATED_SECRET", PARAM_2_SIZE),
            ("AC_RSA_OVERSIZE_SECRET", PARAM_2_SIZE),
            ("AC_RSA_CORRUPT_SECRET", PARAM_2_VALUE),
            ("AC_RSA_ZERO_SECRET", PARAM_2_VALUE),
            ("AC_ECC_EMPTY_SECRET", PARAM_2_INSUFFICIENT),
            ("AC_ECC_TRUNCATED_SECRET", PARAM_2_INSUFFICIENT),
            ("AC_ECC_OVERSIZE_COORDINATE", PARAM_2_SIZE),
            ("AC_ECC_OFF_CURVE_SECRET", PARAM_2_ECC_POINT),
            ("AC_ECC_EMPTY_POINT_SECRET", PARAM_2_ECC_POINT),
            ("AC_ECC_CORRUPT_SECRET", PARAM_2_ECC_POINT),
            ("AC_RSA_TRAILING", SIZE),
            ("AC_RSA_TRUNCATED_PARAMETERS", PARAM_2_INSUFFICIENT),
            ("AC_RSA_NO_SESSIONS", AUTH_MISSING),
            ("AC_RSA_ONE_SESSION", AUTH_MISSING),
            ("AC_RSA_WRONG_ACTIVATE_AUTH", SESSION_1_BAD_AUTH),
            ("AC_RSA_HMAC_WRONG", SESSION_1_BAD_AUTH),
            ("AC_RSA_WRONG_KEY_AUTH", SESSION_2_BAD_AUTH),
            ("AC_POLICY_WITHOUT_COMMAND_CODE", SESSION_1_POLICY_FAIL),
        ] {
            assert_eq!(response_code(vector(label)), expected, "{label}");
        }
    }

    #[test]
    fn pre_seed_rejection_generator_unchanged() {
        let clock = clock();
        let name = object_name("READPUBLIC_RSA_AK");
        for (what, packet) in [
            (
                "an over-long credential",
                make_credential(H0, &[0x5a; 33], &name),
            ),
            (
                "a signing protector",
                make_credential(H1, &credential(), &name),
            ),
            (
                "an oversized name",
                make_credential(H0, &credential(), &[0x11; 69]),
            ),
        ] {
            let mut runtime = runtime_at("RSA_READY", &clock);
            let before = generator_state(&runtime);
            let response = exec_raw(&mut runtime, &clock, packet);
            assert_ne!(response_code(&response), 0, "{what} is refused");
            assert_eq!(generator_state(&runtime), before, "{what}");
        }

        let mut runtime = runtime_at("RSA_READY", &clock);
        let before = generator_state(&runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            make_credential(H0, &credential(), &name),
        );
        assert_eq!(response_code(&response), 0);
        assert_ne!(
            generator_state(&runtime),
            before,
            "a successful credential draws the seed and the OAEP padding"
        );
    }

    #[test]
    fn activate_credential_lazy_self_test_only_draw() {
        let clock = clock();
        let (blob, secret) = made_credential("MC_RSA_SHA256");
        let mut runtime = runtime_at("RSA_READY", &clock);
        let fresh = generator_state(&runtime);
        exec_raw(
            &mut runtime,
            &clock,
            activate_credential(H1, H0, &blob, &secret),
        );
        assert_ne!(
            generator_state(&runtime),
            fresh,
            "the first RSA activation runs the lazy OAEP known-answer test"
        );

        let settled = generator_state(&runtime);
        for (what, packet) in [
            (
                "a repeated activation",
                activate_credential(H1, H0, &blob, &secret),
            ),
            (
                "a refused activation",
                activate_credential(H1, H0, &flipped(&blob, 2), &secret),
            ),
        ] {
            exec_raw(&mut runtime, &clock, packet);
            assert_eq!(generator_state(&runtime), settled, "{what}");
        }
    }

    #[test]
    fn ecc_activate_credential_first_use_no_draw() {
        let clock = clock();
        let (blob, secret) = made_credential("MC_ECC_SHA256");
        let mut runtime = runtime_at("ECC_READY", &clock);
        runtime.self_test = runtime.self_test.restarted();
        let fresh = generator_state(&runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            activate_credential(H1, H0, &blob, &secret),
        );
        assert_eq!(response_code(&response), 0);
        assert_eq!(
            generator_state(&runtime),
            fresh,
            "the ECDH and hash known-answer tests are deterministic"
        );
        for algorithm in [ALG_ECDH, ALG_SHA256, ALG_AES] {
            assert!(
                !runtime.self_test.pending_algorithms().contains(&algorithm),
                "{algorithm:#06x} is still reached without drawing"
            );
        }
    }

    #[test]
    fn starved_generator_ecc_error_no_failure_mode() {
        let clock = clock();
        let mut runtime = runtime_at("ECC_READY", &clock);
        starve_the_generator(&mut runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            make_credential(H0, &credential(), &object_name("READPUBLIC_ECC_AK")),
        );
        assert_ne!(
            response_code(&response),
            0,
            "the ephemeral key cannot be generated"
        );
        assert!(runtime.entropy_bad, "the entropy failure is recorded");
        assert!(!runtime.failure_mode, "a starved generator is not fatal");
    }

    #[test]
    fn starved_generator_rsa_zeroed_seed_wrap() {
        let clock = clock();
        let mut runtime = runtime_at("RSA_READY", &clock);
        starve_the_generator(&mut runtime);
        let response = exec_raw(
            &mut runtime,
            &clock,
            make_credential(H0, &credential(), &object_name("READPUBLIC_RSA_AK")),
        );
        assert_eq!(
            response_code(&response),
            0,
            "the reference keeps going with the zeroed buffer CryptRandomGenerate left behind"
        );
        assert!(runtime.entropy_bad);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn make_credential_protector_scoped_self_tests() {
        let clock = clock();
        for (snapshot, name_label, expected) in [
            (
                "RSA_READY",
                "READPUBLIC_RSA_AK",
                vec![ALG_SHA256, ALG_SHA512, ALG_AES, ALG_OAEP],
            ),
            (
                "ECC_READY",
                "READPUBLIC_ECC_AK",
                vec![ALG_SHA256, ALG_AES, ALG_ECDH],
            ),
            (
                "SHA384_READY",
                "READPUBLIC_AK_SHA384",
                vec![ALG_SHA384, ALG_SHA512, ALG_AES, ALG_OAEP],
            ),
        ] {
            let mut runtime = runtime_at(snapshot, &clock);
            runtime.self_test = runtime.self_test.restarted();
            let before = runtime.self_test.pending_algorithms();
            for algorithm in &expected {
                assert!(before.contains(algorithm), "{snapshot}: {algorithm:#06x}");
            }
            let response = exec_raw(
                &mut runtime,
                &clock,
                make_credential(H0, &credential(), &object_name(name_label)),
            );
            assert_eq!(response_code(&response), 0, "{snapshot} succeeds");
            let after = runtime.self_test.pending_algorithms();
            for algorithm in &expected {
                assert!(
                    !after.contains(algorithm),
                    "{snapshot} clears {algorithm:#06x}"
                );
            }
            for algorithm in before {
                assert!(
                    expected.contains(&algorithm) || after.contains(&algorithm),
                    "{snapshot} cleared {algorithm:#06x}, which it never uses"
                );
            }
        }
    }

    #[test]
    fn pre_arithmetic_rejection_no_self_test() {
        let clock = clock();
        let name = object_name("READPUBLIC_ECC_AK");
        let mut runtime = runtime_at("ECC_READY", &clock);
        runtime.self_test = runtime.self_test.restarted();
        let before = runtime.self_test.pending_algorithms();
        exec_raw(
            &mut runtime,
            &clock,
            make_credential(H0, &[0x5a; 33], &name),
        );
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            before,
            "the credential size is checked before any key agreement"
        );
    }

    #[test]
    fn ecdh_test_after_secret_point_unmarshal() {
        let clock = clock();
        let (blob, secret) = made_credential("MC_ECC_SHA256");
        for (what, encrypted_secret, cleared) in [
            ("a truncated point", secret[..35].to_vec(), false),
            ("a point off the curve", off_curve_point(), true),
            ("the produced point", secret.clone(), true),
        ] {
            let mut runtime = runtime_at("ECC_READY", &clock);
            runtime.self_test = runtime.self_test.restarted();
            assert!(runtime.self_test.pending_algorithms().contains(&ALG_ECDH));
            exec_raw(
                &mut runtime,
                &clock,
                activate_credential(H1, H0, &blob, &encrypted_secret),
            );
            assert_eq!(
                !runtime.self_test.pending_algorithms().contains(&ALG_ECDH),
                cleared,
                "{what}"
            );
        }
    }

    fn off_curve_point() -> Vec<u8> {
        let mut out = 32u16.to_be_bytes().to_vec();
        out.extend_from_slice(&[0x07; 32]);
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(&[0x08; 32]);
        out
    }

    #[test]
    fn valid_secret_recovery_name_algorithm_precedence() {
        let clock = clock();
        for (snapshot, record, protector_hash) in [
            ("RSA_READY", "MC_RSA_SHA256", ALG_SHA256),
            ("ECC_READY", "MC_ECC_SHA256", ALG_SHA256),
        ] {
            let (blob, secret) = made_credential(record);
            let truncated_integrity = blob[..20].to_vec();
            let wrong_integrity = flipped(&blob, 2);
            for (what, candidate, symmetric_cleared) in [
                ("an empty credential blob", Vec::new(), false),
                ("a truncated integrity field", truncated_integrity, false),
                ("an incorrect integrity value", wrong_integrity, false),
                ("the produced credential blob", blob.clone(), true),
            ] {
                let mut runtime = runtime_at(snapshot, &clock);
                runtime.self_test = runtime.self_test.restarted();
                exec_raw(
                    &mut runtime,
                    &clock,
                    activate_credential(H1, H0, &candidate, &secret),
                );
                let pending = runtime.self_test.pending_algorithms();
                assert!(
                    !pending.contains(&protector_hash),
                    "{snapshot}: {what} recovers the seed, which already hashes with the \
                     protector name algorithm"
                );
                assert_eq!(
                    !pending.contains(&ALG_AES),
                    symmetric_cleared,
                    "{snapshot}: {what}"
                );
            }
        }
    }

    #[test]
    fn injected_self_test_failure_command_stop() {
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::self_test::{fails_on_aes, fails_on_sha256};
        const FAILURE: u32 = 0x0000_0101;

        let (rsa_blob, rsa_secret) = made_credential("MC_RSA_SHA256");
        let (ecc_blob, ecc_secret) = made_credential("MC_ECC_SHA256");
        let rsa_name = object_name("READPUBLIC_RSA_AK");
        let ecc_name = object_name("READPUBLIC_ECC_AK");
        struct SelfTestFailureCase {
            label: &'static str,
            snapshot: &'static str,
            runner: fn(PrimitiveTest) -> bool,
            location: FailureLocation,
            packet: Vec<u8>,
        }
        let cases = [
            SelfTestFailureCase {
                label: "TPM2_MakeCredential OAEP encoding",
                snapshot: "RSA_READY",
                runner: fails_on_sha256,
                location: FailureLocation::HashSelfTest,
                packet: make_credential(H0, &credential(), &rsa_name),
            },
            SelfTestFailureCase {
                label: "TPM2_MakeCredential outer encryption",
                snapshot: "RSA_READY",
                runner: fails_on_aes,
                location: FailureLocation::SymmetricSelfTest,
                packet: make_credential(H0, &credential(), &rsa_name),
            },
            SelfTestFailureCase {
                label: "TPM2_ActivateCredential OAEP decoding",
                snapshot: "RSA_READY",
                runner: fails_on_sha256,
                location: FailureLocation::HashSelfTest,
                packet: activate_credential(H1, H0, &rsa_blob, &rsa_secret),
            },
            SelfTestFailureCase {
                label: "TPM2_ActivateCredential outer decryption",
                snapshot: "RSA_READY",
                runner: fails_on_aes,
                location: FailureLocation::SymmetricSelfTest,
                packet: activate_credential(H1, H0, &rsa_blob, &rsa_secret),
            },
            SelfTestFailureCase {
                label: "TPM2_MakeCredential key derivation",
                snapshot: "ECC_READY",
                runner: fails_on_sha256,
                location: FailureLocation::HashSelfTest,
                packet: make_credential(H0, &credential(), &ecc_name),
            },
            SelfTestFailureCase {
                label: "TPM2_MakeCredential outer encryption over ECC",
                snapshot: "ECC_READY",
                runner: fails_on_aes,
                location: FailureLocation::SymmetricSelfTest,
                packet: make_credential(H0, &credential(), &ecc_name),
            },
            SelfTestFailureCase {
                label: "TPM2_ActivateCredential key derivation",
                snapshot: "ECC_READY",
                runner: fails_on_sha256,
                location: FailureLocation::HashSelfTest,
                packet: activate_credential(H1, H0, &ecc_blob, &ecc_secret),
            },
            SelfTestFailureCase {
                label: "TPM2_ActivateCredential outer decryption over ECC",
                snapshot: "ECC_READY",
                runner: fails_on_aes,
                location: FailureLocation::SymmetricSelfTest,
                packet: activate_credential(H1, H0, &ecc_blob, &ecc_secret),
            },
        ];

        for SelfTestFailureCase {
            label,
            snapshot,
            runner,
            location,
            packet,
        } in cases
        {
            let clock = clock();
            let mut runtime = runtime_at(snapshot, &clock);
            runtime.self_test = runtime.self_test.restarted();
            runtime.self_test.set_runner(runner);
            let response = exec_raw(&mut runtime, &clock, packet);
            assert_eq!(response_code(&response), FAILURE, "{label}");
            assert_eq!(response.len(), 10, "{label} publishes no parameters");
            assert!(runtime.failure_mode, "{label} stops the TPM");
            assert_eq!(
                runtime.failure_diagnostics,
                location.diagnostics(),
                "{label} names the vendored self-test site"
            );
        }
    }

    #[test]
    fn rsa_hash_failure_post_seed_pre_oaep_stop() {
        use crate::library::tpm2::self_test::fails_on_sha256;
        let clock = clock();
        let name = object_name("READPUBLIC_RSA_AK");

        let mut settled = runtime_at("RSA_READY", &clock);
        settled.self_test = settled.self_test.restarted();
        let before = generator_state(&settled);
        exec_raw(
            &mut settled,
            &clock,
            make_credential(H0, &credential(), &name),
        );
        let after_success = generator_state(&settled);

        let mut failing = runtime_at("RSA_READY", &clock);
        failing.self_test = failing.self_test.restarted();
        failing.self_test.set_runner(fails_on_sha256);
        exec_raw(
            &mut failing,
            &clock,
            make_credential(H0, &credential(), &name),
        );
        let after_failure = generator_state(&failing);

        assert_ne!(
            after_failure, before,
            "the seed and the lazy OAEP known-answer test are drawn before the hash test"
        );
        assert_ne!(
            after_failure, after_success,
            "the OAEP padding seed is drawn only once the hash test has passed"
        );
    }

    #[test]
    fn make_activate_round_trip() {
        let clock = clock();
        for (snapshot, label, activate, key, expected) in [
            ("RSA_READY", "MC_RSA_SHA256", H1, H0, credential()),
            ("ECC_READY", "MC_ECC_SHA256", H1, H0, credential()),
            ("RSA_READY", "MC_RSA_EMPTY_CREDENTIAL", H1, H0, Vec::new()),
        ] {
            let mut runtime = runtime_at(snapshot, &clock);
            let (blob, secret) = made_credential(label);
            let response = exec_raw(
                &mut runtime,
                &clock,
                activate_credential(activate, key, &blob, &secret),
            );
            assert_eq!(response_code(&response), 0, "{label}");
            let size = u16::from_be_bytes(response[14..16].try_into().expect("two bytes")) as usize;
            assert_eq!(&response[16..16 + size], expected.as_slice(), "{label}");
        }
    }
}
