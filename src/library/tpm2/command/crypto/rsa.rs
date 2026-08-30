use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_SCHEME, TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_H, TPM_RC_P,
};
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use crate::library::tpm2::public::{MAX_RSA_KEY_BYTES, TPM_ALG_RSA};
use crate::library::tpm2::random::{finish_live_rand, take_live_rand};
use crate::library::tpm2::rsa_encryption::{
    RsaDecryptScheme, check_ciphertext_size, crypt_rsa_decrypt, crypt_rsa_encrypt,
    is_label_properly_formatted, parse_rsa_decrypt_scheme, select_rsa_scheme,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::{LazySelfTest, self_test_algorithm, self_test_rsa_scheme};
use crate::library::tpm2::template::{TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TemplateReader};
use crate::types::TpmResult;

const RC_KEY_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_MESSAGE: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_LABEL: TpmResult = TPM_RC_P + TPM_RC_3;

const MAX_LABEL: usize = 2 + 64;

struct Parameters {
    data: Vec<u8>,
    scheme: RsaDecryptScheme,
    label: Vec<u8>,
}

fn parse_parameters(parameters: &[u8], runtime: &Tpm2Runtime) -> Result<Parameters, TpmResult> {
    let profile = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile;
    let mut reader = TemplateReader::new(parameters);
    let data = reader
        .tpm2b(MAX_RSA_KEY_BYTES)
        .map_err(|code| code + RC_MESSAGE)?
        .to_vec();
    let scheme =
        parse_rsa_decrypt_scheme(&mut reader, profile).map_err(|code| code + RC_IN_SCHEME)?;
    let label = reader
        .tpm2b(MAX_LABEL)
        .map_err(|code| code + RC_LABEL)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        data,
        scheme,
        label,
    })
}

fn rsa_key(runtime: &Tpm2Runtime, handle: u32) -> Result<Box<OwnedObjectBody>, TpmResult> {
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    match &object.body {
        OwnedAnyObjectBody::Object(body) => Ok(body.clone()),
        _ => Err(TPM_RC_KEY + RC_KEY_HANDLE),
    }
}

fn forbids_unpadded_encryption(runtime: &Tpm2Runtime) -> Result<bool, TpmResult> {
    Ok(runtime
        .state
        .as_ref()
        .ok_or(TPM_RC_FAILURE)?
        .profile
        .forbids_unpadded_encryption())
}

fn framed(data: Vec<u8>) -> Result<CommandOutput, TpmResult> {
    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&data).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

pub(in crate::library::tpm2::command) fn execute_encrypt(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let parameters = parse_parameters(frame.parameters, runtime)?;

    let key = rsa_key(runtime, key_handle)?;
    if key.public.object_type != TPM_ALG_RSA {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    }
    if key.public.object_attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }
    if !is_label_properly_formatted(&parameters.label) {
        return Err(TPM_RC_VALUE + RC_LABEL);
    }
    let scheme = select_rsa_scheme(&key, parameters.scheme).ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    self_test_rsa_scheme(runtime, scheme.scheme)?;

    let forbids_unpadded = forbids_unpadded_encryption(runtime)?;
    let mut rand = take_live_rand(runtime)?;
    let outcome = {
        let mut run = |algorithm: u16| self_test_algorithm(runtime, algorithm);
        crypt_rsa_encrypt(
            &key.public,
            &scheme,
            &parameters.data,
            &parameters.label,
            forbids_unpadded,
            &mut LazySelfTest::runtime(&mut run),
            &mut rand,
        )
    };
    finish_live_rand(runtime, rand)?;
    framed(outcome?)
}

pub(in crate::library::tpm2::command) fn execute_decrypt(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let parameters = parse_parameters(frame.parameters, runtime)?;

    let key = rsa_key(runtime, key_handle)?;
    if key.public.object_type != TPM_ALG_RSA {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    }
    let attributes = key.public.object_attributes;
    if attributes & TPMA_OBJECT_RESTRICTED != 0 || attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }
    if !is_label_properly_formatted(&parameters.label) {
        return Err(TPM_RC_VALUE + RC_LABEL);
    }
    let scheme = select_rsa_scheme(&key, parameters.scheme).ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;

    check_ciphertext_size(&key, &parameters.data)?;
    self_test_rsa_scheme(runtime, scheme.scheme)?;

    let forbids_unpadded = forbids_unpadded_encryption(runtime)?;
    let mut run = |algorithm: u16| self_test_algorithm(runtime, algorithm);
    let message = crypt_rsa_decrypt(
        &key,
        &scheme,
        &parameters.data,
        &parameters.label,
        forbids_unpadded,
        &mut LazySelfTest::runtime(&mut run),
    )?;
    framed(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::cancel::Cancellation;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_RSA_DECRYPT, TPM_CC_RSA_ENCRYPT, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, TPM_ALG_SHA1, TPM_ALG_SHA256, command, dispatch_bytes, error_response,
        pw_session, response_code, response_parameters,
    };
    use crate::library::tpm2::golden_responses::rsa_encryption::vector;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;
    const TPM_ALG_NULL_ID: u16 = 0x0010;
    const TPM_ALG_RSASSA_ID: u16 = 0x0014;
    const TPM_ALG_RSAES_ID: u16 = 0x0015;
    const TPM_ALG_OAEP_ID: u16 = 0x0017;

    const KEY_NULL: u32 = 0x8000_0000;
    const KEY_OAEP: u32 = 0x8000_0001;
    const KEY_RSAES: u32 = 0x8000_0002;
    const PERSISTENT: u32 = 0x8100_0001;

    const KEY_AUTH: &[u8] = b"dec";

    fn payload(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index * 7 + 3) & 0xff) as u8)
            .collect()
    }

    fn tpm2b(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    fn null_scheme() -> Vec<u8> {
        TPM_ALG_NULL_ID.to_be_bytes().to_vec()
    }

    fn rsaes_scheme() -> Vec<u8> {
        TPM_ALG_RSAES_ID.to_be_bytes().to_vec()
    }

    fn oaep_scheme(hash_alg: u16) -> Vec<u8> {
        let mut out = TPM_ALG_OAEP_ID.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out
    }

    fn parameters(data: &[u8], scheme: &[u8], label: &[u8]) -> Vec<u8> {
        let mut out = tpm2b(data);
        out.extend_from_slice(scheme);
        out.extend_from_slice(&tpm2b(label));
        out
    }

    fn encrypt_command(handle: u32, message: &[u8], scheme: &[u8], label: &[u8]) -> Vec<u8> {
        command(
            TPM_CC_RSA_ENCRYPT,
            &[handle],
            &[],
            &parameters(message, scheme, label),
        )
    }

    fn decrypt_command(
        handle: u32,
        ciphertext: &[u8],
        scheme: &[u8],
        label: &[u8],
        password: &[u8],
    ) -> Vec<u8> {
        command(
            TPM_CC_RSA_DECRYPT,
            &[handle],
            &[password],
            &parameters(ciphertext, scheme, label),
        )
    }

    #[track_caller]
    fn restored(snapshot: &str) -> Tpm2Runtime {
        let mut runtime = restore_permanent_blob_for_test(vector(&format!("PERMALL_{snapshot}")))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector(&format!("VOLATILE_{snapshot}")))
            .expect("the oracle volatile state attaches");
        assert!(
            runtime.startup_received,
            "the snapshot is past TPM2_Startup"
        );
        runtime
    }

    #[track_caller]
    fn rsa_output_of(record: &str) -> Vec<u8> {
        let response = vector(record);
        assert_eq!(
            response_code(response),
            RC_SUCCESS,
            "{record} is a success record"
        );
        let body = response_parameters(response);
        let size = usize::from(u16::from_be_bytes([body[0], body[1]]));
        body[2..2 + size].to_vec()
    }

    #[track_caller]
    fn check(runtime: &mut Tpm2Runtime, record: &str, packet: &[u8]) {
        assert_eq!(
            dispatch_bytes(runtime, packet),
            vector(record),
            "record {record}"
        );
    }

    #[test]
    fn command_registration_upstream_attributes() {
        let encrypt = find(TPM_CC_RSA_ENCRYPT).expect("TPM2_RSA_Encrypt is registered");
        assert_eq!(encrypt.attributes, 0x0200_0174);
        assert_eq!(encrypt.decrypt_size, 2);
        assert_eq!(encrypt.encrypt_size, 2);
        assert!(encrypt.sessions_allowed);
        assert!(!encrypt.physical_presence);
        assert!(matches!(encrypt.nv_access, NvAccess::Neither));
        assert!(matches!(
            encrypt.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(encrypt.handles.len(), 1);
        assert!(
            !encrypt.handles[0].user_auth,
            "encryption uses only the public area"
        );
        assert!(!encrypt.handles[0].admin_role());
        assert!(matches!(encrypt.handles[0].kind, HandleKind::Object));

        let decrypt = find(TPM_CC_RSA_DECRYPT).expect("TPM2_RSA_Decrypt is registered");
        assert_eq!(decrypt.attributes, 0x0200_0159);
        assert_eq!(decrypt.decrypt_size, 2);
        assert_eq!(decrypt.encrypt_size, 2);
        assert!(decrypt.sessions_allowed);
        assert!(!decrypt.physical_presence);
        assert!(matches!(decrypt.nv_access, NvAccess::Neither));
        assert!(matches!(
            decrypt.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(decrypt.handles.len(), 1);
        assert!(decrypt.handles[0].user_auth);
        assert!(!decrypt.handles[0].admin_role());
        assert!(matches!(decrypt.handles[0].kind, HandleKind::Object));
    }

    fn advertised(record: &str) -> Vec<u32> {
        let body = response_parameters(vector(record));
        let count = u32::from_be_bytes(body[5..9].try_into().expect("a count")) as usize;
        (0..count)
            .map(|index| {
                u32::from_be_bytes(
                    body[9 + index * 4..13 + index * 4]
                        .try_into()
                        .expect("an entry"),
                )
            })
            .collect()
    }

    #[test]
    fn command_attributes_oracle_match() {
        for (record, code, attributes) in [
            ("CCATTR_0159", TPM_CC_RSA_DECRYPT, 0x0200_0159u32),
            ("CCATTR_0174", TPM_CC_RSA_ENCRYPT, 0x0200_0174),
        ] {
            assert_eq!(advertised(record), [attributes]);
            assert_eq!(find(code).expect("registered").attributes, attributes);
        }
    }

    #[test]
    fn capability_page_upstream_command_order() {
        use crate::library::tpm2::capability::commands::implemented;

        for (record, start) in [
            ("CCATTR_AROUND_DECRYPT", 0x0157u32),
            ("CCATTR_AROUND_ENCRYPT", 0x0173),
        ] {
            let reference = advertised(record);
            assert!(
                reference
                    .windows(2)
                    .all(|pair| pair[0] & 0xffff < pair[1] & 0xffff),
                "{record} is ordered by command code"
            );
            let last = reference.last().expect("a non-empty page") & 0xffff;
            let ours: Vec<u32> = implemented(start, reference.len() as u32)
                .entries
                .into_iter()
                .filter(|entry| entry & 0xffff <= last)
                .collect();
            let mut remaining = reference.iter().copied();
            for entry in &ours {
                assert!(
                    remaining.any(|reference_entry| reference_entry == *entry),
                    "{record}: {entry:#010x} is missing or out of order upstream"
                );
            }
        }
        assert!(
            advertised("CCATTR_AROUND_DECRYPT").contains(&0x0200_0159),
            "TPM2_RSA_Decrypt sits between TPM2_Load and TPM2_HMAC_Start upstream"
        );
        assert!(
            advertised("CCATTR_AROUND_ENCRYPT").contains(&0x0200_0174),
            "TPM2_RSA_Encrypt sits between TPM2_ReadPublic and TPM2_StartAuthSession upstream"
        );
    }

    #[test]
    fn pre_startup_rejection() {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_BASE"))
            .expect("the oracle permanent state restores");
        assert!(!runtime.startup_received);
        check(
            &mut runtime,
            "ENC_BEFORE_STARTUP",
            &encrypt_command(KEY_NULL, b"abc", &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "DEC_BEFORE_STARTUP",
            &decrypt_command(KEY_NULL, &payload(256), &null_scheme(), b"", KEY_AUTH),
        );
    }

    #[test]
    fn handle_rejection_oracle_parity() {
        let mut runtime = restored("READY");
        for (record, handle) in [
            ("ENC_UNLOADED_TRANSIENT", KEY_NULL),
            ("ENC_MISSING_PERSISTENT", 0x8100_0009),
            ("ENC_HIERARCHY_HANDLE", 0x4000_0001),
            ("ENC_SESSION_HANDLE", 0x0200_0000),
        ] {
            check(
                &mut runtime,
                record,
                &encrypt_command(handle, b"abc", &null_scheme(), b""),
            );
        }
        for (record, handle) in [
            ("DEC_UNLOADED_TRANSIENT", KEY_NULL),
            ("DEC_MISSING_PERSISTENT", 0x8100_0009),
            ("DEC_HIERARCHY_HANDLE", 0x4000_0001),
            ("DEC_SESSION_HANDLE", 0x0200_0000),
        ] {
            check(
                &mut runtime,
                record,
                &decrypt_command(handle, &payload(256), &null_scheme(), b"", KEY_AUTH),
            );
        }
        let mut truncated = encrypt_command(KEY_NULL, b"abc", &null_scheme(), b"");
        truncated.truncate(12);
        truncated[2..6].copy_from_slice(&12u32.to_be_bytes());
        check(&mut runtime, "ENC_TRUNCATED_HANDLE", &truncated);
    }

    #[test]
    fn per_scheme_encryption_oracle_parity() {
        let mut runtime = restored("KEYS");
        let message = payload(32);
        check(
            &mut runtime,
            "ENC_RAW",
            &encrypt_command(KEY_NULL, &message, &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_RSAES",
            &encrypt_command(KEY_NULL, &message, &rsaes_scheme(), b""),
        );
        for (record, hash_alg) in [
            ("ENC_OAEP_SHA1", TPM_ALG_SHA1),
            ("ENC_OAEP_SHA256", TPM_ALG_SHA256),
            ("ENC_OAEP_SHA384", TPM_ALG_SHA384),
            ("ENC_OAEP_SHA512", TPM_ALG_SHA512),
        ] {
            check(
                &mut runtime,
                record,
                &encrypt_command(KEY_NULL, &message, &oaep_scheme(hash_alg), b""),
            );
        }
        check(
            &mut runtime,
            "ENC_OAEP_LABEL",
            &encrypt_command(KEY_NULL, &message, &oaep_scheme(TPM_ALG_SHA256), b"label\0"),
        );
        check(
            &mut runtime,
            "ENC_OAEP_EMPTY_MESSAGE",
            &encrypt_command(KEY_NULL, b"", &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "ENC_RSAES_EMPTY_MESSAGE",
            &encrypt_command(KEY_NULL, b"", &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_RAW_EMPTY_MESSAGE",
            &encrypt_command(KEY_NULL, b"", &null_scheme(), b""),
        );
    }

    #[test]
    fn key_default_scheme_and_conflict_oracle_parity() {
        let mut runtime = restored("KEYS");
        let message = payload(32);
        check(
            &mut runtime,
            "ENC_KEY_DEFAULT_OAEP",
            &encrypt_command(KEY_OAEP, &message, &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_KEY_DEFAULT_OAEP_LABEL",
            &encrypt_command(KEY_OAEP, &message, &null_scheme(), b"label\0"),
        );
        check(
            &mut runtime,
            "ENC_KEY_OAEP_SAME_SCHEME",
            &encrypt_command(KEY_OAEP, &message, &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "ENC_KEY_OAEP_OTHER_HASH",
            &encrypt_command(KEY_OAEP, &message, &oaep_scheme(TPM_ALG_SHA384), b""),
        );
        check(
            &mut runtime,
            "ENC_KEY_OAEP_RSAES",
            &encrypt_command(KEY_OAEP, &message, &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_KEY_DEFAULT_RSAES",
            &encrypt_command(KEY_RSAES, &message, &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_KEY_RSAES_SAME_SCHEME",
            &encrypt_command(KEY_RSAES, &message, &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_KEY_RSAES_OAEP",
            &encrypt_command(KEY_RSAES, &message, &oaep_scheme(TPM_ALG_SHA256), b""),
        );
    }

    #[test]
    fn message_size_boundaries_oracle_match() {
        let mut runtime = restored("KEYS");
        for (record, length, scheme) in [
            ("ENC_RSAES_MAX", 245usize, rsaes_scheme()),
            ("ENC_RSAES_TOO_LARGE", 246, rsaes_scheme()),
            ("ENC_OAEP_SHA1_MAX", 214, oaep_scheme(TPM_ALG_SHA1)),
            ("ENC_OAEP_SHA1_TOO_LARGE", 215, oaep_scheme(TPM_ALG_SHA1)),
            ("ENC_OAEP_SHA256_MAX", 190, oaep_scheme(TPM_ALG_SHA256)),
            (
                "ENC_OAEP_SHA256_TOO_LARGE",
                191,
                oaep_scheme(TPM_ALG_SHA256),
            ),
            ("ENC_OAEP_SHA512_MAX", 126, oaep_scheme(TPM_ALG_SHA512)),
            (
                "ENC_OAEP_SHA512_TOO_LARGE",
                127,
                oaep_scheme(TPM_ALG_SHA512),
            ),
            ("ENC_MESSAGE_OVER_TPM2B", 385, rsaes_scheme()),
        ] {
            check(
                &mut runtime,
                record,
                &encrypt_command(KEY_NULL, &payload(length), &scheme, b""),
            );
        }
    }

    #[test]
    fn raw_encryption_numeric_value_oracle_parity() {
        let mut runtime = restored("KEYS");
        check(
            &mut runtime,
            "ENC_RAW_FULL_WIDTH",
            &encrypt_command(KEY_NULL, &payload(256), &null_scheme(), b""),
        );
        let mut padded = vec![0u8; 8];
        padded.extend_from_slice(&payload(248));
        check(
            &mut runtime,
            "ENC_RAW_LEADING_ZEROS",
            &encrypt_command(KEY_NULL, &padded, &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_RAW_OVER_MODULUS",
            &encrypt_command(KEY_NULL, &[0xff; 256], &null_scheme(), b""),
        );
        let mut long = vec![0x01u8];
        long.extend_from_slice(&payload(256));
        check(
            &mut runtime,
            "ENC_RAW_TOO_LONG",
            &encrypt_command(KEY_NULL, &long, &null_scheme(), b""),
        );
    }

    #[test]
    fn label_and_scheme_rejection_oracle_parity() {
        let mut runtime = restored("KEYS");
        let message = payload(32);
        let mut long_label = payload(65);
        long_label.push(0x00);
        let mut over_label = payload(66);
        over_label.push(0x00);
        for (record, label) in [
            ("ENC_LABEL_NO_TERMINATOR", b"label".to_vec()),
            ("ENC_LABEL_ONLY_NUL", b"\0".to_vec()),
            ("ENC_LABEL_EMBEDDED_NUL", b"a\0b\0".to_vec()),
            ("ENC_LABEL_NUL_FIRST", b"\0b".to_vec()),
            ("ENC_LABEL_MAX", long_label),
            ("ENC_LABEL_OVER_TPM2B", over_label),
        ] {
            check(
                &mut runtime,
                record,
                &encrypt_command(KEY_NULL, &message, &oaep_scheme(TPM_ALG_SHA256), &label),
            );
        }
        let mut rsassa = TPM_ALG_RSASSA_ID.to_be_bytes().to_vec();
        rsassa.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        let mut unknown = 0xffffu16.to_be_bytes().to_vec();
        unknown.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        let mut rsaes_with_details = rsaes_scheme();
        rsaes_with_details.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        for (record, scheme) in [
            ("ENC_SCHEME_RSASSA", rsassa),
            ("ENC_SCHEME_UNKNOWN", unknown),
            ("ENC_OAEP_HASH_NULL", oaep_scheme(TPM_ALG_NULL_ID)),
            ("ENC_OAEP_HASH_UNKNOWN", oaep_scheme(0x00ff)),
            ("ENC_RSAES_WITH_DETAILS", rsaes_with_details),
        ] {
            check(
                &mut runtime,
                record,
                &encrypt_command(KEY_NULL, &message, &scheme, b""),
            );
        }
    }

    #[test]
    fn truncated_extended_parameter_area_oracle_parity() {
        let mut runtime = restored("KEYS");
        let full = encrypt_command(
            KEY_NULL,
            &payload(32),
            &oaep_scheme(TPM_ALG_SHA256),
            b"label\0",
        );
        for (record, length) in [
            ("ENC_EMPTY_PARAMETERS", 14usize),
            ("ENC_TRUNCATED_MESSAGE_SIZE", 15),
            ("ENC_TRUNCATED_MESSAGE", 20),
            ("ENC_TRUNCATED_SCHEME", 48),
            ("ENC_TRUNCATED_OAEP_HASH", 51),
            ("ENC_TRUNCATED_LABEL_SIZE", 53),
            ("ENC_TRUNCATED_LABEL", 58),
        ] {
            let mut cut = full[..length].to_vec();
            cut[2..6].copy_from_slice(&(length as u32).to_be_bytes());
            check(&mut runtime, record, &cut);
        }
        let mut extended = full.clone();
        extended.push(0x00);
        let size = extended.len() as u32;
        extended[2..6].copy_from_slice(&size.to_be_bytes());
        check(&mut runtime, "ENC_TRAILING_BYTE", &extended);

        let dec_full = decrypt_command(
            KEY_NULL,
            &payload(256),
            &oaep_scheme(TPM_ALG_SHA256),
            b"label\0",
            KEY_AUTH,
        );
        for (record, length) in [
            ("DEC_EMPTY_PARAMETERS", 30usize),
            ("DEC_TRUNCATED_CIPHERTEXT", 100),
            ("DEC_TRUNCATED_SCHEME", 288),
            ("DEC_TRUNCATED_LABEL", dec_full.len() - 2),
        ] {
            let mut cut = dec_full[..length].to_vec();
            cut[2..6].copy_from_slice(&(length as u32).to_be_bytes());
            check(&mut runtime, record, &cut);
        }
        let mut extended = dec_full.clone();
        extended.push(0x00);
        let size = extended.len() as u32;
        extended[2..6].copy_from_slice(&size.to_be_bytes());
        check(&mut runtime, "DEC_TRAILING_BYTE", &extended);
    }

    #[test]
    fn wrong_key_type_and_attribute_oracle_parity() {
        let mut runtime = restored("MIXED");
        let message = payload(32);
        let ciphertext = payload(256);
        for (record, handle) in [
            ("ENC_RESTRICTED_KEY", 0x8000_0000u32),
            ("ENC_SIGNING_KEY", 0x8000_0001),
            ("ENC_ECC_KEY", 0x8000_0002),
        ] {
            check(
                &mut runtime,
                record,
                &encrypt_command(handle, &message, &oaep_scheme(TPM_ALG_SHA256), b""),
            );
        }
        for (record, handle) in [
            ("DEC_RESTRICTED_KEY", 0x8000_0000u32),
            ("DEC_SIGNING_KEY", 0x8000_0001),
            ("DEC_ECC_KEY", 0x8000_0002),
        ] {
            check(
                &mut runtime,
                record,
                &decrypt_command(
                    handle,
                    &ciphertext,
                    &oaep_scheme(TPM_ALG_SHA256),
                    b"",
                    KEY_AUTH,
                ),
            );
        }
    }

    #[test]
    fn public_only_key_encrypt_only() {
        let mut runtime = restored("EXTERNAL");
        check(
            &mut runtime,
            "ENC_EXTERNAL_RAW",
            &encrypt_command(KEY_NULL, &payload(32), &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_EXTERNAL_OAEP",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "DEC_EXTERNAL_NO_SENSITIVE",
            &decrypt_command(
                KEY_NULL,
                &payload(256),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                b"",
            ),
        );
        check(
            &mut runtime,
            "DEC_EXTERNAL_NO_SESSION",
            &command(
                TPM_CC_RSA_DECRYPT,
                &[KEY_NULL],
                &[],
                &parameters(&payload(256), &oaep_scheme(TPM_ALG_SHA256), b""),
            ),
        );
    }

    #[test]
    fn other_key_size_oracle_parity() {
        let mut runtime = restored("SIZES");
        check(
            &mut runtime,
            "ENC_3072_OAEP_SHA256",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "ENC_3072_RSAES_MAX",
            &encrypt_command(KEY_NULL, &payload(373), &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_3072_RSAES_TOO_LARGE",
            &encrypt_command(KEY_NULL, &payload(374), &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_1024_OAEP_SHA256",
            &encrypt_command(KEY_OAEP, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "ENC_1024_OAEP_SHA512",
            &encrypt_command(KEY_OAEP, &payload(32), &oaep_scheme(TPM_ALG_SHA512), b""),
        );
        check(
            &mut runtime,
            "DEC_1024_OAEP_SHA512",
            &decrypt_command(
                KEY_OAEP,
                &payload(128),
                &oaep_scheme(TPM_ALG_SHA512),
                b"",
                KEY_AUTH,
            ),
        );
    }

    #[test]
    fn authorization_and_da_accounting_oracle_parity() {
        let mut runtime = restored("KEYS");
        check(
            &mut runtime,
            "DEC_NO_SESSION",
            &command(
                TPM_CC_RSA_DECRYPT,
                &[KEY_NULL],
                &[],
                &parameters(&payload(256), &null_scheme(), b""),
            ),
        );
        check(
            &mut runtime,
            "DEC_WRONG_PASSWORD",
            &decrypt_command(KEY_NULL, &payload(256), &null_scheme(), b"", b"nope"),
        );
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(
                runtime.state.as_ref().expect("decoded state")
            )
            .expect("the permanent state serializes"),
            vector("PERMALL_AFTER_BAD_AUTH"),
            "the failed authorization is accounted for like the oracle"
        );

        let mut runtime = restored("KEYS");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &decrypt_command(KEY_NULL, &payload(256), &null_scheme(), b"", KEY_AUTH),
            )),
            RC_SUCCESS,
            "the raw decryption runs once the password matches"
        );
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(
                runtime.state.as_ref().expect("decoded state")
            )
            .expect("the permanent state serializes"),
            vector("PERMALL_AFTER_GOOD_AUTH"),
            "a correct password leaves the dictionary-attack counters alone"
        );
    }

    #[test]
    fn random_consumption_oracle_match() {
        let random = command(0x0000_017b, &[], &[], &16u16.to_be_bytes());
        let mut runtime = restored("KEYS");
        check(&mut runtime, "RND_BASELINE", &random);

        for (record, packet) in [
            (
                "RND_AFTER_RAW",
                encrypt_command(KEY_NULL, &payload(32), &null_scheme(), b""),
            ),
            (
                "RND_AFTER_RSAES",
                encrypt_command(KEY_NULL, &payload(32), &rsaes_scheme(), b""),
            ),
            (
                "RND_AFTER_OAEP",
                encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
            ),
            (
                "RND_AFTER_REJECTED_LABEL",
                encrypt_command(
                    KEY_NULL,
                    &payload(32),
                    &oaep_scheme(TPM_ALG_SHA256),
                    b"label",
                ),
            ),
            (
                "RND_AFTER_OVERSIZED_MESSAGE",
                encrypt_command(KEY_NULL, &payload(191), &oaep_scheme(TPM_ALG_SHA256), b""),
            ),
            (
                "RND_AFTER_FAILED_RSAES_DECRYPT",
                decrypt_command(KEY_NULL, &payload(256), &rsaes_scheme(), b"", KEY_AUTH),
            ),
            (
                "RND_AFTER_SHORT_CIPHERTEXT",
                decrypt_command(KEY_NULL, &payload(255), &rsaes_scheme(), b"", KEY_AUTH),
            ),
        ] {
            let mut runtime = restored("KEYS");
            dispatch_bytes(&mut runtime, &packet);
            check(&mut runtime, record, &random);
        }

        assert_eq!(
            vector("RND_AFTER_RAW"),
            vector("RND_BASELINE"),
            "the raw known-answer test draws no random bytes"
        );
        assert_eq!(
            vector("RND_AFTER_REJECTED_LABEL"),
            vector("RND_BASELINE"),
            "a rejected label never reaches the generator"
        );
        assert_eq!(
            vector("RND_AFTER_SHORT_CIPHERTEXT"),
            vector("RND_BASELINE"),
            "a ciphertext of the wrong size is rejected before the self test"
        );
        assert_ne!(
            vector("RND_AFTER_RSAES"),
            vector("RND_BASELINE"),
            "RSAES draws a self-test pad and a padding block"
        );
        assert_ne!(
            vector("RND_AFTER_OAEP"),
            vector("RND_BASELINE"),
            "OAEP draws a self-test seed and a padding seed"
        );
    }

    #[test]
    fn persistent_decryption_key_oracle_match() {
        let mut runtime = restored("PERSISTENT");
        check(
            &mut runtime,
            "ENC_PERSISTENT_OAEP",
            &encrypt_command(PERSISTENT, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "ENC_PERSISTENT_RSAES",
            &encrypt_command(PERSISTENT, &payload(32), &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_FLUSHED_TRANSIENT",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );

        let mut runtime = restored("PERSISTENT");
        check(
            &mut runtime,
            "DEC_PERSISTENT_OAEP",
            &decrypt_command(
                PERSISTENT,
                &rsa_output_of("ENC_PERSISTENT_OAEP"),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
    }

    #[test]
    fn profile_unpadded_encryption_gate() {
        let mut runtime = restored("NO_UNPADDED");
        check(
            &mut runtime,
            "ENC_NO_UNPADDED_RAW",
            &encrypt_command(KEY_NULL, &payload(32), &null_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_NO_UNPADDED_OAEP",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "DEC_NO_UNPADDED_RAW",
            &decrypt_command(KEY_NULL, &payload(256), &null_scheme(), b"", KEY_AUTH),
        );
    }

    #[test]
    fn profile_scheme_and_hash_disable() {
        let mut runtime = restored("NO_RSAES");
        check(
            &mut runtime,
            "ENC_NO_RSAES_SCHEME",
            &encrypt_command(KEY_NULL, &payload(32), &rsaes_scheme(), b""),
        );
        check(
            &mut runtime,
            "ENC_NO_RSAES_OAEP",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
        check(
            &mut runtime,
            "DEC_NO_RSAES_SCHEME",
            &decrypt_command(KEY_NULL, &payload(256), &rsaes_scheme(), b"", KEY_AUTH),
        );

        let mut runtime = restored("NO_SHA1");
        check(
            &mut runtime,
            "ENC_NO_SHA1_OAEP",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA1), b""),
        );
        check(
            &mut runtime,
            "ENC_NO_SHA1_OAEP_SHA256",
            &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
        );
    }

    fn start_auth_session_command() -> Vec<u8> {
        let mut params = tpm2b(&payload(32));
        params.extend_from_slice(&tpm2b(b""));
        params.push(0x00);
        params.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
        params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        command(0x0000_0176, &[0x4000_0007, 0x4000_0007], &[], &params)
    }

    fn session_nonce_tpm() -> Vec<u8> {
        let response = vector("SAS_PARAM_SESSION");
        let size = usize::from(u16::from_be_bytes([response[14], response[15]]));
        response[16..16 + size].to_vec()
    }

    fn hide(nonce_caller: &[u8], data: &[u8]) -> Vec<u8> {
        use crate::library::tpm2::crypto::{kdfa, sym_cfb_encrypt};

        let material = kdfa(
            TPM_ALG_SHA256,
            b"",
            b"CFB\0",
            nonce_caller,
            &session_nonce_tpm(),
            (16 + 16) * 8,
        )
        .expect("the session key derives");
        let mut buffer = data.to_vec();
        sym_cfb_encrypt(0x0006, &material[..16], &material[16..32], &mut buffer)
            .expect("the parameter encrypts");
        buffer
    }

    fn encrypting_session_area(nonce_caller: &[u8]) -> Vec<u8> {
        let mut out = 0x0200_0000u32.to_be_bytes().to_vec();
        out.extend_from_slice(&tpm2b(nonce_caller));
        out.push(0x61);
        out.extend_from_slice(&tpm2b(b""));
        out
    }

    fn with_sessions(code: u32, handle: u32, area: &[u8], parameters: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
        payload.extend_from_slice(area);
        payload.extend_from_slice(parameters);
        crate::library::tpm2::command::core::test_support::framed(code, &payload, true)
    }

    #[test]
    fn parameter_encryption_session_oracle_match() {
        let mut runtime = restored("KEYS");
        check(
            &mut runtime,
            "SAS_PARAM_SESSION",
            &start_auth_session_command(),
        );

        let nonce_caller: Vec<u8> = payload(32).into_iter().rev().collect();
        let message = payload(32);
        let mut encrypted = tpm2b(&hide(&nonce_caller, &message));
        encrypted.extend_from_slice(&oaep_scheme(TPM_ALG_SHA256));
        encrypted.extend_from_slice(&tpm2b(b""));

        let mut runtime = restored("SESSION");
        check(
            &mut runtime,
            "ENC_PARAMETER_ENCRYPTED",
            &with_sessions(
                TPM_CC_RSA_ENCRYPT,
                KEY_NULL,
                &encrypting_session_area(&nonce_caller),
                &encrypted,
            ),
        );

        let ciphertext = rsa_output_of("ENC_OAEP_SHA256");
        let mut encrypted = tpm2b(&hide(&nonce_caller, &ciphertext));
        encrypted.extend_from_slice(&oaep_scheme(TPM_ALG_SHA256));
        encrypted.extend_from_slice(&tpm2b(b""));
        let mut area = pw_session(KEY_AUTH);
        area.extend_from_slice(&encrypting_session_area(&nonce_caller));

        let mut runtime = restored("SESSION");
        check(
            &mut runtime,
            "DEC_PARAMETER_ENCRYPTED",
            &with_sessions(TPM_CC_RSA_DECRYPT, KEY_NULL, &area, &encrypted),
        );
    }

    fn drbg_requests(runtime: &Tpm2Runtime) -> u64 {
        runtime.live.orderly.drbg_state.reseed_counter
    }

    fn session_nonce(runtime: &Tpm2Runtime) -> Vec<u8> {
        crate::library::tpm2::session::loaded_session(&runtime.live, 0x0200_0000)
            .expect("the session is loaded")
            .nonce_tpm
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn failed_response_session_rollback_random_draw_kept() {
        use crate::library::tpm2::command::session::processing::{
            ResponseFault, inject_response_fault,
        };

        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                inject_response_fault(None);
            }
        }

        let nonce_caller: Vec<u8> = payload(32).into_iter().rev().collect();
        let mut encrypted = tpm2b(&hide(&nonce_caller, &payload(32)));
        encrypted.extend_from_slice(&oaep_scheme(TPM_ALG_SHA256));
        encrypted.extend_from_slice(&tpm2b(b""));
        let packet = with_sessions(
            TPM_CC_RSA_ENCRYPT,
            KEY_NULL,
            &encrypting_session_area(&nonce_caller),
            &encrypted,
        );

        let mut runtime = restored("SESSION");
        let nonce_before = session_nonce(&runtime);
        let requests_before = drbg_requests(&runtime);
        assert!(runtime.self_test.oaep_pending);

        inject_response_fault(Some(ResponseFault::BeforeFlush));
        let _guard = Guard;
        let response = dispatch_bytes(&mut runtime, &packet);
        inject_response_fault(None);

        assert_eq!(response_code(&response), 0x0000_0101, "TPM_RC_FAILURE");
        assert!(!runtime.failure_mode, "a returned error is not fatal");
        assert_eq!(
            session_nonce(&runtime),
            nonce_before,
            "the response session state is rolled back"
        );
        assert!(
            !runtime.self_test.oaep_pending,
            "the reference never re-arms a self test it already completed"
        );
        assert!(
            drbg_requests(&runtime) > requests_before,
            "the reference never rewinds the random bytes it already drew"
        );
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let mut runtime = restored("KEYS");
        let templates = [
            encrypt_command(
                KEY_NULL,
                &payload(8),
                &oaep_scheme(TPM_ALG_SHA256),
                b"lab\0",
            ),
            decrypt_command(KEY_NULL, &payload(8), &rsaes_scheme(), b"", KEY_AUTH),
        ];
        for template in templates {
            for length in 10..template.len().min(40) {
                let mut cut = template[..length].to_vec();
                let size = cut.len() as u32;
                cut[2..6].copy_from_slice(&size.to_be_bytes());
                let _ = dispatch_bytes(&mut runtime, &cut);
            }
            for index in 10..template.len() {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = template.clone();
                    mutated[index] ^= flip;
                    let _ = dispatch_bytes(&mut runtime, &mutated);
                }
            }
        }
        assert!(!runtime.failure_mode, "no mutation reaches a FAIL() site");
    }

    fn created_object_name(record: &str) -> Vec<u8> {
        let response = vector(record);
        let size = u32::from_be_bytes(response[14..18].try_into().expect("a size")) as usize;
        let body = &response[18..18 + size];
        let mut offset = 0usize;
        let next = |offset: &mut usize| {
            let length = usize::from(u16::from_be_bytes([body[*offset], body[*offset + 1]]));
            let start = *offset + 2;
            *offset = start + length;
            body[start..start + length].to_vec()
        };
        next(&mut offset);
        next(&mut offset);
        next(&mut offset);
        offset += 2 + 4;
        next(&mut offset);
        next(&mut offset)
    }

    fn command_hmac(parameters: &[u8], nonce_caller: &[u8], attributes: u8) -> Vec<u8> {
        use crate::library::tpm2::crypto::{Hasher, HmacState};

        let mut hasher = Hasher::new(TPM_ALG_SHA256).expect("a compiled hash");
        hasher.update(&TPM_CC_RSA_DECRYPT.to_be_bytes());
        hasher.update(&created_object_name("CREATE_NULL_SCHEME"));
        hasher.update(parameters);
        let cp_hash = hasher.finalize();

        let mut hmac = HmacState::new(TPM_ALG_SHA256, KEY_AUTH).expect("a compiled hash");
        hmac.update(&cp_hash);
        hmac.update(nonce_caller);
        hmac.update(&session_nonce_tpm());
        hmac.update(&[attributes]);
        hmac.finalize()
    }

    #[test]
    fn hmac_authorized_decryption_oracle_match() {
        let nonce_caller: Vec<u8> = payload(32).into_iter().rev().collect();
        let mut parameters = tpm2b(&rsa_output_of("ENC_OAEP_SHA256"));
        parameters.extend_from_slice(&oaep_scheme(TPM_ALG_SHA256));
        parameters.extend_from_slice(&tpm2b(b""));
        let mac = command_hmac(&parameters, &nonce_caller, 0x01);

        let area = |mac: &[u8]| {
            let mut out = 0x0200_0000u32.to_be_bytes().to_vec();
            out.extend_from_slice(&tpm2b(&nonce_caller));
            out.push(0x01);
            out.extend_from_slice(&tpm2b(mac));
            out
        };

        let mut runtime = restored("SESSION");
        check(
            &mut runtime,
            "DEC_HMAC_AUTHORIZED",
            &with_sessions(TPM_CC_RSA_DECRYPT, KEY_NULL, &area(&mac), &parameters),
        );

        let mut wrong = mac.clone();
        wrong[0] ^= 0x01;
        let mut runtime = restored("SESSION");
        check(
            &mut runtime,
            "DEC_HMAC_WRONG",
            &with_sessions(TPM_CC_RSA_DECRYPT, KEY_NULL, &area(&wrong), &parameters),
        );
    }

    mod self_tests {
        use super::*;
        use crate::library::CommandInput;
        use crate::library::constants::TPM_RC_FAILURE;
        use crate::library::tpm2::clock::RecordingClock;
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::rsa_vectors::{PaddedRsaSelfTestStage, RawRsaSelfTestStage};
        use core::cell::Cell;

        fn process(
            runtime: &mut Tpm2Runtime,
            command: &CommandInput,
        ) -> Result<Vec<u8>, TpmResult> {
            crate::library::tpm2::process(
                runtime,
                crate::library::tpm2::PlatformInputs::at_locality(0),
                command,
                &RecordingClock::new(1_600_000_000_000, 5_000_000),
                |_| panic!("failure mode must not schedule an NV commit"),
                Cancellation::disabled(),
            )
        }

        thread_local! {
            static OAEP_CALLS: Cell<usize> = const { Cell::new(0) };
            static RSAES_CALLS: Cell<usize> = const { Cell::new(0) };
            static RAW_CALLS: Cell<usize> = const { Cell::new(0) };
        }

        fn counting_oaep(seed: &[u8]) -> Result<(), PaddedRsaSelfTestStage> {
            OAEP_CALLS.with(|calls| calls.set(calls.get() + 1));
            assert_eq!(seed.len(), 64, "the reference draws a SHA-512 sized seed");
            crate::library::tpm2::rsa_vectors::run_oaep_known_answer(seed)
        }

        fn counting_rsaes(padding: &[u8]) -> Result<(), PaddedRsaSelfTestStage> {
            RSAES_CALLS.with(|calls| calls.set(calls.get() + 1));
            assert_eq!(padding.len(), 189, "the reference pads a 64 byte message");
            crate::library::tpm2::rsa_vectors::run_rsaes_known_answer(padding)
        }

        fn counting_raw() -> Result<(), RawRsaSelfTestStage> {
            RAW_CALLS.with(|calls| calls.set(calls.get() + 1));
            crate::library::tpm2::rsa_vectors::run_rsaep_known_answer()
        }

        fn counting_runtime() -> Tpm2Runtime {
            OAEP_CALLS.with(|calls| calls.set(0));
            RSAES_CALLS.with(|calls| calls.set(0));
            RAW_CALLS.with(|calls| calls.set(0));
            let mut runtime = restored("KEYS");
            runtime.self_test.set_oaep_runner(counting_oaep);
            runtime.self_test.set_rsaes_runner(counting_rsaes);
            runtime.self_test.set_raw_rsa_runner(counting_raw);
            runtime
        }

        fn calls() -> (usize, usize, usize) {
            (
                OAEP_CALLS.with(Cell::get),
                RSAES_CALLS.with(Cell::get),
                RAW_CALLS.with(Cell::get),
            )
        }

        #[test]
        fn first_operation_per_scheme_known_answer_test() {
            let mut runtime = counting_runtime();
            dispatch_bytes(
                &mut runtime,
                &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
            );
            assert_eq!(calls(), (1, 0, 0));
            assert!(!runtime.self_test.oaep_pending);
            assert!(
                !runtime.self_test.raw_rsa_pending,
                "TestRsaEncryptDecrypt also clears the RSAEP/RSADP bit"
            );
            assert!(runtime.self_test.rsaes_pending);

            dispatch_bytes(
                &mut runtime,
                &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA384), b""),
            );
            assert_eq!(calls(), (1, 0, 0), "a completed test is not repeated");

            dispatch_bytes(
                &mut runtime,
                &encrypt_command(KEY_NULL, &payload(32), &rsaes_scheme(), b""),
            );
            assert_eq!(calls(), (1, 1, 0));
            assert!(!runtime.self_test.rsaes_pending);

            dispatch_bytes(
                &mut runtime,
                &encrypt_command(KEY_NULL, &payload(32), &null_scheme(), b""),
            );
            assert_eq!(calls(), (1, 1, 0), "the raw bit was already cleared");
        }

        #[test]
        fn raw_operation_rsaep_known_answer_test_first() {
            let mut runtime = counting_runtime();
            dispatch_bytes(
                &mut runtime,
                &encrypt_command(KEY_NULL, &payload(32), &null_scheme(), b""),
            );
            assert_eq!(calls(), (0, 0, 1));
            assert!(!runtime.self_test.raw_rsa_pending);
            assert!(runtime.self_test.oaep_pending && runtime.self_test.rsaes_pending);

            dispatch_bytes(
                &mut runtime,
                &decrypt_command(KEY_NULL, &payload(256), &null_scheme(), b"", KEY_AUTH),
            );
            assert_eq!(calls(), (0, 0, 1), "a completed test is not repeated");
        }

        #[test]
        fn decryption_pending_known_answer_test() {
            let mut runtime = counting_runtime();
            dispatch_bytes(
                &mut runtime,
                &decrypt_command(
                    KEY_NULL,
                    &rsa_output_of("ENC_OAEP_SHA256"),
                    &oaep_scheme(TPM_ALG_SHA256),
                    b"",
                    KEY_AUTH,
                ),
            );
            assert_eq!(calls(), (1, 0, 0));
        }

        #[test]
        fn rejected_command_no_self_test() {
            for packet in [
                encrypt_command(
                    KEY_NULL,
                    &payload(32),
                    &oaep_scheme(TPM_ALG_SHA256),
                    b"label",
                ),
                encrypt_command(KEY_OAEP, &payload(32), &rsaes_scheme(), b""),
                encrypt_command(0x8100_0009, &payload(32), &rsaes_scheme(), b""),
                decrypt_command(KEY_NULL, &payload(255), &rsaes_scheme(), b"", KEY_AUTH),
                decrypt_command(KEY_NULL, &payload(256), &rsaes_scheme(), b"", b"nope"),
            ] {
                let mut runtime = counting_runtime();
                dispatch_bytes(&mut runtime, &packet);
                assert_eq!(calls(), (0, 0, 0));
                assert!(runtime.self_test.oaep_pending);
                assert!(runtime.self_test.rsaes_pending);
                assert!(runtime.self_test.raw_rsa_pending);
                assert!(!runtime.failure_mode);
            }
        }

        fn oaep_stage_table() -> [(
            fn(&[u8]) -> Result<(), PaddedRsaSelfTestStage>,
            FailureLocation,
        ); 5] {
            [
                (
                    |_| Err(PaddedRsaSelfTestStage::Encrypt),
                    FailureLocation::RsaOaepEncrypt,
                ),
                (
                    |_| Err(PaddedRsaSelfTestStage::RoundTripDecrypt),
                    FailureLocation::RsaOaepRoundTripDecrypt,
                ),
                (
                    |_| Err(PaddedRsaSelfTestStage::RoundTripCompare),
                    FailureLocation::RsaOaepRoundTripCompare,
                ),
                (
                    |_| Err(PaddedRsaSelfTestStage::KnownAnswerDecrypt),
                    FailureLocation::RsaOaepKnownAnswerDecrypt,
                ),
                (
                    |_| Err(PaddedRsaSelfTestStage::KnownAnswerCompare),
                    FailureLocation::RsaOaepKnownAnswerCompare,
                ),
            ]
        }

        #[test]
        fn injected_oaep_failure_vendored_site_tpm_stop() {
            for (runner, location) in oaep_stage_table() {
                let mut runtime = restored("KEYS");
                runtime.self_test.set_oaep_runner(runner);
                let response = dispatch_bytes(
                    &mut runtime,
                    &encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b""),
                );
                assert_eq!(response_code(&response), TPM_RC_FAILURE, "{location:?}");
                assert!(runtime.failure_mode);
                assert_eq!(runtime.failure_diagnostics, location.diagnostics());
                assert!(
                    runtime.self_test.oaep_pending,
                    "a failed test stays pending"
                );
            }
        }

        #[test]
        fn injected_rsaes_failure_shared_vendored_sites() {
            for (runner, location) in oaep_stage_table() {
                let mut runtime = restored("KEYS");
                runtime.self_test.set_rsaes_runner(runner);
                let response = dispatch_bytes(
                    &mut runtime,
                    &encrypt_command(KEY_NULL, &payload(32), &rsaes_scheme(), b""),
                );
                assert_eq!(response_code(&response), TPM_RC_FAILURE, "{location:?}");
                assert!(runtime.failure_mode);
                assert_eq!(runtime.failure_diagnostics, location.diagnostics());
                assert!(runtime.self_test.rsaes_pending);
            }
        }

        #[test]
        fn injected_raw_failure_own_vendored_site_stop() {
            for (runner, location) in [
                (
                    (|| Err(RawRsaSelfTestStage::Encrypt)) as fn() -> _,
                    FailureLocation::RsaRawEncrypt,
                ),
                (
                    || Err(RawRsaSelfTestStage::EncryptCompare),
                    FailureLocation::RsaRawEncryptCompare,
                ),
                (
                    || Err(RawRsaSelfTestStage::Decrypt),
                    FailureLocation::RsaRawDecrypt,
                ),
                (
                    || Err(RawRsaSelfTestStage::DecryptCompare),
                    FailureLocation::RsaRawDecryptCompare,
                ),
            ] {
                let mut runtime = restored("KEYS");
                runtime.self_test.set_raw_rsa_runner(runner);
                let response = dispatch_bytes(
                    &mut runtime,
                    &encrypt_command(KEY_NULL, &payload(32), &null_scheme(), b""),
                );
                assert_eq!(response_code(&response), TPM_RC_FAILURE, "{location:?}");
                assert!(runtime.failure_mode);
                assert_eq!(runtime.failure_diagnostics, location.diagnostics());
                assert!(runtime.self_test.raw_rsa_pending);
            }
        }

        #[test]
        fn latched_failure_mode_pre_handler_response() {
            let mut runtime = counting_runtime();
            runtime
                .self_test
                .set_oaep_runner(|_| Err(PaddedRsaSelfTestStage::Encrypt));
            let packet = encrypt_command(KEY_NULL, &payload(32), &oaep_scheme(TPM_ALG_SHA256), b"");
            let input = CommandInput::new(packet.len() as u32, packet.clone());
            let response = process(&mut runtime, &input).expect("the command processes");
            assert_eq!(response, error_response(TPM_RC_FAILURE));
            assert!(runtime.failure_mode);

            runtime
                .self_test
                .set_oaep_runner(|_| panic!("failure mode answers before the handler runs"));
            runtime
                .self_test
                .set_rsaes_runner(|_| panic!("failure mode answers before the handler runs"));
            let follow_up = encrypt_command(KEY_NULL, &payload(32), &rsaes_scheme(), b"");
            let input = CommandInput::new(follow_up.len() as u32, follow_up);
            let response = process(&mut runtime, &input).expect("the command processes");
            assert_eq!(response, error_response(TPM_RC_FAILURE));
        }
    }

    #[test]
    fn per_scheme_reference_ciphertext_decryption() {
        let mut runtime = restored("KEYS");
        check(
            &mut runtime,
            "DEC_RAW",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_RAW"),
                &null_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_RSAES",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_RSAES"),
                &rsaes_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
        for (record, source, hash_alg) in [
            ("DEC_OAEP_SHA1", "ENC_OAEP_SHA1", TPM_ALG_SHA1),
            ("DEC_OAEP_SHA256", "ENC_OAEP_SHA256", TPM_ALG_SHA256),
            ("DEC_OAEP_SHA384", "ENC_OAEP_SHA384", TPM_ALG_SHA384),
            ("DEC_OAEP_SHA512", "ENC_OAEP_SHA512", TPM_ALG_SHA512),
        ] {
            check(
                &mut runtime,
                record,
                &decrypt_command(
                    KEY_NULL,
                    &rsa_output_of(source),
                    &oaep_scheme(hash_alg),
                    b"",
                    KEY_AUTH,
                ),
            );
        }
        check(
            &mut runtime,
            "DEC_OAEP_LABEL",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_OAEP_LABEL"),
                &oaep_scheme(TPM_ALG_SHA256),
                b"label\0",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_OAEP_EMPTY_MESSAGE",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_OAEP_EMPTY_MESSAGE"),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_RSAES_MAX",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_RSAES_MAX"),
                &rsaes_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_OAEP_SHA512_MAX",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_OAEP_SHA512_MAX"),
                &oaep_scheme(TPM_ALG_SHA512),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_RAW_FULL_WIDTH",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_RAW_FULL_WIDTH"),
                &null_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
    }

    #[test]
    fn encryption_decryption_round_trip() {
        let mut runtime = restored("KEYS");
        let message = payload(32);
        let response = dispatch_bytes(
            &mut runtime,
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_OAEP_SHA256"),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
        assert_eq!(response_code(&response), RC_SUCCESS);
        let body = response_parameters(&response);
        assert_eq!(
            body,
            tpm2b(&message),
            "the round trip returns the plaintext"
        );
    }

    #[test]
    fn wrong_label_scheme_ciphertext_oracle_rejection() {
        let mut runtime = restored("KEYS");
        let oaep_ct = rsa_output_of("ENC_OAEP_SHA256");
        let rsaes_ct = rsa_output_of("ENC_RSAES");
        let raw_ct = rsa_output_of("ENC_RAW");
        let label_ct = rsa_output_of("ENC_OAEP_LABEL");
        for (record, ciphertext, scheme, label) in [
            (
                "DEC_OAEP_WRONG_LABEL",
                label_ct.clone(),
                oaep_scheme(TPM_ALG_SHA256),
                b"other\0".to_vec(),
            ),
            (
                "DEC_OAEP_MISSING_LABEL",
                label_ct.clone(),
                oaep_scheme(TPM_ALG_SHA256),
                Vec::new(),
            ),
            (
                "DEC_OAEP_WRONG_HASH",
                oaep_ct.clone(),
                oaep_scheme(TPM_ALG_SHA384),
                Vec::new(),
            ),
            (
                "DEC_OAEP_AS_RSAES",
                oaep_ct.clone(),
                rsaes_scheme(),
                Vec::new(),
            ),
            (
                "DEC_RSAES_AS_OAEP",
                rsaes_ct.clone(),
                oaep_scheme(TPM_ALG_SHA256),
                Vec::new(),
            ),
            (
                "DEC_RAW_AS_RSAES",
                raw_ct.clone(),
                rsaes_scheme(),
                Vec::new(),
            ),
            (
                "DEC_RAW_AS_OAEP",
                raw_ct.clone(),
                oaep_scheme(TPM_ALG_SHA256),
                Vec::new(),
            ),
        ] {
            check(
                &mut runtime,
                record,
                &decrypt_command(KEY_NULL, &ciphertext, &scheme, &label, KEY_AUTH),
            );
        }

        let mut corrupted_oaep = oaep_ct.clone();
        corrupted_oaep[200] ^= 0x01;
        check(
            &mut runtime,
            "DEC_CORRUPTED_OAEP",
            &decrypt_command(
                KEY_NULL,
                &corrupted_oaep,
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
        let mut corrupted_rsaes = rsaes_ct.clone();
        corrupted_rsaes[200] ^= 0x01;
        check(
            &mut runtime,
            "DEC_CORRUPTED_RSAES",
            &decrypt_command(KEY_NULL, &corrupted_rsaes, &rsaes_scheme(), b"", KEY_AUTH),
        );
        check(
            &mut runtime,
            "DEC_SHORT_CIPHERTEXT",
            &decrypt_command(
                KEY_NULL,
                &oaep_ct[..255],
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
        let mut long = oaep_ct.clone();
        long.push(0x00);
        check(
            &mut runtime,
            "DEC_LONG_CIPHERTEXT",
            &decrypt_command(KEY_NULL, &long, &oaep_scheme(TPM_ALG_SHA256), b"", KEY_AUTH),
        );
        check(
            &mut runtime,
            "DEC_CIPHERTEXT_OVER_MODULUS",
            &decrypt_command(
                KEY_NULL,
                &[0xff; 256],
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_CIPHERTEXT_OVER_TPM2B",
            &decrypt_command(
                KEY_NULL,
                &payload(385),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
    }

    #[test]
    fn key_default_scheme_decryption_oracle_parity() {
        let mut runtime = restored("KEYS");
        check(
            &mut runtime,
            "DEC_KEY_DEFAULT_OAEP",
            &decrypt_command(
                KEY_OAEP,
                &rsa_output_of("ENC_KEY_DEFAULT_OAEP"),
                &null_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_KEY_DEFAULT_RSAES",
            &decrypt_command(
                KEY_RSAES,
                &rsa_output_of("ENC_KEY_DEFAULT_RSAES"),
                &null_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_KEY_OAEP_RSAES",
            &decrypt_command(
                KEY_OAEP,
                &rsa_output_of("ENC_KEY_DEFAULT_OAEP"),
                &rsaes_scheme(),
                b"",
                KEY_AUTH,
            ),
        );
        check(
            &mut runtime,
            "DEC_KEY_RSAES_OAEP",
            &decrypt_command(
                KEY_RSAES,
                &rsa_output_of("ENC_KEY_DEFAULT_RSAES"),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );

        let mut runtime = restored("SIZES");
        check(
            &mut runtime,
            "DEC_3072_OAEP_SHA256",
            &decrypt_command(
                KEY_NULL,
                &rsa_output_of("ENC_3072_OAEP_SHA256"),
                &oaep_scheme(TPM_ALG_SHA256),
                b"",
                KEY_AUTH,
            ),
        );
    }
}
