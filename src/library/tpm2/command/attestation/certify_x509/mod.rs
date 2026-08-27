mod der;
mod x509;

use super::builder::QUALIFYING_DATA_MAX;
use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_RESERVED_BITS, TPM_RC_SCHEME,
    TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_H, TPM_RC_P,
};
use crate::library::tpm2::command::crypto::signing_state::{
    load_signing_state, publish_signing_outcome,
};
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::signature::{
    SigScheme, is_signing_object, marshal_signature, parse_sig_scheme, select_sign_scheme,
    sign_digest,
};
use crate::library::tpm2::template::{TemplateReader, digest_size};
use der::{
    DerReader, DerWriter, TAG_APPLICATION_SPECIFIC, TAG_CONSTRUCTED_SEQUENCE, TAG_OCTET_STRING,
};
use x509::{
    OID_KEY_USAGE_EXTENSION, OID_TCG_TPMA_OBJECT, add_public_key, add_signing_algorithm,
    public_key_is_encodable, signing_algorithm_is_encodable,
};

const TPM_RC_ASYMMETRIC: TpmResult = 0x081;

const RC_SIGN_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_OBJECT_HANDLE: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_RESERVED: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_PARTIAL_CERTIFICATE: TpmResult = TPM_RC_P + TPM_RC_3;

const X509_EXTENSIONS: u8 = 0xa3;

const ALLOWED_SEQUENCES: usize = 4;
const SIZE_OF_X509_SERIAL_NUMBER: usize = 20;
const MAX_DIGEST_BUFFER: usize = 1024;
const CERTIFICATE_VERSION: u32 = 2;

const KEY_USAGE_ALLOWED_BITS: u32 = 0xff80_0000;
const KEY_USAGE_NON_REPUDIATION: u32 = 1 << 30;
const KEY_USAGE_KEY_ENCIPHERMENT: u32 = 1 << 29;
const KEY_USAGE_SIGN: u32 = (1 << 25) | (1 << 26) | (1 << 31);
const KEY_USAGE_DECRYPT: u32 = (1 << 23) | (1 << 24) | (1 << 27) | (1 << 28) | (1 << 29);

const TPMA_OBJECT_FIXED_TPM: u32 = 1 << 1;
const TPMA_OBJECT_RESTRICTED: u32 = 1 << 16;
const TPMA_OBJECT_DECRYPT: u32 = 1 << 17;
const TPMA_OBJECT_SIGN: u32 = 1 << 18;

struct Parameters {
    reserved: Vec<u8>,
    scheme: SigScheme,
    partial_certificate: Vec<u8>,
}

struct PartialCertificate<'a> {
    signature: &'a [u8],
    issuer: &'a [u8],
    validity: &'a [u8],
    subject: &'a [u8],
    extensions: &'a [u8],
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let object_handle = handle_at(frame, 0)?;
    let sign_handle = handle_at(frame, 1)?;
    let parameters = parse_parameters(
        frame.parameters,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
    )?;

    if !parameters.reserved.is_empty() {
        return Err(TPM_RC_SIZE + RC_RESERVED);
    }
    let sign_object = key_object(runtime, sign_handle).ok_or(TPM_RC_KEY + RC_SIGN_HANDLE)?;
    if !is_signing_object(&sign_object) {
        return Err(TPM_RC_KEY + RC_SIGN_HANDLE);
    }
    let scheme = select_sign_scheme(Some(&sign_object), parameters.scheme)
        .ok_or(TPM_RC_SCHEME + RC_IN_SCHEME)?;
    let object = key_object(runtime, object_handle)
        .filter(|object| public_key_is_encodable(&object.public))
        .ok_or(TPM_RC_ASYMMETRIC + RC_OBJECT_HANDLE)?;

    let partial = parse_partial_certificate(&parameters.partial_certificate)?;
    if partial.signature.is_empty() && !signing_algorithm_is_encodable(&sign_object.public, &scheme)
    {
        return Err(TPM_RC_SCHEME + RC_SIGN_HANDLE);
    }
    process_extensions(&object, partial.extensions).map_err(|code| {
        code + if code == TPM_RC_ATTRIBUTES {
            RC_OBJECT_HANDLE
        } else {
            RC_PARTIAL_CERTIFICATE
        }
    })?;

    self_test_algorithm(runtime, sign_object.public.name_alg)?;
    self_test_algorithm(runtime, scheme.hash_alg)?;
    let built = build_certificate(&object, &sign_object, &scheme, &partial)?;

    let mut signing = load_signing_state(runtime)?;
    let signature = sign_digest(
        Some(&sign_object),
        &scheme,
        &built.tbs_digest,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
        &mut signing,
    );
    let signature = publish_signing_outcome(runtime, signing, signature)?;

    let mut out = BlobWriter::new();
    out.write_tpm2b(&built.added_to_certificate)
        .map_err(|_| TPM_RC_SIZE)?;
    out.write_tpm2b(&built.tbs_digest)
        .map_err(|_| TPM_RC_SIZE)?;
    out.write_bytes(&marshal_signature(&signature));
    Ok(CommandOutput::from_parameters(out.into_bytes()))
}

fn key_object(runtime: &Tpm2Runtime, handle: u32) -> Option<Box<OwnedObjectBody>> {
    match &resolve_any_object(runtime, handle)?.body {
        OwnedAnyObjectBody::Object(body) => Some(body.clone()),
        _ => None,
    }
}

fn parse_parameters(
    parameters: &[u8],
    profile: &ValidatedProfile,
) -> Result<Parameters, TpmResult> {
    let mut reader = TemplateReader::new(parameters);
    let reserved = reader
        .tpm2b(QUALIFYING_DATA_MAX)
        .map_err(|code| code + RC_RESERVED)?
        .to_vec();
    let scheme = parse_sig_scheme(&mut reader, profile).map_err(|code| code + RC_IN_SCHEME)?;
    let partial_certificate = reader
        .tpm2b(MAX_DIGEST_BUFFER)
        .map_err(|code| code + RC_PARTIAL_CERTIFICATE)?
        .to_vec();
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(Parameters {
        reserved,
        scheme,
        partial_certificate,
    })
}

fn parse_partial_certificate(bytes: &[u8]) -> Result<PartialCertificate<'_>, TpmResult> {
    let Some(mut reader) = DerReader::new(bytes) else {
        return Err(TPM_RC_VALUE + RC_PARTIAL_CERTIFICATE);
    };
    let length = reader.next_tag();
    let consumed = if length < 0 {
        -1
    } else {
        reader.offset().saturating_add(length)
    };
    if reader.tag() != TAG_CONSTRUCTED_SEQUENCE || consumed != bytes.len() as i32 {
        return Err(TPM_RC_SIZE + RC_PARTIAL_CERTIFICATE);
    }

    let mut sequences: Vec<(i32, i32)> = Vec::with_capacity(ALLOWED_SEQUENCES);
    let mut count = 0usize;
    let mut extensions: Option<(i32, i32)> = None;
    while !reader.at_end() {
        let start = reader.offset();
        let length = reader.next_tag();
        if length < 0 {
            break;
        }
        if reader.tag() == TAG_CONSTRUCTED_SEQUENCE {
            reader.skip(length);
            if sequences.len() < ALLOWED_SEQUENCES {
                sequences.push((start, reader.offset() - start));
            }
            count += 1;
            if count > ALLOWED_SEQUENCES {
                break;
            }
        } else if reader.tag() == X509_EXTENSIONS {
            if extensions.is_some() {
                return Err(TPM_RC_VALUE + RC_PARTIAL_CERTIFICATE);
            }
            reader.skip(length);
            extensions = Some((start, reader.offset() - start));
        } else {
            return Err(TPM_RC_VALUE + RC_PARTIAL_CERTIFICATE);
        }
    }
    if !reader.exhausted() || !(3..=ALLOWED_SEQUENCES).contains(&count) {
        return Err(TPM_RC_VALUE + RC_PARTIAL_CERTIFICATE);
    }
    let Some(extensions) = extensions else {
        return Err(TPM_RC_VALUE + RC_PARTIAL_CERTIFICATE);
    };

    let missing = TPM_RC_VALUE + RC_PARTIAL_CERTIFICATE;
    let at = |index: usize| -> Result<&[u8], TpmResult> {
        let span = *sequences.get(index).ok_or(missing)?;
        reader.slice_from(span.0, span.1).ok_or(missing)
    };
    Ok(PartialCertificate {
        signature: if count == ALLOWED_SEQUENCES {
            at(0)?
        } else {
            &[]
        },
        issuer: at(count - 3)?,
        validity: at(count - 2)?,
        subject: at(count - 1)?,
        extensions: reader
            .slice_from(extensions.0, extensions.1)
            .ok_or(missing)?,
    })
}

fn process_extensions(object: &OwnedObjectBody, extension: &[u8]) -> Result<(), TpmResult> {
    let Some(mut reader) = DerReader::new(extension) else {
        return Err(TPM_RC_VALUE);
    };
    if reader.next_tag() < 0 || reader.tag() != X509_EXTENSIONS {
        return Err(TPM_RC_VALUE);
    }
    if reader.next_tag() < 0 || reader.tag() != TAG_CONSTRUCTED_SEQUENCE {
        return Err(TPM_RC_VALUE);
    }

    let attributes = object.public.object_attributes;
    match find_extension_bits(&mut reader, &OID_TCG_TPMA_OBJECT) {
        Ok(Some(value)) if value != attributes => return Err(TPM_RC_ATTRIBUTES),
        Ok(_) => {}
        Err(()) => return Err(TPM_RC_VALUE),
    }

    let Ok(Some(key_usage)) = find_extension_bits(&mut reader, &OID_KEY_USAGE_EXTENSION) else {
        return Err(TPM_RC_VALUE);
    };
    if key_usage & !KEY_USAGE_ALLOWED_BITS != 0 {
        return Err(TPM_RC_RESERVED_BITS);
    }
    let bad_sign = KEY_USAGE_SIGN & key_usage != 0 && attributes & TPMA_OBJECT_SIGN == 0;
    let bad_decrypt = KEY_USAGE_DECRYPT & key_usage != 0 && attributes & TPMA_OBJECT_DECRYPT == 0;
    let bad_fixed_tpm =
        key_usage & KEY_USAGE_NON_REPUDIATION != 0 && attributes & TPMA_OBJECT_FIXED_TPM == 0;
    let bad_restricted =
        key_usage & KEY_USAGE_KEY_ENCIPHERMENT != 0 && attributes & TPMA_OBJECT_RESTRICTED == 0;
    if bad_sign || bad_decrypt || bad_fixed_tpm || bad_restricted {
        return Err(TPM_RC_VALUE);
    }
    Ok(())
}

fn find_extension_bits(reader: &mut DerReader<'_>, oid: &[u8]) -> Result<Option<u32>, ()> {
    let Some(mut found) = find_extension_by_oid(reader, oid)? else {
        return Ok(None);
    };
    extension_bits(&mut found).map(Some).ok_or(())
}

fn find_extension_by_oid<'a>(
    source: &mut DerReader<'a>,
    oid: &[u8],
) -> Result<Option<DerReader<'a>>, ()> {
    let mut reader = source.duplicate();
    while reader.size() > reader.offset() {
        let length = reader.next_tag();
        if length < 0 || reader.tag() != TAG_CONSTRUCTED_SEQUENCE {
            source.poison();
            return Err(());
        }
        if length >= oid.len() as i32 && reader.matches_at_offset(oid) && reader.narrow_to(length) {
            return Ok(Some(reader));
        }
        reader.skip(length);
    }
    if !reader.exhausted() {
        source.poison();
        return Err(());
    }
    Ok(None)
}

fn extension_bits(reader: &mut DerReader<'_>) -> Option<u32> {
    loop {
        let length = reader.next_tag();
        if length <= 0 || reader.size() <= reader.offset() {
            reader.poison();
            return None;
        }
        if reader.tag() == TAG_OCTET_STRING {
            return reader.bit_string_value();
        }
        reader.skip(length);
    }
}

struct BuiltCertificate {
    added_to_certificate: Vec<u8>,
    tbs_digest: Vec<u8>,
}

fn build_certificate(
    object: &OwnedObjectBody,
    sign_object: &OwnedObjectBody,
    scheme: &SigScheme,
    partial: &PartialCertificate<'_>,
) -> Result<BuiltCertificate, TpmResult> {
    let mut writer = DerWriter::new(MAX_DIGEST_BUFFER);
    writer.start();

    let public_key_length = add_public_key(&mut writer, &object.public);
    let public_key = writer.taken(public_key_length);

    let signature_algorithm = if partial.signature.is_empty() {
        let length = add_signing_algorithm(&mut writer, &sign_object.public, scheme);
        writer.taken(length)
    } else {
        partial.signature.to_vec()
    };

    let serial = serial_number(
        object,
        sign_object,
        partial,
        &signature_algorithm,
        &public_key,
    )?;
    let serial_length = writer.push_integer(&serial);
    let serial_number = writer.taken(serial_length);

    writer.start();
    writer.push_uint(CERTIFICATE_VERSION);
    let version_length = writer.end_encapsulation(TAG_APPLICATION_SPECIFIC);
    let version = writer.taken(version_length);

    let body_length: i32 = [
        version_length,
        serial_length,
        signature_algorithm.len() as i32,
        partial.issuer.len() as i32,
        partial.validity.len() as i32,
        partial.subject.len() as i32,
        public_key_length,
        partial.extensions.len() as i32,
    ]
    .into_iter()
    .sum();
    let header_length = writer.push_tag_and_length(TAG_CONSTRUCTED_SEQUENCE, body_length);
    let header = writer.taken(header_length);
    writer.release(header_length);

    if writer.failed() {
        return Err(TPM_RC_FAILURE);
    }

    let mut hasher = Hasher::new(scheme.hash_alg).ok_or(TPM_RC_FAILURE)?;
    for element in [
        header.as_slice(),
        version.as_slice(),
        serial_number.as_slice(),
        signature_algorithm.as_slice(),
        partial.issuer,
        partial.validity,
        partial.subject,
        public_key.as_slice(),
        partial.extensions,
    ] {
        hasher.update(element);
    }
    let tbs_digest = hasher.finalize();

    let added_length = writer.end_encapsulation(TAG_CONSTRUCTED_SEQUENCE);
    let added_to_certificate = writer.taken(added_length);
    if writer.failed() {
        return Err(TPM_RC_FAILURE);
    }
    Ok(BuiltCertificate {
        added_to_certificate,
        tbs_digest,
    })
}

fn serial_number(
    object: &OwnedObjectBody,
    sign_object: &OwnedObjectBody,
    partial: &PartialCertificate<'_>,
    signature_algorithm: &[u8],
    public_key: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let name_alg = sign_object.public.name_alg;
    let size = digest_size(name_alg)
        .filter(|size| *size != 0)
        .ok_or(TPM_RC_FAILURE)?
        .min(SIZE_OF_X509_SERIAL_NUMBER);
    let mut hasher = Hasher::new(name_alg).ok_or(TPM_RC_FAILURE)?;
    for element in [
        signature_algorithm,
        partial.issuer,
        partial.validity,
        partial.subject,
        public_key,
        partial.extensions,
    ] {
        hasher.update(element);
    }
    hasher.update(&sign_object.name);
    hasher.update(&object.name);
    let digest = hasher.finalize();
    Ok(digest.get(..size).ok_or(TPM_RC_FAILURE)?.to_vec())
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::command::attestation::builder::test_support::{
        ALG_ECDSA, ALG_HMAC, ALG_NULL, ALG_RSAPSS, ALG_RSASSA, ALG_SHA1, ALG_SHA256, ALG_SHA384,
        CC_START_AUTH_SESSION, DECRYPT_ATTRS, KEY0, KEY1, QUALIFY, SIGN_ATTRS, TPM_RH_ENDORSEMENT,
        TPM_RH_NULL, TPM_RH_OWNER, command, create_primary, ecc_template, keyedhash_template,
        parameters_of, pw, replay_clock, rsa_template, run, run_ok, sig_scheme, tpm2b,
    };
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, TPM_CC_CERTIFY_X509, find,
    };
    use crate::library::tpm2::command::core::test_support::{RC_SUCCESS, response_code};
    use crate::library::tpm2::golden_responses::certify_x509::{vector, vectors};
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::self_test::PrimitiveTest;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};
    use core::cell::{Cell, RefCell};

    const RC_HANDLE1_VALUE: u32 = 0x184;
    const RC_HANDLE1_KEY: u32 = 0x19c;
    const RC_HANDLE1_SCHEME: u32 = 0x192;
    const RC_HANDLE2_VALUE: u32 = 0x284;
    const RC_HANDLE2_ASYMMETRIC: u32 = 0x281;
    const RC_HANDLE2_ATTRIBUTES: u32 = 0x282;
    const RC_PARAM1_SIZE: u32 = 0x1d5;
    const RC_PARAM2_SCHEME: u32 = 0x2d2;
    const RC_PARAM3_VALUE: u32 = 0x3c4;
    const RC_PARAM3_SIZE: u32 = 0x3d5;
    const RC_PARAM3_RESERVED_BITS: u32 = 0x3e1;
    const RC_AUTH_MISSING: u32 = 0x125;
    const RC_SIZE: u32 = 0x095;

    const KEY_USAGE_DIGITAL_SIGNATURE: [u8; 4] = [0x03, 0x02, 0x07, 0x80];
    const KEY_USAGE_NON_REPUDIATION: [u8; 4] = [0x03, 0x02, 0x06, 0x40];
    const KEY_USAGE_DATA_ENCIPHERMENT: [u8; 4] = [0x03, 0x02, 0x04, 0x10];
    const KEY_USAGE_KEY_ENCIPHERMENT: [u8; 4] = [0x03, 0x02, 0x05, 0x20];
    const KEY_USAGE_RESERVED: [u8; 5] = [0x03, 0x03, 0x00, 0xff, 0xff];

    const RSA_ALGID: [u8; 15] = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];
    const ECDSA_ALGID: [u8; 12] = [
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];

    const STORAGE_ATTRS: u32 = 0x0003_0072;

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            length if length <= 127 => out.push(length as u8),
            length if length <= 255 => out.extend_from_slice(&[0x81, length as u8]),
            length => out.extend_from_slice(&[0x82, (length >> 8) as u8, length as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    fn x509_name(common: &str) -> Vec<u8> {
        let mut attribute = vec![0x06, 0x03, 0x55, 0x04, 0x03];
        attribute.extend_from_slice(&der(0x0c, common.as_bytes()));
        der(0x30, &der(0x31, &der(0x30, &attribute)))
    }

    fn x509_validity() -> Vec<u8> {
        let mut content = der(0x17, b"200101000000Z");
        content.extend_from_slice(&der(0x17, b"300101000000Z"));
        der(0x30, &content)
    }

    fn key_usage_extension(bits: &[u8]) -> Vec<u8> {
        let mut content = vec![0x06, 0x03, 0x55, 0x1d, 0x0f];
        content.extend_from_slice(&der(0x04, bits));
        der(0x30, &content)
    }

    fn tpma_object_extension(attributes: u32) -> Vec<u8> {
        let mut value = vec![0x00];
        value.extend_from_slice(&attributes.to_be_bytes());
        let mut content = vec![0x06, 0x07, 0x67, 0x81, 0x05, 0x0a, 0x01, 0x01, 0x01];
        content.extend_from_slice(&der(0x04, &der(0x03, &value)));
        der(0x30, &content)
    }

    fn extensions(items: &[Vec<u8>]) -> Vec<u8> {
        der(0xa3, &der(0x30, &items.concat()))
    }

    fn default_extensions() -> Vec<u8> {
        extensions(&[
            tpma_object_extension(SIGN_ATTRS),
            key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
        ])
    }

    fn partial_certificate(elements: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &elements.concat())
    }

    fn default_body() -> Vec<u8> {
        partial_certificate(&[
            x509_name("Issuer"),
            x509_validity(),
            x509_name("Subject"),
            default_extensions(),
        ])
    }

    fn body_with(extension: Vec<u8>) -> Vec<u8> {
        partial_certificate(&[
            x509_name("Issuer"),
            x509_validity(),
            x509_name("Subject"),
            extension,
        ])
    }

    fn certify_parameters(reserved: &[u8], scheme: &[u8], partial: &[u8]) -> Vec<u8> {
        let mut out = tpm2b(reserved);
        out.extend_from_slice(scheme);
        out.extend_from_slice(&tpm2b(partial));
        out
    }

    fn certify_command(object: u32, sign: u32, partial: &[u8]) -> Vec<u8> {
        certify_command_with(object, sign, partial, &sig_scheme(ALG_NULL, 0), &[])
    }

    fn certify_command_with(
        object: u32,
        sign: u32,
        partial: &[u8],
        scheme: &[u8],
        reserved: &[u8],
    ) -> Vec<u8> {
        command(
            TPM_CC_CERTIFY_X509,
            &[object, sign],
            Some(&[pw(), pw()]),
            &certify_parameters(reserved, scheme, partial),
        )
    }

    fn rsa_template_named(
        scheme: u16,
        hash_alg: u16,
        attributes: u32,
        name_alg: u16,
        symmetric: &[u8],
    ) -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&name_alg.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(symmetric);
        out.extend_from_slice(&sig_scheme(scheme, hash_alg));
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    fn storage_template() -> Vec<u8> {
        rsa_template_named(
            ALG_NULL,
            0,
            STORAGE_ATTRS,
            ALG_SHA256,
            &[0x00, 0x06, 0x00, 0x80, 0x00, 0x43],
        )
    }

    fn symcipher_template() -> Vec<u8> {
        let mut out = 0x0025u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&STORAGE_ATTRS.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    #[track_caller]
    fn ready() -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_READY"))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector("VOLATILE_READY"))
            .expect("the oracle volatile state attaches");
        runtime
    }

    #[track_caller]
    fn with_keys(templates: &[(u32, Vec<u8>)]) -> Box<Tpm2Runtime> {
        let mut runtime = ready();
        for (hierarchy, template) in templates {
            run_ok(
                &mut runtime,
                &create_primary(*hierarchy, template),
                "the key is created",
            );
        }
        runtime
    }

    fn signer_pair() -> Vec<(u32, Vec<u8>)> {
        vec![
            (
                TPM_RH_ENDORSEMENT,
                rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]
    }

    #[track_caller]
    fn two_signers() -> Box<Tpm2Runtime> {
        let mut runtime = ready();
        assert_eq!(
            run(
                &mut runtime,
                &create_primary(
                    TPM_RH_ENDORSEMENT,
                    &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS)
                )
            ),
            vector("CREATE_RSA_SIGNER"),
            "the endorsement signer matches the oracle"
        );
        assert_eq!(
            run(
                &mut runtime,
                &create_primary(TPM_RH_OWNER, &ecc_template(ALG_ECDSA, ALG_SHA256))
            ),
            vector("CREATE_ECC_SIGNER"),
            "the owner signer matches the oracle"
        );
        runtime
    }

    #[track_caller]
    fn assert_exact(record: &str, templates: &[(u32, Vec<u8>)], command_bytes: &[u8]) {
        let mut runtime = with_keys(templates);
        assert_eq!(run(&mut runtime, command_bytes), vector(record), "{record}");
    }

    fn added_to_certificate(response: &[u8]) -> Vec<u8> {
        let parameters = parameters_of(response);
        let size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        parameters[2..2 + size].to_vec()
    }

    fn tbs_digest(response: &[u8]) -> Vec<u8> {
        let parameters = parameters_of(response);
        let added = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let at = 2 + added;
        let size = u16::from_be_bytes([parameters[at], parameters[at + 1]]) as usize;
        parameters[at + 2..at + 2 + size].to_vec()
    }

    fn certify_signature(response: &[u8]) -> Vec<u8> {
        let parameters = parameters_of(response);
        let added = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        let at = 2 + added;
        let digest = u16::from_be_bytes([parameters[at], parameters[at + 1]]) as usize;
        parameters[at + 2 + digest..].to_vec()
    }

    // Splits `addedToCertificate` into the elements the TPM generated: the
    // version, the serial number, an optional signing AlgorithmIdentifier, and
    // the SubjectPublicKeyInfo.
    fn added_elements(added: &[u8]) -> Vec<Vec<u8>> {
        let mut body = &added[header_length(added)..];
        let mut elements = Vec::new();
        while !body.is_empty() {
            let length = header_length(body) + content_length(body);
            elements.push(body[..length].to_vec());
            body = &body[length..];
        }
        elements
    }

    fn content_length(bytes: &[u8]) -> usize {
        match bytes[1] {
            length if length < 0x80 => usize::from(length),
            0x81 => usize::from(bytes[2]),
            0x82 => usize::from(bytes[2]) << 8 | usize::from(bytes[3]),
            _ => panic!("an unsupported length form"),
        }
    }

    fn header_length(bytes: &[u8]) -> usize {
        match bytes[1] {
            length if length < 0x80 => 2,
            0x81 => 3,
            0x82 => 4,
            _ => panic!("an unsupported length form"),
        }
    }

    // Rebuilds the TBSCertificate the TPM hashed: the caller's issuer, validity,
    // subject, and extensions interleaved with the elements the TPM added.
    fn rebuilt_tbs_certificate(response: &[u8], caller: &[Vec<u8>]) -> Vec<u8> {
        let added = added_to_certificate(response);
        let generated = added_elements(&added);
        let (version, rest) = generated.split_first().expect("a version element");
        let (serial, rest) = rest.split_first().expect("a serial number element");
        let (signature_algorithm, subject_public_key) = if rest.len() == 2 {
            (rest[0].clone(), rest[1].clone())
        } else {
            (caller[0].clone(), rest[0].clone())
        };
        let caller_names = if caller.len() == 5 {
            &caller[1..]
        } else {
            caller
        };
        let mut body = version.clone();
        body.extend_from_slice(serial);
        body.extend_from_slice(&signature_algorithm);
        body.extend_from_slice(&caller_names[0]);
        body.extend_from_slice(&caller_names[1]);
        body.extend_from_slice(&caller_names[2]);
        body.extend_from_slice(&subject_public_key);
        body.extend_from_slice(&caller_names[3]);
        der(0x30, &body)
    }

    #[track_caller]
    fn assert_reconstruction(response: &[u8], caller: &[Vec<u8>], hash_alg: u16) {
        use crate::library::tpm2::crypto::Hasher;
        let tbs = rebuilt_tbs_certificate(response, caller);
        let added = added_to_certificate(response);
        for element in added_elements(&added) {
            assert!(
                tbs.windows(element.len()).any(|window| window == element),
                "the reconstruction contains every added element"
            );
        }
        let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
        hasher.update(&tbs);
        assert_eq!(
            hasher.finalize(),
            tbs_digest(response),
            "tbsDigest covers the reconstructed TBSCertificate"
        );
    }

    #[test]
    fn the_command_attributes_match_the_oracle() {
        let expected = vector("CCATTR_0197");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().expect("four bytes"));
        assert_eq!(TPM_CC_CERTIFY_X509, 0x0000_0197);
        let descriptor = find(TPM_CC_CERTIFY_X509).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x0400_0197);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(!descriptor.physical_presence);
        assert!(!descriptor.physical_presence_required);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles[0].user_auth && descriptor.handles[0].admin_role());
        assert!(descriptor.handles[1].user_auth && !descriptor.handles[1].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
        assert!(matches!(descriptor.handles[1].kind, HandleKind::Object));
        assert!(!descriptor.handles[0].kind.accepts(TPM_RH_NULL));
        assert!(
            !descriptor.handles[1].kind.accepts(TPM_RH_NULL),
            "unlike TPM2_Certify, the signing handle may not be TPM_RH_NULL"
        );
    }

    #[test]
    fn the_neighbouring_command_codes_answer_the_oracle_capabilities() {
        for (record, expected) in [
            ("CCATTR_0196", 0x0400_0197u32),
            ("CCATTR_0197", 0x0400_0197),
            ("CCATTR_0198", 0x0200_0199),
        ] {
            let bytes = vector(record);
            assert_eq!(
                u32::from_be_bytes(bytes[19..23].try_into().expect("four bytes")),
                expected,
                "{record}"
            );
        }
    }

    #[test]
    fn the_signing_keys_match_the_oracle() {
        let _ = two_signers();
    }

    #[test]
    fn an_rsa_signer_certifies_an_ecc_object_like_the_oracle() {
        assert_exact(
            "X509_RSA_SIGNS_ECC",
            &signer_pair(),
            &certify_command(KEY1, KEY0, &default_body()),
        );
    }

    #[test]
    fn an_rsa_signer_certifies_itself_like_the_oracle() {
        assert_exact(
            "X509_RSA_SIGNS_RSA",
            &signer_pair(),
            &certify_command(KEY0, KEY0, &default_body()),
        );
    }

    #[test]
    fn a_caller_supplied_algorithm_identifier_is_used_verbatim() {
        for (record, algid) in [
            ("X509_CALLER_ALGID", &RSA_ALGID[..]),
            ("X509_CALLER_ALGID_UNRELATED", &ECDSA_ALGID[..]),
        ] {
            let partial = partial_certificate(&[
                algid.to_vec(),
                x509_name("Issuer"),
                x509_validity(),
                x509_name("Subject"),
                default_extensions(),
            ]);
            assert_exact(
                record,
                &signer_pair(),
                &certify_command(KEY1, KEY0, &partial),
            );
            let added = added_to_certificate(vector(record));
            assert_eq!(
                added_elements(&added).len(),
                3,
                "{record} adds no signing algorithm of its own"
            );
        }
    }

    #[test]
    fn an_explicit_scheme_that_matches_the_key_is_accepted() {
        assert_exact(
            "X509_EXPLICIT_SCHEME",
            &signer_pair(),
            &certify_command_with(
                KEY1,
                KEY0,
                &default_body(),
                &sig_scheme(ALG_RSASSA, ALG_SHA256),
                &[],
            ),
        );
    }

    #[test]
    fn the_object_attribute_extension_is_optional() {
        assert_exact(
            "X509_ONLY_KEY_USAGE",
            &signer_pair(),
            &certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[key_usage_extension(
                    &KEY_USAGE_DIGITAL_SIGNATURE,
                )])),
            ),
        );
    }

    #[test]
    fn non_repudiation_is_accepted_when_the_object_is_fixed_to_the_tpm() {
        assert_exact(
            "X509_NONREPUDIATION",
            &signer_pair(),
            &certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    tpma_object_extension(SIGN_ATTRS),
                    key_usage_extension(&KEY_USAGE_NON_REPUDIATION),
                ])),
            ),
        );
    }

    #[test]
    fn long_form_der_lengths_round_trip() {
        let partial = partial_certificate(&[
            x509_name(&"I".repeat(90)),
            x509_validity(),
            x509_name(&"S".repeat(90)),
            default_extensions(),
        ]);
        assert!(partial[1] >= 0x81, "the caller used a long-form length");
        assert_exact(
            "X509_LONG_NAMES",
            &signer_pair(),
            &certify_command(KEY1, KEY0, &partial),
        );
    }

    #[test]
    fn a_sha384_signer_truncates_the_serial_number() {
        let templates = vec![
            (
                TPM_RH_OWNER,
                rsa_template_named(
                    ALG_RSASSA,
                    ALG_SHA384,
                    SIGN_ATTRS,
                    ALG_SHA384,
                    &[0x00, 0x10],
                ),
            ),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ];
        assert_exact(
            "X509_SHA384_SIGNER",
            &templates,
            &certify_command(KEY1, KEY0, &default_body()),
        );
        let added = added_to_certificate(vector("X509_SHA384_SIGNER"));
        let serial = &added_elements(&added)[1];
        assert!(
            content_length(serial) <= 21,
            "the serial number is truncated to twenty octets, plus a sign octet"
        );
    }

    #[test]
    fn a_certified_storage_key_may_carry_key_encipherment() {
        assert_exact(
            "X509_STORAGE_OBJECT",
            &[
                (
                    TPM_RH_ENDORSEMENT,
                    rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
                ),
                (TPM_RH_OWNER, storage_template()),
            ],
            &certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    tpma_object_extension(STORAGE_ATTRS),
                    key_usage_extension(&KEY_USAGE_KEY_ENCIPHERMENT),
                ])),
            ),
        );
    }

    #[test]
    fn a_certified_decryption_key_may_carry_data_encipherment() {
        assert_exact(
            "X509_DECRYPT_OBJECT",
            &[
                (
                    TPM_RH_ENDORSEMENT,
                    rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
                ),
                (TPM_RH_OWNER, rsa_template(ALG_NULL, 0, DECRYPT_ATTRS)),
            ],
            &certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    tpma_object_extension(DECRYPT_ATTRS),
                    key_usage_extension(&KEY_USAGE_DATA_ENCIPHERMENT),
                ])),
            ),
        );
    }

    #[test]
    fn a_keyed_hash_signer_answers_an_hmac_signature() {
        assert_exact(
            "X509_HMAC_SIGNER_ALGID",
            &[
                (TPM_RH_OWNER, keyedhash_template(ALG_HMAC, ALG_SHA256)),
                (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
            ],
            &certify_command(
                KEY1,
                KEY0,
                &partial_certificate(&[
                    RSA_ALGID.to_vec(),
                    x509_name("Issuer"),
                    x509_validity(),
                    x509_name("Subject"),
                    default_extensions(),
                ]),
            ),
        );
        let signature = certify_signature(vector("X509_HMAC_SIGNER_ALGID"));
        assert_eq!(&signature[..4], &[0x00, 0x05, 0x00, 0x0b]);
    }

    #[test]
    fn the_reconstructed_certificate_hashes_to_the_returned_digest() {
        let caller = vec![
            x509_name("Issuer"),
            x509_validity(),
            x509_name("Subject"),
            default_extensions(),
        ];
        for record in [
            "X509_RSA_SIGNS_ECC",
            "X509_RSA_SIGNS_RSA",
            "X509_ECC_SIGNS_RSA",
            "X509_ECC_SIGNS_ECC",
            "X509_ONLY_KEY_USAGE",
            "X509_SHA384_SIGNER",
        ] {
            let response = vector(record);
            let extension = if record == "X509_ONLY_KEY_USAGE" {
                extensions(&[key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE)])
            } else {
                default_extensions()
            };
            let mut caller = caller.clone();
            caller[3] = extension;
            let hash_alg = if record == "X509_SHA384_SIGNER" {
                ALG_SHA384
            } else {
                ALG_SHA256
            };
            assert_reconstruction(response, &caller, hash_alg);
        }
    }

    #[test]
    fn an_ecc_signer_certifies_like_the_oracle() {
        for (record, object, sign) in [
            ("X509_ECC_SIGNS_RSA", KEY0, KEY1),
            ("X509_ECC_SIGNS_ECC", KEY1, KEY1),
        ] {
            let mut runtime = with_keys(&signer_pair());
            let expected = vector(record);
            let response = run(
                &mut runtime,
                &certify_command(object, sign, &default_body()),
            );
            assert_eq!(response_code(&response), RC_SUCCESS, "{record}");
            assert_eq!(
                added_to_certificate(&response),
                added_to_certificate(expected),
                "{record} adds the reference bytes"
            );
            assert_eq!(
                tbs_digest(&response),
                tbs_digest(expected),
                "{record} digests the reference certificate"
            );
            let signature = certify_signature(&response);
            assert_eq!(&signature[..4], &[0x00, 0x18, 0x00, 0x0b], "{record}");
            assert_ecdsa_verifies(&runtime, sign, &response);
        }
    }

    #[track_caller]
    fn assert_ecdsa_verifies(runtime: &Tpm2Runtime, handle: u32, response: &[u8]) {
        use crate::library::tpm2::crypto::{BigUint, curve_parameters};
        use crate::library::tpm2::object_create::resolve_any_object;
        use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPublicId};

        let signature = certify_signature(response);
        let r_size = u16::from_be_bytes([signature[4], signature[5]]) as usize;
        let r = BigUint::from_be_bytes(&signature[6..6 + r_size]);
        let s_at = 6 + r_size;
        let s_size = u16::from_be_bytes([signature[s_at], signature[s_at + 1]]) as usize;
        let s = BigUint::from_be_bytes(&signature[s_at + 2..s_at + 2 + s_size]);

        let object = resolve_any_object(runtime, handle).expect("the signer is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("the handle names a key");
        };
        let OwnedPublicId::Ecc { x, y } = &body.public.unique else {
            panic!("an ECC key");
        };
        let curve = curve_parameters(0x0003).expect("a compiled curve");
        let order = &curve.order;

        let digest = BigUint::from_be_bytes(&tbs_digest(response))
            .rem(order)
            .expect("a reduced digest");
        let s_inverse = s.mod_inverse(order).expect("s is invertible");
        let u1 = digest.mod_mul(&s_inverse, order).expect("u1");
        let u2 = r.mod_mul(&s_inverse, order).expect("u2");
        let (x_coordinate, _) = curve
            .multiply_sum(
                &u1,
                (&BigUint::from_be_bytes(x), &BigUint::from_be_bytes(y)),
                &u2,
            )
            .expect("the verification point");
        assert_eq!(
            x_coordinate.rem(order).expect("a reduced x"),
            r.rem(order).expect("a reduced r"),
            "the ECDSA signature verifies against the public key"
        );
    }

    #[test]
    fn the_rsassa_signature_verifies_against_the_signing_key() {
        use crate::library::tpm2::crypto::{BigUint, Hasher};
        use crate::library::tpm2::object_create::resolve_any_object;
        use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedPublicId};

        let mut runtime = with_keys(&signer_pair());
        let response = run(&mut runtime, &certify_command(KEY1, KEY0, &default_body()));
        assert_eq!(response, vector("X509_RSA_SIGNS_ECC"));
        let signature = certify_signature(&response);
        assert_eq!(&signature[..4], &[0x00, 0x14, 0x00, 0x0b]);
        let blob = &signature[6..];

        let object = resolve_any_object(&runtime, KEY0).expect("the signer is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("the handle names a key");
        };
        let OwnedPublicId::Rsa(modulus) = &body.public.unique else {
            panic!("an RSA key");
        };
        let recovered = BigUint::from_be_bytes(blob)
            .mod_exp(&BigUint::from_u64(65537), &BigUint::from_be_bytes(modulus))
            .expect("the public operation succeeds")
            .to_be_bytes(256)
            .expect("the block fits the modulus");
        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        let caller = vec![
            x509_name("Issuer"),
            x509_validity(),
            x509_name("Subject"),
            default_extensions(),
        ];
        hasher.update(&rebuilt_tbs_certificate(&response, &caller));
        let digest = hasher.finalize();
        assert_eq!(&recovered[256 - 32..], &digest[..]);
        assert_eq!(&recovered[..2], &[0x00, 0x01]);
        assert_eq!(tbs_digest(&response), digest);
    }

    #[track_caller]
    fn assert_rsa_signature_verifies(
        runtime: &Tpm2Runtime,
        handle: u32,
        response: &[u8],
        label: &str,
    ) {
        use crate::library::tpm2::object_create::resolve_any_object;
        use crate::library::tpm2::persistent::OwnedAnyObjectBody;
        use crate::library::tpm2::signature::{Verification, parse_signature, validate_signature};
        use crate::library::tpm2::template::TemplateReader;

        let object = resolve_any_object(runtime, handle).expect("the signer is loaded");
        let OwnedAnyObjectBody::Object(body) = &object.body else {
            panic!("the handle names a key");
        };
        let profile = &runtime
            .state
            .as_ref()
            .expect("the runtime carries state")
            .profile;
        let digest = tbs_digest(response);
        let bytes = certify_signature(response);

        let mut reader = TemplateReader::new(&bytes);
        let signature = parse_signature(&mut reader, profile).expect("the signature parses");
        assert!(
            reader.remaining().is_empty(),
            "{label} carries an exact TPMT_SIGNATURE"
        );
        assert!(
            matches!(
                validate_signature(body, false, &digest, &signature, profile),
                Ok(Verification::Complete)
            ),
            "{label} verifies against the signing key over tbsDigest"
        );

        for index in [6, bytes.len() / 2, bytes.len() - 1] {
            let mut corrupted = bytes.clone();
            corrupted[index] ^= 0x01;
            let mut reader = TemplateReader::new(&corrupted);
            let corrupted = parse_signature(&mut reader, profile)
                .expect("a corrupted signature still unmarshals");
            assert!(
                validate_signature(body, false, &digest, &corrupted, profile).is_err(),
                "{label} rejects a one-byte corruption at offset {index}"
            );
        }
    }

    #[test]
    fn a_probabilistic_signature_scheme_signs_the_same_certificate() {
        for (record, hash_alg) in [
            ("X509_PSS_SHA256", ALG_SHA256),
            ("X509_PSS_SHA1", ALG_SHA1),
            ("X509_PSS_SHA384", ALG_SHA384),
        ] {
            let templates = vec![
                (TPM_RH_OWNER, rsa_template(ALG_NULL, 0, SIGN_ATTRS)),
                (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
            ];
            let mut runtime = with_keys(&templates);
            let expected = vector(record);
            let response = run(
                &mut runtime,
                &certify_command_with(
                    KEY1,
                    KEY0,
                    &default_body(),
                    &sig_scheme(ALG_RSAPSS, hash_alg),
                    &[],
                ),
            );
            assert_eq!(response_code(&response), RC_SUCCESS, "{record}");
            assert_eq!(
                added_to_certificate(&response),
                added_to_certificate(expected),
                "{record}"
            );
            assert_eq!(tbs_digest(&response), tbs_digest(expected), "{record}");

            let signature = certify_signature(&response);
            assert_eq!(
                &signature[..4],
                &[0x00, 0x16, (hash_alg >> 8) as u8, hash_alg as u8]
            );
            assert_eq!(
                signature.len(),
                certify_signature(expected).len(),
                "{record} signature layout"
            );
            assert_rsa_signature_verifies(&runtime, KEY0, &response, record);
            assert_rsa_signature_verifies(&runtime, KEY0, expected, &format!("{record} (oracle)"));
        }
    }

    #[test]
    fn the_rejected_requests_match_the_oracle() {
        let good = default_body();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "E_RESERVED_NOT_EMPTY",
                certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_NULL, 0), &[0x5a]),
            ),
            (
                "E_OVERSIZED_RESERVED",
                certify_command_with(
                    KEY1,
                    KEY0,
                    &good,
                    &sig_scheme(ALG_NULL, 0),
                    &(0..67u8).collect::<Vec<u8>>(),
                ),
            ),
            ("E_EMPTY_PARTIAL", certify_command(KEY1, KEY0, &[])),
            (
                "E_NOT_A_SEQUENCE",
                certify_command(KEY1, KEY0, &der(0x31, &[0x00])),
            ),
            ("E_TRAILING_BYTE", {
                let mut partial = good.clone();
                partial.push(0x00);
                certify_command(KEY1, KEY0, &partial)
            }),
            (
                "E_TRUNCATED",
                certify_command(KEY1, KEY0, &good[..good.len() - 1]),
            ),
            ("E_OUTER_LENGTH_SHORT", {
                let mut partial = good.clone();
                partial[1] = 0x02;
                certify_command(KEY1, KEY0, &partial)
            }),
            ("E_LENGTH_FORM_83", {
                let mut partial = vec![0x30, 0x83, 0x00, 0x00, 0x01];
                partial.extend_from_slice(&good[2..]);
                certify_command(KEY1, KEY0, &partial)
            }),
            ("E_LENGTH_FORM_80", {
                let mut partial = vec![0x30, 0x80];
                partial.extend_from_slice(&good[2..]);
                certify_command(KEY1, KEY0, &partial)
            }),
            ("E_LENGTH_FORM_82_NEGATIVE", {
                let mut partial = vec![0x30, 0x82, 0x80, 0x00];
                partial.extend_from_slice(&good[2..]);
                certify_command(KEY1, KEY0, &partial)
            }),
            (
                "E_EXTENDED_TAG",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        vec![0x1f, 0x01, 0x00],
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        default_extensions(),
                    ]),
                ),
            ),
            (
                "E_TWO_SEQUENCES",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        default_extensions(),
                    ]),
                ),
            ),
            (
                "E_FIVE_SEQUENCES",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("A"),
                        x509_name("B"),
                        x509_name("C"),
                        x509_name("D"),
                        x509_name("E"),
                        default_extensions(),
                    ]),
                ),
            ),
            (
                "E_NO_EXTENSIONS",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                    ]),
                ),
            ),
            (
                "E_DUPLICATE_EXTENSIONS",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        default_extensions(),
                        default_extensions(),
                    ]),
                ),
            ),
            (
                "E_UNEXPECTED_TAG",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        der(0xa1, &[0x00]),
                        default_extensions(),
                    ]),
                ),
            ),
            (
                "E_NO_KEY_USAGE",
                certify_command(
                    KEY1,
                    KEY0,
                    &body_with(extensions(&[tpma_object_extension(SIGN_ATTRS)])),
                ),
            ),
            (
                "E_BAD_ATTRIBUTES",
                certify_command(
                    KEY1,
                    KEY0,
                    &body_with(extensions(&[
                        tpma_object_extension(0x0006_0072),
                        key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
                    ])),
                ),
            ),
            (
                "E_KEY_USAGE_DECRYPT",
                certify_command(
                    KEY1,
                    KEY0,
                    &body_with(extensions(&[
                        tpma_object_extension(SIGN_ATTRS),
                        key_usage_extension(&KEY_USAGE_DATA_ENCIPHERMENT),
                    ])),
                ),
            ),
            (
                "E_KEY_USAGE_RESERVED_BITS",
                certify_command(
                    KEY1,
                    KEY0,
                    &body_with(extensions(&[
                        tpma_object_extension(SIGN_ATTRS),
                        key_usage_extension(&KEY_USAGE_RESERVED),
                    ])),
                ),
            ),
            (
                "E_EXTENSIONS_NOT_SEQUENCE",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        der(
                            0xa3,
                            &der(0x31, &key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE)),
                        ),
                    ]),
                ),
            ),
            (
                "E_EXTENSION_ENTRY_NOT_SEQUENCE",
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        der(0xa3, &der(0x30, &der(0x31, &[0x00]))),
                    ]),
                ),
            ),
            ("E_EXTENSION_WITHOUT_OCTET_STRING", {
                let mut content = vec![0x06, 0x03, 0x55, 0x1d, 0x0f];
                content.extend_from_slice(&der(0x03, &[0x07, 0x80]));
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        der(0xa3, &der(0x30, &der(0x30, &content))),
                    ]),
                )
            }),
            ("E_EXTENSION_BAD_BITSTRING", {
                let mut content = vec![0x06, 0x03, 0x55, 0x1d, 0x0f];
                content.extend_from_slice(&der(0x04, &der(0x03, &[0x08, 0x80])));
                certify_command(
                    KEY1,
                    KEY0,
                    &partial_certificate(&[
                        x509_name("Issuer"),
                        x509_validity(),
                        x509_name("Subject"),
                        der(0xa3, &der(0x30, &der(0x30, &content))),
                    ]),
                )
            }),
            (
                "E_NULL_OBJECT_HANDLE",
                certify_command(TPM_RH_NULL, KEY0, &good),
            ),
            (
                "E_NULL_SIGN_HANDLE",
                certify_command(KEY1, TPM_RH_NULL, &good),
            ),
            (
                "E_UNLOADED_OBJECT",
                certify_command(0x8000_0005, KEY0, &good),
            ),
            (
                "E_HIERARCHY_SIGN_HANDLE",
                certify_command(KEY1, TPM_RH_OWNER, &good),
            ),
            (
                "E_WRONG_SCHEME",
                certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_RSAPSS, ALG_SHA256), &[]),
            ),
            (
                "E_WRONG_HASH",
                certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_RSASSA, ALG_SHA1), &[]),
            ),
            (
                "E_MISSING_SESSION",
                command(
                    TPM_CC_CERTIFY_X509,
                    &[KEY1, KEY0],
                    Some(&[pw()]),
                    &certify_parameters(&[], &sig_scheme(ALG_NULL, 0), &good),
                ),
            ),
            (
                "E_NO_SESSIONS",
                command(
                    TPM_CC_CERTIFY_X509,
                    &[KEY1, KEY0],
                    None,
                    &certify_parameters(&[], &sig_scheme(ALG_NULL, 0), &good),
                ),
            ),
            ("E_PARAMETER_TRAILING", {
                let mut parameters = certify_parameters(&[], &sig_scheme(ALG_NULL, 0), &good);
                parameters.push(0x00);
                command(
                    TPM_CC_CERTIFY_X509,
                    &[KEY1, KEY0],
                    Some(&[pw(), pw()]),
                    &parameters,
                )
            }),
            ("E_OVERSIZED_PARTIAL", {
                let mut parameters = tpm2b(&[]);
                parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
                parameters.extend_from_slice(&1025u16.to_be_bytes());
                parameters.extend_from_slice(&[0u8; 1025]);
                command(
                    TPM_CC_CERTIFY_X509,
                    &[KEY1, KEY0],
                    Some(&[pw(), pw()]),
                    &parameters,
                )
            }),
        ];

        let mut runtime = with_keys(&signer_pair());
        for (record, bytes) in &cases {
            assert_eq!(run(&mut runtime, bytes), vector(record), "{record}");
        }

        assert_eq!(
            response_code(vector("E_RESERVED_NOT_EMPTY")),
            RC_PARAM1_SIZE
        );
        assert_eq!(
            response_code(vector("E_OVERSIZED_RESERVED")),
            RC_PARAM1_SIZE
        );
        assert_eq!(response_code(vector("E_EMPTY_PARTIAL")), RC_PARAM3_VALUE);
        assert_eq!(response_code(vector("E_NOT_A_SEQUENCE")), RC_PARAM3_SIZE);
        assert_eq!(response_code(vector("E_TRAILING_BYTE")), RC_PARAM3_SIZE);
        assert_eq!(response_code(vector("E_TRUNCATED")), RC_PARAM3_SIZE);
        assert_eq!(
            response_code(vector("E_OUTER_LENGTH_SHORT")),
            RC_PARAM3_SIZE
        );
        assert_eq!(response_code(vector("E_LENGTH_FORM_83")), RC_PARAM3_SIZE);
        assert_eq!(response_code(vector("E_LENGTH_FORM_80")), RC_PARAM3_SIZE);
        assert_eq!(
            response_code(vector("E_LENGTH_FORM_82_NEGATIVE")),
            RC_PARAM3_SIZE
        );
        assert_eq!(response_code(vector("E_OVERSIZED_PARTIAL")), RC_PARAM3_SIZE);
        for record in [
            "E_EXTENDED_TAG",
            "E_TWO_SEQUENCES",
            "E_FIVE_SEQUENCES",
            "E_NO_EXTENSIONS",
            "E_DUPLICATE_EXTENSIONS",
            "E_UNEXPECTED_TAG",
            "E_NO_KEY_USAGE",
            "E_KEY_USAGE_DECRYPT",
            "E_EXTENSIONS_NOT_SEQUENCE",
            "E_EXTENSION_ENTRY_NOT_SEQUENCE",
            "E_EXTENSION_WITHOUT_OCTET_STRING",
            "E_EXTENSION_BAD_BITSTRING",
        ] {
            assert_eq!(response_code(vector(record)), RC_PARAM3_VALUE, "{record}");
        }
        assert_eq!(
            response_code(vector("E_KEY_USAGE_RESERVED_BITS")),
            RC_PARAM3_RESERVED_BITS
        );
        assert_eq!(
            response_code(vector("E_BAD_ATTRIBUTES")),
            RC_HANDLE2_ATTRIBUTES
        );
        assert_eq!(
            response_code(vector("E_NULL_OBJECT_HANDLE")),
            RC_HANDLE1_VALUE
        );
        assert_eq!(response_code(vector("E_UNLOADED_OBJECT")), RC_HANDLE1_VALUE);
        assert_eq!(
            response_code(vector("E_NULL_SIGN_HANDLE")),
            RC_HANDLE2_VALUE
        );
        assert_eq!(
            response_code(vector("E_HIERARCHY_SIGN_HANDLE")),
            RC_HANDLE2_VALUE
        );
        assert_eq!(response_code(vector("E_WRONG_SCHEME")), RC_PARAM2_SCHEME);
        assert_eq!(response_code(vector("E_WRONG_HASH")), RC_PARAM2_SCHEME);
        assert_eq!(response_code(vector("E_MISSING_SESSION")), RC_AUTH_MISSING);
        assert_eq!(response_code(vector("E_NO_SESSIONS")), RC_AUTH_MISSING);
        assert_eq!(response_code(vector("E_PARAMETER_TRAILING")), RC_SIZE);
    }

    #[test]
    fn an_incompatible_signing_key_or_object_matches_the_oracle() {
        let good = default_body();
        let mut runtime = with_keys(&[
            (TPM_RH_OWNER, keyedhash_template(ALG_HMAC, ALG_SHA256)),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]);
        assert_eq!(
            run(&mut runtime, &certify_command(KEY1, KEY0, &good)),
            vector("E_HMAC_SIGNER_GENERATED_ALGID")
        );
        assert_eq!(
            run(&mut runtime, &certify_command(KEY0, KEY1, &good)),
            vector("E_HMAC_OBJECT")
        );

        let mut runtime = with_keys(&[
            (
                TPM_RH_ENDORSEMENT,
                rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            (TPM_RH_OWNER, symcipher_template()),
        ]);
        assert_eq!(
            run(&mut runtime, &certify_command(KEY1, KEY0, &good)),
            vector("E_SYMMETRIC_OBJECT")
        );

        let mut runtime = with_keys(&[
            (TPM_RH_OWNER, rsa_template(ALG_NULL, 0, DECRYPT_ATTRS)),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]);
        assert_eq!(
            run(&mut runtime, &certify_command(KEY1, KEY0, &good)),
            vector("E_DECRYPT_ONLY_SIGNER")
        );

        let mut runtime = with_keys(&[
            (TPM_RH_OWNER, rsa_template(ALG_NULL, 0, SIGN_ATTRS)),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]);
        assert_eq!(
            run(&mut runtime, &certify_command(KEY1, KEY0, &good)),
            vector("E_NULL_SCHEME_WITHOUT_DEFAULT")
        );

        assert_eq!(
            response_code(vector("E_HMAC_SIGNER_GENERATED_ALGID")),
            RC_HANDLE1_SCHEME
        );
        assert_eq!(
            response_code(vector("E_HMAC_OBJECT")),
            RC_HANDLE2_ASYMMETRIC
        );
        assert_eq!(
            response_code(vector("E_SYMMETRIC_OBJECT")),
            RC_HANDLE2_ASYMMETRIC
        );
        assert_eq!(
            response_code(vector("E_DECRYPT_ONLY_SIGNER")),
            RC_HANDLE1_KEY
        );
        assert_eq!(
            response_code(vector("E_NULL_SCHEME_WITHOUT_DEFAULT")),
            RC_PARAM2_SCHEME
        );
    }

    #[test]
    fn the_command_is_audited_like_the_oracle() {
        let mut runtime = with_keys(&signer_pair());
        let mut parameters = sig_scheme(ALG_NULL, 0);
        parameters.extend_from_slice(&1u32.to_be_bytes());
        parameters.extend_from_slice(&TPM_CC_CERTIFY_X509.to_be_bytes());
        parameters.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            run(
                &mut runtime,
                &command(0x0000_0140, &[TPM_RH_OWNER], Some(&[pw()]), &parameters)
            ),
            vector("AUDIT_ENABLE")
        );
        assert!(
            crate::library::tpm2::command::command_audit_is_required(&runtime, TPM_CC_CERTIFY_X509),
            "the audit bit is set for TPM2_CertifyX509"
        );
        assert_eq!(
            run(&mut runtime, &certify_command(KEY1, KEY0, &default_body())),
            vector("X509_AUDITED")
        );
        let expected = vector("AUDIT_DIGEST");
        replay_clock(&mut runtime, expected);
        let mut digest_parameters = tpm2b(&QUALIFY);
        digest_parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
        assert_eq!(
            run(
                &mut runtime,
                &command(
                    0x0000_0133,
                    &[TPM_RH_ENDORSEMENT, KEY0],
                    Some(&[pw(), pw()]),
                    &digest_parameters
                )
            ),
            expected,
            "the audit digest covers the certification"
        );
    }

    #[test]
    fn a_rejected_certification_leaves_no_trace() {
        let mut runtime = with_keys(&signer_pair());
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &default_body()),
            "the first authorization performs the DA-used transition",
        );
        runtime.nv_update_pending = false;
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let drbg_before = runtime.live.orderly.drbg_state.clone();
        let good = default_body();
        for bytes in [
            certify_command(TPM_RH_NULL, KEY0, &good),
            certify_command(KEY1, KEY0, &[]),
            certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_RSAPSS, ALG_SHA256), &[]),
            certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    tpma_object_extension(0x0006_0072),
                    key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
                ])),
            ),
        ] {
            assert_ne!(response_code(&run(&mut runtime, &bytes)), RC_SUCCESS);
            assert_eq!(
                crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                    .expect("the state serializes"),
                before
            );
            assert_eq!(
                runtime.live.orderly.drbg_state.reseed_counter, drbg_before.reseed_counter,
                "a rejected certification draws no randomness"
            );
        }
    }

    #[test]
    fn partial_certificate_mutations_do_not_panic() {
        let full = default_body();
        let mut runtime = with_keys(&signer_pair());
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x30, 0x7f, 0x80, 0x82, 0xa3, 0xff] {
                let mut partial = full.clone();
                partial[index] = byte;
                let _ = run(&mut runtime, &certify_command(KEY1, KEY0, &partial));
            }
        }
        for length in 0..full.len() {
            let _ = run(&mut runtime, &certify_command(KEY1, KEY0, &full[..length]));
        }
    }

    #[test]
    fn leading_parameter_mutations_do_not_panic() {
        let mut full = tpm2b(&[]);
        full.extend_from_slice(&sig_scheme(ALG_RSASSA, ALG_SHA256));
        full.extend_from_slice(&tpm2b(&default_body()));
        let mut runtime = with_keys(&signer_pair());
        for index in 0..full.len().min(24) {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut parameters = full.clone();
                parameters[index] = byte;
                let _ = run(
                    &mut runtime,
                    &command(
                        TPM_CC_CERTIFY_X509,
                        &[KEY1, KEY0],
                        Some(&[pw(), pw()]),
                        &parameters,
                    ),
                );
            }
        }
    }

    thread_local! {
        static EXECUTED_TESTS: RefCell<Vec<PrimitiveTest>> = const { RefCell::new(Vec::new()) };
        static FAILING_TEST: Cell<Option<PrimitiveTest>> = const { Cell::new(None) };
    }

    fn recording_runner(test: PrimitiveTest) -> bool {
        EXECUTED_TESTS.with(|log| log.borrow_mut().push(test));
        FAILING_TEST.with(Cell::get) != Some(test)
    }

    fn arm_self_tests(runtime: &mut Tpm2Runtime, failing: Option<PrimitiveTest>) {
        EXECUTED_TESTS.with(|log| log.borrow_mut().clear());
        FAILING_TEST.with(|slot| slot.set(failing));
        runtime.self_test.set_runner(recording_runner);
    }

    fn executed_self_tests() -> Vec<PrimitiveTest> {
        EXECUTED_TESTS.with(|log| log.borrow().clone())
    }

    fn pending_self_tests(runtime: &Tpm2Runtime) -> Vec<PrimitiveTest> {
        PrimitiveTest::ALL
            .into_iter()
            .filter(|test| runtime.self_test.pending.contains(*test))
            .collect()
    }

    // The first DA-protected authorization of a cycle is itself a persistent
    // state change, so the failure tests perform it before they snapshot.
    fn burn_da_cycle(runtime: &mut Tpm2Runtime) {
        crate::library::tpm2::dictionary_attack::record_da_used(runtime)
            .expect("the DA-used transition is a production state change");
        runtime.nv_update_pending = false;
    }

    fn split_hash_signer() -> Vec<(u32, Vec<u8>)> {
        vec![
            (
                TPM_RH_OWNER,
                rsa_template_named(
                    ALG_RSASSA,
                    ALG_SHA256,
                    SIGN_ATTRS,
                    ALG_SHA384,
                    &[0x00, 0x10],
                ),
            ),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]
    }

    #[test]
    fn every_primitive_hash_test_is_pending_before_the_first_certification() {
        let runtime = with_keys(&signer_pair());
        assert_eq!(
            pending_self_tests(&runtime),
            [
                PrimitiveTest::Sha1,
                PrimitiveTest::Aes256,
                PrimitiveTest::Sha256,
                PrimitiveTest::Sha384,
                PrimitiveTest::Sha512,
                PrimitiveTest::Ecdh,
            ],
            "creating the keys settles no lazy hash test"
        );
    }

    #[test]
    fn the_serial_number_hash_is_tested_before_the_certificate_hash() {
        let mut runtime = with_keys(&split_hash_signer());
        arm_self_tests(&mut runtime, None);
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &default_body()),
            "the certification succeeds",
        );
        assert_eq!(
            executed_self_tests(),
            [PrimitiveTest::Sha384, PrimitiveTest::Sha256],
            "the signing key nameAlg is tested before the signature hash"
        );
        assert_eq!(
            pending_self_tests(&runtime),
            [
                PrimitiveTest::Sha1,
                PrimitiveTest::Aes256,
                PrimitiveTest::Sha512,
                PrimitiveTest::Ecdh,
            ],
            "both hashes are settled"
        );
    }

    #[test]
    fn one_hash_algorithm_runs_its_primitive_test_once() {
        let mut runtime = with_keys(&signer_pair());
        arm_self_tests(&mut runtime, None);
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &default_body()),
            "the certification succeeds",
        );
        assert_eq!(
            executed_self_tests(),
            [PrimitiveTest::Sha256],
            "a SHA-256 nameAlg and a SHA-256 signature hash share one pending test"
        );
        assert!(!runtime.self_test.pending.contains(PrimitiveTest::Sha256));
    }

    #[test]
    fn a_settled_name_algorithm_leaves_only_the_signature_hash() {
        let mut runtime = with_keys(&split_hash_signer());
        runtime
            .self_test
            .run_pending_algorithm(ALG_SHA384)
            .expect("the SHA-384 known answer passes");
        arm_self_tests(&mut runtime, None);
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &default_body()),
            "the certification succeeds",
        );
        assert_eq!(executed_self_tests(), [PrimitiveTest::Sha256]);
    }

    #[test]
    fn a_settled_signature_hash_leaves_only_the_name_algorithm() {
        let mut runtime = with_keys(&split_hash_signer());
        runtime
            .self_test
            .run_pending_algorithm(ALG_SHA256)
            .expect("the SHA-256 known answer passes");
        arm_self_tests(&mut runtime, None);
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &default_body()),
            "the certification succeeds",
        );
        assert_eq!(executed_self_tests(), [PrimitiveTest::Sha384]);
    }

    #[test]
    fn a_failing_serial_number_hash_test_stops_the_command() {
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::self_test::SelfTestFailure;

        let mut runtime = with_keys(&split_hash_signer());
        burn_da_cycle(&mut runtime);
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let drbg_before = runtime.live.orderly.drbg_state.clone();
        arm_self_tests(&mut runtime, Some(PrimitiveTest::Sha384));

        let response = run(&mut runtime, &certify_command(KEY1, KEY0, &default_body()));
        assert_eq!(
            response,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            executed_self_tests(),
            [PrimitiveTest::Sha384],
            "the signature hash is never reached"
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha384
            })
        );
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha384));
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha256));
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::for_self_test(&runtime.self_test).diagnostics()
        );
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the state serializes"),
            before,
            "a failed hash test writes no persistent state"
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, drbg_before.reseed_counter,
            "a failed hash test draws no signing randomness"
        );

        let follow_up = certify_command(KEY1, KEY0, &default_body());
        assert_eq!(
            crate::library::tpm2::failure_mode::process(
                &mut runtime,
                &crate::library::CommandInput::new(follow_up.len() as u32, follow_up)
            )
            .expect("the failure-mode route answers"),
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01],
            "the next command takes the normal failure-mode boundary"
        );
    }

    #[test]
    fn a_failing_certificate_hash_test_stops_the_command_after_the_serial_number() {
        use crate::library::tpm2::self_test::SelfTestFailure;

        let mut runtime = with_keys(&split_hash_signer());
        burn_da_cycle(&mut runtime);
        let before = crate::library::tpm2::persistent::persistent_all_store(runtime.state())
            .expect("the state serializes");
        let drbg_before = runtime.live.orderly.drbg_state.clone();
        arm_self_tests(&mut runtime, Some(PrimitiveTest::Sha256));

        let response = run(&mut runtime, &certify_command(KEY1, KEY0, &default_body()));
        assert_eq!(
            response,
            [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            executed_self_tests(),
            [PrimitiveTest::Sha384, PrimitiveTest::Sha256],
            "the serial-number hash passes before the certificate hash fails"
        );
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.self_test.failure,
            Some(SelfTestFailure {
                primitive: PrimitiveTest::Sha256
            })
        );
        assert!(
            !runtime.self_test.pending.contains(PrimitiveTest::Sha384),
            "the first hash stays settled"
        );
        assert!(runtime.self_test.pending.contains(PrimitiveTest::Sha256));
        assert_eq!(
            crate::library::tpm2::persistent::persistent_all_store(runtime.state())
                .expect("the state serializes"),
            before
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            drbg_before.reseed_counter
        );
    }

    #[test]
    fn a_rejected_request_settles_no_hash_self_test() {
        let good = default_body();
        let rejected: Vec<Vec<u8>> = vec![
            certify_command(TPM_RH_NULL, KEY0, &good),
            certify_command(KEY1, TPM_RH_OWNER, &good),
            certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_RSAPSS, ALG_SHA256), &[]),
            certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_NULL, 0), &[0x5a]),
            certify_command(KEY1, KEY0, &[]),
            certify_command(KEY1, KEY0, &good[..good.len() - 1]),
            certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[tpma_object_extension(SIGN_ATTRS)])),
            ),
            certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    tpma_object_extension(0x0006_0072),
                    key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
                ])),
            ),
        ];

        let mut runtime = with_keys(&signer_pair());
        let expected = pending_self_tests(&runtime);
        for bytes in &rejected {
            arm_self_tests(&mut runtime, None);
            let response = run(&mut runtime, bytes);
            assert_ne!(response_code(&response), RC_SUCCESS);
            assert_eq!(
                executed_self_tests(),
                [],
                "a rejected request runs no known-answer test"
            );
            assert_eq!(pending_self_tests(&runtime), expected);
            assert!(!runtime.failure_mode);
        }
    }

    fn wide_key_usage(shift: u8, content: &[u8]) -> Vec<u8> {
        let mut bits = vec![0x03, (content.len() + 1) as u8, shift];
        bits.extend_from_slice(content);
        key_usage_extension(&bits)
    }

    fn wide_object_attributes(shift: u8, content: &[u8]) -> Vec<u8> {
        let mut bits = vec![0x03, (content.len() + 1) as u8, shift];
        bits.extend_from_slice(content);
        let mut entry = vec![0x06, 0x07, 0x67, 0x81, 0x05, 0x0a, 0x01, 0x01, 0x01];
        entry.extend_from_slice(&der(0x04, &bits));
        der(0x30, &entry)
    }

    #[test]
    fn a_key_usage_wider_than_thirty_two_bits_reaches_the_extension_check() {
        let mut runtime = with_keys(&signer_pair());
        let response = run(
            &mut runtime,
            &certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    tpma_object_extension(SIGN_ATTRS),
                    wide_key_usage(0x00, &[0xff; 5]),
                ])),
            ),
        );
        assert_eq!(
            response_code(&response),
            RC_PARAM3_VALUE,
            "forty significant bits keep their decipherment bits and the object cannot decrypt"
        );
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_wide_zero_valued_key_usage_is_accepted_like_the_reference() {
        let mut runtime = with_keys(&signer_pair());
        for content in [
            &[0x00u8; 5][..],
            &[0x01, 0x02, 0x03, 0x04, 0x05],
            &[0x00; 8],
        ] {
            let response = run(
                &mut runtime,
                &certify_command(
                    KEY1,
                    KEY0,
                    &body_with(extensions(&[
                        tpma_object_extension(SIGN_ATTRS),
                        wide_key_usage(0x07, content),
                    ])),
                ),
            );
            assert_eq!(
                response_code(&response),
                RC_SUCCESS,
                "a bit string past the thirty-second bit keeps only its lowest bits"
            );
        }
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn a_wide_object_attribute_bit_string_is_an_attribute_mismatch() {
        let mut runtime = with_keys(&signer_pair());
        let response = run(
            &mut runtime,
            &certify_command(
                KEY1,
                KEY0,
                &body_with(extensions(&[
                    wide_object_attributes(0x07, &[0x00; 5]),
                    key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
                ])),
            ),
        );
        assert_eq!(response_code(&response), RC_HANDLE2_ATTRIBUTES);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn wide_bit_strings_in_a_partial_certificate_never_panic() {
        let patterns: [fn(usize) -> u8; 3] = [
            |_| 0x00,
            |_| 0xff,
            |index| if index == 0 { 0x80 } else { 0x00 },
        ];
        let mut runtime = with_keys(&signer_pair());
        for content in [5usize, 6, 9, 18] {
            for shift in 0u8..=8 {
                for pattern in patterns {
                    let payload: Vec<u8> = (0..content).map(pattern).collect();
                    let attributes = run(
                        &mut runtime,
                        &certify_command(
                            KEY1,
                            KEY0,
                            &body_with(extensions(&[
                                wide_object_attributes(shift, &payload),
                                key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
                            ])),
                        ),
                    );
                    assert!(response_code(&attributes) != RC_SUCCESS || attributes.len() > 10);
                    assert!(!runtime.failure_mode, "{content} octets, shift {shift}");
                }
            }
        }
        for shift in 0u8..=8 {
            for pattern in patterns {
                let payload: Vec<u8> = (0..6).map(pattern).collect();
                let usage = run(
                    &mut runtime,
                    &certify_command(
                        KEY1,
                        KEY0,
                        &body_with(extensions(&[
                            tpma_object_extension(SIGN_ATTRS),
                            wide_key_usage(shift, &payload),
                        ])),
                    ),
                );
                assert!(response_code(&usage) != RC_SUCCESS || usage.len() > 10);
                assert!(!runtime.failure_mode, "key usage shift {shift}");
            }
        }
    }

    #[test]
    fn a_certification_never_touches_nv_or_the_object_table() {
        let mut runtime = with_keys(&signer_pair());
        run_ok(
            &mut runtime,
            &certify_command(KEY1, KEY0, &default_body()),
            "the first authorization performs the DA-used transition",
        );
        runtime.nv_update_pending = false;
        let nv_before = runtime.nv_memory.clone();
        let response = run(&mut runtime, &certify_command(KEY0, KEY0, &default_body()));
        assert_eq!(response_code(&response), RC_SUCCESS);
        assert_eq!(
            runtime.nv_memory, nv_before,
            "the command writes no NV data"
        );
        assert!(!runtime.nv_update_pending, "no NV commit is scheduled");
        for handle in [KEY0, KEY1] {
            assert!(
                crate::library::tpm2::object_create::resolve_any_object(&runtime, handle).is_some(),
                "the objects stay loaded"
            );
        }
    }

    const SESSION_NONCE_CALLER: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    const SESSION_HANDLE: u32 = 0x0200_0000;

    #[track_caller]
    fn session_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_X509_SESSION_READY"))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector("VOLATILE_X509_SESSION_READY"))
            .expect("the oracle volatile state attaches");
        runtime
    }

    fn hmac_session_area(attributes: u8) -> Vec<u8> {
        let mut out = SESSION_HANDLE.to_be_bytes().to_vec();
        out.extend_from_slice(&tpm2b(&SESSION_NONCE_CALLER));
        out.push(attributes);
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    fn encrypted_command(attributes: u8, reserved: &[u8]) -> Vec<u8> {
        command(
            TPM_CC_CERTIFY_X509,
            &[KEY1, KEY0],
            Some(&[hmac_session_area(attributes), pw()]),
            &certify_parameters(reserved, &sig_scheme(ALG_NULL, 0), &default_body()),
        )
    }

    fn started_session_nonce() -> Vec<u8> {
        let bytes = vector("X509_SESSION");
        let size = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
        bytes[16..16 + size].to_vec()
    }

    fn response_nonce(response: &[u8]) -> Vec<u8> {
        let parameter_size =
            u32::from_be_bytes(response[10..14].try_into().expect("four bytes")) as usize;
        let sessions = &response[14 + parameter_size..];
        let size = u16::from_be_bytes([sessions[0], sessions[1]]) as usize;
        sessions[2..2 + size].to_vec()
    }

    #[test]
    fn the_session_is_created_with_the_oracle_layout() {
        let mut runtime = with_keys(&signer_pair());
        let start = {
            let mut parameters = tpm2b(&SESSION_NONCE_CALLER);
            parameters.extend_from_slice(&tpm2b(&[]));
            parameters.push(0x00);
            parameters.extend_from_slice(&[0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
            parameters.extend_from_slice(&ALG_SHA256.to_be_bytes());
            command(
                CC_START_AUTH_SESSION,
                &[TPM_RH_NULL, TPM_RH_NULL],
                None,
                &parameters,
            )
        };
        let response = run(&mut runtime, &start);
        let expected = vector("X509_SESSION");
        assert_eq!(response.len(), expected.len());
        assert_eq!(response[..14], expected[..14], "the handle and nonce size");
        assert_eq!(
            u32::from_be_bytes(response[10..14].try_into().expect("four bytes")),
            SESSION_HANDLE
        );
        assert_eq!(started_session_nonce().len(), 32);
    }

    #[test]
    fn a_session_tagged_certification_matches_the_oracle() {
        for (record, attributes) in [
            ("X509_PLAIN_SESSION", 0x01u8),
            ("X509_ENCRYPTED_REQUEST", 0x21),
            ("X509_ENCRYPTED_RESPONSE", 0x41),
            ("X509_ENCRYPTED_BOTH", 0x61),
        ] {
            let mut runtime = session_runtime();
            assert_eq!(
                run(&mut runtime, &encrypted_command(attributes, &[])),
                vector(record),
                "{record}"
            );
        }
    }

    #[test]
    fn an_encrypted_reserved_parameter_is_decrypted_before_its_size_is_checked() {
        use crate::library::tpm2::crypto::{kdfa, sym_cfb_encrypt};

        let stream = kdfa(
            ALG_SHA256,
            &[],
            b"CFB",
            &SESSION_NONCE_CALLER,
            &started_session_nonce(),
            256,
        )
        .expect("the parameter key derives");
        let mut reserved = [0x5au8];
        sym_cfb_encrypt(0x0006, &stream[..16], &stream[16..32], &mut reserved)
            .expect("the parameter encrypts");

        let mut runtime = session_runtime();
        assert_eq!(
            run(&mut runtime, &encrypted_command(0x21, &reserved)),
            vector("X509_ENCRYPTED_RESERVED")
        );
        assert_eq!(
            response_code(vector("X509_ENCRYPTED_RESERVED")),
            RC_PARAM1_SIZE
        );
    }

    #[test]
    fn the_encrypted_response_carries_the_same_certificate() {
        use crate::library::tpm2::crypto::{kdfa, sym_cfb_decrypt};

        let plain = added_to_certificate(vector("X509_PLAIN_SESSION"));
        for record in ["X509_ENCRYPTED_RESPONSE", "X509_ENCRYPTED_BOTH"] {
            let response = vector(record);
            let mut encrypted = added_to_certificate(response);
            assert_ne!(encrypted, plain, "{record} hides the certificate");
            let stream = kdfa(
                ALG_SHA256,
                &[],
                b"CFB",
                &response_nonce(response),
                &SESSION_NONCE_CALLER,
                256,
            )
            .expect("the parameter key derives");
            sym_cfb_decrypt(0x0006, &stream[..16], &stream[16..32], &mut encrypted)
                .expect("the parameter decrypts");
            assert_eq!(encrypted, plain, "{record} recovers the certificate");
            assert_eq!(
                tbs_digest(response),
                tbs_digest(vector("X509_PLAIN_SESSION")),
                "{record} leaves the digest in the clear"
            );
        }
    }

    #[test]
    fn the_validation_order_matches_the_oracle() {
        let good = default_body();
        let malformed_sequence = der(0x31, &[0x00]);
        let short_outer = {
            let mut partial = good.clone();
            partial[1] = 0x02;
            partial
        };
        let missing_key_usage = body_with(extensions(&[tpma_object_extension(SIGN_ATTRS)]));

        let mut runtime = with_keys(&[
            (TPM_RH_OWNER, rsa_template(ALG_NULL, 0, DECRYPT_ATTRS)),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]);
        assert_eq!(
            run(
                &mut runtime,
                &certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_NULL, 0), &[0x5a])
            ),
            vector("ORDER_RESERVED_BEFORE_KEY"),
            "the reserved field is checked before the signing key"
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command_with(KEY1, KEY0, &good, &sig_scheme(ALG_RSAPSS, ALG_SHA256), &[])
            ),
            vector("ORDER_KEY_BEFORE_SCHEME"),
            "the signing key is checked before the scheme"
        );

        let mut runtime = with_keys(&[
            (TPM_RH_OWNER, keyedhash_template(ALG_HMAC, ALG_SHA256)),
            (TPM_RH_OWNER, ecc_template(ALG_ECDSA, ALG_SHA256)),
        ]);
        assert_eq!(
            run(
                &mut runtime,
                &certify_command_with(KEY0, KEY0, &good, &sig_scheme(ALG_RSASSA, ALG_SHA256), &[])
            ),
            vector("ORDER_SCHEME_BEFORE_OBJECT"),
            "the scheme is selected before the certified object is encoded"
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(KEY0, KEY0, &malformed_sequence)
            ),
            vector("ORDER_OBJECT_BEFORE_PARTIAL"),
            "the certified object is checked before the partial certificate is parsed"
        );
        assert_eq!(
            run(&mut runtime, &certify_command(KEY1, KEY0, &short_outer)),
            vector("ORDER_PARTIAL_BEFORE_ALGID"),
            "the partial certificate is parsed before the generated algorithm identifier"
        );
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(KEY1, KEY0, &missing_key_usage)
            ),
            vector("ORDER_ALGID_BEFORE_EXTENSIONS"),
            "the generated algorithm identifier precedes the extensions"
        );

        let mut runtime = with_keys(&signer_pair());
        assert_eq!(
            run(
                &mut runtime,
                &certify_command(
                    KEY1,
                    KEY0,
                    &body_with(extensions(&[
                        tpma_object_extension(0x0006_0072),
                        key_usage_extension(&KEY_USAGE_DIGITAL_SIGNATURE),
                    ]))
                )
            ),
            vector("ORDER_EXTENSIONS_BEFORE_SIGNING"),
            "the extensions are processed before anything is signed"
        );

        for (record, code) in [
            ("ORDER_RESERVED_BEFORE_KEY", RC_PARAM1_SIZE),
            ("ORDER_KEY_BEFORE_SCHEME", RC_HANDLE1_KEY),
            ("ORDER_SCHEME_BEFORE_OBJECT", RC_PARAM2_SCHEME),
            ("ORDER_OBJECT_BEFORE_PARTIAL", RC_HANDLE2_ASYMMETRIC),
            ("ORDER_PARTIAL_BEFORE_ALGID", RC_PARAM3_SIZE),
            ("ORDER_ALGID_BEFORE_EXTENSIONS", RC_HANDLE1_SCHEME),
            ("ORDER_EXTENSIONS_BEFORE_SIGNING", RC_HANDLE2_ATTRIBUTES),
        ] {
            assert_eq!(response_code(vector(record)), code, "{record}");
        }
    }

    #[test]
    fn the_fixture_covers_every_certification_shape() {
        let names: Vec<&str> = vectors().into_iter().map(|record| record.name).collect();
        assert!(
            names
                .iter()
                .filter(|name| name.starts_with("X509_"))
                .count()
                >= 15
        );
        assert!(names.iter().filter(|name| name.starts_with("E_")).count() >= 30);
    }
}
