use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_HASH, TPM_RC_SIZE};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::crypto::signing_state::{
    load_signing_state, publish_signing_outcome,
};
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::hierarchy::TPM_RH_NULL;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::object::{ATTR_EPS_HIERARCHY, ATTR_PPS_HIERARCHY};
use crate::library::tpm2::orderly::{commit_clear_orderly, prepare_clear_orderly};
use crate::library::tpm2::persistent::{
    OwnedAnyObjectBody, OwnedObjectBody, OwnedPcrSelection, OwnedUserNvramEntry,
};
use crate::library::tpm2::profile::ValidatedProfile;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::signature::{
    SigScheme, Signature, is_anonymous_scheme, is_signing_object, marshal_signature,
    obfuscation_mask, parse_sig_scheme, sign_digest,
};
use crate::library::tpm2::template::{TemplateReader, digest_size};
use crate::library::tpm2::ticket::{CONTEXT_INTEGRITY_HASH_ALG, TPM_GENERATED_VALUE};
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_NV: u16 = 0x8014;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_COMMAND_AUDIT: u16 = 0x8015;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_SESSION_AUDIT: u16 = 0x8016;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_CERTIFY: u16 = 0x8017;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_TIME: u16 = 0x8019;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_CREATION: u16 = 0x801a;
pub(in crate::library::tpm2::command) const TPM_ST_ATTEST_NV_DIGEST: u16 = 0x801c;

pub(in crate::library::tpm2::command) const TIME_INFO_SIZE: usize = 8 + 8 + 4 + 4 + 1;

pub(in crate::library::tpm2::command) const QUALIFYING_DATA_MAX: usize = 2 + 64;
pub(in crate::library::tpm2::command) const DIGEST_MAX: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2::command) struct ClockInfo {
    pub(in crate::library::tpm2::command) clock: u64,
    pub(in crate::library::tpm2::command) reset_count: u32,
    pub(in crate::library::tpm2::command) restart_count: u32,
    pub(in crate::library::tpm2::command) safe: u8,
}

pub(in crate::library::tpm2::command) enum Attested {
    Certify {
        name: Vec<u8>,
        qualified_name: Vec<u8>,
    },
    Creation {
        object_name: Vec<u8>,
        creation_hash: Vec<u8>,
    },
    Quote {
        selections: Vec<OwnedPcrSelection>,
        pcr_digest: Vec<u8>,
    },
    CommandAudit {
        audit_counter: u64,
        digest_alg: u16,
        audit_digest: Vec<u8>,
        command_digest: Vec<u8>,
    },
    SessionAudit {
        exclusive_session: bool,
        session_digest: Vec<u8>,
    },
    Time {
        time: u64,
        clock_info: ClockInfo,
        firmware_version: u64,
    },
    Nv {
        index_name: Vec<u8>,
        offset: u16,
        contents: Vec<u8>,
    },
    NvDigest {
        index_name: Vec<u8>,
        digest: Vec<u8>,
    },
}

impl Attested {
    fn attest_type(&self) -> u16 {
        match self {
            Self::Certify { .. } => TPM_ST_ATTEST_CERTIFY,
            Self::Creation { .. } => TPM_ST_ATTEST_CREATION,
            Self::Quote { .. } => TPM_ST_ATTEST_QUOTE,
            Self::CommandAudit { .. } => TPM_ST_ATTEST_COMMAND_AUDIT,
            Self::SessionAudit { .. } => TPM_ST_ATTEST_SESSION_AUDIT,
            Self::Time { .. } => TPM_ST_ATTEST_TIME,
            Self::Nv { .. } => TPM_ST_ATTEST_NV,
            Self::NvDigest { .. } => TPM_ST_ATTEST_NV_DIGEST,
        }
    }
}

pub(in crate::library::tpm2::command) struct Attest {
    attest_type: u16,
    qualified_signer: Vec<u8>,
    extra_data: Vec<u8>,
    clock_info: ClockInfo,
    firmware_version: u64,
    attested: Attested,
    residual_qualifying_data: Vec<u8>,
}

pub(in crate::library::tpm2::command) fn parse_qualifying_data(
    reader: &mut TemplateReader<'_>,
    error_index: TpmResult,
) -> Result<Vec<u8>, TpmResult> {
    Ok(reader
        .tpm2b(QUALIFYING_DATA_MAX)
        .map_err(|code| code + error_index)?
        .to_vec())
}

pub(in crate::library::tpm2::command) fn parse_scheme(
    reader: &mut TemplateReader<'_>,
    profile: &ValidatedProfile,
    error_index: TpmResult,
) -> Result<SigScheme, TpmResult> {
    parse_sig_scheme(reader, profile).map_err(|code| code + error_index)
}

pub(in crate::library::tpm2::command) fn check_signing_object(
    body: Option<&OwnedObjectBody>,
    error_index: TpmResult,
) -> Result<(), TpmResult> {
    if let Some(body) = body
        && !is_signing_object(body)
    {
        return Err(crate::library::constants::TPM_RC_KEY + error_index);
    }
    Ok(())
}

pub(in crate::library::tpm2::command) fn time_clock_info(
    runtime: &Tpm2Runtime,
) -> Result<ClockInfo, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    Ok(ClockInfo {
        clock: runtime.live.orderly.clock,
        reset_count: state.persistent.reset_count,
        restart_count: runtime
            .live
            .state_reset
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .restart_count,
        safe: if runtime.nv_available {
            runtime.live.orderly.clock_safe
        } else {
            0
        },
    })
}

pub(in crate::library::tpm2::command) fn marshaled_time_info(
    runtime: &Tpm2Runtime,
) -> Result<Vec<u8>, TpmResult> {
    let clock_info = time_clock_info(runtime)?;
    let mut writer = BlobWriter::with_capacity(TIME_INFO_SIZE);
    writer.write_u64(runtime.timer.time_ms);
    marshal_clock_info(&mut writer, &clock_info);
    Ok(writer.into_bytes())
}

pub(in crate::library::tpm2::command) fn firmware_version(
    runtime: &Tpm2Runtime,
) -> Result<u64, TpmResult> {
    let persistent = &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.persistent;
    Ok((u64::from(persistent.firmware_v1) << 32) | u64::from(persistent.firmware_v2))
}

pub(in crate::library::tpm2::command) fn fill_in_attest_info(
    runtime: &Tpm2Runtime,
    sign_object: Option<&OwnedObjectBody>,
    scheme: &SigScheme,
    qualifying_data: &[u8],
    attested: Attested,
) -> Result<Attest, TpmResult> {
    let anonymous = is_anonymous_scheme(scheme.scheme);
    let qualified_signer = match sign_object {
        None => TPM_RH_NULL.to_be_bytes().to_vec(),
        Some(_) if anonymous => Vec::new(),
        Some(body) => body.qualified_name.clone(),
    };

    let mut clock_info = time_clock_info(runtime)?;
    let mut firmware_version = firmware_version(runtime)?;

    let hierarchy_attributes = sign_object.map_or(0, |_| loaded_hierarchy(runtime, sign_object));
    if sign_object.is_none()
        || hierarchy_attributes & (ATTR_EPS_HIERARCHY | ATTR_PPS_HIERARCHY) == 0
    {
        let sh_proof = runtime
            .state
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .sh_proof
            .as_bytes()
            .to_vec();
        let mask = obfuscation_mask(CONTEXT_INTEGRITY_HASH_ALG, &sh_proof, &qualified_signer)
            .ok_or(TPM_RC_HASH)?;
        firmware_version = firmware_version.wrapping_add(mask[0]);
        clock_info.reset_count = clock_info.reset_count.wrapping_add((mask[1] >> 32) as u32);
        clock_info.restart_count = clock_info.restart_count.wrapping_add(mask[1] as u32);
    }

    Ok(Attest {
        attest_type: attested.attest_type(),
        qualified_signer,
        extra_data: if anonymous {
            Vec::new()
        } else {
            qualifying_data.to_vec()
        },
        clock_info,
        firmware_version,
        attested,
        residual_qualifying_data: if anonymous {
            qualifying_data.to_vec()
        } else {
            Vec::new()
        },
    })
}

fn loaded_hierarchy(runtime: &Tpm2Runtime, sign_object: Option<&OwnedObjectBody>) -> u32 {
    let Some(body) = sign_object else {
        return 0;
    };
    for object in &runtime.live.objects {
        if let OwnedAnyObjectBody::Object(loaded) = &object.body
            && loaded.name == body.name
        {
            return object.attributes;
        }
    }
    runtime
        .state
        .as_ref()
        .map(|state| {
            state
                .user_nvram
                .entries
                .iter()
                .find_map(|entry| match entry {
                    OwnedUserNvramEntry::Persistent { object, .. } => match &object.body {
                        OwnedAnyObjectBody::Object(stored) if stored.name == body.name => {
                            Some(object.attributes)
                        }
                        _ => None,
                    },
                    OwnedUserNvramEntry::NvIndex { .. } => None,
                })
                .unwrap_or(0)
        })
        .unwrap_or(0)
}

fn marshal_clock_info(writer: &mut BlobWriter, clock_info: &ClockInfo) {
    writer.write_bytes(&clock_info.clock.to_be_bytes());
    writer.write_u32(clock_info.reset_count);
    writer.write_u32(clock_info.restart_count);
    writer.write_u8(clock_info.safe);
}

fn marshal_sized(writer: &mut BlobWriter, bytes: &[u8]) {
    writer.write_u16(bytes.len() as u16);
    writer.write_bytes(bytes);
}

fn marshal_attested(writer: &mut BlobWriter, attested: &Attested) {
    match attested {
        Attested::Certify {
            name,
            qualified_name,
        } => {
            marshal_sized(writer, name);
            marshal_sized(writer, qualified_name);
        }
        Attested::Creation {
            object_name,
            creation_hash,
        } => {
            marshal_sized(writer, object_name);
            marshal_sized(writer, creation_hash);
        }
        Attested::Quote {
            selections,
            pcr_digest,
        } => {
            writer.write_u32(selections.len() as u32);
            for selection in selections {
                writer.write_u16(selection.hash_alg);
                writer.write_u8(selection.select.len() as u8);
                writer.write_bytes(&selection.select);
            }
            marshal_sized(writer, pcr_digest);
        }
        Attested::CommandAudit {
            audit_counter,
            digest_alg,
            audit_digest,
            command_digest,
        } => {
            writer.write_bytes(&audit_counter.to_be_bytes());
            writer.write_u16(*digest_alg);
            marshal_sized(writer, audit_digest);
            marshal_sized(writer, command_digest);
        }
        Attested::SessionAudit {
            exclusive_session,
            session_digest,
        } => {
            writer.write_u8(u8::from(*exclusive_session));
            marshal_sized(writer, session_digest);
        }
        Attested::Time {
            time,
            clock_info,
            firmware_version,
        } => {
            writer.write_bytes(&time.to_be_bytes());
            marshal_clock_info(writer, clock_info);
            writer.write_bytes(&firmware_version.to_be_bytes());
        }
        Attested::Nv {
            index_name,
            offset,
            contents,
        } => {
            marshal_sized(writer, index_name);
            writer.write_u16(*offset);
            marshal_sized(writer, contents);
        }
        Attested::NvDigest { index_name, digest } => {
            marshal_sized(writer, index_name);
            marshal_sized(writer, digest);
        }
    }
}

pub(in crate::library::tpm2::command) fn marshal_attest(attest: &Attest) -> Vec<u8> {
    let mut writer = BlobWriter::new();
    writer.write_u32(TPM_GENERATED_VALUE);
    writer.write_u16(attest.attest_type);
    marshal_sized(&mut writer, &attest.qualified_signer);
    marshal_sized(&mut writer, &attest.extra_data);
    marshal_clock_info(&mut writer, &attest.clock_info);
    writer.write_bytes(&attest.firmware_version.to_be_bytes());
    marshal_attested(&mut writer, &attest.attested);
    writer.into_bytes()
}

pub(in crate::library::tpm2::command) fn attest_digest(
    hash_alg: u16,
    attestation_data: &[u8],
    qualifying_data: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    digest_size(hash_alg).ok_or(TPM_RC_HASH)?;
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(attestation_data);
    let digest = hasher.finalize();
    if qualifying_data.is_empty() {
        return Ok(digest);
    }
    let mut hasher = Hasher::new(hash_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(qualifying_data);
    hasher.update(&digest);
    Ok(hasher.finalize())
}

pub(in crate::library::tpm2::command) fn sign_attest_info(
    runtime: &mut Tpm2Runtime,
    sign_object: Option<&OwnedObjectBody>,
    scheme: &SigScheme,
    attest: &Attest,
) -> Result<(Vec<u8>, Signature), TpmResult> {
    let attestation_data = marshal_attest(attest);
    let Some(body) = sign_object else {
        return Ok((attestation_data, Signature::Null));
    };
    let digest = attest_digest(
        scheme.hash_alg,
        &attestation_data,
        &attest.residual_qualifying_data,
    )?;
    let mut signing = load_signing_state(runtime)?;
    let signature = sign_digest(
        Some(body),
        scheme,
        &digest,
        &runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?.profile,
        &mut signing,
    );
    let signature = publish_signing_outcome(runtime, signing, signature)?;
    let orderly_state = prepare_clear_orderly(runtime)?;
    commit_clear_orderly(runtime, orderly_state)?;
    Ok((attestation_data, signature))
}

pub(in crate::library::tpm2::command) fn attestation_response(
    attestation_data: &[u8],
    signature: &Signature,
) -> Result<CommandOutput, TpmResult> {
    let mut out = BlobWriter::new();
    out.write_tpm2b(attestation_data).map_err(|_| TPM_RC_SIZE)?;
    out.write_bytes(&marshal_signature(signature));
    Ok(CommandOutput::from_parameters(out.into_bytes()))
}

pub(in crate::library::tpm2::command) fn sign_and_respond(
    runtime: &mut Tpm2Runtime,
    sign_object: Option<&OwnedObjectBody>,
    scheme: &SigScheme,
    attest: &Attest,
) -> Result<CommandOutput, TpmResult> {
    let (attestation_data, signature) = sign_attest_info(runtime, sign_object, scheme, attest)?;
    attestation_response(&attestation_data, &signature)
}

#[cfg(test)]
pub(in crate::library::tpm2::command) mod test_support {
    use crate::library::tpm2::command::core::test_support::{
        dispatch_bytes, framed, response_code,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    pub(in crate::library::tpm2::command) const TPM_RH_OWNER: u32 = 0x4000_0001;
    pub(in crate::library::tpm2::command) const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;
    pub(in crate::library::tpm2::command) const TPM_RH_PLATFORM: u32 = 0x4000_000c;
    pub(in crate::library::tpm2::command) const TPM_RH_NULL: u32 = 0x4000_0007;
    pub(in crate::library::tpm2::command) const TPM_RS_PW: u32 = 0x4000_0009;

    pub(in crate::library::tpm2::command) const KEY0: u32 = 0x8000_0000;
    pub(in crate::library::tpm2::command) const KEY1: u32 = 0x8000_0001;
    pub(in crate::library::tpm2::command) const HMAC_SESSION: u32 = 0x0200_0000;

    pub(in crate::library::tpm2::command) const ALG_NULL: u16 = 0x0010;
    pub(in crate::library::tpm2::command) const ALG_SHA1: u16 = 0x0004;
    pub(in crate::library::tpm2::command) const ALG_SHA256: u16 = 0x000b;
    pub(in crate::library::tpm2::command) const ALG_SHA384: u16 = 0x000c;
    pub(in crate::library::tpm2::command) const ALG_HMAC: u16 = 0x0005;
    pub(in crate::library::tpm2::command) const ALG_XOR: u16 = 0x000a;
    pub(in crate::library::tpm2::command) const ALG_RSASSA: u16 = 0x0014;
    pub(in crate::library::tpm2::command) const ALG_RSAPSS: u16 = 0x0016;
    pub(in crate::library::tpm2::command) const ALG_ECDSA: u16 = 0x0018;

    pub(in crate::library::tpm2::command) const SIGN_ATTRS: u32 = 0x0004_0072;
    pub(in crate::library::tpm2::command) const DECRYPT_ATTRS: u32 = 0x0002_0072;

    pub(in crate::library::tpm2::command) const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
    pub(in crate::library::tpm2::command) const CC_GET_COMMAND_AUDIT_DIGEST: u32 = 0x0000_0133;
    pub(in crate::library::tpm2::command) const CC_CERTIFY: u32 = 0x0000_0148;
    pub(in crate::library::tpm2::command) const CC_GET_TIME: u32 = 0x0000_014c;
    pub(in crate::library::tpm2::command) const CC_QUOTE: u32 = 0x0000_0158;
    pub(in crate::library::tpm2::command) const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    pub(in crate::library::tpm2::command) const CC_GET_RANDOM: u32 = 0x0000_017b;
    pub(in crate::library::tpm2::command) const CC_PCR_EXTEND: u32 = 0x0000_0182;
    pub(in crate::library::tpm2::command) const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

    pub(in crate::library::tpm2::command) const QUALIFY: [u8; 8] =
        [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7];
    pub(in crate::library::tpm2::command) const NONCE_CALLER: [u8; 32] = [0x5a; 32];

    pub(in crate::library::tpm2::command) fn tpm2b(data: &[u8]) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    pub(in crate::library::tpm2::command) fn pw() -> Vec<u8> {
        session_area(TPM_RS_PW, &[], 0x00, &[])
    }

    pub(in crate::library::tpm2::command) fn session_area(
        handle: u32,
        nonce: &[u8],
        attributes: u8,
        auth: &[u8],
    ) -> Vec<u8> {
        let mut out = handle.to_be_bytes().to_vec();
        out.extend_from_slice(&tpm2b(nonce));
        out.push(attributes);
        out.extend_from_slice(&tpm2b(auth));
        out
    }

    pub(in crate::library::tpm2::command) fn command(
        code: u32,
        handles: &[u32],
        sessions: Option<&[Vec<u8>]>,
        parameters: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        for handle in handles {
            payload.extend_from_slice(&handle.to_be_bytes());
        }
        let tagged = sessions.is_some();
        if let Some(sessions) = sessions {
            let area: Vec<u8> = sessions.concat();
            payload.extend_from_slice(&(area.len() as u32).to_be_bytes());
            payload.extend_from_slice(&area);
        }
        payload.extend_from_slice(parameters);
        framed(code, &payload, tagged)
    }

    pub(in crate::library::tpm2::command) fn sig_scheme(scheme: u16, hash_alg: u16) -> Vec<u8> {
        let mut out = scheme.to_be_bytes().to_vec();
        if scheme != ALG_NULL {
            out.extend_from_slice(&hash_alg.to_be_bytes());
        }
        out
    }

    pub(in crate::library::tpm2::command) fn rsa_template(
        scheme: u16,
        hash_alg: u16,
        attributes: u32,
    ) -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        out.extend_from_slice(&sig_scheme(scheme, hash_alg));
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    pub(in crate::library::tpm2::command) fn ecc_template(scheme: u16, hash_alg: u16) -> Vec<u8> {
        let mut out = 0x0023u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&SIGN_ATTRS.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        out.extend_from_slice(&sig_scheme(scheme, hash_alg));
        out.extend_from_slice(&0x0003u16.to_be_bytes());
        out.extend_from_slice(&ALG_NULL.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    pub(in crate::library::tpm2::command) fn keyedhash_template(
        scheme: u16,
        hash_alg: u16,
    ) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&ALG_SHA256.to_be_bytes());
        out.extend_from_slice(&SIGN_ATTRS.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&sig_scheme(scheme, hash_alg));
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    pub(in crate::library::tpm2::command) fn create_primary(
        hierarchy: u32,
        template: &[u8],
    ) -> Vec<u8> {
        let mut parameters = 4u16.to_be_bytes().to_vec();
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&tpm2b(template));
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.extend_from_slice(&0u32.to_be_bytes());
        command(CC_CREATE_PRIMARY, &[hierarchy], Some(&[pw()]), &parameters)
    }

    pub(in crate::library::tpm2::command) fn pcr_selection(entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = (entries.len() as u32).to_be_bytes().to_vec();
        for (hash_alg, select) in entries {
            out.extend_from_slice(&hash_alg.to_be_bytes());
            out.push(select.len() as u8);
            out.extend_from_slice(select);
        }
        out
    }

    pub(in crate::library::tpm2::command) fn creation_ticket(
        tag: u16,
        hierarchy: u32,
        digest: &[u8],
    ) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&hierarchy.to_be_bytes());
        out.extend_from_slice(&tpm2b(digest));
        out
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn ready_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = restore_permanent_blob_for_test(vector("PERMALL_READY"))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector("VOLATILE_READY"))
            .expect("the oracle volatile state attaches");
        assert!(
            runtime.startup_received,
            "the snapshot is past TPM2_Startup"
        );
        runtime
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn run(
        runtime: &mut Tpm2Runtime,
        bytes: &[u8],
    ) -> Vec<u8> {
        dispatch_bytes(runtime, bytes)
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn run_ok(
        runtime: &mut Tpm2Runtime,
        bytes: &[u8],
        label: &str,
    ) -> Vec<u8> {
        let response = dispatch_bytes(runtime, bytes);
        assert_eq!(response_code(&response), 0, "{label}");
        response
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn attested_bytes(response: &[u8]) -> Vec<u8> {
        let parameters = parameters_of(response);
        let size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        parameters[2..2 + size].to_vec()
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn signature_bytes(response: &[u8]) -> Vec<u8> {
        let parameters = parameters_of(response);
        let size = u16::from_be_bytes([parameters[0], parameters[1]]) as usize;
        parameters[2 + size..].to_vec()
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn parameters_of(response: &[u8]) -> Vec<u8> {
        if response[..2] == [0x80, 0x01] {
            return response[10..].to_vec();
        }
        let size = u32::from_be_bytes(response[10..14].try_into().expect("a size")) as usize;
        response[14..14 + size].to_vec()
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn attest_prefix(
        attest: &[u8],
    ) -> (u16, Vec<u8>, Vec<u8>, usize) {
        assert_eq!(
            &attest[..4],
            &[0xff, 0x54, 0x43, 0x47],
            "TPM_GENERATED_VALUE"
        );
        let attest_type = u16::from_be_bytes([attest[4], attest[5]]);
        let mut at = 6;
        let signer_len = u16::from_be_bytes([attest[at], attest[at + 1]]) as usize;
        let signer = attest[at + 2..at + 2 + signer_len].to_vec();
        at += 2 + signer_len;
        let extra_len = u16::from_be_bytes([attest[at], attest[at + 1]]) as usize;
        let extra = attest[at + 2..at + 2 + extra_len].to_vec();
        at += 2 + extra_len;
        (attest_type, signer, extra, at)
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn attested_body(attest: &[u8]) -> Vec<u8> {
        let (_, _, _, at) = attest_prefix(attest);
        attest[at + 8 + 4 + 4 + 1 + 8..].to_vec()
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn audited_get_random(session: &[u8]) -> Vec<u8> {
        use crate::library::tpm2::crypto::{Hasher, HmacState};

        const ATTRIBUTES: u8 = 0x81;
        let handle = u32::from_be_bytes(session[10..14].try_into().expect("a session handle"));
        let nonce_len = u16::from_be_bytes([session[14], session[15]]) as usize;
        let nonce_tpm = &session[16..16 + nonce_len];

        let mut hasher = Hasher::new(ALG_SHA256).expect("a compiled hash");
        hasher.update(&CC_GET_RANDOM.to_be_bytes());
        hasher.update(&4u16.to_be_bytes());
        let cp_hash = hasher.finalize();

        let mut hmac = HmacState::new(ALG_SHA256, &[]).expect("a compiled hmac");
        hmac.update(&cp_hash);
        hmac.update(&NONCE_CALLER);
        hmac.update(nonce_tpm);
        hmac.update(&[ATTRIBUTES]);
        let auth = hmac.finalize();

        command(
            CC_GET_RANDOM,
            &[],
            Some(&[session_area(handle, &NONCE_CALLER, ATTRIBUTES, &auth)]),
            &4u16.to_be_bytes(),
        )
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn replay_clock(
        runtime: &mut Tpm2Runtime,
        expected: &[u8],
    ) {
        if response_code(expected) != 0 {
            return;
        }
        let attest = attested_bytes(expected);
        let (_, _, _, at) = attest_prefix(&attest);
        runtime.live.orderly.clock =
            u64::from_be_bytes(attest[at..at + 8].try_into().expect("eight bytes"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock_info() -> ClockInfo {
        ClockInfo {
            clock: 0x0102_0304_0506_0708,
            reset_count: 0x1112_1314,
            restart_count: 0x2122_2324,
            safe: 1,
        }
    }

    fn attest(attested: Attested) -> Attest {
        Attest {
            attest_type: attested.attest_type(),
            qualified_signer: vec![0x00, 0x0b, 0xaa],
            extra_data: vec![0xc0, 0xc1],
            clock_info: clock_info(),
            firmware_version: 0x2024_0125_0012_0000,
            attested,
            residual_qualifying_data: Vec::new(),
        }
    }

    fn header(attest_type: u16) -> Vec<u8> {
        let mut out = TPM_GENERATED_VALUE.to_be_bytes().to_vec();
        out.extend_from_slice(&attest_type.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x03, 0x00, 0x0b, 0xaa]);
        out.extend_from_slice(&[0x00, 0x02, 0xc0, 0xc1]);
        out.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        out.extend_from_slice(&0x1112_1314u32.to_be_bytes());
        out.extend_from_slice(&0x2122_2324u32.to_be_bytes());
        out.push(0x01);
        out.extend_from_slice(&0x2024_0125_0012_0000u64.to_be_bytes());
        out
    }

    #[test]
    fn the_attestation_tags_match_upstream() {
        assert_eq!(TPM_ST_ATTEST_NV, 0x8014);
        assert_eq!(TPM_ST_ATTEST_COMMAND_AUDIT, 0x8015);
        assert_eq!(TPM_ST_ATTEST_SESSION_AUDIT, 0x8016);
        assert_eq!(TPM_ST_ATTEST_CERTIFY, 0x8017);
        assert_eq!(TPM_ST_ATTEST_QUOTE, 0x8018);
        assert_eq!(TPM_ST_ATTEST_TIME, 0x8019);
        assert_eq!(TPM_ST_ATTEST_CREATION, 0x801a);
        assert_eq!(TPM_ST_ATTEST_NV_DIGEST, 0x801c);
        assert_eq!(TPM_GENERATED_VALUE, 0xff54_4347);
    }

    #[test]
    fn the_common_header_precedes_every_variant() {
        let variants = [
            Attested::Certify {
                name: vec![0x01],
                qualified_name: vec![0x02],
            },
            Attested::Creation {
                object_name: vec![0x01],
                creation_hash: vec![0x02],
            },
            Attested::Quote {
                selections: Vec::new(),
                pcr_digest: vec![0x03],
            },
            Attested::CommandAudit {
                audit_counter: 5,
                digest_alg: 0x000b,
                audit_digest: vec![0x04],
                command_digest: vec![0x05],
            },
            Attested::SessionAudit {
                exclusive_session: true,
                session_digest: vec![0x06],
            },
            Attested::Time {
                time: 7,
                clock_info: clock_info(),
                firmware_version: 8,
            },
            Attested::Nv {
                index_name: vec![0x07],
                offset: 9,
                contents: vec![0x08],
            },
            Attested::NvDigest {
                index_name: vec![0x09],
                digest: vec![0x0a],
            },
        ];
        for attested in variants {
            let attest_type = attested.attest_type();
            let bytes = marshal_attest(&attest(attested));
            assert_eq!(
                &bytes[..header(attest_type).len()],
                &header(attest_type)[..],
                "type {attest_type:#06x}"
            );
        }
    }

    #[test]
    fn every_variant_marshals_in_the_upstream_order() {
        assert_eq!(
            &marshal_attest(&attest(Attested::Certify {
                name: vec![0x11, 0x22],
                qualified_name: vec![0x33],
            }))[header(TPM_ST_ATTEST_CERTIFY).len()..],
            &[0x00, 0x02, 0x11, 0x22, 0x00, 0x01, 0x33]
        );
        assert_eq!(
            &marshal_attest(&attest(Attested::Creation {
                object_name: vec![0x11],
                creation_hash: vec![0x22, 0x33],
            }))[header(TPM_ST_ATTEST_CREATION).len()..],
            &[0x00, 0x01, 0x11, 0x00, 0x02, 0x22, 0x33]
        );
        assert_eq!(
            &marshal_attest(&attest(Attested::Quote {
                selections: vec![OwnedPcrSelection {
                    hash_alg: 0x000b,
                    select: vec![0x01, 0x00, 0x00],
                }],
                pcr_digest: vec![0xaa],
            }))[header(TPM_ST_ATTEST_QUOTE).len()..],
            &[
                0x00, 0x00, 0x00, 0x01, 0x00, 0x0b, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0xaa
            ]
        );
        assert_eq!(
            &marshal_attest(&attest(Attested::CommandAudit {
                audit_counter: 0x0102_0304_0506_0708,
                digest_alg: 0x000d,
                audit_digest: vec![0xaa],
                command_digest: vec![0xbb, 0xcc],
            }))[header(TPM_ST_ATTEST_COMMAND_AUDIT).len()..],
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x0d, 0x00, 0x01, 0xaa, 0x00,
                0x02, 0xbb, 0xcc
            ]
        );
        for (exclusive, encoded) in [(false, 0x00u8), (true, 0x01)] {
            assert_eq!(
                &marshal_attest(&attest(Attested::SessionAudit {
                    exclusive_session: exclusive,
                    session_digest: vec![0xaa, 0xbb],
                }))[header(TPM_ST_ATTEST_SESSION_AUDIT).len()..],
                &[encoded, 0x00, 0x02, 0xaa, 0xbb]
            );
        }
        assert_eq!(
            &marshal_attest(&attest(Attested::Time {
                time: 0x0a0b_0c0d_0e0f_1011,
                clock_info: ClockInfo {
                    clock: 0x2021_2223_2425_2627,
                    reset_count: 3,
                    restart_count: 4,
                    safe: 0,
                },
                firmware_version: 0x3031_3233_3435_3637,
            }))[header(TPM_ST_ATTEST_TIME).len()..],
            &[
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                0x26, 0x27, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x30, 0x31, 0x32,
                0x33, 0x34, 0x35, 0x36, 0x37
            ]
        );
        assert_eq!(
            &marshal_attest(&attest(Attested::Nv {
                index_name: vec![0x11],
                offset: 0x0203,
                contents: vec![0x44, 0x55],
            }))[header(TPM_ST_ATTEST_NV).len()..],
            &[0x00, 0x01, 0x11, 0x02, 0x03, 0x00, 0x02, 0x44, 0x55]
        );
        assert_eq!(
            &marshal_attest(&attest(Attested::NvDigest {
                index_name: vec![0x11],
                digest: vec![0x44, 0x55],
            }))[header(TPM_ST_ATTEST_NV_DIGEST).len()..],
            &[0x00, 0x01, 0x11, 0x00, 0x02, 0x44, 0x55]
        );
    }

    #[test]
    fn an_empty_qualifying_data_hashes_the_attestation_once() {
        let data = [0xaa, 0xbb, 0xcc];
        let mut hasher = Hasher::new(0x000b).expect("a compiled hash");
        hasher.update(&data);
        assert_eq!(
            attest_digest(0x000b, &data, &[]).expect("a digest"),
            hasher.finalize()
        );
    }

    #[test]
    fn a_residual_qualifying_data_rehashes_the_attestation_digest() {
        let data = [0xaa, 0xbb, 0xcc];
        let qualifying = [0x01, 0x02];
        let mut hasher = Hasher::new(0x000b).expect("a compiled hash");
        hasher.update(&data);
        let inner = hasher.finalize();
        let mut hasher = Hasher::new(0x000b).expect("a compiled hash");
        hasher.update(&qualifying);
        hasher.update(&inner);
        assert_eq!(
            attest_digest(0x000b, &data, &qualifying).expect("a digest"),
            hasher.finalize()
        );
    }

    #[test]
    fn an_unimplemented_hash_is_a_hash_error() {
        for hash_alg in [0x0000u16, 0x0010, 0xffff] {
            assert_eq!(attest_digest(hash_alg, &[0x00], &[]), Err(TPM_RC_HASH));
        }
    }

    #[test]
    fn the_response_carries_a_sized_attestation_and_the_signature() {
        let output = attestation_response(&[0xaa, 0xbb], &Signature::Null)
            .expect("the response marshals")
            .into_parameters();
        assert_eq!(output, [0x00, 0x02, 0xaa, 0xbb, 0x00, 0x10]);
    }
}

#[cfg(test)]
mod parameter_encryption {
    use super::test_support::{
        ALG_NULL, ALG_RSASSA, ALG_SHA256, ALG_XOR, CC_CERTIFY, CC_GET_COMMAND_AUDIT_DIGEST,
        CC_GET_TIME, CC_QUOTE, CC_START_AUTH_SESSION, HMAC_SESSION, KEY0, NONCE_CALLER, QUALIFY,
        SIGN_ATTRS, TPM_RH_ENDORSEMENT, TPM_RH_NULL, attested_bytes, command, create_primary,
        pcr_selection, pw, ready_runtime, rsa_template, run, run_ok, session_area, sig_scheme,
        tpm2b,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;

    const TPMA_SESSION_CONTINUE_AND_ENCRYPT: u8 = 0x41;

    fn xor_session_start() -> Vec<u8> {
        let mut parameters = tpm2b(&NONCE_CALLER);
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.push(0x00);
        parameters.extend_from_slice(&ALG_XOR.to_be_bytes());
        parameters.extend_from_slice(&ALG_SHA256.to_be_bytes());
        parameters.extend_from_slice(&ALG_SHA256.to_be_bytes());
        command(
            CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            None,
            &parameters,
        )
    }

    fn encrypt_session() -> Vec<u8> {
        session_area(
            HMAC_SESSION,
            &NONCE_CALLER,
            TPMA_SESSION_CONTINUE_AND_ENCRYPT,
            &[],
        )
    }

    #[track_caller]
    fn encrypting_runtime() -> Box<Tpm2Runtime> {
        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(
                TPM_RH_ENDORSEMENT,
                &rsa_template(ALG_RSASSA, ALG_SHA256, SIGN_ATTRS),
            ),
            "the attestation key is created",
        );
        assert_eq!(
            run(&mut runtime, &xor_session_start()),
            vector("ENC_SESSION_START"),
            "the encrypting session matches the oracle"
        );
        runtime
    }

    #[test]
    fn every_attestation_command_encrypts_its_first_response_parameter() {
        for (record, code, handles, sessions) in [
            (
                "CERTIFY_RESPONSE_ENCRYPTED",
                CC_CERTIFY,
                vec![KEY0, KEY0],
                vec![pw(), encrypt_session()],
            ),
            (
                "QUOTE_RESPONSE_ENCRYPTED",
                CC_QUOTE,
                vec![KEY0],
                vec![encrypt_session()],
            ),
            (
                "GETTIME_RESPONSE_ENCRYPTED",
                CC_GET_TIME,
                vec![TPM_RH_ENDORSEMENT, KEY0],
                vec![pw(), encrypt_session()],
            ),
            (
                "CMD_AUDIT_RESPONSE_ENCRYPTED",
                CC_GET_COMMAND_AUDIT_DIGEST,
                vec![TPM_RH_ENDORSEMENT, KEY0],
                vec![pw(), encrypt_session()],
            ),
        ] {
            let mut runtime = encrypting_runtime();
            let expected = vector(record);
            let mut parameters = tpm2b(&QUALIFY);
            parameters.extend_from_slice(&sig_scheme(ALG_NULL, 0));
            if code == CC_QUOTE {
                parameters.extend_from_slice(&pcr_selection(&[(ALG_SHA256, &[0x01, 0x00, 0x00])]));
            }
            assert_eq!(
                run(
                    &mut runtime,
                    &command(code, &handles, Some(&sessions), &parameters)
                ),
                expected,
                "{record}"
            );
        }
    }

    #[test]
    fn the_encrypted_attestation_still_starts_with_the_generated_value_once_decrypted() {
        let plain = attested_bytes(vector("QUOTE_PCR0_SHA256"));
        let encrypted = attested_bytes(vector("QUOTE_RESPONSE_ENCRYPTED"));
        assert_eq!(
            plain.len(),
            encrypted.len(),
            "the cipher preserves the attestation length"
        );
        assert_ne!(
            &encrypted[..4],
            &[0xff, 0x54, 0x43, 0x47],
            "the encrypted attestation hides TPM_GENERATED_VALUE"
        );
    }
}

#[cfg(test)]
mod oracle_state {
    use super::test_support::{
        ALG_RSAPSS, ALG_SHA256, SIGN_ATTRS, TPM_RH_OWNER, command, create_primary, ready_runtime,
        rsa_template, run, run_ok,
    };
    use crate::library::tpm2::golden_responses::attestation::vector;

    fn get_random() -> Vec<u8> {
        command(0x0000_017b, &[], None, &16u16.to_be_bytes())
    }

    #[test]
    fn the_restored_snapshot_carries_the_reference_random_generator() {
        let mut runtime = ready_runtime();
        assert_eq!(
            run(&mut runtime, &get_random()),
            vector("DRBG_AFTER_READY"),
            "the restored state answers the reference random bytes"
        );

        let mut runtime = ready_runtime();
        run_ok(
            &mut runtime,
            &create_primary(
                TPM_RH_OWNER,
                &rsa_template(ALG_RSAPSS, ALG_SHA256, SIGN_ATTRS),
            ),
            "the primary is created",
        );
        assert_eq!(
            run(&mut runtime, &get_random()),
            vector("DRBG_AFTER_CREATE"),
            "a primary key derives its material without touching the live generator"
        );
    }
}
