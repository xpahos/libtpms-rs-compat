use crate::ffi_types::TpmResult;
use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_SIZE};

use super::super::marshal::{BlobReader, BlobWriter, Tpm2bError};
use super::super::runtime::Tpm2Runtime;
use super::super::self_test::self_test_algorithm;
use super::dispatcher::CommandFrame;
use super::hmac_start::{parse_mac_scheme, select_mac};
use super::nv_common::handle_at;
use super::output::CommandOutput;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_BUFFER: TpmResult = TPM_RC_P + TPM_RC_1;

const MAX_DIGEST_BUFFER: usize = 1024;

pub(super) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let handle = handle_at(frame, 0)?;
    let (buffer, in_scheme) = {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    let mac_key = select_mac(runtime, handle, in_scheme)?;
    if let Some(algorithm) = mac_key.self_tested_algorithm() {
        self_test_algorithm(runtime, algorithm)?;
    }

    let digest = mac_key.one_shot(buffer)?;
    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&digest).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<(&'a [u8], u16), TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let buffer = reader
        .read_tpm2b(MAX_DIGEST_BUFFER)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_BUFFER,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_BUFFER,
        })?;
    let in_scheme = parse_mac_scheme(profile_algorithms, &mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok((buffer, in_scheme))
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::golden_responses::hmac::vector;
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::object_load::replay::{
        cap_cc, clock, exec_raw, framed, load_external, password_area, plain, runtime_from, tpm2b,
    };
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::sequence::replay::{RH_NULL, RH_OWNER, create_primary};

    use super::super::registry::{self, CommandLifecycle, HandleKind, NvAccess};

    const CC_HMAC: u32 = 0x0000_0155;
    const CC_HMAC_START: u32 = 0x0000_015b;
    const CC_SEQUENCE_UPDATE: u32 = 0x0000_015c;
    const CC_SEQUENCE_COMPLETE: u32 = 0x0000_013e;

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_HMAC: u16 = 0x0005;
    const TPM_ALG_AES: u16 = 0x0006;
    const TPM_ALG_XOR: u16 = 0x000a;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;
    const TPM_ALG_NULL: u16 = 0x0010;
    const TPM_ALG_KDF1_SP800_108: u16 = 0x0022;
    const TPM_ALG_CMAC: u16 = 0x003f;
    const TPM_ALG_CFB: u16 = 0x0043;

    const HMAC_KEY_ATTR: u32 = 0x0004_0452;
    const SEALED_ATTR: u32 = 0x0000_0452;
    const XOR_KEY_ATTR: u32 = 0x0002_0452;
    const RESTRICTED_ATTR: u32 = 0x0005_0472;
    const RSA_ATTR: u32 = 0x0004_0472;
    const SYM_ATTR: u32 = 0x0006_0452;
    const EXTERNAL_SIGN: u32 = 0x0004_0440;

    const HANDLE: u32 = 0x8000_0000;
    const SEQUENCE: u32 = 0x8000_0001;
    const MESSAGE: &[u8] = b"libtpms-rs stateless crypto";

    fn fresh_clock() -> SteppingClock {
        clock()
    }

    fn key32() -> Vec<u8> {
        (0..32u8).collect()
    }

    fn runtime_at(snapshot: &str, clock: &SteppingClock) -> Box<Tpm2Runtime> {
        runtime_from(
            vector(&format!("PERMALL_{snapshot}")),
            vector(&format!("VOLATILE_{snapshot}")),
            clock,
        )
    }

    #[track_caller]
    fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let response = exec_raw(runtime, clock, bytes);
        assert_eq!(response, vector(label), "{label}");
        response
    }

    fn digest(response: &[u8]) -> &[u8] {
        assert_eq!(response[6..10], [0, 0, 0, 0], "the command succeeded");
        let body = &response[14..];
        let size = usize::from(u16::from_be_bytes([body[0], body[1]]));
        &body[2..2 + size]
    }

    fn keyedhash_public(attributes: u32, scheme: u16, hash_alg: u16, kdf: u16) -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme == TPM_ALG_HMAC {
            out.extend_from_slice(&hash_alg.to_be_bytes());
        } else if scheme == TPM_ALG_XOR {
            out.extend_from_slice(&hash_alg.to_be_bytes());
            out.extend_from_slice(&kdf.to_be_bytes());
        }
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    fn mac(handle: u32, buffer: &[u8], hash_alg: u16) -> Vec<u8> {
        let mut params = tpm2b(buffer);
        params.extend_from_slice(&hash_alg.to_be_bytes());
        mac_raw(handle, &params, &[])
    }

    fn mac_raw(handle: u32, params: &[u8], secret: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&password_area(secret));
        payload.extend_from_slice(params);
        framed(0x8002, CC_HMAC, &payload)
    }

    fn occupied(runtime: &Tpm2Runtime) -> Vec<bool> {
        runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect()
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = registry::find(CC_HMAC).expect("registered");
        assert_eq!(descriptor.attributes, 0x0200_0155);
        assert_eq!(descriptor.decrypt_size, 2);
        assert_eq!(descriptor.encrypt_size, 2);
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.attributes & (1 << 28), 0, "no response handle");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(&mut runtime, &clock, "CAP_CC_HMAC", cap_cc(CC_HMAC));
        let mut payload = 2u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&CC_HMAC.to_be_bytes());
        payload.extend_from_slice(&3u32.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            "CAP_CC_FROM_HMAC",
            plain(0x0000_017a, &payload),
        );
    }

    #[test]
    fn the_command_is_rejected_before_startup() {
        let clock = fresh_clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        exec(
            &mut runtime,
            &clock,
            "HMAC_BEFORE_STARTUP",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );
    }

    #[test]
    fn every_key_scheme_answers_the_sequence_digest() {
        for (label, hash_alg) in [
            ("SHA1", TPM_ALG_SHA1),
            ("SHA256", TPM_ALG_SHA256),
            ("SHA384", TPM_ALG_SHA384),
            ("SHA512", TPM_ALG_SHA512),
        ] {
            let clock = fresh_clock();
            let mut runtime = runtime_at("BASE", &clock);
            exec(
                &mut runtime,
                &clock,
                &format!("A_CREATE_{label}_KEY"),
                create_primary(
                    RH_OWNER,
                    &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, hash_alg, 0),
                    &[],
                    &key32(),
                ),
            );
            let default = exec(
                &mut runtime,
                &clock,
                &format!("A_HMAC_DEFAULT_{label}"),
                mac(HANDLE, MESSAGE, TPM_ALG_NULL),
            );
            let explicit = exec(
                &mut runtime,
                &clock,
                &format!("A_HMAC_EXPLICIT_{label}"),
                mac(HANDLE, MESSAGE, hash_alg),
            );
            assert_eq!(
                digest(&default),
                digest(&explicit),
                "{label} answers the same digest for both scheme forms"
            );
            let empty = exec(
                &mut runtime,
                &clock,
                &format!("A_HMAC_EMPTY_{label}"),
                mac(HANDLE, &[], TPM_ALG_NULL),
            );
            assert_eq!(
                digest(&empty).len(),
                digest(&default).len(),
                "{label} answers a full digest"
            );
            assert_ne!(digest(&empty), digest(&default));
            assert_eq!(
                occupied(&runtime),
                [true, false, false],
                "{label} allocates no sequence slot"
            );
            assert!(!runtime.nv_update_pending, "{label} writes no NV state");

            let mut payload = HANDLE.to_be_bytes().to_vec();
            payload.extend_from_slice(&password_area(&[]));
            payload.extend_from_slice(&tpm2b(&[]));
            payload.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            exec(
                &mut runtime,
                &clock,
                &format!("A_START_{label}"),
                framed(0x8002, CC_HMAC_START, &payload),
            );
            let mut payload = SEQUENCE.to_be_bytes().to_vec();
            payload.extend_from_slice(&password_area(&[]));
            payload.extend_from_slice(&tpm2b(MESSAGE));
            exec(
                &mut runtime,
                &clock,
                &format!("A_UPDATE_{label}"),
                framed(0x8002, CC_SEQUENCE_UPDATE, &payload),
            );
            let mut payload = SEQUENCE.to_be_bytes().to_vec();
            payload.extend_from_slice(&password_area(&[]));
            payload.extend_from_slice(&tpm2b(&[]));
            payload.extend_from_slice(&RH_NULL.to_be_bytes());
            let completed = exec(
                &mut runtime,
                &clock,
                &format!("A_COMPLETE_{label}"),
                framed(0x8002, CC_SEQUENCE_COMPLETE, &payload),
            );
            assert_eq!(
                digest(&completed),
                digest(&default),
                "{label} matches the sequence result"
            );
        }
    }

    #[test]
    fn malformed_and_incompatible_requests_report_the_indexed_errors() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "B_CREATE_SHA256_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &key32(),
            ),
        );
        for (label, hash_alg) in [
            ("B_HMAC_OTHER_HASH", TPM_ALG_SHA384),
            ("B_HMAC_SHA1_ON_SHA256", TPM_ALG_SHA1),
            ("B_HMAC_UNSUPPORTED_HASH", 0x0012),
            ("B_HMAC_ALG_ZERO", 0x0000),
            ("B_HMAC_ALG_FFFF", 0xffff),
            ("B_HMAC_ALG_AES", TPM_ALG_AES),
            ("B_HMAC_CMAC_SCHEME", TPM_ALG_CMAC),
        ] {
            exec(&mut runtime, &clock, label, mac(HANDLE, MESSAGE, hash_alg));
        }
        let maximum = exec(
            &mut runtime,
            &clock,
            "B_HMAC_MAX_BUFFER",
            mac(HANDLE, &[0u8; 1024], TPM_ALG_NULL),
        );
        assert_eq!(digest(&maximum).len(), 32);
        exec(
            &mut runtime,
            &clock,
            "B_HMAC_OVERSIZED_BUFFER",
            mac(HANDLE, &[0u8; 1025], TPM_ALG_NULL),
        );
        for (label, params) in [
            ("B_HMAC_NO_PARAMETERS", Vec::new()),
            ("B_HMAC_TRUNCATED_BUFFER", vec![0x00, 0x04, 0x01, 0x02]),
            ("B_HMAC_TRUNCATED_ALG", {
                let mut params = tpm2b(MESSAGE);
                params.push(0x00);
                params
            }),
            ("B_HMAC_TRAILING", {
                let mut params = tpm2b(MESSAGE);
                params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                params.push(0xee);
                params
            }),
        ] {
            exec(&mut runtime, &clock, label, mac_raw(HANDLE, &params, &[]));
        }
        let mut payload = HANDLE.to_be_bytes().to_vec();
        payload.extend_from_slice(&tpm2b(MESSAGE));
        payload.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            "B_HMAC_NO_SESSIONS",
            plain(CC_HMAC, &payload),
        );
        for (label, handle) in [
            ("B_HMAC_UNLOADED", 0x8000_0002u32),
            ("B_HMAC_PERMANENT", RH_OWNER),
            ("B_HMAC_UNDEFINED_PERSISTENT", 0x8100_0099),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                mac(handle, MESSAGE, TPM_ALG_NULL),
            );
        }
        exec(
            &mut runtime,
            &clock,
            "B_HMAC_TRUNCATED_HANDLE",
            framed(0x8002, CC_HMAC, &[0x80, 0x00, 0x00]),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn wrong_key_kinds_report_the_reference_errors() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_NULL_SCHEME_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(SEALED_ATTR, TPM_ALG_NULL, 0, 0),
                &[],
                &key32(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_HMAC_NULL_SCHEME_KEY",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_XOR_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(
                    XOR_KEY_ATTR,
                    TPM_ALG_XOR,
                    TPM_ALG_SHA256,
                    TPM_ALG_KDF1_SP800_108,
                ),
                &[],
                &key32(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_HMAC_XOR_KEY",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_RESTRICTED_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(RESTRICTED_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &[],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_HMAC_RESTRICTED_KEY",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_RSA_KEY",
            create_primary(RH_OWNER, &rsa_public(), &[], &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "C_HMAC_RSA_KEY",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_SYM_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_ATTR, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &(0..16u8).collect::<Vec<u8>>(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_HMAC_SYM_KEY",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        let mut public = keyedhash_public(EXTERNAL_SIGN, TPM_ALG_HMAC, TPM_ALG_SHA256, 0);
        let length = public.len();
        public[length - 2..].copy_from_slice(&32u16.to_be_bytes());
        public.extend_from_slice(&[0u8; 32]);
        exec(
            &mut runtime,
            &clock,
            "C_LOAD_PUBLIC_ONLY",
            load_external(&[], &public, RH_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "C_HMAC_PUBLIC_ONLY",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );
    }

    fn rsa_public() -> Vec<u8> {
        let mut out = 0x0001u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&RSA_ATTR.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        out.extend_from_slice(&2048u16.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    fn sym_public(attributes: u32, algorithm: u16, key_bits: u16, mode: u16) -> Vec<u8> {
        let mut out = 0x0025u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&algorithm.to_be_bytes());
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    #[test]
    fn a_da_protected_key_counts_failed_authorizations() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "D_CREATE_DA_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(
                    HMAC_KEY_ATTR & !0x0000_0400,
                    TPM_ALG_HMAC,
                    TPM_ALG_SHA256,
                    0,
                ),
                b"key-auth",
                &key32(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "D_HMAC_WRONG_AUTH",
            mac_raw(
                HANDLE,
                &{
                    let mut params = tpm2b(MESSAGE);
                    params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                    params
                },
                b"bad",
            ),
        );
        let succeeded = exec(
            &mut runtime,
            &clock,
            "D_HMAC_RIGHT_AUTH",
            mac_raw(
                HANDLE,
                &{
                    let mut params = tpm2b(MESSAGE);
                    params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                    params
                },
                b"key-auth",
            ),
        );
        assert_eq!(digest(&succeeded).len(), 32);
    }

    #[test]
    fn a_profile_disabled_hash_is_rejected() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("MINIMAL_BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "E_CREATE_SHA256_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &key32(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "E_HMAC_DEFAULT",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "E_HMAC_SHA1_DISABLED",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA1),
        );
        exec(
            &mut runtime,
            &clock,
            "E_HMAC_SHA512_DISABLED",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA512),
        );
    }

    const NONCE_CALLER: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    const SESSION_HANDLE: u32 = 0x0200_0000;
    const CC_START_AUTH_SESSION: u32 = 0x0000_0176;

    fn start_auth_session() -> Vec<u8> {
        let mut payload = RH_NULL.to_be_bytes().to_vec();
        payload.extend_from_slice(&RH_NULL.to_be_bytes());
        payload.extend_from_slice(&tpm2b(&NONCE_CALLER));
        payload.extend_from_slice(&tpm2b(&[]));
        payload.push(0x00);
        payload.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        payload.extend_from_slice(&128u16.to_be_bytes());
        payload.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        payload.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        plain(CC_START_AUTH_SESSION, &payload)
    }

    fn session_nonce(response: &[u8]) -> Vec<u8> {
        let body = &response[14..];
        let size = usize::from(u16::from_be_bytes([body[0], body[1]]));
        body[2..2 + size].to_vec()
    }

    fn parameter_cipher(nonce_tpm: &[u8], data: &[u8]) -> Vec<u8> {
        let material = crate::library::tpm2::crypto::kdfa(
            TPM_ALG_SHA256,
            &[],
            b"CFB\0",
            &NONCE_CALLER,
            nonce_tpm,
            (16 + 16) * 8,
        )
        .expect("the session key derives");
        let mut buffer = data.to_vec();
        crate::library::tpm2::crypto::sym_cfb_encrypt(
            TPM_ALG_AES,
            &material[..16],
            &material[16..],
            &mut buffer,
        )
        .expect("the parameter encrypts");
        buffer
    }

    fn session_command(attributes: u8, parameters: &[u8], mac: &[u8]) -> Vec<u8> {
        let mut sessions = password_area(&[])[4..].to_vec();
        sessions.extend_from_slice(&SESSION_HANDLE.to_be_bytes());
        sessions.extend_from_slice(&tpm2b(&NONCE_CALLER));
        sessions.push(attributes);
        sessions.extend_from_slice(&tpm2b(mac));
        let mut payload = HANDLE.to_be_bytes().to_vec();
        payload.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
        payload.extend_from_slice(&sessions);
        payload.extend_from_slice(parameters);
        framed(0x8002, CC_HMAC, &payload)
    }

    fn session_runtime(clock: &SteppingClock) -> Box<Tpm2Runtime> {
        let mut runtime = runtime_at("BASE", clock);
        exec(
            &mut runtime,
            clock,
            "F_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &key32(),
            ),
        );
        runtime
    }

    #[test]
    fn parameter_encryption_protects_the_buffer_and_the_digest() {
        let clock = fresh_clock();
        let mut runtime = session_runtime(&clock);
        let session = exec(&mut runtime, &clock, "F_SESSION", start_auth_session());
        let nonce_tpm = session_nonce(&session);
        let encrypted = parameter_cipher(&nonce_tpm, MESSAGE);
        assert_ne!(encrypted, MESSAGE, "the request buffer is obscured");
        let mut hidden = tpm2b(&encrypted);
        hidden.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        let mut visible = tpm2b(MESSAGE);
        visible.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());

        let decrypted = exec(
            &mut runtime,
            &clock,
            "F_MAC_DECRYPT_SESSION",
            session_command(0x21, &hidden, &[]),
        );

        let mut runtime = session_runtime(&clock);
        exec(&mut runtime, &clock, "F_SESSION", start_auth_session());
        let encrypted_answer = exec(
            &mut runtime,
            &clock,
            "F_MAC_ENCRYPT_SESSION",
            session_command(0x41, &visible, &[]),
        );
        assert_eq!(digest(&decrypted).len(), digest(&encrypted_answer).len());
        assert_ne!(
            digest(&decrypted),
            digest(&encrypted_answer),
            "the encrypted answer hides the digest"
        );

        let mut runtime = session_runtime(&clock);
        exec(&mut runtime, &clock, "F_SESSION", start_auth_session());
        let both = exec(
            &mut runtime,
            &clock,
            "F_MAC_BOTH_SESSIONS",
            session_command(0x61, &hidden, &[]),
        );
        assert_eq!(
            digest(&both),
            digest(&encrypted_answer),
            "the decrypted buffer answers the same digest"
        );

        let mut runtime = session_runtime(&clock);
        exec(&mut runtime, &clock, "F_SESSION", start_auth_session());
        exec(
            &mut runtime,
            &clock,
            "F_MAC_BAD_SESSION_HMAC",
            session_command(0x41, &visible, &[0u8; 32]),
        );
    }

    #[test]
    fn only_the_hash_self_test_changes_on_success() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "B_CREATE_SHA256_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &key32(),
            ),
        );
        let before = runtime.self_test.pending_algorithms();
        assert!(before.contains(&TPM_ALG_SHA256), "the hash is pending");
        exec(
            &mut runtime,
            &clock,
            "B_HMAC_OTHER_HASH",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA384),
        );
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            before,
            "a rejected scheme runs no self test"
        );
        exec(
            &mut runtime,
            &clock,
            "B_HMAC_MAX_BUFFER",
            mac(HANDLE, &[0u8; 1024], TPM_ALG_NULL),
        );
        let after = runtime.self_test.pending_algorithms();
        assert_eq!(
            after,
            before
                .iter()
                .copied()
                .filter(|&algorithm| algorithm != TPM_ALG_SHA256)
                .collect::<Vec<u16>>(),
            "only the selected hash is tested"
        );
        assert!(!runtime.nv_update_pending);
    }

    const CMAC_SIGN_ATTR: u32 = 0x0004_0452;
    const CMAC_RESTRICTED_ATTR: u32 = 0x0005_0472;
    const TPM_ALG_TDES: u16 = 0x0003;
    const TPM_ALG_CAMELLIA: u16 = 0x0026;

    fn key16() -> Vec<u8> {
        (0..16u8).collect()
    }

    fn key24() -> Vec<u8> {
        (0..24u8).collect()
    }

    fn plain32() -> Vec<u8> {
        vec![
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51,
        ]
    }

    fn cmac_key(algorithm: u16, key_bits: u16) -> Vec<u8> {
        sym_public(CMAC_SIGN_ATTR, algorithm, key_bits, TPM_ALG_CMAC)
    }

    #[test]
    fn a_symmetric_key_answers_a_cmac() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_AES128_CMAC",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_AES, 128), &[], &key16()),
        );
        assert_eq!(
            vector("G_TODO_BEFORE_CMAC"),
            vector("G_TODO_AFTER_CMAC"),
            "the reference leaves its self-test list untouched across a CMAC"
        );
        let pending = runtime.self_test.pending_algorithms();
        let default = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_DEFAULT",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            pending,
            "a CMAC runs no self test"
        );
        assert_eq!(digest(&default).len(), 16, "the digest is one AES block");
        let explicit = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_EXPLICIT",
            mac(HANDLE, MESSAGE, TPM_ALG_CMAC),
        );
        assert_eq!(digest(&explicit), digest(&default));
        let empty = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_EMPTY",
            mac(HANDLE, &[], TPM_ALG_NULL),
        );
        assert_eq!(
            digest(&empty),
            crate::library::tpm2::crypto::CmacState::start(TPM_ALG_AES, 128, &key16())
                .expect("a supported key")
                .finalize()
                .expect("the digest completes"),
            "the empty message answers the bare CMAC"
        );
        let one_block = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_ONE_BLOCK",
            mac(HANDLE, &plain32()[..16], TPM_ALG_NULL),
        );
        let two_blocks = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_TWO_BLOCKS",
            mac(HANDLE, &plain32(), TPM_ALG_NULL),
        );
        assert_ne!(digest(&one_block), digest(&two_blocks));
        let partial = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_PARTIAL",
            mac(HANDLE, &plain32()[..20], TPM_ALG_NULL),
        );
        assert_ne!(digest(&partial), digest(&two_blocks));
        let maximum = exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_MAX",
            mac(HANDLE, &[0u8; 1024], TPM_ALG_NULL),
        );
        assert_eq!(digest(&maximum).len(), 16);
        exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_OVERSIZED",
            mac(HANDLE, &[0u8; 1025], TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "G_MAC_CMAC_HASH_SCHEME",
            mac(HANDLE, MESSAGE, TPM_ALG_SHA256),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a one-shot CMAC allocates no sequence slot"
        );
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn every_cmac_cipher_answers_its_own_digest() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_AES256_CMAC",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_AES, 256), &[], &key32()),
        );
        let aes256 = exec(
            &mut runtime,
            &clock,
            "G_MAC_AES256_CMAC",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );
        assert_eq!(digest(&aes256).len(), 16);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_TDES192_CMAC",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_TDES, 192), &[], &key24()),
        );
        let tdes = exec(
            &mut runtime,
            &clock,
            "G_MAC_TDES192_CMAC",
            mac(0x8000_0001, MESSAGE, TPM_ALG_NULL),
        );
        assert_eq!(digest(&tdes).len(), 8, "TDES answers a 64-bit block");
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_CAMELLIA128_CMAC",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_CAMELLIA, 128), &[], &key16()),
        );
        let camellia = exec(
            &mut runtime,
            &clock,
            "G_MAC_CAMELLIA128_CMAC",
            mac(0x8000_0002, MESSAGE, TPM_ALG_NULL),
        );
        assert_eq!(digest(&camellia).len(), 16);
        assert_ne!(digest(&camellia), digest(&aes256));
    }

    #[test]
    fn a_symmetric_key_selects_its_mac_scheme_like_the_reference() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "H_CREATE_CFB_SIGN_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(CMAC_SIGN_ATTR, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "H_MAC_CFB_DEFAULT",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "H_MAC_CFB_EXPLICIT_CMAC",
            mac(HANDLE, MESSAGE, TPM_ALG_CMAC),
        );

        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "H_CREATE_NULL_MODE_SIGN_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(CMAC_SIGN_ATTR, TPM_ALG_AES, 128, TPM_ALG_NULL),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "H_MAC_NULL_MODE_DEFAULT",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );
        let explicit = exec(
            &mut runtime,
            &clock,
            "H_MAC_NULL_MODE_CMAC",
            mac(HANDLE, MESSAGE, TPM_ALG_CMAC),
        );
        assert_eq!(digest(&explicit).len(), 16);

        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "H_CREATE_RESTRICTED_CMAC",
            create_primary(
                RH_OWNER,
                &sym_public(CMAC_RESTRICTED_ATTR, TPM_ALG_AES, 128, TPM_ALG_CMAC),
                &[],
                &[],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "H_MAC_RESTRICTED_CMAC",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );

        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "H_CREATE_DECRYPT_ONLY_CMAC",
            create_primary(
                RH_OWNER,
                &sym_public(0x0002_0452, TPM_ALG_AES, 128, TPM_ALG_CMAC),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "H_CREATE_NO_SIGN_CMAC",
            create_primary(
                RH_OWNER,
                &sym_public(0x0000_0452, TPM_ALG_AES, 128, TPM_ALG_CMAC),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "H_MAC_NO_SIGN_CMAC",
            mac(HANDLE, MESSAGE, TPM_ALG_NULL),
        );
    }

    #[test]
    fn a_da_protected_cmac_key_counts_failed_authorizations() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "H_CREATE_DA_CMAC",
            create_primary(
                RH_OWNER,
                &sym_public(
                    CMAC_SIGN_ATTR & !0x0000_0400,
                    TPM_ALG_AES,
                    128,
                    TPM_ALG_CMAC,
                ),
                b"cmac-auth",
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "H_MAC_CMAC_WRONG_AUTH",
            mac_raw(
                HANDLE,
                &{
                    let mut params = tpm2b(MESSAGE);
                    params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                    params
                },
                b"bad",
            ),
        );
        let reference = crate::library::tpm2::restore_permanent_blob_for_test(vector(
            "PERMALL_H_AFTER_WRONG_AUTH",
        ))
        .expect("the oracle permanent state restores");
        assert_eq!(
            runtime
                .state
                .as_ref()
                .expect("decoded state")
                .persistent
                .failed_tries,
            reference
                .state
                .as_ref()
                .expect("decoded state")
                .persistent
                .failed_tries,
            "the DA counter follows the reference"
        );
        let succeeded = exec(
            &mut runtime,
            &clock,
            "H_MAC_CMAC_RIGHT_AUTH",
            mac_raw(
                HANDLE,
                &{
                    let mut params = tpm2b(MESSAGE);
                    params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                    params
                },
                b"cmac-auth",
            ),
        );
        assert_eq!(digest(&succeeded).len(), 16);
    }

    #[test]
    fn parameter_encryption_protects_a_cmac_too() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "I_CREATE_CMAC_KEY",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_AES, 128), &[], &key16()),
        );
        let session = exec(&mut runtime, &clock, "I_SESSION", start_auth_session());
        let nonce_tpm = session_nonce(&session);
        let encrypted = parameter_cipher(&nonce_tpm, MESSAGE);
        let mut hidden = tpm2b(&encrypted);
        hidden.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        let mut visible = tpm2b(MESSAGE);
        visible.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        let decrypted = exec(
            &mut runtime,
            &clock,
            "I_MAC_CMAC_DECRYPT_SESSION",
            session_command(0x21, &hidden, &[]),
        );

        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "I_CREATE_CMAC_KEY",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_AES, 128), &[], &key16()),
        );
        exec(&mut runtime, &clock, "I_SESSION", start_auth_session());
        let hidden_answer = exec(
            &mut runtime,
            &clock,
            "I_MAC_CMAC_ENCRYPT_SESSION",
            session_command(0x41, &visible, &[]),
        );
        assert_eq!(digest(&decrypted).len(), digest(&hidden_answer).len());
        assert_ne!(
            digest(&decrypted),
            digest(&hidden_answer),
            "the encrypted answer hides the digest"
        );
    }

    #[test]
    fn a_profile_without_cmac_rejects_the_scheme_and_the_key() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("MINIMAL_BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "E_CREATE_SHA256_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &key32(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "E_MAC_CMAC_DISABLED",
            mac(HANDLE, MESSAGE, TPM_ALG_CMAC),
        );
        exec(
            &mut runtime,
            &clock,
            "E_CREATE_CMAC_KEY_DISABLED",
            create_primary(RH_OWNER, &cmac_key(TPM_ALG_AES, 128), &[], &key16()),
        );
    }

    #[test]
    fn a_malformed_command_never_panics() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "B_CREATE_SHA256_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTR, TPM_ALG_HMAC, TPM_ALG_SHA256, 0),
                &[],
                &key32(),
            ),
        );
        let valid = mac(HANDLE, b"abc", TPM_ALG_SHA256);
        for length in 10..=valid.len() {
            for index in 10..length {
                for flip in [0x01u8, 0x80, 0xff] {
                    let mut mutated = valid[..length].to_vec();
                    mutated[index] ^= flip;
                    let size = (mutated.len() as u32).to_be_bytes();
                    mutated[2..6].copy_from_slice(&size);
                    let _ = exec_raw(&mut runtime, &clock, mutated);
                }
            }
        }
    }
}
