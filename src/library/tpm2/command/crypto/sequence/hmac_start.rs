use super::hash_start::parse_auth;
use crate::ffi_types::TpmResult;
use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_KEY, TPM_RC_SCHEME, TPM_RC_SIZE,
    TPM_RC_SYMMETRIC, TPM_RC_TYPE, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{TPM_ALG_CMAC, algorithm_enabled, hash_profile_name};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::crypto::COMPILED_HASHES;
use crate::library::tpm2::marshal::BlobReader;
use crate::library::tpm2::object_create::{is_persistent_object_handle, resolve_any_object};
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedSecret};
use crate::library::tpm2::public::{
    PublicParms, TPM_ALG_KEYEDHASH, TPM_ALG_NULL, TPM_ALG_SYMCIPHER,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::sequence::{
    MacKey, SequenceKind, allocate_sequence_slot, init_mac_sequence, reserve_evict_slot,
};
use crate::library::tpm2::template::{TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SIGN};

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const RC_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_AUTH: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_IN_SCHEME: TpmResult = TPM_RC_P + TPM_RC_2;

struct MacStartIn<'a> {
    auth: &'a [u8],
    in_scheme: u16,
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = frame.handles.first().copied().ok_or(TPM_RC_FAILURE)?;
    let input = {
        // TODO: Support runtimes without decoded state after the NVChip fallback
        // is implemented.
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        parse_parameters(&state.profile.algorithms, frame.parameters)?
    };

    let mac_key = select_mac(runtime, key_handle, input.in_scheme)?;

    if is_persistent_object_handle(key_handle) {
        let attributes = resolve_any_object(runtime, key_handle)
            .ok_or(TPM_RC_FAILURE)?
            .attributes;
        reserve_evict_slot(runtime, attributes)?;
    }
    let allocated = allocate_sequence_slot(runtime, SequenceKind::Hmac, input.auth)?;
    if let Some(algorithm) = mac_key.self_tested_algorithm() {
        self_test_algorithm(runtime, algorithm)?;
    }
    init_mac_sequence(runtime, allocated.slot, &mac_key)?;

    Ok(CommandOutput::with_handle(allocated.handle, Vec::new()))
}

pub(in crate::library::tpm2::command::crypto) fn select_mac(
    runtime: &Tpm2Runtime,
    key_handle: u32,
    in_scheme: u16,
) -> Result<MacKey, TpmResult> {
    let object = resolve_any_object(runtime, key_handle).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_TYPE + RC_HANDLE);
    };
    let symmetric = match &body.public.parameters {
        PublicParms::KeyedHash(_) if body.public.object_type == TPM_ALG_KEYEDHASH => None,
        PublicParms::SymCipher(symmetric) if body.public.object_type == TPM_ALG_SYMCIPHER => {
            Some(*symmetric)
        }
        _ => return Err(TPM_RC_TYPE + RC_HANDLE),
    };
    let key_alg = match (&body.public.parameters, symmetric) {
        (_, Some(symmetric)) => symmetric.mode.unwrap_or(TPM_ALG_NULL),
        (PublicParms::KeyedHash(scheme), None) if scheme.scheme != TPM_ALG_NULL => {
            scheme.hash_alg.unwrap_or(TPM_ALG_NULL)
        }
        _ => TPM_ALG_NULL,
    };
    let mac_alg = if in_scheme != TPM_ALG_NULL {
        if key_alg != TPM_ALG_NULL && in_scheme != key_alg {
            return Err(TPM_RC_VALUE + RC_IN_SCHEME);
        }
        in_scheme
    } else {
        if key_alg == TPM_ALG_NULL {
            return Err(TPM_RC_VALUE + RC_IN_SCHEME);
        }
        key_alg
    };
    let compatible = match symmetric {
        Some(_) => mac_alg == TPM_ALG_CMAC,
        None => COMPILED_HASHES.iter().any(|&(alg, _)| alg == mac_alg),
    };
    if !compatible {
        return Err(TPM_RC_SCHEME + RC_IN_SCHEME);
    }

    if body.public.object_attributes & TPMA_OBJECT_RESTRICTED != 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_HANDLE);
    }
    if body.public.object_attributes & TPMA_OBJECT_SIGN == 0 {
        return Err(TPM_RC_KEY + RC_HANDLE);
    }

    let key = body
        .sensitive
        .sensitive
        .as_ref()
        .map(|secret| OwnedSecret::copy_of(secret.as_bytes()))
        .unwrap_or_else(|| OwnedSecret::from_vec(Vec::new()));
    Ok(match symmetric {
        Some(symmetric) => MacKey::Cmac {
            algorithm: symmetric.algorithm,
            key_bits: symmetric.key_bits.unwrap_or(0),
            key,
        },
        None => MacKey::Hmac {
            hash_alg: mac_alg,
            key,
        },
    })
}

pub(in crate::library::tpm2::command::crypto) fn parse_mac_scheme(
    profile_algorithms: &[u8],
    reader: &mut BlobReader<'_>,
) -> Result<u16, TpmResult> {
    let in_scheme = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_IN_SCHEME)?;
    if in_scheme == TPM_ALG_NULL {
        return Ok(in_scheme);
    }
    let enabled = if in_scheme == TPM_ALG_CMAC {
        algorithm_enabled(profile_algorithms, b"cmac")
    } else {
        COMPILED_HASHES.iter().any(|&(alg, _)| alg == in_scheme)
            && hash_profile_name(in_scheme)
                .is_some_and(|name| algorithm_enabled(profile_algorithms, name))
    };
    if !enabled {
        return Err(TPM_RC_SYMMETRIC + RC_IN_SCHEME);
    }
    Ok(in_scheme)
}

fn parse_parameters<'a>(
    profile_algorithms: &[u8],
    parameters: &'a [u8],
) -> Result<MacStartIn<'a>, TpmResult> {
    let mut reader = BlobReader::new(parameters);
    let auth = parse_auth(&mut reader, RC_AUTH)?;
    let in_scheme = parse_mac_scheme(profile_algorithms, &mut reader)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(MacStartIn { auth, in_scheme })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{self, HandleKind, TPM_CC_HMAC_START};
    use crate::library::tpm2::object::ATTR_OCCUPIED;
    use crate::library::tpm2::sequence::replay::clock as fresh_clock;
    use crate::library::tpm2::sequence::replay::{self, *};

    const TPM_ALG_SHA1: u16 = 0x0004;
    const TPM_ALG_SHA256: u16 = 0x000b;
    const TPM_ALG_SHA384: u16 = 0x000c;
    const TPM_ALG_SHA512: u16 = 0x000d;

    fn occupied(runtime: &Tpm2Runtime) -> Vec<bool> {
        runtime
            .live
            .objects
            .iter()
            .map(|object| object.attributes & ATTR_OCCUPIED != 0)
            .collect()
    }

    fn failed_tries(runtime: &Tpm2Runtime) -> u32 {
        runtime
            .state
            .as_ref()
            .expect("decoded state")
            .persistent
            .failed_tries
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        assert_eq!(TPM_CC_HMAC_START, 0x0000_015b);
        let descriptor = registry::find(TPM_CC_HMAC_START).expect("registered");
        assert_eq!(descriptor.attributes, 0x1200_015b);
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert_ne!(descriptor.attributes & (1 << 28), 0, "a response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NVRAM update");
        assert_eq!(descriptor.attributes & (1 << 23), 0, "not extensive");
        assert_eq!(descriptor.attributes & (1 << 24), 0, "no flushed handle");
        assert_eq!((descriptor.attributes >> 25) & 0x7, 1, "one command handle");
        assert_eq!(descriptor.handles.len(), 1);
        assert!(descriptor.handles[0].user_auth);
        assert!(!descriptor.handles[0].admin_role());
        assert!(matches!(descriptor.handles[0].kind, HandleKind::Object));
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        let mut params = 2u32.to_be_bytes().to_vec();
        params.extend_from_slice(&0x015bu32.to_be_bytes());
        params.extend_from_slice(&1u32.to_be_bytes());
        exec(
            &mut runtime,
            &clock,
            "CAP_CC_HMAC_START",
            command(0x8001, 0x0000_017a, &params),
        );
    }

    #[test]
    fn the_command_is_rejected_before_startup() {
        let clock = fresh_clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        runtime.entropy = unreachable_entropy;
        exec(
            &mut runtime,
            &clock,
            "HMS_BEFORE_STARTUP",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );
    }

    fn key_runtime(
        clock: &crate::library::tpm2::clock::SteppingClock,
        label: &str,
        public: &[u8],
    ) -> Box<Tpm2Runtime> {
        let mut runtime = base_runtime(clock);
        exec(
            &mut runtime,
            clock,
            label,
            create_primary(RH_OWNER, public, &[], &[]),
        );
        runtime
    }

    #[test]
    fn a_keyed_hash_key_starts_and_completes_an_hmac_sequence() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "Q_CREATE_HMAC_KEY", &hmac_key(TPM_ALG_SHA256));
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_DEFAULT",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        assert_eq!(occupied(&runtime), [true, true, false]);
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_UPDATE",
            sequence_update(0x8000_0001, b"abc", &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_UPDATE_SECOND",
            sequence_update(0x8000_0001, MESSAGE, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_COMPLETE",
            sequence_complete(0x8000_0001, b" tail", RH_OWNER, &[]),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "the key survives, the sequence is released"
        );
    }

    #[test]
    fn the_requested_scheme_must_match_the_key_scheme() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "Q_CREATE_HMAC_KEY", &hmac_key(TPM_ALG_SHA256));
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_MATCHING_ALG",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_COMPLETE_EMPTY",
            sequence_complete(0x8000_0001, b"", RH_NULL, &[]),
        );

        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "Q_CREATE_HMAC_KEY", &hmac_key(TPM_ALG_SHA256));
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_MISMATCHED_ALG",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA384),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_UNSUPPORTED_ALG",
            mac_start(0x8000_0000, &[], 0x0012),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a refused scheme allocates nothing"
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_AUTH_65",
            mac_start(0x8000_0000, &[b'a'; 65], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_AUTH_64",
            mac_start(0x8000_0000, &[b'a'; 64], TPM_ALG_SHA256),
        );
    }

    #[test]
    fn every_key_scheme_hash_produces_the_reference_mac() {
        for (label, hash_alg, start, update, complete) in [
            (
                "R_CREATE_SHA384_KEY",
                TPM_ALG_SHA384,
                "R_HMS_SHA384",
                "R_HMAC_UPDATE",
                "R_HMAC_COMPLETE",
            ),
            (
                "S_CREATE_SHA1_KEY",
                TPM_ALG_SHA1,
                "S_HMS_SHA1",
                "S_HMAC_UPDATE",
                "S_HMAC_COMPLETE",
            ),
            (
                "T_CREATE_SHA512_KEY",
                TPM_ALG_SHA512,
                "T_HMS_SHA512",
                "T_UPDATE_SHA512",
                "T_COMPLETE_SHA512",
            ),
        ] {
            let clock = fresh_clock();
            let mut runtime = base_runtime(&clock);
            if label == "T_CREATE_SHA512_KEY" {
                exec(
                    &mut runtime,
                    &clock,
                    "T_CREATE_NULL_SCHEME_KEY",
                    create_primary(
                        RH_OWNER,
                        &keyedhash_public(HMAC_KEY_ATTRIBUTES, replay::TPM_ALG_NULL, 0),
                        &[],
                        &[],
                    ),
                );
            }
            exec(
                &mut runtime,
                &clock,
                label,
                create_primary(RH_OWNER, &hmac_key(hash_alg), &[], &[]),
            );
            exec(
                &mut runtime,
                &clock,
                start,
                mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
            );
            exec(
                &mut runtime,
                &clock,
                update,
                sequence_update(0x8000_0001, MESSAGE, &[]),
            );
            exec(
                &mut runtime,
                &clock,
                complete,
                sequence_complete(0x8000_0001, b" tail", RH_NULL, &[]),
            );
        }
    }

    #[test]
    fn a_cmac_scheme_is_incompatible_with_a_keyed_hash_key() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "T_CREATE_NULL_SCHEME_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(HMAC_KEY_ATTRIBUTES, replay::TPM_ALG_NULL, 0),
                &[],
                &[],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "T_CREATE_SHA512_KEY",
            create_primary(RH_OWNER, &hmac_key(TPM_ALG_SHA512), &[], &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "T_HMS_SHA512_EXPLICIT",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA512),
        );
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "T_CREATE_SHA512_KEY", &hmac_key(TPM_ALG_SHA512));
        exec(
            &mut runtime,
            &clock,
            "T_HMS_CMAC_SCHEME",
            mac_start(0x8000_0000, &[], 0x003f),
        );
    }

    #[test]
    fn wrong_key_kinds_report_the_reference_errors() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(
            &clock,
            "U_CREATE_RESTRICTED_KEY",
            &keyedhash_public(RESTRICTED_KEY_ATTRIBUTES, 0x0005, TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "U_HMS_RESTRICTED",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "U_CREATE_SEALED_OBJECT",
            create_primary(
                RH_OWNER,
                &keyedhash_public(SEALED_ATTRIBUTES, replay::TPM_ALG_NULL, 0),
                &[],
                b"sealed secret bytes",
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "U_HMS_SEALED_OBJECT",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "U_HMS_SEALED_OBJECT_NULL",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );

        let clock = fresh_clock();
        let mut runtime = key_runtime(
            &clock,
            "U_CREATE_XOR_KEY",
            &keyedhash_public(XOR_KEY_ATTRIBUTES, 0x000a, TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "U_HMS_XOR_KEY",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );

        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "U_CREATE_RSA_KEY", &rsa_storage_public());
        exec(
            &mut runtime,
            &clock,
            "U_HMS_RSA_KEY",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn the_sequence_authorization_travels_with_the_new_object() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "Q_CREATE_HMAC_KEY", &hmac_key(TPM_ALG_SHA256));
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_WITH_AUTH",
            mac_start(0x8000_0000, b"hmac-auth", TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_UPDATE_WRONG_AUTH",
            sequence_update(0x8000_0001, b"abc", b"nope"),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_UPDATE_RIGHT_AUTH",
            sequence_update(0x8000_0001, b"abc", b"hmac-auth"),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMAC_COMPLETE_RIGHT_AUTH",
            sequence_complete(0x8000_0001, b"", RH_NULL, b"hmac-auth"),
        );
    }

    #[test]
    fn malformed_parameters_and_handles_report_the_indexed_errors() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "Q_CREATE_HMAC_KEY", &hmac_key(TPM_ALG_SHA256));
        for (label, params) in [
            ("Q_HMS_NO_PARAMETERS", vec![]),
            ("Q_HMS_TRUNCATED_AUTH", vec![0x00, 0x03, 0x61, 0x62]),
            ("Q_HMS_TRUNCATED_ALG", vec![0x00, 0x00, 0x00]),
            ("Q_HMS_TRAILING", vec![0x00, 0x00, 0x00, 0x0b, 0xee]),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                mac_start_raw(0x8000_0000, &params, &[]),
            );
        }
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_UNLOADED",
            mac_start(0x8000_0002, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_PERMANENT",
            mac_start(RH_OWNER, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "Q_HMS_UNDEFINED_PERSISTENT",
            mac_start(0x8100_0099, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "L_HMS_TRUNCATED_HANDLE",
            command(0x8002, TPM_CC_HMAC_START, &[0x80, 0x00, 0x00]),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn a_persistent_key_consumes_a_transient_slot_like_the_reference() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "V_CREATE_KEY", &hmac_key(TPM_ALG_SHA256));
        exec(
            &mut runtime,
            &clock,
            "V_EVICT_KEY",
            evict_control(0x8000_0000, 0x8100_0010),
        );
        exec(
            &mut runtime,
            &clock,
            "V_FLUSH_TRANSIENT",
            flush_context(0x8000_0000),
        );
        let (permanent, volatile) = state_blobs(&runtime, &clock);
        drop(runtime);

        let clock = fresh_clock();
        let mut runtime = reload(&permanent, &volatile, &clock);
        exec(
            &mut runtime,
            &clock,
            "V_HMS_PERSISTENT",
            mac_start(0x8100_0010, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "V_HMAC_UPDATE",
            sequence_update(0x8000_0001, MESSAGE, &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "V_HMAC_COMPLETE",
            sequence_complete(0x8000_0001, b" tail", RH_NULL, &[]),
        );

        let clock = fresh_clock();
        let mut runtime = reload(&permanent, &volatile, &clock);
        exec(
            &mut runtime,
            &clock,
            "V_FILL_1",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "V_FILL_2",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "V_HMS_PERSISTENT_LAST_SLOT",
            mac_start(0x8100_0010, &[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "V_HMS_TRANSIENT_LAST_SLOT",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
    }

    #[test]
    fn a_transient_key_leaves_no_slot_for_a_third_sequence() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "V_CREATE_TRANSIENT_KEY", &hmac_key(TPM_ALG_SHA256));
        exec(
            &mut runtime,
            &clock,
            "V_TRANSIENT_FILL_1",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "V_TRANSIENT_FILL_2",
            hash_sequence_start(&[], TPM_ALG_SHA256),
        );
        exec(
            &mut runtime,
            &clock,
            "V_HMS_TRANSIENT_NO_SLOT",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA256),
        );
        assert_eq!(occupied(&runtime), [true, true, true]);
    }

    #[test]
    fn a_da_protected_key_counts_failed_authorizations() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "W_CREATE_DA_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(DA_KEY_ATTRIBUTES, 0x0005, TPM_ALG_SHA256),
                b"key-auth",
                &[],
            ),
        );
        assert_eq!(failed_tries(&runtime), 0);
        exec(
            &mut runtime,
            &clock,
            "W_HMS_WRONG_AUTH",
            mac_start_raw(
                0x8000_0000,
                &{
                    let mut params = tpm2b(&[]);
                    params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                    params
                },
                b"bad",
            ),
        );
        assert_eq!(failed_tries(&runtime), 1, "the failure is recorded");
        exec(
            &mut runtime,
            &clock,
            "W_HMS_WRONG_AUTH_SECOND",
            mac_start_raw(
                0x8000_0000,
                &{
                    let mut params = tpm2b(&[]);
                    params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                    params
                },
                b"bad2",
            ),
        );
        assert_eq!(failed_tries(&runtime), 2);
        exec(
            &mut runtime,
            &clock,
            "W_HMS_RIGHT_AUTH",
            mac_start_raw(
                0x8000_0000,
                &{
                    let mut params = tpm2b(&[]);
                    params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                    params
                },
                b"key-auth",
            ),
        );
        assert_eq!(occupied(&runtime), [true, true, false]);
    }

    #[test]
    fn a_profile_disabled_scheme_reports_the_symmetric_error() {
        let clock = fresh_clock();
        let mut runtime = minimal_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "X_CREATE_SHA1_HMAC_KEY",
            create_primary(RH_OWNER, &hmac_key(TPM_ALG_SHA1), &[], &[]),
        );

        let clock = fresh_clock();
        let mut runtime = minimal_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "X_CREATE_HMAC_KEY",
            create_primary(RH_OWNER, &hmac_key(TPM_ALG_SHA256), &[], &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "X_HMS_SHA1_REQUESTED",
            mac_start(0x8000_0000, &[], TPM_ALG_SHA1),
        );
        exec(
            &mut runtime,
            &clock,
            "X_HMS_DEFAULT",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "X_HMAC_COMPLETE",
            sequence_complete(0x8000_0001, MESSAGE, RH_NULL, &[]),
        );
    }

    const TPM_ALG_CMAC_SCHEME: u16 = 0x003f;
    const TPM_ALG_AES: u16 = 0x0006;
    const TPM_ALG_TDES: u16 = 0x0003;
    const TPM_ALG_CFB: u16 = 0x0043;
    const CMAC_SIGN_ATTRIBUTES: u32 = 0x0004_0452;
    const CMAC_MESSAGE: &[u8] = b"libtpms-rs stateless crypto";

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

    fn mac_digest(response: &[u8]) -> &[u8] {
        assert_eq!(response[6..10], [0, 0, 0, 0], "the command succeeded");
        let body = &response[14..];
        let size = usize::from(u16::from_be_bytes([body[0], body[1]]));
        &body[2..2 + size]
    }

    fn cmac_runtime(clock: &crate::library::tpm2::clock::SteppingClock) -> Box<Tpm2Runtime> {
        let mut runtime = base_runtime(clock);
        exec(
            &mut runtime,
            clock,
            "Y_CREATE_CMAC_KEY",
            create_primary(
                RH_OWNER,
                &symcipher_public(CMAC_SIGN_ATTRIBUTES, TPM_ALG_AES, 128, TPM_ALG_CMAC_SCHEME),
                &[],
                &key16(),
            ),
        );
        runtime
    }

    #[test]
    fn a_cmac_sequence_answers_the_one_shot_digest() {
        let clock = fresh_clock();
        let mut runtime = cmac_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_DEFAULT",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        assert_eq!(occupied(&runtime), [true, true, false]);
        let (_, volatile) = state_blobs(&runtime, &clock);
        assert_eq!(
            object_region(&volatile),
            object_region(vector("VOLATILE_Y_AFTER_START")),
            "the serialized CMAC sequence matches the reference"
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_UPDATE",
            sequence_update(0x8000_0001, &CMAC_MESSAGE[..10], &[]),
        );
        let (_, volatile) = state_blobs(&runtime, &clock);
        assert_eq!(
            object_region(&volatile),
            object_region(vector("VOLATILE_Y_AFTER_UPDATE")),
            "an updated CMAC sequence keeps the reference image"
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_UPDATE_SECOND",
            sequence_update(0x8000_0001, &CMAC_MESSAGE[10..], &[]),
        );
        let completed = exec(
            &mut runtime,
            &clock,
            "Y_CMAC_COMPLETE",
            sequence_complete(0x8000_0001, &[], RH_NULL, &[]),
        );
        assert_eq!(
            mac_digest(&completed).len(),
            16,
            "the digest is one AES block"
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a completed sequence is flushed"
        );

        let clock = fresh_clock();
        let mut runtime = cmac_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_TAIL",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        let one_shot = exec(
            &mut runtime,
            &clock,
            "Y_CMAC_COMPLETE_ONE_SHOT",
            sequence_complete(0x8000_0001, CMAC_MESSAGE, RH_NULL, &[]),
        );
        assert_eq!(
            mac_digest(&one_shot),
            mac_digest(&completed),
            "the split updates answer the single-buffer digest"
        );
    }

    #[test]
    fn a_cmac_sequence_handles_every_message_shape() {
        let clock = fresh_clock();
        let mut runtime = cmac_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_EXPLICIT",
            mac_start(0x8000_0000, b"cmac-auth", TPM_ALG_CMAC_SCHEME),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_UPDATE_WRONG_AUTH",
            sequence_update(0x8000_0001, CMAC_MESSAGE, b"bad"),
        );
        let empty = exec(
            &mut runtime,
            &clock,
            "Y_CMAC_COMPLETE_EMPTY",
            sequence_complete(0x8000_0001, &[], RH_NULL, b"cmac-auth"),
        );
        assert_eq!(mac_digest(&empty).len(), 16);

        let clock = fresh_clock();
        let mut runtime = cmac_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_BLOCKS",
            mac_start(0x8000_0000, &[], TPM_ALG_CMAC_SCHEME),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_UPDATE_BLOCK",
            sequence_update(0x8000_0001, &plain32()[..16], &[]),
        );
        let blocks = exec(
            &mut runtime,
            &clock,
            "Y_CMAC_COMPLETE_BLOCK",
            sequence_complete(0x8000_0001, &plain32()[16..], RH_NULL, &[]),
        );
        assert_ne!(mac_digest(&blocks), mac_digest(&empty));
    }

    #[test]
    fn a_cmac_sequence_saves_and_flushes_like_the_reference() {
        let clock = fresh_clock();
        let mut runtime = cmac_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_FLUSHED",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_CONTEXT_SAVE",
            context_save(0x8000_0001),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_FLUSH",
            flush_context(0x8000_0001),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
        let (_, volatile) = state_blobs(&runtime, &clock);
        assert_eq!(
            object_region(&volatile),
            object_region(vector("VOLATILE_Y_AFTER_FLUSH")),
            "the flushed slot matches the reference"
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_UPDATE_FLUSHED",
            sequence_update(0x8000_0001, CMAC_MESSAGE, &[]),
        );
    }

    #[test]
    fn a_triple_des_cmac_sequence_answers_a_short_digest() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_CREATE_TDES_CMAC",
            create_primary(
                RH_OWNER,
                &symcipher_public(CMAC_SIGN_ATTRIBUTES, TPM_ALG_TDES, 192, TPM_ALG_CMAC_SCHEME),
                &[],
                &key24(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_TDES",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_CMAC_TDES_UPDATE",
            sequence_update(0x8000_0001, CMAC_MESSAGE, &[]),
        );
        let completed = exec(
            &mut runtime,
            &clock,
            "Y_CMAC_TDES_COMPLETE",
            sequence_complete(0x8000_0001, &[], RH_NULL, &[]),
        );
        assert_eq!(mac_digest(&completed).len(), 8);
    }

    #[test]
    fn a_symmetric_key_without_a_cmac_scheme_starts_no_sequence() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_CREATE_CFB_SIGN_KEY",
            create_primary(
                RH_OWNER,
                &symcipher_public(CMAC_SIGN_ATTRIBUTES, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_CFB_KEY",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_CFB_EXPLICIT_CMAC",
            mac_start(0x8000_0000, &[], TPM_ALG_CMAC_SCHEME),
        );
        assert_eq!(
            occupied(&runtime),
            [true, false, false],
            "a refused scheme allocates no sequence slot"
        );

        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Y_CREATE_NO_SIGN_CMAC",
            create_primary(
                RH_OWNER,
                &symcipher_public(0x0000_0452, TPM_ALG_AES, 128, TPM_ALG_CMAC_SCHEME),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "Y_MAC_START_NO_SIGN",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
    }

    fn saved_context(response: &[u8]) -> Vec<u8> {
        assert_eq!(response[6..10], [0, 0, 0, 0], "the context was saved");
        response[10..].to_vec()
    }

    fn context_load(context: &[u8]) -> Vec<u8> {
        command(0x8001, 0x0000_0161, context)
    }

    fn transient_handles() -> Vec<u8> {
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0x8000_0000u32.to_be_bytes());
        payload.extend_from_slice(&8u32.to_be_bytes());
        command(0x8001, 0x0000_017a, &payload)
    }

    #[test]
    fn a_saved_cmac_context_loads_without_resuming_the_sequence() {
        let clock = fresh_clock();
        let mut runtime = cmac_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Z_MAC_START",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_CMAC_UPDATE",
            sequence_update(0x8000_0001, &CMAC_MESSAGE[..10], &[]),
        );
        let saved = exec(
            &mut runtime,
            &clock,
            "Z_CMAC_CONTEXT_SAVE",
            context_save(0x8000_0001),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_CMAC_FLUSH",
            flush_context(0x8000_0001),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_TRANSIENT_BEFORE_LOAD",
            transient_handles(),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
        exec(
            &mut runtime,
            &clock,
            "Z_CMAC_CONTEXT_LOAD",
            context_load(&saved_context(&saved)),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_TRANSIENT_AFTER_LOAD",
            transient_handles(),
        );
        assert_eq!(
            occupied(&runtime),
            [true, true, false],
            "the reference allocates the slot the context asked for"
        );
        let response = exec_raw(
            &mut runtime,
            &clock,
            sequence_complete(0x8000_0001, &[], RH_NULL, &[]),
        );
        assert_eq!(
            response[6..10],
            [0x00, 0x00, 0x01, 0x01],
            "the restored sequence carries no CMAC value"
        );
    }

    #[test]
    fn a_saved_hash_or_hmac_sequence_still_resumes() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Z_HASH_START",
            hash_sequence_start(&[], 0x000b),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HASH_UPDATE",
            sequence_update(0x8000_0000, &CMAC_MESSAGE[..10], &[]),
        );
        let saved = exec(
            &mut runtime,
            &clock,
            "Z_HASH_CONTEXT_SAVE",
            context_save(0x8000_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HASH_FLUSH",
            flush_context(0x8000_0000),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HASH_CONTEXT_LOAD",
            context_load(&saved_context(&saved)),
        );
        let completed = exec(
            &mut runtime,
            &clock,
            "Z_HASH_COMPLETE_LOADED",
            sequence_complete(0x8000_0000, &CMAC_MESSAGE[10..], RH_NULL, &[]),
        );
        assert_eq!(mac_digest(&completed).len(), 32);

        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "Z_CREATE_HMAC_KEY",
            create_primary(
                RH_OWNER,
                &keyedhash_public(CMAC_SIGN_ATTRIBUTES, 0x0005, 0x000b),
                &[],
                &(0..32u8).collect::<Vec<u8>>(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HMAC_START",
            mac_start(0x8000_0000, &[], replay::TPM_ALG_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HMAC_UPDATE",
            sequence_update(0x8000_0001, &CMAC_MESSAGE[..10], &[]),
        );
        let saved = exec(
            &mut runtime,
            &clock,
            "Z_HMAC_CONTEXT_SAVE",
            context_save(0x8000_0001),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HMAC_FLUSH",
            flush_context(0x8000_0001),
        );
        exec(
            &mut runtime,
            &clock,
            "Z_HMAC_CONTEXT_LOAD",
            context_load(&saved_context(&saved)),
        );
        let completed = exec(
            &mut runtime,
            &clock,
            "Z_HMAC_COMPLETE_LOADED",
            sequence_complete(0x8000_0001, &CMAC_MESSAGE[10..], RH_NULL, &[]),
        );
        assert_eq!(
            mac_digest(&completed).len(),
            32,
            "an HMAC sequence resumes from its context"
        );
    }

    #[test]
    fn volatile_state_with_a_live_cmac_sequence_is_refused() {
        let clock = fresh_clock();
        let restored =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_Y_AFTER_START"));
        let mut runtime = restored.expect("the oracle permanent state restores");
        assert!(
            crate::library::tpm2::attach_volatile_blob_for_replay(
                &mut runtime,
                vector("VOLATILE_Y_AFTER_START"),
                &clock,
            )
            .is_err(),
            "an unusable CMAC sequence never becomes a live object"
        );
        let mut runtime = crate::library::tpm2::restore_permanent_blob_for_test(vector(
            "PERMALL_Y_AFTER_COMPLETE",
        ))
        .expect("the oracle permanent state restores");
        crate::library::tpm2::attach_volatile_blob_for_replay(
            &mut runtime,
            vector("VOLATILE_Y_AFTER_COMPLETE"),
            &clock,
        )
        .expect("a completed sequence leaves nothing to resume");
    }

    fn hash_state_offsets(blob: &[u8]) -> Vec<usize> {
        const MAGIC: [u8; 4] = [0x56, 0x28, 0x78, 0xa2];
        blob.windows(MAGIC.len())
            .enumerate()
            .filter(|(_, window)| *window == MAGIC)
            .map(|(index, _)| index)
            .collect()
    }

    #[test]
    fn a_live_event_sequence_survives_a_volatile_round_trip() {
        let clock = fresh_clock();
        let mut runtime = base_runtime(&clock);
        exec(
            &mut runtime,
            &clock,
            "N_START_EVENT",
            hash_sequence_start(&[], 0x0010),
        );
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_UPDATE",
            sequence_update(0x8000_0000, b"abc", &[]),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
        let (permanent, volatile) = state_blobs(&runtime, &clock);
        drop(runtime);

        let clock = fresh_clock();
        let mut runtime = reload(&permanent, &volatile, &clock);
        assert_eq!(occupied(&runtime), [true, false, false]);
        exec(
            &mut runtime,
            &clock,
            "N_EVENT_COMPLETE_PCR10",
            event_sequence_complete(0x0000_000a, 0x8000_0000, b"def"),
        );
    }

    #[test]
    fn a_corrupted_event_bank_is_refused_without_touching_the_runtime() {
        let clock = fresh_clock();
        let mut source = base_runtime(&clock);
        let _ = exec_raw(&mut source, &clock, hash_sequence_start(&[], 0x0010));
        let (permanent, volatile) = state_blobs(&source, &clock);
        drop(source);

        let offsets = hash_state_offsets(&volatile);
        assert_eq!(offsets.len(), 4, "one bank per compiled hash");
        for (index, offset) in offsets.iter().enumerate() {
            for (state_type, hash_alg) in [(1u8, 0x0012u16), (2, 0x000b), (0, 0x0000)] {
                let mut broken = volatile.clone();
                broken[offset + 6] = state_type;
                broken[offset + 7..offset + 9].copy_from_slice(&hash_alg.to_be_bytes());
                let clock = fresh_clock();
                let mut runtime = crate::library::tpm2::restore_permanent_blob_for_test(&permanent)
                    .expect("the saved permanent state restores");
                let before = occupied(&runtime);
                assert!(
                    crate::library::tpm2::attach_volatile_blob_for_replay(
                        &mut runtime,
                        &broken,
                        &clock,
                    )
                    .is_err(),
                    "bank {index} with type {state_type} alg {hash_alg:#06x}"
                );
                assert_eq!(
                    occupied(&runtime),
                    before,
                    "a refused attach leaves the object slots alone"
                );
                assert!(
                    runtime
                        .live
                        .objects
                        .iter()
                        .all(|object| object.attributes & ATTR_OCCUPIED == 0),
                    "no partial object survives the refusal"
                );
            }
        }

        let clock = fresh_clock();
        let mut runtime = crate::library::tpm2::restore_permanent_blob_for_test(&permanent)
            .expect("the saved permanent state restores");
        crate::library::tpm2::attach_volatile_blob_for_replay(&mut runtime, &volatile, &clock)
            .expect("the untouched blob still attaches");
        assert_eq!(occupied(&runtime), [true, false, false]);
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = fresh_clock();
        let mut runtime = key_runtime(&clock, "Q_CREATE_HMAC_KEY", &hmac_key(TPM_ALG_SHA256));
        let valid = mac_start(0x8000_0000, b"a", TPM_ALG_SHA256);
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
