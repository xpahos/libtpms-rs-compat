use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_SIZE, TPM_RC_TYPE};
use crate::library::tpm2::command::core::dispatcher::CommandFrame;
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::public::{
    StateFormatLimit, TPM_ALG_ECC, TPM_ALG_KEYEDHASH, TPM_ALG_RSA, TPM_ALG_SYMCIPHER,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::template::{AlgorithmPolicy, TemplateReader, parse_public_parms};
use crate::types::TpmResult;

const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;

const RC_PARAMETERS: TpmResult = TPM_RC_P + TPM_RC_1;

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let policy = AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    };
    let mut reader = TemplateReader::new(frame.parameters);
    parse_parameters(&mut reader, &policy).map_err(|code| code + RC_PARAMETERS)?;
    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(CommandOutput::empty())
}

fn parse_parameters(
    reader: &mut TemplateReader<'_>,
    policy: &AlgorithmPolicy<'_>,
) -> Result<(), TpmResult> {
    let object_type = reader.u16()?;
    if !matches!(
        object_type,
        TPM_ALG_KEYEDHASH | TPM_ALG_RSA | TPM_ALG_ECC | TPM_ALG_SYMCIPHER
    ) {
        return Err(TPM_RC_TYPE);
    }
    parse_public_parms(reader, policy, object_type).map(|_| ())
}

#[cfg(test)]
mod tests {
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::golden_responses::test_parms::vector;
    use crate::library::tpm2::object_load::replay::{
        cap_cc, clock, exec_raw, framed, password_area, plain, runtime_from,
    };
    use crate::library::tpm2::runtime::Tpm2Runtime;

    use crate::library::tpm2::command::core::registry::{self, CommandLifecycle, NvAccess};

    const CC_TEST_PARMS: u32 = 0x0000_018a;

    const ALG_RSA: u16 = 0x0001;
    const ALG_TDES: u16 = 0x0003;
    const ALG_SHA1: u16 = 0x0004;
    const ALG_HMAC: u16 = 0x0005;
    const ALG_AES: u16 = 0x0006;
    const ALG_MGF1: u16 = 0x0007;
    const ALG_KEYEDHASH: u16 = 0x0008;
    const ALG_XOR: u16 = 0x000a;
    const ALG_SHA256: u16 = 0x000b;
    const ALG_SHA384: u16 = 0x000c;
    const ALG_SHA512: u16 = 0x000d;
    const ALG_NULL: u16 = 0x0010;
    const ALG_RSASSA: u16 = 0x0014;
    const ALG_RSAES: u16 = 0x0015;
    const ALG_RSAPSS: u16 = 0x0016;
    const ALG_OAEP: u16 = 0x0017;
    const ALG_ECDSA: u16 = 0x0018;
    const ALG_ECDH: u16 = 0x0019;
    const ALG_ECDAA: u16 = 0x001a;
    const ALG_KDF1_56A: u16 = 0x0020;
    const ALG_KDF2: u16 = 0x0021;
    const ALG_KDF1_108: u16 = 0x0022;
    const ALG_ECC: u16 = 0x0023;
    const ALG_SYMCIPHER: u16 = 0x0025;
    const ALG_CAMELLIA: u16 = 0x0026;
    const ALG_CMAC: u16 = 0x003f;
    const ALG_CTR: u16 = 0x0040;
    const ALG_OFB: u16 = 0x0041;
    const ALG_CBC: u16 = 0x0042;
    const ALG_CFB: u16 = 0x0043;
    const ALG_ECB: u16 = 0x0044;

    fn fresh_clock() -> SteppingClock {
        clock()
    }

    fn runtime_at(snapshot: &str, clock: &SteppingClock) -> Box<Tpm2Runtime> {
        runtime_from(
            vector(&format!("PERMALL_{snapshot}")),
            vector(&format!("VOLATILE_{snapshot}")),
            clock,
        )
    }

    #[track_caller]
    fn exec(runtime: &mut Tpm2Runtime, clock: &SteppingClock, label: &str, bytes: Vec<u8>) {
        assert_eq!(exec_raw(runtime, clock, bytes), vector(label), "{label}");
    }

    fn test_parms(parms: &[u8]) -> Vec<u8> {
        plain(CC_TEST_PARMS, parms)
    }

    fn u16s(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    fn keyedhash(scheme: u16, hash_alg: u16, kdf: u16) -> Vec<u8> {
        let mut out = u16s(&[ALG_KEYEDHASH, scheme]);
        if scheme == ALG_HMAC {
            out.extend_from_slice(&hash_alg.to_be_bytes());
        } else if scheme == ALG_XOR {
            out.extend_from_slice(&u16s(&[hash_alg, kdf]));
        }
        out
    }

    fn symmetric(algorithm: u16, key_bits: u16, mode: u16) -> Vec<u8> {
        let mut out = u16s(&[ALG_SYMCIPHER, algorithm]);
        if algorithm != ALG_NULL {
            out.extend_from_slice(&u16s(&[key_bits, mode]));
        }
        out
    }

    fn rsa(
        sym_alg: u16,
        sym_bits: u16,
        sym_mode: u16,
        scheme: u16,
        scheme_hash: u16,
        key_bits: u16,
        exponent: u32,
    ) -> Vec<u8> {
        let mut out = u16s(&[ALG_RSA, sym_alg]);
        if sym_alg != ALG_NULL {
            out.extend_from_slice(&u16s(&[sym_bits, sym_mode]));
        }
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme != ALG_NULL {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
        }
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&exponent.to_be_bytes());
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn ecc(
        sym_alg: u16,
        sym_bits: u16,
        sym_mode: u16,
        scheme: u16,
        scheme_hash: u16,
        curve: u16,
        kdf: u16,
        kdf_hash: u16,
        count: u16,
    ) -> Vec<u8> {
        let mut out = u16s(&[ALG_ECC, sym_alg]);
        if sym_alg != ALG_NULL {
            out.extend_from_slice(&u16s(&[sym_bits, sym_mode]));
        }
        out.extend_from_slice(&scheme.to_be_bytes());
        if scheme != ALG_NULL {
            out.extend_from_slice(&scheme_hash.to_be_bytes());
            if scheme == ALG_ECDAA {
                out.extend_from_slice(&count.to_be_bytes());
            }
        }
        out.extend_from_slice(&u16s(&[curve, kdf]));
        if kdf != ALG_NULL {
            out.extend_from_slice(&kdf_hash.to_be_bytes());
        }
        out
    }

    #[test]
    fn the_command_is_registered_with_the_upstream_attributes() {
        let descriptor = registry::find(CC_TEST_PARMS).expect("registered");
        assert_eq!(descriptor.attributes, 0x0000_018a);
        assert_eq!(descriptor.decrypt_size, 0);
        assert_eq!(descriptor.encrypt_size, 0);
        assert!(descriptor.sessions_allowed);
        assert!(!descriptor.physical_presence);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!((descriptor.attributes >> 25) & 0x7, 0, "no command handle");
        assert!(descriptor.handles.is_empty());
    }

    #[test]
    fn the_capability_report_matches_the_oracle() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "CAP_CC_TEST_PARMS",
            cap_cc(CC_TEST_PARMS),
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
            "TP_BEFORE_STARTUP",
            test_parms(&symmetric(ALG_AES, 128, ALG_CFB)),
        );
    }

    #[test]
    fn keyed_hash_parameters_follow_the_reference() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        for (label, parms) in [
            ("TP_KEYEDHASH_HMAC_SHA1", keyedhash(ALG_HMAC, ALG_SHA1, 0)),
            (
                "TP_KEYEDHASH_HMAC_SHA256",
                keyedhash(ALG_HMAC, ALG_SHA256, 0),
            ),
            (
                "TP_KEYEDHASH_HMAC_SHA512",
                keyedhash(ALG_HMAC, ALG_SHA512, 0),
            ),
            (
                "TP_KEYEDHASH_HMAC_NULL_HASH",
                keyedhash(ALG_HMAC, ALG_NULL, 0),
            ),
            ("TP_KEYEDHASH_HMAC_BAD_HASH", keyedhash(ALG_HMAC, 0x0012, 0)),
            (
                "TP_KEYEDHASH_XOR_KDF1_108",
                keyedhash(ALG_XOR, ALG_SHA256, ALG_KDF1_108),
            ),
            (
                "TP_KEYEDHASH_XOR_MGF1",
                keyedhash(ALG_XOR, ALG_SHA256, ALG_MGF1),
            ),
            (
                "TP_KEYEDHASH_XOR_NULL_KDF",
                keyedhash(ALG_XOR, ALG_SHA256, ALG_NULL),
            ),
            (
                "TP_KEYEDHASH_XOR_BAD_KDF",
                keyedhash(ALG_XOR, ALG_SHA256, 0x0033),
            ),
            ("TP_KEYEDHASH_NULL", keyedhash(ALG_NULL, 0, 0)),
            ("TP_KEYEDHASH_BAD_SCHEME", keyedhash(ALG_RSASSA, 0, 0)),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
    }

    #[test]
    fn symmetric_parameters_follow_the_reference() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        for (name, algorithm, sizes) in [
            ("AES", ALG_AES, &[128u16, 192, 256][..]),
            ("CAMELLIA", ALG_CAMELLIA, &[128, 192, 256][..]),
            ("TDES", ALG_TDES, &[128, 192][..]),
        ] {
            for &bits in sizes {
                for (mode_name, mode) in [
                    ("CFB", ALG_CFB),
                    ("CBC", ALG_CBC),
                    ("ECB", ALG_ECB),
                    ("CTR", ALG_CTR),
                    ("OFB", ALG_OFB),
                    ("NULL", ALG_NULL),
                    ("CMAC", ALG_CMAC),
                ] {
                    exec(
                        &mut runtime,
                        &clock,
                        &format!("TP_SYM_{name}_{bits}_{mode_name}"),
                        test_parms(&symmetric(algorithm, bits, mode)),
                    );
                }
            }
        }
        for (label, parms) in [
            ("TP_SYM_AES_64", symmetric(ALG_AES, 64, ALG_CFB)),
            ("TP_SYM_AES_512", symmetric(ALG_AES, 512, ALG_CFB)),
            ("TP_SYM_TDES_256", symmetric(ALG_TDES, 256, ALG_CFB)),
            ("TP_SYM_NULL_ALG", symmetric(ALG_NULL, 0, 0)),
            ("TP_SYM_XOR_ALG", symmetric(ALG_XOR, 128, ALG_CFB)),
            ("TP_SYM_BAD_ALG", symmetric(0x0033, 128, ALG_CFB)),
            ("TP_SYM_BAD_MODE", symmetric(ALG_AES, 128, ALG_HMAC)),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
    }

    #[test]
    fn rsa_parameters_follow_the_reference() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        for bits in [1024u16, 2048, 3072] {
            exec(
                &mut runtime,
                &clock,
                &format!("TP_RSA_{bits}"),
                test_parms(&rsa(ALG_NULL, 0, 0, ALG_NULL, 0, bits, 0)),
            );
        }
        for (label, parms) in [
            ("TP_RSA_4096", rsa(ALG_NULL, 0, 0, ALG_NULL, 0, 4096, 0)),
            ("TP_RSA_512", rsa(ALG_NULL, 0, 0, ALG_NULL, 0, 512, 0)),
            (
                "TP_RSA_EXPONENT_65537",
                rsa(ALG_NULL, 0, 0, ALG_NULL, 0, 2048, 65537),
            ),
            (
                "TP_RSA_EXPONENT_THREE",
                rsa(ALG_NULL, 0, 0, ALG_NULL, 0, 2048, 3),
            ),
            (
                "TP_RSA_RSASSA_SHA256",
                rsa(ALG_NULL, 0, 0, ALG_RSASSA, ALG_SHA256, 2048, 0),
            ),
            (
                "TP_RSA_RSAPSS_SHA384",
                rsa(ALG_NULL, 0, 0, ALG_RSAPSS, ALG_SHA384, 2048, 0),
            ),
            (
                "TP_RSA_OAEP_SHA1",
                rsa(ALG_NULL, 0, 0, ALG_OAEP, ALG_SHA1, 2048, 0),
            ),
            ("TP_RSA_RSAES", rsa(ALG_NULL, 0, 0, ALG_RSAES, 0, 2048, 0)),
            (
                "TP_RSA_BAD_SCHEME",
                rsa(ALG_NULL, 0, 0, ALG_ECDSA, ALG_SHA256, 2048, 0),
            ),
            (
                "TP_RSA_SCHEME_BAD_HASH",
                rsa(ALG_NULL, 0, 0, ALG_RSASSA, 0x0012, 2048, 0),
            ),
            (
                "TP_RSA_AES_CFB",
                rsa(ALG_AES, 128, ALG_CFB, ALG_NULL, 0, 2048, 0),
            ),
            (
                "TP_RSA_AES_BAD_MODE",
                rsa(ALG_AES, 128, ALG_HMAC, ALG_NULL, 0, 2048, 0),
            ),
            (
                "TP_RSA_TDES_CBC",
                rsa(ALG_TDES, 192, ALG_CBC, ALG_NULL, 0, 2048, 0),
            ),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
    }

    #[test]
    fn ecc_parameters_follow_the_reference() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        for (name, curve) in [
            ("P192", 0x0001u16),
            ("P224", 0x0002),
            ("P256", 0x0003),
            ("P384", 0x0004),
            ("P521", 0x0005),
            ("BN256", 0x0010),
            ("BN638", 0x0011),
            ("SM2", 0x0020),
        ] {
            exec(
                &mut runtime,
                &clock,
                &format!("TP_ECC_{name}"),
                test_parms(&ecc(ALG_NULL, 0, 0, ALG_NULL, 0, curve, ALG_NULL, 0, 0)),
            );
        }
        for (label, parms) in [
            (
                "TP_ECC_BAD_CURVE",
                ecc(ALG_NULL, 0, 0, ALG_NULL, 0, 0x0006, ALG_NULL, 0, 0),
            ),
            (
                "TP_ECC_CURVE_NONE",
                ecc(ALG_NULL, 0, 0, ALG_NULL, 0, 0x0000, ALG_NULL, 0, 0),
            ),
            (
                "TP_ECC_ECDSA_SHA256",
                ecc(
                    ALG_NULL, 0, 0, ALG_ECDSA, ALG_SHA256, 0x0003, ALG_NULL, 0, 0,
                ),
            ),
            (
                "TP_ECC_ECDAA_SHA256",
                ecc(
                    ALG_NULL, 0, 0, ALG_ECDAA, ALG_SHA256, 0x0010, ALG_NULL, 0, 1,
                ),
            ),
            (
                "TP_ECC_ECDH_KDF1_56A",
                ecc(
                    ALG_NULL,
                    0,
                    0,
                    ALG_ECDH,
                    ALG_SHA256,
                    0x0003,
                    ALG_KDF1_56A,
                    ALG_SHA256,
                    0,
                ),
            ),
            (
                "TP_ECC_KDF2_SHA384",
                ecc(ALG_NULL, 0, 0, ALG_NULL, 0, 0x0004, ALG_KDF2, ALG_SHA384, 0),
            ),
            (
                "TP_ECC_KDF_BAD_HASH",
                ecc(ALG_NULL, 0, 0, ALG_NULL, 0, 0x0003, ALG_KDF2, 0x0012, 0),
            ),
            (
                "TP_ECC_BAD_SCHEME",
                ecc(
                    ALG_NULL, 0, 0, ALG_RSASSA, ALG_SHA256, 0x0003, ALG_NULL, 0, 0,
                ),
            ),
            (
                "TP_ECC_AES_CFB",
                ecc(ALG_AES, 128, ALG_CFB, ALG_NULL, 0, 0x0003, ALG_NULL, 0, 0),
            ),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
    }

    #[test]
    fn malformed_input_reports_the_indexed_errors() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        for (label, parms) in [
            ("TP_TYPE_NULL", u16s(&[ALG_NULL])),
            ("TP_TYPE_ZERO", u16s(&[0x0000])),
            ("TP_TYPE_FFFF", u16s(&[0xffff])),
            ("TP_EMPTY", Vec::new()),
            ("TP_TRUNCATED_TYPE", vec![0x00]),
            ("TP_TRUNCATED_SYM", u16s(&[ALG_SYMCIPHER, ALG_AES])),
            (
                "TP_TRUNCATED_RSA",
                u16s(&[ALG_RSA, ALG_NULL, ALG_NULL, 2048]),
            ),
            ("TP_TRAILING", {
                let mut parms = symmetric(ALG_AES, 128, ALG_CFB);
                parms.push(0xee);
                parms
            }),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
        let mut payload = password_area(&[]);
        payload.extend_from_slice(&symmetric(ALG_AES, 128, ALG_CFB));
        exec(
            &mut runtime,
            &clock,
            "TP_WITH_SESSION",
            framed(0x8002, CC_TEST_PARMS, &payload),
        );
        assert!(!runtime.nv_update_pending, "the command writes no NV state");
        assert!(
            runtime
                .live
                .objects
                .iter()
                .all(|object| object.attributes & crate::library::tpm2::object::ATTR_OCCUPIED == 0),
            "the command allocates no object"
        );
    }

    #[test]
    fn a_reduced_profile_rejects_the_disabled_algorithms() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("MINIMAL_BASE", &clock);
        for (label, parms) in [
            ("MIN_SYM_AES_CFB", symmetric(ALG_AES, 128, ALG_CFB)),
            ("MIN_SYM_AES_CBC", symmetric(ALG_AES, 128, ALG_CBC)),
            ("MIN_SYM_AES_ECB", symmetric(ALG_AES, 128, ALG_ECB)),
            ("MIN_SYM_CAMELLIA", symmetric(ALG_CAMELLIA, 128, ALG_CFB)),
            ("MIN_SYM_TDES", symmetric(ALG_TDES, 192, ALG_CFB)),
            ("MIN_KEYEDHASH_SHA1", keyedhash(ALG_HMAC, ALG_SHA1, 0)),
            ("MIN_KEYEDHASH_SHA256", keyedhash(ALG_HMAC, ALG_SHA256, 0)),
            (
                "MIN_ECC_P521",
                ecc(ALG_NULL, 0, 0, ALG_NULL, 0, 0x0005, ALG_NULL, 0, 0),
            ),
            (
                "MIN_ECC_P256",
                ecc(ALG_NULL, 0, 0, ALG_NULL, 0, 0x0003, ALG_NULL, 0, 0),
            ),
            ("MIN_RSA_2048", rsa(ALG_NULL, 0, 0, ALG_NULL, 0, 2048, 0)),
            (
                "MIN_ECC_ECDAA_DISABLED",
                ecc(
                    ALG_NULL, 0, 0, ALG_ECDAA, ALG_SHA256, 0x0003, ALG_NULL, 0, 1,
                ),
            ),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
    }

    #[test]
    fn a_lower_state_format_level_restricts_the_key_sizes() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("LEVEL3_BASE", &clock);
        for (label, parms) in [
            ("L3_SYM_AES_128", symmetric(ALG_AES, 128, ALG_CFB)),
            ("L3_SYM_AES_192", symmetric(ALG_AES, 192, ALG_CFB)),
            ("L3_SYM_AES_256", symmetric(ALG_AES, 256, ALG_CFB)),
            ("L3_SYM_CAMELLIA_192", symmetric(ALG_CAMELLIA, 192, ALG_CFB)),
        ] {
            exec(&mut runtime, &clock, label, test_parms(&parms));
        }
    }

    #[test]
    fn prefixes_and_bit_flips_do_not_panic() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("BASE", &clock);
        let valid = test_parms(&rsa(
            ALG_AES, 128, ALG_CFB, ALG_RSASSA, ALG_SHA256, 2048, 65537,
        ));
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
