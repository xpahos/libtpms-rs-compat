// Part of the Rust port of libtpms.
//
// Project licensing and upstream notices: LICENSE and LICENSES/README.md.
//
// Rust implementation:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

mod bignum;
mod ecc;
mod fault;
mod ffi;
mod masked;
mod rsa;
mod secret;

pub(in crate::library::tpm2) use bignum::BigUint;
#[cfg(test)]
pub(in crate::library::tpm2) use ecc::reference::curve_parameters;
pub(in crate::library::tpm2) use ecc::{
    EccAffine, EccBackendError, EccCurve, EccPublicScalar, EccScalar, EcdsaAttempt,
    PRIVATE_SCALAR_BYTES, SharedPointError,
};
#[cfg(test)]
pub(in crate::library::tpm2) use fault::{
    Boundary as FaultBoundary, arm as arm_fault, disarm as disarm_fault, fired as faults_fired,
};
pub(in crate::library::tpm2) use rsa::{
    CRT_WORDS, CrtCandidate, CrtWords, PublicCheck, RecoveredExponent, RecoveryError, RsaCrtKey,
    RsaRuntimeCache, RsaSignaturePadding, miller_rabin_witness, normalized_word_count, oaep_unpad,
    pkcs1_type2_unpad, recover_rsa_components, recover_rsa_private_exponent, rsa_private_key_op,
    rsa_public_key_op, rsa_verify_signature, rsassa_sign,
};
#[cfg(test)]
pub(in crate::library::tpm2) use rsa::{crt_words_be, prepared_key_count, review_keys};
pub(in crate::library::tpm2) use secret::{SecretBytes, wipe};

#[cfg(test)]
pub(in crate::library::tpm2) fn native_library_version() -> (u64, &'static str) {
    (
        openssl::version::number() as u64,
        openssl::version::version(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn production_view(source: &str) -> String {
        const MARKER: &str = "#[cfg(test)]";
        let mut out = String::with_capacity(source.len());
        let mut rest = source;
        while let Some(found) = rest.find(MARKER) {
            out.push_str(&rest[..found]);
            let item = &rest[found + MARKER.len()..];
            let statement_end = item.find(';').unwrap_or(item.len());
            let block_start = item.find('{').unwrap_or(item.len());
            if statement_end < block_start {
                rest = &item[statement_end + 1..];
                continue;
            }
            let mut depth = 0usize;
            let mut consumed = item.len();
            for (index, character) in item[block_start..].char_indices() {
                match character {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            consumed = block_start + index + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest = &item[consumed..];
        }
        out.push_str(rest);
        out
    }

    fn visit(root: &Path, dir: &Path, sources: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("the source tree is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                visit(root, &path, sources);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .expect("inside the tree")
                    .to_string_lossy()
                    .replace('\\', "/");
                let source = std::fs::read_to_string(&path).expect("the source file reads");
                sources.push((relative, source));
            }
        }
    }

    fn production_sources() -> Vec<(String, String)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        visit(&root, &root, &mut sources);
        sources
            .into_iter()
            .filter(|(relative, _)| {
                !matches!(
                    relative.as_str(),
                    "library/tpm2/crypto_outputs.rs"
                        | "library/tpm2/crypto/work.rs"
                        | "library/tpm2/ecc_scalar_encoding.rs"
                )
            })
            .map(|(relative, source)| (relative, production_view(&source)))
            .collect()
    }

    fn source<'a>(sources: &'a [(String, String)], name: &str) -> &'a str {
        sources
            .iter()
            .find(|(relative, _)| relative == name)
            .map(|(_, source)| source.as_str())
            .unwrap_or_else(|| panic!("{name} is scanned"))
    }

    fn function_body<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("{signature} is present"));
        let mut depth = 0usize;
        for (index, character) in source[start..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[start..start + index];
                    }
                }
                _ => {}
            }
        }
        panic!("{signature} ends")
    }

    #[test]
    fn linked_native_library_is_openssl_3() {
        let (number, text) = super::native_library_version();
        eprintln!("linked native library: {text} ({number:#010x})");
        assert_eq!(number >> 28, 3, "OpenSSL 3.x provides libcrypto: {text}");
        assert!(text.starts_with("OpenSSL 3."), "{text}");
        if cfg!(target_os = "linux") {
            assert_eq!(
                (number >> 20) & 0xff,
                0,
                "the production target links OpenSSL 3.0; another series needs the native review repeated: {text}"
            );
        }
    }

    #[test]
    fn production_view_keeps_production_items_only() {
        let sources = production_sources();
        let rsa = source(&sources, "library/tpm2/crypto/rsa.rs");
        assert!(rsa.contains("fn generate_rsa_key("));
        assert!(!rsa.contains("mod tests"));
        let signature = source(&sources, "library/tpm2/signature.rs");
        assert!(signature.contains("fn sm2_verify("));
        assert!(signature.contains("pub(super) fn obfuscation_mask("));
        assert!(!signature.contains("fn ecc_scheme_sign_verify_round_trip"));
    }

    #[test]
    fn native_types_stay_behind_the_adapter() {
        let violations: Vec<String> = production_sources()
            .into_iter()
            .filter(|(relative, source)| {
                (source.contains("openssl::")
                    || source.contains("openssl_sys")
                    || source.contains("foreign_types::"))
                    && !relative.starts_with("library/tpm2/crypto/ossl/")
            })
            .map(|(relative, _)| relative)
            .collect();
        assert!(
            violations.is_empty(),
            "OpenSSL types outside crypto/ossl: {violations:?}"
        );
    }

    #[test]
    fn direct_ffi_stays_in_the_ffi_module() {
        let sources = production_sources();
        let mut unsafe_users: Vec<&str> = sources
            .iter()
            .filter(|(relative, source)| {
                relative.starts_with("library/tpm2/crypto/") && source.contains("unsafe")
            })
            .map(|(relative, _)| relative.as_str())
            .collect();
        unsafe_users.sort_unstable();
        assert_eq!(
            unsafe_users,
            [
                "library/tpm2/crypto/entropy.rs",
                "library/tpm2/crypto/ossl/ffi.rs"
            ]
        );
        let externs: Vec<&str> = sources
            .iter()
            .filter(|(_, source)| source.contains("extern \"C\""))
            .map(|(relative, _)| relative.as_str())
            .filter(|relative| relative.starts_with("library/tpm2/"))
            .collect();
        assert_eq!(externs, ["library/tpm2/crypto/ossl/ffi.rs"]);
    }

    #[test]
    fn no_custom_modular_arithmetic_in_production() {
        let sources = production_sources();
        for (relative, source) in &sources {
            let adapter = relative.starts_with("library/tpm2/crypto/ossl/");
            for needle in [
                "crypto_bigint",
                "Montgomery",
                "fn mod_exp",
                "fn mod_inverse",
                "fn div_rem_knuth",
                "fn complete_addition",
                "fn complete_doubling",
                "struct BigUint",
            ] {
                if adapter && needle != "crypto_bigint" {
                    continue;
                }
                assert!(
                    !source.contains(needle),
                    "{relative} contains `{needle}` outside the OpenSSL adapter"
                );
            }
        }
        let bignum = source(&sources, "library/tpm2/crypto/ossl/bignum.rs");
        assert!(
            bignum.contains("pub(in crate::library::tpm2) struct BigUint(SecretBn);"),
            "the key-generation integer is an OpenSSL BIGNUM"
        );
    }

    #[test]
    fn stored_ecc_scalars_reach_arithmetic_through_the_fixed_width_import() {
        let sources = production_sources();
        let mut importers: Vec<&str> = sources
            .iter()
            .filter(|(_, source)| {
                source.contains(".private_scalar(") || source.contains(".fixed_width()")
            })
            .map(|(relative, _)| relative.as_str())
            .collect();
        importers.sort_unstable();
        assert_eq!(
            importers,
            ["library/tpm2/ecc.rs", "library/tpm2/object_load.rs"],
            "only the ECC import and key validation read the fixed-width storage"
        );
        for (relative, source) in &sources {
            let ecc_consumer = relative == "library/tpm2/ecc.rs"
                || relative.starts_with("library/tpm2/command/crypto/ecc/");
            if ecc_consumer {
                assert!(
                    !source.contains("as_bytes()"),
                    "{relative} reads a stored secret by its serialized length"
                );
                let accessors = source.matches("sensitive.sensitive").count();
                let expected = usize::from(relative == "library/tpm2/ecc.rs");
                assert_eq!(
                    accessors, expected,
                    "{relative} reaches the stored scalar directly"
                );
            }
        }
        for (name, signature) in [
            ("library/tpm2/signature.rs", "fn ecc_sign("),
            ("library/tpm2/secret.rs", "fn ecc_decrypt("),
        ] {
            let body = function_body(source(&sources, name), signature);
            assert!(body.contains("ecc_stored_private("), "{name} {signature}");
            for needle in ["as_bytes()", ".scalar(", "sensitive.sensitive"] {
                assert!(
                    !body.contains(needle),
                    "{name} {signature} uses `{needle}` on the private key"
                );
            }
        }
    }

    #[test]
    fn masked_scalars_are_unmasked_only_for_public_outputs_and_key_export() {
        let sources = production_sources();
        let count = |name: &str, needle: &str| source(&sources, name).matches(needle).count();
        let mut reveals: Vec<(String, usize)> = sources
            .iter()
            .filter(|(relative, _)| !relative.starts_with("library/tpm2/crypto/ossl/"))
            .map(|(relative, source)| (relative.clone(), source.matches(".reveal()").count()))
            .filter(|(_, count)| *count > 0)
            .collect();
        reveals.sort();
        assert_eq!(
            reveals,
            [("library/tpm2/signature.rs".to_string(), 3)],
            "the SM2 and Schnorr s values and the ECDAA nonce are the only revealed scalars"
        );
        let exports: Vec<&str> = sources
            .iter()
            .filter(|(_, source)| source.contains(".export_bytes("))
            .map(|(relative, _)| relative.as_str())
            .collect();
        assert_eq!(
            exports,
            ["library/tpm2/crypto/ecc.rs"],
            "only key generation exports d"
        );
        assert_eq!(count("library/tpm2/crypto/ecc.rs", ".export_bytes("), 1);
        let ecc = source(&sources, "library/tpm2/crypto/ossl/ecc.rs");
        let scalar_impl = &ecc[ecc.find("impl EccScalar {").expect("the masked scalar")..];
        let scalar_impl = &scalar_impl[..scalar_impl
            .find("impl EccPublicScalar {")
            .expect("the public scalar")];
        for forbidden in ["mod_inverse(", "checked_mul(", "div_rem(", ".nnmod("] {
            assert!(
                !scalar_impl.contains(forbidden),
                "masked scalar arithmetic calls {forbidden}"
            );
        }
    }

    #[test]
    fn secret_shared_points_and_exports_use_the_constant_width_unmasking() {
        let sources = production_sources();
        let secret = source(&sources, "library/tpm2/secret.rs");
        assert_eq!(secret.matches(".mul_point_shared(").count(), 2);
        assert!(!secret.contains(".mul_point("));
        let ecc = source(&sources, "library/tpm2/ecc.rs");
        let shared = &ecc[ecc
            .find("fn shared_point_multiply(")
            .expect("ECC_Decrypt's multiply")..];
        let shared = &shared[..shared.find("\n}\n").expect("the function end")];
        assert!(shared.contains(".mul_point_shared(") && !shared.contains(".mul_point("));
        let backend = source(&sources, "library/tpm2/crypto/ossl/ecc.rs");
        let method = |name: &str| -> &str {
            let body = &backend[backend.find(name).expect("the method")..];
            &body[..body.find("\n    }\n").expect("the method end")]
        };
        for name in ["fn difference(", "fn export_bytes("] {
            let body = method(name);
            assert!(
                body.contains("unmask_to_bytes("),
                "{name} unmasks at constant width"
            );
            for forbidden in ["affine_coordinates", ".to_be(", "to_vec(", "fn affine("] {
                assert!(!body.contains(forbidden), "{name} calls {forbidden}");
            }
        }
        let offsets = method("fn offset_points(");
        assert!(
            !offsets.contains("masked_part.point(), mask_part.point()"),
            "the two share products are never added to each other"
        );
        let shared = method("pub(in crate::library::tpm2) fn mul_point_shared(");
        assert!(shared.contains("offset_points(") && shared.contains("difference("));
        assert!(!backend.contains("Jprojective") && !backend.contains("jacobian"));
    }

    #[test]
    fn rsa_preparation_validates_before_deriving_d_and_never_sets_up_secret_moduli() {
        let sources = production_sources();
        let rsa = source(&sources, "library/tpm2/crypto/ossl/rsa.rs");
        for removed in [
            "trial_round_trip",
            "exponent_round_trips",
            "from_private_components",
        ] {
            assert!(!rsa.contains(removed), "rsa.rs still contains {removed}");
        }
        let prepare = &rsa[rsa.find("fn prepare(").expect("the preparation")..];
        let prepare = &prepare[..prepare.find("\n}\n").expect("the function end")];
        let product = prepare
            .find("factors_multiply_to(")
            .expect("the exact product check");
        let primes = prepare
            .find("factors_are_prime(")
            .expect("the primality check");
        let exponent = prepare.find("private_exponent(").expect("d");
        assert!(
            product < primes && primes < exponent,
            "validation precedes d"
        );
        assert!(
            prepare.contains("RsaPrivateKeyBuilder::new("),
            "the native key has no CRT values"
        );
        let compute = &rsa[rsa.find("fn compute(").expect("CRT computation")..];
        let compute = &compute[..compute.find("\n    }\n").expect("the method end")];
        for forbidden in [".ucmp(", "mod_inverse(", "blinded_exponent_inverse("] {
            assert!(
                !compute.contains(forbidden),
                "CrtCandidate::compute calls {forbidden}"
            );
        }
        let function = |text: &'static str, name: &str| -> &'static str {
            let body = &text[text.find(name).expect("the function")..];
            &body[..body
                .find("\n}\n")
                .or_else(|| body.find("\n    }\n"))
                .expect("the end")]
        };
        let rsa_static: &'static str = Box::leak(rsa.to_string().into_boxed_str());
        for name in [
            "fn crt_coefficient(",
            "fn fermat_coefficient(",
            "pub(in crate::library::tpm2) fn modulus(",
        ] {
            assert!(
                !function(rsa_static, name).contains("checked_mul("),
                "{name} multiplies plain secret factors"
            );
        }
        for name in ["fn fermat_coefficient(", "fn crt_coefficient("] {
            let body = function(rsa_static, name);
            assert!(
                !body.contains(".is_none()") && !body.contains("unwrap_or"),
                "{name} must not turn a backend failure into a mathematical result"
            );
        }
        let masked: &'static str = Box::leak(
            source(&sources, "library/tpm2/crypto/ossl/masked.rs")
                .to_string()
                .into_boxed_str(),
        );
        let widen = function(masked, "fn widen_with(");
        assert!(
            !widen.contains("&mut nothing")
                && widen.contains("consttime_swap(wrapped, &mut chosen"),
            "widen selects between two masked candidates instead of building a plain correction"
        );
        let ffi = source(&sources, "library/tpm2/crypto/ossl/ffi.rs");
        assert!(
            !ffi.contains("BN_MONT_CTX"),
            "no Montgomery context on a caller-supplied modulus"
        );
    }

    #[test]
    fn production_rsa_module_keeps_integers_out_of_private_operations() {
        let sources = production_sources();
        let rsa = source(&sources, "library/tpm2/crypto/rsa.rs");
        for needle in [
            ".mod_exp(",
            ".mod_inverse(",
            ".mod_mul(",
            ".div_rem(",
            ".rem(",
        ] {
            assert!(
                !rsa.contains(needle),
                "crypto/rsa.rs production code calls {needle}"
            );
        }
    }
}
