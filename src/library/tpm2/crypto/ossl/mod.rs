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
pub(in crate::library::tpm2) use rsa::{
    crt_words_be, forget_validated_factor_sets, prepared_key_count, review_keys,
    validated_factor_sets,
};
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
                        | "library/tpm2/memcheck.rs"
                        | "library/tpm2/crypto_outputs/findings.rs"
                        | "library/tpm2/command/crypto/ecc/memcheck_flows.rs"
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

    const MODULAR_CALLS: [&str; 9] = [
        "mod_inverse(",
        "mod_mul(",
        "mod_sqr(",
        "mod_add(",
        "mod_sub(",
        "mod_exp(",
        "modular_add(",
        "modular_sub(",
        "modular_mul(",
    ];

    fn call_arguments(source: &str, open: usize) -> &str {
        let mut depth = 0usize;
        for (index, character) in source[open..].char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[open..open + index];
                    }
                }
                _ => {}
            }
        }
        &source[open..]
    }

    fn project_point_arithmetic(source: &str) -> Vec<String> {
        let mut hits = Vec::new();
        for formula in [
            "fn difference(",
            "fn offset_points(",
            "fn masked_point(",
            "fn chord(",
            "fn point_add(",
            "fn point_double(",
        ] {
            if source.contains(formula) {
                hits.push(format!("project point formula `{formula}`"));
            }
        }
        for dependency in ["masked::", "masked_import(", "unmask_to_bytes(", "Shares"] {
            if source.contains(dependency) {
                hits.push(format!("masking dependency `{dependency}`"));
            }
        }
        for call in MODULAR_CALLS {
            for (position, _) in source.match_indices(call) {
                let arguments = call_arguments(source, position + call.len() - 1);
                if arguments.contains("field") {
                    hits.push(format!("field arithmetic `{call}{})`", &arguments[1..]));
                }
            }
        }
        hits
    }

    fn project_masking(sources: &[(String, String)]) -> Vec<String> {
        let mut hits = Vec::new();
        for (relative, source) in sources {
            if relative == "library/tpm2/crypto/ossl/masked.rs" {
                hits.push(format!("{relative}: the masking module"));
            }
            for needle in [
                "struct Shares",
                "Shares {",
                "masked_import(",
                "unmask_to_bytes(",
                "fn remasked(",
                "masked_mul(",
                "random_mask(",
                "nonzero_mask(",
                "hensel_inverse(",
                "fermat_coefficient(",
                "consttime_swap(",
            ] {
                if source.contains(needle) {
                    hits.push(format!("{relative}: `{needle}`"));
                }
            }
        }
        hits
    }

    const NATIVE_SHARED_POINT: &str = "
    fn checked_point(&self, x: &[u8], y: &[u8], ctx: &mut BigNumContextRef) -> Option<EcPoint> {
        x_reduced.nnmod(&x, &self.data.field, ctx).ok()?;
        point.set_affine_coordinates_gfp(self.group(), &x_reduced, &y_reduced, ctx).ok()?;
    }
    pub fn mul_point_shared(&self, x: &[u8], y: &[u8], scalar: &EccScalar) -> Option<EccAffine> {
        let product = self.product(Some(&base), scalar, &mut ctx)?;
        self.shared_affine(product.point(), &mut ctx)
    }
    fn combined(&self, other: &BigNumRef) -> Option<Self> {
        modular_mul(&mut value, &self.value, other, self.order(), &mut ctx).ok()?;
    }
";

    const REINTRODUCED_DIFFERENCE: &str = "
    pub fn mul_point_shared(&self, x: &[u8], y: &[u8], scalar: &EccScalar) -> Option<EccAffine> {
        let (sum, offset) = self.sum_and_offset(&base, scalar)?;
        let run = sub_mod(&offset.x, &sum.x, &self.data.field, ctx)?;
        let mut slope = SecretBn::new().ok()?;
        slope.mod_inverse(&run, &self.data.field, ctx).ok()?;
        slope.mod_mul(&slope, &rise, &self.data.field, ctx).ok()?;
    }
";

    #[test]
    fn f18_detector_accepts_a_native_adapter_and_rejects_project_point_arithmetic() {
        assert_eq!(
            project_point_arithmetic(NATIVE_SHARED_POINT),
            Vec::<String>::new(),
            "an adapter that delegates multiplication and coordinate export to OpenSSL"
        );
        let hits = project_point_arithmetic(REINTRODUCED_DIFFERENCE);
        assert!(
            hits.iter()
                .any(|hit| hit.contains("mod_inverse(&run, &self.data.field"))
                && hits.iter().any(|hit| hit.contains("mod_mul(&slope")),
            "{hits:?}"
        );
        let renamed = REINTRODUCED_DIFFERENCE.replace("mul_point_shared", "shared_secret_point");
        assert_eq!(
            project_point_arithmetic(&renamed).len(),
            hits.len(),
            "the detector follows the arithmetic, not the function name"
        );
        let masked = "use super::masked::{Shares, masked_import};";
        assert!(project_point_arithmetic(masked).len() >= 2);
        let fake = vec![(
            "library/tpm2/crypto/ossl/ecc.rs".to_string(),
            "fn scalar() { let shares = masked_import(bytes, order, ctx); }".to_string(),
        )];
        assert_eq!(project_masking(&fake).len(), 1);
    }

    #[test]
    fn f18_production_ecc_has_no_project_point_arithmetic() {
        let sources = production_sources();
        for (relative, source) in &sources {
            if relative.starts_with("library/tpm2/crypto/") || relative == "library/tpm2/ecc.rs" {
                let hits = project_point_arithmetic(source);
                assert!(
                    hits.is_empty(),
                    "{relative} computes points through project formulas: {hits:?}"
                );
            }
        }
        let ecc = source(&sources, "library/tpm2/crypto/ossl/ecc.rs");
        let shared = function_body(ecc, "pub(in crate::library::tpm2) fn mul_point_shared(");
        assert!(
            shared.contains(".product(") && shared.contains(".shared_affine("),
            "the shared point is an OpenSSL product exported by OpenSSL"
        );
        let product = function_body(ecc, "fn product(");
        assert!(product.contains(".mul_generator2(") && product.contains(".mul2("));
    }

    fn raw_sources() -> Vec<(String, String)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut sources = Vec::new();
        visit(&root, &root, &mut sources);
        sources
    }

    fn instrumentation_calls(relative: &str, source: &str) -> Vec<String> {
        let mut hits = Vec::new();
        for needle in [
            "memcheck::public(",
            "memcheck::publish(",
            "memcheck::secret(",
        ] {
            for (position, _) in source.match_indices(needle) {
                let line_start = source[..position].rfind('\n').map_or(0, |index| index + 1);
                if source[line_start..position].matches('"').count() % 2 == 1 {
                    continue;
                }
                let line = source[..position].matches('\n').count() + 1;
                hits.push(format!("{relative}:{line} {needle}"));
            }
        }
        hits
    }

    #[test]
    fn only_the_dispatcher_releases_and_only_provenance_sources_mark() {
        let test_only = [
            "library/tpm2/memcheck.rs",
            "library/tpm2/crypto_outputs.rs",
            "library/tpm2/crypto_outputs/findings.rs",
            "library/tpm2/command/crypto/ecc/memcheck_flows.rs",
        ];
        let mut releases = Vec::new();
        let mut markings = Vec::new();
        for (relative, source) in raw_sources() {
            if test_only.contains(&relative.as_str()) {
                continue;
            }
            let library = source
                .find("#[cfg(test)]\nmod tests {")
                .map_or(source.as_str(), |test_module| &source[..test_module]);
            for hit in instrumentation_calls(&relative, library) {
                if hit.contains("memcheck::secret(") {
                    markings.push(hit);
                } else {
                    releases.push(hit);
                }
            }
        }
        assert!(
            releases
                .iter()
                .all(|hit| hit.starts_with("library/tpm2/command/core/dispatcher.rs:")),
            "library code releases secret-derived values before the enclosing command succeeds: {releases:?}"
        );
        let sources: Vec<&str> = markings
            .iter()
            .map(|hit| hit.split(':').next().unwrap_or_default())
            .collect();
        for forbidden in [
            "library/tpm2/crypto/ossl/secret.rs",
            "library/tpm2/crypto/ossl/bignum.rs",
            "library/tpm2/crypto/ossl/ecc.rs",
            "library/tpm2/crypto/ossl/rsa.rs",
        ] {
            assert!(
                !sources.contains(&forbidden),
                "{forbidden} marks by type instead of at the provenance source: {markings:?}"
            );
        }
        let flagged = instrumentation_calls(
            "synthetic.rs",
            "fn affine() {\n    crate::library::tpm2::memcheck::public(&x);\n}",
        );
        assert_eq!(flagged, ["synthetic.rs:2 memcheck::public("]);
    }

    #[test]
    fn f19_production_keeps_no_project_masks_or_shares() {
        let hits = project_masking(&production_sources());
        assert!(
            hits.is_empty(),
            "production still splits secrets into masks and shares:\n{}",
            hits.join("\n")
        );
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
    fn scalars_are_revealed_only_for_public_outputs_and_key_export() {
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
    }

    #[test]
    fn no_masking_layer_or_project_point_formula_remains_in_production() {
        let sources = production_sources();
        assert!(
            !sources
                .iter()
                .any(|(relative, _)| relative == "library/tpm2/crypto/ossl/masked.rs"),
            "the masking module is gone"
        );
        for (relative, source) in &sources {
            for needle in [
                "masked_import",
                "Shares",
                "remask",
                "unmask",
                "hensel",
                "fn difference(",
                "offset_points",
                "slope",
                "BN_priv_rand",
                "BN_consttime_swap",
                "Jprojective",
            ] {
                assert!(
                    !source.contains(needle),
                    "{relative} still contains `{needle}`"
                );
            }
        }
    }

    #[test]
    fn shared_points_come_from_the_native_point_multiplication() {
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
        let shared = method("pub(in crate::library::tpm2) fn mul_point_shared(");
        assert!(shared.contains(".product(") && shared.contains("shared_affine("));
        let product = method("fn product(");
        assert!(product.contains(".mul_generator2(") && product.contains(".mul2("));
        for caller in ["fn affine(", "fn shared_affine("] {
            assert!(
                method(caller).contains(".coordinates("),
                "{caller} uses the clearing conversion"
            );
        }
        let conversion = method("fn coordinates(");
        assert!(conversion.contains(".affine_coordinates_gfp("));
        assert_eq!(
            conversion.matches("SecretBn::new()").count(),
            2,
            "both coordinate temporaries are cleared on drop"
        );
        assert!(!conversion.contains("BigNum::new()"));
    }

    #[test]
    fn rsa_preparation_validates_before_deriving_the_private_components() {
        let sources = production_sources();
        let rsa = source(&sources, "library/tpm2/crypto/ossl/rsa.rs");
        let prepare = &rsa[rsa.find("fn prepare(").expect("the preparation")..];
        let prepare = &prepare[..prepare.find("\n}\n").expect("the function end")];
        let product = prepare
            .find("factors_multiply_to(")
            .expect("the exact product check");
        let primes = prepare
            .find("factors_are_prime(")
            .expect("the primality check");
        let components = prepare
            .find("private_components(")
            .expect("d and the CRT values");
        assert!(
            product < primes && primes < components,
            "validation precedes the private components"
        );
        assert!(
            prepare.contains(".set_factors(") && prepare.contains(".set_crt_params("),
            "the native key is a complete CRT key"
        );
        let compute = &rsa[rsa.find("fn compute(").expect("CRT computation")..];
        let compute = &compute[..compute.find("\n    }\n").expect("the method end")];
        assert!(compute.contains("crt_exponent(") && compute.contains("crt_coefficient("));
    }

    #[test]
    fn public_points_are_validated_by_openssl_not_by_a_project_curve_equation() {
        let sources = production_sources();
        let ecc = source(&sources, "library/tpm2/crypto/ossl/ecc.rs");
        assert!(!ecc.contains("fn satisfies_equation("));
        let checked = function_body(ecc, "fn checked_point(");
        assert!(
            checked.contains(".set_affine_coordinates_gfp(")
                && checked.contains("only_reason(&error, ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE)")
        );
        for forbidden in ["mod_sqr(", "mod_mul(", "components_gfp("] {
            assert!(
                !checked.contains(forbidden),
                "checked_point calls {forbidden}"
            );
        }
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
