use crate::library::constants::{TPM_RC_FAILURE, TPM_RC_KEY, TPM_RC_TYPE};
use crate::library::tpm2::command::core::response_code::{TPM_RC_1, TPM_RC_H};
use crate::library::tpm2::ecc::is_ecc_object;
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedObjectBody};
use crate::library::tpm2::profile::ATTRIBUTE_NO_ECC_KEY_DERIVATION;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::types::TpmResult;
pub(super) const RC_KEY_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;

pub(super) fn ecc_key(
    runtime: &Tpm2Runtime,
    handle: u32,
) -> Result<Box<OwnedObjectBody>, TpmResult> {
    let object = resolve_any_object(runtime, handle).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    };
    if !is_ecc_object(body) {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    }
    Ok(body.clone())
}

pub(super) fn object_is_public_only(runtime: &Tpm2Runtime, handle: u32) -> bool {
    resolve_any_object(runtime, handle).is_some_and(|object| {
        object.attributes & crate::library::tpm2::object::ATTR_PUBLIC_ONLY != 0
    })
}

pub(super) fn ecc_key_derivation_allowed(runtime: &Tpm2Runtime) -> Result<(), TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    if state
        .profile
        .attribute_enabled(ATTRIBUTE_NO_ECC_KEY_DERIVATION)
    {
        return Err(TPM_RC_TYPE);
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod test_support {
    use crate::library::tpm2::crypto::{Hasher, curve_parameters};
    use crate::library::tpm2::ecc::{EccPoint, point_multiply};
    use crate::library::tpm2::golden_responses::ecc_commands::vector;
    use crate::library::tpm2::runtime::Tpm2Runtime;
    use crate::library::tpm2::{attach_volatile_blob_for_test, restore_permanent_blob_for_test};

    pub(in crate::library::tpm2::command) use crate::library::tpm2::command::core::test_support::{
        dispatch_bytes, response_code, tpm2b,
    };

    pub(in crate::library::tpm2::command) const TPM_RH_NULL: u32 = 0x4000_0007;
    pub(in crate::library::tpm2::command) const CURVE_P256: u16 = 0x0003;
    pub(in crate::library::tpm2::command) const CURVE_P384: u16 = 0x0004;
    pub(in crate::library::tpm2::command) const H0: u32 = 0x8000_0000;

    pub(in crate::library::tpm2::command) const CC_STARTUP: u32 = 0x0000_0144;
    pub(in crate::library::tpm2::command) const CC_LOAD_EXTERNAL: u32 = 0x0000_0167;
    pub(in crate::library::tpm2::command) const CC_ECDH_ZGEN: u32 = 0x0000_0154;
    pub(in crate::library::tpm2::command) const CC_ECDH_KEYGEN: u32 = 0x0000_0163;
    pub(in crate::library::tpm2::command) const CC_ECC_PARAMETERS: u32 = 0x0000_0178;
    pub(in crate::library::tpm2::command) const CC_COMMIT: u32 = 0x0000_018b;
    pub(in crate::library::tpm2::command) const CC_ZGEN_2PHASE: u32 = 0x0000_018d;
    pub(in crate::library::tpm2::command) const CC_EC_EPHEMERAL: u32 = 0x0000_018e;
    pub(in crate::library::tpm2::command) const CC_ECC_ENCRYPT: u32 = 0x0000_0199;
    pub(in crate::library::tpm2::command) const CC_ECC_DECRYPT: u32 = 0x0000_019a;

    pub(in crate::library::tpm2::command) const SHA256: u16 = 0x000b;
    pub(in crate::library::tpm2::command) const SHA384: u16 = 0x000c;
    pub(in crate::library::tpm2::command) const ALG_NULL: u16 = 0x0010;

    pub(in crate::library::tpm2::command) const SCHEME_NULL: [u8; 2] = [0x00, 0x10];
    pub(in crate::library::tpm2::command) const SCHEME_ECDH: [u8; 4] = [0x00, 0x19, 0x00, 0x0b];
    pub(in crate::library::tpm2::command) const SCHEME_ECMQV: [u8; 4] = [0x00, 0x1d, 0x00, 0x0b];
    pub(in crate::library::tpm2::command) const SCHEME_ECDAA: [u8; 6] =
        [0x00, 0x1a, 0x00, 0x0b, 0x00, 0x00];
    pub(in crate::library::tpm2::command) const KDF_NULL: [u8; 2] = [0x00, 0x10];
    pub(in crate::library::tpm2::command) const KDF2_SHA256: [u8; 4] = [0x00, 0x21, 0x00, 0x0b];
    pub(in crate::library::tpm2::command) const KDF2_SHA384: [u8; 4] = [0x00, 0x21, 0x00, 0x0c];
    pub(in crate::library::tpm2::command) const KDF1_SHA256: [u8; 4] = [0x00, 0x20, 0x00, 0x0b];
    pub(in crate::library::tpm2::command) const MGF1_SHA256: [u8; 4] = [0x00, 0x07, 0x00, 0x0b];

    pub(in crate::library::tpm2::command) const ATTR_DECRYPT: u32 = 0x0002_0040;
    pub(in crate::library::tpm2::command) const ATTR_SIGN: u32 = 0x0004_0040;

    pub(in crate::library::tpm2::command) const PRIVATE_SCALAR: [u8; 32] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c, 0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19,
        0x0c, 0xfe,
    ];
    pub(in crate::library::tpm2::command) const KEY_AUTH: &[u8] = b"ecc";
    pub(in crate::library::tpm2::command) const KEYED_AUTH: &[u8] = b"ext-auth";

    pub(in crate::library::tpm2::command) fn point2b(point: &EccPoint) -> Vec<u8> {
        let mut inner = tpm2b(&point.x);
        inner.extend_from_slice(&tpm2b(&point.y));
        tpm2b(&inner)
    }

    pub(in crate::library::tpm2::command) fn raw_point2b(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut inner = tpm2b(x);
        inner.extend_from_slice(&tpm2b(y));
        tpm2b(&inner)
    }

    pub(in crate::library::tpm2::command) fn pw(password: &[u8]) -> Vec<u8> {
        let mut out = 0x4000_0009u32.to_be_bytes().to_vec();
        out.extend_from_slice(&0u16.to_be_bytes());
        out.push(0x00);
        out.extend_from_slice(&tpm2b(password));
        out
    }

    pub(in crate::library::tpm2::command) fn cmd(
        code: u32,
        handles: &[u32],
        auth: Option<&[u8]>,
        parameters: &[u8],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        for handle in handles {
            payload.extend_from_slice(&handle.to_be_bytes());
        }
        if let Some(auth) = auth {
            payload.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            payload.extend_from_slice(auth);
        }
        let tag: u16 = if auth.is_some() { 0x8002 } else { 0x8001 };
        framed(tag, code, &[payload.as_slice(), parameters].concat())
    }

    pub(in crate::library::tpm2::command) fn framed(
        tag: u16,
        code: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = tag.to_be_bytes().to_vec();
        out.extend_from_slice(&(10 + payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    pub(in crate::library::tpm2::command) fn ecc_public(
        attributes: u32,
        scheme: &[u8],
        curve: u16,
        kdf: &[u8],
        x: &[u8],
        y: &[u8],
    ) -> Vec<u8> {
        let mut body = 0x0023u16.to_be_bytes().to_vec();
        body.extend_from_slice(&SHA256.to_be_bytes());
        body.extend_from_slice(&attributes.to_be_bytes());
        body.extend_from_slice(&tpm2b(&[]));
        body.extend_from_slice(&ALG_NULL.to_be_bytes());
        body.extend_from_slice(scheme);
        body.extend_from_slice(&curve.to_be_bytes());
        body.extend_from_slice(kdf);
        body.extend_from_slice(&tpm2b(x));
        body.extend_from_slice(&tpm2b(y));
        tpm2b(&body)
    }

    pub(in crate::library::tpm2::command) fn ecc_private(scalar: &[u8], auth: &[u8]) -> Vec<u8> {
        let mut body = 0x0023u16.to_be_bytes().to_vec();
        body.extend_from_slice(&tpm2b(auth));
        body.extend_from_slice(&tpm2b(&[]));
        body.extend_from_slice(&tpm2b(scalar));
        tpm2b(&body)
    }

    pub(in crate::library::tpm2::command) fn keyed_object() -> (Vec<u8>, Vec<u8>) {
        let seed: Vec<u8> = (0..32u8).collect();
        let data = b"external sealed payload".to_vec();
        let mut hasher = Hasher::new(SHA256).expect("SHA-256");
        hasher.update(&seed);
        hasher.update(&data);
        let unique = hasher.finalize();
        let mut public = 0x0008u16.to_be_bytes().to_vec();
        public.extend_from_slice(&SHA256.to_be_bytes());
        public.extend_from_slice(&0x0000_0440u32.to_be_bytes());
        public.extend_from_slice(&tpm2b(&[]));
        public.extend_from_slice(&ALG_NULL.to_be_bytes());
        public.extend_from_slice(&tpm2b(&unique));
        let mut private = 0x0008u16.to_be_bytes().to_vec();
        private.extend_from_slice(&tpm2b(KEYED_AUTH));
        private.extend_from_slice(&tpm2b(&seed));
        private.extend_from_slice(&tpm2b(&data));
        (tpm2b(&private), tpm2b(&public))
    }

    pub(in crate::library::tpm2::command) fn load_external(
        private: &[u8],
        public: &[u8],
    ) -> Vec<u8> {
        let mut parameters = private.to_vec();
        parameters.extend_from_slice(public);
        parameters.extend_from_slice(&TPM_RH_NULL.to_be_bytes());
        cmd(CC_LOAD_EXTERNAL, &[], None, &parameters)
    }

    pub(in crate::library::tpm2::command) fn public_point() -> EccPoint {
        point_multiply(CURVE_P256, None, &PRIVATE_SCALAR).expect("the public point")
    }

    pub(in crate::library::tpm2::command) fn sign_key() -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_SIGN,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    pub(in crate::library::tpm2::command) fn decrypt_key(auth: &[u8]) -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, auth),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    pub(in crate::library::tpm2::command) fn generator_multiple(scalar: u64) -> EccPoint {
        let curve = curve_parameters(CURVE_P256).expect("NIST P256");
        let value = crate::library::tpm2::crypto::BigUint::from_u64(scalar)
            .to_be_bytes(curve.order.byte_len())
            .expect("a scalar");
        point_multiply(CURVE_P256, None, &value).expect("a generator multiple")
    }

    pub(in crate::library::tpm2::command) fn off_curve_point() -> EccPoint {
        let mut point = generator_multiple(2);
        let last = point.y.len() - 1;
        point.y[last] ^= 0x01;
        point
    }

    pub(in crate::library::tpm2::command) fn message(length: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index * 5 + 1) & 0xff) as u8)
            .collect()
    }

    pub(in crate::library::tpm2::command) fn max_message() -> Vec<u8> {
        (0..1024)
            .map(|index| ((index * 3 + 7) & 0xff) as u8)
            .collect()
    }

    fn kdf2(hash_alg: u16, seed: &[u8], length: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut counter: u32 = 1;
        while out.len() < length {
            let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
            hasher.update(seed);
            hasher.update(&counter.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            counter += 1;
        }
        out.truncate(length);
        out
    }

    pub(in crate::library::tpm2::command) struct Ciphertext {
        pub(in crate::library::tpm2::command) c1: EccPoint,
        pub(in crate::library::tpm2::command) c2: Vec<u8>,
        pub(in crate::library::tpm2::command) c3: Vec<u8>,
    }

    pub(in crate::library::tpm2::command) fn ciphertext(
        ephemeral: &[u8],
        plain_text: &[u8],
        hash_alg: u16,
    ) -> Ciphertext {
        let c1 = point_multiply(CURVE_P256, None, ephemeral).expect("C1");
        let p2 = point_multiply(CURVE_P256, Some(&public_point()), ephemeral).expect("P2");
        let mut hasher = Hasher::new(hash_alg).expect("a compiled hash");
        hasher.update(&p2.x);
        hasher.update(plain_text);
        hasher.update(&p2.y);
        let c3 = hasher.finalize();
        let mut seed = p2.x.clone();
        seed.extend_from_slice(&p2.y);
        let mut c2 = kdf2(hash_alg, &seed, plain_text.len());
        for (masked, clear) in c2.iter_mut().zip(plain_text) {
            *masked ^= clear;
        }
        Ciphertext { c1, c2, c3 }
    }

    pub(in crate::library::tpm2::command) fn decrypt_parameters(
        cipher: &Ciphertext,
        scheme: &[u8],
    ) -> Vec<u8> {
        let mut out = point2b(&cipher.c1);
        out.extend_from_slice(&tpm2b(&cipher.c2));
        out.extend_from_slice(&tpm2b(&cipher.c3));
        out.extend_from_slice(scheme);
        out
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn restored(snapshot: &str) -> Tpm2Runtime {
        let mut runtime = restore_permanent_blob_for_test(vector(&format!("PERMALL_{snapshot}")))
            .expect("the oracle permanent state restores");
        attach_volatile_blob_for_test(&mut runtime, vector(&format!("VOLATILE_{snapshot}")))
            .expect("the oracle volatile state attaches");
        runtime
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn rebooted(snapshot: &str) -> Tpm2Runtime {
        restore_permanent_blob_for_test(vector(&format!("PERMALL_{snapshot}")))
            .expect("the oracle permanent state restores")
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn ready() -> Tpm2Runtime {
        let runtime = restored("READY");
        assert!(runtime.startup_received, "READY is past TPM2_Startup");
        runtime
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn ready_with(loads: &[Vec<u8>]) -> Tpm2Runtime {
        let mut runtime = ready();
        for (index, packet) in loads.iter().enumerate() {
            let response = dispatch_bytes(&mut runtime, packet);
            assert_eq!(
                response_code(&response),
                0,
                "setup command {index} succeeds"
            );
        }
        runtime
    }

    #[track_caller]
    pub(in crate::library::tpm2::command) fn expect(
        runtime: &mut Tpm2Runtime,
        record: &str,
        packet: &[u8],
    ) -> Vec<u8> {
        let response = dispatch_bytes(runtime, packet);
        assert_eq!(response, vector(record), "record {record}");
        response
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        ALG_NULL, ATTR_DECRYPT, ATTR_SIGN, CC_COMMIT, CC_EC_EPHEMERAL, CC_ECC_ENCRYPT,
        CC_ECC_PARAMETERS, CC_ECDH_KEYGEN, CC_ECDH_ZGEN, CC_STARTUP, CC_ZGEN_2PHASE, CURVE_P256,
        CURVE_P384, H0, KDF_NULL, KDF1_SHA256, KDF2_SHA256, KDF2_SHA384, KEY_AUTH, KEYED_AUTH,
        PRIVATE_SCALAR, SCHEME_ECDAA, SCHEME_ECDH, SCHEME_NULL, SHA256, SHA384, TPM_RH_NULL, cmd,
        decrypt_key, ecc_private, ecc_public, expect, framed, generator_multiple, keyed_object,
        load_external, point2b, public_point, pw, raw_point2b, ready, ready_with, rebooted, tpm2b,
    };
    use crate::library::tpm2::algorithm::TPM_ALG_ECDH;
    use crate::library::tpm2::command::core::registry::{
        TPM_CC_COMMIT, TPM_CC_EC_EPHEMERAL, TPM_CC_ECC_DECRYPT, TPM_CC_ECC_ENCRYPT,
        TPM_CC_ECC_PARAMETERS, TPM_CC_ECDH_KEY_GEN, TPM_CC_ECDH_ZGEN, TPM_CC_ZGEN_2_PHASE, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        all_algorithms, dispatch_bytes, response_code, response_parameters,
    };
    use crate::library::tpm2::command::upstream_implements;
    use crate::library::tpm2::commit::CommitState;

    const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    const ECC_COMMANDS: [u32; 8] = [
        TPM_CC_ECDH_ZGEN,
        TPM_CC_ECDH_KEY_GEN,
        TPM_CC_ECC_PARAMETERS,
        TPM_CC_COMMIT,
        TPM_CC_ZGEN_2_PHASE,
        TPM_CC_EC_EPHEMERAL,
        TPM_CC_ECC_ENCRYPT,
        TPM_CC_ECC_DECRYPT,
    ];

    fn ecdh_key() -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_ECDH,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn two_phase(counter: u16) -> Vec<u8> {
        let mut parameters = point2b(&generator_multiple(2));
        parameters.extend_from_slice(&point2b(&generator_multiple(3)));
        parameters.extend_from_slice(&0x0019u16.to_be_bytes());
        parameters.extend_from_slice(&counter.to_be_bytes());
        cmd(CC_ZGEN_2PHASE, &[H0], Some(&pw(&[])), &parameters)
    }

    #[test]
    fn command_implementation_reference_registry_match() {
        for code in ECC_COMMANDS {
            assert!(upstream_implements(code), "code {code:#x}");
            assert!(find(code).is_some(), "code {code:#x} is registered");
        }
    }

    #[test]
    fn key_kdf_scheme_rejection() {
        let point = public_point();
        let mut runtime = ready();
        for (record, sensitive) in [
            ("LOAD_KDF2_REJECTED", ecc_private(&PRIVATE_SCALAR, &[])),
            ("LOAD_KDF2_PUBLIC_REJECTED", tpm2b(&[])),
        ] {
            expect(
                &mut runtime,
                record,
                &load_external(
                    &sensitive,
                    &ecc_public(
                        ATTR_DECRYPT,
                        &SCHEME_NULL,
                        CURVE_P256,
                        &KDF2_SHA256,
                        &point.x,
                        &point.y,
                    ),
                ),
            );
        }
        expect(
            &mut runtime,
            "LOAD_KDF1_REJECTED",
            &load_external(
                &ecc_private(&PRIVATE_SCALAR, &[]),
                &ecc_public(
                    ATTR_DECRYPT,
                    &SCHEME_NULL,
                    CURVE_P256,
                    &KDF1_SHA256,
                    &point.x,
                    &point.y,
                ),
            ),
        );
    }

    #[test]
    fn public_only_key_auth_rejection_keygen_success() {
        let point = public_point();
        let public_only = load_external(
            &tpm2b(&[]),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        );
        let mut runtime = ready_with(&[public_only]);
        expect(
            &mut runtime,
            "ZGEN_PUBLIC_ONLY",
            &cmd(
                CC_ECDH_ZGEN,
                &[H0],
                Some(&pw(&[])),
                &point2b(&generator_multiple(2)),
            ),
        );
        expect(
            &mut runtime,
            "KEYGEN_PUBLIC_ONLY",
            &cmd(CC_ECDH_KEYGEN, &[H0], None, &[]),
        );
    }

    #[test]
    fn two_phase_foreign_key_type_key_error() {
        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        let mut parameters = point2b(&generator_multiple(2));
        parameters.extend_from_slice(&point2b(&generator_multiple(3)));
        parameters.extend_from_slice(&0x0019u16.to_be_bytes());
        parameters.extend_from_slice(&0u16.to_be_bytes());
        expect(
            &mut runtime,
            "ZGEN2_WRONG_TYPE",
            &cmd(CC_ZGEN_2PHASE, &[H0], Some(&pw(KEYED_AUTH)), &parameters),
        );
    }

    #[test]
    fn hmac_session_agreement_authorization() {
        let mut runtime = ready_with(&[load_external(
            &ecc_private(&PRIVATE_SCALAR, KEY_AUTH),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &public_point().x,
                &public_point().y,
            ),
        )]);
        let session = expect(
            &mut runtime,
            "ZGEN_SESSION",
            &start_auth_session(&nonce_caller()),
        );
        let nonce_tpm = response_parameters(&session)[6..6 + 32].to_vec();
        let point = point2b(&generator_multiple(2));
        expect(
            &mut runtime,
            "ZGEN_HMAC_AUTH",
            &cmd(
                CC_ECDH_ZGEN,
                &[H0],
                Some(&hmac_session(KEY_AUTH, &nonce_tpm, &point)),
                &point,
            ),
        );

        let mut runtime = ready_with(&[load_external(
            &ecc_private(&PRIVATE_SCALAR, KEY_AUTH),
            &ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &public_point().x,
                &public_point().y,
            ),
        )]);
        dispatch_bytes(&mut runtime, &start_auth_session(&nonce_caller()));
        expect(
            &mut runtime,
            "ZGEN_HMAC_WRONG",
            &cmd(
                CC_ECDH_ZGEN,
                &[H0],
                Some(&hmac_session(b"bad", &nonce_tpm, &point)),
                &point,
            ),
        );
    }

    fn nonce_caller() -> Vec<u8> {
        (0..32)
            .map(|index| ((index * 11 + 5) & 0xff) as u8)
            .collect()
    }

    fn start_auth_session(nonce: &[u8]) -> Vec<u8> {
        let mut parameters = tpm2b(nonce);
        parameters.extend_from_slice(&tpm2b(&[]));
        parameters.push(0x00);
        parameters.extend_from_slice(&ALG_NULL.to_be_bytes());
        parameters.extend_from_slice(&SHA256.to_be_bytes());
        cmd(
            CC_START_AUTH_SESSION,
            &[TPM_RH_NULL, TPM_RH_NULL],
            None,
            &parameters,
        )
    }

    fn hmac_session(auth: &[u8], nonce_tpm: &[u8], parameters: &[u8]) -> Vec<u8> {
        use crate::library::tpm2::crypto::{Hasher, HmacState};
        let name = {
            let point = public_point();
            let public = ecc_public(
                ATTR_DECRYPT,
                &SCHEME_NULL,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            );
            let mut hasher = Hasher::new(SHA256).expect("SHA-256");
            hasher.update(&public[2..]);
            let mut name = SHA256.to_be_bytes().to_vec();
            name.extend_from_slice(&hasher.finalize());
            name
        };
        let mut hasher = Hasher::new(SHA256).expect("SHA-256");
        hasher.update(&CC_ECDH_ZGEN.to_be_bytes());
        hasher.update(&name);
        hasher.update(parameters);
        let cp_hash = hasher.finalize();

        let nonce = nonce_caller();
        let mut hmac = HmacState::new(SHA256, auth).expect("SHA-256");
        hmac.update(&cp_hash);
        hmac.update(&nonce);
        hmac.update(nonce_tpm);
        hmac.update(&[0x00]);
        let mac = hmac.finalize();

        let mut area = 0x0200_0000u32.to_be_bytes().to_vec();
        area.extend_from_slice(&tpm2b(&nonce));
        area.push(0x00);
        area.extend_from_slice(&tpm2b(&mac));
        area
    }

    fn profile_runtime(
        algorithms: &str,
        attributes: &str,
    ) -> crate::library::tpm2::runtime::Tpm2Runtime {
        use crate::library::tpm2::manufacture::manufacture_state;
        use crate::library::tpm2::profile::validate_user_profile;
        use crate::library::tpm2::runtime::commit_manufactured_state;

        let json = format!(
            r#"{{"Name":"custom","Algorithms":"{algorithms}","Attributes":"{attributes}"}}"#
        );
        let profile =
            validate_user_profile(Some(json.as_bytes())).expect("the custom profile validates");
        let state = manufacture_state(profile, |buffer| {
            let len = buffer.len() as u8;
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (index as u8).wrapping_add(len) ^ 0x55;
            }
            Ok(())
        })
        .expect("manufactures");
        let mut runtime = commit_manufactured_state(state).expect("commits");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x8001, CC_STARTUP, &[0x00, 0x00])
            )),
            0,
            "the custom-profile TPM starts up"
        );
        runtime
    }

    #[test]
    fn profile_gate_kdf_rejection() {
        const TPM_RC_TYPE_CODE: u32 = 0x0000_008a;
        let mut runtime = profile_runtime(&all_algorithms(), "no-ecc-key-derivation");
        let point = public_point();
        let key = load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_SIGN,
                &SCHEME_ECDAA,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        );
        assert_eq!(response_code(&dispatch_bytes(&mut runtime, &key)), 0);

        let mut commit_parameters = raw_point2b(&[], &[]);
        commit_parameters.extend_from_slice(&tpm2b(&[]));
        commit_parameters.extend_from_slice(&tpm2b(&[]));
        for packet in [
            cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
            cmd(CC_COMMIT, &[H0], Some(&pw(&[])), &commit_parameters),
            two_phase(0),
        ] {
            assert_eq!(
                response_code(&dispatch_bytes(&mut runtime, &packet)),
                TPM_RC_TYPE_CODE,
                "the gate answers a bare TPM_RC_TYPE"
            );
        }

        let mut allowed = profile_runtime(&all_algorithms(), "");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut allowed,
                &cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes())
            )),
            0,
            "the same request succeeds without the attribute"
        );
    }

    #[test]
    fn profile_disabled_curve_rejection() {
        const TPM_RC_CURVE_P1: u32 = 0x0000_01e6;
        let algorithms = all_algorithms()
            .split(',')
            .filter(|token| *token != "ecc-nist")
            .chain(["ecc-nist-p256", "ecc-nist-p384"])
            .collect::<Vec<_>>()
            .join(",");
        let mut runtime = profile_runtime(&algorithms, "");
        for curve in [0x0001u16, 0x0002, 0x0005] {
            for code in [CC_ECC_PARAMETERS, CC_EC_EPHEMERAL] {
                assert_eq!(
                    response_code(&dispatch_bytes(
                        &mut runtime,
                        &cmd(code, &[], None, &curve.to_be_bytes())
                    )),
                    TPM_RC_CURVE_P1,
                    "curve {curve:#06x} is disabled for {code:#x}"
                );
            }
        }
        for curve in [CURVE_P256, CURVE_P384] {
            assert_eq!(
                response_code(&dispatch_bytes(
                    &mut runtime,
                    &cmd(CC_ECC_PARAMETERS, &[], None, &curve.to_be_bytes())
                )),
                0,
                "curve {curve:#06x} stays enabled"
            );
        }
    }

    fn ecdaa_key() -> Vec<u8> {
        let point = public_point();
        load_external(
            &ecc_private(&PRIVATE_SCALAR, &[]),
            &ecc_public(
                ATTR_SIGN,
                &SCHEME_ECDAA,
                CURVE_P256,
                &KDF_NULL,
                &point.x,
                &point.y,
            ),
        )
    }

    fn commit_packet(p1: &[u8], s2: &[u8], y2: &[u8]) -> Vec<u8> {
        let mut parameters = p1.to_vec();
        parameters.extend_from_slice(&tpm2b(s2));
        parameters.extend_from_slice(&tpm2b(y2));
        cmd(CC_COMMIT, &[H0], Some(&pw(&[])), &parameters)
    }

    fn commit_operand() -> (Vec<u8>, Vec<u8>) {
        use crate::library::tpm2::crypto::{BigUint, Hasher, curve_parameters};
        let curve = curve_parameters(CURVE_P256).expect("NIST P256");
        let b = BigUint::from_be_bytes(&[
            0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98,
            0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e,
            0x27, 0xd2, 0x60, 0x4b,
        ]);
        for index in 0..100_000u32 {
            let s2 = format!("commit-point-{index}").into_bytes();
            let mut hasher = Hasher::new(SHA256).expect("SHA-256");
            hasher.update(&s2);
            let x = BigUint::from_be_bytes(&hasher.finalize())
                .rem(&curve.prime)
                .expect("a reduced abscissa");
            let rhs = x
                .mod_mul(&x, &curve.prime)
                .and_then(|square| square.mod_mul(&x, &curve.prime))
                .and_then(|cube| {
                    curve
                        .a
                        .mod_mul(&x, &curve.prime)
                        .and_then(|a_x| cube.mod_add(&a_x, &curve.prime))
                })
                .and_then(|value| value.mod_add(&b, &curve.prime))
                .expect("the curve ordinate");
            let root = rhs
                .mod_exp(&curve.prime.add_u64(1).shr(2), &curve.prime)
                .expect("a candidate root");
            if root.mod_mul(&root, &curve.prime).expect("a square") == rhs {
                return (s2, root.to_be_bytes(32).expect("32 bytes"));
            }
        }
        panic!("no quadratic residue found");
    }

    fn commit_state(runtime: &crate::library::tpm2::runtime::Tpm2Runtime) -> (u64, [u8; 16]) {
        let state = CommitState::load(runtime).expect("the commitment state loads");
        (state.counter, state.array)
    }

    #[test]
    fn ecc_command_pre_operation_lazy_self_tests() {
        use crate::library::tpm2::self_test::PrimitiveTest;
        const SHA512: u16 = 0x000d;
        let (s2, y2) = commit_operand();
        let cases = [
            (
                "TPM2_ECDH_ZGen",
                vec![decrypt_key(&[])],
                cmd(
                    CC_ECDH_ZGEN,
                    &[H0],
                    Some(&pw(&[])),
                    &point2b(&generator_multiple(2)),
                ),
                vec![TPM_ALG_ECDH],
            ),
            (
                "TPM2_ECDH_KeyGen",
                vec![decrypt_key(&[])],
                cmd(CC_ECDH_KEYGEN, &[H0], None, &[]),
                vec![TPM_ALG_ECDH],
            ),
            (
                "TPM2_EC_Ephemeral",
                vec![],
                cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
                vec![SHA512, TPM_ALG_ECDH],
            ),
            (
                "TPM2_Commit",
                vec![ecdaa_key()],
                commit_packet(&raw_point2b(&[], &[]), &s2, &y2),
                vec![SHA512, SHA256, TPM_ALG_ECDH],
            ),
            (
                "TPM2_ECC_Encrypt",
                vec![decrypt_key(&[])],
                {
                    let mut parameters = tpm2b(b"gate");
                    parameters.extend_from_slice(&KDF2_SHA384);
                    cmd(CC_ECC_ENCRYPT, &[H0], None, &parameters)
                },
                vec![TPM_ALG_ECDH, SHA384],
            ),
            (
                "TPM2_ZGen_2Phase",
                vec![
                    decrypt_key(&[]),
                    cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
                ],
                two_phase(0),
                vec![SHA512, TPM_ALG_ECDH],
            ),
        ];

        for (label, setup, packet, expected) in cases {
            let mut runtime = ready_with(&setup);
            runtime.self_test = runtime.self_test.restarted();
            let before = runtime.self_test.pending_algorithms();
            for algorithm in &expected {
                assert!(before.contains(algorithm), "{label}: {algorithm:#06x}");
            }
            let response = dispatch_bytes(&mut runtime, &packet);
            assert_eq!(response_code(&response), 0, "{label} succeeds");
            let after = runtime.self_test.pending_algorithms();
            for algorithm in &expected {
                assert!(
                    !after.contains(algorithm),
                    "{label} clears {algorithm:#06x}"
                );
            }
            for algorithm in before {
                assert!(
                    expected.contains(&algorithm) || after.contains(&algorithm),
                    "{label} cleared {algorithm:#06x}, which it never uses"
                );
            }
            let _ = PrimitiveTest::Ecdh;
        }
    }

    #[test]
    fn pre_arithmetic_rejection_no_ecdh_self_test() {
        let (private, public) = keyed_object();
        let mut runtime = ready_with(&[load_external(&private, &public)]);
        let before = runtime.self_test.pending_algorithms();
        dispatch_bytes(&mut runtime, &cmd(CC_ECDH_KEYGEN, &[H0], None, &[]));
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            before,
            "a wrong key type never reaches the ECC arithmetic"
        );

        let mut runtime = ready();
        let before = runtime.self_test.pending_algorithms();
        dispatch_bytes(
            &mut runtime,
            &cmd(CC_EC_EPHEMERAL, &[], None, &0x0006u16.to_be_bytes()),
        );
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            before,
            "an unusable curve never reaches the commitment KDF"
        );
    }

    #[test]
    fn injected_ecdh_failure_stop_no_output() {
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::self_test::fails_on_ecdh;
        const FAILURE: u32 = 0x0000_0101;
        let (s2, y2) = commit_operand();
        let cases = [
            (
                "TPM2_ECDH_ZGen",
                vec![decrypt_key(&[])],
                cmd(
                    CC_ECDH_ZGEN,
                    &[H0],
                    Some(&pw(&[])),
                    &point2b(&generator_multiple(2)),
                ),
            ),
            (
                "TPM2_ECDH_KeyGen",
                vec![decrypt_key(&[])],
                cmd(CC_ECDH_KEYGEN, &[H0], None, &[]),
            ),
            (
                "TPM2_EC_Ephemeral",
                vec![],
                cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
            ),
            (
                "TPM2_Commit",
                vec![ecdaa_key()],
                commit_packet(&raw_point2b(&[], &[]), &s2, &y2),
            ),
            ("TPM2_ECC_Encrypt", vec![decrypt_key(&[])], {
                let mut parameters = tpm2b(b"gate");
                parameters.extend_from_slice(&KDF2_SHA256);
                cmd(CC_ECC_ENCRYPT, &[H0], None, &parameters)
            }),
            (
                "TPM2_ZGen_2Phase",
                vec![
                    decrypt_key(&[]),
                    cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
                ],
                two_phase(0),
            ),
        ];

        for (label, setup, packet) in cases {
            let mut runtime = ready_with(&setup);
            runtime.self_test = runtime.self_test.restarted();
            let commitment = commit_state(&runtime);
            let objects = runtime.live.objects.len();
            let drbg = runtime.live.orderly.drbg_state.seed.expose().to_vec();
            let sessions = runtime.live.sessions.clone();
            runtime.self_test.set_runner(fails_on_ecdh);

            let response = dispatch_bytes(&mut runtime, &packet);
            assert_eq!(response_code(&response), FAILURE, "{label}");
            assert_eq!(response.len(), 10, "{label} publishes no parameters");
            assert!(runtime.failure_mode, "{label} stops the TPM");
            assert_eq!(
                runtime.failure_diagnostics,
                FailureLocation::EcdhSelfTest.diagnostics(),
                "{label} names the vendored TestECDH site"
            );
            assert_eq!(
                commit_state(&runtime),
                commitment,
                "{label} commits nothing"
            );
            assert_eq!(runtime.live.objects.len(), objects, "{label} loads nothing");
            assert_eq!(
                runtime.live.sessions.len(),
                sessions.len(),
                "{label} leaves the session slots alone"
            );
            if label != "TPM2_ECC_Encrypt" && label != "TPM2_ECDH_KeyGen" {
                assert_eq!(
                    runtime.live.orderly.drbg_state.seed.expose(),
                    &drbg[..],
                    "{label} never reaches the generator"
                );
            }
        }
    }

    #[test]
    fn injected_hash_failure_hashing_command_stop() {
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::self_test::fails_on_sha512;
        const FAILURE: u32 = 0x0000_0101;
        let mut runtime = ready();
        let commitment = commit_state(&runtime);
        runtime.self_test.set_runner(fails_on_sha512);
        let response = dispatch_bytes(
            &mut runtime,
            &cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
        );
        assert_eq!(response_code(&response), FAILURE);
        assert!(runtime.failure_mode);
        assert_eq!(
            runtime.failure_diagnostics,
            FailureLocation::HashSelfTest.diagnostics()
        );
        assert_eq!(commit_state(&runtime), commitment);
        assert!(
            runtime
                .self_test
                .pending_algorithms()
                .contains(&TPM_ALG_ECDH),
            "the context hash fails before the ECDH test runs"
        );
    }

    #[test]
    fn canceled_commit_no_allocation() {
        use crate::library::cancel::CancellationToken;
        use crate::library::tpm2::command::core::test_support::dispatch_bytes_with;
        const CANCELED: u32 = 0x0000_0909;
        let (s2, y2) = commit_operand();
        for (label, packet) in [
            (
                "after K and before L",
                commit_packet(&raw_point2b(&[], &[]), &s2, &y2),
            ),
            (
                "after L and before E",
                commit_packet(&point2b(&generator_multiple(2)), &s2, &y2),
            ),
        ] {
            let mut runtime = ready_with(&[ecdaa_key()]);
            let commitment = commit_state(&runtime);

            let response =
                dispatch_bytes_with(&mut runtime, &packet, CancellationToken::requested());
            assert_eq!(response_code(&response), CANCELED, "{label}");
            assert_eq!(response.len(), 10, "{label} publishes no points");
            assert!(!runtime.failure_mode, "{label} is not fatal");
            assert_eq!(
                commit_state(&runtime),
                commitment,
                "{label} leaves the commitment state alone"
            );

            let retried = dispatch_bytes(&mut runtime, &packet);
            assert_eq!(response_code(&retried), 0, "{label} succeeds once cleared");
            let (counter, _) = commit_state(&runtime);
            assert_eq!(counter, commitment.0 + 1, "{label} then commits once");
        }
    }

    #[test]
    fn single_point_commit_no_cancel_checkpoint() {
        use crate::library::cancel::CancellationToken;
        use crate::library::tpm2::command::core::test_support::dispatch_bytes_with;
        let mut runtime = ready_with(&[ecdaa_key()]);
        for packet in [
            commit_packet(&raw_point2b(&[], &[]), &[], &[]),
            commit_packet(&point2b(&generator_multiple(2)), &[], &[]),
        ] {
            let response =
                dispatch_bytes_with(&mut runtime, &packet, CancellationToken::requested());
            assert_eq!(
                response_code(&response),
                0,
                "the [r]G and [r]P1 paths have no vendored checkpoint"
            );
        }
    }

    #[test]
    fn resume_commit_preservation_reset_drop() {
        let mut runtime = ready();
        dispatch_bytes(
            &mut runtime,
            &cmd(CC_EC_EPHEMERAL, &[], None, &CURVE_P256.to_be_bytes()),
        );
        assert!(
            CommitState::load(&runtime)
                .expect("the commitment state loads")
                .is_set(0)
        );

        let mut runtime = rebooted("AFTER_SU_STATE");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x8001, CC_STARTUP, &0x0001u16.to_be_bytes())
            )),
            0,
            "TPM2_Startup(TPM_SU_STATE) resumes"
        );
        dispatch_bytes(&mut runtime, &ecdh_key());
        expect(&mut runtime, "RESUME_ZGEN2", &two_phase(0));

        let mut runtime = rebooted("AFTER_SU_STATE");
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x8001, CC_STARTUP, &0x0000u16.to_be_bytes())
            )),
            0,
            "TPM2_Startup(TPM_SU_CLEAR) after an orderly state shutdown restarts"
        );
        dispatch_bytes(&mut runtime, &ecdh_key());
        expect(&mut runtime, "RESTART_ZGEN2", &two_phase(0));

        let mut runtime = rebooted("AFTER_SU_CLEAR");
        dispatch_bytes(
            &mut runtime,
            &framed(0x8001, CC_STARTUP, &0x0000u16.to_be_bytes()),
        );
        dispatch_bytes(&mut runtime, &ecdh_key());
        expect(&mut runtime, "ORDERLY_RESET_ZGEN2", &two_phase(0));
    }

    #[test]
    fn unorderly_restart_commit_reset_resume_rejection() {
        let mut runtime = rebooted("BEFORE_UNORDERLY");
        expect(
            &mut runtime,
            "UNORDERLY_STARTUP_STATE",
            &framed(0x8001, CC_STARTUP, &0x0001u16.to_be_bytes()),
        );
        assert_eq!(
            response_code(&dispatch_bytes(
                &mut runtime,
                &framed(0x8001, CC_STARTUP, &0x0000u16.to_be_bytes())
            )),
            0,
            "TPM2_Startup(TPM_SU_CLEAR) still works"
        );
        dispatch_bytes(&mut runtime, &ecdh_key());
        expect(&mut runtime, "RESET_ZGEN2", &two_phase(0));
        let commit = CommitState::load(&runtime).expect("the commitment state loads");
        assert!(!commit.is_set(0), "the reset cleared the bitmap");
        assert_eq!(commit.counter, 0);
    }
}
