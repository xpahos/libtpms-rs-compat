use serde::Serialize;

use super::catalog::{Area, Scenario};
use super::integrity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Implemented,
    Outstanding,
}

pub fn status(scenario: Scenario) -> Status {
    match scenario {
        Scenario::ActivateCredential(_)
        | Scenario::LoadIntegrity(_)
        | Scenario::SignTicket
        | Scenario::PasswordAuth
            if !integrity::IMPLEMENTED =>
        {
            Status::Outstanding
        }
        _ => Status::Implemented,
    }
}

pub fn implemented(scenario: Scenario) -> bool {
    status(scenario) == Status::Implemented
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExclusionKind {
    Unsupported,
    Excluded,
    Outstanding,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Exclusion {
    pub area: Area,
    pub configuration: &'static str,
    pub kind: ExclusionKind,
    pub reason: &'static str,
}

pub const EXCLUSIONS: &[Exclusion] = &[
    Exclusion {
        area: Area::AuthenticationIntegrity,
        configuration: "bound+salted sessions, and request protection composed with response protection or with other session hashes",
        kind: ExclusionKind::Outstanding,
        reason: "auth-hmac-bound-* cover bound HMAC sessions for every hash, auth-hmac-salted-sha256 covers an ECC salted session, auth-hmac-request-{aes-cfb,xor} cover multiple-session nonce binding and request parameter protection on SHA-256, auth-hmac-{bound,salted}-secret-* and auth-hmac-request-secret-{aes-cfb,xor} vary equal-length session-secret material between successful classes; compounds of these features and further hashes/salts remain unmeasured",
    },
    Exclusion {
        area: Area::Rsa,
        configuration: "RSA-4096 (all operations)",
        kind: ExclusionKind::Unsupported,
        reason: "compiled out in both backends: default-v1 allows 1024/2048/3072 bits (C TpmProfile_Common.h, Rust MAX_RSA_KEY_BITS = 3072)",
    },
    Exclusion {
        area: Area::Symmetric,
        configuration: "SM4",
        kind: ExclusionKind::Unsupported,
        reason: "compiled out in the C reference (ALG_SM4 NO) and absent from the Rust port",
    },
    Exclusion {
        area: Area::Mac,
        configuration: "SM3, SHA3, SHAKE based HMAC",
        kind: ExclusionKind::Unsupported,
        reason: "hash algorithms compiled out in both backends",
    },
    Exclusion {
        area: Area::Mac,
        configuration: "TPM2_HMAC / TPM2_HMAC_Start command codes",
        kind: ExclusionKind::Unsupported,
        reason: "CC_HMAC and CC_HMAC_Start are compiled out in the C reference because CMAC is enabled; TPM2_MAC (0x155) and TPM2_MAC_Start reach the same HMAC code and are what the scenarios use",
    },
    Exclusion {
        area: Area::Mac,
        configuration: "HMAC keys longer than 128 bytes",
        kind: ExclusionKind::Unsupported,
        reason: "the TPM2B_SENSITIVE_DATA transport buffer (MAX_SYM_DATA = 128) bounds NULL-scheme MAC keys in both backends (C CryptHash/TpmTypes buffer, Rust keyed_hash_key_limit TPM_ALG_NULL = 128); 128 bytes already reaches the SHA-384/512 block, and SHA-1/SHA-256 keys of 63/64/65/128 bytes are measured by mac-hmac-long-*",
    },
    Exclusion {
        area: Area::Mac,
        configuration: "signing-digest HMAC variants for other session compositions",
        kind: ExclusionKind::Outstanding,
        reason: "mac-sequence-* scenarios cover MAC_Start/SequenceUpdate/SequenceComplete for every supported HMAC hash and CMAC key with chunk boundaries at zero, one, block-1, block and block+1; further session compositions are a separate follow-up",
    },
    Exclusion {
        area: Area::Rsa,
        configuration: "RSA_Decrypt OAEP label digests other than the measured set",
        kind: ExclusionKind::Excluded,
        reason: "same OAEP decode path for every digest: SHA-1, SHA-256, SHA-384 and SHA-512 are measured on every mathematically valid key size (RSA-1024 with SHA-384 allows at most 30 message bytes; RSA-1024 with SHA-512 cannot encode even an empty message and is excluded by construction)",
    },
    Exclusion {
        area: Area::Rsa,
        configuration: "RSA_Decrypt RSAES padding beyond the measured encoding kinds",
        kind: ExclusionKind::Outstanding,
        reason: "rsa-decrypt-*-rsaes now measures valid and malformed PKCS#1 v1.5 encodings, including separator boundary positions (PS length 7 and the minimum 8) and an invalid/invalid pair with equal independently predicted implicit-rejection lengths; per-backend outcomes are resolved by fixed independent capability probes against two independently computed contracts (explicit TPM_RC_VALUE, OpenSSL implicit rejection with an exact synthetic plaintext); other malformed-padding constructions are future work",
    },
    Exclusion {
        area: Area::Rsa,
        configuration: "RSA_Encrypt, VerifySignature (RSA)",
        kind: ExclusionKind::Excluded,
        reason: "public-key operations: no TPM-held secret is involved",
    },
    Exclusion {
        area: Area::EcdhKeyExchange,
        configuration: "ECDH_KeyGen, ECC_Encrypt, VerifySignature (ECC)",
        kind: ExclusionKind::Excluded,
        reason: "public-key operations or a fresh internal ephemeral per call: the caller cannot choose a secret per class; the point multiplication they share is measured by the ECDH_ZGen scenarios",
    },
    Exclusion {
        area: Area::EcdhKeyExchange,
        configuration: "ZGen_2Phase with ECMQV (both backends)",
        kind: ExclusionKind::Excluded,
        reason: "registered for all eight curves as named known-functional-failure SKIP; pinned C divides by an uninitialized order and Rust preserves failure mode. Native isolated probes reproduce TPM_RC_FAILURE on every curve. --disable-known-case-skips probes in disposable workers; no passing oracle or timing claim",
    },
    Exclusion {
        area: Area::EcdhKeyExchange,
        configuration: "ZGen_2Phase SM2 on P521/BN638, pinned 64-bit C reference only",
        kind: ExclusionKind::Excluded,
        reason: "native-confirmed known functional failure: unreduced ephemeral scalar times associated value overflows CRYPT_ECC_NUM(Ta)'s 704-bit allocation before reduction, triggering BnFromBytes assertion and TPM_RC_FAILURE. Named skip with isolated opt-out probe; all eight Rust SM2 curves remain measured and independently checked against explicit vendored-compatibility equations",
    },
    Exclusion {
        area: Area::Symmetric,
        configuration: "TPM2_EncryptDecrypt (0x164)",
        kind: ExclusionKind::Excluded,
        reason: "differs from TPM2_EncryptDecrypt2 only in parameter order; both call the same symmetric code, which the EncryptDecrypt2 scenarios measure",
    },
    Exclusion {
        area: Area::Symmetric,
        configuration: "symmetric modes beyond CFB/OFB/CTR/CBC/ECB",
        kind: ExclusionKind::Excluded,
        reason: "the sym-partial-* scenarios exercise every supported cipher, key size and direction with final blocks of zero, partial, exact, block-plus-one and double-block-minus-one bytes in the stream-like modes, and verify the expected TPM_RC_SIZE rejection of partial blocks in CBC and ECB",
    },
    Exclusion {
        area: Area::KeyDerivation,
        configuration: "KDF2 and KDF1_SP800_56A as object key schemes",
        kind: ExclusionKind::Unsupported,
        reason: "the pinned reference rejects any ECC object whose kdf scheme is not NULL; KDF1_SP800_56A (KDFe) is reached through salted sessions instead",
    },
    Exclusion {
        area: Area::KeyGeneration,
        configuration: "TPM2_Create / CreateLoaded with TPM-random keys",
        kind: ExclusionKind::Outstanding,
        reason: "the secret is drawn inside the operation, so a two-class experiment cannot assign it to a class; in the C reference this path uses OpenSSL key generation instead of the seeded sieve measured by CreatePrimary; needs a per-sample correlation design",
    },
    Exclusion {
        area: Area::KeyGeneration,
        configuration: "keygen-primary-rsa1024/2048/3072 at full dudect budgets",
        kind: ExclusionKind::Outstanding,
        reason: "each measurement generates a fresh RSA primary key, so a dudect budget of tens of thousands of samples per class does not finish in practical wall-clock time; the scenarios are implemented and functionally checked, and searches with small evaluation budgets run, but campaigns should bound them explicitly (observed: verify of keygen-primary-rsa2048 made no progress within hours on the validation VM)",
    },
    Exclusion {
        area: Area::AuthenticationIntegrity,
        configuration: "policy digest comparison",
        kind: ExclusionKind::Excluded,
        reason: "compares against the object's authPolicy, which is public",
    },
];

#[cfg(test)]
mod tests {
    use super::super::catalog::all_scenarios;
    use super::*;

    #[test]
    fn every_area_is_accounted_for() {
        for area in Area::ALL {
            let has_scenario = all_scenarios().iter().any(|s| s.area() == area);
            let has_exclusion = EXCLUSIONS.iter().any(|e| e.area == area);
            assert!(
                has_scenario || has_exclusion,
                "{area:?} has neither scenarios nor exclusions"
            );
        }
    }
}
