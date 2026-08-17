use super::Fixture;

const MAGIC: &[u8; 8] = b"CPORACLE";

const FIXTURE: Fixture = Fixture::new(
    "TPM2_CreatePrimary",
    MAGIC,
    include_bytes!("../testdata/oracles/create_primary.bin"),
);

#[track_caller]
pub(in crate::library::tpm2) fn vector(name: &str) -> &'static [u8] {
    FIXTURE.get(name)
}

const EK_POLICY_SHA256: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

const EK_POLICY_SHA384: [u8; 48] = [
    0xb2, 0x6e, 0x7d, 0x28, 0xd1, 0x1a, 0x50, 0xbc, 0x53, 0xd8, 0x82, 0xbc, 0xf5, 0xfd, 0x3a, 0x1a,
    0x07, 0x41, 0x48, 0xbb, 0x35, 0xd3, 0xb4, 0xe4, 0xcb, 0x1c, 0x0a, 0xd9, 0xbd, 0xe4, 0x19, 0xca,
    0xcb, 0x47, 0xba, 0x09, 0x69, 0x96, 0x46, 0x15, 0x0f, 0x9f, 0xc0, 0x00, 0xf3, 0xf8, 0x0e, 0x12,
];

const SYM_AES128_CFB: [u8; 6] = [0x00, 0x06, 0x00, 0x80, 0x00, 0x43];
const SYM_AES256_CFB: [u8; 6] = [0x00, 0x06, 0x01, 0x00, 0x00, 0x43];
const SYM_NULL: [u8; 2] = [0x00, 0x10];

const TPM_ALG_NULL: u16 = 0x0010;
const TYPE_RSA: u16 = 0x0001;
const TYPE_ECC: u16 = 0x0023;
const TYPE_SYMCIPHER: u16 = 0x0025;

fn rsa_template(
    key_bits: u16,
    name_alg: u16,
    key_flags: u32,
    policy: &[u8],
    symmetric: &[u8],
    nonce_bytes: usize,
) -> Vec<u8> {
    let mut out = TYPE_RSA.to_be_bytes().to_vec();
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&key_flags.to_be_bytes());
    out.extend_from_slice(&(policy.len() as u16).to_be_bytes());
    out.extend_from_slice(policy);
    out.extend_from_slice(symmetric);
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&key_bits.to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&(nonce_bytes as u16).to_be_bytes());
    out.resize(out.len() + nonce_bytes, 0x00);
    out
}

fn ecc_template(
    name_alg: u16,
    key_flags: u32,
    policy: &[u8],
    symmetric: &[u8],
    nonce_bytes: usize,
) -> Vec<u8> {
    let mut out = TYPE_ECC.to_be_bytes().to_vec();
    out.extend_from_slice(&name_alg.to_be_bytes());
    out.extend_from_slice(&key_flags.to_be_bytes());
    out.extend_from_slice(&(policy.len() as u16).to_be_bytes());
    out.extend_from_slice(policy);
    out.extend_from_slice(symmetric);
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&0x0004u16.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    for _ in 0..2 {
        out.extend_from_slice(&(nonce_bytes as u16).to_be_bytes());
        out.resize(out.len() + nonce_bytes, 0x00);
    }
    out
}

pub(in crate::library::tpm2) fn null_hierarchy_template() -> Vec<u8> {
    rsa_template(1024, 0x000b, 0x0003_0472, &[], &SYM_AES128_CFB, 0)
}

pub(in crate::library::tpm2) fn oracle_cases() -> Vec<(&'static str, u32, Vec<u8>, &'static [u8])> {
    vec![
        (
            "ek_rsa2048",
            0x4000_000b,
            rsa_template(
                2048,
                0x000b,
                0x0003_00b2,
                &EK_POLICY_SHA256,
                &SYM_AES128_CFB,
                0x100,
            ),
            vector("EK_RSA2048"),
        ),
        (
            "ek_rsa3072",
            0x4000_000b,
            rsa_template(
                3072,
                0x000c,
                0x0003_00f2,
                &EK_POLICY_SHA384,
                &SYM_AES256_CFB,
                0x180,
            ),
            vector("EK_RSA3072"),
        ),
        (
            "ek_ecc_p384",
            0x4000_000b,
            ecc_template(0x000c, 0x0003_00f2, &EK_POLICY_SHA384, &SYM_AES256_CFB, 0),
            vector("EK_ECC_P384"),
        ),
        (
            "spk_rsa2048",
            0x4000_0001,
            rsa_template(2048, 0x000b, 0x0003_0472, &[], &SYM_AES128_CFB, 0x100),
            vector("SPK_RSA2048"),
        ),
        (
            "spk_ecc_p384",
            0x4000_0001,
            ecc_template(0x000c, 0x0003_0472, &[], &SYM_AES256_CFB, 0x30),
            vector("SPK_ECC_P384"),
        ),
        (
            "platform_rsa2048_sign",
            0x4000_000c,
            rsa_template(2048, 0x000b, 0x0004_0472, &[], &SYM_NULL, 0),
            vector("PLATFORM_RSA2048_SIGN"),
        ),
    ]
}

pub(in crate::library::tpm2) const RC_TDES128_SUPPLIED_SHORT: u32 = 0x087;
pub(in crate::library::tpm2) const RC_TDES192_SUPPLIED_SHORT: u32 = 0x087;
pub(in crate::library::tpm2) const RC_TDES128_SUPPLIED_WEAK: u32 = 0x09c;
pub(in crate::library::tpm2) const RC_TDES128_SUPPLIED_SAME: u32 = 0x09c;
pub(in crate::library::tpm2) const RC_TDES192_SUPPLIED_SAME23: u32 = 0x09c;
pub(in crate::library::tpm2) const RC_MIN_RSA1024: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_MIN_RSA2048: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_MIN_ECC_P192: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_MIN_ECC_P224: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_MIN_ECC_P256: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_MIN_AES128: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_MIN_AES192: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_MIN_CAMELLIA128: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_MIN_TDES128: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_MIN_RSA3072_AES128_PARM: u32 = 0x2c4;
pub(in crate::library::tpm2) const RC_NOBN_ECC_BN_P256: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_NOBN_ECC_SM2_P256: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_ONECURVE_ECC_P192: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_ONECURVE_ECC_P521: u32 = 0x2e6;
pub(in crate::library::tpm2) const RC_NOTDES_TDES128: u32 = 0x2d6;

pub(in crate::library::tpm2) const TDES_TWO_KEY: [u8; 16] = [
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
];

pub(in crate::library::tpm2) const TDES_THREE_KEY: [u8; 24] = [
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
    0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
];

pub(in crate::library::tpm2) const TDES_TWO_KEY_NO_PARITY: [u8; 16] = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
];

pub(in crate::library::tpm2) const TDES_TWO_KEY_WEAK: [u8; 16] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
];

pub(in crate::library::tpm2) const TDES_TWO_KEY_REPEATED: [u8; 16] = [
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
];

pub(in crate::library::tpm2) const TDES_THREE_KEY_REPEATED_TAIL: [u8; 24] = [
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
    0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
];

pub(in crate::library::tpm2) const TDES_THREE_KEY_REPEATED_ENDS: [u8; 24] = [
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e, 0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
    0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
];

pub(in crate::library::tpm2) const AES_SUPPLIED_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

pub(in crate::library::tpm2) const SYM_SUPPLIED_ATTRIBUTES: u32 = 0x0002_0052;
pub(in crate::library::tpm2) const SYM_GENERATED_ATTRIBUTES: u32 = 0x0002_0072;
pub(in crate::library::tpm2) const ASYM_STORAGE_ATTRIBUTES: u32 = 0x0003_0472;

pub(in crate::library::tpm2) const MIN_SIZE_PROFILE: &str = "rsa,rsa-min-size=3072,tdes,\
tdes-min-size=192,sha1,hmac,aes,aes-min-size=256,mgf1,keyedhash,xor,sha256,sha384,sha512,null,\
rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,\
kdf1-sp800-108,ecc,ecc-min-size=384,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,\
camellia-min-size=256,cmac,ctr,ofb,cbc,cfb,ecb";

pub(in crate::library::tpm2) const NO_BN_CURVE_PROFILE: &str = "rsa,tdes,sha1,hmac,aes,mgf1,\
keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,\
ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-nist,symcipher,camellia,cmac,ctr,\
ofb,cbc,cfb,ecb";

pub(in crate::library::tpm2) const TWO_CURVE_PROFILE: &str = "rsa,tdes,sha1,hmac,aes,mgf1,\
keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,\
ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-nist-p256,ecc-nist-p384,symcipher,\
camellia,cmac,ctr,ofb,cbc,cfb,ecb";

pub(in crate::library::tpm2) const NO_TDES_PROFILE: &str = "rsa,sha1,hmac,aes,mgf1,keyedhash,\
xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,\
kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,cmac,\
ctr,ofb,cbc,cfb,ecb";

pub(in crate::library::tpm2) fn symcipher_template(
    symmetric: u16,
    key_bits: u16,
    attributes: u32,
) -> Vec<u8> {
    let mut out = TYPE_SYMCIPHER.to_be_bytes().to_vec();
    out.extend_from_slice(&0x000bu16.to_be_bytes());
    out.extend_from_slice(&attributes.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&symmetric.to_be_bytes());
    out.extend_from_slice(&key_bits.to_be_bytes());
    out.extend_from_slice(&0x0043u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

pub(in crate::library::tpm2) fn asym_rsa_template(key_bits: u16, sym_key_bits: u16) -> Vec<u8> {
    let mut symmetric = 0x0006u16.to_be_bytes().to_vec();
    symmetric.extend_from_slice(&sym_key_bits.to_be_bytes());
    symmetric.extend_from_slice(&0x0043u16.to_be_bytes());
    rsa_template(
        key_bits,
        0x000b,
        ASYM_STORAGE_ATTRIBUTES,
        &[],
        &symmetric,
        0,
    )
}

pub(in crate::library::tpm2) fn asym_ecc_template(curve_id: u16, sym_key_bits: u16) -> Vec<u8> {
    let mut out = TYPE_ECC.to_be_bytes().to_vec();
    out.extend_from_slice(&0x000bu16.to_be_bytes());
    out.extend_from_slice(&ASYM_STORAGE_ATTRIBUTES.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0x0006u16.to_be_bytes());
    out.extend_from_slice(&sym_key_bits.to_be_bytes());
    out.extend_from_slice(&0x0043u16.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&curve_id.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::oracles;

    const EXPECTED: [(&str, usize, &str); 17] = [
        (
            "AES128_GENERATED",
            274,
            "b9fed7d4d1d873cee8c88bea684ad6ab4775825fd809ef9f60b3928428a31848",
        ),
        (
            "AES128_SUPPLIED_OK",
            274,
            "53e59c548be6156119435ab15cf3c09b5471220f15e13b0e69ff1eff919ce4c6",
        ),
        (
            "EK_ECC_P384",
            442,
            "d4d01c15226a9d641cf20cf3258a5c142bb824926114e32e1f74ce1066d37393",
        ),
        (
            "EK_RSA2048",
            538,
            "3a7a0f62887bfa92191b6fb93f22679c9a4b7ffca9a09903ac3d791fe0d959d2",
        ),
        (
            "EK_RSA3072",
            730,
            "e9509fc89aa5755a7d8a21ab246c0113ed8a269aa5ad5d65b013b51728782023",
        ),
        (
            "NULL_RSA1024",
            378,
            "739365e5f0217521401df8309e9579460e010e3c3a2d8f33cec75bcb2fcaf846",
        ),
        (
            "PERMALL",
            1978,
            "9f052c1986e36a56e7b0b9aff28217f043706a70426c99b4d53d22281eab7f83",
        ),
        (
            "PLATFORM_RSA2048_SIGN",
            502,
            "096b34e24debe8ad6bdcbd5da75126a63c55296621ad1060ea6b721eee52e8eb",
        ),
        (
            "SPK_ECC_P384",
            394,
            "18026e5c00d7f37e7f7e17d54175d7cbbd37c67d83f8fbafbee535bf80e8ddb9",
        ),
        (
            "SPK_RSA2048",
            506,
            "b5f5e1f22e8f393e329a32fc1e1352028ebec18aece7b27458532dc72e98c782",
        ),
        (
            "SYM_PERMALL",
            1978,
            "a6db9d9ab49dd29877cb87f3d246bbbde0d01289e4809c5270909f07bc5e3f1b",
        ),
        (
            "TDES128_GENERATED",
            274,
            "7b4ba282c2a2ec4c9d219317875231420aaa48272a9525691fdb141d7ee0338a",
        ),
        (
            "TDES128_SUPPLIED_BAD_PARITY",
            274,
            "c43fcd9231aadd3f605c97602e804d4dbfb1937c9a9e694d9db6ff1aa4fcbcba",
        ),
        (
            "TDES128_SUPPLIED_OK",
            274,
            "826fb46994326b0303fe89c24f59cc425ad0d0fdb6819db1abdbabe8a36f7fd2",
        ),
        (
            "TDES192_GENERATED",
            274,
            "2b2931969cbd18772729296d782688abe808324ab8a84a4fed8c9b2cdb25c8f5",
        ),
        (
            "TDES192_SUPPLIED_OK",
            274,
            "cf00cd7ba40edce5a1c7341b439189b8c0504565804206d2f2e857b3ecc5a91e",
        ),
        (
            "TDES192_SUPPLIED_SAME13",
            274,
            "c4bcef74895f81b2855b128af03632272d1efa3b198c8123326c2ddcd7e428a7",
        ),
    ];

    #[test]
    fn every_named_vector_still_decodes_to_its_original_bytes() {
        oracles::assert_records_match(&FIXTURE, &EXPECTED);
    }

    #[test]
    fn the_record_names_are_sorted_and_unique() {
        oracles::assert_names_are_sorted_and_unique(&FIXTURE);
    }

    #[test]
    fn a_missing_vector_is_reported_rather_than_guessed() {
        assert!(FIXTURE.find("NOT_A_VECTOR").is_none());
        assert!(FIXTURE.find("").is_none());
        for (name, _, _) in EXPECTED {
            assert_eq!(vector(name), FIXTURE.find(name).expect("present"));
        }
    }

    #[test]
    fn a_corrupted_header_is_rejected() {
        oracles::assert_rejects_a_corrupted_header(&FIXTURE);
    }

    #[test]
    fn a_corrupted_record_is_rejected() {
        oracles::assert_rejects_a_corrupted_record(&FIXTURE);
    }

    #[test]
    fn truncated_and_extended_fixtures_are_rejected() {
        oracles::assert_rejects_truncation_and_trailing_bytes(&FIXTURE);
    }

    #[test]
    fn the_evict_control_magic_does_not_open_this_fixture() {
        let foreign = oracles::synthesize(b"ECORACLE", oracles::VERSION, 1, &[("ALPHA", &[0xaa])]);
        assert!(FIXTURE.parse(&foreign).is_none());
    }
}
