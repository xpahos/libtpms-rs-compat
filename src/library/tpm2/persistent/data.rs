use core::fmt;

use super::{NvHeader, PersistentAllError, PersistentField, StateSection, parse_nv_header};
use crate::library::tpm2::marshal::{BlobReader, Tpm2bError};

pub(in crate::library::tpm2) const PERSISTENT_DATA_MAGIC: u32 = 0x1221_3443;
const PERSISTENT_DATA_VERSION: u16 = 5;

const MAX_DIGEST_SIZE: usize = 64;
const PRIMARY_SEED_SIZE: usize = 64;
const PROOF_SIZE: usize = 64;

#[derive(Clone, Copy)]
pub(in crate::library::tpm2) struct SecretBytes<'a>(&'a [u8]);

impl<'a> SecretBytes<'a> {
    #[cfg(test)]
    pub(in crate::library::tpm2) fn expose(self) -> &'a [u8] {
        self.0
    }

    pub(in crate::library::tpm2) fn to_owned_secret(self) -> super::attach::OwnedSecret {
        super::attach::OwnedSecret::copy_of(self.0)
    }
}

impl fmt::Debug for SecretBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes {{ len: {} }}", self.0.len())
    }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::library::tpm2) struct PersistentDataPrefix<'a> {
    pub(in crate::library::tpm2) header: NvHeader,

    pub(in crate::library::tpm2) disable_clear: bool,

    pub(in crate::library::tpm2) owner_alg: u16,
    pub(in crate::library::tpm2) endorsement_alg: u16,
    pub(in crate::library::tpm2) lockout_alg: u16,

    pub(in crate::library::tpm2) owner_policy: &'a [u8],
    pub(in crate::library::tpm2) endorsement_policy: &'a [u8],
    pub(in crate::library::tpm2) lockout_policy: &'a [u8],

    pub(in crate::library::tpm2) owner_auth: SecretBytes<'a>,
    pub(in crate::library::tpm2) endorsement_auth: SecretBytes<'a>,
    pub(in crate::library::tpm2) lockout_auth: SecretBytes<'a>,

    pub(in crate::library::tpm2) ep_seed: SecretBytes<'a>,
    pub(in crate::library::tpm2) sp_seed: SecretBytes<'a>,
    pub(in crate::library::tpm2) pp_seed: SecretBytes<'a>,

    pub(in crate::library::tpm2) ph_proof: SecretBytes<'a>,
    pub(in crate::library::tpm2) sh_proof: SecretBytes<'a>,
    pub(in crate::library::tpm2) eh_proof: SecretBytes<'a>,

    pub(in crate::library::tpm2) total_reset_count: u64,
    pub(in crate::library::tpm2) reset_count: u32,

    pub(in crate::library::tpm2) remaining: &'a [u8],
}

const SECTION: StateSection = StateSection::PersistentData;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

fn read_tpm2b_field<'a>(
    reader: &mut BlobReader<'a>,
    field: PersistentField,
    maximum: usize,
) -> Result<&'a [u8], PersistentAllError> {
    reader.read_tpm2b(maximum).map_err(|error| match error {
        Tpm2bError::Truncated => truncated(),
        Tpm2bError::SizeExceeded { actual, maximum } => PersistentAllError::Tpm2bSizeExceeded {
            section: SECTION,
            field,
            actual,
            maximum,
        },
    })
}

fn read_secret_field<'a>(
    reader: &mut BlobReader<'a>,
    field: PersistentField,
    maximum: usize,
) -> Result<SecretBytes<'a>, PersistentAllError> {
    Ok(SecretBytes(read_tpm2b_field(reader, field, maximum)?))
}

pub(in crate::library::tpm2) fn parse_persistent_data_prefix(
    input: &[u8],
) -> Result<PersistentDataPrefix<'_>, PersistentAllError> {
    use PersistentField as F;

    let mut reader = BlobReader::new(input);

    let header = parse_nv_header(
        &mut reader,
        SECTION,
        PERSISTENT_DATA_MAGIC,
        PERSISTENT_DATA_VERSION,
    )?;

    let disable_clear = reader.read_bool().map_err(|_| truncated())?;

    let owner_alg = reader.read_u16().map_err(|_| truncated())?;
    let endorsement_alg = reader.read_u16().map_err(|_| truncated())?;
    let lockout_alg = reader.read_u16().map_err(|_| truncated())?;

    let owner_policy = read_tpm2b_field(&mut reader, F::OwnerPolicy, MAX_DIGEST_SIZE)?;
    let endorsement_policy = read_tpm2b_field(&mut reader, F::EndorsementPolicy, MAX_DIGEST_SIZE)?;
    let lockout_policy = read_tpm2b_field(&mut reader, F::LockoutPolicy, MAX_DIGEST_SIZE)?;

    let owner_auth = read_secret_field(&mut reader, F::OwnerAuth, MAX_DIGEST_SIZE)?;
    let endorsement_auth = read_secret_field(&mut reader, F::EndorsementAuth, MAX_DIGEST_SIZE)?;
    let lockout_auth = read_secret_field(&mut reader, F::LockoutAuth, MAX_DIGEST_SIZE)?;

    let ep_seed = read_secret_field(&mut reader, F::EpSeed, PRIMARY_SEED_SIZE)?;
    let sp_seed = read_secret_field(&mut reader, F::SpSeed, PRIMARY_SEED_SIZE)?;
    let pp_seed = read_secret_field(&mut reader, F::PpSeed, PRIMARY_SEED_SIZE)?;

    let ph_proof = read_secret_field(&mut reader, F::PhProof, PROOF_SIZE)?;
    let sh_proof = read_secret_field(&mut reader, F::ShProof, PROOF_SIZE)?;
    let eh_proof = read_secret_field(&mut reader, F::EhProof, PROOF_SIZE)?;

    let total_reset_count = reader.read_u64().map_err(|_| truncated())?;
    let reset_count = reader.read_u32().map_err(|_| truncated())?;

    Ok(PersistentDataPrefix {
        header,
        disable_clear,
        owner_alg,
        endorsement_alg,
        lockout_alg,
        owner_policy,
        endorsement_policy,
        lockout_policy,
        owner_auth,
        endorsement_auth,
        lockout_auth,
        ep_seed,
        sp_seed,
        pp_seed,
        ph_proof,
        sh_proof,
        eh_proof,
        total_reset_count,
        reset_count,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
pub(in crate::library::tpm2) struct PrefixFixture {
    pub(in crate::library::tpm2) version: u16,
    pub(in crate::library::tpm2) min_version: u16,
    pub(in crate::library::tpm2) disable_clear: u8,
    pub(in crate::library::tpm2) algs: [u16; 3],
    pub(in crate::library::tpm2) tpm2bs: [Vec<u8>; 12],
    pub(in crate::library::tpm2) total_reset_count: u64,
    pub(in crate::library::tpm2) reset_count: u32,
    pub(in crate::library::tpm2) tail: Vec<u8>,
}

#[cfg(test)]
impl Default for PrefixFixture {
    fn default() -> Self {
        Self {
            version: PERSISTENT_DATA_VERSION,
            min_version: 1,
            disable_clear: 0,
            algs: [0; 3],
            tpm2bs: Default::default(),
            total_reset_count: 0,
            reset_count: 0,
            tail: Vec::new(),
        }
    }
}

#[cfg(test)]
impl PrefixFixture {
    pub(in crate::library::tpm2) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&PERSISTENT_DATA_MAGIC.to_be_bytes());
        if self.version >= 2 {
            out.extend_from_slice(&self.min_version.to_be_bytes());
        }
        out.push(self.disable_clear);
        for alg in self.algs {
            out.extend_from_slice(&alg.to_be_bytes());
        }
        for tpm2b in &self.tpm2bs {
            out.extend_from_slice(&u16::try_from(tpm2b.len()).unwrap().to_be_bytes());
            out.extend_from_slice(tpm2b);
        }
        out.extend_from_slice(&self.total_reset_count.to_be_bytes());
        out.extend_from_slice(&self.reset_count.to_be_bytes());
        out.extend_from_slice(&self.tail);
        out
    }

    pub(in crate::library::tpm2) fn with_tpm2b(index: usize, value: Vec<u8>) -> Self {
        let mut fixture = Self::default();
        fixture.tpm2bs[index] = value;
        fixture
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{TPM_RC_BAD_TAG, TPM_RC_BAD_VERSION, TPM_RC_INSUFFICIENT};

    const TPM2B_FIELDS: [(usize, PersistentField, usize); 12] = [
        (0, PersistentField::OwnerPolicy, MAX_DIGEST_SIZE),
        (1, PersistentField::EndorsementPolicy, MAX_DIGEST_SIZE),
        (2, PersistentField::LockoutPolicy, MAX_DIGEST_SIZE),
        (3, PersistentField::OwnerAuth, MAX_DIGEST_SIZE),
        (4, PersistentField::EndorsementAuth, MAX_DIGEST_SIZE),
        (5, PersistentField::LockoutAuth, MAX_DIGEST_SIZE),
        (6, PersistentField::EpSeed, PRIMARY_SEED_SIZE),
        (7, PersistentField::SpSeed, PRIMARY_SEED_SIZE),
        (8, PersistentField::PpSeed, PRIMARY_SEED_SIZE),
        (9, PersistentField::PhProof, PROOF_SIZE),
        (10, PersistentField::ShProof, PROOF_SIZE),
        (11, PersistentField::EhProof, PROOF_SIZE),
    ];

    fn parse(input: &[u8]) -> Result<PersistentDataPrefix<'_>, PersistentAllError> {
        parse_persistent_data_prefix(input)
    }

    #[test]
    fn hand_built_fixture_upstream_marshal_order_parity() {
        let fixture = [
            0x00, 0x05, 0x12, 0x21, 0x34, 0x43, 0x00, 0x01, 0x01, 0x00, 0x0b, 0x00, 0x0c, 0x00,
            0x0d, 0x00, 0x01, 0xa1, 0x00, 0x01, 0xa2, 0x00, 0x01, 0xa3, 0x00, 0x01, 0xb1, 0x00,
            0x01, 0xb2, 0x00, 0x01, 0xb3, 0x00, 0x01, 0xc1, 0x00, 0x01, 0xc2, 0x00, 0x01, 0xc3,
            0x00, 0x01, 0xd1, 0x00, 0x01, 0xd2, 0x00, 0x01, 0xd3, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00,
        ];
        let prefix = parse(&fixture).unwrap();
        assert_eq!(
            prefix.header,
            NvHeader {
                version: 5,
                magic: PERSISTENT_DATA_MAGIC,
                min_version: 1,
            }
        );
        assert!(prefix.disable_clear);
        assert_eq!(prefix.owner_alg, 0x000b);
        assert_eq!(prefix.endorsement_alg, 0x000c);
        assert_eq!(prefix.lockout_alg, 0x000d);
        assert_eq!(prefix.owner_policy, &[0xa1]);
        assert_eq!(prefix.endorsement_policy, &[0xa2]);
        assert_eq!(prefix.lockout_policy, &[0xa3]);
        assert_eq!(prefix.owner_auth.expose(), &[0xb1]);
        assert_eq!(prefix.endorsement_auth.expose(), &[0xb2]);
        assert_eq!(prefix.lockout_auth.expose(), &[0xb3]);
        assert_eq!(prefix.ep_seed.expose(), &[0xc1]);
        assert_eq!(prefix.sp_seed.expose(), &[0xc2]);
        assert_eq!(prefix.pp_seed.expose(), &[0xc3]);
        assert_eq!(prefix.ph_proof.expose(), &[0xd1]);
        assert_eq!(prefix.sh_proof.expose(), &[0xd2]);
        assert_eq!(prefix.eh_proof.expose(), &[0xd3]);
        assert_eq!(prefix.total_reset_count, 2);
        assert_eq!(prefix.reset_count, 3);
        assert_eq!(prefix.remaining, &[0x01, 0x00, 0x00]);
    }

    #[test]
    fn empty_fields_fixture_tail_preservation() {
        let fixture = PrefixFixture {
            tail: vec![0x00, 0x00, 0x00],
            ..PrefixFixture::default()
        };
        let data = fixture.bytes();
        let prefix = parse(&data).unwrap();
        assert!(!prefix.disable_clear);
        assert_eq!(prefix.owner_alg, 0);
        for (index, field, _) in TPM2B_FIELDS {
            let bytes = tpm2b_bytes(&prefix, index);
            assert_eq!(bytes, &[] as &[u8], "{field:?}");
        }
        assert_eq!(prefix.total_reset_count, 0);
        assert_eq!(prefix.reset_count, 0);
        assert_eq!(prefix.remaining, &[0x00, 0x00, 0x00]);
        assert!(core::ptr::eq(
            prefix.remaining.as_ptr(),
            data[data.len() - 3..].as_ptr()
        ));
    }

    fn tpm2b_bytes<'a>(prefix: &PersistentDataPrefix<'a>, index: usize) -> &'a [u8] {
        match index {
            0 => prefix.owner_policy,
            1 => prefix.endorsement_policy,
            2 => prefix.lockout_policy,
            3 => prefix.owner_auth.expose(),
            4 => prefix.endorsement_auth.expose(),
            5 => prefix.lockout_auth.expose(),
            6 => prefix.ep_seed.expose(),
            7 => prefix.sp_seed.expose(),
            8 => prefix.pp_seed.expose(),
            9 => prefix.ph_proof.expose(),
            10 => prefix.sh_proof.expose(),
            11 => prefix.eh_proof.expose(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn tpm2b_field_wire_position_decode() {
        let mut fixture = PrefixFixture::default();
        for (index, _, _) in TPM2B_FIELDS {
            fixture.tpm2bs[index] = vec![index as u8 + 1; 2];
        }
        let data = fixture.bytes();
        let prefix = parse(&data).unwrap();
        for (index, field, _) in TPM2B_FIELDS {
            assert_eq!(
                tpm2b_bytes(&prefix, index),
                &[index as u8 + 1; 2],
                "{field:?}"
            );
        }
    }

    #[test]
    fn nonempty_field_return_input_borrow() {
        for (index, field, _) in [
            TPM2B_FIELDS[0],
            TPM2B_FIELDS[3],
            TPM2B_FIELDS[6],
            TPM2B_FIELDS[9],
        ] {
            let data = PrefixFixture::with_tpm2b(index, vec![0x5c; 5]).bytes();
            let prefix = parse(&data).unwrap();
            let bytes = tpm2b_bytes(&prefix, index);
            assert_eq!(bytes, &[0x5c; 5], "{field:?}");
            assert!(
                data.as_ptr_range().contains(&bytes.as_ptr()),
                "{field:?} must borrow the input"
            );
        }
    }

    #[test]
    fn unknown_algorithm_id_preservation() {
        let data = PrefixFixture {
            algs: [0xffff, 0x1234, 0x0000],
            ..PrefixFixture::default()
        }
        .bytes();
        let prefix = parse(&data).unwrap();
        assert_eq!(prefix.owner_alg, 0xffff);
        assert_eq!(prefix.endorsement_alg, 0x1234);
        assert_eq!(prefix.lockout_alg, 0x0000);
    }

    #[test]
    fn disable_clear_canonical_and_noncanonical_decoding() {
        for (byte, expected) in [(0x00u8, false), (0x01, true), (0x02, true), (0xff, true)] {
            let data = PrefixFixture {
                disable_clear: byte,
                ..PrefixFixture::default()
            }
            .bytes();
            let prefix = parse(&data).unwrap();
            assert_eq!(prefix.disable_clear, expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn reset_counter_big_endian_read() {
        let data = PrefixFixture {
            total_reset_count: 0x0102_0304_0506_0708,
            reset_count: 0x0a0b_0c0d,
            ..PrefixFixture::default()
        }
        .bytes();
        let prefix = parse(&data).unwrap();
        assert_eq!(prefix.total_reset_count, 0x0102_0304_0506_0708);
        assert_eq!(prefix.reset_count, 0x0a0b_0c0d);
    }

    #[test]
    fn header_magic_and_version_section_consistency() {
        let data = PrefixFixture::default().bytes();
        let prefix = parse(&data).unwrap();
        assert_eq!(prefix.header.version, 5);
        assert_eq!(prefix.header.magic, PERSISTENT_DATA_MAGIC);

        let mut data = PrefixFixture::default().bytes();
        data[2] = 0xff;
        assert_eq!(
            parse(&data).unwrap_err(),
            PersistentAllError::InvalidHeaderMagic {
                section: SECTION,
                actual: 0xff21_3443,
            }
        );
    }

    #[test]
    fn older_version_header_acceptance() {
        for version in [2u16, 3, 4] {
            let data = PrefixFixture {
                version,
                ..PrefixFixture::default()
            }
            .bytes();
            let prefix = parse(&data).unwrap();
            assert_eq!(prefix.header.version, version);
        }
        let data = PrefixFixture {
            version: 1,
            ..PrefixFixture::default()
        }
        .bytes();
        let prefix = parse(&data).unwrap();
        assert_eq!(prefix.header.min_version, 0);
    }

    #[test]
    fn future_version_supported_min_acceptance() {
        let data = PrefixFixture {
            version: 9,
            min_version: 5,
            ..PrefixFixture::default()
        }
        .bytes();
        let prefix = parse(&data).unwrap();
        assert_eq!(prefix.header.version, 9);
    }

    #[test]
    fn min_version_above_5_rejection() {
        let fixture = PrefixFixture {
            version: 9,
            min_version: 6,
            ..PrefixFixture::default()
        };
        let error = parse(&fixture.bytes()).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MinimumVersionTooNew {
                section: SECTION,
                minimum: 6,
                supported: 5,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_BAD_VERSION);
    }

    #[test]
    fn truncated_header_field_error() {
        for len in [0usize, 1, 2, 5, 7] {
            let data = &PrefixFixture::default().bytes()[..len];
            let error = parse(data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::Truncated { section: SECTION },
                "prefix length {len}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
    }

    #[test]
    fn strict_prefix_truncation_panic_safety() {
        let full = PrefixFixture {
            tpm2bs: core::array::from_fn(|index| vec![index as u8; 3]),
            ..PrefixFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            assert_eq!(
                parse(&full[..len]).unwrap_err(),
                PersistentAllError::Truncated { section: SECTION },
                "prefix length {len} of {}",
                full.len()
            );
        }
        assert!(parse(&full).is_ok());
    }

    #[test]
    fn tpm2b_body_truncation_error() {
        for (index, field, _) in TPM2B_FIELDS {
            let full = PrefixFixture::with_tpm2b(index, vec![0x77; 8]).bytes();
            let body_start = full.windows(8).position(|w| w == [0x77; 8]).unwrap();
            let data = &full[..body_start + 4];
            let error = parse(data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::Truncated { section: SECTION },
                "{field:?}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
    }

    #[test]
    fn exact_capacity_acceptance() {
        for (index, field, maximum) in TPM2B_FIELDS {
            let data = PrefixFixture::with_tpm2b(index, vec![0x11; maximum]).bytes();
            let prefix = parse(&data).unwrap_or_else(|error| {
                panic!("{field:?} at capacity {maximum} rejected: {error:?}")
            });
            assert_eq!(tpm2b_bytes(&prefix, index).len(), maximum, "{field:?}");
        }
    }

    #[test]
    fn capacity_plus_one_size_exceeded_rejection() {
        for (index, field, maximum) in TPM2B_FIELDS {
            let data = PrefixFixture::with_tpm2b(index, vec![0x11; maximum + 1]).bytes();
            let error = parse(&data).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::Tpm2bSizeExceeded {
                    section: SECTION,
                    field,
                    actual: (maximum + 1) as u16,
                    maximum,
                },
                "{field:?}"
            );
            assert_eq!(
                error.tpm_result(),
                crate::library::constants::TPM_RC_SIZE,
                "{field:?}"
            );
        }
    }

    #[test]
    fn incorrect_magic_bad_tag_mapping() {
        let mut data = PrefixFixture::default().bytes();
        data[3] = 0x00;
        assert_eq!(parse(&data).unwrap_err().tpm_result(), TPM_RC_BAD_TAG);
    }

    #[test]
    fn debug_output_secret_byte_absence() {
        let auth = b"auth-secret-mark".to_vec();
        let seed = b"seed-secret-mark".to_vec();
        let proof = b"proof-secret-mrk".to_vec();
        let policy = b"policy-is-public".to_vec();
        let mut fixture = PrefixFixture::default();
        fixture.tpm2bs[0] = policy.clone();
        for index in 3..6 {
            fixture.tpm2bs[index] = auth.clone();
        }
        for index in 6..9 {
            fixture.tpm2bs[index] = seed.clone();
        }
        for index in 9..12 {
            fixture.tpm2bs[index] = proof.clone();
        }
        let data = fixture.bytes();
        let prefix = parse(&data).unwrap();
        let formatted = format!("{prefix:?}");
        for secret in ["auth-secret-mark", "seed-secret-mark", "proof-secret-mrk"] {
            assert!(
                !formatted.contains(secret),
                "Debug output must not contain {secret:?}: {formatted}"
            );
        }
        assert!(formatted.contains("SecretBytes { len: 16 }"), "{formatted}");
    }

    #[test]
    fn size_error_field_and_length_disclosure_only() {
        let secret = b"oversized-secret-material-that-must-never-leak-into-diagnostics-!";
        assert_eq!(secret.len(), MAX_DIGEST_SIZE + 1);
        let data = PrefixFixture::with_tpm2b(3, secret.to_vec()).bytes();
        let error = parse(&data).unwrap_err();
        let formatted = format!("{error:?}");
        assert!(formatted.contains("OwnerAuth"), "{formatted}");
        assert!(formatted.contains("65"), "{formatted}");
        assert!(formatted.contains("64"), "{formatted}");
        assert!(!formatted.contains("oversized-secret"), "{formatted}");
    }
}
