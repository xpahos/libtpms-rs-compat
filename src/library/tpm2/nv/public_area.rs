use crate::ffi::types::TpmResult;
use crate::library::constants::{TPM_RC_HASH, TPM_RC_RESERVED_BITS, TPM_RC_SIZE, TPM_RC_VALUE};

use super::attributes::TPMA_NV_RESERVED;
use super::index::MAX_NV_INDEX_SIZE;
use crate::library::tpm2::crypto::Hasher;
use crate::library::tpm2::marshal::BlobWriter;
use crate::library::tpm2::persistent::{OwnedNvIndex, OwnedSecret};
use crate::library::tpm2::template::{TemplateReader, digest_size};

pub(in crate::library::tpm2) const NV_INDEX_FIRST: u32 = 0x0100_0000;
pub(in crate::library::tpm2) const NV_INDEX_LAST: u32 = 0x01ff_ffff;

pub(in crate::library::tpm2) const fn is_nv_index_handle(handle: u32) -> bool {
    handle >= NV_INDEX_FIRST && handle <= NV_INDEX_LAST
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::library::tpm2) struct NvPublic {
    pub(in crate::library::tpm2) nv_index: u32,
    pub(in crate::library::tpm2) name_alg: u16,
    pub(in crate::library::tpm2) attributes: u32,
    pub(in crate::library::tpm2) auth_policy: Vec<u8>,
    pub(in crate::library::tpm2) data_size: u16,
}

impl NvPublic {
    pub(in crate::library::tpm2) fn of(index: &OwnedNvIndex) -> Self {
        Self {
            nv_index: index.nv_index,
            name_alg: index.name_alg,
            attributes: index.attributes,
            auth_policy: index.auth_policy.clone(),
            data_size: index.data_size,
        }
    }

    pub(in crate::library::tpm2) fn into_index(self, auth_value: Vec<u8>) -> OwnedNvIndex {
        OwnedNvIndex {
            nv_index: self.nv_index,
            name_alg: self.name_alg,
            attributes: self.attributes,
            auth_policy: self.auth_policy,
            data_size: self.data_size,
            auth_value: OwnedSecret::from_vec(auth_value),
        }
    }
}

pub(in crate::library::tpm2) fn parse_nv_public(
    reader: &mut TemplateReader<'_>,
) -> Result<NvPublic, TpmResult> {
    let nv_index = reader.u32()?;
    if !is_nv_index_handle(nv_index) {
        return Err(TPM_RC_VALUE);
    }
    let name_alg = reader.u16()?;
    if digest_size(name_alg).is_none() {
        return Err(TPM_RC_HASH);
    }
    let attributes = reader.u32()?;
    if attributes & TPMA_NV_RESERVED != 0 {
        return Err(TPM_RC_RESERVED_BITS);
    }
    let auth_policy = reader.tpm2b(DIGEST_TPM2B_MAX)?.to_vec();
    let data_size = reader.u16()?;
    if u32::from(data_size) > MAX_NV_INDEX_SIZE {
        return Err(TPM_RC_SIZE);
    }
    Ok(NvPublic {
        nv_index,
        name_alg,
        attributes,
        auth_policy,
        data_size,
    })
}

pub(in crate::library::tpm2) const DIGEST_TPM2B_MAX: usize = 64;

pub(in crate::library::tpm2) fn parse_sized_nv_public(
    reader: &mut TemplateReader<'_>,
) -> Result<NvPublic, TpmResult> {
    let declared = usize::from(reader.u16()?);
    if declared == 0 {
        return Err(TPM_RC_SIZE);
    }
    let start = reader.consumed();
    let public = parse_nv_public(reader)?;
    if reader.consumed() - start != declared {
        return Err(TPM_RC_SIZE);
    }
    Ok(public)
}

pub(in crate::library::tpm2) fn marshal_nv_public(public: &NvPublic) -> Vec<u8> {
    let mut writer = BlobWriter::with_capacity(14 + public.auth_policy.len());
    writer.write_u32(public.nv_index);
    writer.write_u16(public.name_alg);
    writer.write_u32(public.attributes);
    writer.write_u16(public.auth_policy.len() as u16);
    writer.write_bytes(&public.auth_policy);
    writer.write_u16(public.data_size);
    writer.into_bytes()
}

pub(in crate::library::tpm2) fn marshal_sized_nv_public(public: &NvPublic) -> Vec<u8> {
    let body = marshal_nv_public(public);
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

pub(in crate::library::tpm2) fn nv_index_name(public: &NvPublic) -> Result<Vec<u8>, TpmResult> {
    let mut hasher = Hasher::new(public.name_alg).ok_or(TPM_RC_HASH)?;
    hasher.update(&marshal_nv_public(public));
    let mut name = public.name_alg.to_be_bytes().to_vec();
    name.extend_from_slice(&hasher.finalize());
    Ok(name)
}

pub(in crate::library::tpm2) fn strip_trailing_zeros(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |position| position + 1);
    &bytes[..end]
}

pub(in crate::library::tpm2) fn checked_auth_value(
    auth: &[u8],
    name_alg: u16,
) -> Result<Vec<u8>, TpmResult> {
    let trimmed = strip_trailing_zeros(auth);
    if trimmed.len() > digest_size(name_alg).unwrap_or(0) {
        return Err(TPM_RC_SIZE);
    }
    Ok(trimmed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_RC_INSUFFICIENT;
    use crate::library::tpm2::algorithm::{
        TPM_ALG_NULL, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512,
    };
    use crate::library::tpm2::nv::attributes::{
        TPMA_NV_AUTHREAD, TPMA_NV_AUTHWRITE, TPMA_NV_OWNERREAD, TPMA_NV_OWNERWRITE,
    };

    fn sample() -> NvPublic {
        NvPublic {
            nv_index: 0x0100_0001,
            name_alg: TPM_ALG_SHA256,
            attributes: TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD,
            auth_policy: Vec::new(),
            data_size: 32,
        }
    }

    fn parse(bytes: &[u8]) -> Result<NvPublic, TpmResult> {
        let mut reader = TemplateReader::new(bytes);
        let public = parse_nv_public(&mut reader)?;
        assert!(reader.remaining().is_empty(), "exact consumption");
        Ok(public)
    }

    #[test]
    fn the_handle_range_matches_the_vendored_constants() {
        assert_eq!(NV_INDEX_FIRST, 0x0100_0000);
        assert_eq!(NV_INDEX_LAST, 0x01ff_ffff);
        assert!(is_nv_index_handle(NV_INDEX_FIRST));
        assert!(is_nv_index_handle(NV_INDEX_LAST));
        assert!(is_nv_index_handle(0x0100_0001));
        for handle in [
            0x0000_0000u32,
            0x00ff_ffff,
            0x0200_0000,
            0x4000_0001,
            0x8100_0000,
            u32::MAX,
        ] {
            assert!(!is_nv_index_handle(handle), "handle {handle:#010x}");
        }
    }

    #[test]
    fn a_public_area_round_trips_through_marshalling() {
        for public in [
            sample(),
            NvPublic {
                auth_policy: vec![0x5a; 32],
                ..sample()
            },
            NvPublic {
                name_alg: TPM_ALG_SHA1,
                auth_policy: vec![0x11; 20],
                data_size: 8,
                attributes: TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD,
                ..sample()
            },
        ] {
            let bytes = marshal_nv_public(&public);
            assert_eq!(parse(&bytes).unwrap(), public);
        }
    }

    #[test]
    fn the_marshalled_layout_is_the_upstream_field_order() {
        let public = NvPublic {
            auth_policy: vec![0xaa, 0xbb],
            ..sample()
        };
        let bytes = marshal_nv_public(&public);
        let mut fields = bytes.as_slice();
        for (name, expected) in [
            ("nvIndex", &[0x01, 0x00, 0x00, 0x01][..]),
            ("nameAlg", &[0x00, 0x0b]),
            ("attributes", &[0x00, 0x02, 0x00, 0x02]),
            ("authPolicy", &[0x00, 0x02, 0xaa, 0xbb]),
            ("dataSize", &[0x00, 0x20]),
        ] {
            let (head, rest) = fields.split_at(expected.len());
            assert_eq!(head, expected, "{name}");
            fields = rest;
        }
        assert!(fields.is_empty(), "the public area has no trailing bytes");
    }

    #[test]
    fn a_sized_public_area_carries_its_own_length() {
        let public = sample();
        let sized = marshal_sized_nv_public(&public);
        assert_eq!(
            u16::from_be_bytes([sized[0], sized[1]]) as usize,
            sized.len() - 2
        );
        let mut reader = TemplateReader::new(&sized);
        assert_eq!(parse_sized_nv_public(&mut reader).unwrap(), public);
        assert!(reader.remaining().is_empty());
    }

    #[test]
    fn a_zero_sized_public_area_is_a_size_error() {
        let mut reader = TemplateReader::new(&[0x00, 0x00]);
        assert_eq!(parse_sized_nv_public(&mut reader), Err(TPM_RC_SIZE));
    }

    #[test]
    fn a_declared_size_that_disagrees_with_the_body_is_a_size_error() {
        let body = marshal_nv_public(&sample());
        for declared in [1u16, (body.len() - 1) as u16, (body.len() + 1) as u16] {
            let mut sized = declared.to_be_bytes().to_vec();
            sized.extend_from_slice(&body);
            let mut reader = TemplateReader::new(&sized);
            let result = parse_sized_nv_public(&mut reader);
            assert!(
                matches!(result, Err(TPM_RC_SIZE) | Err(TPM_RC_INSUFFICIENT)),
                "declared {declared} gave {result:?}"
            );
        }
    }

    #[test]
    fn an_out_of_range_index_handle_is_a_value_error() {
        for handle in [0x0000_0001u32, 0x00ff_ffff, 0x0200_0000, 0x8100_0000] {
            let bytes = marshal_nv_public(&NvPublic {
                nv_index: handle,
                ..sample()
            });
            assert_eq!(parse(&bytes), Err(TPM_RC_VALUE), "handle {handle:#010x}");
        }
    }

    #[test]
    fn an_unsupported_name_algorithm_is_a_hash_error() {
        for alg in [TPM_ALG_NULL, 0x0000, 0x0012, 0xffff] {
            let bytes = marshal_nv_public(&NvPublic {
                name_alg: alg,
                ..sample()
            });
            assert_eq!(parse(&bytes), Err(TPM_RC_HASH), "alg {alg:#06x}");
        }
        for alg in [TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512] {
            let bytes = marshal_nv_public(&NvPublic {
                name_alg: alg,
                ..sample()
            });
            assert!(parse(&bytes).is_ok(), "alg {alg:#06x}");
        }
    }

    #[test]
    fn reserved_attribute_bits_are_rejected() {
        for bit in [8u32, 9, 20, 21, 22, 23, 24] {
            let bytes = marshal_nv_public(&NvPublic {
                attributes: sample().attributes | (1 << bit),
                ..sample()
            });
            assert_eq!(parse(&bytes), Err(TPM_RC_RESERVED_BITS), "bit {bit}");
        }
    }

    #[test]
    fn a_data_size_above_the_implementation_limit_is_a_size_error() {
        for size in [2049u16, 4096, u16::MAX] {
            let bytes = marshal_nv_public(&NvPublic {
                data_size: size,
                ..sample()
            });
            assert_eq!(parse(&bytes), Err(TPM_RC_SIZE), "size {size}");
        }
        let bytes = marshal_nv_public(&NvPublic {
            data_size: 2048,
            ..sample()
        });
        assert!(parse(&bytes).is_ok());
    }

    #[test]
    fn an_oversized_auth_policy_is_a_size_error() {
        let mut bytes = 0x0100_0001u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&65u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 65]);
        bytes.extend_from_slice(&8u16.to_be_bytes());
        let mut reader = TemplateReader::new(&bytes);
        assert_eq!(parse_nv_public(&mut reader), Err(TPM_RC_SIZE));
    }

    #[test]
    fn truncation_at_every_boundary_is_insufficient() {
        let bytes = marshal_nv_public(&NvPublic {
            auth_policy: vec![0x33; 32],
            ..sample()
        });
        for len in 0..bytes.len() {
            let mut reader = TemplateReader::new(&bytes[..len]);
            assert_eq!(
                parse_nv_public(&mut reader),
                Err(TPM_RC_INSUFFICIENT),
                "prefix length {len} of {}",
                bytes.len()
            );
        }
    }

    #[test]
    fn nv_public_area_byte_mutations_do_not_panic() {
        let full = marshal_nv_public(&NvPublic {
            auth_policy: vec![0x33; 8],
            ..sample()
        });
        for index in 0..full.len() {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut data = full.clone();
                data[index] = byte;
                let mut reader = TemplateReader::new(&data);
                let _ = parse_nv_public(&mut reader);
                let mut reader = TemplateReader::new(&data);
                let _ = parse_sized_nv_public(&mut reader);
            }
        }
    }

    #[test]
    fn the_name_is_the_name_algorithm_followed_by_its_digest() {
        let public = sample();
        let name = nv_index_name(&public).unwrap();
        assert_eq!(&name[..2], &TPM_ALG_SHA256.to_be_bytes());
        assert_eq!(name.len(), 2 + 32);

        let mut hasher = Hasher::new(TPM_ALG_SHA256).unwrap();
        hasher.update(&marshal_nv_public(&public));
        assert_eq!(&name[2..], &hasher.finalize()[..]);
    }

    #[test]
    fn the_name_length_follows_the_name_algorithm() {
        for (alg, size) in [
            (TPM_ALG_SHA1, 20),
            (TPM_ALG_SHA256, 32),
            (TPM_ALG_SHA384, 48),
            (TPM_ALG_SHA512, 64),
        ] {
            let name = nv_index_name(&NvPublic {
                name_alg: alg,
                ..sample()
            })
            .unwrap();
            assert_eq!(name.len(), 2 + size, "alg {alg:#06x}");
        }
    }

    #[test]
    fn every_public_field_changes_the_name() {
        let base = nv_index_name(&sample()).unwrap();
        let variants = [
            NvPublic {
                nv_index: 0x0100_0002,
                ..sample()
            },
            NvPublic {
                attributes: sample().attributes | TPMA_NV_AUTHREAD,
                ..sample()
            },
            NvPublic {
                auth_policy: vec![0x01; 32],
                ..sample()
            },
            NvPublic {
                data_size: 33,
                ..sample()
            },
        ];
        for variant in variants {
            assert_ne!(nv_index_name(&variant).unwrap(), base, "{variant:?}");
        }
    }

    #[test]
    fn an_unsupported_name_algorithm_has_no_name() {
        assert_eq!(
            nv_index_name(&NvPublic {
                name_alg: TPM_ALG_NULL,
                ..sample()
            }),
            Err(TPM_RC_HASH)
        );
    }

    #[test]
    fn trailing_zeros_are_stripped_like_upstream() {
        assert_eq!(strip_trailing_zeros(&[]), &[] as &[u8]);
        assert_eq!(strip_trailing_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_trailing_zeros(&[1, 2, 0, 0]), &[1, 2]);
        assert_eq!(strip_trailing_zeros(&[0, 1]), &[0, 1]);
    }

    #[test]
    fn an_auth_value_is_stored_without_its_trailing_zeros() {
        assert_eq!(checked_auth_value(&[], TPM_ALG_SHA256), Ok(Vec::new()));
        assert_eq!(
            checked_auth_value(&[0x00; 32], TPM_ALG_SHA256),
            Ok(Vec::new()),
            "an all-zero authValue normalizes to empty"
        );
        assert_eq!(
            checked_auth_value(&[0x41, 0x42, 0x00, 0x00], TPM_ALG_SHA256),
            Ok(vec![0x41, 0x42])
        );
        assert_eq!(
            checked_auth_value(&[0xaa; 32], TPM_ALG_SHA256),
            Ok(vec![0xaa; 32]),
            "a full-length authValue is kept"
        );
    }

    #[test]
    fn an_auth_value_longer_than_the_name_algorithm_digest_is_a_size_error() {
        assert_eq!(
            checked_auth_value(&[0xaa; 33], TPM_ALG_SHA256),
            Err(TPM_RC_SIZE)
        );
        assert_eq!(
            checked_auth_value(&[0xaa; 21], TPM_ALG_SHA1),
            Err(TPM_RC_SIZE)
        );
        assert_eq!(
            checked_auth_value(&[0xaa; 20], TPM_ALG_SHA1),
            Ok(vec![0xaa; 20])
        );
        let mut padded = vec![0xaa; 20];
        padded.extend_from_slice(&[0x00; 44]);
        assert_eq!(
            checked_auth_value(&padded, TPM_ALG_SHA1),
            Ok(vec![0xaa; 20]),
            "the length is measured after stripping trailing zeros"
        );
    }

    #[test]
    fn an_index_converts_to_and_from_its_public_area() {
        let public = NvPublic {
            auth_policy: vec![0x77; 32],
            ..sample()
        };
        let index = public.clone().into_index(vec![0x01, 0x02]);
        assert_eq!(index.nv_index, public.nv_index);
        assert_eq!(index.auth_value.expose(), &[0x01, 0x02]);
        assert_eq!(NvPublic::of(&index), public);
    }
}
