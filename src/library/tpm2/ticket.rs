use super::algorithm::TPM_ALG_SHA512;
use super::crypto::HmacState;
use super::hierarchy::TPM_RH_NULL;
use super::marshal::{BlobWriteError, BlobWriter};

pub(super) const TPM_ST_VERIFIED: u16 = 0x8022;
pub(super) const TPM_ST_AUTH_SECRET: u16 = 0x8023;
pub(super) const TPM_ST_HASHCHECK: u16 = 0x8024;
pub(super) const TPM_ST_AUTH_SIGNED: u16 = 0x8025;
pub(super) const TPM_GENERATED_VALUE: u32 = 0xff54_4347;
pub(super) const GENERATED_VALUE_SIZE: usize = size_of::<u32>();

pub(super) const CONTEXT_INTEGRITY_HASH_ALG: u16 = TPM_ALG_SHA512;

pub(super) struct Ticket {
    pub(super) tag: u16,
    pub(super) hierarchy: u32,
    pub(super) digest: Vec<u8>,
}

impl Ticket {
    pub(super) fn empty(tag: u16) -> Self {
        Self {
            tag,
            hierarchy: TPM_RH_NULL,
            digest: Vec::new(),
        }
    }

    pub(super) fn marshal(&self, writer: &mut BlobWriter) -> Result<(), BlobWriteError> {
        writer.write_u16(self.tag);
        writer.write_u32(self.hierarchy);
        writer.write_tpm2b(&self.digest)
    }

    pub(super) fn into_bytes(self) -> Result<Vec<u8>, BlobWriteError> {
        let mut writer = BlobWriter::new();
        self.marshal(&mut writer)?;
        Ok(writer.into_bytes())
    }
}

pub(super) fn ticket_is_safe(data: &[u8]) -> bool {
    let Some(leading) = data.first_chunk::<GENERATED_VALUE_SIZE>() else {
        return false;
    };
    *leading != TPM_GENERATED_VALUE.to_be_bytes()
}

pub(super) fn compute_hash_check(
    hierarchy: u32,
    proof: &[u8],
    hash_alg: u16,
    digest: &[u8],
) -> Option<Ticket> {
    let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, proof)?;
    hmac.update(&TPM_ST_HASHCHECK.to_be_bytes());
    hmac.update(&hash_alg.to_be_bytes());
    hmac.update(digest);
    Some(Ticket {
        tag: TPM_ST_HASHCHECK,
        hierarchy,
        digest: hmac.finalize(),
    })
}

pub(super) struct AuthTicketInput<'a> {
    pub(super) tag: u16,
    pub(super) hierarchy: u32,
    pub(super) timeout: u64,
    pub(super) expires_on_reset: bool,
    pub(super) cp_hash: &'a [u8],
    pub(super) policy_ref: &'a [u8],
    pub(super) entity_name: &'a [u8],
    pub(super) time_epoch: u32,
    pub(super) total_reset_count: u64,
}

pub(super) fn compute_auth(proof: &[u8], input: &AuthTicketInput<'_>) -> Option<Ticket> {
    let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, proof)?;
    hmac.update(&input.tag.to_be_bytes());
    hmac.update(input.cp_hash);
    hmac.update(input.policy_ref);
    hmac.update(input.entity_name);
    hmac.update(&input.timeout.to_be_bytes());
    if input.timeout != 0 {
        hmac.update(&input.time_epoch.to_be_bytes());
        if input.expires_on_reset {
            hmac.update(&input.total_reset_count.to_be_bytes());
        }
    }
    Some(Ticket {
        tag: input.tag,
        hierarchy: input.hierarchy,
        digest: hmac.finalize(),
    })
}

pub(super) fn compute_verified(
    hierarchy: u32,
    proof: &[u8],
    digest: &[u8],
    key_name: &[u8],
) -> Option<Ticket> {
    let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, proof)?;
    hmac.update(&TPM_ST_VERIFIED.to_be_bytes());
    hmac.update(digest);
    hmac.update(key_name);
    Some(Ticket {
        tag: TPM_ST_VERIFIED,
        hierarchy,
        digest: hmac.finalize(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::hash_vectors::{HashTicketCase, hash_ticket_record};
    use super::super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM};
    use super::*;

    fn ticket_bytes(ticket: &Ticket) -> Vec<u8> {
        let mut writer = BlobWriter::new();
        ticket.marshal(&mut writer).expect("the ticket marshals");
        writer.into_bytes()
    }

    fn oracle_ticket_bytes(case: &HashTicketCase) -> Vec<u8> {
        let digest_size = usize::from(u16::from_be_bytes(
            case.parameters[..2].try_into().expect("a digest header"),
        ));
        case.parameters[2 + digest_size..].to_vec()
    }

    #[test]
    fn the_constants_match_upstream() {
        assert_eq!(TPM_ST_VERIFIED, 0x8022);
        assert_eq!(TPM_ST_HASHCHECK, 0x8024);
        assert_eq!(TPM_GENERATED_VALUE, 0xff54_4347);
        assert_eq!(GENERATED_VALUE_SIZE, 4);
        assert_eq!(CONTEXT_INTEGRITY_HASH_ALG, 0x000d);
    }

    #[test]
    fn a_buffer_shorter_than_the_generated_value_is_never_safe() {
        assert!(!ticket_is_safe(&[]));
        assert!(!ticket_is_safe(&[0xff]));
        assert!(!ticket_is_safe(&[0xff, 0x54]));
        assert!(!ticket_is_safe(&[0xff, 0x54, 0x43]));
        assert!(!ticket_is_safe(&[0x11, 0x22, 0x33]));
    }

    #[test]
    fn a_leading_generated_value_is_not_safe() {
        assert!(!ticket_is_safe(&[0xff, 0x54, 0x43, 0x47]));
        assert!(!ticket_is_safe(&[0xff, 0x54, 0x43, 0x47, 0x00]));
        assert!(!ticket_is_safe(&[0xff, 0x54, 0x43, 0x47, 0xff, 0xff]));
    }

    #[test]
    fn any_other_four_leading_bytes_are_safe() {
        assert!(ticket_is_safe(&[0xff, 0x54, 0x43, 0x48]));
        assert!(ticket_is_safe(&[0xff, 0x54, 0x43, 0x46]));
        assert!(ticket_is_safe(&[0xfe, 0x54, 0x43, 0x47]));
        assert!(ticket_is_safe(&[0x00, 0x00, 0x00, 0x00]));
        assert!(ticket_is_safe(&[0x47, 0x43, 0x54, 0xff]));
    }

    #[test]
    fn the_empty_ticket_is_a_null_hierarchy_hashcheck() {
        let ticket = Ticket::empty(TPM_ST_HASHCHECK);
        assert_eq!(ticket.tag, TPM_ST_HASHCHECK);
        assert_eq!(ticket.hierarchy, TPM_RH_NULL);
        assert!(ticket.digest.is_empty());
        assert_eq!(ticket_bytes(&ticket), [0x80, 0x24, 0x40, 0, 0, 0x07, 0, 0]);
    }

    #[test]
    fn a_computed_ticket_matches_the_vendored_oracle() {
        let record = hash_ticket_record();
        for case in record.cases.iter().filter(|case| case.expects_a_ticket()) {
            let proof = record.proof_for(case.hierarchy).expect("a real hierarchy");
            let digest_size = usize::from(u16::from_be_bytes(
                case.parameters[..2].try_into().expect("a digest header"),
            ));
            let out_hash = &case.parameters[2..2 + digest_size];
            let ticket = compute_hash_check(case.hierarchy, proof, case.hash_alg, out_hash)
                .expect("the compiled integrity algorithm");
            assert_eq!(
                ticket_bytes(&ticket),
                oracle_ticket_bytes(case),
                "{}",
                case.label()
            );
        }
    }

    #[test]
    fn a_ticket_digest_is_a_full_sha512_mac() {
        let ticket = compute_hash_check(TPM_RH_OWNER, &[0x5a; 64], 0x000b, &[0x11; 32])
            .expect("the compiled integrity algorithm");
        assert_eq!(ticket.digest.len(), 64);
        assert_eq!(ticket.tag, TPM_ST_HASHCHECK);
        assert_eq!(ticket.hierarchy, TPM_RH_OWNER);
    }

    #[test]
    fn changing_any_input_changes_the_ticket_digest() {
        let base = compute_hash_check(TPM_RH_OWNER, &[0x5a; 64], 0x000b, &[0x11; 32])
            .expect("the compiled integrity algorithm");
        for other in [
            compute_hash_check(TPM_RH_PLATFORM, &[0x5b; 64], 0x000b, &[0x11; 32]),
            compute_hash_check(TPM_RH_OWNER, &[0x5a; 64], 0x000c, &[0x11; 32]),
            compute_hash_check(TPM_RH_OWNER, &[0x5a; 64], 0x000b, &[0x12; 32]),
            compute_hash_check(TPM_RH_OWNER, &[0x5a; 63], 0x000b, &[0x11; 32]),
        ] {
            let other = other.expect("the compiled integrity algorithm");
            assert_ne!(base.digest, other.digest);
        }
    }

    #[test]
    fn the_hierarchy_travels_with_the_ticket_without_entering_the_mac() {
        let owner = compute_hash_check(TPM_RH_OWNER, &[0x5a; 64], 0x000b, &[0x11; 32])
            .expect("the compiled integrity algorithm");
        let endorsement = compute_hash_check(TPM_RH_ENDORSEMENT, &[0x5a; 64], 0x000b, &[0x11; 32])
            .expect("the compiled integrity algorithm");
        assert_eq!(owner.digest, endorsement.digest, "the proof is the key");
        assert_ne!(ticket_bytes(&owner), ticket_bytes(&endorsement));
    }

    #[test]
    fn the_empty_verified_ticket_is_a_null_hierarchy_tag_only_ticket() {
        let ticket = Ticket::empty(TPM_ST_VERIFIED);
        assert_eq!(
            ticket.into_bytes().expect("the ticket marshals"),
            [0x80, 0x22, 0x40, 0, 0, 0x07, 0, 0]
        );
    }

    #[test]
    fn a_verified_ticket_macs_the_tag_the_digest_and_the_key_name() {
        let proof = [0x5a; 64];
        let digest = [0x11; 32];
        let name = [0x22; 34];
        let ticket = compute_verified(TPM_RH_OWNER, &proof, &digest, &name)
            .expect("the compiled integrity algorithm");
        assert_eq!(ticket.tag, TPM_ST_VERIFIED);
        assert_eq!(ticket.hierarchy, TPM_RH_OWNER);

        let mut hmac = HmacState::new(CONTEXT_INTEGRITY_HASH_ALG, &proof)
            .expect("the compiled integrity algorithm");
        hmac.update(&TPM_ST_VERIFIED.to_be_bytes());
        hmac.update(&digest);
        hmac.update(&name);
        assert_eq!(
            ticket.digest,
            hmac.finalize(),
            "upstream feeds the buffers without their size prefixes"
        );
        assert_eq!(ticket.digest.len(), 64);
    }

    #[test]
    fn changing_the_digest_or_the_key_name_changes_the_verified_ticket() {
        let base = compute_verified(TPM_RH_OWNER, &[0x5a; 64], &[0x11; 32], &[0x22; 34])
            .expect("the compiled integrity algorithm");
        for other in [
            compute_verified(TPM_RH_OWNER, &[0x5b; 64], &[0x11; 32], &[0x22; 34]),
            compute_verified(TPM_RH_OWNER, &[0x5a; 64], &[0x12; 32], &[0x22; 34]),
            compute_verified(TPM_RH_OWNER, &[0x5a; 64], &[0x11; 32], &[0x23; 34]),
        ] {
            let other = other.expect("the compiled integrity algorithm");
            assert_ne!(base.digest, other.digest);
        }
    }

    #[test]
    fn a_verified_ticket_is_not_a_hash_check_over_the_same_inputs() {
        let verified = compute_verified(TPM_RH_OWNER, &[0x5a; 64], &[0x11; 32], &[])
            .expect("the compiled integrity algorithm");
        let hash_check =
            compute_hash_check(TPM_RH_OWNER, &[0x5a; 64], TPM_ST_VERIFIED, &[0x11; 32])
                .expect("the compiled integrity algorithm");
        assert_ne!(verified.digest, hash_check.digest, "the tags differ");
    }

    #[test]
    fn a_marshalled_ticket_is_the_tag_the_hierarchy_and_a_sized_digest() {
        let ticket = compute_hash_check(TPM_RH_PLATFORM, &[0x01; 64], 0x0004, &[0x22; 20])
            .expect("the compiled integrity algorithm");
        let bytes = ticket_bytes(&ticket);
        assert_eq!(bytes.len(), 2 + 4 + 2 + 64);
        assert_eq!(&bytes[..2], &[0x80, 0x24]);
        assert_eq!(&bytes[2..6], &TPM_RH_PLATFORM.to_be_bytes());
        assert_eq!(&bytes[6..8], &[0x00, 0x40]);
        assert_eq!(&bytes[8..], &ticket.digest[..]);
    }
}
