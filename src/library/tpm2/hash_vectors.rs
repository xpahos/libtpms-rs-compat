use super::hierarchy::{TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM};

const FIXTURE: &[u8] = include_bytes!("testdata/hash_ticket_vectors.bin");

pub(in crate::library::tpm2) struct HashTicketCase {
    pub(in crate::library::tpm2) data: Vec<u8>,
    pub(in crate::library::tpm2) hash_alg: u16,
    pub(in crate::library::tpm2) hierarchy: u32,
    pub(in crate::library::tpm2) parameters: Vec<u8>,
}

impl HashTicketCase {
    pub(in crate::library::tpm2) fn label(&self) -> String {
        format!(
            "{} bytes, alg {:#06x}, hierarchy {:#010x}",
            self.data.len(),
            self.hash_alg,
            self.hierarchy
        )
    }

    pub(in crate::library::tpm2) fn out_hash(&self) -> &[u8] {
        let size = self.digest_size();
        &self.parameters[2..2 + size]
    }

    pub(in crate::library::tpm2) fn ticket(&self) -> &[u8] {
        &self.parameters[2 + self.digest_size()..]
    }

    pub(in crate::library::tpm2) fn ticket_hierarchy(&self) -> u32 {
        u32::from_be_bytes(self.ticket()[2..6].try_into().expect("a ticket hierarchy"))
    }

    pub(in crate::library::tpm2) fn ticket_digest(&self) -> &[u8] {
        &self.ticket()[8..]
    }

    pub(in crate::library::tpm2) fn expects_a_ticket(&self) -> bool {
        !self.ticket_digest().is_empty()
    }

    fn digest_size(&self) -> usize {
        usize::from(u16::from_be_bytes(
            self.parameters[..2].try_into().expect("a digest header"),
        ))
    }
}

pub(in crate::library::tpm2) struct HashTicketRecord {
    pub(in crate::library::tpm2) ph_proof: Vec<u8>,
    pub(in crate::library::tpm2) sh_proof: Vec<u8>,
    pub(in crate::library::tpm2) eh_proof: Vec<u8>,
    pub(in crate::library::tpm2) cases: Vec<HashTicketCase>,
}

impl HashTicketRecord {
    pub(in crate::library::tpm2) fn proof_for(&self, hierarchy: u32) -> Option<&[u8]> {
        match hierarchy {
            TPM_RH_PLATFORM => Some(&self.ph_proof),
            TPM_RH_OWNER => Some(&self.sh_proof),
            TPM_RH_ENDORSEMENT => Some(&self.eh_proof),
            _ => None,
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        head
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes(self.take(2).try_into().unwrap())
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.take(4).try_into().unwrap())
    }

    fn blob(&mut self) -> Vec<u8> {
        let length = usize::from(self.u16());
        self.take(length).to_vec()
    }
}

pub(in crate::library::tpm2) fn hash_ticket_record() -> HashTicketRecord {
    let mut reader = Reader(FIXTURE);
    let proof_size = usize::from(reader.u16());
    let ph_proof = reader.take(proof_size).to_vec();
    let sh_proof = reader.take(proof_size).to_vec();
    let eh_proof = reader.take(proof_size).to_vec();
    let count = usize::from(reader.u16());
    let cases = (0..count)
        .map(|_| HashTicketCase {
            data: reader.blob(),
            hash_alg: reader.u16(),
            hierarchy: reader.u32(),
            parameters: reader.blob(),
        })
        .collect();
    assert!(reader.0.is_empty(), "stale fixture layout");
    HashTicketRecord {
        ph_proof,
        sh_proof,
        eh_proof,
        cases,
    }
}

#[cfg(test)]
mod tests {
    use super::super::hierarchy::TPM_RH_NULL;
    use super::*;

    #[test]
    fn the_fixture_carries_three_distinct_full_length_proofs() {
        let record = hash_ticket_record();
        assert_eq!(record.ph_proof.len(), 64);
        assert_eq!(record.sh_proof.len(), 64);
        assert_eq!(record.eh_proof.len(), 64);
        assert_ne!(record.ph_proof, record.sh_proof);
        assert_ne!(record.ph_proof, record.eh_proof);
        assert_ne!(record.sh_proof, record.eh_proof);
    }

    #[test]
    fn the_null_hierarchy_has_no_proof() {
        let record = hash_ticket_record();
        assert!(record.proof_for(TPM_RH_NULL).is_none());
        assert!(record.proof_for(0x4000_000a).is_none());
    }

    #[test]
    fn every_case_covers_a_compiled_algorithm_and_an_accepted_hierarchy() {
        let record = hash_ticket_record();
        assert_eq!(record.cases.len(), 9 * 4 * 4);
        for case in &record.cases {
            assert!(
                matches!(case.hash_alg, 0x0004 | 0x000b | 0x000c | 0x000d),
                "{}",
                case.label()
            );
            assert!(
                matches!(
                    case.hierarchy,
                    TPM_RH_OWNER | TPM_RH_PLATFORM | TPM_RH_ENDORSEMENT | TPM_RH_NULL
                ),
                "{}",
                case.label()
            );
        }
    }

    #[test]
    fn the_recorded_data_sizes_cover_the_documented_range() {
        let record = hash_ticket_record();
        let mut sizes: Vec<usize> = record.cases.iter().map(|case| case.data.len()).collect();
        sizes.sort_unstable();
        sizes.dedup();
        assert_eq!(sizes, [0, 1, 2, 3, 4, 16, 1024]);
    }

    #[test]
    fn every_case_carries_a_digest_and_a_marshalled_ticket() {
        let record = hash_ticket_record();
        for case in &record.cases {
            let expected = match case.hash_alg {
                0x0004 => 20,
                0x000b => 32,
                0x000c => 48,
                _ => 64,
            };
            assert_eq!(case.out_hash().len(), expected, "{}", case.label());
            assert_eq!(&case.ticket()[..2], &[0x80, 0x24], "{}", case.label());
            assert_eq!(
                case.ticket().len(),
                8 + case.ticket_digest().len(),
                "{}",
                case.label()
            );
        }
    }

    #[test]
    fn a_ticket_is_recorded_exactly_for_the_hierarchies_and_inputs_upstream_allows() {
        let record = hash_ticket_record();
        for case in &record.cases {
            let suppressed = case.hierarchy == TPM_RH_NULL
                || case.data.first_chunk::<4>() == Some(&[0xff, 0x54, 0x43, 0x47]);
            assert_eq!(case.expects_a_ticket(), !suppressed, "{}", case.label());
            if case.expects_a_ticket() {
                assert_eq!(case.ticket_hierarchy(), case.hierarchy, "{}", case.label());
                assert_eq!(case.ticket_digest().len(), 64, "{}", case.label());
            } else {
                assert_eq!(case.ticket_hierarchy(), TPM_RH_NULL, "{}", case.label());
            }
        }
    }
}
