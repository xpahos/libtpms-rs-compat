use super::marshal::BlobReader;
use super::persistent::{PersistentAllError, StateSection};

const SECTION: StateSection = StateSection::Lockout;

fn truncated() -> PersistentAllError {
    PersistentAllError::Truncated { section: SECTION }
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct LockoutState<'a> {
    pub(super) failed_tries: u32,
    pub(super) max_tries: u32,
    pub(super) recovery_time: u32,
    pub(super) lockout_recovery: u32,
    pub(super) lockout_auth_enabled: bool,
    pub(super) orderly_state: u16,
    pub(super) remaining: &'a [u8],
}

pub(super) fn parse_lockout_state(input: &[u8]) -> Result<LockoutState<'_>, PersistentAllError> {
    let mut reader = BlobReader::new(input);

    let failed_tries = reader.read_u32().map_err(|_| truncated())?;
    let max_tries = reader.read_u32().map_err(|_| truncated())?;
    let recovery_time = reader.read_u32().map_err(|_| truncated())?;
    let lockout_recovery = reader.read_u32().map_err(|_| truncated())?;
    let lockout_auth_enabled = reader.read_bool().map_err(|_| truncated())?;
    let orderly_state = reader.read_u16().map_err(|_| truncated())?;

    Ok(LockoutState {
        failed_tries,
        max_tries,
        recovery_time,
        lockout_recovery,
        lockout_auth_enabled,
        orderly_state,
        remaining: reader.remaining(),
    })
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct LockoutFixture {
    pub(super) failed_tries: u32,
    pub(super) max_tries: u32,
    pub(super) recovery_time: u32,
    pub(super) lockout_recovery: u32,
    pub(super) lockout_auth_enabled: u8,
    pub(super) orderly_state: u16,
    pub(super) tail: Vec<u8>,
}

#[cfg(test)]
impl LockoutFixture {
    pub(super) fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.failed_tries.to_be_bytes());
        out.extend_from_slice(&self.max_tries.to_be_bytes());
        out.extend_from_slice(&self.recovery_time.to_be_bytes());
        out.extend_from_slice(&self.lockout_recovery.to_be_bytes());
        out.push(self.lockout_auth_enabled);
        out.extend_from_slice(&self.orderly_state.to_be_bytes());
        out.extend_from_slice(&self.tail);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::TPM_RC_INSUFFICIENT;

    fn parse(input: &[u8]) -> Result<LockoutState<'_>, PersistentAllError> {
        parse_lockout_state(input)
    }

    #[test]
    fn hand_built_fixture_matches_the_upstream_marshal_order() {
        let fixture = [
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x04, 0x01, 0x00, 0x01, 0xaa, 0xdc,
        ];
        let parsed = parse(&fixture).unwrap();
        assert_eq!(parsed.failed_tries, 1);
        assert_eq!(parsed.max_tries, 2);
        assert_eq!(parsed.recovery_time, 3);
        assert_eq!(parsed.lockout_recovery, 4);
        assert!(parsed.lockout_auth_enabled);
        assert_eq!(parsed.orderly_state, 0x0001);
        assert_eq!(parsed.remaining, &[0xaa, 0xdc]);
    }

    #[test]
    fn each_counter_is_decoded_big_endian_at_its_own_position() {
        let data = LockoutFixture {
            failed_tries: 0x0102_0304,
            max_tries: 0x0506_0708,
            recovery_time: 0x090a_0b0c,
            lockout_recovery: 0x0d0e_0f10,
            orderly_state: 0x1112,
            ..LockoutFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.failed_tries, 0x0102_0304);
        assert_eq!(parsed.max_tries, 0x0506_0708);
        assert_eq!(parsed.recovery_time, 0x090a_0b0c);
        assert_eq!(parsed.lockout_recovery, 0x0d0e_0f10);
        assert_eq!(parsed.orderly_state, 0x1112);
    }

    #[test]
    fn zero_and_maximum_values_are_preserved() {
        let zero_bytes = LockoutFixture::default().bytes();
        let zero = parse(&zero_bytes).unwrap();
        assert_eq!(zero.failed_tries, 0);
        assert_eq!(zero.max_tries, 0);
        assert_eq!(zero.recovery_time, 0);
        assert_eq!(zero.lockout_recovery, 0);
        assert!(!zero.lockout_auth_enabled);
        assert_eq!(zero.orderly_state, 0);

        let data = LockoutFixture {
            failed_tries: u32::MAX,
            max_tries: u32::MAX,
            recovery_time: u32::MAX,
            lockout_recovery: u32::MAX,
            lockout_auth_enabled: 0xff,
            orderly_state: u16::MAX,
            ..LockoutFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.failed_tries, u32::MAX);
        assert_eq!(parsed.max_tries, u32::MAX);
        assert_eq!(parsed.recovery_time, u32::MAX);
        assert_eq!(parsed.lockout_recovery, u32::MAX);
        assert!(parsed.lockout_auth_enabled);
        assert_eq!(parsed.orderly_state, u16::MAX);
    }

    #[test]
    fn lockout_auth_enabled_decodes_canonical_and_noncanonical_values() {
        for (byte, expected) in [(0x00u8, false), (0x01, true), (0x02, true), (0xff, true)] {
            let data = LockoutFixture {
                lockout_auth_enabled: byte,
                ..LockoutFixture::default()
            }
            .bytes();
            let parsed = parse(&data).unwrap();
            assert_eq!(parsed.lockout_auth_enabled, expected, "byte {byte:#04x}");
        }
    }

    #[test]
    fn orderly_state_is_raw_and_zero_is_not_rejected() {
        for state in [0x0000u16, 0x0001, 0x00ff, 0x1234, u16::MAX] {
            let data = LockoutFixture {
                orderly_state: state,
                ..LockoutFixture::default()
            }
            .bytes();
            assert_eq!(
                parse(&data).unwrap().orderly_state,
                state,
                "state {state:#06x}"
            );
        }
    }

    #[test]
    fn remainder_begins_exactly_at_the_audit_commands_sentinel() {
        let data = LockoutFixture {
            tail: vec![0xde, 0xad, 0xbe],
            ..LockoutFixture::default()
        }
        .bytes();
        let parsed = parse(&data).unwrap();
        assert_eq!(parsed.remaining, &[0xde, 0xad, 0xbe]);
        assert!(core::ptr::eq(
            parsed.remaining.as_ptr(),
            data[data.len() - 3..].as_ptr()
        ));
    }

    #[test]
    fn every_strict_prefix_is_truncated_and_never_panics() {
        let full = LockoutFixture {
            failed_tries: 0x11111111,
            max_tries: 0x22222222,
            recovery_time: 0x33333333,
            lockout_recovery: 0x44444444,
            lockout_auth_enabled: 1,
            orderly_state: 0x5555,
            ..LockoutFixture::default()
        }
        .bytes();
        for len in 0..full.len() {
            let error = parse(&full[..len]).unwrap_err();
            assert_eq!(error, truncated(), "prefix length {len} of {}", full.len());
            assert_eq!(error.tpm_result(), TPM_RC_INSUFFICIENT);
        }
        assert!(parse(&full).is_ok());
    }

    #[test]
    fn malformed_input_never_panics() {
        for len in 0..20usize {
            for byte in [0x00u8, 0x01, 0x7f, 0xff] {
                let _ = parse(&vec![byte; len]);
            }
        }
    }
}
