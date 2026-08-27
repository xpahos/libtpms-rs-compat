mod core;

mod administration;
mod attestation;
mod context;
mod crypto;
mod hierarchy;
mod lifecycle;
mod nv;
mod object;
mod pcr;
mod platform;
mod policy;
mod session;

pub(super) use self::core::dispatcher::dispatch;
#[cfg(test)]
pub(super) use self::core::header::parse_command;
pub(super) use self::core::header::{
    HEADER_SIZE, Response, TPM_ST_NO_SESSIONS, parse_command_within, serialize_response_within,
};
#[cfg(test)]
pub(in crate::library::tpm2) use self::core::registry::TPM_CC_COMMIT;
pub(in crate::library::tpm2) use self::core::registry::{
    TPM_CC_GET_CAPABILITY, TPM_CC_GET_TEST_RESULT, find as find_command,
    implemented as implemented_commands,
};
pub(in crate::library::tpm2) use self::core::upstream_codes::{
    upstream_command_codes, upstream_implements,
};
pub(in crate::library::tpm2) use administration::command_audit_state::{
    command_index as command_bitmap_index, is_required as command_audit_is_required,
};
