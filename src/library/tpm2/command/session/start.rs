use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_INSUFFICIENT, TPM_RC_KEY, TPM_RC_MODE,
    TPM_RC_SIZE, TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{TPM_ALG_CFB, TPM_ALG_NULL, TPM_ALG_XOR};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::command::core::response_code::{
    TPM_RC_1, TPM_RC_2, TPM_RC_3, TPM_RC_4, TPM_RC_H, TPM_RC_P,
};
use crate::library::tpm2::command::session::processing::bound_entity_value;
use crate::library::tpm2::crypto::kdfa;
use crate::library::tpm2::dictionary_attack::is_da_protected_handle;
use crate::library::tpm2::entity::{entity_auth_value, strip_trailing_zeros};
use crate::library::tpm2::hierarchy::{TPM_RH_LOCKOUT, TPM_RH_NULL};
use crate::library::tpm2::marshal::{BlobReader, BlobWriter, Tpm2bError};
use crate::library::tpm2::nv::{is_nv_index_handle, is_pin_index, resolve_index};
use crate::library::tpm2::object::ATTR_PUBLIC_ONLY;
use crate::library::tpm2::object_create::{is_object_handle, resolve_any_object};
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedSecret};
use crate::library::tpm2::public::{StateFormatLimit, SymDefObject};
use crate::library::tpm2::random::generate_random;
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::secret::{
    MAX_ENCRYPTED_SECRET, SECRET_LABEL, is_asymmetric, secret_decrypt_with_runtime,
};
use crate::library::tpm2::session::{
    SESSION_ATTR_IS_BOUND, SESSION_ATTR_IS_DA_BOUND, SESSION_ATTR_IS_LOCKOUT_BOUND,
    SESSION_ATTR_IS_POLICY, SESSION_ATTR_IS_TRIAL_POLICY, TPM_SE_HMAC, TPM_SE_POLICY, TPM_SE_TRIAL,
    allocate_session, digest_size, publish_session, release_session, set_start_time,
};
use crate::library::tpm2::template::{AlgorithmPolicy, TPMA_OBJECT_DECRYPT, TemplateReader};
use crate::library::tpm2::volatile::OwnedSession;
use crate::types::TpmResult;

const TPM_RC_5: TpmResult = 0x500;

const RC_TPM_KEY: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_BIND: TpmResult = TPM_RC_H + TPM_RC_2;
const RC_NONCE_CALLER: TpmResult = TPM_RC_P + TPM_RC_1;
const RC_ENCRYPTED_SALT: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_SESSION_TYPE: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_SYMMETRIC: TpmResult = TPM_RC_P + TPM_RC_4;
const RC_AUTH_HASH: TpmResult = TPM_RC_P + TPM_RC_5;

const MAX_NONCE_SIZE: usize = 64;
const MIN_NONCE_SIZE: usize = 16;

const HMAC_SESSION_FIRST: u32 = 0x0200_0000;
const POLICY_SESSION_FIRST: u32 = 0x0300_0000;

const SESSION_KEY_LABEL: &[u8] = b"ATH\0";

struct StartAuthSessionIn<'a> {
    nonce_caller: &'a [u8],
    encrypted_salt: &'a [u8],
    session_type: u8,
    symmetric: SymDefObject,
    auth_hash: u16,
}

fn parse_parameters<'a>(
    runtime: &Tpm2Runtime,
    parameters: &'a [u8],
) -> Result<StartAuthSessionIn<'a>, TpmResult> {
    let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
    let policy = AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    };

    let mut reader = BlobReader::new(parameters);
    let nonce_caller = reader
        .read_tpm2b(MAX_NONCE_SIZE)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_NONCE_CALLER,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_NONCE_CALLER,
        })?;
    let encrypted_salt = reader
        .read_tpm2b(MAX_ENCRYPTED_SECRET)
        .map_err(|error| match error {
            Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + RC_ENCRYPTED_SALT,
            Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + RC_ENCRYPTED_SALT,
        })?;
    let session_type = reader
        .read_u8()
        .map_err(|_| TPM_RC_INSUFFICIENT + RC_SESSION_TYPE)?;
    if !matches!(session_type, TPM_SE_HMAC | TPM_SE_POLICY | TPM_SE_TRIAL) {
        return Err(TPM_RC_VALUE + RC_SESSION_TYPE);
    }

    let mut template = TemplateReader::new(reader.remaining());
    let symmetric = policy
        .sym_session(&mut template)
        .map_err(|code| code + RC_SYMMETRIC)?;
    let consumed = template.consumed();
    reader.take(consumed).map_err(|_| TPM_RC_FAILURE)?;

    let mut hash_reader = TemplateReader::new(reader.remaining());
    let auth_hash = policy
        .hash_algorithm(&mut hash_reader)
        .map_err(|code| code + RC_AUTH_HASH)?;
    let consumed = hash_reader.consumed();
    reader.take(consumed).map_err(|_| TPM_RC_FAILURE)?;

    if !reader.remaining().is_empty() {
        return Err(TPM_RC_SIZE);
    }
    Ok(StartAuthSessionIn {
        nonce_caller,
        encrypted_salt,
        session_type,
        symmetric,
        auth_hash,
    })
}

fn decrypt_salt(
    runtime: &mut Tpm2Runtime,
    tpm_key: u32,
    encrypted_salt: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    if tpm_key == TPM_RH_NULL {
        if !encrypted_salt.is_empty() {
            return Err(TPM_RC_VALUE + RC_ENCRYPTED_SALT);
        }
        return Ok(Vec::new());
    }

    let object = resolve_any_object(runtime, tpm_key).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_KEY + RC_TPM_KEY);
    };
    if !is_asymmetric(body.public.object_type) {
        return Err(TPM_RC_KEY + RC_TPM_KEY);
    }
    if encrypted_salt.is_empty() {
        return Err(TPM_RC_VALUE + RC_ENCRYPTED_SALT);
    }
    if object.attributes & ATTR_PUBLIC_ONLY != 0 {
        return Err(TPM_RC_HANDLE + RC_TPM_KEY);
    }
    if body.public.object_attributes & TPMA_OBJECT_DECRYPT == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_TPM_KEY);
    }

    let body = body.clone();
    secret_decrypt_with_runtime(runtime, &body, SECRET_LABEL, encrypted_salt).map_err(|code| {
        if code == TPM_RC_FAILURE {
            code
        } else {
            TPM_RC_VALUE + RC_ENCRYPTED_SALT
        }
    })
}

fn check_bind(runtime: &Tpm2Runtime, bind: u32) -> Result<(), TpmResult> {
    if is_object_handle(bind) {
        let object = resolve_any_object(runtime, bind).ok_or(TPM_RC_FAILURE)?;
        if object.attributes & ATTR_PUBLIC_ONLY != 0 {
            return Err(TPM_RC_HANDLE + RC_BIND);
        }
        return Ok(());
    }
    if is_nv_index_handle(bind) {
        let resolved = resolve_index(runtime, bind).ok_or(TPM_RC_FAILURE)?;
        if is_pin_index(resolved.attributes()) {
            return Err(TPM_RC_HANDLE + RC_BIND);
        }
    }
    Ok(())
}

fn check_symmetric(symmetric: &SymDefObject) -> Result<(), TpmResult> {
    if symmetric.algorithm != TPM_ALG_NULL
        && symmetric.algorithm != TPM_ALG_XOR
        && symmetric.mode != Some(TPM_ALG_CFB)
    {
        return Err(TPM_RC_MODE + RC_SYMMETRIC);
    }
    Ok(())
}

fn session_key(
    runtime: &Tpm2Runtime,
    input: &StartAuthSessionIn<'_>,
    bind: u32,
    salt: &[u8],
    nonce_tpm: &[u8],
) -> Result<Vec<u8>, TpmResult> {
    let size = digest_size(input.auth_hash).ok_or(TPM_RC_FAILURE)?;
    let mut key = strip_trailing_zeros(entity_auth_value(runtime, bind)?).to_vec();
    key.extend_from_slice(salt);
    kdfa(
        input.auth_hash,
        &key,
        SESSION_KEY_LABEL,
        nonce_tpm,
        input.nonce_caller,
        (size * 8) as u32,
    )
    .ok_or(TPM_RC_FAILURE)
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let tpm_key = handle_at(frame, 0)?;
    let bind = handle_at(frame, 1)?;
    let input = parse_parameters(runtime, frame.parameters)?;

    let nonce_size = input.nonce_caller.len();
    let digest = digest_size(input.auth_hash).ok_or(TPM_RC_FAILURE)?;
    if nonce_size < MIN_NONCE_SIZE || nonce_size > digest {
        return Err(TPM_RC_SIZE + RC_NONCE_CALLER);
    }

    let salt = decrypt_salt(runtime, tpm_key, input.encrypted_salt)?;
    check_bind(runtime, bind)?;
    check_symmetric(&input.symmetric)?;

    create_session(runtime, &input, bind, &salt)
}

fn create_session(
    runtime: &mut Tpm2Runtime,
    input: &StartAuthSessionIn<'_>,
    bind: u32,
    salt: &[u8],
) -> Result<CommandOutput, TpmResult> {
    let allocated = allocate_session(&mut runtime.live)?;

    let handle = allocated.context_index
        + if input.session_type == TPM_SE_HMAC {
            HMAC_SESSION_FIRST
        } else {
            POLICY_SESSION_FIRST
        };

    match build_session(runtime, input, bind, salt) {
        Ok(session) => {
            let nonce_tpm = session.nonce_tpm.as_bytes().to_vec();
            publish_session(&mut runtime.live, allocated, session);
            let mut writer = BlobWriter::with_capacity(2 + nonce_tpm.len());
            writer.write_tpm2b(&nonce_tpm).map_err(|_| TPM_RC_SIZE)?;
            Ok(CommandOutput::with_handle(handle, writer.into_bytes()))
        }
        Err(code) => {
            release_session(&mut runtime.live, allocated);
            Err(code)
        }
    }
}

fn build_session(
    runtime: &mut Tpm2Runtime,
    input: &StartAuthSessionIn<'_>,
    bind: u32,
    salt: &[u8],
) -> Result<OwnedSession, TpmResult> {
    let mut session = OwnedSession {
        attributes: 0,
        pcr_counter: 0,
        start_time: 0,
        timeout: 0,
        epoch: 0,
        command_code: 0,
        auth_hash_alg: input.auth_hash,
        command_locality: 0,
        symmetric: input.symmetric,
        session_key: OwnedSecret::from_vec(Vec::new()),
        nonce_tpm: OwnedSecret::from_vec(Vec::new()),
        bound_entity: Vec::new(),
        audit_digest: Vec::new(),
    };

    if input.session_type != TPM_SE_HMAC {
        session.attributes |= SESSION_ATTR_IS_POLICY;
        if input.session_type == TPM_SE_TRIAL {
            session.attributes |= SESSION_ATTR_IS_TRIAL_POLICY;
        }
        let epoch = runtime
            .state
            .as_ref()
            .ok_or(TPM_RC_FAILURE)?
            .persistent
            .time_epoch;
        set_start_time(&mut session, runtime.timer.time_ms, epoch);
        session.audit_digest = vec![0u8; digest_size(input.auth_hash).ok_or(TPM_RC_FAILURE)?];
    }

    let nonce_tpm = generate_random(runtime, input.nonce_caller.len())?;
    session.nonce_tpm = OwnedSecret::copy_of(&nonce_tpm);

    if bind != TPM_RH_NULL || !salt.is_empty() {
        let key = session_key(runtime, input, bind, salt, &nonce_tpm)?;
        session.session_key = OwnedSecret::from_vec(key);
    }

    if bind != TPM_RH_NULL && input.session_type == TPM_SE_HMAC {
        session.attributes |= SESSION_ATTR_IS_BOUND;
        session.bound_entity = bound_entity_value(runtime, bind)?;
    }

    if bind != TPM_RH_NULL && is_da_protected_handle(runtime, bind) {
        session.attributes |= SESSION_ATTR_IS_DA_BOUND;
        if bind == TPM_RH_LOCKOUT {
            session.attributes |= SESSION_ATTR_IS_LOCKOUT_BOUND;
        }
    }
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::tpm2::command::core::registry::{
        CommandLifecycle, HandleKind, NvAccess, find,
    };
    use crate::library::tpm2::command::core::test_support::{
        RC_SUCCESS, command, dispatch_bytes, manufactured_runtime, response_code,
    };
    use crate::library::tpm2::command::policy::session::test_support::{
        CC_START_AUTH_SESSION, HMAC_SESSION_0, POLICY_SESSION_0, restored, session_of,
    };
    use crate::library::tpm2::golden_responses::policy_sessions::vector;
    use crate::library::tpm2::public::NAME_SIZE;
    use crate::library::tpm2::state::MAX_ACTIVE_SESSIONS;
    use crate::library::tpm2::volatile::MAX_LOADED_SESSIONS;

    const ALG_SHA1: u16 = 0x0004;
    const ALG_SHA256: u16 = 0x000b;
    const ALG_SHA384: u16 = 0x000c;
    const ALG_SHA512: u16 = 0x000d;
    const ALG_XOR: u16 = 0x000a;
    const ALG_AES: u16 = 0x0006;
    const MODE_CFB: u16 = 0x0043;
    const MODE_CBC: u16 = 0x0042;

    const SYM_NULL: [u8; 2] = [0x00, 0x10];

    const SALT_RSA: &str = "88499b20c9d3c25808e7ab35f9b514d799ddc4bc0c4846873cb16e02e0571f537b43ff9ae3013b0a02717ae3a2717a15fc4db7c75ad31219245af67f0e235e3984c346cc34a15800dedd961055e081ce056f82536b433eb23d597c40e81676a7d673418f7523e66ecabad4b6ac910a7a9486e029ce5cb88a975ff7f69e4522ccaf3a8a1c63f89b3a225c95e4ee9694363903477fa9f2e54e2878b7dd6ed8b31f02eb84c644e6112d3e7e096c47c5e31bb0477c875e2225875ae579d93594567519d71bdb1a3f3f29c06156dfa15371e6078d7b83d82e227c59bd85d79bd95e9f2e4fb1fcd363a81ec1afa78e1f8b94d1698233acfa4fdf01f81b91283171828a";
    const SALT_ECC: &str = "00206413e370318a922cecfaa94ba2188dd419f586356fa774c766cd6c450295fee900205dce9ce0557b0a8f1cef5c663f362cfffc910e3094afc82bbbc7a0a92b0b6bdb";

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits"))
            .collect()
    }

    fn nonce(length: usize) -> Vec<u8> {
        vec![0x5a; length]
    }

    fn sym_aes(mode: u16) -> Vec<u8> {
        let mut out = ALG_AES.to_be_bytes().to_vec();
        out.extend_from_slice(&128u16.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
        out
    }

    fn sym_xor(hash_alg: u16) -> Vec<u8> {
        let mut out = ALG_XOR.to_be_bytes().to_vec();
        out.extend_from_slice(&hash_alg.to_be_bytes());
        out
    }

    struct Request {
        tpm_key: u32,
        bind: u32,
        nonce_caller: Vec<u8>,
        salt: Vec<u8>,
        session_type: u8,
        symmetric: Vec<u8>,
        auth_hash: u16,
        trailing: Vec<u8>,
    }

    impl Default for Request {
        fn default() -> Self {
            Self {
                tpm_key: TPM_RH_NULL,
                bind: TPM_RH_NULL,
                nonce_caller: nonce(16),
                salt: Vec::new(),
                session_type: TPM_SE_HMAC,
                symmetric: SYM_NULL.to_vec(),
                auth_hash: ALG_SHA256,
                trailing: Vec::new(),
            }
        }
    }

    impl Request {
        fn bytes(&self) -> Vec<u8> {
            let mut parameters = Vec::new();
            parameters.extend_from_slice(&(self.nonce_caller.len() as u16).to_be_bytes());
            parameters.extend_from_slice(&self.nonce_caller);
            parameters.extend_from_slice(&(self.salt.len() as u16).to_be_bytes());
            parameters.extend_from_slice(&self.salt);
            parameters.push(self.session_type);
            parameters.extend_from_slice(&self.symmetric);
            parameters.extend_from_slice(&self.auth_hash.to_be_bytes());
            parameters.extend_from_slice(&self.trailing);
            command(
                CC_START_AUTH_SESSION,
                &[self.tpm_key, self.bind],
                &[],
                &parameters,
            )
        }
    }

    #[track_caller]
    fn start(runtime: &mut Tpm2Runtime, request: &Request) -> Vec<u8> {
        dispatch_bytes(runtime, &request.bytes())
    }

    #[track_caller]
    fn assert_record(snapshot: &str, record: &str, request: &Request) {
        let mut runtime = restored(snapshot);
        assert_eq!(start(&mut runtime, request), vector(record), "{record}");
    }

    #[test]
    fn command_attributes_oracle_match() {
        let expected = vector("CCATTR_0176");
        let attributes = u32::from_be_bytes(expected[19..23].try_into().unwrap());
        let descriptor = find(0x0000_0176).expect("a registered command");
        assert_eq!(descriptor.attributes, attributes);
        assert_eq!(descriptor.attributes, 0x1400_0176);
        assert_eq!(
            (descriptor.attributes >> 25) & 0x7,
            2,
            "two command handles"
        );
        assert_ne!(descriptor.attributes & (1 << 28), 0, "a response handle");
        assert_eq!(descriptor.attributes & (1 << 22), 0, "no NV writes");
        assert!(!descriptor.physical_presence);
        assert!(descriptor.sessions_allowed);
        assert!(matches!(descriptor.nv_access, NvAccess::Neither));
        assert!(matches!(
            descriptor.lifecycle,
            CommandLifecycle::RequiresStarted
        ));
        assert_eq!(descriptor.handles.len(), 2);
        assert!(descriptor.handles.iter().all(|spec| !spec.user_auth));
        assert!(descriptor.handles.iter().all(|spec| !spec.admin_role()));
        assert!(matches!(
            descriptor.handles[0].kind,
            HandleKind::ObjectAllowNull
        ));
        assert!(matches!(
            descriptor.handles[1].kind,
            HandleKind::EntityAllowNull
        ));
    }

    #[test]
    fn pre_startup_rejection() {
        let mut runtime = manufactured_runtime();
        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_BEFORE_STARTUP")
        );
    }

    #[test]
    fn session_type_slot_order_and_oracle_nonce() {
        let mut runtime = restored("READY");
        for (record, session_type) in [
            ("SAS_HMAC_UNBOUND", TPM_SE_HMAC),
            ("SAS_POLICY_UNBOUND", TPM_SE_POLICY),
            ("SAS_TRIAL_UNBOUND", TPM_SE_TRIAL),
        ] {
            let request = Request {
                session_type,
                ..Request::default()
            };
            assert_eq!(start(&mut runtime, &request), vector(record), "{record}");
        }
        assert_eq!(runtime.live.free_session_slots, 0);
        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_SESSION_MEMORY"),
            "a fourth session has no slot"
        );
        assert_eq!(runtime.live.free_session_slots, 0);
    }

    #[test]
    fn loaded_session_capability_reporting() {
        let mut runtime = restored("THREE_SESSIONS");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    0x0000_017a,
                    &[],
                    &[],
                    &capability_parameters(1, HMAC_SESSION_0, 8)
                )
            ),
            vector("CAP_LOADED_FROM_HMAC")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    0x0000_017a,
                    &[],
                    &[],
                    &capability_parameters(1, POLICY_SESSION_0, 8)
                )
            ),
            vector("CAP_LOADED_FROM_POLICY")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    0x0000_017a,
                    &[],
                    &[],
                    &capability_parameters(6, 0x0000_020b, 1)
                )
            ),
            vector("CAP_ACTIVE_SESSIONS")
        );
    }

    fn capability_parameters(capability: u32, property: u32, count: u32) -> Vec<u8> {
        let mut out = capability.to_be_bytes().to_vec();
        out.extend_from_slice(&property.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    #[test]
    fn freed_slot_reuse() {
        let mut runtime = restored("THREE_SESSIONS");
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(0x0000_0165, &[], &[], &0x0300_0001u32.to_be_bytes())
            ),
            vector("FLUSH_MIDDLE_SESSION")
        );
        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_REUSED_SLOT")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    0x0000_017a,
                    &[],
                    &[],
                    &capability_parameters(1, HMAC_SESSION_0, 8)
                )
            ),
            vector("CAP_LOADED_AFTER_REUSE")
        );
    }

    #[test]
    fn enabled_session_hash_oracle_parity() {
        for (record, auth_hash, size) in [
            ("SAS_SHA1", ALG_SHA1, 20usize),
            ("SAS_SHA256_LONG_NONCE", ALG_SHA256, 32),
            ("SAS_SHA384", ALG_SHA384, 48),
            ("SAS_SHA512", ALG_SHA512, 64),
        ] {
            assert_record(
                "READY",
                record,
                &Request {
                    nonce_caller: nonce(size),
                    auth_hash,
                    ..Request::default()
                },
            );
        }
    }

    #[test]
    fn symmetric_parameter_reference_validation() {
        for (record, symmetric) in [
            ("SAS_SYM_AES_CFB", sym_aes(MODE_CFB)),
            ("SAS_SYM_XOR", sym_xor(ALG_SHA256)),
            ("SAS_SYM_AES_CBC", sym_aes(MODE_CBC)),
            ("SAS_SYM_UNKNOWN", 0x0013u16.to_be_bytes().to_vec()),
            ("SAS_SYM_XOR_NULL_HASH", sym_xor(TPM_ALG_NULL)),
        ] {
            assert_record(
                "READY",
                record,
                &Request {
                    symmetric,
                    ..Request::default()
                },
            );
        }
        let mut bad_bits = ALG_AES.to_be_bytes().to_vec();
        bad_bits.extend_from_slice(&64u16.to_be_bytes());
        bad_bits.extend_from_slice(&MODE_CFB.to_be_bytes());
        assert_record(
            "READY",
            "SAS_SYM_AES_BAD_BITS",
            &Request {
                symmetric: bad_bits,
                ..Request::default()
            },
        );
        assert_record(
            "READY",
            "SAS_SYM_AES_BAD_MODE",
            &Request {
                symmetric: sym_aes(0x0099),
                ..Request::default()
            },
        );
    }

    #[test]
    fn rejected_input_oracle_parity() {
        for (record, request) in [
            (
                "SAS_NONCE_TOO_SHORT",
                Request {
                    nonce_caller: nonce(15),
                    ..Request::default()
                },
            ),
            (
                "SAS_NONCE_TOO_LONG",
                Request {
                    nonce_caller: nonce(33),
                    ..Request::default()
                },
            ),
            (
                "SAS_NONCE_EMPTY",
                Request {
                    nonce_caller: Vec::new(),
                    ..Request::default()
                },
            ),
            (
                "SAS_NONCE_SHA1_TOO_LONG",
                Request {
                    nonce_caller: nonce(21),
                    auth_hash: ALG_SHA1,
                    ..Request::default()
                },
            ),
            (
                "SAS_BAD_SESSION_TYPE",
                Request {
                    session_type: 0x02,
                    ..Request::default()
                },
            ),
            (
                "SAS_NULL_HASH",
                Request {
                    auth_hash: TPM_ALG_NULL,
                    ..Request::default()
                },
            ),
            (
                "SAS_UNKNOWN_HASH",
                Request {
                    auth_hash: 0x0005,
                    ..Request::default()
                },
            ),
            (
                "SAS_SALT_WITHOUT_KEY",
                Request {
                    salt: vec![0u8; 32],
                    ..Request::default()
                },
            ),
            (
                "SAS_TRAILING_BYTES",
                Request {
                    trailing: vec![0x00],
                    ..Request::default()
                },
            ),
            (
                "SAS_ABSENT_TRANSIENT_KEY",
                Request {
                    tpm_key: 0x8000_0000,
                    salt: vec![0u8; 32],
                    ..Request::default()
                },
            ),
            (
                "SAS_ABSENT_PERSISTENT_KEY",
                Request {
                    tpm_key: 0x8100_0000,
                    salt: vec![0u8; 32],
                    ..Request::default()
                },
            ),
            (
                "SAS_BAD_KEY_HANDLE",
                Request {
                    tpm_key: 0x4000_0001,
                    ..Request::default()
                },
            ),
            (
                "SAS_BAD_BIND_HANDLE",
                Request {
                    bind: 0x0200_0000,
                    ..Request::default()
                },
            ),
            (
                "SAS_ABSENT_BIND_OBJECT",
                Request {
                    bind: 0x8000_0000,
                    ..Request::default()
                },
            ),
            (
                "SAS_AUTH_HANDLE_BIND",
                Request {
                    bind: 0x4000_0010,
                    ..Request::default()
                },
            ),
        ] {
            assert_record("READY", record, &request);
        }
    }

    #[test]
    fn truncated_request_oracle_parity() {
        let mut runtime = restored("READY");
        assert_eq!(
            dispatch_bytes(&mut runtime, &command(CC_START_AUTH_SESSION, &[], &[], &[])),
            vector("SAS_NO_PARAMETERS")
        );
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(CC_START_AUTH_SESSION, &[TPM_RH_NULL], &[], &[])
            ),
            vector("SAS_TRUNCATED_HANDLES")
        );
        let mut short = 16u16.to_be_bytes().to_vec();
        short.extend_from_slice(&nonce(8));
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(
                    CC_START_AUTH_SESSION,
                    &[TPM_RH_NULL, TPM_RH_NULL],
                    &[],
                    &short
                )
            ),
            vector("SAS_TRUNCATED_NONCE")
        );
    }

    #[test]
    fn bound_session_permanent_entity_oracle_parity() {
        for (record, bind) in [
            ("SAS_BOUND_OWNER", 0x4000_0001u32),
            ("SAS_BOUND_LOCKOUT", 0x4000_000a),
            ("SAS_BOUND_PLATFORM", 0x4000_000c),
            ("SAS_BOUND_NULL", TPM_RH_NULL),
            ("SAS_BOUND_PCR0", 0x0000_0000),
        ] {
            assert_record(
                "READY",
                record,
                &Request {
                    bind,
                    ..Request::default()
                },
            );
        }
    }

    #[test]
    fn bound_hmac_session_bind_name_and_da_record() {
        let mut runtime = restored("READY");
        let request = Request {
            bind: 0x4000_0001,
            ..Request::default()
        };
        assert_eq!(start(&mut runtime, &request), vector("SAS_BOUND_OWNER"));
        let session = session_of(&runtime, HMAC_SESSION_0);
        assert_eq!(session.bound_entity.len(), NAME_SIZE);
        assert_eq!(
            &session.bound_entity[..4],
            &0x4000_0001u32.to_be_bytes(),
            "the bound entity starts with the owner handle"
        );
        assert_ne!(session.attributes & SESSION_ATTR_IS_BOUND, 0);
        assert_eq!(
            session.attributes & SESSION_ATTR_IS_DA_BOUND,
            0,
            "every permanent handle except lockout is DA exempt"
        );
        assert_eq!(session.attributes & SESSION_ATTR_IS_LOCKOUT_BOUND, 0);
        assert!(!session.session_key.as_bytes().is_empty());
    }

    #[test]
    fn lockout_bound_session_marking() {
        let mut runtime = restored("READY");
        let request = Request {
            bind: 0x4000_000a,
            ..Request::default()
        };
        assert_eq!(start(&mut runtime, &request), vector("SAS_BOUND_LOCKOUT"));
        let session = session_of(&runtime, HMAC_SESSION_0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_DA_BOUND, 0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_LOCKOUT_BOUND, 0);
    }

    #[test]
    fn null_bind_no_bound_entity_no_session_key() {
        let mut runtime = restored("READY");
        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_HMAC_UNBOUND")
        );
        let session = session_of(&runtime, HMAC_SESSION_0);
        assert!(session.bound_entity.is_empty());
        assert!(session.session_key.as_bytes().is_empty());
        assert_eq!(session.attributes, 0);
    }

    #[test]
    fn policy_and_trial_sessions_unbound_da_bound() {
        for (record, session_type, expected) in [
            (
                "SAS_POLICY_BOUND_OWNER",
                TPM_SE_POLICY,
                SESSION_ATTR_IS_POLICY,
            ),
            (
                "SAS_TRIAL_BOUND_OWNER",
                TPM_SE_TRIAL,
                SESSION_ATTR_IS_POLICY | SESSION_ATTR_IS_TRIAL_POLICY,
            ),
        ] {
            let mut runtime = restored("READY");
            let request = Request {
                bind: 0x4000_0001,
                session_type,
                ..Request::default()
            };
            assert_eq!(start(&mut runtime, &request), vector(record), "{record}");
            let session = session_of(&runtime, POLICY_SESSION_0);
            assert_eq!(session.attributes, expected, "{record}");
            assert!(session.bound_entity.is_empty(), "{record}");
            assert!(
                !session.session_key.as_bytes().is_empty(),
                "{record} still derives a session key"
            );
            assert_eq!(session.audit_digest, vec![0u8; 32], "{record}");
        }
    }

    #[test]
    fn policy_session_start_time_and_epoch_record() {
        let mut runtime = restored("READY");
        let request = Request {
            session_type: TPM_SE_POLICY,
            ..Request::default()
        };
        assert_eq!(
            start(&mut runtime, &request),
            vector("SAS_POLICY_UNBOUND_ALONE")
        );
        let epoch = runtime.state().persistent.time_epoch;
        let session = session_of(&runtime, POLICY_SESSION_0);
        assert_eq!(session.epoch, epoch);
        assert_eq!(session.timeout, 0);
        assert_eq!(session.pcr_counter, 0);
        assert_eq!(session.command_code, 0);
    }

    #[test]
    fn salted_session_oracle_parity() {
        for (snapshot, record, salt) in [
            ("RSA_KEY", "SAS_SALTED_RSA", SALT_RSA),
            ("ECC_KEY", "SAS_SALTED_ECC", SALT_ECC),
        ] {
            let mut runtime = restored(snapshot);
            let request = Request {
                tpm_key: 0x8000_0000,
                salt: hex(salt),
                ..Request::default()
            };
            assert_eq!(start(&mut runtime, &request), vector(record), "{record}");
            let session = session_of(&runtime, HMAC_SESSION_0);
            assert_eq!(
                session.session_key.as_bytes().len(),
                32,
                "{record} derives a session key from the salt"
            );
        }
    }

    #[test]
    fn salted_bound_session_auth_salt_concatenation() {
        let mut runtime = restored("RSA_KEY");
        let request = Request {
            tpm_key: 0x8000_0000,
            bind: 0x4000_0001,
            salt: hex(SALT_RSA),
            ..Request::default()
        };
        assert_eq!(
            start(&mut runtime, &request),
            vector("SAS_SALTED_BOUND_RSA")
        );
        let session = session_of(&runtime, HMAC_SESSION_0);
        assert_ne!(session.attributes & SESSION_ATTR_IS_BOUND, 0);
        assert_eq!(session.session_key.as_bytes().len(), 32);
    }

    #[test]
    fn first_salted_rsa_session_oaep_self_test_consumption() {
        let mut runtime = restored("RSA_KEY");
        assert!(runtime.self_test.oaep_pending);
        let request = Request {
            tpm_key: 0x8000_0000,
            salt: hex(SALT_RSA),
            ..Request::default()
        };
        assert_eq!(start(&mut runtime, &request), vector("SAS_SALTED_RSA"));
        assert!(!runtime.self_test.oaep_pending);
        assert_eq!(
            dispatch_bytes(
                &mut runtime,
                &command(0x0000_0165, &[], &[], &HMAC_SESSION_0.to_be_bytes())
            )[6..10],
            [0, 0, 0, 0],
            "the first session is flushed"
        );
        assert_eq!(
            start(&mut runtime, &request),
            vector("SAS_SALTED_RSA_AGAIN"),
            "the second salted session runs no self test"
        );
        const PARTIAL_SELF_TEST: [u8; 11] = [
            0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x00,
        ];
        let requests = runtime.live.orderly.drbg_state.reseed_counter;
        assert_eq!(
            dispatch_bytes(&mut runtime, &PARTIAL_SELF_TEST)[6..10],
            [0, 0, 0, 0]
        );
        assert!(!runtime.self_test.oaep_pending);
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter,
            requests + 1,
            "the partial test still runs the untouched RSAES known-answer test"
        );

        let requests = runtime.live.orderly.drbg_state.reseed_counter;
        assert_eq!(
            dispatch_bytes(&mut runtime, &PARTIAL_SELF_TEST)[6..10],
            [0, 0, 0, 0]
        );
        assert_eq!(
            runtime.live.orderly.drbg_state.reseed_counter, requests,
            "a partial self test does not rerun a cleared known-answer test"
        );
    }

    #[test]
    fn oaep_self_test_failure_mode_pending_retention() {
        use crate::library::tpm2::failure_mode::FailureLocation;
        use crate::library::tpm2::rsa_vectors::PaddedRsaSelfTestStage;

        for (stage, location) in [
            (
                PaddedRsaSelfTestStage::Encrypt,
                FailureLocation::RsaOaepEncrypt,
            ),
            (
                PaddedRsaSelfTestStage::RoundTripDecrypt,
                FailureLocation::RsaOaepRoundTripDecrypt,
            ),
            (
                PaddedRsaSelfTestStage::RoundTripCompare,
                FailureLocation::RsaOaepRoundTripCompare,
            ),
            (
                PaddedRsaSelfTestStage::KnownAnswerDecrypt,
                FailureLocation::RsaOaepKnownAnswerDecrypt,
            ),
            (
                PaddedRsaSelfTestStage::KnownAnswerCompare,
                FailureLocation::RsaOaepKnownAnswerCompare,
            ),
        ] {
            let mut runtime = restored("RSA_KEY");
            runtime.self_test.set_oaep_runner(match stage {
                PaddedRsaSelfTestStage::Encrypt => |_: &[u8]| Err(PaddedRsaSelfTestStage::Encrypt),
                PaddedRsaSelfTestStage::RoundTripDecrypt => {
                    |_: &[u8]| Err(PaddedRsaSelfTestStage::RoundTripDecrypt)
                }
                PaddedRsaSelfTestStage::RoundTripCompare => {
                    |_: &[u8]| Err(PaddedRsaSelfTestStage::RoundTripCompare)
                }
                PaddedRsaSelfTestStage::KnownAnswerDecrypt => {
                    |_: &[u8]| Err(PaddedRsaSelfTestStage::KnownAnswerDecrypt)
                }
                PaddedRsaSelfTestStage::KnownAnswerCompare => {
                    |_: &[u8]| Err(PaddedRsaSelfTestStage::KnownAnswerCompare)
                }
            });
            let free_before = runtime.live.free_session_slots;
            let response = start(
                &mut runtime,
                &Request {
                    tpm_key: 0x8000_0000,
                    salt: hex(SALT_RSA),
                    ..Request::default()
                },
            );
            assert_eq!(response_code(&response), 0x101, "{stage:?}");
            assert!(runtime.failure_mode, "{stage:?}");
            assert_eq!(
                runtime.failure_diagnostics,
                location.diagnostics(),
                "{stage:?}"
            );
            assert!(
                runtime.self_test.oaep_pending,
                "{stage:?} leaves OAEP untested"
            );
            assert_eq!(runtime.live.free_session_slots, free_before, "{stage:?}");
            assert!(
                runtime.live.sessions.iter().all(|slot| !slot.occupied),
                "{stage:?}"
            );
        }
    }

    #[test]
    fn oaep_self_test_known_answer_before_flag_clear() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn counting_runner(seed: &[u8]) -> Result<(), PaddedRsaSelfTestStage> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            assert_eq!(seed.len(), 64, "the reference draws a SHA-512 sized seed");
            crate::library::tpm2::rsa_vectors::run_oaep_known_answer(seed)
        }
        use crate::library::tpm2::rsa_vectors::PaddedRsaSelfTestStage;

        CALLS.store(0, Ordering::SeqCst);
        let mut runtime = restored("RSA_KEY");
        runtime.self_test.set_oaep_runner(counting_runner);
        let request = Request {
            tpm_key: 0x8000_0000,
            salt: hex(SALT_RSA),
            ..Request::default()
        };
        assert_eq!(start(&mut runtime, &request), vector("SAS_SALTED_RSA"));
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert!(!runtime.self_test.oaep_pending);
        assert!(!runtime.failure_mode);
    }

    #[test]
    fn rejected_salt_size_no_self_test() {
        let mut runtime = restored("RSA_KEY");
        assert_eq!(
            start(
                &mut runtime,
                &Request {
                    tpm_key: 0x8000_0000,
                    salt: vec![0u8; 255],
                    ..Request::default()
                }
            ),
            vector("SAS_SALT_WRONG_LENGTH")
        );
        assert!(
            runtime.self_test.oaep_pending,
            "the size check precedes the self test"
        );
    }

    #[test]
    fn malformed_salt_reference_rejection() {
        let mut runtime = restored("RSA_KEY");
        assert_eq!(
            start(
                &mut runtime,
                &Request {
                    tpm_key: 0x8000_0000,
                    salt: vec![0u8; 255],
                    ..Request::default()
                }
            ),
            vector("SAS_SALT_WRONG_LENGTH")
        );
        assert_eq!(
            start(
                &mut runtime,
                &Request {
                    tpm_key: 0x8000_0000,
                    salt: vec![0u8; 256],
                    ..Request::default()
                }
            ),
            vector("SAS_SALT_CORRUPT")
        );
        let mut runtime = restored("ECC_KEY");
        let mut off_curve = 32u16.to_be_bytes().to_vec();
        off_curve.extend_from_slice(&[0u8; 32]);
        off_curve.extend_from_slice(&32u16.to_be_bytes());
        off_curve.extend_from_slice(&[0u8; 32]);
        assert_eq!(
            start(
                &mut runtime,
                &Request {
                    tpm_key: 0x8000_0000,
                    salt: off_curve,
                    ..Request::default()
                }
            ),
            vector("SAS_SALT_ECC_OFF_CURVE")
        );
    }

    #[test]
    fn loaded_object_bind_name_usage() {
        let mut runtime = restored("RSA_KEY");
        let request = Request {
            bind: 0x8000_0000,
            ..Request::default()
        };
        assert_eq!(
            start(&mut runtime, &request),
            vector("SAS_BOUND_RSA_OBJECT")
        );
        let session = session_of(&runtime, HMAC_SESSION_0);
        assert_eq!(session.bound_entity.len(), NAME_SIZE);
        assert_ne!(session.attributes & SESSION_ATTR_IS_BOUND, 0);
    }

    fn injected(session_type: u8, nonce_caller: &[u8]) -> StartAuthSessionIn<'_> {
        StartAuthSessionIn {
            nonce_caller,
            encrypted_salt: &[],
            session_type,
            symmetric: SymDefObject {
                algorithm: TPM_ALG_NULL,
                key_bits: None,
                mode: None,
            },
            auth_hash: ALG_SHA256,
        }
    }

    #[track_caller]
    fn assert_slot_state_is_pristine(runtime: &Tpm2Runtime) {
        assert_eq!(runtime.live.free_session_slots, MAX_LOADED_SESSIONS as u32);
        assert!(runtime.live.sessions.iter().all(|slot| !slot.occupied));
        assert!(
            runtime
                .live
                .sessions
                .iter()
                .all(|slot| slot.session.is_none())
        );
        assert_eq!(
            context_array(runtime),
            vec![0u16; MAX_ACTIVE_SESSIONS],
            "no context array entry survives a rolled back allocation"
        );
    }

    #[test]
    fn policy_epoch_read_failure_slot_release() {
        let mut runtime = restored("READY");
        let state = runtime.state.take();
        let nonce = nonce(16);
        let request = injected(TPM_SE_POLICY, &nonce);
        assert_eq!(
            create_session(&mut runtime, &request, TPM_RH_NULL, &[]).err(),
            Some(TPM_RC_FAILURE)
        );
        assert_slot_state_is_pristine(&runtime);
        runtime.state = state;
        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_HMAC_UNBOUND"),
            "the released slot is handed out again with the same handle"
        );
    }

    #[test]
    fn nonce_generation_failure_slot_release() {
        let mut runtime = restored("READY");
        let state = runtime.state.take();
        let nonce = nonce(16);
        let request = injected(TPM_SE_HMAC, &nonce);
        assert_eq!(
            create_session(&mut runtime, &request, TPM_RH_NULL, &[]).err(),
            Some(TPM_RC_FAILURE)
        );
        assert_slot_state_is_pristine(&runtime);
        runtime.state = state;
        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_HMAC_UNBOUND")
        );
    }

    #[test]
    fn session_key_derivation_failure_slot_release_drbg_retention() {
        let mut runtime = restored("READY");
        let state_clear = runtime.live.state_clear.take();
        let drbg_before = runtime.live.orderly.drbg_state.clone();
        let nonce = nonce(16);
        let request = injected(TPM_SE_HMAC, &nonce);
        assert_eq!(
            create_session(&mut runtime, &request, 0x4000_000c, &[]).err(),
            Some(TPM_RC_FAILURE)
        );
        assert_slot_state_is_pristine(&runtime);
        assert_ne!(
            runtime.live.orderly.drbg_state.reseed_counter, drbg_before.reseed_counter,
            "the nonce draw the reference performs is not rolled back"
        );
        runtime.live.state_clear = state_clear;
    }

    #[test]
    fn bound_entity_derivation_failure_slot_release() {
        use crate::library::tpm2::persistent::OwnedUserNvramEntry;
        let mut runtime = restored("POLICY_NV");
        for entry in &mut runtime
            .state
            .as_mut()
            .expect("decoded state")
            .user_nvram
            .entries
        {
            if let OwnedUserNvramEntry::NvIndex { index, .. } = entry {
                index.name_alg = TPM_ALG_NULL;
            }
        }
        let free_before = runtime.live.free_session_slots;
        let nonce = nonce(16);
        let request = injected(TPM_SE_HMAC, &nonce);
        assert_eq!(
            create_session(&mut runtime, &request, 0x0100_0000, &[]).err(),
            Some(crate::library::constants::TPM_RC_HASH),
            "an index with no name algorithm has no bound entity"
        );
        assert_eq!(runtime.live.free_session_slots, free_before);
        assert!(runtime.live.sessions.iter().all(|slot| !slot.occupied));
        assert_eq!(context_array(&runtime), vec![0u16; MAX_ACTIVE_SESSIONS]);
    }

    #[test]
    fn released_allocation_field_restoration() {
        use crate::library::tpm2::session::{allocate_session, release_session};
        let mut runtime = restored("READY");
        let allocated = allocate_session(&mut runtime.live).expect("a free slot");
        assert_eq!(
            runtime.live.free_session_slots,
            MAX_LOADED_SESSIONS as u32 - 1
        );
        assert!(runtime.live.sessions[allocated.ram_slot].occupied);
        assert_eq!(context_array(&runtime)[allocated.context_index as usize], 1);
        release_session(&mut runtime.live, allocated);
        assert_slot_state_is_pristine(&runtime);
    }

    #[test]
    fn full_session_table_allocation_rejection() {
        use crate::library::tpm2::session::allocate_session;
        let mut runtime = restored("THREE_SESSIONS");
        let context_before = context_array(&runtime);
        assert_eq!(
            allocate_session(&mut runtime.live).err(),
            Some(0x903),
            "all three slots are already occupied"
        );
        assert_eq!(runtime.live.free_session_slots, 0);
        assert_eq!(context_array(&runtime), context_before);
    }

    #[test]
    fn allocated_slot_no_occupation_without_session() {
        let mut runtime = restored("READY");
        let state = runtime.state.take();
        let nonce = nonce(16);
        for session_type in [TPM_SE_HMAC, TPM_SE_POLICY, TPM_SE_TRIAL] {
            let request = injected(session_type, &nonce);
            assert!(create_session(&mut runtime, &request, TPM_RH_NULL, &[]).is_err());
            assert!(
                runtime
                    .live
                    .sessions
                    .iter()
                    .all(|slot| slot.occupied == slot.session.is_some()),
                "session type {session_type}"
            );
        }
        runtime.state = state;
    }

    #[test]
    fn rejected_request_no_slot_occupation() {
        let mut runtime = restored("READY");
        let free_before = runtime.live.free_session_slots;
        let context_before = context_array(&runtime);
        for request in [
            Request {
                nonce_caller: nonce(15),
                ..Request::default()
            },
            Request {
                session_type: 0x02,
                ..Request::default()
            },
            Request {
                auth_hash: 0x0005,
                ..Request::default()
            },
            Request {
                salt: vec![0u8; 32],
                ..Request::default()
            },
            Request {
                symmetric: sym_aes(MODE_CBC),
                ..Request::default()
            },
            Request {
                tpm_key: 0x8000_0000,
                salt: vec![0u8; 32],
                ..Request::default()
            },
        ] {
            let response = start(&mut runtime, &request);
            assert_ne!(response_code(&response), RC_SUCCESS);
            assert_eq!(runtime.live.free_session_slots, free_before);
            assert_eq!(context_array(&runtime), context_before);
            assert!(runtime.live.sessions.iter().all(|slot| !slot.occupied));
        }
    }

    fn context_array(runtime: &Tpm2Runtime) -> Vec<u16> {
        runtime
            .live
            .state_reset
            .as_ref()
            .expect("state reset present")
            .context_array
            .to_vec()
    }

    #[test]
    fn session_creation_permanent_orderly_nv_preservation() {
        use crate::library::tpm2::persistent::persistent_all_store;
        let mut runtime = restored("READY");
        let permanent = persistent_all_store(runtime.state()).expect("the state serializes");
        let nv_memory = runtime.nv_memory.clone();
        let orderly = runtime.state().persistent.orderly_state;
        assert!(!runtime.nv_update_pending);

        assert_eq!(
            start(&mut runtime, &Request::default()),
            vector("SAS_HMAC_UNBOUND")
        );

        assert_eq!(
            persistent_all_store(runtime.state()).expect("the state serializes"),
            permanent,
            "a new session changes no permanent state"
        );
        assert_eq!(runtime.nv_memory, nv_memory);
        assert_eq!(runtime.state().persistent.orderly_state, orderly);
        assert!(
            !runtime.nv_update_pending,
            "consuming DRBG output schedules no NV write"
        );
    }

    #[test]
    fn context_array_entry_per_session() {
        let mut runtime = restored("READY");
        for index in 0..MAX_LOADED_SESSIONS {
            assert_eq!(response_code(&start(&mut runtime, &Request::default())), 0);
            assert_eq!(context_array(&runtime)[index], index as u16 + 1);
        }
        assert_eq!(
            context_array(&runtime)[MAX_LOADED_SESSIONS..],
            vec![0u16; MAX_ACTIVE_SESSIONS - MAX_LOADED_SESSIONS]
        );
    }

    #[test]
    fn session_isolation() {
        let mut runtime = restored("READY");
        assert_eq!(response_code(&start(&mut runtime, &Request::default())), 0);
        assert_eq!(
            response_code(&start(
                &mut runtime,
                &Request {
                    session_type: TPM_SE_POLICY,
                    auth_hash: ALG_SHA384,
                    nonce_caller: nonce(48),
                    ..Request::default()
                }
            )),
            0
        );
        let first = session_of(&runtime, HMAC_SESSION_0);
        assert_eq!(first.auth_hash_alg, ALG_SHA256);
        assert_eq!(first.nonce_tpm.as_bytes().len(), 16);
        let second = session_of(&runtime, 0x0300_0001);
        assert_eq!(second.auth_hash_alg, ALG_SHA384);
        assert_eq!(second.nonce_tpm.as_bytes().len(), 48);
        assert_eq!(second.audit_digest.len(), 48);
    }

    #[test]
    fn parameter_mutation_panic_safety() {
        let valid = Request::default().bytes();
        for length in 10..valid.len() {
            for byte in [0x00u8, 0x01, 0x80, 0xff] {
                let mut mutated = valid[..length].to_vec();
                *mutated.last_mut().expect("a non-empty prefix") = byte;
                let size = (mutated.len() as u32).to_be_bytes();
                mutated[2..6].copy_from_slice(&size);
                let mut runtime = restored("READY");
                let _ = dispatch_bytes(&mut runtime, &mutated);
            }
        }
    }
}
