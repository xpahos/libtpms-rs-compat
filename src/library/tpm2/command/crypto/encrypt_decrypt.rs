// Part of the Rust port of libtpms.
//
// Identified upstream implementation sources:
// - libtpms/src/tpm2/EncryptDecrypt_spt.c
// - libtpms/src/tpm2/SymmetricCommands.c
//
// Original upstream authors and copyright notices:
// Written by Ken Goldman
// IBM Thomas J. Watson Research Center
// (c) Copyright IBM Corp. and others, 2016 - 2021
//
// Full original notices, license conditions and disclaimers are retained
// in LICENSES/libtpms-notices.txt and LICENSES/libtpms-LICENSE.txt.
//
// Rust translation and modifications:
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex

use crate::library::constants::{
    TPM_RC_ATTRIBUTES, TPM_RC_FAILURE, TPM_RC_INSUFFICIENT, TPM_RC_KEY, TPM_RC_MODE, TPM_RC_SIZE,
    TPM_RC_VALUE,
};
use crate::library::tpm2::algorithm::{algorithm_enabled, algorithm_profile_name};
use crate::library::tpm2::command::core::dispatcher::{CommandFrame, handle_at};
use crate::library::tpm2::command::core::output::CommandOutput;
use crate::library::tpm2::crypto::{
    SymDirection, sym_crypt, sym_key_block_size, sym_mode_is_block_cipher,
};
use crate::library::tpm2::marshal::{BlobReader, BlobWriter, Tpm2bError};
use crate::library::tpm2::object_create::resolve_any_object;
use crate::library::tpm2::persistent::{OwnedAnyObjectBody, OwnedSecret};
use crate::library::tpm2::public::{
    PublicParms, TPM_ALG_CBC, TPM_ALG_ECB, TPM_ALG_NULL, TPM_ALG_SYMCIPHER,
};
use crate::library::tpm2::runtime::Tpm2Runtime;
use crate::library::tpm2::self_test::self_test_algorithm;
use crate::library::tpm2::template::{
    TPMA_OBJECT_DECRYPT, TPMA_OBJECT_RESTRICTED, TPMA_OBJECT_SIGN,
};
use crate::types::TpmResult;

const TPM_RC_H: TpmResult = 0x000;
const TPM_RC_P: TpmResult = 0x040;
const TPM_RC_1: TpmResult = 0x100;
const TPM_RC_2: TpmResult = 0x200;
const TPM_RC_3: TpmResult = 0x300;
const TPM_RC_4: TpmResult = 0x400;

const RC_KEY_HANDLE: TpmResult = TPM_RC_H + TPM_RC_1;
const RC_MODE: TpmResult = TPM_RC_P + TPM_RC_2;
const RC_IV_IN: TpmResult = TPM_RC_P + TPM_RC_3;
const RC_IN_DATA: TpmResult = TPM_RC_P + TPM_RC_4;

const MAX_SYM_BLOCK_SIZE: usize = 16;
const MAX_DIGEST_BUFFER: usize = 1024;

const SHARED_MODE: TpmResult = TPM_RC_MODE + RC_MODE;
const SHARED_IV_IN: TpmResult = TPM_RC_SIZE + RC_IV_IN;
const SHARED_IN_DATA: TpmResult = TPM_RC_SIZE + RC_IN_DATA;

struct EncryptDecryptIn<'a> {
    decrypt: bool,
    mode: u16,
    iv_in: &'a [u8],
    in_data: &'a [u8],
}

pub(in crate::library::tpm2::command) fn execute(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let input = {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        let mut reader = BlobReader::new(frame.parameters);
        let decrypt = read_decrypt(&mut reader, TPM_RC_P + TPM_RC_1)?;
        let mode = read_mode(&state.profile.algorithms, &mut reader, TPM_RC_P + TPM_RC_2)?;
        let iv_in = read_buffer(&mut reader, MAX_SYM_BLOCK_SIZE, TPM_RC_P + TPM_RC_3)?;
        let in_data = read_buffer(&mut reader, MAX_DIGEST_BUFFER, TPM_RC_P + TPM_RC_4)?;
        finish(&reader)?;
        EncryptDecryptIn {
            decrypt,
            mode,
            iv_in,
            in_data,
        }
    };
    execute_shared(runtime, key_handle, &input)
}

pub(in crate::library::tpm2::command) fn execute_two(
    runtime: &mut Tpm2Runtime,
    frame: &CommandFrame<'_>,
) -> Result<CommandOutput, TpmResult> {
    let key_handle = handle_at(frame, 0)?;
    let input = {
        let state = runtime.state.as_ref().ok_or(TPM_RC_FAILURE)?;
        let mut reader = BlobReader::new(frame.parameters);
        let in_data = read_buffer(&mut reader, MAX_DIGEST_BUFFER, TPM_RC_P + TPM_RC_1)?;
        let decrypt = read_decrypt(&mut reader, TPM_RC_P + TPM_RC_2)?;
        let mode = read_mode(&state.profile.algorithms, &mut reader, TPM_RC_P + TPM_RC_3)?;
        let iv_in = read_buffer(&mut reader, MAX_SYM_BLOCK_SIZE, TPM_RC_P + TPM_RC_4)?;
        finish(&reader)?;
        EncryptDecryptIn {
            decrypt,
            mode,
            iv_in,
            in_data,
        }
    };
    execute_shared(runtime, key_handle, &input).map_err(swizzle)
}

fn swizzle(result: TpmResult) -> TpmResult {
    match result {
        SHARED_MODE => TPM_RC_MODE + TPM_RC_P + TPM_RC_3,
        SHARED_IV_IN => TPM_RC_SIZE + TPM_RC_P + TPM_RC_4,
        SHARED_IN_DATA => TPM_RC_SIZE + TPM_RC_P + TPM_RC_1,
        code => code,
    }
}

fn read_decrypt(reader: &mut BlobReader<'_>, modifier: TpmResult) -> Result<bool, TpmResult> {
    match reader.read_u8() {
        Ok(0) => Ok(false),
        Ok(1) => Ok(true),
        Ok(_) => Err(TPM_RC_VALUE + modifier),
        Err(_) => Err(TPM_RC_INSUFFICIENT + modifier),
    }
}

fn read_mode(
    profile_algorithms: &[u8],
    reader: &mut BlobReader<'_>,
    modifier: TpmResult,
) -> Result<u16, TpmResult> {
    let mode = reader
        .read_u16()
        .map_err(|_| TPM_RC_INSUFFICIENT + modifier)?;
    if mode == TPM_ALG_NULL {
        return Ok(mode);
    }
    let enabled = sym_mode_is_block_cipher(mode)
        && algorithm_profile_name(mode)
            .is_some_and(|name| algorithm_enabled(profile_algorithms, name));
    if !enabled {
        return Err(TPM_RC_MODE + modifier);
    }
    Ok(mode)
}

fn read_buffer<'a>(
    reader: &mut BlobReader<'a>,
    maximum: usize,
    modifier: TpmResult,
) -> Result<&'a [u8], TpmResult> {
    reader.read_tpm2b(maximum).map_err(|error| match error {
        Tpm2bError::Truncated => TPM_RC_INSUFFICIENT + modifier,
        Tpm2bError::SizeExceeded { .. } => TPM_RC_SIZE + modifier,
    })
}

fn finish(reader: &BlobReader<'_>) -> Result<(), TpmResult> {
    if reader.remaining().is_empty() {
        Ok(())
    } else {
        Err(TPM_RC_SIZE)
    }
}

fn execute_shared(
    runtime: &mut Tpm2Runtime,
    key_handle: u32,
    input: &EncryptDecryptIn<'_>,
) -> Result<CommandOutput, TpmResult> {
    let object = resolve_any_object(runtime, key_handle).ok_or(TPM_RC_FAILURE)?;
    let OwnedAnyObjectBody::Object(body) = &object.body else {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    };
    if body.public.object_type != TPM_ALG_SYMCIPHER {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    }
    let PublicParms::SymCipher(symmetric) = body.public.parameters else {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    };

    let attributes = body.public.object_attributes;
    let required = if input.decrypt {
        TPMA_OBJECT_DECRYPT
    } else {
        TPMA_OBJECT_SIGN
    };
    if attributes & TPMA_OBJECT_RESTRICTED != 0 || attributes & required == 0 {
        return Err(TPM_RC_ATTRIBUTES + RC_KEY_HANDLE);
    }

    let key_mode = symmetric.mode.unwrap_or(TPM_ALG_NULL);
    if !sym_mode_is_block_cipher(key_mode) && key_mode != TPM_ALG_NULL {
        return Err(TPM_RC_MODE + RC_KEY_HANDLE);
    }
    let mode = if key_mode == TPM_ALG_NULL {
        if input.mode == TPM_ALG_NULL {
            return Err(TPM_RC_MODE + RC_MODE);
        }
        input.mode
    } else {
        if input.mode != TPM_ALG_NULL && input.mode != key_mode {
            return Err(TPM_RC_MODE + RC_MODE);
        }
        key_mode
    };

    let key_bits = symmetric.key_bits.unwrap_or(0);
    let block_size =
        sym_key_block_size(symmetric.algorithm, key_bits).ok_or(TPM_RC_KEY + RC_KEY_HANDLE)?;
    let wanted_iv = if mode == TPM_ALG_ECB { 0 } else { block_size };
    if input.iv_in.len() != wanted_iv {
        return Err(TPM_RC_SIZE + RC_IV_IN);
    }
    if matches!(mode, TPM_ALG_CBC | TPM_ALG_ECB) && !input.in_data.len().is_multiple_of(block_size)
    {
        return Err(TPM_RC_SIZE + RC_IN_DATA);
    }

    let key = body
        .sensitive
        .sensitive
        .as_ref()
        .map_or(&[][..], OwnedSecret::as_bytes);
    if key.len() != usize::from(key_bits) / 8 {
        return Err(TPM_RC_KEY + RC_KEY_HANDLE);
    }
    let key = key.to_vec();
    let algorithm = symmetric.algorithm;

    let mut iv_out = input.iv_in.to_vec();
    let mut out_data = input.in_data.to_vec();
    if !out_data.is_empty() {
        self_test_algorithm(runtime, algorithm)?;
        let direction = if input.decrypt {
            SymDirection::Decrypt
        } else {
            SymDirection::Encrypt
        };
        sym_crypt(algorithm, &key, mode, &mut iv_out, direction, &mut out_data)?;
    }

    let mut writer = BlobWriter::new();
    writer.write_tpm2b(&out_data).map_err(|_| TPM_RC_SIZE)?;
    writer.write_tpm2b(&iv_out).map_err(|_| TPM_RC_SIZE)?;
    Ok(CommandOutput::from_parameters(writer.into_bytes()))
}

#[cfg(test)]
pub(in crate::library::tpm2) mod replay {
    use crate::library::tpm2::clock::SteppingClock;
    pub(in crate::library::tpm2) use crate::library::tpm2::golden_responses::encrypt_decrypt::vector;
    use crate::library::tpm2::object_load::replay::{exec_raw, runtime_from};
    use crate::library::tpm2::runtime::Tpm2Runtime;

    pub(in crate::library::tpm2) const CC_ENCRYPT_DECRYPT: u32 = 0x0000_0164;
    pub(in crate::library::tpm2) const CC_ENCRYPT_DECRYPT2: u32 = 0x0000_0193;

    pub(in crate::library::tpm2) fn runtime_at(
        snapshot: &str,
        clock: &SteppingClock,
    ) -> Tpm2Runtime {
        runtime_from(
            vector(&format!("PERMALL_{snapshot}")),
            vector(&format!("VOLATILE_{snapshot}")),
            clock,
        )
    }

    #[track_caller]
    pub(in crate::library::tpm2) fn exec(
        runtime: &mut Tpm2Runtime,
        clock: &SteppingClock,
        label: &str,
        bytes: Vec<u8>,
    ) -> Vec<u8> {
        let response = exec_raw(runtime, clock, bytes);
        assert_eq!(response, vector(label), "{label}");
        response
    }

    pub(in crate::library::tpm2) fn parameters(response: &[u8]) -> &[u8] {
        assert_eq!(response[6..10], [0, 0, 0, 0], "the command succeeded");
        &response[14..]
    }

    pub(in crate::library::tpm2) fn out_data(response: &[u8]) -> &[u8] {
        let body = parameters(response);
        let size = usize::from(u16::from_be_bytes([body[0], body[1]]));
        &body[2..2 + size]
    }

    pub(in crate::library::tpm2) fn iv_out(response: &[u8]) -> &[u8] {
        let body = parameters(response);
        let skip = 2 + usize::from(u16::from_be_bytes([body[0], body[1]]));
        let size = usize::from(u16::from_be_bytes([body[skip], body[skip + 1]]));
        &body[skip + 2..skip + 2 + size]
    }

    pub(in crate::library::tpm2) fn encrypt_decrypt(
        handle: u32,
        decrypt: bool,
        mode: u16,
        iv: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        encrypt_decrypt_with_auth(handle, decrypt, mode, iv, data, &[])
    }

    pub(in crate::library::tpm2) fn encrypt_decrypt_with_auth(
        handle: u32,
        decrypt: bool,
        mode: u16,
        iv: &[u8],
        data: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        let mut params = vec![u8::from(decrypt)];
        params.extend_from_slice(&mode.to_be_bytes());
        params.extend_from_slice(&tpm2b(iv));
        params.extend_from_slice(&tpm2b(data));
        encrypt_decrypt_raw(handle, &params, secret)
    }

    pub(in crate::library::tpm2) fn encrypt_decrypt_raw(
        handle: u32,
        params: &[u8],
        secret: &[u8],
    ) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&password_area(secret));
        payload.extend_from_slice(params);
        framed(0x8002, CC_ENCRYPT_DECRYPT, &payload)
    }

    pub(in crate::library::tpm2) fn encrypt_decrypt2(
        handle: u32,
        data: &[u8],
        decrypt: bool,
        mode: u16,
        iv: &[u8],
    ) -> Vec<u8> {
        let mut params = tpm2b(data);
        params.push(u8::from(decrypt));
        params.extend_from_slice(&mode.to_be_bytes());
        params.extend_from_slice(&tpm2b(iv));
        encrypt_decrypt2_raw(handle, &params)
    }

    pub(in crate::library::tpm2) fn encrypt_decrypt2_raw(handle: u32, params: &[u8]) -> Vec<u8> {
        let mut payload = handle.to_be_bytes().to_vec();
        payload.extend_from_slice(&password_area(&[]));
        payload.extend_from_slice(params);
        framed(0x8002, CC_ENCRYPT_DECRYPT2, &payload)
    }

    pub(in crate::library::tpm2) fn sym_public(
        attributes: u32,
        algorithm: u16,
        key_bits: u16,
        mode: u16,
    ) -> Vec<u8> {
        let mut out = 0x0025u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&attributes.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&algorithm.to_be_bytes());
        out.extend_from_slice(&key_bits.to_be_bytes());
        out.extend_from_slice(&mode.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    pub(in crate::library::tpm2) use crate::library::tpm2::object_load::replay::{
        clock, framed, load_external, password_area, plain, tpm2b,
    };
    pub(in crate::library::tpm2) use crate::library::tpm2::sequence::replay::{
        RH_NULL, RH_OWNER, create_primary,
    };
}

#[cfg(test)]
mod tests {
    use super::replay::*;
    use crate::library::tpm2::clock::SteppingClock;
    use crate::library::tpm2::object_load::replay::exec_raw;

    use crate::library::tpm2::command::core::test_support::{
        assert_scenario_response, for_each_mutation, occupied, prefix_bit_flips,
    };
    use crate::library::tpm2::command::crypto::test_support::{
        failed_tries, plain32, rsa_public, session_nonce,
    };

    use crate::library::tpm2::runtime::Tpm2Runtime;

    const TPM_ALG_AES: u16 = 0x0006;
    const TPM_ALG_TDES: u16 = 0x0003;
    const TPM_ALG_CAMELLIA: u16 = 0x0026;
    const TPM_ALG_NULL: u16 = 0x0010;
    const TPM_ALG_CMAC: u16 = 0x003f;
    const TPM_ALG_HMAC: u16 = 0x0005;
    const TPM_ALG_CTR: u16 = 0x0040;
    const TPM_ALG_OFB: u16 = 0x0041;
    const TPM_ALG_CBC: u16 = 0x0042;
    const TPM_ALG_CFB: u16 = 0x0043;
    const TPM_ALG_ECB: u16 = 0x0044;

    const SYM_BOTH: u32 = 0x0006_0452;
    const SYM_SIGN_ONLY: u32 = 0x0004_0452;
    const SYM_DECRYPT_ONLY: u32 = 0x0002_0452;
    const SYM_RESTRICTED: u32 = 0x0003_0472;
    const EXTERNAL_BOTH: u32 = 0x0006_0440;
    const HMAC_KEY_ATTR: u32 = 0x0004_0452;

    const HANDLE: u32 = 0x8000_0000;

    fn pattern(length: usize) -> Vec<u8> {
        (0..length).map(|index| index as u8).collect()
    }

    fn key16() -> Vec<u8> {
        pattern(16)
    }

    fn key24() -> Vec<u8> {
        pattern(24)
    }

    fn key32() -> Vec<u8> {
        pattern(32)
    }

    fn iv16() -> Vec<u8> {
        (0..16u8).rev().collect()
    }

    fn iv8() -> Vec<u8> {
        iv16()[..8].to_vec()
    }

    fn plain20() -> Vec<u8> {
        plain32()[..20].to_vec()
    }

    struct Case {
        label: &'static str,
        algorithm: u16,
        key: Vec<u8>,
        mode: u16,
        iv: Vec<u8>,
    }

    fn cases() -> Vec<Case> {
        let case = |label, algorithm, key: Vec<u8>, mode, iv: Vec<u8>| Case {
            label,
            algorithm,
            key,
            mode,
            iv,
        };
        vec![
            case("AES128_CFB", TPM_ALG_AES, key16(), TPM_ALG_CFB, iv16()),
            case("AES128_CBC", TPM_ALG_AES, key16(), TPM_ALG_CBC, iv16()),
            case("AES128_ECB", TPM_ALG_AES, key16(), TPM_ALG_ECB, Vec::new()),
            case("AES128_CTR", TPM_ALG_AES, key16(), TPM_ALG_CTR, iv16()),
            case("AES128_OFB", TPM_ALG_AES, key16(), TPM_ALG_OFB, iv16()),
            case("AES256_CFB", TPM_ALG_AES, key32(), TPM_ALG_CFB, iv16()),
            case("TDES192_CFB", TPM_ALG_TDES, key24(), TPM_ALG_CFB, iv8()),
            case("TDES192_CBC", TPM_ALG_TDES, key24(), TPM_ALG_CBC, iv8()),
            case(
                "CAMELLIA128_CFB",
                TPM_ALG_CAMELLIA,
                key16(),
                TPM_ALG_CFB,
                iv16(),
            ),
            case(
                "CAMELLIA128_CTR",
                TPM_ALG_CAMELLIA,
                key16(),
                TPM_ALG_CTR,
                iv16(),
            ),
        ]
    }

    fn fresh_clock() -> SteppingClock {
        clock()
    }

    fn reference_failed_tries(snapshot: &str) -> u32 {
        let reference = crate::library::tpm2::restore_permanent_blob_for_test(vector(&format!(
            "PERMALL_{snapshot}"
        )))
        .expect("the oracle permanent state restores");
        failed_tries(&reference)
    }

    fn base(clock: &SteppingClock) -> Tpm2Runtime {
        runtime_at("BASE", clock)
    }

    #[test]
    fn pre_startup_rejection() {
        let clock = fresh_clock();
        let mut runtime =
            crate::library::tpm2::restore_permanent_blob_for_test(vector("PERMALL_MANUFACTURED"))
                .expect("the oracle permanent state restores");
        assert_scenario_response(
            "TPM2_EncryptDecrypt before TPM2_Startup: encrypt-decrypt ED_BEFORE_STARTUP",
            vector("ED_BEFORE_STARTUP"),
            || {
                exec_raw(
                    &mut runtime,
                    &clock,
                    encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()[..16]),
                )
            },
        );
        assert_scenario_response(
            "TPM2_EncryptDecrypt2 before TPM2_Startup: encrypt-decrypt ED2_BEFORE_STARTUP",
            vector("ED2_BEFORE_STARTUP"),
            || {
                exec_raw(
                    &mut runtime,
                    &clock,
                    encrypt_decrypt2(HANDLE, &plain32()[..16], false, TPM_ALG_NULL, &iv16()),
                )
            },
        );
    }

    #[test]
    fn algorithm_and_mode_dual_layout_round_trip() {
        for case in cases() {
            let label = case.label;
            let aligned = matches!(case.mode, TPM_ALG_CBC | TPM_ALG_ECB);
            let clock = fresh_clock();
            let mut runtime = base(&clock);
            exec(
                &mut runtime,
                &clock,
                &format!("A_CREATE_{label}"),
                create_primary(
                    RH_OWNER,
                    &sym_public(
                        SYM_BOTH,
                        case.algorithm,
                        (case.key.len() * 8) as u16,
                        case.mode,
                    ),
                    &[],
                    &case.key,
                ),
            );
            let encrypted = exec(
                &mut runtime,
                &clock,
                &format!("A_ENC_{label}"),
                encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &case.iv, &plain32()),
            );
            let cipher_text = out_data(&encrypted).to_vec();
            assert_ne!(cipher_text, plain32(), "{label} encrypts");
            assert_eq!(cipher_text.len(), plain32().len(), "{label} keeps the size");
            let decrypted = exec(
                &mut runtime,
                &clock,
                &format!("A_DEC_{label}"),
                encrypt_decrypt(HANDLE, true, TPM_ALG_NULL, &case.iv, &cipher_text),
            );
            assert_eq!(out_data(&decrypted), plain32(), "{label} round trips");
            let encrypted2 = exec(
                &mut runtime,
                &clock,
                &format!("A_ENC2_{label}"),
                encrypt_decrypt2(HANDLE, &plain32(), false, TPM_ALG_NULL, &case.iv),
            );
            assert_eq!(
                parameters(&encrypted2),
                parameters(&encrypted),
                "{label} answers both layouts alike"
            );
            let decrypted2 = exec(
                &mut runtime,
                &clock,
                &format!("A_DEC2_{label}"),
                encrypt_decrypt2(HANDLE, &cipher_text, true, TPM_ALG_NULL, &case.iv),
            );
            assert_eq!(out_data(&decrypted2), plain32());
            let empty = exec(
                &mut runtime,
                &clock,
                &format!("A_ENC_EMPTY_{label}"),
                encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &case.iv, &[]),
            );
            assert!(out_data(&empty).is_empty(), "{label} answers no data");
            assert_eq!(
                iv_out(&empty),
                &case.iv[..],
                "{label} leaves the chaining value alone"
            );
            let explicit = exec(
                &mut runtime,
                &clock,
                &format!("A_ENC_EXPLICIT_{label}"),
                encrypt_decrypt(HANDLE, false, case.mode, &case.iv, &plain32()),
            );
            assert_eq!(
                parameters(&explicit),
                parameters(&encrypted),
                "{label} accepts its own mode"
            );
            if aligned {
                exec(
                    &mut runtime,
                    &clock,
                    &format!("A_ENC_UNALIGNED_{label}"),
                    encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &case.iv, &plain20()),
                );
                exec(
                    &mut runtime,
                    &clock,
                    &format!("A_ENC2_UNALIGNED_{label}"),
                    encrypt_decrypt2(HANDLE, &plain20(), false, TPM_ALG_NULL, &case.iv),
                );
            } else {
                let partial = exec(
                    &mut runtime,
                    &clock,
                    &format!("A_ENC_PARTIAL_{label}"),
                    encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &case.iv, &plain20()),
                );
                assert_eq!(
                    out_data(&partial),
                    &cipher_text[..20],
                    "{label} truncates the key stream"
                );
                let recovered = exec(
                    &mut runtime,
                    &clock,
                    &format!("A_DEC_PARTIAL_{label}"),
                    encrypt_decrypt(HANDLE, true, TPM_ALG_NULL, &case.iv, out_data(&partial)),
                );
                assert_eq!(out_data(&recovered), plain20());
            }
            let block = if case.algorithm == TPM_ALG_TDES {
                8
            } else {
                16
            };
            let first = exec(
                &mut runtime,
                &clock,
                &format!("A_CHAIN1_{label}"),
                encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &case.iv, &plain32()[..block]),
            );
            let second = exec(
                &mut runtime,
                &clock,
                &format!("A_CHAIN2_{label}"),
                encrypt_decrypt(
                    HANDLE,
                    false,
                    TPM_ALG_NULL,
                    iv_out(&first),
                    &plain32()[block..],
                ),
            );
            let mut joined = out_data(&first).to_vec();
            joined.extend_from_slice(out_data(&second));
            assert_eq!(joined, cipher_text, "{label} chains through ivOut");
            let wrong: Vec<u8> = if case.mode == TPM_ALG_ECB {
                iv16()
            } else {
                Vec::new()
            };
            exec(
                &mut runtime,
                &clock,
                &format!("A_ENC_WRONG_IV_{label}"),
                encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &wrong, &plain32()),
            );
            exec(
                &mut runtime,
                &clock,
                &format!("A_ENC2_WRONG_IV_{label}"),
                encrypt_decrypt2(HANDLE, &plain32(), false, TPM_ALG_NULL, &wrong),
            );
            if case.mode != TPM_ALG_ECB {
                let mut longer = case.iv.clone();
                longer.push(0x00);
                exec(
                    &mut runtime,
                    &clock,
                    &format!("A_ENC_SHORT_IV_{label}"),
                    encrypt_decrypt(
                        HANDLE,
                        false,
                        TPM_ALG_NULL,
                        &case.iv[..case.iv.len() - 1],
                        &plain32(),
                    ),
                );
                exec(
                    &mut runtime,
                    &clock,
                    &format!("A_ENC_LONG_IV_{label}"),
                    encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &longer, &plain32()),
                );
            }
            let other = if case.mode == TPM_ALG_CBC {
                TPM_ALG_CFB
            } else {
                TPM_ALG_CBC
            };
            exec(
                &mut runtime,
                &clock,
                &format!("A_ENC_OTHER_MODE_{label}"),
                encrypt_decrypt(HANDLE, false, other, &case.iv, &plain32()),
            );
            exec(
                &mut runtime,
                &clock,
                &format!("A_ENC2_OTHER_MODE_{label}"),
                encrypt_decrypt2(HANDLE, &plain32(), false, other, &case.iv),
            );
            assert_eq!(
                occupied(&runtime),
                [true, false, false],
                "{label} allocates no object"
            );
            assert!(!runtime.nv_update_pending, "{label} writes no NV state");
        }
    }

    #[test]
    fn modeless_key_explicit_mode_requirement() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "B_CREATE_NULL_MODE",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_NULL),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "B_ENC_NO_MODE",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "B_ENC2_NO_MODE",
            encrypt_decrypt2(HANDLE, &plain32(), false, TPM_ALG_NULL, &iv16()),
        );
        for (name, mode, iv) in [
            ("CFB", TPM_ALG_CFB, iv16()),
            ("CBC", TPM_ALG_CBC, iv16()),
            ("ECB", TPM_ALG_ECB, Vec::new()),
            ("CTR", TPM_ALG_CTR, iv16()),
            ("OFB", TPM_ALG_OFB, iv16()),
        ] {
            let encrypted = exec(
                &mut runtime,
                &clock,
                &format!("B_ENC_{name}"),
                encrypt_decrypt(HANDLE, false, mode, &iv, &plain32()),
            );
            let decrypted = exec(
                &mut runtime,
                &clock,
                &format!("B_DEC_{name}"),
                encrypt_decrypt(HANDLE, true, mode, &iv, out_data(&encrypted)),
            );
            assert_eq!(out_data(&decrypted), plain32(), "{name} round trips");
        }
    }

    #[test]
    fn object_attributes_operation_selection() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_SIGN_ONLY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_SIGN_ONLY, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_ENC_SIGN_ONLY",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "C_DEC_SIGN_ONLY",
            encrypt_decrypt(HANDLE, true, TPM_ALG_NULL, &iv16(), &plain32()),
        );

        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_DECRYPT_ONLY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_DECRYPT_ONLY, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_DEC_DECRYPT_ONLY",
            encrypt_decrypt(HANDLE, true, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "C_ENC_DECRYPT_ONLY",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );

        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_RESTRICTED",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_RESTRICTED, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &[],
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "C_ENC_RESTRICTED",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "C_DEC_RESTRICTED",
            encrypt_decrypt(HANDLE, true, TPM_ALG_NULL, &iv16(), &plain32()),
        );

        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_HMAC_KEY",
            create_primary(RH_OWNER, &keyedhash_public(), &[], &key32()),
        );
        exec(
            &mut runtime,
            &clock,
            "C_ENC_HMAC_KEY",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );

        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "C_CREATE_RSA_KEY",
            create_primary(RH_OWNER, &rsa_public(), &[], &[]),
        );
        exec(
            &mut runtime,
            &clock,
            "C_ENC_RSA_KEY",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );

        let clock = fresh_clock();
        let mut runtime = base(&clock);
        let mut public = sym_public(EXTERNAL_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB);
        let length = public.len();
        public[length - 2..].copy_from_slice(&32u16.to_be_bytes());
        public.extend_from_slice(&[0u8; 32]);
        exec(
            &mut runtime,
            &clock,
            "C_LOAD_PUBLIC_ONLY",
            load_external(&[], &public, RH_NULL),
        );
        exec(
            &mut runtime,
            &clock,
            "C_ENC_PUBLIC_ONLY",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "C_DEC_PUBLIC_ONLY",
            encrypt_decrypt(HANDLE, true, TPM_ALG_NULL, &iv16(), &plain32()),
        );
    }

    fn keyedhash_public() -> Vec<u8> {
        let mut out = 0x0008u16.to_be_bytes().to_vec();
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&HMAC_KEY_ATTR.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out.extend_from_slice(&TPM_ALG_HMAC.to_be_bytes());
        out.extend_from_slice(&0x000bu16.to_be_bytes());
        out.extend_from_slice(&tpm2b(&[]));
        out
    }

    #[test]
    fn malformed_request_indexed_error_reporting() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "D_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        for (label, handle) in [
            ("D_ENC_UNLOADED", 0x8000_0002u32),
            ("D_ENC_PERMANENT", RH_OWNER),
            ("D_ENC_UNDEFINED_PERSISTENT", 0x8100_0099),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                encrypt_decrypt(handle, false, TPM_ALG_NULL, &iv16(), &plain32()),
            );
        }
        exec(
            &mut runtime,
            &clock,
            "D_ENC_TRUNCATED_HANDLE",
            framed(0x8002, CC_ENCRYPT_DECRYPT, &[0x80, 0x00, 0x00]),
        );
        let mut valid = vec![0x00u8];
        valid.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        valid.extend_from_slice(&tpm2b(&iv16()));
        valid.extend_from_slice(&tpm2b(&plain32()));
        exec(
            &mut runtime,
            &clock,
            "D_ENC_NO_SESSIONS",
            plain(CC_ENCRYPT_DECRYPT, &{
                let mut payload = HANDLE.to_be_bytes().to_vec();
                payload.extend_from_slice(&valid);
                payload
            }),
        );
        exec(
            &mut runtime,
            &clock,
            "D_ENC_WRONG_AUTH",
            encrypt_decrypt_with_auth(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32(), b"nope"),
        );
        for (label, params) in [
            ("D_ENC_NO_PARAMETERS", Vec::new()),
            ("D_ENC_TRUNCATED_MODE", vec![0x00, 0x00]),
            (
                "D_ENC_TRUNCATED_IV",
                vec![0x00, 0x00, 0x10, 0x00, 0x10, 0x00],
            ),
            ("D_ENC_TRUNCATED_DATA", {
                let mut params = vec![0x00u8];
                params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                params.extend_from_slice(&tpm2b(&iv16()));
                params.push(0x00);
                params
            }),
            ("D_ENC_TRAILING", {
                let mut params = valid.clone();
                params.push(0xee);
                params
            }),
            ("D_ENC_BAD_DECRYPT", {
                let mut params = valid.clone();
                params[0] = 0x02;
                params
            }),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                encrypt_decrypt_raw(HANDLE, &params, &[]),
            );
        }
        exec(
            &mut runtime,
            &clock,
            "D_ENC_BAD_MODE",
            encrypt_decrypt(HANDLE, false, TPM_ALG_HMAC, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "D_ENC_CMAC_MODE",
            encrypt_decrypt(HANDLE, false, TPM_ALG_CMAC, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "D_ENC_OVERSIZED_IV",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &[0u8; 17], &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "D_ENC_OVERSIZED_DATA",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &[0u8; 1025]),
        );
        let maximum = exec(
            &mut runtime,
            &clock,
            "D_ENC_MAX_DATA",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &[0u8; 1024]),
        );
        assert_eq!(out_data(&maximum).len(), 1024, "the largest buffer answers");
        for (label, params) in [
            ("D_ENC2_NO_PARAMETERS", Vec::new()),
            ("D_ENC2_TRUNCATED_DATA", vec![0x00, 0x04, 0x01]),
            ("D_ENC2_TRUNCATED_DECRYPT", tpm2b(&plain32())),
            ("D_ENC2_TRUNCATED_MODE", {
                let mut params = tpm2b(&plain32());
                params.extend_from_slice(&[0x00, 0x00]);
                params
            }),
            ("D_ENC2_TRUNCATED_IV", {
                let mut params = tpm2b(&plain32());
                params.extend_from_slice(&[0x00, 0x00, 0x10, 0x00, 0x10, 0x00]);
                params
            }),
            ("D_ENC2_TRAILING", {
                let mut params = tpm2b(&plain32());
                params.push(0x00);
                params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                params.extend_from_slice(&tpm2b(&iv16()));
                params.push(0xee);
                params
            }),
            ("D_ENC2_BAD_DECRYPT", {
                let mut params = tpm2b(&plain32());
                params.push(0x02);
                params.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
                params.extend_from_slice(&tpm2b(&iv16()));
                params
            }),
        ] {
            exec(
                &mut runtime,
                &clock,
                label,
                encrypt_decrypt2_raw(HANDLE, &params),
            );
        }
        exec(
            &mut runtime,
            &clock,
            "D_ENC2_BAD_MODE",
            encrypt_decrypt2(HANDLE, &plain32(), false, TPM_ALG_HMAC, &iv16()),
        );
        exec(
            &mut runtime,
            &clock,
            "D_ENC2_OVERSIZED_DATA",
            encrypt_decrypt2(HANDLE, &[0u8; 1025], false, TPM_ALG_NULL, &iv16()),
        );
        exec(
            &mut runtime,
            &clock,
            "D_ENC2_OVERSIZED_IV",
            encrypt_decrypt2(HANDLE, &plain32(), false, TPM_ALG_NULL, &[0u8; 17]),
        );
        let mut payload = HANDLE.to_be_bytes().to_vec();
        payload.extend_from_slice(&tpm2b(&plain32()));
        payload.push(0x00);
        payload.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        payload.extend_from_slice(&tpm2b(&iv16()));
        exec(
            &mut runtime,
            &clock,
            "D_ENC2_NO_SESSIONS",
            plain(CC_ENCRYPT_DECRYPT2, &payload),
        );
        assert_eq!(occupied(&runtime), [true, false, false]);
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn da_protected_key_failed_auth_count() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "E_CREATE_DA_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH & !0x0000_0400, TPM_ALG_AES, 128, TPM_ALG_CFB),
                b"key-auth",
                &key16(),
            ),
        );
        assert_eq!(failed_tries(&runtime), 0);
        exec(
            &mut runtime,
            &clock,
            "E_ENC_WRONG_AUTH",
            encrypt_decrypt_with_auth(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32(), b"bad"),
        );
        assert_eq!(failed_tries(&runtime), 1, "the failure is recorded");
        assert_eq!(
            failed_tries(&runtime),
            reference_failed_tries("E_AFTER_WRONG_AUTH")
        );
        exec(
            &mut runtime,
            &clock,
            "E_ENC_RIGHT_AUTH",
            encrypt_decrypt_with_auth(
                HANDLE,
                false,
                TPM_ALG_NULL,
                &iv16(),
                &plain32(),
                b"key-auth",
            ),
        );
        assert_eq!(
            failed_tries(&runtime),
            reference_failed_tries("E_AFTER_RIGHT_AUTH"),
            "the counter follows the reference"
        );
    }

    #[test]
    fn profile_extra_mode_rejection() {
        let clock = fresh_clock();
        let mut runtime = runtime_at("MINIMAL_BASE", &clock);
        exec(
            &mut runtime,
            &clock,
            "F_CREATE_AES128_CFB",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "F_ENC_CFB",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "F_ENC_CBC_DISABLED",
            encrypt_decrypt(HANDLE, false, TPM_ALG_CBC, &iv16(), &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "F_ENC_ECB_DISABLED",
            encrypt_decrypt(HANDLE, false, TPM_ALG_ECB, &[], &plain32()),
        );
        exec(
            &mut runtime,
            &clock,
            "F_ENC2_CTR_DISABLED",
            encrypt_decrypt2(HANDLE, &plain32(), false, TPM_ALG_CTR, &iv16()),
        );
        exec(
            &mut runtime,
            &clock,
            "F_CREATE_CAMELLIA_DISABLED",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_CAMELLIA, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(
            &mut runtime,
            &clock,
            "F_CREATE_TDES_DISABLED",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_TDES, 192, TPM_ALG_CFB),
                &[],
                &key24(),
            ),
        );
    }

    const NONCE_CALLER: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    const SESSION_HANDLE: u32 = 0x0200_0000;
    const CC_START_AUTH_SESSION: u32 = 0x0000_0176;

    fn start_auth_session() -> Vec<u8> {
        let mut payload = RH_NULL.to_be_bytes().to_vec();
        payload.extend_from_slice(&RH_NULL.to_be_bytes());
        payload.extend_from_slice(&tpm2b(&NONCE_CALLER));
        payload.extend_from_slice(&tpm2b(&[]));
        payload.push(0x00);
        payload.extend_from_slice(&TPM_ALG_AES.to_be_bytes());
        payload.extend_from_slice(&128u16.to_be_bytes());
        payload.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
        payload.extend_from_slice(&0x000bu16.to_be_bytes());
        plain(CC_START_AUTH_SESSION, &payload)
    }

    fn parameter_cipher(nonce_tpm: &[u8], data: &[u8]) -> Vec<u8> {
        let material = crate::library::tpm2::crypto::kdfa(
            0x000b,
            &[],
            b"CFB\0",
            &NONCE_CALLER,
            nonce_tpm,
            (16 + 16) * 8,
        )
        .expect("the session key derives");
        let mut buffer = data.to_vec();
        crate::library::tpm2::crypto::sym_cfb_encrypt(
            TPM_ALG_AES,
            &material[..16],
            &material[16..],
            &mut buffer,
        )
        .expect("the parameter encrypts");
        buffer
    }

    fn session_command(code: u32, attributes: u8, parameters: &[u8], mac: &[u8]) -> Vec<u8> {
        let mut sessions = password_area(&[])[4..].to_vec();
        sessions.extend_from_slice(&SESSION_HANDLE.to_be_bytes());
        sessions.extend_from_slice(&tpm2b(&NONCE_CALLER));
        sessions.push(attributes);
        sessions.extend_from_slice(&tpm2b(mac));
        let mut payload = HANDLE.to_be_bytes().to_vec();
        payload.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
        payload.extend_from_slice(&sessions);
        payload.extend_from_slice(parameters);
        framed(0x8002, code, &payload)
    }

    #[test]
    fn parameter_encryption_command_layout_conformance() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        let session = exec(&mut runtime, &clock, "G_SESSION", start_auth_session());
        let nonce_tpm = session_nonce(&session);
        let encrypted = parameter_cipher(&nonce_tpm, &plain32());
        assert_ne!(encrypted, plain32(), "the request parameter is obscured");

        let mut parameters = tpm2b(&encrypted);
        parameters.push(0x00);
        parameters.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        parameters.extend_from_slice(&tpm2b(&iv16()));
        let decrypted = exec(
            &mut runtime,
            &clock,
            "G_ED2_DECRYPT_SESSION",
            session_command(CC_ENCRYPT_DECRYPT2, 0x21, &parameters, &[]),
        );

        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(&mut runtime, &clock, "G_SESSION", start_auth_session());
        let plain_parameters = {
            let mut parameters = tpm2b(&plain32());
            parameters.push(0x00);
            parameters.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
            parameters.extend_from_slice(&tpm2b(&iv16()));
            parameters
        };
        let plaintext_answer = exec(
            &mut runtime,
            &clock,
            "G_ED2_ENCRYPT_SESSION",
            session_command(CC_ENCRYPT_DECRYPT2, 0x41, &plain_parameters, &[]),
        );
        assert_eq!(
            out_data(&decrypted).len(),
            out_data(&plaintext_answer).len()
        );
        assert_ne!(
            out_data(&decrypted),
            out_data(&plaintext_answer),
            "only the second answer is encrypted"
        );
        assert_eq!(
            iv_out(&decrypted),
            iv_out(&plaintext_answer),
            "the response encryption covers only the first parameter"
        );

        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(&mut runtime, &clock, "G_SESSION", start_auth_session());
        let mut original = vec![0x00u8];
        original.extend_from_slice(&TPM_ALG_NULL.to_be_bytes());
        original.extend_from_slice(&tpm2b(&iv16()));
        original.extend_from_slice(&tpm2b(&plain32()));
        exec(
            &mut runtime,
            &clock,
            "G_ED_ENCRYPT_SESSION",
            session_command(CC_ENCRYPT_DECRYPT, 0x41, &original, &[]),
        );

        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(&mut runtime, &clock, "G_SESSION", start_auth_session());
        exec(
            &mut runtime,
            &clock,
            "G_ED_DECRYPT_REJECTED",
            session_command(CC_ENCRYPT_DECRYPT, 0x21, &original, &[]),
        );

        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "G_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        exec(&mut runtime, &clock, "G_SESSION", start_auth_session());
        exec(
            &mut runtime,
            &clock,
            "G_ED_BAD_SESSION_HMAC",
            session_command(CC_ENCRYPT_DECRYPT, 0x41, &original, &[0u8; 32]),
        );
    }

    #[test]
    fn success_self_test_change_symmetric_only() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "D_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        let before = runtime.self_test.pending_algorithms();
        assert!(before.contains(&TPM_ALG_AES), "the block cipher is pending");
        exec(
            &mut runtime,
            &clock,
            "A_ENC_EMPTY_AES128_CFB",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &[]),
        );
        assert_eq!(
            runtime.self_test.pending_algorithms(),
            before,
            "an empty buffer runs no self test"
        );
        exec(
            &mut runtime,
            &clock,
            "A_ENC_AES128_CFB",
            encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()),
        );
        let after = runtime.self_test.pending_algorithms();
        assert!(!after.contains(&TPM_ALG_AES), "the block cipher was tested");
        assert_eq!(
            after,
            before
                .iter()
                .copied()
                .filter(|&algorithm| algorithm != TPM_ALG_AES)
                .collect::<Vec<u16>>(),
            "no other self test runs"
        );
        assert!(!runtime.nv_update_pending);
    }

    #[test]
    fn prefix_and_bit_flip_panic_safety() {
        let clock = fresh_clock();
        let mut runtime = base(&clock);
        exec(
            &mut runtime,
            &clock,
            "D_CREATE_KEY",
            create_primary(
                RH_OWNER,
                &sym_public(SYM_BOTH, TPM_ALG_AES, 128, TPM_ALG_CFB),
                &[],
                &key16(),
            ),
        );
        for (case, valid) in [
            (
                "TPM2_EncryptDecrypt",
                encrypt_decrypt(HANDLE, false, TPM_ALG_NULL, &iv16(), &plain32()[..16]),
            ),
            (
                "TPM2_EncryptDecrypt2",
                encrypt_decrypt2(HANDLE, &plain32()[..16], false, TPM_ALG_NULL, &iv16()),
            ),
        ] {
            for_each_mutation(case, prefix_bit_flips(&valid, 10, 10, true), |bytes| {
                let _ = crate::library::tpm2::object_load::replay::exec_raw(
                    &mut runtime,
                    &clock,
                    bytes,
                );
            });
        }
    }
}
