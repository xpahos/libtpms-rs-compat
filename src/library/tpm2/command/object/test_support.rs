use crate::library::tpm2::nv::any_object_image;
use crate::library::tpm2::object_load::replay::{plain, push_tpm2b, sessioned};
use crate::library::tpm2::persistent::OwnedAnyObject;
use crate::library::tpm2::volatile::CURRENT_OBJECT_VERSION;

const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_CFB: u16 = 0x0043;

pub(super) fn sym_aes128_cfb() -> Vec<u8> {
    let mut out = TPM_ALG_AES.to_be_bytes().to_vec();
    out.extend_from_slice(&128u16.to_be_bytes());
    out.extend_from_slice(&TPM_ALG_CFB.to_be_bytes());
    out
}

pub(super) fn cap_cc_page(code: u32, count: u32) -> Vec<u8> {
    let mut payload = 2u32.to_be_bytes().to_vec();
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(&count.to_be_bytes());
    plain(0x0000_017a, &payload)
}

pub(super) fn split_tpm2b(blob: &[u8], at: usize) -> (Vec<u8>, usize) {
    let size = u16::from_be_bytes(blob[at..at + 2].try_into().expect("two bytes")) as usize;
    (blob[at + 2..at + 2 + size].to_vec(), at + 2 + size)
}

pub(super) fn cp_command(hierarchy: u32, user_auth: &[u8], template: &[u8]) -> Vec<u8> {
    let mut params = Vec::new();
    params.extend_from_slice(&(4 + user_auth.len() as u16).to_be_bytes());
    push_tpm2b(&mut params, user_auth);
    push_tpm2b(&mut params, &[]);
    push_tpm2b(&mut params, template);
    params.extend_from_slice(&0u16.to_be_bytes());
    params.extend_from_slice(&0u32.to_be_bytes());
    sessioned(0x0000_0131, &[hierarchy], &[], &params)
}

pub(super) fn flush_command(handle: u32) -> Vec<u8> {
    let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0e];
    out.extend_from_slice(&0x0000_0165u32.to_be_bytes());
    out.extend_from_slice(&handle.to_be_bytes());
    out
}

pub(super) fn evict_command(object: u32, persistent: u32) -> Vec<u8> {
    sessioned(
        0x0000_0120,
        &[TPM_RH_OWNER, object],
        &[],
        &persistent.to_be_bytes(),
    )
}

pub(super) fn cap_da_command() -> Vec<u8> {
    let mut out = vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x16];
    out.extend_from_slice(&0x0000_017au32.to_be_bytes());
    out.extend_from_slice(&6u32.to_be_bytes());
    out.extend_from_slice(&0x20eu32.to_be_bytes());
    out.extend_from_slice(&4u32.to_be_bytes());
    out
}

pub(super) fn object_images(objects: &[OwnedAnyObject]) -> Vec<Vec<u8>> {
    objects
        .iter()
        .map(|object| {
            any_object_image(object, CURRENT_OBJECT_VERSION).expect("the object serializes")
        })
        .collect()
}
