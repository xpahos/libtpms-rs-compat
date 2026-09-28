// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

use std::ops::Range;

use sha1::{Digest, Sha1};

use crate::harness::{State, hex};

const VOLATILE_STATE_VERSION: u16 = 4;
const VOLATILE_STATE_MAGIC: [u8; 4] = [0x45, 0x63, 0x78, 0x89];
const ORDERLY_DATA_HEADER: [u8; 8] = [0x00, 0x02, 0x56, 0x65, 0x78, 0x87, 0x00, 0x01];
const SHA1_DIGEST_SIZE: usize = 20;
const PRIMARY_SEED_SIZE: usize = 64;
const TAIL_V4_BLOCK_SIZE: u16 = 35;
const HARDWARE_CLOCK_BLOCK_SIZE: u16 = 16;

type Fields = Vec<(&'static str, Range<usize>)>;

fn u16_at(blob: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([blob[at], blob[at + 1]])
}

fn orderly_data_headers(blob: &[u8]) -> Vec<usize> {
    blob.windows(ORDERLY_DATA_HEADER.len())
        .enumerate()
        .filter(|(_, window)| *window == ORDERLY_DATA_HEADER)
        .map(|(at, _)| at)
        .collect()
}

fn block_header(blob: &[u8], at: usize, size: u16) -> bool {
    blob[at] == 1 && u16_at(blob, at + 1) == size
}

fn checked_u16(blob: &[u8], at: usize) -> Option<usize> {
    let bytes = blob.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
}

fn orderly_time(blob: &[u8], orderly: usize) -> Result<Range<usize>, String> {
    let seed = orderly + 8 + 8 + 1 + 8 + 8 + 4;
    let locate = || {
        let last_value = seed + 2 + checked_u16(blob, seed)?;
        let drbg_block = last_value + 2 + 4 * checked_u16(blob, last_value)?;
        let self_heal = drbg_block + 3 + checked_u16(blob, drbg_block + 1)?;
        let time = self_heal + 3 + 16;
        (blob.get(self_heal) == Some(&1)
            && checked_u16(blob, self_heal + 1) == Some(24)
            && time + 8 <= blob.len())
        .then_some(time..time + 8)
    };
    locate().ok_or_else(|| format!("no ORDERLY_DATA time field after the header at {orderly}"))
}

fn seeds_end(blob: &[u8], mut at: usize, limit: usize) -> Option<usize> {
    for _ in 0..3 {
        if at + 2 > limit {
            return None;
        }
        let size = usize::from(u16_at(blob, at));
        if size > PRIMARY_SEED_SIZE {
            return None;
        }
        at += 2 + size;
    }
    Some(at)
}

fn volatile_host_time_fields(blob: &[u8]) -> Result<Fields, String> {
    let length = blob.len();
    if length < 512 {
        return Err(format!("a {length}-byte volatile state is too short"));
    }
    if u16_at(blob, 0) != VOLATILE_STATE_VERSION || blob[2..6] != VOLATILE_STATE_MAGIC {
        return Err(format!(
            "unexpected volatile state header {}",
            hex(&blob[..8])
        ));
    }
    let magic = length - SHA1_DIGEST_SIZE - 4;
    if blob[magic..magic + 4] != VOLATILE_STATE_MAGIC {
        return Err("the trailing magic is not where the tail should end".to_owned());
    }
    let tail_v5 = magic - 3;
    let tail_v4_values = tail_v5 - 32;
    let tail_v4 = tail_v4_values - 3;
    if !block_header(blob, tail_v5, 0) || !block_header(blob, tail_v4, TAIL_V4_BLOCK_SIZE) {
        return Err("the v4 and v5 tail blocks are not where they belong".to_owned());
    }
    let lowest = tail_v4.saturating_sub(3 + 3 * (2 + PRIMARY_SEED_SIZE));
    let tail_v3: Vec<usize> = (lowest..tail_v4 - 3)
        .filter(|&at| {
            blob[at] == 1
                && usize::from(u16_at(blob, at + 1)) + at + 3 == magic
                && seeds_end(blob, at + 3, tail_v4) == Some(tail_v4)
        })
        .collect();
    let [tail_v3] = tail_v3[..] else {
        return Err(format!("{} candidate v3 tail blocks", tail_v3.len()));
    };
    let backthen = tail_v3 - 8;
    let timer_flags = backthen - 4 - 2;
    let hardware_clock = timer_flags - 16;
    if !block_header(blob, hardware_clock - 3, HARDWARE_CLOCK_BLOCK_SIZE) {
        return Err("the hardware clock block is not where it belongs".to_owned());
    }
    let [orderly, ..] = orderly_data_headers(&blob[..tail_v3])[..] else {
        return Err("no ORDERLY_DATA header".to_owned());
    };
    Ok(vec![
        ("g_time", 12..20),
        ("go.clock", orderly + 8..orderly + 16),
        ("go.time", orderly_time(blob, orderly)?),
        (
            "s_realTimePrevious and s_tpmTime",
            hardware_clock..hardware_clock + 16,
        ),
        ("backthen", backthen..tail_v3),
        ("host clock tail", tail_v4_values..tail_v5),
        ("SHA-1 trailer", length - SHA1_DIGEST_SIZE..length),
    ])
}

fn permanent_host_time_fields(blob: &[u8]) -> Result<Fields, String> {
    let [orderly] = orderly_data_headers(blob)[..] else {
        return Err("not exactly one ORDERLY_DATA header".to_owned());
    };
    Ok(vec![
        ("NV go.clock", orderly + 8..orderly + 16),
        ("NV go.time", orderly_time(blob, orderly)?),
    ])
}

pub fn host_time_fields(kind: State, blob: &[u8]) -> Result<Fields, String> {
    match kind {
        State::Volatile => volatile_host_time_fields(blob),
        State::Permanent => permanent_host_time_fields(blob),
    }
}

pub fn verify_volatile_trailer(blob: &[u8]) -> Result<(), String> {
    let length = blob.len();
    let Some(payload) = length.checked_sub(SHA1_DIGEST_SIZE) else {
        return Err(format!(
            "a {length}-byte volatile state has no room for its {SHA1_DIGEST_SIZE}-byte SHA-1 trailer"
        ));
    };
    let digest = Sha1::digest(&blob[..payload]);
    if digest.as_slice() != &blob[payload..] {
        return Err(format!(
            "the SHA-1 trailer {} is not the SHA-1 {} of the {payload} bytes before it; \
             VolatileState_Save appends exactly that digest, so the export was altered or \
             its trailer was computed over different bytes",
            hex(&blob[payload..]),
            hex(&digest)
        ));
    }
    Ok(())
}

pub fn compare_running_export(kind: State, expected: &[u8], actual: &[u8]) -> Result<(), String> {
    if kind == State::Volatile {
        verify_volatile_trailer(expected).map_err(|error| format!("reference: {error}"))?;
        verify_volatile_trailer(actual).map_err(|error| format!("actual: {error}"))?;
    }
    if expected.len() != actual.len() {
        return Err(format!(
            "{kind:?} state of {} bytes, the reference exported {}",
            actual.len(),
            expected.len()
        ));
    }
    let fields = host_time_fields(kind, expected).map_err(|error| format!("reference: {error}"))?;
    let actual_fields =
        host_time_fields(kind, actual).map_err(|error| format!("actual: {error}"))?;
    if fields != actual_fields {
        return Err(format!(
            "the host time fields sit at {actual_fields:?}, the reference has them at {fields:?}"
        ));
    }
    let masked = |at: usize| fields.iter().any(|(_, range)| range.contains(&at));
    let differing: Vec<usize> = (0..expected.len())
        .filter(|&at| !masked(at) && expected[at] != actual[at])
        .collect();
    let Some(&first) = differing.first() else {
        return Ok(());
    };
    let window = first.saturating_sub(8)..(first + 24).min(expected.len());
    Err(format!(
        "{} bytes outside the host time fields differ, the first at offset {first}: \
         reference {} actual {} (from offset {})",
        differing.len(),
        hex(&expected[window.clone()]),
        hex(&actual[window.clone()]),
        window.start
    ))
}
