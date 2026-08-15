use crate::ffi_types::TpmResult;
use crate::library::constants::TPM_FAIL;

use super::persistent::{PersistentAllError, ProfileComponent, ProfileField};

pub(super) const STATE_FORMAT_LEVEL_CURRENT: u32 = 7;
const MAX_PROFILE_NAME_LEN: usize = 32;
const DESCRIPTION_MAX_SIZE: usize = 250;

const DEFAULT_COMMANDS_PROFILE: &[u8] = b"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,\
0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c";
const NULL_COMMANDS_PROFILE: &[u8] = b"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,\
0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197";
pub(super) const DEFAULT_ALGORITHMS_PROFILE: &[u8] =
    b"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,\
sha1,hmac,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,\
rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,\
ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,\
cmac,ctr,ofb,cbc,cfb,ecb";

struct ProfileDesc {
    level: u32,
    allow_modifications: bool,
    algorithms: &'static [u8],
    commands: &'static [u8],
    description: &'static [u8],
}

const PROFILE_NULL: ProfileDesc = ProfileDesc {
    level: 1,
    allow_modifications: false,
    algorithms: DEFAULT_ALGORITHMS_PROFILE,
    commands: NULL_COMMANDS_PROFILE,
    description: b"The profile enables the commands and algorithms that were \
enabled in libtpms v0.9. This profile is automatically used \
when the state does not have a profile, for example when it was \
created by libtpms v0.9 or before. This profile enables compatibility \
with libtpms >= v0.9.",
};
const PROFILE_DEFAULT_V1: ProfileDesc = ProfileDesc {
    level: STATE_FORMAT_LEVEL_CURRENT,
    allow_modifications: false,
    algorithms: DEFAULT_ALGORITHMS_PROFILE,
    commands: DEFAULT_COMMANDS_PROFILE,
    description: b"This profile enables all libtpms v0.10-supported commands and \
algorithms. This profile is compatible with libtpms >= v0.10.",
};
const PROFILE_CUSTOM: ProfileDesc = ProfileDesc {
    level: 2,
    allow_modifications: true,
    algorithms: DEFAULT_ALGORITHMS_PROFILE,
    commands: DEFAULT_COMMANDS_PROFILE,
    description: b"This profile allows customization of enabled algorithms and commands. \
This profile requires at least libtpms v0.10.",
};

pub(in crate::library::tpm2) const ATTRIBUTE_DRBG_CONTINUOUS_TEST: &[u8] = b"drbg-continous-test";

const ATTRIBUTES: [(&[u8], u32); 10] = [
    (b"no-unpadded-encryption", 7),
    (b"no-sha1-signing", 7),
    (b"no-sha1-verification", 7),
    (b"no-sha1-hmac-creation", 7),
    (b"no-sha1-hmac-verification", 7),
    (b"no-sha1-hmac", 7),
    (b"fips-host", 7),
    (ATTRIBUTE_DRBG_CONTINUOUS_TEST, 7),
    (b"pct", 7),
    (b"no-ecc-key-derivation", 7),
];

struct KeySize {
    size: u16,
    level: u32,
}
const KEY_SIZES_AES: &[KeySize] = &[
    KeySize {
        size: 128,
        level: 1,
    },
    KeySize {
        size: 192,
        level: 4,
    },
    KeySize {
        size: 256,
        level: 1,
    },
];
const KEY_SIZES_CAMELLIA: &[KeySize] = &[
    KeySize {
        size: 128,
        level: 1,
    },
    KeySize {
        size: 192,
        level: 4,
    },
    KeySize {
        size: 256,
        level: 1,
    },
];
const KEY_SIZES_TDES: &[KeySize] = &[
    KeySize {
        size: 128,
        level: 1,
    },
    KeySize {
        size: 192,
        level: 1,
    },
];
const KEY_SIZES_RSA: &[KeySize] = &[
    KeySize {
        size: 1024,
        level: 1,
    },
    KeySize {
        size: 2048,
        level: 1,
    },
    KeySize {
        size: 3072,
        level: 1,
    },
];
const KEY_SIZES_ECC: &[KeySize] = &[
    KeySize {
        size: 192,
        level: 1,
    },
    KeySize {
        size: 224,
        level: 1,
    },
    KeySize {
        size: 256,
        level: 1,
    },
    KeySize {
        size: 256,
        level: 1,
    },
    KeySize {
        size: 256,
        level: 1,
    },
    KeySize {
        size: 384,
        level: 1,
    },
    KeySize {
        size: 521,
        level: 1,
    },
    KeySize {
        size: 638,
        level: 1,
    },
];

const HMAC_MIN_KEY_SIZE_LEVEL: u32 = 7;
const HMAC_MIN_KEY_SIZE_MAX: u64 = 128 * 8;
const MIN_SIZE_MAX: u64 = 4096;

#[derive(Clone, Copy, PartialEq)]
enum TrackedMin {
    None,
    Aes,
    Rsa,
}

struct AlgEntry {
    name: &'static [u8],
    can_be_disabled: bool,
    level: u32,
    key_sizes: Option<&'static [KeySize]>,
    has_min_key_size: bool,
    tracked_min: TrackedMin,
}

const fn alg(
    name: &'static [u8],
    can_be_disabled: bool,
    key_sizes: Option<&'static [KeySize]>,
    has_min_key_size: bool,
    tracked_min: TrackedMin,
) -> AlgEntry {
    AlgEntry {
        name,
        can_be_disabled,
        level: 1,
        key_sizes,
        has_min_key_size,
        tracked_min,
    }
}

const ALGORITHMS: [AlgEntry; 34] = [
    alg(b"rsa", false, Some(KEY_SIZES_RSA), false, TrackedMin::Rsa),
    alg(b"tdes", true, Some(KEY_SIZES_TDES), false, TrackedMin::None),
    alg(b"sha1", true, None, false, TrackedMin::None),
    alg(b"hmac", false, None, true, TrackedMin::None),
    alg(b"aes", false, Some(KEY_SIZES_AES), false, TrackedMin::Aes),
    alg(b"mgf1", false, None, false, TrackedMin::None),
    alg(b"keyedhash", false, None, false, TrackedMin::None),
    alg(b"xor", false, None, false, TrackedMin::None),
    alg(b"sha256", false, None, false, TrackedMin::None),
    alg(b"sha384", false, None, false, TrackedMin::None),
    alg(b"sha512", true, None, false, TrackedMin::None),
    alg(b"null", false, None, false, TrackedMin::None),
    alg(b"rsassa", true, None, false, TrackedMin::None),
    alg(b"rsaes", true, None, false, TrackedMin::None),
    alg(b"rsapss", true, None, false, TrackedMin::None),
    alg(b"oaep", false, None, false, TrackedMin::None),
    alg(b"ecdsa", false, None, false, TrackedMin::None),
    alg(b"ecdh", false, None, false, TrackedMin::None),
    alg(b"ecdaa", true, None, false, TrackedMin::None),
    alg(b"sm2", true, None, false, TrackedMin::None),
    alg(b"ecschnorr", true, None, false, TrackedMin::None),
    alg(b"ecmqv", true, None, false, TrackedMin::None),
    alg(b"kdf1-sp800-56a", false, None, false, TrackedMin::None),
    alg(b"kdf2", false, None, false, TrackedMin::None),
    alg(b"kdf1-sp800-108", false, None, false, TrackedMin::None),
    alg(b"ecc", false, Some(KEY_SIZES_ECC), false, TrackedMin::None),
    alg(b"symcipher", false, None, false, TrackedMin::None),
    alg(
        b"camellia",
        true,
        Some(KEY_SIZES_CAMELLIA),
        false,
        TrackedMin::None,
    ),
    alg(b"cmac", true, None, false, TrackedMin::None),
    alg(b"ctr", true, None, false, TrackedMin::None),
    alg(b"ofb", true, None, false, TrackedMin::None),
    alg(b"cbc", true, None, false, TrackedMin::None),
    alg(b"cfb", false, None, false, TrackedMin::None),
    alg(b"ecb", true, None, false, TrackedMin::None),
];

const ECC_SHORTCUTS: [(&[u8], &[u8]); 2] = [(b"ecc-nist", b"ecc-nist-p"), (b"ecc-bn", b"ecc-bn-p")];

struct CurveEntry {
    name: &'static [u8],
    key_size: u32,
    can_be_disabled: bool,
    level: u32,
}
const ECC_CURVES: [CurveEntry; 8] = [
    CurveEntry {
        name: b"ecc-nist-p192",
        key_size: 192,
        can_be_disabled: true,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-nist-p224",
        key_size: 224,
        can_be_disabled: true,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-nist-p256",
        key_size: 256,
        can_be_disabled: false,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-nist-p384",
        key_size: 384,
        can_be_disabled: false,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-nist-p521",
        key_size: 521,
        can_be_disabled: true,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-bn-p256",
        key_size: 256,
        can_be_disabled: true,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-bn-p638",
        key_size: 638,
        can_be_disabled: true,
        level: 1,
    },
    CurveEntry {
        name: b"ecc-sm2-p256",
        key_size: 256,
        can_be_disabled: true,
        level: 1,
    },
];

const COMMAND_FIRST: u32 = 0x11f;
const COMMAND_COUNT: usize = 0x19f - 0x11f + 1;
#[rustfmt::skip]
const SUPPORTED_COMMANDS: [(u32, bool, u32); 114] = [
    (0x11f, true, 1),
    (0x120, false, 1),
    (0x121, true, 1),
    (0x122, true, 1),
    (0x124, true, 1),
    (0x125, true, 1),
    (0x126, true, 1),
    (0x127, true, 1),
    (0x128, true, 1),
    (0x129, false, 1),
    (0x12a, true, 1),
    (0x12b, false, 1),
    (0x12c, true, 1),
    (0x12d, true, 1),
    (0x12e, true, 1),
    (0x130, true, 1),
    (0x131, false, 1),
    (0x132, true, 1),
    (0x133, true, 1),
    (0x134, true, 1),
    (0x135, true, 1),
    (0x136, true, 1),
    (0x137, true, 1),
    (0x138, true, 1),
    (0x139, true, 1),
    (0x13a, true, 1),
    (0x13b, true, 1),
    (0x13c, false, 1),
    (0x13d, true, 1),
    (0x13e, true, 1),
    (0x13f, true, 1),
    (0x140, true, 1),
    (0x142, true, 1),
    (0x143, false, 1),
    (0x144, false, 1),
    (0x145, false, 1),
    (0x146, true, 1),
    (0x147, true, 1),
    (0x148, false, 1),
    (0x149, true, 1),
    (0x14a, true, 1),
    (0x14b, true, 1),
    (0x14c, true, 1),
    (0x14d, true, 1),
    (0x14e, false, 1),
    (0x14f, true, 1),
    (0x150, true, 1),
    (0x151, true, 1),
    (0x152, true, 1),
    (0x153, false, 1),
    (0x154, true, 1),
    (0x155, true, 1),
    (0x156, false, 1),
    (0x157, false, 1),
    (0x158, false, 1),
    (0x159, true, 1),
    (0x15b, true, 1),
    (0x15c, false, 1),
    (0x15d, true, 1),
    (0x15e, true, 1),
    (0x160, true, 1),
    (0x161, true, 1),
    (0x162, true, 1),
    (0x163, true, 1),
    (0x164, true, 1),
    (0x165, false, 1),
    (0x167, true, 1),
    (0x168, true, 1),
    (0x169, false, 1),
    (0x16a, true, 1),
    (0x16b, true, 1),
    (0x16c, true, 1),
    (0x16d, true, 1),
    (0x16e, true, 1),
    (0x16f, true, 1),
    (0x170, true, 1),
    (0x171, true, 1),
    (0x172, true, 1),
    (0x173, false, 1),
    (0x174, true, 1),
    (0x176, false, 1),
    (0x177, true, 1),
    (0x178, true, 1),
    (0x17a, false, 1),
    (0x17b, true, 1),
    (0x17c, false, 1),
    (0x17d, false, 1),
    (0x17e, false, 1),
    (0x17f, true, 1),
    (0x180, true, 1),
    (0x181, true, 1),
    (0x182, false, 1),
    (0x183, true, 1),
    (0x184, true, 1),
    (0x185, false, 1),
    (0x186, false, 1),
    (0x187, true, 1),
    (0x188, true, 1),
    (0x189, true, 1),
    (0x18a, true, 1),
    (0x18b, true, 1),
    (0x18c, true, 1),
    (0x18d, true, 1),
    (0x18e, true, 1),
    (0x18f, true, 1),
    (0x190, true, 1),
    (0x191, true, 1),
    (0x192, true, 1),
    (0x193, true, 1),
    (0x197, true, 1),
    (0x199, true, 3),
    (0x19a, true, 3),
    (0x19b, true, 5),
    (0x19c, true, 5),
];

fn command_entry(cc: u32) -> Option<(bool, u32)> {
    SUPPORTED_COMMANDS
        .iter()
        .find(|&&(code, _, _)| code == cc)
        .map(|&(_, can_be_disabled, level)| (can_be_disabled, level))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PersistentObjectFormat {
    LegacyRsa3072,
    AnyObject { object_version: u16 },
}

pub(super) fn persistent_object_format(state_format_level: u32) -> PersistentObjectFormat {
    if state_format_level < 2 {
        PersistentObjectFormat::LegacyRsa3072
    } else if state_format_level <= 5 {
        PersistentObjectFormat::AnyObject { object_version: 3 }
    } else {
        PersistentObjectFormat::AnyObject { object_version: 4 }
    }
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn expect(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn skip_spaces(&mut self) {
        while self.peek().is_some_and(is_space) {
            self.pos += 1;
        }
    }

    fn quoted_string(&mut self, min_len: usize) -> Option<&'a [u8]> {
        if !self.expect(b'"') {
            return None;
        }
        let start = self.pos;
        while let Some(byte) = self.peek() {
            if byte == b'"' {
                let content = &self.data[start..self.pos];
                self.pos += 1;
                return (content.len() >= min_len).then_some(content);
            }
            self.pos += 1;
        }
        None
    }

    fn digits(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.pos += 1;
        }
        (self.pos > start).then(|| &self.data[start..self.pos])
    }
}

fn check_profile_shape(json: &[u8]) -> bool {
    let mut scanner = Scanner { data: json, pos: 0 };

    fn entry(scanner: &mut Scanner<'_>) -> bool {
        scanner.skip_spaces();
        if scanner.quoted_string(1).is_none() {
            return false;
        }
        scanner.skip_spaces();
        if !scanner.expect(b':') {
            return false;
        }
        scanner.skip_spaces();
        if scanner.peek() == Some(b'"') {
            if scanner.quoted_string(0).is_none() {
                return false;
            }
        } else if scanner.digits().is_none() {
            return false;
        }
        scanner.skip_spaces();
        true
    }

    if !scanner.expect(b'{') {
        return false;
    }
    scanner.skip_spaces();
    if scanner.peek() == Some(b'"') && !entry(&mut scanner) {
        return false;
    }
    while scanner.peek() == Some(b',') {
        scanner.bump();
        if !entry(&mut scanner) {
            return false;
        }
    }
    scanner.expect(b'}') && scanner.pos == json.len()
}

enum ValueKind {
    NonEmptyString,
    AnyString,
    Digits,
}

fn extract_last<'a>(json: &'a [u8], needle: &[u8], kind: ValueKind) -> Option<&'a [u8]> {
    let mut end = json.len();
    while let Some(found) = json[..end].windows(needle.len()).rposition(|w| w == needle) {
        end = found;
        let mut scanner = Scanner {
            data: json,
            pos: found + needle.len(),
        };
        scanner.skip_spaces();
        if !scanner.expect(b':') {
            continue;
        }
        scanner.skip_spaces();
        let captured = match kind {
            ValueKind::NonEmptyString => scanner.quoted_string(1),
            ValueKind::AnyString => scanner.quoted_string(0),
            ValueKind::Digits => scanner.digits(),
        };
        if let Some(captured) = captured {
            return Some(captured);
        }
    }
    None
}

fn parse_level_digits(digits: &[u8]) -> Result<u32, PersistentAllError> {
    let mut value: u64 = 0;
    for &byte in digits {
        value = value
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'));
    }
    u32::try_from(value).map_err(|_| PersistentAllError::StateFormatLevelNotANumber)
}

fn dedup_list(list: &mut Vec<u8>) {
    fn find_from(list: &[u8], from: usize, byte: u8) -> Option<usize> {
        list.get(from..)?
            .iter()
            .position(|&b| b == byte)
            .map(|p| from + p)
    }
    fn find_subslice(list: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return (from <= list.len()).then_some(from);
        }
        list.get(from..)?
            .windows(needle.len())
            .position(|w| w == needle)
            .map(|p| from + p)
    }

    let mut pos = 0usize;
    loop {
        let Some(comma) = find_from(list, pos, b',') else {
            return;
        };
        let equals = list[pos..comma]
            .iter()
            .position(|&b| b == b'=')
            .map(|e| pos + e);
        let (key_end, exp) = match equals {
            Some(equals) => (equals, b'='),
            None => (comma, b','),
        };
        let slen = key_end - pos;
        let key: Vec<u8> = list[pos..key_end].to_vec();

        let mut found = false;
        let mut ncomma = comma;
        while let Some(dup) = find_subslice(list, ncomma + 1, &key) {
            let before_ok = dup == comma + 1 || list.get(dup - 1) == Some(&b',');
            let after = list.get(dup + slen).copied();
            if (before_ok && after == Some(exp)) || after.is_none() {
                list.drain(pos..=comma);
                found = true;
                break;
            }
            let Some(next) = find_from(list, dup, b',') else {
                break;
            };
            ncomma = next;
        }
        if !found {
            pos = comma + 1;
        }
    }
}

fn strtoul_c(bytes: &[u8], base10_only: bool) -> (u64, usize, bool) {
    let mut i = 0;
    while i < bytes.len() && is_space(bytes[i]) {
        i += 1;
    }
    let mut negative = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        negative = bytes[i] == b'-';
        i += 1;
    }
    let mut base: u64 = 10;
    if !base10_only && bytes.get(i) == Some(&b'0') {
        if matches!(bytes.get(i + 1), Some(b'x' | b'X'))
            && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            base = 16;
            i += 2;
        } else {
            base = 8;
        }
    }
    let digits_start = i;
    let mut value: u64 = 0;
    let mut overflowed = false;
    while i < bytes.len() {
        let digit = match bytes[i] {
            b @ b'0'..=b'9' => u64::from(b - b'0'),
            b @ b'a'..=b'f' if base == 16 => u64::from(b - b'a' + 10),
            b @ b'A'..=b'F' if base == 16 => u64::from(b - b'A' + 10),
            _ => break,
        };
        if digit >= base {
            break;
        }
        match value.checked_mul(base).and_then(|v| v.checked_add(digit)) {
            Some(v) => value = v,
            None => overflowed = true,
        }
        i += 1;
    }
    if i == digits_start {
        return (0, 0, false);
    }
    let value = if overflowed {
        u64::MAX
    } else if negative {
        value.wrapping_neg()
    } else {
        value
    };
    (value, i, overflowed)
}

fn entry_too_new(component: ProfileComponent, required: u32, maximum: u32) -> PersistentAllError {
    PersistentAllError::ProfileEntryLevelTooNew {
        component,
        required,
        maximum,
    }
}

fn apply_attributes(
    profile: &[u8],
    level: &mut u32,
    maximum: u32,
) -> Result<(), PersistentAllError> {
    if profile.is_empty() {
        return Ok(());
    }
    for token in profile.split(|&b| b == b',') {
        let Some(&(_, required)) = ATTRIBUTES.iter().find(|&&(name, _)| name == token) else {
            return Err(PersistentAllError::UnknownProfileAttribute);
        };
        if required > maximum {
            return Err(entry_too_new(
                ProfileComponent::Attributes,
                required,
                maximum,
            ));
        }
        *level = (*level).max(required);
    }
    Ok(())
}

fn apply_algorithms(
    profile: &[u8],
    level: &mut u32,
    maximum: u32,
) -> Result<(), PersistentAllError> {
    const COMPONENT: ProfileComponent = ProfileComponent::Algorithms;

    let mut enabled_algs = [false; ALGORITHMS.len()];
    let mut enabled_curves = [false; ECC_CURVES.len()];
    let mut min_aes: u64 = 128;
    let mut min_rsa: u64 = 1024;

    for token in profile.split(|&b| b == b',') {
        let mut found = false;
        for (index, entry) in ALGORITHMS.iter().enumerate() {
            if token == entry.name {
                if entry.level > maximum {
                    return Err(entry_too_new(COMPONENT, entry.level, maximum));
                }
                enabled_algs[index] = true;
                *level = (*level).max(entry.level);
                found = true;
                break;
            } else if entry.has_min_key_size {
                let Some(rest) = token
                    .strip_prefix(entry.name)
                    .and_then(|r| r.strip_prefix(b"-min-key-size="))
                else {
                    continue;
                };
                let (value, end, _) = strtoul_c(rest, true);
                if end != rest.len() || value > HMAC_MIN_KEY_SIZE_MAX {
                    return Err(PersistentAllError::InvalidProfileKeySize);
                }
                if HMAC_MIN_KEY_SIZE_LEVEL > maximum {
                    return Err(entry_too_new(COMPONENT, HMAC_MIN_KEY_SIZE_LEVEL, maximum));
                }
                *level = (*level).max(HMAC_MIN_KEY_SIZE_LEVEL);
                found = true;
                break;
            } else if let Some(key_sizes) = entry.key_sizes {
                let Some(rest) = token
                    .strip_prefix(entry.name)
                    .and_then(|r| r.strip_prefix(b"-min-size="))
                else {
                    continue;
                };
                let (value, end, _) = strtoul_c(rest, true);
                if end != rest.len() || value > MIN_SIZE_MAX {
                    return Err(PersistentAllError::InvalidProfileKeySize);
                }
                for key_size in key_sizes {
                    if u64::from(key_size.size) >= value && key_size.level <= maximum {
                        *level = (*level).max(key_size.level);
                    }
                }
                match entry.tracked_min {
                    TrackedMin::Aes => min_aes = value,
                    TrackedMin::Rsa => min_rsa = value,
                    TrackedMin::None => {}
                }
                found = true;
                break;
            }
        }

        if !found {
            let shortcut = ECC_SHORTCUTS.iter().find(|&&(name, _)| name == token);
            for curve in &ECC_CURVES {
                let matched = match shortcut {
                    Some(&(_, prefix)) => curve.name.starts_with(prefix),
                    None => curve.name == token,
                };
                if !matched {
                    continue;
                }
                if curve.level > maximum {
                    if shortcut.is_none() {
                        return Err(entry_too_new(COMPONENT, curve.level, maximum));
                    }
                    continue;
                }
                *level = (*level).max(curve.level);
                let index = ECC_CURVES
                    .iter()
                    .position(|c| core::ptr::eq(c, curve))
                    .unwrap();
                enabled_curves[index] = true;
                found = true;
            }
        }

        if !found {
            return Err(PersistentAllError::UnknownProfileAlgorithm);
        }
    }

    for (index, entry) in ALGORITHMS.iter().enumerate() {
        if !entry.can_be_disabled && !enabled_algs[index] {
            return Err(PersistentAllError::MissingRequiredProfileEntry {
                component: COMPONENT,
            });
        }
    }
    for (index, curve) in ECC_CURVES.iter().enumerate() {
        if !curve.can_be_disabled && !enabled_curves[index] {
            return Err(PersistentAllError::MissingRequiredProfileEntry {
                component: COMPONENT,
            });
        }
    }

    if min_aes > 128 && min_rsa == 2048 {
        return Err(PersistentAllError::InvalidProfileKeySize);
    }

    Ok(())
}

const ALGS_WITH_DEFAULT_MIN_SIZE: [&[u8]; 4] = [b"rsa", b"tdes", b"aes", b"camellia"];

struct AlgorithmSelection {
    algorithms: [bool; ALGORITHMS.len()],
    shortcuts: [bool; ECC_SHORTCUTS.len()],
    curves: [bool; ECC_CURVES.len()],
    min_sizes: [u32; ALGORITHMS.len()],
}

fn ecc_index() -> usize {
    ALGORITHMS
        .iter()
        .position(|entry| entry.name == b"ecc")
        .expect("the algorithm table always carries ecc")
}

fn select_algorithms(profile: &[u8]) -> AlgorithmSelection {
    let mut selection = AlgorithmSelection {
        algorithms: [false; ALGORITHMS.len()],
        shortcuts: [false; ECC_SHORTCUTS.len()],
        curves: [false; ECC_CURVES.len()],
        min_sizes: [0; ALGORITHMS.len()],
    };
    for (index, entry) in ALGORITHMS.iter().enumerate() {
        if !ALGS_WITH_DEFAULT_MIN_SIZE.contains(&entry.name) {
            continue;
        }
        if let Some(smallest) = entry.key_sizes.and_then(<[KeySize]>::first) {
            selection.min_sizes[index] = u32::from(smallest.size);
        }
    }

    for token in profile.split(|&byte| byte == b',') {
        if select_algorithm_token(&mut selection, token) {
            continue;
        }
        select_ecc_token(&mut selection, token);
    }

    let ecc_minimum = selection.min_sizes[ecc_index()];
    for (index, curve) in ECC_CURVES.iter().enumerate() {
        if curve.can_be_disabled && ecc_minimum > curve.key_size {
            selection.curves[index] = false;
        }
    }
    selection
}

fn select_algorithm_token(selection: &mut AlgorithmSelection, token: &[u8]) -> bool {
    for (index, entry) in ALGORITHMS.iter().enumerate() {
        if token == entry.name {
            selection.algorithms[index] = true;
            return true;
        }
        let suffix = if entry.has_min_key_size {
            b"-min-key-size=".as_slice()
        } else if entry.key_sizes.is_some() {
            b"-min-size=".as_slice()
        } else {
            continue;
        };
        let Some(rest) = token
            .strip_prefix(entry.name)
            .and_then(|rest| rest.strip_prefix(suffix))
        else {
            continue;
        };
        let (value, end, _) = strtoul_c(rest, true);
        if end == rest.len() {
            selection.min_sizes[index] = value as u32;
        }
        return true;
    }
    false
}

fn select_ecc_token(selection: &mut AlgorithmSelection, token: &[u8]) {
    let shortcut = ECC_SHORTCUTS
        .iter()
        .position(|&(name, _)| name == token)
        .inspect(|&index| selection.shortcuts[index] = true);
    for (index, curve) in ECC_CURVES.iter().enumerate() {
        let matched = match shortcut {
            Some(shortcut) => curve.name.starts_with(ECC_SHORTCUTS[shortcut].1),
            None => curve.name == token,
        };
        if matched {
            selection.curves[index] = true;
        }
    }
}

fn push_decimal(out: &mut String, mut value: u32) {
    let mut digits = [0u8; 10];
    let mut len = 0;
    loop {
        digits[len] = b'0' + (value % 10) as u8;
        len += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for &digit in digits[..len].iter().rev() {
        out.push(digit as char);
    }
}

fn push_name(out: &mut String, name: &[u8]) {
    if !out.is_empty() {
        out.push(',');
    }
    out.push_str(core::str::from_utf8(name).unwrap_or_default());
}

fn render_algorithms(selection: &AlgorithmSelection, wanted: bool) -> String {
    let ecc = ecc_index();
    let mut out = String::new();
    for (index, entry) in ALGORITHMS.iter().enumerate() {
        if selection.algorithms[index] == wanted {
            push_name(&mut out, entry.name);
            let minimum = selection.min_sizes[index];
            if wanted && minimum > 0 && (entry.key_sizes.is_some() || entry.has_min_key_size) {
                out.push(',');
                out.push_str(core::str::from_utf8(entry.name).unwrap_or_default());
                out.push_str(if entry.has_min_key_size {
                    "-min-key-size="
                } else {
                    "-min-size="
                });
                push_decimal(&mut out, minimum);
            }
        }
        if index != ecc {
            continue;
        }
        for (shortcut, &(name, _)) in ECC_SHORTCUTS.iter().enumerate() {
            if selection.shortcuts[shortcut] == wanted {
                push_name(&mut out, name);
            }
        }
        for (curve, entry) in ECC_CURVES.iter().enumerate() {
            if selection.curves[curve] == wanted {
                push_name(&mut out, entry.name);
            }
        }
    }
    out
}

pub(super) fn runtime_algorithm_lists(profile: &[u8]) -> (String, String) {
    let selection = select_algorithms(profile);
    (
        render_algorithms(&selection, true),
        render_algorithms(&selection, false),
    )
}

fn parse_range(token: &[u8]) -> Option<(u32, u32)> {
    let (value, end, overflowed) = strtoul_c(token, false);
    if overflowed || value > u64::from(u32::MAX) {
        return None;
    }
    let lo = value as u32;
    let mut pos = end;
    let hi = if token.get(pos) == Some(&b'-') {
        let (value, end, overflowed) = strtoul_c(&token[pos + 1..], false);
        if overflowed || value > u64::from(u32::MAX) {
            return None;
        }
        pos += 1 + end;
        value as u32
    } else {
        lo
    };
    (pos == token.len()).then_some((lo, hi))
}

pub(super) fn enabled_command_count(commands: &[u8]) -> Result<u32, TpmResult> {
    let mut enabled = [false; COMMAND_COUNT];
    for token in commands.split(|&b| b == b',') {
        let (lo, hi) = parse_range(token).ok_or(TPM_FAIL)?;
        let idx_lo = lo.wrapping_sub(COMMAND_FIRST) as usize;
        let idx_hi = hi.wrapping_sub(COMMAND_FIRST) as usize;
        if idx_lo >= COMMAND_COUNT || idx_hi >= COMMAND_COUNT {
            return Err(TPM_FAIL);
        }
        for slot in &mut enabled[idx_lo..=idx_hi] {
            *slot = true;
        }
    }
    Ok(enabled.iter().filter(|&&on| on).count() as u32)
}

fn apply_commands(profile: &[u8], level: &mut u32, maximum: u32) -> Result<(), PersistentAllError> {
    let mut enabled = [false; COMMAND_COUNT];
    for token in profile.split(|&b| b == b',') {
        let Some((lo, hi)) = parse_range(token) else {
            return Err(PersistentAllError::InvalidProfileCommandRange);
        };
        let idx_lo = lo.wrapping_sub(COMMAND_FIRST) as usize;
        let idx_hi = hi.wrapping_sub(COMMAND_FIRST) as usize;
        if idx_lo >= COMMAND_COUNT || idx_hi >= COMMAND_COUNT {
            return Err(PersistentAllError::InvalidProfileCommandRange);
        }
        #[allow(clippy::needless_range_loop)]
        for idx in idx_lo..=idx_hi {
            let cc = COMMAND_FIRST + idx as u32;
            let Some((_, required)) = command_entry(cc) else {
                return Err(PersistentAllError::InvalidProfileCommandRange);
            };
            if required > maximum {
                return Err(entry_too_new(ProfileComponent::Commands, required, maximum));
            }
            enabled[idx] = true;
            *level = (*level).max(required);
        }
    }

    for &(cc, can_be_disabled, _) in &SUPPORTED_COMMANDS {
        if !can_be_disabled && !enabled[(cc - COMMAND_FIRST) as usize] {
            return Err(PersistentAllError::MissingRequiredProfileEntry {
                component: ProfileComponent::Commands,
            });
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ValidatedProfile {
    pub(super) name: Vec<u8>,
    pub(super) state_format_level: u32,
    pub(super) algorithms: Vec<u8>,
    pub(super) commands: Vec<u8>,
    pub(super) attributes: Option<Vec<u8>>,
    pub(super) description: Vec<u8>,
    pub(super) was_null_profile: bool,
}

impl ValidatedProfile {
    pub(super) fn object_format(&self) -> PersistentObjectFormat {
        persistent_object_format(self.state_format_level)
    }

    pub(super) fn attribute_enabled(&self, name: &[u8]) -> bool {
        self.attributes.as_deref().is_some_and(|profile| {
            profile
                .split(|&byte| byte == b',')
                .any(|token| token == name)
        })
    }

    fn null_profile() -> Self {
        Self {
            name: b"null".to_vec(),
            state_format_level: PROFILE_NULL.level,
            algorithms: PROFILE_NULL.algorithms.to_vec(),
            commands: PROFILE_NULL.commands.to_vec(),
            attributes: None,
            description: PROFILE_NULL.description.to_vec(),
            was_null_profile: true,
        }
    }
}

pub(super) fn validate_profile(
    profile: ProfileField<'_>,
) -> Result<ValidatedProfile, PersistentAllError> {
    let bytes = match profile {
        ProfileField::Absent | ProfileField::Null => return Ok(ValidatedProfile::null_profile()),
        ProfileField::Bytes(bytes) => bytes,
    };
    let json = match bytes.iter().position(|&byte| byte == 0) {
        Some(nul) => &bytes[..nul],
        None => bytes,
    };

    if !check_profile_shape(json) {
        return Err(PersistentAllError::MalformedProfileJson);
    }

    let name = extract_last(json, b"\"Name\"", ValueKind::NonEmptyString)
        .ok_or(PersistentAllError::MissingProfileName)?;
    let name = &name[..name.len().min(MAX_PROFILE_NAME_LEN)];

    let digits = extract_last(json, b"\"StateFormatLevel\"", ValueKind::Digits)
        .ok_or(PersistentAllError::MissingStateFormatLevel)?;
    let level_json = parse_level_digits(digits)?;
    if level_json > STATE_FORMAT_LEVEL_CURRENT {
        return Err(PersistentAllError::StateFormatLevelTooNew {
            actual: level_json,
            supported: STATE_FORMAT_LEVEL_CURRENT,
        });
    }

    let algorithms_json = extract_last(json, b"\"Algorithms\"", ValueKind::NonEmptyString);
    let commands_json = extract_last(json, b"\"Commands\"", ValueKind::NonEmptyString);
    let attributes_json = extract_last(json, b"\"Attributes\"", ValueKind::AnyString);
    let description_json = extract_last(json, b"\"Description\"", ValueKind::NonEmptyString)
        .map(|description| &description[..description.len().min(DESCRIPTION_MAX_SIZE)]);

    let desc = if name == b"null" {
        &PROFILE_NULL
    } else if name == b"default-v1" {
        &PROFILE_DEFAULT_V1
    } else if name == b"custom" || name.starts_with(b"custom:") {
        &PROFILE_CUSTOM
    } else {
        return Err(PersistentAllError::UnknownProfileName);
    };

    let mut algorithms = algorithms_json
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| desc.algorithms.to_vec());
    let mut commands = commands_json
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| desc.commands.to_vec());
    let mut attributes = attributes_json.map(<[u8]>::to_vec);
    if algorithms_json.is_some() {
        dedup_list(&mut algorithms);
    }
    if commands_json.is_some() {
        dedup_list(&mut commands);
    }
    if let Some(attributes) = &mut attributes {
        dedup_list(attributes);
    }
    let description = description_json
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| desc.description.to_vec());

    let (maximum, mut level) = if level_json == 0 {
        if desc.allow_modifications {
            (u32::MAX, 0)
        } else {
            (desc.level, desc.level)
        }
    } else {
        (level_json, level_json)
    };

    if let Some(attributes) = &attributes {
        apply_attributes(attributes, &mut level, maximum)?;
    }
    apply_algorithms(&algorithms, &mut level, maximum)?;
    apply_commands(&commands, &mut level, maximum)?;

    Ok(ValidatedProfile {
        name: name.to_vec(),
        state_format_level: level,
        algorithms,
        commands,
        attributes,
        description,
        was_null_profile: false,
    })
}

pub(super) fn validate_user_profile(
    profile: Option<&[u8]>,
) -> Result<ValidatedProfile, PersistentAllError> {
    let Some(bytes) = profile else {
        return Ok(ValidatedProfile::null_profile());
    };
    let json = match bytes.iter().position(|&byte| byte == 0) {
        Some(nul) => &bytes[..nul],
        None => bytes,
    };

    if !check_profile_shape(json) {
        return Err(PersistentAllError::MalformedProfileJson);
    }

    let name = extract_last(json, b"\"Name\"", ValueKind::NonEmptyString)
        .ok_or(PersistentAllError::MissingProfileName)?;
    let name = &name[..name.len().min(MAX_PROFILE_NAME_LEN)];

    let level_json = match extract_last(json, b"\"StateFormatLevel\"", ValueKind::Digits) {
        Some(digits) => parse_level_digits(digits)?,
        None => 0,
    };
    if level_json > STATE_FORMAT_LEVEL_CURRENT {
        return Err(PersistentAllError::StateFormatLevelTooNew {
            actual: level_json,
            supported: STATE_FORMAT_LEVEL_CURRENT,
        });
    }

    let algorithms_json = extract_last(json, b"\"Algorithms\"", ValueKind::NonEmptyString);
    let commands_json = extract_last(json, b"\"Commands\"", ValueKind::NonEmptyString);
    let attributes_json = extract_last(json, b"\"Attributes\"", ValueKind::AnyString);
    let description_json = extract_last(json, b"\"Description\"", ValueKind::NonEmptyString)
        .map(|description| &description[..description.len().min(DESCRIPTION_MAX_SIZE)]);

    let desc = if name == b"null" {
        &PROFILE_NULL
    } else if name == b"default-v1" {
        &PROFILE_DEFAULT_V1
    } else if name == b"custom" || name.starts_with(b"custom:") {
        &PROFILE_CUSTOM
    } else {
        return Err(PersistentAllError::UnknownProfileName);
    };

    if !desc.allow_modifications
        && (level_json != 0
            || algorithms_json.is_some()
            || commands_json.is_some()
            || attributes_json.is_some()
            || description_json.is_some())
    {
        return Err(PersistentAllError::ProfileCustomizationNotAllowed);
    }

    let mut algorithms = algorithms_json
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| desc.algorithms.to_vec());
    let mut commands = commands_json
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| desc.commands.to_vec());
    let mut attributes = attributes_json.map(<[u8]>::to_vec);
    if algorithms_json.is_some() {
        dedup_list(&mut algorithms);
    }
    if commands_json.is_some() {
        dedup_list(&mut commands);
    }
    if let Some(attributes) = &mut attributes {
        dedup_list(attributes);
    }
    let description = description_json
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| desc.description.to_vec());

    let (maximum, mut level) = if desc.allow_modifications {
        match level_json {
            0 => (u32::MAX, 0),
            1 => return Err(PersistentAllError::CustomProfileLevelTooLow),
            explicit => (explicit, explicit),
        }
    } else {
        (desc.level, desc.level)
    };

    if let Some(attributes) = &attributes {
        apply_attributes(attributes, &mut level, maximum)?;
    }
    apply_algorithms(&algorithms, &mut level, maximum)?;
    apply_commands(&commands, &mut level, maximum)?;

    Ok(ValidatedProfile {
        name: name.to_vec(),
        state_format_level: level,
        algorithms,
        commands,
        attributes,
        description,
        was_null_profile: name == b"null",
    })
}

pub(super) fn command_enabled(commands: &[u8], command_code: u32) -> bool {
    commands.split(|&b| b == b',').any(|token| {
        parse_range(token).is_some_and(|(lo, hi)| lo <= command_code && command_code <= hi)
    })
}

#[cfg(test)]
pub(super) fn effective_state_format_level(
    profile: ProfileField<'_>,
) -> Result<u32, PersistentAllError> {
    validate_profile(profile).map(|profile| profile.state_format_level)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::constants::{
        TPM_RC_FAILURE, TPM_RC_KEY_SIZE, TPM_RC_NO_RESULT, TPM_RC_VALUE,
    };

    fn level(json: &[u8]) -> Result<u32, PersistentAllError> {
        effective_state_format_level(ProfileField::Bytes(json))
    }

    fn json(name: &str, level: u32, extra: &str) -> Vec<u8> {
        format!("{{\"Name\":\"{name}\",\"StateFormatLevel\":{level}{extra}}}").into_bytes()
    }

    fn algorithms_str() -> String {
        String::from_utf8(DEFAULT_ALGORITHMS_PROFILE.to_vec()).unwrap()
    }

    fn null_commands_str() -> String {
        String::from_utf8(NULL_COMMANDS_PROFILE.to_vec()).unwrap()
    }

    const MINIMAL_ALGORITHMS: &str = "rsa,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,null,oaep,\
ecdsa,ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,symcipher,cfb,ecc-nist-p256,ecc-nist-p384";

    #[test]
    fn absent_and_null_profiles_map_to_level_1() {
        assert_eq!(effective_state_format_level(ProfileField::Absent), Ok(1));
        assert_eq!(effective_state_format_level(ProfileField::Null), Ok(1));
    }

    #[test]
    fn serialized_null_profile_at_level_1_uses_its_descriptor_defaults() {
        assert_eq!(level(br#"{"Name":"null","StateFormatLevel":1}"#), Ok(1));
        assert_eq!(level(br#"{"Name":"null","StateFormatLevel":2}"#), Ok(2));
    }

    #[test]
    fn default_v1_accepts_its_valid_current_levels() {
        assert_eq!(level(&json("default-v1", 5, "")), Ok(5));
        assert_eq!(level(&json("default-v1", 6, "")), Ok(6));
        assert_eq!(level(&json("default-v1", 7, "")), Ok(7));
    }

    #[test]
    fn default_v1_with_an_insufficient_level_is_rejected() {
        assert_eq!(
            level(&json("default-v1", 2, "")).unwrap_err(),
            PersistentAllError::ProfileEntryLevelTooNew {
                component: ProfileComponent::Commands,
                required: 3,
                maximum: 2,
            }
        );
        for maximum in [3u32, 4] {
            let error = level(&json("default-v1", maximum, "")).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::ProfileEntryLevelTooNew {
                    component: ProfileComponent::Commands,
                    required: 5,
                    maximum,
                },
                "level {maximum}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn level_zero_falls_back_per_profile() {
        assert_eq!(level(br#"{"Name":"null","StateFormatLevel":0}"#), Ok(1));
        assert_eq!(level(&json("default-v1", 0, "")), Ok(7));
        assert_eq!(level(&json("custom", 0, "")), Ok(5));
    }

    #[test]
    fn custom_accepts_explicit_levels_with_fitting_components() {
        let low_commands = format!(",\"Commands\":\"{}\"", null_commands_str());
        let mid_commands = format!(",\"Commands\":\"{},0x199-0x19a\"", null_commands_str());
        assert_eq!(level(&json("custom", 2, &low_commands)), Ok(2));
        assert_eq!(level(&json("custom:mine", 2, &low_commands)), Ok(2));
        assert_eq!(level(&json("custom", 3, &mid_commands)), Ok(3));
        assert_eq!(level(&json("custom", 4, &mid_commands)), Ok(4));
        assert_eq!(level(&json("custom", 5, "")), Ok(5));
        assert_eq!(level(&json("custom", 6, "")), Ok(6));
        assert_eq!(level(&json("custom", 7, "")), Ok(7));
    }

    #[test]
    fn custom_level_zero_components_compute_the_effective_level() {
        let extra = format!(
            ",\"Commands\":\"{}\",\"Algorithms\":\"{MINIMAL_ALGORITHMS}\"",
            null_commands_str()
        );
        assert_eq!(level(&json("custom", 0, &extra)), Ok(1));

        let extra = format!(",\"Commands\":\"{}\"", null_commands_str());
        assert_eq!(level(&json("custom", 0, &extra)), Ok(4));

        let extra = format!(
            ",\"Commands\":\"{}\",\"Attributes\":\"pct\"",
            null_commands_str()
        );
        assert_eq!(level(&json("custom", 0, &extra)), Ok(7));
    }

    #[test]
    fn computed_levels_select_the_object_section_version() {
        use PersistentObjectFormat as F;

        let five = level(&json("custom", 0, "")).unwrap();
        assert_eq!(
            persistent_object_format(five),
            F::AnyObject { object_version: 3 }
        );
        let seven = level(&json("custom", 0, ",\"Attributes\":\"pct\"")).unwrap();
        assert_eq!(
            persistent_object_format(seven),
            F::AnyObject { object_version: 4 }
        );

        assert_eq!(persistent_object_format(0), F::LegacyRsa3072);
        assert_eq!(persistent_object_format(1), F::LegacyRsa3072);
        for l in 2..=5 {
            assert_eq!(
                persistent_object_format(l),
                F::AnyObject { object_version: 3 }
            );
        }
        for l in [6, 7] {
            assert_eq!(
                persistent_object_format(l),
                F::AnyObject { object_version: 4 }
            );
        }
    }

    #[test]
    fn attribute_requiring_level_7_is_gated_by_the_maximum() {
        let error = level(&json("null", 1, ",\"Attributes\":\"pct\"")).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ProfileEntryLevelTooNew {
                component: ProfileComponent::Attributes,
                required: 7,
                maximum: 1,
            }
        );
        let error = level(&json("custom", 6, ",\"Attributes\":\"fips-host\"")).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        let all = "no-unpadded-encryption,no-sha1-signing,no-sha1-verification,\
no-sha1-hmac-creation,no-sha1-hmac-verification,no-sha1-hmac,fips-host,\
drbg-continous-test,pct,no-ecc-key-derivation";
        assert_eq!(
            level(&json("custom", 7, &format!(",\"Attributes\":\"{all}\""))),
            Ok(7)
        );
    }

    #[test]
    fn unknown_attribute_is_tpm_rc_failure() {
        for attrs in ["nosuch", "pct,nosuch", "PCT", ""] {
            let data = json("custom", 7, &format!(",\"Attributes\":\"{attrs}\""));
            match attrs {
                "" => assert_eq!(level(&data), Ok(7)),
                _ => {
                    let error = level(&data).unwrap_err();
                    assert_eq!(
                        error,
                        PersistentAllError::UnknownProfileAttribute,
                        "attrs {attrs:?}"
                    );
                    assert_eq!(error.tpm_result(), TPM_RC_FAILURE);
                }
            }
        }
    }

    #[test]
    fn unknown_algorithm_specifier_is_rc_value() {
        for token in ["foo", "sha1x", "rsa-min-size", "ecc-nist-", ""] {
            let algorithms = format!("{},{token}", algorithms_str());
            let error = level(&json(
                "custom",
                0,
                &format!(",\"Algorithms\":\"{algorithms}\""),
            ))
            .unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::UnknownProfileAlgorithm,
                "token {token:?}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn hmac_min_key_size_requires_level_7() {
        let algorithms = format!("{},hmac-min-key-size=128", algorithms_str());
        let extra = format!(",\"Algorithms\":\"{algorithms}\"");
        let error = level(&json("custom", 6, &extra)).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ProfileEntryLevelTooNew {
                component: ProfileComponent::Algorithms,
                required: 7,
                maximum: 6,
            }
        );
        assert_eq!(level(&json("custom", 0, &extra)), Ok(7));
        assert_eq!(level(&json("custom", 7, &extra)), Ok(7));
    }

    #[test]
    fn min_size_values_are_validated_like_strtoul() {
        for bad in [
            "aes-min-size=12x",
            "aes-min-size=5000",
            "aes-min-size=-1",
            "hmac-min-key-size=1025",
            "hmac-min-key-size=99z",
        ] {
            let algorithms = format!("{},{bad}", algorithms_str());
            let error = level(&json(
                "custom",
                0,
                &format!(",\"Algorithms\":\"{algorithms}\""),
            ))
            .unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidProfileKeySize,
                "token {bad:?}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_KEY_SIZE);
        }
        let algorithms = format!("{},aes-min-size=,tdes-min-size=+128", algorithms_str());
        assert!(
            level(&json(
                "custom",
                0,
                &format!(",\"Algorithms\":\"{algorithms}\"")
            ))
            .is_ok()
        );
    }

    #[test]
    fn min_size_skips_key_sizes_beyond_the_maximum() {
        assert_eq!(level(br#"{"Name":"null","StateFormatLevel":1}"#), Ok(1));
        let extra = format!(",\"Commands\":\"{}\"", null_commands_str());
        assert_eq!(level(&json("custom", 4, &extra)), Ok(4));
    }

    #[test]
    fn missing_required_algorithm_or_curve_is_rc_value() {
        let algorithms = MINIMAL_ALGORITHMS.replace("aes,", "");
        let error = level(&json(
            "custom",
            0,
            &format!(",\"Algorithms\":\"{algorithms}\""),
        ))
        .unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingRequiredProfileEntry {
                component: ProfileComponent::Algorithms,
            }
        );
        let algorithms = MINIMAL_ALGORITHMS.replace(",ecc-nist-p384", "");
        let error = level(&json(
            "custom",
            0,
            &format!(",\"Algorithms\":\"{algorithms}\""),
        ))
        .unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_VALUE);
    }

    #[test]
    fn ecc_shortcuts_enable_their_curve_families() {
        let algorithms = "rsa,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,null,oaep,ecdsa,ecdh,\
kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,symcipher,cfb,ecc-nist,ecc-bn";
        let extra = format!(
            ",\"Algorithms\":\"{algorithms}\",\"Commands\":\"{}\"",
            null_commands_str()
        );
        assert_eq!(level(&json("custom", 0, &extra)), Ok(1));
    }

    #[test]
    fn aes_rsa_min_size_consistency_is_enforced() {
        let algorithms = algorithms_str()
            .replace("aes-min-size=128", "aes-min-size=256")
            .replace("rsa-min-size=1024", "rsa-min-size=2048");
        let error = level(&json(
            "custom",
            0,
            &format!(",\"Algorithms\":\"{algorithms}\""),
        ))
        .unwrap_err();
        assert_eq!(error, PersistentAllError::InvalidProfileKeySize);
        let algorithms = algorithms_str()
            .replace("aes-min-size=128", "aes-min-size=256")
            .replace("rsa-min-size=1024", "rsa-min-size=3072");
        assert!(
            level(&json(
                "custom",
                0,
                &format!(",\"Algorithms\":\"{algorithms}\"")
            ))
            .is_ok()
        );
    }

    #[test]
    fn duplicate_entries_keep_the_last_occurrence() {
        let algorithms = format!(
            "{},hmac-min-key-size=2048,hmac-min-key-size=128",
            algorithms_str()
        );
        assert_eq!(
            level(&json(
                "custom",
                0,
                &format!(",\"Algorithms\":\"{algorithms}\"")
            )),
            Ok(7)
        );
        let algorithms = format!("{},aes-min-size=4097,aes-min-size=192", algorithms_str());
        assert_eq!(
            level(&json(
                "custom",
                0,
                &format!(",\"Algorithms\":\"{algorithms}\"")
            )),
            Ok(5)
        );
    }

    #[test]
    fn dedup_matches_the_upstream_algorithm() {
        let mut list = b"sha1,sha1".to_vec();
        dedup_list(&mut list);
        assert_eq!(list, b"sha1");

        let mut list = b"aes-min-size=256,ctr,aes-min-size=128".to_vec();
        dedup_list(&mut list);
        assert_eq!(list, b"ctr,aes-min-size=128");

        let mut list = b"aes,aes-min-size=128".to_vec();
        dedup_list(&mut list);
        assert_eq!(list, b"aes,aes-min-size=128");

        let mut list = b"sha1,xsha1".to_vec();
        dedup_list(&mut list);
        assert_eq!(list, b"xsha1");
    }

    #[test]
    fn command_requiring_a_newer_level_is_rejected() {
        let commands = format!(",\"Commands\":\"{},0x199\"", null_commands_str());
        let error = level(&json("custom", 2, &commands)).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::ProfileEntryLevelTooNew {
                component: ProfileComponent::Commands,
                required: 3,
                maximum: 2,
            }
        );
        let commands = format!(",\"Commands\":\"{},0x19b\"", null_commands_str());
        let error = level(&json("custom", 4, &commands)).unwrap_err();
        assert_eq!(error.tpm_result(), TPM_RC_VALUE);
    }

    #[test]
    fn unknown_or_invalid_command_ranges_are_rc_value() {
        for commands in [
            "banana",
            "0x11f-",
            "0x11e",
            "0x1a0",
            "0x123",
            "0x12f",
            "0x19f",
            "0x11f-0x123",
            "0x120x",
            "",
        ] {
            let full = format!(",\"Commands\":\"{},{commands}\"", null_commands_str());
            let error = level(&json("custom", 0, &full)).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::InvalidProfileCommandRange,
                "commands {commands:?}"
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn command_ranges_accept_the_strtoul_base_0_forms() {
        let commands = format!(
            ",\"Commands\":\"{},287,0x140-0x130,0446- 0447\"",
            null_commands_str()
        );
        assert_eq!(level(&json("custom", 2, &commands)), Ok(2));
    }

    #[test]
    fn missing_required_command_is_rc_value() {
        let error = level(&json("custom", 0, ",\"Commands\":\"0x144-0x145\"")).unwrap_err();
        assert_eq!(
            error,
            PersistentAllError::MissingRequiredProfileEntry {
                component: ProfileComponent::Commands,
            }
        );
        assert_eq!(error.tpm_result(), TPM_RC_VALUE);
    }

    #[test]
    fn empty_and_missing_component_fields_use_the_defaults() {
        assert_eq!(
            level(&json("custom", 0, ",\"Algorithms\":\"\",\"Commands\":\"\"")),
            Ok(5)
        );
        assert_eq!(level(&json("custom", 0, ",\"Attributes\":\"\"")), Ok(5));
    }

    #[test]
    fn state_profiles_may_override_non_modifiable_defaults() {
        let extra = format!(",\"Algorithms\":\"{MINIMAL_ALGORITHMS}\"");
        assert_eq!(level(&json("null", 1, &extra)), Ok(1));
    }

    #[test]
    fn realistic_profiles_with_extra_fields_parse() {
        let data = json(
            "default-v1",
            7,
            ",\"Description\":\"some text\",\"Extra\":42",
        );
        assert_eq!(level(&data), Ok(7));
        assert_eq!(
            level(b"{ \"StateFormatLevel\" :\t007 ,\n\"Name\" : \"default-v1\" }"),
            Ok(7)
        );
    }

    #[test]
    fn malformed_json_is_no_result() {
        for json in [
            &b""[..],
            b"null",
            b"{",
            b"}",
            b"{}x",
            b" {\"Name\":\"null\",\"StateFormatLevel\":1}",
            b"{\"Name\":null}",
            b"{\"Name\":\"a\",}",
            b"{\"Name\":\"a\" \"S\":1}",
            b"{\"Name\":{\"a\":1}}",
            b"{\"Name\":[1]}",
            b"{\"\":1}",
            b"{\"Name\":-1}",
            b"{\"Name\":1.5}",
        ] {
            let error = level(json).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::MalformedProfileJson,
                "json {:?}",
                String::from_utf8_lossy(json)
            );
            assert_eq!(error.tpm_result(), TPM_RC_NO_RESULT);
        }
    }

    #[test]
    fn upstream_regex_quirks_are_reproduced() {
        assert_eq!(level(br#"{,"Name":"null","StateFormatLevel":1}"#), Ok(1));
        assert_eq!(
            level(b"{}").unwrap_err(),
            PersistentAllError::MissingProfileName
        );
        assert_eq!(
            level(br#"{"StateFormatLevel":2,"StateFormatLevel":1,"Name":"null"}"#),
            Ok(1)
        );
        assert_eq!(
            level(b"{\"Name\":\"null\",\"StateFormatLevel\":1}\0{garbage"),
            Ok(1)
        );
    }

    #[test]
    fn missing_name_is_no_result() {
        for json in [
            &br#"{"StateFormatLevel":1}"#[..],
            br#"{"Name":"","StateFormatLevel":1}"#,
            br#"{"name":"null","StateFormatLevel":1}"#,
        ] {
            let error = level(json).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::MissingProfileName,
                "json {:?}",
                String::from_utf8_lossy(json)
            );
            assert_eq!(error.tpm_result(), TPM_RC_NO_RESULT);
        }
    }

    #[test]
    fn missing_state_format_level_is_no_result() {
        let error = level(br#"{"Name":"null"}"#).unwrap_err();
        assert_eq!(error, PersistentAllError::MissingStateFormatLevel);
        assert_eq!(error.tpm_result(), TPM_RC_NO_RESULT);
    }

    #[test]
    fn unknown_profile_names_are_rc_value() {
        for json in [
            &br#"{"Name":"nosuch","StateFormatLevel":1}"#[..],
            br#"{"Name":"default","StateFormatLevel":1}"#,
            br#"{"Name":"customx","StateFormatLevel":2}"#,
            br#"{"Name":"NULL","StateFormatLevel":1}"#,
        ] {
            let error = level(json).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::UnknownProfileName,
                "json {:?}",
                String::from_utf8_lossy(json)
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn long_names_are_truncated_before_the_lookup() {
        let json = br#"{"Name":"custom:0123456789012345678901234567890123","StateFormatLevel":2}"#;
        let error = level(json).unwrap_err();
        assert!(
            matches!(error, PersistentAllError::ProfileEntryLevelTooNew { .. }),
            "{error:?}"
        );
        let json = br#"{"Name":"x2345678901234567890123456789012null","StateFormatLevel":1}"#;
        assert_eq!(
            level(json).unwrap_err(),
            PersistentAllError::UnknownProfileName
        );
    }

    #[test]
    fn too_new_levels_are_rc_value() {
        for (json, actual) in [
            (&br#"{"Name":"null","StateFormatLevel":8}"#[..], 8u32),
            (
                br#"{"Name":"default-v1","StateFormatLevel":4294967295}"#,
                u32::MAX,
            ),
        ] {
            let error = level(json).unwrap_err();
            assert_eq!(
                error,
                PersistentAllError::StateFormatLevelTooNew {
                    actual,
                    supported: STATE_FORMAT_LEVEL_CURRENT,
                }
            );
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn levels_beyond_uint_max_are_not_a_number() {
        for json in [
            &br#"{"Name":"null","StateFormatLevel":4294967296}"#[..],
            br#"{"Name":"null","StateFormatLevel":99999999999999999999999999}"#,
        ] {
            let error = level(json).unwrap_err();
            assert_eq!(error, PersistentAllError::StateFormatLevelNotANumber);
            assert_eq!(error.tpm_result(), TPM_RC_VALUE);
        }
    }

    #[test]
    fn malformed_input_never_panics() {
        let base = json(
            "custom",
            0,
            ",\"Algorithms\":\"aes,aes-min-size=128\",\"Commands\":\"0x11f-0x122\",\"Attributes\":\"pct\"",
        );
        for index in 0..base.len() {
            for byte in [0x00u8, b'"', b',', b'=', b'-', b'{', b'}', 0xff] {
                let mut mutated = base.clone();
                mutated[index] = byte;
                let _ = level(&mutated);
            }
        }
        for len in 0..base.len() {
            let _ = level(&base[..len]);
        }
    }

    #[test]
    fn absent_and_null_profiles_produce_the_null_profile_state() {
        for field in [ProfileField::Absent, ProfileField::Null] {
            let profile = validate_profile(field).unwrap();
            assert!(profile.was_null_profile);
            assert_eq!(profile.name, b"null");
            assert_eq!(profile.state_format_level, 1);
            assert_eq!(profile.algorithms, DEFAULT_ALGORITHMS_PROFILE);
            assert_eq!(profile.commands, NULL_COMMANDS_PROFILE);
            assert!(profile.attributes.is_none());
            assert_eq!(profile.description, PROFILE_NULL.description);
            assert_eq!(
                profile.object_format(),
                PersistentObjectFormat::LegacyRsa3072
            );
        }
    }

    #[test]
    fn serialized_null_profile_is_not_the_null_profile_fallback() {
        let profile = validate_profile(ProfileField::Bytes(
            br#"{"Name":"null","StateFormatLevel":1}"#,
        ))
        .unwrap();
        assert!(!profile.was_null_profile, "C wasNullProfile stays FALSE");
        assert_eq!(profile.name, b"null");
        assert_eq!(profile.state_format_level, 1);
    }

    #[test]
    fn serialized_components_are_stored_deduplicated() {
        let commands = null_commands_str();
        let json = format!(
            "{{\"Name\":\"custom:x\",\"StateFormatLevel\":7,\
             \"Algorithms\":\"{MINIMAL_ALGORITHMS},rsa\",\
             \"Commands\":\"{commands},{commands}\",\"Attributes\":\"pct,pct\"}}"
        );
        let profile = validate_profile(ProfileField::Bytes(json.as_bytes())).unwrap();
        let expected = format!("{MINIMAL_ALGORITHMS},rsa").replace("rsa,", "");
        assert_eq!(profile.algorithms, expected.as_bytes());
        assert_eq!(profile.commands, commands.as_bytes());
        assert_eq!(profile.attributes.as_deref(), Some(&b"pct"[..]));
        assert_eq!(profile.name, b"custom:x");
    }

    #[test]
    fn missing_components_fall_back_to_the_descriptor_defaults() {
        let profile = validate_profile(ProfileField::Bytes(
            br#"{"Name":"default-v1","StateFormatLevel":7}"#,
        ))
        .unwrap();
        assert_eq!(profile.algorithms, DEFAULT_ALGORITHMS_PROFILE);
        assert_eq!(profile.commands, DEFAULT_COMMANDS_PROFILE);
        assert!(profile.attributes.is_none());
        assert_eq!(profile.description, PROFILE_DEFAULT_V1.description);
    }

    #[test]
    fn json_description_is_preserved_and_truncated() {
        let profile = validate_profile(ProfileField::Bytes(
            br#"{"Name":"null","StateFormatLevel":1,"Description":"my state"}"#,
        ))
        .unwrap();
        assert_eq!(profile.description, b"my state");

        let long = "d".repeat(DESCRIPTION_MAX_SIZE + 30);
        let json =
            format!("{{\"Name\":\"null\",\"StateFormatLevel\":1,\"Description\":\"{long}\"}}");
        let profile = validate_profile(ProfileField::Bytes(json.as_bytes())).unwrap();
        assert_eq!(profile.description.len(), DESCRIPTION_MAX_SIZE);

        let profile = validate_profile(ProfileField::Bytes(
            br#"{"Name":"null","StateFormatLevel":1,"Description":""}"#,
        ))
        .unwrap();
        assert_eq!(profile.description, PROFILE_NULL.description);
    }

    #[test]
    fn long_names_are_truncated_before_lookup() {
        let json = format!(
            "{{\"Name\":\"custom:{}\",\"StateFormatLevel\":7}}",
            "x".repeat(40)
        );
        let profile = validate_profile(ProfileField::Bytes(json.as_bytes())).unwrap();
        assert_eq!(profile.name.len(), 32);
        assert!(profile.name.starts_with(b"custom:"));
    }

    #[test]
    fn user_null_pointer_selects_the_null_profile() {
        let profile = validate_user_profile(None).unwrap();
        assert_eq!(profile.name, b"null");
        assert_eq!(profile.state_format_level, 1);
        assert!(profile.was_null_profile);
    }

    #[test]
    fn user_bare_names_resolve_to_their_descriptor_levels() {
        let null = validate_user_profile(Some(br#"{"Name":"null"}"#)).unwrap();
        assert_eq!(null.state_format_level, 1);
        assert!(null.was_null_profile, "a by-name null profile counts");
        assert_eq!(null.commands, NULL_COMMANDS_PROFILE);

        let default = validate_user_profile(Some(br#"{"Name":"default-v1"}"#)).unwrap();
        assert_eq!(default.state_format_level, STATE_FORMAT_LEVEL_CURRENT);
        assert!(!default.was_null_profile);
        assert_eq!(default.commands, DEFAULT_COMMANDS_PROFILE);
    }

    #[test]
    fn user_explicit_level_zero_acts_like_an_absent_level() {
        let profile =
            validate_user_profile(Some(br#"{"Name":"default-v1","StateFormatLevel":0}"#)).unwrap();
        assert_eq!(profile.state_format_level, STATE_FORMAT_LEVEL_CURRENT);
    }

    #[test]
    fn user_customization_of_non_modifiable_profiles_is_rejected() {
        for json in [
            br#"{"Name":"null","StateFormatLevel":1}"#.as_slice(),
            br#"{"Name":"default-v1","StateFormatLevel":7}"#.as_slice(),
            br#"{"Name":"default-v1","Commands":"0x11f-0x193"}"#.as_slice(),
            br#"{"Name":"null","Algorithms":"rsa"}"#.as_slice(),
            br#"{"Name":"null","Attributes":""}"#.as_slice(),
            br#"{"Name":"default-v1","Description":"mine"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_user_profile(Some(json)).unwrap_err(),
                PersistentAllError::ProfileCustomizationNotAllowed,
                "{}",
                String::from_utf8_lossy(json)
            );
        }
    }

    #[test]
    fn user_custom_profile_level_rules() {
        assert_eq!(
            validate_user_profile(Some(br#"{"Name":"custom","StateFormatLevel":1}"#)).unwrap_err(),
            PersistentAllError::CustomProfileLevelTooLow
        );
        assert_eq!(
            validate_user_profile(Some(br#"{"Name":"custom","StateFormatLevel":2}"#)).unwrap_err(),
            PersistentAllError::ProfileEntryLevelTooNew {
                component: ProfileComponent::Commands,
                required: 3,
                maximum: 2,
            }
        );
        let restricted = format!(
            r#"{{"Name":"custom","StateFormatLevel":2,"Commands":"{}"}}"#,
            null_commands_str()
        );
        let profile = validate_user_profile(Some(restricted.as_bytes())).unwrap();
        assert_eq!(profile.state_format_level, 2);
        assert!(!profile.was_null_profile);
        let computed = validate_user_profile(Some(br#"{"Name":"custom"}"#)).unwrap();
        assert_eq!(computed.state_format_level, 5);
    }

    #[test]
    fn user_unknown_names_and_too_new_levels_are_rejected() {
        assert_eq!(
            validate_user_profile(Some(br#"{"Name":"nope"}"#)).unwrap_err(),
            PersistentAllError::UnknownProfileName
        );
        assert_eq!(
            validate_user_profile(Some(br#"{"Name":"custom","StateFormatLevel":8}"#)).unwrap_err(),
            PersistentAllError::StateFormatLevelTooNew {
                actual: 8,
                supported: STATE_FORMAT_LEVEL_CURRENT,
            }
        );
        assert_eq!(
            validate_user_profile(Some(b"not json")).unwrap_err(),
            PersistentAllError::MalformedProfileJson
        );
        assert_eq!(
            validate_user_profile(Some(br#"{"StateFormatLevel":2}"#)).unwrap_err(),
            PersistentAllError::MissingProfileName
        );
    }

    #[test]
    fn command_enabled_consults_the_validated_ranges() {
        assert!(command_enabled(NULL_COMMANDS_PROFILE, 0x140));
        assert!(command_enabled(DEFAULT_COMMANDS_PROFILE, 0x140));
        assert!(command_enabled(DEFAULT_COMMANDS_PROFILE, 0x199));
        assert!(!command_enabled(NULL_COMMANDS_PROFILE, 0x199));
        assert!(!command_enabled(NULL_COMMANDS_PROFILE, 0x12f), "0x12f gap");
    }
}

#[cfg(test)]
mod runtime_algorithm_tests {
    use super::*;

    const IMPLEMENTED: &str = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,\
hmac-min-key-size=1,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,\
rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,\
ecc-min-size=192,ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p256,ecc-nist-p384,\
ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,\
cmac,ctr,ofb,cbc,cfb,ecb";

    const DEFAULT_ENABLED: &str = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,\
aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,\
ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,\
ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,ecc-bn-p256,\
ecc-bn-p638,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb";

    const CAN_BE_DISABLED: [&str; 24] = [
        "tdes",
        "sha1",
        "sha512",
        "rsassa",
        "rsaes",
        "rsapss",
        "ecdaa",
        "sm2",
        "ecschnorr",
        "ecmqv",
        "ecc-nist",
        "ecc-bn",
        "ecc-nist-p192",
        "ecc-nist-p224",
        "ecc-nist-p521",
        "ecc-bn-p256",
        "ecc-bn-p638",
        "ecc-sm2-p256",
        "camellia",
        "cmac",
        "ctr",
        "ofb",
        "cbc",
        "ecb",
    ];

    #[track_caller]
    fn lists(profile: &str) -> (String, String) {
        runtime_algorithm_lists(profile.as_bytes())
    }

    fn swtpm_setup_profile(disabled: &[&str]) -> String {
        let mut algorithms = IMPLEMENTED.replace(',', " ");
        for name in disabled {
            if let Some(start) = algorithms.find(name) {
                algorithms.replace_range(start..start + name.len(), "");
            }
            while algorithms.contains("  ") {
                algorithms = algorithms.replace("  ", " ");
            }
            algorithms = algorithms.trim().to_string();
        }
        algorithms.replace(' ', ",")
    }

    #[test]
    fn the_default_profile_enables_everything_it_names() {
        let (enabled, disabled) =
            lists(core::str::from_utf8(DEFAULT_ALGORITHMS_PROFILE).expect("the table is ASCII"));
        assert_eq!(enabled, DEFAULT_ENABLED);
        assert_eq!(disabled, "");
    }

    #[test]
    fn every_built_in_profile_reports_the_same_lists() {
        for profile in [PROFILE_NULL, PROFILE_DEFAULT_V1, PROFILE_CUSTOM] {
            let (enabled, disabled) = runtime_algorithm_lists(profile.algorithms);
            assert_eq!(enabled, DEFAULT_ENABLED);
            assert_eq!(disabled, "");
        }
    }

    #[test]
    fn an_empty_profile_is_the_pre_init_state() {
        let (enabled, disabled) = lists("");
        assert_eq!(enabled, "");
        assert_eq!(
            disabled,
            "rsa,tdes,sha1,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,\
rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,\
ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,\
ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,symcipher,camellia,cmac,ctr,ofb,cbc,cfb,ecb",
            "nothing is enabled and no minimum key size is reported"
        );
    }

    #[test]
    fn a_profile_with_only_tdes_removed_disables_exactly_tdes() {
        let (enabled, disabled) = lists(&swtpm_setup_profile(&["tdes"]));
        assert_eq!(disabled, "tdes");
        assert_eq!(
            enabled,
            "rsa,rsa-min-size=1024,sha1,hmac,hmac-min-key-size=1,aes,aes-min-size=128,mgf1,\
keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,\
ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,ecc-bn,ecc-nist-p192,\
ecc-nist-p224,ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,\
symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb",
            "the surviving tdes-min-size= entry never brings tdes back"
        );
    }

    #[test]
    fn the_progressive_disable_sequence_matches_the_oracle() {
        for step in 1..=CAN_BE_DISABLED.len() {
            let removed = &CAN_BE_DISABLED[..step];
            let (_, disabled) = lists(&swtpm_setup_profile(removed));
            assert_eq!(disabled, removed.join(","), "after {step} removals");
        }
    }

    #[test]
    fn algorithms_and_curves_that_cannot_be_disabled_always_stay_enabled() {
        let (enabled, _) = lists(&swtpm_setup_profile(&CAN_BE_DISABLED));
        assert_eq!(
            enabled,
            "rsa,rsa-min-size=1024,hmac,hmac-min-key-size=1,aes,aes-min-size=128,mgf1,keyedhash,\
xor,sha256,sha384,null,oaep,ecdsa,ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,\
ecc-nist-p256,ecc-nist-p384,symcipher,cfb"
        );
        for entry in ALGORITHMS.iter().filter(|entry| !entry.can_be_disabled) {
            let name = core::str::from_utf8(entry.name).unwrap();
            assert!(
                enabled.split(',').any(|token| token == name),
                "{name} must stay enabled"
            );
        }
        for curve in ECC_CURVES.iter().filter(|curve| !curve.can_be_disabled) {
            let name = core::str::from_utf8(curve.name).unwrap();
            assert!(
                enabled.split(',').any(|token| token == name),
                "{name} must stay enabled"
            );
        }
    }

    #[test]
    fn omitted_minimum_size_entries_fall_back_to_the_build_minimums() {
        let (enabled, disabled) = lists(
            "rsa,tdes,sha1,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,\
rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,\
ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,cmac,ctr,ofb,cbc,cfb,ecb",
        );
        assert_eq!(disabled, "");
        assert_eq!(
            enabled,
            "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,aes-min-size=128,mgf1,\
keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,\
ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,\
ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,symcipher,\
camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb"
        );
    }

    #[test]
    fn raised_minimum_sizes_are_reported_and_filter_the_curves() {
        let (enabled, disabled) = lists(
            "rsa,rsa-min-size=2048,tdes,tdes-min-size=192,sha1,hmac,hmac-min-key-size=16,aes,\
aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,\
ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=256,ecc-nist,\
ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=256,cmac,ctr,ofb,cbc,cfb,ecb",
        );
        assert_eq!(
            enabled,
            "rsa,rsa-min-size=2048,tdes,tdes-min-size=192,sha1,hmac,hmac-min-key-size=16,aes,\
aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,\
ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=256,ecc-nist,\
ecc-bn,ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,symcipher,\
camellia,camellia-min-size=256,cmac,ctr,ofb,cbc,cfb,ecb"
        );
        assert_eq!(
            disabled, "ecc-nist-p192,ecc-nist-p224",
            "the mandatory 256 and 384 bit curves survive the minimum"
        );
    }

    #[test]
    fn curves_named_individually_leave_the_shortcuts_disabled() {
        let (enabled, disabled) = lists(
            "rsa,tdes,sha1,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,\
rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,\
ecc-nist-p256,ecc-nist-p384,symcipher,camellia,cmac,ctr,ofb,cbc,cfb,ecb",
        );
        assert!(enabled.contains("kdf1-sp800-108,ecc,ecc-nist-p256,ecc-nist-p384,symcipher"));
        assert_eq!(
            disabled,
            "ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,\
ecc-sm2-p256",
            "the shortcuts lead the curves, as upstream prints them"
        );
    }

    #[test]
    fn a_shortcut_enables_every_curve_it_covers() {
        let (enabled, disabled) = lists("ecc,ecc-nist");
        assert_eq!(
            enabled,
            "ecc,ecc-nist,ecc-nist-p192,ecc-nist-p224,ecc-nist-p256,ecc-nist-p384,ecc-nist-p521"
        );
        assert!(disabled.contains("ecc-bn,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256"));
    }

    #[test]
    fn the_two_lists_partition_every_reported_name() {
        for profile in [
            core::str::from_utf8(DEFAULT_ALGORITHMS_PROFILE).unwrap(),
            "",
            &swtpm_setup_profile(&["tdes", "sha1", "camellia"]),
        ] {
            let (enabled, disabled) = lists(profile);
            let names = |list: &str| -> Vec<String> {
                list.split(',')
                    .filter(|token| !token.is_empty() && !token.contains('='))
                    .map(str::to_string)
                    .collect()
            };
            let mut all = names(&enabled);
            all.extend(names(&disabled));
            all.sort_unstable();
            let mut expected: Vec<String> = ALGORITHMS
                .iter()
                .map(|entry| core::str::from_utf8(entry.name).unwrap().to_string())
                .chain(
                    ECC_SHORTCUTS
                        .iter()
                        .map(|&(name, _)| core::str::from_utf8(name).unwrap().to_string()),
                )
                .chain(
                    ECC_CURVES
                        .iter()
                        .map(|curve| core::str::from_utf8(curve.name).unwrap().to_string()),
                )
                .collect();
            expected.sort_unstable();
            assert_eq!(all, expected, "profile {profile:?}");
        }
    }

    #[test]
    fn the_lists_are_stable_across_repeated_calls() {
        let profile = swtpm_setup_profile(&["tdes", "ecc-nist"]);
        let first = lists(&profile);
        for _ in 0..4 {
            assert_eq!(lists(&profile), first);
        }
    }

    #[test]
    fn an_unparsable_minimum_size_never_panics() {
        for profile in [
            "rsa-min-size=",
            "rsa-min-size=abc",
            "rsa-min-size=99999999999999999999",
            "hmac-min-key-size=",
            "ecc-min-size=x",
            ",,,",
            "ecc-nist-",
            "rsa,rsa",
        ] {
            let _ = lists(profile);
        }
    }
}
