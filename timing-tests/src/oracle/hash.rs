use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

macro_rules! with_hash {
    ($alg:expr, $h:ident => $body:expr) => {
        match $alg {
            HashAlg::Sha1 => {
                type $h = Sha1;
                $body
            }
            HashAlg::Sha256 => {
                type $h = Sha256;
                $body
            }
            HashAlg::Sha384 => {
                type $h = Sha384;
                $body
            }
            HashAlg::Sha512 => {
                type $h = Sha512;
                $body
            }
        }
    };
}

impl HashAlg {
    pub const ALL: [HashAlg; 4] = [Self::Sha1, Self::Sha256, Self::Sha384, Self::Sha512];

    pub fn alg_id(self) -> u16 {
        match self {
            Self::Sha1 => 0x0004,
            Self::Sha256 => 0x000b,
            Self::Sha384 => 0x000c,
            Self::Sha512 => 0x000d,
        }
    }

    pub fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn block_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256 => 64,
            Self::Sha384 | Self::Sha512 => 128,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    pub fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        with_hash!(self, H => {
            let mut h = H::new();
            for part in parts {
                h.update(part);
            }
            h.finalize().to_vec()
        })
    }

    pub fn hmac(self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        with_hash!(self, H => {
            let mut mac = <Hmac<H> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            for part in parts {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        assert_eq!(
            hex::encode(HashAlg::Sha256.digest(&[b"ab", b"c"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(HashAlg::Sha1.digest(&[b"abc"])),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(
                HashAlg::Sha256.hmac(b"key", &[b"The quick brown fox jumps over the lazy dog"])
            ),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}
