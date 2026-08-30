use super::super::crypto::compiled_curves;
use super::super::persistent::OwnedPersistentState;
use super::super::public::StateFormatLimit;
use super::super::template::AlgorithmPolicy;
use super::{CapabilityPage, MAX_CAP_DATA, paginate};

const SIZEOF_TPM_ECC_CURVE: usize = 2;
const MAX_ECC_CURVES: usize = MAX_CAP_DATA / SIZEOF_TPM_ECC_CURVE;

fn policy(state: &OwnedPersistentState) -> AlgorithmPolicy<'_> {
    AlgorithmPolicy {
        profile_algorithms: &state.profile.algorithms,
        state_format: StateFormatLimit::new(state.profile.state_format_level),
    }
}

pub(in crate::library::tpm2) fn is_usable(state: &OwnedPersistentState, curve_id: u16) -> bool {
    policy(state).curve_allowed(curve_id)
}

pub(in crate::library::tpm2) fn collect(
    state: &OwnedPersistentState,
    starting_curve: u32,
    requested_count: u32,
) -> CapabilityPage<u16> {
    paginate(
        compiled_curves()
            .filter(|&curve| u32::from(curve) >= starting_curve && is_usable(state, curve)),
        requested_count,
        MAX_ECC_CURVES,
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_runtime::{started, started_with_algorithms};
    use super::*;

    const P192: u16 = 0x0001;
    const P224: u16 = 0x0002;
    const P256: u16 = 0x0003;
    const P384: u16 = 0x0004;
    const P521: u16 = 0x0005;
    const BN_P256: u16 = 0x0010;
    const BN_P638: u16 = 0x0011;
    const SM2_P256: u16 = 0x0020;

    const DEFAULT_CURVES: [u16; 8] = [P192, P224, P256, P384, P521, BN_P256, BN_P638, SM2_P256];

    #[test]
    fn capacity_vendored_structure_size_match() {
        assert_eq!(MAX_ECC_CURVES, 508);
    }

    #[test]
    fn complete_page_vendored_array_order() {
        let runtime = started();
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, 0, 1000);
        assert_eq!(page.entries, DEFAULT_CURVES);
        assert!(!page.more_data);
    }

    #[test]
    fn starting_curve_inclusive_boundary() {
        let runtime = started();
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, u32::from(P384), 1000);
        assert_eq!(page.entries, [P384, P521, BN_P256, BN_P638, SM2_P256]);
        assert!(!page.more_data);

        let page = collect(state, u32::from(P384) + 1, 1000);
        assert_eq!(page.entries, [P521, BN_P256, BN_P638, SM2_P256]);
        assert!(!page.more_data);
    }

    #[test]
    fn start_past_last_curve_empty_page() {
        let runtime = started();
        let state = runtime.state.as_ref().expect("decoded state");
        for start in [u32::from(SM2_P256) + 1, 0x0000_ffff, u32::MAX] {
            let page = collect(state, start, 1000);
            assert!(page.entries.is_empty(), "{start:#x}");
            assert!(!page.more_data, "{start:#x}");
        }
    }

    #[test]
    fn zero_count_more_data_remainder_dependence() {
        let runtime = started();
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, 0, 0);
        assert!(page.entries.is_empty());
        assert!(page.more_data);

        let page = collect(state, u32::from(SM2_P256) + 1, 0);
        assert!(page.entries.is_empty());
        assert!(!page.more_data);
    }

    #[test]
    fn requested_count_page_truncation() {
        let runtime = started();
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, 0, 2);
        assert_eq!(page.entries, [P192, P224]);
        assert!(page.more_data);

        let page = collect(state, 0, DEFAULT_CURVES.len() as u32);
        assert_eq!(page.entries.len(), DEFAULT_CURVES.len());
        assert!(!page.more_data);
    }

    const ALL_ALGORITHMS: &str = "rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,\
aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,\
ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,\
ecc-bn,ecc-sm2-p256,symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb";

    fn algorithms_with(replacements: &[(&str, &str)]) -> String {
        ALL_ALGORITHMS
            .split(',')
            .filter_map(
                |token| match replacements.iter().find(|(from, _)| *from == token) {
                    Some((_, "")) => None,
                    Some((_, to)) => Some((*to).to_string()),
                    None => Some(token.to_string()),
                },
            )
            .collect::<Vec<_>>()
            .join(",")
    }

    #[test]
    fn profile_disabled_curve_omission() {
        let runtime = started_with_algorithms(&algorithms_with(&[
            ("ecc-nist", "ecc-nist-p192,ecc-nist-p256,ecc-nist-p384"),
            ("ecc-bn", ""),
        ]));
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, 0, 1000);
        assert_eq!(page.entries, [P192, P256, P384, SM2_P256]);
        assert!(!page.more_data);
        assert!(is_usable(state, P256));
        assert!(!is_usable(state, P224));
        assert!(!is_usable(state, BN_P256));
    }

    #[test]
    fn profile_minimum_key_size_small_curve_omission() {
        let runtime = started_with_algorithms(&algorithms_with(&[(
            "ecc-min-size=192",
            "ecc-min-size=256",
        )]));
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, 0, 1000);
        assert_eq!(page.entries, [P256, P384, P521, BN_P256, BN_P638, SM2_P256]);
        assert!(!page.more_data);
    }

    #[test]
    fn disabled_start_curve_omission() {
        let runtime = started_with_algorithms(&algorithms_with(&[
            ("ecc-nist", "ecc-nist-p256,ecc-nist-p384"),
            ("ecc-bn", ""),
        ]));
        let state = runtime.state.as_ref().expect("decoded state");
        let page = collect(state, u32::from(P192), 1000);
        assert_eq!(page.entries, [P256, P384, SM2_P256]);
        assert!(!page.more_data);
    }
}
