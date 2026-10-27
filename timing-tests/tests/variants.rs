use tpms_timing_tests::oracle::hash::HashAlg;
use tpms_timing_tests::oracle::rsa::RsaBits;
use tpms_timing_tests::oracle::sym::{SymKey, SymMode};
use tpms_timing_tests::scenario::{Direction, PreparedPair, RsaPadding, Scenario, scenario_seeds};

#[test]
fn mac_sequence_and_partial_symmetric_and_wide_oaep_scenarios_prepare_seed_pairs() {
    let mut scenarios = Vec::new();
    for hash in HashAlg::ALL {
        scenarios.push(Scenario::HmacSequence(hash));
    }
    for key in SymKey::ALL {
        scenarios.push(Scenario::CmacSequence(key));
        for mode in SymMode::ALL {
            for direction in Direction::ALL {
                scenarios.push(Scenario::SymPartial(key, mode, direction));
            }
        }
    }
    for bits in RsaBits::ALL {
        for padding in [RsaPadding::OaepSha384, RsaPadding::OaepSha512] {
            if bits.bytes() >= 2 * padding.oaep_hash().unwrap().size() + 2 {
                scenarios.push(Scenario::RsaDecrypt(bits, padding));
            }
        }
    }
    assert!(!scenarios.is_empty());
    for scenario in &scenarios {
        let seeds = scenario_seeds(*scenario, 7, 1);
        assert!(!seeds.is_empty(), "{}: no seeds", scenario.name());
        for seed in seeds {
            // try_prepare validates both classes and both load orders.
            PreparedPair::try_prepare(*scenario, seed.pair)
                .unwrap_or_else(|e| panic!("{}: seed {}: {e}", scenario.name(), seed.name));
        }
    }
    assert!(Scenario::parse("rsa-decrypt-1024-oaep-sha512").is_err());
}

#[test]
fn rsaes_malformed_inputs_are_available_for_independent_backend_resolution() {
    let scenario = Scenario::parse("rsa-decrypt-1024-rsaes").unwrap();
    let mut pair = scenario_seeds(scenario, 7, 0).remove(0).pair;
    pair.a[0] = 1;
    assert!(PreparedPair::try_prepare(scenario, pair).is_ok());
}
