use crate::types::TpmlibInfoFlags;

use super::profile;

const INFO_TPMSPECIFICATION: u32 = 1;
const INFO_TPMATTRIBUTES: u32 = 2;
const INFO_TPMFEATURES: u32 = 4;
const INFO_RUNTIME_ALGORITHMS: u32 = 8;
const INFO_RUNTIME_COMMANDS: u32 = 16;
const INFO_ACTIVE_PROFILE: u32 = 32;
const INFO_AVAILABLE_PROFILES: u32 = 64;
const INFO_RUNTIME_ATTRIBUTES: u32 = 128;

const TPM_SPECIFICATION: &str = r#""TPMSpecification":{"family":"2.0","level":0,"revision":183}"#;

const TPM_ATTRIBUTES: &str = concat!(
    r#""TPMAttributes":{"manufacturer":"id:00001014","#,
    r#""version":"id:20240125","model":"swtpm"}"#
);

const TPM_FEATURES: &str = concat!(
    r#""TPMFeatures":{"RSAKeySizes":[1024,2048,3072],"#,
    r#""CamelliaKeySizes":[128,192,256]}"#
);

const ALGORITHMS_IMPLEMENTED: &str = concat!(
    r#"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,hmac-min-key-size=1,"#,
    r#"aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,"#,
    r#"rsapss,oaep,ecdsa,ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,"#,
    r#"kdf1-sp800-108,ecc,ecc-min-size=192,ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,"#,
    r#"ecc-nist-p256,ecc-nist-p384,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,"#,
    r#"symcipher,camellia,camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb"#
);

const ALGORITHMS_CAN_BE_DISABLED: &str = concat!(
    r#"tdes,sha1,sha512,rsassa,rsaes,rsapss,ecdaa,sm2,ecschnorr,ecmqv,"#,
    r#"ecc-nist,ecc-bn,ecc-nist-p192,ecc-nist-p224,ecc-nist-p521,ecc-bn-p256,"#,
    r#"ecc-bn-p638,ecc-sm2-p256,camellia,cmac,ctr,ofb,cbc,ecb"#
);

fn runtime_algorithms(active_algorithms: Option<&[u8]>) -> String {
    let (enabled, disabled) = profile::runtime_algorithm_lists(active_algorithms.unwrap_or(b""));
    let mut out = String::from(r#""RuntimeAlgorithms":{"Implemented":""#);
    out.push_str(ALGORITHMS_IMPLEMENTED);
    out.push_str(r#"","CanBeDisabled":""#);
    out.push_str(ALGORITHMS_CAN_BE_DISABLED);
    out.push_str(r#"","Enabled":""#);
    out.push_str(&enabled);
    out.push_str(r#"","Disabled":""#);
    out.push_str(&disabled);
    out.push_str(r#""}"#);
    out
}

const RUNTIME_COMMANDS: &str = concat!(
    r#""RuntimeCommands":{"Implemented":"0x11f-0x122,0x124-0x12e,0x130-0x140,"#,
    r#"0x142-0x159,0x15b-0x15e,0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,"#,
    r#"0x199-0x19c","#,
    r#""CanBeDisabled":"0x11f,0x121-0x122,0x124-0x128,0x12a,0x12c-0x12e,0x130,"#,
    r#"0x132-0x13b,0x13d-0x140,0x142,0x146-0x147,0x149-0x14d,0x14f-0x152,0x154-0x155,"#,
    r#"0x159,0x15b,0x15d-0x15e,0x160-0x164,0x167-0x168,0x16a-0x172,0x174,0x177-0x178,"#,
    r#"0x17b,0x17f-0x181,0x183-0x184,0x187-0x193,0x197,0x199-0x19c","#,
    r#""Enabled":"","#,
    r#""Disabled":"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,"#,
    r#"0x160-0x165,0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c"}"#
);

const RUNTIME_ATTRIBUTES: &str = concat!(
    r#""RuntimeAttributes":{"Implemented":"no-unpadded-encryption,no-sha1-signing,"#,
    r#"no-sha1-verification,no-sha1-hmac-creation,no-sha1-hmac-verification,"#,
    r#"no-sha1-hmac,fips-host,drbg-continous-test,pct,no-ecc-key-derivation","#,
    r#""CanBeDisabled":"no-unpadded-encryption,no-sha1-signing,no-sha1-verification,"#,
    r#"no-sha1-hmac-creation,no-sha1-hmac-verification,no-sha1-hmac,fips-host,"#,
    r#"drbg-continous-test,pct,no-ecc-key-derivation","#,
    r#""Enabled":"","#,
    r#""Disabled":"no-unpadded-encryption,no-sha1-signing,no-sha1-verification,"#,
    r#"no-sha1-hmac-creation,no-sha1-hmac-verification,no-sha1-hmac,fips-host,"#,
    r#"drbg-continous-test,pct,no-ecc-key-derivation"}"#
);

const AVAILABLE_PROFILES: &str = concat!(
    r#""AvailableProfiles":[{"Name":"default-v1","StateFormatLevel":7,"Commands":""#,
    r#"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,"#,
    r#"0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c"#,
    r#"","Algorithms":""#,
    r#"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,aes-min-size=128,"#,
    r#"mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,"#,
    r#"ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,"#,
    r#"ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"#,
    r#"camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb"#,
    r#"","Description":"This profile enables all libtpms v0.10-supported commands "#,
    r#"and algorithms. This profile is compatible with libtpms >= v0.10."},"#,
    r#"{"Name":"null","StateFormatLevel":1,"Commands":""#,
    r#"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,"#,
    r#"0x167-0x174,0x176-0x178,0x17a-0x193,0x197"#,
    r#"","Algorithms":""#,
    r#"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,aes-min-size=128,"#,
    r#"mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,"#,
    r#"ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,"#,
    r#"ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"#,
    r#"camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb"#,
    r#"","Description":"The profile enables the commands and algorithms that were "#,
    r#"enabled in libtpms v0.9. This profile is automatically used when the state "#,
    r#"does not have a profile, for example when it was created by libtpms v0.9 or "#,
    r#"before. This profile enables compatibility with libtpms >= v0.9."},"#,
    r#"{"Name":"custom","StateFormatLevel":2,"Commands":""#,
    r#"0x11f-0x122,0x124-0x12e,0x130-0x140,0x142-0x159,0x15b-0x15e,0x160-0x165,"#,
    r#"0x167-0x174,0x176-0x178,0x17a-0x193,0x197,0x199-0x19c"#,
    r#"","Algorithms":""#,
    r#"rsa,rsa-min-size=1024,tdes,tdes-min-size=128,sha1,hmac,aes,aes-min-size=128,"#,
    r#"mgf1,keyedhash,xor,sha256,sha384,sha512,null,rsassa,rsaes,rsapss,oaep,ecdsa,"#,
    r#"ecdh,ecdaa,sm2,ecschnorr,ecmqv,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,"#,
    r#"ecc-min-size=192,ecc-nist,ecc-bn,ecc-sm2-p256,symcipher,camellia,"#,
    r#"camellia-min-size=128,cmac,ctr,ofb,cbc,cfb,ecb"#,
    r#"","Description":"This profile allows customization of enabled algorithms "#,
    r#"and commands. This profile requires at least libtpms v0.10."}]"#
);

pub fn get_info(
    flags: TpmlibInfoFlags,
    active_profile: Option<&str>,
    active_algorithms: Option<&[u8]>,
) -> String {
    let flags = flags as u32;
    let active = active_profile.map(|json| format!("\"ActiveProfile\":{json}"));
    let algorithms = runtime_algorithms(active_algorithms);
    let selected: [(u32, Option<&str>); 8] = [
        (INFO_TPMSPECIFICATION, Some(TPM_SPECIFICATION)),
        (INFO_TPMATTRIBUTES, Some(TPM_ATTRIBUTES)),
        (INFO_TPMFEATURES, Some(TPM_FEATURES)),
        (INFO_RUNTIME_ALGORITHMS, Some(algorithms.as_str())),
        (INFO_RUNTIME_COMMANDS, Some(RUNTIME_COMMANDS)),
        (INFO_RUNTIME_ATTRIBUTES, Some(RUNTIME_ATTRIBUTES)),
        (INFO_ACTIVE_PROFILE, active.as_deref()),
        (INFO_AVAILABLE_PROFILES, Some(AVAILABLE_PROFILES)),
    ];
    let sections: Vec<&str> = selected
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .filter_map(|&(_, section)| section)
        .collect();
    format!("{{{}}}", sections.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_info_string(flags: u32) -> String {
        get_info(flags as TpmlibInfoFlags, None, None)
    }

    #[test]
    fn no_flags_yields_empty_object() {
        assert_eq!(get_info_string(0), "{}");
    }

    #[test]
    fn unknown_flags_are_ignored() {
        assert_eq!(get_info_string(1 << 20), "{}");
    }

    #[test]
    fn active_profile_is_omitted_before_main_init() {
        assert_eq!(get_info_string(INFO_ACTIVE_PROFILE), "{}");
        assert_eq!(
            get_info_string(INFO_TPMSPECIFICATION | INFO_ACTIVE_PROFILE),
            get_info_string(INFO_TPMSPECIFICATION),
        );
    }

    #[test]
    fn active_profile_is_reported_after_main_init() {
        const PROFILE: &str = r#"{"Name":"null","StateFormatLevel":1}"#;
        assert_eq!(
            get_info(INFO_ACTIVE_PROFILE as TpmlibInfoFlags, Some(PROFILE), None),
            r#"{"ActiveProfile":{"Name":"null","StateFormatLevel":1}}"#
        );
        let all = get_info(255 as TpmlibInfoFlags, Some(PROFILE), None);
        let attrs = all.find("RuntimeAttributes").unwrap();
        let active = all.find("ActiveProfile").unwrap();
        let available = all.find("AvailableProfiles").unwrap();
        assert!(attrs < active && active < available);
    }

    #[test]
    fn tpmspecification_matches_reference() {
        assert_eq!(
            get_info_string(INFO_TPMSPECIFICATION),
            r#"{"TPMSpecification":{"family":"2.0","level":0,"revision":183}}"#
        );
    }

    #[test]
    fn sections_use_c_emission_order() {
        let all = get_info_string(255);
        let order = [
            "TPMSpecification",
            "TPMAttributes",
            "TPMFeatures",
            "RuntimeAlgorithms",
            "RuntimeCommands",
            "RuntimeAttributes",
            "AvailableProfiles",
        ];
        let positions: Vec<usize> = order
            .iter()
            .map(|section| all.find(section).expect(section))
            .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}");
    }

    #[test]
    fn profile_names_are_listed_in_table_order() {
        let profiles = get_info_string(INFO_AVAILABLE_PROFILES);
        let default_pos = profiles.find(r#""Name":"default-v1""#).unwrap();
        let null_pos = profiles.find(r#""Name":"null""#).unwrap();
        let custom_pos = profiles.find(r#""Name":"custom""#).unwrap();
        assert!(default_pos < null_pos && null_pos < custom_pos);
    }

    #[test]
    fn runtime_sections_report_pre_init_state() {
        let algos = get_info_string(INFO_RUNTIME_ALGORITHMS);
        assert!(algos.contains(r#""Enabled":"""#));
        assert!(algos.contains(r#""Implemented":"rsa,rsa-min-size=1024,"#));
        let cmds = get_info_string(INFO_RUNTIME_COMMANDS);
        assert!(cmds.contains(r#""Implemented":"0x11f-0x122,"#));
    }
}

#[cfg(test)]
mod runtime_algorithms_tests {
    use super::*;
    use crate::library::tpm2::profile::DEFAULT_ALGORITHMS_PROFILE;

    #[track_caller]
    fn field<'a>(info: &'a str, key: &str) -> &'a str {
        let opening = format!("\"{key}\":\"");
        let start = info.find(&opening).expect(key) + opening.len();
        let len = info[start..].find('"').expect("a closing quote");
        &info[start..start + len]
    }

    fn section(profile: Option<&[u8]>) -> String {
        get_info(INFO_RUNTIME_ALGORITHMS as TpmlibInfoFlags, None, profile)
    }

    const REDUCED: &[u8] = b"rsa,hmac,aes,mgf1,keyedhash,xor,sha256,sha384,null,oaep,ecdsa,\
ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-nist-p256,ecc-nist-p384,symcipher,cfb";

    #[test]
    fn the_implemented_and_can_be_disabled_lists_are_profile_independent() {
        let pre_init = section(None);
        for profile in [DEFAULT_ALGORITHMS_PROFILE, REDUCED] {
            let info = section(Some(profile));
            assert_eq!(field(&info, "Implemented"), field(&pre_init, "Implemented"));
            assert_eq!(
                field(&info, "CanBeDisabled"),
                field(&pre_init, "CanBeDisabled")
            );
        }
    }

    #[test]
    fn the_section_reports_the_active_profile() {
        let info = section(Some(DEFAULT_ALGORITHMS_PROFILE));
        assert_eq!(field(&info, "Disabled"), "");
        assert!(field(&info, "Enabled").starts_with("rsa,rsa-min-size=1024,tdes,"));

        let info = section(Some(REDUCED));
        assert_eq!(
            field(&info, "Enabled"),
            "rsa,rsa-min-size=1024,hmac,aes,aes-min-size=128,mgf1,keyedhash,xor,sha256,sha384,\
null,oaep,ecdsa,ecdh,kdf1-sp800-56a,kdf2,kdf1-sp800-108,ecc,ecc-nist-p256,ecc-nist-p384,\
symcipher,cfb"
        );
        assert_eq!(
            field(&info, "Disabled"),
            "tdes,sha1,sha512,rsassa,rsaes,rsapss,ecdaa,sm2,ecschnorr,ecmqv,ecc-nist,ecc-bn,\
ecc-nist-p192,ecc-nist-p224,ecc-nist-p521,ecc-bn-p256,ecc-bn-p638,ecc-sm2-p256,camellia,cmac,\
ctr,ofb,cbc,ecb"
        );
    }

    #[test]
    fn a_profile_without_tdes_reports_exactly_tdes_as_disabled() {
        let profile: Vec<u8> = DEFAULT_ALGORITHMS_PROFILE
            .split(|&byte| byte == b',')
            .filter(|token| *token != b"tdes")
            .collect::<Vec<_>>()
            .join(&b","[..]);
        assert_eq!(field(&section(Some(&profile)), "Disabled"), "tdes");
    }

    #[test]
    fn a_profile_with_several_disabled_algorithms_lists_them_in_table_order() {
        let dropped: [&[u8]; 3] = [b"camellia", b"sha1", b"cbc"];
        let profile: Vec<u8> = DEFAULT_ALGORITHMS_PROFILE
            .split(|&byte| byte == b',')
            .filter(|token| !dropped.contains(token))
            .collect::<Vec<_>>()
            .join(&b","[..]);
        assert_eq!(
            field(&section(Some(&profile)), "Disabled"),
            "sha1,camellia,cbc",
            "the order follows the algorithm table, not the profile"
        );
    }

    #[test]
    fn the_section_keeps_its_key_order_and_stays_valid_json() {
        for profile in [None, Some(DEFAULT_ALGORITHMS_PROFILE), Some(REDUCED)] {
            let info = section(profile);
            assert!(info.starts_with("{\"RuntimeAlgorithms\":{\"Implemented\":\""));
            assert!(info.ends_with("\"}}"));
            let keys = ["Implemented", "CanBeDisabled", "Enabled", "Disabled"];
            let positions: Vec<usize> = keys
                .iter()
                .map(|key| info.find(&format!("\"{key}\"")).expect(key))
                .collect();
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(info.matches('{').count(), info.matches('}').count());
            assert_eq!(info.matches('"').count() % 2, 0);
            assert!(!info.contains(",,"), "no empty list entries");
        }
    }

    #[test]
    fn the_section_is_stable_across_calls() {
        let first = section(Some(REDUCED));
        for _ in 0..4 {
            assert_eq!(section(Some(REDUCED)), first);
        }
    }
}
