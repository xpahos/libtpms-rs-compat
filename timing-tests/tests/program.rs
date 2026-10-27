//! The C parser is exercised without dudect's x86 timer; live TPM proof is opt-in.
use std::{fs, path::PathBuf, process::Command, sync::OnceLock};
use tpms_timing_tests::{
    program::{CipherKey, Contract, Program, Step},
    tpm,
};

fn decoder() -> &'static PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("program-decoder-{}",std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let worker = tpms_timing_tests::worker::WORKER_SOURCE;
        let fragment = worker.split("/* Versioned bounded test-only programs.").nth(1).unwrap().split("static int created_resource").next().unwrap();
        let source = format!(r#"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#define MAX_COMMAND 4096
#define SLOT_SIZE 2048
#define TPM_SUCCESS 0
#define TPM_FAIL 9
#define BACKEND_TPM 1
typedef uint32_t TPM_RESULT;
static int g_kind=BACKEND_TPM;
static void *g_library;
static unsigned char *g_response;
static uint32_t g_response_capacity=4096;
static unsigned char raw[4096];
static uint32_t raw_len, calls;
static TPM_RESULT (*g_drbg_hook)(const unsigned char *,uint32_t,unsigned char *,uint32_t,uint32_t *);
static void fail(const char *message) {{
    printf("error %s calls=%u\n",message,calls);exit(3);
}}
static unsigned char g_caps[8][512];
static uint32_t g_cap_lens[8];
static uint32_t g_cap_n;
static int g_capture;
static TPM_RESULT fake_process(unsigned char **out,uint32_t *len,uint32_t *cap,unsigned char *in,uint32_t n) {{
    (void)cap;calls++;memcpy(*out,raw,raw_len);*len=raw_len;
    if (g_capture && n<=512 && g_cap_n<8) {{ memcpy(g_caps[g_cap_n],in,n); g_cap_lens[g_cap_n]=n; g_cap_n++; }}
    return 0;
}}
static TPM_RESULT (*g_process)(unsigned char **,uint32_t *,uint32_t *,unsigned char *,uint32_t)=fake_process;
/* Versioned bounded test-only programs.{fragment}
int main(int argc,char **argv) {{
    if(argc!=3)return 2;
    unsigned char command[4096];FILE *f=fopen(argv[1],"rb");if(!f)return 2;uint32_t n=fread(command,1,sizeof(command),f);fclose(f);
    f=fopen(argv[2],"rb");if(!f)return 2;raw_len=fread(raw,1,sizeof(raw),f);fclose(f);
    g_response=malloc(4096);struct program_step steps[8];memset(steps,0,sizeof(steps));uint32_t count=0;
    int valid=program_decode(command,n,steps,&count);
    if(valid) for(uint32_t k=0;k<n;k++) {{ memset(steps,0,sizeof(steps));if(program_decode(command,k,steps,&count))return 5; }}
    g_capture=1;g_cap_n=0;
    uint32_t len=0;TPM_RESULT rc=dispatch_command(command,n,&len);uint32_t first_calls=calls;
    printf("valid=%d rc=%08x length=%u poison=%d first_calls=%u ",valid,rc,len,g_poisoned,first_calls);
    unsigned char startup[12]={{0x80,1,0,0,0,12,0,0,1,0x44,0,0}};dispatch_command(startup,12,&len);
    printf("calls=%u\n",calls);
    printf("caps=%u",g_cap_n);
    for (uint32_t k=0;k<g_cap_n;k++) {{
        printf(" cap%u=",k);
        for (uint32_t j=0;j<g_cap_lens[k];j++) printf("%02x",g_caps[k][j]);
    }}
    printf("\n");
    g_capture=0;
        printf("calls=%u\n",calls);free(g_response);return 0;
}}
"#);
        let path=dir.join("decoder.c");fs::write(&path,source).unwrap();let bin=dir.join("decoder");
        let mut cc=Command::new("cc");cc.args(["-std=c11","-Wall","-Wextra","-Werror"]).arg(&path).arg("-o").arg(&bin);
        if cfg!(target_os="linux") { cc.arg("-ldl"); }
        let result=cc.output().unwrap();assert!(result.status.success(),"{}",String::from_utf8_lossy(&result.stderr));bin
    })
}
fn run_c_output(label: &str, bytes: &[u8], response: &[u8]) -> std::process::Output {
    let bin = decoder();
    let dir = bin.parent().unwrap();
    let input = dir.join(format!("{label}.program"));
    let raw = dir.join(format!("{label}.response"));
    fs::write(&input, bytes).unwrap();
    fs::write(&raw, response).unwrap();
    Command::new(bin).arg(input).arg(raw).output().unwrap()
}
/// Interpreter linked against the real OpenSSL HMAC, mirroring the live worker.
/// Builds only where libcrypto is available (the campaign host); skipped elsewhere.
fn decoder_crypto() -> Option<&'static PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("program-decoder-crypto-{}", std::process::id()));
        let base = decoder().parent().unwrap().join("decoder.c");
        let path = dir.join("decoder.c");
        let _ = fs::create_dir_all(&dir);
        fs::write(&path, fs::read_to_string(&base).unwrap()).unwrap();
        let bin = dir.join("decoder");
        let mut cc = Command::new("cc");
        cc.args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(&path)
            .arg("-o")
            .arg(&bin)
            // The interpreter resolves HMAC through dlsym, so libcrypto must stay in
            // DT_NEEDED even though no symbol is referenced directly; --as-needed
            // would drop it and kind 2/3 execution would fail.
            .args(["-Wl,--no-as-needed", "-lcrypto", "-Wl,--as-needed"]);
        if cfg!(target_os = "linux") {
            cc.arg("-ldl");
        }
        if cfg!(target_os = "macos") {
            return None;
        }
        let result = cc.output().unwrap();
        if !result.status.success() {
            eprintln!(
                "skipped crypto interpreter: no libcrypto ({})",
                String::from_utf8_lossy(&result.stderr)
            );
            return None;
        }
        bin.into()
    })
    .as_ref()
}
fn run_c(label: &str, bytes: &[u8], response: &[u8]) -> String {
    let result = run_c_output(label, bytes, response);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}
#[test]
fn c_dispatcher_rejects_missing_drbg_hook_without_tpm_fallback() {
    let result = run_c_output("missing-drbg-hook", b"\xffDR1", &[]);
    assert_eq!(result.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("error missing-drbg-timing-hook calls=0")
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("TPMS_TIMING_DRBG_v1 missing"));
    assert!(stderr.contains("--features timing-test-hooks"));
    assert!(stderr.contains("instrumented C reference build"));
}
#[test]
fn c_decoder_rejects_truncation_bounds_and_unknown_version_before_dispatch() {
    let response = tpm::success_response(&[], &[], 0);
    let p = Program {
        outcome_step: None,
        steps: vec![Step::new(
            tpm::startup_clear(),
            Contract::exact(response.clone(), 0),
        )],
    };
    let good = p.encode().unwrap().bytes;
    assert!(run_c("good", &good, &response).contains("valid=1 rc=00000000"));
    for (label, at, value) in [
        ("version", 4, 2),
        ("count", 5, 9),
        ("outcome", 8, 9),
        ("slot", 11, 255),
        ("handles", 13, 2),
        ("patches", 17, 17),
    ] {
        let mut bad = good.clone();
        bad[at] = value;
        assert!(Program::decode(&bad).is_err(), "{label}");
        let output = run_c(label, &bad, &response);
        assert!(
            output.contains("valid=0 rc=fffffffd length=0 poison=1 first_calls=0 calls=0"),
            "{label}: {output}"
        );
    }
}
#[test]
fn c_checks_every_actual_response_and_poison_prevents_the_next_dispatch() {
    let response = tpm::success_response(&[], &[], 0);
    let p = Program {
        outcome_step: None,
        steps: vec![Step::new(
            tpm::startup_clear(),
            Contract::exact(response.clone(), 0),
        )],
    };
    let good = p.encode().unwrap().bytes;
    for (label, at, value) in [("badtag", 1, 3), ("badlength", 5, 11), ("badcode", 9, 1)] {
        let mut bad = response.clone();
        bad[at] = value;
        let output = run_c(label, &good, &bad);
        assert!(
            output.contains("valid=1 rc=fffffffd length=10 poison=1 first_calls=1 calls=1"),
            "{label}: {output}"
        );
    }
}

fn mac_pair() -> tpms_timing_tests::scenario::PreparedPair {
    use tpms_timing_tests::{
        oracle::hash::HashAlg,
        program::{Patch, Resource, ResponseArea, ResponseRange},
        scenario::{self, Check, HandleRef, PreparedPair, Scenario},
    };
    let scenario = Scenario::Hmac(HashAlg::Sha256);
    let seed = scenario::scenario_seeds(scenario, 1, 0)
        .into_iter()
        .find(|s| s.name == "same-message-different-key")
        .unwrap();
    let mut prepared = PreparedPair::prepare(scenario, seed.pair);
    for class in 0..2 {
        let input = prepared.pair.class(class);
        let key = &input[..32];
        let message = &input[32..];
        let start = tpm::build_command(0x15b, &[0], &[&[]], &[0, 0, 0, 11]).bytes;
        let start_response = tpm::success_response(&[0], &[], 1);
        let mut contract = Contract::exact(start_response, 1);
        contract.mask[10..14].fill(0);
        let mut producer = Step::new(start, contract);
        producer.produces = Resource::Handle;
        let patch = Patch::Copy {
            at: 10,
            source: ResponseRange {
                step: 0,
                area: ResponseArea::Raw,
                offset: 10,
                len: 4,
            },
            xor: vec![0; 4],
        };
        let mut params = vec![];
        tpm::put_2b(&mut params, &message[..32]);
        let mut update = Step::new(
            tpm::build_command(0x15c, &[0], &[&[]], &params).bytes,
            Contract::exact(tpm::success_response(&[], &[], 1), 0),
        );
        update.patches.push(patch.clone());
        let mut params = vec![];
        tpm::put_2b(&mut params, &message[32..]);
        tpm::put_u32(&mut params, tpm::TPM_RH_NULL);
        let mut expected = vec![];
        tpm::put_2b(&mut expected, &HashAlg::Sha256.hmac(key, &[message]));
        expected.extend_from_slice(&[0x80, 0x24, 0x40, 0, 0, 7, 0, 0]);
        let mut complete = Step::new(
            tpm::build_command(0x13e, &[0], &[&[]], &params).bytes,
            Contract::exact(tpm::success_response(&[], &expected, 1), 0),
        );
        complete.patches.push(patch);
        complete.consumes.push(0);
        let program = Program {
            outcome_step: None,
            steps: vec![producer, update, complete],
        };
        let encoded = program.encode().unwrap();
        let (expected, mask) = program.expectation().unwrap();
        prepared.layout.measured[class] =
            scenario::Step::new("MAC_Start+SequenceUpdate+SequenceComplete", encoded.bytes)
                .handle_at(encoded.command_offsets[0] + 10, HandleRef::Class(0));
        prepared.classes[class].expected_response = expected;
        prepared.classes[class].mask = mask;
        prepared.classes[class].check = Some(Check::Program { program });
    }
    prepared
}

#[test]
fn mac_program_has_independent_complete_response_and_nested_handle_offset() {
    let p = mac_pair();
    for order in [
        tpms_timing_tests::measure::LoadOrder::ClassAFirst,
        tpms_timing_tests::measure::LoadOrder::ClassBFirst,
    ] {
        let resolved = p.resolve(order);
        for class in 0..2 {
            let decoded = Program::decode(&resolved.measured[class]).unwrap();
            assert_eq!(
                &decoded.steps[0].command[10..14],
                &resolved.class_handles[class].unwrap().to_be_bytes()
            );
            assert_eq!(decoded.steps.len(), 3);
        }
    }
}

#[test]
fn live_mac_sequence_repeats_beyond_capacity_and_failure_poison_is_immediate() {
    use tpms_timing_tests::{
        measure::{LoadOrder, Measurer, WorkerMeasurer},
        scenario::Check,
        worker::{BackendName, BackendSpec, Limits, WorkerProcess, build_worker},
    };
    let Some(library) = std::env::var_os("TPMS_TIMING_RUST_LIB") else {
        eprintln!("skipped native program proof: set TPMS_TIMING_RUST_LIB");
        return;
    };
    let work = PathBuf::from(
        std::env::var_os("TPMS_TIMING_WORK_DIR").unwrap_or_else(|| "../target/timing-tests".into()),
    );
    let include = PathBuf::from(
        std::env::var_os("TPMS_TIMING_INCLUDE").unwrap_or_else(|| "../libtpms/include".into()),
    );
    let binary = build_worker(&work, &include).unwrap();
    let backend = BackendSpec::Library {
        name: BackendName::Rust,
        path: library.into(),
    };
    let prepared = mac_pair();
    let mut worker = WorkerMeasurer::start(
        &binary.path,
        backend.clone(),
        None,
        &work.join("program-live.log"),
        Limits::default(),
    )
    .unwrap();
    for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
        let loaded = worker.load(&prepared, order).unwrap();
        tpms_timing_tests::search::functional_gate(&mut worker, &prepared, &loaded).unwrap();
        let measured = worker.measure(&loaded, 64, 8, 0x42).unwrap();
        assert_eq!(measured.class0.len(), 64);
        assert_eq!(measured.class1.len(), 64);
    }
    worker.close_checked().unwrap();
    // The same interpreter is used inside upstream dudect warmup and measurement.
    for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
        for bad in [false, true] {
            for warmup in [0, 2] {
                let resolved = prepared.resolve(order);
                let mut commands = resolved.measured;
                let mut expected = prepared.classes.clone().map(|c| c.expected_response);
                let mut masks = prepared.classes.clone().map(|c| c.mask);
                if bad {
                    for class in 0..2 {
                        let mut p = Program::decode(&commands[class]).unwrap();
                        p.steps[1].contract =
                            Contract::exact(tpm::success_response(&[], &[1], 1), 0);
                        p.steps[1].slot = p.steps[1].contract.max;
                        commands[class] = p.encode().unwrap().bytes;
                        (expected[class], masks[class]) = p.expectation().unwrap();
                    }
                }
                let mut setup = vec![tpm::startup_clear()];
                setup.extend(resolved.setup.into_iter().map(|s| s.command));
                let plan = tpms_timing_tests::worker::DudectPlan {
                    backend: backend.clone(),
                    cpu: None,
                    setup,
                    setup_patches: vec![],
                    class_commands: commands,
                    expected,
                    masks,
                    posts: [None, None],
                    patches: [vec![], vec![]],
                    warmup,
                    batch: 32,
                    budget: 64,
                    time_limit_s: 20.0,
                };
                let path = work.join(format!("program-dudect-{order:?}-{bad}-{warmup}.plan"));
                fs::write(&path, plan.render().unwrap()).unwrap();
                let output = Command::new(&binary.path)
                    .arg("dudect")
                    .arg(&path)
                    .output()
                    .unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    stdout.contains(if bad {
                        "status=functional-failure"
                    } else {
                        "status=insufficient-measurements"
                    }),
                    "{stdout}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
    live_hmac_patch(&binary.path, &backend, &work, &prepared);
    live_counter_failure(&binary.path, &backend, &work);
    live_context_and_event_sequence(&binary.path, &backend, &work, &prepared);

    // The Rust supervisor must also remember the interpreter poison, rather than retrying it.
    for functional in [true, false] {
        let mut bad = prepared.clone();
        for class in 0..2 {
            let Some(Check::Program { program }) = &mut bad.classes[class].check else {
                panic!("program check missing")
            };
            program.steps[1].contract = Contract::exact(tpm::success_response(&[], &[1], 1), 0);
            program.steps[1].slot = program.steps[1].contract.max;
            let encoded = program.encode().unwrap();
            bad.layout.measured[class].command = encoded.bytes;
            bad.layout.measured[class].handles[0].0 = encoded.command_offsets[0] + 10;
            (
                bad.classes[class].expected_response,
                bad.classes[class].mask,
            ) = program.expectation().unwrap();
        }
        let mut measurer = WorkerMeasurer::start(
            &binary.path,
            backend.clone(),
            None,
            &work.join(format!("program-supervisor-{functional}.log")),
            Limits::default(),
        )
        .unwrap();
        let loaded = measurer.load(&bad, LoadOrder::ClassAFirst).unwrap();
        if functional {
            assert!(measurer.execute_once(&loaded).is_err());
        } else {
            assert!(measurer.measure(&loaded, 8, 0, 42).is_err());
        }
        assert!(
            measurer.unrecovered().is_some(),
            "program poison must reach Rust supervisor"
        );
        assert!(measurer.load(&prepared, LoadOrder::ClassAFirst).is_err());
        measurer.close_checked().unwrap();
    }
    // A valid producer followed by an unexpected update response must poison all subsequent dispatch.
    for warmup in [0, 1] {
        let mut worker = WorkerProcess::spawn(
            &binary.path,
            &backend,
            None,
            &work.join(format!("program-failure-{warmup}.log")),
            Limits::default(),
        )
        .unwrap();
        let resolved = prepared.resolve(LoadOrder::ClassAFirst);
        assert_eq!(worker.exec(&tpm::startup_clear()).unwrap().0, 0);
        for setup in &resolved.setup {
            let (rc, response) = worker.exec(&setup.command).unwrap();
            assert_eq!(rc, 0);
            tpm::expect_success(&response).unwrap();
        }
        let mut bad = Program::decode(&resolved.measured[0]).unwrap();
        // The update actually succeeds, but the declared contract demands an extra parameter.
        bad.steps[1].contract = Contract::exact(tpm::success_response(&[], &[1], 1), 0);
        bad.steps[1].slot = bad.steps[1].contract.max;
        let bad_bytes = bad.encode().unwrap().bytes;
        let (expected, mask) = bad.expectation().unwrap();
        let reply = worker
            .measure(
                8,
                0x42,
                warmup,
                [&bad_bytes, &bad_bytes],
                [&expected, &expected],
                [&mask, &mask],
                [None, None],
            )
            .unwrap();
        assert!(matches!(
            reply,
            tpms_timing_tests::worker::MeasureReply::Mismatch {
                tpmlib_rc: 0xffff_fffd,
                ..
            }
        ));
        let (rc, response) = worker.exec(&tpm::startup_clear()).unwrap();
        assert_eq!(rc, 0xffff_fffd);
        assert!(response.is_empty());
        worker.close().unwrap();
    }
    // Final expected error is a legitimate outcome: the created sequence is flushed automatically.
    let mut worker = WorkerProcess::spawn(
        &binary.path,
        &backend,
        None,
        &work.join("program-expected-error.log"),
        Limits::default(),
    )
    .unwrap();
    let resolved = prepared.resolve(LoadOrder::ClassAFirst);
    assert_eq!(worker.exec(&tpm::startup_clear()).unwrap().0, 0);
    for setup in &resolved.setup {
        let (rc, response) = worker.exec(&setup.command).unwrap();
        assert_eq!(rc, 0);
        tpm::expect_success(&response).unwrap();
    }
    let mut expected_error = Program::decode(&resolved.measured[0]).unwrap();
    expected_error.steps.truncate(2);
    expected_error.steps[1].command[6..10].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    expected_error.steps[1].contract =
        Contract::exact(vec![0x80, 1, 0, 0, 0, 10, 0, 0, 1, 0x43], 0);
    expected_error.steps[1].slot = 10;
    let encoded = expected_error.encode().unwrap();
    for _ in 0..16 {
        let (rc, response) = worker.exec(&encoded.bytes).unwrap();
        assert_eq!(rc, 0);
        expected_error.transcript(&response).unwrap();
    }
    let (rc, response) = worker.exec(&resolved.measured[0]).unwrap();
    assert_eq!(rc, 0);
    if let Some(Check::Program { program }) = &prepared.classes[0].check {
        program.transcript(&response).unwrap();
    } else {
        panic!("program check missing")
    }
    worker.close().unwrap();
}

fn live_hmac_patch(
    binary: &std::path::Path,
    backend: &tpms_timing_tests::worker::BackendSpec,
    work: &std::path::Path,
    prepared: &tpms_timing_tests::scenario::PreparedPair,
) {
    use tpms_timing_tests::{
        measure::LoadOrder,
        oracle::hash::HashAlg,
        program::{Part, Patch, Resource, ResponseArea, ResponseRange},
        scenario::{Expect, family::cp_hash},
        worker::{Limits, WorkerProcess},
    };
    let hash = HashAlg::Sha256;
    let caller = vec![0x56; 32];
    let mut worker = WorkerProcess::spawn(
        binary,
        backend,
        None,
        &work.join("program-hmac-patch.log"),
        Limits::default(),
    )
    .unwrap();
    worker.exec(&tpm::startup_clear()).unwrap();
    let resolved = prepared.resolve(LoadOrder::ClassAFirst);
    let mut names = vec![];
    for setup in &resolved.setup {
        let (rc, response) = worker.exec(&setup.command).unwrap();
        assert_eq!(rc, 0);
        tpm::expect_success(&response).unwrap();
        names.push(
            tpm::read_2b(tpm::response_parameters(&response, 1).unwrap(), 0)
                .unwrap()
                .0
                .to_vec(),
        );
    }
    let mut prior_nonce = vec![];
    for invalid in [false, true] {
        for (class, name) in names.iter().enumerate() {
            let mut start_params = vec![];
            tpm::put_2b(&mut start_params, &caller);
            tpm::put_2b(&mut start_params, &[]);
            start_params.extend_from_slice(&[0, 0, 0x10, 0, 11]);
            let mut nonce = vec![];
            tpm::put_2b(&mut nonce, &[0; 32]);
            let mut contract = Contract::exact(tpm::success_response(&[0], &nonce, 0), 1);
            contract.mask[10..14].fill(0);
            contract.mask[16..48].fill(0);
            let mut start = Step::new(
                tpm::build_command(
                    0x176,
                    &[tpm::TPM_RH_NULL, tpm::TPM_RH_NULL],
                    &[],
                    &start_params,
                )
                .bytes,
                contract,
            );
            start.produces = Resource::Handle;
            let input = prepared.pair.class(class);
            let mut params = vec![];
            tpm::put_2b(&mut params, &input[32..]);
            tpm::put_u16(&mut params, tpm::TPM_ALG_NULL);
            let cp = cp_hash(hash, tpm::TPM_CC_MAC, &[name], &params);
            let mut session = vec![0; 4];
            tpm::put_2b(&mut session, &caller);
            session.push(1);
            tpm::put_2b(&mut session, &[0; 32]);
            let mut body = resolved.class_handles[class]
                .unwrap()
                .to_be_bytes()
                .to_vec();
            tpm::put_u32(&mut body, session.len() as u32);
            body.extend(session);
            body.extend(&params);
            let command = tpm::command(tpm::TPM_ST_SESSIONS, tpm::TPM_CC_MAC, &body);
            let mut expected_params = vec![];
            tpm::put_2b(
                &mut expected_params,
                &hash.hmac(&input[..32], &[&input[32..]]),
            );
            let mut expected = tpm::success_response(&[], &expected_params, 1);
            expected.truncate(expected.len() - 5);
            tpm::put_2b(&mut expected, &[0; 32]);
            expected.push(1);
            tpm::put_2b(&mut expected, &[0; 32]);
            let len = expected.len() as u32;
            expected[2..6].copy_from_slice(&len.to_be_bytes());
            let mut contract = Contract::exact(expected, 0);
            let auth = 14 + expected_params.len();
            contract.mask[auth + 2..auth + 34].fill(0);
            contract.mask[auth + 37..auth + 69].fill(0);
            if invalid {
                contract = Contract::exact(vec![0x80, 1, 0, 0, 0, 10, 0, 0, 9, 0xa2], 0);
            }
            let mut mac = Step::new(command, contract);
            mac.patches.push(Patch::Copy {
                at: 18,
                source: ResponseRange {
                    step: 0,
                    area: ResponseArea::Raw,
                    offset: 10,
                    len: 4,
                },
                xor: vec![0; 4],
            });
            let mut delta = vec![0; 32];
            if invalid {
                delta[31] = 1;
            }
            mac.patches.push(Patch::Hmac {
                at: 59,
                hash,
                key: vec![],
                parts: vec![
                    Part::Literal(cp),
                    Part::Literal(caller.clone()),
                    Part::Response(ResponseRange {
                        step: 0,
                        area: ResponseArea::Parameters,
                        offset: 2,
                        len: 32,
                    }),
                    Part::Literal(vec![1]),
                ],
                xor: delta,
            });
            let program = Program {
                outcome_step: None,
                steps: vec![start, mac],
            };
            let encoded = program.encode().unwrap();
            assert_eq!(Program::decode(&encoded.bytes).unwrap(), program);
            for _ in 0..16 {
                let (rc, response) = worker.exec(&encoded.bytes).unwrap();
                assert_eq!(rc, 0, "{}", hex::encode(&response));
                let frames = program.transcript(&response).unwrap();
                let nonce = tpm::response_parameters(frames[0], 1).unwrap()[2..].to_vec();
                assert_ne!(nonce, prior_nonce, "fresh nonceTPM must enter every HMAC");
                prior_nonce = nonce;
                if !invalid {
                    Expect::SessionAuthenticated {
                        key: vec![],
                        hash,
                        nonce_caller: caller.clone(),
                        command_code: tpm::TPM_CC_MAC,
                        parameters: expected_params.clone(),
                    }
                    .verify(frames[1])
                    .unwrap();
                }
            }
        }
    }
    worker.close().unwrap();
}

#[test]
fn bounded_session_program_rejects_missing_and_extra_response_authorizations() {
    let command = tpm::build_command(tpm::TPM_CC_MAC, &[0], &[&[]], &[0, 0, 0, 0x10]).bytes;
    let p = Program {
        outcome_step: None,
        steps: vec![Step::new(command, Contract::bounded(0, 10, 64))],
    };
    let encoded = p.encode().unwrap().bytes;
    let one = tpm::success_response(&[], &[], 1);
    assert!(run_c("bounded-auth-good", &encoded, &one).contains("valid=1 rc=00000000"));
    for count in [0, 2, 3] {
        let wrong = tpm::success_response(&[], &[], count);
        let output = run_c(&format!("bounded-auth-{count}"), &encoded, &wrong);
        assert!(
            output.contains("rc=fffffffd"),
            "bounded contract must reject wrong auth count {count}: {output}"
        );
        let mut transcript = tpm::success_response(&[], &[0; 6 + 4 + 64], 0);
        transcript[10..16].copy_from_slice(b"TPTR\x01\x01");
        transcript[16..18].copy_from_slice(&(wrong.len() as u16).to_be_bytes());
        transcript[18..20].copy_from_slice(&64u16.to_be_bytes());
        transcript[20..20 + wrong.len()].copy_from_slice(&wrong);
        assert!(
            p.transcript(&transcript).is_err(),
            "Rust bounded contract must reject auth count {count}"
        );
    }
}

fn live_counter_failure(
    binary: &std::path::Path,
    backend: &tpms_timing_tests::worker::BackendSpec,
    work: &std::path::Path,
) {
    use tpms_timing_tests::{
        program::{Patch, Resource, ResponseArea, ResponseRange},
        worker::{Limits, WorkerProcess},
    };
    let mut worker = WorkerProcess::spawn(
        binary,
        backend,
        None,
        &work.join("program-counter-failure.log"),
        Limits::default(),
    )
    .unwrap();
    worker.exec(&tpm::startup_clear()).unwrap();
    let mut producer = Step::new(
        tpm::build_command(0x18e, &[], &[], &[0, 3]).bytes,
        Contract::bounded(0, 12, 82),
    );
    producer.produces = Resource::Counter;
    // A structurally valid consumer carrying the real counter, but an absent key handle.
    let params = [0, 4, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0x19, 0, 0];
    let command = tpm::build_command(0x18d, &[0x8000_0000], &[&[]], &params);
    let mut consumer = Step::new(command.bytes, Contract::bounded(0, 19, 200));
    consumer.consumes.push(0);
    consumer.patches.push(Patch::Copy {
        at: (command.parameters_at + 14) as u16,
        source: ResponseRange {
            step: 0,
            area: ResponseArea::ParametersTail,
            offset: 0,
            len: 2,
        },
        xor: vec![0; 2],
    });
    let program = Program {
        outcome_step: None,
        steps: vec![producer, consumer],
    };
    let encoded = program.encode().unwrap();
    let (rc, response) = worker.exec(&encoded.bytes).unwrap();
    assert_eq!(rc, 0xffff_fffd);
    assert_ne!(
        tpm::response_code(&response).unwrap(),
        0,
        "preserve original failed consumer response"
    );
    let (rc, response) = worker.exec(&tpm::startup_clear()).unwrap();
    assert_eq!(rc, 0xffff_fffd);
    assert!(response.is_empty());
    worker.close().unwrap();
}

#[test]
fn review_all_allocating_commands_must_declare_handles() {
    let response = tpm::success_response(&[0x8000_0000], &[], 0);
    let p = Program::new(vec![Step::new(
        tpm::startup_clear(),
        Contract::exact(response.clone(), 1),
    )]);
    let encoded = p.encode().unwrap();
    for code in [0x161u32, 0x191] {
        let mut bytes = encoded.bytes.clone();
        let at = encoded.command_offsets[0] + 6;
        bytes[at..at + 4].copy_from_slice(&code.to_be_bytes());
        let output = run_c(&format!("untracked-{code:x}"), &bytes, &response);
        assert!(
            output.contains("valid=0 rc=fffffffd length=0 poison=1 first_calls=0 calls=0"),
            "untracked allocation was accepted: {output}"
        );
        assert!(Program::decode(&bytes).is_err());
    }
}

#[test]
fn review_event_sequence_consumer_uses_second_handle() {
    use tpms_timing_tests::program::{Patch, Resource, ResponseArea, ResponseRange};
    let response = tpm::success_response(&[0x8000_0000], &[], 0);
    let mut producer = Step::new(
        tpm::build_command(0x186, &[], &[], &[0, 0, 0, 0x10]).bytes,
        Contract::exact(response.clone(), 1),
    );
    producer.produces = Resource::Handle;
    let mut consumer = Step::new(
        tpm::build_command(0x185, &[tpm::TPM_RH_NULL, 0], &[], &[]).bytes,
        Contract::exact(response.clone(), 0),
    );
    consumer.consumes.push(0);
    consumer.patches.push(Patch::Copy {
        at: 14,
        source: ResponseRange {
            step: 0,
            area: ResponseArea::Raw,
            offset: 10,
            len: 4,
        },
        xor: vec![0; 4],
    });
    let p = Program::new(vec![producer, consumer]);
    let bytes = p.encode().unwrap().bytes;
    let output = run_c("second-handle-consumption", &bytes, &response);
    assert!(output.contains("valid=1 rc=00000000"), "{output}");
    assert!(output.contains("first_calls=2 calls=3"), "{output}");
}

fn live_context_and_event_sequence(
    binary: &std::path::Path,
    backend: &tpms_timing_tests::worker::BackendSpec,
    work: &std::path::Path,
    prepared: &tpms_timing_tests::scenario::PreparedPair,
) {
    use tpms_timing_tests::{
        measure::LoadOrder,
        oracle::hash::HashAlg,
        program::{Patch, Resource, ResponseArea, ResponseRange},
        worker::{Limits, WorkerProcess},
    };
    let mut worker = WorkerProcess::spawn(
        binary,
        backend,
        None,
        &work.join("program-context-event.log"),
        Limits::default(),
    )
    .unwrap();
    worker.exec(&tpm::startup_clear()).unwrap();
    let resolved = prepared.resolve(LoadOrder::ClassAFirst);
    for setup in &resolved.setup {
        let (rc, response) = worker.exec(&setup.command).unwrap();
        assert_eq!(rc, 0);
        tpm::expect_success(&response).unwrap();
    }
    let handle = resolved.class_handles[0].unwrap();
    let (rc, saved) = worker
        .exec(&tpm::build_command(0x162, &[handle], &[], &[]).bytes)
        .unwrap();
    assert_eq!(rc, 0);
    tpm::expect_success(&saved).unwrap();
    let context = tpm::response_parameters(&saved, 0).unwrap();
    let (rc, flushed) = worker.exec(&tpm::flush_context(handle)).unwrap();
    assert_eq!(rc, 0);
    tpm::expect_success(&flushed).unwrap();
    let mut contract = Contract::exact(tpm::success_response(&[0], &[], 0), 1);
    contract.mask[10..14].fill(0);
    let mut load = Step::new(
        tpm::build_command(0x161, &[], &[], context).bytes,
        contract.clone(),
    );
    load.produces = Resource::Handle;
    let program = Program::new(vec![load]);
    let encoded = program.encode().unwrap();
    for _ in 0..16 {
        let (rc, response) = worker.exec(&encoded.bytes).unwrap();
        assert_eq!(rc, 0, "{}", hex::encode(&response));
        program.transcript(&response).unwrap();
    }
    let mut start = Step::new(
        tpm::build_command(0x186, &[], &[], &[0, 0, 0, 0x10]).bytes,
        contract,
    );
    start.produces = Resource::Handle;
    let message = b"command program event sequence";
    let mut params = vec![];
    tpm::put_2b(&mut params, message);
    let mut digests = 4u32.to_be_bytes().to_vec();
    for hash in HashAlg::ALL {
        tpm::put_u16(&mut digests, hash.alg_id());
        digests.extend(hash.digest(&[message]));
    }
    let mut complete = Step::new(
        tpm::build_command(0x185, &[tpm::TPM_RH_NULL, 0], &[&[], &[]], &params).bytes,
        Contract::exact(tpm::success_response(&[], &digests, 2), 0),
    );
    complete.consumes.push(0);
    complete.patches.push(Patch::Copy {
        at: 14,
        source: ResponseRange {
            step: 0,
            area: ResponseArea::Raw,
            offset: 10,
            len: 4,
        },
        xor: vec![0; 4],
    });
    let program = Program::new(vec![start, complete]);
    let encoded = program.encode().unwrap();
    for _ in 0..16 {
        let (rc, response) = worker.exec(&encoded.bytes).unwrap();
        assert_eq!(rc, 0, "{}", hex::encode(&response));
        program.transcript(&response).unwrap();
    }
    worker.close().unwrap();
}

#[test]
fn c_ecdaa_response_contract_rejects_malformed_inner_signature() {
    let mut params = tpm::sized(&[7; 32]);
    params.extend_from_slice(&[0, 0x1a, 0, 0x0b, 0, 0]);
    params.extend_from_slice(&[0x80, 0x24, 0x40, 0, 0, 7, 0, 0]);
    let p = Program::new(vec![Step::new(
        tpm::build_command(0x15d, &[0x80000000], &[&[]], &params).bytes,
        Contract::bounded(0, 60, 91),
    )]);
    let encoded = p.encode().unwrap().bytes;
    let mut signature = vec![0, 0x1a, 0, 0x0b, 0, 1, 1, 0, 32];
    signature.extend([7; 32]);
    let good = tpm::success_response(&[], &signature, 1);
    assert!(run_c("ecdaa-good", &encoded, &good).contains("rc=00000000"));
    let mut bad_width = vec![0, 0x1a, 0, 0x0b, 0, 2, 1, 1, 0, 31];
    bad_width.extend([7; 31]);
    let bad_width = tpm::success_response(&[], &bad_width, 1);
    let output = run_c("ecdaa-wrong-s-width", &encoded, &bad_width);
    assert!(output.contains("rc=fffffffd"), "wrong s width: {output}");
    for (label, index) in [
        ("algorithm", 15),
        ("hash", 17),
        ("nonce-size", 19),
        ("s-size", 22),
    ] {
        let mut bad = good.clone();
        bad[index] ^= 1;
        let output = run_c(&format!("ecdaa-{label}"), &encoded, &bad);
        assert!(output.contains("rc=fffffffd"), "{label}: {output}");
    }
}

/// Exact replay contract with the fresh session nonce masked out so a
/// different nonceTPM in the replayed response stays acceptable.
fn fresh_nonce_contract(raw: &[u8], nonce_len: usize) -> Contract {
    let mut contract = Contract::exact(raw.to_vec(), 0);
    let start = raw.len() - nonce_len;
    for byte in &mut contract.mask[start..] {
        *byte = 0;
    }
    contract
}

fn session_hmac_program() -> (Program, Vec<u8>, Vec<u8>) {
    use tpms_timing_tests::oracle::hash::HashAlg;
    use tpms_timing_tests::oracle::kdf::kdfa;
    use tpms_timing_tests::program::{Part, Patch, ResponseArea, ResponseRange};
    let hash = HashAlg::Sha256;
    let caller = vec![0x56; 32];
    let kdf_key = vec![0x71; 24];
    let extra_key = vec![0x63; 32];
    let nonce_area = ResponseRange {
        step: 0,
        area: ResponseArea::Parameters,
        offset: 2,
        len: 32,
    };
    // Structural producer: any command works because the fake backend replays one response.
    let raw = tpm::success_response(&[], &tpm::sized(&[0x92; 32]), 0);
    let producer = Step::new(tpm::startup_clear(), fresh_nonce_contract(&raw, 32));
    let session_key = kdfa(hash, &kdf_key, b"ATH", &[0x92; 32], &caller, 256);
    // Independent layout check: one KDFa block is [1,"ATH\0",u,v,bits].
    assert_eq!(
        session_key,
        hash.hmac(
            &kdf_key,
            &[
                &1u32.to_be_bytes(),
                b"ATH\0",
                &[0x92; 32],
                &caller,
                &256u32.to_be_bytes(),
            ],
        )
    );
    let digest = hash.hmac(
        &[session_key.as_slice(), &extra_key].concat(),
        &[b"body", &caller, &[1]],
    );
    let mut command = tpm::startup_clear();
    command.resize(64, 0);
    command[2..6].copy_from_slice(&64u32.to_be_bytes());
    command[30..62].copy_from_slice(&digest);
    let mut mac = Step::new(command, fresh_nonce_contract(&raw, 32));
    mac.patches.push(Patch::SessionHmac {
        at: 30,
        hash,
        kdf_key,
        u_parts: vec![Part::Response(nonce_area)],
        v_parts: vec![Part::Literal(caller.clone())],
        extra_key,
        parts: vec![
            Part::Literal(b"body".to_vec()),
            Part::Literal(caller),
            Part::Literal(vec![1]),
        ],
        xor: vec![0; 32],
        cp_hash: None,
    });
    (
        Program {
            outcome_step: None,
            steps: vec![producer, mac],
        },
        raw,
        digest,
    )
}

#[test]
fn session_hmac_program_bytes_agree_between_implementations_under_mutation() {
    let (p, raw, _) = session_hmac_program();
    let good = p.encode().unwrap().bytes;
    for position in 0..good.len() {
        for value in [0x00u8, 0xff] {
            if good[position] == value {
                continue;
            }
            let mut bad = good.clone();
            bad[position] = value;
            let output = run_c_output(&format!("sh-agree-{position}-{value:x}"), &bad, &raw);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let c_valid = stdout.contains("valid=1");
            let rust_valid = Program::decode(&bad).is_ok();
            assert_eq!(
                c_valid, rust_valid,
                "position {position} value {value:02x}: C={rust_valid} disagrees"
            );
        }
    }
    let output = run_c("sh-agree-good", &good, &raw);
    assert!(output.contains("valid=1"), "{output}");
}

fn captured_hex(stdout: &str, index: usize) -> Vec<u8> {
    let marker = format!(" cap{index}=");
    let start = stdout
        .find(&marker)
        .unwrap_or_else(|| panic!("capture {index} missing: {stdout}"));
    let hex = &stdout[start + marker.len()..];
    let end = hex
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(hex.len());
    (0..end)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn encrypt_program(cfb: bool) -> (Program, Vec<u8>, Vec<u8>) {
    use tpms_timing_tests::oracle::{hash::HashAlg, kdf::kdfa, protection};
    use tpms_timing_tests::program::{Patch, ResponseArea, ResponseRange};
    let hash = HashAlg::Sha256;
    let caller = vec![0x57; 32];
    let plain: Vec<u8> = (0..35u8).collect();
    let nonce = vec![0x92; 32];
    let raw = tpm::success_response(&[], &tpm::sized(&nonce), 0);
    let producer = Step::new(
        tpm::startup_clear(),
        fresh_nonce_contract(&raw, nonce.len()),
    );
    let expected = if cfb {
        let material = kdfa(hash, &[], b"CFB", &caller, &nonce, 256);
        protection::cfb(&material[..16], &material[16..], &plain, true)
    } else {
        let mask = kdfa(hash, &[], b"XOR", &caller, &nonce, plain.len() * 8);
        plain.iter().zip(&mask).map(|(a, b)| a ^ b).collect()
    };
    let mut command = tpm::startup_clear();
    command.resize(96, 0);
    command[2..6].copy_from_slice(&96u32.to_be_bytes());
    let mut mac = Step::new(command, fresh_nonce_contract(&raw, nonce.len()));
    mac.patches.push(Patch::Encrypt {
        at: 30,
        hash,
        cfb,
        key: CipherKey::Fixed(vec![]),
        caller,
        nonce: ResponseRange {
            step: 0,
            area: ResponseArea::Parameters,
            offset: 2,
            len: 32,
        },
        plain: plain.clone(),
    });
    (
        Program {
            outcome_step: None,
            steps: vec![producer, mac],
        },
        raw,
        expected,
    )
}

#[test]
fn encrypt_patch_roundtrip_and_c_downstream_agreement() {
    for cfb in [false, true] {
        let (p, raw, expected) = encrypt_program(cfb);
        let good = p.encode().unwrap().bytes;
        assert!(Program::decode(&good).unwrap() == p);
        for n in 0..good.len() {
            assert!(Program::decode(&good[..n]).is_err(), "{cfb} {n}");
        }
        let output = run_c_output(&format!("encrypt-structure-{cfb}"), &good, &raw);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("valid=1"), "{cfb}: {stdout}");
        let Some(bin) = decoder_crypto() else {
            eprintln!("skipped: crypto interpreter unavailable");
            return;
        };
        let input = bin.parent().unwrap().join("encrypt.program");
        let response = bin.parent().unwrap().join("encrypt.response");
        fs::write(&input, &good).unwrap();
        fs::write(&response, &raw).unwrap();
        let out = Command::new(bin)
            .arg(&input)
            .arg(&response)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let captured = captured_hex(&stdout, 1);
        assert!(
            captured[30..30 + expected.len()] == expected[..],
            "{cfb}: interpreter ciphertext must equal the oracle ciphertext: {stdout}"
        );
        // A different fresh nonceTPM must produce a different ciphertext.
        let at = raw.len() - 1;
        let mut changed = raw.clone();
        changed[at] ^= 1;
        fs::write(&response, &changed).unwrap();
        let out = Command::new(bin)
            .arg(&input)
            .arg(&response)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let captured = captured_hex(&stdout, 1);
        assert_ne!(
            &captured[30..30 + expected.len()],
            &expected[..],
            "{cfb}: ciphertext must depend on the fresh nonce: {stdout}"
        );
    }
}

#[test]
fn session_hmac_patch_digest_matches_rust_oracle_via_real_hmac() {
    let Some(bin) = decoder_crypto() else {
        eprintln!("skipped: crypto interpreter unavailable");
        return;
    };
    let (p, raw, digest) = session_hmac_program();
    let good = p.encode().unwrap().bytes;
    let input = bin.parent().unwrap().join("sh-digest.program");
    let response = bin.parent().unwrap().join("sh-digest.response");
    fs::write(&input, &good).unwrap();
    fs::write(&response, &raw).unwrap();
    let out = Command::new(bin)
        .arg(&input)
        .arg(&response)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let captured = captured_hex(&stdout, 1);
    assert!(
        captured[30..62] == digest[..],
        "C HMAC must reproduce the Rust-oracle digest: {stdout}"
    );
    // A different fresh nonceTPM must change the derived key, hence the digest.
    let at = raw.len() - 1;
    let mut changed = raw.clone();
    changed[at] ^= 1;
    fs::write(&response, &changed).unwrap();
    let out = Command::new(bin)
        .arg(&input)
        .arg(&response)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let captured = captured_hex(&stdout, 1);
    assert_ne!(
        &captured[30..62],
        &digest[..],
        "session key must depend on the fresh nonce: {stdout}"
    );
}

#[test]
fn session_hmac_cp_hash_program_is_valid_to_the_c_interpreter() {
    use tpms_timing_tests::scenario::{PreparedPair, Scenario, scenario_seeds};
    let scenario = Scenario::parse("auth-hmac-request-xor").unwrap();
    let seed = scenario_seeds(scenario, 7, 1).into_iter().next().unwrap();
    let prepared = PreparedPair::try_prepare(scenario, seed.pair).unwrap();
    for class in 0..2 {
        let bytes = prepared.measured_command(class, 0x80000001);
        assert!(Program::decode(&bytes).is_ok(), "rust decode class {class}");
        let raw = tpm::success_response(&[], &tpm::sized(&[0x92; 32]), 0);
        let output = run_c_output(&format!("sh-cp-class{class}"), &bytes, &raw);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("valid=1"), "class {class}: {stdout}");
    }
}

fn session_hmac_cp_program() -> (Program, Vec<u8>, Vec<u8>) {
    use tpms_timing_tests::oracle::hash::HashAlg;
    use tpms_timing_tests::oracle::kdf::kdfa;
    use tpms_timing_tests::program::{
        CipherKey, EncryptedCpHash, Part, Patch, ResponseArea, ResponseRange,
    };
    let hash = HashAlg::Sha256;
    let caller = vec![0x56; 32];
    let session_caller = vec![0x57; 32];
    let nonce = vec![0x92; 32];
    let plain: Vec<u8> = (0..35u8).collect();
    let name: Vec<u8> = (0..32u8).collect();
    let prefix = vec![0x00, plain.len() as u8];
    let suffix = vec![0x00, 0x10];
    let raw = tpm::success_response(&[], &tpm::sized(&nonce), 0);
    let producer = Step::new(tpm::startup_clear(), fresh_nonce_contract(&raw, 32));
    let nonce_area = ResponseRange {
        step: 0,
        area: ResponseArea::Parameters,
        offset: 2,
        len: 32,
    };
    let session_key = kdfa(hash, &[0x71; 24], b"ATH", &nonce, &caller, 256);
    let mask = kdfa(hash, &[], b"XOR", &session_caller, &nonce, plain.len() * 8);
    let cipher: Vec<u8> = plain.iter().zip(&mask).map(|(a, b)| a ^ b).collect();
    let cp_hash = hash.digest(&[&0x15eu32.to_be_bytes(), &name, &prefix, &cipher, &suffix]);
    // The interpreter prepends the runtime cpHash before the declared parts.
    let digest = hash.hmac(&session_key, &[&cp_hash, &b"body"[..], &caller]);
    let mut command = tpm::startup_clear();
    command.resize(128, 0);
    command[2..6].copy_from_slice(&128u32.to_be_bytes());
    command[34..66].copy_from_slice(&digest);
    let mut mac = Step::new(command, fresh_nonce_contract(&raw, 32));
    mac.patches.push(Patch::SessionHmac {
        at: 34,
        hash,
        kdf_key: vec![0x71; 24],
        u_parts: vec![Part::Response(nonce_area.clone())],
        v_parts: vec![Part::Literal(caller.clone())],
        extra_key: vec![],
        parts: vec![Part::Literal(b"body".to_vec()), Part::Literal(caller)],
        xor: vec![0; 32],
        cp_hash: Some(EncryptedCpHash {
            cc: 0x15e,
            name,
            cfb: false,
            key: CipherKey::Fixed(vec![]),
            caller: session_caller,
            nonce: nonce_area,
            prefix,
            suffix,
            plain,
        }),
    });
    (
        Program {
            outcome_step: None,
            steps: vec![producer, mac],
        },
        raw,
        digest,
    )
}

#[test]
fn session_hmac_cp_hash_program_bytes_agree_between_implementations_under_mutation() {
    let (p, raw, _) = session_hmac_cp_program();
    let good = p.encode().unwrap().bytes;
    for position in 0..good.len() {
        for value in [0x00u8, 0xff] {
            if good[position] == value {
                continue;
            }
            let mut bad = good.clone();
            bad[position] = value;
            let output = run_c_output(&format!("sh-cp-agree-{position}-{value:x}"), &bad, &raw);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let c_valid = stdout.contains("valid=1");
            let rust_valid = Program::decode(&bad).is_ok();
            assert_eq!(
                c_valid, rust_valid,
                "position {position} value {value:02x}: C and Rust disagree"
            );
        }
    }
    let output = run_c("sh-cp-agree-good", &good, &raw);
    assert!(output.contains("valid=1"), "{output}");
}

#[test]
fn session_hmac_cp_hash_patch_digest_matches_rust_oracle_via_real_hmac() {
    let Some(bin) = decoder_crypto() else {
        eprintln!("skipped: crypto interpreter unavailable");
        return;
    };
    let (p, raw, digest) = session_hmac_cp_program();
    let good = p.encode().unwrap().bytes;
    let input = bin.parent().unwrap().join("sh-cp-digest.program");
    let response = bin.parent().unwrap().join("sh-cp-digest.response");
    fs::write(&input, &good).unwrap();
    fs::write(&response, &raw).unwrap();
    let out = Command::new(bin)
        .arg(&input)
        .arg(&response)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let captured = captured_hex(&stdout, 1);
    assert!(
        captured[34..66] == digest[..],
        "C cpHash HMAC must reproduce the Rust-oracle digest: {stdout}"
    );
}
