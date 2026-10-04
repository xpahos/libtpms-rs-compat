use std::fs;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::scalar::SCALAR_BYTES;
use crate::scenario::{Scenario, SplitMix, control_output, masked_tail_bits};

pub const STATE_ENV: &str = "TPMS_TIMING_FAKE_STATE";

fn state_dir() -> Option<PathBuf> {
    std::env::var_os(STATE_ENV).map(PathBuf::from)
}

fn serve_mode() -> String {
    state_dir()
        .and_then(|d| fs::read_to_string(d.join("serve-mode")).ok())
        .map(|m| m.trim().to_string())
        .unwrap_or_else(|| "normal".into())
}

fn next_dudect_mode() -> String {
    let Some(dir) = state_dir() else {
        return "auto".into();
    };
    let modes = fs::read_to_string(dir.join("dudect-modes")).unwrap_or_default();
    let count: usize = fs::read_to_string(dir.join("dudect-count"))
        .ok()
        .and_then(|c| c.trim().parse().ok())
        .unwrap_or(0);
    let _ = fs::write(dir.join("dudect-count"), (count + 1).to_string());
    modes
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .nth(count)
        .unwrap_or("auto")
        .to_string()
}

fn session() -> String {
    let mut bytes = [0u8; 16];
    if fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_err()
    {
        bytes[..4].copy_from_slice(&std::process::id().to_be_bytes());
    }
    hex::encode(bytes)
}

fn scenario_for(kind: &str, argument: &str) -> Option<Scenario> {
    match (kind, argument) {
        ("control", "positive") => Some(Scenario::ControlPositive),
        ("control", "negative") => Some(Scenario::ControlNegative),
        _ => None,
    }
}

fn output(scenario: Option<Scenario>, input: &[u8], wrong: bool) -> Option<Vec<u8>> {
    let scenario = scenario?;
    let bytes: [u8; SCALAR_BYTES] = input.try_into().ok()?;
    let mut out = control_output(scenario, &bytes).to_vec();
    if wrong {
        out[0] ^= 0xff;
    }
    Some(out)
}

fn info_lines(prefix: &str, kind: &str, argument: &str, cpu: &str) -> Vec<String> {
    let libcrypto = if kind == "tpm" { argument } else { "-" };
    let openssl = if kind == "tpm" { "fake-openssl" } else { "-" };
    vec![
        format!("{prefix}protocol 1"),
        format!("{prefix}pid {}", std::process::id()),
        format!("{prefix}session {}", session()),
        format!("{prefix}backend {kind} {argument}"),
        format!("{prefix}libcrypto_path {libcrypto}"),
        format!("{prefix}openssl_version {openssl}"),
        format!("{prefix}timer fake-worker-synthetic"),
        format!("{prefix}ticks_per_ns 1.0"),
        format!("{prefix}timer_granularity_ticks 1"),
        format!("{prefix}affinity_requested {cpu}"),
        format!("{prefix}affinity_applied no"),
        format!("{prefix}affinity_detail fake-worker"),
    ]
}

fn serve() -> ExitCode {
    let mode = serve_mode();
    let wrong = mode == "wrong-output";
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let _ = writeln!(out, "ready 1");
    let _ = out.flush();
    let mut scenario = None;
    let mut execs = 0usize;
    let mut measures = 0usize;
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let parts: Vec<&str> = line.split(' ').collect();
        match parts.first().copied() {
            Some("init") if parts.len() == 4 => {
                scenario = scenario_for(parts[1], parts[2]);
                for info in info_lines("info ", parts[1], parts[2], parts[3]) {
                    let _ = writeln!(out, "{info}");
                }
                let _ = writeln!(out, "ok");
            }
            Some("exec") if parts.len() == 2 => {
                let input = hex::decode(parts[1]).unwrap_or_default();
                match output(scenario, &input, wrong) {
                    Some(response) => {
                        let _ = writeln!(out, "resp 00000000 {}", hex::encode(response));
                        execs += 1;
                        if mode == "vanish-after-second-exec" && execs == 2 {
                            let _ = out.flush();
                            return ExitCode::SUCCESS;
                        }
                    }
                    None => {
                        let _ = writeln!(out, "resp 00000101 ");
                    }
                }
            }
            Some("measure") if parts.len() == 8 => {
                let rounds: usize = parts[1].parse().unwrap_or(0);
                let seed = u64::from_str_radix(parts[2], 16).unwrap_or(1);
                let commands = [
                    hex::decode(parts[4]).unwrap_or_default(),
                    hex::decode(parts[6]).unwrap_or_default(),
                ];
                let expected = [
                    hex::decode(parts[5]).unwrap_or_default(),
                    hex::decode(parts[7]).unwrap_or_default(),
                ];
                let _ = writeln!(out, "measure-begin\nnvstores_warmup 0\nnvstores_measured 0");
                let mismatch = (0..2).find(|c| {
                    output(scenario, &commands[*c], wrong).as_deref()
                        != Some(expected[*c].as_slice())
                });
                if let Some(class) = mismatch {
                    let _ = writeln!(out, "mismatch {class} 00000000 00");
                } else {
                    let mut rng = SplitMix::new(seed);
                    let base = |c: usize| -> u64 {
                        let bytes: [u8; SCALAR_BYTES] = commands[c].as_slice().try_into().unwrap();
                        match scenario {
                            Some(Scenario::ControlPositive) => {
                                50_000 + masked_tail_bits(&bytes) * 1000
                            }
                            _ => 80_000,
                        }
                    };
                    let mut order = String::new();
                    let mut ticks = [Vec::new(), Vec::new()];
                    for _ in 0..rounds {
                        order.push(if rng.next_u64() & 1 == 1 { '1' } else { '0' });
                        for (c, samples) in ticks.iter_mut().enumerate() {
                            samples.push((base(c) + rng.next_u64() % 400).to_string());
                        }
                    }
                    let _ = writeln!(out, "order {}", if rounds == 0 { "-" } else { &order });
                    for (c, samples) in ticks.iter().enumerate() {
                        let joined = samples.join(",");
                        let _ =
                            writeln!(out, "class{c} {}", if rounds == 0 { "-" } else { &joined });
                    }
                }
                let _ = writeln!(out, "measure-end");
                measures += 1;
            }
            Some("quit") => {
                let served_exec = execs > 0;
                let served_measure = measures > 0;
                match mode.as_str() {
                    "exit9-on-quit" => return ExitCode::from(9),
                    "exit9-on-quit-after-exec" if served_exec => {
                        let _ = writeln!(out, "bye");
                        let _ = out.flush();
                        return ExitCode::from(9);
                    }
                    "exit9-on-quit-after-measure" if served_measure => {
                        let _ = writeln!(out, "bye");
                        let _ = out.flush();
                        return ExitCode::from(9);
                    }
                    "abort-on-quit-after-exec" if served_exec => std::process::abort(),
                    "abort-on-quit-after-measure" if served_measure => std::process::abort(),
                    _ => {}
                }
                let _ = writeln!(out, "bye");
                let _ = out.flush();
                return ExitCode::SUCCESS;
            }
            _ => {
                let _ = writeln!(out, "error unknown-request");
                let _ = out.flush();
                return ExitCode::from(3);
            }
        }
        let _ = out.flush();
    }
    ExitCode::SUCCESS
}

fn dudect(plan: &Path) -> ExitCode {
    let text = fs::read_to_string(plan).unwrap_or_default();
    let field = |key: &str| -> String {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key} ")))
            .unwrap_or("")
            .to_string()
    };
    let backend = field("backend");
    let (kind, argument) = backend.split_once(' ').unwrap_or(("", ""));
    let scenario = scenario_for(kind, argument);
    let budget: u64 = field("budget").parse().unwrap_or(0);
    let batch: u64 = field("batch").parse().unwrap_or(1).max(1);
    let mut mode = next_dudect_mode();
    let functional = (0..2).all(|c| {
        let command = hex::decode(field(&format!("class{c}"))).unwrap_or_default();
        let expected = hex::decode(field(&format!("expect{c}"))).unwrap_or_default();
        output(scenario, &command, false).as_deref() == Some(expected.as_slice())
    });
    if mode == "block" {
        if let Some(dir) = state_dir() {
            let _ = fs::write(dir.join("blocked.pid"), std::process::id().to_string());
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
    if !functional && mode != "crash" && mode != "malformed" {
        mode = "mismatch".into();
    }
    let mut out = std::io::stdout();
    for info in info_lines("tpms-timing info ", kind, argument, &field("cpu")) {
        let _ = writeln!(out, "{info}");
    }
    let measured = (budget / batch) * batch;
    let enough = measured.saturating_sub(batch) / 2 > 10_000;
    let (status, measurements, max_t) = match mode.as_str() {
        "signal" => ("leakage-found", measured.min(12_000), 42.0),
        "nosignal" => ("budget-exhausted", measured, 1.0),
        "auto" if enough => ("budget-exhausted", measured, 1.0),
        "auto" | "insufficient" => ("insufficient-measurements", measured, 0.0),
        "timelimit" => ("time-limit", measured / 2, 1.0),
        "interrupted" => ("interrupted", measured / 2, 1.0),
        "mismatch" => {
            let _ = writeln!(
                out,
                "tpms-timing mismatch phase=measurement batch=1 count=1 class=0 tpmlib_rc=00000000"
            );
            ("functional-failure", batch, 0.0)
        }
        "crash" => {
            let _ = writeln!(
                out,
                "meas:    0.00 M, not enough measurements (9000 still to go)."
            );
            let _ = out.flush();
            std::process::abort();
        }
        "malformed" => {
            let _ = writeln!(out, "this is not dudect output\ntpms-timing resul");
            let _ = out.flush();
            return ExitCode::SUCCESS;
        }
        other => {
            let _ = writeln!(out, "error unknown-fake-mode-{other}");
            return ExitCode::from(3);
        }
    };
    if max_t > 0.0 {
        let verdict = if max_t > 10.0 {
            "Probably not constant time."
        } else {
            "For the moment, maybe constant time."
        };
        let _ = writeln!(
            out,
            "meas: {:7.2} M, max t: {max_t:+7.2}, max tau: 1.00e-02, (5/tau)^2: 2.50e+05. {verdict}",
            measurements as f64 / 1e6
        );
    } else {
        let _ = writeln!(
            out,
            "meas:    0.00 M, not enough measurements (10000 still to go)."
        );
    }
    let _ = writeln!(
        out,
        "tpms-timing test index=0 kind=raw n0={} n1={} t={max_t} eligible={}",
        measurements / 2,
        measurements / 2,
        if enough { "yes" } else { "no" }
    );
    let _ = writeln!(
        out,
        "tpms-timing result status={status} measurements={measurements} batches={} nvstores=0 mismatches={} elapsed_s=0.001",
        measurements / batch,
        u8::from(status == "functional-failure")
    );
    let _ = out.flush();
    ExitCode::SUCCESS
}

pub fn run(args: &[String]) -> ExitCode {
    match args {
        [mode] if mode == "serve" => serve(),
        [mode, plan] if mode == "dudect" => dudect(Path::new(plan)),
        _ => {
            eprintln!("usage: __fake-worker serve | dudect PLAN");
            ExitCode::from(2)
        }
    }
}
