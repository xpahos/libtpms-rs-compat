// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026 Alexander Gryanko <xpahos@gmail.com>
// Copyright (c) 2026 Yandex
//
// License text: LICENSE.
// Upstream notices: LICENSES/libtpms-notices.txt.

use crate::harness::{
    self, Fixture, ProcessReply, State, StateReply, TPM_SUCCESS, Tpm, TpmResult, hex, host,
};
use crate::layout;
use crate::scenario::{self, Case, Op};

pub fn replay(tpm: &Tpm, fixture: &Fixture, case: &Case) {
    harness::note(format!(
        "# case {} (scenario line {})",
        case.name, case.line
    ));
    assert_eq!(tpm.choose_tpm2(), TPM_SUCCESS, "TPMLIB_ChooseTPMVersion");
    assert_eq!(
        tpm.register_callbacks(),
        TPM_SUCCESS,
        "TPMLIB_RegisterCallbacks"
    );
    let mut replay = Replay {
        tpm,
        fixture,
        running: false,
        io_init: TPM_SUCCESS,
        nvram_init: TPM_SUCCESS,
    };
    for op in &case.ops {
        replay.step(op);
    }
}

struct Replay<'a> {
    tpm: &'a Tpm,
    fixture: &'a Fixture,
    running: bool,
    io_init: TpmResult,
    nvram_init: TpmResult,
}

fn unhex(line: usize, text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "line {line}: odd hex digit count"
    );
    (0..text.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&text[at..at + 2], 16)
                .unwrap_or_else(|_| panic!("line {line}: {text} is not hexadecimal"))
        })
        .collect()
}

fn code(op: &Op, index: usize) -> TpmResult {
    op.word(index)
        .parse()
        .unwrap_or_else(|_| panic!("line {}: {} is not a decimal code", op.line, op.word(index)))
}

fn state(op: &Op, index: usize) -> State {
    State::parse(op.word(index)).unwrap_or_else(|| {
        panic!(
            "line {}: {} is neither permanent nor volatile",
            op.line,
            op.word(index)
        )
    })
}

fn process_record(reply: &ProcessReply) -> Vec<u8> {
    let mut record = reply.result.to_be_bytes().to_vec();
    if reply.result == TPM_SUCCESS {
        record.extend_from_slice(reply.response.as_deref().unwrap_or_default());
    }
    record
}

impl Replay<'_> {
    fn blob(&self, reference: &str) -> Vec<u8> {
        let bytes = scenario::blob(self.fixture, reference);
        host::remember(reference, &bytes);
        bytes
    }

    #[track_caller]
    fn expect(&self, op: &Op, actual: &[u8]) {
        let name = op.word(0);
        let expected = self.fixture.get(name);
        assert!(
            expected == actual,
            "line {} `{}`: {name} differs from the reference\n  reference {}\n  actual    {}",
            op.line,
            op.text,
            hex(expected),
            hex(actual)
        );
    }

    #[track_caller]
    fn expect_result(&self, op: &Op, result: TpmResult) {
        self.expect(op, &result.to_be_bytes());
    }

    fn expect_state(&self, op: &Op, kind: State, reply: StateReply) {
        let name = op.word(0);
        let expected = self.fixture.get(name);
        let mut head = reply.result.to_be_bytes().to_vec();
        head.push(u8::from(reply.blob.is_some()));
        assert!(
            expected.len() >= 5 && expected[..5] == head[..],
            "line {} `{}`: result and buffer presence {} differ from the reference {}",
            op.line,
            op.text,
            hex(&head),
            hex(&expected[..expected.len().min(5)])
        );
        let Some(actual) = reply.blob else {
            return;
        };
        let expected = &expected[5..];
        if !self.running {
            assert!(
                expected == actual.as_slice(),
                "line {} `{}`: the staged {kind:?} state differs from the reference \
                 ({} bytes, reference {} bytes)",
                op.line,
                op.text,
                actual.len(),
                expected.len()
            );
            return;
        }
        if let Err(difference) = layout::compare_running_export(kind, expected, &actual) {
            panic!("line {} `{}`: {difference}", op.line, op.text);
        }
    }

    fn step(&mut self, op: &Op) {
        harness::note(format!("# line {}: {}", op.line, op.text));
        match op.name.as_str() {
            "terminate" => {
                self.tpm.terminate();
                self.running = false;
            }
            "main-init" => {
                let result = self.tpm.main_init();
                if self.io_init == TPM_SUCCESS && self.nvram_init == TPM_SUCCESS {
                    self.running = true;
                }
                self.expect_result(op, result);
            }
            "set-state" => {
                let kind = state(op, 1);
                let bytes = self.blob(op.word(2));
                let result = self.tpm.set_state(kind, op.word(2), &bytes);
                self.expect_result(op, result);
            }
            "get-state" => {
                let kind = state(op, 1);
                let reply = self
                    .tpm
                    .get_state(kind)
                    .unwrap_or_else(|violation| panic!("line {}: {violation}", op.line));
                self.expect_state(op, kind, reply);
            }
            "volatile-all-store" => {
                let reply = self
                    .tpm
                    .volatile_all_store()
                    .unwrap_or_else(|violation| panic!("line {}: {violation}", op.line));
                self.expect_state(op, State::Volatile, reply);
            }
            "set-profile" => {
                let result = self.tpm.set_profile(op.rest_after(0));
                self.expect_result(op, result);
            }
            "process" => {
                let reply = self
                    .tpm
                    .process(&unhex(op.line, op.word(1)))
                    .unwrap_or_else(|violation| panic!("line {}: {violation}", op.line));
                self.expect(op, &process_record(&reply));
            }
            "was-manufactured" => {
                let manufactured = self.tpm.was_manufactured();
                self.expect(op, &[manufactured]);
            }
            "established" => {
                let (result, established) = self.tpm.established_get();
                let mut record = result.to_be_bytes().to_vec();
                record.push(established);
                self.expect(op, &record);
            }
            "established-reset" => {
                let result = self.tpm.established_reset();
                self.expect_result(op, result);
            }
            "hash-start" => {
                let result = self.tpm.hash_start();
                self.expect_result(op, result);
            }
            "hash-data" => {
                let result = self.tpm.hash_data(&unhex(op.line, op.word(1)));
                self.expect_result(op, result);
            }
            "hash-end" => {
                let result = self.tpm.hash_end();
                self.expect_result(op, result);
            }
            "nvram-put" => {
                let bytes = self.blob(op.word(1));
                host::put(op.word(0), op.word(1), bytes);
            }
            "load-fails" => host::fail_loads(op.word(0), code(op, 1)),
            "io-init" => {
                self.io_init = code(op, 0);
                host::io_init_answers(self.io_init);
            }
            "nvram-init" => {
                self.nvram_init = code(op, 0);
                host::nvram_init_answers(self.nvram_init);
            }
            "callbacks" => {
                let log = host::take_callbacks();
                let mut record = (log.len() as u32).to_be_bytes().to_vec();
                for line in &log {
                    record.extend_from_slice(line.as_bytes());
                    record.push(b'\n');
                }
                let name = op.word(0);
                let expected = self.fixture.get(name);
                assert!(
                    expected == record.as_slice(),
                    "line {} `{}`: the callbacks differ from the reference\n--- reference\n{}\n--- actual\n{}",
                    op.line,
                    op.text,
                    String::from_utf8_lossy(expected.get(4..).unwrap_or_default()),
                    String::from_utf8_lossy(&record[4..])
                );
            }
            other => panic!("line {}: unknown case op {other}", op.line),
        }
    }
}
