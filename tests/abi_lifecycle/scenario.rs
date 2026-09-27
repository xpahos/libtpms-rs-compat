use std::collections::HashMap;

use crate::harness::Fixture;

pub struct Op {
    pub line: usize,
    pub name: String,
    pub words: Vec<String>,
    pub text: String,
}

impl Op {
    #[track_caller]
    pub fn word(&self, index: usize) -> &str {
        self.words.get(index).map_or_else(
            || panic!("line {}: `{}` lacks argument {index}", self.line, self.text),
            String::as_str,
        )
    }

    pub fn rest_after(&self, index: usize) -> &str {
        let mut rest = self.text.as_str();
        for _ in 0..=index {
            rest = rest
                .trim_start()
                .split_once(char::is_whitespace)
                .map_or("", |(_, tail)| tail);
        }
        rest.trim()
    }
}

pub struct Case {
    pub name: String,
    pub line: usize,
    pub ops: Vec<Op>,
}

fn blob_reference(op: &Op) -> Option<&str> {
    match op.name.as_str() {
        "set-state" => op.words.get(2),
        "nvram-put" => op.words.get(1),
        _ => None,
    }
    .map(String::as_str)
}

fn snapshot_name(reference: &str) -> Option<&str> {
    let record = reference
        .split_once('@')
        .map_or(reference, |(record, _)| record);
    record
        .strip_prefix("PERMALL_")
        .or_else(|| record.strip_prefix("VOLATILE_"))
}

pub fn cases(source: &str) -> Vec<Case> {
    let mut cases = Vec::new();
    let mut open: Option<Case> = None;
    let mut snapshots: HashMap<String, usize> = HashMap::new();
    for (index, raw) in source.lines().enumerate() {
        let line = index + 1;
        let text = raw.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        let mut words = text.split_whitespace().map(str::to_owned);
        let name = words.next().expect("a non-empty line has a word");
        let words: Vec<String> = words.collect();
        match name.as_str() {
            "case" => {
                assert!(open.is_none(), "line {line}: a case opens inside a case");
                open = Some(Case {
                    name: words.first().cloned().expect("case has a name"),
                    line,
                    ops: Vec::new(),
                });
            }
            "end-case" => cases.push(
                open.take()
                    .unwrap_or_else(|| panic!("line {line}: end-case outside a case")),
            ),
            _ => {
                let op = Op {
                    line,
                    name,
                    words,
                    text: text.to_owned(),
                };
                match open.as_mut() {
                    Some(case) => {
                        if let Some(reference) = blob_reference(&op) {
                            let known =
                                snapshot_name(reference).and_then(|name| snapshots.get(name));
                            assert!(
                                known.is_some(),
                                "line {line}: {reference} names no snapshot recorded before case {}",
                                case.name
                            );
                        }
                        case.ops.push(op);
                    }
                    None => note_snapshot(&op, &mut snapshots),
                }
            }
        }
    }
    assert!(open.is_none(), "the last case is never closed");
    cases
}

fn note_snapshot(op: &Op, snapshots: &mut HashMap<String, usize>) {
    let Some(name) = op.words.first() else {
        return;
    };
    match op.name.as_str() {
        "snapshot" => {
            snapshots.entry(name.clone()).or_insert(op.line);
        }
        "checkpoint" => {
            if let Some(recorded) = snapshots.get(name) {
                panic!(
                    "line {}: checkpoint {name} would overwrite the snapshot recorded on line \
                     {recorded}; a case would read the checkpoint while the fixture keeps the \
                     snapshot",
                    op.line
                );
            }
        }
        _ => {}
    }
}

fn decimal(reference: &str, text: &str) -> usize {
    text.parse()
        .unwrap_or_else(|_| panic!("{reference}: {text} is not a decimal number"))
}

fn apply_modifier(reference: &str, bytes: &mut Vec<u8>, modifier: &str) {
    let length = bytes.len();
    if modifier == "sha1" {
        let payload = length
            .checked_sub(20)
            .unwrap_or_else(|| panic!("{reference}: no room for a SHA-1 trailer"));
        let digest = <sha1::Sha1 as sha1::Digest>::digest(&bytes[..payload]);
        bytes[payload..].copy_from_slice(&digest);
        return;
    }
    let (kind, argument) = modifier
        .split_once('=')
        .unwrap_or_else(|| panic!("{reference}: a modifier is kind=N or sha1"));
    match kind {
        "head" => {
            let amount = decimal(reference, argument);
            assert!(amount <= length, "{reference}: longer than the blob");
            bytes.truncate(amount);
        }
        "drop" => {
            let amount = decimal(reference, argument);
            assert!(amount <= length, "{reference}: longer than the blob");
            bytes.truncate(length - amount);
        }
        "flip" => bytes[decimal(reference, argument)] ^= 0xff,
        "flip-end" => {
            let amount = decimal(reference, argument);
            assert!(
                (1..=length).contains(&amount),
                "{reference}: outside the blob"
            );
            bytes[length - amount] ^= 0xff;
        }
        "set" => {
            let (at, hex) = argument
                .split_once(':')
                .unwrap_or_else(|| panic!("{reference}: set needs N:HEX"));
            let at = decimal(reference, at);
            let value: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|index| {
                    u8::from_str_radix(&hex[index..index + 2], 16)
                        .unwrap_or_else(|_| panic!("{reference}: {hex} is not hexadecimal"))
                })
                .collect();
            let end = at + value.len();
            assert!(end <= length, "{reference}: set runs past the blob");
            bytes[at..end].copy_from_slice(&value);
        }
        other => panic!("{reference}: unknown blob modifier {other}"),
    }
}

pub fn blob(fixture: &Fixture, reference: &str) -> Vec<u8> {
    let mut parts = reference.split('@');
    let record = parts.next().unwrap_or(reference);
    let mut bytes = fixture.get(record).to_vec();
    for modifier in parts {
        apply_modifier(reference, &mut bytes, modifier);
    }
    bytes
}
