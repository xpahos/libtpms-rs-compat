use serde::{Deserialize, Serialize};

use crate::measure::LoadOrder;
use crate::tpm::{FIRST_TRANSIENT_HANDLE, HMAC_SESSION_FIRST};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HandleRef {
    Shared(usize),
    Class(usize),
    NextObject,
    NextSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Creates {
    Nothing,
    Object,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepRef {
    Shared(usize),
    Class(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    pub at: usize,
    pub source: StepRef,
    pub from: usize,
    pub len: usize,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub xor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub label: String,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub command: Vec<u8>,
    pub handles: Vec<(usize, HandleRef)>,
    pub creates: Creates,
    pub patches: Vec<Patch>,
}

impl Step {
    pub fn new(label: impl Into<String>, command: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            command,
            handles: Vec::new(),
            creates: Creates::Nothing,
            patches: Vec::new(),
        }
    }

    pub fn creates(mut self, creates: Creates) -> Self {
        self.creates = creates;
        self
    }

    pub fn handle_at(mut self, at: usize, handle: HandleRef) -> Self {
        self.handles.push((at, handle));
        self
    }

    pub fn patch(mut self, patch: Patch) -> Self {
        self.patches.push(patch);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Post {
    pub step: Step,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub expected: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layout {
    pub shared: Vec<Step>,
    pub per_class: [Vec<Step>; 2],
    pub measured: [Step; 2],
    pub post: [Option<Post>; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedPatch {
    pub at: usize,
    pub setup_index: usize,
    pub from: usize,
    pub len: usize,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub xor: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedSetup {
    pub label: String,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub command: Vec<u8>,
    pub expected_handle: Option<u32>,
    #[serde(default)]
    pub patches: Vec<ResolvedPatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub setup: Vec<ResolvedSetup>,
    pub measured: [Vec<u8>; 2],
    pub patches: [Vec<ResolvedPatch>; 2],
    pub post: [Option<(Vec<u8>, Vec<u8>)>; 2],
    pub class_handles: [Option<u32>; 2],
}

struct Counter {
    objects: u32,
    sessions: u32,
}

impl Counter {
    fn allocate(&mut self, creates: Creates) -> Option<u32> {
        match creates {
            Creates::Nothing => None,
            Creates::Object => {
                self.objects += 1;
                Some(FIRST_TRANSIENT_HANDLE + self.objects - 1)
            }
            Creates::Session => {
                self.sessions += 1;
                Some(HMAC_SESSION_FIRST + self.sessions - 1)
            }
        }
    }
}

fn substitute(
    step: &Step,
    shared: &[u32],
    class: &[u32],
    counter: &Counter,
) -> Result<Vec<u8>, String> {
    let mut bytes = step.command.clone();
    for (at, reference) in &step.handles {
        let value = match reference {
            HandleRef::Shared(k) => *shared
                .get(*k)
                .ok_or_else(|| format!("{}: shared object {k} does not exist", step.label))?,
            HandleRef::Class(k) => *class
                .get(*k)
                .ok_or_else(|| format!("{}: class object {k} does not exist", step.label))?,
            HandleRef::NextObject => FIRST_TRANSIENT_HANDLE + counter.objects,
            HandleRef::NextSession => HMAC_SESSION_FIRST + counter.sessions,
        };
        bytes
            .get_mut(*at..*at + 4)
            .ok_or_else(|| format!("{}: handle offset {at} is outside the command", step.label))?
            .copy_from_slice(&value.to_be_bytes());
    }
    Ok(bytes)
}

impl Layout {
    pub fn resolve(&self, order: LoadOrder) -> Result<Resolved, String> {
        let mut counter = Counter {
            objects: 0,
            sessions: 0,
        };
        let mut setup = Vec::new();
        let mut shared_handles = Vec::new();
        let mut shared_index = Vec::new();
        for step in &self.shared {
            let command = substitute(step, &shared_handles, &[], &counter)?;
            let patches = resolve_patches(step, &shared_index, &[])?;
            let handle = counter.allocate(step.creates);
            if step.creates == Creates::Object {
                shared_handles.push(handle.unwrap());
            }
            shared_index.push(setup.len());
            setup.push(ResolvedSetup {
                label: step.label.clone(),
                command,
                expected_handle: handle,
                patches,
            });
        }
        let mut class_handles: [Vec<u32>; 2] = [Vec::new(), Vec::new()];
        let mut class_index: [Vec<usize>; 2] = [Vec::new(), Vec::new()];
        for class in order.classes() {
            for step in &self.per_class[class] {
                let command = substitute(step, &shared_handles, &class_handles[class], &counter)?;
                let patches = resolve_patches(step, &shared_index, &class_index[class])?;
                let handle = counter.allocate(step.creates);
                if step.creates == Creates::Object {
                    class_handles[class].push(handle.unwrap());
                }
                class_index[class].push(setup.len());
                setup.push(ResolvedSetup {
                    label: format!("class{class} {}", step.label),
                    command,
                    expected_handle: handle,
                    patches,
                });
            }
        }
        let mut measured: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        let mut patches: [Vec<ResolvedPatch>; 2] = [Vec::new(), Vec::new()];
        let mut post: [Option<(Vec<u8>, Vec<u8>)>; 2] = [None, None];
        for class in 0..2 {
            let step = &self.measured[class];
            measured[class] = substitute(step, &shared_handles, &class_handles[class], &counter)?;
            patches[class] = resolve_patches(step, &shared_index, &class_index[class])?;
            if let Some(p) = &self.post[class] {
                post[class] = Some((
                    substitute(&p.step, &shared_handles, &class_handles[class], &counter)?,
                    p.expected.clone(),
                ));
            }
        }
        if measured[0].len() != measured[1].len() {
            return Err("the two measured class commands must have the same length".into());
        }
        Ok(Resolved {
            setup,
            measured,
            patches,
            post,
            class_handles: [
                class_handles[0].first().copied(),
                class_handles[1].first().copied(),
            ],
        })
    }
}

fn resolve_patches(
    step: &Step,
    shared: &[usize],
    class: &[usize],
) -> Result<Vec<ResolvedPatch>, String> {
    step.patches
        .iter()
        .map(|patch| {
            let setup_index = match patch.source {
                StepRef::Shared(k) => shared.get(k),
                StepRef::Class(k) => class.get(k),
            }
            .copied()
            .ok_or_else(|| {
                format!(
                    "{}: patch source {:?} is not a prior setup step",
                    step.label, patch.source
                )
            })?;
            if patch.len == 0
                || patch
                    .at
                    .checked_add(patch.len)
                    .is_none_or(|end| end > step.command.len())
                || patch.from.checked_add(patch.len).is_none()
                || patch.xor.len() != patch.len
            {
                return Err(format!("{}: patch does not fit the command", step.label));
            }
            Ok(ResolvedPatch {
                at: patch.at,
                setup_index,
                from: patch.from,
                len: patch.len,
                xor: patch.xor.clone(),
            })
        })
        .collect()
}

pub fn apply_patches(
    command: &mut [u8],
    patches: &[ResolvedPatch],
    responses: &[Vec<u8>],
) -> Result<(), String> {
    for patch in patches {
        let source_end = patch
            .from
            .checked_add(patch.len)
            .ok_or("patch source overflow")?;
        let destination_end = patch
            .at
            .checked_add(patch.len)
            .ok_or("patch destination overflow")?;
        if patch.len == 0 || destination_end > command.len() || patch.xor.len() != patch.len {
            return Err("patch destination or XOR length is invalid".into());
        }
        let source = responses
            .get(patch.setup_index)
            .ok_or_else(|| format!("setup response {} missing", patch.setup_index))?;
        let bytes = source.get(patch.from..source_end).ok_or_else(|| {
            format!(
                "setup response {} has {} bytes; patch needs {}..{}",
                patch.setup_index,
                source.len(),
                patch.from,
                source_end
            )
        })?;
        for (i, byte) in bytes.iter().enumerate() {
            command[patch.at + i] = byte ^ patch.xor[i];
        }
    }
    Ok(())
}

pub fn masked_equal(response: &[u8], expected: &[u8], mask: &[u8]) -> bool {
    response.len() == expected.len()
        && response
            .iter()
            .zip(expected)
            .enumerate()
            .all(|(i, (r, e))| {
                let m = mask.get(i).copied().unwrap_or(0xff);
                r & m == e & m
            })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(label: &str, creates: Creates) -> Step {
        Step::new(label, vec![0u8; 12]).creates(creates)
    }

    #[test]
    fn handles_follow_creation_order_and_load_order() {
        let layout = Layout {
            shared: vec![step("parent", Creates::Object)],
            per_class: [
                vec![step("key", Creates::Object).handle_at(4, HandleRef::Shared(0))],
                vec![step("key", Creates::Object)],
            ],
            measured: [
                step("use", Creates::Nothing).handle_at(0, HandleRef::Class(0)),
                step("use", Creates::Nothing).handle_at(0, HandleRef::Class(0)),
            ],
            post: [None, None],
        };
        let a = layout.resolve(LoadOrder::ClassAFirst).unwrap();
        assert_eq!(&a.measured[0][..4], &0x8000_0001u32.to_be_bytes());
        assert_eq!(&a.measured[1][..4], &0x8000_0002u32.to_be_bytes());
        assert_eq!(&a.setup[1].command[4..8], &0x8000_0000u32.to_be_bytes());
        let b = layout.resolve(LoadOrder::ClassBFirst).unwrap();
        assert_eq!(&b.measured[0][..4], &0x8000_0002u32.to_be_bytes());
        assert_eq!(&b.measured[1][..4], &0x8000_0001u32.to_be_bytes());
        assert_eq!(b.setup[1].label, "class1 key");
    }

    #[test]
    fn patches_copy_and_xor_setup_output() {
        let layout = Layout {
            shared: vec![step("source", Creates::Nothing)],
            per_class: [Vec::new(), Vec::new()],
            measured: [
                step("m", Creates::Nothing).patch(Patch {
                    at: 2,
                    source: StepRef::Shared(0),
                    from: 1,
                    len: 2,
                    xor: vec![0, 0xff],
                }),
                step("m", Creates::Nothing),
            ],
            post: [None, None],
        };
        let resolved = layout.resolve(LoadOrder::ClassAFirst).unwrap();
        let mut command = resolved.measured[0].clone();
        apply_patches(&mut command, &resolved.patches[0], &[vec![9, 0x12, 0x34]]).unwrap();
        assert_eq!(&command[2..4], &[0x12, 0xcb]);
        assert!(apply_patches(&mut command, &resolved.patches[0], &[vec![1]]).is_err());
    }

    #[test]
    fn setup_patches_resolve_only_prior_steps_in_each_load_order() {
        let patch = |source| Patch {
            at: 2,
            source,
            from: 1,
            len: 2,
            xor: vec![0, 0xff],
        };
        let mut layout = Layout {
            shared: vec![
                step("source", Creates::Nothing),
                step("dependent", Creates::Nothing).patch(patch(StepRef::Shared(0))),
            ],
            per_class: [
                vec![
                    step("a source", Creates::Nothing),
                    step("a dependent", Creates::Nothing).patch(patch(StepRef::Class(0))),
                ],
                vec![
                    step("b source", Creates::Nothing),
                    step("b dependent", Creates::Nothing).patch(patch(StepRef::Class(0))),
                ],
            ],
            measured: [step("a", Creates::Nothing), step("b", Creates::Nothing)],
            post: [None, None],
        };
        for order in [LoadOrder::ClassAFirst, LoadOrder::ClassBFirst] {
            let resolved = layout.resolve(order).unwrap();
            let json = serde_json::to_value(&resolved.setup).unwrap();
            assert_eq!(
                json[1]["patches"][0]["setup_index"], 0,
                "shared dependency retained"
            );
            assert_eq!(
                json[3]["patches"][0]["setup_index"], 2,
                "first class dependency"
            );
            assert_eq!(
                json[5]["patches"][0]["setup_index"], 4,
                "second class dependency"
            );
        }
        layout.shared[0].patches.push(patch(StepRef::Shared(1)));
        assert!(
            layout.resolve(LoadOrder::ClassAFirst).is_err(),
            "forward setup dependency accepted"
        );
    }

    #[test]
    fn malformed_resolved_patch_is_an_error_without_mutating_the_command() {
        let valid = ResolvedPatch {
            at: 0,
            setup_index: 0,
            from: 0,
            len: 2,
            xor: vec![0; 2],
        };
        let mut cases = vec![];
        for field in 0..5 {
            let mut patch = valid.clone();
            match field {
                0 => patch.at = usize::MAX,
                1 => patch.from = usize::MAX,
                2 => patch.setup_index = 1,
                3 => patch.xor.clear(),
                _ => patch.len = 0,
            }
            cases.push(patch);
        }
        for patch in cases {
            let mut command = vec![7; 4];
            assert!(apply_patches(&mut command, &[patch], &[vec![1; 4]]).is_err());
            assert_eq!(command, vec![7; 4]);
        }
    }

    #[test]
    fn masks_ignore_only_masked_bits() {
        assert!(masked_equal(&[1, 2, 3], &[1, 9, 3], &[0xff, 0, 0xff]));
        assert!(!masked_equal(&[1, 2, 3], &[1, 9, 4], &[0xff, 0, 0xff]));
        assert!(!masked_equal(&[1, 2], &[1, 2, 3], &[]));
        assert!(masked_equal(&[1, 2], &[1, 2], &[]));
    }
}
