use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::scenario::layout::apply_patches;
use crate::scenario::{PreparedPair, SplitMix};
use crate::tpm;
use crate::worker::{
    BackendSpec, Limits, MeasureReply, POST_FAILED_RC, TimeoutBound, WorkerError, WorkerInfo,
    WorkerProcess,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadOrder {
    ClassAFirst,
    ClassBFirst,
}

impl LoadOrder {
    pub fn from_bit(bit: bool) -> Self {
        if bit {
            Self::ClassBFirst
        } else {
            Self::ClassAFirst
        }
    }

    pub fn classes(self) -> [usize; 2] {
        match self {
            Self::ClassAFirst => [0, 1],
            Self::ClassBFirst => [1, 0],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadedPair {
    pub order: LoadOrder,
    pub handles: Option<[u32; 2]>,
    #[serde(skip)]
    pub commands: [Vec<u8>; 2],
    #[serde(skip)]
    pub expected: [Vec<u8>; 2],
    #[serde(skip)]
    pub masks: [Vec<u8>; 2],
    #[serde(skip)]
    pub posts: [Option<(Vec<u8>, Vec<u8>)>; 2],
    #[serde(skip)]
    pub validations: [Option<crate::scenario::Validation>; 2],
}

impl LoadedPair {
    pub fn plain(order: LoadOrder, commands: [Vec<u8>; 2], expected: [Vec<u8>; 2]) -> Self {
        Self {
            order,
            handles: None,
            commands,
            expected,
            masks: [Vec::new(), Vec::new()],
            posts: [None, None],
            validations: [None, None],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawBatch {
    pub seed: u64,
    pub order: String,
    pub class0: Vec<u64>,
    pub class1: Vec<u64>,
    pub nv_stores_measured: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum MeasureFailure {
    Functional {
        class: Option<usize>,
        detail: String,
    },
    Infrastructure {
        detail: String,
    },
    Timeout {
        operation: String,
        campaign_deadline: bool,
        detail: String,
    },
}

impl fmt::Display for MeasureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Functional { class, detail } => {
                write!(f, "functional failure (class {class:?}): {detail}")
            }
            Self::Infrastructure { detail } => write!(f, "infrastructure failure: {detail}"),
            Self::Timeout {
                operation,
                campaign_deadline,
                detail,
            } => write!(
                f,
                "worker timeout during {operation} ({}): {detail}",
                if *campaign_deadline {
                    "campaign deadline"
                } else {
                    "operation limit"
                }
            ),
        }
    }
}

impl From<WorkerError> for MeasureFailure {
    fn from(error: WorkerError) -> Self {
        match &error {
            WorkerError::Timeout {
                operation, bound, ..
            } => Self::Timeout {
                operation: operation.clone(),
                campaign_deadline: *bound == TimeoutBound::CampaignDeadline,
                detail: error.to_string(),
            },
            _ => Self::Infrastructure {
                detail: error.to_string(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationRecord {
    pub class: usize,
    pub label: String,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub command: Vec<u8>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub response: Vec<u8>,
    pub model: String,
}

/// Why a pair could not be prepared for measurement.
///
/// `Invalid` rejects one candidate input (the evaluation continues); `Backend` reports
/// that the backend itself could not resolve an independently validated expectation, for
/// example because the fixed RSAES capability probes failed or were inconsistent. A
/// backend failure must abort the campaign or artifact instead of being filed as an
/// invalid candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PrepareFailure {
    Invalid(String),
    Backend(String),
}

impl PrepareFailure {
    pub fn detail(&self) -> &str {
        match self {
            Self::Invalid(detail) | Self::Backend(detail) => detail,
        }
    }
}

impl fmt::Display for PrepareFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "invalid candidate input: {detail}"),
            Self::Backend(detail) => write!(f, "backend expectation failure: {detail}"),
        }
    }
}

pub trait Measurer {
    /// Prepare a pair for measurement on this backend.
    ///
    /// Backends whose functional contract depends on the library build (malformed RSAES
    /// padding) resolve the contract here with fixed, independently computed capability
    /// probes; a probe failure is a [`PrepareFailure::Backend`], never an invalid input.
    fn prepare(
        &mut self,
        scenario: crate::scenario::Scenario,
        pair: crate::scenario::InputPair,
    ) -> Result<PreparedPair, PrepareFailure> {
        PreparedPair::try_prepare(scenario, pair).map_err(PrepareFailure::Invalid)
    }

    fn label(&self) -> String;
    fn info(&self) -> WorkerInfo;
    fn load(&mut self, pair: &PreparedPair, order: LoadOrder)
    -> Result<LoadedPair, MeasureFailure>;
    fn measure(
        &mut self,
        loaded: &LoadedPair,
        rounds: usize,
        warmup: usize,
        seed: u64,
    ) -> Result<RawBatch, MeasureFailure>;
    fn execute_once(&mut self, loaded: &LoadedPair) -> Result<[Vec<u8>; 2], MeasureFailure>;
    /// Probe an operation known to enter failure mode without contaminating this measurer.
    fn isolated_functional_probe(&mut self, _pair: &PreparedPair) -> Result<(), MeasureFailure> {
        Err(MeasureFailure::Infrastructure {
            detail: "this measurer cannot create an isolated functional probe".into(),
        })
    }
    fn validation_records(&self) -> Vec<ValidationRecord> {
        Vec::new()
    }
    fn set_deadline(&mut self, _deadline: Option<Instant>) {}
}

pub struct WorkerMeasurer {
    rsaes_evidence: Option<crate::expectation::RsaesEvidence>,
    sym_evidence: Option<crate::expectation::SymChainingEvidence>,
    executable: PathBuf,
    probe_stderr: PathBuf,
    probe_limits: Limits,
    probe_deadline: Option<Instant>,
    process: Option<WorkerProcess>,
    backend: BackendSpec,
    loaded_handles: Vec<u32>,
    validations: Vec<ValidationRecord>,
    unrecovered: Option<String>,
}

impl WorkerMeasurer {
    pub fn start(
        worker: &Path,
        backend: BackendSpec,
        cpu: Option<usize>,
        stderr: &Path,
        limits: Limits,
    ) -> Result<Self, WorkerError> {
        let mut process = WorkerProcess::spawn(worker, &backend, cpu, stderr, limits)?;
        if let BackendSpec::Library { .. } = backend {
            let (rc, response) = process.exec(&tpm::startup_clear())?;
            if rc != 0 || tpm::expect_success(&response).is_err() {
                return Err(WorkerError::Reported(format!(
                    "TPM2_Startup failed: tpmlib rc {rc:08x} response {}",
                    hex::encode(&response)
                )));
            }
        }
        Ok(Self {
            rsaes_evidence: None,
            sym_evidence: None,
            executable: worker.to_path_buf(),
            probe_stderr: stderr.with_extension("isolated-probe.log"),
            probe_limits: limits,
            probe_deadline: None,
            process: Some(process),
            backend,
            loaded_handles: Vec::new(),
            validations: Vec::new(),
            unrecovered: None,
        })
    }

    fn process(&mut self) -> Result<&mut WorkerProcess, MeasureFailure> {
        if let Some(reason) = &self.unrecovered {
            return Err(MeasureFailure::Infrastructure {
                detail: format!(
                    "refusing to reuse a worker whose TPM state could not be restored: {reason}"
                ),
            });
        }
        self.process
            .as_mut()
            .ok_or_else(|| MeasureFailure::Infrastructure {
                detail: "worker already failed".into(),
            })
    }

    pub fn unrecovered(&self) -> Option<&str> {
        self.unrecovered.as_deref()
    }

    fn run_validation(
        &mut self,
        class: usize,
        loaded: &LoadedPair,
        response: &[u8],
    ) -> Result<(), MeasureFailure> {
        let Some(validation) = &loaded.validations[class] else {
            return Ok(());
        };
        let validation = validation.clone();
        let steps = validation
            .steps(response)
            .map_err(|detail| MeasureFailure::Functional {
                class: Some(class),
                detail,
            })?;
        for step in steps {
            match self.process()?.exec(&step.command) {
                Ok((0, reply)) => {
                    self.validations.push(ValidationRecord {
                        class,
                        label: step.label.clone(),
                        command: step.command.clone(),
                        response: reply.clone(),
                        model: validation.describe(),
                    });
                    step.expect
                        .verify(&reply)
                        .map_err(|detail| MeasureFailure::Functional {
                            class: Some(class),
                            detail: format!("{}: {detail}", step.label),
                        })?;
                }
                Ok((rc, _)) => {
                    return Err(MeasureFailure::Functional {
                        class: Some(class),
                        detail: format!("{}: TPMLIB_Process returned {rc:08x}", step.label),
                    });
                }
                Err(error) => return self.fail(error),
            }
        }
        Ok(())
    }

    fn run_cleanup(&mut self, class: usize, loaded: &LoadedPair) -> Result<(), MeasureFailure> {
        let Some((command, expected)) = loaded.posts[class].clone() else {
            return Ok(());
        };
        match self.process()?.exec(&command) {
            Ok((0, response)) if response == expected => Ok(()),
            Ok((rc, response)) => Err(MeasureFailure::Functional {
                class: Some(class),
                detail: format!(
                    "cleanup command failed: rc {rc:08x} response {}",
                    hex::encode(response)
                ),
            }),
            Err(error) => self.fail(error),
        }
    }

    fn fail<T>(&mut self, error: WorkerError) -> Result<T, MeasureFailure> {
        self.process = None;
        Err(error.into())
    }

    pub fn close_checked(mut self) -> Result<String, WorkerError> {
        match self.process.take() {
            Some(process) => process.close(),
            None => Ok("worker already terminated".into()),
        }
    }
}

impl Measurer for WorkerMeasurer {
    fn prepare(
        &mut self,
        scenario: crate::scenario::Scenario,
        pair: crate::scenario::InputPair,
    ) -> Result<PreparedPair, PrepareFailure> {
        if crate::expectation::is_rsaes(scenario) {
            if self.rsaes_evidence.is_none() {
                let backend = self.backend.clone();
                self.rsaes_evidence = Some(
                    crate::expectation::probe(self, &backend).map_err(PrepareFailure::Backend)?,
                );
            }
            let evidence = self.rsaes_evidence.as_ref().expect("probe succeeded");
            if !evidence.consistent() {
                return Err(PrepareFailure::Backend(format!(
                    "RSAES capability record is internally inconsistent for backend {}: contract {:?} does not match its own probe vectors",
                    evidence.backend, evidence.contract
                )));
            }
            let mut prepared = PreparedPair::try_prepare_profile(scenario, pair, evidence.contract)
                .map_err(PrepareFailure::Invalid)?;
            prepared.metadata.rsaes_evidence = Some(evidence.clone());
            return Ok(prepared);
        }
        if crate::expectation::is_partial_cfb(scenario) {
            // Partial final CFB blocks: the two supported backends return
            // different chaining values (ivOut suffix); the exact contract is
            // selected by fixed, independently computed capability probes.
            if self.sym_evidence.is_none() {
                let backend = self.backend.clone();
                self.sym_evidence = Some(
                    crate::expectation::chaining_probe(self, scenario, &backend)
                        .map_err(PrepareFailure::Backend)?,
                );
            }
            let evidence = self.sym_evidence.as_ref().expect("probe succeeded");
            if !evidence.consistent() {
                return Err(PrepareFailure::Backend(format!(
                    "CFB chaining record is internally inconsistent for backend {}: contract {:?} does not match its own probe vectors",
                    evidence.backend, evidence.contract
                )));
            }
            let mut prepared =
                PreparedPair::try_prepare_chaining(scenario, pair, evidence.contract)
                    .map_err(PrepareFailure::Invalid)?;
            prepared.metadata.sym_evidence = Some(evidence.clone());
            return Ok(prepared);
        }
        PreparedPair::try_prepare(scenario, pair).map_err(PrepareFailure::Invalid)
    }

    fn isolated_functional_probe(&mut self, pair: &PreparedPair) -> Result<(), MeasureFailure> {
        let mut limits = self.probe_limits;
        limits.deadline = self.probe_deadline.or(limits.deadline);
        let mut isolated = Self::start(
            &self.executable,
            self.backend.clone(),
            None,
            &self.probe_stderr,
            limits,
        )?;
        let loaded = isolated.load(pair, LoadOrder::ClassAFirst)?;
        let result = isolated.execute_once(&loaded);
        let closed = isolated.close_checked();
        match result {
            Err(MeasureFailure::Functional { class, detail }) => Err(MeasureFailure::Functional {
                class,
                detail: format!("isolated known-failure probe; worker discarded: {detail}"),
            }),
            Err(other) => Err(other),
            Ok(responses) => {
                closed?;
                for (class, response) in responses.iter().enumerate() {
                    pair.classes[class].validate(response).map_err(|detail|MeasureFailure::Functional {class:Some(class),detail:format!("isolated probe returned a response rejected by the independent oracle: {detail}")})?;
                }
                Ok(())
            }
        }
    }

    fn label(&self) -> String {
        self.backend.label()
    }

    fn validation_records(&self) -> Vec<ValidationRecord> {
        self.validations.clone()
    }

    fn set_deadline(&mut self, deadline: Option<Instant>) {
        self.probe_deadline = deadline;
        if let Some(process) = self.process.as_mut() {
            process.set_deadline(deadline);
        }
    }

    fn info(&self) -> WorkerInfo {
        self.process
            .as_ref()
            .map(|p| p.info.clone())
            .unwrap_or_default()
    }

    fn load(
        &mut self,
        pair: &PreparedPair,
        order: LoadOrder,
    ) -> Result<LoadedPair, MeasureFailure> {
        let expected = [
            pair.classes[0].expected_response.clone(),
            pair.classes[1].expected_response.clone(),
        ];
        let masks = [pair.classes[0].mask.clone(), pair.classes[1].mask.clone()];
        if pair.scenario.is_control() {
            let resolved = pair.resolve(order);
            let mut loaded = LoadedPair::plain(order, resolved.measured, expected);
            loaded.masks = masks;
            return Ok(loaded);
        }
        let previous = std::mem::take(&mut self.loaded_handles);
        for handle in previous {
            let result = self.process()?.exec(&tpm::flush_context(handle));
            match result {
                Ok((0, response)) if tpm::expect_success(&response).is_ok() => {}
                Ok((rc, response)) => {
                    return Err(MeasureFailure::Infrastructure {
                        detail: format!(
                            "FlushContext({handle:08x}) failed: rc {rc:08x} {}",
                            hex::encode(response)
                        ),
                    });
                }
                Err(error) => return self.fail(error),
            }
        }
        let resolved = pair.resolve(order);
        let mut responses = Vec::new();
        for step in &resolved.setup {
            let mut command = step.command.clone();
            apply_patches(&mut command, &step.patches, &responses)
                .map_err(|detail| MeasureFailure::Infrastructure { detail })?;
            let (rc, response) = match self.process()?.exec(&command) {
                Ok(reply) => reply,
                Err(error) => return self.fail(error),
            };
            if rc != 0 {
                return Err(MeasureFailure::Infrastructure {
                    detail: format!("TPMLIB_Process returned {rc:08x} for {}", step.label),
                });
            }
            if let Err(error) = tpm::expect_success(&response) {
                return Err(MeasureFailure::Functional {
                    class: None,
                    detail: format!("{} failed: {error}", step.label),
                });
            }
            if let Some(expected_handle) = step.expected_handle {
                let actual = tpm::loaded_handle(&response).ok();
                if actual != Some(expected_handle) {
                    return Err(MeasureFailure::Infrastructure {
                        detail: format!(
                            "{} returned handle {actual:08x?}, layout expects {expected_handle:08x}",
                            step.label
                        ),
                    });
                }
                if expected_handle & 0xff00_0000 == tpm::FIRST_TRANSIENT_HANDLE {
                    self.loaded_handles.push(expected_handle);
                }
            }
            responses.push(response);
        }
        let mut commands = resolved.measured.clone();
        for (command, patches) in commands.iter_mut().zip(&resolved.patches) {
            apply_patches(command, patches, &responses)
                .map_err(|detail| MeasureFailure::Infrastructure { detail })?;
        }
        Ok(LoadedPair {
            order,
            handles: match resolved.class_handles {
                [Some(a), Some(b)] => Some([a, b]),
                _ => None,
            },
            commands,
            expected,
            masks,
            posts: resolved.post.clone(),
            validations: [
                pair.classes[0].validation.clone(),
                pair.classes[1].validation.clone(),
            ],
        })
    }

    fn measure(
        &mut self,
        loaded: &LoadedPair,
        rounds: usize,
        warmup: usize,
        seed: u64,
    ) -> Result<RawBatch, MeasureFailure> {
        let reply = self.process()?.measure(
            rounds,
            seed,
            warmup,
            [&loaded.commands[0], &loaded.commands[1]],
            [&loaded.expected[0], &loaded.expected[1]],
            [&loaded.masks[0], &loaded.masks[1]],
            [loaded.posts[0].as_ref(), loaded.posts[1].as_ref()],
        );
        let needs_cleanup = loaded.posts.iter().any(Option::is_some);
        match reply {
            Ok(MeasureReply::Samples {
                class,
                order,
                nv_stores_measured,
                cleanup,
                ..
            }) => {
                if nv_stores_measured != 0 {
                    return Err(MeasureFailure::Infrastructure {
                        detail: format!("{nv_stores_measured} NV stores during timed executions"),
                    });
                }
                if needs_cleanup && !cleanup.recovered() {
                    let detail = format!(
                        "the worker reported cleanup {cleanup:?} for a measurement whose classes create TPM state"
                    );
                    self.unrecovered = Some(detail.clone());
                    return Err(MeasureFailure::Infrastructure { detail });
                }
                let [class0, class1] = class;
                Ok(RawBatch {
                    seed,
                    order,
                    class0,
                    class1,
                    nv_stores_measured,
                })
            }
            Ok(MeasureReply::Mismatch {
                class,
                tpmlib_rc,
                response,
                cleanup,
                ..
            }) => {
                if tpmlib_rc == crate::worker::PROGRAM_FAILED_RC {
                    self.unrecovered =
                        Some("command program failed and poisoned the worker".into());
                }
                let mut detail = if tpmlib_rc == POST_FAILED_RC {
                    "the cleanup command after the measured command failed".to_string()
                } else {
                    format!(
                        "unexpected response (TPMLIB_Process {tpmlib_rc:08x}): {}",
                        hex::encode(&response)
                    )
                };
                if needs_cleanup && !cleanup.recovered() {
                    let reason = format!(
                        "the worker reported cleanup {cleanup:?}, so its TPM state is not known to be restored and it will not be reused"
                    );
                    detail = format!("{detail}; {reason}");
                    self.unrecovered = Some(reason);
                }
                Err(MeasureFailure::Functional {
                    class: Some(class),
                    detail,
                })
            }
            Err(error) => self.fail(error),
        }
    }

    fn execute_once(&mut self, loaded: &LoadedPair) -> Result<[Vec<u8>; 2], MeasureFailure> {
        let mut out: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        #[allow(clippy::needless_range_loop)]
        for class in 0..2 {
            match self.process()?.exec(&loaded.commands[class]) {
                Ok((0, response)) => out[class] = response,
                Ok((rc, response)) => {
                    if rc == crate::worker::PROGRAM_FAILED_RC {
                        self.unrecovered =
                            Some("command program failed and poisoned the worker".into());
                    }
                    return Err(MeasureFailure::Functional {
                        class: Some(class),
                        detail: format!(
                            "TPMLIB_Process returned {rc:08x}: {}",
                            hex::encode(response)
                        ),
                    });
                }
                Err(error) => return self.fail(error),
            }
            let validated = self.run_validation(class, loaded, &out[class].clone());
            let created_resource = tpm::response_code(&out[class]) == Ok(0);
            let recovered = if created_resource {
                self.run_cleanup(class, loaded)
            } else {
                Ok(())
            };
            match (validated, recovered) {
                (Ok(()), Ok(())) => {}
                (Err(failure), Ok(())) => return Err(failure),
                (Ok(()), Err(failure)) => {
                    self.unrecovered = Some(failure.to_string());
                    return Err(failure);
                }
                (Err(failure), Err(cleanup)) => {
                    self.unrecovered = Some(cleanup.to_string());
                    let detail = format!(
                        "{failure}; the worker state could not be restored afterwards ({cleanup}), so it will not be reused"
                    );
                    return Err(match failure {
                        MeasureFailure::Functional { class, .. } => {
                            MeasureFailure::Functional { class, detail }
                        }
                        MeasureFailure::Infrastructure { .. } => {
                            MeasureFailure::Infrastructure { detail }
                        }
                        MeasureFailure::Timeout {
                            operation,
                            campaign_deadline,
                            ..
                        } => MeasureFailure::Timeout {
                            operation,
                            campaign_deadline,
                            detail,
                        },
                    });
                }
            }
        }
        Ok(out)
    }
}

pub type EffectFn = fn(&PreparedPair, usize) -> u64;

pub struct FixtureMeasurer {
    pub label: String,
    pub base: u64,
    pub noise: u64,
    pub effect: EffectFn,
    pub fail_when: Option<fn(&PreparedPair) -> Option<MeasureFailure>>,
    pub corrupt_response: Option<fn(&PreparedPair, usize, &mut Vec<u8>)>,
    pub info_extra: Vec<(String, String)>,
    pub batches: usize,
    pub executions: usize,
    current: Option<PreparedPair>,
}

impl FixtureMeasurer {
    pub fn new(label: &str, effect: EffectFn) -> Self {
        Self {
            label: label.into(),
            base: 100_000,
            noise: 4000,
            effect,
            fail_when: None,
            corrupt_response: None,
            info_extra: Vec::new(),
            batches: 0,
            executions: 0,
            current: None,
        }
    }
}

pub fn popcount_tail_effect(pair: &PreparedPair, class: usize) -> u64 {
    let bytes: [u8; crate::scalar::SCALAR_BYTES] = pair
        .pair
        .class(class)
        .try_into()
        .expect("fixture effect needs 66-byte inputs");
    crate::scenario::masked_tail_bits(&bytes) * 400
}

pub fn no_effect(_pair: &PreparedPair, _class: usize) -> u64 {
    0
}

impl Measurer for FixtureMeasurer {
    fn label(&self) -> String {
        self.label.clone()
    }

    fn info(&self) -> WorkerInfo {
        let mut info = WorkerInfo::new();
        info.insert("backend".into(), format!("fixture {}", self.label));
        info.insert("session".into(), format!("fixture-{}", self.label));
        for (key, value) in &self.info_extra {
            info.insert(key.clone(), value.clone());
        }
        info
    }

    fn load(
        &mut self,
        pair: &PreparedPair,
        order: LoadOrder,
    ) -> Result<LoadedPair, MeasureFailure> {
        if let Some(check) = self.fail_when
            && let Some(failure) = check(pair)
        {
            return Err(failure);
        }
        self.current = Some(pair.clone());
        let resolved = pair.resolve(order);
        Ok(LoadedPair {
            order,
            handles: match resolved.class_handles {
                [Some(a), Some(b)] => Some([a, b]),
                _ => None,
            },
            commands: resolved.measured,
            expected: [
                pair.classes[0].expected_response.clone(),
                pair.classes[1].expected_response.clone(),
            ],
            masks: [pair.classes[0].mask.clone(), pair.classes[1].mask.clone()],
            posts: resolved.post,
            validations: [
                pair.classes[0].validation.clone(),
                pair.classes[1].validation.clone(),
            ],
        })
    }

    fn measure(
        &mut self,
        _loaded: &LoadedPair,
        rounds: usize,
        _warmup: usize,
        seed: u64,
    ) -> Result<RawBatch, MeasureFailure> {
        let pair = self
            .current
            .as_ref()
            .ok_or_else(|| MeasureFailure::Infrastructure {
                detail: "fixture measured before load".into(),
            })?;
        self.batches += 1;
        let mut rng = SplitMix::new(seed);
        let mut order = String::with_capacity(rounds);
        let mut class = [Vec::with_capacity(rounds), Vec::with_capacity(rounds)];
        let effects = [(self.effect)(pair, 0), (self.effect)(pair, 1)];
        for _ in 0..rounds {
            order.push(if rng.next_u64() & 1 == 1 { '1' } else { '0' });
            for (c, samples) in class.iter_mut().enumerate() {
                samples.push(self.base + effects[c] + rng.next_u64() % self.noise);
            }
        }
        let [class0, class1] = class;
        Ok(RawBatch {
            seed,
            order,
            class0,
            class1,
            nv_stores_measured: 0,
        })
    }

    fn execute_once(&mut self, loaded: &LoadedPair) -> Result<[Vec<u8>; 2], MeasureFailure> {
        self.executions += 1;
        let mut responses = loaded.expected.clone();
        if let (Some(corrupt), Some(pair)) = (self.corrupt_response, self.current.as_ref()) {
            for (class, response) in responses.iter_mut().enumerate() {
                corrupt(pair, class, response);
            }
        }
        Ok(responses)
    }
}
