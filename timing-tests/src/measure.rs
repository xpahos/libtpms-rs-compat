use std::fmt;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::scenario::{PreparedPair, Scenario, SplitMix};
use crate::tpm;
use crate::worker::{
    BackendSpec, Limits, MeasureReply, TimeoutBound, WorkerError, WorkerInfo, WorkerProcess,
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

pub trait Measurer {
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
    fn set_deadline(&mut self, _deadline: Option<Instant>) {}
}

pub struct WorkerMeasurer {
    process: Option<WorkerProcess>,
    backend: BackendSpec,
    loaded_handles: Vec<u32>,
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
            process: Some(process),
            backend,
            loaded_handles: Vec::new(),
        })
    }

    fn process(&mut self) -> Result<&mut WorkerProcess, MeasureFailure> {
        self.process
            .as_mut()
            .ok_or_else(|| MeasureFailure::Infrastructure {
                detail: "worker already failed".into(),
            })
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
    fn label(&self) -> String {
        self.backend.label()
    }

    fn set_deadline(&mut self, deadline: Option<Instant>) {
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
        if pair.scenario.is_control() {
            return Ok(LoadedPair {
                order,
                handles: None,
                commands: [pair.measured_command(0, 0), pair.measured_command(1, 0)],
                expected,
            });
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
        let mut handles = [0u32; 2];
        for class in order.classes() {
            let command = pair.load_command(class).expect("ecdh classes load objects");
            let (rc, response) = match self.process()?.exec(&command) {
                Ok(reply) => reply,
                Err(error) => return self.fail(error),
            };
            if rc != 0 {
                return Err(MeasureFailure::Infrastructure {
                    detail: format!("TPMLIB_Process returned {rc:08x} for LoadExternal"),
                });
            }
            match tpm::loaded_handle(&response) {
                Ok(handle) => {
                    handles[class] = handle;
                    self.loaded_handles.push(handle);
                }
                Err(error) => {
                    return Err(MeasureFailure::Functional {
                        class: Some(class),
                        detail: format!("LoadExternal failed: {error}"),
                    });
                }
            }
        }
        Ok(LoadedPair {
            order,
            handles: Some(handles),
            commands: [
                pair.measured_command(0, handles[0]),
                pair.measured_command(1, handles[1]),
            ],
            expected,
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
        );
        match reply {
            Ok(MeasureReply::Samples {
                class,
                order,
                nv_stores_measured,
                ..
            }) => {
                if nv_stores_measured != 0 {
                    return Err(MeasureFailure::Infrastructure {
                        detail: format!("{nv_stores_measured} NV stores during timed executions"),
                    });
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
                ..
            }) => Err(MeasureFailure::Functional {
                class: Some(class),
                detail: format!(
                    "unexpected response (TPMLIB_Process {tpmlib_rc:08x}): {}",
                    hex::encode(response)
                ),
            }),
            Err(error) => self.fail(error),
        }
    }

    fn execute_once(&mut self, loaded: &LoadedPair) -> Result<[Vec<u8>; 2], MeasureFailure> {
        let mut out: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        for (class, slot) in out.iter_mut().enumerate() {
            match self.process()?.exec(&loaded.commands[class]) {
                Ok((0, response)) => *slot = response,
                Ok((rc, _)) => {
                    return Err(MeasureFailure::Functional {
                        class: Some(class),
                        detail: format!("TPMLIB_Process returned {rc:08x}"),
                    });
                }
                Err(error) => return self.fail(error),
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
    pub batches: usize,
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
            batches: 0,
            current: None,
        }
    }
}

pub fn popcount_tail_effect(pair: &PreparedPair, class: usize) -> u64 {
    crate::scenario::masked_tail_bits(pair.pair.class(class).bytes()) * 400
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
        let handles = (pair.scenario == Scenario::EcdhP521).then_some([0x8000_0000, 0x8000_0001]);
        Ok(LoadedPair {
            order,
            handles,
            commands: [
                pair.measured_command(0, 0x8000_0000),
                pair.measured_command(1, 0x8000_0001),
            ],
            expected: [
                pair.classes[0].expected_response.clone(),
                pair.classes[1].expected_response.clone(),
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
        Ok(loaded.expected.clone())
    }
}
