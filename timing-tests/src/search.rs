use std::borrow::Cow;
use std::cell::RefCell;
use std::fs;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use libafl::corpus::ondisk::OnDiskMetadataFormat;
use libafl::corpus::{Corpus, CorpusId, InMemoryCorpus, InMemoryOnDiskCorpus, Testcase};
use libafl::events::NopEventManager;
use libafl::executors::{Executor, ExitKind, HasObservers};
use libafl::feedbacks::{CrashFeedback, Feedback, StateInitializer};
use libafl::fuzzer::{Evaluator, Fuzzer, StdFuzzer};
use libafl::inputs::{BytesInput, HasMutatorBytes};
use libafl::mutators::{
    BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteRandMutator, BytesCopyMutator, CrossoverReplaceMutator,
    HavocScheduledMutator, MutationResult, Mutator, QwordAddMutator,
};
use libafl::observers::Observer;
use libafl::schedulers::Scheduler;
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, HasExecutions, HasRand, StdState};
use libafl::{Error, HasMetadata};
use libafl_bolts::rands::{Rand, StdRand};
use libafl_bolts::tuples::{Handle, Handled, MatchNameRef, RefIndexable, tuple_list};
use libafl_bolts::{Named, impl_serdeany};
use serde::{Deserialize, Serialize};

use crate::artifacts::display_label;
use crate::identity::sha256_bytes;
use crate::measure::{LoadOrder, MeasureFailure, Measurer, RawBatch};
use crate::scalar::{
    PAIR_BYTES, SCALAR_BYTES, Scalar521, ScalarPair, offset, order_minus, power_of_two,
};
use crate::scenario::{PreparedPair, PublicMetadata, Scenario, SeedKind, SplitMix, seeds};
use crate::stats::{BatchStats, Score, StatConfig, batch_stats, first_batch_passes, score};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchConfig {
    pub scenario: Scenario,
    pub seed: u64,
    pub max_evaluations: usize,
    pub max_duration_s: u64,
    pub samples_per_class: usize,
    pub warmup: usize,
    pub stats: StatConfig,
    pub max_candidates: usize,
    pub random_seed_pairs: usize,
    pub stage_max_iterations: usize,
    pub mutation_stack_pow: usize,
    pub timing_feedback: bool,
}

impl SearchConfig {
    pub fn sha256(&self) -> String {
        sha256_bytes(&serde_json::to_vec(self).unwrap())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Origin {
    Seed {
        name: String,
        seed_kind: SeedKind,
    },
    Mutation {
        parent_corpus_id: Option<usize>,
        parent_evaluation: Option<usize>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub evaluation: usize,
    pub origin: Origin,
    pub input_hex: String,
    pub load_order: Option<LoadOrder>,
    pub handles: Option<[u32; 2]>,
    pub batches: Vec<BatchStats>,
    #[serde(skip)]
    pub raw: Vec<RawBatch>,
    pub failure: Option<MeasureFailure>,
    pub invalid: Option<String>,
    pub score: Score,
    pub public_metadata: Option<PublicMetadata>,
    pub elapsed_s: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub candidate: bool,
    pub seed_met_criteria: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HistoryEntry {
    #[serde(flatten)]
    pub observation: Observation,
    pub decision: Decision,
}

#[derive(Debug, Default)]
pub struct SearchLog {
    pub evaluations: usize,
    pub next_origin: Option<Origin>,
    pub history: Vec<HistoryEntry>,
    pub raw: Vec<(usize, Vec<RawBatch>)>,
    pub rejected_mutations: u64,
    pub unchanged_mutations: u64,
    pub stop_reason: Option<String>,
    pub infrastructure_failure: Option<String>,
    pub interrupted_operation: Option<String>,
}

pub type SharedLog = Rc<RefCell<SearchLog>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingObserver {
    name: Cow<'static, str>,
    pub observation: Option<Observation>,
}

impl TimingObserver {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("timing"),
            observation: None,
        }
    }
}

impl Default for TimingObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for TimingObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S> Observer<I, S> for TimingObserver {
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.observation = None;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMetadata {
    pub evaluation: usize,
    pub selection_score: f64,
    pub score: Score,
    pub candidate: bool,
    pub origin: Origin,
    pub reason: String,
}

impl_serdeany!(TimingMetadata);

pub struct TimingExecutor<M> {
    measurer: M,
    observers: (TimingObserver, ()),
    config: SearchConfig,
    log: SharedLog,
    rng: SplitMix,
    deadline: Instant,
}

impl<M: Measurer> TimingExecutor<M> {
    pub fn new(mut measurer: M, config: SearchConfig, log: SharedLog) -> Self {
        let deadline = Instant::now() + Duration::from_secs(config.max_duration_s);
        measurer.set_deadline(Some(deadline));
        Self {
            measurer,
            observers: tuple_list!(TimingObserver::new()),
            rng: SplitMix::new(config.seed ^ 0x7469_6d69_6e67),
            deadline,
            config,
            log,
        }
    }

    pub fn into_measurer(self) -> M {
        self.measurer
    }

    fn evaluate(
        &mut self,
        prepared: &PreparedPair,
        observation: &mut Observation,
    ) -> Result<(), MeasureFailure> {
        let order = LoadOrder::from_bit(self.rng.next_u64() & 1 == 1);
        observation.load_order = Some(order);
        let loaded = self.measurer.load(prepared, order)?;
        observation.handles = loaded.handles;
        let batches = 1 + self.config.stats.confirm_batches;
        for index in 0..batches {
            let seed = self.rng.next_u64();
            let raw = self.measurer.measure(
                &loaded,
                self.config.samples_per_class,
                if index == 0 { self.config.warmup } else { 0 },
                seed,
            )?;
            let stats = batch_stats(&raw.class0, &raw.class1, self.config.stats.crop_percentile)
                .ok_or_else(|| MeasureFailure::Infrastructure {
                    detail: "batch too small for statistics".into(),
                })?;
            observation.raw.push(raw);
            let passes = first_batch_passes(&stats, &self.config.stats);
            let sign_flip = observation
                .batches
                .first()
                .is_some_and(|first| first.t.signum() != stats.t.signum());
            observation.batches.push(stats);
            if !passes || sign_flip {
                break;
            }
        }
        observation.score = score(&observation.batches, &self.config.stats);
        Ok(())
    }
}

impl<M> HasObservers for TimingExecutor<M> {
    type Observers = (TimingObserver, ());

    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        RefIndexable::from(&self.observers)
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        RefIndexable::from(&mut self.observers)
    }
}

impl<M, EM, S, Z> Executor<EM, BytesInput, S, Z> for TimingExecutor<M>
where
    M: Measurer,
    S: HasCorpus<BytesInput> + HasExecutions,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut S,
        _mgr: &mut EM,
        input: &BytesInput,
    ) -> Result<ExitKind, Error> {
        let (evaluation, origin) = {
            let mut log = self.log.borrow_mut();
            if log.evaluations >= self.config.max_evaluations {
                log.stop_reason = Some(format!(
                    "evaluation budget of {} reached",
                    self.config.max_evaluations
                ));
                return Err(Error::shutting_down());
            }
            if Instant::now() >= self.deadline {
                log.stop_reason = Some(format!(
                    "duration budget of {} s reached",
                    self.config.max_duration_s
                ));
                return Err(Error::shutting_down());
            }
            let origin = match log.next_origin.take() {
                Some(origin) => origin,
                None => {
                    let parent = *state.corpus().current();
                    let parent_evaluation = parent.and_then(|id| {
                        state.corpus().get(id).ok().and_then(|cell| {
                            cell.borrow()
                                .metadata::<TimingMetadata>()
                                .ok()
                                .map(|m| m.evaluation)
                        })
                    });
                    Origin::Mutation {
                        parent_corpus_id: parent.map(usize::from),
                        parent_evaluation,
                    }
                }
            };
            let evaluation = log.evaluations;
            log.evaluations += 1;
            (evaluation, origin)
        };
        *state.executions_mut() += 1;
        let started = Instant::now();
        let bytes = input.mutator_bytes();
        let mut observation = Observation {
            evaluation,
            origin,
            input_hex: hex::encode(bytes),
            load_order: None,
            handles: None,
            batches: Vec::new(),
            raw: Vec::new(),
            failure: None,
            invalid: None,
            score: Score::BelowThreshold {
                abs_t: 0.0,
                relative_percent: 0.0,
            },
            public_metadata: None,
            elapsed_s: 0.0,
        };
        let mut exit = ExitKind::Ok;
        match ScalarPair::from_bytes(bytes) {
            Err(error) => observation.invalid = Some(error.to_string()),
            Ok(pair) => {
                let prepared = PreparedPair::prepare(self.config.scenario, pair);
                observation.public_metadata = Some(prepared.metadata.clone());
                if let Err(failure) = self.evaluate(&prepared, &mut observation) {
                    if let MeasureFailure::Timeout {
                        operation,
                        campaign_deadline: true,
                        detail,
                    } = &failure
                    {
                        let operation = operation.clone();
                        let detail = detail.clone();
                        observation.failure = Some(failure);
                        observation.elapsed_s = started.elapsed().as_secs_f64();
                        let mut log = self.log.borrow_mut();
                        log.interrupted_operation = Some(format!(
                            "evaluation {evaluation}: {operation} interrupted by the campaign deadline; worker terminated ({detail})"
                        ));
                        log.stop_reason = Some(format!(
                            "duration budget of {} s reached during {operation} of evaluation {evaluation}",
                            self.config.max_duration_s
                        ));
                        log.history.push(HistoryEntry {
                            observation,
                            decision: Decision {
                                candidate: false,
                                seed_met_criteria: false,
                                reason: format!(
                                    "incomplete: campaign deadline reached during {operation}; worker terminated; not a timing result"
                                ),
                            },
                        });
                        return Err(Error::shutting_down());
                    }
                    if let MeasureFailure::Infrastructure { detail }
                    | MeasureFailure::Timeout { detail, .. } = &failure
                    {
                        let detail = detail.clone();
                        observation.failure = Some(failure);
                        observation.elapsed_s = started.elapsed().as_secs_f64();
                        let mut log = self.log.borrow_mut();
                        log.infrastructure_failure = Some(detail.clone());
                        log.history.push(HistoryEntry {
                            observation,
                            decision: Decision {
                                candidate: false,
                                seed_met_criteria: false,
                                reason: format!(
                                    "infrastructure failure, campaign aborted: {detail}"
                                ),
                            },
                        });
                        return Err(Error::illegal_state(detail));
                    }
                    observation.failure = Some(failure);
                    exit = ExitKind::Crash;
                }
            }
        }
        observation.elapsed_s = started.elapsed().as_secs_f64();
        if exit == ExitKind::Crash {
            let mut log = self.log.borrow_mut();
            log.history.push(HistoryEntry {
                observation: observation.clone(),
                decision: Decision {
                    candidate: false,
                    seed_met_criteria: false,
                    reason: "functional failure: recorded as a LibAFL objective, never as a timing candidate".into(),
                },
            });
        }
        self.observers.0.observation = Some(observation);
        Ok(exit)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FeedbackState {
    pub best: Option<f64>,
    pub retained: usize,
}

pub fn decide(
    observation: &Observation,
    exit_ok: bool,
    enabled: bool,
    config: &SearchConfig,
    state: &FeedbackState,
) -> Decision {
    let reject = |reason: String| Decision {
        candidate: false,
        seed_met_criteria: false,
        reason,
    };
    if !exit_ok || observation.failure.is_some() {
        return reject("functional failure: excluded from timing evaluation".into());
    }
    if let Some(invalid) = &observation.invalid {
        return reject(format!("invalid scalar pair: {invalid}"));
    }
    let is_seed = matches!(observation.origin, Origin::Seed { .. });
    if !enabled {
        return reject(format!(
            "timing feedback disabled (search score {:.3} recorded only)",
            observation.score.ranking_value()
        ));
    }
    let threshold = config.stats.t_threshold;
    match observation.score {
        Score::Confirmed {
            score,
            min_abs_t,
            sign,
        } => {
            if is_seed {
                return Decision {
                    candidate: false,
                    seed_met_criteria: true,
                    reason: format!(
                        "seed forced into corpus; its batches met the timing criteria (relative median difference {score:.3}%, min |t| {min_abs_t:.2}, sign {sign})"
                    ),
                };
            }
            if state.retained >= config.max_candidates {
                return reject(format!(
                    "confirmed effect {score:.3}% but the candidate bound of {} is reached",
                    config.max_candidates
                ));
            }
            if let Some(best) = state.best {
                let needed = best * (1.0 + config.stats.min_improvement);
                if score < needed {
                    return reject(format!(
                        "confirmed effect {score:.3}% (min |t| {min_abs_t:.2}) does not beat best known {best:.3}% by the required {:.0}% (needs {needed:.3}%)",
                        config.stats.min_improvement * 100.0
                    ));
                }
            }
            Decision {
                candidate: true,
                seed_met_criteria: false,
                reason: format!(
                    "retained: all {} batches crossed |t| >= {threshold} with sign {sign} (min |t| {min_abs_t:.2}); relative median difference {score:.3}% improves on best known {:?}",
                    observation.batches.len(),
                    state.best.map(|b| (b * 1000.0).round() / 1000.0)
                ),
            }
        }
        Score::BelowThreshold {
            abs_t,
            relative_percent,
        } => reject(format!(
            "first batch |t| {abs_t:.2} below threshold {threshold} (relative median difference {relative_percent:.3}%){}",
            if is_seed {
                " (seed forced into corpus)"
            } else {
                ""
            }
        )),
        Score::NotConfirmed { batches, min_abs_t } => reject(format!(
            "not confirmed: min |t| {min_abs_t:.2} over {batches} batches{}",
            if is_seed {
                " (seed forced into corpus)"
            } else {
                ""
            }
        )),
        Score::SignChanged => reject(format!(
            "confirmation batch changed the sign of t{}",
            if is_seed {
                " (seed forced into corpus)"
            } else {
                ""
            }
        )),
    }
}

pub struct TimingFeedback {
    enabled: bool,
    config: SearchConfig,
    handle: Handle<TimingObserver>,
    log: SharedLog,
    state: FeedbackState,
    last: Option<TimingMetadata>,
}

impl TimingFeedback {
    pub fn new(observer: &TimingObserver, config: &SearchConfig, log: SharedLog) -> Self {
        Self {
            enabled: config.timing_feedback,
            config: config.clone(),
            handle: observer.handle(),
            log,
            state: FeedbackState {
                best: None,
                retained: 0,
            },
            last: None,
        }
    }
}

impl Named for TimingFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("TimingFeedback");
        &NAME
    }
}

impl<S> StateInitializer<S> for TimingFeedback {}

impl<EM, OT, S> Feedback<EM, BytesInput, OT, S> for TimingFeedback
where
    OT: MatchNameRef,
{
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &BytesInput,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let observation = observers
            .get(&self.handle)
            .and_then(|o| o.observation.clone())
            .ok_or_else(|| Error::illegal_state("timing observation missing"))?;
        let decision = decide(
            &observation,
            *exit_kind == ExitKind::Ok,
            self.enabled,
            &self.config,
            &self.state,
        );
        if decision.candidate || decision.seed_met_criteria {
            let value = observation.score.ranking_value();
            self.state.best = Some(self.state.best.map_or(value, |b| b.max(value)));
        }
        if decision.candidate {
            self.state.retained += 1;
        }
        let selection_score = if self.enabled {
            observation.score.ranking_value()
        } else {
            0.0
        };
        self.last = Some(TimingMetadata {
            evaluation: observation.evaluation,
            selection_score,
            score: observation.score.clone(),
            candidate: decision.candidate,
            origin: observation.origin.clone(),
            reason: decision.reason.clone(),
        });
        let mut log = self.log.borrow_mut();
        let raw = observation.raw.clone();
        log.raw.push((observation.evaluation, raw));
        if *exit_kind == ExitKind::Ok {
            log.history.push(HistoryEntry {
                observation,
                decision: decision.clone(),
            });
        }
        Ok(decision.candidate)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<BytesInput>,
    ) -> Result<(), Error> {
        if let Some(metadata) = self.last.take() {
            testcase.add_metadata(metadata);
        }
        Ok(())
    }
}

pub const ELITE_WEIGHT: f64 = 20.0;

pub fn selection_weight(score: f64, best: f64) -> f64 {
    if score > 0.0 && best > 0.0 {
        1.0 + (ELITE_WEIGHT - 1.0) * (score / best).powi(2)
    } else {
        1.0
    }
}

#[derive(Debug, Default)]
pub struct TimingWeightedScheduler {
    entries: Vec<(CorpusId, f64)>,
}

impl<S> Scheduler<BytesInput, S> for TimingWeightedScheduler
where
    S: HasCorpus<BytesInput> + HasRand,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        let current = *state.corpus().current();
        let score = {
            let mut testcase = state.corpus().get(id)?.borrow_mut();
            testcase.set_parent_id_optional(current);
            testcase
                .metadata::<TimingMetadata>()
                .map(|m| m.selection_score)
                .unwrap_or(0.0)
        };
        self.entries.push((id, score));
        Ok(())
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        if self.entries.is_empty() {
            return Err(Error::empty("timing corpus is empty"));
        }
        let best = self.entries.iter().map(|(_, s)| *s).fold(0.0, f64::max);
        let weights: Vec<f64> = self
            .entries
            .iter()
            .map(|(_, s)| selection_weight(*s, best))
            .collect();
        let total: f64 = weights.iter().sum();
        let threshold = state.rand_mut().next_float() * total;
        let mut cumulative = 0.0;
        let mut chosen = self.entries[self.entries.len() - 1].0;
        for ((id, _), weight) in self.entries.iter().zip(&weights) {
            cumulative += weight;
            if cumulative >= threshold {
                chosen = *id;
                break;
            }
        }
        <Self as Scheduler<BytesInput, S>>::set_current_scheduled(self, state, Some(chosen))?;
        Ok(chosen)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        *state.corpus_mut().current_mut() = next_id;
        Ok(())
    }
}

fn nz(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("non-zero")
}

pub struct ScalarBoundaryMutator {
    name: Cow<'static, str>,
}

impl ScalarBoundaryMutator {
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("ScalarBoundaryMutator"),
        }
    }
}

impl Default for ScalarBoundaryMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for ScalarBoundaryMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

pub const LIMB_EXPONENTS: [usize; 9] = [64, 128, 192, 256, 320, 384, 448, 512, 520];

pub fn boundary_scalar(
    op: usize,
    r: u64,
    current: &[u8; SCALAR_BYTES],
    other: &[u8; SCALAR_BYTES],
) -> [u8; SCALAR_BYTES] {
    match op {
        0 => {
            let mut out = [0u8; SCALAR_BYTES];
            out[SCALAR_BYTES - 2..].copy_from_slice(&((r % 0xffff) as u16 + 1).to_be_bytes());
            out
        }
        1 => order_minus((r % 0xffff) as u128 + 1),
        2 => {
            let zeros = 1 + (r % 16) as usize;
            let mut out = *current;
            out[..zeros].fill(0);
            out
        }
        3 => {
            let exponent = LIMB_EXPONENTS[(r % LIMB_EXPONENTS.len() as u64) as usize];
            let delta = ((r >> 8) % 3) as i64 - 1;
            offset(power_of_two(exponent), delta)
        }
        4 => {
            let mut out = *other;
            let bit = (r % 521) as usize;
            out[SCALAR_BYTES - 1 - bit / 8] ^= 1 << (bit % 8);
            out
        }
        _ => {
            let mut out = *current;
            out[0] ^= 0x01;
            out
        }
    }
}

impl<S> Mutator<BytesInput, S> for ScalarBoundaryMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let bytes = input.mutator_bytes_mut();
        if bytes.len() != PAIR_BYTES {
            return Ok(MutationResult::Skipped);
        }
        let class = state.rand_mut().below(nz(2));
        let op = state.rand_mut().below(nz(6));
        let r = state.rand_mut().next();
        let (first, second) = bytes.split_at_mut(SCALAR_BYTES);
        let (target, other) = if class == 0 {
            (first, second)
        } else {
            (second, first)
        };
        let current: [u8; SCALAR_BYTES] = (&*target).try_into().unwrap();
        let other: [u8; SCALAR_BYTES] = (&*other).try_into().unwrap();
        target.copy_from_slice(&boundary_scalar(op, r, &current, &other));
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

pub struct ValidPairMutator<M> {
    inner: M,
    log: SharedLog,
    name: Cow<'static, str>,
}

impl<M> ValidPairMutator<M> {
    pub fn new(inner: M, log: SharedLog) -> Self {
        Self {
            inner,
            log,
            name: Cow::Borrowed("ValidPairMutator"),
        }
    }
}

impl<M> Named for ValidPairMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<M, S> Mutator<BytesInput, S> for ValidPairMutator<M>
where
    M: Mutator<BytesInput, S>,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        let original = input.mutator_bytes().to_vec();
        if self.inner.mutate(state, input)? == MutationResult::Skipped {
            return Ok(MutationResult::Skipped);
        }
        let mutated = input.mutator_bytes();
        if mutated == original.as_slice() {
            self.log.borrow_mut().unchanged_mutations += 1;
            return Ok(MutationResult::Skipped);
        }
        if ScalarPair::from_bytes(mutated).is_err() {
            self.log.borrow_mut().rejected_mutations += 1;
            *input = BytesInput::new(original);
            return Ok(MutationResult::Skipped);
        }
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateKind {
    AdaptiveDiscovery,
    SeededDiagnostic,
}

pub const CANDIDATE_FORMAT: &str = "tpms-timing-candidate/v2";
pub const LEGACY_CANDIDATE_FORMAT: &str = "tpms-timing-candidate/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Orientation {
    AsRecorded,
    Reversed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub label: String,
    pub kind: CandidateKind,
    pub search_backend: Option<String>,
    pub search_run: Option<PathBuf>,
    pub campaign_seed: u64,
    pub evaluation: Option<usize>,
    pub origin: Origin,
    pub retention_reason: String,
    pub search_score: Option<Score>,
    pub config_sha256: Option<String>,
    pub source_file: Option<PathBuf>,
    pub source_sha256: Option<String>,
    pub orientation: Orientation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateFile {
    pub format: String,
    pub id: String,
    pub scenario: Scenario,
    pub kind: CandidateKind,
    pub search_backend: Option<String>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub scalar_a: Vec<u8>,
    #[serde(with = "crate::scalar::hex_bytes")]
    pub scalar_b: Vec<u8>,
    pub campaign_seed: u64,
    pub evaluation: Option<usize>,
    pub origin: Origin,
    pub retention_reason: String,
    pub search_score: Option<Score>,
    pub search_batches: Vec<BatchStats>,
    pub search_raw: Vec<RawBatch>,
    pub search_run: Option<PathBuf>,
    pub config_sha256: Option<String>,
    pub public_metadata: PublicMetadata,
    #[serde(default)]
    pub content_sha256: Option<String>,
    #[serde(default)]
    pub provenance: Vec<Provenance>,
}

impl CandidateFile {
    pub fn pair(&self) -> Result<ScalarPair, String> {
        if self.format != CANDIDATE_FORMAT && self.format != LEGACY_CANDIDATE_FORMAT {
            return Err(format!(
                "unsupported candidate format {:?} in candidate {}; this tool reads {CANDIDATE_FORMAT} and {LEGACY_CANDIDATE_FORMAT}; regenerate the candidate with `tpms-timing-tests search` or convert it to one of those formats",
                self.format,
                display_label(&self.id)
            ));
        }
        let mut bytes = self.scalar_a.clone();
        bytes.extend_from_slice(&self.scalar_b);
        ScalarPair::from_bytes(&bytes)
            .map_err(|e| format!("candidate {}: {e}", display_label(&self.id)))
    }

    pub fn content_sha256(&self) -> Result<String, String> {
        Ok(crate::artifacts::content_sha256(
            self.scenario,
            &self.pair()?,
        ))
    }

    pub fn artifact_stem(&self) -> Result<String, String> {
        Ok(crate::artifacts::artifact_stem(
            self.scenario,
            &self.pair()?,
        ))
    }

    pub fn validate(&self) -> Result<(), String> {
        let actual = self.content_sha256()?;
        if let Some(recorded) = &self.content_sha256
            && *recorded != actual
        {
            return Err(format!(
                "candidate {} records content_sha256 {recorded} but its scenario and scalars hash to {actual}",
                display_label(&self.id)
            ));
        }
        Ok(())
    }

    pub fn own_provenance(&self, source: Option<(&Path, String)>) -> Provenance {
        Provenance {
            label: self.id.clone(),
            kind: self.kind,
            search_backend: self.search_backend.clone(),
            search_run: self.search_run.clone(),
            campaign_seed: self.campaign_seed,
            evaluation: self.evaluation,
            origin: self.origin.clone(),
            retention_reason: self.retention_reason.clone(),
            search_score: self.search_score.clone(),
            config_sha256: self.config_sha256.clone(),
            source_file: source.as_ref().map(|(p, _)| p.to_path_buf()),
            source_sha256: source.map(|(_, h)| h),
            orientation: Orientation::AsRecorded,
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut candidate: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("malformed candidate {}: {e}", path.display()))?;
        candidate
            .validate()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if candidate.provenance.is_empty() {
            let provenance =
                candidate.own_provenance(Some((path, crate::identity::sha256_bytes(&bytes))));
            candidate.provenance.push(provenance);
        } else {
            for entry in &mut candidate.provenance {
                if entry.source_file.is_none() {
                    entry.source_file = Some(path.to_path_buf());
                    entry.source_sha256 = Some(crate::identity::sha256_bytes(&bytes));
                }
            }
        }
        Ok(candidate)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut stored = self.clone();
        stored.format = CANDIDATE_FORMAT.into();
        stored.content_sha256 = self.content_sha256().ok();
        if stored.provenance.is_empty() {
            stored.provenance.push(self.own_provenance(None));
        }
        crate::artifacts::write_new(path, &serde_json::to_vec_pretty(&stored).unwrap())
    }

    pub fn merge(&mut self, other: &CandidateFile) -> Result<(), String> {
        if self.scenario != other.scenario || self.content_sha256()? != other.content_sha256()? {
            return Err(
                "only candidates with identical scenario and input content can be merged".into(),
            );
        }
        let reversed = self.scalar_a != other.scalar_a;
        let mut incoming = if other.provenance.is_empty() {
            vec![other.own_provenance(None)]
        } else {
            other.provenance.clone()
        };
        for entry in &mut incoming {
            if reversed {
                entry.orientation = match entry.orientation {
                    Orientation::AsRecorded => Orientation::Reversed,
                    Orientation::Reversed => Orientation::AsRecorded,
                };
            }
            if !self.provenance.contains(entry) {
                self.provenance.push(entry.clone());
            }
        }
        if other.kind == CandidateKind::AdaptiveDiscovery {
            self.kind = CandidateKind::AdaptiveDiscovery;
        }
        Ok(())
    }
}

pub fn seeded_candidate(
    scenario: Scenario,
    name: &str,
    pair: ScalarPair,
    campaign_seed: u64,
) -> CandidateFile {
    let prepared = PreparedPair::prepare(scenario, pair);
    CandidateFile {
        format: CANDIDATE_FORMAT.into(),
        id: format!("seed-{name}"),
        scenario,
        kind: CandidateKind::SeededDiagnostic,
        search_backend: None,
        scalar_a: pair.a.bytes().to_vec(),
        scalar_b: pair.b.bytes().to_vec(),
        campaign_seed,
        evaluation: None,
        origin: Origin::Seed {
            name: name.into(),
            seed_kind: SeedKind::Boundary,
        },
        retention_reason: "explicit boundary seed pair verified as a seeded diagnostic case, not an adaptive discovery".into(),
        search_score: None,
        search_batches: Vec::new(),
        search_raw: Vec::new(),
        search_run: None,
        config_sha256: None,
        public_metadata: prepared.metadata,
        content_sha256: None,
        provenance: Vec::new(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSummary {
    pub backend: String,
    pub scenario: Scenario,
    pub evaluations: usize,
    pub seeds: usize,
    pub corpus_entries: usize,
    pub candidates: Vec<String>,
    pub seeds_meeting_criteria: Vec<String>,
    pub functional_failures: usize,
    pub rejected_invalid_mutations: u64,
    pub skipped_unchanged_mutations: u64,
    pub best_candidate_score: Option<f64>,
    pub max_seed_ranking_value: Option<f64>,
    pub score_trajectory: Vec<(usize, f64)>,
    pub stop_reason: String,
    pub infrastructure_failure: Option<String>,
    pub interrupted_operation: Option<String>,
    pub elapsed_s: f64,
    pub timing_feedback: bool,
    pub worker_info: crate::worker::WorkerInfo,
}

pub struct CampaignOutput<M> {
    pub summary: CampaignSummary,
    pub candidates: Vec<CandidateFile>,
    pub measurer: M,
}

#[derive(Debug)]
pub enum SearchError {
    Libafl(Error),
    Io(std::io::Error),
    Infrastructure(String),
}

impl std::fmt::Display for SearchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Libafl(e) => write!(f, "LibAFL error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Infrastructure(e) => write!(f, "infrastructure failure: {e}"),
        }
    }
}

impl std::error::Error for SearchError {}

impl From<Error> for SearchError {
    fn from(error: Error) -> Self {
        Self::Libafl(error)
    }
}

impl From<std::io::Error> for SearchError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

fn write_jsonl<T: Serialize>(
    path: &Path,
    items: impl IntoIterator<Item = T>,
) -> std::io::Result<()> {
    let mut file = crate::artifacts::create_new_file(path)?;
    for item in items {
        serde_json::to_writer(&mut file, &item)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

pub fn run_campaign<M: Measurer>(
    measurer: M,
    config: &SearchConfig,
    dir: &Path,
    corpus_dir: &Path,
    search_run: Option<&Path>,
) -> Result<CampaignOutput<M>, SearchError> {
    fs::create_dir_all(dir)?;
    let started = Instant::now();
    let label = measurer.label();
    let worker_info = measurer.info();
    let log: SharedLog = Rc::new(RefCell::new(SearchLog::default()));
    let mut executor = TimingExecutor::new(measurer, config.clone(), log.clone());
    let mut feedback = TimingFeedback::new(&executor.observers.0, config, log.clone());
    let mut objective = CrashFeedback::new();
    let corpus = InMemoryOnDiskCorpus::<BytesInput>::with_meta_format(
        corpus_dir,
        Some(OnDiskMetadataFormat::JsonPretty),
    )?;
    let mut state = StdState::new(
        StdRand::with_seed(config.seed),
        corpus,
        InMemoryCorpus::<BytesInput>::new(),
        &mut feedback,
        &mut objective,
    )?;
    let scheduler = TimingWeightedScheduler::default();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let mut manager = NopEventManager::new();
    let seed_list = seeds(config.seed, config.random_seed_pairs);
    let mut aborted: Option<String> = None;
    for seed in &seed_list {
        log.borrow_mut().next_origin = Some(Origin::Seed {
            name: seed.name.clone(),
            seed_kind: seed.kind.clone(),
        });
        match fuzzer.add_input(
            &mut state,
            &mut executor,
            &mut manager,
            BytesInput::new(seed.pair.to_bytes()),
        ) {
            Ok(_) => {}
            Err(Error::ShuttingDown) => break,
            Err(error) => {
                aborted = Some(error.to_string());
                break;
            }
        }
    }
    if state.corpus().count() == 0 && aborted.is_none() && log.borrow().stop_reason.is_none() {
        aborted = Some("no seed could be added to the corpus".into());
    }
    let mutator = ValidPairMutator::new(
        HavocScheduledMutator::with_max_stack_pow(
            tuple_list!(
                BitFlipMutator::new(),
                ByteFlipMutator::new(),
                ByteIncMutator::new(),
                ByteDecMutator::new(),
                ByteRandMutator::new(),
                ByteAddMutator::new(),
                ByteInterestingMutator::new(),
                QwordAddMutator::new(),
                BytesCopyMutator::new(),
                CrossoverReplaceMutator::new(),
                ScalarBoundaryMutator::new(),
                ScalarBoundaryMutator::new()
            ),
            config.mutation_stack_pow,
        ),
        log.clone(),
    );
    let mut stages = tuple_list!(StdMutationalStage::with_max_iterations(
        mutator,
        nz(config.stage_max_iterations.max(1))
    ));
    if aborted.is_none() && log.borrow().stop_reason.is_none() {
        loop {
            match fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut manager) {
                Ok(_) => {}
                Err(Error::ShuttingDown) => break,
                Err(error) => {
                    aborted = Some(error.to_string());
                    break;
                }
            }
        }
    }
    let measurer = executor.into_measurer();
    let log = Rc::try_unwrap(log)
        .map(RefCell::into_inner)
        .unwrap_or_else(|shared| std::mem::take(&mut *shared.borrow_mut()));
    write_jsonl(&dir.join("history.jsonl"), &log.history)?;
    write_jsonl(
        &dir.join("samples.jsonl"),
        log.raw.iter().map(|(evaluation, batches)| {
            serde_json::json!({"evaluation": evaluation, "batches": batches})
        }),
    )?;
    let failures: Vec<&HistoryEntry> = log
        .history
        .iter()
        .filter(|h| h.observation.failure.is_some())
        .collect();
    write_jsonl(&dir.join("functional-failures.jsonl"), &failures)?;
    let candidate_dir = dir.join("candidates");
    fs::create_dir_all(&candidate_dir)?;
    let mut candidates: Vec<CandidateFile> = Vec::new();
    let mut seed_signals: Vec<CandidateFile> = Vec::new();
    let mut seeds_meeting = Vec::new();
    let mut trajectory = Vec::new();
    let seed_signal_dir = dir.join("seed-signals");
    fs::create_dir_all(&seed_signal_dir)?;
    let add =
        |list: &mut Vec<CandidateFile>, candidate: CandidateFile| -> Result<(), SearchError> {
            let stem = candidate
                .artifact_stem()
                .map_err(SearchError::Infrastructure)?;
            match list
                .iter_mut()
                .find(|c| c.artifact_stem().ok().as_deref() == Some(stem.as_str()))
            {
                Some(existing) => existing
                    .merge(&candidate)
                    .map_err(SearchError::Infrastructure),
                None => {
                    list.push(candidate);
                    Ok(())
                }
            }
        };
    for entry in &log.history {
        if entry.decision.seed_met_criteria
            && let Origin::Seed { name, .. } = &entry.observation.origin
        {
            seeds_meeting.push(name.clone());
            let bytes = hex::decode(&entry.observation.input_hex).expect("history input is hex");
            let pair = ScalarPair::from_bytes(&bytes).expect("seed inputs are valid");
            let mut seeded = seeded_candidate(config.scenario, name, pair, config.seed);
            seeded.id = format!("{label}-seed-{name}");
            seeded.search_backend = Some(label.clone());
            seeded.evaluation = Some(entry.observation.evaluation);
            seeded.origin = entry.observation.origin.clone();
            seeded.retention_reason = format!(
                "seeded diagnostic, not an adaptive discovery: {}",
                entry.decision.reason
            );
            seeded.search_score = Some(entry.observation.score.clone());
            seeded.search_batches = entry.observation.batches.clone();
            seeded.search_run = search_run.map(Path::to_path_buf);
            seeded.config_sha256 = Some(config.sha256());
            add(&mut seed_signals, seeded)?;
        }
        if !entry.decision.candidate {
            continue;
        }
        trajectory.push((
            entry.observation.evaluation,
            entry.observation.score.ranking_value(),
        ));
        let bytes = hex::decode(&entry.observation.input_hex).expect("history input is hex");
        let pair = ScalarPair::from_bytes(&bytes).expect("candidate inputs are valid");
        let raw = log
            .raw
            .iter()
            .find(|(evaluation, _)| *evaluation == entry.observation.evaluation)
            .map(|(_, raw)| raw.clone())
            .unwrap_or_default();
        let candidate = CandidateFile {
            format: CANDIDATE_FORMAT.into(),
            id: format!("{label}-e{:05}", entry.observation.evaluation),
            scenario: config.scenario,
            kind: CandidateKind::AdaptiveDiscovery,
            search_backend: Some(label.clone()),
            scalar_a: pair.a.bytes().to_vec(),
            scalar_b: pair.b.bytes().to_vec(),
            campaign_seed: config.seed,
            evaluation: Some(entry.observation.evaluation),
            origin: entry.observation.origin.clone(),
            retention_reason: entry.decision.reason.clone(),
            search_score: Some(entry.observation.score.clone()),
            search_batches: entry.observation.batches.clone(),
            search_raw: raw,
            search_run: search_run.map(Path::to_path_buf),
            config_sha256: Some(config.sha256()),
            public_metadata: entry
                .observation
                .public_metadata
                .clone()
                .expect("valid inputs carry metadata"),
            content_sha256: None,
            provenance: Vec::new(),
        };
        add(&mut candidates, candidate)?;
    }
    for (list, target) in [
        (&candidates, &candidate_dir),
        (&seed_signals, &seed_signal_dir),
    ] {
        for candidate in list {
            let stem = candidate
                .artifact_stem()
                .map_err(SearchError::Infrastructure)?;
            candidate.save(&target.join(format!("{stem}.json")))?;
        }
    }
    let max_seed = log
        .history
        .iter()
        .filter(|h| matches!(h.observation.origin, Origin::Seed { .. }))
        .map(|h| h.observation.score.ranking_value())
        .fold(None, |acc: Option<f64>, v| {
            Some(acc.map_or(v, |a| a.max(v)))
        });
    let summary = CampaignSummary {
        backend: label,
        scenario: config.scenario,
        evaluations: log.evaluations,
        seeds: seed_list.len(),
        corpus_entries: state.corpus().count(),
        candidates: candidates.iter().map(|c| c.id.clone()).collect(),
        seeds_meeting_criteria: seeds_meeting,
        functional_failures: failures.len(),
        rejected_invalid_mutations: log.rejected_mutations,
        skipped_unchanged_mutations: log.unchanged_mutations,
        best_candidate_score: trajectory
            .iter()
            .map(|(_, s)| *s)
            .fold(None, |a: Option<f64>, v| Some(a.map_or(v, |x| x.max(v)))),
        max_seed_ranking_value: max_seed,
        score_trajectory: trajectory,
        stop_reason: aborted
            .clone()
            .map(|a| format!("aborted: {a}"))
            .or(log.stop_reason.clone())
            .unwrap_or_else(|| "stopped".into()),
        infrastructure_failure: log.infrastructure_failure.clone(),
        interrupted_operation: log.interrupted_operation.clone(),
        elapsed_s: started.elapsed().as_secs_f64(),
        timing_feedback: config.timing_feedback,
        worker_info,
    };
    crate::artifacts::write_new(
        &dir.join("summary.json"),
        &serde_json::to_vec_pretty(&summary).unwrap(),
    )?;
    if let Some(failure) = log.infrastructure_failure {
        return Err(SearchError::Infrastructure(failure));
    }
    if let Some(reason) = aborted {
        return Err(SearchError::Infrastructure(reason));
    }
    Ok(CampaignOutput {
        summary,
        candidates,
        measurer,
    })
}

pub fn valid_scalar(bytes: &[u8]) -> bool {
    Scalar521::from_slice(bytes).is_ok()
}
