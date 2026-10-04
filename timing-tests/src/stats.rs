use serde::{Deserialize, Serialize};

pub const SEARCH_STATISTIC: &str = "Per batch: Welch t-statistic between the two classes after dropping pooled samples above the crop percentile (significance gate), and the signed relative median difference (median0 - median1) / mean(median0, median1) in percent (effect size). A pair is confirmed when its initial batch and every confirmation batch reach |t| >= t_threshold with the same sign and the median difference points the same way; its score is the smallest relative median difference over those batches. Confirmed mutations are retained when the score beats the best score seen so far (seeds included) by min_improvement. The scheduler picks corpus entries with probability proportional to 1 + 19 * (score / best score in the corpus)^2, or uniformly when feedback is disabled. The effect size, not |t|, ranks pairs because |t| tracks the momentary host noise level.";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StatConfig {
    pub t_threshold: f64,
    pub crop_percentile: f64,
    pub confirm_batches: usize,
    pub min_improvement: f64,
}

impl Default for StatConfig {
    fn default() -> Self {
        Self {
            t_threshold: 4.5,
            crop_percentile: 0.9,
            confirm_batches: 1,
            min_improvement: 0.1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchStats {
    pub n: [usize; 2],
    pub kept: [usize; 2],
    pub crop_ticks: u64,
    pub mean: [f64; 2],
    pub median: [f64; 2],
    pub t: f64,
    pub relative_median_diff_percent: f64,
}

fn median(sorted: &[u64]) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] as f64 + sorted[mid] as f64) / 2.0
    } else {
        sorted[mid] as f64
    }
}

fn mean_var(values: &[u64]) -> (f64, f64) {
    let n = values.len() as f64;
    let mean = values.iter().map(|v| *v as f64).sum::<f64>() / n;
    let var = values
        .iter()
        .map(|v| (*v as f64 - mean).powi(2))
        .sum::<f64>()
        / (n - 1.0);
    (mean, var)
}

pub fn welch_t(a: &[u64], b: &[u64]) -> Option<f64> {
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    let (ma, va) = mean_var(a);
    let (mb, vb) = mean_var(b);
    let denominator = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if denominator == 0.0 {
        return Some(if ma == mb {
            0.0
        } else {
            (ma - mb).signum() * 1.0e6
        });
    }
    Some((ma - mb) / denominator)
}

pub fn batch_stats(class0: &[u64], class1: &[u64], crop_percentile: f64) -> Option<BatchStats> {
    if class0.len() < 2 || class1.len() < 2 || !(0.0..=1.0).contains(&crop_percentile) {
        return None;
    }
    let mut pooled: Vec<u64> = class0.iter().chain(class1).copied().collect();
    pooled.sort_unstable();
    let index = ((pooled.len() as f64 * crop_percentile) as usize).min(pooled.len() - 1);
    let crop = pooled[index];
    let keep = |values: &[u64]| -> Vec<u64> {
        let mut kept: Vec<u64> = values.iter().copied().filter(|v| *v <= crop).collect();
        kept.sort_unstable();
        kept
    };
    let kept0 = keep(class0);
    let kept1 = keep(class1);
    let t = welch_t(&kept0, &kept1)?;
    let medians = [median(&kept0), median(&kept1)];
    let center = (medians[0] + medians[1]) / 2.0;
    let relative = if center > 0.0 {
        (medians[0] - medians[1]) / center * 100.0
    } else {
        0.0
    };
    Some(BatchStats {
        n: [class0.len(), class1.len()],
        kept: [kept0.len(), kept1.len()],
        crop_ticks: crop,
        mean: [mean_var(&kept0).0, mean_var(&kept1).0],
        median: medians,
        t,
        relative_median_diff_percent: relative,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Score {
    BelowThreshold {
        abs_t: f64,
        relative_percent: f64,
    },
    NotConfirmed {
        batches: usize,
        min_abs_t: f64,
    },
    SignChanged,
    Confirmed {
        score: f64,
        min_abs_t: f64,
        sign: i8,
    },
}

impl Score {
    pub fn ranking_value(&self) -> f64 {
        match self {
            Self::Confirmed { score, .. } => *score,
            _ => 0.0,
        }
    }
}

pub fn first_batch_passes(stats: &BatchStats, config: &StatConfig) -> bool {
    stats.t.abs() >= config.t_threshold
}

pub fn score(batches: &[BatchStats], config: &StatConfig) -> Score {
    let Some(first) = batches.first() else {
        return Score::BelowThreshold {
            abs_t: 0.0,
            relative_percent: 0.0,
        };
    };
    if !first_batch_passes(first, config) {
        return Score::BelowThreshold {
            abs_t: first.t.abs(),
            relative_percent: first.relative_median_diff_percent,
        };
    }
    let sign = first.t.signum();
    if batches.iter().any(|b| b.t.signum() != sign) {
        return Score::SignChanged;
    }
    let min_abs_t = batches
        .iter()
        .map(|b| b.t.abs())
        .fold(f64::INFINITY, f64::min);
    if batches.len() < 1 + config.confirm_batches || min_abs_t < config.t_threshold {
        return Score::NotConfirmed {
            batches: batches.len(),
            min_abs_t,
        };
    }
    let effect = batches
        .iter()
        .map(|b| b.relative_median_diff_percent * sign)
        .fold(f64::INFINITY, f64::min);
    if effect <= 0.0 {
        return Score::SignChanged;
    }
    Score::Confirmed {
        score: effect,
        min_abs_t,
        sign: sign as i8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_samples_have_zero_t() {
        let a = vec![100, 101, 102, 103, 104, 105];
        let stats = batch_stats(&a, &a, 1.0).unwrap();
        assert_eq!(stats.t, 0.0);
    }

    #[test]
    fn a_single_slow_outlier_is_cropped() {
        let a: Vec<u64> = (0..100).map(|i| 1000 + (i % 7)).collect();
        let mut b = a.clone();
        b[50] = 10_000_000;
        let stats = batch_stats(&a, &b, 0.9).unwrap();
        assert!(stats.t.abs() < 1.0, "{stats:?}");
        let uncropped = batch_stats(&a, &b, 1.0).unwrap();
        assert!(stats.crop_ticks < uncropped.crop_ticks);
    }

    #[test]
    fn score_requires_confirmation_and_sign_consistency() {
        let config = StatConfig::default();
        let batch = |t: f64| BatchStats {
            n: [10, 10],
            kept: [9, 9],
            crop_ticks: 0,
            mean: [0.0, 0.0],
            median: [0.0, 0.0],
            t,
            relative_median_diff_percent: t / 3.0,
        };
        assert!(matches!(
            score(&[batch(2.0)], &config),
            Score::BelowThreshold { .. }
        ));
        assert!(matches!(
            score(&[batch(9.0)], &config),
            Score::NotConfirmed { .. }
        ));
        assert_eq!(
            score(&[batch(9.0), batch(-9.0)], &config),
            Score::SignChanged
        );
        assert!(matches!(
            score(&[batch(9.0), batch(3.0)], &config),
            Score::NotConfirmed { .. }
        ));
        assert_eq!(
            score(&[batch(-9.0), batch(-6.0)], &config),
            Score::Confirmed {
                score: 2.0,
                min_abs_t: 6.0,
                sign: -1
            }
        );
        let mut disagreeing = batch(9.0);
        disagreeing.relative_median_diff_percent = -1.0;
        assert_eq!(
            score(&[batch(9.0), disagreeing], &config),
            Score::SignChanged
        );
    }
}
