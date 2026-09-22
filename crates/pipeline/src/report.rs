//! Stage 5 — PERIOD REPORT: the triaged data batch for the human at the period
//! boundary.
//!
//! A period ends at an exec-count threshold N (see the orchestrator), NOT on a
//! timer. Any timestamp in the report is a LABEL only, never a stopping criterion —
//! so `report` never reads the clock itself; the caller passes the label in.
//!
//! `report` JOINS the two judgment artifacts of the period — ANOMALY_SCORES
//! (`score`'s ranking) and DIFF_FINDINGS (`diff`'s documented-vs-observed
//! divergences) — into one per-record triage batch, ordered for human attention.
//!
//! GUARDRAIL: ordering uses ONLY the existing anomaly score; `report` invents no
//! new ranking or severity of its own (score ranks; diff states; report assembles).
//! The human owns the decision at this boundary — that is the whole point of the
//! period handoff.

use crate::diff::{DiffFindings, DivergenceFinding};
use crate::score::AnomalyScores;
use contract::{Artifact, PeriodPaths, Producer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One record's triage view: its anomaly score + reasons joined with the diff
/// divergences found for it. Ordered within the report by `score` (descending).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriageItem {
    /// Index into the period's records (join key across score + diff).
    pub record_index: u64,
    /// Anomaly score from `score` (higher = more worth a human's attention).
    pub score: f64,
    /// Human-readable reasons from `score`.
    pub score_reasons: Vec<String>,
    /// Documented-vs-observed divergences from `diff` for this record.
    pub divergences: Vec<DivergenceFinding>,
}

/// Period-level triage summary.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Records in the period (from ANOMALY_SCORES).
    pub record_count: u64,
    /// Helper-arg comparisons the diff stage actually performed (from
    /// DIFF_FINDINGS). Makes "0 helper findings" interpretable: 0 out of many is
    /// evidence, 0 out of zero is an idle detector leg.
    #[serde(default)]
    pub helper_args_checked: u64,
    /// Records at/above the score flag threshold (from ANOMALY_SCORES).
    pub flagged: u64,
    /// Total diff findings, including period-level ones (from DIFF_FINDINGS).
    pub divergence_count: u64,
    /// Highest anomaly score in the period (from ANOMALY_SCORES).
    pub top_score: f64,
}

/// Parse-health accounting for the period — kept SEPARATE from divergences so a
/// parser's own blind-spots are never counted as verifier signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ParseHealth {
    /// Native blocks seen in this period: `records + unparsed_blocks`. Reported so
    /// the counts reconcile at a glance (records alone never equals blocks).
    pub blocks: u64,
    /// Records the parser produced.
    pub records: u64,
    /// Records parsed with caveats (non-empty parse_notes) — lower confidence.
    pub records_with_notes: u64,
    /// Blocks that produced no record (`not_observed + unrecognized`).
    pub unparsed_blocks: u64,
    /// Of those: nothing to observe (the tool emitted no verifier output, e.g. the
    /// load failed at the syscall boundary). EXPECTED at volume, not a deficiency.
    pub unparsed_not_observed: u64,
    /// Of those: the parser WAS given verifier output and failed on it. THE
    /// blind-spot metric — this is the number that must stay near zero.
    pub unrecognized: u64,
}

/// Human-facing, triaged report for one period (the PERIOD_REPORT payload).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeriodReport {
    /// Exec count N (carried through from the upstream artifacts).
    pub exec_count: u64,
    /// Timestamp LABEL for the harvest (never a stopping criterion). `None` if the
    /// caller supplied no label.
    pub generated_unix: Option<u64>,
    /// Per-record triage items, ordered by score descending (ties: index ascending).
    pub items: Vec<TriageItem>,
    /// Diff findings not tied to a single record (`record_index == None`).
    pub period_findings: Vec<DivergenceFinding>,
    /// Period-level summary.
    pub summary: ReportSummary,
    /// Parse health (blind-spots), kept apart from divergences.
    pub parse_health: ParseHealth,
}

/// Errors from the report stage.
#[derive(Debug)]
pub enum ReportError {
    /// Reading an upstream artifact or writing PERIOD_REPORT failed.
    Contract(contract::ContractError),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Contract(e) => write!(f, "report contract error: {e}"),
        }
    }
}

impl std::error::Error for ReportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReportError::Contract(e) => Some(e),
        }
    }
}

impl From<contract::ContractError> for ReportError {
    fn from(e: contract::ContractError) -> Self {
        ReportError::Contract(e)
    }
}

/// Assemble the triaged period report from the period's ANOMALY_SCORES and
/// DIFF_FINDINGS artifacts, and write PERIOD_REPORT.
///
/// `generated_unix` is a label the caller stamps (e.g. the harvest time); pass
/// `None` to omit it. Reads only the two judgment artifacts — never NORMALIZED
/// (per the chosen report scope) and never re-scores.
pub fn run(period: &PeriodPaths, generated_unix: Option<u64>) -> Result<PeriodReport, ReportError> {
    let scores: AnomalyScores = contract::read_artifact(&period.anomaly_scores())?.payload;
    let diff: DiffFindings = contract::read_artifact(&period.diff_findings())?.payload;
    let diff_summary = diff.summary;

    // Partition diff findings: per-record (join key) vs period-level (None).
    let mut per_record: BTreeMap<u64, Vec<DivergenceFinding>> = BTreeMap::new();
    let mut period_findings: Vec<DivergenceFinding> = Vec::new();
    for f in diff.findings {
        match f.record_index {
            Some(i) => per_record.entry(i).or_default().push(f),
            None => period_findings.push(f),
        }
    }

    // Join over the union of record indices appearing in either artifact, so a
    // record with divergences but no score (or vice versa) is not silently dropped.
    let score_by_index: BTreeMap<u64, &_> = scores.scored.iter().map(|s| (s.index, s)).collect();
    let mut indices: Vec<u64> = score_by_index.keys().copied().collect();
    for i in per_record.keys() {
        if !score_by_index.contains_key(i) {
            indices.push(*i);
        }
    }
    indices.sort_unstable();
    indices.dedup();

    let mut items: Vec<TriageItem> = indices
        .into_iter()
        .map(|i| {
            let (score, reasons) = match score_by_index.get(&i) {
                Some(s) => (s.score, s.reasons.clone()),
                None => (0.0, Vec::new()),
            };
            TriageItem {
                record_index: i,
                score,
                score_reasons: reasons,
                divergences: per_record.remove(&i).unwrap_or_default(),
            }
        })
        .collect();

    // GUARDRAIL: order by the EXISTING anomaly score only (descending); ties break
    // by record index. No new ranking is invented here.
    items.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.record_index.cmp(&b.record_index))
    });

    let summary = ReportSummary {
        record_count: scores.summary.record_count,
        helper_args_checked: diff_summary.helper_args_checked,
        flagged: scores.summary.flagged,
        divergence_count: diff.summary.finding_count,
        top_score: scores.summary.max_score,
    };

    // Parse health from NORMALIZED (optional: the report unit test builds only
    // scores+diff). Blind-spots stay OUT of the divergence count.
    let parse_health = contract::read_artifact::<crate::normalize::NormalizedMetrics>(
        &period.normalized(),
    )
    .map(|a| {
        let n = a.payload;
        let unrecognized = n
            .unparsed
            .iter()
            .filter(|u| u.kind == crate::normalize::UnparsedKind::Unrecognized)
            .count() as u64;
        ParseHealth {
            blocks: (n.records.len() + n.unparsed.len()) as u64,
            records: n.records.len() as u64,
            records_with_notes: n.records.iter().filter(|r| !r.parse_notes.is_empty()).count()
                as u64,
            unparsed_blocks: n.unparsed.len() as u64,
            unparsed_not_observed: n.unparsed.len() as u64 - unrecognized,
            unrecognized,
        }
    })
    .unwrap_or_default();

    let report = PeriodReport {
        exec_count: scores.exec_count,
        generated_unix,
        items,
        period_findings,
        summary,
        parse_health,
    };

    // Write PERIOD_REPORT (borrow the payload so we can return it after the block).
    {
        let artifact = Artifact::new(period.period_id, Producer::Report, &report);
        contract::write_artifact(&period.period_report(), &artifact)?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{DiffFindings, DiffSummary, DivergenceFinding, GroundTruthSource};
    use crate::score::{AnomalyScores, RecordScore, ScoreSummary};
    use std::path::PathBuf;

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-report-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn finding(record_index: Option<u64>, kind: &str) -> DivergenceFinding {
        DivergenceFinding {
            record_index,
            source: GroundTruthSource::LogicalInvariant,
            kind: kind.to_string(),
            aspect: "tnum".to_string(),
            expected: "e".to_string(),
            observed: "o".to_string(),
            detail: "d".to_string(),
        }
    }

    /// Seed a period with canned ANOMALY_SCORES + DIFF_FINDINGS (no Python/diff run).
    fn seed(period: &PeriodPaths) {
        let scores = AnomalyScores {
            exec_count: 4200,
            scored: vec![
                RecordScore { index: 0, score: 0.1, reasons: vec![] },
                RecordScore {
                    index: 1,
                    score: 0.9,
                    reasons: vec!["helper violation".to_string()],
                },
            ],
            summary: ScoreSummary { record_count: 2, flagged: 1, max_score: 0.9 },
            method: "test".to_string(),
        };
        contract::write_artifact(
            &period.anomaly_scores(),
            &Artifact::new(period.period_id, Producer::Score, &scores),
        )
        .unwrap();

        let diff = DiffFindings {
            exec_count: 4200,
            findings: vec![
                finding(Some(1), "tnum_malformed"),
                finding(None, "period_level_thing"),
            ],
            notes: Vec::new(),
            summary: DiffSummary { record_count: 2, finding_count: 2, ..Default::default() },
        };
        contract::write_artifact(
            &period.diff_findings(),
            &Artifact::new(period.period_id, Producer::Diff, &diff),
        )
        .unwrap();
    }

    #[test]
    fn joins_orders_and_summarizes() {
        let base = scratch_dir("join");
        let period = PeriodPaths::new(&base.join("data"), 9);
        seed(&period);

        let report = run(&period, Some(1_700_000_000)).unwrap();

        // Ordered by score DESC: record 1 (0.9) before record 0 (0.1).
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.items[0].record_index, 1);
        assert_eq!(report.items[0].score, 0.9);
        // The per-record divergence joined onto record 1.
        assert_eq!(report.items[0].divergences.len(), 1);
        assert_eq!(report.items[0].divergences[0].kind, "tnum_malformed");
        assert!(report.items[1].divergences.is_empty());

        // Period-level finding separated out.
        assert_eq!(report.period_findings.len(), 1);
        assert_eq!(report.period_findings[0].kind, "period_level_thing");

        // Summary joins both artifacts.
        assert_eq!(report.summary.record_count, 2);
        assert_eq!(report.summary.flagged, 1);
        assert_eq!(report.summary.divergence_count, 2);
        assert_eq!(report.summary.top_score, 0.9);
        assert_eq!(report.generated_unix, Some(1_700_000_000));
        assert_eq!(report.exec_count, 4200);

        // PERIOD_REPORT round-trips through the contract.
        let art: Artifact<PeriodReport> = contract::read_artifact(&period.period_report()).unwrap();
        assert_eq!(art.producer, Producer::Report);
        assert_eq!(art.period_id, 9);
        assert_eq!(art.payload.items.len(), 2);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn timestamp_label_is_optional() {
        let base = scratch_dir("nolabel");
        let period = PeriodPaths::new(&base.join("data"), 1);
        seed(&period);

        let report = run(&period, None).unwrap();
        assert_eq!(report.generated_unix, None);

        std::fs::remove_dir_all(&base).ok();
    }
}
