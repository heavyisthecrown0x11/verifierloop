//! Ground-truth source 4 — cross-version patch diffs (git history over the verifier).
//!
//! SCOPE, STATED PLAINLY: this source does **not** generate findings on its own. A
//! full cross-version behavioural diff would need observations from *two* kernel
//! revisions, and the lab builds one. What git history *can* answer today, from the
//! CODE rather than from prose, is the question that source 2 cannot answer about
//! itself:
//!
//!   > A documented-vs-observed divergence has two possible causes — the verifier
//!   > regressed, or the documentation went stale. Which is more likely?
//!
//! Citation anchoring (see [`super::verifier_rst`]) guarantees a documented sentence
//! still EXISTS; it cannot guarantee it is still TRUE. This module supplies the
//! missing evidence mechanically: how far the documentation has fallen behind the
//! code it describes. That evidence is attached to source-2 findings so the triage
//! question arrives already answered-ish, instead of being asked from scratch.

use std::path::Path;
use std::process::Command;

/// A commit touching one of the verifier paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    /// Abbreviated sha.
    pub sha: String,
    /// Author date, `YYYY-MM-DD`.
    pub date: String,
    /// Subject line.
    pub subject: String,
}

/// Git-derived view of how documentation and verifier code have moved relative to
/// each other.
#[derive(Debug, Default, Clone)]
pub struct PatchDiffModel {
    /// Last commit touching `Documentation/bpf/verifier.rst`.
    pub doc_last: Option<CommitInfo>,
    /// Last commit touching `kernel/bpf/verifier.c`.
    pub code_last: Option<CommitInfo>,
    /// Commits to the verifier implementation since the documentation last moved.
    /// The staleness measure: large means the prose describes an older verifier.
    pub code_commits_since_doc: u64,
}

impl PatchDiffModel {
    /// One-line evidence for triage, or `None` if git history was unavailable.
    ///
    /// Deliberately states the FACT and not a verdict — it says how far apart the
    /// two are, and leaves "real bug or stale doc" to the human, now informed.
    pub fn staleness_note(&self) -> Option<String> {
        let doc = self.doc_last.as_ref()?;
        let code = self.code_last.as_ref()?;
        Some(format!(
            "documentation last changed {} ({}), verifier.c last changed {} ({}), \
             {} verifier.c commits since",
            doc.date, doc.sha, code.date, code.sha, self.code_commits_since_doc
        ))
    }

    /// Whether any git history was resolved at all.
    pub fn is_empty(&self) -> bool {
        self.doc_last.is_none() && self.code_last.is_none()
    }
}

const DOC_PATH: &str = "Documentation/bpf/verifier.rst";
const CODE_PATH: &str = "kernel/bpf/verifier.c";

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn last_commit(repo: &Path, path: &str) -> Option<CommitInfo> {
    let line = git(
        repo,
        &["log", "-1", "--format=%h%x09%ad%x09%s", "--date=short", "--", path],
    )?;
    parse_commit_line(&line)
}

/// Parse `<sha>\t<date>\t<subject>` (exposed for testing without a repo).
pub(crate) fn parse_commit_line(line: &str) -> Option<CommitInfo> {
    let mut it = line.splitn(3, '\t');
    let sha = it.next()?.trim().to_string();
    let date = it.next()?.trim().to_string();
    let subject = it.next().unwrap_or("").trim().to_string();
    if sha.is_empty() || date.is_empty() {
        return None;
    }
    Some(CommitInfo { sha, date, subject })
}

/// Load git-derived staleness evidence from a bpf-next checkout.
///
/// Returns an empty model (never an error) when the tree is not a git repository
/// or history is unavailable — missing evidence must degrade to silence, exactly
/// like an unloaded oracle, not to a fabricated claim.
pub fn load(kernel_src: &Path) -> PatchDiffModel {
    let doc_last = last_commit(kernel_src, DOC_PATH);
    let code_last = last_commit(kernel_src, CODE_PATH);
    let code_commits_since_doc = doc_last
        .as_ref()
        .and_then(|_| {
            let doc_sha = git(
                kernel_src,
                &["log", "-1", "--format=%H", "--", DOC_PATH],
            )?;
            let count = git(
                kernel_src,
                &[
                    "rev-list",
                    "--count",
                    &format!("{doc_sha}..HEAD"),
                    "--",
                    CODE_PATH,
                ],
            )?;
            count.parse::<u64>().ok()
        })
        .unwrap_or(0);

    PatchDiffModel {
        doc_last,
        code_last,
        code_commits_since_doc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_commit_line() {
        let c = parse_commit_line("107e16979905\t2025-09-18\tbpf: disable liveness").unwrap();
        assert_eq!(c.sha, "107e16979905");
        assert_eq!(c.date, "2025-09-18");
        assert_eq!(c.subject, "bpf: disable liveness");
    }

    #[test]
    fn malformed_lines_yield_nothing_rather_than_a_guess() {
        assert!(parse_commit_line("").is_none());
        assert!(parse_commit_line("onlysha").is_none());
    }

    #[test]
    fn staleness_note_states_the_fact_not_a_verdict() {
        let m = PatchDiffModel {
            doc_last: Some(CommitInfo {
                sha: "aaa".into(),
                date: "2025-09-18".into(),
                subject: "doc".into(),
            }),
            code_last: Some(CommitInfo {
                sha: "bbb".into(),
                date: "2026-08-18".into(),
                subject: "code".into(),
            }),
            code_commits_since_doc: 351,
        };
        let note = m.staleness_note().unwrap();
        assert!(note.contains("2025-09-18") && note.contains("2026-08-18"));
        assert!(note.contains("351 verifier.c commits since"));
        // No verdict words: the human decides, the note only informs.
        for verdict in ["stale", "bug", "likely", "probably"] {
            assert!(!note.contains(verdict), "note must not editorialise: {note}");
        }
    }

    #[test]
    fn missing_history_degrades_to_silence() {
        let m = load(Path::new("/nonexistent-tree"));
        assert!(m.is_empty());
        assert!(m.staleness_note().is_none(), "no evidence -> no claim");
    }
}
