//! Real per-tool parser #2 — the differential/verifier-log harness output.
//!
//! Interprets the native output of `harness/diffharness.c` into [`CoreMetrics`].
//! This is the producer of the verifier-SEMANTIC CORE fields (decision +
//! register-state evolution) that syzkaller does not emit (see devlog 0010/0011).
//!
//! Native format (one block per program):
//! ```text
//! ===PROG <name> type=<t> ===
//! RESULT decision=<accept|reject> fd=<n> errno=<e> load_ns=<n>
//! ---LOG---
//! <verbatim kernel verifier log>
//! ---END---
//! ```
//!
//! v0 scope: `decision`, reject `reason` (verbatim), `register_evolution`,
//! `processed`. `jit_interp_diff` is `None` — the primary kernel is
//! `BPF_JIT_ALWAYS_ON` so there is no interpreter to diff against (deferred to a
//! cross-kernel mode). Helper `arg_type` violations are decided at the `diff`
//! stage, not here.
//!
//! UNCHANGED-AT-SOURCE: this reads bytes and never mutates them; shaping into the
//! schema is interpretation, done here in `normalize` and nowhere earlier.

use std::borrow::Cow;

use crate::normalize::{ParseOutput, ParsedRecord, RecordParser, UnparsedBlock, UnparsedKind};
use metrics::core::{
    CoreMetrics, CoverageDelta, HelperArgObservation, Processed, RegSnapshot, RegState, Tnum,
    VerifierDecision,
};

/// Parser for the differential/verifier-log harness native output.
pub struct VerifierLogParser;

impl RecordParser for VerifierLogParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> ParseOutput {
        let text = String::from_utf8_lossy(bytes);
        let mut records = Vec::new();
        let mut unparsed = Vec::new();
        for b in split_blocks(&text) {
            match classify_block(&b) {
                Ok(pr) => records.push(pr),
                Err(ub) => unparsed.push(ub),
            }
        }
        ParseOutput { records, unparsed }
    }
}

/// Split the harness output into per-program blocks (each starts at `===PROG `).
fn split_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("===PROG ") {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            cur = Some(String::new());
        }
        if let Some(b) = cur.as_mut() {
            b.push_str(line);
            b.push('\n');
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    blocks
}

/// Classify one native block: either a trustworthy record, or an [`UnparsedBlock`]
/// kept in a SEPARATE bucket. UNPARSED POLICY — a block the parser cannot trust
/// (no verifier decision, or a non-verifier RESULT) is NEVER turned into a
/// default-filled record (which could masquerade as a clean accept) and NEVER
/// treated as an anomaly; it is surfaced as a parser blind-spot. Recognized blocks
/// may still carry per-record `notes` for partially-unrecognized content.
fn classify_block(block: &str) -> Result<ParsedRecord, UnparsedBlock> {
    let label = block_label(block);
    let raw: Vec<&str> = block.lines().collect();
    let (repaired, console_splices) = repair_console_interleaving(&raw);
    let mut result_line: Option<&str> = None;
    let mut in_log = false;
    let mut log: Vec<&str> = Vec::new();
    let mut runtime_lines: Vec<&str> = Vec::new();
    let mut expect_line: Option<&str> = None;
    let mut jitdiff_lines: Vec<&str> = Vec::new();
    let mut store_line: Option<&str> = None;
    let mut prune_line: Option<&str> = None;
    let mut liveness_line: Option<&str> = None;

    for line in repaired.iter().map(|l| l.as_ref()) {
        if line.starts_with("RESULT ") {
            result_line = Some(line);
        } else if line.starts_with("RUNTIME ") {
            runtime_lines.push(line);
        } else if line.starts_with("JITDIFF ") {
            jitdiff_lines.push(line);
        } else if line.starts_with("EXPECT ") {
            expect_line = Some(line);
        } else if line.starts_with("STORE ") {
            store_line = Some(line);
        } else if line.starts_with("PRUNE ") {
            prune_line = Some(line);
        } else if line.starts_with("LIVENESS ") {
            liveness_line = Some(line);
        } else if line.starts_with("---LOG---") {
            in_log = true;
        } else if line.starts_with("---END---") {
            in_log = false;
        } else if in_log {
            log.push(line);
        }
    }

    // Block-level unparsed: no trustworthy verifier decision -> do NOT invent a record.
    let result = match result_line {
        Some(r) => r,
        None => {
            return Err(UnparsedBlock {
                label: label.clone(),
                kind: UnparsedKind::Unrecognized,
                reason: "no RESULT line — decision unknown".to_string(),
            })
        }
    };
    let mut reason_unidentified = false;
    let decision = if result.contains("decision=accept") {
        VerifierDecision::Accept
    } else if result.contains("decision=reject") {
        let reason = parse_reject_reason(&log).unwrap_or_else(|| {
            reason_unidentified = true;
            "unknown".to_string()
        });
        VerifierDecision::Reject { reason }
    } else {
        // e.g. `decision=error` (harness map-create failure) — not a verifier obs.
        return Err(UnparsedBlock {
            label: label.clone(),
            kind: UnparsedKind::NotObserved,
            reason: format!("non-verifier RESULT: {}", result.trim()),
        });
    };

    // An empty verifier log means nothing was observed: the load failed before (or
    // without) verification (e.g. E2BIG at the syscall boundary), or the log was
    // not produced. Attributing a `reject` reason here would invent verifier text
    // that does not exist, so this is a blind-spot, not an observation.
    if log.iter().all(|l| l.trim().is_empty()) {
        return Err(UnparsedBlock {
            label: label.clone(),
            kind: UnparsedKind::NotObserved,
            reason: format!(
                "empty verifier log ({}) — verifier never ran",
                result.trim().trim_start_matches("RESULT ")
            ),
        });
    }

    let core = CoreMetrics {
        verifier_decision: decision,
        register_evolution: parse_register_evolution(&log),
        processed: parse_processed(&log),
        // Set when the harness loaded the SAME program twice — once JITted, once with
        // net.core.bpf_jit_enable=0 — and ran both. It stayed None for the project's whole
        // history because the lab kernel is built CONFIG_BPF_JIT_ALWAYS_ON, which compiles
        // the interpreter out; 0066 measured that the jit_interp_divergence invariant had
        // therefore never examined a single record. A kernel variant without that symbol
        // (0075) makes the comparison possible, and this is where it arrives.
        jit_interp_diff: parse_jit_interp(&runtime_lines, &jitdiff_lines),
        coverage_delta: CoverageDelta::default(), // exec_n stamped by normalize
        helper_arg_observations: parse_helper_calls(&log),
        helper_arg_violations: Vec::new(),        // legacy synthetic path
        runtime_samples: parse_runtime_samples(&runtime_lines),
        intended_retval: expect_line.and_then(parse_intended_retval),
        multi_path: expect_line.and_then(|l| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix("paths="))
                .map(|v| v.trim() == "multi")
        }),
        store_site: store_line.and_then(parse_store_site),
        prune_probe: prune_line.and_then(parse_prune_probe),
        liveness_gate: parse_liveness_gate(liveness_line, &log),
    };

    // Record-level parse notes: partial-parse caveats (lower confidence, NOT anomalies).
    let mut notes = Vec::new();
    if reason_unidentified {
        // Never let a fabricated reason pass as verifier text unnoticed. Carry the
        // syscall-level errno (observed, not synthesized verifier text) so triage
        // can tell a data limit from a parser gap at a glance.
        let errno = result
            .split_whitespace()
            .find_map(|t| t.strip_prefix("errno="))
            .unwrap_or("?");
        notes.push(format!(
            "reject reason not identified in log (errno={errno}; verifier printed no message)"
        ));
    }
    if !log.iter().any(|l| l.trim_start().starts_with("processed ")) {
        notes.push("missing 'processed' counters".to_string());
    }
    if console_splices > 0 {
        notes.push(format!(
            "repaired {console_splices} console-interleaved line(s) (kernel printk spliced into the serial capture)"
        ));
    }
    for fam in unrecognized_reg_families(&core) {
        notes.push(format!("unrecognized reg-type form: {fam}"));
    }

    Ok(ParsedRecord {
        core,
        notes,
        label: Some(label),
    })
}

/// Parse the harness's `RUNTIME input=0x.. retval=0x..` lines (BPF_PROG_TEST_RUN
/// ground-truth samples) that sit between the RESULT line and the verifier log.
/// A line carrying `error=` marks a sample the harness could not execute; it is
/// kept (so the count is honest) but flagged so the diff oracle skips it.
fn parse_runtime_samples(lines: &[&str]) -> Vec<metrics::core::RuntimeSample> {
    fn parse_u(v: &str) -> Option<u64> {
        let v = v.trim();
        if let Some(h) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
            u64::from_str_radix(h, 16).ok()
        } else {
            v.parse::<u64>().ok()
        }
    }
    let mut out = Vec::new();
    for l in lines {
        let mut input = None;
        let mut retval = None;
        let mut store_off: Option<i64> = None;
        let mut store_len: Option<i64> = None;
        let mut store_size: Option<i64> = None;
        let mut executed: Option<bool> = None;
        let mut intended: Option<u64> = None;
        let mut error = false;
        for tok in l.split_whitespace() {
            if let Some(v) = tok.strip_prefix("input=") {
                input = parse_u(v);
            } else if let Some(v) = tok.strip_prefix("retval=") {
                retval = parse_u(v);
            } else if let Some(v) = tok.strip_prefix("store_off=") {
                // "none" = the sentinel was absent = the store landed out of bounds.
                store_off = Some(if v.trim() == "none" {
                    -1
                } else {
                    v.trim().parse::<i64>().unwrap_or(-1)
                });
            } else if let Some(v) = tok.strip_prefix("store_len=") {
                // multi-byte (--gen-rtw2): consecutive sentinel bytes actually found.
                store_len = v.trim().parse::<i64>().ok();
            } else if let Some(v) = tok.strip_prefix("store_size=") {
                // multi-byte (--gen-rtw2): the store's width in bytes.
                store_size = v.trim().parse::<i64>().ok();
            } else if let Some(v) = tok.strip_prefix("executed=") {
                // --gen-loc: did this run reach the store at all? (branch-bounded arm)
                executed = v.trim().parse::<i64>().ok().map(|n| n != 0);
            } else if let Some(v) = tok.strip_prefix("intended_retval=") {
                // The generator's per-input claim. Parsed BEFORE the `retval=` arm would
                // ever see it, and it cannot collide anyway: these are whole tokens matched
                // by prefix, and "intended_retval=" does not start with "retval=".
                intended = parse_u(v);
            } else if tok.starts_with("error=") {
                error = true;
            }
        }
        if let Some(i) = input {
            // A sample is valid if it observed EITHER channel (retval or store_off).
            let observed = retval.is_some() || store_off.is_some();
            out.push(metrics::core::RuntimeSample {
                input: i,
                retval: retval.unwrap_or(0),
                retval_observed: retval.is_some(),
                intended_retval: intended,
                store_off,
                store_len,
                store_size,
                executed,
                error: error || !observed,
            });
        }
    }
    out
}

/// The `===PROG <name> ...` label of a block (for triage), or "block".
fn block_label(block: &str) -> String {
    block
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("===PROG "))
        .map(|r| r.split_whitespace().next().unwrap_or("?").to_string())
        .unwrap_or_else(|| "block".to_string())
}

/// Reg-type families the parser does NOT recognize (novel forms a high-volume
/// period might surface). Flagged as a note so a blind-spot cannot pass as clean.
fn unrecognized_reg_families(core: &CoreMetrics) -> Vec<String> {
    const KNOWN: &[&str] = &[
        "scalar", "map_ptr", "map_value", "map_value_or_null", "ctx", "fp", "pkt",
        "pkt_meta", "pkt_end", "flow_keys", "sock", "sock_common", "tcp_sock",
        "func", "stack", "buf", "mem", "ptr",
    ];
    let mut out = std::collections::BTreeSet::new();
    for snap in &core.register_evolution {
        for r in &snap.regs {
            let base = base_family(&r.reg_type);
            if !KNOWN.contains(&base.as_str()) {
                out.insert(base);
            }
        }
    }
    out.into_iter().collect()
}

/// Collapse a verifier reg-type to its base family.
///
/// `log.c:reg_type_str()` builds the printed name as PREFIX + base + POSTFIX, where the
/// prefix is a concatenation of every set type flag —
/// `rdonly_ ringbuf_ user_ percpu_ rcu_ untrusted_ trusted_` (log.c:435-443) — and the
/// postfix is either `_or_null` or, for PTR_TO_BTF_ID, the infix `or_null_` placed BEFORE
/// the struct name. PTR_TO_BTF_ID's base is `ptr_` with the BTF type name glued straight on
/// (log.c:418 and :650-651), so it prints as `ptr_sk_buff`, `trusted_ptr_task_struct`,
/// `ptr_or_null_sk_buff` — never as a bare `btf_id`.
///
/// None of that was stripped, which made `rdonly_mem` — an ordinary read-only dynptr slice
/// — report as an unknown family on 634 of the composition corpus's 896 records. A
/// permanent note at that volume is worse than no note: it is exactly the noise a genuinely
/// novel shape would have to be spotted inside.
fn base_family(reg_type: &str) -> String {
    if reg_type.starts_with("fp") {
        return "fp".to_string();
    }
    let mut t = reg_type;
    loop {
        let stripped = ["rdonly_", "ringbuf_", "user_", "percpu_", "rcu_", "untrusted_",
                        "trusted_"]
            .iter()
            .find_map(|p| t.strip_prefix(p));
        match stripped {
            Some(rest) => t = rest,
            None => break,
        }
    }
    // PTR_TO_BTF_ID: `ptr_` (+ `or_null_`) + the BTF struct name, which is unbounded.
    if let Some(rest) = t.strip_prefix("ptr_") {
        let _ = rest;
        return "ptr".to_string();
    }
    t.strip_suffix("_or_null").unwrap_or(t).to_string()
}

/// Does `t` begin with a `<digits>:` head (an instruction / state / liveness line)?
fn has_digit_head(t: &str) -> bool {
    match t.find(':') {
        Some(c) => {
            let head = &t[..c];
            !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Analysis scaffolding a verifier log emits around the real failure text: the
/// pre-analysis preamble, precision/liveness tracking, state-walk markers, the
/// `processed` summary, and bpf-next's structured diagnostic headers.
fn is_analysis_noise(t: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "func#",
        "topo_order",
        "subprog#",
        "stack use/def",
        "Live regs",
        "processed ",
        "mark_precise:",
        "from ",              // "from 8 to 10: R0=..." state-walk marker
        // SCC (strongly-connected-component) walk markers, kernel/bpf/states.c:174/
        // 216/246 — printed BETWEEN insn lines and BEFORE the real failure text, so
        // without this they get reported as the reject reason. Found by measuring
        // observed reasons against the kernel's own message strings (devlog 0023).
        "SCC enter",
        "SCC exit",
        "SCC backedge",
        "Verification failed:", // structured diagnostic (kept as a fallback below)
        "Reason:",
        "At:",
        "Suggestion:",
        "Instruction context",
    ];
    t.starts_with('(') || PREFIXES.iter().any(|p| t.starts_with(p))
}

/// The verifier's failure text, verbatim, or `None` if it could not be identified.
///
/// Scans the WHOLE log for the first un-indented, non-empty line that is neither a
/// state/insn line nor analysis scaffolding — the concise verifier token (e.g.
/// `R0 !read_ok`, `last insn is not an exit or jmp`). VOLUME LESSON (devlog 0018):
/// most real rejects fail BEFORE any per-insn state is printed, so this must not
/// require a preceding state section. If no concise token exists, fall back to
/// bpf-next's structured headline (`Verification failed: ...`), which is still the
/// verifier's own text. `None` (rather than a fabricated "unknown") lets the caller
/// record a parse note instead of inventing verifier text.
fn parse_reject_reason(log: &[&str]) -> Option<String> {
    let mut headline: Option<String> = None;
    for line in log {
        if line.starts_with(' ') {
            continue; // indented: disasm / liveness / diagnostic detail
        }
        let t = line.trim();
        if t.is_empty() || has_digit_head(t) {
            continue;
        }
        if t.starts_with("Verification failed:") {
            headline.get_or_insert_with(|| t.to_string());
            continue;
        }
        if is_analysis_noise(t) {
            continue;
        }
        return Some(strip_glued_summary(t).to_string());
    }
    headline
}

/// Some verifier messages are emitted without a trailing newline, so the
/// `processed N insns (limit ...)` summary ends up glued onto the failure text
/// (e.g. `invalid type id 1 in func infoprocessed 0 insns (limit 1000000) ...`).
/// Cut the summary back off so the recorded reason is the verifier's message only.
fn strip_glued_summary(t: &str) -> &str {
    if let Some(i) = t.find("processed ") {
        if i > 0 && t[i..].contains(" insns (limit") {
            return t[..i].trim_end();
        }
    }
    t
}

/// Byte index of a kernel console timestamp (`[<spaces><secs>.<6 digits>]`) in
/// `line`, or `None`. printk formats these as `[%5lu.%06lu]`, so demanding exactly
/// six fractional digits keeps this from firing on verifier text.
fn console_timestamp_at(line: &str) -> Option<usize> {
    let b = line.as_bytes();
    for (i, _) in line.match_indices('[') {
        let mut j = i + 1;
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        let secs = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == secs || j >= b.len() || b[j] != b'.' {
            continue;
        }
        j += 1;
        let frac = j;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j - frac == 6 && j < b.len() && b[j] == b']' {
            return Some(i);
        }
    }
    None
}

/// The harness output is captured off the VM's serial console, which the kernel
/// also writes to. A printk can land in the MIDDLE of a line: the console gets the
/// line's prefix, then the whole dmesg line, then the original line resumes on the
/// next one. Both shapes were observed on real bpf-next runs (2026-09-01):
///
/// ```text
/// processed 10 insns (limit 1000000) max_states_per_i[    2.301324] clocksource: ...
/// nsn 0 total_states 1 peak_states 1 mark_read 0
/// ```
///
/// Left alone this is SILENT corruption, the failure mode this project guards
/// against hardest: `processed ` still matches, so `parse_processed` reads
/// `insn_processed` correctly and never sees `total_states` — `unwrap_or(0)` then
/// records a real `total_states 1` as `0`, and nothing is flagged. It is a parser
/// bug that would present as a verifier observation.
///
/// Rejoin the split line and drop whole console lines. Returns the repaired lines
/// and how many splices were mended, so the caller can NOTE it rather than hide it.
fn repair_console_interleaving<'a>(lines: &[&'a str]) -> (Vec<Cow<'a, str>>, usize) {
    if !lines.iter().any(|l| console_timestamp_at(l).is_some()) {
        return (lines.iter().copied().map(Cow::Borrowed).collect(), 0);
    }
    let mut out: Vec<Cow<'a, str>> = Vec::with_capacity(lines.len());
    let mut repairs = 0usize;
    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        match console_timestamp_at(line) {
            // A whole console line between two verifier lines: not verifier output.
            Some(0) => i += 1,
            // A console line spliced into this one: keep the prefix, drop the
            // injected text, glue on the continuation that follows it. The
            // continuation may itself be split, so keep consuming until it is not.
            Some(cut) => {
                let mut joined = line[..cut].to_string();
                let mut j = i + 1;
                loop {
                    while j < lines.len() && console_timestamp_at(lines[j]) == Some(0) {
                        j += 1;
                    }
                    if j >= lines.len() {
                        break;
                    }
                    let next = lines[j];
                    j += 1;
                    match console_timestamp_at(next) {
                        Some(c) => joined.push_str(&next[..c]),
                        None => {
                            joined.push_str(next);
                            break;
                        }
                    }
                }
                out.push(Cow::Owned(joined));
                repairs += 1;
                i = j;
            }
            None => {
                out.push(Cow::Borrowed(line));
                i += 1;
            }
        }
    }
    (out, repairs)
}

/// `processed N insns ... total_states T ...` -> insn_processed = N, states = T.
fn parse_processed(log: &[&str]) -> Processed {
    for line in log {
        let t = line.trim_start();
        if t.starts_with("processed ") {
            return Processed {
                insn_processed: num_after(t, "processed ").unwrap_or(0),
                states_processed: num_after(t, "total_states ").unwrap_or(0),
            };
        }
    }
    Processed::default()
}

/// Build the per-insn register-state snapshots from the verifier log.
/// Strip a `frameN:` call-depth prefix from a state string.
///
/// A program with subprograms prefixes every state with its call depth, and the prefix
/// sits AHEAD of the register tokens (`33: frame1: R3=map_value(...)`). It has to come off
/// before the full-state / instruction-line decision, because `frame1: R3=...` does not
/// look like a register token and would otherwise be dropped SILENTLY — an empty register
/// evolution, not an unrecognized line, so the only symptom is a denominator of zero.
fn strip_frame(st: &str) -> &str {
    let after = match st.strip_prefix("frame") {
        Some(a) => a,
        None => return st,
    };
    let digits = after.len() - after.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    if digits == 0 || !after[digits..].starts_with(':') {
        return st;
    }
    after[digits + 1..].trim_start()
}

/// Parse a `from <prev> to <idx>[ (speculative execution)]: <state>` dump.
///
/// Returns the DESTINATION index — `env->insn_idx`, the instruction the state belongs to —
/// and the state text with any `frameN:` prefix already removed.
fn parse_from_to(t: &str) -> Option<(u32, &str)> {
    let rest = t.strip_prefix("from ")?;
    let (_prev, rest) = rest.split_once(" to ")?;
    let colon = rest.find(':')?;
    let (head, state) = rest.split_at(colon);
    // `head` is the destination index, optionally followed by the speculative marker.
    let digits: String = head.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let tail = head[digits.len()..].trim();
    if !tail.is_empty() && tail != "(speculative execution)" {
        return None;
    }
    let idx: u32 = digits.parse().ok()?;
    Some((idx, strip_frame(state[1..].trim_start())))
}

fn parse_register_evolution(log: &[&str]) -> Vec<RegSnapshot> {
    let mut snaps = Vec::new();
    // Set by a `to caller at N:` header and consumed by the indented full-state dump on
    // the very next line. See the comment on that branch below.
    let mut pending_idx: Option<u32> = None;
    for line in log {
        if line.starts_with(' ') {
            // MOSTLY liveness lines ("      0: .........."), which are noise — but NOT
            // always. `print_verifier_state()` starts every register with a leading space
            // (log.c: `verbose(env, " R%d", i)`), so any state dump whose header ended in a
            // newline lands here too. Dropping the whole class cost the richest snapshots
            // in the log: the caller/callee transfer at a subprogram boundary is printed
            // ONLY here, and nowhere else.
            //
            // Only a dump with a printed instruction index is taken. `to caller at %d:`
            // (verifier.c, prepare_func_exit) states the index; `caller:`, `callee:` and
            // `returning from callee:` do not, and inventing one for them would feed a
            // claim the log never made into the store-location check.
            if let Some(idx) = pending_idx.take() {
                let t = strip_frame(line.trim_start());
                if looks_like_reg_token_start(t) {
                    let regs = parse_reg_tokens(t);
                    if !regs.is_empty() {
                        snaps.push(RegSnapshot { insn_idx: idx, regs });
                    }
                }
            }
            continue;
        }
        pending_idx = None;
        let t = line.trim();

        // `to caller at 15:` — the next line carries the caller's restored state.
        if let Some(rest) = t.strip_prefix("to caller at ") {
            if let Some(n) = rest.strip_suffix(':').and_then(|d| d.parse::<u32>().ok()) {
                pending_idx = Some(n);
            }
            continue;
        }

        // `from 33 to 15:` / `from 33 to 15 (speculative execution):` — a full state dump
        // at a prune point or back-edge, printed at BPF_LOG_LEVEL2 with print_all=true, so
        // it carries EVERY live register rather than only the scratched ones. The trailing
        // number is `env->insn_idx` (verifier.c: `verbose(env, "\nfrom %d to %d%s:",
        // env->prev_insn_idx, env->insn_idx, ...)`) — the instruction this state belongs
        // to, exactly as for an ordinary `15: R1=ctx()` line. Attribution here is what the
        // log says, not an inference.
        //
        // These were dropped because the head is `from 33 to 15`, which is not all digits.
        // 5851 of them sit in the committed corpora, and they are the freshest merged claim
        // at precisely the loop and prune points the store-location check cares about —
        // so missing them was not only a lost denominator but a FALSE-FINDING risk: the
        // check compared a store against a SUBSET of the claims the verifier actually made.
        if let Some((idx, state)) = parse_from_to(t) {
            let regs = parse_reg_tokens(state);
            if !regs.is_empty() {
                snaps.push(RegSnapshot { insn_idx: idx, regs });
            }
            continue;
        }
        let colon = match t.find(':') {
            Some(c) => c,
            None => continue,
        };
        let head = &t[..colon];
        if head.is_empty() || !head.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let insn_idx: u32 = match head.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let rest = t[colon + 1..].trim_start();

        // A program with subprogs prefixes every state with its call depth, and the
        // prefix sits in BOTH shapes:
        //   33: frame1: R3=map_value(...) R7=scalar(id=1,...)
        //   23: (25) if r6 > 0x7 ; frame1: R6=scalar(id=1,...)
        // It has to come off BEFORE the full-state / instruction-line decision, because
        // `frame1: R3=...` does not look like a register token and would otherwise fall
        // through to the `;` branch and be dropped. This fails SILENTLY — an empty
        // register evolution, not an unrecognized line — so the only symptom is a
        // denominator of zero, which is exactly how it surfaced: `--gen-frame` reported
        // store_locations_checked = 0 on a log full of frame1 states.
        //
        // The frame index is deliberately not carried into the snapshot. Instruction
        // indices are unique across a program's subprograms, so an instruction belongs to
        // exactly one subprogram; and if a future family ever reaches one instruction at
        // two call depths, the claims merge — which since 0047 the store-location check
        // treats as a UNION, the conservative direction.
        let rest = strip_frame(rest);

        // (a) full-state line: "R1=ctx() R10=fp0"  (starts with a reg token)
        // (b) instruction line: "(b7) r0 = 0 ; R0=0"  (state after ';')
        let state = if looks_like_reg_token_start(rest) {
            Some(rest)
        } else {
            rest.find(';').map(|s| strip_frame(rest[s + 1..].trim()))
        };

        if let Some(ss) = state {
            let regs = parse_reg_tokens(ss);
            if !regs.is_empty() {
                snaps.push(RegSnapshot { insn_idx, regs });
            }
        }
    }
    snaps
}

/// True if `s` begins with a `R<digits>=` token.
fn looks_like_reg_token_start(s: &str) -> bool {
    reg_token_name_len(s).is_some()
}

/// Length of a `R<n>` / `R<n>_w` register name at the start of `s`, if it is followed
/// by `=`.
///
/// The `_w` suffix marks a register WRITTEN by the instruction, and older kernels print
/// it (`R3_w=scalar(...)`). The tree we capture against does not — our fixtures contain
/// zero `_w` tokens — but a log from an older kernel is exactly what a calibration run
/// produces, and without this the states do not parse AT ALL: the denominator silently
/// goes to zero while `parser_unrecognized` stays at zero too, because nothing was
/// rejected, merely never recognised.
fn reg_token_name_len(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    if b.is_empty() || b[0] != b'R' {
        return None;
    }
    let mut i = 1;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == 1 {
        return None;
    }
    if b[i..].starts_with(b"_w") {
        i += 2;
    }
    if i < b.len() && b[i] == b'=' {
        Some(i)
    } else {
        None
    }
}

/// Split a state string into `R<k>=<expr>` tokens. Robust to spaces inside a
/// value's parens (e.g. `var_off=(0x0; 0xff)`): tokens break only at a boundary
/// where a space is followed by `R<digits>=`.
fn split_reg_tokens(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let n = b.len();
    let mut starts = Vec::new();
    let mut i = 0;
    while i < n {
        if b[i] == b'R' && (i == 0 || b[i - 1] == b' ') && reg_token_name_len(&s[i..]).is_some() {
            starts.push(i);
        }
        i += 1;
    }
    let mut out = Vec::new();
    for k in 0..starts.len() {
        let a = starts[k];
        let e = if k + 1 < starts.len() { starts[k + 1] } else { n };
        out.push(s[a..e].trim());
    }
    out
}

fn parse_reg_tokens(s: &str) -> Vec<RegState> {
    split_reg_tokens(s)
        .into_iter()
        .filter_map(parse_reg_token)
        .collect()
}

/// The value part of a reg token: everything up to the first space at paren depth
/// 0. The verifier appends per-line metadata after the last register (e.g.
/// `R2=1 refs=2`), which must not be glued onto the value; but a value's own
/// parens may contain spaces (`var_off=(0x0; 0xff)`) and must be kept whole.
fn value_head(expr: &str) -> &str {
    let b = expr.as_bytes();
    let mut depth = 0i32;
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b' ' if depth <= 0 => return expr[..i].trim_end(),
            _ => {}
        }
    }
    expr
}

/// Parse one `R<k>=<expr>` token into a RegState.
fn parse_reg_token(tok: &str) -> Option<RegState> {
    let eq = reg_token_name_len(tok)?;
    // `R3` or `R3_w` — the write marker is not part of the register's identity.
    let digits = tok[1..eq].trim_end_matches("_w");
    let reg: u8 = digits.parse().ok()?;
    Some(build_regstate(reg, value_head(tok[eq + 1..].trim())))
}

/// Strip a pre-2022 SCALAR_VALUE type prefix, returning what follows it.
///
/// `reg_type_str[SCALAR_VALUE]` was `"inv"` until 2022 and a precise register got a
/// `"P"` appended (verifier.c, `print_verifier_state`). So the era prints `inv1337`,
/// `invP(id=0,...)`, `inv-5` and a bare `inv` for a fully unknown scalar.
///
/// The guard matters: `invP` must be tried before `inv`, and what follows the prefix
/// must actually begin a value — otherwise an unrelated type whose name merely starts
/// with those three letters would be silently re-labelled a scalar.
fn strip_legacy_scalar_prefix(expr: &str) -> Option<&str> {
    for p in ["invP", "inv"] {
        if let Some(rest) = expr.strip_prefix(p) {
            let ok = rest.is_empty()
                || rest.starts_with('(')
                || rest.starts_with('-')
                || rest.starts_with(|c: char| c.is_ascii_digit());
            if !ok {
                continue;
            }
            // `invP4294967295(id=0,imm=...,smin_value=...)` — the constant AND the field
            // list together. The kernel's ordinary per-insn line never emits this (a
            // constant scalar prints the bare number and returns, and has since 2017), but
            // a full-state dump does and commit messages quote it. The fields are explicit
            // while the leading number merely repeats var_off, so the field list is the
            // more informative parse — and taking it stops the whole token falling through
            // to the pointer branch and acquiring a reg_type of "4294967295".
            let digits = rest.len()
                - rest.trim_start_matches(|c: char| c.is_ascii_digit() || c == '-').len();
            if digits > 0 && rest[digits..].starts_with('(') {
                return Some(&rest[digits..]);
            }
            return Some(rest);
        }
    }
    None
}

/// The pre-2022 spelling of a bound field, if `key` has one.
///
/// The rename happened with the log rewrite that also shortened `R3_w=scalar(...)`:
/// `umin_value=` became `umin=`, `u32_min_value=` became `umin32=`. Every bound lookup
/// tries the modern name first and falls back to this. The two spellings cannot be
/// confused as substrings of one another — `umin=` does not occur inside
/// `umin_value=`, and `umin_value=` does not occur inside `u32_min_value=` — which is
/// the check this project's token collisions have twice been caught skipping.
fn legacy_bound_key(key: &str) -> Option<&'static str> {
    Some(match key {
        "umin=" => "umin_value=",
        "umax=" => "umax_value=",
        "smin=" => "smin_value=",
        "smax=" => "smax_value=",
        "umin32=" => "u32_min_value=",
        "umax32=" => "u32_max_value=",
        "smin32=" => "s32_min_value=",
        "smax32=" => "s32_max_value=",
        _ => return None,
    })
}

/// Interpret a register value expression into a RegState.
///
/// Never fabricates a malformed tnum: a const gets `mask=0`, an unknown scalar
/// gets `value=0` (so `value & mask == 0` always holds and the `diff` stage's
/// tnum invariant is not tripped by parsing).
fn build_regstate(reg: u8, expr: &str) -> RegState {
    // Pre-2022 kernels spell SCALAR_VALUE `inv`, with a `P` suffix when the register
    // is marked precise. `print_verifier_state` in that era emits the const form with
    // no parentheses at all (`verbose(env, "%lld", ...)` => `inv1337`, `inv-5`) and
    // the tracked form as `inv(id=0,...)`. Normalising here rather than in the diff
    // stage keeps ONE notion of "this is a scalar" in the pipeline; leaving it alone
    // sent every such register down the pointer branch, where it acquired the reg_type
    // "inv" and was then skipped by every scalar check — silently, since an
    // unrecognised FAMILY is reported but a skipped CHECK is not.
    let expr = strip_legacy_scalar_prefix(expr).unwrap_or(expr);

    // (a) const scalar: a bare integer (decimal/hex, maybe negative).
    if let Some((u, i)) = parse_const_int(expr) {
        return RegState {
            reg,
            reg_type: "scalar".to_string(),
            tnum: Tnum { value: u, mask: 0 },
            umin: u,
            umax: u,
            smin: i,
            smax: i,
            // A bare const carries no separate 32-bit view in the log.
            ..Default::default()
        };
    }
    // (b) scalar(...) with optional bounds / var_off. `expr` is empty or starts with
    // `(` when it arrived as a legacy `inv`/`invP` token, which the field lookups below
    // handle through their legacy aliases.
    if expr.is_empty() || expr == "scalar" || expr.starts_with("scalar(") || expr.starts_with('(')
    {
        let (value, mask) = parse_var_off(expr).unwrap_or((0, u64::MAX));
        return RegState {
            reg,
            reg_type: "scalar".to_string(),
            tnum: Tnum { value, mask },
            umin: field_u64(expr, "umin=").unwrap_or(0),
            umax: field_u64(expr, "umax=").unwrap_or(u64::MAX),
            smin: field_i64(expr, "smin=").unwrap_or(i64::MIN),
            smax: field_i64(expr, "smax=").unwrap_or(i64::MAX),
            // The 32-bit view is OPTIONAL because the kernel OMITS a bound that
            // sits at its extreme (log.c: `omit` when smin32 == S32_MIN, umax32 ==
            // U32_MAX, ...). `None` therefore means "the verifier said nothing here",
            // and the consumer — not the parser — decides that this is the same as
            // "at the extreme". Substituting the extreme here would turn a silence
            // into an observation.
            u32_min: field_u64(expr, "umin32="),
            u32_max: field_u64(expr, "umax32="),
            s32_min: field_s32(expr, "smin32="),
            s32_max: field_s32(expr, "smax32="),
            bounds_from_log: ["umin=", "umax=", "smin=", "smax="].iter().any(|k| {
                value_after_key(expr, k).is_some()
                    || legacy_bound_key(k)
                        .map(|l| value_after_key(expr, l).is_some())
                        .unwrap_or(false)
            }),
            // A scalar has no pointer base, so no constant pointer offset.
            ptr_off: None,
        };
    }
    // (c) pointer / ctx / fp / map_value / etc. — verbatim type prefix.
    //
    // A pointer's printed state carries the verifier's OWN claim about where a
    // store through it can land: a constant part (`off=`) plus a variable part
    // (`var_off` / `umin` / `umax`), e.g.
    //   R7=map_value(ks=4,vs=64,smin=0,smax=umax=7,var_off=(0x0; 0x7))
    // means "somewhere in [0,7], and only at offsets whose bits fit (0x0; 0x7)".
    // Defaulting those to zero — as this branch used to — silently discarded the
    // claim, so the store-location check had nothing to compare against.
    //
    // The two absences here follow DIFFERENT conventions, and conflating them is how
    // this branch first went wrong:
    //   * `var_off` absent = the variable part is a known constant, i.e. no unknown
    //     bits (mask 0). For a pointer the constant part is printed separately as
    //     `off=`, so `map_value(ks=4,vs=64)` really is "the value's first byte".
    //   * a BOUND absent = it sits at its EXTREME and the kernel omitted it (log.c
    //     prints umin/umax/smin/smax only when they differ from the defaults). This
    //     is the SAME convention the scalar branch uses, and it is not optional:
    //     `map_value(...,umin=0xfffffffffffffff0,var_off=(0xfffffffffffffff0; 0xf))`
    //     omits `umax` because it is U64_MAX. Reading that absence as 0 manufactures
    //     an inverted unsigned range and makes the bounds invariants fire on a
    //     perfectly consistent pointer state — a parser bug wearing a finding's
    //     clothes, which is exactly what the golden-fixture guardrail is for.
    let ty = expr.split(['(', ' ']).next().unwrap_or(expr);
    // `var_off=(v; m)` is printed only when the variable part is NOT a known constant.
    // When it IS constant the kernel prints the value as `imm=` instead, and only when
    // it is non-zero (log.c:682-687):
    //     if (tnum_is_const(reg->var_off)) { if (reg->var_off.value) verbose_a("imm="); }
    // So for a pointer, `imm=N` means var_off = {value: N, mask: 0} — the landing site is
    // pinned exactly. Missing it read the constant as 0, which is how a store through a
    // pointer with a fixed non-zero offset looked like it had escaped its own claim.
    // `off=` is a DIFFERENT field (reg->off), handled by parse_ptr_const_off.
    let (value, mask) = parse_var_off(expr)
        .unwrap_or_else(|| (parse_ptr_field(expr, "imm=").unwrap_or(0) as u64, 0));
    RegState {
        reg,
        reg_type: if ty.is_empty() { expr.to_string() } else { ty.to_string() },
        tnum: Tnum { value, mask },
        umin: field_u64(expr, "umin=").unwrap_or(0),
        umax: field_u64(expr, "umax=").unwrap_or(u64::MAX),
        smin: field_i64(expr, "smin=").unwrap_or(i64::MIN),
        smax: field_i64(expr, "smax=").unwrap_or(i64::MAX),
        ptr_off: parse_ptr_const_off(expr),
        ..Default::default()
    }
}

/// Parse a bare integer const: `13`, `-1`, `0xff`, `-0x10`. Returns (u64 bits, i64).
fn parse_const_int(s: &str) -> Option<(u64, i64)> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let v = u64::from_str_radix(h, 16).ok()?;
        return Some((v, v as i64));
    }
    if let Some(h) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        let v = i64::from_str_radix(h, 16).ok().map(|x| -x)?;
        return Some((v as u64, v));
    }
    if let Ok(v) = s.parse::<i64>() {
        return Some((v as u64, v));
    }
    if let Ok(v) = s.parse::<u64>() {
        return Some((v, v as i64));
    }
    None
}

/// Parse the generator's `STORE insn=<i> reg=<r> off=<o> size=<w>` declaration.
///
/// Provenance note: these are facts about the program the HARNESS built, emitted by
/// the harness — never recovered from the verifier's own disassembly. The oracle
/// must not learn where the store is from the component it is auditing.
/// Parse `EXPECT intended_retval=<n>` — the generator's own statement of what the program
/// must return, independent of anything the verifier said.
///
/// The token is deliberately not spelled `retval=`: `parse_runtime_samples` prefix-matches
/// that on every whitespace token, and this project has twice shipped a bug where one
/// output token was silently matched by another's pattern (devlog 0041, 0042).
/// Pair each `JITDIFF input=... retval_interp=...` with the JITted `RUNTIME` sample for the
/// same input.
///
/// One `JitInterpDiff` per record, so a disagreement on ANY input is reported — and the
/// pair carried is the FIRST one that differs, because that is the one worth triaging. With
/// no disagreement the first common input is carried, so the record still counts toward the
/// denominator instead of vanishing from it.
fn parse_jit_interp(
    runtime: &[&str],
    jitdiff: &[&str],
) -> Option<metrics::core::JitInterpDiff> {
    fn tok(l: &str, k: &str) -> Option<u64> {
        let v = l.split_whitespace().find_map(|t| t.strip_prefix(k))?;
        if let Some(h) = v.strip_prefix("0x") {
            u64::from_str_radix(h, 16).ok()
        } else {
            v.parse::<u64>().ok()
        }
    }
    if jitdiff.is_empty() {
        return None;
    }
    let mut first: Option<(u64, u64)> = None;
    for j in jitdiff {
        let input = tok(j, "input=")?;
        let interp = tok(j, "retval_interp=")?;
        let jit = runtime
            .iter()
            .find(|r| tok(r, "input=") == Some(input))
            .and_then(|r| tok(r, "retval="));
        let jit = match jit {
            Some(v) => v,
            None => continue,
        };
        if jit != interp {
            return Some(metrics::core::JitInterpDiff {
                retval_jit: jit as i64,
                retval_interp: interp as i64,
                data_out_equal: true,
            });
        }
        if first.is_none() {
            first = Some((jit, interp));
        }
    }
    first.map(|(jit, interp)| metrics::core::JitInterpDiff {
        retval_jit: jit as i64,
        retval_interp: interp as i64,
        data_out_equal: true,
    })
}

fn parse_intended_retval(line: &str) -> Option<u64> {
    let tok = line
        .split_whitespace()
        .find_map(|t| t.strip_prefix("intended_retval="))?;
    if let Some(h) = tok.strip_prefix("0x") {
        u64::from_str_radix(h, 16).ok()
    } else {
        tok.parse::<u64>().ok()
    }
}

fn parse_store_site(line: &str) -> Option<metrics::core::StoreSite> {
    let mut insn_idx = None;
    let mut base_reg = None;
    let mut insn_off = None;
    let mut size = None;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("insn=") {
            insn_idx = v.parse::<u32>().ok();
        } else if let Some(v) = tok.strip_prefix("reg=") {
            base_reg = v.parse::<u8>().ok();
        } else if let Some(v) = tok.strip_prefix("off=") {
            insn_off = v.parse::<i64>().ok();
        } else if let Some(v) = tok.strip_prefix("size=") {
            size = v.parse::<u32>().ok();
        }
    }
    Some(metrics::core::StoreSite {
        insn_idx: insn_idx?,
        base_reg: base_reg?,
        insn_off: insn_off?,
        size: size?,
    })
}

/// Parse the `PRUNE ...` line: the same program's verdict under three load flag
/// settings, declared by the GENERATOR that ran them.
///
/// The verdict tokens are `*_verdict=`, deliberately NOT `*_decision=`: the block's
/// own decision is matched as the substring `decision=` in several places, so a
/// `base_decision=accept` token would be counted as an extra program decision. Same
/// collision class as `find("off=")` matching inside `var_off=(...)`.
fn parse_prune_probe(line: &str) -> Option<metrics::core::PruneProbe> {
    let mut fall = None;
    let mut taken = None;
    let mut fall_safe = None;
    let mut taken_safe = None;
    let mut stack = false;
    let mut base_accept = None;
    let mut base_errno = 0i64;
    let mut base_states = 0u64;
    let mut base_reason = String::new();
    let mut freq_accept = None;
    let mut freq_errno = 0i64;
    let mut freq_states = 0u64;
    let mut freq_reason = String::new();
    let mut inv_accept = None;
    let mut inv_errno = 0i64;
    let mut inv_reason = String::new();
    let verdict = |v: &str| match v {
        "accept" => Some(true),
        "reject" => Some(false),
        _ => None,
    };
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("fall=") {
            fall = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("taken=") {
            taken = Some(v.to_string());
        } else if let Some(v) = tok.strip_prefix("fall_safe=") {
            fall_safe = v.parse::<i64>().ok().map(|n| n != 0);
        } else if let Some(v) = tok.strip_prefix("taken_safe=") {
            taken_safe = v.parse::<i64>().ok().map(|n| n != 0);
        } else if let Some(v) = tok.strip_prefix("stack=") {
            stack = v.parse::<i64>().map(|n| n != 0).unwrap_or(false);
        } else if let Some(v) = tok.strip_prefix("base_verdict=") {
            base_accept = verdict(v);
        } else if let Some(v) = tok.strip_prefix("base_errno=") {
            base_errno = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("base_states=") {
            base_states = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("base_reason=") {
            base_reason = v.to_string();
        } else if let Some(v) = tok.strip_prefix("freq_verdict=") {
            freq_accept = verdict(v);
        } else if let Some(v) = tok.strip_prefix("freq_errno=") {
            freq_errno = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("freq_states=") {
            freq_states = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("freq_reason=") {
            freq_reason = v.to_string();
        } else if let Some(v) = tok.strip_prefix("inv_verdict=") {
            inv_accept = verdict(v);
        } else if let Some(v) = tok.strip_prefix("inv_errno=") {
            inv_errno = v.parse().unwrap_or(0);
        } else if let Some(v) = tok.strip_prefix("inv_reason=") {
            inv_reason = v.to_string();
        }
    }
    Some(metrics::core::PruneProbe {
        fall: fall?,
        taken: taken?,
        fall_safe: fall_safe?,
        taken_safe: taken_safe?,
        stack,
        base_accept: base_accept?,
        base_errno,
        base_states,
        base_reason,
        freq_accept: freq_accept?,
        freq_errno,
        freq_states,
        freq_reason,
        inv_accept: inv_accept?,
        inv_errno,
        inv_reason,
    })
}

/// Parse a pointer's CONSTANT offset (`map_value(off=8,ks=4,vs=64)`) -> 8.
///
/// Deliberately boundary-aware: a plain `find("off=")` also matches inside
/// `var_off=(0x0; 0x7)`, which would read the VARIABLE part's known-bits as if it
/// were the constant part. The key must start the expression or follow `(` or `,`.
fn parse_ptr_const_off(expr: &str) -> Option<i64> {
    parse_ptr_field(expr, "off=")
}

/// Read one `key=<int>` field out of a pointer's printed state, boundary-aware.
///
/// The boundary check is not cosmetic: a plain `find("off=")` also matches inside
/// `var_off=(0x0; 0x7)`, which would read the VARIABLE part's known bits as if they were
/// the constant part. The key must start the expression or follow `(` or `,`.
fn parse_ptr_field(expr: &str, key: &str) -> Option<i64> {
    let b = expr.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = expr[from..].find(key) {
        let at = from + rel;
        let ok = at == 0 || b[at - 1] == b'(' || b[at - 1] == b',';
        if ok {
            let rest = &expr[at + key.len()..];
            let end = rest.find([',', ')', ' ']).unwrap_or(rest.len());
            return parse_const_int(rest[..end].trim()).map(|(_, i)| i);
        }
        from = at + key.len();
    }
    None
}

/// Parse `var_off=(<value>; <mask>)` -> (value, mask).
fn parse_var_off(s: &str) -> Option<(u64, u64)> {
    let start = s.find("var_off=(")? + "var_off=(".len();
    let rest = &s[start..];
    let close = rest.find(')')?;
    let mut parts = rest[..close].split(';');
    let v = parse_uint(parts.next()?.trim())?;
    let m = parse_uint(parts.next()?.trim())?;
    Some((v, m))
}

fn parse_uint(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Return the numeric token a `key` equals, skipping any chained `word=`
/// assignments the verifier prints for shared values (e.g. `smax=umax=255` or
/// `smax=umax=smax32=umax32=255` — all equal the trailing number).
fn value_after_key<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let b = s.as_bytes();
    let mut pos = s.find(key)? + key.len();
    loop {
        if pos < b.len() && (b[pos].is_ascii_digit() || b[pos] == b'-') {
            let start = pos;
            let mut end = pos;
            if b[end] == b'-' {
                end += 1;
            }
            while end < b.len()
                && (b[end].is_ascii_hexdigit() || b[end] == b'x' || b[end] == b'X')
            {
                end += 1;
            }
            return Some(&s[start..end]);
        }
        // Skip an intervening `word=` chain (`umax=` in `smax=umax=255`).
        let start = pos;
        while pos < b.len() && (b[pos].is_ascii_alphanumeric() || b[pos] == b'_') {
            pos += 1;
        }
        if pos > start && pos < b.len() && b[pos] == b'=' {
            pos += 1;
            continue;
        }
        return None;
    }
}

/// The token a bound field equals, under either the modern or the pre-2022 spelling.
fn bound_token<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    value_after_key(s, key).or_else(|| value_after_key(s, legacy_bound_key(key)?))
}

fn field_u64(s: &str, key: &str) -> Option<u64> {
    parse_uint(bound_token(s, key)?)
}

fn field_i64(s: &str, key: &str) -> Option<i64> {
    let (_, i) = parse_const_int(bound_token(s, key)?)?;
    Some(i)
}

/// Parse a 32-bit SIGNED bound (`smin32=` / `smax32=`), which the kernel prints by
/// a rule the 64-bit fields do not share.
///
/// `kernel/bpf/log.c:print_scalar_ranges()` states it outright: signed values are
/// printed as decimals when they read naturally, otherwise in hex — and
/// "we avoid sign extension if we choose to print values in hex". So
/// `smin32=0x80000010` is the raw `(u32)` bit pattern of a NEGATIVE number
/// (-2147483632), not the positive integer it reads as. Parsing it as a plain
/// integer yields a value outside the i32 domain entirely, which then looks exactly
/// like the verifier reporting an inverted range.
///
/// Decimal forms are already sign-correct and pass through untouched.
fn field_s32(s: &str, key: &str) -> Option<i64> {
    let tok = bound_token(s, key)?;
    let is_hex = tok.starts_with("0x") || tok.starts_with("0X") || tok.starts_with("-0x");
    let (u, i) = parse_const_int(tok)?;
    if is_hex {
        // Reinterpret the printed 32-bit pattern as i32, then widen.
        Some((u as u32) as i32 as i64)
    } else {
        Some(i)
    }
}

/// Parse the leading unsigned integer immediately after `key` in `s`.
fn num_after(s: &str, key: &str) -> Option<u64> {
    let idx = s.find(key)? + key.len();
    let digits: String = s[idx..].chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Normalize a verifier reg-type to a coarse FAMILY for helper-arg comparison:
/// stack pointers (`fp-4`, `fp0`) collapse to `fp`; everything else (already
/// stripped of its `(...)` detail by `build_regstate`) passes through.
fn reg_family(reg_type: &str) -> String {
    if reg_type.starts_with("fp") {
        "fp".to_string()
    } else {
        reg_type.to_string()
    }
}

/// Extract helper-call argument OBSERVATIONS from the verifier log: accumulate
/// each register's reg-type family across the (un-indented) state trace, and at a
/// `(85) call <helper>#<id>` site record the observed family of arg registers
/// R1..R5 that have a tracked state (arg N = R(N+1)). The EXPECTED arg_type is not
/// decided here — that is ground truth's job at the `diff` stage.
fn parse_helper_calls(log: &[&str]) -> Vec<HelperArgObservation> {
    use std::collections::BTreeMap;
    let mut current: BTreeMap<u8, String> = BTreeMap::new();
    let mut obs = Vec::new();

    for line in log {
        if line.starts_with(' ') {
            continue; // indented preamble / liveness / precision annotations
        }
        let t = line.trim();
        let colon = match t.find(':') {
            Some(c) => c,
            None => continue,
        };
        let head = &t[..colon];
        if head.is_empty() || !head.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let rest = t[colon + 1..].trim_start();

        // Full-state line ("R1=ctx() R10=fp0"): refresh every listed reg.
        if looks_like_reg_token_start(rest) {
            for r in parse_reg_tokens(rest) {
                current.insert(r.reg, reg_family(&r.reg_type));
            }
            continue;
        }

        // Instruction line: "(op) disasm [; <state deltas>]".
        let (disasm, state) = match rest.find(';') {
            Some(i) => (rest[..i].trim(), rest[i + 1..].trim()),
            None => (rest, ""),
        };

        // A call site: record args from the state accumulated BEFORE this insn.
        if let Some(helper) = disasm.strip_prefix("(85) call ").map(|h| {
            h.split(['#', ' ']).next().unwrap_or(h).to_string()
        }) {
            for reg in 1u8..=5 {
                if let Some(fam) = current.get(&reg) {
                    obs.push(HelperArgObservation {
                        helper: helper.clone(),
                        arg_index: reg - 1,
                        observed: fam.clone(),
                    });
                }
            }
        }

        // Apply this line's state deltas (e.g. the call's `; R0=map_value`).
        if !state.is_empty() {
            for r in parse_reg_tokens(state) {
                current.insert(r.reg, reg_family(&r.reg_type));
            }
        }
    }
    obs
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real diffharness output (host kernel 6.18), trimmed to the three blocks.
    // Mirrors harness/samples/host-6.18-sample.txt — the parser's known-good input.
    const SAMPLE: &str = "\
===PROG return0 type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=68595
---LOG---
func#0 @0
Live regs before insn:
      0: .......... (b7) r0 = 0
      1: 0......... (95) exit
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=0
1: (95) exit
processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0

---END---
===PROG alu_state type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=30275
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 1                        ; R0=1
1: (67) r0 <<= 3                      ; R0=8
2: (57) r0 &= 255                     ; R0=8
3: (07) r0 += 5                       ; R0=13
4: (95) exit
processed 5 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
---END---
===PROG uninit_r0 type=socket_filter ===
RESULT decision=reject fd=-1 errno=13 load_ns=14182
---LOG---
0: R1=ctx() R10=fp0
0: (95) exit
R0 !read_ok
processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
---END---
";

    fn parse_all() -> Vec<CoreMetrics> {
        VerifierLogParser
            .parse("diffharness", SAMPLE.as_bytes())
            .records
            .into_iter()
            .map(|r| r.core)
            .collect()
    }

    fn reg_in(snaps: &[RegSnapshot], reg: u8) -> Option<RegState> {
        snaps
            .iter()
            .flat_map(|s| s.regs.iter())
            .find(|r| r.reg == reg)
            .cloned()
    }

    #[test]
    fn parses_three_programs() {
        assert_eq!(parse_all().len(), 3);
    }

    #[test]
    fn return0_is_accept_with_counters_and_const_r0() {
        let c = &parse_all()[0];
        assert_eq!(c.verifier_decision, VerifierDecision::Accept);
        assert_eq!(c.processed.insn_processed, 2);
        assert_eq!(c.processed.states_processed, 0);
        assert!(c.jit_interp_diff.is_none());
        // R0=0 const scalar: tnum well-formed (mask 0), bounds pinned to 0.
        let r0 = reg_in(&c.register_evolution, 0).expect("R0 present");
        assert_eq!(r0.reg_type, "scalar");
        assert_eq!(r0.tnum, Tnum { value: 0, mask: 0 });
        assert_eq!((r0.umin, r0.umax, r0.smin, r0.smax), (0, 0, 0, 0));
        // Non-scalar ctx/fp captured verbatim as reg types.
        let r1 = reg_in(&c.register_evolution, 1).expect("R1 present");
        assert_eq!(r1.reg_type, "ctx");
        let r10 = reg_in(&c.register_evolution, 10).expect("R10 present");
        assert_eq!(r10.reg_type, "fp0");
    }

    #[test]
    fn alu_state_tracks_r0_evolution() {
        let c = &parse_all()[1];
        assert_eq!(c.verifier_decision, VerifierDecision::Accept);
        assert_eq!(c.processed.insn_processed, 5);
        // The R0 values seen across the program, in order.
        let r0_vals: Vec<u64> = c
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .filter(|r| r.reg == 0)
            .map(|r| r.tnum.value)
            .collect();
        assert_eq!(r0_vals, vec![1, 8, 8, 13]);
        // Every parsed tnum stays well-formed (value & mask == 0).
        for snap in &c.register_evolution {
            for r in &snap.regs {
                assert_eq!(r.tnum.value & r.tnum.mask, 0, "malformed tnum from parser");
            }
        }
    }

    #[test]
    fn uninit_r0_is_reject_with_verbatim_reason() {
        let c = &parse_all()[2];
        assert_eq!(
            c.verifier_decision,
            VerifierDecision::Reject {
                reason: "R0 !read_ok".to_string()
            }
        );
        assert_eq!(c.processed.insn_processed, 1);
    }

    #[test]
    fn extracts_the_32_bit_subregister_view() {
        let r = parse_reg_token("R0=scalar(umin=256,umax=511,umin32=1000,umax32=2000)")
            .expect("reg parses");
        assert_eq!((r.umin, r.umax), (256, 511));
        assert_eq!((r.u32_min, r.u32_max), (Some(1000), Some(2000)));
        // Omitted fields stay None: the kernel drops a bound sitting at its extreme
        // (log.c), and turning that silence into a number here would invent an
        // observation the verifier never made.
        assert_eq!((r.s32_min, r.s32_max), (None, None));
    }

    #[test]
    fn a_hex_printed_s32_is_read_as_a_32_bit_signed_value() {
        // kernel/bpf/log.c:print_scalar_ranges() prints signed bounds in hex WITHOUT
        // sign extension, so `smin32=0x80000010` is the raw u32 pattern of
        // -2147483632. Reading it as a plain integer yields +2147483664 — outside the
        // i32 domain entirely — which then looks exactly like an inverted range.
        // That mistake produced ten bogus findings on the first real capture (0026).
        let r = parse_reg_token(
            "R0=scalar(smin=umin=256,smax=umax=0x1000000ff,smin32=0x80000010,var_off=(0x10; 0x1ffffffef))",
        )
        .expect("reg parses");
        assert_eq!(r.s32_min, Some(-2_147_483_632));
        // The 64-bit fields keep two's-complement semantics on the full width.
        assert_eq!(r.smax, 0x1_000_000_ff);
    }

    #[test]
    fn a_prune_point_state_dump_is_attributed_to_the_instruction_it_names() {
        // `verbose(env, "\nfrom %d to %d%s:", env->prev_insn_idx, env->insn_idx, ...)`
        // followed by print_verifier_state(print_all=true). The SECOND number is the
        // instruction the state belongs to; the head is not all digits, so the ordinary
        // digit-head test dropped the whole line.
        let snaps = parse_register_evolution(&[
            "from 33 to 15: R0=scalar(umin=1,umax=7) R10=fp0",
        ]);
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].insn_idx, 15, "the DESTINATION index, not the source");
        assert_eq!(snaps[0].regs.len(), 2);
        assert_eq!((snaps[0].regs[0].umin, snaps[0].regs[0].umax), (1, 7));

        // The speculative-execution marker sits between the index and the colon.
        let spec = parse_register_evolution(&[
            "from 8 to 10 (speculative execution): R1=ctx() R10=fp0",
        ]);
        assert_eq!(spec.len(), 1);
        assert_eq!(spec[0].insn_idx, 10);

        // A `frameN:` prefix still comes off first.
        let framed = parse_register_evolution(&["from 21 to 32: frame1: R10=fp0"]);
        assert_eq!(framed.len(), 1);
        assert_eq!(framed[0].insn_idx, 32);

        // The pruned-state variant carries no register state and must add nothing.
        assert!(parse_register_evolution(&["from 33 to 15: safe"]).is_empty());
    }

    /// THE TRAP THIS PARSER EXISTS TO AVOID. `liveness.c` prints an optional SCC id before
    /// the instruction index (`%3d ` then `%3d: `), so a row for instruction 20 inside SCC 2
    /// reads `"  2  20: ..."`. Treating the SCC field as an optional leading run of digits
    /// makes the index parse as 0 — every row in the program mis-attributed, with a
    /// perfectly plausible-looking agreement rate coming out the other end. It was measured
    /// wrong exactly once, by taking the FIRST digits instead of the last token.
    #[test]
    fn the_scc_prefix_is_not_part_of_the_instruction_index() {
        assert_eq!(
            parse_liveness_row("      0: .1........ (7b) *(u64 *)(r10 -16) = r1"),
            Some((0, 0b0000000010))
        );
        assert_eq!(
            parse_liveness_row("  2  20: .......7.. (72) *(u8 *)(r7 +0) = -1"),
            Some((20, 0b0010000000))
        );
        // A column is the register's own number when live, so the DIGIT is redundant with
        // the position. The position is what is read.
        assert_eq!(
            parse_liveness_row("     13: ..2.4..7.. (04) w2 += 1073741824"),
            Some((13, 0b0010010100))
        );
        assert_eq!(parse_liveness_row("     16: .......... (05) goto pc+6"), Some((16, 0)));
        // Not table rows.
        assert!(parse_liveness_row("Live regs before insn:").is_none());
        assert!(parse_liveness_row("      R0=scalar() R10=fp0").is_none());
        assert!(parse_liveness_row("     16: ......... (05) goto pc+6").is_none()); // 9 cols
    }

    #[test]
    fn a_liveness_claim_without_a_matching_length_is_refused_not_padded() {
        let table = ["Live regs before insn:", "      0: 0......... (95) exit"];
        // Well-formed: two instructions, three hex digits each.
        let g = parse_liveness_gate(Some("LIVENESS status=ok n=2 mask=001000"), &table).unwrap();
        assert_eq!(g.claim_status, "ok");
        assert_eq!(g.claim.unwrap(), vec![0x001, 0x000]);
        assert_eq!(g.kernel, vec![(0, 1)]);

        // Ragged: n says three instructions, the mask carries two. Padding it would invent
        // a disagreement with the kernel on the instruction that is missing.
        let g = parse_liveness_gate(Some("LIVENESS status=ok n=3 mask=001000"), &table).unwrap();
        assert!(g.claim.is_none());
        assert_eq!(g.claim_status, "malformed");

        // The harness declining to model a program is recorded, never silently dropped.
        let g = parse_liveness_gate(
            Some("LIVENESS status=unsupported n=9 at=4 why=opcode_outside_the_model"),
            &table,
        )
        .unwrap();
        assert!(g.claim.is_none());
        assert!(g.claim_status.starts_with("unsupported: "));

        // No claim at all: nothing to compare against, so no gate is recorded.
        assert!(parse_liveness_gate(None, &table).is_none());
    }

    #[test]
    fn the_caller_state_at_a_subprogram_return_is_read_from_its_indented_dump() {
        // `to caller at %d:` states the index; print_verifier_state then emits the state on
        // the NEXT line, starting with a space (log.c: `verbose(env, " R%d", i)`). Every
        // space-prefixed line used to be discarded as liveness noise, so this — the only
        // place the register transfer at a call boundary is ever printed — vanished.
        let snaps = parse_register_evolution(&[
            "33: (95) exit",
            "returning from callee:",
            " frame1: R0=0 R10=fp0",
            "to caller at 15:",
            " R0=0 R10=fp0",
        ]);
        // Exactly one dump is taken: the one whose index the log states. `returning from
        // callee:` names no instruction, and inventing one would feed the store-location
        // check a claim the verifier never made at that site.
        let taken: Vec<_> = snaps.iter().filter(|s| s.insn_idx == 15).collect();
        assert_eq!(taken.len(), 1, "{snaps:?}");
        assert_eq!(taken[0].regs.len(), 2);
        assert_eq!(taken[0].regs[0].reg, 0);
        assert_eq!(taken[0].regs[0].umax, 0);
        assert!(
            snaps.iter().all(|s| s.insn_idx == 15 || s.insn_idx == 33),
            "no snapshot may be invented for an unindexed dump: {snaps:?}"
        );
    }

    #[test]
    fn indented_liveness_lines_are_still_discarded() {
        // The reason the space-prefixed class was blanket-dropped in the first place. A
        // liveness line has a digit head and no register tokens; it must not become a
        // snapshot, and must not consume a pending caller index either.
        let snaps = parse_register_evolution(&[
            "Live regs before insn:",
            "      0: .......... (85) call bpf_get_prandom_u32#7",
            "      1: 0......... (57) r0 &= 1",
        ]);
        assert!(snaps.is_empty(), "{snaps:?}");
    }

    #[test]
    fn flag_prefixed_and_btf_id_pointer_types_are_known_families() {
        // log.c:435-443 glues the set type flags in front of the base name, and
        // PTR_TO_BTF_ID's base is `ptr_` with the struct name appended (log.c:418, :650).
        // `rdonly_mem` is an ordinary read-only dynptr slice and was reported as an unknown
        // family on 634 of the composition corpus's 896 records.
        assert_eq!(base_family("rdonly_mem"), "mem");
        assert_eq!(base_family("ringbuf_mem"), "mem");
        assert_eq!(base_family("rcu_untrusted_mem"), "mem");
        assert_eq!(base_family("ptr_sk_buff"), "ptr");
        assert_eq!(base_family("trusted_ptr_task_struct"), "ptr");
        assert_eq!(base_family("ptr_or_null_sk_buff"), "ptr");
        assert_eq!(base_family("map_value_or_null"), "map_value");
        assert_eq!(base_family("fp-16"), "fp");
        // And a genuinely unknown family must still come through as unknown, or the
        // whitelist has stopped doing its job.
        assert_eq!(base_family("something_new"), "something_new");
    }

    #[test]
    fn the_pre_2022_scalar_spelling_is_recognised_as_a_scalar() {
        // `reg_type_str[SCALAR_VALUE]` was "inv" until 2022, with "P" appended for a
        // precise register, and the const form carries no parentheses at all.
        let c = parse_reg_token("R0_w=inv1337").expect("const");
        assert_eq!(c.reg_type, "scalar");
        assert_eq!((c.umin, c.umax, c.tnum.value, c.tnum.mask), (1337, 1337, 1337, 0));

        let neg = parse_reg_token("R1=inv-5").expect("negative const");
        assert_eq!(neg.reg_type, "scalar");
        assert_eq!(neg.smin, -5);

        let unknown = parse_reg_token("R2=inv").expect("fully unknown");
        assert_eq!(unknown.reg_type, "scalar");
        assert_eq!(unknown.tnum.mask, u64::MAX);

        let precise = parse_reg_token(
            "R3_w=invP(id=0,umin_value=1,umax_value=255,var_off=(0x1; 0xfe),u32_min_value=1,u32_max_value=255)",
        )
        .expect("precise tracked scalar");
        assert_eq!(precise.reg_type, "scalar");
        assert_eq!((precise.umin, precise.umax), (1, 255));
        assert_eq!((precise.u32_min, precise.u32_max), (Some(1), Some(255)));
        assert_eq!((precise.tnum.value, precise.tnum.mask), (1, 0xfe));
    }

    #[test]
    fn a_type_that_merely_starts_with_inv_is_not_relabelled_a_scalar() {
        // The prefix strip must require a value to follow. Turning an unrelated type
        // into a scalar would hand it to every scalar invariant with zeroed bounds —
        // a fabricated observation, which is worse than an unrecognised family.
        let r = parse_reg_token("R4=invalid(off=0)").expect("token");
        assert_eq!(r.reg_type, "invalid");
    }

    #[test]
    fn the_pre_2022_bound_field_names_are_read() {
        // `umin_value=` / `u32_min_value=` became `umin=` / `umin32=` with the 2022 log
        // rewrite. Neither spelling occurs inside the other, so the fallback cannot
        // collide — the check this project's token bugs have twice been caught skipping.
        let r = parse_reg_token(
            "R2_w=inv(id=0,smin_value=-9223372036854775807 (0x8000000000000001),umin_value=1,umax_value=0xffffffff00000001,var_off=(0x1; 0xffffffff00000000),s32_min_value=1,s32_max_value=1,u32_min_value=1,u32_max_value=1)",
        )
        .expect("token");
        assert_eq!((r.umin, r.umax), (1, 0xffffffff00000001));
        assert_eq!(r.smin, -9223372036854775807);
        assert_eq!((r.u32_min, r.u32_max), (Some(1), Some(1)));
        assert_eq!((r.s32_min, r.s32_max), (Some(1), Some(1)));
        // The commit message glosses signed bounds with a hex form the kernel never
        // prints; the annotation must be ignored, not folded into the value.
        assert_eq!(r.tnum.mask, 0xffffffff00000000);
    }

    #[test]
    fn a_decimal_negative_s32_passes_through_unchanged() {
        let r = parse_reg_token("R0=scalar(umin=0,umax=100,smin32=-5,smax32=-4)")
            .expect("reg parses");
        assert_eq!((r.s32_min, r.s32_max), (Some(-5), Some(-4)));
    }

    #[test]
    fn tokenizer_handles_spaces_inside_var_off() {
        // Synthetic full-scalar form (not in the host sample) — best-effort path.
        let toks = split_reg_tokens("R0=scalar(umin=0,umax=255,var_off=(0x0; 0xff)) R6=ctx()");
        assert_eq!(toks, vec!["R0=scalar(umin=0,umax=255,var_off=(0x0; 0xff))", "R6=ctx()"]);
        let r0 = parse_reg_token(toks[0]).unwrap();
        assert_eq!(r0.reg_type, "scalar");
        assert_eq!(r0.tnum, Tnum { value: 0, mask: 0xff });
        assert_eq!((r0.umin, r0.umax), (0, 255));
        assert_eq!(r0.tnum.value & r0.tnum.mask, 0);
    }

    // Forms first surfaced by REPLAYING THE SYZKALLER CORPUS (volume), pinned so
    // they cannot regress. Each was a real parser blind-spot found by volume, not
    // a verifier bug — see devlog 0018.
    #[test]
    fn volume_discovered_forms_parse_correctly() {
        // (a) trailing per-line metadata (`refs=2`) must not glue onto the value,
        // (b) `_or_null` is a nullability suffix, not an unknown family.
        const VOL: &str = "\
===PROG syz#0 type=3 ===
RESULT decision=accept fd=3 errno=0 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
7: (bf) r9 = r0                       ; R0=ringbuf_mem_or_null(id=2,ref_obj_id=2,sz=20) R9=ringbuf_mem_or_null(id=2,ref_obj_id=2,sz=20) refs=2
11: (b7) r2 = 1                       ; R2=1 refs=2
12: (95) exit
processed 13 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        let out = VerifierLogParser.parse("syzreplay", VOL.as_bytes());
        assert_eq!(out.records.len(), 1);
        assert!(out.unparsed.is_empty());
        let rec = &out.records[0];
        assert!(
            rec.notes.is_empty(),
            "no blind-spot notes expected for these forms: {:?}",
            rec.notes
        );
        let regs: Vec<(u8, String, u64)> = rec
            .core
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .map(|r| (r.reg, r.reg_type.clone(), r.tnum.value))
            .collect();
        // `R2=1 refs=2` is the const 1, NOT a reg-type called "1".
        assert!(
            regs.iter().any(|(reg, ty, v)| *reg == 2 && ty == "scalar" && *v == 1),
            "R2 should be const scalar 1: {regs:?}"
        );
        // The or_null pointer keeps its verbatim reg-type (no metadata glued on).
        assert!(
            regs.iter().any(|(reg, ty, _)| *reg == 0 && ty == "ringbuf_mem_or_null"),
            "R0 keeps its verbatim reg-type: {regs:?}"
        );
    }

    // A load that fails before/without verification produces no log; inventing a
    // reject reason there would fabricate verifier text -> it is a blind-spot.
    #[test]
    fn empty_verifier_log_is_unparsed_not_a_reject_record() {
        const EMPTY: &str = "\
===PROG syz#1 type=3 ===
RESULT decision=reject fd=-1 errno=7 load_ns=2357
---LOG---

---END---
";
        let out = VerifierLogParser.parse("syzreplay", EMPTY.as_bytes());
        assert!(out.records.is_empty(), "no record invented from an empty log");
        assert_eq!(out.unparsed.len(), 1);
        assert!(
            out.unparsed[0].reason.contains("empty verifier log"),
            "{:?}",
            out.unparsed[0]
        );
    }

    // Reject-log forms found by the FIRST SYZKALLER-DRIVEN VOLUME PERIOD (devlog
    // 0018). Most real rejects fail before any per-insn state is printed, so the
    // reason scan must not require a state section first.
    #[test]
    fn reject_reason_without_any_state_section() {
        const R: &str = "\
===PROG syz#0 type=3 ===
RESULT decision=reject fd=-1 errno=22 load_ns=1
---LOG---
func#0 @0
last insn is not an exit or jmp
Verification failed: Program Structure: Subprogram can fall through
Reason:
  Subprogram 0 reaches its last instruction 117 without an exit or jump.
At:
  insn 117
Suggestion:
  End each subprogram with an exit.
processed 0 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        let out = VerifierLogParser.parse("syzreplay", R.as_bytes());
        assert_eq!(out.records.len(), 1);
        assert_eq!(
            out.records[0].core.verifier_decision,
            VerifierDecision::Reject {
                reason: "last insn is not an exit or jmp".to_string()
            },
            "the concise verifier token, not the structured headline or 'unknown'"
        );
        assert!(out.records[0].notes.is_empty());
    }

    // Some messages are emitted without a trailing newline, gluing the `processed`
    // summary onto the failure text; it must be cut back off.
    #[test]
    fn glued_processed_summary_is_stripped_from_the_reason() {
        const R: &str = "\
===PROG syz#1 type=3 ===
RESULT decision=reject fd=-1 errno=22 load_ns=1
---LOG---
func#0 @0
invalid type id 1 in func infoprocessed 0 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        let out = VerifierLogParser.parse("syzreplay", R.as_bytes());
        assert_eq!(
            out.records[0].core.verifier_decision,
            VerifierDecision::Reject {
                reason: "invalid type id 1 in func info".to_string()
            }
        );
    }

    // A reject whose log carries no failure text at all: flag it as a blind-spot
    // rather than fabricating verifier text.
    #[test]
    fn unidentifiable_reject_reason_is_noted_not_invented() {
        const R: &str = "\
===PROG syz#2 type=3 ===
RESULT decision=reject fd=-1 errno=22 load_ns=1
---LOG---
processed 0 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        let out = VerifierLogParser.parse("syzreplay", R.as_bytes());
        assert_eq!(out.records.len(), 1, "still an observation (decision is known)");
        assert!(
            out.records[0]
                .notes
                .iter()
                .any(|n| n.contains("reject reason not identified")),
            "the gap is surfaced as a parse note: {:?}",
            out.records[0].notes
        );
    }

    // Precision-tracking lines are analysis scaffolding, never a failure reason.
    #[test]
    fn mark_precise_lines_are_not_mistaken_for_a_reason() {
        const R: &str = "\
===PROG syz#3 type=3 ===
RESULT decision=reject fd=-1 errno=22 load_ns=1
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 1                        ; R0=1
R0 !read_ok
mark_precise: frame0: last_idx 9 first_idx 0 subseq_idx -1
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        let out = VerifierLogParser.parse("syzreplay", R.as_bytes());
        assert_eq!(
            out.records[0].core.verifier_decision,
            VerifierDecision::Reject {
                reason: "R0 !read_ok".to_string()
            }
        );
    }

    /// SCC walk markers (kernel/bpf/states.c) print between insn lines and BEFORE
    /// the real failure text. Reporting one as the reject reason yields a
    /// plausible-but-WRONG value — worse than "unknown". Real block from volume.
    #[test]
    fn scc_markers_are_not_mistaken_for_the_reject_reason() {
        const R: &str = "\
===PROG syz#0 type=3 ===
RESULT decision=reject fd=-1 errno=22 load_ns=1
---LOG---
func#0 @0
11: (18) r3 = 0xffff888005af5d20      ; R3=map_value(ks=4,vs=8)
13: (b7) r5 = 8
SCC enter (1)
14:
14: (85) call bpf_for_each_map_elem#164
R1 type=fp expected=map_ptr
Verification failed: Call Type Safety: Invalid call argument
Reason:
Suggestion:
processed 13 insns (limit 1000000) total_states 1 peak_states 1
---END---
";
        let out = VerifierLogParser.parse("syzreplay", R.as_bytes());
        assert_eq!(
            out.records[0].core.verifier_decision,
            VerifierDecision::Reject {
                reason: "R1 type=fp expected=map_ptr".to_string()
            },
            "the real verifier message, not the SCC scaffolding that precedes it"
        );
    }

    // Authoritative in-VM capture from the self-built bpf-next kernel: a richer log
    // (topo_order/subprog/stack use-def preamble + multi-line reject diagnostic).
    const BPF_NEXT_SAMPLE: &str = include_str!("../../../harness/samples/bpf-next-sample.txt");

    #[test]
    fn parses_bpf_next_richer_format() {
        let recs: Vec<CoreMetrics> = VerifierLogParser
            .parse("diffharness", BPF_NEXT_SAMPLE.as_bytes())
            .records
            .into_iter()
            .map(|r| r.core)
            .collect();
        assert_eq!(
            recs.len(),
            20,
            "20 blocks (3 basic + 3 ranged + 1 helper + 3 documented prose + 10 documented messages)"
        );

        // Accept + counters survive the extra preamble.
        assert_eq!(recs[0].verifier_decision, VerifierDecision::Accept);
        assert_eq!(recs[0].processed.insn_processed, 2);

        // The pre-analysis disasm (indented) must NOT create bogus snapshots — the
        // R0 evolution is still exactly the real state line values.
        let r0_vals: Vec<u64> = recs[1]
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .filter(|r| r.reg == 0)
            .map(|r| r.tnum.value)
            .collect();
        assert_eq!(r0_vals, vec![1, 8, 8, 13]);

        // Reject reason is the concise token, NOT the trailing "Suggestion:" line.
        assert_eq!(
            recs[2].verifier_decision,
            VerifierDecision::Reject {
                reason: "R0 !read_ok".to_string()
            }
        );

        // FULL scalar(...) form on REAL data — the chained-value fields
        // (`smax=umax=smax32=umax32=255`) and var_off must parse correctly.
        // ranged_and (rec 3): `r0 &= 255` -> var_off=(0x0; 0xff), bounds 0..255.
        let masked = recs[3]
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .find(|r| r.reg == 0 && r.tnum.mask == 0xff)
            .expect("masked R0 scalar present");
        assert_eq!(masked.reg_type, "scalar");
        assert_eq!(masked.tnum, Tnum { value: 0, mask: 0xff });
        assert_eq!((masked.umin, masked.umax), (0, 255));
        assert_eq!((masked.smin, masked.smax), (0, 255));

        // shift_unknown (rec 4): `r0 <<= 8` -> var_off=(0x0; 0xffffffff00).
        let shifted = recs[4]
            .register_evolution
            .iter()
            .flat_map(|s| s.regs.iter())
            .find(|r| r.reg == 0 && r.tnum.mask == 0xffffffff00)
            .expect("shifted R0 scalar present");
        assert_eq!(shifted.tnum.value, 0);

        // map_lookup (rec 6): the helper-call parser OBSERVES the arg reg-type
        // families from the real call site — no expected/decision here.
        let mlk = &recs[6].helper_arg_observations;
        assert!(
            mlk.iter().any(|o| o.helper == "bpf_map_lookup_elem" && o.arg_index == 0 && o.observed == "map_ptr"),
            "arg0 observed as map_ptr; got {mlk:?}"
        );
        assert!(
            mlk.iter().any(|o| o.helper == "bpf_map_lookup_elem" && o.arg_index == 1 && o.observed == "fp"),
            "arg1 observed as fp (PTR_TO_STACK); got {mlk:?}"
        );
        // The scalar-only programs record NO helper observations.
        assert!(recs[3].helper_arg_observations.is_empty());

        // The 10 documented-message programs (verifier.rst:353-560) all parse, and
        // their reject reasons are pinned VERBATIM. This is the parser-level
        // confirmation-bias guard: these five error shapes are new to the corpus
        // (`unreachable insn`, stack write, misaligned value, mem access, unreleased
        // reference), so if the parser ever starts mangling one, the test fails here
        // instead of the detector quietly reporting a clean period.
        let labelled = VerifierLogParser.parse("diffharness", BPF_NEXT_SAMPLE.as_bytes());
        let by_label = |id: &str| {
            labelled
                .records
                .iter()
                .find(|r| r.label.as_deref() == Some(id))
                .unwrap_or_else(|| panic!("{id} missing from the authoritative capture"))
        };
        let reason = |id: &str| match &by_label(id).core.verifier_decision {
            VerifierDecision::Reject { reason } => reason.clone(),
            VerifierDecision::Accept => "accept".to_string(),
        };
        assert_eq!(reason("doc_msg_unreachable_insn"), "unreachable insn 1");
        assert_eq!(reason("doc_msg_uninit_r0_exit"), "R0 !read_ok");
        assert_eq!(reason("doc_msg_stack_oob"), "invalid write to stack R10 off=8 size=8");
        assert_eq!(
            reason("doc_msg_unchecked_map_value"),
            "R0 invalid mem access 'map_value_or_null'"
        );
        assert_eq!(reason("doc_msg_misaligned_value"), "misaligned value access off 0+4 size 8");
        assert_eq!(reason("doc_msg_branch_imm_deref"), "R0 invalid mem access 'scalar'");
        assert_eq!(reason("doc_msg_invalid_map_fd"), "fd 0 is not pointing to valid bpf_map");
        assert_eq!(reason("doc_msg_unreleased_ref_null"), "Unreleased reference id=2 alloc_insn=7");
        assert_eq!(reason("doc_msg_unreleased_ref_nocheck"), "Unreleased reference id=2 alloc_insn=7");
        // The one documented case the current kernel ACCEPTS — kept pinned so the
        // supersede citation in `groundtruth::verifier_rst` is measured, not assumed.
        assert_eq!(
            by_label("doc_msg_uninit_stack_arg").core.verifier_decision,
            VerifierDecision::Accept
        );

        // Every parsed tnum stays well-formed (value & mask == 0) across all recs —
        // the parser must never manufacture an inconsistency that diff would flag.
        for rec in &recs {
            for snap in &rec.register_evolution {
                for r in &snap.regs {
                    assert_eq!(r.tnum.value & r.tnum.mask, 0, "malformed tnum from parser");
                }
            }
        }
    }

    // Kernel printk spliced into the serial capture (devlog: the Win11/KVM cash-in,
    // 2026-09-01). Both shapes below are VERBATIM from real bpf-next runs. This is
    // the parser-not-verifier guardrail: before the repair, the split summary line
    // silently reported `total_states 1` as `0` with NO note and NO unparsed block,
    // which is exactly a parser bug wearing a verifier observation's clothes.
    #[test]
    fn console_interleaving_is_repaired_and_recorded() {
        // Captured at gen-kvm.log:1593 — the printk lands mid-token, inside
        // `max_states_per_insn`, so `total_states` ends up on the next line.
        const SPLIT_SUMMARY: &str = "\
===PROG p type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=100
---LOG---
0: R1=ctx() R10=fp0
0: (b7) r0 = 0                        ; R0=0
1: (95) exit
processed 10 insns (limit 1000000) max_states_per_i[    2.301324] clocksource: Watchdog remote CPU 1 read timed out
nsn 0 total_states 1 peak_states 1 mark_read 0
---END---
";
        let out = VerifierLogParser.parse("diffharness", SPLIT_SUMMARY.as_bytes());
        assert_eq!(out.records.len(), 1);
        assert!(out.unparsed.is_empty());
        let rec = &out.records[0];
        assert_eq!(rec.core.processed.insn_processed, 10);
        assert_eq!(
            rec.core.processed.states_processed, 1,
            "total_states must survive the splice — silently reading 0 here is the bug"
        );
        assert!(
            rec.notes.iter().any(|n| n.contains("console-interleaved")),
            "a repair that is not recorded is just quieter corruption: {:?}",
            rec.notes
        );

        // Captured at gen-tcg.log:8829 — the printk lands at the END of a register
        // line, so the continuation is the original line's own (empty) remainder.
        const SPLIT_TAIL: &str = "\
===PROG p type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=100
---LOG---
0: R1=ctx() R10=fp0
0: (61) r0 = *(u32 *)(r1 +0)          ; R0=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R1=ctx()[   16.053446] random: crng init done

1: (95) exit
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        const CLEAN_TAIL: &str = "\
===PROG p type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=100
---LOG---
0: R1=ctx() R10=fp0
0: (61) r0 = *(u32 *)(r1 +0)          ; R0=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff)) R1=ctx()
1: (95) exit
processed 2 insns (limit 1000000) total_states 0 peak_states 0
---END---
";
        let dirty = VerifierLogParser.parse("diffharness", SPLIT_TAIL.as_bytes());
        let clean = VerifierLogParser.parse("diffharness", CLEAN_TAIL.as_bytes());
        assert_eq!(
            dirty.records[0].core.register_evolution, clean.records[0].core.register_evolution,
            "repaired capture must yield the SAME register states as an uninterrupted one"
        );
        assert!(dirty.records[0]
            .notes
            .iter()
            .any(|n| n.contains("console-interleaved")));
        assert!(
            clean.records[0].notes.is_empty(),
            "clean input must not be annotated"
        );
    }

    // A console line that lands BETWEEN two verifier lines corrupts nothing; it is
    // simply not verifier output and must be dropped without a repair note.
    #[test]
    fn whole_console_line_is_dropped_not_spliced() {
        const C: &str = "\
===PROG p type=socket_filter ===
RESULT decision=accept fd=3 errno=0 load_ns=100
---LOG---
0: R1=ctx() R10=fp0
[    2.301324] clocksource: Watchdog remote CPU 1 read timed out
0: (b7) r0 = 0                        ; R0=0
1: (95) exit
processed 2 insns (limit 1000000) total_states 3 peak_states 0
---END---
";
        let out = VerifierLogParser.parse("diffharness", C.as_bytes());
        assert_eq!(out.records[0].core.processed.states_processed, 3);
        assert_eq!(out.records[0].core.register_evolution.len(), 2);
        assert!(out.records[0].notes.is_empty());
    }

    // The timestamp shape must be narrow enough that verifier text is never eaten.
    #[test]
    fn console_timestamp_does_not_match_verifier_text() {
        assert_eq!(console_timestamp_at("0: (b7) r0 = 0     ; R0=0"), None);
        assert_eq!(console_timestamp_at("R2=map_value(map=m,ks=4,vs=8)"), None);
        assert_eq!(
            console_timestamp_at("value [0.5] and [12.34] and [1.23456789]"),
            None
        );
        assert_eq!(console_timestamp_at("[    2.301324] real"), Some(0));
        assert_eq!(console_timestamp_at("tail[12345.000001] real"), Some(4));
    }
}

/// Parse the kernel's `Live regs before insn:` table together with the harness's own
/// `LIVENESS` claim about the same program.
///
/// The table (liveness.c:2312, BPF_LOG_LEVEL2) is printed as
/// `[%3d ]%3d: <10 columns> <disassembly>[; zext]`, where the optional first field is the
/// instruction's SCC id. **The instruction index is the last whitespace-separated token
/// before the colon, never a leading run of digits** — a regex that treats the SCC prefix
/// as optional will parse `" 2  20: ..."` as instruction 0 and silently mis-attribute every
/// row in the program. That mistake was made once while measuring this channel and is the
/// reason this function splits on the colon instead.
///
/// Returns `None` when the harness emitted no claim at all: without the second source there
/// is nothing to compare, and a table on its own is not evidence about anything.
fn parse_liveness_gate(
    claim_line: Option<&str>,
    log: &[&str],
) -> Option<metrics::core::LivenessGate> {
    let claim_line = claim_line?;
    let mut claim = None;
    let mut status = String::from("absent");
    if claim_line.contains("status=ok") {
        if let Some(hex) = claim_line.split_whitespace().find_map(|t| t.strip_prefix("mask=")) {
            let n = claim_line
                .split_whitespace()
                .find_map(|t| t.strip_prefix("n="))
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            // Three hex digits per instruction, ten meaningful bits. A short or ragged
            // string is refused rather than padded: a truncated claim that parsed would be
            // a silent disagreement with the kernel on every missing instruction.
            if n > 0 && hex.len() == n * 3 {
                let mut v = Vec::with_capacity(n);
                let mut ok = true;
                for i in 0..n {
                    match u16::from_str_radix(&hex[i * 3..i * 3 + 3], 16) {
                        Ok(m) => v.push(m & 0x03ff),
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                if ok {
                    status = String::from("ok");
                    claim = Some(v);
                }
            }
        }
        if claim.is_none() {
            status = String::from("malformed");
        }
    } else if claim_line.contains("status=unsupported") {
        let why = claim_line
            .split_whitespace()
            .find_map(|t| t.strip_prefix("why="))
            .unwrap_or("unstated");
        status = format!("unsupported: {why}");
    }

    let mut kernel = Vec::new();
    let mut in_table = false;
    for line in log {
        if line.trim() == "Live regs before insn:" {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        match parse_liveness_row(line) {
            Some(row) => kernel.push(row),
            // The table is one contiguous block; the first row that does not parse ends it.
            None => in_table = false,
        }
    }

    Some(metrics::core::LivenessGate { claim, claim_status: status, kernel })
}

/// One row of the liveness table -> (insn_idx, mask). See `parse_liveness_gate` for why the
/// index is taken from the end of the head rather than the start.
fn parse_liveness_row(line: &str) -> Option<(u32, u16)> {
    if !line.starts_with(' ') {
        return None;
    }
    let (head, rest) = line.split_once(':')?;
    let idx: u32 = head.split_whitespace().last()?.parse().ok()?;
    let rest = rest.strip_prefix(' ')?;
    let cols = rest.get(..10)?;
    if cols.len() != 10 || !cols.bytes().all(|b| b == b'.' || b.is_ascii_digit()) {
        return None;
    }
    // A column is the register's own index when live and '.' when dead, so position is the
    // register number and the printed digit is redundant. Reading the position rather than
    // the digit keeps this independent of that redundancy.
    let mut mask = 0u16;
    for (j, c) in cols.bytes().enumerate() {
        if c != b'.' {
            mask |= 1 << j;
        }
    }
    Some((idx, mask))
}
