# Held-out batch 1 — PREREGISTRATION (sealed BEFORE verification)

**Date:** 2026-09-10 · **Purpose:** to close §4.1's `n=1` held-out weakness.

This file was committed **before** verification. The verification results are in a separate commit
(`RESULTS.md`). The order can be checked from the git history; this is the
only evidence that the test is held-out.

---

## 1. Frame — mechanical, and DELIBERATELY different from the original

```
git -C .lab/bpf-next log --grep="^Fixes:" --since=2023-01-01 -- \
    kernel/bpf/{verifier,states,backtrack,cnum,tnum,liveness}.c
```
→ **208** commits. Then two exclusions:

- Commits whose body **quotes verifier state** (`R[0-9]=`, `var_off`,
  `smin_value`, `umax_value`, `tnum(`, `scalar(`, `u32_m(in|ax)`): **28**. These
  are the filter of the original 50-commit frame; they have already been classified.
- Sixteen calibration commits and the five title-traps named in devlog 0102.

→ **held-out frame: 176** commits (`frame.txt`).

**Why we EXCLUDE the ones that quote:** §6's first threat is that the original frame
was selected by the "message quotes state" criterion. Drawing the held-out set from the
**complement** of that criterion does two jobs at once: it tests the procedure on independent
cases, and it measures the direction of the frame bias.

**Accepted deviation:** the 2023 cutoff is for buildability. This biases the sample toward
newer code, and §5.3 already says the surface churns there.

## 2. Draw rule — content-independent, reproducible

```
sort frame.txt | head -10
```

Ascending sort by SHA. The rule carries no relation to the commit's **content**,
yet it can be reproduced exactly afterward. The ten cases are in `draw.txt`.

## 3. Question (§3.3), for oracle **B** (the subsumption model)

Does the fix change the **PREDICATE** that compares two states (`states_equal`,
`regsafe`, `range_within`, `check_ids`, `stacksafe`), or the code that writes a
**STATE** field the model reads raw (`u{32,64}_m{in,ax}`, `s{32,64}_m{in,ax}`, `var_off`,
`id`, `precise`, `live`, `type`, `off`, `range`) — or neither
(**IRRELEVANT**)?

The decision is made **from the diff alone**, with a `file:function` citation.

## 4. Classification and PREDICTIONS

| # | commit | date | decision | anchor | prediction (falsifiable) |
|---|---|---|---|---|---|
| H1 | `00244bdaa423` | 2026-08-05 | IRRELEVANT | `btf_id_allow_sleepable()` — BTF/attach policy | writes no field B reads, not a predicate |
| H2 | `00750788dfc6` | 2024-09-04 | IRRELEVANT | `convert_ctx_accesses()` — indentation only | no semantic change |
| H3 | `0108a4e9f358` | 2023-06-12 | IRRELEVANT | `jit_subprogs()` — kallsyms/`extable` | post-verification JIT bookkeeping |
| H4 | `032547272eb0` | 2025-07-03 | IRRELEVANT | `record_func_key()` — `verifier_bug`+EFAULT → `verbose`+EINVAL | diagnostic class only; B reads the state row, not the verdict |
| H5 | `05670f81d128` | 2023-11-01 | IRRELEVANT | `CONFIG_CGROUPS`, BTF_ID sets | compilation error |
| H6 | `0613d8ca9ab3` | 2023-05-18 | IRRELEVANT | `convert_ctx_accesses()` — `ALU64_IMM`→`ALU32_IMM` | instruction rewrite after exploration has ended |
| H7 | `06d686f771dd` | 2023-09-13 | IRRELEVANT | `check_kfunc_args()`, `KF_ARG_PTR_TO_CALLBACK` | argument-check path; `subprogno` is not in B's read set |
| H8 | `082cdc69a465` | 2023-03-15 | IRRELEVANT | `check_stack_read()` — spec_v1 rejection removed | verdict change, not a state field |
| H9 | `09c447564fca` | 2026-08-14 | IRRELEVANT | `save_aux_ptr_type()` → `insn_aux_data.ptr_type` | not `bpf_reg_state`; `states_equal` does not compare this |
| **H10** | `0acd03a5bd18` | 2023-12-02 | **STATE** | `prepare_func_exit()`: `mark_reg_read(REG_LIVE_READ64)` + `mark_chain_precision(BPF_REG_0)` | **B cannot see this**: `precise` and `live` are fields B raw-CONSUMES; the corrupted flag arrives at B as data, not as an error |

**Composition: 9 IRRELEVANT · 1 STATE · 0 PREDICATE.**

## 5. Verification protocol — to be run after sealing

1. **H10 (the real test):** in B's source (`scripts/subsume-check.py`, `harness/bpfsubs.h`),
   are `precise`/`live` genuinely **consumed input**, or a modeled predicate arm? If they are
   consumed input, the prediction held; if a modeled arm, **the prediction was falsified** and
   will be reported as such.
2. **H1–H9:** none of the touched functions should be modeled in B's source.
   If even one is modeled, the prediction for that case was falsified.
3. The composition difference (9/10 vs the original 15/40) will also be measured — this is a
   RESULT bearing on §6's first threat, not part of the independent test.

## 6. This batch's weakness, known in advance

Nine of the ten cases came out IRRELEVANT, so **the only case that tests the blind boundary is H10**.
This is not a selection error but the frame's composition — and the composition is itself a measurement.
Testing the blind boundary further requires later batches; this batch will *not* steer the next
draw, because that one too will proceed by the same rule, with the next 10 (`sort frame.txt | sed -n '11,20p'`).
