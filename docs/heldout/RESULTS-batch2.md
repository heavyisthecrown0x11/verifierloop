# Held-out batch 2 — RESULTS

Preregistration: `PREREGISTRATION-batch2.md`, commit `956b461`. This file is **after** it.

## 1. Two STATE predictions — both held

| # | field | where it comes from in B | how it enters the verdict | result |
|---|---|---|---|---|
| **H11** | `id` | capture regex `id=([0-9a-f]+)` (lines 139/147/162) → `o['id']` | `check_ids(o['id'], c['id'])`, line 338 | **consumed** → blind. Prediction held |
| **H16** | `type` | capture regex `type=(\d+)` → `o['t']` | `if o['t'] != c['t']: break`, line 306 | **consumed** → blind. Prediction held |

The falsification condition (independent recomputation → verdict) occurred in none of them.
The only independent recomputation in B's source is `bpflive.h`'s liveness mask, and it
too goes only to counters (`live_bit`, lines 298–304); the gate that issues the verdict at line
307 uses the kernel's own `o['live']` field.

## 2. Eight IRRELEVANT predictions — 8/8

`push_insn`, `insn_state`, `check_alu_op`, `process_iter_arg`, `check_return_code`,
`retval_range`, `process_spin_lock`, `check_raw_mode_ok`, `do_misc_fixups`,
`type_may_be_null`, `free_states`, `compute_scc`, `scc_cnt` — all thirteen names occur
**0** times in B's source.

## 3. Cumulative

| | batch 1 | batch 2 | total |
|---|---|---|---|
| cases | 10 | 10 | **20** |
| predictions held | 10 | 10 | **20** |
| falsified | 0 | 0 | **0** |
| testing the blind boundary (STATE) | 1 | 2 | **3** |
| IRRELEVANT | 9 | 8 | **17** |
| PREDICATE | 0 | 0 | **0** |

**§4.1's held-out count: 1 → 21.** (20 new + the existing one.)

## 4. Frame composition — §6's first threat, cumulative

| frame | IRRELEVANT | on the state-equivalence path |
|---|---|---|
| original (message quotes state), n=40 | 15 (37.5%) | 25 (62.5%) |
| held-out (the complement of that criterion), n=20 | **17 (85%)** | 3 (15%) |

Fisher exact test, two-sided: **p = 0.00077**.

So §5.3's 58% blind / 5% target figures are **conditional on the frame**, and the direction of the
condition was measured: selecting by messages that quote state **over-represents** the errors on the
state-equivalence path by roughly **fourfold** (62.5% vs 15%).

This does not refute §5.3's figures — it corrects **what they are a proportion of**.

## 5. Weaknesses that remain, honestly

- **PREDICATE predictions: zero.** In twenty cases not a single one came out "potentially visible",
  so the bound's **upper** arm (visibility) is still not held-out tested.
  The tested side of the boundary is only the blind side.
- **Verification is source-level.** In none of the three STATE cases was the kernel compiled and
  the oracle run; verification was the question "is the field consumed in B's source".
  This is the same level as §4.1's single existing held-out case — but building and running the system
  would have been stronger, and was not done.
- **n=20 is still small**, and the 2023 cutoff biases the sample toward new code.
