# Held-out batch 4 — RESULTS: the visible arm was closed, and the trichotomy opened a gap

Preregistration: `PREREGISTRATION-batch4.md`, commit `bd10090`. This file is **after** it.

## 1. H21 — the visible arm, and stronger than predicted

Prediction: the change in `regsafe()`'s SCALAR_VALUE arm (`memcmp(..., offsetof(id))` +
`check_scalar_ids()` instead of `regs_exact()`) **B can see.**

Found in the source: `check_scalar_ids` is transcribed (lines 96, 120) and is a real
**verdict arm**:

```python
# subsume-check.py:383
if not p['idmap'].check_scalar_ids(o['id'], c['id']):
    p['arm'] = 'check_scalar_ids'; verdict = 'break'; break
```

Moreover: this arm is B's **calibrated positive** itself — in the `2f2ec8e7730e`
pair, in the buggy kernel `disagree=1 arm=check_scalar_ids`, 15 disagreements at corpus
scale, 0 in fixed. So the held-out VISIBLE prediction does not just say "the arm is modeled";
**it is independently known that this arm fires on a real bug.**

**Prediction held.** The upper arm of the boundary is now held-out tested.

## 2. H26 — PREDICATE but INVISIBLE, and the second case of this distinction

`check_ids(parent_id)` is added to `refsafe()` — an indisputable comparison
function, i.e. PREDICATE. But in B's source `refsafe` appears only in the **unimplemented
arms** report:

```
refsafe_idmap_seed=not-observable-from-capture   (subsume-check.py:442,449)
```

**Prediction held**, and §5.3's *"PREDICATE does not imply visible"* sentence
gained a second independent case after `1ad2f5838d34` — this time held-out.

## 3. H23 — outside the trichotomy, and this was written in the preregistration

`2b2efe1937ca` adds a condition **before** the `states_equal` call in the may_goto arm of
`is_state_visited()`. Verification:

| searched | in B |
|---|---|
| `is_state_visited`, `may_goto_depth`, `may_goto`, `update_loop_entry` | **0** |
| `states_equal` itself | unchanged (not in diff) |
| any field B reads | not corrupted |

So: not PREDICATE, not STATE, and **not outside** the path either. §3.3's trichotomy
cannot name this case. The correct answer is a fourth category: **on the path, but in a part
no oracle models.** Appendix A already carries this for the pointer arm with the `u`
mark; §3.3 did not.

**And here THIS PART OF MY PREREGISTRATION WAS FALSIFIED.** The preregistration said "§3.3's trichotomy
must be corrected". On looking at the source, §3.3 is already correct: the question it asks is
*"Does $d$ corrupt an artifact in $O$'s consumption set?"* — i.e. defined over the **consumption
set**, not over the "path". H23 gives a clean **No** to that question,
and §3.3's "No" clause already says *"subject to its predicate covering the
class"*; §3.4 also separately writes the necessary-condition/sufficient-condition difference.

What is loose is not §3.3, but **§5.3's bucket name**: *"15 of 40 lie outside the
state-equivalence path entirely."* That bucket conflates two different things — those genuinely
outside the path and the parts that are **on the path but modeled by no oracle**.
H23 is a held-out example of the second. That is the place to fix.

## 4. The remaining five predictions

| # | decision | verification | result |
|---|---|---|---|
| H22 | STATE | `collect_linked_regs` is 0 in B; `id` is **consumed** at line 338 | held |
| H24 | STATE | B **never compares** stack slots (lines 99–100: the patch does not print the stack, the model makes no decision) — blind twice | held |
| H25 | IRRELEVANT | `might_throw`, `cfg.c`, `bpf_check_cfg`, `exception` → all 0 | held |
| H27 | STATE | `propagate_precision` is 0 in B; `precise` is **consumed** at line 375 (§5.4's gate) | held |
| H28 | STATE | `check_stack_write` is 0 in B; `id` is consumed | held |

## 5. Cumulative

| | batch 1 | batch 2 | batch 4 | total |
|---|---|---|---|---|
| cases | 10 | 10 | 8 | **28** |
| held | 10 | 10 | 8 | **28** |
| falsified | 0 | 0 | 0 | **0** |

**§4.1's held-out count: 1 → 29** (28 preregistered + one original).

Testing of the arms:
- **blind arm:** 7 cases (H10, H11, H16, H22, H24, H27, H28)
- **visible arm:** **1 case (H21)** — was zero before this batch
- **PREDICATE-but-invisible:** 1 case (H26)
- **unmodeled (fourth category):** 1 case (H23)
- IRRELEVANT: 18

## 6. Limits that remain, honestly

- **Verification is still source-level.** A stronger one was possible for H21 —
  `1ffc85d9298e~1` and `1ffc85d9298e` could have been compiled and run with the min/max era capture patch
  — and was **not done**. H21's strength comes from the arm being an independent calibrated positive,
  not from this batch's own execution.
- **The stratum is enriched.** This batch's composition is not an estimate of base rates,
  and batch 1–2's composition measurement (p=0.0008) was not updated with it.
- n=29 is still small; the 2023 cutoff biases the sample toward new code.
