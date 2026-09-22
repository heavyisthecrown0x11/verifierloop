# Held-out batch 4 — PREREGISTRATION: **the visible arm**

Batches 1–2 produced twenty cases and **none came out PREDICATE**, so the visibility
arm of the boundary was not tested held-out. §4.1 admits this itself. This batch
targets that gap.

## 1. Stratified draw — and why it is not circular

In the unfiltered frame the predicate-defect rate is ~1–2%; continuing to draw by the same rule
gives zero PREDICATE on any reasonable budget. So I use **a declared stratum**:

> **Stratum S** = commits in the held-out frame (176), not drawn in batches 1–2, and
> whose **commit MESSAGE** contains one of these words: `prun`,
> `states_equal`, `state equival`, `regsafe`, `range_within`, `check_ids`,
> `scalar_ids`, `stacksafe`, `refsafe`, `equivalen`. → **19 commits**
> (`stratumS.txt`).

**Not circular, and there is a measured reason for this:** the stratum looks at the **message**,
the classification at the **source**. The **eight title-traps** this project measured on an
earlier population (devlog 0102: `71b547f56124`, `763aa759d3b2`,
`cc52d9140aa9`, `4cabc5b186b5` and four earlier ones) are direct evidence that the message does
not determine the class.

**Cost accepted in advance:** the stratum is enriched, so **this batch's
composition is NOT an estimate of the base rates.** Batches 1–2's composition measurement (17/20
IRRELEVANT, p=0.0008) will not be updated with this batch.

The draw is again content-independent: `sort stratumS.txt | head -8` → `draw4.txt`.

## 2. Falsification conditions (the corrected form from batch 2)

- A **VISIBLE** prediction is falsified if the comparison arm the fix touches is
  **not modeled** in B's source.
- A **STATE** prediction is falsified if B, instead of consuming that field from the kernel,
  **computes it independently and binds it to the verdict**.
- An **IRRELEVANT** prediction is falsified if the touched function/field is modeled in
  B's source.

## 3. Classification and predictions

| # | commit | decision | anchor (from the diff alone) | prediction |
|---|---|---|---|---|
| **H21** | `1ffc85d9298e` | **PREDICATE → VISIBLE** | `regsafe()` SCALAR_VALUE arm: `memcmp(..., offsetof(id))` + `check_scalar_ids()` instead of `regs_exact()` | **B CAN see this** — B models exactly this arm, in its corrected form |
| H22 | `2658a1720a19` | STATE | `collect_linked_regs()` now skips registers not in `live_regs_before` → writes `reg->id` | blind: B consumes `id` |
| **H23** | `2b2efe1937ca` | **UNMODELED** | the may_goto arm of `is_state_visited()`: adds a `may_goto_depth` condition BEFORE the `states_equal` call | blind, **but outside the trichotomy**: `states_equal` does not change, no field B reads is corrupted; the defect is in a GATE that B does not model |
| H24 | `3a354149bcea` | STATE | `__clean_func_state()`: pointer spill metadata preserved in the dead hi-half → stack slot state | blind, and doubly so: the capture never prints stack slots |
| H25 | `3d562d35a044` | IRRELEVANT | `might_throw`, `cfg.c` — exception paths | not in B's read set |
| **H26** | `41025f441fe6` | **PREDICATE → INVISIBLE** | `refsafe()`: adds `check_ids(parent_id)` for REF_TYPE_PTR | **PREDICATE but B does not see it** — `refsafe` is not modeled in B (`refsafe_idmap_seed=not-observable-from-capture`). The second instance of §5.3's "PREDICATE ≠ visible" distinction |
| H27 | `52c2b005a3c1` | STATE | `propagate_precision()` now also looks for `REG_LIVE_READ` → writes `precise` | blind: B consumes `precise` (§5.4's gate) |
| H28 | `713274f1f2c8` | STATE | `check_stack_write_fixed_off()`: `spilled_ptr.id = 0` on a narrowing spill | blind: B consumes `id` |

**Composition: 1 VISIBLE · 1 PREDICATE-but-invisible · 4 STATE · 1 UNMODELED · 1 IRRELEVANT.**

## 4. H23 opens a gap in the trichotomy — I am recording it now

§3.3 recognizes three answers: PREDICATE / STATE / IRRELEVANT. H23 fits none of them cleanly:
`states_equal` does not change (not PREDICATE), no field B reads is corrupted
(not STATE), yet it is right in the middle of the state-equivalence path (not IRRELEVANT either).
The right answer is a fourth category: **on the path, but in a part no oracle models** —
what Appendix A already carries with the `u` mark for the pointer arm.

I am writing this not as a result but as **part of the prediction**: if
verification really places H23 in this fourth box, §3.3's trichotomy must be
corrected — "IRRELEVANT" is defined in the current text as *"off the path"*, whereas the
correct definition is *"outside what the oracle consumes"*.

## 5. Verification protocol

For each case, B's source (`scripts/subsume-check.py`, `harness/bpfsubs.h`):
is the touched arm/field modeled, and if modeled, **is it consumed, or recomputed
and bound to the verdict**.

**Accepted in advance:** this is the same level as batches 1–2's source-level verification.
A stronger one is possible for H21 — `1ffc85d9298e~1` and `1ffc85d9298e` are built and run with the
min/max-era capture patch — and if it was not done, it will be reported as such.
