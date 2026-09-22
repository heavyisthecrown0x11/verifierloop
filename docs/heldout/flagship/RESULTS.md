# Reproduction of the flagship partition — RESULTS

Preregistration `1cff1f1`; Rater 1 seal `04905f0` (before Rater 2 was read); this file is after it.

## Composition (57 commits, mechanical frame, in the file)

| | Rater 1 (this session) | Rater 2 (blind model) |
|---|---|---|
| **Yes** — corrupts a field B consumes → blind | **24 (42%)** | 27 (47%) |
| No-unconsumed — a place B never reads | 31 | — |
| No-examined — the predicate side, outside B's scope | 1 | — |
| No (total) | 32 | 29 |
| Undecided | 1 | 1 |

**Old partition:** 23/40 blind (58%), 2/40 predicate (5%) — could not be reproduced.
**New:** blind 42% (R1) / 47% (R2); bound 1/57; realized access **0/57** (the single
predicate case `1ad2f5838d34` is in the pointer arm, B does not model it). The headline, per the preregistration,
is drawn to Rater 1's sealed partition: **42% blind, 2% target, 0% realized.**

## Reliability

- Raw agreement **53/57 = 0.930**, p_e = 0.485, **Cohen κ = 0.864** — Landis–Koch *almost
  perfect*. (On the held-out 28 it was κ = 0.714; both measurements are above the preregistration threshold.)
- Both raters gave **one** Undecided each, on different cases.

## Four disagreements — and on two of them Rater 2 is right

| commit | R1 | R2 | reading |
|---|---|---|---|
| `2aaf67f0516f` | No | Undecided | R2: the write protected by the r0_size guard is not visible in the diff. Defensible. |
| `efc11a667878` | Undecided | Yes | R2: `___mark_reg_known` rewrites consumed fields. R1's Undecided was for the "imprecise ≠ corrupt" distinction. |
| `bb7f0f989ca7` | No | **Yes** | **R2 is right.** A hunk of the diff not in R1's excerpt forces `__mark_reg_unknown` — a bound write. R1 read from a truncated excerpt. |
| `fce366a9dd0d` | No | **Yes** | **R2 is right.** It constrains the `dst_reg->type = PTR_TO_MAP_VALUE_ADJ` write; `type` is consumed. Again outside R1's excerpt. |

**Protocol asymmetry, for the record:** Rater 1 read the diffs in 16–28-line excerpts
(to get through 57 commits in one session); Rater 2 saw 9000 characters. Two disagreements
stem directly from this asymmetry. The gold was not changed, per the preregistration; but the correct reading
is most likely Rater 2's, and the true blind share is between 42% and 47%.

## What changed

- §4.2's "check any row" claim is **now true** for the flagship partition: the frame, the two
  rater files, and the rationales are artifacts.
- The headline 58 → 42. The old frame had been hand-selected and was **even** more enriched toward the
  oracle's path; §6's fourfold measurement already said so.
- On the path (Yes + No-examined) 25/57 = 44% vs unfiltered 3/20 = 15%, Fisher p = 0.030.
