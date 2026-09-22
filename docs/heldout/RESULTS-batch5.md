# Batch 5 — the H21 pair was BUILT and RUN: the visible arm verified in both channels

Referee objection 3: *"You managed to build 9 pairs — why did you not build the single visible held-out
case?"* It was right; a round earlier I had objected that it was "marginal" and I was wrong —
the issue was not information but reliability. It was built.

## Setup

- `1ffc85d9298e~1` (`dec020280373`, buggy) and `1ffc85d9298e` (fixed), 2023-06-13.
- Config **byte-identical** (single md5). Capture patch: none of the three era variants
  fit; a **fourth** was written (`patches/prunepair-instrumentation-2023.patch`, a port of the 2021
  block to the `hit:` label — same print format, same fields).
- Trigger: **the commit message's own example, verbatim** (`f2probe.c: dump_h21`).
  §3.5's sentence: the cheapest calibration is what the commit already does.

## Kernel channel — calibrated

| | base | `BPF_F_TEST_STATE_FREQ` |
|---|---|---|
| buggy | reject 22 | **accept** |
| fixed | reject 22 | **reject 22** |

`STATE_FREQ` is part of the input, not the detector (the lesson of 0103): without the flag
the heuristic does not set up the checkpoint, path II cannot be pruned to path I, the bug does not surface.

## Model channel — the first run is SILENT, and the reason is the finding itself

In the first run B **did not fire** on the buggy capture: `disagree=0, id_checks=0`. Yet the critical
pair had been captured, matching the commit example exactly:

```
PRUNEPAIR insn=14 side=old r6 ... id=3 prec=1 live=1      (yol I:  r6.id=b)
PRUNEPAIR insn=14 side=old r7 ... id=3 prec=1 live=1      (        r7.id=b)
PRUNEPAIR insn=14 side=cur r6 ... id=2                    (yol II: r6.id=a)
PRUNEPAIR insn=14 side=cur r7 ... id=3                    (        r7.id=b)
```

The reason, in `subsume-check.py`:

```python
if o['era'] == '2021':   # EVERY row carrying live= -> 2021 arm
    # ... id/delta/ADD_CONST arms don't exist yet: only range_within && tnum_in
```

The `live=` field was the model's era marker; 2023-06 also prints `live=`. The model routed the 2023
capture to the 2021 arm, and in that arm `check_scalar_ids` is **absent by design** —
it was absent in the 2021 kernel too. **The same print format carries two different predicates; the format
cannot determine the era.** Source-level verification had said "the arm is implemented": true for the
cnum path, false for the path this capture takes. Execution found this; reading could not.

The fix is not inference but explicit declaration: the `--era 2023` flag. The 2023 arm = one-sided
precision short-circuit, the `REG_LIVE_READ` gate, `check_scalar_ids`, then
`range_within && tnum_in` — the fixed kernel's predicate.

## Second run

| | `--era 2023` | `--era 2021` (control) |
|---|---|---|
| buggy | **`candidate insn=14 arm=check_scalar_ids`, disagree=1** | disagree=0 (silent) |
| fixed | disagree=0, and **the prune event itself is absent** (3 pairs → 1) | — |

Exactly the predicted arm, exactly the commit's pair, silent in fixed.
The exact same signature as `2f2ec8e7730e` (it too `arm=check_scalar_ids`, it too has the
prune vanish in fixed) — two separate bugs, same arm, same behavior.

## The sequence, honestly

1. Held-out classification: VISIBLE (`bd10090`, sealed).
2. Source-level verification: held.
3. Run #1: **silent** — a model limit that source reading could not see.
4. Model fix (`--era 2023`), AFTER the run, its rationale written.
5. Run #2: fired; fixed silent; control silent.

Step 4 came after the run; therefore H21 counts not as a **held-out confirmation** but as the **sixteenth
built calibration pair**, and enters the held-out record as "held at source level;
in execution first hit a model limit, the limit was fixed, then held".

## Open

- The C twin (`bpfsubs.h`) does not know the 2023 arm; the 2023 capture was not added as a
  fixture to the Rust parity test. If it is to be added, the C side needs the arm first.
