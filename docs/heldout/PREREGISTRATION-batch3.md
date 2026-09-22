# Batch 3 — PREREGISTRATION: is there a misattributed true-positive?

**Seal date:** 2026-09-10. This file was committed **before any run**.
The results are in a separate commit (`RESULTS-batch3.md`). The difference from batches 1–2:
verification here is not source reading but a **run**.

## 1. The thesis under test

The symmetry the reviewer proposed: evidential dependence produces not only a blind spot but at the
same time a **misattributed true-positive** — the oracle consumes some fields and
recomputes others; when they conflict it reports a genuine disagreement but
assigns the blame to the wrong place.

## 2. Prediction derived from the mechanism — and THE OPPOSITE OF THE EXCITING ONE

Model B **recomputes** `range_within`, but its input is the kernel's own
capture (`PRUNEPAIR ... r64=base+size`). So the kernel's predicate and the model's
transcription run **over the same values**. A corrupted value coming from upstream
(F2's empty range) enters both in the same way.

Hence the mechanical expectation: **the model IS SILENT.** For a misattribution the model would
have to recompute from **another input** that the kernel does not use — which is exactly
what the axis says.

This prediction is deliberately the opposite of the exciting result: if it is silent, the reviewer's
symmetry thesis **is refuted for this oracle**; if it speaks, the thesis **is
confirmed** and enters the paper at the highest strength.

## 3. Three falsifiable propositions

**P1 (precondition).** In the capture of an F2-shaped program on the instrumented kernel,
there will be **at least one `PRUNEPAIR` row** carrying
`r64=ffffffffffffffff+ffffffffffffffff` or `r32=ffffffff+ffffffff`. (`CNUM64_EMPTY` = `{base=U64_MAX,
size=U64_MAX}`; the instrumentation prints `base+size` raw, not a projection.)

**P2 (the main proposition).** If P1 holds, `subsume-check.py` will **report no
disagreement** for that pair (`disagree=0` on that pair; `agree` or `unmodelled`).

**P3 (if P2 falls).** If the model reports a disagreement, the reported arm
(`p['arm']`) will be from the `range_within`/tnum family — that is, the model blames the **predicate** while
the real defect is upstream, in `sync_linked_regs`.

## 4. Outcome table — three branches, all three named in advance

| observation | reading |
|---|---|
| **P1 falls** (no empty range in the capture) | **INCONCLUSIVE.** The empty state could not be carried to a prune point. Not evidence for or against the thesis; what would be needed will be written down. It will not be presented as falsification. |
| P1 holds, **P2 holds** (the model is silent) | **The symmetry thesis is REFUTED for this oracle.** A fully-consuming oracle produces blindness, not misattribution; misattribution requires recomputation from an independent input. It enters the paper in this form. |
| P1 holds, **P2 falls**, P3 holds | **The symmetry thesis is CONFIRMED**, by a run. It enters the paper at the highest strength. |
| P1 holds, P2 falls, **P3 also falls** | There is a disagreement but the arm is not where expected. Partial; the actual arm will be reported, and the interpretation written accordingly. |

## 5. Protocol

1. Two things will be added to `harness/f2probe.c`: (a) printing the **full verifier
   log** of the selected program, (b) variants aimed at letting the empty range reach a prune point
   unrepaired — `N0` (no load) and a version with a converging branch added.
   The loads will also be done with `BPF_F_TEST_STATE_FREQ` (every instruction a checkpoint →
   prune attempts maximized).
2. The run is on `.lab/build/bzImage-instr` (`bpf-instr` = `dffc1150e2cc` +
   a print-only `states.c` patch; the patch does not change verifier logic).
3. The resulting log will be fed to `scripts/subsume-check.py`.
4. Report: each of P1/P2/P3 separately, and with the branch name from the table above.

## 6. Limits accepted in advance

- A single oracle (B), a single system. What is measured is not "misattribution never happens" but
  "in this oracle it does/does not happen in this way."
- Whether P1 holds depends on the program's shape and is not guaranteed; the inconclusive branch is a real
  possibility, and that is why it was named in advance.
