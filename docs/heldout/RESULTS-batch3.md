# Batch 3 — RESULTS: symmetry **could not be structurally exercised**, and the reason is the finding itself

Preregistration: `PREREGISTRATION-batch3.md`, commit `4c2e455`. This file is **after** it.
Verification this time is not source reading but **execution** — on `.lab/build/bzImage-instr`
(= `dffc1150e2cc` + a print-only `states.c` patch).

## Branch: **P1 held, P2 held** → *"The symmetry thesis is refuted for this oracle"*

The second of the four branches in the preregistration occurred.

### P1 — an empty range entered a prune pair ✅

The first two shapes (`N0` no load, `CV` converging branch) **fail**: r6 is
**dead** at the prune point, so it does not enter `live_regs_before`, is not compared, is not printed.
This is not coincidence but structural: nearly every operation that reads an empty register
triggers `reg_bounds_sanity_check` and repairs it with `__mark_reg_unbounded`.

The escape route: **the store's source**. `check_store_reg()` applies no sanity
check to the source register (only `check_load_mem` applies it to the target, verifier.c:6703). So
`*(u32 *)(r8 +0) = r6` **keeps r6 live and does not repair it**. The third shape (`KL`):

```
PRUNEPAIR insn=17 exact=0 side=old fr=0 r6 type=1 delta=0 var=0/2 r64=0+2 ...
PRUNEPAIR insn=17 exact=0 side=cur fr=0 r6 type=1 delta=0 var=0/2 \
          r64=ffffffffffffffff+ffffffffffffffff r32=ffffffff+ffffffff ...
```

On the `cur` side `CNUM64_EMPTY`, and the kernel **pruned this pair** (lines are printed only
for prunes that are taken). Five empty lines across four captures.

### P2 — the model reported no disagreement ✅ (prediction held)

| capture | empty lines | pairs | disagree | nontrivial | scalar_cmp | shortcircuited |
|---|---|---|---|---|---|---|
| `KL_keeplive` | 2 | 3 | **0** | 0 | 0 | 3 |
| `KL_keeplive_freq` | 1 | 3 | **0** | 0 | 0 | 3 |
| `MG_maygoto` | 1 | 1 | **0** | 0 | 0 | 1 |
| `MG_maygoto_freq` | 1 | 3 | **0** | 0 | 0 | 2 |

None have a misattributed finding. **P3 was not reached.**

## And the reason differs from my rationale in the preregistration — sharper

My rationale in the preregistration was: *"the kernel's predicate and the model's transcription run on the
same values, so they give the same answer."* The counters say this is **not the operative
mechanism**: `scalar_comparisons=0`, `nontrivial_pairs=0`,
`shortcircuited_regs>0`. So the recomputed containment **never ran**.

What cuts is `subsume-check.py:375`:

```python
if o['prec'] == 0 and p['exact'] == 0:
    st.shortcircuit += 1; continue        # precision short-circuit
```

`prec` is a **consumed** field. That is:

> Evidential dependence does double duty. A consumed value is not merely
> **an input** to the recomputed predicate; a consumed value can also decide
> **whether that recomputation runs at all.** In this oracle it is the latter:
> the precision flag the component writes determines whether the oracle's own independent arithmetic
> runs. A defect above that flag is not subjected to a wrong
> verdict — it is **never examined at all.**

## What remains open — and was attempted to close

Because the short-circuit fires first, the question "if the recomputed arm had run on an empty range,
would it have agreed or disagreed" is **unanswered**. To open the short-circuit,
`may_goto` was tried (the `is_may_goto_insn_at` arm makes the prune happen with `exact=RANGE_WITHIN`):
**failed** — in none of the four captures was a pair carrying `exact=2`
produced; the prune carrying the empty register still happened at the `exact=0` point.
An iterator or callback shape would have been the next attempt; it was not done in this batch.

So the standing claim is: *this oracle, in these shapes, produced no misattributed true-positive,
and the reason it did not is that a consumed field acts as a gate.*
It is **not** a general claim that "misattribution never happens".

## The gate is ONTOLOGICAL, not incidental — verified from source

The critical question: is line 375's short-circuit an optimization of my script, or something every
faithful model must do? **A mirror of the kernel, i.e. ontological:**

```
kernel today (tip)   kernel/bpf/states.c:548   if (!rold->precise && exact == NOT_EXACT) return true;
kernel dffc1150e2cc  kernel/bpf/states.c:551   if (!rold->precise && exact == NOT_EXACT) return true;
kernel 2019-12       kernel/bpf/verifier.c:7096 if (!rold->precise && !rcur->precise)     return true;
model                scripts/subsume-check.py:375  if o['prec'] == 0 and p['exact'] == 0: continue
```

Because the kernel gates on `prec`, the model must too. The gate **belongs to the principle, not to this
oracle**.

## And this gate is already on the map — two independent routes land in the same place

`f54c7898ed1c` (2019-12, "Fix precision tracking for unbounded scalars") is invisible to this oracle
precisely because of this gate: at the checkpoint old R1 is constant, cur R1 is fully unknown,
**both imprecise** → the short-circuit fires → the state is pruned → the not-walked branch
is rewritten to `goto pc-1` → the program **hangs**. This was brought down by hand with channel verification
on 2026-09-08 (at source level, without building the kernel).

So batch 3 is not a new observation: **an execution-verification of the mechanism of a documented
structural blindness**, reached from symmetry probing, by an independent route.

## Count and the correct framing

- Preregistered propositions: 3 (P1, P2, P3). Held: 2. Not reached: 1. Falsified: 0.
- Verification level: **execution** (batch 1–2's source-reading caveat does not apply to this batch).

**The framing must be built carefully.** "Tested and not supported" is misleading taken plainly,
because the recomputation **never ran** (`scalar_comparisons=0`) — symmetry was not given a chance,
its path was closed. The accurate statement: the preregistered symmetry sampling ran; the
recomputation was **shut off by a consumed field**; an empty-register `exact=2`
pair could not be forced with `may_goto`; therefore **symmetry could not be structurally exercised, and we
have the execution-verified answer for why it could not.**
