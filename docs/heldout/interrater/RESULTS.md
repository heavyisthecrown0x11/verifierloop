# Inter-rater — RESULTS

Preregistration: `PREREGISTRATION.md` (commit `6f3effe`). Rater 2 = a fresh-context model
instance, only `PACKET.md` + B's source; it had no access to the labels. Output `RATER2.txt`.

## Numbers

| | Yes | No | Undecided |
|---|---|---|---|
| Rater 1 (this session) | 7 | 21 | **0** |
| Rater 2 (blind) | 4 | 22 | **2** |

- Raw agreement **25/28 = 0.893**
- Chance agreement p_e = 0.625 (the 7/21 distribution raises chance; κ is therefore informative)
- **Cohen κ = 0.714** — Landis–Koch *substantial*. The preregistration's falsification threshold
  (κ < 0.6) was **not crossed**; the "almost perfect" band (≥ 0.8) was **not reached** either.

## Rater 2 said Undecided twice — Rater 1 zero

The preregistration had bound this in advance as: *"if Rater 2 gives more than zero Undecided,
it counts as evidence for the referee's suspicion of a 'reluctance to say undecided'."* It counts. My having given
zero Undecided out of forty and zero out of twenty-eight, placed next to a blind reader stopping on
two of the same diffs, makes §6's threat now a measured
observation.

## Three disagreements — both with their rationale, no silent resolution

| commit | R1 | R2 | R2's rationale | reading |
|---|---|---|---|---|
| `2658a1720a19` (H22) | Yes | **Undecided** | `collect_linked_regs` filters the registers entering linked_regs; how `id` is corrupted is unclear from the diff | R1's Yes rested on the inference that the id write is consumed by B; the diff does **not** say this, R1 knew it. Undecided is defensible. |
| `3a354149bcea` (H24) | Yes | **No** | `__clean_func_state` corrupts a stack slot's `spilled_ptr`/`slot_type`, **B does not consume stack slots** | **R2 is right, literally.** §3.3's question is "does it corrupt an artifact in B's consumption set" — a stack slot is NOT in the consumption set, the answer is No. R1 had written Yes saying "blind twice"; the two agree on blindness, but not on the **bucket**. |
| `713274f1f2c8` (H28) | Yes | **Undecided** | `check_stack_write_fixed_off` zeroes a stack slot's `spilled_ptr.id` (unmodeled) | The same seam: the written field is a **stack slot**, B does not read it. |

**All three are on the same seam:** a field written to a stack slot. B never consumes stack slots
(the capture does not print them). Such a bug is **blind** to B — but in §3.3's trichotomy
this blindness is not "Yes" (consumed was corrupted) but **"No"** (not consumed), and the "No"
"potentially visible" reading comes out wrong here. H23 had opened the same seam from the other side
(on the path but unmodeled). So the disagreements point less to rater noise than to
**the problem's own weak point**: "not consumed" covers two different things —
a field the oracle never looks at, and an arm the oracle does not model — and both are blind.

The gold was not changed (preregistration). But what needs fixing is not the gold, but the **question**: §3.3's
"No" answer must be split in two, or "blind because unconsumed" must be named separately.

## Limits

- Rater 2 is not human. What is measured: *whether an independent reader reading the same question from the
  same source gives the same answer.* Not human inter-rater agreement.
- n=28, and the flagship 40 could not be re-scored (the list was not kept).
- Rater 1's "Yes" class is small at 7 cases; all three of the three disagreements are in that class, so
  Yes-class agreement is 4/7.
