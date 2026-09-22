# Held-out batch 1 — RESULTS

Preregistration: `PREREGISTRATION.md`, commit `58967bf`. This file was written **after** that commit.

## 1. H1–H9 (IRRELEVANT predictions): 9/9 held

Prediction: none of the touched functions/fields will be modeled in oracle B's source
(`scripts/subsume-check.py`, `harness/bpfsubs.h`).

| searched | occurrences in B |
|---|---|
| `btf_id_allow_sleepable`, `convert_ctx_accesses`, `jit_subprogs`, `record_func_key`, `check_kfunc_args`, `check_stack_read`, `save_aux_ptr_type`, `merge_ptr_types` | 0 |
| `insn_aux_data`, `subprogno`, `ptr_type` | 0 |

Nine out of nine.

## 2. H10 (`0acd03a5bd18`) — the real test

Prediction: **B cannot see this**, because `prepare_func_exit()` writes `precise` and `live`,
and these two fields are raw inputs B CONSUMES.

Found in the source:

```python
# subsume-check.py:375  — precision short-circuit
if o['prec'] == 0 and p['exact'] == 0:
    st.shortcircuit += 1; continue

# subsume-check.py:307  — liveness gate
if o['era'] == '2021' and not o['live']:
    st.live_gated += 1; continue
```

Both `o['prec']` and `o['live']` come **from the kernel's own capture**
(`PRUNEPAIR ... prec=(\d+) live=(\d+)`, lines 165 / 213 / 219 / 221). If the kernel
skips marking precision, the capture says `prec=0`, the model also reads `prec=0` and
takes the **same** short-circuit. The same for `live`. **Prediction held.**

### And I almost erred in the opposite direction

`live_bit()` (line 264) reads `bpflive.h`'s **independent recomputation** —
the `LIVENESS status=ok mask=` line, `bpflive_run(ins, n, &out)`, its input the instruction stream.
For a moment I took this for a gate and was about to declare my own prediction falsified. But
`live_bit`'s return goes only to **counters** (`live_cmps`, `dead_reg_cmps`,
`saw_tracked_reg`, lines 298–304); it gates nothing. The docstring already
said so: *"the model does NOT enforce the liveness gate, but so that it can count the COST
of not enforcing it."*

This is the distinction at the very heart of the paper's thesis: **an independent recomputation may
exist and still not be bound to the verdict.** Evidential independence is not the independence of the
input, but the independence of **the input that feeds the verdict**.

### The preregistration's falsification condition was BADLY WRITTEN — noted for the record

The condition I wrote: *"if `precise`/`live` is a predicate arm modeled in B, the prediction
fails."* Both are modeled arms (short-circuit and gate), but **by consuming the kernel's
values**. So if the condition is read literally, H10 counts as falsified;
if read by substance, it counts as held.

The criterion that draws the distinction correctly is the paper's own: **does it recompute, or does it
consume.** By that criterion I count H10 as "held" and declare it here — but a stricter
reviewer might count H10 as *undecided*, and that reading is defensible. Batch 2's
falsification condition will therefore be written as **"if B independently recomputes this field and
binds it to the verdict, the prediction fails"**.

## 3. Composition — a direct measurement of §6's first threat

| frame | IRRELEVANT | on the state-equivalence path |
|---|---|---|
| original (message quotes state), n=40 | 15 (37.5%) | 25 (62.5%) |
| held-out (the complement of that criterion), n=10 | **9 (90%)** | 1 (10%) |

Fisher exact test, two-sided: **p = 0.0040**.

So §6's sentence "the frame is biased and we know its direction" now carries a number:
selecting fixes whose message quotes the verifier state **markedly over-represents**
the errors on the state-equivalence path. The consequence: §5.3's 58% blind / 5%
target figures are **conditional on that frame**. In an unfiltered frame both oracle B's
blind share and target share drop.

This is a consequence, not part of the independent test — the preregistration said so.

## 4. Count

- **Held-out cases: 1 → 11.** (10 new + §4.1's existing one.)
- Of these, the number testing the **blind boundary**: 1 (H10). Nine test the IRRELEVANT arm.
- Falsified predictions: 0. Possibly undecided: 1 (H10, for the reason above).

Testing the blind boundary further requires batch 2: same rule,
`sort frame.txt | sed -n '11,20p'`.
