# patches/ — print-only kernel instrumentation

The patches here are applied to the tree under test and **only produce output**. None
of them changes a decision of the verifier, and this is not a claim but a
**condition**: a patch may be used only if the stock and patched kernels give the
**byte-for-byte same verdict sequence** on the same corpus.

## `prunepair-instrumentation.patch`

`kernel/bpf/states.c`, the `hit:` label — i.e. the moment `states_equal()` finds two
states equivalent and decides to prune. There **both `sl->state` (old/checkpoint) and
`cur` (current)** are in scope; the log, however (measured in 0088), carries **neither
side** of that pair.

Why `print_verifier_state` was not reused: that function cannot express the load's
domain. `range_within` is now arc-containment over `cnum{base,size}` whereas the log
prints eight derived projections; `precise`, which decides whether the check will be
done, exists in the log only as a `P` prefix; because `id` is printed masked, the
ADD_CONST32/64 distinction that `regsafe` counts as a hard mismatch is lost. That is
why the **raw fields** are printed.

Setup:

```bash
git -C .lab/bpf-next worktree add --detach $PWD/.lab/bpf-instr HEAD
git -C .lab/bpf-instr apply $PWD/patches/prunepair-instrumentation.patch
SRC=$PWD/.lab/bpf-instr OUT=$PWD/.lab/build/bzImage-instr scripts/build-kernel.sh
```

MANDATORY verification before use (run and passed in 0098):

```bash
HARNESS_ARGS=--gen-comp TIMEOUT=1800 scripts/run-harness-vm.sh /tmp/stock.log
KERNEL=$PWD/.lab/build/bzImage-instr HARNESS_ARGS=--gen-comp TIMEOUT=1800 \
  scripts/run-harness-vm.sh /tmp/instr.log
diff <(grep -oE '^RESULT decision=[a-z]+ .*errno=[0-9]+' /tmp/stock.log) \
     <(grep -oE '^RESULT decision=[a-z]+ .*errno=[0-9]+' /tmp/instr.log)   # must be EMPTY
```

**A finding is never left on the patched kernel.** The patch is an oracle, not a
verdict: everything that comes out of the patched kernel must be re-derived on the
stock kernel.

## `prunepair-instrumentation-minmax.patch` — era variant (pre-cnum)

The same instrumentation, for the tree BEFORE 2026-04-24. Two differences:

- the file is `kernel/bpf/verifier.c` (`kernel/bpf/states.c` does not exist in that revision),
- the fields are `umin..umax` / `smin..smax` / `u32` / `s32` instead of `r64`/`r32`, and there is no `parent_id`.

The separator is meaningful and tells the consumer which load it owes: **`+` a
base+size arc** (cnum, `cnum_is_subset`), **`..` a min..max range** (pre-cnum, the
eight-comparison `range_within`). `scripts/subsume-check.py` reads both forms and at
every catch applies that era's OWN load — carrying that era's bug one-to-one too,
because otherwise every difference in between looks like a "finding".

Setup and mandatory verification, the same as the tip variant; for the `2f2ec8e7730e`
pair **both halves** were run:

```
stock  .lab/build/bzImage-buggy8     896 blocks, 775 accept / 121 reject
patch  .lab/build/bzImage-instr-b8   896 blocks, 775 accept / 121 reject
verdict sequence, INCLUDING errno: SAME    ·    PRUNEPAIR: patched 11,866, stock 0
```

This is the first time the contract was run with the **correct control**: the two
kernels being compared are on the same revision and differ only in the patch. The era
run in 0100 compared era-patched ↔ tip-stock, which does not isolate the patch.

## Era sensitivity

The patch is era-sensitive depending on the FIELDS it prints, and each calibration
target may need a small variant. Measured boundaries:

| field | present since |
|---|---|
| `r64` / `r32` (cnum) | **2026-04-24**, `bbc631085503` — the patch does not build on a kernel older than this |
| `parent_id` | after `cd5b460ed1ec~1` |
| `kernel/bpf/states.c` | split out as a file later; in the pre-cnum tree it is all in `verifier.c` |

**CORRECTION (leg 0101).** This base was FIRST justified wrongly: "the model
implements `cnum_is_subset`, and that load does not exist before 2026-04-24." The
load not being on the old kernel is NOT a limit of the model — it is its reason for
being; indeed `cd5b460ed1ec` is the commit that ADDS `is_subset` to `cnum_defs.h`, so
that load simply does not exist on the buggy tree.

The real base is the **fields**: the patch does not build without `r64`/`r32`. And a
base that comes from the fields is **removable** — the min/max variant in this file
removed it. That is why it is not a sibling of the 2023-11-11 REG_INVARIANTS base:
that base is ontological (the flag does not exist in the kernel), this base was a
consequence of the chosen catch form. `2f2ec8e7730e` (2026-04-11) was CALIBRATED,
not un-calibratable, thanks to this distinction.
