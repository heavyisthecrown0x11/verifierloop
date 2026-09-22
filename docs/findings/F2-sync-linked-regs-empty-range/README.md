# F2 — `sync_linked_regs()` drops a register into an EMPTY range, and no check catches it

**Kernel:** bpf-next `5e289c5a4a52` (2026-08-22) + one local patch; in the VM `7.2.0-gdffc1150e2cc`
**And it is also produced on today's tip:** `7.3.0-rc2-gaf0b84a9215d` (bpf-next, 2026-09-08)
**Found by:** verifierloop, hunt round 11, seed `0x5EED0011` (2026-09-10)
**Class:** verifier internal invariant violation (`REG INVARIANTS VIOLATION`).
**NO SECURITY IMPACT** — measured, not assumed: see "Gate 2".
**Attribution:** `bbc631085503` ("bpf: replace min/max fields with struct cnum{32,64}") — narrowed to a single commit
**Status:** reproduced on the stock kernel, minimized, reduced to a hand-written three-control-arm minimal
repro, mechanism nailed down in source, attribution closed with two byte-identical-config builds,
and **checked against the current tip of both trees**. Not sent upstream.

> **PROVENANCE CORRECTION.** The first draft (and my first review) described the kernel as "clean upstream
> dffc1150e2cc". **Wrong.** `dffc1150e2cc` is our own commit —
> F1's `kernel/bpf/disasm.c` guard, 4 lines. The real upstream base is `5e289c5a4a52`
> (2026-08-22). Also, `Not tainted` says nothing about a source patch; it says
> no out-of-tree module is loaded, and I used it as a false anchor in the first review.
> The finding still stands because that patch only changes the disassembler's printing path and
> cannot enter the verifier's state computation — but the claim now rests on measurement: **the same program, on
> today's upstream tip with no local patch, produces the same violation.**

---

## In one sentence

On the **impossible** arm of a conditional branch, a third register that does not enter
the comparison is dropped into an empty range (`CNUM64_EMPTY`) by `sync_linked_regs()`;
because dead-branch detection and the invariant check run **before** this write, no one sees it.

## What was observed

```
verifier bug: REG INVARIANTS VIOLATION (alu): range bounds violation
  r64={.base=0xffffffffffffffff, .size=0xffffffffffffffff}
  r32={.base=0xffffffff, .size=0xffffffff} var_off=(0x0, 0x6)
WARNING: kernel/bpf/verifier.c:2211 at reg_bounds_sanity_check+0x178/0xa10
```

`{U64_MAX, U64_MAX}` = `CNUM64_EMPTY`: the register's range is the empty set, its tnum is still `{0,2,4,6}`.

## Minimized reproducer (20 gen → 4 gen)

Genome: `genes=4 hi=0:15.2.0.8.41,3.1.1.1.31,15.0.2.2.32,10.0.1.7.39`
Core sequence (unknown scalars read from the r6/r9 map value):

```
17: (25) if r9 > 0x9 goto pc+1
18: (57) r6 &= 9            ; r6 ∈ {0,1,8,9}
19: (27) r6 *= 2            ; r6 ∈ {0,2,16,18}  var_off=(0x0; 0x12)  range [0,18]
20: (26) if w6 > 0x3 goto pc+1
21: (57) r9 &= 3
22: (bf) r7 = r6            ; LINK — r6 and r7 share an id
23: (07) r7 += 8            ; BPF_ADD_CONST, id=3+8
24: (bf) r9 = r6
25: (25) if r7 > 0x10 goto pc+1
26: (0f) r6 += r6           ; <-- REG INVARIANTS VIOLATION (alu)
27: (bf) r0 = r6
28: (95) exit
```

At 24, `R6=scalar(id=3, umin=4, umax=18, var_off=(0x0; 0x12))` → the true set is `{16,18}`;
`R7 = r6+8` → `{24,26}`. The **fall-through arm of the `r7 > 16` branch is impossible** (`[12,16] ∩ {24,26} = ∅`).
The verifier still walks that arm, and after 25 the kernel's own log prints this:

```
25: (25) if r7 > 0x10 goto pc+1
   R6=scalar(id=3,smin=smin32=-1,smax=smax32=-2,var_off=(0x0; 0x2))
   R7=scalar(id=3+8,smin=umin=smin32=umin32=12,smax=umax=smax32=umax32=16,var_off=(0x8; 0x12))
```

This line carries the whole finding: **R7, refined by the comparison, is sound**
(`[12,16]`, well-formed); R6, written **after** it, is the one that goes empty (`smin=-1, smax=-2` — the signed
spelling of `CNUM64_EMPTY`).

## Mechanism — the exact place in source

`check_cond_jmp_op()`, `kernel/bpf/verifier.c`:

| line | what |
|---|---|
| 16157 / 16169 | `regs_refine_cond_op()` — refinement of the arms |
| **17050** | `regs_bounds_sanity_check_branches()` — **THE CHECK** |
| **17063–17071** | `sync_linked_regs()` — **THE WRITE, AFTER the check** |

- `regs_bounds_sanity_check_branches()` (16617) checks only `true_reg1/2`, `false_reg1/2` —
  i.e. only the registers that **enter the comparison** (16621–16624).
- `is_branch_taken()` → `simulate_both_branches_taken()` already detects the dead arm with an
  empty range (`range_bounds_violation()`, 16165/16177) — but again only for those two registers.
- Our register that goes empty (r6) is NOT in the comparison. `25: (25) if r7 > 0x10` is a
  `BPF_JGT|BPF_K`; dst=r7, no src register — so the `BPF_SRC == BPF_X` arm at 17063 never
  runs, only the dst arm at 17069 does. That is the only thing that touches r6.
- At the end of `sync_linked_regs()`, `reg_bounds_sync(reg)` → `__reg_bound_offset()` →
  `cnum64_intersect_with(&reg->r64, cnum64_from_tnum(reg->var_off))` (2082) → `EMPTY`.
  The result is checked nowhere, the path is not declared dead.

**The gap in one sentence:** dead-branch detection and the invariant check run BEFORE
linked-register propagation; `sync_linked_regs()` can empty a third register, and no one sees it.

## This is NOT an observation effect (Heisenberg) — proof from source

`BPF_F_TEST_REG_INVARIANTS` is read in **exactly one place** in the whole kernel, and **after** the report:

```c
2211:  verifier_bug(env, "REG INVARIANTS VIOLATION (%s): %s ...");   /* report */
2217:  if (env->test_reg_invariants)
2218:          return -EFAULT;                                        /* THE ONE read */
2219:  __mark_reg_unbounded(reg);                                     /* flagless path */
```

(`grep -rn test_reg_invariants kernel/bpf/` → only 2217 and the assignment from `attr` at 21213.)

The flag cannot enter any state computation. `verifier_bug` too is only `BPF_WARN_ONCE` +
`bpf_log` — it changes no state. On the harness side the parity is complete too: `prune_load_typed()`
uses `log_level=2` in all three of the three loads, the only thing that varies is `prog_flags`.

The empty range occurs without the flag too; the flag only makes it visible.

## What is NOT being claimed: "accept" alone is not proof of unsoundness

| load | result |
|---|---|
| `base` (flagless) | accept |
| `BPF_F_TEST_STATE_FREQ` | accept |
| `BPF_F_TEST_REG_INVARIANTS` | reject, errno 14 (EFAULT) |

Reading this table as "the verifier accepts a corrupt state" **would be wrong.** On the flagless path
2219 runs: `__mark_reg_unbounded(reg)` — it **widens** the empty set to ⊤, i.e. the sound direction.
The stock kernel verifies and accepts the program not with `r6=∅` but with `r6=⊤`. Moreover,
because it is `BPF_WARN_ONCE`, in production everything after the first is a completely silent widening.

The content of the finding is not acceptance, it is this: **the verifier constructs a state its own
invariant forbids, via a path no check covers**, and the only reason it stays sound is a blanket
fallback that discards all information about that register.

## Attribution: 17 commits → a single commit

Two stock builds, **byte-identical config** (`md5 f5a6ed6d…`), the same minimal genome:

| commit | what it does | inv_verdict |
|---|---|---|
| `789b7c1c64b9` (pre-cnum, 2026-04-24) | — | accept, no violation |
| `b93f7180f0bc` | accessor functions for min/max (mechanical) | accept, no violation |
| **`bbc631085503`** | **min/max fields → `struct cnum{32,64}`** | reject errno=14, violation present |

In all of them `base_verdict=accept base_states=4 freq_states=12` — i.e. the negative controls do not
reject the program for an unrelated reason, they **verify it the same way**; the only difference is the
invariant check. Raw lines: `evidence.txt`.

    Fixes: bbc631085503 ("bpf: replace min/max fields with struct cnum{32,64}")

## Independent verification (review leg, 2026-09-10)

Separately from the run that found it, on the review leg four kernels were re-run and all four produced
the table above. In addition:

- The `.lab/bpf-next` tree at `dffc1150e2cc` is clean (`git status` empty, `git diff` empty).
- The `vmlinux` banner is `7.2.0-gdffc1150e2cc`; `verifier.c:2211` in the tree is exactly the
  `verifier_bug` call named in the kernel's WARNING — i.e. the binary matches this source.
- `bzImage` ≠ `bzImage-instr` (different md5): the finding is on the stock kernel, not the instrumented one.

## Novelty — honest and narrow

This is **not a new bug class.** Harishankar Vishwanathan's RFC describes exactly this problem:
*"bpf, verifier: Detect empty intersection between tnum and ranges"*
([lkml, 2025-11-07](https://lkml.org/lkml/2025/11/7/1313); with Paul Chaignon's reply,
[2025-11-13](https://lkml.org/lkml/2025/11/13/1451)). The RFC's own example is the same shape as ours:
`t = x0x1 {1,3,9,11}, r = [4,8]` — `tmin <= umax && tmax >= umin`, and yet the intersection is empty.

**The symptom type is also a known type.** The RFC's cover letter says this explicitly: fuzzing
campaigns have already reported programs that trigger `REG INVARIANTS VIOLATION`. So "a fuzzer
found this" is not in itself a contribution.

The surviving contribution is **one sentence**, and it is verifiable from source: the RFC points to
after the `regs_refine_cond_op()` calls (~16169) as the integration point; `sync_linked_regs()` runs at
17063, i.e. **after that**. A check placed there would not catch this shape — because the register that
goes empty is not the register the condition refines, but the linked register written after it.

The same class has also been seen in the real world (Cilium/Talos, kernel 6.18.x — siderolabs/talos#12726;
this attribution is second-hand, unverified).

## The three gates — F1's lesson, applied by measurement

In F1 the finding was real but upstream had already fixed it and we were on an old checkout. This time all
three gates were passed explicitly. The instrument: `harness/f2probe.c` — a separate, **self-contained
binary that never touches diffharness** (the concurrent hunt round uses that instrument). Run:
`scripts/run-f2probe-vm.sh`.

### Gate 1 — tip-edge, or a duplicate? **Produced at the tip-edge. Not a duplicate.**

The clone's `origin/master` was frozen on 2026-08-22 and had never been fetched (`FETCH_HEAD` did not exist).
Both trees were fetched:

| tree | tip | result |
|---|---|---|
| bpf-next | `af0b84a9215d` (2026-09-08), **9889 commits** ahead of our base | built, `P0` **produces the same violation** |
| bpf (fixes) | `e4a62833adff` (2026-09-09) | ordering unchanged (check 17050, sync 17063/17069) |

**None of the 9889 intervening commits touch `sync_linked_regs`.** There is a single
`REG INVARIANTS` fix in the range — `150aeba624e8` ("Fix REG INVARIANTS VIOLATION on speculative
pointer arithmetic") — and it moves `__mark_reg32_unbounded` inside `adjust_ptr_min_max_vals` to after
`sanitize_ptr_alu`: a different path, it does not touch our shape.

Remaining residue: a fix that landed in `bpf.git` in the last day and has not yet flowed to bpf-next was
not checked (the fixes tip is 2026-09-09).

### Gate 2 — a bug, or the flag doing its job by design? **NO security impact, and this was measured.**

The question was: what happens if empty-range R6 enters a memory access as base+offset? A controlled
experiment — **same access, same value range**, the only difference being whether the register goes empty:

| program | R6 empty | load | run |
|---|---|---|---|
| `M1_store_via_ptr` (`r1 = r8; r1 += r6; *(u8*)(r1+0) = 0x41`) | **yes** | **reject, errno 13** | — |
| `M2_load_via_ptr` | **yes** | **reject, errno 13** | — |
| `M3_store_no_link` (no link → R6 never goes empty) | no | **accept** | ran, clean |
| `M4_load_no_link` | no | **accept** | ran, clean |

The control arm isolates the reason for rejection: the access and the range are the same, **when the
emptiness is removed it is accepted.** So the rejection stems from the emptiness, not from an ordinary
bounds check. And the text of the rejection states the direction:

```
Suggestion: Preserve a pointer-valued register where needed, or reload and revalidate
the pointer after scalar arithmetic, helper calls, or other operations that can invalidate it.
```

**The direction is CONSERVATIVE: the empty range makes the verifier stricter, not looser.** On a
KASAN kernel there is no oops/KASAN report.

Source explains this. `CNUM64_EMPTY = {base=U64_MAX, size=U64_MAX}` looks like this from the accessors:

- `urange_overflow` → true ⇒ `umin=0`, `umax=U64_MAX` — **the unsigned view is fully free**,
  i.e. "I know nothing", the safe direction.
- `srange_overflow` → false (because `contains()` is always false when empty) ⇒ `smin=(s64)U64_MAX=-1`,
  `smax=(s64)(U64_MAX+U64_MAX)=-2` — **an inverted signed range**, and every place with a `smin < 0`
  check rejects.

Moreover `include/linux/cnum.h` states this explicitly: *"The caller should ensure `!is_empty(cnum)`
holds when calling `cnum{T}_umin`/`umax`/`smin`/`smax`."* What is violated is a documented
precondition; the consequence is rejection in both directions.

**Conclusion: same class as F1** — real, nailed in source, but with no security impact. What is proven is
"the verifier violates its own invariant and calls it a bug itself"; what is proven is **not** OOB or a
false-accept.

### Gate 3 — a deterministic, control-arm minimal repro. **19 instructions, three controls.**

Not a genome, a hand-written program. Each control arm removes **a single component**:

| program | removed | violation |
|---|---|---|
| `P0_alu` (19 instructions) | — | **PRESENT** (`ctx=alu`) |
| `C1_no_addconst` | `r7 += 8` (BPF_ADD_CONST) | none |
| `C2_no_link` | the link (r7 loaded independently, same range) | none |
| `C3_no_umin` | `if w6 > 3` (the branch that pulls umin to 4) | none |

All three are the same on the stock kernel and on today's tip. So the violation is the **intersection**
of three components: the linked register + the constant offset + the umin narrowing.

A fourth observation, worth documenting: `N0_no_payload` — if the emptied R6 is never touched again
afterward, **no diagnostic appears and the program is accepted**. The repair (`__mark_reg_unbounded`)
runs only where `reg_bounds_sanity_check` is called (2265, 6703, 10507, 16060, 16621–24), and none of
those are memory accesses. So the empty state lives silently until an operation that checks it comes
along.

## What was NOT proven

- **The pruning direction is open.** Whether the states produced by the dead path are used to prune live
  paths was not measured. `N0_no_payload` shows why this risk is real: the empty state can exist without
  producing any diagnostic. (0092/`92424801261d` is a historical example: "fix state pruning of fake
  registers".) Closing this is a separate experiment.
- **Exploitability was not shown, and Gate 2 produced evidence in the opposite direction** — the direct
  memory-access path was measured and is rejected.
- This is not an *unsoundness* claim.

## THE SECOND-SHAPE CLAIM IS WITHDRAWN — same symptom, mechanism NOT VERIFIED

The first draft (and my first version that carried it) presented round 12 as "the same bug, an
independent shape". **This is not supported.** On review two claims collapsed separately:

**1. "470 violations in the hunt log" — a misnomer.** In `fuzz-hunt-12.log` there is **one**
`REG INVARIANTS` line (`BPF_WARN_ONCE`, once per boot). The number 470 comes from the
`invfault=470` field and counts this in the harness (diffharness.c:4977):
the base load accepted **and** the invariants-flagged load was rejected with EFAULT.
So 470 is **program instances**, from a single mutation lineage (425 distinct genomes) — not 470
independent findings.

**2. "again a LINKED register (shared id, smin=-1, smax=-2)" — could not be verified.**
In `replay-r12-stock.log` there is no id-bearing register with `smin=-1`. This grep was run
on review, **returned empty**, and I waved it off saying "probably a different formatting".
The error is not a missing check, it is **excusing a failed check**.

**And the tnum signatures differ**, so it is probably not even the same producer:

| round | `var_off` | set | mechanism |
|---|---|---|---|
| 11 (F2, `P0`), 28 | `(0x0, 0x6)` | {0,2,4,6} | `sync_linked_regs` — **verified**, three control arms |
| 12, 17 | `(0xe, 0x1)` | {14,15} | **unknown** |

The only thing in common is the symptom: an empty range reaching an ALU check. A common
mechanism is **not claimed**.

Per-round numbers (`invchecked` / `invfault`): 11 → 76709/76 · 12 → 71790/470 ·
13 → 68902/0 · 17 → 66128/398 · 29 → 69538/0. Round 28 is not a hunt round: it is a replay of
F2's minimal genome on the instrumented kernel
(`verifier.c:2122`, not the 2211 in stock).

What is needed to add shape B to F2 is clear and was not done: minimization, and showing whether
`sync_linked_regs` is the producer with control arms —
the same thing `f2probe` does.

## Reproduction

```bash
# NOTE: SSHPORT is required. If a concurrent hunt VM holds the default 10022, qemu silently
# fails to start and the script says "markers not found" — which looks like a load error.
SSHPORT=10122 KERNEL=$PWD/.lab/build/bzImage \
  HARNESS_ARGS='--fuzz-replay "genes=4 hi=0:15.2.0.8.41,3.1.1.1.31,15.0.2.2.32,10.0.1.7.39"' \
  TIMEOUT=300 scripts/run-harness-vm.sh .lab/replay-min-stock.log
grep -E "^PRUNE " .lab/replay-min-stock.log      # inv_verdict=reject inv_errno=14
grep "REG INVARIANTS" .lab/replay-min-stock.log
```

For the negative control use `KERNEL=$PWD/.lab/build/bzImage-cn-a` (accept, no violation).

The hand-written, control-arm probe (needs no genome, does not touch diffharness):

```bash
cc -O2 -static -o harness/f2probe harness/f2probe.c
SSHPORT=10122 KERNEL=$PWD/.lab/build/bzImage \
  scripts/run-f2probe-vm.sh .lab/f2-stock.log
grep '^F2 name=' .lab/f2-stock.log
# expected: P0 viol=1 ctx=alu; C1/C2/C3 viol=0; M1/M2 reject 13; M3/M4 accept
```

Against today's tip: `KERNEL=$PWD/.lab/build/bzImage-tip` (worktree `.lab/bpf-tip`,
built with `SRC=... OUT=... scripts/build-kernel.sh`).

## Provenance and evidence gaps

- Raw logs are under `.lab/` (gitignored, heavy): `fuzz-hunt-11.log` (76 findings),
  `replay-inv-stock.log`, `replay-min-stock.log`, `replay-min-precnum.log`,
  `replay-min-cn-a.log`, `replay-min-cn-b.log`, `replay-r12-stock.log`.
  The `evidence.txt` in this directory is the minimal, version-controlled evidence extracted from them.
- **The control logs that produce no violation do not carry their own kernel identity** — with no WARNING
  there is no version dump either, so the provenance is not in the artifact but in the env var at run time.
  Closed by re-running on the review leg; the artifact alone does not prove it.
  Open item: OPEN-ITEMS **OI-18**.
- `.lab/harness-serial.log` is a single, shared file; concurrent runs overwrite each other.
  Open item: OPEN-ITEMS **OI-19**.
