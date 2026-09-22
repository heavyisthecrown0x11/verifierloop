# Open items — tracked, not blocking

Findings and hypotheses that are **deliberately left open** rather than closed or
dropped. Each says *why* it is open, what would settle it, and its priority. This
file exists so an unresolved item cannot quietly become a settled one.

Closed items are removed from here and their resolution recorded in the devlog.

---

## OI-1 — Two `int3` crashes: artifact hypothesis is FALSIFIABLE; KVM-TESTED BUT NULL STILL VOID

- **Status:** OPEN (low priority). *Not* "diagnosed and closed." **Now KVM-tested but
  the null is still VOID** — see the 2026-09-03 update.
- **Raised:** 2026-08-28 (devlog 0020)
- **Update (2026-09-03, devlog 0028):** KVM is available (0027) so the block is no
  longer the accelerator — it is now **pipeline instability**. Across five KVM
  campaigns this turn, **int3 never recurred** (~0.67M cumulative execs), which
  *supports* the TCG-artifact hypothesis. BUT the pre-registered criterion (one CLEAN
  run clearing exec ≥ 150k; a self-crashing campaign voids the null) was **never met**:
  every campaign eventually self-crashed. Three poisons were fixed (binfmt, F1 panic,
  `PROG_TEST_RUN` RCU stall = OI-11) and a fourth contained (reproduction-starvation =
  OI-12), but an underlying elevated VM-death rate under nested KVM degrades every long
  run. So the int3=0 result is **suggestive, not sufficient**; OI-1 stays open. Cheapest
  next probe: a **single-VM** KVM campaign (removes 8-VM contention; also one of OI-1's
  original partial discriminators).
- **Update (2026-09-03, devlog 0029) — single-VM probe RUN, also VOID:** it was
  *worse*, not better — **31 VM disconnects in 30 min**, corpus triage NEVER completed
  (candidates stuck at 1057), only **~4.2k execs** (35x under the 150k bar). So the
  instability is NOT 8-VM contention: even one VM disconnects constantly under
  sustained load. (Confound: this probe also raised VMCPU 2→4 / VMMEM 2048→4096; the
  pre-registered hard-stop forbade a re-run to disambiguate, and the conclusion holds
  either way.) **Verdict:** WSL2 nested-KVM on this host cannot sustain a productive
  syzkaller campaign, so OI-1 cannot be settled on the syzkaller path here. int3=0
  across ~0.68M cumulative execs is accepted as **SUGGESTIVE** of the TCG-artifact
  hypothesis, not proof. OI-1 stays open at low priority; a real settling needs
  bare-metal or a non-nested KVM host (outside this repo's control, like the original
  Win11 precondition).
- **Superseded block (kept for history) — Blocked by:** KVM unavailable on this host (probed 2026-08-28: `/dev/kvm` exists
  but `-enable-kvm` → `No such device`, and `grep -c '(vmx|svm)' /proc/cpuinfo` = **0**,
  i.e. the CPU virtualization flags are not exposed at all).
  **Correction (reviewer, 2026-09-01):** WSL2 nested virtualization is **Windows
  11-specific** and does not work on Windows 10. An earlier expectation that it might
  work on Win10 was wrong and is retracted. So the Win11 migration is a genuine
  PRECONDITION for KVM, not an optional tweak — which also means this item cannot be
  settled by any amount of work inside the repo.

**What happened.** A 30-minute syzkaller campaign produced two crashes:
`int3 in sk_filter_trim_cap` and `int3 in __seccomp_filter`
(`.lab/syzkaller/workdir/crashes/`).

**Hypothesis (emulation artifact, not a verifier logic bug).** Supporting evidence,
strongest first:

1. **Both RIPs are the same site**: `filter.h:763` =
   `static_branch_unlikely(&bpf_stats_enabled_key)` (declared `filter.h:744`) — a
   live-patched static branch, exactly where int3-based text poking happens.
2. **The crashes are not in the fuzzed programs**: they land in unrelated daemons
   (`udev-worker` via a netlink broadcast socket filter; `systemd-udevd` via
   seccomp). Any process running a BPF program can be at that site when the key flips.
3. **The trigger is present**: syzkaller's enabled surface includes `bpf$ENABLE_STATS`,
   which toggles `bpf_stats_enabled_key`, forcing the kernel to text-patch that branch.
4. We run **`-accel tcg,thread=multi`**; concurrent code patching across vCPUs is a
   known weak area for TCG.

**Explicitly NOT decisive evidence.** Both crashes are `repro=false`. Non-reproducibility
is *consistent with* an emulation race, but **genuine race-condition kernel bugs are
also non-deterministic**, so this is supporting, not discriminating. (Devlog 0020
originally leaned on it too heavily; corrected.)

**What would settle it (the falsifying test).** Re-run the same campaign under **KVM**
(or bare metal), same kernel, same syzkaller config:

```bash
# once /dev/kvm works: flip the accel in the manager config, regenerate, re-run
QEMU_ARGS="-enable-kvm -cpu host" ./scripts/gen-syz-config.sh
DURATION=... ./scripts/run-syzkaller.sh
```

- Crashes **disappear** under KVM → supports the TCG-artifact hypothesis.
- Crashes **reproduce** under KVM → the hypothesis is wrong; this becomes a real
  kernel-side lead and gets triaged properly.

**Power caveat (do not run a token test and call it settled).** The observed base rate
is ~2 crashes per 30 minutes across 4 TCG VMs. A single short KVM run showing zero
crashes is **weak** evidence. Match or exceed the original exposure — and note KVM is
~10–20x faster, so equal *exec count* is reached in far less wall-clock; compare on
**execs, not minutes**, consistent with the project's period model.

**Available-now tests and why they are not run.** Two partial discriminators exist
without KVM: (a) single-threaded `-accel tcg` (removes the concurrency the hypothesis
blames), (b) dropping `bpf$ENABLE_STATS` from the enabled syscalls (removes the key
flip). Both are **underpowered** at the observed base rate — a null result in one
30-minute run would not distinguish the hypotheses — and (b) also narrows the hunt
surface. Left unrun deliberately rather than run for the appearance of rigor.

**Why low priority.** This is not the target bug class (verifier logic), it does not
affect the pipeline's correctness, and the crashes are outside the loop's data path
(syzkaller crash reports are not yet ingested — see OI-2).

---

## OI-2 — syzkaller crash reports are outside the pipeline

- **Status:** OPEN (medium priority)
- **What:** crashes land in `.lab/syzkaller/workdir/crashes/` and are read by hand.
  They are not ingested, normalized, or surfaced in a period report.
- **Why it matters:** a crash is a real signal channel the loop currently cannot see;
  triage depends on someone remembering to look.
- **Shape of the fix:** a syzkaller crash/coverage parser feeding DERIVED + a
  period-level finding (not CORE — a crash is not a per-verifier-invocation observation).

---

## OI-3 — One of five ground-truth sources is still a stub

- **Status:** OPEN (medium priority) — *narrowed 2026-08-28 by devlog 0022,
  narrowed again 2026-09-01 by devlog 0024.*
- **Live now:** intrinsic invariants; helper `bpf_func_proto` (source 3, extracted —
  274 contracts); **`Documentation/bpf/verifier.rst` (source 2, 13 anchored cases —
  12 checked + 1 superseded)**.
- **Also live (0023):** **patch-diff (source 4), partially** — as doc-vs-code
  staleness EVIDENCE qualifying source 2, not as an independent check.
- **Still a stub:** `verifier.c` state-transition logic (source 1). **This is now the
  only stub**, and the next planned step is a pilot on ONE transition family (e.g.
  `check_alu_op` bounds) rather than the whole file — the point is to learn whether
  source 1 is mechanically extractable before investing in all of it.
- **Why it matters:** source 1 is a research problem in itself (parsing verifier
  semantics into checkable transitions). Source 4 remains partial for a *dependency*
  reason, not effort: a real cross-version behavioural diff needs observations from
  **two** kernel revisions and the lab builds one.

---

---

*(OI-4 — `bpf_func_proto` slice curated rather than extracted — **CLOSED** 2026-08-28
by devlog 0021: `helper_proto::extract_from_tree` now generates the slice from the
kernel tree; 12 → 274 contracts, 8 → 194 helpers, validated with 0 false positives on
both volume captures.)*

---

## OI-5 — The extracted proto table is too large to audit by inspection

- **Status:** OPEN (low priority, but load-bearing when it matters)
- **Raised:** 2026-08-28 (review of devlog 0021)
- **What:** `data/groundtruth/helper_protos.tsv` holds **274 contracts across 194
  helpers**, generated by `helper_proto::extract_from_tree`. The *inclusion rule*
  (only `arg_type`s that pin exactly one verifier reg-type family) has been reviewed
  and tested. **The 274 individual contracts have not been, and cannot practically be,
  audited one by one.**
- **Why it matters (the failure mode):** a rule that is correct in general can still
  be wrong for a specific argument — e.g. an arg that legitimately accepts different
  reg types depending on program type, promoted to a strict contract. That produces a
  **false mismatch that looks exactly like a real finding**: "the verifier accepted a
  program violating its documented contract".
- **Standing instruction:** when the FIRST real `helper_arg_type_mismatch` appears,
  the extraction table is the **first suspect**, before the verifier. Confirm against
  `bpf_func_proto` in the tree and check whether the arg is program-type dependent,
  BEFORE reporting it as a verifier bug.
- **Partial mitigations in place:** the accept-only gate (a rejected program's
  mismatch is the verifier working, not a finding); 0 false positives across two real
  volume captures (~150 checks); the mapping table is small and commented.

---

## OI-6 — A documented divergence will have two possible causes

- **Status:** OPEN (standing triage instruction, not a defect)
- **Raised:** 2026-08-28 (review of devlog 0022)
- **What:** citation anchoring guarantees a documented sentence still EXISTS in
  `verifier.rst`; it cannot guarantee the sentence is still TRUE. So the first
  `documented_behavior_mismatch` has two candidate causes: a real verifier
  regression, or documentation that fell behind the code.
- **Evidence already attached (0023):** source 4 puts git facts on the finding —
  currently *"documentation last changed 2025-09-18, verifier.c last changed
  2026-08-18, 351 verifier.c commits since"*. The documentation is roughly eleven
  months and 351 verifier commits behind, so **stale prose is a live hypothesis, not
  a remote one**.
- **Standing instruction:** on the first divergence, check whether the specific
  behaviour changed in those commits (`git log -S` over the relevant verifier code)
  BEFORE reporting a regression.
- **FIRST REAL INSTANCE (2026-09-01, devlog 0024) — and it was the documentation.**
  `doc_msg_uninit_stack_arg` (verifier.rst:398, "doesn't initialize stack before
  passing its address into function") is **accepted** by the tree. Cause located in
  the source, not guessed: `kernel/bpf/verifier.c:21141`
  `env->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token)` →
  `bpf_token_capable(token, CAP_PERFMON)` (`include/linux/bpf.h:2869`). The documented
  rejection is **unprivileged-only** and the document states it unconditionally. So
  the first decision-level divergence this source produced was a documentation gap —
  exactly the outcome this item predicted. The case is now superseded (see OI-7),
  not deleted.
- **Related:** OI-5 is the same shape for source 3 (extraction table first suspect);
  OI-8 is the same shape for the source-2 harness programs.

---

## OI-7 — `superseded_by` is a silencer, and silencers create false negatives

- **Status:** OPEN (standing audit instruction, not a defect)
- **Raised:** 2026-09-01 (devlog 0024)
- **What:** a documented case may be silenced by a [`SourcePrecondition`] — a kernel
  source citation showing the documented claim does not apply to our load path. Today
  exactly **one** case is silenced this way (`doc_msg_uninit_stack_arg`, see OI-6).
- **Why it matters (the failure mode):** this is the only mechanism in the loop that
  can turn a real divergence into silence. A loosely chosen citation — one that is
  merely *nearby* the behaviour rather than *causing* it — would hide precisely the
  signal the leg exists to produce, and it would hide it permanently and quietly.
- **Guards already in place:** silencing needs a file + line + verbatim code text;
  `verifier_rst::load` re-checks that text is still in the tree on every load; a case
  whose citation disappears **revives by itself**; an unreadable source silences
  nothing; superseded cases are counted and printed with their reason, and are
  excluded from `documented_cases_checked` so they cannot inflate the denominator.
- **Standing instruction:** review the superseded list at every review, and require of
  each citation that it *causally* establishes the precondition. When in doubt, leave
  the case live and accept the false alarm — a visible false positive is cheaper than
  an invisible false negative.

---

## OI-8 — The documented-message programs carry translation judgements

- **Status:** OPEN (standing triage instruction, not a defect)
- **Raised:** 2026-09-01 (devlog 0024)
- **What:** the 11 examples in verifier.rst:353-560 are printed in `BPF_*` macro form,
  so transcription is exact — but the document leaves three things unstated, and
  `harness/diffharness.c` had to choose them (each marked JUDGEMENT at its case):
  a real map fd where the document writes `BPF_LD_MAP_FD(…, 0)` yet its own log shows
  a real map; `value_size = 16`, which the document never states; and the program type
  / load flag two cases need (`sched_cls` for the socket helpers, and
  `BPF_F_STRICT_ALIGNMENT`, without which x86's efficient-unaligned-access support
  makes the alignment claim inapplicable).
- **Why it matters:** a wrong choice here changes *which condition the program
  actually exercises*, so it can produce a mismatch that looks exactly like a real
  finding — the same shape as OI-5 for source 3.
- **Standing instruction:** on the first `documented_behavior_mismatch` from a
  `doc_msg_*` case, re-read that case's JUDGEMENT comment and confirm the program
  still reaches the documented condition BEFORE reporting a verifier bug.

---

## OI-13 — Which loop mechanism the first back-edge family targets

- **Status:** OPEN but DECIDABLE — the source reconnaissance below was done 2026-09-05
  (after devlog 0042) so the next leg can open with a decision instead of a question.
  Nothing is built yet.
- **Why it needs deciding first:** eBPF has three unrelated loop mechanisms and they
  trigger DIFFERENT verifier code paths. Picking wrong means the family never touches
  the surface it was built for — the failure mode [[oracle-times-input]] warns about,
  one level up.

### The three, as the tree actually has them

**1. `may_goto` — `BPF_JMP | BPF_JCOND`, `src_reg = BPF_MAY_GOTO`.**
Encoding is one raw instruction and nothing else: `BPF_JCOND` is `0xe0`,
`BPF_MAY_GOTO` is `0`, and `verifier.c:19075` requires `dst_reg == 0 && imm == 0`, so
the insn is `{.code = BPF_JMP|BPF_JCOND, .dst_reg = 0, .src_reg = 0, .off = <target>,
.imm = 0}`. No BTF, no kfunc, no subprog, no map. NOT in the distro uapi header we
compile against, so the harness must `#ifndef`-define both constants — the same pattern
0042 already uses for `BPF_F_TEST_REG_INVARIANTS`.
What it exercises (`verifier.c:16923`): the verifier queues the fall-through as a new
state, bumps `queued_st->may_goto_depth`, and — the interesting part — calls
`widen_imprecise_scalars(env, prev_st, queued_st)` against the previous entry at the
same instruction found by `find_prev_entry`. That is a DELIBERATE over-approximation
inserted to force convergence, sitting directly on top of precision marking and state
pruning. Note also a runtime wrinkle for later: the budget has a timed variant
(`bpf_check_timed_may_goto`, `bpf_jit_supports_timed_may_goto`), which matters only if
the family is ever executed rather than just loaded.

**2. Open-coded iterators — `bpf_iter_*` kfuncs, `process_iter_next_call`
(`verifier.c:8043`).**
A real back-edge simulated by forking ACTIVE/DRAINED iterator states and relying on
state convergence to terminate. This is the mechanism most entangled with pruning, and
the kernel says so in its own words (`states.c`, in `bpf_is_state_visited`): *"BPF
open-coded iterators loop detection is special. states_maybe_looping() logic is too
simplistic in detecting states that *might* be equivalent, because it doesn't know
about ID remapping, so don't even perform it."* A special case in the pruning path,
justified by an admitted simplification, is the densest target on this list. Cost:
kfunc calls need `BPF_PSEUDO_KFUNC_CALL` with a BTF id resolved at load time — real new
machinery for a raw-insn harness with no libbpf.

**3. `bpf_loop` helper — `BPF_FUNC_loop`, `set_loop_callback_state`
(`verifier.c:10118`).**
Not a back-edge at all: the verifier does not simulate the loop, it verifies the
CALLBACK body once as a separate frame with a synthesized state. A different axis
(callback state and precision across frames), worth its own leg, but it does not answer
"our first program with a back-edge". Cost: subprogs plus a `BPF_PSEUDO_FUNC`
relocation for the callback pointer.

### Recommendation: `may_goto` first, iterators second, `bpf_loop` third

`may_goto` is the only one that yields a genuine back-edge at ZERO new harness cost,
and what it lands on — `widen_imprecise_scalars` + `find_prev_entry` +
`may_goto_depth` — is a convergence over-approximation, which is precisely the shape
0042's kernel-vs-kernel differential was built to attack. The instrument transfers
unchanged: same three loads, same directional predicate, same `freq_states > base_states`
denominator. It is also the newest of the three and therefore the least fuzzed.
Iterators are the higher-value target and should be second, funded by whatever the
`may_goto` leg teaches about back-edge program shapes; their kfunc/BTF machinery is
worth paying for once, not as the first step into a program shape we have never emitted.

**Observability precondition carries over unchanged** ([[kernel-vs-kernel-differential]]):
a back-edge family only has teeth if the loop-carried state differs across iterations in
a way the convergence step must judge, AND a downstream access's safety depends on it.
A loop whose body leaves the deciding register unchanged is a tautology arm and must be
excluded, the same way the pure-tnum arm was excluded from `--gen-prune`.

## OI-13b — The idmap exhaustion path is NOT reachable from our shapes (derived, closed)

- **Status:** CLOSED by derivation 2026-09-05, recorded so the leg is not attempted again.
- `check_ids` fails verification when its table fills (states.c:349-353, "the map can be
  exhausted ... fail the verification by treating the states as not equivalent"), which
  looked like a testable boundary after 0047.
- **It is not reachable.** `BPF_ID_MAP_SIZE = (MAX_BPF_REG + MAX_BPF_STACK/BPF_REG_SIZE
  + MAX_STACK_ARG_SLOTS) * MAX_CALL_FRAMES = (11 + 64 + 7) * 16 = 1312`. The id-carrying
  slots a program can actually populate are registers plus spilled stack slots: 11 + 64 =
  75 per frame, so 1200 even at the maximum call depth of 16 — below the capacity by
  construction. The kernel's own comment says the same thing: exhaustion needs
  "referenced dynptrs [that] acquire intermediate references that do not live in either",
  a path our shapes do not build.
- **Consequence:** any exhaustion family built from linked scalars, spills or call depth
  would be vacuous. If this is ever revisited it has to come through referenced dynptrs,
  which is its own infrastructure step.

## OI-14 — A prune's exact_level is not observable from the log (measured bound, CLOSED)

- **Status:** CLOSED by measurement 2026-09-05 (devlog 0052), recorded so the attempt is
  not repeated.
- `regsafe` behaves very differently per `exact_level`, and two legs tried to test
  predictions of the form "context X selects level Y": 0051 (may_goto loop) and 0052
  (splitting before an iterator loop so the states meet at the next-call instruction,
  states.c:1333, which passes RANGE_WITHIN unconditionally).
- **Both predictions failed, and the second explains why they are untestable this way.**
  Reading :1333 to the end, `loop = true; goto hit;` — `hit` IS the prune path, so
  RANGE_WITHIN can merge states there. But the block is gated on `sl->state.branches`, and
  completed states fall through to the main comparison at :1405 with
  `loop ? RANGE_WITHIN : NOT_EXACT`. Both can merge the same pair, and **nothing in the
  log names which one fired.**
- **EXACT is the only level with an external marker**: reaching it prints "infinite loop
  detected at insn %d" (used as a marker in 0051).
- **What remains measurable** is whether a merge happened and what it cost — 0052 pins
  that with an exact 2:1 ratio of active-iterator states between the precise and imprecise
  arms. Aim future legs at merge/cost observables, not at level attribution.
- Reaching level attribution would need something the kernel does not currently print;
  the cheap version would be a debug patch to the local tree, which changes the thing
  under test and is its own decision.

## OI-12 — Agni's coverage window is unverified, and it is the reason we are leaving the ALU axis

- **Status:** OPEN, raised 2026-09-05 (devlog 0042).
- The strategic decision to stop growing the oracle on single-instruction ALU transfer
  functions rests partly on those operators already being SMT-checked by Agni (CAV'23)
  and the tnum soundness proofs (CGO'22). That claim is from memory: the papers exist,
  but WHICH kernel versions they covered, and whether anything equivalent runs in
  current CI, is unverified. A proof about one version says nothing about a later
  regression in the same operators.
- **Why it matters:** if the coverage window is old, the ALU axis is not as closed as
  the 0042 diagnosis assumes, and our existing families would be worth re-pointing at
  operators added or rewritten since. If it is current and continuous, the axis stays
  closed and the input-shape pivot is unambiguously right.
- **Cheap resolution:** read the Agni paper's evaluation section for the kernel range,
  and grep the tree for any in-tree equivalent. Secondary to the loop/iterator work —
  it refines a decision already made for independent reasons (reason (iii), the shape
  poverty of our input space, stands on its own).

## OI-9 — The targeted family covers one program SHAPE, not the input space

- **Status:** OPEN, **NARROWED 2026-09-01 by devlog 0026.** The 32<->64 half is done;
  what is listed below under "still not reached" is what remains. Register-register operands are now DONE (2026-09-01): the reg-reg leg (`--gen-rr`, 242 programs, all accepted) scores tnum_bounds_checked=**2453** — the largest denominator of any family (single-width 1497, mixed >1500) — with 0/2453 divergences and 0 parser blind-spots; pinned in `crates/pipeline/tests/register_register_calibration.rs`. reg-reg is a different axis from 32<->64 (reg32_checked=0). **Multi-branch/multi-merge now DONE (2026-09-03, devlog 0029):** the `--gen-mb` family (242 programs, all accepted, two sequential branches + two merge points) scores tnum_bounds_checked=**2050**, 0/2050 divergences, 0 parser blind-spots, reg32_checked=0; pinned in `crates/pipeline/tests/multi_branch_calibration.rs`. True *looping* (back-edges) is still open. **Pointer arithmetic now DONE — FIRST increment (2026-09-03, devlog 0030):** `--gen-ptr` (242 programs, map_value ptr += bounded scalar, then a STORE through it — the OOB-*write* decision) is a genuine accept/reject surface: **34 accept / 208 reject** (199 EACCES + 9 EINVAL diagnostics-path), tnum_bounds_checked=**1191** (on the scalar offset AND the pointer's own var_off), 0 divergences, **0 parser blind-spots** (robust first run); pinned in `crates/pipeline/tests/pointer_arith_calibration.rs`. This first increment is 1-byte store + map-value only. **Packet pointer now DONE — FIRST increment (2026-09-03, devlog 0031):** `--gen-pkt` (242 programs, SCHED_CLS; `data += bounded scalar`, then the program's own `if data+1 > data_end` compare, then a STORE) exercises the OTHER pointer kind — a bound the PROGRAM proves and the verifier statically tracks as `range` (`find_good_pkt_pointers`). **49 accept / 193 reject** (184 EACCES = the MAX_PACKET_OFF guard, + the same 9 EINVAL indices as map-value → a scalar-shaping property), tnum_bounds_checked=**1254**, 0 divergences, 0 blind-spots; the static range is visible in the log (`r=0` → `r=16` across the compare). Pinned in `crates/pipeline/tests/packet_pointer_calibration.rs`. Corrected along the way: NO runtime `data_end`-fixing mechanism is needed — the decision is load-time static. **Packet `data_end` compare-op sweep (T1-3) now DONE (2026-09-03, devlog 0032):** `--gen-pkt-cmp` (240 programs, SCHED_CLS; offset shaping pinned to `r4 &= 7` so the decision is a pure function of the range machinery; grid form{gt,ge,lt,le} × headroom M(1..5) × store-offset(0..3) × width{1,2,4}B) isolates `find_good_pkt_pointers`' two historically bug-prone axes. **128 accept / 112 reject**, per form gt=27/ge=37/lt=27/le=37; **operand-order symmetry holds exactly** (gt==lt, ge==le) and the **closed vs right-open boundary differs by EXACTLY one byte** — all 240 decisions match `accept ⟺ off+W ≤ range` with closed range=M, right-open range=M+1, 0 exceptions; tnum_bounds_checked=**720**, 0 divergences, 0 blind-spots. The verifier proves precisely what the program checked — no off-by-one on this kernel. Pinned in `crates/pipeline/tests/packet_compare_calibration.rs` (5 tests). **Negative-offset map-value smin path (T1-2) now DONE (2026-09-03, devlog 0033):** `--gen-ptr-neg` (120 programs; `r1 &= 15; r1 -= C` pushes smin to -C; form{raw = no guard, grd = `if r1 s<0 goto skip`} × C(10) × reach(6)) drives the LOWER bound — an OOB-*below* write. **60 accept / 60 reject**; raw=4/60 (every accept is C==0 — NO negative-capable store is accepted) and grd=56/60 (the signed guard rescues, so the verifier is not merely over-rejecting). Decision predicate matches all 120 with 0 exceptions; the "R0 min value is negative" check is exercised and enforced; tnum_bounds_checked=**438**, 0 divergences, 0 blind-spots. Verdict: the smin lower-bound check is enforced — no OOB-below accept on this kernel; pinned in `crates/pipeline/tests/pointer_neg_calibration.rs`. **32<->64 × pointer-offset, SOUNDNESS HALF (T1-1a) now DONE (2026-09-03, devlog 0034):** setup decided by measurement (the `--probe-t1` three-claim probe: naive 32-bit shaping zero-extends → reg32=0, the 0025 trap; 32-bit ALU on a pointer is prohibited outright → Option B dead; only the "hi" upper-unknown construction reaches the surface). `--gen-ptr-hi` (52 programs = hi{cons(2)×cmp(5)×K(4)}=40 + bnd{mask(3)×reach(4)}=12) is the **first family to lift reg32_checked off zero in a pointer context: reg32_checked=52, ENTIRELY from the hi arm (bnd=0)**. hi is all-reject (0/40 accept — mutual exclusivity: reg32>0 ⟺ upper-unknown ⟺ reject; a reviewer's K<value_size idea was ruled out pre-build as it yields the empty set in hi), rejecting at `adjust_ptr_min_max_vals` (verifier.c:14665, on the 64-bit `off_reg` bounds — the verifier structurally never consults u32/s32 for a pointer offset). bnd=8/12 accept (control: not over-rejecting). 0 divergences, 0 blind-spots; pinned in `crates/pipeline/tests/pointer_hi_calibration.rs`. **The DISCRIMINATING half (T1-1b) now DONE (2026-09-04, devlog 0035, `--gen-sync`):** the CVE-2020-8835 class desync guard. The 0034 prediction was CORRECTED — NO new oracle arm was needed: reviewing fix commit `f2d67fec0b43` (`__reg_bound_offset32`) showed the desync is EXACTLY the existing invariant B (`tnum32_bounds_inconsistent`, diff.rs) — the buggy code clamped the tnum low-32 to {0} while u32 compares set [0x200,0x400], so tnum32=[0,0] vs u32=[512,1024] are disjoint → B fires. So T1-1b was ONE job: a sync-fragile family reusing B, not a new invariant. `--gen-sync` (24 programs = cve{pair×win}=16 + shift{win×pol}=8; SYNC_WIN[0]=[0x200,0x400] the historical CVE window) drives the verifier into the narrowed 32↔64 state; the programs are trivially safe (`MOV r0,0; EXIT` after narrowing) so the surface is the register STATE, not the decision — **24 accept / 0 reject**. **reg32_checked=56 (cve=32, shift=24), finding_count=0**: B ran across all sync states (a regression WOULD fire) and stayed silent (the 32↔64 views are consistent = a working guard, no false positives). The sharp result: **all 56 checkable scalar-states are multi-block** (umin>>32≠umax>>32), so invariant C (single-block gated) is disabled throughout and B is the SOLE live guard — exactly why CVE-2020-8835 was historically catchable only by the tnum-vs-u32 redundancy (pre-5.7 had no separate u32 bounds). 0 divergences, 0 blind-spots; pinned in `crates/pipeline/tests/sync_calibration.rs` (6 tests). Bound: the consistency oracle catches DESYNC; a "consistent-but-wrong" corruption (both views wrong identically) is the deferred (b) differential-recompute territory — CVE-2020-8835 was a desync, so it is in B's scope. Still open from T1-1: wider map-value stores (2/4/8B) and the EINVAL sub-family; true looping (back-edges). **NEW ORACLE — runtime ground truth now DONE, FIRST increment (2026-09-04, devlog 0036, `--gen-rt`):** the first detector that does NOT trust the verifier log to be self-consistent, so it escapes the "consistent-but-wrong" blind spot every Ω (internal-consistency) leg shares. It proves the stronger Ω_rt: if the verifier accepted a program and proved `[lo,hi]` on the return register, the ACTUAL runtime return value is in `[lo,hi]`. Mechanism: program returns a verifier-bounded value derived from a fully attacker-controlled 32-bit map input; the harness EXECUTES it via `BPF_PROG_TEST_RUN` over a 12-value sweep (repeat=1 — deliberately low, see OI-11) and records the real `retval`; the diff stage compares each retval against the UNION of r0's proven scalar bounds (a conservative superset → a wide union can MISS a violation, never fabricate one). 37 programs (and/andadd/andlsh/cmp/alu32, all ≤32-bit), **runtime_checked=444, finding_count=0** — no runtime value escaped its bound. Oracle shown non-vacuous (a planted out-of-bound retval fires exactly once) and off-by-one-sound (retval==umax does not fire, umax+1 does); pinned in `crates/pipeline/tests/runtime_calibration.rs` (6 tests). This is a DIFFERENT attack on the same blind spot as the deferred differential-recompute (b): recompute re-derives the bound abstractly, runtime observes the actual value — runtime needs no second bounds implementation but only sees what the retval channel exposes. v2: wider observation channels (map/packet write, 64-bit), pointer-access OOB at runtime, and loop/iterator inputs. **v2 memory-safety axis now DONE, FIRST increment (2026-09-04, devlog 0037, `--gen-rtw`):** the runtime oracle extended from a returned SCALAR to the actual MEMORY-SAFETY property. Program shapes an attacker-input into a verifier-in-bounds offset and STORES a sentinel through a map-value pointer; the harness zeroes the target map, runs via BPF_PROG_TEST_RUN, reads it back, and locates the sentinel. An accepted store is CLAIMED in-bounds, so on a sound kernel the sentinel must land inside the value — `store_off=none` (absent) = the store escaped into kernel memory = an OOB write the verifier accepted. NO bound parsing needed — the direct memory-safety check. 9 programs (7 accept / 2 reject; rejects = over-wide masks, the verifier's static line), **runtime_writes_checked=84, finding_count=0** — every accepted store landed in-bounds. Oracle shown non-vacuous (a planted `store_off=none` fires runtime_oob_write exactly once); pinned in `crates/pipeline/tests/runtime_write_calibration.rs` (5 tests). Next: store width 2/4/8B (T2-2 — off+size<=value_size off-by-one), packet write, comparing store_off against the verifier's proven pointer-offset bound (pointer-tracking desync, not just "inside the value"), then loop/iterator inputs. **Store-WIDTH axis now DONE (2026-09-04, devlog 0038, `--gen-rtw2`):** the memory-safety oracle extended from a single sentinel byte to N-byte stores — the axis is store WIDTH, because the off-by-one a real bug hits lives in the `off + size <= value_size` check. The store writes `size` bytes of 0xFF (imm=-1); the harness re-zeroes the target map BEFORE EVERY run (the sole 0xFF source is the store, so a stale sentinel from a prior sweep step can never be miscounted), finds the FIRST 0xFF (`store_off`) and counts the consecutive run (`store_len`) against the intended width (`store_size`). The pipeline requires `store_len == store_size` for an accepted store; a short run (`store_len < store_size`) is a PARTIAL OOB write the single-byte family could not express (`map_or(true)` keeps the 1-byte fixture backward-compatible). Two shapes: **and.wN** (attacker offset `r6 &= MASK`, accept ⟺ MASK+N ≤ 64) and **bndc.wN** (const offset baked into the ST insn: off=64-N ends exactly at the value end = ACCEPT, off=65-N runs one byte past = REJECT — the exact off-by-one control). 20 programs (13 accept / 7 reject; rejects = the width overflows), **runtime_writes_checked=156, finding_count=0** — every accepted store wrote its full width inside the value; the tightest boundary is bndc.w8 (base off=56, 8-byte run ends exactly at 64). Non-vacuity shown TWO ways: a planted `store_off=none` AND a planted truncated run (`store_len<store_size`) each fire `runtime_oob_write` exactly once. Pinned in `crates/pipeline/tests/runtime_write2_calibration.rs` (7 tests). Next: packet write (SCHED_CLS), comparing store_off against the verifier's proven pointer-offset bound (pointer-tracking desync), then loop/iterator inputs. **Packet-write axis now DONE (2026-09-04, devlog 0039, `--gen-pktw`):** the runtime memory-safety oracle's PACKET leg — a store through a `PTR_TO_PACKET`, whose bound the verifier does NOT know statically (the program proves it with its own `data + M > data_end` compare, tracked as `range` by `find_good_pkt_pointers` — the historically densest packet-bounds bug region). Unlike the load-only packet families (`--gen-pkt`/`--gen-pkt-cmp`, which see only accept/reject and internal consistency), this leg EXECUTES each accepted program via `BPF_PROG_TEST_RUN` (SCHED_CLS/skb) and reads the packet back, catching a range that is internally consistent but WRONG. Runtime packet length = EXACTLY M (`data_size_in = PKTW_M = 32`, ≥ ETH_HLEN), so `data_end` lands at byte M and the accepted store executes; on a sound kernel every accepted store has `off + W ≤ M`, so all W sentinel bytes land in `[0, M)` and are copied back in `data_out` (`store_len == store_size`). A verifier that accepted `off + W = M + 1` (a range off-by-one) puts the store's last byte AT `data_end` — in skb tailroom, which `test_run` never copies back — so the run truncates or vanishes: the SHARED predicate (`check_runtime_write_safety`, reused UNCHANGED — output is byte-identical to `--gen-rtw2`) fires. **Critical design:** offset is CONSTANT (the compare proves M bytes, the store reaches off+W, and the verifier is the SOLE arbiter of `off+W ≤ M`); a variable shape whose compare re-checks the exact store region would be a TAUTOLOGY (runtime self-protects) and is excluded per oracle×input. Shape: W{1,2,4,8} × 3 arms (off 0 interior-accept, off=M−W boundary-accept, off=M−W+1 off-by-one reject). Measured — and matching, exactly, the counts DERIVED from `off+W ≤ M` before the run: 12 programs, **8 accept / 4 reject, runtime_writes_checked=8, finding_count=0, parser_unrecognized=0**. The accept boundary sits at `off = M−W` for every width (w1 o31 accept / o32 reject, w2 o30/o31, w4 o28/o29, w8 o24/o25 — the reject is always a single byte of overrun), and every accepted store wrote its FULL width inside `[0, M)`; the tightest is w8 at off 24, an 8-byte run ending exactly at byte 32 = `data_end`. Non-vacuity shown on THIS family's real capture two ways: a planted `store_off=none` and a planted truncated run each fire `runtime_oob_write` exactly once. Pinned in `crates/pipeline/tests/packet_write_calibration.rs` (7 tests), fixture `fixtures/volume/gen-pktw-12.log`. **Channel measured (2026-09-04, devlog 0040, `--probe-pktw`):** the one argued link in this leg — "test_run copies back only [0, skb->len), so an OOB store is unobservable" — was read out of the kernel source, never observed, because a sound verifier rejects every OOB store and so only the channel's POSITIVE half was ever exercised. The probe reaches the negative half with ACCEPTED programs by moving the WINDOW instead of the store: `bpf_skb_change_tail()` shrinks `skb->len` AFTER the store, leaving an already-written byte beyond the returned length. Measured, 4 arms, all accepted, retval=0: `win32` in=32 -> out_size=32 store_off=31; `win40` in=40 -> out_size=40 (the window TRACKS skb->len, it is not a constant); `trim.o19` store 19 + trim to 20 -> out_size=20 store_off=**19** (the last returned byte IS resolved); `trim.o20` store 20 + trim to 20 -> out_size=20 store_off=**none** (a byte physically written into the packet buffer at index == out_size is NOT returned). The two trim arms differ by ONE byte of store offset and nothing else, with opposite observability — the window edge is byte-precise and "absent" is positional, not an artefact of change_tail. `tail_zero=1` everywhere gives the other direction: the pre-zeroed output buffer stays zero past out_size, so nothing out there can be MISREAD as a sentinel. This closes the precondition for the store-location desync leg, which will assert "the verifier proved X, the store landed at Y". Pinned in `crates/pipeline/tests/packet_channel_calibration.rs` (7 tests), fixture `fixtures/volume/probe-pktw-4.log`. **STORE-LOCATION DESYNC — the hunt itself; now DONE (2026-09-05, devlog 0041, `--gen-loc`):** every runtime-write leg so far asks only whether the store stayed INSIDE the object. A verifier can pass that and still be wrong: an unsound abstract offset lands the store where its OWN state says it cannot, while still inside the object, so every earlier leg stays silent — the "consistent-but-wrong" class an internal-consistency oracle cannot see by construction. This leg compares the observed landing site against the verifier's own printed claim at the store (`17: R7=map_value(vs=64,umax=7,var_off=(0x0; 0x7))`): proven window = `ptr_off + insn_off + [umin, umax]`, narrowed by the var_off tnum. The tnum half is essential — `r6 &= 3; r6 <<= 2` proves {0,4,8,12}, so offset 6 is inside [0,12] and still impossible. **Parser gap closed on the way:** the pointer branch of `build_regstate` was flattening a pointer register to its type string and zeroing bounds/var_off/off, so the verifier's location claim never reached the pipeline at all; absence is now read as exactly zero FOR POINTERS (the verifier omits var_off when the variable part is genuinely zero) while the scalar branch must keep the opposite reading (absent = at the extreme). Provenance: the store's instruction, base register and immediate offset come from the GENERATOR (`STORE insn= reg= off= size=`), never from the verifier's own disassembly. Family = one program per abstract transfer function (and7, and31, orand, addc, subc, lsh2, lsh3, rsh, mul, xor, alu32, jmp = bounded by a BRANCH rather than a mask, shpair, compose, off4). **Measured: 15 programs all accepted (the decision is not the surface), `store_locations_checked=170` — a SEPARATE counter, because zero findings mean nothing unless the claim was actually read — `runtime_writes_checked=170`, `finding_count=0`, `parser_unrecognized=0`.** Every accepted store landed inside the set the verifier proved for it, confirmed independently by hand-derivation from the quoted log lines; the tnum half is non-vacuous (lsh2 hit exactly {0,4,8,12}, compose {4,8,12,16}, and nothing between). Teeth: (1) an offset inside the map value but outside the proven window fires `store_location_desync` while `runtime_oob_write` stays SILENT (that silence is exactly the blind spot being closed), (2) an offset inside the window but excluded by the tnum fires and is reported as a tnum violation, (3) an offset ignoring the store's own +4 fires on the off4 arm. Plus a non-vacuity guard that every proven window is narrow (`umax-umin <= 56`). **The capture corrected the pre-run derivation in two places, both on the ORACLE side, and neither by lowering a bar.** (i) 180 → 170: `store_off = none` conflated "the store went out of bounds" with "the store never ran". Every earlier runtime-write family reaches its store unconditionally, so `none` could only mean the first; the `jmp` arm bounds the offset with a BRANCH, and 10 of the 12 sweep inputs skip the store entirely. The first capture reported them as 10 `runtime_oob_write` findings; hand-derivation cleared the kernel and located the fault here. The fix disambiguates at the SOURCE — the program returns a distinct value on the storing path, the harness reports it as `executed=`, and a run that never stored is not judged — so 170 is a derived count (180 sweep runs minus the 10 that provably never stored), and the teeth are untouched: an unconditional-store family emits no witness and keeps the original reading, while `executed=1` with an absent sentinel is still an OOB write. A fourth tooth pins that discrimination directly. (ii) The parser gap fix had itself introduced a bug: it applied "absence = exactly zero" to a pointer's BOUNDS as well as its `var_off`. That rule holds only for `var_off`; a bound is omitted when it sits at its EXTREME (log.c), the same convention the scalar branch uses. Reading the absent `umax` in `map_value(...,umin=0xfffffffffffffff0,var_off=(0xfffffffffffffff0; 0xf))` as 0 manufactured an inverted unsigned range and fired `unsigned_bounds_inverted` six times on a perfectly consistent pointer state — caught by `pointer_neg_calibration` in the workspace suite before 0041 was committed, which is exactly what the golden-fixture guardrail exists for. Pinned in `crates/pipeline/tests/store_location_calibration.rs` (9 tests), fixture `fixtures/volume/gen-loc-15.log`, runner `scripts/run-loc.sh`; workspace suite 186 green. First increment pins the closed `>` idiom; the compare-form sweep (`>=` right-open, operand-order symmetry) is the natural follow-up, as `--gen-pkt` → `--gen-pkt-cmp` did.
- **Raised:** 2026-09-01 (devlog 0025)
- **Closed half (0026):** mixed-width programs now exist — four sub-families, 396
  programs (`mix#64-32`, `mix#32-64`, `mix#movsx*`, `mix#hi`), and the 32<->64
  denominator went from **0 to 353** on the real tree. Measured along the way: the
  obvious version of this (just interleaving widths) scored only **4** on bpf-next,
  because its deduction reconciles the two views almost perfectly whenever the value
  fits in one 2^32 block — and a ctx `u32` load always does. What actually reaches
  the region is `mix#hi`: shift the unknown bits into the UPPER half, then narrow only
  the lower one. Yield is still only ~18% of registers that print a 32-bit view.
- **Still not reached:** **looping** control flow (back-edges), `BPF_LD_IMM64`
  64-bit constants, the **stack** pointer, the DISCRIMINATING 32<->64 × pointer-offset
  test (T1-1b — the CVE-2020-8835-class sync arm, needs a new 32↔64-sync oracle leg;
  T1-1a soundness half DONE 2026-09-03), and the map-value family's WIDER store surface
  (2/4/8-byte stores — DONE 2026-09-04 as T2-2, devlog 0038, `--gen-rtw2`: 0/156, both
  the absent-store and truncated-run teeth fire). (reg-reg
  DONE 2026-09-01; multi-branch DONE 2026-09-03; map-value pointer AND packet pointer
  FIRST increments DONE 2026-09-03; packet `data_end` compare-op sweep — jgt/jge/jlt/jle
  → `range_right_open` — DONE 2026-09-03 as T1-3, devlog 0032: symmetric, one-byte-exact,
  0/720 divergence; map-value negative offset / smin lower-bound — DONE 2026-09-03 as
  T1-2, devlog 0033: enforced, no OOB-below accept, 0/438 divergence.)
- **What:** `diffharness --gen` enumerates `11 alu x 11 compare x {64,32}-bit` = 242
  programs, and that cross-product IS covered. But every one of them is the same
  8-instruction skeleton: one shaping op, one branch, one op per path, immediate
  operands only.
- **What it therefore does NOT reach:** register-to-register ALU (the immediate
  forms take a different verifier path from the register forms), multi-branch and
  looping control flow, pointer arithmetic, sign-extension moves (`movsx`), 64-bit
  immediates, and — most importantly — **32-bit and 64-bit operations mixed inside
  one program**. Each generated program is purely one width, so the reconciliation
  between `u32_min/u32_max` and the 64-bit bounds is exercised only across programs,
  never within one.
- **Why it matters:** "0 findings out of 1497 checks" is a real result, but it is a
  result about ONE program shape. Reading it as "the verifier's range tracking is
  sound" would be exactly the over-reading this file exists to prevent.
- **Next increment (highest value first):** the packet `data_end` **compare-operator
  sweep** (jgt/jge/jlt/jle → the `range_right_open` off-by-one edge, the kernel's own
  densest packet-bounds bug region), then wider stores (2/4/8-byte) on both pointer
  families, the shared 9-EINVAL signed-compare sub-family, then looping (back-edges —
  a separate leg, needs a provably-bounded counter). (scalar imm, reg-reg, mixed-width,
  `movsx`, multi-branch, map-value pointer, packet pointer: all first increments done.)

---

## OI-10 — The capture transport is shared with the kernel, and the repair is a mitigation

- **Opened:** 2026-09-01 (devlog 0027).
- **What:** the harness and syzreplay both capture their output over the VM's serial
  console (`console=ttyS0`), which the kernel also writes to. A printk can land in
  the MIDDLE of a verifier line. `repair_console_interleaving` now mends this and
  NOTES it, and three tests pin the behaviour against verbatim real captures.
- **Why this stays open:** the repair rests on an ASSUMPTION about how the
  interleaving looks — that the printk carries its own newline and the original
  line's remainder resumes on the next one. Both shapes observed so far obey it. A
  printk emitted without a trailing newline, or two CPUs interleaving into the same
  line, would not, and the repair would then mis-join rather than mend. It is a
  mitigation for a lossy transport, not a guarantee.
- **The real fix** is to stop sharing the transport: give the harness its own
  channel (a dedicated virtio-serial port, or write the output to a file inside the
  rootfs and pull it off the image afterwards) so kernel messages cannot reach it at
  all. Then the repair becomes a belt-and-braces check instead of a load-bearing one.
- **Measured impact so far (why this is not urgent):** across seven committed
  captures there are 7 interleavings; 6 are whole console lines (harmless) and 1 is
  a real mid-line splice (`syz-replay-184.log:5094`). CORE metrics over 885 records
  are BYTE-IDENTICAL before and after the fix — the one real splice happened to land
  on an indented line the parser already skips. Past results stand, but **by luck,
  not by design**, which is precisely why the transport should not stay shared.
- **Frequency scales with runs:** KVM (devlog 0027) makes runs cheap, so the absolute
  number of interleavings will grow even though the rate does not.

---

## OI-11 — `BPF_PROG_TEST_RUN` high-`repeat` trips the RCU-stall detector under KCOV+KASAN

- **Opened:** 2026-09-03 (devlog 0028), during the OI-1 clean-retest attempt.
- **Status:** OPEN (contained, not a target bug). Pipeline-side containment applied;
  the "is it a real DoS" question is left open deliberately.
- **What:** with `enable_syscalls: ["bpf*"]`, syzkaller reaches
  `bpf$BPF_PROG_TEST_RUN` and issues it with a large `repeat`. On our KCOV+KASAN
  kernel every basic block is instrumented (`__sanitizer_cov_trace_pc`), so the
  program-execution loop (`bpf_test_timer_continue`, `net/bpf/test_run.c:83`, via
  `bpf_test_run` / `bpf_prog_test_run_skb`, `kernel/bpf/syscall.c:4804`) runs long
  enough to cross the 21s RCU-stall threshold (`t=21002 jiffies`). syzkaller saves
  the coverage-raising program to the corpus and replays it on every VM, so ONE
  such program wedges all 8 VMs → an `INFO: rcu detected stall in sys_bpf` followed
  by a `SYZFAIL: repeatedly failed to execute the program` cascade; throughput fell
  ~720 → 70 exec/s. This is what poisoned the 0028 OI-1 retest (see below).
- **Why it is NOT a target bug, twice over:** (1) `PROG_TEST_RUN` is program
  EXECUTION, not verification — off the verifier surface the loop hunts; (2) the
  stall is a well-known KCOV+KASAN instrumentation artifact — the loop reschedules
  cooperatively, so it is a soft "stall", not a hang, and vanishes on a
  non-instrumented kernel.
- **Containment (devlog 0028):** `disable_syscalls: [bpf$BPF_PROG_TEST_RUN,
  bpf$BPF_PROG_TEST_RUN_LIVE, bpf$auto_BPF_PROG_TEST_RUN]` in
  `scripts/gen-syz-config.sh`. This AIMS the input budget at the verifier
  (`oracle × input` rule: aim, don't just enlarge) rather than merely enlarging it.
  A first `disable_syscalls: ["bpf$*TEST_RUN*"]` glob was rejected
  (`[FATAL] unknown disabled syscall`) — syzkaller wants recognized names, so the
  three exact variants are listed.
- **Left open on purpose:** whether an *uninstrumented* kernel also lets a crafted
  `repeat`/program make `PROG_TEST_RUN` run unreasonably long (a genuine local DoS)
  is a separate question this containment does NOT answer — it only removes the
  artifact from the verifier hunt. Not chased now; not the target class.

---
## OI-12 — syzkaller reproduction-starvation on executor/infra failures under nested KVM

- **Opened:** 2026-09-03 (devlog 0028), during the OI-1 powered retest.
- **Status:** OPEN. Containment applied (ignore the infra-failure title so it is not
  reproduced); efficacy PARTIAL (measured): it stops the `repeatedly failed` reproduction loop
  (0 afterward), but smoke4 showed reproduction just shifts to `lost connection` and
  the underlying VM-death rate persists (16 lost-connections in 6 min, throughput
  851→79 exec/s). The root cause is environment-level, below any single ignore.
- **What:** after F1 and the PROG_TEST_RUN stall (OI-11) were contained, a 20-min KVM
  campaign was healthy for ~2 min (~700 exec/s, peak 988) then **progressively
  degraded** (700→260→120→7 exec/s) and sat dead for its final ~10 min. No int3,
  **no rcu stall, no kernel crash report** was saved (b83ebc/9deb carry no
  OOM/hung-task/lockup signature; host memory stayed at 18 GB free). The manager log
  shows the trigger: at 04:24:56 syzkaller `start reproducing 'SYZFAIL: repeatedly
  failed to execute the program'`, and throughput fell immediately after. syzkaller
  dedicates VMs to REPRODUCING an executor/infra failure that is not a reproducible
  kernel bug; those VMs leave the fuzzing pool, the remaining VMs fail more, more
  reproduction is queued → a starvation cascade (47 `repeatedly failed` over the run).
  Same shape as F1's reproduction churn, one layer down.
- **Why "repeatedly failed to execute" is infra, not a kernel bug:** it is syz-executor
  in the guest failing to run programs, not a verifier/kernel fault. It never produces
  a symbolized crash; it is `[suppressed]` for SAVING but was still being REPRODUCED.
- **Containment (devlog 0028):** add `"SYZFAIL: repeatedly failed to execute the
  program"` to `ignores` so it is never reproduced (reproduction, not saving, is what
  starved the pool). Deliberately NOT ignoring `"lost connection to test machine"` —
  that can signal a real kernel hang and must stay visible; int3 is symbolized
  separately and is unaffected by these ignores.
- **The deeper open question:** WHY do executor failures accumulate over ~10 min at
  all? Leading hypothesis: nested-virt (WSL2→KVM→QEMU) VM instability under sustained
  8-VM load, and/or slow guest resource accumulation under KASAN in 2 GB guests. The
  ignore removes the *starvation amplifier*; it does not prove the underlying failure
  rate is acceptable. Cheap next probes (not yet run): raise `VMMEM` 2048→4096; lower
  `VMCOUNT` 8→4 to reduce nested-virt contention; enable periodic VM reboots.
- **Impact on OI-1:** every KVM campaign so far self-crashes before a single
  CLEAN run clears the pre-registered 150k-exec bar; int3 has NOT recurred across
  ~0.5M cumulative execs (suggestive of the TCG-artifact hypothesis) but no run met
  the clean-powered criterion, so OI-1 stays OPEN.

---

## Standing rule — a detector leg without a denominator is not measurable

- **Established:** 2026-09-01 (devlog 0025), the hard way.
- Sources 2 and 3 had reported denominators since 0022/0016. The **intrinsic leg
  never did**, and that hid the single most important fact about the corpus: across
  279 blocks of committed syzkaller volume the capture contains **zero** `var_off=`
  and **zero** `umin=`, so that leg had literally nothing to examine. Its
  "0 divergences" looked identical to the other legs' "0 out of 101" while being
  "0 out of 0".
- **The rule:** every leg reports how many times it was actually GIVEN something to
  check, and the denominator must exclude comparisons that cannot fail (see
  `diff::tnum_bounds_checkable` — a constant's tnum and bounds come from the same
  parsed token, so comparing them is a tautology and must not be counted).
- **Applies to source 1** when its pilot lands: no leg ships without its denominator.

---

## Coverage note — source 2's ceiling, MEASURED (corrected 2026-09-01)

Source 2 now encodes **13** documented claims (12 checked + 1 superseded). Unlike
`bpf_func_proto` contracts, these cannot be auto-extracted: they are assertions
embedded in prose, so each new case means finding another sentence the document
states OUTRIGHT.

**The earlier "a few dozen high-value invariants" target was wrong and is corrected
here.** It was an estimate, never a measurement. Measured (V14, devlog 0024): the
prose vein holds 7 candidate claims, 3 of them encoded, so ~4 remain; the message
vein holds 11 examples and **all 11 are now encoded**. The document's real ceiling is
therefore about **17 cases**, not "a few dozen" — and past that, growth in source 2
requires the *document itself* to grow, which is outside this project's control.

---

## OI-15 — The pruning differential is structurally blind to a prune the BASELINE already takes

- **Opened:** 2026-09-08 (devlog 0092), by building the detector's first positive control.
- **Status:** OPEN. The limit is measured and understood; no same-kernel detector exists for
  the class it excludes.
- **What was measured.** `2f2ec8e7730e` changes nothing but `check_scalar_ids()` — sixteen
  lines, no value-domain effect — so the buggy kernel's ONLY difference is a prune it should
  not take. `--probe-idbase` reproduces it: the trigger is accepted on `2f2ec8e7730e~1` and
  rejected on the fix and on tip, while the one-register control is accepted everywhere.
  On the buggy kernel `check_prune_differential` ran with a live denominator
  (`base_states=2` → `freq_states=8`, so the flag demonstrably widened the state space) and
  reported **nothing**.
- **Why, and it is structural rather than a defect.** `BPF_F_TEST_STATE_FREQ` only makes
  pruning MORE aggressive. The soundness direction the check reports is
  `freq ACCEPT && base REJECT` — the extra checkpoints revealing a prune that was not there.
  A bug where the default checkpointing *already* takes the unsound prune produces the same
  accepting verdict on both sides of the flag, and no flag differential can see it.
- **Consequence for the numbers already reported.** The 43,379 (later 138,912) prune pairs
  with zero flips are evidence about the DETECTOR's reach, not about the corpus. They must
  not be quoted as coverage of unsound pruning.
- **What would close it.** A same-kernel reference for the pruning DECISION. 0088 measured
  that the decision is not auditable from the log — the prune record carries neither state,
  and the log cannot express `range_within`'s domain (arc containment on `cnum{base,size}`
  against eight printed projections). So closing this needs either a debug patch to the tree
  under test (which changes the thing under test, and is its own decision) or an oracle whose
  reference is something other than the log. The liveness GATE (OI-16) is the part of this
  that turned out to be auditable.

---

## OI-16 — `bpflive.h` refuses subprogram calls, and that is 334 of 896 corpus programs

- **Opened:** 2026-09-08 (devlog 0088/0095).
- **Status:** OPEN, bounded, with a measured cost.
- The liveness gate's independent model covers single-frame programs. A `BPF_PSEUDO_CALL`
  makes the whole program `UNSUPPORTED` — deliberately, because the finding direction
  (model LIVE / kernel DEAD) is also the direction a coarser analysis produces, so an
  approximated interprocedural liveness would manufacture findings out of the model's own
  gaps.
- **The cost is measured**: on `--gen-comp` the model handles 562 of 896 programs, and every
  one of the 334 refusals is the subprogram call. The fuzz grammar emits none, so
  `liveunsup=0` there — but that changes the moment a call gene is added.
- **What would close it.** Interprocedural liveness: a call's use-set from the callee's live-in,
  its def-set from the callee's clobbers, and the return edge. This is ordinary dataflow, not
  research — but it must be calibrated before it judges, the same way the intraprocedural
  model was calibrated against the kernel's own `compute_live_registers.c` selftests (which
  found three defects in it that our own corpus could never have surfaced).

---

## OI-17 — A verifier-accepted program that CRASHES the kernel has no pipeline channel

- **Opened:** 2026-09-08 (devlog 0093).
- **Status:** OPEN. The evidence is captured; the pipeline cannot consume it.
- **What happened.** Calibration pair twelve (`bc308be380c1`) produced the strongest evidence
  this instrument has: on the buggy kernel the verifier ACCEPTS the program and the kernel
  page-faults running it — `Oops: 0002` (a write fault) at `RIP: bpf_prog_...` inside the
  JITed code, reached through `bpf_test_run`.
- **And the oracle it was built for cannot report it.** `check_runtime_write_safety` reports a
  sentinel that never arrives; the observation requires surviving the store, and with a 4 GB
  divergence the store is fatal by construction. For this class **the detector is the crash**.
- **Half-closed.** `run-harness-vm.sh` now recognises an oops instead of losing the run as
  "markers not found": it saves the serial to `<out>-crash-serial.log`, prints the BUG and RIP
  lines, flags the case where a `RESULT decision=accept` preceded the crash, and exits 2.
- **What remains.** The pipeline has no record kind for it, so a crash is evidence a human
  reads rather than a finding the oracles count. A crash channel with its own denominator —
  "accepted programs that were run" — would make it countable. Note the serial interleaves
  harness stdout with printk character by character, so parsing it needs care.

---

## OI-18 — A run that produces no warning leaves no record of which kernel produced it

- **Opened:** 2026-09-10 (F2 review leg).
- **Status:** OPEN. Closed by hand for F2; not closed structurally.
- **What happened.** F2's attribution rests on four runs of one program against four kernels.
  The two that violate the invariant stamp their own identity into the captured output, because
  the WARNING dump carries `Not tainted 7.2.0-g<sha>`. The two **negative controls do not** —
  no warning, no version line. Their provenance lives in the `KERNEL=` environment variable at
  run time and nowhere in the artifact.
- **Why it matters here specifically.** A calibration pair's whole value is that one side is
  silent. So the side that carries the least evidence of what it ran is, by construction, the
  side the design depends on. This is the same shape as the store-location freshness defect
  (devlog 0111, error eight): the artifact looked right and was about the wrong thing.
- **Cost of closing.** One line: have the harness print `uname -r` (or the `LINUX_VERSION_CODE`
  it was built against) in its own output, before the first program block. Then every captured
  log names its kernel whether or not anything fired.
- **Until then.** Any claim of the form "kernel A is silent on this program" must be re-run,
  not read from an archived log.

---

## OI-19 — `.lab/harness-serial.log` is a single shared file across concurrent runs

- **Opened:** 2026-09-10 (F2 review leg).
- **Status:** OPEN.
- **What happened.** `run-harness-vm.sh` writes the serial console to a fixed path,
  `$LAB/harness-serial.log`. During the F2 review the night driver was running hunt round 28 in
  its own VM; its serial output overwrote the review's mid-check, and a kernel-identity grep
  against that file returned nothing for a run that had in fact stamped its version.
- **What is at risk.** Only evidence that lives *solely* in the serial log. The extracted
  `$OUT` file is per-run and safe, and the crash path (OI-17) copies to `<out>-crash-serial.log`,
  which is also per-run. The exposure is the window between boot and extraction, and any manual
  inspection of `harness-serial.log` while a second run is live.
- **Cost of closing.** Derive the serial path from `$OUT` the way the crash log already does
  (`${OUT%.log}-serial.log`), so the serial is per-run like everything else it documents.
- **Related.** The default `SSHPORT=10022` is also fixed, so a second concurrent VM fails to
  boot with a host-forwarding error that `run-harness-vm.sh` reports as "markers not found" —
  an infrastructure collision wearing a harness failure's clothes. `SSHPORT=<other>` works.
