# verifierloop

A differential-testing lab for the **Linux eBPF verifier**, and the artifact for the
paper ***Where a Test Oracle Reads From: Evidential independence as a design criterion
for differential testing*** (ISSTA submission).

The lab builds self-built `bpf-next` kernels, runs BPF programs under disposable VMs,
and compares what the verifier does against independent oracles. The paper's thesis
grew out of it: a differential oracle's blind-spot class is fixed not by how
independently its reference was *written* but by what its reference *reads*, and that
class can be measured before the oracle exists.

**Author:** Utku Erol, Independent Researcher — utkuerol71@gmail.com

**License:** GPL-2.0-only ([LICENSE](LICENSE)) — matches the Linux kernel; `patches/`
is kernel-derived. **Reproduction guide:** [ARTIFACT.md](ARTIFACT.md).

## Quick start (no kernel, no VM)

Most of the paper's evidence reproduces offline in minutes:

```bash
python3 scripts/subsume-check.py --self-test   # oracle B, 72 golden vectors -> failed=0
cargo test                                     # 392 tests, 0 failures
scripts/build-paper.sh                         # the paper PDF (needs TeX Live)
```

The classification study is committed text: `docs/heldout/` holds every
pre-registration and its results, and `git log --oneline -- docs/heldout` shows each
each `PRE-REGISTRATION` landing **before** its `RESULTS` — the
ordering is the evidence.

## The two oracles

The paper contrasts two oracles for the same verifier, differing in what they read —
visible in their type signatures:

| | reads | file |
|---|---|---|
| **A** — liveness gate | the emitted instruction stream (upstream of the verifier) | `harness/bpflive.h` |
| **B** — subsumption model | the abstract state the verifier itself wrote (downstream) | `scripts/subsume-check.py`, `harness/bpfsubs.h` |

B is an independent reimplementation of `states_equal`'s scalar arm, calibrated against
real defects and run at fuzz volume in-VM. It is *algorithmically* independent of the
verifier and *evidentially* entangled with it — the paper's central example.

## Findings

- **F1** (`docs/findings/F1-print_bpf_insn-oob/`) — a verbose-path OOB read in the
  disassembler; root-caused, upstream patch prepared.
- **F2** (`docs/findings/F2-sync-linked-regs-empty-range/`) — `sync_linked_regs()`
  drives a register to an empty range that no check covers; reproduces on the current
  tip, real but security-inert (measured, not assumed).

## Layout

```
crates/    Rust pipeline: parsers, invariants (Ω), 392 tests, calibration fixtures
harness/   guest-side C: diffharness, bpflive.h (A), bpfsubs.h + subsume-check.py (B), f2probe.c
scripts/   build/run drivers, subsume-check.py, prepare-artifact.sh
patches/   print-only kernel instrumentation, four kernel-era variants
docs/      findings/, heldout/ (the classification study), RUNBOOK
paper/     LaTeX (acmart/sigconf), build-paper.sh, OVERLEAF.md
```

## The lab loop

The hunt is a closed loop: **fuzz → observe → normalize → score → diff against ground
truth → hand a triaged batch to a human → repeat**. Two languages meet at a typed,
file-based JSON contract — Rust for orchestration and the loop runtime, Python for
scoring — with no shared process memory. Ground truth is not a formal model: it is
documentation, patch diffs, and classic logical invariants over the parsed verifier
state (tnum well-formedness, bound ordering, tnum/bounds consistency,
JIT↔interpreter equivalence).

A **confirmation-bias guardrail** is a first-class design constraint, not an
afterthought: the loop must not become a counterfactual-optimizing fuzzer that
generates input to confirm its own expectation. The guards — CORE metrics kept
independent of the counterfactual layer, an explicit "did the loop expect this?" flag
so bias is measured rather than hidden, and a human at every period boundary — are
stated in `crates/orchestrator/src/loop_runtime.rs` and must survive every change to
the scoring path.

## Full environment (kernels + VMs)

Tier-2 reproduction (calibration builds, the hunt, F2's control arms) needs an
`x86_64` host with QEMU/KVM, a `bpf-next` checkout under `.lab/bpf-next`, `gcc`, and
`pahole`. See [`docs/RUNBOOK.md`](docs/RUNBOOK.md) for the step-by-step. All heavy
artifacts live under `.lab/` (gitignored); `scripts/build-kernel.sh` takes
`SRC`/`OUT` so a second kernel at a fix's parent builds with the **same config**,
which is what makes a calibration pair meaningful.

## Scope

No external engine is integrated, and there is no theorem prover — the loop's ground
truth is documentation plus logical analysis, not a formal model.
