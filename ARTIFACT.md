# Artifact — *Where a Test Oracle Reads From*

This repository is the artifact for the paper *Where a Test Oracle Reads From:
Evidential independence as a design criterion for differential testing*. It contains
the two oracles built for the Linux eBPF verifier, the subsumption model and its
calibration, the held-out classification study with its pre-registrations, and the
paper source.

The paper's own evidence includes **the git history**: several claims (the held-out
batches of §4.1, the flagship re-partition of §5.3) rest on classifications being
committed *before* the results that test them. The commit ordering and timestamps are
therefore part of the artifact — the history is preserved, never squashed. See
`scripts/prepare-artifact.sh`.

## Two reproduction tiers

Most claims are reproducible **without a kernel or VM** — the subsumption model, the
inter-rater study, the test suite, and the paper build all run offline against
captured logs. Only the calibration *builds* (compiling two kernels per pair) need the
full environment.

### Tier 1 — no kernel, no VM (minutes)

| Command | Reproduces |
|---|---|
| `python3 scripts/subsume-check.py --self-test` | Oracle B (subsumption model), 72 golden vectors, `failed=0` (§5.1) |
| `cargo test` | 392 tests, 0 failures: parsers, invariants, calibration fixtures, the C≡Python 8-counter equality (§5.2) |
| `scripts/build-paper.sh` | The paper PDF from source (needs TeX Live; see `paper/OVERLEAF.md`) |
| `python3 scripts/subsume-check.py <capture.log>` | Run B on any captured `PRUNEPAIR` log; `--era 2023` selects the H21-era arm (§4.1) |

**Inter-rater study (§4.5), fully offline.** Every rating is a committed text file:

- Held-out, κ = 0.71: `docs/heldout/interrater/` — `PACKET.md` (the blind rater's
  input), `RATER2.txt` (blind model rater), gold labels derived from the batch
  `RESULTS-*.md`.
- Flagship, κ = 0.86: `docs/heldout/flagship/` — `frame.txt` (the 57-commit mechanical
  frame), `PACKET.md`, `RATER1.txt` (sealed before RATER2, see git order), `RATER2.txt`,
  `RESULTS.md`.

The pre-registrations (`docs/heldout/**/PREREGISTRATION*.md`) were committed before the
matching `RESULTS*.md`; `git log --oneline -- docs/heldout` shows the order.

### Tier 2 — full environment (hours, per pair)

Needs: an `x86_64` host with QEMU/KVM, a `bpf-next` checkout under `.lab/bpf-next`,
`gcc`, `pahole` (dwarves) for BTF. See `docs/RUNBOOK.md`.

| Command | Reproduces |
|---|---|
| `scripts/fetch-kernel.sh` then `scripts/build-kernel.sh` | The lab kernel (BPF+JIT, KCOV, sanitizers, KVM guest) |
| `scripts/run-calibration.sh` | A calibration pair: two kernels from one config differing only in the fix (§5.2) |
| `scripts/run-f2probe-vm.sh` | The F2 finding and its three control arms on a chosen kernel (§5.4) |
| `scripts/run-fuzz.sh` | The coverage-guided hunt loop |

`SRC=<worktree> OUT=<bzImage> scripts/build-kernel.sh` builds a second tree at a fix's
parent with the **same config**, which is what makes a calibration pair meaningful.

## Where each paper claim lives

| Paper | Artifact |
|---|---|
| Oracle A (reads the instruction stream) | `harness/bpflive.h` — `bpflive_run(const bpf_insn*, int, result*)` |
| Oracle B (reads the state the verifier wrote) | `scripts/subsume-check.py` (reference), `harness/bpfsubs.h` (in-VM twin) |
| The 16 calibration pairs (Appendix B) | `docs/findings/`, `patches/prunepair-instrumentation*.patch` (four eras), `crates/pipeline/tests/fixtures/calibration/` |
| Held-out study, 29 cases, 4 batches (§4.1) | `docs/heldout/PREREGISTRATION-batch*.md`, `RESULTS-batch*.md`, `draw*.txt` |
| Flagship re-partition, 57 cases (§5.3) | `docs/heldout/flagship/` |
| The precision-flag gate / switch-vs-operand (§5.4) | `subsume-check.py:375`, mirrors `states.c` `!rold->precise && exact==NOT_EXACT` |
| F2 (`sync_linked_regs` empty range) | `docs/findings/F2-sync-linked-regs-empty-range/`, `harness/f2probe.c` |
| F1 (disasm OOB) | `docs/findings/F1-print_bpf_insn-oob/` — root-caused, upstream patch prepared |

## Layout

```
crates/       Rust pipeline: parsers, invariants (Ω), tests, calibration fixtures
harness/      guest-side C: diffharness, bpflive.h (A), bpfsubs.h/subsume-check (B), bpfclaim.h, f2probe.c
scripts/      build + run drivers, subsume-check.py, prepare-artifact.sh
patches/      print-only kernel instrumentation, four era variants
docs/         findings/, heldout/ (the classification study), RUNBOOK
paper/        LaTeX source (acmart/sigconf), build-paper.sh, OVERLEAF.md
```

## License

GPL-2.0-only (`LICENSE`). The repository includes kernel-derived instrumentation
(`patches/`) and guest programs that link the kernel UAPI; GPL-2.0 matches the Linux
kernel and keeps the whole artifact under one consistent, legally clean license.
