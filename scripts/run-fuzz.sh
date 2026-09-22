#!/usr/bin/env bash
# Coverage-guided continuous fuzzing of the verifier.
#
# The strategic position this occupies: after seven calibration pairs the ORACLE is no
# longer the bottleneck — volume and aim are. KCOV gives a real, saturating signal across a
# BPF_PROG_LOAD (measured in 0077), so a program reaching verifier code nothing has reached
# before is kept and perturbed.
#
# What is mutated is the GENOME, not the bytecode: byte-level mutation produces
# mostly-malformed programs the verifier discards before any oracle sees them. Perturbing
# genes keeps every mutant inside the typed grammar.
#
# Every program is still judged by the oracle whose reference is NOT the verifier — bpfref
# computes what the body must return and the kernel's answer is compared against it.
# Coverage decides only what is KEPT.
#
# The reference interpreter is calibrated FIRST; an uncalibrated instrument would turn every
# program into a possible false finding.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
SECONDS_BUDGET="${SECONDS_BUDGET:-600}"
LOG="${1:-$REPO_ROOT/.lab/fuzz.log}"

scripts/probe-ref.sh >/dev/null || { echo "reference interpreter NOT calibrated — stopping" >&2; exit 1; }
echo "[fuzz] reference calibrated; budget ${SECONDS_BUDGET}s"
# THE SLACK MUST SCALE WITH THE BUDGET. The guest clock runs ~8% slower than the host's, so
# a fixed 180s margin is proportionally thinner the longer the run: a 1800s budget finished
# with ~36s to spare, and a 3600s one was killed at in-guest elapsed=3486s with the whole
# hour's result lost — the log is only extracted after the end marker, so a kill this close
# to the finish line loses everything. 20% plus the old floor.
HARNESS_ARGS="--fuzz $SECONDS_BUDGET" \
  TIMEOUT=$((SECONDS_BUDGET + SECONDS_BUDGET / 5 + 180)) \
  scripts/run-harness-vm.sh "$LOG" >/dev/null

grep -m1 '^FUZZ start' "$LOG" || true
grep '^FUZZ abort' "$LOG" && { echo "[fuzz] aborted — see the reason above" >&2; exit 1; }
grep '^FUZZ done' "$LOG" | sed 's/^/  /'
echo "  corpus entries kept: $(grep -c '^CORPUS' "$LOG")"
n=$(grep -c '^FINDING' "$LOG" || true)
echo "  findings: $n"
if [ "$n" != "0" ]; then
  echo "  TRIAGE ORDER: the emitted bytes, then bpfref, then the kernel." >&2
  grep '^FINDING' "$LOG" | head -20 >&2
  exit 1
fi
