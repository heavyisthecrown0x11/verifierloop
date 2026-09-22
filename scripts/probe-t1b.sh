#!/usr/bin/env bash
# T1-1b oracle probe: build the harness, run the CVE-2020-8835-shaped programs in the
# VM, and measure per-program reg32_checked + finding_count with the pipeline.
#
# Wanted result (fixed kernel):
#   probe#cve8835  reg32_checked > 0   finding_count = 0
#   probe#shift    reg32_checked > 0   finding_count = 0
# i.e. the existing tnum32/reg32 invariants (0026, diff.rs) RUN on the desync-shaped
# state (so a CVE-2020-8835 regression would be caught) and are SILENT on this kernel.
#
# Run this outside auto mode (default permission mode) or in a fresh session, since
# auto mode's safety classifier may block the build/VM steps mid-session.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LOG="$REPO_ROOT/.lab/harness-probe-t1b.log"

echo "[probe-t1b] building harness + running --probe-t1b in the VM ..."
HARNESS_ARGS=--probe-t1b TIMEOUT=120 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== decisions ==="
grep -E "===PROG probe|^RESULT" "$LOG"

echo
echo "=== per-program reg32_checked + finding_count (the two numbers) ==="
PROBE_LOG="$LOG" cargo test -p pipeline --test probe_t1b_reg32 -- --ignored --nocapture 2>&1 \
  | grep -E "PROBE-T1B|test result"
