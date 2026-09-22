#!/usr/bin/env bash
# BTF/kfunc machinery probe (--probe-iter). Resolves bpf_iter_num_new/next/destroy out of
# the running kernel's vmlinux BTF and reports the ids, then loads three programs: a bare
# iterator loop, a masked accumulator with a store, and an unbounded accumulator with a
# store. Wanted: accept / accept / reject. The ids are printed because a WRONG id is not
# a load error — it is a silent call to a different function — and the BTF type walk that
# produces them desynchronises on any kind whose trailing size is mishandled.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-probe-iter.log"
HARNESS_ARGS=--probe-iter TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"
echo
grep "^CHANNEL" "$LOG"
