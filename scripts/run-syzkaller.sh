#!/usr/bin/env bash
# Run the syzkaller manager (the PRIMARY fuzzer) against the self-built kernel.
# Generates the config on first use. Pass a duration to run a bounded campaign
# (e.g. for a throughput benchmark), otherwise runs until interrupted.
#
#   scripts/run-syzkaller.sh              # run until Ctrl-C
#   DURATION=300 scripts/run-syzkaller.sh # run ~5 min then stop (benchmark)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
SYZ="$LAB/syzkaller"
CFG="${CFG:-$SYZ/manager.cfg}"

[ -x "$SYZ/bin/syz-manager" ] || { echo "[run] build syzkaller first: scripts/setup-syzkaller.sh" >&2; exit 1; }
[ -f "$LAB/build/bzImage" ]   || { echo "[run] no kernel: scripts/build-kernel.sh" >&2; exit 1; }
[ -f "$LAB/images/rootfs.img" ] || { echo "[run] no rootfs: scripts/create-rootfs.sh" >&2; exit 1; }
[ -f "$CFG" ] || "$REPO_ROOT/scripts/gen-syz-config.sh"

echo "[run] syz-manager -config $CFG"
if [ -n "${DURATION:-}" ]; then
  echo "[run] bounded campaign: ${DURATION}s"
  exec timeout --signal=INT "${DURATION}" "$SYZ/bin/syz-manager" -config "$CFG"
else
  exec "$SYZ/bin/syz-manager" -config "$CFG"
fi
