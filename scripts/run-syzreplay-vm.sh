#!/usr/bin/env bash
# Replay the syzkaller corpus INSIDE the disposable bpf-next VM and capture the
# real verifier logs in the harness native format.
#
# This is the syzkaller-DRIVEN volume path: the programs are syzkaller's (from its
# coverage-guided corpus), rendered to C by syz-prog2c and linked against our shim,
# which injects log_level=2 so the verifier's decision + register-state is captured.
# Same VM pattern as run-harness-vm.sh (init= + serial console, -snapshot).
#
#   scripts/run-syzreplay-vm.sh [OUTFILE]     # default .lab/syzreplay-out.log
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
ROOTFS="${ROOTFS:-$LAB/images/rootfs.img}"
OUT="${1:-$LAB/syzreplay-out.log}"
SERIAL="$LAB/syzreplay-serial.log"
TIMEOUT="${TIMEOUT:-600}"
PER_PROG_TIMEOUT="${PER_PROG_TIMEOUT:-10}"
BINDIR="$LAB/syzreplay/bin"

# 1. build replay binaries from the corpus
"$REPO_ROOT/scripts/syz-replay-build.sh" "$LAB/syzreplay"
count=$(ls "$BINDIR" 2>/dev/null | wc -l)
[ "$count" -gt 0 ] || { echo "[syzreplay] no replay binaries built" >&2; exit 1; }
[ -f "$ROOTFS" ]   || { echo "[syzreplay] no rootfs at $ROOTFS" >&2; exit 1; }

# 2. inject binaries + runner into the rootfs
MNT="$(mktemp -d)"
cleanup() { mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT
mount -o loop "$ROOTFS" "$MNT"
rm -rf "$MNT/root/syzreplay"; mkdir -p "$MNT/root/syzreplay"
cp "$BINDIR"/* "$MNT/root/syzreplay/"
chmod +x "$MNT/root/syzreplay"/*
cat > "$MNT/root/run-syzreplay.sh" <<EOS
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
echo "===HARNESS-BEGIN==="
for b in /root/syzreplay/*; do
  timeout ${PER_PROG_TIMEOUT} "\$b" 2>/dev/null
done
echo "===HARNESS-END==="
poweroff -f 2>/dev/null || { echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger; }
EOS
chmod +x "$MNT/root/run-syzreplay.sh"
sync
cleanup
trap - EXIT

# 3. boot (TCG), init = replay runner, capture serial
echo "[syzreplay] booting (tcg) with $count replay binaries, timeout ${TIMEOUT}s ..."
ACCEL=tcg \
APPEND="console=ttyS0 root=/dev/vda rw panic=1 oops=panic init=/root/run-syzreplay.sh" \
  timeout "$TIMEOUT" "$REPO_ROOT/scripts/boot-vm.sh" >"$SERIAL" 2>&1 || true

# 4. extract the native output between the markers
if grep -q "===HARNESS-BEGIN===" "$SERIAL" && grep -q "===HARNESS-END===" "$SERIAL"; then
  sed -n '/===HARNESS-BEGIN===/,/===HARNESS-END===/p' "$SERIAL" | sed '1d;$d' | tr -d '\r' > "$OUT"
  echo "[syzreplay] captured $(grep -c '===PROG' "$OUT" || echo 0) program block(s) -> $OUT"
else
  echo "[syzreplay] FAILED: markers not found. Last 30 serial lines:" >&2
  tail -30 "$SERIAL" >&2
  exit 1
fi
