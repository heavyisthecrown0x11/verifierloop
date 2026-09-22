#!/usr/bin/env bash
# The exact equivalent of run-harness-vm.sh for f2probe. Installs to the shared rootfs under a
# SEPARATE name (/root/f2probe), so it doesn't touch the concurrent hunt run's diffharness.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB=$REPO_ROOT/.lab
ROOTFS=$LAB/images/rootfs.img
OUT="${1:?outfile}"
KERNEL="${KERNEL:?kernel}"
SERIAL="${OUT%.log}-serial.log"
TIMEOUT="${TIMEOUT:-300}"
BIN=$REPO_ROOT/harness/f2probe
MNT="$(mktemp -d)"
cleanup() { mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT
mount -o loop "$ROOTFS" "$MNT"
install -m755 "$BIN" "$MNT/root/f2probe"
cat > "$MNT/root/run-f2probe.sh" <<'EOS'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
echo "===F2-BEGIN==="
/root/f2probe
echo "===F2-END==="
poweroff -f 2>/dev/null || { echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger; }
EOS
chmod +x "$MNT/root/run-f2probe.sh"
sync; cleanup; trap - EXIT
ACCEL=kvm SSHPORT="${SSHPORT:-10122}" KERNEL="$KERNEL" ROOTFS="$ROOTFS" \
APPEND="console=ttyS0 root=/dev/vda rw panic=1 oops=panic init=/root/run-f2probe.sh" \
  timeout "$TIMEOUT" "$REPO_ROOT/scripts/boot-vm.sh" >"$SERIAL" 2>&1 || true
if grep -q "===F2-BEGIN===" "$SERIAL"; then
  sed -n '/===F2-BEGIN===/,/===F2-END===/p' "$SERIAL" | tr -d '\r' > "$OUT"
  echo "[f2] captured -> $OUT"
else
  echo "[f2] FAILED, serial: $SERIAL" >&2; tail -20 "$SERIAL" >&2; exit 1
fi
