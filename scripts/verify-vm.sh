#!/usr/bin/env bash
# Automated boot verification: boot the disposable VM with init=/root/verify.sh
# (bypassing systemd), which prints markers and powers off. We capture the serial
# log, then assert the kernel reached userspace with BTF + bpffs + kcov available.
# Tries KVM first; falls back to TCG if KVM init fails.
#
#   scripts/verify-vm.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
export KERNEL="${KERNEL:-$LAB/build/bzImage}"
export ROOTFS="${ROOTFS:-$LAB/images/rootfs.img}"
export APPEND="console=ttyS0 root=/dev/vda rw panic=1 oops=panic init=/root/verify.sh"
TIMEOUT="${TIMEOUT:-120}"
LOG="$LAB/verify-serial.log"

[ -f "$KERNEL" ] || { echo "[verify] no kernel at $KERNEL" >&2; exit 1; }
[ -f "$ROOTFS" ] || { echo "[verify] no rootfs at $ROOTFS" >&2; exit 1; }

boot() {
  local accel="$1"
  echo "[verify] booting ($accel), timeout ${TIMEOUT}s ..."
  # -no-reboot + panic=1 means poweroff/panic ends QEMU; timeout is a backstop.
  ACCEL="$accel" timeout "$TIMEOUT" "$REPO_ROOT/scripts/boot-vm.sh" >"$LOG" 2>&1 || true
}

assess() {
  if grep -q "VERIFIERLOOP-VM-OK" "$LOG"; then
    echo "[verify] reached userspace:"
    grep -E "VERIFIERLOOP-VM-OK|Linux version|BTF|bpffs|kcov|VERIFIERLOOP-VM-DONE" "$LOG" | sed 's/^/    /'
    grep -q "BTF present" "$LOG"    && echo "[verify] PASS: BTF"    || echo "[verify] WARN: BTF not confirmed"
    grep -q "bpffs mounted" "$LOG"  && echo "[verify] PASS: bpffs"  || echo "[verify] WARN: bpffs not confirmed"
    grep -q "kcov present" "$LOG"   && echo "[verify] PASS: kcov"   || echo "[verify] WARN: kcov not confirmed"
    return 0
  fi
  return 1
}

boot kvm
if assess; then echo "[verify] OK (KVM). serial log: $LOG"; exit 0; fi

echo "[verify] KVM boot did not reach userspace; trying TCG fallback ..."
boot tcg
if assess; then echo "[verify] OK (TCG). serial log: $LOG"; exit 0; fi

echo "[verify] FAILED to reach userspace under KVM or TCG. Last 40 lines:" >&2
tail -40 "$LOG" >&2
exit 1
