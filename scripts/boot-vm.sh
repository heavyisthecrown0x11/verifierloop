#!/usr/bin/env bash
# Boot a disposable VM running the self-built bpf-next kernel. Thin wrapper that
# fills in .lab defaults and dispatches to the KVM (primary) or TCG (fallback)
# QEMU launch template. Interactive serial console (Ctrl-a x to quit QEMU).
#
#   scripts/boot-vm.sh              # KVM
#   ACCEL=tcg scripts/boot-vm.sh    # TCG fallback
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
ACCEL="${ACCEL:-kvm}"

export KERNEL="${KERNEL:-$LAB/build/bzImage}"
export ROOTFS="${ROOTFS:-$LAB/images/rootfs.img}"

[ -f "$KERNEL" ] || { echo "[boot] no kernel at $KERNEL — run scripts/build-kernel.sh" >&2; exit 1; }
[ -f "$ROOTFS" ] || { echo "[boot] no rootfs at $ROOTFS — run scripts/create-rootfs.sh" >&2; exit 1; }

if [ "$ACCEL" = "kvm" ]; then
  [ -w /dev/kvm ] || { echo "[boot] /dev/kvm not writable — use ACCEL=tcg (see config/wsl/wslconfig.note.md)" >&2; exit 1; }
  echo "[boot] KVM: kernel=$KERNEL rootfs=$ROOTFS"
  exec "$REPO_ROOT/config/qemu/launch-kvm.sh"
else
  echo "[boot] TCG (no KVM): kernel=$KERNEL rootfs=$ROOTFS"
  exec "$REPO_ROOT/config/qemu/launch-tcg.sh"
fi
