#!/usr/bin/env bash
# QEMU launch — TCG software-emulation FALLBACK (no KVM).
#
# SLOWER than KVM. Use ONLY for manual PoC / differential runs on hosts without
# /dev/kvm, never as the main hunting throughput path.
#
# Env: KERNEL, ROOTFS (required); MEM, SMP, SSHPORT, APPEND, EXTRA_ARGS (optional).
# Normally invoked via scripts/boot-vm.sh (ACCEL=tcg), which fills in .lab defaults.
set -euo pipefail

KERNEL="${KERNEL:?path to self-built bpf-next bzImage}"
ROOTFS="${ROOTFS:?path to disposable rootfs image}"
MEM="${MEM:-2048}"
SMP="${SMP:-2}"
SSHPORT="${SSHPORT:-10022}"
APPEND="${APPEND:-console=ttyS0 root=/dev/vda rw earlyprintk=serial panic=1 oops=panic nokaslr}"

# No -enable-kvm; -cpu is an emulated model (TCG).
exec qemu-system-x86_64 \
  -accel tcg \
  -cpu qemu64 \
  -m "${MEM}" -smp "${SMP}" \
  -kernel "${KERNEL}" \
  -drive file="${ROOTFS}",format=raw,if=virtio \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:"${SSHPORT}"-:22 \
  -device virtio-net-pci,netdev=net0 \
  -append "${APPEND}" \
  -no-reboot \
  -nographic \
  -snapshot \
  ${EXTRA_ARGS:-}
