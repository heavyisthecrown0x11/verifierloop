#!/usr/bin/env bash
# QEMU launch — KVM-accelerated disposable VM (PRIMARY hunt path).
#
# The Ubuntu 22.04/WSL2 layer is ONLY host/orchestration. This boots a disposable
# VM running a SELF-BUILT bpf-next kernel. Requires /dev/kvm + nested virt (see
# config/wsl/wslconfig.note.md). For KVM-less hosts use launch-tcg.sh.
#
# Env: KERNEL, ROOTFS (required); MEM, SMP, SSHPORT, APPEND, EXTRA_ARGS (optional).
# Normally invoked via scripts/boot-vm.sh, which fills in .lab defaults.
set -euo pipefail

KERNEL="${KERNEL:?path to self-built bpf-next bzImage}"
ROOTFS="${ROOTFS:?path to disposable rootfs image}"
MEM="${MEM:-2048}"
SMP="${SMP:-2}"
SSHPORT="${SSHPORT:-10022}"

# panic=1 oops=panic: turn any oops/warn into a catchable panic (fuzzing policy).
# nokaslr: stable addresses for triage. init= may be overridden (boot-verify).
APPEND="${APPEND:-console=ttyS0 root=/dev/vda rw earlyprintk=serial panic=1 oops=panic nokaslr}"

exec qemu-system-x86_64 \
  -enable-kvm -cpu host \
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
