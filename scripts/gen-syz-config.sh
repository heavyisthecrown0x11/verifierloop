#!/usr/bin/env bash
# Generate a real syz-manager config from the lab layout (replaces the
# config/syzkaller/*.placeholder). QEMU vm type, focused on the eBPF verifier:
# enable_syscalls is restricted to bpf* (BPF_PROG_LOAD is where the verifier runs);
# disable_syscalls drops bpf$*TEST_RUN* — program EXECUTION, not verification, and a
# known KCOV+KASAN artifact: a high `repeat` PROG_TEST_RUN loops the program past the
# 21s RCU-stall threshold (net/bpf/test_run.c bpf_test_timer_continue), wedging VMs.
# Off-target for the verifier hunt AND a throughput poison. See devlog 0028 / OI-11.
# syzkaller collects DEFAULT-mode output; normalization is a separate pipeline
# stage, never at the source.
#
# The accelerator is auto-detected. This config OVERRIDES qemu_args, so the
# `-enable-kvm` syzkaller would otherwise supply for linux/amd64 has to be passed
# here explicitly — omitting it silently drops the whole run back to TCG.
#
#   scripts/gen-syz-config.sh            # -> .lab/syzkaller/manager.cfg
#   ACCEL=tcg scripts/gen-syz-config.sh  # force the pre-Win11 TCG path
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
SYZ="$LAB/syzkaller"
OUT="${OUT:-$SYZ/manager.cfg}"

ACCEL="${ACCEL:-}"
if [ -z "$ACCEL" ]; then
  if [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi
fi

# Defaults differ by accelerator because the bottleneck does. Under TCG a VM burns
# host cores emulating, so few VMs with thread=multi was the sensible ceiling; under
# KVM a guest vCPU is a host thread that mostly sleeps, so the budget goes into VM
# COUNT instead. These KVM numbers are a documented starting point on a 24-core /
# 31 GB host, NOT a tuned optimum — measure before trusting them.
if [ "$ACCEL" = "kvm" ]; then
  VMCOUNT="${VMCOUNT:-8}"
  VMCPU="${VMCPU:-2}"
  VMMEM="${VMMEM:-2048}"
  PROCS="${PROCS:-8}"
  QEMU_ARGS="${QEMU_ARGS:--enable-kvm -cpu host}"
else
  VMCOUNT="${VMCOUNT:-4}"   # parallel TCG VMs (raise to trade cores for throughput)
  VMCPU="${VMCPU:-2}"
  VMMEM="${VMMEM:-2048}"
  PROCS="${PROCS:-4}"
  # thread=multi lets one TCG VM use several host threads.
  QEMU_ARGS="${QEMU_ARGS:--accel tcg,thread=multi -cpu qemu64}"
fi
HTTP="${HTTP:-127.0.0.1:56741}"

mkdir -p "$SYZ/workdir"

cat > "$OUT" <<JSON
{
  "target": "linux/amd64",
  "http": "$HTTP",
  "workdir": "$SYZ/workdir",
  "kernel_obj": "$LAB/build",
  "kernel_src": "$LAB/bpf-next",
  "image": "$LAB/images/rootfs.img",
  "sshkey": "$LAB/images/vm-id_ed25519",
  "syzkaller": "$SYZ",
  "procs": $PROCS,
  "sandbox": "none",
  "type": "qemu",
  "enable_syscalls": ["bpf*"],
  "disable_syscalls": ["bpf\$BPF_PROG_TEST_RUN", "bpf\$BPF_PROG_TEST_RUN_LIVE", "bpf\$auto_BPF_PROG_TEST_RUN"],
  "ignores": [
    "SYZFAIL: mount.binfmt_misc. failed",
    "array-index-out-of-bounds in print_bpf_insn",
    "SYZFAIL: repeatedly failed to execute the program"
  ],
  "vm": {
    "count": $VMCOUNT,
    "kernel": "$LAB/build/bzImage",
    "cpu": $VMCPU,
    "mem": $VMMEM,
    "qemu_args": "$QEMU_ARGS"
  }
}
JSON

echo "[syz-cfg] wrote $OUT"
echo "[syz-cfg] vm.count=$VMCOUNT cpu=$VMCPU mem=$VMMEM procs=$PROCS accel=${ACCEL^^} focus=bpf*"
