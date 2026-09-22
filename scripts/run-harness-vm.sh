#!/usr/bin/env bash
# Run the differential/verifier-log harness INSIDE the disposable bpf-next VM and
# capture its DEFAULT native output on the host. Mirrors verify-vm.sh: an init
# script + serial console (no ssh/networking). The harness binary is injected into
# the rootfs via loop-mount; the boot itself uses -snapshot, so the VM's own writes
# stay ephemeral. This doubles as the in-VM authoritative capture of the verifier
# log format on our self-built kernel.
#
#   scripts/run-harness-vm.sh [OUTFILE]      # default OUTFILE: .lab/harness-out.log
#
# HARNESS_ARGS passes arguments through to the in-VM harness. The two data sources
# are kept apart on purpose (different provenance, different pinned fixtures):
#   HARNESS_ARGS=          the fixed authoritative program set (20 programs)
#   HARNESS_ARGS=--gen     the enumerated targeted family (devlog 0025)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
ROOTFS="${ROOTFS:-$LAB/images/rootfs.img}"
OUT="${1:-$LAB/harness-out.log}"
HARNESS_ARGS="${HARNESS_ARGS:-}"
SERIAL="$LAB/harness-serial.log"
TIMEOUT="${TIMEOUT:-180}"

# 1. fresh static harness binary
"$REPO_ROOT/scripts/build-harness.sh" >/dev/null
BIN="$REPO_ROOT/harness/diffharness"
[ -x "$BIN" ]     || { echo "[harness-vm] no harness binary at $BIN" >&2; exit 1; }
[ -f "$ROOTFS" ]  || { echo "[harness-vm] no rootfs at $ROOTFS" >&2; exit 1; }

# 2. inject binary + init wrapper into the rootfs (loop-mount; persists on base img)
MNT="$(mktemp -d)"
cleanup() { mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT
mount -o loop "$ROOTFS" "$MNT"
install -m755 "$BIN" "$MNT/root/diffharness"
cat > "$MNT/root/run-harness.sh" <<EOS
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
# KCOV lives in debugfs, and coverage-guided generation needs it. Harmless when the
# kernel has no KCOV: the mount fails and the harness reports the probe as unavailable
# rather than silently producing no feedback.
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null
echo "===HARNESS-BEGIN==="
/root/diffharness $HARNESS_ARGS
echo "===HARNESS-END==="
poweroff -f 2>/dev/null || { echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger; }
EOS
chmod +x "$MNT/root/run-harness.sh"
sync
cleanup
trap - EXIT

# 3. boot, init = harness wrapper, capture serial console.
# ACCEL is auto-detected: KVM when the host can actually give it to us, TCG
# otherwise. Both run the SAME self-built bpf-next kernel, so the verifier log a
# program produces must not depend on which one ran it — accelerator choice is a
# throughput decision, never a semantic one. Override with ACCEL=tcg to compare.
if [ -z "${ACCEL:-}" ]; then
  if [ -w /dev/kvm ]; then ACCEL=kvm; else ACCEL=tcg; fi
fi
echo "[harness-vm] booting (${ACCEL}), timeout ${TIMEOUT}s ..."
ACCEL="$ACCEL" \
APPEND="console=ttyS0 root=/dev/vda rw panic=1 oops=panic init=/root/run-harness.sh" \
  timeout "$TIMEOUT" "$REPO_ROOT/scripts/boot-vm.sh" >"$SERIAL" 2>&1 || true

# 4. extract the harness native output between the markers
if grep -q "===HARNESS-BEGIN===" "$SERIAL" && grep -q "===HARNESS-END===" "$SERIAL"; then
  sed -n '/===HARNESS-BEGIN===/,/===HARNESS-END===/p' "$SERIAL" | sed '1d;$d' | tr -d '\r' > "$OUT"
  echo "[harness-vm] captured $(grep -c '===PROG' "$OUT" || echo 0) program block(s) -> $OUT"
else
  # A MISSING END MARKER IS NOT ALWAYS A HARNESS FAILURE. 0093 measured a calibration pair
  # (bc308be380c1) where the verifier ACCEPTS a program whose runtime store lands 4 GB out of
  # bounds: the kernel oopses inside the JITed program and the VM dies before the harness can
  # print anything. Treating that as "markers not found" throws away the strongest evidence
  # this instrument can produce -- a verifier-accepted program that crashes the kernel.
  #
  # So the two cases are separated by name. The serial log is preserved either way, because
  # it is the only record of what happened.
  CRASHLOG="${OUT%.log}-crash-serial.log"
  if grep -qE "BUG: unable to handle|Oops: |general protection fault|Kernel panic" "$SERIAL"; then
    cp "$SERIAL" "$CRASHLOG"
    echo "[harness-vm] KERNEL CRASH while running the harness -- serial saved to $CRASHLOG" >&2
    grep -m1 -E "BUG: unable to handle|general protection fault" "$SERIAL" >&2 || true
    grep -m1 -E "^\[[ 0-9.]+\] RIP: " "$SERIAL" >&2 || true
    # An oops under an ACCEPTED program is a finding about the verifier, not about us.
    if grep -q "RESULT decision=accept" "$SERIAL"; then
      echo "[harness-vm] the crash followed an ACCEPTED program: treat as a verifier finding" >&2
    fi
    exit 2
  fi
  echo "[harness-vm] FAILED: markers not found. Last 30 serial lines:" >&2
  tail -30 "$SERIAL" >&2
  exit 1
fi
