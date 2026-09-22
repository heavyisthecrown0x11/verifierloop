#!/usr/bin/env bash
# Build a self-built bpf-next bzImage for the verifier lab: BPF+JIT, KCOV, the
# sanitizers, and DEBUG_INFO_BTF (needs pahole), plus the KVM-guest bits so it
# boots under QEMU. Config = x86_64 defconfig + kvm_guest.config + the lab
# fragment (config/kernel/bpf-verifier-lab.config), resolved with olddefconfig.
#
#   scripts/build-kernel.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
# SRC and OUT are overridable so a SECOND tree — a git worktree parked at the parent of a
# known verifier fix — can be built with exactly the same config as the main lab kernel.
# Calibrating the oracle against a real bug means running the kernel that HAD it, and the
# comparison only means something if the two kernels differ in the fix and nothing else.
SRC="${SRC:-$LAB/bpf-next}"
OUT="${OUT:-$LAB/build/bzImage}"
FRAG="$REPO_ROOT/config/kernel/bpf-verifier-lab.config"
JOBS="${JOBS:-$(nproc)}"

# `.git` is a DIRECTORY in a clone but a FILE in a git worktree, and the calibration
# kernel is built from a worktree parked at a fix's parent commit.
[ -e "$SRC/.git" ] || { echo "[build] no source at $SRC — run scripts/fetch-kernel.sh first" >&2; exit 1; }
command -v pahole >/dev/null 2>&1 || { echo "[build] pahole (dwarves) required for DEBUG_INFO_BTF" >&2; exit 1; }

echo "[build] pahole $(pahole --version 2>/dev/null) | gcc $(gcc -dumpfullversion) | -j$JOBS"
cd "$SRC"

# 1. Base config: x86_64 defconfig, then merge the KVM-guest fragment shipped in
#    the kernel tree, then our lab fragment, then resolve everything.
make -j"$JOBS" defconfig
make -j"$JOBS" kvm_guest.config
./scripts/kconfig/merge_config.sh -m .config "$FRAG"
# EXTRA_FRAG lets a caller build a VARIANT of the same tree — e.g. one without
# CONFIG_BPF_JIT_ALWAYS_ON, which is what makes the kernel's own interpreter reachable and
# therefore what a JIT-vs-interpreter differential needs. Applied after the lab fragment so
# it wins, and reported below like every other key symbol.
if [ -n "${EXTRA_FRAG:-}" ]; then
  echo "[build] extra fragment -> $EXTRA_FRAG"
  ./scripts/kconfig/merge_config.sh -m .config "$EXTRA_FRAG"
fi
make -j"$JOBS" olddefconfig

# 2. Sanity: the symbols we depend on actually survived olddefconfig.
echo "[build] key symbols after olddefconfig:"
for s in CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_BPF_JIT_ALWAYS_ON \
         CONFIG_KCOV CONFIG_KASAN CONFIG_KCSAN CONFIG_UBSAN CONFIG_DEBUG_INFO_BTF; do
  if grep -q "^$s=y" .config; then printf '  %-28s = y\n' "$s"; else printf '  %-28s !! NOT ENABLED\n' "$s"; fi
done

# 3. Build.
make -j"$JOBS" bzImage

BZ="arch/x86/boot/bzImage"
[ -f "$BZ" ] || { echo "[build] bzImage not produced" >&2; exit 1; }

mkdir -p "$LAB/build"
mkdir -p "$(dirname "$OUT")"; cp "$BZ" "$OUT"
# THE SHARED ARTEFACTS BELONG TO THE DEFAULT BUILD ONLY, and the test is the OUTPUT PATH,
# not the presence of a config fragment. 0079 added this guard keyed on EXTRA_FRAG, and it
# was not enough: the buggy-kernel builds pass only SRC and OUT, so they took the else
# branch and silently replaced .lab/build/vmlinux with a 2023 tree's. Nothing noticed until
# a coverage symbolization needed it. Keying on OUT covers every variant, however invoked.
if [ "$OUT" != "$LAB/build/bzImage" ]; then
  # A variant must not overwrite the main kernel's vmlinux/config: those are what every
  # other script reads, and a silently swapped config is the worst kind of stale artifact.
  cp .config "${OUT}.config"
else
  [ -f vmlinux ] && cp vmlinux "$LAB/build/vmlinux" || true
  cp .config "$LAB/build/kernel.config"
fi

# 4. Verify BTF is embedded in the FINAL artifact (the point of the pahole
#    prerequisite). Authoritative confirmation is in-VM (/sys/kernel/btf/vmlinux,
#    checked by scripts/verify-vm.sh); this is the static cross-check.
#
#    EVERY LINE BELOW MUST DESCRIBE THE BUILD THAT JUST RAN. Until 0087 the three
#    closing lines were unconditional: a variant build checked BTF on the SHARED
#    vmlinux, announced a vmlinux it had not written, and printed the MAIN tree's
#    revision. All three were false for a variant, and each one is the same shape as
#    the stale artefact 0085 lost a measurement to — a report about the wrong image.
VMLINUX_HERE="vmlinux"                      # the one this build produced, in $SRC
if readelf -S "$VMLINUX_HERE" 2>/dev/null | grep -qE '\.BTF([[:space:]]|_ids)'; then
  echo "[build] .BTF section present in $SRC/vmlinux (confirm in-VM with verify-vm.sh)"
else
  echo "[build] WARNING: no .BTF section in $SRC/vmlinux"
fi
echo "[build] bzImage  -> $OUT ($(du -h "$BZ" | cut -f1))"
if [ "$OUT" != "$LAB/build/bzImage" ]; then
  echo "[build] vmlinux  -> $SRC/vmlinux  (variant; the shared $LAB/build/vmlinux was left alone)"
  echo "[build] config   -> ${OUT}.config  (variant; the shared config was left alone)"
else
  echo "[build] vmlinux  -> $LAB/build/vmlinux"
  echo "[build] config   -> $LAB/build/kernel.config"
fi
# The revision of the tree that was actually built. `.lab/kernel.rev` records the MAIN
# tree and says nothing about a worktree parked at some fix's parent.
echo "[build] revision -> $(git -C "$SRC" rev-parse HEAD 2>/dev/null || cat "$LAB/kernel.rev" 2>/dev/null || echo unknown)"
