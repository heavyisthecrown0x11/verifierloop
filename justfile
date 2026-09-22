# verifierloop — task runner (SCAFFOLDING).
#
# Every hunt recipe is a PLACEHOLDER: it prints intent + a TODO and exits non-zero
# so an un-implemented step fails loudly instead of pretending to work. Fill each
# in as the corresponding stage is implemented.
#
# Requires: `just` (https://github.com/casey/just).

# Root dir holding per-period artifacts (the "periodic harvest" output).
data_root := "data"

# Default: list recipes.
default:
    @just --list

# --- hunt pipeline (placeholders) -------------------------------------------

# Fetch bpf-next source (blobless partial clone) into .lab/bpf-next.
fetch-kernel:
    ./scripts/fetch-kernel.sh

# Build the self-built bpf-next bzImage (defconfig + kvm_guest + lab fragment, BTF).
build-kernel:
    ./scripts/build-kernel.sh

# Create the disposable Debian rootfs image (debootstrap) for the fuzzing VM.
create-rootfs:
    ./scripts/create-rootfs.sh

# Automated boot verification: boot the VM, assert BTF + bpffs + kcov, power off.
verify-vm:
    ./scripts/verify-vm.sh

# Boot a disposable KVM-accelerated VM (PRIMARY hunt path); interactive serial console.
boot-vm-kvm:
    ./scripts/boot-vm.sh

# Boot a disposable TCG VM (FALLBACK: no KVM, slower, manual PoC/differential only).
boot-vm-tcg:
    ACCEL=tcg ./scripts/boot-vm.sh

# Install Go (if needed) + build syzkaller into .lab/syzkaller.
setup-syzkaller:
    ./scripts/setup-syzkaller.sh

# Start syzkaller (PRIMARY fuzzer) against the self-built kernel. DURATION=<s> for a bounded run.
run-fuzzers:
    ./scripts/run-syzkaller.sh

# Collect metrics + hand them to the Python analysis side (Rust `score` boundary).
collect-metrics:
    @echo "[collect-metrics] TODO: ingest raw output, normalize, write the NORMALIZED artifact,"
    @echo "                  then invoke 'python -m verifierloop_analysis' for anomaly scoring."
    @exit 1

# Run one period: fuzz until exec-count threshold N, then run the pipeline. (N, not time.)
run-period:
    @echo "[run-period] TODO: drive the orchestrator loop for one period (boundary = exec count N)."
    @exit 1

# Emit the triaged period report for the human-in-the-loop at the period boundary.
period-report:
    @echo "[period-report] TODO: assemble the triaged batch into {{data_root}}/periods/<N>/."
    @exit 1

# --- skeleton self-checks (these actually run) ------------------------------

# Compile the Rust workspace skeleton.
build-rust:
    cargo build

# Confirm the Python package imports on a bare interpreter.
check-python:
    python -c "import sys; sys.path.insert(0, 'python/src'); import verifierloop_analysis, verifierloop_analysis.contract, verifierloop_analysis.schemas; print('python import OK')"

# The denominator for seen_pcs: enumerate every KCOV coverage point in vmlinux, intersect
# with a run's PCSET dump, and report the fraction of the verification pass we reach.
coverage-fraction LOG=".lab/fuzz-pcset.log":
    python3 scripts/coverage-fraction.py .lab/build/vmlinux {{LOG}} .lab/bpf-next/kernel/bpf \
      | tee .lab/coverage-fraction.txt
