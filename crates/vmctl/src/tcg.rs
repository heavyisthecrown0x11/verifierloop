//! QEMU/TCG backend (FALLBACK, no KVM). Launch template: config/qemu/launch-tcg.sh.
//!
//! SLOWER than KVM. Use only for manual PoC / differential runs on hosts without
//! /dev/kvm, never as the main hunting throughput.

use super::Vm;
use std::path::Path;

/// Boot a disposable TCG-emulated VM running the given self-built kernel. STUB.
/// TODO(vmctl-tcg): shell out to config/qemu/launch-tcg.sh; wire monitor + ssh.
pub fn boot(_kernel_image: &Path) -> Vm {
    todo!("scaffold: boot TCG fallback VM from self-built bpf-next kernel")
}
