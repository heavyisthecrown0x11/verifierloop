//! QEMU/KVM backend (PRIMARY). Launch template: config/qemu/launch-kvm.sh.

use super::Vm;
use std::path::Path;

/// Boot a disposable KVM-accelerated VM running the given self-built kernel. STUB.
/// TODO(vmctl-kvm): shell out to config/qemu/launch-kvm.sh; wire monitor + ssh;
/// require /dev/kvm (see config/wsl/wslconfig.note.md).
pub fn boot(_kernel_image: &Path) -> Vm {
    todo!("scaffold: boot KVM VM from self-built bpf-next kernel")
}
