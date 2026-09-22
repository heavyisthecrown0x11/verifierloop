//! Disposable QEMU VM control for self-built bpf-next kernels.
//!
//! Two backends:
//!   * [`kvm`] — QEMU/KVM with nested virt on WSL2. PRIMARY hunt path.
//!   * [`tcg`] — pure-software TCG fallback (no KVM). SLOWER; for manual PoC /
//!     differential only, never the main hunting throughput.
//!
//! The Ubuntu 22.04 layer is ONLY host/orchestration. The actual hunt runs
//! INSIDE these self-built bpf-next VMs.

pub mod kvm;
pub mod tcg;

/// A booted, disposable VM handle.
#[derive(Debug)]
#[non_exhaustive]
pub struct Vm {
    // TODO(vmctl): finalize (qemu child handle, ssh/monitor endpoints, kernel id).
}

/// Which backend booted a VM.
#[derive(Debug, Clone, Copy)]
pub enum Backend {
    /// Hardware-accelerated (KVM). Primary.
    Kvm,
    /// Software emulation (TCG). Fallback only.
    Tcg,
}
