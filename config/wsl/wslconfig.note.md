# `.wslconfig` — nested virtualization for the WSL2 host

The KVM path needs **nested virtualization** exposed to the WSL2 Ubuntu 22.04
guest so QEMU can use `-enable-kvm`. This is host-Windows configuration — it is
NOT part of the repo build. Set it once on the Windows side.

Put this in `C:\Users\<you>\.wslconfig` (Windows user profile), then run
`wsl --shutdown` and restart WSL:

    [wsl2]
    nestedVirtualization=true
    # TODO: size memory/processors for the fuzzing host as needed.
    # memory=16GB
    # processors=8

Verify inside WSL after restart:

    ls -l /dev/kvm                        # must exist
    egrep -c '(vmx|svm)' /proc/cpuinfo    # must be > 0

If `/dev/kvm` is absent, KVM is unavailable — use the TCG fallback
(`just boot-vm-tcg`), which is slower and only for manual PoC / differential.

Requirements: Windows 11, a recent WSL2, and CPU virtualization enabled in
BIOS/UEFI.
