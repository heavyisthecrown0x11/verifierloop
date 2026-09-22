# harness — differential / verifier-log harness (guest-side)

`diffharness.c` produces the **verifier-semantic CORE signal** that syzkaller does
NOT emit on its own: the verifier's **accept/reject decision** and its
**register-state evolution**. It loads small BPF programs with `log_level=2` and
prints the kernel verifier log buffer **verbatim**, wrapped in a minimal frame.

This is the real raw input the `normalize` stage's **verifier-log parser** will
interpret into `CoreMetrics` (the second of the two real parsers — see devlog 0010
data-source map).

## Build & run

```bash
./scripts/build-harness.sh          # -> harness/diffharness  (or: cc -O2 -o harness/diffharness harness/diffharness.c)
./harness/diffharness               # needs root / CAP_SYS_ADMIN for BPF_PROG_LOAD
```

The compiled binary is gitignored (build artifact); the source and a captured
sample are committed.

## Native output format (one block per program)

```
===PROG <name> type=socket_filter ===
RESULT decision=<accept|reject> fd=<n|-1> errno=<e> load_ns=<n>
---LOG---
<raw kernel verifier log, byte-for-byte>
---END---
```

Inside `---LOG---` the parser reads:
- **decision** — from the `RESULT` line (`accept`/`reject`).
- **reject reason** — the verifier's failure line (e.g. `R0 !read_ok`), kept as a
  verbatim `String` (labels drift across kernel versions — never enum'd).
- **register-state evolution** — the per-insn `N: (op) ... ; Rk=...` lines.
- **insn_processed / states** — the `processed N insns ... total_states T peak_states P` line.

A committed sample is in `samples/host-6.18-sample.txt`.

## Two important constraints

1. **JIT↔interpreter differential is NOT possible on the primary kernel.**
   It is built with `CONFIG_BPF_JIT_ALWAYS_ON=y`, so the interpreter is compiled
   out and `bpf_jit_enable` is forced to 1. The JIT/interp retval+`data_out` CORE
   field therefore needs a **separate interpreter-only kernel** (`ALWAYS_ON` off,
   `bpf_jit_enable=0`) and a cross-kernel run — deferred to a later harness mode.
   v0 produces **decision + register-state only**.

2. **Host vs bpf-next capture.** The committed sample was captured on the host WSL
   kernel (representative of the format). The **authoritative** capture is the same
   binary run **inside the bpf-next VM** (rev in `.lab/kernel.rev`); register-state
   verbosity at `log_level=2` can differ slightly. Running it in-VM is part of
   wiring the real `FuzzDriver`.

## Why C (not Rust)

Raw `bpf()` syscall, zero dependencies, statically buildable, runs unchanged on the
host and inside the disposable Debian VM. Matches the project principle: collect a
tool's DEFAULT native output UNCHANGED; normalize later, never at the source.
