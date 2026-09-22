# F1 — Verbose-path OOB read in `print_bpf_insn` via the new `diagnostics.c` facility

**Kernel:** bpf-next `7.2.0-g5e289c5a4a52`
**Found by:** verifierloop (syzkaller under KVM, 2026-09-01)
**Class:** memory-safety (OOB read), NOT a verifier soundness/logic bug
**Reachability:** verbose only (`log_level >= 1`); unreachable on the silent `log_level=0` prog-load path
**Status:** root-caused; **upstream patch prepared** (`0001-*.patch` + `SUBMISSION.md`),
send is a human action (DCO real-name + `git send-email`); the **lab kernel now carries
the guard** (0028) so F1 no longer panics fuzz VMs. Not yet sent upstream.

---

## One-line

Disassembling a `BPF_LDX | BPF_MEMSX | BPF_DW` opcode indexes the 3-element
`bpf_ldsx_string[]` at index 3 (`BPF_DW >> 3 == 3`), a fixed +1 out-of-bounds
read of the adjacent `.rodata` pointer, which is then dereferenced as `%s`.
It fires only when the verifier is asked to render diagnostics/verbose output.

## The bug

`kernel/bpf/disasm.c`:

```c
static const char *const bpf_ldsx_string[] = {   /* line 115 — THREE entries */
	[BPF_W >> 3]  = "s32",
	[BPF_H >> 3]  = "s16",
	[BPF_B >> 3]  = "s8",
};
...
} else if (class == BPF_LDX) {                     /* line 297 */
	if (BPF_MODE(insn->code) != BPF_MEM && BPF_MODE(insn->code) != BPF_MEMSX) {
		verbose(cbs->private_data, "BUG_ldx_%02x", insn->code);
		return;
	}
	verbose(cbs->private_data, "(%02x) r%d = *(%s *)(r%d %+d)",   /* line 302 */
		insn->code, insn->dst_reg,
		BPF_MODE(insn->code) == BPF_MEM ?
			 bpf_ldst_string[BPF_SIZE(insn->code) >> 3] :
			 bpf_ldsx_string[BPF_SIZE(insn->code) >> 3],          /* line 306 */
		insn->src_reg, insn->off);
```

`bpf_ldst_string[]` has 4 entries (W/H/B/DW), but `bpf_ldsx_string[]` has only 3
(W/H/B) — sign-extended DW load is not a valid instruction. The LDX branch checks
the *mode* is MEM or MEMSX but never checks that a MEMSX access is not DW-sized. So
for `BPF_MEMSX | BPF_DW`, `BPF_SIZE(code) >> 3 == 3` indexes one element past the
array end:

- **UBSAN** `disasm.c:306` — array-index-out-of-bounds, index 3 out of range for `char *[3]`.
- **KASAN** `disasm.c:302` — global-out-of-bounds, 8-byte read (the adjacent
  `const char *` slot) which `verbose("...%s...")` then dereferences.

The OOB is a *fixed* +1, not attacker-scaled: it always reads the single global that
happens to follow the array in `.rodata`. On KASAN/UBSAN kernels this is a clean
crash/DoS; on a production kernel it reads a deterministic adjacent pointer and
derefs it as a string into the user-visible verifier log (content is build-fixed,
not attacker-chosen).

## Reachability / call chain

From the KASAN report:

```
print_bpf_insn             disasm.c:306   <- OOB index / :302 read+deref
format_disasm_line         diagnostics.c:633
diag_print_insn_context    diagnostics.c:783
bpf_diag_source            diagnostics.c:896
bpf_diag_program_structure diagnostics.c:1215
check_subprogs             verifier.c:3093
bpf_check                  verifier.c:21236
bpf_prog_load              syscall.c:3133
__sys_bpf                  syscall.c:6367
```

`check_subprogs()` (`verifier.c:3091`) calls `bpf_diag_program_structure(...)` when
it detects a "jump out of range" — and this runs *before* `check_insn_fields`
(19287) and `do_check_main` (21306), so a raw, unvalidated opcode reaches the
disassembler. (This tree also has no MEMSX+DW rejection in `check_insn_fields`, but
that is downstream of where the OOB already fired.)

## Reviewer's three questions — answered

### Q1. `log_level=0` (silent prod path) or only verbose? — ONLY VERBOSE (`log_level >= 1`).

`print_bpf_insn` has exactly TWO callers in the whole tree, both gated on log level:

1. **Classic** — `bpf_verbose_insn` (`verifier.c:3384`), called only at
   `verifier.c:18426`, inside `if (env->log.level & BPF_LOG_LEVEL) { ... }`.
2. **This path** — `diagnostics.c:633` is reached only through `bpf_diag_source`,
   which opens with:
   ```c
   if (!bpf_diag_enabled(env)) return;
   if (!env->diag) return;
   ```
   where `bpf_diag_enabled(env)` is `env->log.level & BPF_LOG_LEVEL`, and `env->diag`
   is allocated only in `bpf_diag_init` — itself guarded by `if (!bpf_diag_enabled(env)) return 0;`.

So at `log_level=0` the whole diagnostics facility is inert (`env->diag == NULL`) and
the classic disassembler is never invoked. **There is no `log_level=0` path to
`print_bpf_insn`; the OOB cannot fire.** (Classification: Possibility B(a) — real
bug on an observation-gated surface, not the silent production path.)

### Q2. Attacker-controlled? — YES, but bounded.

The index derives from `insn->code`, which is program-supplied. However it is a
*fixed* +1 OOB (index 3 into a 3-element array), not a scalable offset, so it is an
adjacent-`.rodata` read, not an arbitrary-read primitive.

### Q3. Harness-specific or stock path? — STOCK.

`diagnostics.c` is genuine upstream bpf-next (author Kumar Kartikeya Dwivedi
<memxor@gmail.com>, Meta; SPDX GPL-2.0; committed 2026-08-15), compiled
unconditionally under `CONFIG_BPF_SYSCALL`, and invoked from `check_subprogs` on the
normal `bpf_prog_load` syscall path. A stock `bpftool`/`libbpf` load of a malformed
program that requests a verifier log (`log_level >= 1`) hits the same OOB. The
verifierloop harness is NOT required — it only ever runs at `log_level >= 1`, which
is the normal way any tool obtains a verifier log. NOT a harness artifact.

## Trigger conditions

1. `log_level >= 1` (a verifier log buffer requested), AND
2. a jump-out-of-range in `check_subprogs` (to invoke `bpf_diag_program_structure`), AND
3. a `BPF_LDX | BPF_MEMSX | BPF_DW` instruction within the disassembled context window.

No unprivileged reach on modern kernels (unpriv BPF disabled → needs CAP_BPF/CAP_SYS_ADMIN).

## Severity (honest, narrow)

Local, verbose-path, capability-gated OOB **read**. On KASAN/UBSAN builds:
crash / DoS. On production: deterministic adjacent-`.rodata` `%s` deref (build-fixed
content). Not privilege escalation; not a verifier logic/soundness bug. Worth an
upstream report on its own merits (fresh code, clean memory-safety defect), framed
exactly this narrowly.

## Fix options

1. **(preferred) Make the disassembler total for MEMSX+DW**, mirroring the existing
   `BUG_ldx_%02x` guard style — the disassembler is designed to run on unvalidated
   input, so it must not index OOB:
   ```c
   if (BPF_MODE(insn->code) == BPF_MEMSX && BPF_SIZE(insn->code) == BPF_DW) {
       verbose(cbs->private_data, "BUG_ldsx_%02x", insn->code);
       return;
   }
   ```
2. Alternatively give `bpf_ldsx_string[]` a 4th (sentinel/"BUG") entry so the index
   is in-bounds — less clear, since LDSX-DW is not a real instruction.
3. Design question for the maintainer: whether the diagnostics path should
   disassemble instructions before field validation at all. The memory-safety fix
   still belongs in `disasm.c` (defense in depth), independent of that.

## Notes / provenance

- `diagnostics.c` series (author memxor@Meta, 2026-08-15): "Add verifier diagnostics
  report helpers", "Add source and instruction diagnostic context", ... through
  "Preserve source attribution without source text".
- syz-manager could not auto-produce a repro (`repro=false`) only because
  `scripts/get_maintainer.pl` is missing from the tree (symbolization failed) — a
  tooling gap, unrelated to the bug. Easy fix.

## Does not change project status

This is a memory-safety bug in a disassembly/diagnostics helper on the verbose path.
It does **not** count as the verifier logic/soundness bug the loop hunts for; the
"0 logic bugs" status is unchanged.
