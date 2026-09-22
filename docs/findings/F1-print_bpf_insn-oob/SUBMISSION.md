# F1 — upstream submission packet

**Patch:** `0001-bpf-disasm-guard-print_bpf_insn-against-BPF_MEMSX-BP.patch`
**Target tree:** bpf-next
**Status:** prepared + **checkpatch-clean** (0 errors; the only checkpatch warnings are
`Unknown commit id b9c5d822f677`, a `--no-tree` false positive that resolves against the
real tree). NOT yet sent — sending is a human action; this sandbox has no mail transport
(`git send-email` unavailable, no SMTP), and the send goes out under your identity.

**Human steps — 1 of 2 DONE:**
1. ~~Real name in Signed-off-by~~ — **DONE (2026-09-03):** the lab-tree commit was amended
   with the real-name DCO Signed-off-by and the `.patch` re-exported (lab commit
   `dffc1150e2cc`). The diff itself is unchanged (`index 50b3ca5149a0..70c2b281cfe9`);
   checkpatch re-verified clean on the finalized patch.
2. **Send from your own environment** (the Win11/Desktop copy) with the `git send-email`
   line below — the ONLY remaining step. This sandbox has no mail transport.

## Subject
`[PATCH bpf-next] bpf: disasm: guard print_bpf_insn against BPF_MEMSX | BPF_DW`

## Recipients (from scripts/get_maintainer.pl on the patch)
**To** (maintainers of kernel/bpf/disasm.c + the reachability commit's author):
- Alexei Starovoitov <ast@kernel.org>
- Daniel Borkmann <daniel@iogearbox.net>
- Andrii Nakryiko <andrii@kernel.org>
- Eduard Zingerman <eddyz87@gmail.com>
- Kumar Kartikeya Dwivedi <memxor@gmail.com>  (authored the diagnostics.c series in Fixes:)

**Cc:** Martin KaFai Lau <martin.lau@linux.dev>, Song Liu <song@kernel.org>,
Yonghong Song <yonghong.song@linux.dev>, Jiri Olsa <jolsa@kernel.org>,
Quentin Monnet <qmo@kernel.org>, Emil Tsalapatis <emil@etsalapatis.com>,
Ihor Solodrai <ihor.solodrai@linux.dev>, bpf@vger.kernel.org, linux-kernel@vger.kernel.org

## Before sending — two human steps
1. **Signed-off-by must be your real name** (DCO). The patch currently carries
   `Signed-off-by: tylersec <freedawg71@gmail.com>` as a placeholder — edit it to
   your legal name if that is not it, or the maintainers will bounce it.
2. Send with git send-email from the lab tree:
   ```bash
   cd .lab/bpf-next
   git send-email \
     --to ast@kernel.org --to daniel@iogearbox.net --to andrii@kernel.org \
     --to eddyz87@gmail.com --to memxor@gmail.com \
     --cc bpf@vger.kernel.org --cc linux-kernel@vger.kernel.org \
     ../../docs/findings/F1-print_bpf_insn-oob/0001-*.patch
   ```

## What to say in the cover / notes-under-the-scissors (optional but honest)
- Found by fuzzing bpf-next `5e289c5a4a52` with syzkaller under KVM (verifierloop).
- Verbose-path only (`log_level >= 1`); the silent `log_level=0` prog-load path is
  unaffected (diagnostics facility is inert without a log). Not privilege escalation;
  an OOB **read** of an adjacent `.rodata` pointer, deref'd as `%s` into the log.
- KASAN/UBSAN splats + full call chain are in `kasan-report.txt` / `README.md`.
- The fix hardens the disassembler (which is documented to run on unvalidated input);
  it does not change verifier accept/reject behaviour.

## Provenance
- Fixes: b9c5d822f677 ("bpf: Add source and instruction diagnostic context")
- 3-entry `bpf_ldsx_string[]` predates this and is correct for validated input;
  the defect is the new pre-validation reach, so the hardening lives in disasm.c.
