// verifierloop differential/verifier-log harness (v0) — GUEST-SIDE.
//
// Purpose: produce the verifier-SEMANTIC CORE signal that syzkaller does NOT emit
// on its own — the verifier's accept/reject decision plus its register-state
// evolution — by loading small BPF programs with log_level=2 and capturing the
// kernel verifier log buffer VERBATIM. This is the real raw input the normalize
// stage's verifier-log parser will interpret into CoreMetrics.
//
// Why C (not Rust): raw bpf() syscall, zero deps, statically buildable, trivially
// runs both on the host and inside the disposable Debian VM. Matches the project's
// "collect DEFAULT native output UNCHANGED" principle — the verifier log is emitted
// byte-for-byte; only a minimal per-program frame is added around it.
//
// NOTE on JIT<->interpreter: the primary hunt kernel is built with
// CONFIG_BPF_JIT_ALWAYS_ON=y, so the interpreter is compiled OUT and a
// single-kernel JIT/interp retval differential is IMPOSSIBLE. That signal needs a
// separate interpreter-only kernel (bpf_jit_enable=0) and is deferred to a later
// cross-kernel harness mode. v0 produces decision + register-state only.
//
// Output: a simple line-framed native format on stdout (one block per program):
//   ===PROG <name> type=<t> ===
//   RESULT decision=<accept|reject> fd=<n|-1> errno=<e> load_ns=<n>
//   ---LOG---
//   <raw verifier log, verbatim>
//   ---END---
//
// Build:  cc -O2 -static -o diffharness diffharness.c   (or without -static)
// Run:    ./diffharness            (needs CAP_SYS_ADMIN / root for BPF_PROG_LOAD)

#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

// --- minimal BPF insn encoding (classic macros from the kernel samples) ------
#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_MOV64_IMM(DST, IMM)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K,                    \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
/* 32-bit register move: the alu32 form zero-extends, which is exactly why the verifier
   keeps BPF_ADD_CONST32 and BPF_ADD_CONST64 as distinct link flags and refuses to prune
   across them. */
#define BPF_MOV32_REG(DST, SRC)                                                \
    ((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_X,                      \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_MOV64_REG(DST, SRC)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                    \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K,                   \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
// 32-bit (subregister) forms. The verifier tracks u32_min/u32_max separately from
// the 64-bit bounds and must keep the two views in sync; these are the insns that
// force that sync to happen.
#define BPF_ALU32_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K,                   \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
/* Present in the kernel's uapi since 2023 but absent from distro headers, so define it
   the way include/uapi/linux/bpf.h does. */
#ifndef BPF_MEMSX
#define BPF_MEMSX 0x80
#endif

#include "bpfref.h"
#include "bpflive.h"
#include "bpfsubs.h"
#include "bpfclaim.h"

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                                       \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
// Register-to-register (BPF_X) forms — the classic macros above are all immediate
// (BPF_K). OI-9's next increment needs these: two registers, each carrying its own
// abstract state, meeting in one op (a different verifier path from the imm forms).
#define BPF_ALU64_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                 \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_MOV32_IMM(DST, IMM)                                                \
    ((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_K,                      \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = (IMM)})
#define BPF_ALU32_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_X,                   \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_JMP_REG(OP, DST, SRC, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X,                   \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_JMP32_REG(OP, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_X,                 \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_JMP_A(OFF)                                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_JA,                               \
                       .dst_reg = 0, .src_reg = 0, .off = OFF, .imm = 0})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                                        \
    ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,              \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
// Pseudo LD_IMM64 loading a map fd. Occupies TWO insn slots — the macro expands
// to both, exactly as the kernel's own bpf_insn.h spells it (and as
// Documentation/bpf/verifier.rst writes it in its examples).
#define BPF_LD_MAP_FD(DST, FD)                                                 \
    ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = DST,      \
                       .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = (FD)}),  \
    ((struct bpf_insn){0})
#define BPF_EMIT_CALL(FUNC)                                                    \
    ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (FUNC)})
#define BPF_EXIT_INSN()                                                        \
    ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0})

static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* 4 MB, raised from 256 KB in 0098. A verifier log that does not fit comes back as
   -ENOSPC, which 0097 measured being read as a verdict — so a buffer that is merely
   'usually enough' is a silent source of false rejections. The instrumented kernel's
   prune-pair dumps make a deep program's log much larger, and a verdict-identity check
   run against a truncating buffer would be measuring our own limit. */
static char g_log[4 * 1024 * 1024];

// Load one program with log_level=2 and print its native frame.
//
// `prog_type`/`type_name` and `prog_flags` are explicit because a few documented
// cases are only reachable under a specific program type (the socket helpers are
// not callable from a socket filter) or a specific load flag (strict alignment).
// The header line stays byte-identical for the default socket_filter/no-flag
// programs — the extra `flags=` field is printed only when a flag is actually set.
static void run_one_ex(const char *name, const struct bpf_insn *insns, int n,
                       int prog_type, const char *type_name, uint32_t prog_flags) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.prog_flags = prog_flags;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;                            // full register-state evolution
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=%s%s ===\n", name, type_name,
           prog_flags & BPF_F_STRICT_ALIGNMENT ? " flags=strict_alignment" : "");
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);
    printf("---LOG---\n%s\n---END---\n", g_log);
    if (fd >= 0)
        close(fd);
}

// Default program shape: socket filter, no load flags (loadable as root, no attach).
static void run_one(const char *name, const struct bpf_insn *insns, int n) {
    run_one_ex(name, insns, n, BPF_PROG_TYPE_SOCKET_FILTER, "socket_filter", 0);
}

// Create a small ARRAY map and run a CORRECT bpf_map_lookup_elem(&map, &key) call
// so the verifier log shows a real helper-call site (arg register types at the
// call). This is what the verifier-log parser extracts as the OBSERVED arg type.
static void run_map_lookup(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 8;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG map_lookup type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
        return;
    }
    struct bpf_insn insns[] = {
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),   // *(u32*)(r10-4) = 0  (key on stack)
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),   // r2 = r10
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),  // r2 = &key (PTR_TO_STACK) = arg1
        // r1 = map (pseudo LD_MAP_FD, 2 slots) = arg0
        ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                           .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd}),
        ((struct bpf_insn){0}),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    run_one("map_lookup", insns, (int)(sizeof(insns) / sizeof(insns[0])));
    close(map_fd);
}

// ---------------------------------------------------------------------------
// DOCUMENTED-BEHAVIOUR CASES (ground-truth source 2).
//
// Each program below is the pseudo-asm example printed in
// Documentation/bpf/verifier.rst, translated to real insns. The label matches a
// `DocumentedCase::id` in pipeline::groundtruth::verifier_rst, where the
// document's own sentence is quoted and anchor-checked. The EXPECTED outcome
// lives there (from the doc); this file only supplies the program.
//
// The pseudo-asm -> insn translation is a reviewable judgement, kept literal:
// register numbers and instruction kinds follow the document exactly.
// ---------------------------------------------------------------------------
static void run_documented_cases(void) {
    // verifier.rst:25-30 — "If register was never written to, it's not readable"
    //   bpf_mov R0 = R2
    //   bpf_exit
    struct bpf_insn doc_unreadable_reg[] = {
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
        BPF_EXIT_INSN(),
    };

    // verifier.rst:37-45 — "Since R6-R9 are callee saved, their state is preserved
    // across the call" ... "is a correct program".
    //   bpf_mov R6 = 1 ; bpf_call foo ; bpf_mov R0 = R6 ; bpf_exit
    // `foo` is instantiated as a helper callable from a socket filter.
    struct bpf_insn doc_callee_saved_r6[] = {
        BPF_MOV64_IMM(BPF_REG_6, 1),
        BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_6),
        BPF_EXIT_INSN(),
    };

    // verifier.rst:49-56 — load/store only with valid pointer types; the example
    //   bpf_mov R1 = 1 ; bpf_mov R2 = 2 ; bpf_xadd *(u32 *)(R1 + 3) += R2 ; bpf_exit
    // "will be rejected, since R1 doesn't have a valid pointer type".
    struct bpf_insn doc_bad_ptr_xadd[] = {
        BPF_MOV64_IMM(BPF_REG_1, 1),
        BPF_MOV64_IMM(BPF_REG_2, 2),
        ((struct bpf_insn){.code = BPF_STX | BPF_W | BPF_ATOMIC,
                           .dst_reg = BPF_REG_1, .src_reg = BPF_REG_2,
                           .off = 3, .imm = BPF_ADD}),
        BPF_EXIT_INSN(),
    };

    run_one("doc_unreadable_reg", doc_unreadable_reg,
            (int)(sizeof(doc_unreadable_reg) / sizeof(doc_unreadable_reg[0])));
    run_one("doc_callee_saved_r6", doc_callee_saved_r6,
            (int)(sizeof(doc_callee_saved_r6) / sizeof(doc_callee_saved_r6[0])));
    run_one("doc_bad_ptr_xadd", doc_bad_ptr_xadd,
            (int)(sizeof(doc_bad_ptr_xadd) / sizeof(doc_bad_ptr_xadd[0])));
}

// ---------------------------------------------------------------------------
// DOCUMENTED-BEHAVIOUR CASES, part 2 — the "Understanding eBPF verifier
// messages" section (verifier.rst:353-560).
//
// These 11 programs differ from the prose examples above in a way that matters:
// the document prints them ALREADY in `BPF_*` macro form — the same macros this
// harness uses — so getting them in here is transcription, not translation
// judgement. Each also carries its exact expected error string, anchored by
// `DocumentedCase::expected_error` on the Rust side. All 11 are programs the
// verifier MUST reject, so they test the verifier's SOUNDNESS: an accept here is
// a real finding, not a documentation quibble.
//
// Three places where the document leaves something implicit and a choice had to
// be made. Each is a reviewable judgement, marked JUDGEMENT at its case:
//  (a) The document writes `BPF_LD_MAP_FD(BPF_REG_1, 0)` even in examples whose
//      OWN log shows `r1 = 1` (i.e. captured with a real map). fd 0 fails at
//      pseudo-ldimm64 resolution — before the condition the case is about — so
//      those cases get a real map. The one case that IS about fd 0 keeps 0.
//  (b) The document never states the map's value_size. 16 is used so the
//      documented offsets (`off 4 size 8`) are in bounds and the case reaches the
//      condition it is about instead of failing the bounds check first.
//  (c) Two cases call socket helpers, which a socket filter cannot call at all,
//      and one is about alignment, which x86 skips unless strict alignment is
//      requested. Both are stated per case.
// ---------------------------------------------------------------------------

// An ARRAY map big enough for every documented offset in the section (b).
static int make_doc_map(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 16;
    m.max_entries = 1;
    return bpf(BPF_MAP_CREATE, &m, sizeof(m));
}

static void run_documented_message_cases(void) {
    // verifier.rst:356 — "Program with unreachable instructions" -> `unreachable insn 1`
    struct bpf_insn doc_msg_unreachable_insn[] = {
        BPF_EXIT_INSN(),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_unreachable_insn", doc_msg_unreachable_insn,
            (int)(sizeof(doc_msg_unreachable_insn) / sizeof(doc_msg_unreachable_insn[0])));

    // verifier.rst:367 — "Program that reads uninitialized register" -> `R2 !read_ok`.
    // This is the SAME program as the prose example above (doc_unreadable_reg);
    // it is not duplicated here — the prose case carries the error string instead.

    // verifier.rst:377 — "Program that doesn't initialize R0 before exiting"
    //   -> `R0 !read_ok`
    struct bpf_insn doc_msg_uninit_r0_exit[] = {
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_uninit_r0_exit", doc_msg_uninit_r0_exit,
            (int)(sizeof(doc_msg_uninit_r0_exit) / sizeof(doc_msg_uninit_r0_exit[0])));

    // verifier.rst:388 — "Program that accesses stack out of bounds"
    //   -> `invalid stack off=8 size=8`
    struct bpf_insn doc_msg_stack_oob[] = {
        BPF_ST_MEM(BPF_DW, BPF_REG_10, 8, 0),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_stack_oob", doc_msg_stack_oob,
            (int)(sizeof(doc_msg_stack_oob) / sizeof(doc_msg_stack_oob[0])));

    int map_fd = make_doc_map();
    if (map_fd < 0) {
        // Say so instead of silently skipping: a missing denominator must be
        // visible, not look like a clean run.
        printf("===PROG doc_msg_map_cases type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
    } else {
        // verifier.rst:398 — "Program that doesn't initialize stack before passing
        //   its address into function" -> `invalid indirect read from stack off -8+0 size 8`
        // JUDGEMENT (a): real map fd; with the document's literal fd 0 the load
        // would fail at map resolution and never reach the uninitialized-stack check.
        struct bpf_insn doc_msg_uninit_stack_arg[] = {
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_EXIT_INSN(),
        };
        run_one("doc_msg_uninit_stack_arg", doc_msg_uninit_stack_arg,
                (int)(sizeof(doc_msg_uninit_stack_arg) / sizeof(doc_msg_uninit_stack_arg[0])));

        // verifier.rst:432 — "Program that doesn't check return value of
        //   map_lookup_elem() before accessing map element"
        //   -> `R0 invalid mem access 'map_value_or_null'`
        struct bpf_insn doc_msg_unchecked_map_value[] = {
            BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("doc_msg_unchecked_map_value", doc_msg_unchecked_map_value,
                (int)(sizeof(doc_msg_unchecked_map_value) / sizeof(doc_msg_unchecked_map_value[0])));

        // verifier.rst:453 — "checks for NULL, but accesses the memory with
        //   incorrect alignment" -> `misaligned access off 4 size 8`
        // JUDGEMENT (c): x86_64 has efficient unaligned access, so the verifier
        // skips this check unless the load asks for it. BPF_F_STRICT_ALIGNMENT is
        // what makes the documented condition reachable at all on this arch;
        // without it the program is legitimately accepted here and the document's
        // claim simply does not apply.
        struct bpf_insn doc_msg_misaligned_value[] = {
            BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 4, 0),
            BPF_EXIT_INSN(),
        };
        run_one_ex("doc_msg_misaligned_value", doc_msg_misaligned_value,
                   (int)(sizeof(doc_msg_misaligned_value) / sizeof(doc_msg_misaligned_value[0])),
                   BPF_PROG_TYPE_SOCKET_FILTER, "socket_filter", BPF_F_STRICT_ALIGNMENT);

        // verifier.rst:477 — "accesses memory with correct alignment in one side of
        //   'if' branch, but fails to do so in the other" -> `R0 invalid mem access 'imm'`
        struct bpf_insn doc_msg_branch_imm_deref[] = {
            BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
            BPF_EXIT_INSN(),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 1),
            BPF_EXIT_INSN(),
        };
        run_one("doc_msg_branch_imm_deref", doc_msg_branch_imm_deref,
                (int)(sizeof(doc_msg_branch_imm_deref) / sizeof(doc_msg_branch_imm_deref[0])));

        close(map_fd);
    }

    // verifier.rst:414 — "Program that uses invalid map_fd=0 while calling to
    //   map_lookup_elem()" -> `fd 0 is not pointing to valid bpf_map`
    // fd 0 is kept deliberately: here the invalid fd IS the documented condition.
    struct bpf_insn doc_msg_invalid_map_fd[] = {
        BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_LD_MAP_FD(BPF_REG_1, 0),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_invalid_map_fd", doc_msg_invalid_map_fd,
            (int)(sizeof(doc_msg_invalid_map_fd) / sizeof(doc_msg_invalid_map_fd[0])));

    // verifier.rst:508 / :536 — the two socket-lookup cases
    //   -> `Unreleased reference id=1, alloc_insn=7` (both)
    // JUDGEMENT (c): bpf_sk_lookup_tcp is not callable from a socket filter, so
    // these run as BPF_PROG_TYPE_SCHED_CLS — the classic tc program type these
    // examples come from. The program text itself is the document's, unchanged.
    struct bpf_insn doc_msg_unreleased_ref_null[] = {
        BPF_MOV64_IMM(BPF_REG_2, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -8),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_MOV64_IMM(BPF_REG_3, 4),
        BPF_MOV64_IMM(BPF_REG_4, 0),
        BPF_MOV64_IMM(BPF_REG_5, 0),
        BPF_EMIT_CALL(BPF_FUNC_sk_lookup_tcp),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    run_one_ex("doc_msg_unreleased_ref_null", doc_msg_unreleased_ref_null,
               (int)(sizeof(doc_msg_unreleased_ref_null) / sizeof(doc_msg_unreleased_ref_null[0])),
               BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);

    struct bpf_insn doc_msg_unreleased_ref_nocheck[] = {
        BPF_MOV64_IMM(BPF_REG_2, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -8),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_MOV64_IMM(BPF_REG_3, 4),
        BPF_MOV64_IMM(BPF_REG_4, 0),
        BPF_MOV64_IMM(BPF_REG_5, 0),
        BPF_EMIT_CALL(BPF_FUNC_sk_lookup_tcp),
        BPF_EXIT_INSN(),
    };
    run_one_ex("doc_msg_unreleased_ref_nocheck", doc_msg_unreleased_ref_nocheck,
               (int)(sizeof(doc_msg_unreleased_ref_nocheck) / sizeof(doc_msg_unreleased_ref_nocheck[0])),
               BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);
}

// ===========================================================================
// TARGETED GENERATION (devlog 0025) — aim the input budget, do not sprinkle it.
//
// Reviewer's diagnosis (2026-09-01): bug hunting = oracle x input. The oracle side
// has three calibrated legs; the input side is ~241 programs total because KVM is
// blocked and everything runs on TCG. Random volume cannot fix that at this scale —
// 279 blocks of syzkaller corpus never produced six of the error classes eleven
// hand-written programs produced in one run. So the input budget gets AIMED.
//
// WHAT IT IS AIMED AT, and why exactly this: the ONE detector leg that needs no
// external ground truth is the intrinsic-invariant leg — it checks the verifier
// against ITSELF (tnum well-formedness, bound ordering, and tnum-vs-bounds
// agreement). That leg can only fire on registers whose abstract state is actually
// interesting: partially-known bits AND narrowed bounds at the same time. Programs
// like that do not appear by accident in a syscall fuzzer's corpus; they have to be
// constructed. This generator constructs them, and nothing else.
//
// NOT RANDOM, ENUMERATIVE. With a few hundred executions to spend, sampling a space
// wastes the budget. Every (alu op x compare x width) combination is emitted exactly
// once, so the cross-product is COVERED rather than sampled, and program N is the
// same program on every run — a finding is reproducible from its label alone.
//
// The skeleton is fixed and every part of it is load-bearing:
//
//   0: r0 = *(u32 *)(r1 + 0)   unknown scalar from ctx -> full 32-bit range
//   1: <alu op1>               shapes the tnum (and/or/xor/shifts) or the bounds
//                              (add/sub/mul/div/mod) -- the two are tracked by
//                              DIFFERENT verifier code paths
//   2: if r0 <cmp> imm goto 5  narrows bounds on both branches; back-propagating a
//                              comparison into the tnum is where the two trackers
//                              must agree
//   3: <alu op2>               arithmetic on the narrowed value (not-taken path)
//   4: goto 6
//   5: <alu op2'>              arithmetic on the OTHER narrowing (taken path)
//   6: r0 &= 0xffff            bound the return value
//   7: exit                    -> insn 6 is a MERGE point: two different abstract
//                              states join, which is where a range desync would show
//
// A 32-bit variant of each program uses BPF_ALU32/BPF_JMP32, because the verifier
// keeps u32_min/u32_max separately from the 64-bit bounds and has to reconcile them.
// That reconciliation is historically the densest source of verifier range bugs.
// ===========================================================================

struct gen_alu {
    const char *name;
    int op;
    int imm1;   // shaping immediate
    int imm2;   // not-taken path immediate
    int imm3;   // taken path immediate
};

// Mixed on purpose: bitwise ops move the tnum and leave the bounds to be deduced;
// arithmetic ops move the bounds and leave the tnum to be deduced. The interesting
// states come from chaining one kind after the other.
static const struct gen_alu GEN_ALU[] = {
    {"and",  BPF_AND,  0x0f0f, 0x00ff, 0xff00},
    {"or",   BPF_OR,   0x00f0, 0x0003, 0x1000},
    {"xor",  BPF_XOR,  0xff00, 0x0f0f, 0x00f0},
    {"lsh",  BPF_LSH,       5,      3,      9},
    {"rsh",  BPF_RSH,       3,      7,      2},
    {"arsh", BPF_ARSH,      7,      2,     11},
    {"add",  BPF_ADD,   0x100,   0x40,   -17},
    {"sub",  BPF_SUB,    0x40,     23,   -64},
    {"mul",  BPF_MUL,      12,      3,      7},
    {"div",  BPF_DIV,       7,      3,      5},
    {"mod",  BPF_MOD,       9,     16,      6},
};

// Every compare form, signed and unsigned, plus JSET (the only one that narrows
// BITS rather than a range — so it is the compare most likely to disagree with the
// bounds tracker).
struct gen_cmp {
    const char *name;
    int op;
    int imm;
};
static const struct gen_cmp GEN_CMP[] = {
    {"jeq",  BPF_JEQ,   64},
    {"jne",  BPF_JNE,   64},
    {"jgt",  BPF_JGT,  100},
    {"jge",  BPF_JGE,  100},
    {"jlt",  BPF_JLT,  100},
    {"jle",  BPF_JLE,  100},
    {"jsgt", BPF_JSGT,  -5},
    {"jsge", BPF_JSGE,  -5},
    {"jslt", BPF_JSLT,  -5},
    {"jsle", BPF_JSLE,  -5},
    {"jset", BPF_JSET, 0x10},
};

#define GEN_ALU_N ((int)(sizeof(GEN_ALU) / sizeof(GEN_ALU[0])))
#define GEN_CMP_N ((int)(sizeof(GEN_CMP) / sizeof(GEN_CMP[0])))

// Emit one program of the family. `w32` selects the subregister variant.
static void run_generated(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[8];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    if (w32) {
        insns[1] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
    } else {
        insns[1] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
    }
    insns[4] = BPF_JMP_A(1);
    insns[6] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[7] = BPF_EXIT_INSN();

    // The label IS the recipe: it names the exact program, so any finding can be
    // rebuilt from the report without consulting a seed or a corpus file.
    char name[64];
    snprintf(name, sizeof(name), "gen#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 8);
}

// The whole enumerated family: every alu x compare x width, once each.
static void run_generated_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// MIXED-WIDTH FAMILY (devlog 0026) — aimed at the 32<->64 reconciliation.
//
// OI-9 named the blind spot the first family had by construction: every program in
// it was purely 64-bit or purely 32-bit, so the verifier's two views of a scalar
// always agreed and it printed them as ONE shared token (`umax=umax32=255`). Two
// views that are literally the same token cannot be caught disagreeing — measured:
// the 242-program family scored 0 on the 32<->64 denominator.
//
// The verifier keeps u32_min/u32_max/s32_min/s32_max separately from the 64-bit
// bounds and reconciles them in reg_bounds_sync() (__reg32_deduce_bounds /
// __reg64_deduce_bounds). Historically that reconciliation is the densest source of
// verifier range bugs. To reach it, the two views have to be forced APART inside one
// program, which needs a width CHANGE mid-program:
//
//   * a 32-bit ALU op writes the low half and ZEROES the upper half, so whatever
//     64-bit knowledge existed is discarded and must be rebuilt from the 32-bit view
//   * a 32-bit compare narrows only the 32-bit view, and the 64-bit view has to be
//     re-derived from it (and vice versa for a 64-bit compare after a 32-bit op)
//   * a sign-extending move (movsx) propagates the low half's sign into the upper
//     half, which is the one operation that ties the two views together arithmetically
//
// Three sub-families, each enumerated in full:
//   64->32  : shape 64-bit, then 32-bit op, then 32-bit compare   (121 programs)
//   32->64  : shape 32-bit, then 64-bit op, then 64-bit compare   (121 programs)
//   movsx   : shape 32-bit, sign-extend from 8/16/32, then signed
//             64-bit compare                                       (33 programs)
// ===========================================================================

// Sign-extending move, `r0 = (sN)r0`. Not in the classic macro set because it
// postdates it: BPF_MOV with a non-zero off is movsx (N = 8, 16 or 32).
#define BPF_MOVSX64_REG(DST, SRC, SZ)                                          \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                    \
                       .dst_reg = DST, .src_reg = SRC, .off = SZ, .imm = 0})

// One program of the 64->32 or 32->64 sub-family. `wide_first` selects which view
// gets shaped first; the compare always follows the SECOND op's width, so the
// narrowing lands on the view the preceding op did not just rebuild.
static void run_mixed(int alu_i, int cmp_i, int wide_first, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[9];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    if (wide_first) {
        insns[1] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[3] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[4] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
    } else {
        insns[1] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[3] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[4] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
    }
    insns[5] = BPF_JMP_A(1);
    insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[8] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "mix#%s.%s.%s#%03d",
             wide_first ? "64-32" : "32-64", a->name, c->name, index);
    run_one(name, insns, 9);
}

// One program of the movsx sub-family: shape the low bits, sign-extend them into
// the upper half, then compare SIGNED 64-bit — the compare's outcome now depends on
// bits the 32-bit view produced.
static void run_movsx(int sz, int cmp_i, int index) {
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[9];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    insns[1] = BPF_ALU32_IMM(BPF_OR, BPF_REG_0, 0x80);   // make the sign bits reachable
    insns[2] = BPF_MOVSX64_REG(BPF_REG_0, BPF_REG_0, sz);
    insns[3] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
    insns[4] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 7);
    insns[5] = BPF_JMP_A(1);
    insns[6] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, 3);
    insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[8] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "mix#movsx%d.%s#%03d", sz, c->name, index);
    run_one(name, insns, 9);
}

// The shape that actually forces the two views apart on a well-synced verifier:
// shift the unknown bits into the UPPER half, then narrow only the LOWER one.
//
// Measured first, then written (0026): the 64->32 / 32->64 orderings above scored
// 152 independent views on the older host kernel but only 4 on bpf-next, because
// bpf-next's deduction reconciles the two views almost perfectly whenever the value
// fits in one 2^32 block — and a ctx u32 load always does. `r0 <<= 32` breaks that:
// the 64-bit range then spans many blocks (so the 64-bit endpoints constrain the low
// half not at all) while a 32-bit compare still pins the low half exactly. That is
// precisely the state where the two views must be independently maintained.
//
// Note a BPF property that rules out the obvious alternative: every 32-bit ALU op
// zero-extends into the upper half, so the low half cannot be edited while keeping
// the upper half unknown. The shaping has to be 64-bit; only the COMPARE is 32-bit.
static void run_upper_half(int alu_i, int cmp_i, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[9];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    insns[1] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 32);   // unknown bits -> upper half
    insns[2] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
    insns[3] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
    insns[4] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
    insns[5] = BPF_JMP_A(1);
    insns[6] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
    insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[8] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "mix#hi.%s.%s#%03d", a->name, c->name, index);
    run_one(name, insns, 9);
}

static void run_mixed_family(void) {
    int index = 0;
    for (int wide_first = 1; wide_first >= 0; wide_first--)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_mixed(alu_i, cmp_i, wide_first, index++);
    static const int SIZES[] = {8, 16, 32};
    for (int i = 0; i < 3; i++)
        for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
            run_movsx(SIZES[i], cmp_i, index++);
    for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
        for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
            run_upper_half(alu_i, cmp_i, index++);
}

// ===========================================================================
// REGISTER-TO-REGISTER FAMILY (OI-9 next increment) — the classic --gen family
// combines a ranged register with a CONSTANT (BPF_K). The verifier takes a
// DIFFERENT path when both operands are registers carrying their own abstract
// state: scalar_min_max_* / reg_bounds_sync over two non-const scalars, and a
// reg-reg branch that back-propagates the narrowing onto BOTH registers. That path
// is historically the densest range-bug surface and the imm family never touches it.
//
// Two INDEPENDENT unknowns (separate ctx loads at r1+0 and r1+4) so the op is a
// genuine two-range combination, not a linked-reg tautology (mirrors the
// constant-tautology exclusion in the denominator). Both are shaped before they
// meet, so each carries partially-known bits AND a narrowed range — exactly the
// state the intrinsic tnum-vs-bounds leg needs to fire.
//
//   0: r0 = *(u32*)(r1+0)     unknown A
//   1: r6 = *(u32*)(r1+4)     unknown B (independent of A)
//   2: r6 <op> imm1           shape B (still non-constant)
//   3: r0 <op> imm1           shape A
//   4: if r0 <cmp> r6 goto 7  REG-REG compare -> narrows BOTH, differently per path
//   5: r0 <op> r6             REG-REG alu on the not-taken (fall-through) state
//   6: goto 8
//   7: r0 <op> r6             REG-REG alu on the taken state (same op, narrowed inputs)
//   8: r0 &= 0xffff           bound the return value
//   9: exit                   insn 8 MERGES the two reg-reg-combined states
//
// Bonus surfaces the imm family cannot reach: div/mod by a register whose range may
// include 0, and variable-amount shifts (shift by a register).
// ===========================================================================
static void run_generated_rr(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[10];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1, 4);
    if (w32) {
        insns[2] = BPF_ALU32_IMM(a->op, BPF_REG_6, a->imm1);
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[4] = BPF_JMP32_REG(c->op, BPF_REG_0, BPF_REG_6, 2);
        insns[5] = BPF_ALU32_REG(a->op, BPF_REG_0, BPF_REG_6);
        insns[7] = BPF_ALU32_REG(a->op, BPF_REG_0, BPF_REG_6);
    } else {
        insns[2] = BPF_ALU64_IMM(a->op, BPF_REG_6, a->imm1);
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[4] = BPF_JMP_REG(c->op, BPF_REG_0, BPF_REG_6, 2);
        insns[5] = BPF_ALU64_REG(a->op, BPF_REG_0, BPF_REG_6);
        insns[7] = BPF_ALU64_REG(a->op, BPF_REG_0, BPF_REG_6);
    }
    insns[6] = BPF_JMP_A(1);
    insns[8] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[9] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genrr#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 10);
}

// Every alu x compare x width, once each — same enumeration shape as --gen so a
// finding is reproducible from its label alone.
static void run_generated_rr_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_rr(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// MULTI-BRANCH FAMILY (OI-9 next increment) — the --gen / --gen-rr families each
// have exactly ONE compare and ONE merge point. The verifier's state-merge logic
// (states_equal / regsafe / reg_bounds_sync at a join) is exercised once per
// program. A program with TWO sequential branches has TWO merge points, and the
// SECOND branch narrows a register whose abstract state is itself the JOIN of the
// first branch's two paths. That is a different surface: bounds/tnum must survive
// branch -> merge -> branch -> merge, and a desync introduced at merge 1 gets a
// second chance to surface (or to be masked) at branch 2 and merge 2.
//
//   0:  r0 = *(u32*)(r1+0)      unknown scalar
//   1:  r0 <op> imm1            shape it (tnum and/or bounds)
//   2:  if r0 <cmp> imm_a goto 5   BRANCH 1
//   3:  r0 <op> imm2            not-taken-1 arithmetic
//   4:  goto 6
//   5:  r0 <op> imm3            taken-1 arithmetic
//   6:  [MERGE 1] if r0 <cmp> imm_b goto 9   BRANCH 2, on the merged state
//   7:  r0 <op> imm2            not-taken-2
//   8:  goto 10
//   9:  r0 <op> imm3            taken-2
//   10: [MERGE 2] r0 &= 0xffff   bound the return value
//   11: exit
//
// imm_a = c->imm (first threshold), imm_b = a->imm2 (a DIFFERENT constant, so the
// second branch is a genuine second narrowing, not a trivially-decided repeat of the
// first). Both derive from the enumerated (alu, cmp) pair, so the label alone rebuilds
// the exact program -- same reproducible-from-recipe contract as the other families.
// All-accepted by construction (same valid ops as --gen, just chained), so the
// tnum-vs-bounds denominator stays clean.
// ===========================================================================
static void run_generated_mb(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[12];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    if (w32) {
        insns[1] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_JMP32_IMM(c->op, BPF_REG_0, a->imm2, 2);
        insns[7] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[9] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
    } else {
        insns[1] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_JMP_IMM(c->op, BPF_REG_0, a->imm2, 2);
        insns[7] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[9] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
    }
    insns[4]  = BPF_JMP_A(1);
    insns[8]  = BPF_JMP_A(1);
    insns[10] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[11] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genmb#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 12);
}

// Every alu x compare x width, once each -- same enumeration shape as --gen so a
// finding is reproducible from its label alone.
static void run_generated_mb_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_mb(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// POINTER-ARITHMETIC FAMILY (OI-9 next increment) — the scalar families
// (--gen / --gen-rr / --gen-mb / --gen-mix) only ever combine SCALARS. This one
// aims the verifier's POINTER-safety decision: it takes a real PTR_TO_MAP_VALUE
// (from a bpf_map_lookup_elem on a 64-byte ARRAY value), adds a shaped+narrowed
// scalar offset to it, and then STORES through the adjusted pointer. The store is
// where the verifier decides "is this pointer access in bounds" (check_mem_access /
// adjust_ptr_min_max_vals / sanitize bounds). A logic bug here is not an OOB read of
// a log string (cf. F1) but a wrongly-ACCEPTED out-of-bounds WRITE — higher severity
// and a historically dense bug region, which is why this leg is flagged highest-EV.
//
//   0: *(u32*)(r10-4) = 0        key on stack
//   1: r2 = r10   2: r2 += -4     r2 = &key
//   3: r1 = map_fd (LD_MAP_FD, slots 3-4)
//   5: call bpf_map_lookup_elem   r0 = PTR_TO_MAP_VALUE_OR_NULL (value_size=64)
//   6: if r0 == 0 goto 15         mandatory null-check
//   7: r1 = *(u32*)(r0+0)         unknown scalar offset (read from the value)
//   8: r1 <alu> imm1              shape it (tnum and/or bounds)
//   9: if r1 <cmp> imm goto 12    narrow r1 differently on each path
//  10: r1 <alu> imm2  11: goto 13  (not-taken)      12: r1 <alu> imm3 (taken)
//  13: r0 += r1                    POINTER ARITHMETIC: map_value_ptr += scalar
//  14: *(u8*)(r0+0) = r1           STORE through the adjusted ptr -> the bounds check
//  15: r0 = 0   16: exit
//
// This family is NOT all-accepted by construction: acceptance depends on whether the
// verifier can prove the offset stays within value_size, which is exactly the
// decision under test. A mix of accept/reject is the point. Rejected programs still
// print their register state up to the faulting insn, so the intrinsic tnum-vs-bounds
// leg still has the shaped scalar (and the pointer's own var_off) to examine.
// First increment writes a 1-byte store (r1's low byte); wider stores are a follow-up.
// ===========================================================================
static void run_generated_ptr(int alu_i, int cmp_i, int w32, int index, int map_fd) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[17];
    insns[0] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    insns[1] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    insns[2] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    insns[3] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    insns[4] = (struct bpf_insn){0};
    insns[5] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    insns[6] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8);       /* null -> insn 15 */
    insns[7] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
    if (w32) {
        insns[8]  = BPF_ALU32_IMM(a->op, BPF_REG_1, a->imm1);
        insns[9]  = BPF_JMP32_IMM(c->op, BPF_REG_1, c->imm, 2);  /* taken -> insn 12 */
        insns[10] = BPF_ALU32_IMM(a->op, BPF_REG_1, a->imm2);
        insns[12] = BPF_ALU32_IMM(a->op, BPF_REG_1, a->imm3);
    } else {
        insns[8]  = BPF_ALU64_IMM(a->op, BPF_REG_1, a->imm1);
        insns[9]  = BPF_JMP_IMM(c->op, BPF_REG_1, c->imm, 2);
        insns[10] = BPF_ALU64_IMM(a->op, BPF_REG_1, a->imm2);
        insns[12] = BPF_ALU64_IMM(a->op, BPF_REG_1, a->imm3);
    }
    insns[11] = BPF_JMP_A(1);                               /* -> insn 13 */
    insns[13] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);  /* ptr += scalar */
    insns[14] = BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0);   /* store through ptr */
    insns[15] = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[16] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genptr#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 17);
}

// Create the value_size=64 ARRAY map once, then every alu x compare x width, once
// each -- same enumeration/label contract as the scalar families.
static void run_generated_ptr_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 64;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genptr type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_ptr(alu_i, cmp_i, w32, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// NEGATIVE-OFFSET MAP-VALUE FAMILY (T1-2) — the --gen-ptr family adds a POSITIVE
// bounded scalar to a map_value pointer, so the deciding check is the UPPER bound
// (umax + size <= value_size). The other, historically bug-prone edge is the LOWER
// bound: an offset whose signed minimum can go NEGATIVE, which would read/write BELOW
// the start of the map value. The kernel guards it with a distinct check
// (`check_map_access`: "R%d min value is negative, either use unsigned index or do a
// if (index >=0) check"). Historically that smin path has been skipped/mis-derived,
// which would ACCEPT an out-of-bounds-BELOW write — the severe class.
//
// The offset is pushed negative deterministically: mask to [0,15], then SUBTRACT a
// constant C so the signed window becomes [-C, 15-C] (smin = -C). Two forms:
//   raw  — no guard. If smin<0 the store MUST be rejected. A raw C>0 that ACCEPTS a
//          live store is the bug this leg hunts.
//   grd  — a signed guard `if (r1 s< 0) goto skip_store` before the arith. On the
//          store path the verifier must re-derive smin>=0 and ACCEPT (proving it is
//          not merely over-rejecting everything negative). Tests smin re-derivation
//          after a signed branch, the exact code path.
//
//   ... r1 = *(u32*)(r0+0);  r1 &= 15;  r1 -= C;   [grd: if r1 s<0 goto skip]
//       r0 += r1;  *(uW*)(r0+off) = r1;  skip: r0 = 0; exit
//
// Decision is a pure function of the instruction stream (load-time), same contract as
// --gen-ptr. Reject REASON (negative-min vs value_size) is read from the log to tell
// the lower-bound path from the upper-bound one.
// ===========================================================================
static const int PTRNEG_C[] = {0, 1, 2, 4, 8, 16, 24, 32, 48, 64};
#define PTRNEG_C_N ((int)(sizeof(PTRNEG_C) / sizeof(PTRNEG_C[0])))
static const struct { int off; int w; } PTRNEG_REACH[] = {
    {0, 1}, {0, 4}, {44, 4}, {48, 1}, {49, 1}, {48, 4}, /* last three cross value_size=64 */
};
#define PTRNEG_REACH_N ((int)(sizeof(PTRNEG_REACH) / sizeof(PTRNEG_REACH[0])))

static void run_generated_ptrneg(int form, int c_i, int reach_i, int index, int map_fd) {
    const int grd = (form == 1);
    const int C = PTRNEG_C[c_i];
    const int off = PTRNEG_REACH[reach_i].off;
    const int W = PTRNEG_REACH[reach_i].w;
    const int szmode = (W == 1) ? BPF_B : (W == 2) ? BPF_H : BPF_W;

    struct bpf_insn ins[16];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};                              /* LD_DW upper half */
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);   /* patched */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);       /* unknown [0,2^32-1] */
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 15);            /* -> [0,15] */
    ins[n++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, C);            /* -> smin = -C */
    int jguard = -1;
    if (grd) { jguard = n; ins[n++] = BPF_JMP_IMM(BPF_JSLT, BPF_REG_1, 0, 0); } /* patched */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);      /* ptr += offset */
    ins[n++] = BPF_STX_MEM(szmode, BPF_REG_0, BPF_REG_1, off);    /* store through ptr */
    const int exitprep = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();

    ins[jnull].off = exitprep - jnull - 1;                        /* null -> r0=0 */
    if (grd) ins[jguard].off = exitprep - jguard - 1;            /* negative -> skip store */

    char name[80];
    snprintf(name, sizeof(name), "genptrneg#%s.C%d.o%d.w%d#%03d",
             grd ? "grd" : "raw", C, off, W, index);
    run_one(name, ins, n);
}

static void run_generated_ptrneg_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 64;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genptrneg type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int form = 0; form < 2; form++)
        for (int c_i = 0; c_i < PTRNEG_C_N; c_i++)
            for (int reach_i = 0; reach_i < PTRNEG_REACH_N; reach_i++)
                run_generated_ptrneg(form, c_i, reach_i, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// T1-1 SETUP PROBE — three hand-built programs, one per claim, to decide the family
// construction from MEASUREMENT (per-program reg32_checked + reject message), not
// from reading the kernel. Each is loaded against a value_size=64 map, same as --gen-ptr.
//   probe#naiveA : w1 &= 0x3f (32-bit ALU zero-extends) then r0 += r1. Claim: reg32=0
//                  (the two views coincide -> the 0025 payda-zero trap).
//   probe#hi     : r1 upper-unknown (<<32 | second load), then a 32-bit compare narrows
//                  ONLY the low half; then r0 += r1. Claim: reg32>0 (32-tight/64-loose),
//                  and the pointer add must REJECT (accept = the bug).
//   probe#ptr32  : w0 += w1 (32-bit ALU on the pointer). Claim: "32-bit pointer
//                  arithmetic prohibited" EACCES, never reaching bounds logic.
// ===========================================================================
static void run_probe_t1_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG probe type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    struct bpf_insn ld1 = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    struct bpf_insn ld2 = (struct bpf_insn){0};

    /* probe#naiveA -- 32-bit AND zero-extends; r0 += r1. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld2,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),          /* null -> r0=0 */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
            BPF_ALU32_IMM(BPF_AND, BPF_REG_1, 0x3f),        /* 32-bit AND -> zext [0,0x3f] */
            BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),   /* ptr += bounded scalar */
            BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("probe#naiveA#000", p, (int)(sizeof(p) / sizeof(p[0])));
    }

    /* probe#hi -- upper-unknown offset, 32-bit compare narrows only the low half. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld2,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),          /* null -> r0=0 */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),    /* low unknown */
            BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),          /* unknown -> UPPER 32 */
            BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4),    /* second unknown, low 32 */
            BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8),    /* -> full 64-bit unknown */
            BPF_JMP32_IMM(BPF_JGE, BPF_REG_1, 0x40, 2),     /* if w1>=64 skip: narrows LOW only */
            BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),   /* ptr += (umax huge) -> must reject */
            BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("probe#hi#001", p, (int)(sizeof(p) / sizeof(p[0])));
    }

    /* probe#ptr32 -- 32-bit ALU directly on the pointer. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld2,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3),          /* null -> r0=0 */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
            BPF_ALU32_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),   /* 32-bit ALU on pointer -> prohibited */
            BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("probe#ptr32#002", p, (int)(sizeof(p) / sizeof(p[0])));
    }
    close(map_fd);
}

// ===========================================================================
// 32<->64 x POINTER-OFFSET FAMILY (T1-1a) — the upper-unknown soundness probe.
// The probe above settled the construction from measurement: a 32-bit-shaped offset
// zero-extends (views coincide, reg32=0, the 0025 trap), and 32-bit ALU on a pointer
// is prohibited outright (Option B). Only the "hi" construction reaches the 32-tight/
// 64-loose surface (reg32>0). Two arms:
//
//   hi  (soundness, ~3/4): the offset has its UPPER 32 bits unknown while a 32-bit
//        compare narrows ONLY the low half. Its 64-bit smin is S64_MIN / umax ~ U64_MAX,
//        so adjust_ptr_min_max_vals (verifier.c:14665, check_reg_sane_offset_scalar on
//        the 64-bit bounds) MUST reject at `r0 += r1`. reg32>0 proves the independent
//        32-view formed; any ACCEPT is the bug. Two constructions (shift-or, u64 load)
//        x 5 low-narrowing compares x 4 thresholds K -- K cannot make it accept (upper
//        stays unknown for every K: mutual exclusivity), the variety is code-path breadth.
//   bnd (control, ~1/4): a 32-bit AND zero-extends to a genuinely 64-bounded offset
//        (reg32=0), which the verifier ACCEPTS when it fits -- proving it is not merely
//        over-rejecting everything 32-bit-shaped.
//
// value_size=64, same map as --gen-ptr. This arm is decision-invariant on the hi side
// (all-reject) BY the mutual-exclusivity theorem (reg32>0 <=> upper-unknown <=> reject);
// its signature is reg32_checked>0 with 0 wrongly-accepted hi programs, NOT an
// accept/reject balance. The discriminating "which view / sync" test is T1-1b (a
// separate oracle arm), not here.
// ===========================================================================
static const struct { const char *name; int op; } HI_CMP[] = {
    {"lt", BPF_JLT}, {"le", BPF_JLE}, {"gt", BPF_JGT}, {"ge", BPF_JGE}, {"set", BPF_JSET},
};
#define HI_CMP_N ((int)(sizeof(HI_CMP) / sizeof(HI_CMP[0])))
static const int HI_K[] = {8, 16, 64, 256};
#define HI_K_N ((int)(sizeof(HI_K) / sizeof(HI_K[0])))
static const int HI_MASK[] = {0x0f, 0x1f, 0x3f};
#define HI_MASK_N ((int)(sizeof(HI_MASK) / sizeof(HI_MASK[0])))
static const struct { int off; int w; } HI_REACH[] = { {0,1}, {0,4}, {8,4}, {48,1} };
#define HI_REACH_N ((int)(sizeof(HI_REACH) / sizeof(HI_REACH[0])))

static struct bpf_insn hi_ld1(int map_fd) {
    return (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                             .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
}

static void run_hi_soundness(int cons, int cmp_i, int k_i, int index, int map_fd) {
    const int K = HI_K[k_i];
    struct bpf_insn ins[18];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = hi_ld1(map_fd); ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    if (cons == 0) {                                    /* shift-or: unknown -> UPPER 32 */
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);
        ins[n++] = BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8);
    } else {                                            /* direct 64-bit unknown load */
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0);
    }
    const int jskip = n;                                /* 32-bit compare narrows LOW only */
    ins[n++] = BPF_JMP32_IMM(HI_CMP[cmp_i].op, BPF_REG_1, K, 0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);   /* umax huge -> must reject */
    ins[n++] = BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0);
    const int exitp = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = exitp - jnull - 1;
    ins[jskip].off = exitp - jskip - 1;

    char name[80];
    snprintf(name, sizeof(name), "genhi#hi.%s.%s.K%d#%03d",
             cons ? "ld" : "so", HI_CMP[cmp_i].name, K, index);
    run_one(name, ins, n);
}

static void run_hi_bounded(int m_i, int r_i, int index, int map_fd) {
    const int mask = HI_MASK[m_i];
    const int off = HI_REACH[r_i].off, W = HI_REACH[r_i].w;
    const int szmode = (W == 1) ? BPF_B : (W == 2) ? BPF_H : BPF_W;
    struct bpf_insn ins[16];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = hi_ld1(map_fd); ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
    ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_1, mask);        /* zext -> 64-bounded [0,mask] */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);
    ins[n++] = BPF_STX_MEM(szmode, BPF_REG_0, BPF_REG_1, off);
    const int exitp = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = exitp - jnull - 1;

    char name[80];
    snprintf(name, sizeof(name), "genhi#bnd.m%d.o%d.w%d#%03d", mask, off, W, index);
    run_one(name, ins, n);
}

static void run_generated_hi_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genhi type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int cons = 0; cons < 2; cons++)
        for (int cmp_i = 0; cmp_i < HI_CMP_N; cmp_i++)
            for (int k_i = 0; k_i < HI_K_N; k_i++)
                run_hi_soundness(cons, cmp_i, k_i, index++, map_fd);
    for (int m_i = 0; m_i < HI_MASK_N; m_i++)
        for (int r_i = 0; r_i < HI_REACH_N; r_i++)
            run_hi_bounded(m_i, r_i, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// T1-1b ORACLE PROBE — does the EXISTING tnum32_bounds_inconsistent invariant (0026,
// diff.rs:652) actually RUN on the register state a CVE-2020-8835-shaped program
// produces, and stay SILENT on this (fixed) kernel? CVE-2020-8835 was a desync: the
// buggy __reg_bound_offset32 clamped the tnum's low-32 to {0} when the compares had
// established u32 in [0x200,0x400] (fix f2d67fec0b43). On a fixed kernel the two agree,
// so the leg must be silent; the probe confirms it also RUNS (reg32_checked>0), i.e. the
// state is genuinely reg32-independent, so a regression WOULD be caught.
//   probe#cve8835 : the commit's own reproducer -- a full-unknown r1 bounded by two
//                   jmp64 compares (into [0x2000000000, 0x4000000000]) then two jmp32
//                   compares (w1 into [0x200,0x400]). 64-bit range spans blocks, u32 is
//                   narrow -> the exact 32-tight/64-loose state where the desync lived.
//   probe#shift   : the <<32|load construction reaching the same independent-view state.
// ===========================================================================
static void run_probe_t1b_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG probe type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    struct bpf_insn ld1 = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    struct bpf_insn ld0 = (struct bpf_insn){0};

    /* probe#cve8835 -- the fix commit's own reproducer shape. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld0,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 11),               /* 6: null -> SKIP(18) */
            BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0),         /* 7: full 64-bit unknown */
            (struct bpf_insn){.code = BPF_LD|BPF_DW|BPF_IMM, .dst_reg = BPF_REG_2, .imm = 0}, /* 8 */
            (struct bpf_insn){.imm = 0x40},                       /* 9: r2 = 0x4000000000 */
            (struct bpf_insn){.code = BPF_LD|BPF_DW|BPF_IMM, .dst_reg = BPF_REG_3, .imm = 0}, /* 10 */
            (struct bpf_insn){.imm = 0x20},                       /* 11: r3 = 0x2000000000 */
            BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_2, 5),        /* 12: r1>umax -> SKIP */
            BPF_JMP_REG(BPF_JLT, BPF_REG_1, BPF_REG_3, 4),        /* 13: r1<umin -> SKIP */
            BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, 0x400, 3),          /* 14: w1>0x400 -> SKIP */
            BPF_JMP32_IMM(BPF_JLT, BPF_REG_1, 0x200, 2),          /* 15: w1<0x200 -> SKIP */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 16: r1 constrained here */
            BPF_EXIT_INSN(),                                      /* 17 */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 18: SKIP */
            BPF_EXIT_INSN(),                                      /* 19 */
        };
        run_one("probe#cve8835#000", p, (int)(sizeof(p) / sizeof(p[0])));
    }

    /* probe#shift -- the <<32|load construction reaching the same independent-view state. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld0,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8),                /* 6: null -> SKIP(15) */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),          /* 7: low unknown */
            BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),               /* 8: -> UPPER 32 */
            BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4),          /* 9: second unknown */
            BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8),          /* 10: full unknown */
            BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, 0x400, 3),          /* 11: w1>0x400 -> SKIP */
            BPF_JMP32_IMM(BPF_JLT, BPF_REG_1, 0x200, 2),          /* 12: w1<0x200 -> SKIP */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 13: constrained here */
            BPF_EXIT_INSN(),                                      /* 14 */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 15: SKIP */
            BPF_EXIT_INSN(),                                      /* 16 */
        };
        run_one("probe#shift#001", p, (int)(sizeof(p) / sizeof(p[0])));
    }
    close(map_fd);
}

// ===========================================================================
// 32<->64 SYNC-FRAGILE FAMILY (T1-1b, first increment) — the discriminating half.
// The --probe-t1b probe confirmed by MEASUREMENT that the existing invariant B
// (tnum32_bounds_inconsistent, diff.rs:652) RUNS on a CVE-2020-8835-shaped state
// (reg32_checked>0) and stays SILENT on this fixed kernel (finding_count=0). So this
// family reuses that proven leg -- NO new oracle -- and enumerates the two VALIDATED
// constructions that drive a register into the 32-tight/64-loose state where a
// reg_bounds_sync desync (the CVE-2020-8835 class) would show as an empty tnum32-vs-u32
// intersection. Each program is an accepting scalar (the desync is a scalar property,
// caught at its source, upstream of any pointer use). Signature: reg32_checked>0 across
// many sync states + 0 divergence (the kernel is sync-consistent); a regression would fire B.
//   gensync#cve : full-unknown r1 -> two jmp64 compares into a multi-block [LO,HI] ->
//                 two jmp32 compares into a low window [KLO,KHI]. The fix commit's own
//                 reproducer shape (f2d67fec0b43), generalized over range and window.
//   gensync#shift : r1 = (unknown<<32)|unknown -> two jmp32 compares narrow the low half.
// Exotic sync paths (ARSH-under-ALU32, movsx, 32-bit div/mod) are a deferred 2nd increment.
// ===========================================================================
static const struct { uint64_t lo, hi; } SYNC_PAIRS[] = {
    {0x2000000000ULL, 0x4000000000ULL},   /* blocks 0x20..0x40 */
    {0x100000000ULL,  0x500000000ULL},    /* blocks 1..5 */
    {0x40000000ULL,   0x2c0000000ULL},    /* block 0 -> block 2 */
    {0x180000000ULL,  0x680000000ULL},    /* block 1 -> block 6 */
};
#define SYNC_PAIRS_N ((int)(sizeof(SYNC_PAIRS) / sizeof(SYNC_PAIRS[0])))
static const struct { int lo, hi; } SYNC_WIN[] = {
    {0x200, 0x400}, {0x10, 0x1000}, {0x100, 0x800}, {0, 0x40},
};
#define SYNC_WIN_N ((int)(sizeof(SYNC_WIN) / sizeof(SYNC_WIN[0])))

static void sync_emit_ld64(struct bpf_insn *ins, int *n, int reg, uint64_t val) {
    ins[(*n)++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
                                    .dst_reg = reg, .imm = (int)(uint32_t)(val & 0xffffffff)};
    ins[(*n)++] = (struct bpf_insn){.imm = (int)(uint32_t)(val >> 32)};
}

static void run_sync_cve(int p_i, int w_i, int index, int map_fd) {
    struct bpf_insn ins[26];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0);         /* full 64-bit unknown */
    sync_emit_ld64(ins, &n, BPF_REG_2, SYNC_PAIRS[p_i].hi);
    sync_emit_ld64(ins, &n, BPF_REG_3, SYNC_PAIRS[p_i].lo);
    const int j1 = n; ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_2, 0);   /* r1>HI */
    const int j2 = n; ins[n++] = BPF_JMP_REG(BPF_JLT, BPF_REG_1, BPF_REG_3, 0);   /* r1<LO */
    const int j3 = n; ins[n++] = BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, SYNC_WIN[w_i].hi, 0); /* w1>KHI */
    const int j4 = n; ins[n++] = BPF_JMP32_IMM(BPF_JLT, BPF_REG_1, SYNC_WIN[w_i].lo, 0); /* w1<KLO */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);                          /* constrained state here */
    ins[n++] = BPF_EXIT_INSN();
    const int skip = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = skip - jnull - 1;
    ins[j1].off = skip - j1 - 1;
    ins[j2].off = skip - j2 - 1;
    ins[j3].off = skip - j3 - 1;
    ins[j4].off = skip - j4 - 1;

    char name[80];
    snprintf(name, sizeof(name), "gensync#cve.p%d.w%d#%03d", p_i, w_i, index);
    run_one(name, ins, n);
}

static void run_sync_shift(int w_i, int pol, int index, int map_fd) {
    const int op_hi = pol ? BPF_JGE : BPF_JGT;
    const int op_lo = pol ? BPF_JLE : BPF_JLT;
    struct bpf_insn ins[20];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);
    ins[n++] = BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8);
    const int j1 = n; ins[n++] = BPF_JMP32_IMM(op_hi, BPF_REG_1, SYNC_WIN[w_i].hi, 0);
    const int j2 = n; ins[n++] = BPF_JMP32_IMM(op_lo, BPF_REG_1, SYNC_WIN[w_i].lo, 0);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);                          /* constrained state here */
    ins[n++] = BPF_EXIT_INSN();
    const int skip = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = skip - jnull - 1;
    ins[j1].off = skip - j1 - 1;
    ins[j2].off = skip - j2 - 1;

    char name[80];
    snprintf(name, sizeof(name), "gensync#shift.w%d.pol%d#%03d", w_i, pol, index);
    run_one(name, ins, n);
}

static void run_generated_sync_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG gensync type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int p_i = 0; p_i < SYNC_PAIRS_N; p_i++)
        for (int w_i = 0; w_i < SYNC_WIN_N; w_i++)
            run_sync_cve(p_i, w_i, index++, map_fd);
    for (int w_i = 0; w_i < SYNC_WIN_N; w_i++)
        for (int pol = 0; pol < 2; pol++)
            run_sync_shift(w_i, pol, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// PACKET-POINTER FAMILY (OI-9 next increment) — the pointer-arith family used a
// PTR_TO_MAP_VALUE, whose bound the verifier KNOWS (value_size). A packet pointer is
// the other kind: the verifier does NOT know where the packet ends. Instead the
// PROGRAM must prove the bound with its own `if (data + N > data_end)` compare, and
// the verifier statically TRACKS that proof as a per-pointer `range`
// (find_good_pkt_pointers, verifier.c) — then checks every packet access against the
// recorded range at load time. Nothing here is runtime: the harness only LOADS, and
// accept/reject is a pure function of the instruction stream, so the deterministic
// enumeration and its denominator carry over unchanged.
//
// The interesting edges live in that range machinery: MAX_PACKET_OFF (0xffff) — a
// larger offset umax gives NO range ("risk of overflow") and the access is rejected —
// and range_right_open (`>` vs `>=`). This is the historically densest packet-bounds
// bug region. socket_filter forbids direct packet access (sk_filter_is_valid_access
// returns false for data/data_end), so this family loads as SCHED_CLS.
//
//   0: r2 = *(u32*)(r1+76)      skb->data     -> PTR_TO_PACKET
//   1: r3 = *(u32*)(r1+80)      skb->data_end -> PTR_TO_PACKET_END
//   2: r4 = *(u32*)(r1+0)       skb->len       unknown scalar offset
//   3: r4 <alu> imm1            shape it
//   4: if r4 <cmp> imm goto 7   narrow it per path
//   5: r4 <alu> imm2  6: goto 8  (not-taken)     7: r4 <alu> imm3 (taken)
//   8: r2 += r4                  PACKET POINTER ARITH: data += bounded scalar
//   9: r5 = r2  10: r5 += 1      end of the intended 1-byte access
//  11: if r5 > r3 goto 13        THE PROGRAM'S OWN BOUNDS CHECK -> verifier sets range
//  12: *(u8*)(r2+0) = r4         STORE through the packet ptr, checked vs range
//  13: r0 = 0   14: exit
//
// Acceptance ~ whether the shaping bounds the offset's umax within MAX_PACKET_OFF so a
// range can be recorded: a genuine accept/reject sweep of exactly that guard. The
// data_end compare is held fixed at `>` (the canonical idiom) in this first increment;
// enumerating it (jgt/jge/jlt/jle -> right-open vs closed) is the natural follow-up.
// ===========================================================================
static void run_generated_pkt(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[15];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* data */
    insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* data_end */
    insns[2] = BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, 0);    /* len: unknown */
    if (w32) {
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_4, a->imm1);
        insns[4] = BPF_JMP32_IMM(c->op, BPF_REG_4, c->imm, 2);  /* taken -> 7 */
        insns[5] = BPF_ALU32_IMM(a->op, BPF_REG_4, a->imm2);
        insns[7] = BPF_ALU32_IMM(a->op, BPF_REG_4, a->imm3);
    } else {
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_4, a->imm1);
        insns[4] = BPF_JMP_IMM(c->op, BPF_REG_4, c->imm, 2);
        insns[5] = BPF_ALU64_IMM(a->op, BPF_REG_4, a->imm2);
        insns[7] = BPF_ALU64_IMM(a->op, BPF_REG_4, a->imm3);
    }
    insns[6]  = BPF_JMP_A(1);                                   /* -> 8 */
    insns[8]  = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_4);   /* pkt += scalar */
    insns[9]  = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
    insns[10] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 1);
    insns[11] = BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 1);   /* OOB -> 13 */
    insns[12] = BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_4, 0);    /* store via pkt */
    insns[13] = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[14] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genpkt#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one_ex(name, insns, 15, BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);
}

// Every alu x compare x width, once each -- same enumeration/label contract.
static void run_generated_pkt_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_pkt(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// PACKET data_end COMPARE-OPERATOR SWEEP (T1-3) — the --gen-pkt family held the
// program's own bounds check fixed at `>` (BPF_JGT), the canonical idiom. That
// operator is exactly where the packet-bounds machinery has been historically wrong:
// `find_good_pkt_pointers` records a per-pointer `range` from the compare, and whether
// the range's right endpoint is CLOSED (`>`, `<`) or RIGHT-OPEN (`>=`, `<=`) shifts the
// last provable byte by one. An off-by-one here means the verifier proves ONE BYTE MORE
// (or fewer) than the program actually checked — a real OOB-write accept if it errs high.
//
// This sweep pins the offset shaping to a small known scalar and varies ONLY the range
// machinery, over two orthogonal axes the base family never touched:
//   (1) closed vs right-open — {gt,lt} prove `r5 <= end`, {ge,le} prove `r5 < end`.
//   (2) operand-order symmetry — gt (`r5 > end`) vs lt (`end < r5`) are the SAME OOB
//       condition written two ways; the verifier must treat them identically. Likewise
//       ge vs le. A gt/lt or ge/le disagreement is a symmetry bug in find_good_pkt_pointers.
//
//   0: r2 = data   1: r3 = data_end   2: r4 = skb->len
//   3: r4 &= 7                 bounded scalar offset [0,7] (partially-known -> tnum leg)
//   4: r2 += r4                PTR_TO_PACKET at data + r4
//   5: r5 = r2   6: r5 += M     headroom: the compare proves M bytes past r2
//   7: if (r5 <dcmp> r3) goto 9   THE RANGE-SETTING COMPARE (swept)   -> skip store on OOB
//   8: *(uW *)(r2 + off) = r4  STORE reaching byte off+W; accept iff off+W <= range(M,form)
//   9: r0 = 0   10: exit
//
// Prediction is NOT hand-derived: the verifier is the oracle. We MEASURE the accept
// boundary per form and assert (a) gt==lt and ge==le exactly (symmetry), (b) the closed
// and open boundaries differ by exactly one byte, (c) 0 tnum-vs-bounds divergence across
// all programs. SCHED_CLS, same as --gen-pkt.
// ===========================================================================
static const struct { const char *name; int op; int swap; } PKT_DCMP[] = {
    {"gt", BPF_JGT, 0},   // if r5 >  end  -> OOB (skip store); proves r5 <= end   CLOSED
    {"ge", BPF_JGE, 0},   // if r5 >= end  -> OOB;              proves r5 <  end   RIGHT-OPEN
    {"lt", BPF_JLT, 1},   // if end <  r5  -> OOB (== r5 > end);  proves r5 <= end  CLOSED (swapped)
    {"le", BPF_JLE, 1},   // if end <= r5  -> OOB (== r5 >= end); proves r5 <  end  RIGHT-OPEN (swapped)
};
#define PKT_DCMP_N ((int)(sizeof(PKT_DCMP) / sizeof(PKT_DCMP[0])))
static const int PKTCMP_W[] = {1, 2, 4};   // BPF_B / BPF_H / BPF_W store width

static void run_generated_pktcmp(int form_i, int m, int off, int wi, int index) {
    const int W = PKTCMP_W[wi];
    const int szmode = (W == 1) ? BPF_B : (W == 2) ? BPF_H : BPF_W;

    struct bpf_insn insns[11];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* data */
    insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* data_end */
    insns[2] = BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, 0);    /* len -> unknown */
    insns[3] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 7);           /* bound offset to [0,7] */
    insns[4] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_4);   /* pkt ptr = data + r4 */
    insns[5] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
    insns[6] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, m);           /* headroom M */
    if (PKT_DCMP[form_i].swap)
        insns[7] = BPF_JMP_REG(PKT_DCMP[form_i].op, BPF_REG_3, BPF_REG_5, 1); /* end <op> r5 */
    else
        insns[7] = BPF_JMP_REG(PKT_DCMP[form_i].op, BPF_REG_5, BPF_REG_3, 1); /* r5 <op> end */
    insns[8]  = BPF_STX_MEM(szmode, BPF_REG_2, BPF_REG_4, off); /* store reaching byte off+W */
    insns[9]  = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[10] = BPF_EXIT_INSN();

    char name[80];
    snprintf(name, sizeof(name), "genpc#%s.M%d.o%d.w%d#%03d",
             PKT_DCMP[form_i].name, m, off, W, index);
    run_one_ex(name, insns, 11, BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);
}

// form x headroom x store-offset x width -- 4*5*4*3 = 240, same order as the label index.
static void run_generated_pktcmp_family(void) {
    int index = 0;
    for (int form_i = 0; form_i < PKT_DCMP_N; form_i++)
        for (int m = 1; m <= 5; m++)
            for (int off = 0; off <= 3; off++)
                for (int wi = 0; wi < 3; wi++)
                    run_generated_pktcmp(form_i, m, off, wi, index++);
}

// ---- runtime ground-truth oracle (--gen-rt) --------------------------------
// The FIRST oracle that does not trust the verifier's own log to be self-
// consistent. Load an accepted program that RETURNS a verifier-bounded value
// derived from a fully attacker-controlled 32-bit input (a map value we set from
// userspace), then EXECUTE it via BPF_PROG_TEST_RUN over a sweep of inputs and
// print the ACTUAL retval for each. The pipeline compares each retval against the
// verifier's claimed bound on the return register: a retval outside
// [u32_min,u32_max] means the verifier proved a bound the runtime violated -- a
// soundness bug caught even when the tnum and u32 views AGREE with each other
// (the "consistent-but-wrong" blind spot every log-only invariant shares).
//
// v1 keeps every shape's result within 32 bits (umax < 2^32) so retval is the
// return register's exact value and the comparison is unambiguous.

static int rt_map_set(int map_fd, uint32_t key, uint32_t val) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = map_fd;
    a.key = (uint64_t)(unsigned long)&key;
    a.value = (uint64_t)(unsigned long)&val;
    a.flags = 0; /* BPF_ANY */
    return bpf(BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

/* extremes + interior values that hit the bound edges of the shapes below. */
static const uint32_t RT_INPUTS[] = {
    0x00000000u, 0x00000001u, 0x0000007fu, 0x000000ffu, 0x00007fffu, 0x0000ffffu,
    0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu, 0x5a5a5a5au, 0xdeadbeefu,
};
#define RT_INPUTS_N ((int)(sizeof(RT_INPUTS) / sizeof(RT_INPUTS[0])))

static void run_rt_one(const char *name, const struct bpf_insn *insns, int n, int map_fd) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        /* 64-byte zero packet: content is irrelevant (the computed input comes
           from the map), but skb-based test_run needs a non-empty packet. */
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            int uerr = rt_map_set(map_fd, 0, in);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            if (r < 0 || uerr < 0)
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d map_err=%d\n",
                       in, r < 0 ? errno : 0, uerr);
            else
                printf("RUNTIME input=0x%08x retval=0x%08x\n", in,
                       (unsigned)t.test.retval);
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

enum rt_shape { RT_AND, RT_AND_ADD, RT_AND_LSH, RT_CMP, RT_ALU32 };
static const char *rt_shape_name(enum rt_shape s) {
    switch (s) {
    case RT_AND:     return "and";
    case RT_AND_ADD: return "andadd";
    case RT_AND_LSH: return "andlsh";
    case RT_CMP:     return "cmp";
    case RT_ALU32:   return "alu32";
    }
    return "?";
}

static void run_rt_prog(enum rt_shape shape, uint32_t p1, uint32_t p2,
                        int idx, int map_fd) {
    struct bpf_insn ins[32];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0); /* r6 = attacker input */
    int jcmp = -1;
    switch (shape) {
    case RT_AND:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, p1);
        break;
    case RT_AND_ADD:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, p1);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, p2);
        break;
    case RT_AND_LSH:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, p1);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, p2);
        break;
    case RT_CMP:
        jcmp = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, p1, 0); /* >p1 -> return 0 */
        break;
    case RT_ALU32:
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, p1);
        ins[n++] = BPF_ALU32_IMM(BPF_OR, BPF_REG_6, p2);
        break;
    }
    ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6); /* return the bounded value */
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = exit0 - jnull - 1;
    if (jcmp >= 0) ins[jcmp].off = exit0 - jcmp - 1;

    char name[80];
    snprintf(name, sizeof(name), "genrt#%s#%03d", rt_shape_name(shape), idx);
    run_rt_one(name, ins, n, map_fd);
}

static void run_generated_rt_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genrt type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int idx = 0;
    const uint32_t and_masks[] = {0x1u, 0x7fu, 0xffu, 0xffffu, 0xfffffu, 0x7fffffffu};
    for (int i = 0; i < (int)(sizeof(and_masks)/sizeof(and_masks[0])); i++)
        run_rt_prog(RT_AND, and_masks[i], 0, idx++, map_fd);
    /* AND then ADD: [add, mask+add], both fit in 32 bits. */
    const uint32_t aa_mask[] = {0xffu, 0xffffu, 0xfffffu};
    const uint32_t aa_add[]  = {1u, 100u, 0x1000u};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            run_rt_prog(RT_AND_ADD, aa_mask[i], aa_add[j], idx++, map_fd);
    /* AND then LSH: mask<<shift stays < 2^32. */
    const uint32_t al_mask[] = {0xfu, 0xffu, 0xfffu};
    const uint32_t al_shift[] = {4u, 8u, 12u};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            run_rt_prog(RT_AND_LSH, al_mask[i], al_shift[j], idx++, map_fd);
    /* compare-narrow: return path has value in [0, K]. */
    const uint32_t cmp_k[] = {10u, 0xffu, 0xffffu, 0x7fffffu};
    for (int i = 0; i < 4; i++)
        run_rt_prog(RT_CMP, cmp_k[i], 0, idx++, map_fd);
    /* 32-bit ALU AND|OR: the CVE-2021-3490 flavour (32-bit bounds update path). */
    const uint32_t a32_and[] = {0xffu, 0xffffu, 0xf0f0f0u};
    const uint32_t a32_or[]  = {0x0u, 0x5u, 0xf00u};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            run_rt_prog(RT_ALU32, a32_and[i], a32_or[j], idx++, map_fd);
    close(map_fd);
}

// ---- runtime memory-safety oracle for map-value STORES (--gen-rtw) ----------
// The v2 extension of the runtime oracle: instead of checking a returned SCALAR
// against the verifier's bound, it checks MEMORY SAFETY directly. The program
// computes an attacker-controlled offset (verifier-bounded to be in-bounds) and
// STORES a sentinel through a map-value pointer at that offset. Userspace zeroes
// the target map, runs the program, reads the map back, and locates the sentinel.
//
// The check needs NO bound parsing: an accepted store is CLAIMED in-bounds, so on
// a sound kernel the sentinel MUST land inside the map value. If the sentinel is
// ABSENT, the store went out of bounds (into kernel memory we cannot see) — the
// verifier accepted an OOB write. This is the direct memory-safety property, the
// surface where real exploitable verifier bugs live.

static int rt_map_set_bytes(int map_fd, uint32_t key, const void *val) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = map_fd;
    a.key = (uint64_t)(unsigned long)&key;
    a.value = (uint64_t)(unsigned long)val;
    a.flags = 0;
    return bpf(BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

static int rt_map_get(int map_fd, uint32_t key, void *val_out) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = map_fd;
    a.key = (uint64_t)(unsigned long)&key;
    a.value = (uint64_t)(unsigned long)val_out;
    return bpf(BPF_MAP_LOOKUP_ELEM, &a, sizeof(a));
}

#define RTW_VALUE_SIZE 64
#define RTW_SENTINEL 0xFF

enum rtw_shape { RTW_AND, RTW_ANDADD, RTW_OVER };
static const char *rtw_shape_name(enum rtw_shape s) {
    switch (s) {
    case RTW_AND:    return "and";
    case RTW_ANDADD: return "andadd";
    case RTW_OVER:   return "over";
    }
    return "?";
}

static void run_rtw_one(const char *name, const struct bpf_insn *insns, int n,
                        int map_in, int map_out) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none\n", in);
            else
                printf("RUNTIME input=0x%08x store_off=%d\n", in, off);
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_rtw_prog(enum rtw_shape shape, uint32_t mask, uint32_t add,
                         int idx, int map_in, int map_out) {
    struct bpf_insn ins[40];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);            /* key = 0 */
    /* lookup map_in -> r0 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int j1 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);     /* r6 = attacker input */
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, mask);         /* shape the offset */
    if (shape == RTW_ANDADD)
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, add);
    /* lookup map_out -> r0 (r6 survives: callee-saved) */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int j2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);             /* r7 = map_out value ptr */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);    /* r7 += offset */
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, 0, RTW_SENTINEL);   /* store sentinel byte */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[j1].off = exit0 - j1 - 1;
    ins[j2].off = exit0 - j2 - 1;

    char name[80];
    snprintf(name, sizeof(name), "genrtw#%s#%03d", rtw_shape_name(shape), idx);
    run_rtw_one(name, ins, n, map_in, map_out);
}

static void run_generated_rtw_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genrtw type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int idx = 0;
    /* in-bounds masks (off <= mask <= 63, 1-byte store fits) -> ACCEPT, runtime-checked. */
    const uint32_t masks[] = {0x7u, 0xfu, 0x1fu, 0x3fu};
    for (int i = 0; i < 4; i++)
        run_rtw_prog(RTW_AND, masks[i], 0, idx++, map_in, map_out);
    /* AND then ADD: off in [C, C+15], all <= 63 -> ACCEPT. */
    const uint32_t adds[] = {0u, 24u, 48u};
    for (int i = 0; i < 3; i++)
        run_rtw_prog(RTW_ANDADD, 0xfu, adds[i], idx++, map_in, map_out);
    /* over-wide masks (off up to 127 > 63) -> the verifier must REJECT (control). */
    const uint32_t over[] = {0x7fu, 0xffu};
    for (int i = 0; i < 2; i++)
        run_rtw_prog(RTW_OVER, over[i], 0, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- T2-2: multi-byte store-WIDTH memory-safety oracle (--gen-rtw2) ----------
// The off-by-one a real verifier bug would hit lives in the in-bounds check
// `off + size <= value_size`, so the axis under test is the store WIDTH, not just
// the base offset. A multi-byte store is memory-safe iff ALL `size` sentinel bytes
// land inside the map value; a store that ends one byte past the end is a partial
// OOB write even though its base offset is in-bounds. The program stores `size`
// bytes of 0xFF (BPF_ST_MEM imm=-1). Userspace zeroes map_out BEFORE EVERY run
// (inherited from --gen-rtw's per-input loop — the sole 0xFF source is this store,
// so a stale sentinel from a prior sweep step can never be miscounted), runs the
// program, reads the value back, finds the FIRST 0xFF (store_off) and counts the
// consecutive 0xFF run (store_len), and reports store_size. The pipeline requires
// store_len == store_size for an accepted store: a truncated run (store_len <
// store_size) or store_off=none is a partial/total OOB write the verifier accepted.
// Two shapes: (a) and.wN — attacker offset r6 &= MASK, store size N at map_out+r6
// (accept iff MASK + N <= value_size); (b) bndc.wN — a CONST offset baked into the
// ST insn's off field: off = V-N stores up to exactly the end (ACCEPT), off = V-N+1
// runs one byte past it (REJECT) — the exact off-by-one control.

static int rtw2_size_code(int size) {
    switch (size) {
    case 1: return BPF_B;
    case 2: return BPF_H;
    case 4: return BPF_W;
    case 8: return BPF_DW;
    }
    return BPF_B;
}

static void run_rtw2_one(const char *name, const struct bpf_insn *insns, int n,
                         int map_in, int map_out, int store_size) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero); /* re-zero BEFORE every run */
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=%d\n",
                       in, store_size);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++)
                    len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=%d\n",
                       in, off, len, store_size);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

enum rtw2_shape { RTW2_AND, RTW2_BNDC };

static void run_rtw2_prog(enum rtw2_shape shape, uint32_t mask, int store_size,
                          int const_off, int idx, int map_in, int map_out) {
    struct bpf_insn ins[40];
    int n = 0;
    int sc = rtw2_size_code(store_size);
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);               /* key = 0 */
    if (shape == RTW2_AND) {
        /* lookup map_in -> r0 (attacker offset source) */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int j1 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);    /* r6 = attacker input */
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, mask);        /* r6 &= MASK -> [0,MASK] */
        /* lookup map_out -> r0 (r6 survives: callee-saved) */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int j2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);            /* r7 = map_out value ptr */
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);   /* r7 += offset */
        ins[n++] = BPF_ST_MEM(sc, BPF_REG_7, 0, -1);              /* store N sentinel bytes */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        ins[j1].off = exit0 - j1 - 1;
        ins[j2].off = exit0 - j2 - 1;
    } else { /* RTW2_BNDC: const offset baked into the ST insn's off field */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int j1 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);            /* r7 = map_out value ptr */
        ins[n++] = BPF_ST_MEM(sc, BPF_REG_7, const_off, -1);      /* store N bytes at const off */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        ins[j1].off = exit0 - j1 - 1;
    }

    char name[96];
    snprintf(name, sizeof(name), "genrtw2#%s.w%d#%03d",
             shape == RTW2_AND ? "and" : "bndc", store_size, idx);
    run_rtw2_one(name, ins, n, map_in, map_out, store_size);
}

static void run_generated_rtw2_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genrtw2 type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int idx = 0;
    const uint32_t masks[] = {0x7u, 0x1fu, 0x3fu};
    const int sizes[] = {1, 2, 4, 8};
    /* (a) and.wN: r6 &= MASK (umax = MASK), store size N at map_out+r6.
       Accept iff MASK + N <= value_size (64). 0x7/0x1f accept every N;
       0x3f accepts only N=1 (63+1=64), rejects N>=2 (65,67,71 > 64). */
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            run_rtw2_prog(RTW2_AND, masks[i], sizes[j], 0, idx++, map_in, map_out);
    /* (b) bndc.wN: const offset. off = V-N ends exactly at V (ACCEPT);
       off = V-N+1 runs one byte past V (REJECT) — the exact off-by-one. */
    for (int j = 0; j < 4; j++) {
        run_rtw2_prog(RTW2_BNDC, 0, sizes[j], RTW_VALUE_SIZE - sizes[j],
                      idx++, map_in, map_out);       /* accept: ends at V */
        run_rtw2_prog(RTW2_BNDC, 0, sizes[j], RTW_VALUE_SIZE - sizes[j] + 1,
                      idx++, map_in, map_out);       /* reject: one past V */
    }
    close(map_in);
    close(map_out);
}

// ---- store-LOCATION desync oracle (--gen-loc) -------------------------------
// The runtime-write legs so far (0037/0038/0039) ask one question: did the store
// stay INSIDE the object? A verifier can pass that and still be wrong. If its
// abstract arithmetic for the offset is unsound, the store lands at an offset its
// OWN state says is impossible — and still inside the object, so every previous leg
// stays silent. That is the "consistent-but-wrong" class: the verifier's two views
// agree with each other and disagree only with reality, which is exactly what an
// internal-consistency oracle can never see.
//
// So this family asks the strictly stronger question: did the store land WHERE THE
// VERIFIER SAID it could? The verifier prints its own claim at the store:
//   17: R7=map_value(ks=4,vs=64,smin=0,smax=umax=7,var_off=(0x0; 0x7))
//   17: (72) *(u8 *)(r7 +0) = -1
// i.e. "offset in [0,7], and only at offsets whose bits fit (0x0; 0x7)". The runtime
// says where the sentinel actually landed. The diff stage compares the two.
//
// The AXIS is therefore the ALU chain that shapes the offset — one program per
// abstract transfer function, because that is where a too-narrow (unsound) bound
// would come from. Each chain is chosen so its proven window is TIGHT: a wide window
// would let a wrong offset pass, and the tnum arms (lsh/mul/compose) are the sharpest
// because their proven set has HOLES — `r6 &= 3; r6 <<= 2` proves {0,4,8,12}, so an
// offset of 6 is inside [0,12] and still impossible. An interval check alone would
// miss it; the tnum half is what makes "where it SAID" mean the exact set.
//
// The harness declares the store site (`STORE insn= reg= off= size=`) because it
// BUILT the program: which instruction stores, through which register, is ground
// truth about the input. Recovering it from the verifier's own disassembly would
// make the oracle depend on the component it is auditing.

enum loc_shape {
    LOC_AND7, LOC_AND31, LOC_ORAND, LOC_ADDC, LOC_SUBC,
    LOC_LSH2, LOC_LSH3, LOC_RSH, LOC_MUL, LOC_XOR,
    LOC_ALU32, LOC_JMP, LOC_SHPAIR, LOC_COMPOSE, LOC_OFF4,
};

static const char *loc_shape_name(enum loc_shape s) {
    switch (s) {
    case LOC_AND7:    return "and7";
    case LOC_AND31:   return "and31";
    case LOC_ORAND:   return "orand";
    case LOC_ADDC:    return "addc";
    case LOC_SUBC:    return "subc";
    case LOC_LSH2:    return "lsh2";
    case LOC_LSH3:    return "lsh3";
    case LOC_RSH:     return "rsh";
    case LOC_MUL:     return "mul";
    case LOC_XOR:     return "xor";
    case LOC_ALU32:   return "alu32";
    case LOC_JMP:     return "jmp";
    case LOC_SHPAIR:  return "shpair";
    case LOC_COMPOSE: return "compose";
    case LOC_OFF4:    return "off4";
    }
    return "?";
}

static void run_loc_one(const char *name, const struct bpf_insn *insns, int n,
                        int map_in, int map_out, int store_insn, int store_off) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);
    /* generator provenance: where the store IS, not where the verifier says it is */
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, store_off);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero); /* re-zero BEFORE every run */
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++)
                    len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_loc_prog(enum loc_shape shape, int idx, int map_in, int map_out) {
    struct bpf_insn ins[48];
    int n = 0;
    int jfix[4]; int nj = 0;
    int st_off = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);               /* key = 0 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jfix[nj++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);        /* r6 = attacker input */

    /* the axis: one abstract transfer function per program */
    switch (shape) {
    case LOC_AND7:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;            /* [0,7] */
    case LOC_AND31:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 31); break;           /* [0,31] */
    case LOC_ORAND:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_OR, BPF_REG_6, 8); break;             /* [8,15] */
    case LOC_ADDC:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 16); break;           /* [16,23] */
    case LOC_SUBC:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 32);
        ins[n++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_6, 8); break;            /* [24,31] */
    case LOC_LSH2:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 2); break;            /* {0,4,8,12} */
    case LOC_LSH3:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 3); break;            /* {0,8,..,56} */
    case LOC_RSH:
        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 29); break;           /* [0,7] */
    case LOC_MUL:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 5); break;            /* {0,5,10,15} */
    case LOC_XOR:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_6, 5); break;            /* [0,7] */
    case LOC_ALU32:
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 7); break;            /* 32-bit op */
    case LOC_JMP:
        /* bound by a BRANCH, not a mask: reg_set_min_max, a different code path */
        jfix[nj++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0); break;
    case LOC_SHPAIR:
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 60);
        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 60); break;           /* [0,15] */
    case LOC_COMPOSE:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 2); break;            /* {4,8,12,16} */
    case LOC_OFF4:
        /* same [0,7] offset, but the store carries its own +4: exercises the
           `ptr_off + insn_off + var` arithmetic on both sides of the comparison */
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); st_off = 4; break;
    }

    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jfix[nj++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);                /* r7 = map_out value */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);       /* r7 += shaped offset */
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, st_off, -1);           /* the observed store */
    /* EXECUTION WITNESS. `store_off=none` means "no sentinel in the value", which
       conflates two very different things: the store ran and went OUT OF BOUNDS, or
       the store never ran at all. Every earlier runtime-write family (--gen-rtw,
       --gen-rtw2, --gen-pktw) reached its store unconditionally, so `none` could only
       mean the first. The LOC_JMP arm breaks that: it bounds the offset with a BRANCH,
       so every sweep input above the bound skips the store entirely. The program
       itself reports which happened -- r0=1 only on the path that performed the
       store, r0=0 on every skip path -- so the disambiguation is runtime ground
       truth from the input side, not a guess in the diff stage. */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nj; i++)
        ins[jfix[i]].off = exit0 - jfix[i] - 1;

    char name[96];
    snprintf(name, sizeof(name), "genloc#%s#%03d", loc_shape_name(shape), idx);
    run_loc_one(name, ins, n, map_in, map_out, store_insn, st_off);
}

static void run_generated_loc_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genloc type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Every chain keeps the landing site well inside the 64-byte value, so the
       DECISION is not the surface here — all 15 are expected to be accepted, and the
       surface is WHERE each accepted store lands versus what the verifier proved. */
    const enum loc_shape shapes[] = {
        LOC_AND7, LOC_AND31, LOC_ORAND, LOC_ADDC, LOC_SUBC,
        LOC_LSH2, LOC_LSH3, LOC_RSH, LOC_MUL, LOC_XOR,
        LOC_ALU32, LOC_JMP, LOC_SHPAIR, LOC_COMPOSE, LOC_OFF4,
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
        run_loc_prog(shapes[i], idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- packet-write runtime memory-safety oracle (--gen-pktw) -----------------
// The runtime-write oracle so far (--gen-rtw / --gen-rtw2) stores through a
// PTR_TO_MAP_VALUE, whose bound the verifier KNOWS statically (value_size). This
// leg is the PACKET analog: a store through a PTR_TO_PACKET, whose bound the
// verifier does NOT know — the PROGRAM proves it with its own `data + M > data_end`
// compare and the verifier statically TRACKS the resulting `range`
// (find_good_pkt_pointers, verifier.c). That range machinery is the historically
// densest packet-bounds bug region, and the load-only packet families (--gen-pkt /
// --gen-pkt-cmp) can only see accept/reject and the verifier's OWN self-consistency
// — never where the store actually LANDS. This one EXECUTES the accepted program
// via BPF_PROG_TEST_RUN and reads the packet back, so it catches a range that is
// internally consistent but WRONG (the blind spot every log-only leg shares).
//
// Shape (SCHED_CLS — socket_filter forbids direct packet access):
//   0: r2 = *(u32*)(r1+76)   data      -> PTR_TO_PACKET
//   1: r3 = *(u32*)(r1+80)   data_end  -> PTR_TO_PACKET_END
//   2: r5 = r2   3: r5 += M   headroom the compare will prove
//   4: if (r5 > r3) goto 6    proves data + M <= data_end -> range = M bytes
//   5: *(uW*)(r2 + off) = -1  store W sentinel bytes; accepted iff off + W <= M
//   6: r0 = 0   7: exit
//
// The runtime packet length is set to EXACTLY M, so data_end lands at byte M and the
// compare `data+M > data_end` is false (M <= M) — the accepted store executes. On a
// sound kernel every accepted store has off + W <= M, so all W sentinel bytes land
// in [0, M) and are copied back in data_out (store_len == store_size). A verifier
// that accepted off + W = M + 1 (a range off-by-one) would put the store's last byte
// AT data_end — in skb tailroom, which test_run never copies back — so the sentinel
// run is truncated (store_len < store_size) or absent: exactly the runtime_oob_write
// the shared diff predicate already fires on. The one-past programs (off = M-W+1) are
// the reject control: a sound verifier rejects them, so they never execute and never
// count — a buggy one would accept, run, and truncate.
//
// The output format is byte-identical to --gen-rtw2, so the parser, the diff
// predicate (check_runtime_write_safety), and the metrics counters are reused
// UNCHANGED; only the bytes' provenance differs (packet read-back vs map read-back).
// First increment pins the compare to the canonical closed `>` idiom; sweeping the
// operator (`>=` right-open, operand-order symmetry) is the natural follow-up, as
// --gen-pkt -> --gen-pkt-cmp did for the load-only side.

#define PKTW_M 32   /* proven headroom == runtime packet length (>= ETH_HLEN = 14) */

static void run_pktw_one(const char *name, const struct bpf_insn *insns, int n,
                         int pkt_size, int store_size) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=sched_cls ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        /* Fresh skb per run: data_in is zeroed, so the ONLY 0xFF bytes come from
           the store. data_end lands at data + pkt_size, so byte pkt_size is the
           first out-of-bounds byte (skb tailroom, never copied back to data_out). */
        unsigned char in[RTW_VALUE_SIZE];
        unsigned char out[RTW_VALUE_SIZE];
        memset(in, 0, sizeof(in));
        memset(out, 0, sizeof(out));
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)in;
        t.test.data_size_in = pkt_size;
        t.test.data_out = (uint64_t)(unsigned long)out;
        t.test.data_size_out = sizeof(out);
        t.test.repeat = 1;
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        if (r < 0) {
            printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n", pkt_size, errno);
        } else {
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=%d\n",
                       pkt_size, store_size);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++)
                    len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=%d\n",
                       pkt_size, off, len, store_size);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_pktw_prog(int store_size, int const_off, int idx) {
    struct bpf_insn ins[16];
    int n = 0;
    int sc = rtw2_size_code(store_size);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* r2 = data */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* r3 = data_end */
    ins[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);            /* r5 = data */
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, PKTW_M);      /* r5 = data + M */
    const int jc = n;
    ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 0);  /* if r5 > data_end -> skip */
    ins[n++] = BPF_ST_MEM(sc, BPF_REG_2, const_off, -1);       /* store W sentinel bytes at data+off */
    const int skip = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jc].off = skip - jc - 1;

    char name[96];
    snprintf(name, sizeof(name), "genpktw#w%d.o%d#%03d", store_size, const_off, idx);
    run_pktw_one(name, ins, n, PKTW_M, store_size);
}

static void run_generated_pktw_family(void) {
    int idx = 0;
    const int sizes[] = {1, 2, 4, 8};
    /* Closed `>` form: the compare proves M bytes past data, so a store reaching
       byte off + W is accepted iff off + W <= M (= PKTW_M). Three arms per width:
       an interior accept at off 0, a boundary accept ending exactly at byte M-1
       (off = M-W, the tightest in-bounds store), and the off-by-one at off = M-W+1
       whose last byte would be AT data_end -> the verifier must REJECT it. */
    for (int j = 0; j < 4; j++) {
        int W = sizes[j];
        run_pktw_prog(W, 0, idx++);                 /* interior accept */
        run_pktw_prog(W, PKTW_M - W, idx++);        /* boundary accept: ends at byte M-1 */
        run_pktw_prog(W, PKTW_M - W + 1, idx++);    /* off-by-one -> reject */
    }
}

// ---- packet-write observation-channel probe (--probe-pktw) ------------------
// 0039's packet oracle rests on a CLAIM about the observation channel:
// bpf_prog_test_run_skb copies back only [0, skb->len), so a store past data_end lands
// in skb tailroom and is never returned — which is exactly why an absent or truncated
// sentinel run is read as an OOB write. That claim was ARGUED from reading the kernel,
// never MEASURED: on a sound verifier every OOB store is REJECTED, so 0039 never
// observed a true OOB and never exercised the channel's negative half. The next leg
// (store-location desync) will assert "the verifier proved X, the store landed at Y",
// so the channel has to be shown to resolve bytes precisely BEFORE it is trusted to
// locate a store — otherwise a desync finding could be a channel artefact.
//
// The probe measures the window using ACCEPTED programs only, by moving the WINDOW
// instead of the store: bpf_skb_change_tail() shrinks skb->len AFTER the store has run,
// so a byte that WAS written into the packet buffer ends up beyond the returned length —
// the exact geometry of an OOB store, produced without needing a buggy verifier.
//
//   probe#pktw.win32     in=32, store at 31           -> out_size == 32, store visible
//   probe#pktw.win40     in=40, same program          -> out_size tracks skb->len (40)
//   probe#pktw.trim.o19  in=32, store at 19, tail->20 -> VISIBLE: last returned byte
//   probe#pktw.trim.o20  in=32, store at 20, tail->20 -> ABSENT: first byte past it
//
// The last two are the byte-precise edge: identical shape, identical shrink, offsets one
// apart, opposite observability — so "absent" is positional, not an artefact of
// change_tail touching the data. `tail_zero` additionally reports that our pre-zeroed
// output buffer is STILL zero beyond out_size, so bytes out there can never be misread
// as a sentinel (the positive half of the same claim).

static void run_pktw_probe_one(const char *name, const struct bpf_insn *insns, int n,
                               int in_size) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=sched_cls ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        unsigned char in[RTW_VALUE_SIZE];
        unsigned char out[RTW_VALUE_SIZE];
        memset(in, 0, sizeof(in));
        memset(out, 0, sizeof(out));
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)in;
        t.test.data_size_in = in_size;
        t.test.data_out = (uint64_t)(unsigned long)out;
        t.test.data_size_out = sizeof(out);
        t.test.repeat = 1;
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        if (r < 0) {
            printf("CHANNEL in_size=%d error=1 testrun_errno=%d\n", in_size, errno);
        } else {
            /* the kernel writes the ACTUAL output length back into the attr */
            unsigned out_size = t.test.data_size_out;
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int tail_zero = 1;
            for (unsigned b = out_size; b < (unsigned)RTW_VALUE_SIZE; b++)
                if (out[b] != 0) { tail_zero = 0; break; }
            if (off < 0)
                printf("CHANNEL in_size=%d out_size=%u retval=%u store_off=none tail_zero=%d\n",
                       in_size, out_size, t.test.retval, tail_zero);
            else
                printf("CHANNEL in_size=%d out_size=%u retval=%u store_off=%d tail_zero=%d\n",
                       in_size, out_size, t.test.retval, off, tail_zero);
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

/* store 1 sentinel byte at `off` behind the usual `data + PKTW_M > data_end` proof;
   when trim_to > 0, shrink skb->len to trim_to AFTERWARDS so the window moves under
   an already-written byte. r1 still holds the ctx at the call site. */
static void run_pktw_probe_prog(const char *name, int off, int in_size, int trim_to) {
    struct bpf_insn ins[16];
    int n = 0;
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* r2 = data */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* r3 = data_end */
    ins[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, PKTW_M);      /* r5 = data + M */
    const int jc = n;
    ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 0);  /* skip store if short */
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, off, -1);          /* sentinel at data+off */
    const int skip = n;
    if (trim_to > 0) {
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, trim_to);          /* new_len */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 0);                /* flags */
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_skb_change_tail);    /* r0 = 0 on success */
    } else {
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    }
    ins[n++] = BPF_EXIT_INSN();
    ins[jc].off = skip - jc - 1;
    run_pktw_probe_one(name, ins, n, in_size);
}

static void run_probe_pktw_family(void) {
    /* window geometry: out_size == skb->len, and it MOVES with the input length */
    run_pktw_probe_prog("probe#pktw.win32",    PKTW_M - 1, PKTW_M,     0);
    run_pktw_probe_prog("probe#pktw.win40",    PKTW_M - 1, PKTW_M + 8, 0);
    /* byte-precise edge: same shrink, offsets one apart, opposite observability */
    run_pktw_probe_prog("probe#pktw.trim.o19", 19,         PKTW_M,     20);
    run_pktw_probe_prog("probe#pktw.trim.o20", 20,         PKTW_M,     20);
}


// ---- pruning-soundness differential (--gen-prune) ---------------------------
// A NEW ORACLE CLASS: kernel-vs-kernel. Every earlier leg compares the verifier
// against something WE compute (an invariant, a bound, a runtime observation). This
// one compares the verifier against ITSELF under a flag the kernel provides for
// exactly this purpose, so there is no bound parsing and no oracle of ours to be
// wrong.
//
// BPF_F_TEST_STATE_FREQ (states.c: `force_new_state = env->test_state_freq || ...`,
// then `add_new_state = force_new_state`) makes the verifier record a checkpoint at
// EVERY instruction. The default heuristic only checkpoints after >= 2 jumps AND
// >= 8 instructions. So the flag does NOT disable pruning -- it makes pruning MORE
// aggressive, by handing regsafe()/states_equal() far more candidate pairs.
//
// That fixes the direction of the finding:
//   flagged ACCEPT + default REJECT  ->  a path that produces the rejection was
//                                        pruned away: a PRUNING SOUNDNESS bug.
//   flagged REJECT + default ACCEPT  ->  almost certainly a resource artefact
//                                        (BPF_COMPLEXITY_LIMIT_INSNS, "BPF program
//                                        is too large", -E2BIG), classified by the
//                                        reject reason and NOT counted as a finding.
// A difference in state COUNT is not a finding either -- it is the denominator that
// proves the flag engaged at all. Identical counts would make a zero finding count
// meaningless, exactly like store_locations_checked in 0041.
//
// For a wrong prune to be OBSERVABLE the program needs three things: convergent
// control flow, two incoming states that regsafe must genuinely judge (not identical),
// and a downstream access whose safety DEPENDS on which path was taken. The last one
// is what turns a wrong prune into a decision flip; without it the bug is silent.
//
// Shape: two attacker values (offset source r6, branch selector r9) are read from one
// map value, so the split does NOT constrain the offset -- each path's state for r6
// comes purely from its own shaper. The paths converge and store 1 byte at
// map_value + r6 + 56, which is in bounds iff umax(r6) <= 7. The verifier explores the
// FALL-THROUGH first (check_cond_jmp_op pushes the jump target for later), so the
// fall-through shaper is the one that records the checkpoint at the merge -- which is
// why the ORDER is an axis and not an accident.
/* Not in every distro's uapi header yet; the value is fixed ABI (uapi/linux/bpf.h). */
#ifndef BPF_F_TEST_STATE_FREQ
#define BPF_F_TEST_STATE_FREQ (1U << 3)
#endif
#ifndef BPF_F_TEST_REG_INVARIANTS
#define BPF_F_TEST_REG_INVARIANTS (1U << 7)
#endif

#define PRUNE_STORE_OFF 56   /* 1-byte store is in bounds iff umax(r6) <= 7 */

static char g_log2[4 * 1024 * 1024];

enum prune_shaper {
    SH_N7,   /* r6 &= 7          -> [0,7]        SAFE  */
    SH_T6,   /* (r6 &= 3) << 1   -> {0,2,4,6}    SAFE, tnum-refined inside [0,7] */
    SH_W63,  /* r6 &= 63         -> [0,63]       unsafe, strict superset of [0,7] */
    SH_M39,  /* (r6 &= 7) | 32   -> [32,39]      unsafe, DISJOINT from [0,7] */
    SH_O19,  /* (r6 &= 15) + 4   -> [4,19]       unsafe, OVERLAPS [0,7] */
    SH_S56,  /* (r6 &= 7) << 3   -> {0,8,..,56}  unsafe, same umin, holey tnum */
    SH_A32,  /* r6 &= 63 (32-bit)-> [0,63]       unsafe, via the alu32 path */
};

static const char *prune_shaper_name(enum prune_shaper s) {
    switch (s) {
    case SH_N7:  return "n7";
    case SH_T6:  return "t6";
    case SH_W63: return "w63";
    case SH_M39: return "m39";
    case SH_O19: return "o19";
    case SH_S56: return "s56";
    case SH_A32: return "a32";
    }
    return "?";
}

static int emit_prune_shaper(struct bpf_insn *ins, int n, enum prune_shaper s) {
    switch (s) {
    case SH_N7:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;
    case SH_T6:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 1); break;
    case SH_W63:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 63); break;
    case SH_M39:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_OR, BPF_REG_6, 32); break;
    case SH_O19:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 15);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 4); break;
    case SH_S56:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 3); break;
    case SH_A32:
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 63); break;
    }
    return n;
}

/* Is a store at +PRUNE_STORE_OFF in bounds under this shaper's range? */
static int prune_shaper_is_safe(enum prune_shaper s) {
    return s == SH_N7 || s == SH_T6;
}

struct prune_load {
    int accept;
    int err;
    unsigned long states;
    const char *reason;   /* none | verdict | too_large | too_many_states | efault */
};

/* `prog_type` is a parameter because not every surface is reachable from
   socket_filter: bpf_dynptr_slice_rdwr requires a program type that permits direct
   packet writes (verifier.c:13737, "the prog does not allow writes to packet data") --
   and it applies that gate to EVERY dynptr type, including a LOCAL dynptr over a map
   value that has nothing to do with packets. */
static struct prune_load prune_load_typed(const struct bpf_insn *insns, int n,
                                          uint32_t flags, char *logbuf, size_t logsz,
                                          int prog_type) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = logsz;
    attr.log_buf = (uint64_t)(unsigned long)logbuf;
    attr.prog_flags = flags;
    logbuf[0] = '\0';

    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    struct prune_load r;
    r.accept = fd >= 0;
    r.err = fd >= 0 ? 0 : e;
    /* `processed N insns (limit ...) max_states_per_insn M total_states T ...`
       -- take the LAST occurrence: one summary is printed per subprog. */
    r.states = 0;
    for (const char *p = logbuf; (p = strstr(p, "total_states ")) != NULL; p++)
        r.states = strtoul(p + strlen("total_states "), NULL, 10);
    if (fd >= 0)
        r.reason = "none";
    else if (strstr(logbuf, "BPF program is too large"))
        r.reason = "too_large";           /* BPF_COMPLEXITY_LIMIT_INSNS, not a finding */
    else if (strstr(logbuf, "too many states"))
        r.reason = "too_many_states";     /* BPF_COMPLEXITY_LIMIT_STATES, not a finding */
    else if (e == EFAULT)
        r.reason = "efault";              /* REG INVARIANTS VIOLATION path */
    /* ENOSPC IS NOT A VERDICT. kernel/bpf/log.c:295 returns it when the verifier LOG was
       truncated (`log->len_max > log->len_total`) — a statement about our buffer, not about
       the program. It reached here as "verdict" and produced the hunt's only FINDING: a
       state-freq load that explored 202 states instead of 49, wrote four times the
       log_level=2 output, overflowed a 256 KB buffer, and was reported as a pruning
       disagreement. Seventh time the triage answer was (c)-negative. */
    else if (e == ENOSPC)
        r.reason = "log_truncated";       /* OUR buffer, not the kernel's decision */
    else
        r.reason = "verdict";             /* the verifier actually decided */
    if (fd >= 0)
        close(fd);
    return r;
}

static struct prune_load prune_load_once(const struct bpf_insn *insns, int n,
                                         uint32_t flags, char *logbuf, size_t logsz) {
    return prune_load_typed(insns, n, flags, logbuf, logsz, BPF_PROG_TYPE_SOCKET_FILTER);
}

/* THE STATE COUNT NEEDS log_level=1, NOT 2. `total_states` lives in the one-line summary
   that level 1 already prints; level 2 adds the whole per-instruction state dump, which for
   a deep exploration is two orders of magnitude more text and the only reason the buffer can
   overflow at all. The flagged load in the fuzz loop reads nothing but that count, so it now
   asks for the level it needs — which REMOVES the ENOSPC source rather than merely
   classifying it. The BASE load stays at level 2 because the liveness gate reads its table. */
static struct prune_load prune_load_states(const struct bpf_insn *insns, int n,
                                           uint32_t flags, char *logbuf, size_t logsz) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 1;
    attr.log_size = logsz;
    attr.log_buf = (uint64_t)(unsigned long)logbuf;
    attr.prog_flags = flags;
    logbuf[0] = '\0';
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    struct prune_load r;
    r.accept = fd >= 0;
    r.err = fd >= 0 ? 0 : e;
    r.states = 0;
    for (const char *p = logbuf; (p = strstr(p, "total_states ")) != NULL; p++)
        r.states = strtoul(p + strlen("total_states "), NULL, 10);
    if (fd >= 0)                                          r.reason = "none";
    else if (strstr(logbuf, "BPF program is too large"))  r.reason = "too_large";
    else if (strstr(logbuf, "too many states"))           r.reason = "too_many_states";
    else if (e == EFAULT)                                 r.reason = "efault";
    else if (e == ENOSPC)                                 r.reason = "log_truncated";
    else                                                  r.reason = "verdict";
    if (fd >= 0) close(fd);
    return r;
}

static void run_prune_prog(enum prune_shaper fall, enum prune_shaper taken,
                           int use_stack, int idx, int map_in, int map_out) {
    struct bpf_insn ins[64];
    int n = 0;
    int jexit[4]; int nx = 0;
    int jsplit, jmerge;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);                /* key = 0 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);         /* offset source  */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 4);         /* branch selector */

    /* The split tests r9, never r6: the two paths' states for the offset register
       come purely from their own shapers, not from the branch condition. */
    jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 0, 0);

    /* fall-through path -- explored FIRST, so this is the state that checkpoints */
    n = emit_prune_shaper(ins, n, fall);
    if (use_stack) {
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -16);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0);
    }
    jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);

    /* taken path */
    ins[jsplit].off = n - jsplit - 1;
    n = emit_prune_shaper(ins, n, taken);
    if (use_stack) {
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -16);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0);
    }

    /* merge */
    ins[jmerge].off = n - jmerge - 1;
    if (use_stack)
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, -16);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, PRUNE_STORE_OFF, -1);   /* the deciding access */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* Three loads of the SAME program: default, state-freq, reg-invariants. */
    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    char name[96];
    snprintf(name, sizeof(name), "genprune#%s%s-%s#%03d",
             use_stack ? "stk." : "", prune_shaper_name(fall),
             prune_shaper_name(taken), idx);

    printf("===PROG %s type=socket_filter ===\n", name);
    /* The block's RESULT is the DEFAULT load, so every existing stage keeps working. */
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           base.accept ? "accept" : "reject", base.accept ? 1 : -1, base.err);
    /* Generator provenance: what each path proves, and where the deciding store is. */
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, PRUNE_STORE_OFF);
    /* NOTE the token names: `*_verdict=` and NOT `*_decision=`. The pipeline and its
       measurement helpers match `decision=` as a SUBSTRING, so `base_decision=accept`
       would be counted as a fourth program decision. Same collision class as
       `find("off=")` matching inside `var_off=(...)` in 0041 -- a naming choice, made
       once, is cheaper than a boundary-aware matcher everywhere downstream. */
    printf("PRUNE fall=%s taken=%s fall_safe=%d taken_safe=%d stack=%d"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           prune_shaper_name(fall), prune_shaper_name(taken),
           prune_shaper_is_safe(fall), prune_shaper_is_safe(taken), use_stack,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    bpflive_print_claim(ins, n);
    printf("---LOG---\n%s\n---END---\n", g_log);
}

// ---- back-edge / loop-convergence family (--gen-loop) -----------------------
// THE FIRST PROGRAM SHAPE WITH A BACK-EDGE. Every family before this one is a forward
// DAG, which is why six legs of oracle growth found nothing: the real bug list lives in
// state pruning, precision and convergence, and none of those can be reached without a
// loop. The ORACLE here is 0042's, transferred UNCHANGED -- same three loads, same
// directional predicate, same `freq_states > base_states` denominator -- so this leg is
// purely an INPUT increment. That is the whole point: aim the input, do not grow the
// oracle.
//
// MECHANISM: `may_goto`, chosen over open-coded iterators and bpf_loop in OI-13.
// Encoding is one raw instruction and nothing else (BPF_JCOND = 0xe0, BPF_MAY_GOTO = 0,
// and verifier.c:19075 requires dst_reg == 0 && imm == 0): no BTF, no kfunc, no subprog,
// no map. Confirmed against the kernel's own `__cond_break` macro, which emits
// `.byte 0xe5` with the offset pointing at `l_break` -- so the JUMP is the loop EXIT and
// the FALL-THROUGH continues into the body.
//
// WHAT IT LANDS ON (verifier.c:16923): the verifier follows the jump (exit), queues the
// fall-through (body) as a new state, bumps `may_goto_depth`, and calls
//   widen_imprecise_scalars(env, prev_st, queued_st)
// against the previous entry at the same instruction. That widening is a DELIBERATE
// over-approximation inserted to force convergence, sitting directly on top of precision
// marking and state pruning -- exactly the shape the 0042 instrument attacks.
//
// THE AXIS is the loop-carried transfer function: what the body does to the register the
// store's safety depends on. A too-narrow fixpoint is what an unsound convergence
// produces, and the store turns it into a decision.
//
// The `nop` arms cannot flip (the body never touches the deciding register) and are kept
// as explicit CONTROLS, labelled as such: they prove that adding a back-edge does not by
// itself change a verdict.
#define LOOP_STORE_OFF 56   /* 1-byte store in bounds iff umax(r6) <= 7 */

#ifndef BPF_JCOND
#define BPF_JCOND 0xe0
#endif
#ifndef BPF_MAY_GOTO
#define BPF_MAY_GOTO 0
#endif

/* may_goto +off : jump to +off when the budget is exhausted, else fall through. */
#define BPF_MAY_GOTO_INSN(OFF)                                                 \
    ((struct bpf_insn){.code = BPF_JMP | BPF_JCOND,                            \
                       .dst_reg = 0, .src_reg = BPF_MAY_GOTO, .off = OFF, .imm = 0})

enum loop_body {
    LB_NOP,      /* body leaves r6 alone            -> control, cannot flip     */
    LB_MASK,     /* r6 &= 7        idempotent       -> invariant [0,7]          */
    LB_INCMASK,  /* r6 += 1; r6 &= 7                -> [0,7]                    */
    LB_MASKINC,  /* r6 &= 7; r6 += 1                -> [1,8]  EXACT off-by-one  */
    LB_SHR,      /* r6 >>= 1       shrinks          -> [0,3]                    */
    LB_XOR3,     /* r6 ^= 3        stays in [0,7]                               */
    LB_COND,     /* if (r6 > 7) r6 = 0  -- invariant kept by a BRANCH, not a mask */
    LB_INC,      /* r6 += 1        unbounded growth -> must widen               */
    LB_SHL,      /* r6 <<= 1       growth                                       */
    LB_ADD8,     /* r6 += 8        growth                                       */
};

static const char *loop_body_name(enum loop_body b) {
    switch (b) {
    case LB_NOP:     return "nop";
    case LB_MASK:    return "mask";
    case LB_INCMASK: return "incmask";
    case LB_MASKINC: return "maskinc";
    case LB_SHR:     return "shr";
    case LB_XOR3:    return "xor3";
    case LB_COND:    return "cond";
    case LB_INC:     return "inc";
    case LB_SHL:     return "shl";
    case LB_ADD8:    return "add8";
    }
    return "?";
}

static int emit_loop_body(struct bpf_insn *ins, int n, enum loop_body b) {
    switch (b) {
    case LB_NOP:
        break;
    case LB_MASK:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;
    case LB_INCMASK:
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;
    case LB_MASKINC:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1); break;
    case LB_SHR:
        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 1); break;
    case LB_XOR3:
        ins[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_6, 3); break;
    case LB_COND:
        /* The invariant is re-established by a BRANCH -- reg_set_min_max inside a loop
           body, a different code path from a mask. The threshold is 3, not the entry
           bound 7, ON PURPOSE: with `r6 <= 7` the condition is always true for an entry
           range of [0,7], the reset is dead code and the branch is one-way, i.e. a
           vacuous arm. At 3 both sides are reachable and the join is genuinely computed. */
        ins[n++] = BPF_JMP_IMM(BPF_JLE, BPF_REG_6, 3, 1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0); break;
    case LB_INC:
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1); break;
    case LB_SHL:
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 1); break;
    case LB_ADD8:
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 8); break;
    }
    return n;
}

static void run_loop_prog(enum loop_body body, int init_mask, int idx,
                          int map_in, int map_out) {
    struct bpf_insn ins[64];
    int n = 0;
    int jexit[4]; int nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, init_mask);   /* the entry invariant */

    /* THE LOOP. The jump target of may_goto is the break label, so the state reaching
       the store is the JOIN over 0, 1, 2, ... iterations -- the ZERO-iteration path
       included. An arm whose body NARROWS the range is therefore still unsafe if its
       ENTRY range is unsafe, and that is a decision a wrong fixpoint could get wrong. */
    const int loop_head = n;
    const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
    n = emit_loop_body(ins, n, body);
    /* The back-edge index MUST be taken before the store: writing
       `ins[n++] = BPF_JMP_IMM(..., loop_head - n - 1)` leaves the side effect on `n`
       unsequenced against the offset expression, and the first capture emitted
       `goto pc-4` (landing on the entry mask) instead of `pc-3` (the may_goto). That
       made every iteration re-establish the entry invariant, so all ten loop bodies
       produced identical states and identical verdicts -- a VACUOUS family that looked
       like ten clean accepts. */
    const int jback = n;
    ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);   /* back-edge */
    n++;
    ins[jbreak].off = n - jbreak - 1;

    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    char name[96];
    snprintf(name, sizeof(name), "genloop#%s.m%d#%03d", loop_body_name(body), init_mask, idx);

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           base.accept ? "accept" : "reject", base.accept ? 1 : -1, base.err);
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, LOOP_STORE_OFF);
    /* `fall`/`taken` carry the loop body and the entry mask so the differential line
       stays byte-compatible with --gen-prune: same parser, same predicate, same tests. */
    printf("PRUNE fall=%s taken=m%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           loop_body_name(body), init_mask,
           init_mask <= 7, init_mask <= 7,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    printf("LOOP body=%s init_mask=%d store_off=%d\n",
           loop_body_name(body), init_mask, LOOP_STORE_OFF);
    printf("---LOG---\n%s\n---END---\n", g_log);
}

/* Residue sweep shared by every loop family whose entry state is `input & 7`: the
   shared RT_INPUTS collapses to only five distinct residues, so seven of its twelve
   runs would buy nothing. Declared here because both --gen-iter and --gen-loopr use it. */
static const uint32_t LOOPR_INPUTS[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
#define LOOPR_INPUTS_N ((int)(sizeof(LOOPR_INPUTS) / sizeof(LOOPR_INPUTS[0])))

// ---- open-coded iterators: BTF resolution + probe (--probe-iter) ------------
// The third loop mechanism from OI-13, and the one the kernel itself flags as risky:
// `bpf_is_state_visited` (states.c) special-cases iterator loop detection with the
// comment that `states_maybe_looping()` is "too simplistic in detecting states that
// *might* be equivalent, because it doesn't know about ID remapping, so don't even
// perform it". A special case in the pruning path, justified by an admitted
// simplification, is the densest target on the list.
//
// The cost is real and it is why this is a PROBE first: an iterator loop is built from
// kfunc calls, and a kfunc call is `BPF_CALL` with `src_reg = BPF_PSEUDO_KFUNC_CALL` and
// `imm` = the function's BTF id -- a number that only exists at load time, in the
// running kernel's own BTF. With no libbpf, the harness has to read
// /sys/kernel/btf/vmlinux and walk the type section itself.
//
// The walk is the fiddly part: every BTF type is a fixed 12-byte header followed by
// kind-specific trailing data, so skipping a type wrong desynchronises every id after
// it -- and a wrong id is not a load error, it is a call to a DIFFERENT function. The
// distro header we compile against stops at BTF_KIND_FLOAT, so the three kinds added
// since (DECL_TAG, TYPE_TAG, ENUM64) are defined here; without them the walk would
// silently drift on any modern vmlinux.
#ifndef BTF_KIND_DECL_TAG
#define BTF_KIND_DECL_TAG 17
#endif
#ifndef BTF_KIND_TYPE_TAG
#define BTF_KIND_TYPE_TAG 18
#endif
#ifndef BTF_KIND_ENUM64
#define BTF_KIND_ENUM64 19
#endif

static char *g_btf;
static unsigned g_btf_len;

static int btf_load_vmlinux(void) {
    if (g_btf) return 0;
    FILE *f = fopen("/sys/kernel/btf/vmlinux", "rb");
    if (!f) return -1;
    unsigned cap = 1u << 24, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return -1; }
    size_t r;
    while ((r = fread(buf + len, 1, cap - len, f)) > 0) {
        len += (unsigned)r;
        if (len == cap) break;
    }
    fclose(f);
    g_btf = buf; g_btf_len = len;
    return 0;
}

/* Trailing bytes after the 12-byte btf_type header, per kind. */
static long btf_type_tail(unsigned kind, unsigned vlen) {
    switch (kind) {
    case BTF_KIND_INT:        return 4;
    case BTF_KIND_ARRAY:      return 12;                 /* struct btf_array */
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:      return (long)vlen * 12;    /* struct btf_member */
    case BTF_KIND_ENUM:       return (long)vlen * 8;     /* struct btf_enum */
    case BTF_KIND_FUNC_PROTO: return (long)vlen * 8;     /* struct btf_param */
    case BTF_KIND_VAR:        return 4;                  /* struct btf_var */
    case BTF_KIND_DATASEC:    return (long)vlen * 12;    /* struct btf_var_secinfo */
    case BTF_KIND_DECL_TAG:   return 4;                  /* struct btf_decl_tag */
    case BTF_KIND_ENUM64:     return (long)vlen * 12;    /* struct btf_enum64 */
    default:                  return 0;                  /* PTR, FWD, TYPEDEF, CONST,
                                                            VOLATILE, RESTRICT, FUNC,
                                                            FLOAT, TYPE_TAG */
    }
}

/* Resolve a BTF_KIND_FUNC by name -> its BTF id, or -1. */
static int btf_find_func_id(const char *want) {
    if (btf_load_vmlinux() < 0) return -1;
    if (g_btf_len < sizeof(struct btf_header)) return -1;
    const struct btf_header *h = (const void *)g_btf;
    if (h->magic != 0xeB9F) return -1;
    const char *types = g_btf + h->hdr_len + h->type_off;
    const char *tend  = types + h->type_len;
    const char *strs  = g_btf + h->hdr_len + h->str_off;
    const char *p = types;
    int id = 0;
    while (p + 12 <= tend) {
        id++;
        unsigned name_off, info;
        memcpy(&name_off, p, 4);
        memcpy(&info, p + 4, 4);
        unsigned kind = BTF_INFO_KIND(info);
        unsigned vlen = info & 0xffff;
        if (kind == BTF_KIND_FUNC && name_off &&
            strcmp(strs + name_off, want) == 0)
            return id;
        p += 12 + btf_type_tail(kind, vlen);
    }
    return -1;
}

#ifndef BPF_PSEUDO_KFUNC_CALL
#define BPF_PSEUDO_KFUNC_CALL 2
#endif
#define BPF_KFUNC_CALL(BTF_ID)                                                 \
    ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                             \
                       .dst_reg = 0, .src_reg = BPF_PSEUDO_KFUNC_CALL,         \
                       .off = 0, .imm = (BTF_ID)})

/* struct bpf_iter_num is 8 bytes, 8-aligned (uapi/linux/bpf.h), so the iterator lives
   in the stack slot at fp-8 and the verifier tracks that slot's iterator state. */
#define ITER_SLOT 8

struct iter_ids { int new_id, next_id, destroy_id; };

static int iter_resolve(struct iter_ids *out) {
    out->new_id     = btf_find_func_id("bpf_iter_num_new");
    out->next_id    = btf_find_func_id("bpf_iter_num_next");
    out->destroy_id = btf_find_func_id("bpf_iter_num_destroy");
    return (out->new_id > 0 && out->next_id > 0 && out->destroy_id > 0) ? 0 : -1;
}

/* Emit the canonical open-coded iterator loop, with `body` shaping r6 each iteration.
   Layout:
       r1 = fp-8; r2 = start; r3 = end; call bpf_iter_num_new
   head:
       r1 = fp-8; call bpf_iter_num_next; if r0 == 0 goto done
       <body>
       goto head
   done:
       r1 = fp-8; call bpf_iter_num_destroy                                        */
static int emit_iter_loop(struct bpf_insn *ins, int n, const struct iter_ids *ids,
                          int start, int end, enum loop_body body) {
    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -ITER_SLOT);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_2, start);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_3, end);
    ins[n++] = BPF_KFUNC_CALL(ids->new_id);

    const int head = n;
    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -ITER_SLOT);
    ins[n++] = BPF_KFUNC_CALL(ids->next_id);
    const int jdone = n;
    ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    n = emit_loop_body(ins, n, body);
    const int jback = n;
    ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, head - jback - 1);
    n++;
    ins[jdone].off = n - jdone - 1;

    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -ITER_SLOT);
    ins[n++] = BPF_KFUNC_CALL(ids->destroy_id);
    return n;
}

/* Not in the distro uapi header. The value is read off the kernel's own helper mapper,
   `FN(dynptr_from_mem, 197, ##ctx)` in include/uapi/linux/bpf.h — verified rather than
   guessed, because a wrong helper id is not a load error, it calls a DIFFERENT helper. */
#ifndef BPF_FUNC_dynptr_from_mem
#define BPF_FUNC_dynptr_from_mem 197
#endif

// ---- calibration probe: the sign-extension truncation (--probe-sx) -----------
// The FIXED half of calibration pair four, captured rather than derived.
//
// THE BUG. Commit ae67b9fb8c4e, "bpf: Fix truncation bug in coerce_reg_to_size_sx()"
// (2024-10-14), reported by Shung-Hsi Yu and Zac Ecob. After a sign-extending move the
// verifier wrote the new bounds with a CHAINED assignment:
//
//     reg->umin_value = reg->u32_min_value = s64_min;
//
// which is `u32_min_value = (u32)s64_min` first and then `umin_value = u32_min_value` —
// so the 64-bit bound is set from the already-TRUNCATED 32-bit one. The fix only swaps
// the order (`reg->u32_min_value = reg->umin_value = s64_min`), which assigns the 64-bit
// field first and derives the 32-bit one from it.
//
// WHY IT IS VISIBLE TO US. The same function sets `var_off = tnum_range(s64_min, s64_max)`
// from the UNtruncated values, so on the buggy kernel the tnum says
// [0xfffffffffffffffe, 0xffffffffffffffff] while the unsigned bounds say
// [0xfffffffe, 0xffffffff]. Those two sets are DISJOINT, and disjoint tnum-vs-bounds is
// the project's oldest invariant — `tnum_bounds_inconsistent`, from the first leg.
//
// THE SHAPE, transcribed from the commit's own disassembly: take an unknown scalar, mask
// it to one bit, add a constant that puts the pair just below the width's sign boundary,
// then sign-extend at that width. `r0 &= 1` then `r0 += 254` gives [254, 255], and
// `(s8)` maps that to [-2, -1] — both negative, which is the branch the bug lives in.
// The s16 and s32 arms are the same shape at the other two widths.
//
// This probe runs on the CURRENT kernel, so what it captures is the FIXED behaviour. The
// buggy side comes from the commit message, which quotes the corrupted state directly.
static void run_probe_sx(void) {
    static const struct { const char *name; int off; int add; } ARMS[] = {
        {"s8",  8,  254},        /* [254,255]     -> (s8)  -> [-2,-1] */
        {"s16", 16, 65534},      /* [65534,65535] -> (s16) -> [-2,-1] */
        {"s32", 32, -2},         /* [-2,-1]       -> (s32) -> [-2,-1] */
    };
    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[8];
        int n = 0;
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, ARMS[a].add);
        /* `r0 = (sN)r0`: BPF_ALU64|BPF_MOV|BPF_X with the width in `off`. */
        ins[n++] = (struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,
                                     .dst_reg = BPF_REG_0, .src_reg = BPF_REG_0,
                                     .off = (short)ARMS[a].off, .imm = 0};
        ins[n++] = BPF_EXIT_INSN();

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int err = errno;
        if (fd >= 0) close(fd);

        printf("===PROG sx#ae67b9fb8c4e#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : err);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
}

// ---- calibration probe: the broken scalar link (--probe-idlink) --------------
// Calibration pair five (af9e89d8dd39, "bpf: Preserve id of register in
// sync_linked_regs()", 2026-01), and the first target whose bug is an OVER-REJECTION
// rather than an unsoundness — which makes the question "what channel could see it?"
// the whole point of the leg.
//
// THE BUG. `sync_linked_regs()` copied `known_reg`'s id onto `reg` when propagating
// bounds, including the BPF_ADD_CONST flag. So after
//     r1 = r0        ; both get id=1
//     r1 += 4        ; r1 gets id=1+4 (ADD_CONST)
//     if r1 < 10 ... ; sync propagates r1's bounds to r0 AND gives r0 ADD_CONST too
// the next `r2 = r0` sees ADD_CONST on r0, and `assign_scalar_id_before_mov` mints a
// FRESH id for it — silently breaking r0's link to r1. Later bounds found for r1 then
// never reach r0.
//
// WHY IT MATTERS TO US. The resulting state is perfectly self-consistent; it is merely
// WIDER than the truth. Every invariant this project has is an internal-consistency
// check, so none of them can fire — an over-approximation is exactly what a sound
// verifier is allowed to produce. The bug is observable only in the VERDICT: the
// selftest program is safe iff the verifier is precise enough to prove the branch at
// insn 7 is always taken, so a buggy kernel rejects it with "div by zero" and a fixed
// one accepts.
//
// THE PROGRAM, transcribed from the commit's own disassembly, plus a CONTROL that
// removes only the second link (`r2 = r0`). Without that instruction nothing re-mints
// r0's id, so the control must accept on BOTH kernels — if it flips too, the flip is
// not about the broken link and the arm proves nothing.
static void run_probe_idlink(void) {
    for (int arm = 0; arm < 2; arm++) {
        const int second_link = (arm == 0);   /* arm 0 = the trigger, arm 1 = control */
        struct bpf_insn ins[16];
        int n = 0, j_a, j_b, j_c;
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 255);   /* r0 in [0,255]        */
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);      /* link: both get id=1  */
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 4);     /* r1 gets id=1+4       */
        j_a = n; ins[n++] = BPF_JMP_IMM(BPF_JLT, BPF_REG_1, 10, 0);
        if (second_link)
            ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);  /* THE trigger          */
        j_b = n; ins[n++] = BPF_JMP_IMM(BPF_JLT, BPF_REG_1, 14, 0);
        /* r1 >= 14 implies r0 >= 10, so this branch is always taken — IF the link held. */
        j_c = n; ins[n++] = BPF_JMP_IMM(BPF_JGE, BPF_REG_0, 10, 0);
        /* Reachable only when the verifier lost the bound. `div by zero` is a static
         * reject, so reachability alone decides the verdict. */
        ins[n++] = BPF_ALU64_IMM(BPF_DIV, BPF_REG_0, 0);
        const int exit_at = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        ins[j_a].off = exit_at - j_a - 1;
        ins[j_b].off = exit_at - j_b - 1;
        ins[j_c].off = exit_at - j_c - 1;

        struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
        struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                                 g_log2, sizeof(g_log2));
        struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                                 g_log2, sizeof(g_log2));

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        if (fd >= 0) close(fd);

        printf("===PROG idlink#af9e89d8dd39#%s type=socket_filter ===\n",
               second_link ? "trigger" : "control");
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               base.accept ? "accept" : "reject", base.accept ? 1 : -1, base.err);
        printf("PRUNE fall=idlink taken=c0 fall_safe=1 taken_safe=1 stack=0"
               " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
               " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
               " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
               base.accept ? "accept" : "reject", base.err, base.states, base.reason,
               freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
               inv.accept ? "accept" : "reject", inv.err, inv.reason);
        /* The state-level tell the commit points at: whether the second link re-minted
         * r0's id, quoted so a capture explains itself without the pipeline. */
        printf("CHANNEL div_by_zero_reject=%d\n",
               strstr(g_log, "div by zero") != NULL);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
}

/* Report — and optionally change — which implementation will execute the programs.
 *
 * A capture that does not say whether the JIT was on is ambiguous about the most important
 * thing in a JIT-vs-interpreter differential, so this prints the mode unconditionally.
 * `--nojit` asks for the interpreter; on a kernel built with CONFIG_BPF_JIT_ALWAYS_ON the
 * write is refused and the read-back says so rather than the run silently proceeding under
 * the JIT and being labelled as interpreted. */
static void report_jit_mode(int argc, char **argv) {
    int want_off = 0;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--nojit") == 0) want_off = 1;
    const char *path = "/proc/sys/net/core/bpf_jit_enable";
    if (want_off) {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) { ssize_t w = write(fd, "0\n", 2); (void)w; close(fd); }
    }
    char buf[16] = {0};
    int actual = -1;
    int fd = open(path, O_RDONLY);
    if (fd >= 0) { ssize_t r = read(fd, buf, sizeof(buf) - 1); (void)r; close(fd); actual = atoi(buf); }
    printf("JITMODE requested=%s actual=%d\n", want_off ? "interp" : "default", actual);
}

// ---- is an atomic RMW on an UNINITIALISED stack slot accepted? (--probe-uninit) ----
//
// The coverage-guided run produced thousands of disagreements the moment atomics were
// added, and the kernel's side of them was not a wrong computation but values like
// 0xffff8c00 and 0x050a3c78 — stale kernel stack. Triage order says the generator first:
// its atomic step targets fp-32/fp-28, and nothing necessarily writes there beforehand, so
// it emits programs that are not closed-form and the reference cannot predict them. That
// is a harness bug and it is fixed separately.
//
// But it raises a question worth answering precisely rather than assuming: the verifier
// normally REJECTS a read from an uninitialised stack slot ("invalid read from stack").
// check_atomic_rmw calls check_mem_access(BPF_READ) twice — once with value_regno = -1 and
// again with the load register — so if the first call has the side effect of marking the
// slot initialised, the second would pass and a fetching atomic would hand the program
// whatever was on the kernel stack.
//
// This probe asks that one question with a control beside it. Both programs touch the SAME
// untouched slot; only the instruction differs.
//   plain   — an ordinary 8-byte load. Expected: REJECTED.
//   atomic  — a fetch-add. If this is ACCEPTED, the asymmetry is real, and the returned
//             value says whether anything was leaked.
// The atomic arm is run three times: a value that changes between runs of the SAME program
// is uninitialised memory, not a computation.
static void run_probe_uninit(void) {
    for (int arm = 0; arm < 2; arm++) {
        struct bpf_insn ins[8];
        int n = 0;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_1, 1);
        if (arm == 0) {
            ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -64);
        } else {
            ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
            ins[n++] = (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW,
                                         .dst_reg = BPF_REG_10, .src_reg = BPF_REG_1,
                                         .off = -64, .imm = BPF_ADD | BPF_FETCH};
            ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_1);
        }
        ins[n++] = BPF_EXIT_INSN();

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("UNINIT arm=%s load=%s errno=%d\n",
               arm == 0 ? "plain_load" : "atomic_fetch",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : lerr);
        if (fd >= 0) {
            for (int r = 0; r < 3; r++) {
                static char pin[64], pout[64];
                union bpf_attr t;
                memset(&t, 0, sizeof(t));
                t.test.prog_fd = fd;
                t.test.data_in = (uint64_t)(unsigned long)pin;
                t.test.data_out = (uint64_t)(unsigned long)pout;
                t.test.data_size_in = sizeof(pin);
                t.test.data_size_out = sizeof(pout);
                t.test.repeat = 1;
                if (bpf(BPF_PROG_TEST_RUN, &t, sizeof(t)) == 0)
                    printf("UNINIT arm=%s run=%d retval=0x%08x\n",
                           arm == 0 ? "plain_load" : "atomic_fetch", r, t.test.retval);
                else
                    printf("UNINIT arm=%s run=%d testrun_errno=%d\n",
                           arm == 0 ? "plain_load" : "atomic_fetch", r, errno);
            }
            close(fd);
        } else {
            /* The rejection text is the interesting half for the control arm. */
            const char *nl = strrchr(g_log, '\n');
            printf("UNINIT arm=%s reason=%s\n", arm == 0 ? "plain_load" : "atomic_fetch",
                   nl && nl != g_log ? "see log" : "(none)");
            printf("---LOG---\n%s\n---END---\n", g_log);
        }
    }
}

// ---- KCOV: does the verifier's code coverage actually vary per program? ------
//
// The plan is coverage-guided generation: keep and mutate the programs that reach kernel
// code nothing has reached yet. That only works if a program's load actually PRODUCES a
// distinguishing coverage signal — if two different programs light up the same PCs, the
// feedback carries no information and the whole idea is dead. So this measures it before
// anything is built on it.
//
// KCOV is per-task and excludes interrupts, so what it records here is essentially the
// BPF_PROG_LOAD syscall path — the verifier. CONFIG_KCOV_INSTRUMENT_ALL means every
// kernel function is instrumented, so the absolute counts are large; what matters is
// whether the SETS differ.
#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE     _IO('c', 100)
#define KCOV_DISABLE    _IO('c', 101)
#define KCOV_TRACE_PC   0
/* Sized against the LONGEST program the grammar emits, not the average. 0085 lengthened
   genomes to 6-20 genes and 41 loads in 144k promptly filled a 1<<18 buffer — and a
   truncated load loses coverage, which looks exactly like a plateau. The guest has room for
   the larger mapping; the harness's own footprint is a few megabytes either way.
   RAISED AGAIN AFTER 0095. The iterator gene put three kfunc calls and a back-edge into 59%
   of programs, and the first million-program hunt came back `trunc=1` — one load in 1,011,360
   refilled a 1<<20 buffer. One in a million does not move `seen_pcs`, but the DIRECTION does:
   truncation had been 0 and returned the moment the grammar reached deeper code, so the next
   gene would climb from here. 1<<21 is 16 MB of a guest with 1.6 GB free. The point of the
   counter is that "plateaued" and "overflowed" must never be able to look alike. */
#define KCOV_ENTRIES    (1 << 21)

struct kcov_ctx { int fd; unsigned long *area; };

static int kcov_open(struct kcov_ctx *k) {
    k->fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (k->fd < 0) return -1;
    if (ioctl(k->fd, KCOV_INIT_TRACE, (unsigned long)KCOV_ENTRIES) != 0) {
        close(k->fd); k->fd = -1; return -1;
    }
    k->area = (unsigned long *)mmap(NULL, KCOV_ENTRIES * sizeof(unsigned long),
                                    PROT_READ | PROT_WRITE, MAP_SHARED, k->fd, 0);
    if (k->area == MAP_FAILED) { close(k->fd); k->fd = -1; return -1; }
    return 0;
}
/* Coverage is collected for the calling thread between ENABLE and DISABLE; area[0] is the
   number of PCs recorded, area[1..] the PCs themselves. */
static void kcov_start(struct kcov_ctx *k) {
    if (k->fd < 0) return;
    ioctl(k->fd, KCOV_ENABLE, KCOV_TRACE_PC);
    __atomic_store_n(&k->area[0], 0, __ATOMIC_RELAXED);
}
static unsigned long kcov_stop(struct kcov_ctx *k) {
    if (k->fd < 0) return 0;
    unsigned long n = __atomic_load_n(&k->area[0], __ATOMIC_RELAXED);
    ioctl(k->fd, KCOV_DISABLE, 0);
    return n < KCOV_ENTRIES ? n : KCOV_ENTRIES - 1;
}

/* A cheap set of seen PCs: open-addressed table over the low bits, enough for a probe. */
#define KSEEN_BITS 20
#define KSEEN_N (1u << KSEEN_BITS)
static unsigned long *g_kseen;
static unsigned g_kseen_count;
static int kseen_add(unsigned long pc) {   /* 1 if new */
    unsigned h = (unsigned)((pc * 0x9e3779b97f4a7c15ULL) >> (64 - KSEEN_BITS));
    for (unsigned i = 0; i < 64; i++) {
        unsigned s = (h + i) & (KSEEN_N - 1);
        if (g_kseen[s] == 0) { g_kseen[s] = pc; g_kseen_count++; return 1; }
        if (g_kseen[s] == pc) return 0;
    }
    return 0;
}

static void run_probe_kcov(void) {
    struct kcov_ctx k;
    if (kcov_open(&k) != 0) {
        printf("KCOV unavailable errno=%d (is debugfs mounted and CONFIG_KCOV set?)\n", errno);
        return;
    }
    g_kseen = (unsigned long *)calloc(KSEEN_N, sizeof(unsigned long));
    if (!g_kseen) { printf("KCOV alloc failed\n"); return; }

    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));

    /* Deliberately DIFFERENT shapes, so "coverage varies" is a claim about the verifier's
       paths and not about noise: a bare exit, plain ALU, a branch, a spill/reload, a
       linked pair with a delta, and a rejected program. */
    /* A LOCAL rng, deliberately. This probe sits above the gen-intent family, and reusing
       that family's gi_pick() would be the declaration-ordering trap for the fourth time
       (0045 LOOPR_INPUTS, 0054 BPF_FUNC_dynptr_from_mem, 0056 the coverage tables). The
       cheapest cure is not to hoist but not to depend. */
    uint32_t kr = 0x12345678u;
    #define KPICK(N) ({ kr ^= kr << 13; kr ^= kr >> 17; kr ^= kr << 5; (int)(kr % (unsigned)(N)); })
    for (int prog = 0; prog < 24; prog++) {
        struct bpf_insn ins[64];
        int n = 0;
        const int kind = prog % 6;
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
        switch (kind) {
        case 0: break;
        case 1: ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7 + KPICK(24)); break;
        case 2: ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 3 + KPICK(12), 1);
                ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0); break;
        case 3: ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -16);
                ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, -16); break;
        case 4: ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
                ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4);
                ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 12, 1);
                ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_7); break;
        case 5: ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_6);
                ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, 0, 1); break;  /* expect reject */
        }
        ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
        ins[n++] = BPF_EXIT_INSN();
        const int e0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        ins[jnull].off = e0 - jnull - 1;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";

        kcov_start(&k);
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        unsigned long cnt = kcov_stop(&k);
        int lerr = errno;
        if (fd >= 0) close(fd);

        unsigned fresh = 0;
        for (unsigned long i = 0; i < cnt; i++)
            fresh += (unsigned)kseen_add(k.area[i + 1]);
        printf("KCOV prog=%02d kind=%d verdict=%s errno=%d pcs=%lu new=%u total_seen=%u\n",
               prog, kind, fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : lerr,
               cnt, fresh, g_kseen_count);
    }
    close(map_in);
    free(g_kseen);
    #undef KPICK
}

// ---- the aimed closed-form family (--gen-intent) ----------------------------
// THE HUNT. This is the first family whose oracle does not consult the verifier at all.
// Each program's return value is computed by bpfref.h — an independent implementation of
// the ISA, calibrated against the kernel on sixteen traps (0073) — and compared against
// what the kernel's JIT actually returns. A disagreement means an ACCEPTED program did
// something its own instructions do not permit.
//
// WHY THIS SHAPE. Screening the tree's history for "accepted program behaves differently
// from what its instructions mean" found thirteen instances, six of them in the last 34
// months and four in a single month, with two commit messages using the phrase
// "verifier-vs-runtime mismatch" outright. The single most productive shape is
// LINK-THEN-DIVERGE: mint a shared scalar id with `rB = rA`, tag one member with a
// constant delta, do something that should but might not fully clear the link, then narrow
// one member by a branch and USE the other. That is exactly what calibration pair five
// (af9e89d8dd39) named and what the `relink` composition piece was built from. The second
// most productive is a 32-bit width or sign mis-tracking consumed by a signed compare.
//
// CLOSED-FORM FOR US, UNKNOWN TO THE VERIFIER. Pure constants would leave nothing for the
// range tracker to get wrong, so the seed scalars are read from a map — which the verifier
// cannot see into, and which this harness wrote a moment earlier. bpfref therefore starts
// at the BODY with those seeds preloaded; the fixed prologue (lookup + three loads) is not
// interpreted, and the null path returns a sentinel so a failed lookup can never be
// mistaken for a computed answer.
#define GI_MAXPROG 4096
#define GI_NULL_SENTINEL 0xdead
#define GI_INPUTS_N 8
/* Chosen for the boundaries the historical fixes cluster on: zero, small values that stay
   inside a narrowing bound, the signed 32-bit extremes, and -1 — the divisor that makes
   the sdiv overflow case reachable. */
static const uint32_t GI_INPUTS[GI_INPUTS_N] = {
    0, 1, 7, 0x7fffffff, 0x80000000, 0xffffffff, 0xfffffff9, 0x0000ffff
};

struct gi_ctx { uint32_t rng; };
static uint32_t gi_rand(struct gi_ctx *c) {
    c->rng ^= c->rng << 13; c->rng ^= c->rng >> 17; c->rng ^= c->rng << 5;
    return c->rng;
}
static int gi_pick(struct gi_ctx *c, int n) { return (int)(gi_rand(c) % (unsigned)n); }

/* The body's alphabet, weighted toward the two shapes history says break most often. */
enum gi_step {
    GI_LINK,      /* rB = rA — mints the shared id                                  */
    GI_DELTA,     /* rB += C (alu64) or wB += C (alu32): the ADD_CONST tag           */
    GI_SELFOP,    /* rA op= rA — dst mutated before delta tracking reads src         */
    GI_CLEAROP,   /* a non-add/sub op that should clear the link but may leave delta */
    GI_NARROW,    /* branch on one member; the bound must reach the other            */
    GI_RELINK,    /* a SECOND link taken from the base after a sync                  */
    GI_SPILL,     /* spill and refill, sometimes sign-extending the refill           */
    GI_W32,       /* a 32-bit ALU op — width mis-tracking                            */
    GI_SHIFT,     /* logical or arithmetic shift, both widths                        */
    GI_SCMP,      /* a signed compare, 64- or 32-bit, consuming the above            */
    GI_PAIR,      /* the whole link-then-diverge shape, emitted as one unit           */
    GI_STORE,     /* a store through a map value — the grammar's DECISION surface      */
    GI_STACKVAR,  /* VARIABLE-offset stack access, stored and read back                 */
    GI_ATOMIC,    /* atomic RMW — 250 lines of verifier code no other step reaches       */
    GI_MOVSX,     /* register-to-register sign-extending MOV — a DIFFERENT kernel path   */
    GI_DIAMOND,   /* a branch that RECONVERGES — two states meeting, which is what        */
                  /* states_equal actually compares                                       */
    GI_LOOP,      /* a COUNTED back-edge: deep state exploration, and deterministic       */
    GI_PIN,       /* make the verifier believe it knows the value EXACTLY              */
    GI_SDIV,      /* signed div/mod — the interpreter-level UB shape                   */
    GI_ITER,      /* an open-coded iterator loop — the grammar's FIRST kfunc calls,      */
                  /* and with them 13% of the verification pass it had never entered     */
    GI_STEP_N
};

static const char *gi_step_name(enum gi_step s) {
    switch (s) {
    case GI_LINK: return "link"; case GI_DELTA: return "delta";
    case GI_SELFOP: return "selfop"; case GI_CLEAROP: return "clear";
    case GI_NARROW: return "narrow"; case GI_RELINK: return "relink";
    case GI_SPILL: return "spill"; case GI_W32: return "w32";
    case GI_SHIFT: return "shift"; case GI_SCMP: return "scmp";
    case GI_PAIR: return "pair"; case GI_PIN: return "pin";
    case GI_STORE: return "store";
    case GI_STACKVAR: return "stackvar";
    case GI_ATOMIC: return "atomic";
    case GI_MOVSX: return "movsx";
    case GI_DIAMOND: return "diamond";
    case GI_LOOP: return "loop";
    case GI_SDIV: return "sdiv";
    case GI_ITER: return "iter";
    default: return "?";
    }
}

/* Read and write net.core.bpf_jit_enable. A kernel built with
   CONFIG_BPF_JIT_ALWAYS_ON refuses the write, which is reported rather than assumed. */
static int gi_read_jit(void) {
    char buf[16] = {0};
    int fd = open("/proc/sys/net/core/bpf_jit_enable", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return r > 0 ? atoi(buf) : -1;
}
static int gi_set_jit(int v) {
    char buf[8];
    int len = snprintf(buf, sizeof(buf), "%d\n", v);
    int fd = open("/proc/sys/net/core/bpf_jit_enable", O_WRONLY);
    if (fd < 0) return -1;
    ssize_t w = write(fd, buf, (size_t)len);
    close(fd);
    return (w == len && gi_read_jit() == v) ? 0 : -1;
}

/* THE GENOME. A program body is a short list of genes, each a step plus its parameters,
   and `gi_emit_body` is DETERMINISTIC given one — no rng inside. That is what makes a body
   mutable and reproducible: the coverage-guided loop keeps genomes, perturbs them, and can
   replay any of them exactly. It also keeps every mutant inside the typed grammar, so a
   mutation cannot produce a malformed program the way byte-level mutation would. */
/* LONGER PROGRAMS, because that is what makes the verifier CHECKPOINT. is_state_visited
   only records a state when `jmps_processed - prev >= 2 && insn_processed - prev >= 8`
   (kernel/bpf/states.c), so a short program with a couple of branches produces almost no
   checkpoints — which is exactly why the measured depth was avgstates=1 and the pruning
   differential was comparing nothing. The lever is not loops but LENGTH times BRANCHES. */
/* THE ITERATOR'S OWN STACK SLOT. `ITER_SLOT` is fp-8, which is exactly where the grammar's
   spill genes start (`stack_next = -8`); sharing it would let a spill overwrite a live
   `struct bpf_iter_num` and turn every such program into a structural rejection. The grammar
   bounds itself at -200, so -256 is out of its reach by construction. */
#define GI_ITER_SLOT 256

/* Resolved once per fuzz run, from the BTF walk the harness already does. Left at zero when
   the kernel has no BTF or the symbols move: the gene then emits nothing rather than a call
   to id 0, and `iterskipped` says how often that happened. */
static struct iter_ids g_fz_iter;
static int g_fz_iter_ok = 0;
static unsigned long g_fz_iter_emitted = 0, g_fz_iter_skipped = 0;

#define GI_MAXGENES 24
struct gi_gene { uint8_t st, a, b, k, opt; };
struct gi_genome { uint8_t n, hi; struct gi_gene g[GI_MAXGENES]; };

static void gi_gene_random(struct gi_ctx *c, struct gi_gene *g) {
    g->st  = (uint8_t)gi_pick(c, GI_STEP_N);
    g->a   = (uint8_t)gi_pick(c, 3);
    g->b   = (uint8_t)gi_pick(c, 3);
    g->k   = (uint8_t)(1 + gi_pick(c, 15));
    g->opt = (uint8_t)gi_pick(c, 64);
}
static void gi_genome_random(struct gi_ctx *c, struct gi_genome *G) {
    G->n = (uint8_t)(6 + gi_pick(c, 15));
    G->hi = (uint8_t)gi_pick(c, 2);
    for (int i = 0; i < G->n; i++) gi_gene_random(c, &G->g[i]);
}

/* Emit one genome. Every choice comes from the gene, never from an rng. */
/* Store sites emitted by the LAST gi_emit_body() call, so the fuzz loop can ask the
   verifier what it claimed about each one. A file-scope array rather than another
   out-parameter: gi_emit_body has three call sites and only one of them wants this. */
#define GI_MAXSTORES 32
/* `fixed >= 0` means the site's landing offset is a CONSTANT and needs no claim from the
   log — the atomic gene writes at a literal offset. Registering those matters as much as
   registering the variable ones: the first run left them out and 15,696 of 16,084 observed
   bytes had no claim, while the ones that did were judged against a DIFFERENT site's claim
   and produced 79 desyncs on a kernel known to be correct. All ours, all from an incomplete
   site list. */
struct gi_store_site { int insn; int k; int fixed; };
static struct gi_store_site g_gi_stores[GI_MAXSTORES];
static int g_gi_nstores;

static int gi_emit_body(const struct gi_genome *G, struct bpf_insn *ins, int n,
                        int *jexit, int *nx, char *recipe, size_t rsz) {
    g_gi_nstores = 0;
    /* Only r6/r7/r9 are seeded by the prologue; picking r8 read an uninitialised register
       and cost 207 of an early run's 512 programs a STRUCTURAL rejection (0074). */
    static const int REGS[3] = { 6, 7, 9 };
    int stack_next = -8;
    int loops_emitted = 0;
    int iters_emitted = 0;
    for (int s = 0; s < G->n && s < GI_MAXGENES; s++) {
        const struct gi_gene *g = &G->g[s];
        const enum gi_step st = (enum gi_step)(g->st % GI_STEP_N);
        const int A = REGS[g->a % 3];
        int B = REGS[g->b % 3];
        if (B == A) B = (A == 6 ? 7 : 6);
        const int K = 1 + (g->k % 15);
        const unsigned o = g->opt;
        switch (st) {
        case GI_LINK:
            ins[n++] = BPF_MOV64_REG(B, A);
            break;
        case GI_DELTA:
            if (o & 1) ins[n++] = BPF_ALU64_IMM(BPF_ADD, B, K);
            else       ins[n++] = BPF_ALU32_IMM(BPF_ADD, B, K);
            break;
        case GI_SELFOP: {
            static const int ops[] = { BPF_ADD, BPF_SUB, BPF_XOR, BPF_OR };
            ins[n++] = BPF_ALU64_REG(ops[o & 3], A, A);
            break;
        }
        case GI_CLEAROP: {
            static const int ops[] = { BPF_XOR, BPF_OR, BPF_AND, BPF_MUL };
            ins[n++] = BPF_ALU64_IMM(ops[o & 3], B, K);
            break;
        }
        case GI_NARROW:
            jexit[(*nx)++] = n;
            ins[n++] = BPF_JMP_IMM(BPF_JGT, B, K, 0);
            break;
        case GI_RELINK:
            ins[n++] = BPF_MOV64_REG(9, A);
            break;
        case GI_SPILL:
            if (stack_next > -200) stack_next -= 8;
            ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, A, stack_next);
            if ((o % 3) == 0)
                ins[n++] = (struct bpf_insn){.code = BPF_LDX | BPF_MEMSX | BPF_W,
                                             .dst_reg = A, .src_reg = BPF_REG_10,
                                             .off = (short)stack_next, .imm = 0};
            else
                ins[n++] = BPF_LDX_MEM(BPF_DW, A, BPF_REG_10, stack_next);
            break;
        case GI_W32: {
            static const int ops[] = { BPF_ADD, BPF_SUB, BPF_MUL, BPF_AND, BPF_OR, BPF_XOR };
            ins[n++] = BPF_ALU32_IMM(ops[o % 6], A, K);
            break;
        }
        case GI_SHIFT: {
            const int sh = 1 + (o % 31);
            switch ((o >> 5) & 3) {
            case 0: ins[n++] = BPF_ALU64_IMM(BPF_LSH, A, sh); break;
            case 1: ins[n++] = BPF_ALU64_IMM(BPF_RSH, A, sh); break;
            case 2: ins[n++] = BPF_ALU64_IMM(BPF_ARSH, A, sh); break;
            default: ins[n++] = BPF_ALU32_IMM(BPF_ARSH, A, sh); break;
            }
            break;
        }
        case GI_SCMP:
            jexit[(*nx)++] = n;
            if (o & 1) ins[n++] = BPF_JMP_IMM(BPF_JSLT, A, K, 0);
            else       ins[n++] = BPF_JMP32_IMM(BPF_JSLT, A, K, 0);
            break;
        case GI_SDIV: {
            /* Subclass B: the interpreter/JIT disagreeing with the ISA rather than with the
               verifier. off=1 selects the signed forms, and the divisor is a register so the
               verifier must insert its guard rewrites. */
            const int cls = (o & 1) ? BPF_ALU64 : BPF_ALU;
            const int op = (o & 2) ? BPF_DIV : BPF_MOD;
            ins[n++] = (struct bpf_insn){.code = cls | BPF_X | op, .dst_reg = A,
                                         .src_reg = B, .off = 1, .imm = 0};
            break;
        }
        case GI_ITER: {
            /* THE GRAMMAR'S FIRST KFUNC CALLS. [[coverage-fraction]] measured that one
               feature — kfunc/BTF calls — holds 1318 of the verification pass's coverage
               points, 13% of it and four times the next largest theme, and that the grammar
               had never emitted a single one. Everything the loop had reached until now was
               scalar arithmetic and memory, which is precisely the surface the oracles are
               strongest on and precisely the surface that is saturated.
               An open-coded iterator is the cheapest way in: three kfunc calls, a real
               back-edge, and a `struct bpf_iter_num` the verifier must track across it.
               ONE PER PROGRAM. Two would need two slots and a nesting discipline; a second
               gene emits nothing rather than silently sharing fp-256 with the first. */
            if (!g_fz_iter_ok || iters_emitted) { g_fz_iter_skipped++; break; }
            if (n + 16 > 300) { g_fz_iter_skipped++; break; }
            iters_emitted++;
            g_fz_iter_emitted++;
            ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -GI_ITER_SLOT);
            ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
            ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 1 + (int)(o % 4));
            ins[n++] = BPF_KFUNC_CALL(g_fz_iter.new_id);
            const int head = n;
            ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -GI_ITER_SLOT);
            ins[n++] = BPF_KFUNC_CALL(g_fz_iter.next_id);
            const int jdone = n;
            ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
            /* The body shapes a callee-saved register so the loop-carried state actually
               changes across iterations — a body that leaves it alone is the tautology arm
               OI-13 rules out. r1-r5 are clobbered by next(), so only r6/r7/r9 may be used.
               EVERY BODY MUST KEEP AN INVARIANT, and this is the second time that has been
               learned the hard way. The verifier tracks an open-coded iterator's `depth` but
               does NOT use the constant trip range to bound it (see [[verifier-facts]]): it
               waits for the loop-carried state to CONVERGE. A monotone unbounded body never
               converges, so the state space grows until the guest is OOM-killed — which is
               what a plain `A += K` here did at 51 seconds, and what 0084 hit from the other
               direction with a counter that was also the body's target. So the increment is
               masked back into [0,7] and the alternative is idempotent. */
            if (o & 1) {
                ins[n++] = BPF_ALU64_IMM(BPF_ADD, A, K);
                ins[n++] = BPF_ALU64_IMM(BPF_AND, A, 7);
            } else {
                ins[n++] = BPF_ALU64_IMM(BPF_AND, A, 7);
            }
            ins[n] = BPF_JMP_IMM(BPF_JA, 0, 0, head - n - 1);
            n++;
            ins[jdone].off = n - jdone - 1;
            ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -GI_ITER_SLOT);
            ins[n++] = BPF_KFUNC_CALL(g_fz_iter.destroy_id);
            break;
        }
        case GI_PIN:
            /* Manufacture the state a dead-branch rewrite needs: a value the verifier
               believes it knows EXACTLY. */
            if (o & 1) {
                if (stack_next > -200) stack_next -= 8;
                const int imm = ((o & 2) ? -1 : 1) * (1 + (int)((o >> 2) % 64));
                ins[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_10, stack_next, imm);
                ins[n++] = BPF_LDX_MEM(BPF_DW, A, BPF_REG_10, stack_next);
            } else {
                jexit[(*nx)++] = n;
                ins[n++] = BPF_JMP_IMM(BPF_JNE, A, K, 0);
            }
            break;
        case GI_STORE: {
            /* THE GRAMMAR'S CEILING, RAISED. 0078 measured 456k programs and not one
               rejection: with no memory access whose bound must be PROVEN, the verifier
               never makes a hard decision and its whole rejection path — check_mem_access,
               adjust_ptr_min_max_vals, the bounds refinement around them — is unreachable.
               This adds the decision: copy the map-value pointer, offset it by a scalar
               whose range the verifier has to know, and store one byte.
               r8 holds the pointer and is never itself modified, so the shape can repeat;
               r1 is dead after the prologue's helper call and serves as scratch. */
            ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
            ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, A);
            if (g_gi_nstores < GI_MAXSTORES) {
                /* The claim to ask for is r1's, ON the store instruction: for a pointer the
                   printed bounds ARE the variable offset, and `K` is the instruction's own
                   immediate on top of it. The store-location family declares exactly this
                   triple (`STORE insn= reg= off=`) and the offline oracle has judged it
                   since 0044 — so the in-VM reader is calibrated against that, not invented. */
                /* ASK AT THE ADD, NOT AT THE STORE. The verifier prints only the registers
                   an instruction CHANGED, and a store changes none — measured on a replayed
                   candidate, whose store line was `37: (72) *(u8 *)(r1 +2) = -1   ;` with
                   nothing after the semicolon at all. r1 gets its value on the preceding
                   `r1 += A`, and that is where the claim is printed. */
                g_gi_stores[g_gi_nstores].insn = n - 1;
                g_gi_stores[g_gi_nstores].k = (int)(K % 8);
                g_gi_stores[g_gi_nstores].fixed = -1;
                g_gi_nstores++;
            }
            ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_1, (short)(K % 8), -1);
            break;
        }
        case GI_STACKVAR: {
            /* A DIFFERENT branch of check_mem_access from the map store: the stack, and at
               a VARIABLE offset, which goes through check_stack_access_within_bounds and
               the var_off handling around it. Commit 107c26a70ca8 lived exactly here — the
               maximum end of a variable-offset indirect stack access was computed as
               `umax_value + off` with no magnitude check.
               The value is written and READ BACK into the same register, so the address the
               access actually uses reaches the return value: a disagreement about WHERE the
               access lands becomes a disagreement about WHAT the program returns, which is
               the only channel whose reference is not the verifier. */
            ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
            ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, A);
            ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_1, -64, (int)(o & 0x7f));
            ins[n++] = BPF_LDX_MEM(BPF_B, A, BPF_REG_1, -64);
            break;
        }
        case GI_ATOMIC: {
            /* RANK 1 on the reachability audit: check_atomic and its three sub-functions
               plus atomic_ptr_type_ok are ~250 lines that NO other step reaches, and the
               cost is zero — new instruction encodings on the map value and stack pointers
               the corpus already carries, same program type, same context, fully
               deterministic.
               The FETCH forms leave the OLD value in the source register, so the result of
               the atomic reaches the return value and a disagreement about it is visible
               to the one oracle whose reference is not the verifier. CMPXCHG is included
               deliberately: r0 must take the old value ALWAYS, and 39491867ace5 exists
               because x86's native CMPXCHG loads its accumulator only on failure. */
            static const int aops[] = { BPF_ADD, BPF_OR, BPF_AND, BPF_XOR };
            const int dw = (o & 1);
            const int sz = dw ? BPF_DW : BPF_W;
            int imm;
            switch ((o >> 1) & 7) {
            case 0: case 1: case 2: case 3: imm = aops[(o >> 1) & 3]; break;
            case 4: case 5: imm = aops[(o >> 4) & 3] | BPF_FETCH; break;
            case 6: imm = BPF_XCHG; break;
            default: imm = BPF_CMPXCHG; break;
            }
            /* SEED THE TARGET FIRST. An atomic RMW READS its location, and a privileged
               program is ALLOWED to read an uninitialised stack slot — measured directly
               with --probe-uninit, where a plain load of an untouched slot was accepted and
               returned 0xa7292e75, stable across runs but a function of whatever the kernel
               left there. So the read is legal and the program is simply NOT CLOSED-FORM,
               which the reference interpreter (whose stack starts zeroed) cannot predict.
               Adding the atomic step without this produced 3347 disagreements in one run,
               every one of them ours.
               Seeding from a register rather than an immediate keeps the starting value
               varied, so the shape still exercises the arithmetic rather than always
               folding from zero. */
            if (o & 0x20) {
                const short soff = (short)(dw ? -32 : -28);
                ins[n++] = BPF_STX_MEM(sz, BPF_REG_10, B, soff);
                ins[n++] = (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | sz,
                                             .dst_reg = BPF_REG_10, .src_reg = A,
                                             .off = soff, .imm = imm};
            } else {
                const short moff = (short)(dw ? 0 : 4);
                for (int q = 0; q < (dw ? 8 : 4) && g_gi_nstores < GI_MAXSTORES; q++) {
                    g_gi_stores[g_gi_nstores].insn = n;
                    g_gi_stores[g_gi_nstores].k = 0;
                    g_gi_stores[g_gi_nstores].fixed = moff + q;
                    g_gi_nstores++;
                }
                ins[n++] = BPF_STX_MEM(sz, BPF_REG_8, B, moff);
                ins[n++] = (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | sz,
                                             .dst_reg = BPF_REG_8, .src_reg = A,
                                             .off = moff, .imm = imm};
            }
            break;
        }
        case GI_MOVSX: {
            /* Justified by history rather than intuition. Screening all 21 reconstructable
               verifier fixes for "could this fuzzer have found it" produced exactly ONE
               grammar addition that flips a verdict: register-to-register MOVSX, which
               unlocks 44b7f7151dfc and 380d5f89a481 — companion patches landed the same day.
               The grammar already sign-extends, but through a stack fill (BPF_MEMSX), and
               that reaches `coerce_reg_to_size_sx`; both bugs live in
               `coerce_subreg_to_size_sx` / `set_sext32_default_val`, reachable ONLY from the
               ALU MOVSX path. Sibling feature, different function. */
            static const short widths[] = { 8, 16, 32 };
            const int cls = (o & 1) ? BPF_ALU64 : BPF_ALU;
            /* the 32-bit class has no 32-bit sign-extend: that would be a plain move */
            const int wi = (cls == BPF_ALU) ? (int)(o >> 1) % 2 : (int)(o >> 1) % 3;
            ins[n++] = (struct bpf_insn){.code = cls | BPF_X | BPF_MOV, .dst_reg = A,
                                         .src_reg = B, .off = widths[wi], .imm = 0};
            break;
        }
        case GI_DIAMOND: {
            /* THE FUEL THE PRUNING ORACLE WAS MISSING. 0083 gave the STATE_FREQ verdict
               differential a real denominator — 43,379 pairs where the flag demonstrably
               widened the state space — and it found nothing. Looking at what the grammar
               emits explains why: every branch it produces jumps straight to the tail, so
               the program is a LADDER and no two states ever meet inside the body. But
               states_equal and the pruning it drives operate exactly where two states DO
               meet, so the oracle was aimed at a region the grammar never built.
               This step builds it: a forward branch that skips a couple of instructions and
               RECONVERGES, so the merge point is reached with two different states. That is
               a diamond, and it is what a prune has to decide about. */
            const int skip_a = A, skip_b = B;
            const int jd = n;
            if (o & 1) ins[n++] = BPF_JMP_IMM(BPF_JGT, skip_a, K, 0);
            else       ins[n++] = BPF_JMP32_IMM(BPF_JGT, skip_a, K, 0);
            /* The skipped side shapes the registers differently, so the two states that
               meet at the merge are genuinely distinct rather than a formality. */
            ins[n++] = BPF_ALU64_IMM(((o >> 1) & 1) ? BPF_OR : BPF_AND, skip_b, K);
            if ((o >> 2) & 1)
                ins[n++] = BPF_ALU64_REG(BPF_ADD, skip_a, skip_b);
            ins[jd].off = n - jd - 1;          /* the merge point is right here */
            break;
        }
        case GI_LOOP: {
            /* WHAT THE PRUNING ORACLE ACTUALLY NEEDS. Measuring the search depth after
               adding diamonds gave `avgstates=1`: the verifier explores essentially ONE
               state per program, so the differential's 33k "prune pairs" were 33k trivial
               comparisons. A non-zero denominator is not enough when the individual
               comparisons cannot fail — the same lesson 0076 learned about constants, one
               level up.
               A back-edge is what makes the verifier reach one instruction repeatedly with
               DIFFERENT states, which is when states_equal and its pruning have something to
               decide. `may_goto` would do it, but its budget is TIME-based and the trip
               count is not reproducible, so it would break the closed-form property the
               reference interpreter depends on. A COUNTED loop keeps both: the verifier
               proves termination by state convergence, and the trip count is fixed. */
            /* BOUNDED HARD, because the first attempt OOM-killed the VM in 57 seconds.
               A back-edge multiplies the verifier's state count, and under KASAN each state
               is large enough that one pathological program can exhaust the guest before
               BPF_COMPLEXITY_LIMIT_STATES stops it. Two defences: a small trip count, and
               at most ONE loop per program — a genome carrying several would compound them.
               This is the cost of the fuel; the shape is worth having anyway, but not at
               the price of a guest that dies before it reports. */
            if (loops_emitted) break;
            loops_emitted = 1;
            const int trips = 2 + (int)(o % 3);          /* 2..4 */
            /* THE COUNTER MUST NOT BE THE BODY'S TARGET. r9 is one of the three scalars
               the step may pick as `A`, and when it picked itself the body mutated the
               counter — `r9 ^= K` before `r9 -= 1` — so the count stopped decreasing
               monotonically, the loop had no proof of termination, and the verifier
               explored until it exhausted the guest's memory. That is what OOM-killed the
               VM twice; capping the trip count did not help because the trip count was
               never the problem. */
            const int ctr = (A == 9) ? 7 : 9;
            ins[n++] = BPF_MOV64_IMM(ctr, trips);
            const int head = n;
            ins[n++] = BPF_ALU64_IMM(((o >> 3) & 1) ? BPF_ADD : BPF_XOR, A, K);
            ins[n++] = BPF_ALU64_IMM(BPF_SUB, ctr, 1);
            const int jback = n;
            ins[n++] = BPF_JMP_IMM(BPF_JGT, ctr, 0, 0);
            ins[jback].off = (short)(head - jback - 1);
            break;
        }
        case GI_PAIR: {
            /* The aimed shape as one unit — drawing link, delta and narrow independently
               assembled it in 2 of 305 programs (0074). */
            const int base = A, other = B;
            ins[n++] = BPF_MOV64_REG(other, base);
            if (o & 1) ins[n++] = BPF_ALU64_IMM(BPF_ADD, other, K);
            else       ins[n++] = BPF_ALU32_IMM(BPF_ADD, other, K);
            switch ((o >> 1) & 3) {
            case 0: break;
            case 1: ins[n++] = BPF_ALU64_REG(BPF_ADD, base, base); break;
            case 2: ins[n++] = BPF_ALU64_IMM(BPF_XOR, other, K); break;
            case 3: ins[n++] = BPF_MOV64_REG(9, base); break;
            }
            jexit[(*nx)++] = n;
            ins[n++] = BPF_JMP_IMM(BPF_JGT, other, K + 8, 0);
            ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_6, base);
            break;
        }
        default: break;
        }
        if (recipe) {
            strncat(recipe, gi_step_name(st), rsz - strlen(recipe) - 2);
            strncat(recipe, ",", rsz - strlen(recipe) - 2);
        }
    }
    return n;
}

static void run_gen_intent_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genintent#err type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n",
               errno);
        return;
    }

    struct gi_ctx c;
    c.rng = 0x9e3779b9u;
    for (int prog = 0; prog < GI_MAXPROG; prog++) {
        const uint32_t seed = c.rng;
        struct bpf_insn ins[320];
        int n = 0, jexit[2 * GI_MAXGENES + 8], nx = 0;
        char recipe[160]; recipe[0] = '\0';

        /* ---- fixed prologue: three seeds the verifier must treat as unknown ---- */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);
        /* A second value, whose POINTER the body may store through. r6/r7/r9 are
           callee-saved so they survive this helper call; r8 then holds the pointer for the
           rest of the program and is never modified, so the store shape can repeat. */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int jnull2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
        const int body = n;

        /* ---- generated body: closed-form once r6/r7/r9 are known ---- */
        struct gi_genome G;
        gi_genome_random(&c, &G);
        n = gi_emit_body(&G, ins, n, jexit, &nx, recipe, sizeof(recipe));
        /* ---- tail: return one half of the accumulated value ----
           Every in-body branch lands HERE, not on the sentinel. On the first run 727 of
           1830 samples took a narrowing branch straight to a constant, so they agreed with
           the reference while observing nothing about the computation — a denominator
           inflated with samples that could not have disagreed. Only the map-null path,
           which must stay distinguishable from any computed answer, keeps the sentinel. */
        const int tail = n;
        const int hi = G.hi;
        if (hi) ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
        ins[n++] = BPF_EXIT_INSN();
        const int exit_sentinel = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, GI_NULL_SENTINEL);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = tail - jexit[i] - 1;
        ins[jnull].off = exit_sentinel - jnull - 1;
        ins[jnull2].off = exit_sentinel - jnull2 - 1;

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG genintent#s%08x#%03d type=socket_filter ===\n", seed, prog);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        /* The programs branch, so their exit is reached along several paths — which is
           the precondition the verifier-referenced retval oracle needs and does not have.
           Declared here rather than inferred there. */
        printf("EXPECT paths=multi\n");
        printf("INTENT seed=0x%08x insns=%d body=%d recipe=%s hi=%d\n",
               seed, n, body, recipe, hi);

        if (fd >= 0) {
            for (int i = 0; i < GI_INPUTS_N; i++) {
                const uint32_t in = GI_INPUTS[i];
                uint32_t val[4] = { in, in ^ 0x5a5a5a5au, in + 3, 0 };
                static const unsigned char zero16[16] = {0};
                if (rt_map_set_bytes(map_in, 0, (const unsigned char *)val) < 0 ||
                    rt_map_set_bytes(map_out, 0, zero16) < 0) {
                    printf("RUNTIME input=0x%08x error=1 testrun_errno=0 map_err=1\n", in);
                    continue;
                }
                /* The reference: bpfref starts at the BODY with the seeds this harness
                   just wrote, and interprets the emitted bytes from there. */
                struct bpfref_result ref = bpfref_run_seeded_map(ins, n, body, val[0], val[1], val[2]);

                static char pin[64], pout[64];
                union bpf_attr t;
                memset(&t, 0, sizeof(t));
                t.test.prog_fd = fd;
                t.test.data_in = (uint64_t)(unsigned long)pin;
                t.test.data_out = (uint64_t)(unsigned long)pout;
                t.test.data_size_in = sizeof(pin);
                t.test.data_size_out = sizeof(pout);
                t.test.repeat = 1;
                if (bpf(BPF_PROG_TEST_RUN, &t, sizeof(t)) < 0) {
                    printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n", in, errno);
                    continue;
                }
                /* No claim is printed when the reference could not model the body — an
                   absent expectation is honest; a guessed one would be a false finding. */
                if (ref.status == BPFREF_OK)
                    printf("RUNTIME input=0x%08x retval=0x%08x intended_retval=%u"
                           " ref_status=ok\n",
                           in, t.test.retval, (unsigned)(uint32_t)ref.retval);
                else
                    printf("RUNTIME input=0x%08x retval=0x%08x ref_status=%s ref_pc=%d\n",
                           in, t.test.retval, bpfref_status_name(ref.status), ref.fault_pc);
            }
            close(fd);

            /* THE JIT-vs-INTERPRETER DIFFERENTIAL, per program.
               `bpf_jit_enable` is consulted at LOAD time (bpf_prog_select_runtime), so
               flipping it under an already-loaded program changes nothing — the program
               has to be loaded a SECOND time with the JIT off. Doing both in one process
               is what lets the two results be attributed to one record, which is what the
               jit_interp_divergence invariant has been waiting for since it was written:
               0066 measured that it had never examined a single record, because
               CONFIG_BPF_JIT_ALWAYS_ON compiles the interpreter out and the parser had
               been hardcoding `jit_interp_diff: None` ever since.
               On a kernel that still forces the JIT on, the write below fails, the reload
               is JITted too, and the comparison is between two identical runs — so the
               mode is reported rather than assumed. */
            int jit_was = gi_read_jit();
            if (jit_was == 1 && gi_set_jit(0) == 0) {
                int fd2 = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
                if (fd2 >= 0) {
                    for (int i = 0; i < GI_INPUTS_N; i++) {
                        const uint32_t in = GI_INPUTS[i];
                        uint32_t val[4] = { in, in ^ 0x5a5a5a5au, in + 3, 0 };
                        if (rt_map_set_bytes(map_in, 0, (const unsigned char *)val) < 0)
                            continue;
                        static char pin2[64], pout2[64];
                        union bpf_attr t2;
                        memset(&t2, 0, sizeof(t2));
                        t2.test.prog_fd = fd2;
                        t2.test.data_in = (uint64_t)(unsigned long)pin2;
                        t2.test.data_out = (uint64_t)(unsigned long)pout2;
                        t2.test.data_size_in = sizeof(pin2);
                        t2.test.data_size_out = sizeof(pout2);
                        t2.test.repeat = 1;
                        if (bpf(BPF_PROG_TEST_RUN, &t2, sizeof(t2)) == 0)
                            printf("JITDIFF input=0x%08x retval_interp=0x%08x\n",
                                   in, t2.test.retval);
                    }
                    close(fd2);
                }
                gi_set_jit(jit_was);
            }
        }
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
    close(map_in);
    close(map_out);
}

// ---- coverage-guided continuous fuzzing (--fuzz <seconds>) ------------------
//
// The strategic move behind this mode: after seven calibration pairs the ORACLE is no
// longer the bottleneck — volume and aim are. 0077 measured that KCOV gives a real,
// saturating signal across a BPF_PROG_LOAD, so a program that reaches verifier code
// nothing has reached before can be kept and perturbed.
//
// WHAT IS MUTATED IS THE GENOME, NOT THE BYTECODE. Byte-level mutation would produce
// mostly-malformed programs the verifier throws away before any oracle sees them — the
// denominator-zero trap one layer up that 0054 solved with a typed walk. Perturbing genes
// keeps every mutant inside the grammar, so a rejected program is rejected on BOUNDS, not
// on malformedness.
//
// EVERY PROGRAM IS STILL JUDGED BY THE FULL ORACLE. Coverage decides only what is KEPT.
// The oracle is the one whose reference is not the verifier: bpfref computes what the body
// must return and the kernel's answer is compared against it.
//
// OUTPUT IS BOUNDED ON PURPOSE. Programs load at log_level=0, so a multi-hour run does not
// produce gigabytes; only STATUS, CORPUS and FINDING lines are printed. A finding triggers
// a RELOAD at log_level=2 so the full block reaches the pipeline — the one place the
// expensive log is worth paying for.
#define FZ_CORPUS_MAX 4096

struct fz_entry { struct gi_genome G; unsigned new_pcs; };

static void fz_mutate(struct gi_ctx *c, const struct gi_genome *src, struct gi_genome *dst) {
    *dst = *src;
    const int ops = 1 + gi_pick(c, 2);          /* one or two edits */
    for (int i = 0; i < ops; i++) {
        switch (gi_pick(c, 6)) {
        case 0: if (dst->n < GI_MAXGENES) {     /* insert */
                    int at = gi_pick(c, dst->n + 1);
                    for (int j = dst->n; j > at; j--) dst->g[j] = dst->g[j - 1];
                    gi_gene_random(c, &dst->g[at]);
                    dst->n++;
                }
                break;
        case 1: if (dst->n > 6) {               /* delete */
                    int at = gi_pick(c, dst->n);
                    for (int j = at; j + 1 < dst->n; j++) dst->g[j] = dst->g[j + 1];
                    dst->n--;
                }
                break;
        case 2: gi_gene_random(c, &dst->g[gi_pick(c, dst->n)]); break;   /* replace */
        case 3: dst->g[gi_pick(c, dst->n)].st = (uint8_t)gi_pick(c, GI_STEP_N); break;
        case 4: dst->g[gi_pick(c, dst->n)].opt = (uint8_t)gi_pick(c, 64); break;
        default: {                              /* nudge a register or a constant */
            struct gi_gene *g = &dst->g[gi_pick(c, dst->n)];
            if (gi_pick(c, 2)) g->k = (uint8_t)(1 + gi_pick(c, 15));
            else { g->a = (uint8_t)gi_pick(c, 3); g->b = (uint8_t)gi_pick(c, 3); }
            break;
        }
        }
    }
    if (gi_pick(c, 8) == 0) dst->hi ^= 1;
}

static void fz_print_genome(const struct gi_genome *G) {
    printf("genes=%u hi=%u:", G->n, G->hi);
    for (int i = 0; i < G->n; i++)
        printf("%s%u.%u.%u.%u.%u", i ? "," : "",
               G->g[i].st, G->g[i].a, G->g[i].b, G->g[i].k, G->g[i].opt);
}

/* REPLAY A GENOME (--fuzz-replay "genes=N hi=H:st.a.b.k.opt,..."). 
 *
 * The devlog has claimed since 0077 that "every genome is replayable, and a finding carries
 * its genome in the report". Half of that was true: the genome was printed. Nothing could
 * read it back. 0097's first FINDING made the gap concrete — a report nobody could reproduce
 * is not a finding, it is a rumour with numbers on it.
 *
 * The rebuild is the fuzz loop's own prologue, body and epilogue, so a replay is the same
 * program the loop loaded and not a second implementation that might differ. Output is a
 * full pipeline record, so the same oracles that judge every other family judge this one. */
static void run_fuzz_replay(const char *spec) {
    struct gi_genome G;
    memset(&G, 0, sizeof(G));
    unsigned gn = 0, hi = 0;
    const char *p = strstr(spec, "genes=");
    if (!p || sscanf(p, "genes=%u hi=%u", &gn, &hi) != 2 || gn == 0 || gn > GI_MAXGENES) {
        printf("===PROG fuzzreplay type=socket_filter ===\n"
               "RESULT decision=error bad_genome errno=0\n---LOG---\n---END---\n");
        return;
    }
    G.n = (uint8_t)gn; G.hi = (uint8_t)hi;
    const char *q = strchr(p, ':');
    if (!q) { printf("===PROG fuzzreplay type=socket_filter ===\n"
                     "RESULT decision=error bad_genome errno=0\n---LOG---\n---END---\n");
              return; }
    q++;
    for (unsigned i = 0; i < gn; i++) {
        unsigned st, a, b, kk, opt;
        if (sscanf(q, "%u.%u.%u.%u.%u", &st, &a, &b, &kk, &opt) != 5) {
            printf("===PROG fuzzreplay type=socket_filter ===\n"
                   "RESULT decision=error bad_genome_at=%u errno=0\n---LOG---\n---END---\n", i);
            return;
        }
        G.g[i].st = (uint8_t)st; G.g[i].a = (uint8_t)a; G.g[i].b = (uint8_t)b;
        G.g[i].k = (uint8_t)kk;  G.g[i].opt = (uint8_t)opt;
        const char *comma = strchr(q, ',');
        if (!comma) { if (i + 1 != gn) { printf("===PROG fuzzreplay type=socket_filter ===\n"
                                                "RESULT decision=error short_genome errno=0\n"
                                                "---LOG---\n---END---\n"); return; } break; }
        q = comma + 1;
    }

    g_fz_iter_ok = (iter_resolve(&g_fz_iter) == 0);
    if (g_fz_iter_ok) {
        bpflive_register_kfunc(g_fz_iter.new_id, 3);
        bpflive_register_kfunc(g_fz_iter.next_id, 1);
        bpflive_register_kfunc(g_fz_iter.destroy_id, 1);
    }
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG fuzzreplay type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n",
               errno);
        return;
    }

    struct bpf_insn ins[320];
    int n = 0, jexit[2 * GI_MAXGENES + 8], nx = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
    n = gi_emit_body(&G, ins, n, jexit, &nx, NULL, 0);
    const int tail = n;
    if (G.hi) ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 32);
    ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
    ins[n++] = BPF_EXIT_INSN();
    const int sentinel = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, GI_NULL_SENTINEL);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++) ins[jexit[i]].off = tail - jexit[i] - 1;
    ins[jnull].off = sentinel - jnull - 1;
    ins[jnull2].off = sentinel - jnull2 - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int lerr = errno;

    printf("===PROG fuzzreplay#%u type=socket_filter ===\n", gn);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
    printf("REPLAY insns=%d ", n);
    fz_print_genome(&G);
    printf("\n");
    printf("PRUNE fall=replay taken=replay fall_safe=1 taken_safe=1 stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    /* The flagged load's log too: when the two verdicts differ, the REASON the flagged run
       gives is the whole question, and it lives only in that buffer. */
    printf("FREQREASON %s\n", g_log2[0] ? "captured" : "empty");
    if (fd >= 0) close(fd);
    bpflive_print_claim(ins, n);
    printf("---LOG---\n%s\n---END---\n", g_log);
    close(map_in); close(map_out);
}

static void run_fuzz(int seconds, unsigned seed) {
    /* Resolve the iterator kfuncs ONCE, and tell the independent liveness model their
       arities. Without the registration bpflive.h refuses every program containing the gene
       — correctly, since guessing an arity is a false LIVE claim in exactly the direction
       the gate reports — and `liveunsup` would climb instead of `livecells`. The arities are
       the kfuncs' published signatures, not anything read out of the kernel's analysis. */
    g_fz_iter_ok = (iter_resolve(&g_fz_iter) == 0);
    if (g_fz_iter_ok) {
        bpflive_register_kfunc(g_fz_iter.new_id, 3);      /* (it, start, end) */
        bpflive_register_kfunc(g_fz_iter.next_id, 1);     /* (it)             */
        bpflive_register_kfunc(g_fz_iter.destroy_id, 1);  /* (it)             */
    }
    printf("FUZZ iter_kfuncs=%s new=%d next=%d destroy=%d\n",
           g_fz_iter_ok ? "ok" : "unavailable",
           g_fz_iter.new_id, g_fz_iter.next_id, g_fz_iter.destroy_id);
    struct kcov_ctx k;
    if (kcov_open(&k) != 0) {
        /* Running without feedback would still LOOK like fuzzing while being a plain
           random walk, so refuse rather than degrade silently. */
        printf("FUZZ abort reason=kcov_unavailable errno=%d\n", errno);
        return;
    }
    g_kseen = (unsigned long *)calloc(KSEEN_N, sizeof(unsigned long));
    struct fz_entry *corpus = (struct fz_entry *)calloc(FZ_CORPUS_MAX, sizeof(*corpus));
    if (!g_kseen || !corpus) { printf("FUZZ abort reason=alloc\n"); return; }
    int corpus_n = 0;

    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("FUZZ abort reason=map_create errno=%d\n", errno); return;
    }

    /* THE WALK'S SEED, and why it had to become an argument (leg 0113). hunt-05..10
       were six rounds of the SAME program sequence: a fixed 0xC0FFEE meant every
       round replayed the previous one's genomes byte for byte (verified by diffing
       the CORPUS lines of hunt-08/09/10). Flat coverage across rounds was therefore
       tautological, not evidence about the grammar. 0 keeps the historical walk. */
    struct gi_ctx c; c.rng = seed ? seed : 0xC0FFEEu;
    const time_t t0 = time(NULL);
    unsigned long iters = 0, accepted = 0, rejected = 0, compared = 0, findings = 0;
    /* A load whose PC list filled the buffer lost coverage, and lost coverage looks exactly
       like a plateau. Counted so "the ceiling" is a statement about the grammar rather than
       about the buffer. */
    unsigned long truncated = 0, prune_flips = 0, inv_faults = 0;
    unsigned long prune_pairs = 0, prune_artifacts = 0;
    unsigned long max_base_states = 0, max_freq_states = 0, sum_base_states = 0;
    unsigned long inv_checked = 0;
    /* The liveness gate's counters. `live_cells` is the denominator the pipeline calls
       `liveness_gate_checked`: cells the independent model calls LIVE, because only those
       can fail. `live_unsup` is the honest scope — programs the model refused rather than
       approximated — and reporting it next to the zero is what keeps the zero readable. */
    unsigned long live_cells = 0, live_rows = 0, live_miss = 0, live_unsup = 0;
    unsigned long subs_rows = 0, subs_pairs = 0, subs_nontrivial = 0;
    unsigned long subs_disagree = 0, subs_unsup = 0;
    unsigned long subsf_pairs = 0, subsf_nontrivial = 0, subsf_disagree = 0, subsf_unsup = 0;
    unsigned long store_progs = 0, store_bytes = 0, store_none = 0, store_readfail = 0;
    unsigned long store_sampled = 0, store_unamb = 0, store_stale = 0;

    printf("FUZZ start budget=%ds corpus_max=%d seed=0x%08x\n",
           seconds, FZ_CORPUS_MAX, c.rng);
    while (time(NULL) - t0 < seconds) {
        struct gi_genome G;
        if (corpus_n > 0 && gi_pick(&c, 10) < 8)
            fz_mutate(&c, &corpus[gi_pick(&c, corpus_n)].G, &G);
        else
            gi_genome_random(&c, &G);

        struct bpf_insn ins[320];
        int n = 0, jexit[2 * GI_MAXGENES + 8], nx = 0;
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);
        /* A second value, whose POINTER the body may store through. r6/r7/r9 are
           callee-saved so they survive this helper call; r8 then holds the pointer for the
           rest of the program and is never modified, so the store shape can repeat. */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int jnull2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
        const int body = n;
        n = gi_emit_body(&G, ins, n, jexit, &nx, NULL, 0);
        const int tail = n;
        if (G.hi) ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6);
        ins[n++] = BPF_EXIT_INSN();
        const int sentinel = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, GI_NULL_SENTINEL);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = tail - jexit[i] - 1;
        ins[jnull].off = sentinel - jnull - 1;
        ins[jnull2].off = sentinel - jnull2 - 1;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";

        kcov_start(&k);
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        unsigned long cnt = kcov_stop(&k);
        iters++;
        if (fd >= 0) accepted++; else rejected++;

        if (cnt >= KCOV_ENTRIES - 1) truncated++;
        unsigned fresh = 0;
        for (unsigned long i = 0; i < cnt; i++) fresh += (unsigned)kseen_add(k.area[i + 1]);
        if (fresh > 0 && corpus_n < FZ_CORPUS_MAX) {
            corpus[corpus_n].G = G;
            corpus[corpus_n].new_pcs = fresh;
            corpus_n++;
            printf("CORPUS n=%d new_pcs=%u seen=%u verdict=%s ",
                   corpus_n, fresh, g_kseen_count, fd >= 0 ? "accept" : "reject");
            fz_print_genome(&G);
            printf("\n");
        }
        /* THE EXPENSIVE ORACLES GO TO THE INTERESTING INPUTS. Two extra loads per
           program cost 2.5x throughput — 511k iterations became 202k — which is a bad
           trade to pay on every random mutant. A program that reached NEW verifier code
           is by definition the one worth the second look; everything else is sampled.
           The cheap oracle, the reference-interpreter comparison, still runs on all of
           them. */
        /* WHETHER `g_log` DESCRIBES THIS PROGRAM. The level-2 load rides this gate, so on
           the other seven eighths of iterations the buffer still holds an EARLIER program's
           log. The store sampler ran outside the gate and emitted blocks pairing this
           program's store sites with that program's log: 79 of 86 sampled blocks declared
           an instruction the log showed as something else entirely (`STORE insn=36` against
           `36: (bf) r6 = (s32)r7`). The site list itself was fine — a self-check against the
           instruction array reported storestale=0 — which is exactly why the mismatch had to
           be looked for on the OTHER side. Same shape as 0085's stale artefact: a report
           about the wrong image. */
        const int log_is_current = (fresh > 0 || (iters & 7) == 0);
        if (log_is_current) {
            /* TWO MORE ORACLES, ON THE SAME KERNEL. Screening the 21 historical fixes found
               that three of them are triggerable by this grammar today and STILL invisible,
               because they are cross-state pruning defects that no single-state check can see.
               The suggested cure was a kernel-VERSION differential — but 0068 established that
               two versions are ALLOWED to disagree on a verdict, so that is a calibration
               instrument, not a hunting oracle.
               What IS sound is a differential against the same kernel under a flag that must
               not change the answer: BPF_F_TEST_STATE_FREQ only intensifies checkpointing, so a
               verdict FLIP means a prune decided something the unpruned walk did not — exactly
               the class. And BPF_F_TEST_REG_INVARIANTS promotes the kernel's own bounds
               assertion from warn-and-recover to a hard fault.
               The resource direction is excluded: state-freq inflates the state count by
               construction, so a flagged rejection on a complexity limit is the instrument's
               own artefact and not a finding (0042). */
            {
                /* THE DENOMINATOR, which 0042 made non-negotiable: a pair counts only
                   once the flag DEMONSTRABLY changed the state space. Two verdicts from
                   identical explorations prove nothing about pruning, and counting them
                   would make `pruneflip=0` mean "0 out of 0" while reading exactly like
                   "0 out of many" — the 0025 trap, in the newest instrument.
                   Reading the state count needs log_level=1, so this reuses 0042's own
                   helper rather than a second implementation of the same parse. */
                struct prune_load base = prune_load_typed(ins, n, 0, g_log, sizeof(g_log),
                                                          BPF_PROG_TYPE_SOCKET_FILTER);
                struct prune_load freq = prune_load_states(ins, n, BPF_F_TEST_STATE_FREQ,
                                                          g_log2, sizeof(g_log2));
                const int widened = freq.states > base.states;
                if (widened) prune_pairs++;

                /* THE LIVENESS GATE, on the highest-volume input this project has.
                   `func_states_equal` compares only the registers the verifier believes are
                   live where two states meet, so a register wrongly called dead is a prune
                   that never had to justify itself. 0088 built that oracle and 0089
                   calibrated it against a real bug, but until now it ran only on the small
                   hand-built families — the widest denominator in the project was attached
                   to the narrowest input.
                   It rides the GATED sample rather than every program, for the reason 0082
                   gave: the table only exists at log_level=2, which is what makes these
                   loads expensive. `base`'s log already has it, so this costs a parse.
                   Only aggregates and real disagreements leave the VM; a per-program claim
                   would be gigabytes of log for a number. */
                /* THE SUBSUMPTION MODEL, on the same gated sample and for the same
                   reason. 11,996 prune-pair rows per 896 programs is ~1.5 KB each; at the
                   loop's ~1900 programs/sec that is ~10 GB of log per hour if shipped out,
                   so the comparison happens HERE and only numbers leave. `subs_rows`
                   separates "this kernel carries no instrumentation" from "instrumented and
                   nothing pruned" — without it both print pairs=0 and read as clean. */
                /* AND THE SAME MODEL ON A DIFFERENT CHECKPOINT POLICY.
                 *
                 * 0106 measured the input saturated: three rounds, coverage flat at ~6260,
                 * doubling the budget bought +3 PCs. More of the same hour buys nothing, so
                 * this round changes WHICH pairs the model sees rather than how many.
                 *
                 * The reason that is not cosmetic was measured in 0103: the default
                 * checkpoint heuristic DECLINES a new state at a merge until >=20 jumps or
                 * >=100 insns have passed, so the pair `--probe-wraparc2` needed did not
                 * exist at all until TEST_STATE_FREQ forced it — 4 pairs with
                 * scalar_comparisons=0 became a real comparison at the merge. Every shape of
                 * that kind is invisible to the model today.
                 *
                 * The differential's own freq load stays at log_level=1 and untouched: it
                 * needs a state COUNT, this needs the prune-pair dump, and quietly changing
                 * a level under an existing oracle would move its denominator without
                 * saying so. So this is a separate load, and its cost is honest.
                 *
                 * DIRECTION, and it is the same one OI-15 turns on: the flag only makes
                 * pruning more aggressive. It cannot make the kernel take an unsound prune
                 * it would otherwise refuse — it can only offer more prunes to audit, and
                 * the audit is still `range_within`'s own decision, judged by the model.
                 */
                {
                    struct prune_load fq2 = prune_load_typed(ins, n, BPF_F_TEST_STATE_FREQ,
                                                             g_log2, sizeof(g_log2),
                                                             BPF_PROG_TYPE_SOCKET_FILTER);
                    struct bpfsubs_cmp fc;
                    bpfsubs_compare_log(g_log2, &fc);
                    subsf_pairs += fc.pairs;
                    subsf_nontrivial += fc.nontrivial;
                    subsf_unsup += fc.unsupported;
                    if (fc.disagree) {
                        subsf_disagree += fc.disagree;
                        printf("FINDING kind=subsumption_candidate_freq iter=%lu %s ",
                               iters, fc.first);
                        fz_print_genome(&G);
                        printf("\n");
                    }
                    (void)fq2;   /* the helper owns the fd; only its log is wanted here */
                }
                {
                    struct bpfsubs_cmp sc;
                    bpfsubs_compare_log(g_log, &sc);
                    subs_rows += sc.rows;
                    subs_pairs += sc.pairs;
                    subs_nontrivial += sc.nontrivial;
                    subs_unsup += sc.unsupported;
                    if (sc.disagree) {
                        subs_disagree += sc.disagree;
                        printf("FINDING kind=subsumption_candidate iter=%lu %s ",
                               iters, sc.first);
                        fz_print_genome(&G);
                        printf("\n");
                    }
                }
                {
                    struct bpflive_cmp lc;
                    bpflive_compare_log(ins, n, g_log, &lc);
                    if (lc.status != BPFLIVE_OK) {
                        live_unsup++;
                    } else {
                        live_cells += lc.checked;
                        live_rows += lc.rows;
                        if (lc.overreach) {
                            live_miss += lc.overreach;
                            printf("FINDING kind=liveness_gate_overreach iter=%lu insn=%d"
                                   " reg=%d kernel_mask=0x%03x model_mask=0x%03x cells=%d ",
                                   iters, lc.first_insn, lc.first_reg, lc.kmask, lc.omask,
                                   lc.overreach);
                            fz_print_genome(&G);
                            printf("\n");
                        }
                    }
                }
                /* HOW DEEP the search actually went. Coverage rising says the grammar
                   reached new code; it does NOT say pruning had anything to decide. A
                   verifier that explores two or three states per program is not pruning in
                   any interesting sense, so the differential's 43k pairs could still be 43k
                   trivial comparisons. Reported so "the pruning oracle found nothing" can be
                   read against how much pruning there was to do. */
                if (base.states > max_base_states) max_base_states = base.states;
                if (freq.states > max_freq_states) max_freq_states = freq.states;
                sum_base_states += base.states;
                const int flipped = base.accept != freq.accept;
                /* State-freq inflates the state count by construction, so a flagged
                   rejection on a complexity limit is the instrument's own artefact. */
                const int resource = !freq.accept &&
                                     (strcmp(freq.reason, "too_many_states") == 0 ||
                                      strcmp(freq.reason, "too_large") == 0 ||
                                      strcmp(freq.reason, "log_truncated") == 0);
                if (resource) prune_artifacts++;
                /* THE DIRECTION IS THE FINDING, and this check used to collapse both into
                   one name. `diff.rs`'s check_prune_differential separates them carefully:
                     freq ACCEPT + base REJECT -- the extra checkpoints pruned away a path
                       that produced the rejection. Only an unsound regsafe does that.
                     freq REJECT + base ACCEPT -- the reverse. The complexity-limit case is
                       filtered above, but there is a THIRD cause the filter does not catch:
                       forcing a checkpoint at every instruction stores states with
                       `mark_all_scalars_imprecise()` applied, so the flagged run can LOSE
                       precision and fail to prove something the default run proves. That is
                       an over-rejection produced by the instrument, not unsoundness.
                   Reporting the second under the first's name is how a weak-direction
                   disagreement arrives looking like a soundness finding — which is exactly
                   what the first hunt's only FINDING turned out to be (0097). */
                const int unsound_dir = freq.accept && !base.accept;
                if (widened && flipped && !resource) {
                    prune_flips++;
                    printf("FINDING kind=%s iter=%lu base=%s freq=%s"
                           " base_states=%lu freq_states=%lu reason=%s ",
                           unsound_dir ? "prune_soundness_desync"
                                       : "prune_verdict_disagreement",
                           iters, base.accept ? "accept" : "reject",
                           freq.accept ? "accept" : "reject", base.states, freq.states,
                           freq.reason);
                    fz_print_genome(&G);
                    printf("\n");
                }

                /* THE SAME DENOMINATOR RULE, applied to the channel that still lacked
                   one. The invariant load only says anything when the BASE load accepted:
                   a program the verifier rejected outright never reached the state whose
                   consistency is in question, so counting it would make `invfault=0` read
                   as evidence about programs that were never examined. This is exactly the
                   gap 0083 closed for the pruning differential, still open here. */
                union bpf_attr a3 = attr;
                a3.prog_flags = BPF_F_TEST_REG_INVARIANTS;
                a3.log_level = 0; a3.log_size = 0; a3.log_buf = 0;
                int fdi = bpf(BPF_PROG_LOAD, &a3, sizeof(a3));
                int ierr = errno;
                if (fdi >= 0) close(fdi);
                if (fd >= 0) inv_checked++;
                if (fd >= 0 && fdi < 0 && ierr == EFAULT) {
                    inv_faults++;
                    printf("FINDING kind=reg_invariants_violation iter=%lu ", iters);
                    fz_print_genome(&G);
                    printf("\n");
                }
            }
        }

        if (fd >= 0) {
            for (int i = 0; i < GI_INPUTS_N; i++) {
                const uint32_t in = GI_INPUTS[i];
                uint32_t val[4] = { in, in ^ 0x5a5a5a5au, in + 3, 0 };
                static const unsigned char zero16[16] = {0};
                /* map_out survives between the sweep's runs, and a program that STORES into
                   it and later READS it back would see the previous input's leftovers —
                   the same not-closed-form failure as the stack, arriving from the other
                   side. Re-zeroed every run so the reference's zeroed map matches. */
                if (rt_map_set_bytes(map_in, 0, (const unsigned char *)val) < 0) continue;
                if (rt_map_set_bytes(map_out, 0, zero16) < 0) continue;
                struct bpfref_result ref = bpfref_run_seeded_map(ins, n, body, val[0], val[1], val[2]);
                if (ref.status != BPFREF_OK) continue;
                static char pin[64], pout[64];
                union bpf_attr t;
                memset(&t, 0, sizeof(t));
                t.test.prog_fd = fd;
                t.test.data_in = (uint64_t)(unsigned long)pin;
                t.test.data_out = (uint64_t)(unsigned long)pout;
                t.test.data_size_in = sizeof(pin);
                t.test.data_size_out = sizeof(pout);
                t.test.repeat = 1;
                if (bpf(BPF_PROG_TEST_RUN, &t, sizeof(t)) < 0) continue;
                compared++;

                /* THE STORE-LOCATION CHANNEL'S DENOMINATOR, asked BEFORE the oracle is
                   built. `check_store_location` is the one oracle whose reference is the
                   runtime landing site rather than the verifier's own claim, and the 0101
                   fan-out measured that 58% of historical verifier bugs are STATE bugs —
                   the class every consistency oracle misses and this one is aimed at. It
                   is also the only oracle NOT on this loop: 4,560 comparisons on a
                   hand-built corpus against the pruning model's 283,361.
                   Before plumbing it in, the question 0084 would ask: does the channel have
                   any volume here at all? GI_STORE offsets the map-value pointer by a
                   SCALAR register and writes one 0xFF byte, and map_out is zeroed before
                   every run — so any 0xFF read back is that store, and a program with none
                   contributes nothing no matter how good the oracle is. */
                {
                    unsigned char mv[RTW_VALUE_SIZE];
                    memset(mv, 0, sizeof(mv));
                    if (rt_map_get(map_out, 0, mv) == 0) {
                        int seen = 0;
                        for (int b = 0; b < 16; b++) {
                            if (mv[b] != 0xff) continue;
                            seen++; store_bytes++;

                            /* THE ORACLE. `b` is where the store actually landed; the
                               question is whether the verifier's own claim admits it.
                               A finding needs NO site to admit it — the union over sites
                               AND over the paths each was printed on. Both unions only
                               lose sensitivity: the run took one path and wrote through
                               one site, and we cannot tell which from here, so anything
                               narrower would manufacture findings out of our ignorance.
                               Same rule as the idmap arm the subsumption model refuses to
                               guess at. */
                            /* THE VERDICT MOVED OUT OF THE VM, and this is a measured
                               retreat rather than a preference.
                               Five corrections were made to an in-VM claim reader, every
                               one a real bug and not one of them in the PREDICATE: the
                               map_value print shape, the store's own immediate, what
                               `had_claim` must mean, an unreadable occurrence silently
                               narrowing the union, and `imm=N` as a fifth spelling of a
                               constant offset. False desyncs on a kernel known to be
                               correct went 79 -> 247 -> 8 -> 18 -> 49. It was not
                               converging, and the reason is structural: the thing being
                               re-implemented in here is not a closed-form predicate (as
                               `cnum_is_subset` was for the subsumption model, where eight
                               counters matched the reference exactly) but the kernel's
                               PRINTING CONVENTIONS, which the offline parser has spent
                               forty legs getting right and which 0065 and 0070 already
                               charged this project for once each.
                               So the loop keeps only what it can measure honestly — how
                               many observable stores there are — and SAMPLES the rest out
                               with its verifier log, for the mature oracle to judge.
                               Volume permits it: ~28k storing programs per 150s, of which
                               1-in-256 is ~2,700/hour, against the hand-built corpus's
                               4,560 store comparisons in total. Less volume, and a verdict
                               that is not a fifth guess at a log format. */
                            (void)0;
                        }
                        if (seen) {
                            store_progs++;
                            /* SAMPLE ONLY WHAT IS UNAMBIGUOUS. A program with two variable
                               store sites emits two claims, and the observed bytes cannot
                               be attributed to one of them from out here — feed that to the
                               oracle and it judges every byte against a single claim, which
                               is exactly how the first sampled batch produced desyncs on a
                               correct kernel ("a store through R1 at insn 28 lands in 4+[0,..]"
                               against a byte written by a different site). The oracle was
                               right; the input was ambiguous. One site, one observed byte,
                               and the pairing is forced. */
                            /* VERIFY THE SITE AGAINST THE PROGRAM BEFORE TRUSTING IT.
                               The declared index is only useful if `ins[insn+1]` really is
                               the one-byte store this site describes; block 15 of the first
                               sampled batch declared insn=29 while the log showed
                               `29: (07) r1 += -256` — a stack pointer. Rather than reason
                               about how that happens, the harness now checks and COUNTS. */
                            int nvar = 0, stale = 0;
                            for (int si = 0; si < g_gi_nstores; si++) {
                                if (g_gi_stores[si].fixed >= 0) continue;
                                nvar++;
                                int at = g_gi_stores[si].insn + 1;
                                if (at < 0 || at >= n ||
                                    ins[at].code != (BPF_ST | BPF_MEM | BPF_B) ||
                                    ins[at].dst_reg != BPF_REG_1)
                                    stale = 1;
                            }
                            if (stale) store_stale++;
                            if (nvar == 1 && seen == 1 && !stale && log_is_current)
                                store_unamb++;
                            if (nvar == 1 && seen == 1 && !stale && log_is_current &&
                                (store_unamb & 0x3F) == 0) {
                                store_sampled++;
                                printf("===PROG fuzzstore#%lu type=socket_filter ===\n"
                                       "RESULT decision=accept fd=1 errno=0 load_ns=0\n",
                                       iters);
                                /* SELF-DESCRIBING, because the triage rule's first step is
                                   to re-derive by hand and a block that cannot be replayed
                                   cannot be triaged. */
                                printf("REPLAY ");
                                fz_print_genome(&G);
                                printf("\n");
                                for (int si = 0; si < g_gi_nstores; si++)
                                    if (g_gi_stores[si].fixed < 0)
                                        printf("STORE insn=%d reg=1 off=%d size=1\n",
                                               g_gi_stores[si].insn + 1, g_gi_stores[si].k);
                                for (int b2 = 0; b2 < 16; b2++)
                                    if (mv[b2] == 0xff)
                                        printf("RUNTIME input=0x%08x store_off=%d "
                                               "store_len=1 store_size=1 executed=1\n",
                                               in, b2);
                                printf("---LOG---\n%s\n---END---\n", g_log);
                            }
                        } else store_none++;
                    } else {
                        store_readfail++;
                    }
                }

                if (t.test.retval != (uint32_t)ref.retval) {
                    findings++;
                    printf("FINDING iter=%lu input=0x%08x kernel=0x%08x reference=0x%08x ",
                           iters, in, t.test.retval, (unsigned)(uint32_t)ref.retval);
                    fz_print_genome(&G);
                    printf("\n");
                    /* The expensive log, paid for only here: reload verbosely so the full
                       block reaches the pipeline and the triage can start from the
                       verifier's own words. */
                    g_log[0] = '\0';
                    attr.log_level = 2;
                    attr.log_size = sizeof(g_log);
                    attr.log_buf = (uint64_t)(unsigned long)g_log;
                    int fd2 = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
                    printf("===PROG fuzz#i%lu type=socket_filter ===\n", iters);
                    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
                           fd2 >= 0 ? "accept" : "reject", fd2 >= 0 ? 1 : -1,
                           fd2 >= 0 ? 0 : errno);
                    printf("EXPECT paths=multi\n");
                    printf("RUNTIME input=0x%08x retval=0x%08x intended_retval=%u"
                           " ref_status=ok\n",
                           in, t.test.retval, (unsigned)(uint32_t)ref.retval);
                    printf("---LOG---\n%s\n---END---\n", g_log);
                    if (fd2 >= 0) close(fd2);
                    attr.log_level = 0; attr.log_size = 0; attr.log_buf = 0;
                }
            }
            close(fd);
        }

        if ((iters % 2000) == 0)
            printf("STATUS iters=%lu accept=%lu reject=%lu corpus=%d seen_pcs=%u"
                   " compared=%lu findings=%lu trunc=%lu prunepairs=%lu pruneflip=%lu pruneartifact=%lu maxstates=%lu/%lu avgstates=%lu invchecked=%lu invfault=%lu livecells=%lu liverows=%lu livemiss=%lu liveunsup=%lu subsrows=%lu subspairs=%lu subsnontrivial=%lu subsdisagree=%lu subsunsup=%lu subsfpairs=%lu subsfnontrivial=%lu subsfdisagree=%lu subsfunsup=%lu storeprogs=%lu storebytes=%lu storenone=%lu storereadfail=%lu storesampled=%lu storeunamb=%lu storestale=%lu iteremitted=%lu iterskipped=%lu elapsed=%lds\n",
                   iters, accepted, rejected, corpus_n, g_kseen_count, compared, findings,
                   truncated, prune_pairs, prune_flips, prune_artifacts, max_base_states,
                   max_freq_states, prune_pairs ? sum_base_states / prune_pairs : 0, inv_checked, inv_faults, live_cells, live_rows, live_miss, live_unsup,
           subs_rows, subs_pairs, subs_nontrivial, subs_disagree, subs_unsup,
           subsf_pairs, subsf_nontrivial, subsf_disagree, subsf_unsup,
           store_progs, store_bytes, store_none, store_readfail,
           store_sampled, store_unamb, store_stale, g_fz_iter_emitted, g_fz_iter_skipped, (long)(time(NULL) - t0));
    }
    /* THE PC SET ITSELF, so the coverage number can become a FRACTION. 5406 distinct PCs
       is uninterpretable on its own: CONFIG_KCOV_INSTRUMENT_ALL means the list includes the
       syscall path, the allocator and everything else a load touches, and we have no
       denominator for the verifier's own size. Dumping the addresses lets a host-side
       script split them against vmlinux's symbol ranges. Packed several per line to keep a
       long run's output bounded. */
    {
        unsigned printed = 0;
        for (unsigned i = 0; i < KSEEN_N; i++) {
            if (!g_kseen[i]) continue;
            if ((printed % 8) == 0) printf("PCSET");
            printf(" %lx", g_kseen[i]);
            if ((++printed % 8) == 0) printf("\n");
        }
        if (printed % 8) printf("\n");
        printf("PCSET total=%u\n", printed);
    }
    printf("FUZZ done iters=%lu accept=%lu reject=%lu corpus=%d seen_pcs=%u"
           " compared=%lu findings=%lu trunc=%lu prunepairs=%lu pruneflip=%lu pruneartifact=%lu maxstates=%lu/%lu avgstates=%lu invchecked=%lu invfault=%lu livecells=%lu liverows=%lu livemiss=%lu liveunsup=%lu subsrows=%lu subspairs=%lu subsnontrivial=%lu subsdisagree=%lu subsunsup=%lu subsfpairs=%lu subsfnontrivial=%lu subsfdisagree=%lu subsfunsup=%lu storeprogs=%lu storebytes=%lu storenone=%lu storereadfail=%lu storesampled=%lu storeunamb=%lu storestale=%lu iteremitted=%lu iterskipped=%lu elapsed=%lds\n",
           iters, accepted, rejected, corpus_n, g_kseen_count, compared, findings,
           truncated, prune_pairs, prune_flips, prune_artifacts, max_base_states,
           max_freq_states, prune_pairs ? sum_base_states / prune_pairs : 0, inv_checked, inv_faults, live_cells, live_rows, live_miss, live_unsup,
           subs_rows, subs_pairs, subs_nontrivial, subs_disagree, subs_unsup,
           subsf_pairs, subsf_nontrivial, subsf_disagree, subsf_unsup,
           store_progs, store_bytes, store_none, store_readfail,
           store_sampled, store_unamb, store_stale, g_fz_iter_emitted, g_fz_iter_skipped, (long)(time(NULL) - t0));
    free(corpus);
    free(g_kseen);
    close(map_in);
    close(map_out);
}


// ---- reference-interpreter calibration (--probe-ref) ------------------------
// bpfref.h is a second implementation of the ISA, written so the intent oracle has a
// reference that never consults the kernel. A second implementation is only worth having
// if it AGREES with the first everywhere the first is right — so before it is allowed to
// judge anything, it is judged: the fifteen places a naive interpreter goes wrong are
// emitted as programs, run on the real kernel AND on bpfref, and required to match.
//
// The comparison is at 32 bits because BPF_PROG_TEST_RUN's retval is a __u32, so each
// program is shaped to land its distinguishing bits in the LOW half — several of these
// traps are about the UPPER 32 bits, and returning the value directly would compare the
// half that carries no information.
struct ref_trap { const char *name; int n; struct bpf_insn ins[16]; };

/* `r1 = <imm64>` occupies two slots; the second carries the high half in its imm. */
#define REF_LD64(DST, VAL)                                                              \
    (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = (DST),              \
                      .src_reg = 0, .off = 0, .imm = (int)(uint32_t)((uint64_t)(VAL))}, \
    (struct bpf_insn){.code = 0, .dst_reg = 0, .src_reg = 0, .off = 0,                  \
                      .imm = (int)(uint32_t)(((uint64_t)(VAL)) >> 32)}
/* ALU with a non-zero `off`: signed div/mod (off=1) and the sign-extending mov. */
#define REF_ALU_OFF(CLS, OP, DST, SRC, OFF)                                             \
    (struct bpf_insn){.code = (CLS) | BPF_X | (OP), .dst_reg = (DST),                   \
                      .src_reg = (SRC), .off = (OFF), .imm = 0}

static void run_probe_ref(void) {
    static struct ref_trap traps[] = {
      /* 1. ALU64 MOV|K sign-extends the immediate; the 32-bit form does not. Shift the
            upper half down so the difference is visible in a u32 retval. */
      {"mov64_k_sign_extends", 4, {BPF_MOV64_IMM(BPF_REG_1, -1),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
        BPF_EXIT_INSN()}},
      {"mov32_k_zero_extends", 4, {BPF_MOV32_IMM(BPF_REG_1, -1),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
        BPF_EXIT_INSN()}},
      /* 2. EVERY 32-bit ALU op zero-extends the result, with no exception. */
      {"alu32_add_zero_extends", 6, {REF_LD64(BPF_REG_1, 0xffffffff00000001ULL),
        BPF_ALU32_IMM(BPF_ADD, BPF_REG_1, 1), BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
      /* 3. JMP32 compares the low half and never inspects the upper one. */
      {"jmp32_ignores_upper_half", 6, {BPF_MOV64_IMM(BPF_REG_0, 0),
        REF_LD64(BPF_REG_1, 0x0000000100000005ULL),
        BPF_JMP32_IMM(BPF_JNE, BPF_REG_1, 5, 1), BPF_MOV64_IMM(BPF_REG_0, 7),
        BPF_EXIT_INSN()}},
      /* 4. A runtime-zero divisor does not trap: x/0 = 0 and x%0 = x. */
      {"udiv_by_runtime_zero_is_zero", 5, {BPF_MOV64_IMM(BPF_REG_1, 7),
        BPF_MOV64_IMM(BPF_REG_2, 0), BPF_ALU64_REG(BPF_DIV, BPF_REG_1, BPF_REG_2),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
      {"umod_by_runtime_zero_is_dst", 5, {BPF_MOV64_IMM(BPF_REG_1, 7),
        BPF_MOV64_IMM(BPF_REG_2, 0), BPF_ALU64_REG(BPF_MOD, BPF_REG_1, BPF_REG_2),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
      /* 5. S64_MIN sdiv -1 is S64_MIN, not an overflow. */
      {"sdiv64_min_by_minus_one", 7, {REF_LD64(BPF_REG_1, 0x8000000000000000ULL),
        BPF_MOV64_IMM(BPF_REG_2, -1), REF_ALU_OFF(BPF_ALU64, BPF_DIV, BPF_REG_1, BPF_REG_2, 1),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
        BPF_EXIT_INSN()}},
      /* 6. Negating the minimum value wraps to itself. */
      {"neg64_of_min_wraps", 6, {REF_LD64(BPF_REG_1, 0x8000000000000000ULL),
        BPF_ALU64_IMM(BPF_NEG, BPF_REG_1, 0), BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
      /* 7. A DW immediate store SIGN-extends the s32 imm before the 8-byte write — the
            exact rule 811c363645b3 fixed in the verifier's parallel bookkeeping. */
      {"st_dw_imm_sign_extends", 4, {BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, -1),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32), BPF_EXIT_INSN()}},
      /* 8. MEMSX sign-extends into the FULL 64-bit register. */
      {"ldx_memsx_fills_upper_half", 4, {BPF_ST_MEM(BPF_W, BPF_REG_10, -4, -1),
        (struct bpf_insn){.code = BPF_LDX | BPF_MEMSX | BPF_W, .dst_reg = BPF_REG_0,
                          .src_reg = BPF_REG_10, .off = -4, .imm = 0},
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32), BPF_EXIT_INSN()}},
      /* 9. An ordinary byte load zero-extends even when the byte reads as -1. */
      {"ldx_b_zero_extends", 3, {BPF_ST_MEM(BPF_B, BPF_REG_10, -1, -1),
        BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_10, -1), BPF_EXIT_INSN()}},
      /* 10. A sign-extending mov in the 32-bit class stops at 32 bits, then zero-extends. */
      {"movsx32_then_zero_extends", 5, {BPF_MOV64_IMM(BPF_REG_1, 0xff),
        REF_ALU_OFF(BPF_ALU, BPF_MOV, BPF_REG_2, BPF_REG_1, 8),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
        BPF_EXIT_INSN()}},
      {"movsx64_fills_upper_half", 5, {BPF_MOV64_IMM(BPF_REG_1, 0xff),
        REF_ALU_OFF(BPF_ALU64, BPF_MOV, BPF_REG_2, BPF_REG_1, 8),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
        BPF_EXIT_INSN()}},
      /* 11. The 32-bit MOD zeroes the upper half on the zero-divisor path; ALU64 MOD does
             not touch the destination at all. */
      {"alu32_mod_by_zero_zeroes_upper", 7, {REF_LD64(BPF_REG_1, 0xffffffff00000007ULL),
        BPF_MOV64_IMM(BPF_REG_2, 0), BPF_ALU32_REG(BPF_MOD, BPF_REG_1, BPF_REG_2),
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
        BPF_EXIT_INSN()}},
      /* 12. `off` is signed: fp-8 must not become fp+65528. */
      {"negative_stack_off_is_signed", 3, {BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 5),
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8), BPF_EXIT_INSN()}},
      /* 14. ATOMIC FETCH puts the OLD value in the SOURCE register, not the new one. */
      {"atomic_fetch_add_returns_old", 5, {BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 7),
        BPF_MOV64_IMM(BPF_REG_1, 5),
        (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_10,
                          .src_reg = BPF_REG_1, .off = -8, .imm = BPF_ADD | BPF_FETCH},
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
      /* 15. ...and the memory really did take the sum. */
      {"atomic_add_updates_memory", 5, {BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 7),
        BPF_MOV64_IMM(BPF_REG_1, 5),
        (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_10,
                          .src_reg = BPF_REG_1, .off = -8, .imm = BPF_ADD},
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_10, -8), BPF_EXIT_INSN()}},
      /* 16. CMPXCHG loads r0 with the old value ALWAYS — including on a FAILED compare.
             x86's native CMPXCHG loads the accumulator only on failure, and 39491867ace5
             exists because the JIT once inherited exactly that asymmetry. Here the compare
             SUCCEEDS, which is the direction a naive implementation gets wrong. */
      {"cmpxchg_returns_old_on_success", 7, {BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 7),
        BPF_MOV64_IMM(BPF_REG_0, 7), BPF_MOV64_IMM(BPF_REG_1, 9),
        (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_DW, .dst_reg = BPF_REG_10,
                          .src_reg = BPF_REG_1, .off = -8, .imm = BPF_CMPXCHG},
        BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, -8),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
      /* 17. A 32-bit XCHG zero-extends the old value into the source register. */
      {"xchg32_zero_extends_the_old_value", 7, {BPF_ST_MEM(BPF_W, BPF_REG_10, -4, -1),
        REF_LD64(BPF_REG_1, 0xffffffff00000005ULL),
        (struct bpf_insn){.code = BPF_STX | BPF_ATOMIC | BPF_W, .dst_reg = BPF_REG_10,
                          .src_reg = BPF_REG_1, .off = -4, .imm = BPF_XCHG},
        BPF_ALU64_IMM(BPF_RSH, BPF_REG_1, 32), BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),
        BPF_EXIT_INSN()}},
      /* 13. LD_IMM64 occupies two slots; a decoder that advances one corrupts the rest. */
      {"ld_imm64_consumes_two_slots", 4, {REF_LD64(BPF_REG_1, 0x1122334455667788ULL),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_1), BPF_EXIT_INSN()}},
    };

    /* A COUNTED summary as well as the per-trap lines. The serial console is shared with
       the kernel's printk, so a line can be split mid-word (OI-10, and it happened on this
       very probe: `verdict=agre`). A shell check that greps for DISAGREE would miss a
       SPLIT disagreement, so the authority is this single short line — and if the kernel
       manages to split even that, the checker sees no summary and fails loudly instead of
       passing on absence. */
    int n_total = 0, n_agree = 0;
    for (unsigned t = 0; t < sizeof(traps) / sizeof(traps[0]); t++) {
        struct ref_trap *T = &traps[t];
        /* A trap that declares more instructions than it initialises ends on a zeroed
           insn, which the verifier rejects as unreachable — and the result reads as a trap
           that measured nothing rather than as the typo it is. This has now happened three
           times (the jmp32 trap in 0073, an atomic trap here), so it is checked instead of
           remembered: every trap must end in EXIT and carry no zeroed instruction. */
        if (T->n <= 0 || T->ins[T->n - 1].code != (BPF_JMP | BPF_EXIT)) {
            printf("REFTRAP name=%s verdict=MALFORMED reason=last_insn_is_not_exit n=%d\n",
                   T->name, T->n);
            n_total++;
            continue;
        }
        struct bpfref_result ref = bpfref_run(T->ins, T->n, 0);

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = T->n;
        attr.insns = (uint64_t)(unsigned long)T->ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 1;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        uint32_t kern = 0;
        int ran = 0, rerr = 0;
        if (fd >= 0) {
            static char pin[64], pout[64];
            union bpf_attr r;
            memset(&r, 0, sizeof(r));
            r.test.prog_fd = fd;
            r.test.data_in = (uint64_t)(unsigned long)pin;
            r.test.data_out = (uint64_t)(unsigned long)pout;
            r.test.data_size_in = sizeof(pin);
            r.test.data_size_out = sizeof(pout);
            r.test.repeat = 1;
            if (bpf(BPF_PROG_TEST_RUN, &r, sizeof(r)) == 0) { ran = 1; kern = r.test.retval; }
            else rerr = errno;
            close(fd);
        }
        uint32_t refv = (uint32_t)ref.retval;
        /* A load rejection or a run error is NOT a semantic disagreement, and reporting
           it as one would make the calibration cry wolf — the same lesson 0055 learned
           about the validity counter. Say which of the three happened. */
        const char *verdict = !ran ? "not-run"
                            : ref.status != BPFREF_OK ? "ref-fault"
                            : refv == kern ? "agree" : "DISAGREE";
        printf("REFTRAP name=%s load=%s load_errno=%d ran=%d run_errno=%d"
               " ref_status=%s ref=0x%08x kernel=0x%08x verdict=%s\n",
               T->name, fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : lerr, ran, rerr,
               bpfref_status_name(ref.status), refv, kern, verdict);
        n_total++;
        if (strcmp(verdict, "agree") == 0) n_agree++;
    }
    printf("REFCAL total=%d agree=%d\n", n_total, n_agree);
}

// ---- calibration probe: the sign-lost stack spill (--probe-spill) -----------
// Calibration pair six (811c363645b3, "bpf: Fix check_stack_write_fixed_off() to correctly
// spill imm", 2023-11-01, found by Hao Sun) — and the first target for the RUNTIME channel.
//
// THE BUG, one cast. `check_stack_write_fixed_off()` tracked the immediate of a 64-bit
// `BPF_ST_MEM` as `__mark_reg_known(&fake_reg, (u32)insn->imm)`. `insn->imm` is an s32, so
// the cast DROPS THE SIGN: storing -44 is tracked as 4294967252. Reloading the slot then
// gives the verifier a register it believes is a large positive constant.
//
// WHY THE RUNTIME CHANNEL IS THE ONE THAT SEES IT. The corrupted state is a single pinned
// constant — `R0_w=4294967252`, tnum const, bounds pinned to it — with NO internal
// contradiction, so every consistency invariant is silent and `reg_bounds_sanity_check`
// has nothing to flag (and would not exist on that kernel anyway: it arrived 2023-11-11,
// ten days after this fix). What the bug DOES do is make `if r0 s< 0xa` look permanently
// false, so the verifier explores only the fall-through and proves the program returns 1.
// At runtime the stored value really is sign-extended -44, the branch really is taken, and
// the program returns 0. Verifier-proved retval 1, observed retval 0: exactly the
// invariant the 0036 oracle checks.
//
// THE PROGRAM is the commit's own, transcribed verbatim:
//     r2 = r10; *(u64 *)(r2 -40) = -44; r0 = *(u64 *)(r2 -40)
//     if r0 s< 0xa goto +2; r0 = 1; exit; r0 = 0; exit
//
// A CONTROL arm stores +44 instead. A positive immediate survives the cast unchanged, so
// the verifier's tracking is correct there and both kernels must agree — if the control
// diverges too, the divergence is not about the lost sign.
static void run_probe_spill(void) {
    static const struct { const char *name; int imm; } ARMS[] = {
        {"neg", -44},   /* the commit's trigger: sign dropped by the (u32) cast */
        {"pos",  44},   /* control: unaffected by the cast                      */
    };
    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[12];
        int n = 0;
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_2, -40, ARMS[a].imm);
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, -40);
        const int jlt = n;
        ins[n++] = BPF_JMP_IMM(BPF_JSLT, BPF_REG_0, 10, 0);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        ins[jlt].off = n - jlt - 1;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG spill#811c363645b3#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        /* THE GENERATOR'S OWN CLAIM, derived from the program text and nothing else: the
           64-bit slot holds the sign-extended immediate, the reload returns it, and
           `if r0 s< 10` decides the exit value. It does not consult the verifier, which is
           the entire point — see check_runtime_intent in diff.rs. */
        printf("EXPECT intended_retval=%d\n", ARMS[a].imm < 10 ? 0 : 1);

        /* The runtime half. The program reads nothing external, so the input is a
           formality — one sample is the whole observation. */
        if (fd >= 0) {
            static char pkt_in[64], pkt_out[64];
            union bpf_attr r;
            memset(&r, 0, sizeof(r));
            r.test.prog_fd = fd;
            r.test.data_in = (uint64_t)(unsigned long)pkt_in;
            r.test.data_out = (uint64_t)(unsigned long)pkt_out;
            r.test.data_size_in = sizeof(pkt_in);
            r.test.data_size_out = sizeof(pkt_out);
            r.test.repeat = 1;
            int rc = bpf(BPF_PROG_TEST_RUN, &r, sizeof(r));
            if (rc < 0)
                printf("RUNTIME input=0x00000000 error=1 testrun_errno=%d\n", errno);
            else
                printf("RUNTIME input=0x00000000 retval=0x%08x\n", r.test.retval);
            close(fd);
        }
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
}

// ---- calibration probe: the 32-bit delta replayed as 64-bit (--probe-deltalink) ------
// Calibration pair EIGHT (3878ae04e9fc, "bpf: Fix incorrect delta propagation between
// linked registers", 2024-10-16) -- and the first pair aimed at the STORE-LOCATION
// channel, which 0041 called "the hunt" and which no real bug had ever exercised.
//
// THE BUG, one missing condition. `adjust_reg_min_max_vals()` stamped BPF_ADD_CONST and
// recorded `dst_reg->off = val` for a 32-BIT add as readily as for a 64-bit one, but the
// record keeps only id+off -- it does not remember the width. `sync_linked_regs()` then
// replays the delta in FULL 64-BIT arithmetic:
//     __mark_reg_known(&fake_reg, (s32)reg->off - (s32)known_reg->off);
//     copy_register_state(reg, known_reg); scalar_min_max_add(reg, &fake_reg);
// When the original add was alu32 the CPU zero-extends, so the true value can never carry
// out of the low word -- but a negative delta added in 64 bits BORROWS into the upper
// word. The fix adds `&& !alu32`, unlinking such registers entirely.
//
// WHY THIS PAIR IS THE STORE-LOCATION ONE. The resulting state is self-consistent: a
// pinned constant with tnum and bounds in agreement. Every internal-consistency invariant
// is silent by construction, and the verdict is ACCEPT on both kernels. What is wrong is
// only the RELATION to reality -- the verifier's constant is not the CPU's -- and the one
// oracle whose reference is the runtime landing site is check_store_location.
//
// THE SHAPE is the divergence generator from the maintainers' own selftest
// (`verifier_linked_scalars.c`, added by db123e42304d in the same series), with its
// pointer-arithmetic amplification replaced by a SMALL in-bounds store. The selftest
// drives the store to fp+0x7FFFFFFE, which is a wild write that would take the VM with
// it; here the divergent bit is narrowed to one bit and scaled to 8 bytes, so BOTH the
// proven and the real landing site sit inside the same 64-byte map value. That is the
// difference between a crash and an observation.
//
//     r1 = <base> ll ; r1 /= 1        -- value-preserving; drops the constant so r1 gets an id
//     r2 = r1 ; r4 = r1               -- LINK: one id, three members
//     w2 += 0x40000000                -- alu32: stamps ADD_CONST, off=0x40000000
//     w4 += 0                         -- alu32: stamps ADD_CONST, off=0
//     if r2 == <cmp> goto L1          -- pins known_reg, fires sync_linked_regs
//   L1: r4 >>= 63                     -- the divergent bit, and nothing else
//     r4 <<= 3 ; r7 += r4             -- 0 or 8 bytes into the map value
//     *(u8 *)(r7 + 0) = 0xFF          -- THE STORE
//
// THE ARMS DIFFER IN ONE THING: whether the 32-bit add WRAPS.
//   wrap   base=0xC0000001 -> w2 wraps to 1; known_reg=1, delta=-0x40000000, and the
//          64-bit replay borrows: the verifier believes r4=0xFFFFFFFFC0000001, so
//          r4>>63 = 1 and it proves the store at map_value+8. The CPU has r4=0xC0000001,
//          r4>>63 = 0, and stores at map_value+0.
//   nowrap base=0x00000001 -> w2 = 0x40000001, no wrap; known_reg=0x40000001 is above the
//          delta so the replay does not borrow, r4=1 on both sides, and proven == real.
// 0062 added this bug's LINK shape to --gen-spill but explicitly not its wraparound
// trigger; the control arm is that missing ingredient isolated as a variable.
static void run_probe_deltalink(void) {
    static const struct { const char *name; unsigned int base; int cmp; } ARMS[] = {
        {"wrap",   0xC0000001u, 0x00000001},  /* trigger: the 32-bit add wraps to 1  */
        {"nowrap", 0x00000001u, 0x40000001},  /* control: same shape, no wraparound  */
    };
    const int ADD = 0x40000000;   /* same in both arms, and <= (u32)S32_MAX so the
                                     BPF_ADD_CONST stamp is not declined */

    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = RTW_VALUE_SIZE;
    m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) {
        printf("===PROG deltalink#3878ae04e9fc type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n",
               errno);
        return;
    }

    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[32];
        int n = 0, jexit[2], nx = 0;

        /* The map value pointer FIRST: r1-r5 are caller-saved, so no helper call may
           follow the divergence block that lives in them. */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);

        /* A full 64-bit immediate load: BPF_MOV64_IMM would SIGN-extend 0xC0000001 and
           the base would not be the one this arm names. */
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = 0, .off = 0, .imm = (int)ARMS[a].base};
        ins[n++] = (struct bpf_insn){0};              /* high word = 0 */
        ins[n++] = BPF_ALU64_IMM(BPF_DIV, BPF_REG_1, 1);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_1);
        ins[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_1);
        ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_2, ADD);
        ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_4, 0);
        const int jeq = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_2, ARMS[a].cmp, 0);
        jexit[nx++] = n; ins[n++] = BPF_JMP_A(0);     /* r2 != cmp: unreachable at runtime */
        ins[jeq].off = n - jeq - 1;

        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_4, 63);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 3);
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_4);
        const int store_insn = n;
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, 0, -1);   /* -1 == RTW_SENTINEL byte */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++)
            ins[jexit[i]].off = exit0 - jexit[i] - 1;

        struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
        struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                                 g_log2, sizeof(g_log2));
        struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                                 g_log2, sizeof(g_log2));

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG deltalink#3878ae04e9fc#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        printf("STORE insn=%d reg=7 off=0 size=1\n", store_insn);
        /* The generator's own claim, read off the program text and the ISA -- never off
           the verifier. Both arms reach the store, so both return 1. */
        printf("EXPECT intended_retval=1\n");
        printf("PRUNE fall=deltalink taken=%s fall_safe=1 taken_safe=1 stack=0"
               " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
               " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
               " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
               ARMS[a].name,
               base.accept ? "accept" : "reject", base.err, base.states, base.reason,
               freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
               inv.accept ? "accept" : "reject", inv.err, inv.reason);

        if (fd >= 0) {
            unsigned char pkt[64], zero[RTW_VALUE_SIZE], out[RTW_VALUE_SIZE];
            memset(pkt, 0, sizeof(pkt));
            memset(zero, 0, sizeof(zero));
            /* The program reads nothing external, so one sample IS the observation --
               but the map still has to be cleared, or a previous arm's sentinel would
               be read as this arm's landing site. */
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x00000000 error=1 testrun_errno=%d\n",
                       r < 0 ? errno : 0);
            } else {
                int off = -1;
                for (int b = 0; b < RTW_VALUE_SIZE; b++)
                    if (out[b] == RTW_SENTINEL) { off = b; break; }
                int executed = (t.test.retval == 1);
                if (off < 0)
                    printf("RUNTIME input=0x00000000 retval=0x%08x store_off=none"
                           " store_len=0 store_size=1 executed=%d\n",
                           t.test.retval, executed);
                else {
                    int len = 0;
                    for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                    printf("RUNTIME input=0x00000000 retval=0x%08x store_off=%d"
                           " store_len=%d store_size=1 executed=%d\n",
                           t.test.retval, off, len, executed);
                }
            }
            close(fd);
        }
        bpflive_print_claim(ins, n);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
    close(map_out);
}

// ---- calibration probe: the missing JSET edge (--probe-jsetlive) ------------------------
// Calibration pair NINE (3157f7e29996, "bpf: handle jset (if a & b ...) as a jump in CFG
// computation", 2025-06-13, reported by syzbot) — and the first pair aimed at the LIVENESS
// GATE, the cross-state channel 0088 built.
//
// THE BUG, one missing case label. `can_jump()` enumerates the conditional-jump opcodes
// whose taken edge `insn_successors()` reports, and BPF_JSET was not in the list:
//
//     case BPF_JSLT: case BPF_JSLE: case BPF_JCOND:
//   + case BPF_JSET:
//             return true;
//
// So the CFG the liveness analysis walks is MISSING an edge, and the commit says exactly
// what that costs: "a jump to (5) would be missed and r2 won't be marked as alive at (3)".
//
// WHY THIS IS THE GATE'S OWN PAIR, and why the DIRECTION is the whole point. A register the
// verifier calls dead is never compared by `func_states_equal` — so a liveness that is too
// SMALL is a prune that never had to justify itself. That is precisely the direction
// `check_liveness_gate` reports and `bpflive.h` is built to be trusted in: independent
// analysis says LIVE, kernel says DEAD.
//
// THE PROGRAM is the commit's own reproducer, with an unknown scalar in front so the branch
// is real rather than folded:
//
//     r0 = call get_prandom_u32 ; r1 = r0      -- an unknown scalar to test
//     r0 = 1 ; r2 = 2
//     if r1 <OP> 0x7 goto +1                   -- the edge under test
//     exit                                     -- fall-through returns r0 = 1
//     r0 = r2 ; exit                           -- taken branch READS r2, returns 2
//
// At the jump, r2 is live because the taken branch reads it. On the buggy kernel the taken
// edge does not exist, so the table prints r2 as dead there — one cell, and it is the cell
// the oracle is built to find.
//
// THE ARMS DIFFER IN ONE THING: the comparison opcode.
//   jset  BPF_JSET -- absent from the buggy can_jump(): the taken edge is invisible
//   jne   BPF_JNE  -- present in BOTH kernels' can_jump(), so the edge is seen on both and
//                     the two analyses must agree. If the control diverged too, the finding
//                     would be about the shape rather than about the missing case label.
static void run_probe_jsetlive(void) {
    static const struct { const char *name; int op; } ARMS[] = {
        {"jset", BPF_JSET},   /* the trigger: the opcode can_jump() forgot */
        {"jne",  BPF_JNE},    /* control: an opcode it never forgot        */
    };
    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[12];
        int n = 0;
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 2);
        ins[n++] = BPF_JMP_IMM(ARMS[a].op, BPF_REG_1, 0x7, 1);
        ins[n++] = BPF_EXIT_INSN();
        ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_2);
        ins[n++] = BPF_EXIT_INSN();

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG jsetlive#3157f7e29996#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        /* No EXPECT: the branch is decided by get_prandom_u32, so the generator has no
           claim to make about the return value and 0072's rule forbids inventing one.
           This pair's channel is the liveness table, and that is printed either way. */
        bpflive_print_claim(ins, n);
        if (fd >= 0)
            close(fd);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
}

// ---- calibration probe: may_goto's spurious r0 use (--probe-maygotolive) ---------------
// Calibration pair TEN (871ef8d50e7c, "bpf: correct use/def for may_goto instruction",
// 2025-03-05) — and the pair is here to measure a SILENCE, not a finding.
//
// THE BUG, one missing case label, in the same function 3157f7e29996 later fixed elsewhere:
//
//       case BPF_JA:
//     + case BPF_JCOND:
//               def = 0; use = 0; break;
//
// Without it `may_goto` fell through to the generic conditional-jump arm, which for a BPF_K
// jump reads the destination register — and may_goto's dst_reg field is 0. So the analysis
// marked **r0 as used** at every may_goto. The commit's words: "thus unnecessarily marking
// r0 as used".
//
// WHY THIS PAIR IS A BOUNDARY AND MUST STAY ONE. check_liveness_gate reports one direction
// only: the kernel calling DEAD what the independent analysis calls LIVE, because that is
// the register `func_states_equal` then never compares. This bug is the OTHER direction —
// the kernel calls LIVE something that is dead, so it compares a register it did not have
// to. That costs precision and risks nothing, and an oracle that reported it would be
// reporting conservatism as unsoundness.
//
// So the wanted result is: the two kernels' printed tables DIFFER, and the pipeline is
// silent on both. A silence is only evidence when the thing it is silent about actually
// happened, which is why this probe prints the table row that changes.
//
// THE PROGRAM is the maintainers' own `may_goto` case from
// tools/testing/selftests/bpf/progs/compute_live_registers.c, whose fixed expectation is
// pinned there as `1: .1........ (e5) may_goto pc+1` — r1 live, r0 NOT.
//
//     0: r1 = 1
//     1: may_goto +1        <- the row under test
//     2: goto -3            (back to 0; the may_goto budget ends the loop)
//     3: r0 <OP> r1
//     4: exit
//
// THE ARMS DIFFER IN ONE INSTRUCTION, and it is the one that decides whether r0 is dead at
// the may_goto at all:
//   mov  `r0 = r1`  -- r0 is DEAD before insn 3, so the spurious use is visible
//   add  `r0 += r1` -- r0 is genuinely READ at insn 3, so it is live at the may_goto on
//                      BOTH kernels and the row cannot differ. If the control's row moved
//                      too, the difference would not be about the missing case label.
static void run_probe_maygotolive(void) {
    static const struct { const char *name; int add; } ARMS[] = {
        {"mov", 0},   /* trigger: r0 dead at the may_goto */
        {"add", 1},   /* control: r0 live there on both kernels */
    };
    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[8];
        int n = 0;
        /* r0 is initialised up front so BOTH arms load: the control READS r0 at the end,
           and without this it would reject with "R0 !read_ok" — a rejected control is a
           weaker control, and this project pairs every shape with an ACCEPTED one. The
           loop below re-enters at insn 1, so this runs once and changes nothing else. */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_1, 1);
        ins[n++] = BPF_MAY_GOTO_INSN(1);
        ins[n++] = BPF_JMP_A(-3);
        ins[n++] = ARMS[a].add ? BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1)
                               : BPF_MOV64_REG(BPF_REG_0, BPF_REG_1);
        ins[n++] = BPF_EXIT_INSN();

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG maygotolive#871ef8d50e7c#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        bpflive_print_claim(ins, n);
        if (fd >= 0)
            close(fd);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
}

// ---- calibration probe: the kernel's OWN liveness selftests (--probe-livetraps) --------
//
// WHY THIS EXISTS. bpflive.h is an independent re-implementation of the verifier's
// live-register analysis, and 0088 built the whole liveness gate on top of it. Its own
// header states the load-bearing precondition: "because [too-large liveness] is also the
// direction a COARSER analysis produces, this file has to be at least as precise as the
// kernel's before it is allowed to judge." Until now the only evidence for that was
// --probe-jsetlive, which exercises ONE opcode on TWO arms. That is a calibration of a
// single cell, not of the model.
//
// The kernel ships the missing corpus itself:
// tools/testing/selftests/bpf/progs/compute_live_registers.c is a set of hand-written
// programs, each annotated with the EXACT liveness row the verifier is expected to print
// for every instruction. Those __msg lines are a maintainer-maintained oracle for the
// analysis bpflive.h duplicates — the one reference in this project that was not derived
// from our own model. Replaying them through the harness turns "we believe bpflive.h is at
// least as precise as the kernel" into a measurement with a denominator: 15 programs,
// ~50 pinned instruction rows, and a named disagreement wherever there is one.
//
// THE DIRECTION IS STILL THE POINT. A row where bpflive says LIVE and the kernel says DEAD
// is either a kernel bug (the finding we hunt) or a bpflive imprecision (a manufactured
// finding, and a reason to distrust every prior zero). These selftests are the only inputs
// where we know a priori which of the two it is, because the expected row is written down.
// Every disagreement here is therefore a bpflive defect by construction, and the value of
// the probe is exactly the list it produces.
//
// SCOPE, and what was left out. The harness emits SOCKET_FILTER programs and bpflive.h
// models a single frame over ALU/ALU64, LDX/STX/ST (incl. ATOMIC and MEMSX), LD_IMM64,
// JMP/JMP32 (incl. gotol and may_goto), helper CALL and EXIT. Five of the source file's
// twenty programs fall outside that and are NOT replayed: ldabs (LD_ABS/LD_IND — bpflive
// returns UNSUPPORTED by design), addr_space_cast (arena map + a kfunc + fentry), subprog1
// and subprog_ret_reg_pair (BPF_PSEUDO_CALL — interprocedural, explicitly out of model),
// and gotox (indirect jump through a BPF_MAP_TYPE_INSN_ARRAY jump table). See
// livetraps-expected.md for the row-by-row reasons.
//
// WHAT IS NOT LOST BY A REJECT. bpf_compute_live_registers() runs in bpf_check() BEFORE
// do_check_main() (verifier.c:21298), and prints its table at BPF_LOG_LEVEL2 the moment it
// finishes. So the liveness rows appear in the log even for a program the verifier later
// refuses — a `load` that reads uninitialised stack without CAP_PERFMON, or a store-release
// on a kernel that predates it, still yields the signal this probe is here for. The RESULT
// line records the verdict; it is not a gate on the measurement.
//
// PLACEMENT. This file is a fragment of diffharness.c: it uses g_log, bpf(), the insn
// macros and bpflive_print_claim(). Paste it after run_probe_jsetlive() and add the
// --probe-livetraps arm to main(). The four opcodes the harness has no macro for are
// spelled locally below, in the same raw-struct idiom diffharness.c already uses for
// atomics (see doc_bad_ptr_xadd and run_probe_deltalink).

/* Newer opcode bits. Present in the kernel's uapi but not necessarily in distro headers,
   so define them the way include/uapi/linux/bpf.h does — same reason BPF_MEMSX is guarded
   at the top of diffharness.c. */
#ifndef BPF_FETCH
#define BPF_FETCH     0x01
#endif
#ifndef BPF_XCHG
#define BPF_XCHG      (0xe0 | BPF_FETCH)
#endif
#ifndef BPF_CMPXCHG
#define BPF_CMPXCHG   (0xf0 | BPF_FETCH)
#endif
#ifndef BPF_LOAD_ACQ
#define BPF_LOAD_ACQ  0x100
#endif
#ifndef BPF_STORE_REL
#define BPF_STORE_REL 0x110
#endif
#ifndef BPF_JCOND
#define BPF_JCOND     0xe0
#endif
#ifndef BPF_MAY_GOTO
#define BPF_MAY_GOTO  0
#endif

/* An atomic RMW, spelled exactly as the kernel's own BPF_ATOMIC_OP: DST holds the ADDRESS
   and SRC the operand — except for BPF_LOAD_ACQ, where the roles are REVERSED (DST is the
   value destination, SRC the address). That reversal is the single most likely place for an
   independent analysis to be wrong, which is why the selftest pins it. */
#define LT_ATOMIC(SIZE, OP, DST, SRC, OFF)                                     \
    ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,          \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = (OP)})

/* Byte-order conversion: reads AND writes dst, which is what makes it different from a
   MOV for liveness purposes. `r2 = le64 r2` is BPF_ALU|BPF_END|BPF_TO_LE with imm=64. */
#define LT_END(CLASS, TOEND, DST, LEN)                                         \
    ((struct bpf_insn){.code = (CLASS) | BPF_END | (TOEND),                    \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = (LEN)})

/* gotol: a LONG unconditional jump whose displacement lives in imm, not off. Reading `off`
   here yields 0 and turns the jump into a fall-through — the exact trap bpflive.h's
   bpflive_succ() documents having found in this very selftest file. */
#define LT_GOTOL(DISP)                                                         \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_JA,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (DISP)})

/* may_goto +off: the budget-exhausted edge. Reads no register, but its TAKEN edge is what
   keeps the loop-carried registers alive at the head. */
#define LT_MAY_GOTO(OFF)                                                       \
    ((struct bpf_insn){.code = BPF_JMP | BPF_JCOND,                            \
                       .dst_reg = 0, .src_reg = BPF_MAY_GOTO, .off = OFF, .imm = 0})

/* A plain 64-bit immediate load. BPF_LD_MAP_FD stamps BPF_PSEUDO_MAP_FD in src_reg; this
   one must leave src_reg at 0 or the verifier resolves it as a map. Two slots, like every
   LD_IMM64, and the second is the high word. */
#define LT_LD_IMM64(DST, IMM)                                                  \
    ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = DST,      \
                       .src_reg = 0, .off = 0, .imm = (IMM)}),                 \
    ((struct bpf_insn){0})

/* Helper ids are taken from the public numbering in include/uapi/linux/bpf.h's
   __BPF_FUNC_MAPPER — FN(map_lookup_elem, 1) at line 6004, FN(trace_printk, 6) at line
   6009 — which is the same source bpflive_helper_argc() cites and is not the liveness
   code. The selftest's own expected log confirms the second: "(85) call bpf_trace_printk#6". */
#define LT_FN_MAP_LOOKUP_ELEM 1
#define LT_FN_TRACE_PRINTK    6

enum livetrap_id {
    LT_ASSIGN_CHAIN,
    LT_ARITHMETICS,
    LT_STORE,
    LT_LOAD,
    LT_ENDIAN,
    LT_ATOMIC_RMW,
    LT_ATOMIC_ACQ_REL,
    LT_REGULAR_CALL,
    LT_IF1,
    LT_IF2,
    LT_IF3_JSET_BUG,
    LT_LOOP,
    LT_GOTOL_CASE,
    LT_MAY_GOTO_CASE,
    LT_LDIMM64,
};

struct livetrap_case {
    const char *name;   /* the selftest function name — the row this pins */
    int id;
    int needs_map;      /* the ARRAY map the source file calls `test_map` */
};

/* The order is the source file's order, so a diff of two runs lines up with the file. */
static const struct livetrap_case LIVETRAPS[] = {
    /* A dependency chain with no branches: the only way to be wrong is to misread MOV's
       def/use, and every row differs from every other, so a constant-mask bug is visible. */
    {"assign_chain",       LT_ASSIGN_CHAIN,   0},
    /* `r1 += 7` whose result nothing ever reads, yet r1 is LIVE before it: a non-MOV ALU
       reads its destination. The row that separates liveness from usefulness. */
    {"arithmetics",        LT_ARITHMETICS,    0},
    /* BPF_ST's use set is {dst} and BPF_STX's is {dst, src} — two different rules for two
       instructions the disassembly prints almost identically. */
    {"store",              LT_STORE,          0},
    /* insn 3 is a second `r4 += -8` whose result is dead; r4 AND r5 are live there anyway.
       Getting this row right requires the dst-is-also-a-use rule to survive a dead result. */
    {"load",               LT_LOAD,           0},
    /* BPF_END is the one ALU op that both defines and uses dst. Treating it as a MOV would
       drop r2 from row 1 and nothing else in the corpus would notice. */
    {"endian",             LT_ENDIAN,         0},
    /* The atomic family in one program: FETCH writes back into SRC, the non-fetch form
       writes nothing, XCHG writes SRC, and CMPXCHG implicitly READS AND WRITES r0. Rows
       12-14 also swap r0 and r1 through r2, so an off-by-one in the fixpoint shows up. */
    {"atomic",             LT_ATOMIC_RMW,     1},
    /* load-acquire REVERSES dst/src: dst is the value destination, src the address. Every
       other BPF_STX|BPF_ATOMIC in the ISA reads dst as a pointer. Row 4 is the assertion. */
    {"atomic_load_acq_store_rel", LT_ATOMIC_ACQ_REL, 0},
    /* A helper's use set is its PROTO's argument count, not five. bpf_trace_printk takes
       two (fmt, len), so r3-r5 are dead at the call — the row that punishes a model which
       assumes the maximum. */
    {"regular_call",       LT_REGULAR_CALL,   0},
    /* Conditional jump, BPF_K form: use = {dst}. */
    {"if1",                LT_IF1,            0},
    /* Conditional jump, BPF_X form: use = {dst, src}. */
    {"if2",                LT_IF2,            0},
    /* The source file's own comment: "Verifier misses that r2 is alive if jset is not
       handled properly". This is calibration pair NINE's bug expressed as a pinned row —
       the same shape --probe-jsetlive drives, but with the maintainers' expected value. */
    {"if3_jset_bug",       LT_IF3_JSET_BUG,   0},
    /* A back edge. r1 and r2 are live across the whole body only after the fixpoint has
       gone round the loop; a single backward sweep gets rows 2-4 wrong. */
    {"loop",               LT_LOOP,           0},
    /* The displacement is in imm. A model that reads off sees a fall-through and gets every
       row after the jump wrong while still looking self-consistent. */
    {"gotol",              LT_GOTOL_CASE,     0},
    /* may_goto reads nothing, but its taken edge reaches the r1 reader, so r1 must be live
       at the head — the liveness of a register kept alive purely by an edge. */
    {"may_goto",           LT_MAY_GOTO_CASE,  0},
    /* LD_IMM64 occupies two slots. The kernel PRINTS no row for the tail (liveness.c skips
       it via bpf_is_ldimm64), so index 3 follows index 1 in the log while bpflive's mask
       string still carries a slot for index 2. Alignment, not arithmetic. */
    {"ldimm64",            LT_LDIMM64,        0},
};

/* Build one case. Returns the instruction count, or 0 if the case needs a map we could not
   create. `map_fd` is the plain BPF_MAP_TYPE_ARRAY the source file declares as `test_map`
   (key __u32, value __u64, one entry) — the only map any in-scope case touches. */
static int livetrap_build(int id, int map_fd, struct bpf_insn *ins)
{
    switch (id) {

    case LT_ASSIGN_CHAIN: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_0, 42),
            BPF_MOV64_REG(BPF_REG_1, BPF_REG_0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
            BPF_MOV64_REG(BPF_REG_3, BPF_REG_2),
            BPF_MOV64_REG(BPF_REG_4, BPF_REG_3),
            BPF_MOV64_REG(BPF_REG_5, BPF_REG_4),
            BPF_MOV64_REG(BPF_REG_6, BPF_REG_5),
            BPF_MOV64_REG(BPF_REG_7, BPF_REG_6),
            BPF_MOV64_REG(BPF_REG_8, BPF_REG_7),
            BPF_MOV64_REG(BPF_REG_9, BPF_REG_8),
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_9),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_ARITHMETICS: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_1, 7),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 7),
            BPF_MOV64_IMM(BPF_REG_2, 7),
            BPF_MOV64_IMM(BPF_REG_3, 42),
            BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_3),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_STORE: {
        struct bpf_insn a[] = {
            BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
            BPF_ST_MEM(BPF_DW, BPF_REG_1, 0, 7),
            BPF_MOV64_IMM(BPF_REG_2, 42),
            BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, 0),
            /* The duplicate store is deliberate: two identical rows in a row make an
               off-by-one in the printed table impossible to miss. */
            BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_2, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_LOAD: {
        struct bpf_insn a[] = {
            BPF_MOV64_REG(BPF_REG_4, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
            /* Reads uninitialised stack. Privileged loads accept it (allow_uninit_stack ==
               CAP_PERFMON); unprivileged ones reject AFTER the liveness table is printed,
               so the row survives either way. */
            BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_4, 0),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -8),
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_5),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_ENDIAN: {
        struct bpf_insn a[] = {
            /* r1 is the socket_filter ctx; +0 is skb->len, a legal 4-byte ctx read. */
            BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0),
            LT_END(BPF_ALU, BPF_TO_LE, BPF_REG_2, 64),
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_ATOMIC_RMW: {
        if (map_fd < 0)
            return 0;
        struct bpf_insn a[] = {
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                       /*  0 */
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),                      /*  1 */
            BPF_MOV64_IMM(BPF_REG_1, 0),                                /*  2 */
            BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_1, 0),               /*  3 */
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),                           /*  4,5 */
            BPF_EMIT_CALL(LT_FN_MAP_LOOKUP_ELEM),                       /*  6 */
            /* The null check is the only reason the atomics below are reachable; its
               target is the single exit at 15, so off = 15 - 7 - 1. */
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),                      /*  7 */
            BPF_MOV64_IMM(BPF_REG_1, 1),                                /*  8 */
            /* FETCH: leaves the OLD value in r1, so r1 is DEFINED here as well as used. */
            LT_ATOMIC(BPF_DW, BPF_ADD | BPF_FETCH, BPF_REG_0, BPF_REG_1, 0), /* 9 */
            /* No FETCH, and 32-bit: defines nothing. */
            LT_ATOMIC(BPF_W,  BPF_ADD,             BPF_REG_0, BPF_REG_1, 0), /* 10 */
            LT_ATOMIC(BPF_DW, BPF_XCHG,            BPF_REG_0, BPF_REG_1, 0), /* 11 */
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_0),                        /* 12 */
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),                        /* 13 */
            /* CMPXCHG: address in dst (r2), new value in src (r1), compared-and-returned
               value implicitly in r0 — the only instruction with an implicit register. */
            LT_ATOMIC(BPF_DW, BPF_CMPXCHG,         BPF_REG_2, BPF_REG_1, 0), /* 14 */
            BPF_EXIT_INSN(),                                            /* 15 */
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_ATOMIC_ACQ_REL: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_1, 42),                                    /* 0 */
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),                            /* 1 */
            /* store-release: dst is the address, src the value — the normal roles. */
            LT_ATOMIC(BPF_DW, BPF_STORE_REL, BPF_REG_2, BPF_REG_1, -8),      /* 2 */
            BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),                            /* 3 */
            /* load-acquire: dst is the DESTINATION, src the address. Row 4's expected mask
               is `...3......` — r4 is written, not read. */
            LT_ATOMIC(BPF_DW, BPF_LOAD_ACQ,  BPF_REG_4, BPF_REG_3, -8),      /* 4 */
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_4),                             /* 5 */
            BPF_EXIT_INSN(),                                                 /* 6 */
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_REGULAR_CALL: {
        struct bpf_insn a[] = {
            /* r7 is callee-saved, so it must survive the call and be live on both sides of
               it — the row that proves the clobber set stops at r5. */
            BPF_MOV64_IMM(BPF_REG_7, 1),
            BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -8),
            BPF_MOV64_IMM(BPF_REG_2, 1),
            BPF_EMIT_CALL(LT_FN_TRACE_PRINTK),
            BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_IF1: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_0, 1),
            BPF_MOV64_IMM(BPF_REG_2, 2),
            /* r1 is the ctx pointer, so the branch is genuinely two-way and neither edge
               is const-folded away before liveness runs. */
            BPF_JMP_IMM(BPF_JGT, BPF_REG_1, 7, 1),
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_IF2: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_0, 1),
            BPF_MOV64_IMM(BPF_REG_2, 2),
            BPF_MOV64_IMM(BPF_REG_3, 7),
            BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_3, 1),
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_IF3_JSET_BUG: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_0, 1),
            BPF_MOV64_IMM(BPF_REG_2, 2),
            /* If JSET's taken edge is missing from the CFG, insn 4 is unreachable and r2
               is reported dead here. That is the whole bug, in one cell. */
            BPF_JMP_IMM(BPF_JSET, BPF_REG_1, 7, 1),
            BPF_EXIT_INSN(),
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
            BPF_EXIT_INSN(),
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_LOOP: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_1, 0),                /* 0 */
            BPF_MOV64_IMM(BPF_REG_2, 7),                /* 1 */
            BPF_JMP_IMM(BPF_JGT, BPF_REG_1, 7, 4),      /* 2 -> 7 */
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, 1),       /* 3 */
            BPF_ALU64_IMM(BPF_MUL, BPF_REG_2, 2),       /* 4 */
            /* `goto +0` is a no-op jump kept from the source: it makes the block boundary
               explicit without adding an edge anywhere new. */
            BPF_JMP_A(0),                               /* 5 */
            BPF_JMP_A(-5),                              /* 6 -> 2, the back edge */
            BPF_MOV64_IMM(BPF_REG_0, 0),                /* 7 */
            BPF_EXIT_INSN(),                            /* 8 */
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_GOTOL_CASE: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_2, 42),               /* 0 */
            BPF_MOV64_IMM(BPF_REG_3, 24),               /* 1 */
            BPF_JMP_IMM(BPF_JGT, BPF_REG_1, 7, 2),      /* 2 -> 5 */
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),        /* 3 */
            LT_GOTOL(1),                                /* 4 -> 6, displacement in imm */
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_3),        /* 5 */
            BPF_EXIT_INSN(),                            /* 6 */
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_MAY_GOTO_CASE: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_1, 1),                /* 0, also the loop head */
            LT_MAY_GOTO(1),                             /* 1 -> 3 when the budget runs out */
            BPF_JMP_A(-3),                              /* 2 -> 0 */
            BPF_MOV64_REG(BPF_REG_0, BPF_REG_1),        /* 3 */
            BPF_EXIT_INSN(),                            /* 4 */
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    case LT_LDIMM64: {
        struct bpf_insn a[] = {
            BPF_MOV64_IMM(BPF_REG_0, 0),                /* 0 */
            LT_LD_IMM64(BPF_REG_2, 7),                  /* 1,2 — 2 is the high word */
            BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_2), /* 3 */
            BPF_EXIT_INSN(),                            /* 4 */
        };
        memcpy(ins, a, sizeof(a));
        return (int)(sizeof(a) / sizeof(a[0]));
    }

    default:
        return 0;
    }
}

static void run_probe_livetraps(void)
{
    /* The source file's `test_map`: BPF_MAP_TYPE_ARRAY, __u32 key, __u64 value, one entry.
       Only the `atomic` case needs it, and only to obtain a PTR_TO_MAP_VALUE the atomics
       can address; the value must be 8 bytes wide for the BPF_DW forms. */
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 8;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    int map_err = map_fd < 0 ? errno : 0;

    for (unsigned c = 0; c < sizeof(LIVETRAPS) / sizeof(LIVETRAPS[0]); c++) {
        struct bpf_insn ins[32];
        int n = livetrap_build(LIVETRAPS[c].id, map_fd, ins);

        if (n <= 0) {
            /* A case we could not build is reported, never skipped silently: a missing row
               would otherwise read downstream as a case that agreed. */
            printf("===PROG livetrap#%s type=socket_filter ===\n", LIVETRAPS[c].name);
            printf("RESULT decision=error fd=-1 errno=%d load_ns=0\n",
                   LIVETRAPS[c].needs_map ? map_err : 0);
            printf("---LOG---\n---END---\n");
            continue;
        }

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG livetrap#%s type=socket_filter ===\n", LIVETRAPS[c].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        /* No EXPECT: none of these programs has a return value the generator can claim
           without consulting the verifier, and 0072's rule forbids inventing one. The
           channel here is the liveness table on both sides, and it is printed either way —
           the kernel's rows come out of bpf_compute_live_registers() before do_check, so a
           reject above still leaves the comparison intact. */
        bpflive_print_claim(ins, n);
        if (fd >= 0)
            close(fd);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }

    if (map_fd >= 0)
        close(map_fd);
}
// ---- calibration probe: the unmapped BASE id (--probe-idbase) --------------------------
// Calibration pair ELEVEN (2f2ec8e7730e, "bpf: Enforce regsafe base id consistency for
// BPF_ADD_CONST scalars", 2026-04-11) — and the first positive control the PRUNING
// differential has ever had.
//
// WHY THIS PAIR MATTERS MORE THAN ANOTHER VALUE-TRACKING BUG. 0083 gave that differential
// its denominator and 0085 pushed it to 43,379 pairs; every one of them agreed. A zero on an
// oracle that has never fired cannot be read: "no unsound prunes in the corpus" and "the
// detector is dead" produce the identical number. This commit is the cleanest possible
// positive control, because its diff touches NOTHING but `check_scalar_ids()` — sixteen
// lines, no value-domain effect at all. The buggy kernel's only difference from the fixed one
// is a prune it should not take.
//
// THE BUG, in the commit's own words: "old has r2.id=A, r3.id=A|flag (r3 = r2 + delta), cur
// has r2.id=B, r3.id=C|flag (r3 derived from unrelated r4). Without the base check, idmap
// gets two independent entries A->B and A|flag->C|flag, missing that A->C conflicts with
// A->B." So two states whose LINK STRUCTURE differs compare equal.
//
// THE SHAPE. Two paths reach one instruction with the same registers but a different link:
//
//     r6 = prandom ; r7 = prandom          -- two independent unknowns
//     if <selector> goto L2
//        r2 = r6 ; r3 = r6 ; r3 += 1       -- r3 LINKED to r2   (id A, A|ADD_CONST)
//        goto MERGE
//     L2: r2 = r6 ; r3 = r7 ; r3 += 1      -- r3 linked to r7   (id A, C|ADD_CONST)
//     MERGE:
//     if r2 > 7 goto out                   -- narrows r2, and in the LINKED state r3 with it
//     *(u8 *)(map_value + r3) = 0xFF       -- safe only if r3 was narrowed
//
// The store is safe on the linked path and not on the unlinked one. If the two states are
// wrongly merged, the unlinked path is never walked and the program is accepted.
//
// THE DETECTOR IS THE FLAG DIFFERENTIAL, and its direction is what makes this work. The
// default checkpoint heuristic (>=2 jumps AND >=8 insns) may place no checkpoint at MERGE, so
// both paths get walked and the unsafe one is rejected. BPF_F_TEST_STATE_FREQ forces a
// checkpoint there, the buggy `check_scalar_ids` accepts the merge, and the rejection
// disappears. Flagged ACCEPT with default REJECT is exactly the soundness direction
// check_prune_differential reports as `prune_soundness_desync`; the reverse direction is
// counted as a resource artefact and never as a finding.
//
// THE ARMS DIFFER IN ONE REGISTER. The trigger's second path derives r3 from r7; the
// control's derives it from r6, so BOTH paths carry the same link and no id conflict exists.
// If the control flipped too, the flip would be about the merge, not about the base id.
static void run_probe_idbase(void) {
    static const struct { const char *name; int src; } ARMS[] = {
        {"unlinked", BPF_REG_7},   /* trigger: r3 tied to a DIFFERENT base on path 2 */
        {"linked",   BPF_REG_6},   /* control: same base on both paths                */
    };
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) {
        printf("===PROG idbase#2f2ec8e7730e type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }

    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[48];
        int n = 0, jexit[3], nx = 0;

        /* THE MAP VALUE POINTER FIRST, and it lives in a callee-saved register. A helper
           call clobbers r0-r5, so a lookup placed after the link is built would destroy the
           very register the store uses — which is exactly what the first version of this
           probe did, and the verifier said so: "R3 !read_ok". 0087's deltalink probe
           carries the same note; the rule had to be relearned once. */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_0);   /* map value ptr, callee-saved */

        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);   /* path selector */

        const int jsel = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
        /* path 1: r3 is r6 + 1, so r3 and r2 share a base id */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_6);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 1);
        const int jmerge = n;
        ins[n++] = BPF_JMP_A(0);
        /* path 2: the arm's whole difference is which register r3 comes from */
        ins[jsel].off = n - jsel - 1;
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_3, ARMS[a].src);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, 1);
        ins[jmerge].off = n - jmerge - 1;

        /* MERGE. Narrowing r2 narrows r3 too -- but only where they are actually linked. */
        jexit[nx++] = n;
        ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_2, 7, 0);

        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_3);
        const int store_insn = n;
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_9, 0, -1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

        struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
        struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                                 g_log2, sizeof(g_log2));
        struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                                 g_log2, sizeof(g_log2));

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG idbase#2f2ec8e7730e#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        printf("STORE insn=%d reg=9 off=0 size=1\n", store_insn);
        printf("PRUNE fall=idbase taken=%s fall_safe=1 taken_safe=%d stack=0"
               " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
               " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
               " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
               ARMS[a].name, ARMS[a].src == BPF_REG_6,
               base.accept ? "accept" : "reject", base.err, base.states, base.reason,
               freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
               inv.accept ? "accept" : "reject", inv.err, inv.reason);
        if (fd >= 0) close(fd);
        bpflive_print_claim(ins, n);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
    close(map_out);
}

// ---- calibration probe: the mixed-width linked delta (--probe-mixwidth) ----------------
// Calibration pair TWELVE (bc308be380c1, "bpf: Fix sync_linked_regs regarding
// BPF_ADD_CONST32 zext propagation", 2026-03-19) — aimed at the RUNTIME WRITE-SAFETY
// channel, which no real bug has ever exercised.
//
// THE BUG this arm targets is the commit's THIRD worked example, the mixed-width one. Two
// registers linked to the same base, one advanced with alu32 and the other with alu64:
//
//     r7 = r6 ; w7 += 1      -- r7.id = N | BPF_ADD_CONST32   (CPU zero-extends)
//     r8 = r6 ; r8 += 2      -- r8.id = N | BPF_ADD_CONST64   (CPU does NOT)
//     if w7 < 0xFFFFFFFF ... -- pins r7, and sync_linked_regs propagates to r8
//
// The delta relationship does not hold across widths, but the buggy sync propagated anyway
// and then applied `zext_32_to_64()` because KNOWN_REG carried the 32-bit flag. The commit
// states the consequence: "the CPU does NOT zero-extend it. The actual CPU value of r8 is
// 0xFFFFFFFE + 2 = 0x100000000, not 0. The verifier now underestimates r8's 64-bit bounds,
// which is a soundness violation."
//
// WHY WRITE-SAFETY AND NOT STORE-LOCATION. The verifier proves the store offset is 0; the
// CPU uses 0x100000000. Those differ by 4 GB, so the sentinel cannot land anywhere inside a
// 64-byte map value and `store_off=none` is what comes back — which check_store_location
// skips by design ("an absent sentinel is an OOB write, which check_runtime_write_safety
// already reports"). The two other worked examples in that commit are invisible to every
// oracle we have: one is an over-estimate, and the other is a case the old code got right.
//
// THE ARMS DIFFER IN ONE INSTRUCTION, and it is the width of a single add:
//   mixed  `r8 += 2`  (alu64) -- r8 carries ADD_CONST64 while r7 carries ADD_CONST32
//   same   `w8 += 2`  (alu32) -- both are 32-bit, the zext the verifier applies is CORRECT,
//                                and the CPU agrees. Verifier and runtime both put the store
//                                at offset 0, the sentinel is found, nothing fires.
static void run_probe_mixwidth(void) {
    static const struct { const char *name; int alu64; } ARMS[] = {
        {"mixed", 1},   /* trigger: alu64 on r8 against alu32 on r7 */
        {"same",  0},   /* control: both 32-bit                     */
    };
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    m.value_size = RTW_VALUE_SIZE;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG mixwidth#bc308be380c1 type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }

    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[48];
        int n = 0, jexit[4], nx = 0;

        /* The input map first: r6 takes a 32-bit value from it, which is what constrains the
           base to [0, U32_MAX] without a 64-bit jump immediate. */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);

        /* The output map, BEFORE the link is built: a helper call clobbers r0-r5, and r9 is
           callee-saved so the pointer survives the rest of the program. */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_0);

        /* The link, and the one instruction the arms differ in. */
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_7, 1);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_6);
        ins[n++] = ARMS[a].alu64 ? BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 2)
                                 : BPF_ALU32_IMM(BPF_ADD, BPF_REG_8, 2);
        /* Pin r7 to 0xFFFFFFFF on the fall-through. The compare is 32-bit because the
           constant does not fit a positive s32 immediate. */
        jexit[nx++] = n;
        ins[n++] = BPF_JMP32_IMM(BPF_JLT, BPF_REG_7, -1, 0);

        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_8);
        const int store_insn = n;
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_9, 0, -1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG mixwidth#bc308be380c1#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        printf("STORE insn=%d reg=9 off=0 size=1\n", store_insn);

        if (fd >= 0) {
            /* The input that makes w7 wrap to 0xFFFFFFFF is r6 = 0xFFFFFFFE, which is the
               only value that reaches the store at all — the branch sends every other one to
               the exit, and `executed=` records which happened. */
            unsigned char pkt[64], zero[RTW_VALUE_SIZE], out[RTW_VALUE_SIZE], val[16];
            memset(pkt, 0, sizeof(pkt));
            static const uint32_t INS[2] = {0xFFFFFFFEu, 0x00000001u};
            for (int i = 0; i < 2; i++) {
                memset(zero, 0, sizeof(zero)); memset(val, 0, sizeof(val));
                memcpy(val, &INS[i], 4);
                int ue = rt_map_set_bytes(map_in, 0, val);
                int ze = rt_map_set_bytes(map_out, 0, zero);
                union bpf_attr t;
                memset(&t, 0, sizeof(t));
                t.test.prog_fd = fd;
                t.test.data_in = (uint64_t)(unsigned long)pkt;
                t.test.data_size_in = sizeof(pkt);
                t.test.repeat = 1;
                int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
                memset(out, 0, sizeof(out));
                int ge = rt_map_get(map_out, 0, out);
                if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                    printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                           INS[i], r < 0 ? errno : 0);
                    continue;
                }
                int off = -1;
                for (int b = 0; b < RTW_VALUE_SIZE; b++)
                    if (out[b] == RTW_SENTINEL) { off = b; break; }
                int executed = (t.test.retval == 1);
                if (off < 0)
                    printf("RUNTIME input=0x%08x retval=0x%08x store_off=none store_len=0"
                           " store_size=1 executed=%d\n", INS[i], t.test.retval, executed);
                else {
                    int len = 0;
                    for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                    printf("RUNTIME input=0x%08x retval=0x%08x store_off=%d store_len=%d"
                           " store_size=1 executed=%d\n", INS[i], t.test.retval, off, len, executed);
                }
            }
            close(fd);
        }
        bpflive_print_claim(ins, n);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
    close(map_in); close(map_out);
}

// ---- calibration probe: the wrapping cnum arc (--probe-wraparc) ------------------------
// Calibration pair THIRTEEN (cd5b460ed1ec, "bpf: range_within() must check cnum ranges
// instead of min/max pairs", 2026-04-25) — and the first pair aimed at the SUBSUMPTION
// model 0099 built.
//
// THE BUG, in the commit's own words: range_within() decided with the min/max accessors,
//   reg_umin(old) <= reg_umin(cur) <= reg_umax(old)
// "This is wrong for cnums that cross both UT_MAX/0 and ST_MAX/ST_MIN boundaries. Consider
// cnum32{base=0x7FFFFFF0, size=0x80000020} ... A register with range [0x100, 0x200] (which
// lies entirely in the gap of the wrapping range) would pass the min/max check despite
// having no overlap with the actual cnum arc."
//
// WHY THE CORPUS COULD NOT FIND IT. 0100 ran the whole 896-program corpus on this kernel:
// 2038 prune pairs, and the model agreed with the buggy kernel on every one. A wrapping arc
// has to cross zero, and nothing in the grammar had a reason to build one. The bug is
// reachable only by a shape that is CONSTRUCTED, not stumbled upon — which is 0062's lesson
// again: a real bug names its input shape, and the shape is the deliverable.
//
// THE SHAPE. Two paths meet at one instruction with ranges that the two predicates judge
// differently:
//
//   old path: w6 &= 0x20 ; w6 -= 0x10   -> [0xFFFFFFF0..U32_MAX] u [0..0x10]   (WRAPS)
//   cur path: w6 &= 0x1ff ; w6 |= 0x100 -> [0x100, 0x1ff]                      (in the GAP)
//
// The wrapping arc projects to u32_min=0 / u32_max=U32_MAX, so the buggy min/max check reads
// the cur range as contained. The arc itself does not contain it at all.
//
// THE ARMS DIFFER IN ONE INSTRUCTION: whether the first path's subtraction wraps.
//   wrap    `w6 -= 0x10`  after `w6 &= 0x20`  -- crosses zero, arc wraps
//   nowrap  `w6 += 0x10`  after `w6 &= 0x20`  -- stays [0x10, 0x30], no wrap, and then the
//                                                two predicates must agree on both kernels
static void run_probe_wraparc(void) {
    static const struct { const char *name; int sub; } ARMS[] = {
        {"wrap",   1},   /* trigger: the arc crosses zero */
        {"nowrap", 0},   /* control: it does not          */
    };
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) {
        printf("===PROG wraparc#cd5b460ed1ec type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }

    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[64];
        int n = 0, jexit[4], nx = 0;

        /* Map value pointer first: r1-r5 are caller-saved and no helper call may follow. */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);      /* path selector */
        /* The padding below reads r7, so it must exist on every path. Using an
           uninitialised register as filler costs an "R7 !read_ok" rejection and the whole
           experiment with it — the third time this project has paid for that. */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 0);

        const int jsel = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
        /* path A: build the wrapping arc (or, in the control, one that does not wrap) */
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 0x20);
        ins[n++] = ARMS[a].sub ? BPF_ALU32_IMM(BPF_SUB, BPF_REG_6, 0x10)
                               : BPF_ALU32_IMM(BPF_ADD, BPF_REG_6, 0x10);
        const int jmerge = n;
        ins[n++] = BPF_JMP_A(0);
        /* path B: a value in the wrap's GAP whose tnum the old state still CONTAINS.
           Both halves matter and the first attempt got the second one wrong. `range_within`
           is not reached unless `tnum_in` passes first, and the old state's tnum here is
           (0x10; 0xffffffe0) — its low five bits are pinned to 0x10. A range like
           [0x100,0x1ff] has tnum (0x100; 0xff), whose low bits are NOT inside that, so the
           states were never equivalent and the prune never happened. 0x110 has low bits
           0x10, so it sits inside the tnum, and it is outside the arc
           [0xFFFFFFF0..U32_MAX] u [0..0x10] — which leaves range_within as the only check
           that can decide, and that is the one the bug got wrong. */
        ins[jsel].off = n - jsel - 1;
        ins[n++] = BPF_MOV32_IMM(BPF_REG_6, 0x110);
        ins[jmerge].off = n - jmerge - 1;

        /* MERGE. Padding so the checkpoint heuristic (>=2 jumps AND >=8 insns) can fire, and
           a store whose bound the merged range has to justify. */
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 0);
        /* A STORE, AND IT IS NOT ABOUT MEMORY SAFETY. Without it the old register stays
           IMPRECISE, and `regsafe`'s first rule is `!rold->precise && exact == NOT_EXACT ->
           true`: the kernel short-circuits and never consults range_within, so the bug
           cannot manifest no matter how the arcs are shaped. That was measured — the pair
           was captured with the wrapping arc against 0x110 and pruned on the short-circuit.
           0050 named the mechanism: a store forces `mark_chain_precision`, which backtracks
           and marks the checkpoint's register precise, so the NEXT comparison at that
           instruction has to do the range work. The mask keeps the access in bounds; the
           precision is what is actually wanted. */
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_6);
        const int store_insn = n;
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_9, 0, -1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

        struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
        struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                                 g_log2, sizeof(g_log2));
        struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                                 g_log2, sizeof(g_log2));
        /* The state dump the subsumption model reads comes from the STATE_FREQ load, because
           the default heuristic may place no checkpoint where the two paths meet. */
        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        attr.prog_flags = BPF_F_TEST_STATE_FREQ;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG wraparc#cd5b460ed1ec#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        printf("STORE insn=%d reg=9 off=0 size=1\n", store_insn);
        printf("PRUNE fall=wraparc taken=%s fall_safe=1 taken_safe=1 stack=0"
               " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
               " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
               " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
               ARMS[a].name,
               base.accept ? "accept" : "reject", base.err, base.states, base.reason,
               freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
               inv.accept ? "accept" : "reject", inv.err, inv.reason);
        if (fd >= 0) close(fd);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
    close(map_out);
}

// ---- calibration probe: the BOTH-BOUNDARY wrapping arc (--probe-wraparc2) --------------
// The INPUT half of pair `cd5b460ed1ec` ("range_within() must check cnum ranges instead of
// min/max pairs", 2026-04-25). 0100 built the oracle side and could not build the shape; it
// ended by naming the trigger's three conditions, and this probe is aimed at all three.
//
// CONDITION (c) WAS THE HARD ONE and 0100 measured why. Its arc crossed only the UT_MAX/0
// boundary, so the s32 projection stayed [-16, 16] and the buggy min/max check correctly
// refused at `16 >= 272`. For every projection to open to the full range — which is what
// blinds min/max — the arc must contain BOTH ST_MAX and ST_MIN as well, i.e. cover more than
// half the space. The commit's own counterexample is cnum32{base=0x7FFFFFF0,size=0x80000020}
// = [0x7FFFFFF0 .. U32_MAX] u [0 .. 0x10], and in BPF arithmetic that is two instructions:
//
//     if w6 > 0x80000020 goto out      -- fallthrough: w6 in [0, 0x80000020], size > 2^31
//     w6 += 0x7FFFFFF0                 -- rotate the base: {0x7FFFFFF0, 0x80000020}
//
// A CONDITIONAL JUMP CANNOT PRODUCE IT. Jumps narrow to contiguous intervals, so "not in
// [a,b]" arrives as two separate states, never as one wrapping arc. The wrap has to come
// from ARITHMETIC, which is why the add is the whole trick and why 0100's `&= 0x20; -= 0x10`
// shape could not reach it: masking first PINS the low bits, and then condition (a) —
// tnum containment — fails before range_within is ever consulted.
//
// CONDITION (a), tnum: the jump leaves w6's low bits unknown, so old's var_off stays wide
// and contains the second path's constant. 0100 lost the pair here.
//
// CONDITION (b), precision: the merged register is narrowed and used as a variable store
// offset, so mark_chain_precision walks back and marks it precise in the checkpoint —
// 0050's mechanism. 0100 saw the prune disappear when it forced precision, but for a reason
// specific to its arc: with only the unsigned boundary crossed the min/max check refused on
// its own. With both boundaries crossed there is nothing left for it to refuse on.
//
// THE ARMS differ in ONE thing: how far the pre-add range reaches.
//   both  -- w6 <= 0x80000020, so the arc spans both boundaries: every projection opens to
//            the full range, min/max is blind, cnum arc containment is not.
//   unsig -- w6 <= 0x20, so the arc {0x7FFFFFF0, 0x20} crosses only UT_MAX/0; the s32
//            projection survives and the buggy check refuses correctly. This is 0100's
//            shape, kept as the control that says the signal comes from the SPANNING and
//            not from wrapping as such.
//
// EXPECTED, on the buggy kernel (cd5b460ed1ec~1, .lab/build/bzImage-instr-cn): old is the
// arc, cur is a constant sitting in the arc's GAP. min/max sees old's projections as the
// full range and prunes; cnum arc containment says the gap value is not in the arc. That
// disagreement is `arm=range_within` and it exercises the cnum branch B1 lived in.
static void run_probe_wraparc2(void) {
    static const struct { const char *name; int lim; } ARMS[] = {
        {"both",  0x80000020},   /* trigger: spans UT_MAX/0 AND ST_MAX/ST_MIN */
        {"unsig", 0x20},         /* control: spans only UT_MAX/0 (0100's shape) */
    };
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) {
        printf("===PROG wraparc2#cd5b460ed1ec type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }

    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[48];
        int n = 0, jout[4], no = 0;

        /* map value pointer first, in a callee-saved register (0087/0092's rule: a helper
           call clobbers r0-r5, so a lookup after the shape is built destroys it). */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jout[no++] = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_0);

        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);          /* the shaped scalar */
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);          /* path selector */

        const int jsel = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);        /* -> path 2 */

        /* PATH 1, explored first, so its state becomes the CHECKPOINT (`old`): build the
           arc. The jump bounds w6 without pinning any bit; the add rotates the base. */
        jout[no++] = n;
        ins[n++] = BPF_JMP32_IMM(BPF_JGT, BPF_REG_6, ARMS[a].lim, 0);
        ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_6, 0x7FFFFFF0);
        const int jmerge = n;
        ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);

        /* PATH 2 (`cur`): a constant that sits in the arc's GAP, [0x11 .. 0x7FFFFFEF]. */
        ins[jsel].off = n - jsel - 1;
        ins[n++] = BPF_MOV32_IMM(BPF_REG_6, 0x100);

        /* MERGE. The checkpoint the two paths meet at is the pair we want printed. */
        ins[jmerge].off = n - jmerge - 1;

        /* CONDITION (b): narrow, then use as a VARIABLE STORE OFFSET so
           mark_chain_precision walks back and marks r6 precise in the checkpoint. The
           narrowing also makes the store itself in-bounds on every path. */
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 0x7);
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_6);
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_9, 0, 0xFF);

        for (int k = 0; k < no; k++)
            ins[jout[k]].off = n - jout[k] - 1;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        /* THE MERGE MUST BE A CHECKPOINT, and by default it is not: the heuristic in
           is_state_visited declines a new state until >=20 jumps or >=100 insns have passed,
           so both paths walk 17 independently and the only prune lands at the exit block on
           r10 alone (measured: 4 pairs, scalar_comparisons=0). TEST_STATE_FREQ forces the
           checkpoint. It makes pruning MORE aggressive, which for the FLAG DIFFERENTIAL is a
           direction problem (OI-15) — but here the flag is not the detector: it only creates
           the opportunity to ask, and the decision the model audits is range_within's own. */
        attr.prog_flags = BPF_F_TEST_STATE_FREQ;
        g_log[0] = 0;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG wraparc2#cd5b460ed1ec#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        if (fd >= 0) close(fd);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
    close(map_out);
}

// ---- calibration probe: the jmp32 pruning decision (--probe-jmp32prune) ----------------
// Calibration pair FOURTEEN (fd675184fc7a, "bpf: Fix verifier jmp32 pruning decision logic",
// 2021-02-05) — the SECOND positive control for the subsumption model, and the first one
// that lands on `range_within` rather than `check_scalar_ids`.
//
// WHY THIS PAIR. The 0101 fan-out screened 40 historical state-quoting verifier fixes under
// the predicate/state typology and found exactly ONE the model can see. This is it: the
// entire fix is four comparisons ADDED to range_within —
//
//     +	       old->u32_min_value <= cur->u32_min_value &&
//     +	       old->u32_max_value >= cur->u32_max_value &&
//     +	       old->s32_min_value <= cur->s32_min_value &&
//     +	       old->s32_max_value >= cur->s32_max_value;
//
// so the buggy kernel judges a jmp32-narrowed pair on 64-bit bounds alone. The fields are
// written correctly; only the decision taken from them is wrong. That is the whole reason
// the model reaches it: our range_within_minmax implements all eight.
//
// THE PROGRAM IS THE COMMIT'S OWN, transcribed from its bpftool dump. The commit even
// quotes the disagreeing pair's bounds, so the expected signal is known in advance:
//
//     old: s32_min=0x80000000 s32_max=0x00003030  u32_min=0x0        u32_max=0xffffffff
//     cur: s32_min=0x00003031 s32_max=0x7fffffff  u32_min=0x00003031 u32_max=0x7fffffff
//
// old.s32_max (12336) >= cur.s32_max (2147483647) is FALSE, so the eight-comparison form
// refuses; the four-comparison form sees only the 64-bit bounds, which agree, and prunes.
//
// THE ARMS DIFFER IN ONE THING: whether the two narrowing jumps are jmp32 or jmp64. A
// 64-bit jump narrows the 64-bit bounds, which the buggy range_within DOES compare — so the
// control must behave identically on both kernels, and the model must stay silent on it.
//
// The runtime consequence upstream reported is a HANG (the unwalked branch is dead-code
// rewritten to `goto pc-1`), which is why this probe does not run the program: the detector
// here is the model on the PRUNEPAIR capture, not execution. See the f54c7898ed1c channel
// verification for why a hang is not observable by any oracle this project has.
static void run_probe_jmp32prune(void) {
    static const struct { const char *name; int use32; } ARMS[] = {
        {"jmp32", 1},   /* trigger: narrowing lands ONLY on the 32-bit bounds */
        {"jmp64", 0},   /* control: narrowing lands on the 64-bit bounds too   */
    };

    for (unsigned a = 0; a < sizeof(ARMS) / sizeof(ARMS[0]); a++) {
        struct bpf_insn ins[16];
        int n = 0;
        const int u32 = ARMS[a].use32;

        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 808464450);
        ins[n++] = BPF_MOV32_IMM(BPF_REG_4, 808464432);
        ins[n++] = BPF_ALU32_REG(BPF_MOD, BPF_REG_4, BPF_REG_0);
        ins[n++] = BPF_JMP32_IMM(BPF_JSGT, BPF_REG_4, 0x30303030, 0);
        ins[n++] = BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_0);
        ins[n++] = BPF_ALU32_REG(BPF_MOD, BPF_REG_4, BPF_REG_0);
        /* THE ARM. insn 6 creates the checkpoint state, insn 7 is where the prune lands. */
        ins[n++] = u32 ? BPF_JMP32_IMM(BPF_JSGT, BPF_REG_0, 0x3030, 0)
                       : BPF_JMP_IMM(BPF_JSGT, BPF_REG_0, 0x3030, 0);
        ins[n++] = u32 ? BPF_JMP32_IMM(BPF_JSLE, BPF_REG_0, 0x303030, 1)
                       : BPF_JMP_IMM(BPF_JSLE, BPF_REG_0, 0x303030, 1);
        ins[n++] = BPF_MOV32_IMM(BPF_REG_4, 0);   /* the arm the buggy kernel never walks */
        ins[n++] = BPF_EXIT_INSN();

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 2;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        /* NO prog_flags: BPF_F_TEST_REG_INVARIANTS does not exist in 2021, and the commit's
           own trace prunes under DEFAULT checkpointing — adding TEST_STATE_FREQ would change
           the very decision under test. */
        g_log[0] = 0;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int lerr = errno;

        printf("===PROG jmp32prune#fd675184fc7a#%s type=socket_filter ===\n", ARMS[a].name);
        printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
               fd >= 0 ? "accept" : "reject", fd >= 0 ? 1 : -1, fd >= 0 ? 0 : lerr);
        if (fd >= 0) close(fd);
        printf("---LOG---\n%s\n---END---\n", g_log);
    }
}

// ---- calibration probe: the fake_reg corruption (--probe-fakereg) -----------
// The SECOND kind of calibration. 0061 tested the oracle against a bug whose inconsistent
// state the commit message printed, so no kernel had to be built. This one cannot work
// that way: the violating registers (`true_reg2`, `false_reg2`) are internal to
// reg_set_min_max and are never printed as ordinary register state — they appear only
// inside the kernel's own "REG INVARIANTS VIOLATION" message. Our detection channel is
// therefore not the parsed state but the VERDICT: 0042's third load, where
// BPF_F_TEST_REG_INVARIANTS turns reg_bounds_sanity_check from warn-and-recover into a
// hard -EFAULT. Testing that requires running the kernel that HAD the bug.
//
// THE BUG. Commit 92424801261d, "bpf: Fix reg_set_min_max corruption of fake_reg"
// (2024-06-13), reported by Juan via a coverage-guided buzzer run. Comparing a register
// against a CONSTANT makes the verifier build a "fake" register holding that constant and
// hand it to reg_set_min_max(). regs_refine_cond_op() then intersects the two var_offs
// and writes the result back into BOTH registers — including the fake one, which was
// meant to stay constant. The kernel's own checker reports it as
//   REG INVARIANTS VIOLATION (true_reg2):  range bounds violation u64=[0x7fffffff, 0x7ffffffd]
//   REG INVARIANTS VIOLATION (false_reg2): const tnum out of sync with range bounds
// — an inverted unsigned range and a constant tnum that does not pin its bounds, which
// are our `unsigned_bounds_inverted` and `const_tnum_range_mismatch` under other names.
//
// THE TRIGGER, transcribed from the commit's own disassembly: mask an unknown scalar down
// to 31 bits, set bit 1, then compare for equality against a constant whose bit 1 is
// CLEAR. The false branch is mathematically unreachable — 0x7ffffffd is 1111...1101 — but
// the verifier analyses it anyway, and that analysis is what corrupts the fake register.
//
// Expected: on the buggy kernel the default load succeeds while the REG_INVARIANTS load
// returns -EFAULT, which is exactly what `check_prune_differential` reports as
// reg_invariants_violation. On the fixed kernel all three loads agree and it stays silent.
static void run_probe_fakereg(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0) {
        printf("===PROG fakereg type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }

    struct bpf_insn ins[32];
    int n = 0, jexit;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0);   /* unknown scalar   */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_MOV32_IMM(BPF_REG_0, -1);
    ins[n++] = BPF_ALU32_IMM(BPF_RSH, BPF_REG_0, 1);           /* r0 = 0x7fffffff  */
    ins[n++] = BPF_ALU32_REG(BPF_AND, BPF_REG_6, BPF_REG_0);   /* r6 in [0,2^31)   */
    ins[n++] = BPF_ALU32_IMM(BPF_OR, BPF_REG_6, 2);            /* bit 1 set        */
    /* The false branch of this compare is unreachable, and analysing it is the bug. */
    ins[n++] = BPF_JMP32_IMM(BPF_JNE, BPF_REG_6, 0x7ffffffd, 1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jexit].off = exit0 - jexit - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd >= 0) close(fd);

    printf("===PROG fakereg#92424801261d#000 type=socket_filter ===\n");
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           base.accept ? "accept" : "reject", base.accept ? 1 : -1, base.err);
    printf("PRUNE fall=fakereg taken=c0 fall_safe=1 taken_safe=1 stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    /* The kernel's own verdict, quoted so a capture is self-explaining. */
    printf("CHANNEL reg_invariants_violation_in_log=%d\n",
           strstr(g_log, "REG INVARIANTS VIOLATION") != NULL);
    printf("---LOG---\n%s\n---END---\n", g_log);
    close(map_in);
}

// ---- composition generator (--gen-comp) -------------------------------------
// THE SECOND HALF OF THE FOURTH PIVOT. Switching surface (0053) addressed one axis:
// mature code versus fresh. It did NOT address the other: every family so far, this one's
// predecessors included, produces shapes whose bug class I can NAME. "Clean" has therefore
// only ever meant "clean on the shapes I thought to write". This generator composes the
// pieces built across 0043-0053 at random, with the oracles held fixed, so that "clean"
// starts to say something about shapes nobody named.
//
// THE HARD PART IS NOT THE ORACLE, IT IS VALIDITY. A randomly concatenated program is
// almost always rejected, and a rejected program never reaches the runtime oracles — a
// denominator-zero trap one layer up from the ones 0041-0050 kept finding. The fix is to
// stop treating a program as a byte string and treat it as a walk over a typed CONTEXT:
// every piece declares what it REQUIRES of the live state and what it PROVIDES, and the
// generator only ever picks a piece whose requirements currently hold.
//
// The context has to carry more than register types, and dynptr is the reason: its
// interface is the richest of the pieces. It consumes a 16-byte STACK_DYNPTR slot pair
// that the verifier tracks by id, and it yields a PTR_TO_MEM whose size is a constant the
// caller chose — plus, for the observation channel, an OFFSET into the map value that the
// slice's base corresponds to. That last field is 0053's coordinate translation
// generalised: the store's declared offset is always expressed in the coordinates the
// sentinel readback uses.
//
// Determinism is not optional: a finding has to be replayable, so the walk is driven by a
// seeded xorshift and the seed is printed with every program.
#define COMP_VALUE 64
/* The constant a delta-link adds. Named because CP_RELINK has to subtract it back out
   when it converts a bound on the offset member into a bound on the class base. */
#define COMP_LINK_DELTA 4
/* The longest recipe the walk emits. It also sizes the jump-patch table below, so the two
   cannot drift apart. */
#define COMP_MAXSTEPS 8
/* The corpus has to grow with the pool: the achievable adjacent-triple space grows as
   N^3 (679 at nine pieces, 916 at ten), so a fixed program count means coverage falls off
   with every addition even though the absolute number of realised triples rises. */
#define COMP_MAXPROG 896

struct comp_ctx {
    uint32_t rng;
    int scalar_regs;      /* bitmask over r6..r9 holding non-constant scalars   */
    int mapval_reg;       /* register holding the map_value pointer, or -1      */
    int mem_reg;          /* register holding a dynptr slice (PTR_TO_MEM), or -1*/
    int mem_size;         /* the slice's proven size (the caller's constant)    */
    int store_base_off;   /* where the store pointer's base sits in map_out     */
    int stack_next;       /* next free stack offset, growing down               */
    int narrowed_max;     /* the tightest umax proven on a scalar so far, or -1 */
    int narrow_reg;       /* which register that bound belongs to               */
    int ctx_slot;         /* where the skb context pointer was spilled          */
    int iter_slot;        /* the iterator's 8-byte slot, or 0 if unused         */
    int used_iter;        /* an iterator is emitted at most once per program    */
    int call_site;        /* index of the call insn awaiting its target, or -1  */
    int used_dynskb;      /* one skb dynptr per program keeps slot use simple   */
    int used_ringbuf;     /* likewise for the ringbuf reservation                */
    int used_skref;       /* and for the socket reference                        */
};

static uint32_t comp_rand(struct comp_ctx *c) {
    c->rng ^= c->rng << 13; c->rng ^= c->rng >> 17; c->rng ^= c->rng << 5;
    return c->rng;
}
static int comp_pick(struct comp_ctx *c, int n) { return (int)(comp_rand(c) % (unsigned)n); }

enum comp_piece {
    CP_SHAPE,    /* ALU on a live scalar                                        */
    CP_LINK,     /* rB = rA (optionally + const): a shared-id class             */
    CP_NARROW,   /* branch that proves an upper bound on a scalar               */
    CP_SPILL,    /* spill a scalar to the stack and reload it                   */
    CP_LOOP,     /* a complete bounded may_goto loop with a shaping body        */
    CP_DYNPTR,   /* build a dynptr over the map value and take a writable slice */
    CP_ALU32,    /* 32-bit ALU: the only piece that lifts reg32 off zero        */
    CP_ITER,     /* an open-coded iterator loop — a different back-edge kind    */
    CP_PKT,      /* packet pointer with a program-proven range, then a LOAD     */
    CP_CALL,     /* a subprogram call — the only piece that opens a second FRAME  */
    CP_DYNSKB,   /* an SKB dynptr and a READ-ONLY slice of it                     */
    CP_RINGBUF,  /* reserve/submit a ringbuf dynptr — REFERENCE tracking          */
    CP_SKREF,    /* socket lookup/release — a REFCOUNTED POINTER with a ref_obj_id */
    CP_RELINK,   /* re-link from the BASE of an already-synced delta class          */
    CP_PIECE_N
};

static const char *comp_piece_name(enum comp_piece p) {
    switch (p) {
    case CP_SHAPE:  return "shape";
    case CP_LINK:   return "link";
    case CP_NARROW: return "narrow";
    case CP_SPILL:  return "spill";
    case CP_LOOP:   return "loop";
    case CP_DYNPTR: return "dynptr";
    case CP_ALU32:  return "alu32";
    case CP_ITER:   return "iter";
    case CP_PKT:    return "pkt";
    case CP_CALL:   return "call";
    case CP_DYNSKB: return "dynskb";
    case CP_RINGBUF: return "ringbuf";
    case CP_SKREF: return "skref";
    case CP_RELINK: return "relink";
    default:        return "?";
    }
}

/* COVERAGE DIRECTION. A uniform walk saturates the PAIR space quickly — the first
   192-program corpus realised every achievable adjacent pair — but reached only 35% of the
   achievable adjacent TRIPLES (235 of 679). Since the bug classes this project is aimed at
   live in the interaction of two or more features, the frontier is the triple, not the
   piece. These tables are corpus-wide, so selection can prefer a piece that completes a
   combination nothing has produced yet; ties fall back to the seeded RNG, which keeps the
   whole corpus reproducible. */
/* Read off the kernel's own helper mapper (include/uapi/linux/bpf.h):
   FN(ringbuf_reserve_dynptr, 198), FN(ringbuf_submit_dynptr, 199). Verified, not guessed —
   a wrong helper id loads fine and calls a different function. */
/* FN(sk_lookup_tcp, 84) and FN(sk_release, 86) in the kernel's helper mapper; both are
   exposed by tc_cls_act_func_proto, so SCHED_CLS can reach them. */
#ifndef BPF_FUNC_sk_lookup_tcp
#define BPF_FUNC_sk_lookup_tcp 84
#endif
#ifndef BPF_FUNC_sk_release
#define BPF_FUNC_sk_release 86
#endif
#ifndef BPF_FUNC_ringbuf_reserve_dynptr
#define BPF_FUNC_ringbuf_reserve_dynptr 198
#endif
#ifndef BPF_FUNC_ringbuf_submit_dynptr
#define BPF_FUNC_ringbuf_submit_dynptr 199
#endif

static int g_from_skb_id, g_slice_ro_id, g_ringbuf_fd;

static unsigned char g_seen_pair[CP_PIECE_N][CP_PIECE_N];
static unsigned char g_seen_triple[CP_PIECE_N][CP_PIECE_N][CP_PIECE_N];

/* Can this piece run in the current context? This predicate IS the validity story: a
   piece that is emitted without its requirements produces a program the verifier throws
   away, and a thrown-away program teaches the oracles nothing. */
static int comp_can(const struct comp_ctx *c, enum comp_piece p) {
    switch (p) {
    case CP_SHAPE:  return c->scalar_regs != 0;
    case CP_LINK:   return __builtin_popcount(c->scalar_regs) >= 2;
    case CP_NARROW: return c->scalar_regs != 0;
    case CP_SPILL:  return c->scalar_regs != 0 && c->stack_next > -200;
    case CP_LOOP:   return c->scalar_regs != 0;
    /* dynptr needs the map value, a free 16-byte slot pair, and it is emitted at most
       once because a second slice would overwrite the first's coordinate mapping. */
    case CP_DYNPTR: return c->mapval_reg >= 0 && c->mem_reg < 0 && c->stack_next > -160;
    case CP_ALU32:  return c->scalar_regs != 0;
    /* One iterator per program: a second would reuse the slot the first is still
       tracked in, and the verifier follows that slot by id. */
    case CP_ITER:   return c->scalar_regs != 0 && !c->used_iter;
    /* The packet piece needs a free scalar register to land the loaded byte in, and the
       context pointer, which the prologue spilled because r1 is clobbered by every
       helper call before it. */
    case CP_PKT:    return c->scalar_regs != 0;
    /* One subprogram per program: the callee is appended after the main body and its call
       patched afterwards, so a second would need a second patch site. */
    case CP_CALL:   return c->scalar_regs != 0 && c->call_site < 0;
    case CP_DYNSKB: return c->scalar_regs != 0 && !c->used_dynskb && c->stack_next > -300;
    case CP_RINGBUF: return c->scalar_regs != 0 && !c->used_ringbuf && c->stack_next > -380;
    case CP_SKREF:  return c->scalar_regs != 0 && !c->used_skref && c->stack_next > -420;
    /* Needs three live scalars: the class BASE, the member that carries the delta, and a
       third register to re-link from the base. It is self-contained — it builds the whole
       shape itself rather than depending on which register an earlier narrow happened to
       pick — so it can repeat, and it touches no stack slot or reference. */
    case CP_RELINK: return __builtin_popcount(c->scalar_regs) >= 3;
    default:        return 0;
    }
}

static int comp_scalar_reg(struct comp_ctx *c) {
    int cands[4], n = 0;
    for (int r = 6; r <= 9; r++)
        if (c->scalar_regs & (1 << r)) cands[n++] = r;
    return cands[comp_pick(c, n)];
}

static int comp_emit(struct bpf_insn *ins, int n, struct comp_ctx *c, enum comp_piece p,
                     const struct iter_ids *ids, int slice_id, int map_out, int *jexit,
                     int *nx) {
    switch (p) {
    case CP_RELINK: {
        /* THE SHAPE CALIBRATION PAIR FIVE NAMED (af9e89d8dd39, devlog 0068). A delta-link
           is built and then SYNCED by a branch on its offset member; the sync is where the
           buggy kernel stamped the base with ADD_CONST. A SECOND link taken from the base
           then hits assign_scalar_id_before_mov's ADD_CONST branch, which clears the base's
           id and mints a fresh one — silently dropping it out of the class. A later, tighter
           branch on the offset member therefore never reaches the base.

           The piece emits the whole sequence rather than relying on the walk to place a
           narrow on the right register: which register CP_NARROW picks is random, so as
           separate pieces the shape would almost never assemble.

           It is DECISION-RELEVANT by construction. The store offset is computed from the
           SECOND (tighter) bound, which the base only carries if its link survived the
           re-link. On a kernel with the bug the base keeps the first, looser bound and the
           store is rejected as out of range — so this shape reaches the oracle through the
           ordinary verdict, without needing a new channel. */
        int base = comp_scalar_reg(c), off_reg, dst;
        do { off_reg = comp_scalar_reg(c); } while (off_reg == base);
        do { dst = comp_scalar_reg(c); } while (dst == base || dst == off_reg);

        const int k1 = 8 + comp_pick(c, 8);          /* first, looser bound on base   */
        const int k2 = 1 + comp_pick(c, k1 - 1);     /* second, strictly tighter one  */

        ins[n++] = BPF_MOV64_REG(off_reg, base);     /* link: both take one id        */
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, off_reg, COMP_LINK_DELTA);

        /* off_reg <= k1 + DELTA proves base <= k1 through the class — and this is the
           sync that corrupts the base's id on a buggy kernel. */
        jexit[(*nx)++] = n;
        ins[n++] = BPF_JMP_IMM(BPF_JGT, off_reg, k1 + COMP_LINK_DELTA, 0);

        ins[n++] = BPF_MOV64_REG(dst, base);         /* THE second link               */

        /* And the tighter one, which only reaches the base if the class survived. */
        jexit[(*nx)++] = n;
        ins[n++] = BPF_JMP_IMM(BPF_JGT, off_reg, k2 + COMP_LINK_DELTA, 0);

        c->narrowed_max = k2;
        c->narrow_reg = base;
        break;
    }
    case CP_SHAPE: {
        int r = comp_scalar_reg(c);
        static const int ops[] = { BPF_AND, BPF_OR, BPF_XOR, BPF_LSH, BPF_RSH, BPF_ADD };
        int op = ops[comp_pick(c, 6)];
        int imm = (op == BPF_LSH || op == BPF_RSH) ? 1 + comp_pick(c, 3)
                                                   : 1 + comp_pick(c, 15);
        ins[n++] = BPF_ALU64_IMM(op, r, imm);
        c->narrowed_max = -1;               /* any shaping invalidates a proven bound */
        break;
    }
    case CP_LINK: {
        int a = comp_scalar_reg(c), b;
        do { b = comp_scalar_reg(c); } while (b == a);
        ins[n++] = BPF_MOV64_REG(b, a);
        if (comp_pick(c, 2)) ins[n++] = BPF_ALU64_IMM(BPF_ADD, b, COMP_LINK_DELTA);
        c->narrowed_max = -1;
        break;
    }
    case CP_NARROW: {
        int r = comp_scalar_reg(c);
        int bound = 1 + comp_pick(c, 15);
        jexit[(*nx)++] = n;
        ins[n++] = BPF_JMP_IMM(BPF_JGT, r, bound, 0);
        c->narrowed_max = bound;
        c->narrow_reg = r;
        break;
    }
    case CP_SPILL: {
        int r = comp_scalar_reg(c);
        c->stack_next -= 8;
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, r, c->stack_next);
        ins[n++] = BPF_LDX_MEM(BPF_DW, r, BPF_REG_10, c->stack_next);
        break;
    }
    case CP_LOOP: {
        /* Every register the body touches must be live BEFORE the head: may_goto can
           break out on entry and the zero-iteration path would otherwise read an
           uninitialised register (0051 learned this the hard way). The body only shapes
           a register that is already a live scalar, so that holds by construction. */
        int r = comp_scalar_reg(c);
        const int head = n;
        const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, r, 7);
        const int jback = n;
        ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, head - jback - 1);
        n++;
        ins[jbreak].off = n - jbreak - 1;
        c->narrowed_max = -1;
        break;
    }
    case CP_DYNPTR: {
        int off = 8 * comp_pick(c, 3);          /* 0, 8 or 16 */
        int szk = 8;
        c->stack_next -= 16;
        int slot = c->stack_next;
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, c->mapval_reg);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 32);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, slot);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_dynptr_from_mem);
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, slot);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, off);
        ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
        c->stack_next -= 64;
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, c->stack_next);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_4, szk);
        ins[n++] = BPF_KFUNC_CALL(slice_id);
        jexit[(*nx)++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
        c->scalar_regs &= ~(1 << 8);            /* r8 now holds a pointer, not a scalar */
        c->mem_reg = BPF_REG_8;
        c->mem_size = szk;
        c->store_base_off = off;                /* the coordinate translation, generalised */
        break;
    }
    case CP_ALU32: {
        /* The 32-bit path is its own transfer function: alu32 zero-extends where alu64
           does not, which is why the verifier keeps BPF_ADD_CONST32 and ADD_CONST64 as
           distinct link flags. It is also the only piece that lifts reg32_checked off
           zero, so the corpus otherwise never exercises the sub-register view. */
        int r = comp_scalar_reg(c);
        static const int ops32[] = { BPF_AND, BPF_OR, BPF_ADD, BPF_LSH };
        ins[n++] = BPF_ALU32_IMM(ops32[comp_pick(c, 4)], r, 1 + comp_pick(c, 15));
        c->narrowed_max = -1;
        break;
    }
    case CP_ITER: {
        int r = comp_scalar_reg(c);
        (void)r;
        n = emit_iter_loop(ins, n, ids, 0, 4, LB_MASK);
        c->used_iter = 1;
        c->narrowed_max = -1;
        break;
    }
    case CP_SKREF: {
        /* A REFCOUNTED POINTER. The ringbuf piece brought reference tracking in through a
           dynptr; this brings it through a POINTER — bpf_sk_lookup_tcp returns
           PTR_TO_SOCKET_OR_NULL carrying a ref_obj_id that bpf_sk_release consumes. That
           id is not decoration: `regsafe`/`stacksafe` run it through check_ids, so this
           piece puts a refcounted pointer into the same id-mapping machinery 0046 and
           0047 probed with plain scalars.
           The reference never crosses into another piece: acquire, read, release, and the
           null path skips both — a NULL carries no reference, so skipping the release
           there is correct rather than a leak. */
        int r = comp_scalar_reg(c);
        c->stack_next -= 16;
        int tup = c->stack_next;                 /* struct bpf_sock_tuple ipv4 = 12 B */
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, tup + 0, 0);
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, tup + 4, 0);
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, tup + 8, 0);
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, c->ctx_slot);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, tup);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 12);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_4, -1);  /* BPF_F_CURRENT_NETNS */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_5, 0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_sk_lookup_tcp);
        const int jnull = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, r, BPF_REG_0, 0);   /* bpf_sock->family */
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_sk_release);
        ins[jnull].off = n - jnull - 1;
        c->used_skref = 1;
        c->narrowed_max = -1;
        break;
    }
    case CP_RINGBUF: {
        /* A CORRECTNESS PROPERTY THE POOL DID NOT HAVE. Everything else here is about
           bounds; a ringbuf reservation is about REFERENCES — the verifier must prove the
           reservation is released on EVERY path, or the program leaks it and is rejected.
           A third dynptr type (RINGBUF) and a new map type come along with it.
           The null branch of the slice jumps to the SUBMIT, not to the program's exit:
           routing it to the exit would leave the reservation live on that path and the
           verifier would reject every program containing this piece, which is a leak the
           generator would be creating rather than a property it is testing. */
        int r = comp_scalar_reg(c);
        c->stack_next -= 16;
        int slot = c->stack_next;
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = g_ringbuf_fd};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 16);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, slot);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_ringbuf_reserve_dynptr);

        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, slot);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
        c->stack_next -= 32;
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, c->stack_next);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_4, 8);
        ins[n++] = BPF_KFUNC_CALL(g_slice_ro_id);
        const int jnull = n;
        ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_B, r, BPF_REG_0, comp_pick(c, 8));
        ins[jnull].off = n - jnull - 1;          /* -> the submit, never the exit */

        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, slot);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_ringbuf_submit_dynptr);
        c->used_ringbuf = 1;
        c->narrowed_max = -1;
        break;
    }
    case CP_DYNSKB: {
        /* A SECOND dynptr TYPE. The LOCAL dynptr of 0053 is built over a map value; this
           one is built over the skb, so the slice carries a different type flag
           (get_dynptr_type_flag) and goes down the skb path, where the data may be
           non-linear and the slice can legitimately copy into the caller's buffer instead
           of pointing into the packet.
           The READ-ONLY variant is deliberate twice over: it exercises the MEM_RDONLY
           flag the rdwr variant never sets, and it cannot write into the packet — a write
           there would move the observation channel off the map value and break the
           coordinate mapping the whole corpus shares, the same reason CP_PKT is a load. */
        int r = comp_scalar_reg(c);
        c->stack_next -= 16;
        int slot = c->stack_next;
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, c->ctx_slot);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, slot);
        ins[n++] = BPF_KFUNC_CALL(g_from_skb_id);
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, slot);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
        c->stack_next -= 32;
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, c->stack_next);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_4, 8);
        ins[n++] = BPF_KFUNC_CALL(g_slice_ro_id);
        jexit[(*nx)++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_B, r, BPF_REG_0, comp_pick(c, 8));
        c->used_dynskb = 1;
        c->narrowed_max = -1;
        break;
    }
    case CP_CALL: {
        /* The only piece that opens a second FRAME. states_equal compares each frame in
           turn, and 0048 measured that a scalar's link id survives into the callee's
           argument registers — so this piece puts whatever id structure the earlier
           pieces built across a frame boundary. Only r1-r5 cross; r6-r9 are callee-saved
           and the callee below touches neither. */
        int r = comp_scalar_reg(c);
        ins[n++] = BPF_MOV64_REG(BPF_REG_1, r);
        c->call_site = n;
        ins[n++] = (struct bpf_insn){.code = BPF_JMP | BPF_CALL, .dst_reg = 0,
                                     .src_reg = BPF_PSEUDO_CALL, .off = 0, .imm = 0};
        ins[n++] = BPF_MOV64_REG(r, BPF_REG_0);   /* the callee's bounded return value */
        c->narrowed_max = 15;                     /* proven INSIDE the callee's frame   */
        c->narrow_reg = r;
        break;
    }
    case CP_PKT: {
        /* A LOAD, deliberately, not a store: a packet store would move the observation
           channel from the map value to the packet and break the coordinate mapping the
           whole corpus shares. A load still brings PTR_TO_PACKET and the range the
           program proves for itself (find_good_pkt_pointers) into the composition, and
           hands back a fresh scalar. */
        int r = comp_scalar_reg(c);
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_10, c->ctx_slot);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* skb->data     */
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* skb->data_end */
        ins[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 8);
        jexit[(*nx)++] = n;
        ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 0);  /* proves 8 bytes */
        ins[n++] = BPF_LDX_MEM(BPF_B, r, BPF_REG_2, comp_pick(c, 8));
        c->narrowed_max = -1;
        break;
    }
    default: break;
    }
    (void)ids; (void)map_out;
    return n;
}

static void run_comp_prog(const struct iter_ids *ids, int slice_id, uint32_t seed,
                          int idx, int map_in, int map_out) {
    struct bpf_insn ins[160];
    /* SIZING, and it is not slack: every piece that can branch to the common exit parks
       its jump here for patching. CP_NARROW parks one, the null checks of dynptr/dynskb/
       ringbuf/skref one each, and CP_RELINK parks TWO — so the bound is the recipe's
       maximum length times the worst piece, plus the map-lookup null check and the
       epilogue's optional re-narrow. `jexit[16]` held while every piece parked at most
       one; adding a two-jump piece put an 8-step recipe over the edge, which would have
       written past the array with no diagnostic at all. */
    int n = 0, jexit[2 * COMP_MAXSTEPS + 4], nx = 0;
    struct comp_ctx c;
    memset(&c, 0, sizeof(c));
    c.rng = seed ? seed : 1;
    c.mapval_reg = -1; c.mem_reg = -1; c.narrowed_max = -1; c.narrow_reg = -1;
    /* Fixed slots first, then the bump allocator: fp-4 key, fp-16 the spilled context,
       fp-24 the iterator. r1 holds the context only at entry and every helper call
       clobbers it, so it has to be saved before anything else runs. */
    c.ctx_slot = -16;
    c.iter_slot = -24;
    c.stack_next = -32;
    c.call_site = -1;
    c.used_dynskb = 0;
    c.used_ringbuf = 0;
    c.used_skref = 0;
    ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, c.ctx_slot);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    /* r9 is loaded 64 bits wide ON PURPOSE. A 32-bit load zero-extends, so the sub-
       register view coincides with the 64-bit one and there is nothing for the 32/64
       consistency check to evaluate -- which is why the first widened corpus scored
       reg32_checked = 0 even though alu32 was its most-used piece. An upper-unknown
       operand is what gives alu32 a distinct 32-bit view to constrain. */
    ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_0, 8);
    c.scalar_regs = (1 << 6) | (1 << 7) | (1 << 9);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
    c.mapval_reg = BPF_REG_8;

    /* The walk. Only pieces whose requirements hold are ever offered. */
    /* Recipes start at three: a two-piece recipe contributes no triple at all, and in the
       first corpus a quarter of the programs were that short. */
    char recipe[160]; recipe[0] = '\0';
    int steps = 3 + comp_pick(&c, COMP_MAXSTEPS - 2);
    int prev = -1, prev2 = -1;
    for (int i = 0; i < steps && n < 130; i++) {
        enum comp_piece avail[CP_PIECE_N]; int na = 0;
        for (int p = 0; p < CP_PIECE_N; p++)
            if (comp_can(&c, (enum comp_piece)p)) avail[na++] = (enum comp_piece)p;
        if (!na) break;

        /* Prefer, in order: a piece completing an unseen TRIPLE, then one completing an
           unseen PAIR, then anything. The classes are collected first and chosen from
           with the seeded RNG, so the direction never costs reproducibility. */
        enum comp_piece best[CP_PIECE_N]; int nb = 0;
        if (prev2 >= 0 && prev >= 0)
            for (int j = 0; j < na; j++)
                if (!g_seen_triple[prev2][prev][avail[j]]) best[nb++] = avail[j];
        if (!nb && prev >= 0)
            for (int j = 0; j < na; j++)
                if (!g_seen_pair[prev][avail[j]]) best[nb++] = avail[j];
        if (!nb)
            for (int j = 0; j < na; j++) best[nb++] = avail[j];

        enum comp_piece p = best[comp_pick(&c, nb)];
        if (prev >= 0) g_seen_pair[prev][p] = 1;
        if (prev2 >= 0 && prev >= 0) g_seen_triple[prev2][prev][p] = 1;
        prev2 = prev; prev = p;

        n = comp_emit(ins, n, &c, p, ids, slice_id, map_out, jexit, &nx);
        strncat(recipe, comp_piece_name(p), sizeof(recipe) - strlen(recipe) - 2);
        strncat(recipe, ",", sizeof(recipe) - strlen(recipe) - 2);
    }

    /* Epilogue: one store whose safety is decidable from the context, expressed in the
       observation channel's coordinates. Through a slice the base sits at the slice's
       offset in the map value; otherwise at 0. */
    int store_reg, store_off, base_off;
    if (c.mem_reg >= 0) {
        store_reg = c.mem_reg;
        store_off = comp_pick(&c, c.mem_size);       /* inside the proven slice */
        base_off = c.store_base_off;
    } else {
        int r = comp_scalar_reg(&c);
        /* YIELD. Most pieces invalidate whatever bound was proven, so without this the
           corpus mostly ends in "R<n> unbounded memory access" and the runtime oracles
           go hungry -- a rejected program observes nothing. Re-proving a bound here turns
           those into programs that actually reach the oracle. It is done only three times
           in four, because a rejection is a legitimate verdict and a corpus with no
           reject side would stop exercising the decision surface at all. */
        if (c.narrowed_max < 0 && comp_pick(&c, 4) != 0) {
            int bound = 1 + comp_pick(&c, 15);
            jexit[nx++] = n;
            ins[n++] = BPF_JMP_IMM(BPF_JGT, r, bound, 0);
            c.narrowed_max = bound;
            c.narrow_reg = r;
        }
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_8, r);
        store_reg = BPF_REG_8;
        /* Safe only if a bound is currently proven on that very register; otherwise the
           program is expected to be rejected, which is a legitimate outcome. */
        store_off = (c.narrowed_max >= 0 && c.narrow_reg == r)
                        ? COMP_VALUE - 1 - c.narrowed_max : 0;
        base_off = 0;
    }
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, store_reg, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* The callee goes after the main body's last exit, and its call is patched now that
       the address is known. It narrows its argument and returns it, so the bound the
       caller then relies on exists only because of what happened inside a DIFFERENT
       frame — which is the whole reason this piece is in the pool. */
    if (c.call_site >= 0) {
        const int sub = n;
        ins[c.call_site].imm = sub - c.call_site - 1;
        const int jhigh = n;
        ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_1, 15, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_1);
        ins[n++] = BPF_EXIT_INSN();
        ins[jhigh].off = n - jhigh - 1;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
    }

    const int PT = BPF_PROG_TYPE_SCHED_CLS;
    struct prune_load base = prune_load_typed(ins, n, 0, g_log, sizeof(g_log), PT);
    struct prune_load freq = prune_load_typed(ins, n, BPF_F_TEST_STATE_FREQ,
                                              g_log2, sizeof(g_log2), PT);
    struct prune_load inv  = prune_load_typed(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                              g_log2, sizeof(g_log2), PT);

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = PT;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "gencomp#s%08x#%03d", seed, idx);
    printf("===PROG %s type=sched_cls ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=%d off=%d size=1\n", store_insn, store_reg,
           base_off + store_off);
    printf("COMP seed=0x%08x insns=%d recipe=%s slice=%d base_off=%d\n",
           seed, n, recipe[0] ? recipe : "-", c.mem_reg >= 0, base_off);
    printf("PRUNE fall=comp taken=s%d fall_safe=1 taken_safe=1 stack=1"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n", idx,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4); memcpy(val + 4, &in, 4); memcpy(val + 8, &in, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int soff = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { soff = b; break; }
            int executed = (t.test.retval == 1);
            if (soff < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = soff; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, soff, len, executed);
            }
        }
        close(fd);
    }
    bpflive_print_claim(ins, n);
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_comp_family(void) {
    struct iter_ids ids;
    iter_resolve(&ids);
    int slice_id = btf_find_func_id("bpf_dynptr_slice_rdwr");
    g_slice_ro_id = btf_find_func_id("bpf_dynptr_slice");
    g_from_skb_id = btf_find_func_id("bpf_dynptr_from_skb");
    if (slice_id <= 0 || g_slice_ro_id <= 0 || g_from_skb_id <= 0) {
        printf("===PROG gencomp type=sched_cls ===\n"
               "RESULT decision=error btf_resolve_failed rdwr=%d ro=%d skb=%d\n"
               "---LOG---\n---END---\n", slice_id, g_slice_ro_id, g_from_skb_id);
        return;
    }
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = COMP_VALUE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_RINGBUF;
    m.key_size = 0; m.value_size = 0; m.max_entries = 1 << 12;   /* page-aligned pow2 */
    g_ringbuf_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0 || g_ringbuf_fd < 0) {
        printf("===PROG gencomp type=sched_cls ===\n"
               "RESULT decision=error map_create_failed in=%d out=%d ring=%d errno=%d\n"
               "---LOG---\n---END---\n", map_in, map_out, g_ringbuf_fd, errno);
        return;
    }
    printf("CHANNEL btf=ok slice_rdwr=%d slice_ro=%d from_skb=%d ringbuf_fd=%d\n",
           slice_id, g_slice_ro_id, g_from_skb_id, g_ringbuf_fd);
    /* Teach the independent liveness model the arity of every kfunc this family emits.
       The ids come from the BTF walk this harness already does; the ARITIES come from the
       kfuncs' published signatures, not from the kernel's liveness analysis. A kfunc left
       out here is refused by the model rather than approximated -- which is how 0088 found
       that one unregistered kfunc was silently costing 823 of 896 programs. */
    bpflive_register_kfunc(ids.new_id, 3);      /* bpf_iter_num_new(it, start, end)      */
    bpflive_register_kfunc(ids.next_id, 1);     /* bpf_iter_num_next(it)                 */
    bpflive_register_kfunc(ids.destroy_id, 1);  /* bpf_iter_num_destroy(it)              */
    bpflive_register_kfunc(slice_id, 4);        /* bpf_dynptr_slice_rdwr(p,off,buf,szk)  */
    bpflive_register_kfunc(g_slice_ro_id, 4);   /* bpf_dynptr_slice(p,off,buf,szk)       */
    bpflive_register_kfunc(g_from_skb_id, 3);   /* bpf_dynptr_from_skb(skb,flags,ptr)    */
    memset(g_seen_pair, 0, sizeof(g_seen_pair));
    memset(g_seen_triple, 0, sizeof(g_seen_triple));
    /* Fixed seeds: the walk is random but the CORPUS is reproducible, which is what a
       finding needs. Each program prints its own seed so one can be replayed alone. */
    for (int i = 0; i < COMP_MAXPROG; i++)
        run_comp_prog(&ids, slice_id, 0x9E3779B9u * (uint32_t)(i + 1), i, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- dynptr slices: a two-part safety contract (--gen-dyn) ------------------
// FIRST LEG ON A FRESH SURFACE. Everything up to here has probed the verifier's most
// hardened regions -- ALU transfer functions, ranges, pruning, state comparison. dynptr
// is recent code, and the reason it is worth aiming at is visible in what the verifier
// actually proves about a slice (verifier.c:13729):
//
//     regs[BPF_REG_0].mem_size = meta->arg_constant.value;   /* = buffer__szk */
//     regs[BPF_REG_0].type = PTR_TO_MEM | type_flag;
//
// The static bound comes from the CALLER'S CONSTANT, not from the dynptr's extent and
// not from `size - offset`. The real bound is enforced at runtime (helpers.c):
//
//     u64 len = buffer__szk;
//     err = bpf_dynptr_check_off_len(ptr, offset, len);
//     if (err) return NULL;
//     case BPF_DYNPTR_TYPE_LOCAL: return ptr->data + ptr->offset + offset;
//
// So safety is a TWO-PART CONTRACT: the verifier proves the store sits inside
// [0, buffer__szk) of whatever came back, and the runtime guarantees that what came back
// really has that many bytes, or is NULL. Neither half is sufficient alone, and no
// earlier leg has had a shape where the two halves come from different places. For a
// LOCAL dynptr the slice points INTO the original memory, so our existing sentinel
// readback observes the composition end to end with no new oracle.
//
// COORDINATE TRANSLATION, decided BEFORE the capture rather than after a false positive.
// The slice pointer's base is `map_value + dynptr_offset`, but the verifier sees only a
// `mem(sz=N)` with no relation to the map value, while the runtime readback is in map
// value coordinates. The STORE line is generator provenance, so the generator supplies
// the translation and declares the store at `dynptr_offset + K` -- the offset in the
// coordinate system the observation channel uses. What that makes checkable is real: the
// slice must hand back a pointer at exactly `data + offset`, and a store at +K through it
// must land at exactly `dynptr_offset + K`.
#define DYN_VALUE 64      /* map_out size, and the buffer the dynptr is built over */
#define DYN_SIZE  32      /* the dynptr's declared extent, deliberately < DYN_VALUE */


/* off = dynptr offset passed to the slice, szk = the constant the verifier trusts,
   k = the store's offset within the slice. */
static void run_dyn_prog(const struct iter_ids *unused, int slice_id, int off, int szk,
                         int k, int idx, int map_out) {
    (void)unused;
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_0);          /* keep the map value */

    /* bpf_dynptr_from_mem(data, size, flags, &dynptr) -- a plain helper, and the dynptr
       occupies a 16-byte STACK_DYNPTR pair the verifier tracks by id. */
    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_2, DYN_SIZE);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -32);
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_dynptr_from_mem);

    /* bpf_dynptr_slice_rdwr(&dynptr, offset, buffer, buffer__szk) */
    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -32);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_2, off);
    ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -128);      /* the optional buffer */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_4, szk);
    ins[n++] = BPF_KFUNC_CALL(slice_id);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);

    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_0, k, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    const int PT = BPF_PROG_TYPE_SCHED_CLS;
    struct prune_load base = prune_load_typed(ins, n, 0, g_log, sizeof(g_log), PT);
    struct prune_load freq = prune_load_typed(ins, n, BPF_F_TEST_STATE_FREQ,
                                              g_log2, sizeof(g_log2), PT);
    struct prune_load inv  = prune_load_typed(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                              g_log2, sizeof(g_log2), PT);

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = PT;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "gendyn#o%d.z%d.k%d#%03d", off, szk, k, idx);
    printf("===PROG %s type=sched_cls ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    /* Translated into map-value coordinates -- see the note above. */
    printf("STORE insn=%d reg=0 off=%d size=1\n", store_insn, off + k);
    printf("DYN dynptr_size=%d slice_off=%d slice_szk=%d store_k=%d"
           " runtime_slice_ok=%d\n",
           DYN_SIZE, off, szk, k, (off + szk) <= DYN_SIZE);

    printf("PRUNE fall=o%d taken=z%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           off, szk, k < szk, (off + szk) <= DYN_SIZE,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int soff = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { soff = b; break; }
            /* retval 1 only on the path that stored; a NULL slice exits with 0, which is
               exactly the executed=0 case 0041 added the witness for. */
            int executed = (t.test.retval == 1);
            if (soff < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = soff; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, soff, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_dyn_family(void) {
    int slice_id = btf_find_func_id("bpf_dynptr_slice_rdwr");
    if (slice_id <= 0) {
        printf("===PROG gendyn type=sched_cls ===\n"
               "RESULT decision=error btf_resolve_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    printf("CHANNEL btf=ok slice_rdwr=%d\n", slice_id);
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = DYN_VALUE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) {
        printf("===PROG gendyn type=sched_cls ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Two independent boundaries, deliberately separated:
         k vs szk           -> the VERIFIER's static bound (the caller's constant)
         off + szk vs size  -> the RUNTIME's bound (slice returns NULL past the extent)
       The `big` and `past` arms are the point of the leg: the verifier accepts a slice
       claim it has no basis for, and only the runtime NULL keeps the program safe. */
    const struct { int off, szk, k; } arms[] = {
        {  0,  8, 0 },   /* interior                                    -> accept, lands 0  */
        {  0,  8, 7 },   /* last byte of the slice                      -> accept, lands 7  */
        {  0,  8, 8 },   /* one past the constant: the static off-by-one -> REJECT          */
        { 24,  8, 7 },   /* off+szk == size exactly                     -> accept, lands 31 */
        { 28,  8, 0 },   /* off+szk > size: runtime NULL, store skipped -> accept, no store */
        {  0, 64, 0 },   /* szk twice the dynptr: verifier trusts it anyway                 */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_dyn_prog(NULL, slice_id, arms[i].off, arms[i].szk, arms[i].k, idx++, map_out);
    close(map_out);
}

// ---- reaching RANGE_WITHIN on purpose (--gen-rw) ----------------------------
// 0051 predicted that the precision short-circuit would stop working inside a loop,
// because it is gated on `exact == NOT_EXACT`. The measurement said otherwise: a may_goto
// loop does not select RANGE_WITHIN, since the gate on the main path is
// `incomplete_read_marks` and not the presence of a back-edge.
//
// There IS a call site that passes RANGE_WITHIN unconditionally (states.c:1333):
//
//     if (is_iter_next_insn(env, insn_idx)) {
//             if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) { ... }
//
// but note WHICH instruction it applies to: the iterator's next-call site, not every
// instruction in the loop body. So to put the precision pair under that comparison, the
// two states have to MEET at the loop head — which means the split has to happen BEFORE
// the iterator loop, not inside it. Getting that wrong would compare the pair at an
// ordinary instruction and measure the same NOT_EXACT path all over again.
//
// PREDICTION, now aimed at a call site rather than at "a loop": with the pair meeting at
// the iter_next instruction, the precision short-circuit is off, so the dead-register arm
// can no longer buy a prune and the gap that 0050 measured should CLOSE. The flat pair
// rides along in the same capture so the comparison is within one run.
#define RW_STORE_OFF 40

static void run_rw_prog(const struct iter_ids *ids, int use_iter, int store_src,
                        int idx, int map_in, int map_out) {
    struct bpf_insn ins[96];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);

    /* The split is BEFORE the loop on purpose: the two states must MEET at the
       iterator's next-call site, which is the instruction states.c:1333 compares with
       RANGE_WITHIN. Splitting inside the body would put the meeting point at an ordinary
       instruction and measure the main NOT_EXACT path again. */
    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 8);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 16);
    ins[jmerge].off = n - jmerge - 1;

    if (use_iter)
        n = emit_iter_loop(ins, n, ids, 0, 4, LB_NOP);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2,
                             store_src == 7 ? BPF_REG_7 : BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, RW_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    unsigned long mp_r7 = 0;
    for (const char *q = g_log; (q = strstr(q, "regs=r7 ")) != NULL; q++) mp_r7++;
    unsigned long iter_states = 0;
    for (const char *q = g_log; (q = strstr(q, "state=active")) != NULL; q++) iter_states++;

    char name[96];
    snprintf(name, sizeof(name), "genrw#%s.s%d#%03d",
             use_iter ? "iter" : "flat", store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, RW_STORE_OFF);
    printf("RW ctx=%s store_src=%d r7_backtracked=%lu iter_active=%lu\n",
           use_iter ? "iter" : "flat", store_src, mp_r7, iter_states);
    printf("PRUNE fall=%s taken=s%d fall_safe=1 taken_safe=1 stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           use_iter ? "iter" : "flat", store_src,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 4, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_rw_family(void) {
    struct iter_ids ids;
    if (iter_resolve(&ids) < 0) {
        printf("===PROG genrw type=socket_filter ===\n"
               "RESULT decision=error btf_resolve_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genrw type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    const struct { int use_iter, src; } arms[] = {
        { 0, 7 },   /* flat baseline: r7 decides -> precise, no prune  */
        { 0, 6 },   /* flat baseline: r7 dead    -> imprecise, prune   */
        { 1, 7 },   /* the pair meets at the iter_next insn            */
        { 1, 6 },   /* ...where RANGE_WITHIN should disable the prune  */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_rw_prog(&ids, arms[i].use_iter, arms[i].src, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- which exact_level our shapes reach (--gen-exact) -----------------------
// `regsafe` takes an `exact_level` and behaves very differently per level (states.c):
//   EXACT        -> regs_exact(): memcmp + check_ids, the strictest possible comparison
//   NOT_EXACT    -> the precision short-circuit applies: `!rold->precise` matches anything
//   RANGE_WITHIN -> range/tnum logic runs, but the precision short-circuit does NOT
// and the three arrive from different call sites:
//   :1405  states_equal(..., loop ? RANGE_WITHIN : NOT_EXACT)   the main pruning path,
//          where `loop = incomplete_read_marks(env, &sl->state)` -- note this is NOT
//          simply "there is a back-edge"
//   :1333/:1358/:1364  RANGE_WITHIN, the iterator paths
//   :1372  EXACT, used ONLY for infinite-loop detection
//
// That last one is directly observable: reaching it prints "infinite loop detected at
// insn %d". So a program whose state repeats unchanged at a back-edge gives us a marker
// that the EXACT path ran -- the only level we can confirm from outside.
//
// The reason this leg exists is a PREDICTION from that table rather than a new mechanism.
// 0050 measured the precision lever on straight-line code: with the store using the
// register the two paths disagree about, r7 must be precise and both states are explored;
// with the store using a dead register, `!rold->precise` short-circuits and one state is
// pruned. That short-circuit is gated on `exact == NOT_EXACT`. So the SAME pair placed
// inside a loop should behave differently if the loop takes a RANGE_WITHIN comparison.
// Whether it does is exactly what `incomplete_read_marks` decides, which is not something
// to assert from a reading -- so the family carries both the flat pair and the looped
// pair in ONE capture and lets the state counts answer.
#define EXACT_STORE_OFF 40

enum exact_shape {
    EXS_INF,     /* back-edge whose state repeats unchanged -> infinite loop detected */
    EXS_FLAT,    /* 0050's pair, straight-line: the NOT_EXACT baseline                */
    EXS_LOOP,    /* the same pair inside a may_goto loop                              */
};

static const char *exact_shape_name(enum exact_shape e) {
    switch (e) {
    case EXS_INF:  return "inf";
    case EXS_FLAT: return "flat";
    case EXS_LOOP: return "loop";
    }
    return "?";
}

static void run_exact_prog(enum exact_shape shape, int store_src, int idx,
                           int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);

    if (shape == EXS_INF) {
        /* The state at the head repeats unchanged after the first pass (the mask is
           idempotent), which is what states_maybe_looping + EXACT detect.
           The back-edge must be CONDITIONAL: an unconditional `goto head` makes
           everything after it unreachable and check_cfg rejects the program outright
           ("Remove the unreachable instruction", processed 0 insns) before a single
           state is walked -- so the EXACT path would never be reached at all. The
           condition is always true for r6 in [0,7], so the loop really is infinite. */
        const int head = n;
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        const int jb = n;
        ins[jb] = BPF_JMP_IMM(BPF_JLT, BPF_REG_6, 10, head - jb - 1);
        n++;
    } else {
        int loop_head = -1, jbreak = -1;
        if (shape == EXS_LOOP) {
            /* r7 must be live BEFORE the head: may_goto can break out on entry, and on
               that zero-iteration path the split never runs. Same zero-iteration path
               that decides the verdicts in 0043 -- here it showed up as
               "Initialize R7 on every path before this instruction". */
            ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 8);
            loop_head = n;
            jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
        }
        /* 0050's pair: the two paths differ ONLY in the constant they put in r7. */
        const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 8);
        const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
        ins[jsplit].off = n - jsplit - 1;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 16);
        ins[jmerge].off = n - jmerge - 1;
        if (shape == EXS_LOOP) {
            const int jback = n;
            ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);
            n++;
            ins[jbreak].off = n - jbreak - 1;
        }
    }

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2,
                             store_src == 7 ? BPF_REG_7 : BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, EXACT_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    unsigned long mp_r7 = 0;
    for (const char *q = g_log; (q = strstr(q, "regs=r7 ")) != NULL; q++) mp_r7++;
    const int inf_detected = strstr(g_log, "infinite loop detected") != NULL;

    char name[96];
    snprintf(name, sizeof(name), "genexact#%s.s%d#%03d",
             exact_shape_name(shape), store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, EXACT_STORE_OFF);
    printf("EXACT shape=%s store_src=%d infinite_loop_detected=%d r7_backtracked=%lu\n",
           exact_shape_name(shape), store_src, inf_detected, mp_r7);
    printf("PRUNE fall=%s taken=s%d fall_safe=1 taken_safe=1 stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           exact_shape_name(shape), store_src,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    /* The measurement here is state counts, but reporting a clean result with a zero
       location denominator is exactly what this project's own rule forbids -- so the
       accepted programs are executed like every other family's. */
    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 4, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_exact_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genexact type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The flat and looped pairs sit in ONE capture so the precision gap can be compared
       between them directly rather than across two runs. */
    const struct { enum exact_shape shape; int src; } arms[] = {
        { EXS_INF,  6 },   /* marker: the EXACT path prints "infinite loop detected" */
        { EXS_FLAT, 7 },   /* NOT_EXACT, r7 decides   -> precise, no prune           */
        { EXS_FLAT, 6 },   /* NOT_EXACT, r7 dead      -> imprecise, prune            */
        { EXS_LOOP, 7 },   /* same pair, in a loop                                   */
        { EXS_LOOP, 6 },   /* same pair, in a loop, r7 dead                          */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_exact_prog(arms[i].shape, arms[i].src, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- precision as the pruning lever (--gen-prec) ----------------------------
// `regsafe` (states.c:551) contains the single most powerful pruning rule in the
// verifier:
//
//     if (!rold->precise && exact == NOT_EXACT)
//             return true;
//
// An IMPRECISE old scalar matches ANY current scalar. So precision is exactly what stops
// a prune: if a register whose value decides memory safety is not marked precise, two
// states differing only in that register are equated and the unsafe one is pruned away.
// `mark_chain_precision` is what has to get that right, `precise.c` is on the kernel's
// own danger list, and the backtracker logs its work (`mark_precise: frame%d: regs=%s`,
// backtrack.c:280), so the mechanism is observable rather than merely inferred.
//
// THE AXIS is whether the differing register PARTICIPATES in the deciding access:
//   * store through r7 -> r7's value decides safety -> it must be marked precise ->
//     the two states are not equatable -> both paths are explored;
//   * store through r6 (a masked, always-safe offset) -> r7 is never used -> it need not
//     be precise -> the short-circuit above applies and the second state CAN be pruned.
// The two differ in one operand of one instruction, so the state counts and the
// mark_precise lines isolate precision itself.
//
// Store offset 40 makes the decision a pure function of the constant: in bounds iff
// umax <= 23, so 23 accepts and 24 rejects — an exact one-byte boundary that proves the
// verdict tracks the VALUE and not the shape.
#define PREC_STORE_OFF 40

/* store_src: 7 = the register the two paths disagree about (precision required),
   6 = a masked always-safe offset (r7 unused, precision not required). */
static void run_prec_prog(int c_fall, int c_taken, int store_src, int idx,
                          int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);          /* always-safe offset */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);   /* path selector */

    /* The two paths differ ONLY in the constant they put in r7. */
    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, c_fall);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, c_taken);
    ins[jmerge].off = n - jmerge - 1;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2,
                             store_src == 7 ? BPF_REG_7 : BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, PREC_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    /* How many `mark_precise:` lines the backtracker emitted for the DEFAULT load: the
       direct observable of whether precision work happened at all. */
    unsigned long mp = 0;
    for (const char *q = g_log; (q = strstr(q, "mark_precise:")) != NULL; q++)
        mp++;

    char name[96];
    snprintf(name, sizeof(name), "genprec#c%d_%d.s%d#%03d", c_fall, c_taken, store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, PREC_STORE_OFF);
    printf("PREC c_fall=%d c_taken=%d store_src=%d store_off=%d mark_precise_lines=%lu\n",
           c_fall, c_taken, store_src, PREC_STORE_OFF, mp);
    printf("PRUNE fall=c%d taken=c%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           c_fall, c_taken,
           store_src == 7 ? (c_fall + PREC_STORE_OFF < 64) : 1,
           store_src == 7 ? (c_taken + PREC_STORE_OFF < 64) : 1,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 4, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_prec_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genprec type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The first two arms differ in ONE operand of ONE instruction — which register the
       store adds — so any difference in state count or precision work between them is
       precision itself and nothing else. 23 vs 24 is the exact one-byte boundary. */
    const struct { int cf, ct, src; } arms[] = {
        {  8, 16, 7 },   /* r7 decides safety -> must be precise -> no prune -> accept */
        {  8, 16, 6 },   /* r7 unused -> need not be precise -> prune allowed -> accept */
        {  8, 23, 7 },   /* 40 + 23 + 1 == 64 exactly                        -> accept */
        {  8, 24, 7 },   /* one byte over                                    -> reject */
        {  8, 40, 7 },   /* well over                                        -> reject */
        {  8,  8, 7 },   /* identical states, trivial prune                  -> accept */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_prec_prog(arms[i].cf, arms[i].ct, arms[i].src, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- spilled links and delta arithmetic (--gen-spill) -----------------------
// Two gaps left by 0046-0048, both visible in sync_linked_regs (verifier.c:16847):
//
//   reg = e->is_reg ? &vstate->frame[e->frameno]->regs[e->regno]
//                   : &vstate->frame[e->frameno]->stack[e->spi].spilled_ptr;
//
// (1) A linked scalar's set spans STACK SLOTS, not just registers, and `stacksafe` has
//     its own check_ids calls for spilled state. Every id family so far kept its scalars
//     in registers, so the spilled half of both mechanisms is untested.
//
// (2) The ADD_CONST branch does real ARITHMETIC when two members of a class carry
//     different deltas:
//         __mark_reg_known(&fake_reg, (s64)reg->delta - (s64)known_reg->delta);
//         *reg = *known_reg;  /* then reg += fake_reg */
//     0046 and 0047 only ever had ONE delta (4) linked to a bare base, so the
//     subtraction never had two non-trivial operands. Two registers at different offsets
//     from the same base exercise it directly, and a wrong delta is a bounds error.
//
// Same paired design as 0046: every REJECT shape has an ACCEPT control differing only in
// whether the link exists on both paths, so the verdicts isolate linkage rather than
// shape. Store offset 44 keeps every correctly-narrowed variant in bounds -- bare gives
// umax 7, delta 4 gives 11, delta 12 gives 19, and 44 + 19 + 1 = 64 -- so the decision
// never turns on offset arithmetic, only on whether the class was narrowed.
enum spill_shape {
    SPL_NONE,      /* no link                                                        */
    SPL_SPILL,     /* r7 = r6, then spill r7: the linked copy lives in a stack slot   */
    SPL_DELTA,     /* r7 = r6; r7 += 4  and  r9 = r6; r9 += 12: two deltas, one base  */
    SPL_DELTA32,   /* the same, in 32-BIT form: the shape a real bug lived in         */
};

static const char *spill_shape_name(enum spill_shape p) {
    switch (p) {
    case SPL_NONE:  return "none";
    case SPL_SPILL: return "spill";
    case SPL_DELTA: return "delta";
    case SPL_DELTA32: return "delta32";
    }
    return "?";
}

/* `linked` selects whether this path forms the link at all; the unlinked variant still
   spills, so the two states differ ONLY in the id structure of the spilled slot. */
static int emit_spill_shape(struct bpf_insn *ins, int n, enum spill_shape p, int linked) {
    switch (p) {
    case SPL_NONE:
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16);
        break;
    case SPL_SPILL:
        if (linked)
            ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16);
        break;
    case SPL_DELTA32:
        /* THE SHAPE A REAL BUG LIVED IN. Commit 3878ae04e9fc ("bpf: Fix incorrect delta
           propagation between linked registers", 2024-10) fixed sync_linked_regs
           propagating a 32-BIT delta as if it were 64-bit: with known_reg = 0xFFFFFFFF
           and a delta of 1 the verifier concluded 0x100000000 while the real value wraps
           to 0 — "can lead to accepting a program with OOB access".
           0049 pinned the delta arithmetic by value, but only in the alu64 form, so this
           shape had never been generated at all. The fix is in our tree, so the expected
           result is clean; what this arm buys is that the shape is now covered and any
           regression in that class has a detector. Reading a real bug tells you which
           INPUT matters, not only whether the oracle can see it. */
        if (linked) {
            ins[n++] = BPF_MOV32_REG(BPF_REG_7, BPF_REG_6);
            ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_7, 4);
            ins[n++] = BPF_MOV32_REG(BPF_REG_9, BPF_REG_6);
            ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_9, 12);
        } else {
            ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_7, 4);
            ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_9, 12);
        }
        break;
    case SPL_DELTA:
        if (linked) {
            ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4);
            ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 12);
        } else {
            /* same registers written, same widths, no shared base */
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 12);
        }
        break;
    }
    return n;
}

/* store_src: 0 = the slot reloaded from the stack, 7 = the delta-4 register,
   9 = the delta-12 register, 6 = the register the check narrows directly (control). */
static void run_spill_prog(enum spill_shape shape, int link_fall, int link_taken,
                           int store_src, int store_off, int idx,
                           int map_in, int map_out) {
    struct bpf_insn ins[96];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 12);   /* path selector */

    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    n = emit_spill_shape(ins, n, shape, link_fall);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    n = emit_spill_shape(ins, n, shape, link_taken);
    ins[jmerge].off = n - jmerge - 1;

    /* Names r6 only. Everything else can be narrowed ONLY through the shared class --
       including, for the spill arms, a copy that is sitting in a stack slot. */
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);
    if (store_src == 0)
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, -16);  /* reload the slot */

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    int src = store_src == 0 ? BPF_REG_8
            : store_src == 7 ? BPF_REG_7
            : store_src == 9 ? BPF_REG_9 : BPF_REG_6;
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, src);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genspill#%s.%s.s%d#%03d", spill_shape_name(shape),
             (link_fall && link_taken) ? "both" : (link_fall || link_taken) ? "one" : "no",
             store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, store_off);
    printf("SPILL shape=%s link_fall=%d link_taken=%d store_src=%d store_off=%d\n",
           spill_shape_name(shape), link_fall, link_taken, store_src, store_off);
    printf("PRUNE fall=%s taken=s%d fall_safe=%d taken_safe=%d stack=1"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           spill_shape_name(shape), store_src, link_fall, link_taken,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            memcpy(val + 4, &in, 4);
            memcpy(val + 8, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 12, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    bpflive_print_claim(ins, n);
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_spill_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genspill type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    const struct { enum spill_shape shape; int lf, lt, src; } arms[] = {
        { SPL_SPILL, 0, 0, 0 },   /* baseline: spilled copy never linked   -> reject */
        { SPL_SPILL, 1, 0, 0 },   /* THE SHAPE: linked on one path         -> reject */
        { SPL_SPILL, 1, 1, 0 },   /* does a SPILLED copy get narrowed?     -> answer */
        { SPL_SPILL, 1, 0, 6 },   /* control: store through r6 directly    -> accept */
        { SPL_DELTA, 0, 0, 9 },   /* baseline for the delta arm            -> reject */
        { SPL_DELTA, 1, 0, 9 },   /* linked on one path                    -> reject */
        { SPL_DELTA, 1, 1, 9 },   /* delta 12: is the subtraction right?   -> answer */
        { SPL_DELTA, 1, 1, 7 },   /* delta 4, same class                   -> accept */
        { SPL_DELTA32, 0, 0, 9 },  /* 32-bit delta baseline                 -> reject */
        { SPL_DELTA32, 1, 0, 9 },  /* linked on one path only               -> reject */
        { SPL_DELTA32, 1, 1, 9 },  /* the real bug's shape: delta 12, alu32 -> answer */
        { SPL_DELTA32, 1, 1, 7 },  /* delta 4, alu32                        -> answer */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_spill_prog(arms[i].shape, arms[i].lf, arms[i].lt, arms[i].src, 44, idx++,
                       map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- multi-frame states / subprogs (--gen-frame) ----------------------------
// Every program this project has generated so far lives in ONE frame. `states_equal`
// opens with `if (old->curframe != cur->curframe) return false` and then compares each
// frame in turn, so the whole multi-frame half of state comparison has never been
// touched -- and `calls.c` is on the kernel's own danger list (it is one of the files
// that sets BPF_F_TEST_STATE_FREQ).
//
// A subprog call needs no BTF and no kfunc: `BPF_CALL` with `src_reg = BPF_PSEUDO_CALL`
// and `imm` = the pc-relative offset of the callee. The interesting question is what
// crosses the boundary. Only r1-r5 are passed; the callee's r6-r9 start uninitialised.
// If a scalar's link ID survives into the callee's argument register, then narrowing one
// argument narrows the other through sync_linked_regs -- INSIDE a different frame from
// the one where the link was formed. If it does not survive, the callee sees two
// independent scalars.
//
// The family answers that by construction rather than by assumption, using the same
// paired design as 0046: link on ONE path versus link on BOTH. If both variants reject,
// ids do not cross the frame boundary. If one-path rejects while both-path accepts, they
// do -- and the caller's differing linkage is something `states_equal` must distinguish
// while comparing two frames rather than one.
enum frame_shape {
    FRM_NOLINK,    /* no link at all -- baseline                                   */
    FRM_ONE,       /* link on the fall-through path only                           */
    FRM_BOTH,      /* link on both paths                                           */
};

static const char *frame_shape_name(enum frame_shape f) {
    switch (f) {
    case FRM_NOLINK: return "nolink";
    case FRM_ONE:    return "one";
    case FRM_BOTH:   return "both";
    }
    return "?";
}

/* `use_arg1` stores through the argument the callee narrows directly, which must be safe
   whatever the ids say -- the control that fences the result from the other side. */
static void run_frame_prog(enum frame_shape shape, int use_arg1, int store_off,
                           int idx, int map_in, int map_out) {
    struct bpf_insn ins[96];
    int n = 0, jexit[4], nx = 0;

    /* ---- caller frame ---- */
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 8);   /* path selector */

    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    if (shape != FRM_NOLINK)
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);       /* link, fall-through */
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    if (shape == FRM_BOTH)
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);       /* link, taken path */
    ins[jmerge].off = n - jmerge - 1;

    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);           /* arg 1 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_7);           /* arg 2 */
    const int jcall = n; ins[n++] = (struct bpf_insn){0};     /* patched below */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* ---- callee frame: narrows arg1, stores through the chosen arg ---- */
    const int sub = n;
    ins[jcall] = (struct bpf_insn){.code = BPF_JMP | BPF_CALL, .dst_reg = 0,
                                   .src_reg = BPF_PSEUDO_CALL, .off = 0,
                                   .imm = sub - jcall - 1};
    int sexit[4]; int sx = 0;
    ins[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);           /* keep args across the */
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_2);           /* upcoming helper call */
    /* Names r6 (= arg1) only: r7 can be narrowed ONLY through a shared id that survived
       the frame boundary. */
    sexit[sx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    sexit[sx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_3, use_arg1 ? BPF_REG_6 : BPF_REG_7);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_3, store_off, -1);
    const int sexit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < sx; i++)
        ins[sexit[i]].off = sexit0 - sexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genframe#%s.a%d#%03d",
             frame_shape_name(shape), use_arg1 ? 1 : 2, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=3 off=%d size=1\n", store_insn, store_off);
    printf("FRAME shape=%s store_arg=%d sub_at=%d store_off=%d\n",
           frame_shape_name(shape), use_arg1 ? 1 : 2, sub, store_off);
    printf("PRUNE fall=%s taken=a%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           frame_shape_name(shape), use_arg1 ? 1 : 2, base.accept, base.accept,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            memcpy(val + 4, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 8, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            /* The caller returns 1 only after the subprog returned, so the witness still
               means "the store path ran" -- the callee's own exit clears r0 to 0 first. */
            int executed = (off >= 0);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_frame_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genframe type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    const struct { enum frame_shape shape; int use_arg1; } arms[] = {
        { FRM_NOLINK, 0 },   /* baseline: arg2 never narrowed                     */
        { FRM_NOLINK, 1 },   /* control:  store through the narrowed arg1         */
        { FRM_ONE,    0 },   /* THE SHAPE: link on one path, store through arg2   */
        { FRM_BOTH,   0 },   /* the answer: does the link cross the frame at all? */
        { FRM_ONE,    1 },   /* control                                           */
        { FRM_BOTH,   1 },   /* control                                           */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_frame_prog(arms[i].shape, arms[i].use_arg1, 48, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- id-map BIJECTION / partition structure (--gen-idpart) ------------------
// 0046 asked whether a link is PRESENT. This asks whether the mapping between the two
// states' ids is a BIJECTION, which is the actual contract of check_ids (states.c:319):
//
//   for (i = 0; i < idmap->cnt; i++) {
//           if (map[i].old == old_id) return map[i].cur == cur_id;  /* consistency */
//           if (map[i].cur == cur_id) return false;                 /* injectivity */
//   }
//
// Which of those two `if`s fires is NOT controllable from the program: registers are
// compared in order and whichever inconsistency is reached first decides. What IS
// controllable, and what actually matters, is the id STRUCTURE -- the partition of
// registers into linked classes. Two states whose partitions differ in a way that
// matters must never be equated; two states whose partitions are IDENTICAL but whose id
// NUMBERS differ must be equated, or the mapping is vacuously strict.
//
// That second direction is the half every earlier leg is missing. Everything so far
// tests soundness (never accept something unsafe). `swap` tests COMPLETENESS: the same
// partition built by a different instruction order mints different id numbers
// (++env->id_gen is global), so accepting it is only possible if the remapping genuinely
// works. If check_ids required identical ids, that arm would over-reject.
//
// Shape: four attacker scalars and a selector, a split that constrains none of them, a
// narrowing check naming r6 alone, and a store through r9 -- so r9's safety is exactly
// "does r9 end up in r6's linked class". Store offset 48 leaves room for the +4 delta of
// the ADD_CONST arm: linked and narrowed, r9 is at most 7 (bare) or 11 (delta), and
// 48 + 11 + 1 = 60 <= 64, so the decision never turns on offset arithmetic.
enum idpart_shape {
    IDP_SAME,     /* r7 = r6; r9 = r6      one class {r6,r7,r9}                     */
    IDP_CHAIN,    /* r7 = r6; r9 = r7      transitive: r9 must still join r6's class */
    IDP_ADDC,     /* r7 = r6; r9 = r6; r9 += 4   class + BPF_ADD_CONST64 delta       */
    IDP_SWAPPED,  /* r9 = r6; r7 = r6      SAME partition, different mint order      */
    IDP_TIED8,    /* r7 = r6; r9 = r8      r9 in r8's class -> never narrowed        */
};

static const char *idpart_shape_name(enum idpart_shape p) {
    switch (p) {
    case IDP_SAME:    return "same";
    case IDP_CHAIN:   return "chain";
    case IDP_ADDC:    return "addc";
    case IDP_SWAPPED: return "swap";
    case IDP_TIED8:   return "tied8";
    }
    return "?";
}

static int emit_idpart(struct bpf_insn *ins, int n, enum idpart_shape p) {
    switch (p) {
    case IDP_SAME:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6); break;
    case IDP_CHAIN:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_7); break;
    case IDP_ADDC:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 4); break;
    case IDP_SWAPPED:
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6); break;
    case IDP_TIED8:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_8); break;
    }
    return n;
}

/* Does this shape put r9 in the class the narrowing check touches? */
static int idpart_narrows_r9(enum idpart_shape p) { return p != IDP_TIED8; }

static void run_idpart_prog(enum idpart_shape fall, enum idpart_shape taken,
                            int store_off, int idx, int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 8);
    /* The selector lives in a caller-saved register on purpose: no call happens between
       this load and the branch, and using r6-r9 would cost one of the four scalars. */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 12);

    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0);
    n = emit_idpart(ins, n, fall);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    n = emit_idpart(ins, n, taken);
    ins[jmerge].off = n - jmerge - 1;

    /* Names r6 only: r9 can be narrowed ONLY by being in r6's linked class. */
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genidpart#%s-%s#%03d",
             idpart_shape_name(fall), idpart_shape_name(taken), idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, store_off);
    printf("IDPART fall=%s taken=%s fall_narrows=%d taken_narrows=%d store_off=%d\n",
           idpart_shape_name(fall), idpart_shape_name(taken),
           idpart_narrows_r9(fall), idpart_narrows_r9(taken), store_off);
    printf("PRUNE fall=%s taken=%s fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           idpart_shape_name(fall), idpart_shape_name(taken),
           idpart_narrows_r9(fall), idpart_narrows_r9(taken),
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            memcpy(val + 4, &in, 4);
            memcpy(val + 8, &in, 4);
            uint32_t sel = i & 1;              /* both paths are taken at runtime */
            memcpy(val + 12, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_idpart_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genidpart type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Derived: accept iff BOTH paths put r9 in r6's linked class, because the state
       reaching the store is the join of the two. The `swap` pairs are the completeness
       half -- identical partitions, different id NUMBERS -- and must accept. */
    const struct { enum idpart_shape fall, taken; } arms[] = {
        { IDP_SAME,    IDP_SAME    },  /* both narrow r9                    -> accept */
        { IDP_SAME,    IDP_TIED8   },  /* second state leaves r9 unnarrowed -> reject */
        { IDP_TIED8,   IDP_SAME    },  /* mirror                            -> reject */
        { IDP_CHAIN,   IDP_CHAIN   },  /* transitive linking                -> accept */
        { IDP_CHAIN,   IDP_TIED8   },  /*                                   -> reject */
        { IDP_ADDC,    IDP_ADDC    },  /* ADD_CONST class, r9 = r6 + 4      -> accept */
        { IDP_ADDC,    IDP_TIED8   },  /*                                   -> reject */
        { IDP_SAME,    IDP_SWAPPED },  /* SAME partition, different id numbers        */
        { IDP_SWAPPED, IDP_SAME    },  /* mirror of the completeness arm              */
        { IDP_SAME,    IDP_CHAIN   },  /* same class reached two ways       -> accept */
        { IDP_SAME,    IDP_ADDC    },  /* class with and without the delta            */
        { IDP_TIED8,   IDP_TIED8   },  /* neither narrows r9                -> reject */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_idpart_prog(arms[i].fall, arms[i].taken, 48, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- scalar ID remapping (--gen-idmap) --------------------------------------
// THE thing states.c calls "too simplistic". `check_ids()` (states.c:319) builds a
// BIJECTIVE old<->cur id mapping while comparing two states, and `check_scalar_ids()`
// wraps it for scalars. The kernel's own comment in regsafe spells out why it must
// exist, and it is a program, not a hypothetical:
//
//   1: r6 = ... unbound scalar, ID=a ...
//   2: r7 = ... unbound scalar, ID=b ...
//   3: if (r6 > r7) goto +1
//   4: r6 = r7                 <- both now carry id=b: LINKED
//   5: if (r6 > X) goto ...    <- sync_linked_regs narrows r7 too, because they share id
//   6: ... memory operation using r7 ...
//
// Instruction 6 is reached in TWO states: I. r6{id=b}, r7{id=b} via 1-6, and
// II. r6{id=a}, r7{id=b} via 1-4,6. In state II the bound check at 5 never touched r7,
// so the memory operation is unsafe. If check_ids() equated the two, state II would be
// PRUNED against state I and the unsafe access accepted. That is a decision-flipping
// shape, which is what makes it testable at all.
//
// The axis is HOW the link is formed, because each form carries a different id:
//   * plain `rX = rY` mints an id on the source (assign_scalar_id_before_mov,
//     verifier.c:3470) and copies it, so both registers share a bare id;
//   * `rX = rY; rY += const` additionally sets BPF_ADD_CONST64 (bit 31) with a delta,
//     so the two registers carry id and id|flag -- and check_scalar_ids must map BOTH
//     the compound and the base id consistently;
//   * the 32-bit form sets BPF_ADD_CONST32 (bit 30) instead, and the kernel refuses to
//     prune across differing flag types because alu32 zero-extends and alu64 does not.
//
// Every arm pairs a REJECT shape (the link exists on one path only, so one state
// arrives unnarrowed) with an ACCEPT control (the link exists on both paths, or the
// store uses the register that is narrowed directly). Without the controls a reject
// would only prove the shape is unsafe, not that linkage is what decides it.
//
// 0042's instrument rides along unchanged and is an especially good fit here:
// BPF_F_TEST_STATE_FREQ multiplies the pruning attempts, so an id-mapping mistake has
// far more chances to be exercised with the flag than without.
enum idmap_link {
    IDL_NONE,      /* no link at all -- baseline: r7 is never narrowed          */
    IDL_MOV,       /* r7 = r6            bare shared id                          */
    IDL_ADDC64,    /* r7 = r6; r7 += 4   id | BPF_ADD_CONST64, delta 4           */
    IDL_ADDC32,    /* w7 = w6; w7 += 4   id | BPF_ADD_CONST32                    */
};

static const char *idmap_link_name(enum idmap_link l) {
    switch (l) {
    case IDL_NONE:   return "nolink";
    case IDL_MOV:    return "mov";
    case IDL_ADDC64: return "addc64";
    case IDL_ADDC32: return "addc32";
    }
    return "?";
}

static int emit_idmap_link(struct bpf_insn *ins, int n, enum idmap_link l) {
    switch (l) {
    case IDL_NONE:
        break;
    case IDL_MOV:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6); break;
    case IDL_ADDC64:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4); break;
    case IDL_ADDC32:
        ins[n++] = BPF_MOV32_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_7, 4); break;
    }
    return n;
}

/* `both` = emit the link on BOTH paths (the control); otherwise only on the
   fall-through, so the two states arriving at the narrowing check differ in exactly
   their id structure. `use_r6` stores through the register the check narrows directly,
   which must be safe no matter what the ids say. */
static void run_idmap_prog(enum idmap_link link, int both, int use_r6, int store_off,
                           int idx, int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);   /* scalar A */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);   /* scalar B */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);   /* path selector */

    /* The split tests r9 alone, so neither scalar is constrained by the branch and the
       only difference between the two arriving states is the LINK. */
    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 0, 0);
    n = emit_idmap_link(ins, n, link);                        /* fall-through path */
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    if (both)
        n = emit_idmap_link(ins, n, link);                    /* taken path too */
    ins[jmerge].off = n - jmerge - 1;

    /* The narrowing check names r6 only. r7 is narrowed ONLY through the shared id, by
       sync_linked_regs -- which is exactly the knowledge a wrong prune would smuggle
       into a state that never had it. */
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_8, use_r6 ? BPF_REG_6 : BPF_REG_7);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_8, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genidmap#%s.%s.r%d#%03d", idmap_link_name(link),
             both ? "both" : "one", use_r6 ? 6 : 7, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=8 off=%d size=1\n", store_insn, store_off);
    printf("IDMAP link=%s both=%d store_reg=r%d store_off=%d\n",
           idmap_link_name(link), both, use_r6 ? 6 : 7, store_off);
    printf("PRUNE fall=%s taken=%s fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           idmap_link_name(link), both ? "both" : "one", base.accept, base.accept,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);          /* scalar A */
            memcpy(val + 4, &in, 4);          /* scalar B */
            uint32_t sel = i & 1;             /* exercise BOTH paths at runtime */
            memcpy(val + 8, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_idmap_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;   /* two scalars + selector */
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genidmap type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Store offset 48 leaves room for the +4 delta of the ADD_CONST arms: linked and
       narrowed, r7 is at most 7 (bare) or 11 (delta 4), so 48 + 11 + 1 = 60 <= 64. The
       decision therefore turns on LINKAGE, never on the offset arithmetic. */
    const struct { enum idmap_link link; int both, use_r6; } arms[] = {
        { IDL_NONE,   0, 0 },   /* baseline: r7 never narrowed on either path   */
        { IDL_NONE,   0, 1 },   /* control:  store through the narrowed r6       */
        { IDL_MOV,    0, 0 },   /* THE SHAPE: link on one path only              */
        { IDL_MOV,    1, 0 },   /* control:  link on both paths                  */
        { IDL_MOV,    0, 1 },   /* control:  one-path link, store through r6     */
        { IDL_ADDC64, 0, 0 },   /* BPF_ADD_CONST64 link on one path only         */
        { IDL_ADDC64, 1, 0 },   /* control:  both paths                          */
        { IDL_ADDC32, 0, 0 },   /* BPF_ADD_CONST32 link on one path only         */
        { IDL_ADDC32, 1, 0 },   /* control:  both paths                          */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_idmap_prog(arms[i].link, arms[i].both, arms[i].use_r6, 48, idx++,
                       map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- open-coded iterator family (--gen-iter) --------------------------------
// The SAME loop bodies as --gen-loop, driven by a DIFFERENT loop mechanism. That makes
// the leg a mechanism differential on top of everything else: both are back-edges over
// the same transfer function, so for a body whose reachable set does not depend on the
// trip count the two mechanisms must agree. Where they legitimately DIFFER is the
// interesting part -- an open-coded iterator over [0,8) is a BOUNDED loop, while
// may_goto's count is unbounded, so a body that grows the offset is bounded here and not
// there. The `.o48` arms exist to expose exactly that: at store offset 48 the access is
// in bounds iff umax(r6) <= 15, which an 8-trip `inc` satisfies ([0,7] entry + at most 8
// increments) and an unbounded may_goto loop cannot.
//
// Iterators are also CHEAP to execute: at most 8 iterations, with none of may_goto's
// 250ms time budget (0044), so the runtime store-location oracle rides along for free.
// Every accepted program is executed over the full residue sweep and the landing site is
// compared against what the verifier proved -- the strictly stronger question, now on
// the mechanism the kernel itself special-cases in its pruning path.
static void run_iter_prog(const struct iter_ids *ids, enum loop_body body,
                          int store_off, int idx, int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);          /* entry invariant [0,7] */

    n = emit_iter_loop(ins, n, ids, 0, 8, body);              /* at most 8 trips */

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);                   /* witness: store ran */
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* 0042's instrument, unchanged, plus a fourth load that keeps the fd for running. */
    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "geniter#%s.o%d#%03d", loop_body_name(body), store_off, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, store_off);
    printf("PRUNE fall=%s taken=o%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           loop_body_name(body), store_off, base.accept, base.accept,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    printf("LOOP body=%s init_mask=7 store_off=%d\n", loop_body_name(body), store_off);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_iter_family(void) {
    struct iter_ids ids;
    if (iter_resolve(&ids) < 0) {
        printf("===PROG geniter type=socket_filter ===\n"
               "RESULT decision=error btf_resolve_failed errno=%d\n---LOG---\n---END---\n",
               errno);
        return;
    }
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG geniter type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Ten bodies at offset 56 -- directly comparable to --gen-loop's may_goto table --
       plus the two `.o48` arms where BOUNDEDNESS decides: at 48 the access is in bounds
       iff umax(r6) <= 15, which an 8-trip `inc` can satisfy and an unbounded loop
       cannot. */
    const struct { enum loop_body body; int off; } arms[] = {
        { LB_NOP,     56 }, { LB_MASK,    56 }, { LB_INCMASK, 56 }, { LB_MASKINC, 56 },
        { LB_SHR,     56 }, { LB_XOR3,    56 }, { LB_COND,    56 }, { LB_INC,     56 },
        { LB_SHL,     56 }, { LB_ADD8,    56 },
        { LB_INC,     48 }, { LB_NOP,     48 },
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_iter_prog(&ids, arms[i].body, arms[i].off, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

/* --probe-iter: does the kfunc/BTF machinery work at all, and is there a decision
   surface? Reports the resolved ids so a WRONG id (which is not a load error, just a
   call to another function) is visible rather than silent. */
static void run_probe_iter(void) {
    struct iter_ids ids;
    if (iter_resolve(&ids) < 0) {
        printf("CHANNEL btf=fail new=%d next=%d destroy=%d\n",
               ids.new_id, ids.next_id, ids.destroy_id);
        return;
    }
    printf("CHANNEL btf=ok new=%d next=%d destroy=%d btf_bytes=%u\n",
           ids.new_id, ids.next_id, ids.destroy_id, g_btf_len);

    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) { printf("CHANNEL error=map_create errno=%d\n", errno); return; }

    /* arm 0: bare loop, no store -- does the mechanism verify at all?
       arm 1: accumulate then mask, then store: is there a decision surface?
       arm 2: accumulate WITHOUT mask, then store: the unsound-fixpoint shape. */
    for (int arm = 0; arm < 3; arm++) {
        struct bpf_insn ins[64];
        int n = 0, jexit[2], nx = 0;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0);
        n = emit_iter_loop(ins, n, &ids, 0, 8,
                           arm == 1 ? LB_INCMASK : LB_INC);
        if (arm > 0) {
            ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0);
            ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16);
            ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
                                         .dst_reg = BPF_REG_1,
                                         .src_reg = BPF_PSEUDO_MAP_FD, .off = 0,
                                         .imm = map_out};
            ins[n++] = (struct bpf_insn){0};
            ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
            jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
            ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
            ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
            ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
        }
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        if (nx) {
            /* Only emit the null-path exit when something actually BRANCHES to it.
               Arm 0 has no map lookup, so an unconditional trailing block would be
               unreachable and the verifier rejects before walking a single insn
               ("processed 0 insns", EINVAL) -- a malformed probe, not a signal. */
            const int exit0 = n;
            ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
            ins[n++] = BPF_EXIT_INSN();
            for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;
        }

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 1;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int e = errno;
        const char *tail = "";
        if (fd < 0) {
            /* last non-empty line of the log = the reason */
            static char why[256];
            const char *nl = g_log, *last = g_log;
            for (const char *q = g_log; *q; q++) if (*q == '\n' && q[1]) last = q + 1;
            (void)nl;
            snprintf(why, sizeof(why), "%s", last);
            for (char *q = why; *q; q++) if (*q == '\n') { *q = '\0'; break; }
            tail = why;
        }
        printf("CHANNEL arm=%d insns=%d verdict=%s errno=%d reason=\"%s\"\n",
               arm, n, fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : e, tail);
        if (fd >= 0) close(fd);
    }
    close(map_out);
}

// ---- loop fixpoint vs runtime (--gen-loopr) ---------------------------------
// 0043 asked whether a back-edge program's VERDICT survives a change in checkpoint
// frequency. This asks the strictly stronger question 0041 introduced, now on a loop:
// the verifier proves a bound on the offset register at the store by computing a
// FIXPOINT over an unbounded number of iterations -- does that bound hold for the
// number of iterations the machine ACTUALLY runs?
//
// It also closes a hole in 0043: that family emits a STORE line but never executes, so
// `store_locations_checked` was 0 -- by this project's own rule, the claim was never
// read, and zero findings there meant nothing.
//
// COST, MEASURED FIRST (--probe-loopr): on x86-64 `bpf_jit_supports_timed_may_goto()`
// is true, so the budget is TIME-based and every run spends the full
// `NSEC_PER_SEC / 4`. Measured: 250.3 / 250.5 / 251.4 ms -- the budget exactly. Being
// time-based is what makes this affordable at all: KASAN/KCOV slowness lowers the
// iteration count inside the same 250ms instead of extending the run (OI-11).
// Six shapes x eight inputs x 250ms is about 12 seconds of kernel-side spinning.
//
// THE SWEEP IS THIS FAMILY'S OWN. The shared RT_INPUTS has twelve values, but the entry
// state here is `input & 7`, and those twelve collapse to only FIVE distinct residues --
// seven runs of 250ms each buying nothing. LOOPR_INPUTS covers all eight.
//
// NON-DETERMINISM IS A FEATURE HERE. The final offset depends on how many iterations
// fit in the time budget, so a shape like `incmask` lands somewhere different on every
// run. The oracle asks for MEMBERSHIP in the verifier's proven set, never equality, so
// each run samples the fixpoint at a fresh point. Nothing downstream may assert an exact
// store_off for these arms.

static void run_loopr_prog(enum loop_body body, int idx, int map_in, int map_out) {
    struct bpf_insn ins[64];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
    const int loop_head = n;
    const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
    n = emit_loop_body(ins, n, body);
    const int jback = n;
    ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);
    n++;
    ins[jbreak].off = n - jbreak - 1;
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);   /* witness: the store path ran */
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    char name[96];
    snprintf(name, sizeof(name), "genloopr#%s#%03d", loop_body_name(body), idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e, (unsigned long long)dt);
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, LOOP_STORE_OFF);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_loopr_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genloopr type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The six shapes 0043 measured as ACCEPTED, plus one rejected shape as a control
       that the decision surface is still real here. A rejected program never runs, so
       it contributes no runtime samples and no 250ms. */
    const enum loop_body shapes[] = {
        LB_NOP, LB_MASK, LB_INCMASK, LB_SHR, LB_XOR3, LB_COND,
        LB_MASKINC,   /* control: join [0,8] -> rejected, contributes no runtime */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
        run_loopr_prog(shapes[i], idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

/* --probe-loopr: MEASURE before committing to a runtime loop family.
 *
 * On x86-64 `bpf_jit_supports_timed_may_goto()` is true, so the may_goto budget is
 * TIME-based: bpf_check_timed_may_goto() refreshes a 0xffff counter until
 * `NSEC_PER_SEC / 4` has elapsed, i.e. ~250ms of kernel-side spinning PER RUN. A full
 * 12-input sweep over the six accepted loop shapes would be ~18s of that, in 250ms
 * uninterruptible chunks -- and OI-11 is exactly the lesson that says do not guess about
 * this. So: one run per shape, wall time and landing site reported, and the family gets
 * sized from the measurement instead of from an assumption.
 *
 * Being time-based is the reassuring half: KASAN/KCOV slowness cannot extend the budget,
 * it only lowers the iteration count inside the same 250ms. The measurement says whether
 * the whole idea is affordable. */
static void run_probe_loopr(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("CHANNEL error=map_create errno=%d\n", errno);
        return;
    }
    const enum loop_body shapes[] = { LB_NOP, LB_INCMASK, LB_SHR };
    for (unsigned si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
        struct bpf_insn ins[64];
        int n = 0, jexit[4], nx = 0;
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        const int loop_head = n;
        const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
        n = emit_loop_body(ins, n, shapes[si]);
        const int jback = n;
        ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);
        n++;
        ins[jbreak].off = n - jbreak - 1;
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 1;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        if (fd < 0) {
            printf("CHANNEL shape=%s load=reject errno=%d\n", loop_body_name(shapes[si]), errno);
            continue;
        }
        unsigned char zero[RTW_VALUE_SIZE], out[RTW_VALUE_SIZE], pkt[64];
        memset(zero, 0, sizeof(zero)); memset(pkt, 0, sizeof(pkt));
        rt_map_set(map_in, 0, 0x5a5a5a5a);
        rt_map_set_bytes(map_out, 0, zero);
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)pkt;
        t.test.data_size_in = sizeof(pkt);
        t.test.repeat = 1;
        uint64_t t0 = now_ns();
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        uint64_t dt = now_ns() - t0;
        memset(out, 0, sizeof(out));
        rt_map_get(map_out, 0, out);
        int off = -1;
        for (int b = 0; b < RTW_VALUE_SIZE; b++)
            if (out[b] == RTW_SENTINEL) { off = b; break; }
        printf("CHANNEL shape=%s load=accept testrun_rc=%d retval=%u wall_ns=%llu",
               loop_body_name(shapes[si]), r, (unsigned)t.test.retval,
               (unsigned long long)dt);
        if (off < 0) printf(" store_off=none\n"); else printf(" store_off=%d\n", off);
        close(fd);
    }
    close(map_in);
    close(map_out);
}

static void run_generated_loop_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genloop type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Derived expectation (the capture is the authority): with the store at +56 the
       access is in bounds iff the JOIN over all iteration counts keeps umax(r6) <= 7.
       `maskinc` vs `incmask` is the sharp pair -- same two operations, opposite ORDER,
       [1,8] vs [0,7], one byte apart. `narrow` is the zero-iteration probe: its body
       tightens the range, but entering with [0,63] and taking the break immediately
       leaves [0,63] at the store, so it must still be rejected. */
    const struct { enum loop_body body; int init_mask; } arms[] = {
        { LB_NOP,     7  },   /* control: back-edge alone must not change a verdict */
        { LB_MASK,    7  },
        { LB_INCMASK, 7  },
        { LB_MASKINC, 7  },   /* [1,8] -- the exact off-by-one against incmask */
        { LB_SHR,     7  },
        { LB_XOR3,    7  },
        { LB_COND,    7  },
        { LB_INC,     7  },
        { LB_SHL,     7  },
        { LB_ADD8,    7  },
        { LB_MASK,    63 },   /* zero-iteration path: body narrows, entry does not */
        { LB_NOP,     63 },   /* control: wide entry, nothing narrows it */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_loop_prog(arms[i].body, arms[i].init_mask, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

static void run_generated_prune_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genprune type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The axis is the RELATION between the two merging states, crossed with the ORDER
       (which one checkpoints first). `dang.*` puts the SAFE state on the fall-through,
       so a wrong prune of the unsafe path would flip the decision to accept -- the
       only arms where a pruning bug is observable. `ctrl.*` is the mirror: the unsafe
       state checkpoints first and the safe one is legitimately subsumed, so a prune
       there is SOUND and proves the mechanism engages. `safe.*` accepts on both paths.
       A pure-tnum arm (same interval, different tnum) is deliberately ABSENT: the
       store's safety depends on umax alone, so no tnum difference can flip the
       decision -- it could only be a vacuous arm. */
    const struct { enum prune_shaper fall, taken; int stack; } arms[] = {
        { SH_N7,  SH_N7,  0 },   /* safe.eq    -- identical states, trivial prune */
        { SH_T6,  SH_N7,  0 },   /* safe.tnum  -- both safe, refined vs interval  */
        { SH_N7,  SH_W63, 0 },   /* dang.sup   -- superset arrives second         */
        { SH_N7,  SH_M39, 0 },   /* dang.disj  -- disjoint                        */
        { SH_N7,  SH_O19, 0 },   /* dang.ovl   -- overlapping                     */
        { SH_N7,  SH_S56, 0 },   /* dang.shift -- same umin, holey tnum           */
        { SH_N7,  SH_A32, 0 },   /* dang.alu32 -- 32-bit shaping path             */
        { SH_T6,  SH_W63, 0 },   /* dang.tnum  -- refined first, wide second      */
        { SH_W63, SH_N7,  0 },   /* ctrl.sup   -- sound prune (subset second)     */
        { SH_M39, SH_N7,  0 },   /* ctrl.disj                                     */
        { SH_O19, SH_N7,  0 },   /* ctrl.ovl                                      */
        { SH_S56, SH_N7,  0 },   /* ctrl.shift                                    */
        { SH_A32, SH_N7,  0 },   /* ctrl.alu32                                    */
        { SH_W63, SH_T6,  0 },   /* ctrl.tnum                                     */
        { SH_N7,  SH_W63, 1 },   /* stk.dang   -- the judge is stacksafe, not regsafe */
        { SH_W63, SH_N7,  1 },   /* stk.ctrl                                      */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_prune_prog(arms[i].fall, arms[i].taken, arms[i].stack, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}


int main(int argc, char **argv) {
    // Two data sources, kept apart on purpose (different provenance):
    //   (no args) the fixed authoritative program set, pinned by tests
    //   --gen     the enumerated targeted family (devlog 0025)
    if (argc > 1 && strcmp(argv[1], "--gen") == 0) {
        run_generated_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-mix") == 0) {
        run_mixed_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rr") == 0) {
        run_generated_rr_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-mb") == 0) {
        run_generated_mb_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-ptr") == 0) {
        run_generated_ptr_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-ptr-neg") == 0) {
        run_generated_ptrneg_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-t1") == 0) {
        run_probe_t1_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-ptr-hi") == 0) {
        run_generated_hi_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-t1b") == 0) {
        run_probe_t1b_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-sync") == 0) {
        run_generated_sync_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-pkt") == 0) {
        run_generated_pkt_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-pkt-cmp") == 0) {
        run_generated_pktcmp_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rt") == 0) {
        run_generated_rt_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rtw") == 0) {
        run_generated_rtw_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rtw2") == 0) {
        run_generated_rtw2_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-loc") == 0) {
        run_generated_loc_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-pktw") == 0) {
        run_probe_pktw_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-pktw") == 0) {
        run_generated_pktw_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-prune") == 0) {
        run_generated_prune_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-loop") == 0) {
        run_generated_loop_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-loopr") == 0) {
        run_probe_loopr();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-loopr") == 0) {
        run_generated_loopr_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-iter") == 0) {
        run_probe_iter();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-iter") == 0) {
        run_generated_iter_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-idmap") == 0) {
        run_generated_idmap_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-idpart") == 0) {
        run_generated_idpart_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-frame") == 0) {
        run_generated_frame_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-spill") == 0) {
        run_generated_spill_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-prec") == 0) {
        run_generated_prec_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-exact") == 0) {
        run_generated_exact_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rw") == 0) {
        run_generated_rw_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-dyn") == 0) {
        run_generated_dyn_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-comp") == 0) {
        run_generated_comp_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-fakereg") == 0) {
        run_probe_fakereg();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-sx") == 0) {
        run_probe_sx();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-idlink") == 0) {
        run_probe_idlink();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-spill") == 0) {
        run_probe_spill();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-deltalink") == 0) {
        run_probe_deltalink();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-jsetlive") == 0) {
        run_probe_jsetlive();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-maygotolive") == 0) {
        run_probe_maygotolive();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-livetraps") == 0) {
        run_probe_livetraps();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-idbase") == 0) {
        run_probe_idbase();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-mixwidth") == 0) {
        run_probe_mixwidth();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-wraparc2") == 0) {
        run_probe_wraparc2();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-jmp32prune") == 0) {
        run_probe_jmp32prune();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-wraparc") == 0) {
        run_probe_wraparc();
        return 0;
    }
    if (argc > 2 && strcmp(argv[1], "--fuzz-replay") == 0) {
        run_fuzz_replay(argv[2]);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--fuzz") == 0) {
        report_jit_mode(argc, argv);
        run_fuzz(argc > 2 ? atoi(argv[2]) : 300,
                 argc > 3 ? (unsigned)strtoul(argv[3], NULL, 0) : 0u);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-uninit") == 0) {
        run_probe_uninit();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-kcov") == 0) {
        run_probe_kcov();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-ref") == 0) {
        run_probe_ref();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-intent") == 0) {
        report_jit_mode(argc, argv);
        run_gen_intent_family();
        return 0;
    }

    // Program A: clean, minimal accepted prog — `return 0`.
    struct bpf_insn prog_return0[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    // Program B: some ALU to create richer register state, then return.
    //   r0 = 1; r0 <<= 3; r0 &= 0xff; r0 += 5; exit
    struct bpf_insn prog_alu[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 3),
        BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xff),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 5),
        BPF_EXIT_INSN(),
    };

    // Program C: deliberately invalid — exit with R0 uninitialized (reject).
    struct bpf_insn prog_uninit[] = {
        BPF_EXIT_INSN(),
    };

    // Program D: bounded unknown scalar — read a ctx u32 (skb->len, unknown),
    // mask to 0..255. Produces the FULL scalar form: var_off=(0x0; 0xff).
    struct bpf_insn prog_ranged_and[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
        BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xff),
        BPF_EXIT_INSN(),
    };

    // Program E: unknown high bits — read a ctx u32, shift left 8 (low 8 bits
    // known-zero, the rest unknown). Exercises var_off mask with known-zero bits.
    struct bpf_insn prog_shift[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
        BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 8),
        BPF_EXIT_INSN(),
    };

    // Program F: comparison-narrowed bound — read a ctx u32, cap it at 10 via a
    // conditional. Exercises verifier bound narrowing (umax) on one path.
    struct bpf_insn prog_bounded[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
        BPF_JMP_IMM(BPF_JLE, BPF_REG_0, 10, 1),
        BPF_MOV64_IMM(BPF_REG_0, 10),
        BPF_EXIT_INSN(),
    };

    run_one("return0", prog_return0,
            (int)(sizeof(prog_return0) / sizeof(prog_return0[0])));
    run_one("alu_state", prog_alu,
            (int)(sizeof(prog_alu) / sizeof(prog_alu[0])));
    run_one("uninit_r0", prog_uninit,
            (int)(sizeof(prog_uninit) / sizeof(prog_uninit[0])));
    run_one("ranged_and", prog_ranged_and,
            (int)(sizeof(prog_ranged_and) / sizeof(prog_ranged_and[0])));
    run_one("shift_unknown", prog_shift,
            (int)(sizeof(prog_shift) / sizeof(prog_shift[0])));
    run_one("bounded_cmp", prog_bounded,
            (int)(sizeof(prog_bounded) / sizeof(prog_bounded[0])));
    run_map_lookup();
    run_documented_cases();
    run_documented_message_cases();
    return 0;
}
