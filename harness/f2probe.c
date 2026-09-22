// f2probe — HAND-WRITTEN, control-armed probe for F2 (sync_linked_regs empty-range).
//
// WHY A SEPARATE BINARY: diffharness.c is used by a concurrent hunt run and there is
// a single binary installed to the shared rootfs. So that this probe never touches that tool,
// it is entirely self-contained: its own macros, its own bpf() wrapper.
//
// ANSWERS THREE QUESTIONS SEPARATELY:
//   Gate 2 — what happens if an empty-range register enters a MEMORY ACCESS as base+offset?
//            (M1 store, M2 load). If accepted, it is run on a KASAN kernel.
//   Gate 3 — not a genome, a hand-written minimal program + THREE CONTROL ARMS. Each control
//            removes a single component; shows the violation depends on that component.
//
// Output is line-framed: F2 name=<name> flags=<0|inv> verdict=<accept|reject> errno=<n>
//                        viol=<0|1> ctx=<...> tail=<last line of the rejection>
//
// Build: cc -O2 -static -o harness/f2probe harness/f2probe.c

#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_ALU64_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                 \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_MOV64_IMM(DST, IMM)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K,                    \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_MOV64_REG(DST, SRC)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                    \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K,                   \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                                       \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_JMP_REG(OP, DST, SRC, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X,                   \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                                        \
    ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,              \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
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

static char g_log[1 << 22];

/* Variable part: the payload placed at the point where the violation occurs. Each variant diverges here. */
enum payload { PL_ALU, PL_STORE, PL_LOAD, PL_NONE, PL_CONVERGE, PL_KEEPLIVE, PL_MAYGOTO };

/* Control arms: each removes a SINGLE component.
   NO_ADDCONST — r7 = r6 but no +8       -> intersection {16}, not empty
   NO_LINK     — r7 loaded independently  -> sync_linked_regs never touches r6
   NO_UMIN     — no w6>3 branch           -> umin stays 0, intersection contains 0   */
enum arm { ARM_FULL, ARM_NO_ADDCONST, ARM_NO_LINK, ARM_NO_UMIN };

static int build(struct bpf_insn *p, int map_fd, enum arm arm, enum payload pl) {
    int n = 0;
    p[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    p[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    { struct bpf_insn ld[] = { BPF_LD_MAP_FD(BPF_REG_1, map_fd) };
      p[n++] = ld[0]; p[n++] = ld[1]; }
    p[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    int jnull = n;
    p[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);   /* off filled in later */
    p[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);     /* r8 = map_value ptr */
    p[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    p[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 9);    /* {0,1,8,9} */
    p[n++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 2);    /* {0,2,16,18} */

    if (arm != ARM_NO_UMIN) {
        p[n++] = BPF_JMP32_IMM(BPF_JGT, BPF_REG_6, 3, 1);  /* taken: umin 4 */
        p[n++] = BPF_MOV64_IMM(BPF_REG_9, 0);              /* skipped filler */
    }

    if (arm == ARM_NO_LINK) {
        /* r7 carries the same range but NO LINK: independent load + same arithmetic. */
        p[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
        p[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_7, 9);
        p[n++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, 2);
        p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 8);
    } else {
        p[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);      /* LINK: same id */
        if (arm != ARM_NO_ADDCONST)
            p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 8); /* BPF_ADD_CONST */
    }

    /* Impossible arm: the FALL-THROUGH arm of r7 > 16. The payload is placed there. */
    int npl = (pl == PL_ALU) ? 1 : (pl == PL_STORE ? 3 : (pl == PL_LOAD ? 3 :
              (pl == PL_CONVERGE ? 3 : (pl == PL_KEEPLIVE ? 4 :
              (pl == PL_MAYGOTO ? 3 : 0)))));
    p[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_7, 16, npl);

    switch (pl) {
    case PL_ALU:
        p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_6);
        break;
    case PL_STORE:
        p[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
        p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_6); /* ptr += empty scalar */
        p[n++] = BPF_ST_MEM(BPF_B, BPF_REG_1, 0, 0x41);
        break;
    case PL_LOAD:
        p[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_8);
        p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_1, BPF_REG_6);
        p[n++] = BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0);
        break;
    case PL_NONE: break;
    case PL_MAYGOTO:
        /* In KL the model was SILENT but never compared the range: the precision short-circuit
           (prec=0 && exact=NOT_EXACT) skipped the scalars. may_goto forces the prune
           with exact=RANGE_WITHIN (verifier.c is_may_goto_insn_at arm),
           so the short-circuit closes and the RECOMPUTED containment actually runs. */
        p[n++] = ((struct bpf_insn){.code = BPF_JMP | 0xe0 /* BPF_JCOND */,
                                    .dst_reg = 0, .src_reg = 0 /* BPF_MAY_GOTO */,
                                    .off = 1, .imm = 0});
        p[n++] = BPF_MOV64_IMM(BPF_REG_9, 1);
        p[n++] = BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, 0);   /* keep r6 LIVE */
        break;
    case PL_KEEPLIVE:
        /* To keep empty r6 LIVE WITHOUT REPAIRING it: read it as the SOURCE of a store.
           check_store_reg() does NOT apply reg_bounds_sanity_check to the source register
           (only check_load_mem applies it to the target, verifier.c:6703), so r6 stays
           empty. In front of it is a converging branch so a prune attempt is born; because r6
           is read below on that branch it enters live_regs_before and IS COMPARED. */
        p[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_8, 8);   /* fresh unknown */
        p[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_1, 5, 1);         /* not static */
        p[n++] = BPF_MOV64_IMM(BPF_REG_9, 1);
        p[n++] = BPF_STX_MEM(BPF_W, BPF_REG_8, BPF_REG_6, 0);   /* r6 IS READ */
        break;
    case PL_CONVERGE:
        /* No payload -> r6 stays unrepaired. Then a converging branch: the same instruction
           is visited with two different states, so a prune attempt is born. */
        p[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_8, 0, 1);
        p[n++] = BPF_MOV64_IMM(BPF_REG_9, 1);
        p[n++] = BPF_MOV64_IMM(BPF_REG_9, 2);
        break;
    }

    p[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    p[n++] = BPF_EXIT_INSN();
    p[jnull].off = n - jnull - 2;   /* if null, jump to the last two insns (r0=0; exit) */
    return n;
}

static void run(const char *name, int map_fd, enum arm arm, enum payload pl, uint32_t flags) {
    struct bpf_insn ins[64];
    int n = build(ins, map_fd, arm, pl);

    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insn_cnt = n;
    a.insns = (uint64_t)(unsigned long)ins;
    a.license = (uint64_t)(unsigned long)"GPL";
    a.log_level = 2;
    a.log_size = sizeof(g_log);
    a.log_buf = (uint64_t)(unsigned long)g_log;
    a.prog_flags = flags;
    g_log[0] = '\0';
    int fd = bpf(BPF_PROG_LOAD, &a, sizeof(a));
    int e = errno;

    const char *v = strstr(g_log, "REG INVARIANTS VIOLATION");
    char ctx[32] = "-";
    if (v) {
        const char *o = strchr(v, '('), *c = o ? strchr(o, ')') : NULL;
        if (o && c && (size_t)(c - o) < sizeof(ctx)) {
            size_t k = (size_t)(c - o - 1);
            memcpy(ctx, o + 1, k); ctx[k] = '\0';
        }
    }
    /* The reason for the rejection is the last non-empty line of the log; it is the only thing that explains the verdict. */
    /* We need the REASON for the rejection: print all of the last non-empty lines, skipping
       the "processed N insns" summary. Selecting a single line is fragile output -- in some
       rejections there is a blank line after the reason line. */
    char tail[400] = "-";
    if (fd < 0) {
        const char *lines[8]; int nl = 0;
        char *buf = strdup(g_log);
        for (char *t = strtok(buf, "\n"); t; t = strtok(NULL, "\n")) {
            if (!*t) continue;
            if (!strncmp(t, "processed ", 10)) continue;
            if (nl < 8) { lines[nl++] = t; }
            else { memmove(lines, lines + 1, 7 * sizeof(*lines)); lines[7] = t; }
        }
        tail[0] = '\0';
        for (int i = (nl > 3 ? nl - 3 : 0); i < nl; i++) {
            strncat(tail, lines[i], sizeof(tail) - strlen(tail) - 4);
            strncat(tail, " | ", sizeof(tail) - strlen(tail) - 1);
        }
        free(buf);
    }
    printf("F2 name=%-22s insns=%2d flags=%-3s verdict=%-6s errno=%-3d viol=%d ctx=%-10s\n     tail=%s\n",
           name, n, flags ? "inv" : "0", fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : e,
           v ? 1 : 0, ctx, tail);
    fflush(stdout);

    /* Gate 2's real question: what happens WHEN an accepted memory access is RUN?
       We learn this not from userspace but from the kernel's KASAN — so we just
       run it and look at what lands on the console. */
    if (fd >= 0 && (pl == PL_STORE || pl == PL_LOAD) && flags == 0) {
        char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)pkt;
        t.test.data_size_in = sizeof(pkt);
        t.test.repeat = 1;
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        printf("F2 RUN  name=%-22s testrun=%d errno=%d retval=0x%08x\n",
               name, r, r < 0 ? errno : 0, r < 0 ? 0 : (unsigned)t.test.retval);
        fflush(stdout);
    }
    if (fd >= 0) close(fd);
}

/* Part 3: the instrumented kernel prints PRUNEPAIR lines to the LOG BUFFER via verbose().
   So the log needs to be emitted as-is -- this is subsume-check.py's
   input. TEST_STATE_FREQ checkpoints every instruction, so the prune attempts are
   maximized; and so is the chance of the empty range falling into a prune pair. */
static void dump(const char *name, int map_fd, enum arm arm, enum payload pl, uint32_t flags) {
    struct bpf_insn ins[64];
    int n = build(ins, map_fd, arm, pl);
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insn_cnt = n;
    a.insns = (uint64_t)(unsigned long)ins;
    a.license = (uint64_t)(unsigned long)"GPL";
    a.log_level = 2;
    a.log_size = sizeof(g_log);
    a.log_buf = (uint64_t)(unsigned long)g_log;
    a.prog_flags = flags;
    g_log[0] = '\0';
    int fd = bpf(BPF_PROG_LOAD, &a, sizeof(a));
    int e = errno;
    printf("===P3PROG name=%s flags=%s verdict=%s errno=%d insns=%d ===\n",
           name, flags ? "freq" : "0", fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : e, n);
    printf("---LOG---\n%s\n---END---\n", g_log);
    fflush(stdout);
    if (fd >= 0) close(fd);
}

/* ---- H21 (1ffc85d9298e) trigger: the commit message's OWN example, verbatim ----
 *   1: r9 = pointer with range X      7: r9 += r7
 *   2: r6 = unbound scalar ID=a       8: *(u64 *)r9 = Y
 *   3: r7 = unbound scalar ID=b
 *   4: if (r6 > r7) goto +1          Path I  (1-6):    r6{id=b} r7{id=b}  -> r7 bounded
 *   5: r6 = r7                       Path II (1-4,6):  r6{id=a} r7{id=b}  -> r7 UNBOUNDED
 *   6: if (r6 > X) goto ...          Buggy regsafe: no check_ids on scalars -> I == II
 *   --- checkpoint ---               -> path II pruned into I -> UNSAFE store ACCEPTED.
 * 2023-06 buggy kernel: MOV of a scalar mints an id (the fix stops doing that for
 * constants only), so `r1 = r6` / `r2 = r7` give r6 and r7 distinct ids. */
static void dump_h21(const char *name, int map_fd, uint32_t flags) {
    struct bpf_insn p[32]; int n = 0;
    p[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    p[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    p[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    { struct bpf_insn ld[] = { BPF_LD_MAP_FD(BPF_REG_1, map_fd) }; p[n++] = ld[0]; p[n++] = ld[1]; }
    p[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    int jnull = n; p[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    p[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_0);            /* 1: ptr, range 64   */
    p[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0, 0);   /* 2: unbound scalar  */
    p[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 8);   /* 3: unbound scalar  */
    p[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);            /*    mint id=a on r6 */
    p[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_7);            /*    mint id=b on r7 */
    p[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_6, BPF_REG_7, 1);  /* 4                  */
    p[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_7);            /* 5: r6.id = b       */
    int jx = n; p[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 56, 0); /* 6: X = 64-8    */
    p[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_9, BPF_REG_7);   /* 7                  */
    p[n++] = BPF_ST_MEM(BPF_DW, BPF_REG_9, 0, 0x59);         /* 8: the store       */
    int exitl = n;
    p[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    p[n++] = BPF_EXIT_INSN();
    p[jnull].off = exitl - jnull - 1;
    p[jx].off    = exitl - jx - 1;

    union bpf_attr a; memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER; a.insn_cnt = n;
    a.insns = (uint64_t)(unsigned long)p; a.license = (uint64_t)(unsigned long)"GPL";
    a.log_level = 2; a.log_size = sizeof(g_log); a.log_buf = (uint64_t)(unsigned long)g_log;
    a.prog_flags = flags; g_log[0] = '\0';
    int fd = bpf(BPF_PROG_LOAD, &a, sizeof(a)); int e = errno;
    printf("===P3PROG name=%s flags=%s verdict=%s errno=%d insns=%d ===\n",
           name, flags ? "freq" : "0", fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : e, n);
    printf("---LOG---\n%s\n---END---\n", g_log); fflush(stdout);
    if (fd >= 0) close(fd);
}

int main(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 64;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) { printf("F2 ERROR map_create errno=%d\n", errno); return 1; }

    printf("F2 BEGIN\n");
    struct { const char *name; enum arm arm; enum payload pl; } T[] = {
        { "P0_alu",            ARM_FULL,          PL_ALU   },  /* reference: violation expected */
        { "C1_no_addconst",    ARM_NO_ADDCONST,   PL_ALU   },  /* control: not expected      */
        { "C2_no_link",        ARM_NO_LINK,       PL_ALU   },  /* control: not expected      */
        { "C3_no_umin",        ARM_NO_UMIN,       PL_ALU   },  /* control: not expected      */
        { "M1_store_via_ptr",  ARM_FULL,          PL_STORE },  /* GATE 2: store             */
        { "M2_load_via_ptr",   ARM_FULL,          PL_LOAD  },  /* GATE 2: load              */
        { "M3_store_no_link",  ARM_NO_LINK,       PL_STORE },  /* GATE 2 CONTROL: not empty */
        { "M4_load_no_link",   ARM_NO_LINK,       PL_LOAD  },  /* GATE 2 CONTROL: not empty */
        { "N0_no_payload",     ARM_FULL,          PL_NONE  },  /* what happens with no payload */
    };
    for (unsigned i = 0; i < sizeof(T)/sizeof(T[0]); i++) {
        run(T[i].name, map_fd, T[i].arm, T[i].pl, 0);
        run(T[i].name, map_fd, T[i].arm, T[i].pl, 1u << 7 /* BPF_F_TEST_REG_INVARIANTS */);
    }
    printf("F2 END\n");

    /* --- Part 3: PRUNEPAIR capture --- */
    printf("P3 BEGIN\n");
    dump("P0_alu",      map_fd, ARM_FULL, PL_ALU,      0);
    dump("P0_alu_freq", map_fd, ARM_FULL, PL_ALU,      1u << 3 /* TEST_STATE_FREQ */);
    dump("N0_none",     map_fd, ARM_FULL, PL_NONE,     0);
    dump("N0_none_freq",map_fd, ARM_FULL, PL_NONE,     1u << 3);
    dump("CV_conv",     map_fd, ARM_FULL, PL_CONVERGE, 0);
    dump("CV_conv_freq",map_fd, ARM_FULL, PL_CONVERGE, 1u << 3);
    dump("KL_keeplive",     map_fd, ARM_FULL, PL_KEEPLIVE, 0);
    dump("KL_keeplive_freq",map_fd, ARM_FULL, PL_KEEPLIVE, 1u << 3);
    dump("MG_maygoto",      map_fd, ARM_FULL, PL_MAYGOTO, 0);
    dump("MG_maygoto_freq", map_fd, ARM_FULL, PL_MAYGOTO, 1u << 3);
    printf("P3 END\n");

    /* --- Part 5: H21 visible-arm calibration (run on two kernels) --- */
    printf("P5 BEGIN\n");
    dump_h21("H21_scalar_ids",      map_fd, 0);
    dump_h21("H21_scalar_ids_freq", map_fd, 1u << 3);
    printf("P5 END\n");
    close(map_fd);
    return 0;
}
