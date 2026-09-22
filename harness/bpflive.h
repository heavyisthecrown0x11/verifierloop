/* bpflive.h — an INDEPENDENT live-register analysis for the eBPF subset this harness emits.
 *
 * WHY IT EXISTS. Since 0fb3cf6110a5 (2025-03, "use register liveness information for
 * func_states_equal") the verifier compares only the registers it believes are LIVE at the
 * instruction where two states meet:
 *
 *     u16 live_regs = env->insn_aux_data[insn_idx].live_regs_before;
 *     for (i = 0; i < MAX_BPF_REG; i++)
 *             if (((1 << i) & live_regs) && !regsafe(env, &old->regs[i], &cur->regs[i], ...))
 *                     return false;
 *
 * A register marked dead is not compared at all. So liveness is the GATE on every pruning
 * decision, and a register wrongly called dead is a prune that never had to justify itself.
 *
 * 0088 measured that the decision itself is unauditable: the prune record carries neither
 * state (verifier.c:18387-18392), and the log cannot even express the predicate's domain
 * (range_within is arc containment on cnum{base,size}; the log prints eight derived
 * projections). The GATE, however, IS printed — `Live regs before insn:` at BPF_LOG_LEVEL2
 * (liveness.c:2312) — and unlike the decision it is a property of the instruction stream
 * alone, so a second implementation can recompute it.
 *
 * INDEPENDENCE IS THE WHOLE POINT, so this file obeys bpfref.h's two rules:
 *   1. It consumes the EMITTED `struct bpf_insn` array, not the generator's intent.
 *   2. It shares no code with any emitter, and none with the kernel's liveness.c: the
 *      use/def sets are transcribed from the instruction-set semantics, not from
 *      compute_live_registers().
 *
 * SCOPE, and what it refuses rather than guesses. Single-frame programs over the subset the
 * harness emits: ALU/ALU64, LDX/STX/ST (incl. ATOMIC and MEMSX), LD_IMM64, JMP/JMP32,
 * JCOND (may_goto), helper CALL, EXIT. A BPF_PSEUDO_CALL (subprogram) makes the whole
 * program UNSUPPORTED — an interprocedural analysis is a different piece of work and
 * guessing it would be exactly the silence this project keeps finding. Same for an
 * out-of-range jump or an unknown opcode class.
 *
 * THE DIRECTION THAT MATTERS. If the kernel says LIVE where this says DEAD, the kernel is
 * being conservative and nothing is at risk. If the kernel says DEAD where this says LIVE,
 * a register that can still be read was excluded from the state comparison. Only the second
 * direction is a candidate finding — and, because it is also the direction a COARSER
 * analysis produces, this file has to be at least as precise as the kernel's before it is
 * allowed to judge. That is what the calibration arm measures.
 */
#ifndef BPFLIVE_H
#define BPFLIVE_H

#include <stdint.h>
#include <string.h>

#define BPFLIVE_MAXINSN 8192

enum bpflive_status {
    BPFLIVE_OK = 0,
    BPFLIVE_UNSUPPORTED,   /* opcode/shape outside the model — never a silent guess */
};

struct bpflive_result {
    int status;
    int n;                              /* instruction count */
    int unsupported_at;                 /* index that stopped us, -1 otherwise */
    const char *why;
    uint16_t live_before[BPFLIVE_MAXINSN];   /* bit j set = r_j is live before insn i */
};

/* The opcode pieces, spelled locally so this file depends on no header an emitter uses. */
#define BL_CLASS(c)   ((c) & 0x07)
#define BL_OP(c)      ((c) & 0xf0)
#define BL_SRC(c)     ((c) & 0x08)
#define BL_MODE(c)    ((c) & 0xe0)
#define BL_LD    0x00
#define BL_LDX   0x01
#define BL_ST    0x02
#define BL_STX   0x03
#define BL_ALU   0x04
#define BL_JMP   0x05
#define BL_JMP32 0x06
#define BL_ALU64 0x07
#define BL_MOV   0xb0
#define BL_END   0xd0
#define BL_CALL  0x80
#define BL_EXIT  0x90
#define BL_JA    0x00
#define BL_JCOND 0xe0
#define BL_IMM   0x00
#define BL_ATOMIC 0xc0
#define BL_DW    0x18   /* code of LD_IMM64: BPF_LD|BPF_DW|BPF_IMM */
#define BL_X     0x08
#define BL_FETCH 0x01
#define BL_XCHG  0xe1
#define BL_CMPXCHG 0xf1
#define BL_LOAD_ACQ  0x100
#define BL_STORE_REL 0x110

#define BL_BIT(r) ((uint16_t)1u << (r))
#define BL_TRACKED 0x03ff   /* r0..r9 — r10 is the frame pointer and is never compared */

/* Helper argument counts, keyed by helper id, for the helpers this harness emits. The
 * kernel learns these from the proto; we take them from the same public numbering the
 * emitters use, which is not the liveness code.
 *
 * AN UNLISTED HELPER IS REFUSED, NOT GUESSED. The first version returned 5 for anything
 * unlisted, reasoning that claiming MORE registers live is the conservative choice. That is
 * backwards: "more live" is exactly the direction check_liveness_gate reports as a finding,
 * so an unlisted helper is a standing FALSE CLAIM in the one direction that matters. The
 * kernel's own compute_live_registers.c selftest proved it on bpf_trace_printk (id 6, two
 * args by its proto), where the guess of five falsely claimed r3/r4/r5 live across five
 * rows. Refusing costs a program; guessing costs the oracle's credibility. */
static int bpflive_helper_argc(int imm) {
    switch (imm) {
    case 1:  return 2;   /* map_lookup_elem(map, key)                    */
    case 2:  return 4;   /* map_update_elem(map, key, value, flags)      */
    case 3:  return 2;   /* map_delete_elem(map, key)                    */
    case 7:  return 0;   /* get_prandom_u32()                            */
    case 84: return 5;   /* sk_lookup_tcp(ctx, tuple, len, netns, flags) */
    case 86: return 1;   /* sk_release(sk)                               */
    case 197: return 4;  /* dynptr_from_mem(data, size, flags, dynptr)   */
    case 198: return 4;  /* ringbuf_reserve_dynptr(rb, size, fl, ptr)    */
    case 199: return 2;  /* ringbuf_submit_dynptr(ptr, flags)            */
    case 200: return 2;  /* ringbuf_discard_dynptr(ptr, flags)           */
    case 6:  return 2;   /* trace_printk(fmt, fmt_size)                 */
    default: return -1;  /* unlisted: refuse the program, never guess    */
    }
}

/* KFUNCS. A kfunc call has a helper's register discipline (args in r1.., return in r0,
 * r0-r5 clobbered) but its `imm` is a BTF id resolved against the running kernel, so the
 * argument count cannot be read off the bytes alone. The harness resolves those ids itself
 * — walking /sys/kernel/btf/vmlinux, which is not the liveness code — and registers them
 * here with the arity of the kfunc's published signature. An UNREGISTERED kfunc is refused,
 * exactly like an unknown opcode: guessing five arguments would claim r1-r5 live and
 * manufacture findings out of this file's own ignorance, which is the one direction that
 * must never be approximated. */
struct bpflive_kfunc { int btf_id; int argc; };
static struct bpflive_kfunc bpflive_kfuncs[32];
static int bpflive_nkfunc = 0;

static void bpflive_register_kfunc(int btf_id, int argc) {
    if (btf_id <= 0 || bpflive_nkfunc >= (int)(sizeof(bpflive_kfuncs)/sizeof(bpflive_kfuncs[0])))
        return;
    for (int i = 0; i < bpflive_nkfunc; i++)
        if (bpflive_kfuncs[i].btf_id == btf_id) return;
    bpflive_kfuncs[bpflive_nkfunc].btf_id = btf_id;
    bpflive_kfuncs[bpflive_nkfunc].argc = argc;
    bpflive_nkfunc++;
}

static int bpflive_kfunc_argc(int btf_id) {
    for (int i = 0; i < bpflive_nkfunc; i++)
        if (bpflive_kfuncs[i].btf_id == btf_id) return bpflive_kfuncs[i].argc;
    return -1;
}

/* use/def for one instruction. Returns 0 on an opcode outside the model. */
static int bpflive_usedef(const struct bpf_insn *in, uint16_t *use, uint16_t *def) {
    const uint8_t code = in->code;
    const uint8_t cls = BL_CLASS(code);
    const uint16_t d = BL_BIT(in->dst_reg), s = BL_BIT(in->src_reg);
    *use = 0; *def = 0;

    switch (cls) {
    case BL_ALU:
    case BL_ALU64:
        if (BL_OP(code) == BL_END) {          /* byteswap: reads and writes dst */
            *use = d; *def = d; return 1;
        }
        *def = d;
        /* MOV overwrites dst without reading it; every other ALU op reads it. */
        if (BL_OP(code) != BL_MOV) *use |= d;
        if (BL_SRC(code) == BL_X) *use |= s;
        return 1;
    case BL_LDX:
        *def = d; *use = s; return 1;
    case BL_ST:
        *use = d; return 1;
    case BL_STX:
        if (BL_MODE(code) == BL_ATOMIC) {
            /* An atomic reads the address and the operand. The FETCH variants also WRITE
               the operand register back, and CMPXCHG additionally reads AND writes r0. */
            /* BPF_LOAD_ACQ is the one atomic whose operands are REVERSED: dst is the value
               destination and src is the address -- a load, not a store. Its imm is 0x100,
               so the FETCH bit is clear and the ordinary rule below would call it a READ of
               the destination. The kernel's compute_live_registers.c pins the opposite, and
               getting it wrong propagated backwards through five rows. */
            if (in->imm == BL_LOAD_ACQ) { *def = d; *use = s; return 1; }
            if (in->imm == BL_STORE_REL) { *use = d | s; return 1; }
            *use = d | s;
            if (in->imm & BL_FETCH) *def |= s;
            if ((in->imm & 0xff) == (int)(BL_CMPXCHG & 0xff)) { *use |= BL_BIT(0); *def |= BL_BIT(0); }
            return 1;
        }
        *use = d | s; return 1;
    case BL_LD:
        if (code == BL_DW) { *def = d; return 1; }   /* LD_IMM64 (incl. map fd) */
        return 0;                                     /* LD_ABS/LD_IND: not emitted */
    case BL_JMP:
    case BL_JMP32:
        switch (BL_OP(code)) {
        case BL_EXIT: *use = BL_BIT(0); return 1;     /* the return value */
        case BL_JA:   return 1;                        /* unconditional: reads nothing */
        case BL_JCOND: return 1;                       /* may_goto: reads nothing */
        case BL_CALL: {
            int argc;
            if (in->src_reg == 1) return 0;            /* PSEUDO_CALL: interprocedural, out of model */
            if (in->src_reg == 2) {                    /* PSEUDO_KFUNC_CALL */
                argc = bpflive_kfunc_argc(in->imm);
                if (argc < 0) return 0;                /* unregistered: refuse, never guess */
            } else if (in->src_reg == 0) {
                argc = bpflive_helper_argc(in->imm);
                if (argc < 0) return 0;                /* unlisted helper: refuse */
            } else {
                return 0;
            }
            for (int r = 1; r <= argc; r++) *use |= BL_BIT(r);
            /* A helper call clobbers r0-r5. */
            for (int r = 0; r <= 5; r++) *def |= BL_BIT(r);
            return 1;
        }
        default:
            *use = d;
            if (BL_SRC(code) == BL_X) *use |= s;
            return 1;
        }
    default:
        return 0;
    }
}

/* Successors of insn i, written into succ[], returns the count (or -1 if out of model). */
static int bpflive_succ(const struct bpf_insn *ins, int n, int i, int *succ) {
    const uint8_t code = ins[i].code;
    const uint8_t cls = BL_CLASS(code);
    const int next = (code == BL_DW) ? i + 2 : i + 1;   /* LD_IMM64 occupies two slots */
    int k = 0;
    if (cls != BL_JMP && cls != BL_JMP32) {
        if (next >= n) return -1;
        succ[k++] = next; return k;
    }
    switch (BL_OP(code)) {
    case BL_EXIT: return 0;                    /* single frame: exit leaves the program */
    case BL_CALL: if (next >= n) return -1; succ[k++] = next; return k;
    case BL_JA: {
        /* `gotox` is BPF_JA with BPF_X: the target comes from a register via a jump table,
           so there is no static successor set. Refused rather than silently read as a
           fall-through, which is what reading `off` would have done. */
        if (BL_SRC(code) == BL_X) return -1;
        /* `gotol` is BPF_JMP32|BPF_JA and carries its offset in imm, not off — a long jump.
           Reading `off` there yields 0 and makes the jump look like a fall-through, which
           silently mis-computes liveness for every instruction after it. Found by reading
           the kernel's own compute_live_registers.c selftest, which has a `gotol` case. */
        int disp = (cls == BL_JMP32) ? ins[i].imm : ins[i].off;
        int t = i + 1 + disp;
        if (t < 0 || t >= n) return -1;
        succ[k++] = t; return k;
    }
    default: {                                  /* conditional, and may_goto */
        int t = i + 1 + ins[i].off;
        if (t < 0 || t >= n || next > n) return -1;
        succ[k++] = t;
        if (next < n) succ[k++] = next;
        return k;
    }
    }
}

/* The analysis: live_before[i] = use[i] | (union of live_before[succ] & ~def[i]).
   Backward dataflow to a fixed point; liveness is a may-analysis so the least fixed point
   reached by iterating to stability is the exact answer for this CFG. */
static void bpflive_run(const struct bpf_insn *ins, int n, struct bpflive_result *out) {
    memset(out, 0, sizeof(*out));
    out->n = n; out->unsupported_at = -1; out->status = BPFLIVE_OK; out->why = "";
    if (n <= 0 || n > BPFLIVE_MAXINSN) {
        out->status = BPFLIVE_UNSUPPORTED; out->why = "insn count out of range"; return;
    }
    static uint16_t use[BPFLIVE_MAXINSN], def[BPFLIVE_MAXINSN];
    static int succ[BPFLIVE_MAXINSN][2], nsucc[BPFLIVE_MAXINSN];
    static uint8_t skip[BPFLIVE_MAXINSN];
    memset(skip, 0, sizeof(uint8_t) * n);

    for (int i = 0; i < n; i++) {
        if (skip[i]) { nsucc[i] = 0; use[i] = def[i] = 0; continue; }
        if (!bpflive_usedef(&ins[i], &use[i], &def[i])) {
            out->status = BPFLIVE_UNSUPPORTED; out->unsupported_at = i;
            out->why = "opcode outside the model"; return;
        }
        int k = bpflive_succ(ins, n, i, succ[i]);
        if (k < 0) {
            out->status = BPFLIVE_UNSUPPORTED; out->unsupported_at = i;
            out->why = "jump target out of range"; return;
        }
        nsucc[i] = k;
        if (ins[i].code == BL_DW && i + 1 < n) skip[i + 1] = 1;   /* the imm64 tail */
    }

    for (int changed = 1, guard = 0; changed && guard < 4 * BPFLIVE_MAXINSN; guard++) {
        changed = 0;
        for (int i = n - 1; i >= 0; i--) {
            if (skip[i]) continue;
            uint16_t after = 0;
            for (int k = 0; k < nsucc[i]; k++) after |= out->live_before[succ[i][k]];
            uint16_t v = (uint16_t)((use[i] | (after & (uint16_t)~def[i])) & BL_TRACKED);
            if (v != out->live_before[i]) { out->live_before[i] = v; changed = 1; }
        }
    }
}

/* Emit the claim the pipeline compares against the kernel's printed table. One line per
   program, hex, 10 bits per instruction — compact enough that a 900-program corpus grows by
   a fraction of what a per-instruction line would cost. `n` is the instruction count so the
   consumer can tell a truncated claim from a short program. */
static void bpflive_print_claim(const struct bpf_insn *ins, int n) {
    struct bpflive_result r;
    bpflive_run(ins, n, &r);
    if (r.status != BPFLIVE_OK) {
        printf("LIVENESS status=unsupported n=%d at=%d why=%s\n", n, r.unsupported_at, r.why);
        return;
    }
    printf("LIVENESS status=ok n=%d mask=", n);
    for (int i = 0; i < n; i++) printf("%03x", r.live_before[i] & BL_TRACKED);
    printf("\n");
}

/* ---- comparing against the kernel's printed table, in-VM ------------------------------
 *
 * The fuzz loop runs hundreds of thousands of programs, so it cannot emit a claim per
 * program and let the pipeline compare them — that is gigabytes of log for a number. The
 * comparison therefore happens here, and only the AGGREGATES plus any actual disagreement
 * leave the VM. Same predicate as `check_liveness_gate` in diff.rs, same direction: only a
 * cell this model calls LIVE can fail, and only the kernel calling it DEAD is a finding.
 */
struct bpflive_cmp {
    int status;        /* BPFLIVE_OK, or BPFLIVE_UNSUPPORTED when the model declined  */
    int rows;          /* table rows the kernel printed and we could pair             */
    int checked;       /* cells that COULD have fired: this model says LIVE           */
    int overreach;     /* cells where the kernel says DEAD and this model says LIVE   */
    int first_insn;    /* the first such cell, for triage                             */
    int first_reg;
    int kmask, omask;  /* and both masks at that row                                  */
};

/* Parse one row of `Live regs before insn:` out of a log buffer. `p` points at the start of
   a line; returns the line's end, or NULL when the line is not a table row. The instruction
   index is the LAST whitespace-separated token before the colon — liveness.c prints an
   optional SCC id ahead of it (`%3d ` then `%3d: `), and taking the first digits instead
   parses row 20 of SCC 2 as row 0. That mistake was made once, while measuring this very
   channel. */
static const char *bpflive_parse_row(const char *p, int *idx, uint16_t *mask) {
    if (*p != ' ') return NULL;
    const char *colon = p;
    while (*colon && *colon != ':' && *colon != '\n') colon++;
    if (*colon != ':') return NULL;
    const char *q = colon;                       /* walk back over the index digits */
    while (q > p && q[-1] >= '0' && q[-1] <= '9') q--;
    if (q == colon) return NULL;
    int v = 0;
    for (const char *d = q; d < colon; d++) v = v * 10 + (*d - '0');
    const char *cols = colon + 1;
    if (*cols != ' ') return NULL;
    cols++;
    uint16_t m = 0;
    for (int j = 0; j < 10; j++) {
        char c = cols[j];
        if (c != '.' && (c < '0' || c > '9')) return NULL;
        if (c != '.') m |= BL_BIT(j);
    }
    if (cols[10] != ' ') return NULL;
    *idx = v; *mask = m;
    const char *eol = cols;
    while (*eol && *eol != '\n') eol++;
    return eol;
}

static void bpflive_compare_log(const struct bpf_insn *ins, int n, const char *log,
                                struct bpflive_cmp *out) {
    memset(out, 0, sizeof(*out));
    out->first_insn = -1; out->first_reg = -1;
    struct bpflive_result r;
    bpflive_run(ins, n, &r);
    out->status = r.status;
    if (r.status != BPFLIVE_OK) return;

    const char *t = strstr(log, "Live regs before insn:");
    if (!t) { out->status = BPFLIVE_UNSUPPORTED; return; }   /* no table: nothing to compare */
    t = strchr(t, '\n');
    if (!t) { out->status = BPFLIVE_UNSUPPORTED; return; }
    t++;
    for (;;) {
        int idx; uint16_t kmask;
        const char *eol = bpflive_parse_row(t, &idx, &kmask);
        if (!eol) break;                          /* the table is one contiguous block */
        if (idx >= 0 && idx < n) {
            out->rows++;
            uint16_t ours = r.live_before[idx];
            for (int reg = 0; reg < 10; reg++) {
                uint16_t bit = BL_BIT(reg);
                if (!(ours & bit)) continue;      /* we say dead: the kernel cannot overreach */
                out->checked++;
                if (kmask & bit) continue;
                out->overreach++;
                if (out->first_insn < 0) {
                    out->first_insn = idx; out->first_reg = reg;
                    out->kmask = kmask; out->omask = ours;
                }
            }
        }
        if (*eol != '\n') break;
        t = eol + 1;
    }
}

#endif /* BPFLIVE_H */
