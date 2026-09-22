/* bpfref.h — an INDEPENDENT reference interpreter for the eBPF subset this harness emits.
 *
 * WHY IT EXISTS. Every oracle in this project until 0071 used the kernel as its own
 * reference: the verifier compared against itself, or a runtime observation compared
 * against the verifier's printed claim. 0070 measured what that costs — when the verifier
 * is confidently wrong, `bpf_opt_hard_wire_dead_code_branches()` bakes the wrong belief
 * into the emitted program, so the run agrees with the wrong proof and every such oracle
 * is silent. The only way out is a second implementation of the ISA that never consults
 * the kernel at all.
 *
 * INDEPENDENCE IS THE WHOLE POINT, so this file obeys two rules:
 *   1. It consumes the EMITTED `struct bpf_insn` array, not the generator's intent. If a
 *      generator emits something other than what it meant, this follows the bytes.
 *   2. It shares no code with any emitter. Its only input is the instruction stream.
 *
 * Semantics are transcribed from kernel/bpf/core.c's ___bpf_prog_run() plus the
 * instruction-set standardisation document, with the fifteen places a naive implementation
 * goes wrong called out at their site. `probe-ref` runs those fifteen against the real
 * kernel and requires agreement, so this file is calibrated rather than merely believed.
 *
 * SCOPE: ALU/ALU64 (K and X), MOV/MOVSX, JMP/JMP32, LD_IMM64, stack LDX/STX/ST including
 * MEMSX, EXIT. No helpers, no maps, no pointers other than the frame pointer. A program
 * using anything else is reported as UNSUPPORTED rather than guessed at.
 */
#ifndef BPFREF_H
#define BPFREF_H

#include <stdint.h>
#include <string.h>

#define BPFREF_STACK 512
/* Two memory regions, addressed numerically so the interpreter can follow a pointer the
   program COPIES and offsets rather than only recognising a hardcoded base register. The
   bases are arbitrary but far apart, so an access that lands in neither is a genuine
   out-of-range rather than an accident of layout. */
#define BPFREF_STACK_BASE 0x20000UL
#define BPFREF_MAP_BASE   0x10000UL
#define BPFREF_MAP_SIZE   16
#define BPFREF_PKT_BASE   0x30000UL
#define BPFREF_PKT_SIZE   64
/* The packet the harness hands to BPF_PROG_TEST_RUN. Its CONTENT has to be identical on
   both sides or every packet read becomes a false disagreement, so the pattern is defined
   here once and the harness fills its buffer from the same rule. A zero-filled packet would
   be worse than useless: every read would return 0 and a wrong address would be
   indistinguishable from a right one. */
#define BPFREF_PKT_BYTE(i) ((unsigned char)(((i) * 7 + 13) & 0xff))

/* Which pointer registers the harness has pre-loaded before the body starts. */
#define BPFREF_R_MAP 0x1
#define BPFREF_R_PKT 0x2

enum bpfref_status {
    BPFREF_OK = 0,
    BPFREF_UNSUPPORTED,   /* an opcode outside the modelled subset */
    BPFREF_OOB,           /* a stack access outside [-512, 0)      */
    BPFREF_LOOP,          /* instruction budget exhausted          */
    BPFREF_BADPC,         /* control flow left the program         */
};

struct bpfref_result {
    enum bpfref_status status;
    uint64_t retval;      /* valid only when status == BPFREF_OK */
    int fault_pc;         /* where it stopped, for triage        */
    uint8_t fault_code;
};

/* The subset's opcode pieces, spelled out locally so this file depends on no header the
   emitters also use. */
#define BR_CLASS(c)  ((c) & 0x07)
#define BR_OP(c)     ((c) & 0xf0)
#define BR_SRC(c)    ((c) & 0x08)
#define BR_SIZE(c)   ((c) & 0x18)
#define BR_MODE(c)   ((c) & 0xe0)

#define BR_LD 0x00
#define BR_LDX 0x01
#define BR_ST 0x02
#define BR_STX 0x03
#define BR_ALU 0x04
#define BR_JMP 0x05
#define BR_JMP32 0x06
#define BR_ALU64 0x07

/* Resolve an address to a region. Returns the byte pointer, or NULL when the access is
   out of every region — which for a program the verifier ACCEPTED would itself be worth
   knowing, and is reported as BPFREF_OOB rather than guessed at. */
static inline unsigned char *bpfref_resolve(unsigned char *stack, unsigned char *map,
                                            unsigned char *pkt, uint64_t addr, int size) {
    if (addr >= BPFREF_STACK_BASE - BPFREF_STACK && addr + (uint64_t)size <= BPFREF_STACK_BASE)
        return stack + (addr - (BPFREF_STACK_BASE - BPFREF_STACK));
    if (addr >= BPFREF_MAP_BASE && addr + (uint64_t)size <= BPFREF_MAP_BASE + BPFREF_MAP_SIZE)
        return map + (addr - BPFREF_MAP_BASE);
    if (addr >= BPFREF_PKT_BASE && addr + (uint64_t)size <= BPFREF_PKT_BASE + BPFREF_PKT_SIZE)
        return pkt + (addr - BPFREF_PKT_BASE);
    return NULL;
}

static struct bpfref_result bpfref_run_at2(const struct bpf_insn *ins, int n, int start_pc,
                                           uint64_t ctx, uint64_t s6, uint64_t s7,
                                           uint64_t s9, int regions);

/* The general entry point: begin at `start_pc` with r6/r7/r9 preloaded.
 *
 * `bpfref_run` (start at 0, all registers zero) and `bpfref_run_seeded` are the two ways
 * in. r10 is the frame pointer; its numeric value is never observed by this subset. */
static struct bpfref_result bpfref_run_at(const struct bpf_insn *ins, int n, int start_pc,
                                          uint64_t ctx, uint64_t s6, uint64_t s7,
                                          uint64_t s9) {
    return bpfref_run_at2(ins, n, start_pc, ctx, s6, s7, s9, 0);
}

static struct bpfref_result bpfref_run_at2(const struct bpf_insn *ins, int n, int start_pc,
                                           uint64_t ctx, uint64_t s6, uint64_t s7,
                                           uint64_t s9, int regions) {
    struct bpfref_result out;
    memset(&out, 0, sizeof(out));
    uint64_t r[11];
    memset(r, 0, sizeof(r));
    unsigned char stack[BPFREF_STACK];
    unsigned char map[BPFREF_MAP_SIZE];
    unsigned char pkt[BPFREF_PKT_SIZE];
    memset(stack, 0, sizeof(stack));
    memset(map, 0, sizeof(map));
    for (int i = 0; i < BPFREF_PKT_SIZE; i++) pkt[i] = BPFREF_PKT_BYTE(i);
    r[1] = ctx;
    r[6] = s6;
    r[7] = s7;
    r[9] = s9;
    r[10] = BPFREF_STACK_BASE;
    /* Which registers hold pointers is declared by the harness, never guessed at by the
       interpreter: r8 for a map value, r2/r3 for the packet's start and end. */
    if (regions & BPFREF_R_MAP) r[8] = BPFREF_MAP_BASE;
    if (regions & BPFREF_R_PKT) {
        r[2] = BPFREF_PKT_BASE;
        r[3] = BPFREF_PKT_BASE + BPFREF_PKT_SIZE;
    }

    long budget = 1L << 22;
    int pc = start_pc;
    while (1) {
        if (pc < 0 || pc >= n) { out.status = BPFREF_BADPC; out.fault_pc = pc; return out; }
        if (--budget < 0) { out.status = BPFREF_LOOP; out.fault_pc = pc; return out; }
        const struct bpf_insn *I = &ins[pc];
        const uint8_t code = (uint8_t)I->code;
        const int dst = I->dst_reg, src = I->src_reg;
        /* TRAP 12: `off` is SIGNED. Reading it unsigned turns fp-8 into fp+65528. */
        const int64_t off = (int64_t)(int16_t)I->off;
        /* TRAP 1/2: how `imm` widens is decided per class below, never here. */
        const int32_t imm = I->imm;
        const int cls = BR_CLASS(code);

        if (dst > 10 || src > 10) { out.status = BPFREF_UNSUPPORTED; goto fault; }

        switch (cls) {
        case BR_ALU:
        case BR_ALU64: {
            const int is64 = (cls == BR_ALU64);
            /* ALU64 K sign-extends; ALU K is a raw 32-bit pattern (TRAP 1). */
            const uint64_t k = is64 ? (uint64_t)(int64_t)imm : (uint64_t)(uint32_t)imm;
            const uint64_t v = BR_SRC(code) ? r[src] : k;
            uint64_t d = r[dst];
            uint64_t res;
            switch (BR_OP(code)) {
            case 0x00: res = is64 ? d + v : (uint32_t)((uint32_t)d + (uint32_t)v); break;
            case 0x10: res = is64 ? d - v : (uint32_t)((uint32_t)d - (uint32_t)v); break;
            case 0x20: res = is64 ? d * v : (uint32_t)((uint32_t)d * (uint32_t)v); break;
            case 0x40: res = is64 ? (d | v) : (uint32_t)((uint32_t)d | (uint32_t)v); break;
            case 0x50: res = is64 ? (d & v) : (uint32_t)((uint32_t)d & (uint32_t)v); break;
            case 0xa0: res = is64 ? (d ^ v) : (uint32_t)((uint32_t)d ^ (uint32_t)v); break;
            /* TRAP 15: the shift amount is masked ONLY for a register source. A K-sourced
               out-of-range shift is rejected at verify time and never reaches here. */
            case 0x60: {
                uint64_t s = BR_SRC(code) ? (is64 ? (v & 63) : (v & 31)) : v;
                res = is64 ? (d << s) : (uint32_t)((uint32_t)d << (uint32_t)s);
                break;
            }
            case 0x70: {
                uint64_t s = BR_SRC(code) ? (is64 ? (v & 63) : (v & 31)) : v;
                res = is64 ? (d >> s) : (uint32_t)((uint32_t)d >> (uint32_t)s);
                break;
            }
            /* TRAP: ARSH in the 32-bit class takes its sign from bit 31 of the LOW half and
               discards the upper half entirely. */
            case 0xc0: {
                uint64_t s = BR_SRC(code) ? (is64 ? (v & 63) : (v & 31)) : v;
                res = is64 ? (uint64_t)(((int64_t)d) >> s)
                           : (uint32_t)(((int32_t)(uint32_t)d) >> (uint32_t)s);
                break;
            }
            /* TRAP 6: negation of the minimum value WRAPS; it must not trap or saturate. */
            case 0x80: res = is64 ? (uint64_t)(0 - d) : (uint32_t)(0 - (uint32_t)d); break;
            case 0xb0: { /* MOV / MOVSX */
                if (I->off == 0) {
                    /* TRAP 1 again: `w1 = -1` is 0x00000000ffffffff, `r1 = -1` is all ones. */
                    res = is64 ? v : (uint32_t)v;
                } else if (BR_SRC(code)) {
                    /* TRAP 10: in the 32-bit class the sign extension stops at 32 bits and
                       the result is THEN zero-extended; in ALU64 it goes straight to 64. */
                    int64_t sx;
                    switch (I->off) {
                    case 8:  sx = (int8_t)v; break;
                    case 16: sx = (int16_t)v; break;
                    case 32: sx = (int32_t)v; break;
                    default: out.status = BPFREF_UNSUPPORTED; goto fault;
                    }
                    res = is64 ? (uint64_t)sx : (uint32_t)(int32_t)sx;
                } else {
                    out.status = BPFREF_UNSUPPORTED; goto fault; /* MOVSX is X-only */
                }
                break;
            }
            /* DIV / MOD. The zero and MIN/-1 cases below are the ISA's documented results;
               the real kernel produces them by REWRITING the bytecode before execution
               (kernel/bpf/fixups.c), not in the interpreter's opcode body — so transcribing
               core.c literally here would be wrong. off==1 selects the signed forms. */
            case 0x30: { /* DIV */
                if (I->off == 0) {
                    if (is64) res = v ? d / v : 0;
                    else { uint32_t a = (uint32_t)d, b = (uint32_t)v; res = (uint32_t)(b ? a / b : 0); }
                } else if (I->off == 1) {
                    if (is64) {
                        int64_t a = (int64_t)d, b = (int64_t)v;
                        res = b == 0 ? 0
                            : (b == -1 && a == INT64_MIN) ? (uint64_t)a
                            : (uint64_t)(a / b);
                    } else {
                        int32_t a = (int32_t)(uint32_t)d, b = (int32_t)(uint32_t)v;
                        int32_t q = b == 0 ? 0
                                  : (b == -1 && a == INT32_MIN) ? a
                                  : a / b;
                        res = (uint32_t)q;
                    }
                } else { out.status = BPFREF_UNSUPPORTED; goto fault; }
                break;
            }
            case 0x90: { /* MOD */
                if (I->off == 0) {
                    if (is64) res = v ? d % v : d;
                    /* TRAP 11: the 32-bit form still zero-extends on the zero-divisor path,
                       unlike ALU64 MOD which leaves the destination completely untouched. */
                    else { uint32_t a = (uint32_t)d, b = (uint32_t)v; res = (uint32_t)(b ? a % b : a); }
                } else if (I->off == 1) {
                    if (is64) {
                        int64_t a = (int64_t)d, b = (int64_t)v;
                        res = b == 0 ? d
                            : (b == -1 && a == INT64_MIN) ? 0
                            : (uint64_t)(a % b);
                    } else {
                        int32_t a = (int32_t)(uint32_t)d, b = (int32_t)(uint32_t)v;
                        int32_t m = b == 0 ? a
                                  : (b == -1 && a == INT32_MIN) ? 0
                                  : a % b;
                        res = (uint32_t)m;
                    }
                } else { out.status = BPFREF_UNSUPPORTED; goto fault; }
                break;
            }
            default: out.status = BPFREF_UNSUPPORTED; goto fault;
            }
            /* TRAP 2: the 32-bit class zero-extends on EVERY op, MOV and NEG included.
               That is already ensured by the (uint32_t) casts above. */
            r[dst] = res;
            pc++;
            continue;
        }

        case BR_LD: {
            /* TRAP 13: LD_IMM64 occupies TWO slots and the pc must advance by two. */
            if (code == (BR_LD | 0x00 | 0x18)) {
                if (src != 0) { out.status = BPFREF_UNSUPPORTED; goto fault; }
                if (pc + 1 >= n) { out.status = BPFREF_BADPC; goto fault; }
                r[dst] = (uint64_t)(uint32_t)imm
                       | ((uint64_t)(uint32_t)ins[pc + 1].imm << 32);
                pc += 2;
                continue;
            }
            out.status = BPFREF_UNSUPPORTED; goto fault;
        }

        case BR_LDX: {
            const int size = BR_SIZE(code);
            const int w = size == 0x10 ? 1 : size == 0x08 ? 2 : size == 0x00 ? 4 : 8;
            const unsigned char *p = bpfref_resolve(stack, map, pkt, r[src] + (uint64_t)off, w);
            if (!p) { out.status = BPFREF_OOB; goto fault; }
            uint64_t raw = 0;
            memcpy(&raw, p, (size_t)w);
            if (BR_MODE(code) == 0x60) {
                /* TRAP 9: an ordinary load always zero-extends, even a byte of 0xff. */
                r[dst] = raw;
            } else if (BR_MODE(code) == 0x80) {
                /* TRAP 8: MEMSX sign-extends into the FULL 64-bit register — it does not
                   stop at 32 bits the way a 32-bit ALU op would. */
                int64_t sx;
                switch (w) {
                case 1: sx = (int8_t)raw; break;
                case 2: sx = (int16_t)raw; break;
                case 4: sx = (int32_t)raw; break;
                default: out.status = BPFREF_UNSUPPORTED; goto fault;
                }
                r[dst] = (uint64_t)sx;
            } else { out.status = BPFREF_UNSUPPORTED; goto fault; }
            pc++;
            continue;
        }

        case BR_ST:
        case BR_STX: {
            /* ATOMICS. `BPF_STX | BPF_ATOMIC | size`, with `imm` selecting the operation.
               The kernel's own rule that an implementation gets wrong first is CMPXCHG's:
               r0 is loaded with the old value ALWAYS, not only on failure — x86's native
               CMPXCHG loads the accumulator only when the comparison fails, and
               39491867ace5 exists because the JIT once inherited that. The FETCH variants
               put the OLD value in the SOURCE register, and at 32-bit width that write
               zero-extends like any other 32-bit result. */
            if (cls == BR_STX && BR_MODE(code) == 0xc0) {
                const int size = BR_SIZE(code);
                if (size != 0x00 && size != 0x18) { out.status = BPFREF_UNSUPPORTED; goto fault; }
                const int w = (size == 0x00) ? 4 : 8;
                unsigned char *p = bpfref_resolve(stack, map, pkt, r[dst] + (uint64_t)off, w);
                if (!p) { out.status = BPFREF_OOB; goto fault; }
                uint64_t old = 0;
                memcpy(&old, p, (size_t)w);
                const int fetch = (imm & 0x01) != 0;
                const int aop = imm & ~0x01;
                uint64_t sv = (w == 4) ? (uint64_t)(uint32_t)r[src] : r[src];
                uint64_t res;
                switch (aop) {
                case 0x00: res = old + sv; break;                 /* ADD  */
                case 0x40: res = old | sv; break;                 /* OR   */
                case 0x50: res = old & sv; break;                 /* AND  */
                case 0xa0: res = old ^ sv; break;                 /* XOR  */
                case 0xe0: res = sv; break;                       /* XCHG */
                case 0xf0: {                                      /* CMPXCHG */
                    uint64_t cmp = (w == 4) ? (uint64_t)(uint32_t)r[0] : r[0];
                    res = (old == cmp) ? sv : old;
                    /* r0 takes the old value unconditionally. */
                    r[0] = (w == 4) ? (uint64_t)(uint32_t)old : old;
                    break;
                }
                default: out.status = BPFREF_UNSUPPORTED; goto fault;
                }
                if (w == 4) res = (uint32_t)res;
                memcpy(p, &res, (size_t)w);
                if (fetch && aop != 0xf0)
                    r[src] = (w == 4) ? (uint64_t)(uint32_t)old : old;
                pc++;
                continue;
            }
            if (BR_MODE(code) != 0x60) { out.status = BPFREF_UNSUPPORTED; goto fault; }
            const int size = BR_SIZE(code);
            const int w = size == 0x10 ? 1 : size == 0x08 ? 2 : size == 0x00 ? 4 : 8;
            unsigned char *p = bpfref_resolve(stack, map, pkt, r[dst] + (uint64_t)off, w);
            if (!p) { out.status = BPFREF_OOB; goto fault; }
            uint64_t val;
            if (cls == BR_STX) {
                val = r[src];
            } else if (w == 8) {
                /* TRAP 7: a DW immediate store WIDENS — the s32 imm is sign-extended to 64
                   bits before the 8-byte write. This is the exact rule 811c363645b3 fixed
                   in the verifier's parallel bookkeeping. */
                val = (uint64_t)(int64_t)imm;
            } else {
                val = (uint64_t)(uint32_t)imm;   /* narrowing: raw low-order bytes */
            }
            memcpy(p, &val, (size_t)w);
            pc++;
            continue;
        }

        case BR_JMP:
        case BR_JMP32: {
            const int j32 = (cls == BR_JMP32);
            const int op = BR_OP(code);
            if (op == 0x90) {                       /* EXIT — JMP class only */
                if (j32) { out.status = BPFREF_UNSUPPORTED; goto fault; }
                out.status = BPFREF_OK;
                out.retval = r[0];
                return out;
            }
            if (op == 0x00) {                       /* JA */
                /* TRAP 14: the branch field depends on the CLASS — off for JMP, imm for
                   JMP32 — not on a uniform convention. */
                pc += 1 + (j32 ? (int)imm : (int)off);
                continue;
            }
            /* TRAP 3: JMP32 compares the LOW 32 bits and never inspects the upper half. */
            const uint64_t a = j32 ? (uint64_t)(uint32_t)r[dst] : r[dst];
            const uint64_t bk = j32 ? (uint64_t)(uint32_t)imm : (uint64_t)(int64_t)imm;
            const uint64_t b = BR_SRC(code)
                                 ? (j32 ? (uint64_t)(uint32_t)r[src] : r[src])
                                 : bk;
            const int64_t sa = j32 ? (int64_t)(int32_t)a : (int64_t)a;
            const int64_t sb = j32 ? (int64_t)(int32_t)b : (int64_t)b;
            int take;
            switch (op) {
            case 0x10: take = a == b; break;                 /* JEQ  */
            case 0x50: take = a != b; break;                 /* JNE  */
            case 0x20: take = a > b; break;                  /* JGT  */
            case 0x30: take = a >= b; break;                 /* JGE  */
            case 0xa0: take = a < b; break;                  /* JLT  */
            case 0xb0: take = a <= b; break;                 /* JLE  */
            case 0x40: take = (a & b) != 0; break;           /* JSET */
            case 0x60: take = sa > sb; break;                /* JSGT */
            case 0x70: take = sa >= sb; break;               /* JSGE */
            case 0xc0: take = sa < sb; break;                /* JSLT */
            case 0xd0: take = sa <= sb; break;               /* JSLE */
            default: out.status = BPFREF_UNSUPPORTED; goto fault;
            }
            pc += 1 + (take ? (int)off : 0);
            continue;
        }

        default:
            out.status = BPFREF_UNSUPPORTED;
            goto fault;
        }
    fault:
        out.fault_pc = pc;
        out.fault_code = code;
        return out;
    }
}

/* Run from instruction 0 with every register zero. */
static inline struct bpfref_result bpfref_run(const struct bpf_insn *ins, int n,
                                              uint64_t ctx) {
    return bpfref_run_at(ins, n, 0, ctx, 0, 0, 0);
}

/* Start at `start_pc` with three seed scalars already in r6/r7/r9.
 *
 * A program whose scalars are all compile-time constants gives the verifier's range
 * tracker nothing to get wrong, so the interesting families seed themselves from a map —
 * unknown to the verifier, known to the harness that wrote it a moment earlier. The fixed
 * prologue performing that lookup calls a helper and is outside this subset, so it is
 * SKIPPED rather than modelled: interpretation begins at the generated body, which is in
 * the subset, and still reads the emitted bytes rather than any generator's intent.
 *
 * The seeds arrive in the real program through `BPF_LDX_MEM(BPF_W, ...)`, so they are
 * zero-extended 32-bit values; the caller passes them already in that form. */
static inline struct bpfref_result bpfref_run_seeded(const struct bpf_insn *ins, int n,
                                                     int start_pc, uint64_t r6, uint64_t r7,
                                                     uint64_t r9) {
    return bpfref_run_at2(ins, n, start_pc, 0, r6, r7, r9, 0);
}

/* Same, for a family whose prologue also leaves a map-value pointer in r8. */
static inline struct bpfref_result bpfref_run_seeded_map(const struct bpf_insn *ins, int n,
                                                         int start_pc, uint64_t r6,
                                                         uint64_t r7, uint64_t r9) {
    return bpfref_run_at2(ins, n, start_pc, 0, r6, r7, r9, BPFREF_R_MAP);
}

/* Same again, for a family whose prologue also leaves the packet bounds in r2/r3. */
static inline struct bpfref_result bpfref_run_seeded_pkt(const struct bpf_insn *ins, int n,
                                                         int start_pc, uint64_t r6,
                                                         uint64_t r7, uint64_t r9) {
    return bpfref_run_at2(ins, n, start_pc, 0, r6, r7, r9,
                          BPFREF_R_MAP | BPFREF_R_PKT);
}

static inline const char *bpfref_status_name(enum bpfref_status s) {
    switch (s) {
    case BPFREF_OK: return "ok";
    case BPFREF_UNSUPPORTED: return "unsupported";
    case BPFREF_OOB: return "oob";
    case BPFREF_LOOP: return "loop";
    case BPFREF_BADPC: return "badpc";
    }
    return "?";
}

#endif /* BPFREF_H */
