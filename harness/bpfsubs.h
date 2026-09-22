/* bpfsubs.h — the subsumption model, IN-VM.
 *
 * WHY IT HAS TO LIVE HERE. `scripts/subsume-check.py` reads a capture off disk, and that is
 * fine for an 896-program corpus (11,996 PRUNEPAIR lines, ~18 MB). It is not fine for the
 * fuzz loop: ~1.5 KB of prune-pair dump per program at ~1900 programs/sec is ~10 GB of log
 * per hour, for a number. `bpflive.h` hit exactly this wall in 0094 and the answer was the
 * same one: do the comparison in the VM and let only AGGREGATES plus real disagreements out.
 *
 * A SECOND IMPLEMENTATION IS A COST, and this project only pays it deliberately. Here it is
 * forced by volume, not chosen — so the discipline is that this C model and the Python one
 * must agree on every capture we have, and that equality is a test, not a hope. The Python
 * model stays the reference: it is the one calibrated against real bugs (pairs thirteen,
 * fourteen and sixteen), and this file is calibrated against IT.
 *
 * SCOPE, stated rather than implied: this parses the same PRUNEPAIR/PRUNEPAIR_PFX lines the
 * patch emits at tip (cnum era). The min/max and 2021 era formats are NOT handled here —
 * the fuzz loop runs on tip, and a format this file cannot read must make it REFUSE, never
 * silently report zero. `unsupported` is that refusal, and it is reported.
 */
#ifndef BPFSUBS_H
#define BPFSUBS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define SUBS_MAXREG   24          /* 2 frames x 11 regs, with room */
#define SUBS_PFXHEX  160          /* offsetof(bpf_reg_state,id) is well under 80 bytes */
#define SUBS_SCALAR    1
#define SUBS_ADD_CONST (((uint32_t)1 << 31) | ((uint32_t)1 << 30))

struct subs_reg {
    int      key;                 /* fr * 16 + regno, so sorting is numeric   */
    int      t, delta, fno, prec;
    uint64_t vv, vm, b64, sz64;
    uint32_t b32, sz32, id, pid;
    int      have_pfx, vo;
    char     pfx[SUBS_PFXHEX];
};

struct bpfsubs_cmp {
    unsigned long pairs, agree, disagree, unmodelled;
    unsigned long nontrivial, scalar_cmp, ptr_cmp, shortcircuit, unsupported;
    unsigned long rows;           /* PRUNEPAIR lines SEEN, parsed or not.
                                   * Without it `pairs=0 unsupported=0` is ambiguous
                                   * between "no instrumentation in this kernel" and
                                   * "instrumented and nothing pruned" — two very
                                   * different facts that must not print the same. */
    char first[192];              /* the first disagreement, insn + arm       */
};

/* ---- the idmap, transcribed from states.c's check_ids/check_scalar_ids ---------------- */
struct subs_idmap { uint32_t o[64], c[64]; int n; uint32_t tmp; };

static int subs_check_ids(struct subs_idmap *m, uint32_t o, uint32_t c) {
    int i;
    if (!!o != !!c) return 0;
    if (o == 0) return 1;
    for (i = 0; i < m->n; i++) {
        if (m->o[i] == o) return m->c[i] == c;
        if (m->c[i] == c) return 0;
    }
    if (m->n >= (int)(sizeof(m->o) / sizeof(m->o[0]))) return 0;
    m->o[m->n] = o; m->c[m->n] = c; m->n++;
    return 1;
}

static int subs_check_scalar_ids(struct subs_idmap *m, uint32_t o, uint32_t c) {
    if (!o) return 1;
    if (!c) c = ++m->tmp;
    if (!subs_check_ids(m, o, c)) return 0;
    if (o & SUBS_ADD_CONST)
        if (!subs_check_ids(m, o & ~SUBS_ADD_CONST, c & ~SUBS_ADD_CONST)) return 0;
    return 1;
}

/* ---- cnum arc containment, transcribed from cnum_defs.h ------------------------------- */
static int subs_is_empty64(uint64_t b, uint64_t s) { return b == UINT64_MAX && s == UINT64_MAX; }
static int subs_is_empty32(uint32_t b, uint32_t s) { return b == UINT32_MAX && s == UINT32_MAX; }

static int subs_subset64(uint64_t bb, uint64_t bs, uint64_t sb, uint64_t ss) {
    if (subs_is_empty64(sb, ss)) return 1;
    if (subs_is_empty64(bb, bs)) return 0;
    sb -= bb;
    /* the final add WRAPS in the kernel; keeping that is the whole of finding B1 */
    if (ss > UINT64_MAX - sb && bs < UINT64_MAX) return 0;
    return (uint64_t)(sb + ss) <= bs;
}

static int subs_subset32(uint32_t bb, uint32_t bs, uint32_t sb, uint32_t ss) {
    if (subs_is_empty32(sb, ss)) return 1;
    if (subs_is_empty32(bb, bs)) return 0;
    sb -= bb;
    if (ss > UINT32_MAX - sb && bs < UINT32_MAX) return 0;
    return (uint32_t)(sb + ss) <= bs;
}

static int subs_tnum_in(uint64_t av, uint64_t am, uint64_t bv, uint64_t bm) {
    if (bm & ~am) return 0;
    return av == (bv & ~am);
}

static int subs_range_within(const struct subs_reg *o, const struct subs_reg *c) {
    return subs_subset64(o->b64, o->sz64, c->b64, c->sz64) &&
           subs_subset32(o->b32, o->sz32, c->b32, c->sz32);
}

/* `range` is the union's first member: type(4) + delta(4), so bytes 8..12, signed LE. */
static int subs_pfx_range(const struct subs_reg *r) {
    uint32_t v = 0; int i;
    for (i = 0; i < 4; i++) {
        int hi = r->pfx[16 + i * 2], lo = r->pfx[17 + i * 2];
        hi = hi <= '9' ? hi - '0' : hi - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
        v |= (uint32_t)((hi << 4) | lo) << (i * 8);
    }
    return (int)v;
}

/* ---- one pair through regsafe, mirroring subsume-check.py's evaluate() exactly --------- */
enum { SUBS_AGREE = 0, SUBS_BREAK = 1, SUBS_UNMOD = 2 };

static const struct subs_reg *subs_find(const struct subs_reg *v, int n, int key) {
    int i;
    for (i = 0; i < n; i++) if (v[i].key == key) return &v[i];
    return NULL;
}

static int subs_eval(const struct subs_reg *old, int no, const struct subs_reg *cur, int nc,
                     int exact, struct bpfsubs_cmp *st, const char **arm) {
    struct subs_idmap m; int i, j, ran = 0;
    struct subs_reg srt[SUBS_MAXREG];

    if (no == 0 || nc == 0) return SUBS_UNMOD;
    memset(&m, 0, sizeof(m));
    m.tmp = 1u << 20;

    /* frame, then register order — the kernel walks regs in that order and check_ids
       fills the table INCREMENTALLY, so the order is part of the predicate. */
    memcpy(srt, old, (size_t)no * sizeof(srt[0]));
    for (i = 1; i < no; i++) {
        struct subs_reg t = srt[i];
        for (j = i - 1; j >= 0 && srt[j].key > t.key; j--) srt[j + 1] = srt[j];
        srt[j + 1] = t;
    }

    for (i = 0; i < no; i++) {
        const struct subs_reg *o = &srt[i];
        const struct subs_reg *c = subs_find(cur, nc, o->key);
        int base;

        if (!c) return SUBS_UNMOD;
        if (o->t != c->t) { *arm = "type"; return SUBS_BREAK; }

        if (o->t != SUBS_SCALAR) {
            if (!o->have_pfx || !c->have_pfx) continue;   /* counted by the caller */
            base = o->t & 0xFF;
            st->ptr_cmp++;
            if (base == 18) continue;                     /* PTR_TO_ARENA: unconditional */
            if (base == 4 || base == 5 || base == 17 || base == 19 || base == 14 || base == 21) {
                if (memcmp(o->pfx, c->pfx, (size_t)o->vo * 2) != 0) { *arm = "ptr_memcmp"; return SUBS_BREAK; }
                if (!subs_range_within(o, c)) { *arm = "ptr_range_within"; return SUBS_BREAK; }
                if (!subs_tnum_in(o->vv, o->vm, c->vv, c->vm)) { *arm = "ptr_tnum_in"; return SUBS_BREAK; }
                if (base != 21 && !(subs_check_ids(&m, o->id, c->id) &&
                                    subs_check_ids(&m, o->pid, c->pid))) {
                    *arm = "ptr_check_ids"; return SUBS_BREAK;
                }
                continue;
            }
            if (base == 7 || base == 8) {                 /* PTR_TO_PACKET{,_META} */
                int ro = subs_pfx_range(o), rc = subs_pfx_range(c);
                if (ro < 0 || rc < 0) { if (ro != rc) { *arm = "pkt_range"; return SUBS_BREAK; } }
                else if (ro > rc) { *arm = "pkt_range"; return SUBS_BREAK; }
                if (!subs_check_ids(&m, o->id, c->id)) { *arm = "ptr_check_ids"; return SUBS_BREAK; }
                if (!(subs_range_within(o, c) && subs_tnum_in(o->vv, o->vm, c->vv, c->vm))) {
                    *arm = "ptr_range_within"; return SUBS_BREAK;
                }
                continue;
            }
            if (strcmp(o->pfx, c->pfx) != 0) { *arm = "regs_exact"; return SUBS_BREAK; }
            if (base == 6 && o->fno != c->fno) { *arm = "frameno"; return SUBS_BREAK; }
            if (!(subs_check_ids(&m, o->id, c->id) && subs_check_ids(&m, o->pid, c->pid))) {
                *arm = "ptr_check_ids"; return SUBS_BREAK;
            }
            continue;
        }

        if (o->prec == 0 && exact == 0) { st->shortcircuit++; continue; }
        if (o->id && (o->id & SUBS_ADD_CONST) != (c->id & SUBS_ADD_CONST)) {
            *arm = "add_const_flag"; return SUBS_BREAK;
        }
        if ((o->id & SUBS_ADD_CONST) && o->delta != c->delta) { *arm = "delta"; return SUBS_BREAK; }
        if (!subs_check_scalar_ids(&m, o->id, c->id)) { *arm = "check_scalar_ids"; return SUBS_BREAK; }
        st->scalar_cmp++; ran = 1;
        if (!subs_range_within(o, c)) { *arm = "range_within"; return SUBS_BREAK; }
        if (!subs_tnum_in(o->vv, o->vm, c->vv, c->vm)) { *arm = "tnum_in"; return SUBS_BREAK; }
    }
    if (ran) st->nontrivial++;
    return SUBS_AGREE;
}

/* ---- scan a verifier log, in the VM, and leave only numbers behind -------------------- */
static void bpfsubs_compare_log(const char *log, struct bpfsubs_cmp *out) {
    struct subs_reg old[SUBS_MAXREG], cur[SUBS_MAXREG], r;
    int no = 0, nc = 0, insn = 0, exact = 0, prev_old = 0, open = 0;
    int pend_vo = -1; char pend_pfx[SUBS_PFXHEX];
    const char *p = log;

    memset(out, 0, sizeof(*out));
    pend_pfx[0] = 0;

    while (p && *p) {
        const char *eol = strchr(p, '\n');
        char line[512];
        size_t len = eol ? (size_t)(eol - p) : strlen(p);

        if (len < sizeof(line)) {
            memcpy(line, p, len); line[len] = 0;

            if (strncmp(line, "PRUNEPAIR_PFX vo=", 17) == 0) {
                if (sscanf(line, "PRUNEPAIR_PFX vo=%d %159s", &pend_vo, pend_pfx) != 2)
                    pend_vo = -1;
            } else if (strncmp(line, "PRUNEPAIR insn=", 15) == 0) {
                char side[8]; int fr, rn, i2, e2;
                out->rows++;
                unsigned long long vv, vm, b64, s64;
                unsigned b32, s32, id, pid;
                memset(&r, 0, sizeof(r));
                if (sscanf(line,
                        "PRUNEPAIR insn=%d exact=%d side=%7s fr=%d r%d type=%d delta=%d "
                        "var=%llx/%llx r64=%llx+%llx r32=%x+%x id=%x pid=%x fno=%d prec=%d",
                        &i2, &e2, side, &fr, &rn, &r.t, &r.delta, &vv, &vm, &b64, &s64,
                        &b32, &s32, &id, &pid, &r.fno, &r.prec) == 17) {
                    int is_old = side[0] == 'o';
                    r.key = fr * 16 + rn;
                    r.vv = vv; r.vm = vm; r.b64 = b64; r.sz64 = s64;
                    r.b32 = b32; r.sz32 = s32; r.id = id; r.pid = pid;
                    if (pend_vo >= 0) {
                        r.have_pfx = 1; r.vo = pend_vo;
                        strncpy(r.pfx, pend_pfx, sizeof(r.pfx) - 1);
                        pend_vo = -1;
                    }
                    if (is_old && (!open || !prev_old)) {
                        if (open) {   /* close the previous pair */
                            const char *arm = "?";
                            int v = subs_eval(old, no, cur, nc, exact, out, &arm);
                            out->pairs++;
                            if (v == SUBS_BREAK) { out->disagree++;
                                if (!out->first[0])
                                    snprintf(out->first, sizeof(out->first),
                                             "insn=%d exact=%d arm=%s", insn, exact, arm);
                            } else if (v == SUBS_UNMOD) out->unmodelled++;
                            else out->agree++;
                        }
                        no = nc = 0; open = 1; insn = i2; exact = e2;
                    }
                    if (is_old) { if (no < SUBS_MAXREG) old[no++] = r; }
                    else        { if (nc < SUBS_MAXREG) cur[nc++] = r; }
                    prev_old = is_old;
                } else {
                    out->unsupported++;   /* a format this build cannot read is a REFUSAL */
                }
            }
        }
        p = eol ? eol + 1 : NULL;
    }
    if (open) {
        const char *arm = "?";
        int v = subs_eval(old, no, cur, nc, exact, out, &arm);
        out->pairs++;
        if (v == SUBS_BREAK) { out->disagree++;
            if (!out->first[0])
                snprintf(out->first, sizeof(out->first), "insn=%d exact=%d arm=%s", insn, exact, arm);
        } else if (v == SUBS_UNMOD) out->unmodelled++;
        else out->agree++;
    }
}

#endif /* BPFSUBS_H */
