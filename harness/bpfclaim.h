/* bpfclaim.h — read the VERIFIER'S OWN CLAIM about one register at one instruction.
 *
 * WHAT THIS IS FOR. `check_store_location` is the only oracle here whose reference is the
 * runtime landing site rather than the verifier's own state, and the 0101 fan-out measured
 * why that matters: 58% of historical verifier bugs corrupt a FIELD, which every
 * consistency oracle inherits and this one does not. Putting it on the fuzz loop needs the
 * claim in-VM, because shipping the verifier logs out is the 10 GB/hour wall again.
 *
 * WHY IT REFUSES RATHER THAN GUESSES. The register print has at least four shapes, seen in
 * real captures:
 *
 *     R7=map_value(ks=4,vs=64,smin=...,smax=umax=...=7,var_off=(0x0; 0x7))
 *     R6=scalar()                                        fully unknown
 *     R6=scalar(id=1)                                    known only by identity
 *     R6=scalar(id=1+4,smin=smin32=0,smax=umax=...=10,var_off=(0x0; 0xf))
 *     R1=map_value(ks=4,vs=16,imm=2)                     a CONSTANT variable-offset
 *     R6=0                                               a constant
 *
 * and this project has twice paid for a parser that quietly read one of these wrong (0065,
 * where an invariant was correct and could not read the log; 0070, three silent blind spots
 * in a row). So every shape this cannot decide is COUNTED, never assumed: a claim that does
 * not parse must reduce the denominator, not pass as permissive.
 *
 * THE CHAIN IS THE TRAP. `smax=umax=smax32=umax32=10` assigns one number to four fields, so
 * a search for "umax=" has to skip further `name=` tokens before reading the value — and
 * "umax32=" contains "umax", so the match must be anchored on the character before it.
 */
#ifndef BPFCLAIM_H
#define BPFCLAIM_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

enum { CLAIM_OK = 0, CLAIM_ABSENT = 1, CLAIM_UNPARSED = 2 };

struct bpfclaim {
    int status;
    uint64_t umin, umax;
};

/* Anchored field match: `name=` must not be preceded by an identifier character, so
   "umax=" never matches inside "umax32=" or "u32_umax=". */
static const char *claim_find_field(const char *s, const char *end, const char *name) {
    size_t nl = strlen(name);
    for (const char *p = s; p + nl < end; p++) {
        if (memcmp(p, name, nl) != 0) continue;
        if (p > s) {
            char c = p[-1];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_') continue;
        }
        return p + nl;
    }
    return NULL;
}

/* After `umax=` there may be more `name=` tokens before the number (the chained form).
   Returns 0 on success. */
static int claim_read_value(const char *p, const char *end, uint64_t *out) {
    int hops = 0;
    while (p < end && hops++ < 8) {
        while (p < end && *p == ' ') p++;
        if (p < end && (*p == '-' || (*p >= '0' && *p <= '9'))) {
            char *e = NULL;
            long long v = strtoll(p, &e, 0);
            if (e == p) return -1;
            *out = (uint64_t)v;
            return 0;
        }
        /* skip an identifier and its '=' */
        const char *q = p;
        while (q < end && ((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
                           (*q >= '0' && *q <= '9') || *q == '_')) q++;
        if (q == p || q >= end || *q != '=') return -1;
        p = q + 1;
    }
    return -1;
}

/* Find the log line for `insn` and read register `reg`'s claim from it.
 *
 * The verifier prints the state AFTER the instruction on the same line, behind a `;`, and
 * the same instruction appears once per explored path. Different paths carry different
 * claims and the run executes exactly ONE of them, which we cannot identify from here — so
 * the claim returned is the UNION over every occurrence. That is deliberately weaker than a
 * per-path claim: it can only lose sensitivity, never manufacture a finding out of the
 * ambiguity. Same reasoning as the idmap arm the subsumption model refuses to guess. */
static struct bpfclaim bpfclaim_at(const char *log, int insn, int reg) {
    struct bpfclaim out;
    char pfx[24], rtok[8];
    int seen = 0, unparsed = 0;
    uint64_t lo = UINT64_MAX, hi = 0;

    out.status = CLAIM_ABSENT; out.umin = 0; out.umax = 0;
    snprintf(pfx, sizeof(pfx), "%d: (", insn);
    snprintf(rtok, sizeof(rtok), "R%d=", reg);

    for (const char *p = log; p && *p; ) {
        const char *eol = strchr(p, '\n');
        const char *end = eol ? eol : p + strlen(p);
        if (strncmp(p, pfx, strlen(pfx)) == 0) {
            const char *r = NULL;
            for (const char *q = p; q + 3 < end; q++)
                if ((q == p || q[-1] == ' ') && strncmp(q, rtok, strlen(rtok)) == 0) { r = q; break; }
            if (r) {
                const char *v = r + strlen(rtok);
                uint64_t a, b;
                if (*v >= '0' && *v <= '9') {                 /* R6=7 — a constant */
                    a = b = strtoull(v, NULL, 0);
                    seen++; if (a < lo) lo = a; if (b > hi) hi = b;
                } else if (strchr(v, '(') && strchr(v, '(') < end) {
                    /* ANY typed print — scalar(), map_value(), pkt() — carries the bounds
                       in its own parenthesised group, and for a POINTER those bounds ARE
                       the variable offset, which is exactly the claim a store needs. The
                       search is bounded to that group (depth-counted, because var_off
                       nests parens) so a neighbouring register's fields can never be read
                       as this one's: the first version searched the whole line and would
                       have taken R6's numbers for R7's claim on any line printing both. */
                    const char *gs = strchr(v, '(');
                    const char *ge = gs; int depth = 0;
                    for (; ge < end; ge++) {
                        if (*ge == '(') depth++;
                        else if (*ge == ')' && --depth == 0) break;
                    }
                    if (ge >= end) { unparsed++; goto next_line; }
                    const char *mn = claim_find_field(gs, ge, "umin=");
                    const char *mx = claim_find_field(gs, ge, "umax=");
                    const char *im = claim_find_field(gs, ge, "imm=");
                    if (!mx && im && claim_read_value(im, ge, &a) == 0) {
                        /* A CONSTANT offset, printed as `imm=N` rather than as bounds. The
                           first version had no case for it, and because an unreadable
                           occurrence was merely SKIPPED, the union was built from the other
                           paths only — narrower than the truth, which is how a correct
                           kernel produced a desync. Hand-derived from the replay: store at
                           insn 29 with immediate +4, claim imm=2, landing 6. Exactly the
                           observed byte. */
                        b = a;
                        seen++; if (a < lo) lo = a; if (b > hi) hi = b;
                    } else if (!mx) {                          /* no stated upper bound */
                        unparsed++;                            /* U64_MAX by convention,
                                                                  and an unbounded claim
                                                                  admits everything — that
                                                                  is not evidence, so it is
                                                                  counted, not used. */
                    } else if (claim_read_value(mx, ge, &b) != 0 ||
                               (mn && claim_read_value(mn, ge, &a) != 0)) {
                        unparsed++;
                    } else {
                        if (!mn) a = 0;
                        seen++; if (a < lo) lo = a; if (b > hi) hi = b;
                    }
                } else {
                    unparsed++;                                /* a shape we do not know */
                }
            }
        }
next_line:
        p = eol ? eol + 1 : NULL;
    }

    /* AN UNREADABLE OCCURRENCE POISONS THE WHOLE CLAIM. The union is over the paths the
       instruction was printed on, and the run took exactly one of them; dropping a path we
       could not read makes the union NARROWER than the truth, which manufactures desyncs
       instead of losing sensitivity. Every mistake in this oracle so far has been the same
       shape — not the predicate, but how the unreadable is counted. */
    if (unparsed) { out.status = CLAIM_UNPARSED; return out; }
    if (seen == 0) { out.status = CLAIM_ABSENT; return out; }
    out.status = CLAIM_OK; out.umin = lo; out.umax = hi;
    return out;
}

#endif /* BPFCLAIM_H */
