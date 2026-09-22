#!/usr/bin/env python3
"""Standalone `states_equal` model — and first its own calibration (devlog 0099).

`bpflive.h` recomputes the liveness analysis independently of the emitted bytes; this is the
counterpart of the same thing for the PRUNING DECISION. Its input is a capture taken with
`patches/prunepair-instrumentation.patch`: the RAW fields of both sides at the moment the
kernel finds two states equivalent and prunes (`PRUNEPAIR` lines).

WHY RAW FIELDS. 0088 measured that the decision cannot be audited from the log, and the reason
was not format but expressiveness: `range_within` is now arc-containment over `cnum{base,size}`
while the log prints eight derived projections; when `precise` decides whether the check is
performed the log has only a single `P` prefix; and because `id` is printed masked the
ADD_CONST32/64 distinction is lost.

DIRECTION AND DISCIPLINE. We only have the prunes the kernel TOOK, so only one direction is
visible: the kernel pruned and the model says "no containment". This is either the kernel's
unsoundness or a gap in our model — and per `bpflive.h`'s lesson, until proven the latter is
assumed. The model does NOT GUESS a pair it cannot decide, it counts it `unmodelled`.

TRIVIALITY CHECK (0084). An agreement count alone is worthless: the precision short-circuit
(`!rold->precise && exact == NOT_EXACT`) passes a register without comparing it at all. So the
script additionally reports the number of pairs where the range/tnum check ACTUALLY ran.

Usage:
    scripts/subsume-check.py <capture carrying PRUNEPAIR>
"""
import re, sys

UT64 = (1 << 64) - 1
UT32 = (1 << 32) - 1
SCALAR_VALUE = 1
BPF_ADD_CONST = (1 << 31) | (1 << 30)

# enum bpf_reg_type, and base_type(t) = t & 0xFF (BPF_BASE_TYPE_BITS = 8).
PTR_TO_MAP_VALUE, PTR_TO_MAP_KEY, PTR_TO_STACK = 4, 5, 6
PTR_TO_PACKET_META, PTR_TO_PACKET, PTR_TO_TP_BUFFER = 7, 8, 14
PTR_TO_MEM, PTR_TO_ARENA, PTR_TO_BUF, PTR_TO_INSN = 17, 18, 19, 21
# regsafe's "memcmp + range + tnum + two check_ids" family.
PFX_FAMILY = {PTR_TO_MAP_KEY, PTR_TO_MAP_VALUE, PTR_TO_MEM, PTR_TO_BUF, PTR_TO_TP_BUFFER}

def pfx_range(pfx):
    """`int range`, the first member of the union in bpf_reg_state — after type(4) + delta(4),
    i.e. bytes 8..12, little-endian and SIGNED. Derived from the prefix because the raw bytes
    the patch prints are already there; printing it separately would be a second source of truth."""
    b = bytes.fromhex(pfx[16:24])
    return int.from_bytes(b, 'little', signed=True)

# transcribed from kernel/bpf/cnum_defs.h, not copied from it.
def cnum_is_empty(base, size, mask):
    return base == mask and size == mask

def cnum_urange_overflow(base, size, mask):
    return size > mask - base

def cnum_is_subset(bb, bs, sb, ss, mask):
    """bigger ⊇ smaller"""
    if cnum_is_empty(sb, ss, mask):
        return True
    if cnum_is_empty(bb, bs, mask):
        return False
    sb = (sb - bb) & mask          # re-base bigger.base to the origin
    if cnum_urange_overflow(sb, ss, mask) and bs < mask:
        return False
    # The kernel does this addition inside `ut`, so it WRAPS (cnum_defs.h:244). Python's
    # unbounded integer does not wrap, and the two sides diverge exactly here: when bigger.size
    # == UT_MAX and the re-based smaller wraps, the kernel returns true while the unmasked
    # model returns false -- i.e. in the FALSE-POSITIVE direction. It never fired on this corpus;
    # its condition is "unknown scalar at checkpoint + wrapping arc in the current state", which
    # --probe-wraparc tries to produce exactly. Vectors: SELFTEST_SUBSET.
    return ((sb + ss) & mask) <= bs

def s64(x):
    return x - (1 << 64) if x >> 63 else x

def s32(x):
    return x - (1 << 32) if x >> 31 else x

def range_within_minmax(o, c):
    """The `range_within` of the kernel BEFORE 2026-04-24: eight min/max comparisons.

    This is a weaker approximation of cnum arc-containment and `cd5b460ed1ec` fixed exactly
    this. When the model models that era it applies that era's PREDICATE — otherwise every
    difference between them looks like a 'finding' and the denominator turns to garbage. The era
    floor comes from the FIELDS, not the predicate ([[era-floors]])."""
    return (o['umin'] <= c['umin'] and o['umax'] >= c['umax'] and
            o['smin'] <= c['smin'] and o['smax'] >= c['smax'] and
            o['u32min'] <= c['u32min'] and o['u32max'] >= c['u32max'] and
            o['s32min'] <= c['s32min'] and o['s32max'] >= c['s32max'])

def tnum_in(a_value, a_mask, b_value, b_mask):
    """a ⊇ b"""
    if b_mask & ~a_mask:
        return False
    return a_value == (b_value & ~a_mask)

class IdMap:
    """`check_ids` + `check_scalar_ids` of kernel/bpf/states.c, transcribed.

    Order MATTERS: the idmap is reset on every `states_equal` call and registers are filled in
    frame order, then stack slots. Because the patch does not yet print the stack, the model does
    not decide on a program that COULD have a stack slot carrying an id — `check_ids` filling the
    table INCREMENTALLY means a missing entry shifts every subsequent decision."""

    def __init__(self, tmp_id_gen_seed=1 << 20):
        self.map = []
        self.tmp = tmp_id_gen_seed

    def check_ids(self, old_id, cur_id):
        if bool(old_id) != bool(cur_id):
            return False
        if old_id == 0:
            return True
        for o, c in self.map:
            if o == old_id:
                return c == cur_id
            if c == cur_id:
                return False
        self.map.append((old_id, cur_id))
        return True

    def check_scalar_ids(self, old_id, cur_id):
        """FIXED version (after 2f2ec8e7730e). The buggy version only matched the compound id;
        the check that the base id must also be mapped consistently was missing, and this is
        exactly the point where the model diverges from the buggy kernel."""
        if not old_id:
            return True
        if not cur_id:
            self.tmp += 1
            cur_id = self.tmp
        if not self.check_ids(old_id, cur_id):
            return False
        if old_id & BPF_ADD_CONST:
            if not self.check_ids(old_id & ~BPF_ADD_CONST, cur_id & ~BPF_ADD_CONST):
                return False
        return True


ROW = re.compile(
    r'^PRUNEPAIR insn=(\d+) exact=(\d+) side=(old|cur) fr=(\d+) r(\d+) '
    r'type=(\d+) delta=(-?\d+) var=([0-9a-f]+)/([0-9a-f]+) '
    r'r64=([0-9a-f]+)\+([0-9a-f]+) r32=([0-9a-f]+)\+([0-9a-f]+) '
    r'id=([0-9a-f]+) pid=([0-9a-f]+) fno=(\d+) prec=(\d+)$')

# ERA VARIANT: `..` means a min..max range, `+` a base+size arc. The separator tells the
# consumer which predicate it owes.
ROW_MM = re.compile(
    r'^PRUNEPAIR insn=(\d+) exact=(\d+) side=(old|cur) fr=(\d+) r(\d+) '
    r'type=(\d+) delta=(-?\d+) var=([0-9a-f]+)/([0-9a-f]+) '
    r'u64=([0-9a-f]+)\.\.([0-9a-f]+) s64=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'u32=([0-9a-f]+)\.\.([0-9a-f]+) s32=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'id=([0-9a-f]+) fno=(\d+) prec=(\d+)$')

# 2021 ERA: the `live=` field is both required (that era's regsafe is gated by REG_LIVE_READ)
# and an era marker — the line itself tells the consumer which regsafe it owes.
# Pointer arms compare BYTES, not fields: regsafe's map_value family does
# memcmp(rold,rcur,offsetof(var_off)), and regs_exact up to offsetof(id). The patch prints that
# prefix raw and the model slices it — WITHOUT GUESSING the union's layout, exactly the same
# comparison. `vo` tells where the short cut ends.
PFX = re.compile(r'^PRUNEPAIR_PFX vo=(\d+) ([0-9a-f]+)$')

# ERA FORCING (part 5, H21). Lines carrying `live=` go to the 2021 arm by default and that
# arm has NO scalar id check -- it wasn't in the 2021 kernel either.
# 2023-06 is between the two eras: live= is present, and after 1ffc85d9298e check_scalar_ids
# is present too. Two different predicates come from the same print format; the format cannot
# determine the era, so it is stated EXPLICITLY (--era 2023), not inferred.
FORCE_ERA = None

ROW_21 = re.compile(
    r'^PRUNEPAIR insn=(\d+) exact=(\d+) side=(old|cur) fr=(\d+) r(\d+) '
    r'type=(\d+) delta=(-?\d+) var=([0-9a-f]+)/([0-9a-f]+) '
    r'u64=([0-9a-f]+)\.\.([0-9a-f]+) s64=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'u32=([0-9a-f]+)\.\.([0-9a-f]+) s32=([0-9a-f]+)\.\.([0-9a-f]+) '
    r'id=([0-9a-f]+) fno=(\d+) prec=(\d+) live=(\d+)$')

LIVE = re.compile(r'^LIVENESS status=ok n=(\d+) mask=([0-9a-f]+)$')

def parse_lines(lines):
    """A pair = one `old` run + the `cur` run following it. The correctness of this grouping
    can be verified independently: the pair count must match the number of `: safe` prune events
    in the log (0088 measured 2038, and this script also finds 2038).

    If the capture carries a LIVENESS line (the harness prints the `bpflive.h` claim) that claim
    is attached to the pair: the model does NOT enforce the liveness gate, but so that the COST of
    not enforcing it can be counted."""
    pairs, cur = [], None
    live_mask, live_n = None, 0
    pend_pfx = None
    for line in lines:
        line = line.rstrip()
        if line.startswith("===PROG"):
            live_mask, live_n = None, 0
            continue
        mlive = LIVE.match(line)
        if mlive:
            live_n, live_mask = int(mlive[1]), mlive[2]
            continue
        if line.startswith("LIVENESS status=unsupported"):
            live_mask, live_n = None, 0
            continue
        mp = PFX.match(line)
        if mp:
            pend_pfx = (int(mp[1]), mp[2])
            continue
        m = ROW_21.match(line)
        era = FORCE_ERA if (m and FORCE_ERA) else '2021'
        if not m:
            m = ROW.match(line)
            era = 'cnum'
        if not m:
            m = ROW_MM.match(line)
            era = 'minmax'
        if not m:
            continue
        insn, exact, side, fr, reg = int(m[1]), int(m[2]), m[3], int(m[4]), int(m[5])
        rec = dict(t=int(m[6]), delta=int(m[7]), vv=int(m[8], 16), vm=int(m[9], 16),
                   era=era)
        if era == 'cnum':
            rec.update(b64=int(m[10], 16), sz64=int(m[11], 16),
                       b32=int(m[12], 16), sz32=int(m[13], 16),
                       id=int(m[14], 16), pid=int(m[15], 16), fno=int(m[16]),
                   prec=int(m[17]))
        else:
            rec.update(umin=int(m[10], 16), umax=int(m[11], 16),
                       smin=s64(int(m[12], 16)), smax=s64(int(m[13], 16)),
                       u32min=int(m[14], 16), u32max=int(m[15], 16),
                       s32min=s32(int(m[16], 16)), s32max=s32(int(m[17], 16)),
                       id=int(m[18], 16), prec=int(m[20]))
            if era in ('2021', '2023'):
                rec['live'] = int(m[21])
        if side == 'old' and (cur is None or cur['done']):
            cur = {'insn': insn, 'exact': exact, 'old': {}, 'cur': {}, 'done': False,
                   'live': live_mask, 'live_n': live_n}
            pairs.append(cur)
        if cur is None:
            continue
        if pend_pfx is not None:
            rec['vo'], rec['pfx'] = pend_pfx
            pend_pfx = None
        (cur['old'] if side == 'old' else cur['cur'])[(fr, reg)] = rec
        if side == 'cur':
            cur['done'] = True
    return pairs

def parse(path):
    with open(path, errors="replace") as fh:
        return parse_lines(fh)


class Stats:
    """Counters. `denominator()` returns a PARTITION: the sum of the four terminal categories
    MUST equal the pair count, otherwise a 'non-trivial' numerator is just a new name for the old one."""

    def __init__(self):
        self.scalar_cmp = self.shortcircuit = self.other_type = self.id_checks = 0
        self.agree_trivial = self.agree_nontrivial = 0
        self.breaks = self.unmodelled = 0
        self.nontrivial_legacy = 0
        self.reasons = {}
        # THE COST OF UNIMPLEMENTED ARMS — none in the model, two countable from the capture
        self.ptr_cmp = 0                 # the pointer arm ACTUALLY ran (0084's rule)
        self.live_gated = 0              # 2021: REG_LIVE_READ gate (MODELLED in that era)
        self.ptr_id_pairs = 0            # a pointer id seeds the kernel's idmap, the model skips it
        self.dead_reg_cmps = 0           # a comparison we did on a register the kernel NEVER compared
        self.live_cmps = 0
        self.pairs_no_live_claim = 0     # bpflive REJECTED that program — no claim
        self.pairs_no_tracked_reg = 0    # there is a claim, but the pair has no tracked register (only r10)

    def pairs(self):
        return self.agree_trivial + self.agree_nontrivial + self.breaks + self.unmodelled


def live_bit(p, fr, reg):
    """The kernel `func_states_equal` only compares registers in `live_regs_before`.
    None = no claim (the model rejected that program), True/False = live/dead."""
    if p['live'] is None or fr != 0 or reg >= 10 or p['insn'] >= p['live_n']:
        return None
    return bool(int(p['live'][p['insn'] * 3:p['insn'] * 3 + 3], 16) & (1 << reg))


def evaluate(p, st):
    """Run a single pair through the kernel's `regsafe` scalar arm.
    Returns: 'unmodelled' | 'agree' | 'break'. On a break, p['arm'] says which arm dropped it —
    that is triage's first question when a candidate appears.

    SINGLE EXIT: accounting at the end, once. `nontrivial` counts a pair in every case where
    range/tnum ACTUALLY ran, even if it breaks (0084's rule, and the semantics of the original
    version)."""
    if not p['old'] or not p['cur']:
        st.unmodelled += 1
        st.reasons['missing side'] = st.reasons.get('missing side', 0) + 1
        return 'unmodelled'

    verdict = 'agree'
    ran_range = False
    saw_tracked_reg = False
    ptr_id = False

    for key, o in sorted(p['old'].items()):          # frame, then register order
        fr, reg = key
        c = p['cur'].get(key)
        if c is None:
            st.unmodelled += 1
            st.reasons["not in cur"] = st.reasons.get("not in cur", 0) + 1
            return 'unmodelled'

        lb = live_bit(p, fr, reg)
        if lb is not None:
            saw_tracked_reg = True
            if lb:
                st.live_cmps += 1
            else:
                st.dead_reg_cmps += 1

        if o['t'] != c['t']:
            p['arm'] = 'type'; verdict = 'break'; break
        if o['era'] in ('2021', '2023') and not o['live']:
            # 2021 regsafe's FIRST line: `if (!(rold->live & REG_LIVE_READ)) return true;`
            # This is the ancestor of today's live_regs_before gate and is printed per register —
            # so in that era the gate CAN BE MODELLED, no guessing needed.
            st.live_gated += 1; continue
        if o['t'] != SCALAR_VALUE:
            if 'pfx' not in o or 'pfx' not in c:
                # Captures without a prefix (era variants and pre-0102 type): the arm is
                # NOT MODELLED and this IS COUNTED. Passing is the loose direction, so it does not
                # produce a false positive — but staying silent about it was B3 itself.
                st.other_type += 1
                if o['id'] or c['id']:
                    ptr_id = True
                continue
            base = o['t'] & 0xFF
            st.ptr_cmp += 1
            if base == PTR_TO_ARENA:
                continue                              # regsafe: unconditional true
            rw = (cnum_is_subset(o['b64'], o['sz64'], c['b64'], c['sz64'], UT64) and
                  cnum_is_subset(o['b32'], o['sz32'], c['b32'], c['sz32'], UT32)) \
                 if o['era'] == 'cnum' else range_within_minmax(o, c)
            ti = tnum_in(o['vv'], o['vm'], c['vv'], c['vm'])
            if base in PFX_FAMILY or base == PTR_TO_INSN:
                if o['pfx'][:o['vo'] * 2] != c['pfx'][:o['vo'] * 2]:
                    p['arm'] = 'ptr_memcmp'; verdict = 'break'; break
                if not rw:
                    p['arm'] = 'ptr_range_within'; verdict = 'break'; break
                if not ti:
                    p['arm'] = 'ptr_tnum_in'; verdict = 'break'; break
                if base != PTR_TO_INSN:               # the INSN arm does not compare id
                    if not (p['idmap'].check_ids(o['id'], c['id']) and
                            p['idmap'].check_ids(o['pid'], c['pid'])):
                        p['arm'] = 'ptr_check_ids'; verdict = 'break'; break
                continue
            if base in (PTR_TO_PACKET, PTR_TO_PACKET_META):
                ro, rc = pfx_range(o['pfx']), pfx_range(c['pfx'])
                if ro < 0 or rc < 0:
                    if ro != rc:
                        p['arm'] = 'pkt_range'; verdict = 'break'; break
                elif ro > rc:
                    p['arm'] = 'pkt_range'; verdict = 'break'; break
                if not p['idmap'].check_ids(o['id'], c['id']):
                    p['arm'] = 'ptr_check_ids'; verdict = 'break'; break
                if not (rw and ti):
                    p['arm'] = 'ptr_range_within'; verdict = 'break'; break
                continue
            # PTR_TO_STACK and default: regs_exact, i.e. the WHOLE prefix + two check_ids.
            if o['pfx'] != c['pfx']:
                p['arm'] = 'regs_exact'; verdict = 'break'; break
            if base == PTR_TO_STACK and o['fno'] != c['fno']:
                p['arm'] = 'frameno'; verdict = 'break'; break
            if not (p['idmap'].check_ids(o['id'], c['id']) and
                    p['idmap'].check_ids(o['pid'], c['pid'])):
                p['arm'] = 'ptr_check_ids'; verdict = 'break'; break
            continue
        # regsafe's scalar arm, in order:
        if o['era'] == '2021':
            # That era's short-circuit is TWO-SIDED and the id/delta/ADD_CONST arms do not yet EXIST:
            # the scalar arm is exactly `range_within(rold,rcur) && tnum_in(...)`.
            if o['prec'] == 0 and c['prec'] == 0:
                st.shortcircuit += 1; continue
            st.scalar_cmp += 1; ran_range = True
            if not range_within_minmax(o, c):
                p['arm'] = 'range_within'; verdict = 'break'; break
            if not tnum_in(o['vv'], o['vm'], c['vv'], c['vm']):
                p['arm'] = 'tnum_in'; verdict = 'break'; break
            continue
        if o['prec'] == 0 and p['exact'] == 0:
            st.shortcircuit += 1; continue        # precision short-circuit
        if o['id'] and (o['id'] & BPF_ADD_CONST) != (c['id'] & BPF_ADD_CONST):
            p['arm'] = 'add_const_flag'; verdict = 'break'; break
        if (o['id'] & BPF_ADD_CONST) and o['delta'] != c['delta']:
            p['arm'] = 'delta'; verdict = 'break'; break
        if o['id'] or c['id']:
            st.id_checks += 1        # the id arm ACTUALLY ran (0084's rule)
        if not p['idmap'].check_scalar_ids(o['id'], c['id']):
            p['arm'] = 'check_scalar_ids'; verdict = 'break'; break
        st.scalar_cmp += 1; ran_range = True
        if o['era'] == 'cnum':
            held = (cnum_is_subset(o['b64'], o['sz64'], c['b64'], c['sz64'], UT64) and
                    cnum_is_subset(o['b32'], o['sz32'], c['b32'], c['sz32'], UT32))
        else:
            held = range_within_minmax(o, c)
        if not held:
            p['arm'] = 'range_within'; verdict = 'break'; break
        if not tnum_in(o['vv'], o['vm'], c['vv'], c['vm']):
            p['arm'] = 'tnum_in'; verdict = 'break'; break

    if ptr_id:
        st.ptr_id_pairs += 1
    if p['live'] is None:
        st.pairs_no_live_claim += 1
    elif not saw_tracked_reg:
        # a pair carrying only r10 (PTR_TO_STACK): `live_regs_before` tracks r0-r9, so
        # the kernel COMPARES no register here either. There is no auditable cell.
        st.pairs_no_tracked_reg += 1
    if ran_range:
        st.nontrivial_legacy += 1
    if verdict == 'break':
        st.breaks += 1
    elif ran_range:
        st.agree_nontrivial += 1
    else:
        st.agree_trivial += 1
    return verdict


def run(pairs):
    st = Stats()
    candidates = []
    for p in pairs:
        p['idmap'] = IdMap()          # reset for each pair, as in the kernel
        p['arm'] = None
        if evaluate(p, st) == 'break':
            candidates.append(p)
    return st, candidates


def main(path):
    pairs = parse(path)
    st, candidates = run(pairs)
    for p in candidates:
        print(f"SUBSUME candidate insn={p['insn']} exact={p['exact']} arm={p['arm']}")
    agree = st.agree_trivial + st.agree_nontrivial
    print(f"SUBSUME pairs={len(pairs)} modelled={agree + st.breaks} "
          f"agree={agree} disagree={st.breaks} unmodelled={st.unmodelled}")
    print(f"SUBSUME nontrivial_pairs={st.nontrivial_legacy} scalar_comparisons={st.scalar_cmp} "
          f"shortcircuited_regs={st.shortcircuit} other_type_regs={st.other_type} "
          f"ptr_cmps={st.ptr_cmp} "
          f"id_checks={st.id_checks}")
    # DENOMINATOR RULE: the four terminal categories must sum to the pair count.
    print(f"SUBSUME denominator pairs={len(pairs)} trivial={st.agree_trivial} "
          f"nontrivial={st.agree_nontrivial} breaks={st.breaks} "
          f"unmodelled={st.unmodelled} sums={'ok' if st.pairs() == len(pairs) else 'MISMATCH'}")
    # UNIMPLEMENTED ARMS. refsafe's idmap seeding is NOT OBSERVABLE from the capture — the patch
    # does not print refs[]/active_lock_id — and saying so is the number itself.
    print(f"SUBSUME unimplemented_arms ptr_id_pairs={st.ptr_id_pairs} "
          f"dead_reg_cmps={st.dead_reg_cmps} live_reg_cmps={st.live_cmps} "
          f"pairs_without_liveness_claim={st.pairs_no_live_claim} "
          f"pairs_without_tracked_reg={st.pairs_no_tracked_reg} "
          f"live_gated_regs={st.live_gated} "
          f"refsafe_idmap_seed=not-observable-from-capture")
    for k, v in sorted(st.reasons.items()):
        print(f"SUBSUME unmodelled_reason {k}={v}")
    return 0


# ---- SELF-CALIBRATION ---------------------------------------------------------------
#
# A model's test must FAIL when the model is WRONG; a vector that passes on both sides is not a
# test of that bug, it is a vector that passes it by. Each vector below is tied to a measured
# event, and which arm dropped it is written by name.

SELFTEST_SUBSET = [
    # (name, bigger(base,size), smaller(base,size), mask, expected)
    ("B1 · old UNKNOWN, cur WRAPPING ARC — the unmasked model produces a FALSE POSITIVE here",
     (0, UT32), (0xfffffff0, 0x20), UT32, True),
    ("B1 · same, bigger.base non-zero",
     (5, UT32), (0xfffffff0, 0x20), UT32, True),
    ("B1 · the 64-bit counterpart",
     (0, UT64), (UT64 - 0xf, 0x20), UT64, True),
    ("cd5b460ed1ec's own counterexample — a value in the GAP of the wrapping arc",
     (0x7FFFFFF0, 0x80000020), (0x100, 0x100), UT32, False),
    ("when bigger.size < UT_MAX a wrapping smaller must still be rejected",
     (0x10, 0x20), (0xfffffff0, 0x20), UT32, False),
    ("an empty smaller is always contained", (0, 0), (UT32, UT32), UT32, True),
    ("an empty bigger contains nothing", (UT32, UT32), (0, 0), UT32, False),
    ("const ⊇ const", (7, 0), (7, 0), UT32, True),
    ("const ⊉ a different const", (7, 0), (8, 0), UT32, False),
]

SELFTEST_TNUM = [
    ("unknown ⊇ const", (0, UT64), (5, 0), True),
    ("const ⊉ unknown", (5, 0), (0, UT64), False),
    ("arc with fixed low bits, matching value", (0x10, 0xffffffe0), (0x110, 0), True),
    ("arc with fixed low bits, NON-matching value", (0x10, 0xffffffe0), (0x100, 0), False),
]

SELFTEST_IDS = [
    # 2f2ec8e7730e's own example: old r2.id=A, r3.id=A|flag; cur r2.id=B, r3.id=C|flag.
    # It would pass WITHOUT the base cross-check; the FIXED predicate drops it. This is the
    # model's POSITIVE check against that bug — the buggy kernel prunes, the model rejects.
    ("2f2ec8e7730e · base id inconsistency must be caught",
     [(0xA, 0xB), (0xA | BPF_ADD_CONST, 0xC | BPF_ADD_CONST)], False),
    ("a consistent base must pass",
     [(0xA, 0xB), (0xA | BPF_ADD_CONST, 0xB | BPF_ADD_CONST)], True),
    ("old_id=0 always passes", [(0, 0x5)], True),
    ("the same old cannot map to two different curs", [(0xA, 0xB), (0xA, 0xC)], False),
]

# ERA ARM (min/max `range_within` before 2026-04-24). If a new arm is added without being
# tested, B4 itself is repeated, so this one is vectored too.
def _mm(umin, umax, smin, smax, u32min, u32max, s32min, s32max):
    return dict(umin=umin, umax=umax, smin=smin, smax=smax,
                u32min=u32min, u32max=u32max, s32min=s32min, s32max=s32max)

FULL64 = _mm(0, UT64, -(1 << 63), (1 << 63) - 1, 0, UT32, -(1 << 31), (1 << 31) - 1)
CONST7 = _mm(7, 7, 7, 7, 7, 7, 7, 7)

SELFTEST_MINMAX = [
    ("unknown ⊇ const", FULL64, CONST7, True),
    ("const ⊉ unknown", CONST7, FULL64, False),
    ("const ⊇ itself", CONST7, CONST7, True),
    # cd5b460ed1ec's OWN counterexample: the projections of a wrapping arc open to the full range,
    # so a value in the gap PASSES the min/max check. The era model must carry this WEAKNESS
    # exactly — otherwise it diverges from the era kernel everywhere and the denominator turns to garbage.
    ("cd5b460ed1ec · a value in the gap of a wrapping arc PASSES min/max (the era's bug)",
     FULL64, _mm(0x100, 0x200, 0x100, 0x200, 0x100, 0x200, 0x100, 0x200), True),
    ("signed bound: drops if old.smin > cur.smin",
     _mm(0, UT64, 0, (1 << 63) - 1, 0, UT32, 0, (1 << 31) - 1),
     _mm(0, UT64, -1, (1 << 63) - 1, 0, UT32, -1, (1 << 31) - 1), False),
]

# End-to-end parsing of the era format: the `..` separator means min..max, and signed fields
# are printed as raw two's-complement (s64=ffff..ffff -> -1).
SELFTEST_ERA = """\
===PROG selftest#era ===
PRUNEPAIR insn=3 exact=2 side=old fr=0 r6 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..7fffffff id=0 fno=0 prec=1
PRUNEPAIR insn=3 exact=2 side=cur fr=0 r6 type=1 delta=0 var=7/0 u64=7..7 s64=7..7 u32=7..7 s32=7..7 id=0 fno=0 prec=1
"""

# POINTER ARMS, end-to-end. The prefix is synthetic but its STRUCTURE is real: type(4) + delta(4) +
# union(4) + tail(4), and vo=12, so the short cut ends exactly at the end of the union —
# the counterpart of offsetof(var_off) in the kernel. `range` is read from bytes 8..12.
def _pfx(t, delta=0, uni=0, tail=0):
    return (t.to_bytes(4, "little") + (delta & 0xffffffff).to_bytes(4, "little")
            + (uni & 0xffffffff).to_bytes(4, "little")
            + (tail & 0xffffffff).to_bytes(4, "little")).hex()

def _row(side, t, pfx, *, reg=6, b64=0, s64=0, b32=0, s32=0, vv=0, vm=0,
         rid=0, pid=0, fno=0, prec=1):
    return (f"PRUNEPAIR_PFX vo=12 {pfx}\n"
            f"PRUNEPAIR insn=5 exact=0 side={side} fr=0 r{reg} type={t} delta=0 "
            f"var={vv:x}/{vm:x} r64={b64:x}+{s64:x} r32={b32:x}+{s32:x} "
            f"id={rid:x} pid={pid:x} fno={fno} prec={prec}")

def _cap(rows):
    return "===PROG selftest#ptr ===\n" + "\n".join(rows) + "\n"

SELFTEST_PTR = [
    # (name, rows, expected break, expected arm)
    ("map_value: same prefix, old bound contains cur -> agreement",
     [_row("old", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE), s64=UT64, s32=UT32, vm=UT64),
      _row("cur", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE))], 0, None),
    ("map_value: DIFFERENT prefix (union field) -> memcmp drops",
     [_row("old", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE, uni=1), s64=UT64, s32=UT32, vm=UT64),
      _row("cur", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE, uni=2))], 1, 'ptr_memcmp'),
    ("map_value: same prefix but old bound is NARROW -> range_within drops",
     [_row("old", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE)),
      _row("cur", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE), s64=UT64, s32=UT32, vm=UT64)],
     1, 'ptr_range_within'),
    ("arena: unconditional true, even if the bounds don't hold",
     [_row("old", PTR_TO_ARENA, _pfx(PTR_TO_ARENA)),
      _row("cur", PTR_TO_ARENA, _pfx(PTR_TO_ARENA), s64=UT64, s32=UT32, vm=UT64)], 0, None),
    ("stack: regs_exact, the WHOLE prefix equal -> agreement",
     [_row("old", PTR_TO_STACK, _pfx(PTR_TO_STACK), reg=10),
      _row("cur", PTR_TO_STACK, _pfx(PTR_TO_STACK), reg=10)], 0, None),
    ("stack: tail byte differs -> regs_exact drops (the short cut wouldn't see this)",
     [_row("old", PTR_TO_STACK, _pfx(PTR_TO_STACK, tail=1), reg=10),
      _row("cur", PTR_TO_STACK, _pfx(PTR_TO_STACK, tail=2), reg=10)], 1, 'regs_exact'),
    ("stack: same prefix, DIFFERENT frameno -> frameno drops",
     [_row("old", PTR_TO_STACK, _pfx(PTR_TO_STACK), reg=10, fno=0),
      _row("cur", PTR_TO_STACK, _pfx(PTR_TO_STACK), reg=10, fno=1)], 1, 'frameno'),
    ("packet: old.range > cur.range -> pkt_range drops",
     [_row("old", PTR_TO_PACKET, _pfx(PTR_TO_PACKET, uni=64), s64=UT64, s32=UT32, vm=UT64),
      _row("cur", PTR_TO_PACKET, _pfx(PTR_TO_PACKET, uni=32))], 1, 'pkt_range'),
    ("packet: old.range <= cur.range -> passes",
     [_row("old", PTR_TO_PACKET, _pfx(PTR_TO_PACKET, uni=32), s64=UT64, s32=UT32, vm=UT64),
      _row("cur", PTR_TO_PACKET, _pfx(PTR_TO_PACKET, uni=64))], 0, None),
    ("packet: negative range (BEYOND/AT_PKT_END) passes only if EQUAL",
     [_row("old", PTR_TO_PACKET, _pfx(PTR_TO_PACKET, uni=-1), s64=UT64, s32=UT32, vm=UT64),
      _row("cur", PTR_TO_PACKET, _pfx(PTR_TO_PACKET, uni=-2))], 1, 'pkt_range'),
    ("map_value: id mapping collides -> ptr_check_ids drops",
     [_row("old", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE), reg=6, rid=1, s64=UT64, s32=UT32, vm=UT64),
      _row("old", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE), reg=7, rid=1, s64=UT64, s32=UT32, vm=UT64),
      _row("cur", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE), reg=6, rid=2),
      _row("cur", PTR_TO_MAP_VALUE, _pfx(PTR_TO_MAP_VALUE), reg=7, rid=3)], 1, 'ptr_check_ids'),
]

# 2021 ERA, end-to-end. Three separate behaviors are pinned: the REG_LIVE_READ gate, the
# TWO-SIDED short-circuit, and fd675184fc7a's own signature — the 64-bit bounds are the same, the
# 32-bit bounds diverge. The buggy kernel prunes because it does only four 64-bit comparisons; the
# model rejects because it applies all eight. This is that pair's EXPECTED signal.
SELFTEST_2021_TRIGGER = """\
===PROG selftest#era2021 ===
PRUNEPAIR insn=7 exact=0 side=old fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..3030 id=0 fno=0 prec=1 live=1
PRUNEPAIR insn=7 exact=0 side=cur fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..7fffffff id=0 fno=0 prec=1 live=1
"""

# The same pair, but old is DEAD: that era's regsafe says `return true` on the first line, and so does the model.
SELFTEST_2021_LIVEGATE = """\
===PROG selftest#era2021gate ===
PRUNEPAIR insn=7 exact=0 side=old fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..3030 id=0 fno=0 prec=1 live=0
PRUNEPAIR insn=7 exact=0 side=cur fr=0 r4 type=1 delta=0 var=0/ffffffffffffffff u64=0..ffffffffffffffff s64=8000000000000000..7fffffffffffffff u32=0..ffffffff s32=80000000..7fffffff id=0 fno=0 prec=1 live=0
"""

# The same pair, both sides imprecise: the TWO-SIDED short-circuit passes.
SELFTEST_2021_SC = SELFTEST_2021_TRIGGER.replace("prec=1", "prec=0")

# B3a · DEAD REGISTER. The model does not enforce the liveness gate: the kernel NEVER compares a
# register outside `live_regs_before`, the model does. In the pair below r6 is dead and
# containment does not hold — the kernel would prune, the model says "candidate". The vector pins
# this GAP: if the behavior changes (the gate is wired in) this fails and is updated deliberately.
SELFTEST_DEADREG = """\
===PROG selftest#deadreg ===
LIVENESS status=ok n=4 mask=001001001001
PRUNEPAIR insn=2 exact=2 side=old fr=0 r6 type=1 delta=0 var=7/0 r64=7+0 r32=7+0 id=0 pid=0 fno=0 prec=1
PRUNEPAIR insn=2 exact=2 side=cur fr=0 r6 type=1 delta=0 var=0/ffffffffffffffff r64=0+ffffffffffffffff r32=0+ffffffff id=0 pid=0 fno=0 prec=1
"""


def self_test():
    fails = []

    def check(group, name, got, want):
        if got != want:
            fails.append(f"{group}: {name}\n    expected={want} got={got}")

    for name, big, small, mask, want in SELFTEST_SUBSET:
        check("cnum_is_subset", name,
              cnum_is_subset(big[0], big[1], small[0], small[1], mask), want)

    for name, a, b, want in SELFTEST_TNUM:
        check("tnum_in", name, tnum_in(a[0], a[1], b[0], b[1]), want)

    for name, rows, want_breaks, want_arm in SELFTEST_PTR:
        pr = parse_lines(_cap(rows).splitlines())
        check("pointer arm", name + " [parsing]", len(pr), 1)
        if pr:
            stp, cp = run(pr)
            check("pointer arm", name, stp.breaks, want_breaks)
            check("pointer arm", name + " [arm]", cp[0]['arm'] if cp else None, want_arm)
            check("pointer arm", name + " [arm ran]", stp.ptr_cmp > 0, True)

    for name, body, want_breaks, want_arm in [
            ("fd675184fc7a signature: 64-bit same, 32-bit diverges → must be rejected",
             SELFTEST_2021_TRIGGER, 1, 'range_within'),
            ("REG_LIVE_READ gate: old dead → comparison is never done",
             SELFTEST_2021_LIVEGATE, 0, None),
            ("two-sided short-circuit: both sides imprecise → passes",
             SELFTEST_2021_SC, 0, None)]:
        pr = parse_lines(body.splitlines())
        check("2021 era", name + " [parsing]", len(pr), 1)
        if pr:
            check("2021 era", name + " [era]", pr[0]['old'][(0, 4)]['era'], '2021')
            st21, c21 = run(pr)
            check("2021 era", name, st21.breaks, want_breaks)
            if want_arm:
                check("2021 era", name + " [arm]", c21[0]['arm'] if c21 else None, want_arm)

    for name, big, small, want in SELFTEST_MINMAX:
        check("range_within_minmax", name, range_within_minmax(big, small), want)

    era = parse_lines(SELFTEST_ERA.splitlines())
    check("parse", "the era format must produce a pair", len(era), 1)
    if era:
        o = era[0]['old'][(0, 6)]
        check("parse", "the era format must be marked 'minmax'", o['era'], 'minmax')
        check("parse", "a signed field must be decoded from two's-complement", o['smin'], -(1 << 63))
        st_e, _ = run(era)
        check("era arm", "unknown ⊇ const, agreement expected",
              (st_e.breaks, st_e.agree_nontrivial), (0, 1))

    for name, seq, want in SELFTEST_IDS:
        idmap = IdMap()
        got = all(idmap.check_scalar_ids(o, c) for o, c in seq)
        check("check_scalar_ids", name, got, want)

    pairs = parse_lines(SELFTEST_DEADREG.splitlines())
    check("parse", "the dead-register vector must produce a single pair", len(pairs), 1)
    if pairs:
        st, cands = run(pairs)
        check("B3a gap", "kernel would prune, model says candidate (gate NOT ENFORCED)",
              (st.breaks, st.dead_reg_cmps), (1, 1))
        check("B3a gap", "the dropping arm must be range_within",
              cands[0]['arm'] if cands else None, 'range_within')

    for f in fails:
        print("SELFTEST FAIL " + f)
    total = (len(SELFTEST_SUBSET) + len(SELFTEST_TNUM) + len(SELFTEST_IDS)
             + len(SELFTEST_MINMAX) + 7 + 10 + 3 * len(SELFTEST_PTR))
    print(f"SELFTEST vectors={total} failed={len(fails)}")
    return 1 if fails else 0


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        sys.exit(self_test())
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "--era":
        FORCE_ERA = args[1]; args = args[2:]
    if len(args) != 1:
        print(__doc__); sys.exit(2)
    sys.exit(main(args[0]))
