#!/usr/bin/env python3
"""The denominator for `seen_pcs` (devlog 0086).

Since 0078 the fuzz loop has reported a coverage number — 4789, then 5203, 5406, 5443 —
and every one of those was a bare count. A count is not a fraction: it says the number
went up, never how much is left. This script supplies the missing half.

KCOV records `_RET_IP_` of `__sanitizer_cov_trace_pc`, which is the address of the
instruction FOLLOWING the call. So the reachable coverage points are exactly the return
addresses of those calls, and they can be enumerated statically from vmlinux. Intersect
that set with what a run actually saw, attribute both sides to the object file each
function came from, and the result is a real percentage of the verification pass.

Usage: coverage-fraction.py <vmlinux> <fuzz log with PCSET lines> <kernel/bpf obj dir>
"""
import bisect
import collections
import re
import subprocess
import sys

# The verification pass, as this tree splits it: bpf_check() and everything it reaches to
# PROVE a program safe. core.o is the runtime, syscall.o the entry, and the map
# implementations are not the thing under test — they are reported but not counted.
VERIFICATION_PASS = {
    'verifier.o', 'states.o', 'liveness.o', 'cnum.o', 'tnum.o', 'backtrack.o',
    'const_fold.o', 'cfg.o', 'check_btf.o', 'fixups.o', 'log.o', 'disasm.o',
}

# Grouping for the never-entered remainder. The point of the whole measurement is to say
# where to aim next, and that answer is only legible in themes, not in 238 function names.
THEMES = [
    ('kfunc / BTF calls',          r'kfunc|btf_check_func|fetch_kfunc|pseudo_btf|ptr_to_btf'),
    ('log + disasm printing',      r'^print_|verifier_vlog|verbose|disasm|fmt_'),
    ('reference / spin lock',      r'reference|spin_lock|release_reg|rcu_protected|irq_flag'),
    ('attach target / trampoline', r'attach_target|tramp|struct_ops'),
    ('callbacks / subprogs',       r'callback|func_exit|subprog'),
    ('dynptr / iterator',          r'dynptr|_iter'),
    ('packet pointers',            r'pkt_pointer|pkt_ptr|find_good_pkt'),
    ('arena / map special',        r'arena|map_ptr|timer|wq|kptr|map_field'),
]

FUNC_RE = re.compile(r'^([0-9a-f]+) <(.+)>:$')
INSN_RE = re.compile(r'^\s*([0-9a-f]+):\t')


def static_sites(vmlinux):
    """addr -> function name, for every KCOV coverage point in the image."""
    sites, funcs, cur, pending = {}, [], None, False
    p = subprocess.Popen(['objdump', '-d', '--no-show-raw-insn', vmlinux],
                         stdout=subprocess.PIPE, text=True, bufsize=1 << 20)
    for line in p.stdout:
        m = FUNC_RE.match(line)
        if m:
            cur = m.group(2)
            funcs.append((int(m.group(1), 16), cur))
            pending = False
            continue
        m = INSN_RE.match(line)
        if not m:
            continue
        if pending:
            sites[int(m.group(1), 16)] = cur
            pending = False
        if 'call' in line and '__sanitizer_cov_trace_pc' in line:
            pending = True
    p.wait()
    funcs.sort()
    return sites, funcs


def symbol_owners(objdir):
    """function name -> object file, dropping every name more than one object defines.

    Every translation unit carries GCC's `_sub_I_65535_1`/`_sub_D_65535_0` stubs. Keying
    a dict by name hands them all to whichever file was read last, and in the first run
    of this script that single mistake put 5396 of 15241 coverage points — a third of the
    denominator — behind two symbols nothing could ever enter. An ambiguous name cannot
    attribute a PC, so it is dropped rather than guessed.
    """
    import glob
    import os
    owners = collections.defaultdict(set)
    for o in sorted(glob.glob(os.path.join(objdir, '*.o'))):
        base = os.path.basename(o)
        if base.endswith('.mod.o') or base == 'built-in.o':
            continue
        out = subprocess.run(['nm', '--defined-only', o], capture_output=True, text=True)
        for line in out.stdout.splitlines():
            f = line.split()
            if len(f) == 3 and f[1] in ('t', 'T'):
                owners[f[2]].add(base)
    return {s: next(iter(v)) for s, v in owners.items() if len(v) == 1}


def observed(log):
    pcs = set()
    for line in open(log, errors='replace'):
        if line.startswith('PCSET ') and 'total=' not in line:
            for t in line.split()[1:]:
                if re.fullmatch(r'[0-9a-f]{16}', t):
                    pcs.add(int(t, 16))
    return pcs


def main():
    vmlinux, log, objdir = sys.argv[1], sys.argv[2], sys.argv[3]
    sites, funcs = static_sites(vmlinux)
    sym2obj = symbol_owners(objdir)
    pcs = observed(log)
    hit = pcs & set(sites)

    def obj(fn):
        return sym2obj.get(fn) or sym2obj.get(fn.split('.')[0])

    print(f"COVFRAC image_sites={len(sites)} observed={len(pcs)} matched={len(hit)} "
          f"unmatched={len(pcs) - len(hit)}")
    # An unmatched PC is a coverage point this script's disassembly walk did not locate —
    # a jump table inside .text desynchronises objdump. They land in functions we DO
    # reach, and the same walk loses sites on the denominator side, so the error is not
    # one-sided. Reported so it is a measured limit and not a silent one.
    starts = [a for a, _ in funcs]
    lost = collections.Counter()
    for p in sorted(pcs - hit):
        i = bisect.bisect_right(starts, p) - 1
        lost[funcs[i][1] if i >= 0 else '?'] += 1
    print("COVFRAC unmatched-lands-in " +
          " ".join(f"{f}:{n}" for f, n in lost.most_common(6)))

    per_obj_n, per_obj_d = collections.Counter(), collections.Counter()
    for a, fn in sites.items():
        o = obj(fn)
        if o:
            per_obj_d[o] += 1
    for p in hit:
        o = obj(sites[p])
        if o:
            per_obj_n[o] += 1

    print("\nper kernel/bpf object:")
    for o, d in sorted(per_obj_d.items(), key=lambda kv: -per_obj_n.get(kv[0], 0)):
        n = per_obj_n.get(o, 0)
        if n or d >= 300:
            mark = '*' if o in VERIFICATION_PASS else ' '
            print(f" {mark} {o:22s} {n:6d} / {d:6d}  {100 * n / d:5.1f}%")

    vn = sum(per_obj_n.get(o, 0) for o in VERIFICATION_PASS)
    vd = sum(per_obj_d.get(o, 0) for o in VERIFICATION_PASS)

    per = collections.defaultdict(lambda: [0, 0])
    for a, fn in sites.items():
        if obj(fn) in VERIFICATION_PASS:
            per[fn][1] += 1
    for p in hit:
        fn = sites[p]
        if obj(fn) in VERIFICATION_PASS:
            per[fn][0] += 1
    never = sum(t for h, t in per.values() if h == 0)
    partial = sum(t - h for h, t in per.values() if h > 0)

    print(f"\nCOVFRAC verification_pass hit={vn} total={vd} pct={100 * vn / vd:.1f}")
    print(f"COVFRAC split reached={vn} unreached_in_entered_functions={partial} "
          f"in_functions_never_entered={never}")
    print(f"COVFRAC share_of_our_coverage_that_is_the_verifier="
          f"{100 * vn / max(1, len(hit)):.1f}")

    groups, rest = collections.Counter(), []
    for fn, (h, t) in per.items():
        if h:
            continue
        for name, pat in THEMES:
            if re.search(pat, fn):
                groups[name] += t
                break
        else:
            rest.append((t, fn))
    print(f"\nnever-entered, by theme ({never} points):")
    for name, n in groups.most_common():
        print(f"COVFRAC theme {name:30s} {n:5d}")
    print(f"COVFRAC theme {'everything else':30s} {sum(t for t, _ in rest):5d}")
    rest.sort(reverse=True)
    print("  largest ungrouped: " + ", ".join(f"{f}({t})" for t, f in rest[:10]))


main()
