# Held-out batch 2 — PREREGISTRATION (sealed BEFORE verification)

Frame and question are the same as batch 1 (`PREREGISTRATION.md` §1, §3).
Draw: `sort frame.txt | sed -n '11,20p'` → `draw2.txt`. The same content-independent rule.

## Falsification condition — batch 1's was poorly written, corrected here

The condition I wrote in batch 1 conflated "a modeled predicate arm" with "recomputed
independently" (see `RESULTS-batch1.md` §2). In this batch the condition is:

> A **STATE** prediction is falsified if B is shown to **recompute that field
> independently and bind it to the VERDICT instead of consuming it from the kernel**. The field
> appearing in a modeled arm does not by itself falsify it — what is decisive is where
> the value that reaches the verdict comes from.
>
> An **IRRELEVANT** prediction is falsified if the touched function or field is modeled in
> B's source.

## Classification and predictions

| # | commit | date | decision | anchor | prediction |
|---|---|---|---|---|---|
| **H11** | `0db63c0b86e9` | 2024-04-26 | **STATE** | `mark_btf_ld_reg()`: if `type_may_be_null(flag)` then `reg->id = ++env->id_gen` | B **consumes** `id` from the capture (`id=` field, `check_ids`); an unassigned id arrives the same on both sides → invisible |
| H12 | `10e14e9652bf` | 2023-11-09 | IRRELEVANT | `push_insn()` — CFG discovery, `env->cfg.insn_state` | not in B's read set (A's domain) |
| H13 | `122fdbd2a030` | 2024-03-22 | IRRELEVANT | `check_alu_op()` — addr_space_cast rejection when there is no arena | verdict only |
| H14 | `12659d28615d` | 2024-12-02 | IRRELEVANT | `process_iter_arg()` — PTR_TO_STACK type check | argument validation |
| H15 | `17c4b65a2493` | 2024-11-08 | IRRELEVANT | `check_return_code()` — kprobe session retval range | program-exit path, not a pruning predicate (the `763aa759d3b2` precedent from 0102) |
| **H16** | `180c7000712d` | 2026-08-03 | **STATE** | `process_spin_lock()`: `invalidate_rcu_protected_refs()` on the final unlock | the invalidation writes the register `type`; B consumes `type` (`o['t'] != c['t']`), both sides carry the stale type → invisible |
| H17 | `18752d73c189` | 2024-09-13 | IRRELEVANT | `check_raw_mode_ok()` — helper proto arguments | not a state field |
| H18 | `18cdd90aba79` | 2025-02-27 | IRRELEVANT | `do_misc_fixups()` — `MOV32_IMM`→`MOV64_IMM` inline percpu | post-verification instruction rewrite (A's domain) |
| H19 | `1ae497c78f01` | 2024-09-05 | IRRELEVANT | `type_may_be_null()` moved to a header | pure refactor |
| H20 | `1b30d4441727` | 2025-08-01 | IRRELEVANT | `free_states()` / `compute_scc()` — `scc_cnt` memory leak | memory management |

**Batch 2 composition: 8 IRRELEVANT · 2 STATE · 0 PREDICATE.**
**Cumulative (20 cases): 17 IRRELEVANT · 3 STATE · 0 PREDICATE.**
