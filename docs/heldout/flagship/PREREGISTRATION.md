# REPRODUCTION of the flagship partition — PREREGISTRATION (sealed BEFORE classification)

## Why

Reviewer objection A: the paper's headline number (58%/5%) comes from a 40-commit partition,
and that partition's **list was not kept as an artifact**. Recovery was attempted and failed:
0102's criterion ("body quotes verifier state") was a judgment, not a regex —
the closest mechanical proxy gives 68, not 50; there is no fan-out artifact in the old session
scratchpads or in .lab; the devlog names 9 SHAs. **The list is lost.** So, instead of managing it
with wording, the partition is regenerated from scratch, in an auditable form.

## Frame — this time mechanical and on disk

`git log --grep=^Fixes:` (up to 5e289c5a4a52, six state-equivalence files) →
437; body quotes verifier state by this regex → **68**:
`R[0-9]+(_w)?=|var_off|smin_value|umax_value|umin_value|smax_value|tnum\(|scalar\(|u32_m(in|ax)`
minus 16 calibration pairs, minus 28 held-out (already classified) → **FRAME = 57**
(`frame.txt`, `frame-subjects.txt`). This set is **not the same** as the original 40 and will not
be presented as such; the same *kind* of frame, this time reproducible.

## Design — two raters, both under a protocol sealed before classification

- **Rater 1** (this session): §3.3's question, from the diff alone, with a file:function anchor,
  using the CORRECTED trichotomy (Yes / No-unconsumed / No-examined / Undecided — §3.3's
  new "No" distinction). The result is `RATER1.txt`, committed without reading rater 2.
- **Rater 2** (a blind model instance): `PACKET.md` (the same question and consumption-set
  definition as the held-out packet) — reading `docs/heldout/` is forbidden. The result is `RATER2.txt`.
- Rater 1 and 2 run **concurrently**; neither sees the other. The order is audited from git.

## What will be reported

1. The new partition's composition (Yes / No / Undecided, and No's two subtypes).
2. κ (Rater 1 × Rater 2), on the trichotomy; every disagreement with both its rationales.
3. **Comparison with the old 23/2/15** — only at the aggregate level, because the old list does not exist.
   If the new blind share is close to the old, the headline stands and is now auditable; if it is far,
   the headline is pulled to the NEW number and the old number is reported as "an unrecoverable first attempt."
4. Rater 1's Undecided count as well — if it comes out zero, §6's suspicion still holds.

## The headline's fate — in advance

The paper's 58%/5% will be replaced with the result of **this partition**, whichever way it goes.
The old partition will be noted in the Appendix as "could not be reproduced."
