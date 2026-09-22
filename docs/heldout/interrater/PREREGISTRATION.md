# Inter-rater PREREGISTRATION — sealed BEFORE the run

Reviewer objection 6: *"the partition was produced 'with assistance', audited once, zero
undecided out of 40… not measuring reproducibility in a method whose output is a classification
leaves the heart of the contribution empty."* Correct. This is what §4.5 calls the "smallest experiment."

## Sample — and why not 40

**28 held-out commits** (`draw.txt` + `draw2.txt` + `draw4.txt`). The flagship 40-commit
partition **cannot be re-scored**, because the commit list was not recorded —
there are only the aggregate counts and a few SHAs named in devlog 0102. This is a gap against §4.2's
"check any row of it" claim and should be stated in the paper.

## Rater 2

An independent model instance (fresh context), reading only `PACKET.md`: §3.3's question,
the factual definition of B's consumption set, 28 diffs. **It has no access to the labels**
(`docs/heldout/` is excluded and reading it is forbidden). Rater 1 = the classifier in this session.
**Rater 2 is not a human**; this narrows what the experiment measures —
"does an independent reader reading the same question from the same source give the same answer", not
human-rater agreement. It enters the paper with this limit.

## Level of comparison

§3.3's **trichotomy**: Yes / No / Undecided. Rater 1's labels are mapped:
STATE → Yes; VISIBLE, PREDICATE-invisible, UNMODELED, IRRELEVANT → No.
Gold: **7 Yes, 21 No, 0 Undecided.**

## Metric and the expectation stated in advance

- Raw agreement and **Cohen's κ** (3 classes). With a 7/21 distribution, chance agreement is high; κ is
  more informative than raw agreement.
- Every disagreement is reported **with both rationales**; no silent resolution, the gold is
  not changed.
- Rater 2's **Undecided count** is reported separately. Rater 1 gave zero; if Rater 2
  gives more than zero, this counts as evidence in favor of the reviewer's "reluctance to say
  uncertain" suspicion and will be written as such.
- No threshold (a threshold is an invitation to gaming). The Landis–Koch band is reported.

## Falsification

If κ < 0.6, §4.2's auditability claim is **weakened**, "check any row" being replaced
with "rows disagree at rate X". If κ ≥ 0.8, the paper writes this, with its limit
(a model rater), into §4.5.
