# paper/

Source: `main.tex` (skeleton + section contracts), `intro.tex` (written),
`refs.bib` (only entries read from source).

**Building cannot be done here** — `acmart.cls` is not in the container. Upload to
Overleaf, or run `latexmk -pdf main.tex` on a machine with `texlive-publishers`
installed.

## Three structural decisions made up front

1. **The page limit is not written as a number.** It is to be filled from the CFP. A
   made-up number in this project is the very thing we exist to avoid.
2. **Case study ≤ 2.5 pages, hard.** The material behind it is a 112-entry
   engineering log; its weight pulls the section toward chronology, and chronology is
   the log wearing a paper's clothes. The content allowed in §5 of `main.tex` is
   written out item by item, and so is what is forbidden.
3. **The map is a single figure in the body, all of it in Appendix A.** An empty cell
   means "untested", not "blind" — the appendix has to say this where the reader will
   see it.

## Filter

The last sentence of `intro.tex` is the filter for the case study. Every paragraph
written in §5 must pass the test "does this carry the *where the reference reads*
claim". If it does not, it is chronology and it comes out.

## Venue

acmart sigconf, aimed at ISSTA. ICSE is the same class; the ISSTA-collocated workshops
are a shorter form of the same class. Moving down or sideways is a format change, not a
rewrite. The follow-up work (partitioning the external defect population) does not go
into this paper; it is named by design in §7.
