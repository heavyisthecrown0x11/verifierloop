# Building on Overleaf

## Upload

`verifierloop-paper-overleaf.zip` → Overleaf → **New Project → Upload Project**.

Overleaf selects `main.tex` itself as the main file (the only `\documentclass` in
the root directory is in it). The compiler is **pdfLaTeX**, the TeX Live version does
not matter — `acmart` has been in every Overleaf image since 2020.

What is in the zip: `main.tex` + eight `\input` files + `refs.bib`. `acmart.cls` and
`ACM-Reference-Format.bst` were **deliberately not included** — Overleaf's own TeX Live
already has them, and putting a copy in the directory produces a version conflict.

## Expected output

- **~7 pages**, two columns, `sigconf`.
- The numbers in the margins are **line numbers, not a word count.** They are the work
  of the `review` option (`acmart.cls:2516`), so that a reviewer can cite a line.
  Measured: **9 pages** whether `review` is on or off — it does not change the
  pagination. To remove it, delete `review` from the `\documentclass` line.
- In the title block, whitespace instead of an author and *"Conference acronym 'XX, June 03–05, 2018,
  Woodstock, NY"* — both are acmart's **placeholders**, not errors. They go away once
  `\author{...}` and `\acmConference{...}` are filled in at submission.
- The bibliography has three sources. `bibtex` runs automatically; if you see `[?]` on the
  first build, press **Recompile** once more.

## Submission / camera-ready switches

| stage | `\documentclass` | also |
|---|---|---|
| double-blind submission | `[sigconf,review,anonymous]` | `\acmConference{...}` must be filled in |
| camera-ready | `[sigconf]` | `\author`/`\affiliation` real, `\acmDOI`, `\acmISBN`, `\copyrightyear` |

The *"Conference'17, July 2017, Washington, DC, USA"* at the bottom of the page is the
placeholder acmart prints in the absence of `\acmConference` — not an error, but it looks
unfilled.

Measured structure: body pp.1–7, Appendix A p.8, REFERENCES p.9.

## Building the same thing locally

```bash
scripts/build-paper.sh          # -> paper/build/main.pdf
```

Requirements: `texlive-latex-recommended texlive-latex-extra texlive-publishers
texlive-fonts-recommended texlive-fonts-extra`. Without `texlive-fonts-extra`,
acmart falls back to Computer Modern instead of libertine and microtype gives a
**fatal** error, "auto expansion is only possible with scalable fonts" — this does
not happen on Overleaf, it happens locally.

## Regenerating the zip

```bash
scripts/make-overleaf-zip.sh    # -> paper/build/verifierloop-paper-overleaf.zip
```
