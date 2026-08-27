# docs/worklogs/

Append-only evidence journal for our **Lore fork**. Use it for substantial fork-side evidence, not
as a receipt for every change.

## When to add

Add one only when at least one applies:

- live/staging incident or discriminating experiment;
- cross-repo, protocol, storage, or architectural transition whose chronology matters;
- unique evidence such as timings, corpus/churn counts, hashes, or compatibility results;
- unresolved reviewer finding or upstream hand-off with no better tracker;
- multi-session campaign reaching a meaningful phase boundary.

Otherwise use the signed commit, Lore change request, issue, or current-state documentation. Batch
repetitive waves.

## Shape

Name entries `NNN-kebab-summary.md`; reserve the next monotonic number and never renumber or edit a
landed entry. Keep new entries about 15-30 lines with date/status, [SERVER]/[CLIENT] classification
when relevant, outcome/why, unique evidence or deferrals, and pointers.

Omit routine file inventories, standard gate lists, and zero-finding reviews. There is deliberately
no directory index; use `rg --files docs/worklogs` or Git history on demand.
