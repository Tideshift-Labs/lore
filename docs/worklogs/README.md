# docs/worklogs/

Append-only chronological journal of work in **this repo** (`lore`, our fork on
`tideshift/main`). One entry per discrete chunk, numbered monotonically. Entries are written
*after* the work lands so a future session can catch up cold without reading the whole git log.

Convention borrowed from the `lorehub` repo's `docs/worklogs/README.md` (same shape, same
close-out `worklog-scribe` lane) — adopted here starting with the CR-009 chunk, per the workspace
`CLAUDE.md` ("`lore/` adopts them for substantial fork-side work").

## Naming

`NNN-kebab-case-summary.md`

- `NNN` is a zero-padded 3-digit number, monotonically increasing. **Never renumber existing
  entries.** Pick the next number; if two chunks land close together, file them in commit order.
- The slug should be specific enough to locate something from the directory listing.

## When to add

After any chunk that would be the body of a substantive PR description — a CR (change request)
landing, a multi-file refactor, or a bugfix spanning more than one crate. Skip trivial one-line
fixes; a commit message is enough for those.

## What goes in an entry

Aim for 30-60 lines. Required at the top:

- **Date** and **Status** (Done / In progress / etc.)
- **Summary** — one paragraph.
- **What changed** — concrete file/crate list or grouped notes.
- **Why now** — what triggered this.

Optional, high-value: **What this unblocks**, **Reviewer findings** (applied vs deferred, from
`lore-reviewer`), **Follow-ups created**, **Notes / surprises**.

Classify the change **[SERVER]** vs **[CLIENT]** where relevant (see `lore/CLAUDE.md` and the
`lore-fork-patches-inventory` learning) — SERVER-side is low-risk (we control the build);
CLIENT-side is gated on upstream merge.

Don't repeat content that lives in code or `docs/testing-guide.md`. Cross-reference instead.

## Relationship to other docs

| Doc | Scope | Cadence |
|---|---|---|
| `worklogs/` (this dir) | Chronological journal of work chunks | After each chunk |
| `docs/testing-guide.md` | How our fork-delta tests are organized + deep gotchas | Every `lore-test-specialist` run |
| `../lorehub/docs/lore-change-requests/` | The CR spec that drove a fork-side change (Lorehub-side tracking) | When a Lorehub need drives a Lore change |

## Index

No `bun`/JS tooling lives in this Rust workspace, so there is no `worklog-toc` auto-generation
script here (unlike `lorehub`) — the table below is maintained by hand; keep it newest-first.

<!-- toc:start -->

| # | Date | Title |
|---|---|---|
| 015 | 2026-07-29 | [Run upstream revision-tree integration suite after merge](015-run-upstream-revision-tree-integration-suite.md) |
| 014 | 2026-07-29 | [Merge upstream (33 commits) into `tideshift/main`](014-merge-upstream-33-commits-into-tideshift-main.md) |
| 013 | 2026-07-29 | [Preserve local-read overload classification (CR-021 Part 2c)](013-preserve-local-read-overload-cr021-part2c.md) |
| 012 | 2026-07-29 | [Branch-push metadata and no-op side-effect suppression](012-branch-push-metadata-and-noop-suppression.md) |
| 011 | 2026-07-26 | [lore-postgres: report infra-gated tests as ignored, not passed](011-lore-postgres-ignore-infra-gated-tests.md) |
| 010 | 2026-07-26 | [Add RepositoryStorageStats, a per-repo stored-bytes RPC (CR-016)](010-repository-storage-stats-cr016.md) |
| 009 | 2026-07-25 | [Report an overloaded store from the fragment walk (CR-021 Part 2b)](009-fragment-walk-overload-honesty-cr021-part2b.md) |
| 008 | 2026-07-25 | [Configurable AWS client retry (CR-021 Part 2a)](008-configurable-aws-client-retry-cr021-part2a.md) |
| 007 | 2026-07-25 | [Throttle honesty in `load_metadata` (CR-021 Part 1)](007-throttle-honesty-load-metadata-cr021-part1.md) |
| 006 | 2026-07-23 | [Provider-neutral authentication refresh (CR-020)](006-provider-neutral-authentication-refresh-cr020.md) |
| 005 | 2026-07-08 | [Bounded retry on the lorehub_notify post-commit hook (WP-066 Chunk 2)](005-lorehub-notify-bounded-retry-wp066.md) |
| 004 | 2026-07-04 | [Expose per-entry + revision total byte size on revision reads (CR-008)](004-tree-entry-size-cr008.md) |
| 003 | 2026-07-03 | [Scope RepositoryMetadataGet/Set to the caller's repository (CR-011)](003-repository-metadata-repo-authz-cr011.md) |
| 002 | 2026-07-03 | [Bind notification Subscribe to the JWT-authorized repository (CR-010)](002-notification-subscribe-repo-authz-cr010.md) |
| 001 | 2026-07-03 | [Opt-in graceful QUIC drain for loreserver (CR-009)](001-graceful-quic-drain-cr009.md) |

<!-- toc:end -->
