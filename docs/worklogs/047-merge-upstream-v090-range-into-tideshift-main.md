# Merge upstream v0.9.0 range into `tideshift/main`

**Date:** 2026-08-30
**Status:** Done, merged locally; not pushed.
**Classification:** [CLIENT]. The reconciliation is all `lore-revision`, `lore-transport` and
`lore/tests`; the merge itself is upstream's code.

Merge `ea3306a` takes Epic's 23 commits `7e785450..65822ad4` (144 files, v0.9.0 plus nine post-tag
commits) onto fork tip `168b1eb`, followed by `d66fa95` and `00f3d77`. A merge, not a rebase like
[029](029-rebase-tideshift-main-latest-upstream.md): those 234 fork commits are already published on
`origin/tideshift/main`, and replaying them would need a force push over history other checkouts
hold. 029 rebased because its predecessor had never been published, which is not the case here.

## Unique evidence

**Merge fidelity, measured rather than asserted.** Across all 377 files the fork has patched since
`7e785450`, the fork's added and removed lines are byte-identical before and after the merge for
**373**. The four that differ are exactly the four resolved by hand (`Cargo.lock`, `commit.rs`,
`exact_selection.rs`, `revision/sync.rs`). Nothing was silently dropped.

**A merge can drop a parameter without conflicting.** Git textually merged upstream's new
`modified_times` onto the fork's `commit_files_and_rehash` wrapper while the wrapper's delegation
call still passed only the fork's `None`. It compiled, and no conflict marker pointed at it. Found by
reading whole functions around each conflict rather than only the marked regions.

**`b98b4d6`'s renumbering broke five fork-owned pins, not one.** INV-EK predicted the
lorehub-desktop constant and did not look inside the fork:
`lore/tests/merge_finalize_transaction.rs` pinned 21/1/23 and `lore-transport/src/error.rs` pinned
12/6 (now 40/3/43 and 16/28). All five are the CLI exit-status contract, so they stay pinned
numerically; each now names `lore-base/src/error.rs`.

**`start_paused` is unsound over real I/O in this workspace.** `#[tokio::test(start_paused = true)]`
is the documented pattern for timer-driven tests, but wrapping `lore_io` work in `tokio::time::timeout`
under the auto-advancing clock reports the full budget elapsed regardless of outcome. Proven: a
deliberately broken comparison still reported the full budget and passed vacuously. Recorded in
`docs/testing-guide.md`.

**One fork-local divergence inside upstream code.** `state.rs` in `wait_until_settled` trips
`clippy::nonminimal_bool` on our toolchain (1.95.0) where upstream's gate did not. Took clippy's own
`is_none_or` rewrite; confirmed behaviour-identical by truth table, including the `None` case the doc
comment depends on. Expect it at the next merge; worth sending upstream.

**Disk, not code, nearly blocked this.** `D:` had 3.5 GB free against a 229 GB `lore/target`;
`target/debug/incremental` alone was 94.2 GB. Check free space before scheduling a refresh.

## Gates

`cargo +nightly fmt --all --check` and `cargo clippy --workspace --all-targets -D warnings
--no-deps` clean. `cargo test --workspace`: **4172 passed / 0 failed / 213 ignored** across 191
binaries plus 20 doctest targets.

Live runners, five green: domain-enforcement PASS=7/7, domain-maintenance PASS=20/20,
fragment-lifecycle PASS=30/30, local-authority 9/9, cell-schema-install 5/5.

**`run-lock-fencing-live.ps1` is NOT RUN — PASS=0 FAIL=0 NOT RUN=29 EXPECTED=29.** Its inventory
guard fail-closed before provisioning: `domain::tests::a_mediated_prepare_key_cannot_be_consumed_by_a_repository_scoped_governed_mutation`
is an ignored case under a prefix this runner claims, but is absent from its `Cases` list. **This
predates the merge.** That test arrived in `168b1eb`, the fork commit immediately before it, and
`ea3306a` touched neither the runner nor `lore-server/src/domain`, so both guard inputs are unchanged
across the merge. The guard is working as designed. The fix belongs to whoever owns `168b1eb`: that
case is executed by `run-domain-enforcement-live.ps1` (its seventh), so the runner needs a
covered-elsewhere acknowledgement rather than a new execution entry. Not papered over here.

## Deferrals and pointers

- Downstream: lorehub `1df8f11c` (repository-name mirror) and `6239a17f` (linked-diff posture), both
  green; lorehub-desktop `23321d5` (FFI 39 -> 44, a guard test deriving the value from the merged
  `lore_base::error::LocalModifications::FFI_CODE`, and a `LoreBranchInfoArgs` link-field fix).
  **The desktop gate is split:** lib tier 174/0 against the merged tree, but `src-tauri` and
  integration tiers NOT RUN because `clear_session_on_empty_store_is_idempotent_and_leaves_parseable_file`
  fails against this range. Queued as its own slice.
- INV-DS was **not** re-pinned; its own rule is that an artifact re-pins when its own entry gate is
  cleared, and this refresh clears none.
- INV-EK carries a dated addendum recording actuals against its predictions.
