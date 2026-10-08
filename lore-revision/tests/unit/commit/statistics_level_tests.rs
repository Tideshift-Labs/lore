// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_revision::commit::*;
use lore_revision::interface::ExecutionContext;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::relay::EventDispatcher;

/// Run `body` under an execution context asking for `stats`.
async fn at_statistics_level<T>(stats: u32, body: impl Future<Output = T>) -> T {
    let globals = LoreGlobalArgs {
        stats,
        ..Default::default()
    };
    let execution = Arc::new(ExecutionContext::new_client(
        globals,
        EventDispatcher::no_dispatch(),
    ));
    LORE_CONTEXT.scope(execution, body).await
}

/// Statistics level zero reports nothing, so it keeps nothing beyond what a
/// progress event reads: the content read off disk, which it reports as the
/// bytes transferred.
#[tokio::test]
async fn a_count_is_kept_only_where_something_reports_it() {
    for (level, kept) in [(0, 0), (1, 1)] {
        let files = at_statistics_level(level, async {
            let stats = CommitStats::new();
            stats.file_read(4096);
            stats.record_file_action(0, 4096);
            stats.file_stats()
        })
        .await;

        assert_eq!(files.files, kept, "level {level}");
        assert_eq!(files.files_read, kept, "level {level}");
        assert_eq!(files.file_bytes, kept * 4096, "level {level}");
        assert_eq!(files.bytes_transferred, 4096, "level {level}");
    }
}
