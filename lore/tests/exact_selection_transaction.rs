// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT

#![allow(clippy::disallowed_methods)] // Contenders intentionally start outside Lore command context.

mod test_util;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use lore::repository::LoreRepositoryCreateArgs;
    use lore_revision::exact_selection::ExactSelectionOptions;
    use lore_revision::exact_selection::ExpectedFileAction;
    use lore_revision::exact_selection::FileMetadataSelection;
    use lore_revision::exact_selection::SelectedFile;
    use lore_revision::interface::LoreEvent;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::repository::RepositoryWriteToken;

    use super::test_util::TempDir;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn facade_releases_client_token_and_context_for_competing_writer() {
        let tempdir = TempDir::new("lore-exact-selection-facade-");
        let repository_path = tempdir.path().to_path_buf();
        let globals = LoreGlobalArgs {
            repository_path: repository_path.as_path().into(),
            offline: 1,
            identity: "exact-selection-facade-test".into(),
            ..Default::default()
        };
        let create = LoreRepositoryCreateArgs {
            repository_url: format!("lore://localhost/{}", uuid::Uuid::now_v7()).into(),
            id: LoreString::default(),
            description: LoreString::default(),
            use_shared_store: 0,
            shared_store_path: LoreString::default(),
        };
        assert_eq!(
            lore::repository::create(globals.clone(), create, None).await,
            0,
            "create facade exact-selection repository"
        );

        let mut files = Vec::new();
        for index in 0..100 {
            let path = format!("actor-{index:03}.bin");
            std::fs::write(repository_path.join(&path), b"facade bytes\n")
                .expect("write facade exact-selection input");
            files.push(SelectedFile {
                path,
                expected_effective_action: ExpectedFileAction::Add,
                source_hash: Some("0d53bad53f9f2a053fdf0faa5c07a205".to_string()),
                file_metadata: FileMetadataSelection::Unchanged,
            });
        }
        let options = ExactSelectionOptions {
            message: "facade exact-selection transaction".to_string(),
            files,
            revision_metadata: Vec::new(),
            stats: false,
        };

        // Hold the path mutex while the facade reaches its internal acquisition,
        // then enqueue a second writer behind it. Tokio's mutex is FIFO.
        let gate = RepositoryWriteToken::acquire(&repository_path).await;
        let stage_started = Arc::new(AtomicBool::new(false));
        let callback_started = stage_started.clone();
        let facade = tokio::spawn(lore::revision::commit_exact_selection(
            globals,
            options,
            Some(Box::new(move |event| {
                if matches!(event, LoreEvent::FileStageBegin(_)) {
                    callback_started.store(true, Ordering::SeqCst);
                }
            })),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !facade.is_finished(),
            "facade must wait while the preceding CLIENT token is held"
        );

        let competing_path = repository_path.clone();
        let competing =
            tokio::spawn(async move { RepositoryWriteToken::acquire(&competing_path).await });
        tokio::task::yield_now().await;
        drop(gate);

        tokio::time::timeout(Duration::from_secs(10), async {
            while !stage_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("facade must acquire the CLIENT token and begin staging");
        assert!(
            !competing.is_finished(),
            "competing writer must remain blocked while facade token/context are live"
        );

        let result = tokio::time::timeout(Duration::from_secs(30), facade)
            .await
            .expect("facade transaction must finish")
            .expect("facade task must not panic")
            .expect("facade exact-selection transaction must commit");
        assert!(!result.revision.is_zero());

        let competing_token = tokio::time::timeout(Duration::from_secs(2), competing)
            .await
            .expect("competing writer must acquire after facade cleanup")
            .expect("competing writer task must not panic");
        drop(competing_token);
    }
}
