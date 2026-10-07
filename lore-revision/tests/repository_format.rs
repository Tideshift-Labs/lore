// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
mod tests {
    #![allow(clippy::disallowed_methods)] // Test fixture writes; not subject to repository write-token discipline.

    use lore_base::test_util::TempDir;
    use lore_revision::repository::DOT_URC;
    use lore_revision::repository::DOT_URCIGNORE;
    use lore_revision::util::path::RelativePath;

    fn assert_ignored(
        filter: &lore_revision::filter::Filter,
        path: &str,
        directory: bool,
        expected: bool,
    ) {
        assert_eq!(
            filter.ignore.excludes(
                &RelativePath::new_from_initial_path(path).expect("fixture path"),
                directory
            ),
            expected,
            "ignore behavior for {path}"
        );
    }

    #[test]
    fn hash_salt_divergence_between_formats() {
        // Same function name, different salts -> different keys (R2, R11)
        let key_urc = lore_storage::hash::hash_function(b"urc", "test_func");
        let key_lore = lore_storage::hash::hash_function(b"lore", "test_func");
        assert_ne!(key_urc, key_lore);

        // Same salt -> same key (deterministic)
        let key_urc2 = lore_storage::hash::hash_function(b"urc", "test_func");
        assert_eq!(key_urc, key_urc2);
    }

    #[test]
    fn discovery_finds_lore_directory() {
        // Simulate directory walk: a parent with .lore/ should be found
        let temp = TempDir::new("lore-test-discovery-lore-");
        let base = temp.path().to_path_buf();
        let nested = base.join("a").join("b");
        std::fs::create_dir_all(&nested).expect("create nested dirs");
        std::fs::create_dir_all(base.join(".lore")).expect("create .lore dir");

        // Walk up from nested, looking for .lore or .urc
        let mut current = nested.as_path();
        let found = loop {
            if current.join(".urc").is_dir() || current.join(".lore").is_dir() {
                break Some(current.to_path_buf());
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break None,
            }
        };
        assert_eq!(found, Some(base.clone()));
    }

    #[test]
    fn discovery_finds_urc_directory() {
        let temp = TempDir::new("lore-test-discovery-urc-");
        let base = temp.path().to_path_buf();
        let nested = base.join("a").join("b");
        std::fs::create_dir_all(&nested).expect("create nested dirs");
        std::fs::create_dir_all(base.join(".urc")).expect("create .urc dir");

        let mut current = nested.as_path();
        let found = loop {
            if current.join(".urc").is_dir() || current.join(".lore").is_dir() {
                break Some(current.to_path_buf());
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break None,
            }
        };
        assert_eq!(found, Some(base.clone()));
    }

    #[test]
    fn load_filter_lore_format_falls_back_to_urcignore() {
        use lore_revision::repository::load_filter;

        let temp = TempDir::new("lore-test-ignore-fallback-");
        let dir = temp.path().to_path_buf();
        std::fs::create_dir_all(dir.join(".lore")).expect("create .lore dir");

        // Write a .urcignore with a pattern (no .loreignore present)
        std::fs::write(dir.join(".urcignore"), "secret.txt\n").expect("write .urcignore");

        let filter = load_filter(&dir).expect("filter should load");
        // The ignore filter should contain user-defined rules from .urcignore
        // One user rule plus eight generated exclusions, including the bootstrap lock.
        assert_eq!(filter.ignore.lines.len(), 9);
        assert_ignored(&filter, "secret.txt", false, true);
        assert_ignored(&filter, "a.txt", false, false);
        assert_ignored(&filter, ".lore-workflow", true, true);
        assert_ignored(&filter, ".lore-workflow.bootstrap.lock", false, true);
    }

    #[test]
    fn load_filter_lore_format_prefers_loreignore() {
        use lore_revision::repository::load_filter;

        let temp = TempDir::new("lore-test-ignore-prefer-");
        let dir = temp.path().to_path_buf();
        std::fs::create_dir_all(dir.join(".lore")).expect("create .lore dir");

        // Both files present — .loreignore should win
        std::fs::write(dir.join(".loreignore"), "a.txt\nb.txt\n").expect("write .loreignore");
        std::fs::write(dir.join(".urcignore"), "secret.txt\n").expect("write .urcignore");

        let filter = load_filter(&dir).expect("filter should load");
        // Two primary-file rules plus eight generated exclusions.
        assert_eq!(filter.ignore.lines.len(), 10);
        assert_ignored(&filter, "a.txt", false, true);
        assert_ignored(&filter, "b.txt", false, true);
        assert_ignored(&filter, "secret.txt", false, false);
        assert_ignored(&filter, ".lore-workflow", true, true);
        assert_ignored(&filter, ".lore-workflow.bootstrap.lock", false, true);
    }

    #[test]
    fn load_filter_urc_format_falls_back_to_urcignore() {
        use lore_revision::repository::load_filter;

        // The .urcignore fallback is universal: even a legacy .urc-format
        // repository (whose primary ignore file is now also .loreignore) loads
        // a lone .urcignore when no .loreignore is present.
        let temp = TempDir::new("lore-test-ignore-fallback-urc-");
        let dir = temp.path().to_path_buf();
        std::fs::create_dir_all(dir.join(DOT_URC)).expect("create .urc dir");

        std::fs::write(dir.join(DOT_URCIGNORE), "secret.txt\n").expect("write .urcignore");

        let filter = load_filter(&dir).expect("filter should load");
        // Legacy repositories receive the same eight generated exclusions.
        assert_eq!(filter.ignore.lines.len(), 9);
        assert_ignored(&filter, "secret.txt", false, true);
        assert_ignored(&filter, "a.txt", false, false);
        assert_ignored(&filter, ".lore-workflow", true, true);
        assert_ignored(&filter, ".lore-workflow.bootstrap.lock", false, true);
    }
}
