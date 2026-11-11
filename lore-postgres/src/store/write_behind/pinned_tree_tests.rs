// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift), WP-115 drain guard (review B1 of round 4): a
//! staged read opens its file beneath the pinned `staged/` descriptor, and a
//! miss counts only while the root path still names the pinned root and its
//! pinned `staged/`. Linux only (`openat2`).
//!
//! A hook runs between the root check and the open, so a test can replace
//! `<root>/staged` exactly there.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use super::ConfinedRoot;
use super::WriteBehindError;
use super::derived_staged_key;

type Action = Arc<dyn Fn() + Send + Sync>;

static BEFORE_READ: std::sync::LazyLock<Mutex<BTreeMap<PathBuf, Action>>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Called by the staged read after its first root check, before the open.
pub(super) fn before_read(path: &Path) {
    let action = BEFORE_READ.lock().unwrap().get(path).cloned();
    if let Some(action) = action {
        action();
    }
}

/// Runs `action` before each read of `path` until dropped.
struct Armed(PathBuf);

impl Armed {
    fn new(path: &Path, action: impl Fn() + Send + Sync + 'static) -> Self {
        BEFORE_READ
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), Arc::new(action));
        Self(path.to_path_buf())
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        BEFORE_READ.lock().unwrap().remove(&self.0);
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lore-pinned-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Replace `<root>/staged` with a new empty directory.
fn swap_staged(root: &Path) {
    std::fs::rename(root.join("staged"), root.join("staged.moved")).unwrap();
    std::fs::create_dir(root.join("staged")).unwrap();
}

/// `<root>/staged` is replaced after the first root check: a miss is
/// refused (the check after the miss fails), never `Ok(None)`. Without that
/// check the miss would read as absent.
#[tokio::test]
async fn a_staged_dir_replaced_before_a_miss_is_refused_not_absent() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0x31; 32];
    let resolved = root
        .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
        .unwrap();
    assert_eq!(root.read_regular(&resolved).await, Ok(None), "control");
    let at = scratch.0.clone();
    let _armed = Armed::new(resolved.path(), move || swap_staged(&at));
    assert_eq!(
        root.read_regular(&resolved).await,
        Err(WriteBehindError::RootDeviceChanged)
    );
}

/// `<root>/staged` is replaced after the first root check: the read still
/// opens the file beneath the PINNED `staged/` (now at `staged.moved`), so a
/// file this stage staged is found there. A read through the path would
/// miss in the new directory instead.
#[tokio::test]
async fn a_staged_dir_replaced_before_a_hit_still_reads_the_pinned_file() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0x32; 32];
    let resolved = root
        .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
        .unwrap();
    super::super::finalize::finalize(&root, &resolved, &bytes::Bytes::from_static(b"pinned"))
        .await
        .expect("staged");
    let at = scratch.0.clone();
    let _armed = Armed::new(resolved.path(), move || swap_staged(&at));
    assert_eq!(
        root.read_regular(&resolved).await.unwrap().as_deref(),
        Some(b"pinned".as_slice())
    );
}

/// `<root>/staged` is replaced after open: a finalizer still creates its
/// fan-out directories beneath the PINNED `staged/`, never by path in the
/// new directory. (`finalize` refuses earlier, at its root check; this is
/// the step after it.)
#[test]
fn fanout_dirs_are_created_beneath_the_pinned_staged_dir() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0x33; 32];
    let resolved = root
        .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
        .unwrap();
    swap_staged(&scratch.0);
    root.ensure_parent(&resolved)
        .map(|_| ())
        .expect("created beneath the pinned staged dir");
    assert!(scratch.0.join("staged.moved/33/33").is_dir());
    assert!(!scratch.0.join("staged/33").exists());
}
