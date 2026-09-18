// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Observe actual directory fsync completion. These tests do not simulate power loss.

use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use super::ConfinedRoot;
use super::WriteBehindError;
use super::derived_staged_key;

type Observer = Box<dyn FnMut(&Path, bool) -> Result<(), WriteBehindError>>;
thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

pub(super) fn observe_sync(path: &Path, completed: bool) -> Result<(), WriteBehindError> {
    OBSERVER.with_borrow_mut(|observer| {
        if let Some(observer) = observer {
            observer(path, completed)
        } else {
            Ok(())
        }
    })
}

struct Hook;
impl Hook {
    fn install(
        observer: impl FnMut(&Path, bool) -> Result<(), WriteBehindError> + 'static,
    ) -> Self {
        OBSERVER.with_borrow_mut(|slot| {
            assert!(slot.is_none());
            *slot = Some(Box::new(observer));
        });
        Self
    }
}
impl Drop for Hook {
    fn drop(&mut self) {
        OBSERVER.with_borrow_mut(|slot| *slot = None);
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lore-fsync-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record_completed() -> (Hook, Arc<Mutex<Vec<PathBuf>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let recorded = paths.clone();
    let hook = Hook::install(move |path, completed| {
        if completed {
            recorded.lock().unwrap().push(path.to_path_buf());
        }
        Ok(())
    });
    (hook, paths)
}

#[test]
fn open_syncs_root_after_provisioning_both_top_level_directories() {
    let scratch = Scratch::new();
    let root_path = scratch.0.canonicalize().unwrap();
    let observed = Arc::new(Mutex::new(false));
    let completed = observed.clone();
    let expected = root_path.clone();
    let _hook = Hook::install(move |path, done| {
        if path == expected && done {
            assert!(path.join("staged").is_dir());
            assert!(path.join("incoming").is_dir());
            *completed.lock().unwrap() = true;
        }
        Ok(())
    });
    ConfinedRoot::open(&root_path).expect("open fresh root");
    assert!(
        *observed.lock().unwrap(),
        "root provisioning must complete its parent fsync"
    );
}

#[test]
fn root_fsync_failure_refuses_open() {
    let scratch = Scratch::new();
    let root_path = scratch.0.canonicalize().unwrap();
    let expected = root_path.clone();
    let _hook = Hook::install(move |path, done| {
        if path == expected && !done {
            return Err(WriteBehindError::RootProbeFailed);
        }
        Ok(())
    });
    assert!(matches!(
        ConfinedRoot::open(&root_path),
        Err(WriteBehindError::RootProbeFailed)
    ));
}

#[test]
fn each_writer_syncs_both_ancestors_even_when_creator_has_not_synced_them() {
    for pause_at_first_parent in [true, false] {
        let scratch = Scratch::new();
        let root = ConfinedRoot::open(&scratch.0).unwrap();
        let staged = scratch.0.canonicalize().unwrap().join("staged");
        let first_parent = staged.join("ab");
        let pause_path = if pause_at_first_parent {
            staged.clone()
        } else {
            first_parent.clone()
        };
        let hash = [0xab; 32];
        let first = root
            .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
            .unwrap();
        let second = root
            .resolve(&hash, 2, &derived_staged_key(&hash, 2).unwrap())
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let creator_root = root.clone();
        let creator = std::thread::spawn(move || {
            let _hook = Hook::install(move |path, done| {
                if path == pause_path && !done {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                Ok(())
            });
            creator_root.ensure_parent(&first)
        });
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let (_hook, paths) = record_completed();
        let result = if entered.is_ok() {
            root.ensure_parent(&second)
        } else {
            Err(WriteBehindError::RootProbeFailed)
        };
        let _ = release_tx.send(());
        let creator_result = creator.join().expect("creator finishes");
        entered.expect("creator reached fsync before release");
        creator_result.expect("creator succeeds");
        result.expect("second writer succeeds independently");
        assert_eq!(
            *paths.lock().unwrap(),
            vec![staged, first_parent],
            "second writer must complete both parent fsyncs before returning"
        );
    }
}

#[test]
fn existing_fanout_parent_fsync_failure_refuses_the_second_writer() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0xab; 32];
    let resolved = root
        .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
        .unwrap();
    root.ensure_parent(&resolved).unwrap();
    for failed_parent in [scratch.0.join("staged"), scratch.0.join("staged/ab")] {
        let _hook = Hook::install(move |path, done| {
            if path == failed_parent && !done {
                return Err(WriteBehindError::RootProbeFailed);
            }
            Ok(())
        });
        assert_eq!(
            root.ensure_parent(&resolved),
            Err(WriteBehindError::RootProbeFailed)
        );
    }
}
