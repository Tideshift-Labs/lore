// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Test-only path-scoped elapsed counters. Nested totals are inclusive, not additive wall time.

use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Metric {
    pub count: usize,
    pub total: Duration,
    pub max: Duration,
}

type Counters = Arc<Mutex<BTreeMap<&'static str, Metric>>>;
fn registry() -> &'static Mutex<BTreeMap<PathBuf, Counters>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Counters>>> = OnceLock::new();
    REGISTRY.get_or_init(Default::default)
}

pub(super) struct Probe {
    root: PathBuf,
    counters: Counters,
}
impl Probe {
    pub fn install(root: PathBuf) -> Self {
        let counters = Arc::default();
        let mut registered = registry().lock().unwrap();
        assert!(
            !registered
                .keys()
                .any(|old| root.starts_with(old) || old.starts_with(&root)),
            "diagnostic fixture roots must not overlap"
        );
        registered.insert(root.clone(), Arc::clone(&counters));
        Self { root, counters }
    }
    pub fn snapshot(&self) -> BTreeMap<&'static str, Metric> {
        self.counters.lock().unwrap().clone()
    }
}
impl Drop for Probe {
    fn drop(&mut self) {
        registry().lock().unwrap().remove(&self.root);
    }
}

/// Each call owns its own start time, including overlapping waits from distinct workers.
pub(super) struct Span {
    phase: &'static str,
    started: Instant,
    counters: Option<Counters>,
}
pub(super) fn start(path: Option<&Path>, phase: &'static str) -> Span {
    let counters = path.and_then(|path| {
        registry()
            .lock()
            .unwrap()
            .iter()
            .find(|(root, _)| path.starts_with(root))
            .map(|(_, counters)| Arc::clone(counters))
    });
    Span {
        phase,
        started: Instant::now(),
        counters,
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed();
        if let Some(counters) = &self.counters {
            let mut counters = counters.lock().unwrap();
            let metric = counters.entry(self.phase).or_default();
            metric.count += 1;
            metric.total += elapsed;
            metric.max = metric.max.max(elapsed);
        }
    }
}
