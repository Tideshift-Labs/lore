// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::file::stage::*;
use lore_revision::util::path::DepthPath;
use lore_revision::util::path::RelativePath;
use lore_revision::util::path::path_depth;

fn antichain(targets: &[&str]) -> Vec<RelativePath> {
    RelativePath::dedup_to_supersets(
        targets
            .iter()
            .map(|path| RelativePath::new_from_initial_path(path).expect("Path init failed"))
            .collect(),
    )
}

fn derived(targets: &[&str]) -> Vec<String> {
    shared_ancestors(&antichain(targets))
        .iter()
        .map(|ancestor| ancestor.path().to_string())
        .collect()
}

/// Every ancestor of every target, counted. What the scan over neighbours
/// arrives at without the counting.
fn counted(targets: &[RelativePath]) -> Vec<String> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for target in targets {
        let mut ancestor = target.clone();
        ancestor.pop();
        while !ancestor.is_empty() {
            *counts.entry(ancestor.as_str().to_string()).or_insert(0) += 1;
            ancestor.pop();
        }
    }
    let mut shared: Vec<String> = counts
        .into_iter()
        .filter_map(|(path, count)| (count >= 2).then_some(path))
        .collect();
    shared.sort_unstable_by(|a, b| path_depth(a).cmp(&path_depth(b)).then_with(|| a.cmp(b)));
    shared
}

#[test]
fn only_a_directory_two_targets_share_is_returned() {
    assert!(derived(&[]).is_empty());
    assert!(derived(&["a/b/c"]).is_empty());
    assert!(derived(&["a/x", "b/y"]).is_empty());
    assert_eq!(derived(&["a/x", "a/y"]), vec!["a"]);
}

#[test]
fn the_result_is_prefix_closed() {
    assert_eq!(derived(&["a/b/c/x", "a/b/c/y"]), vec!["a", "a/b", "a/b/c"]);
}

#[test]
fn one_depth_is_a_contiguous_range_shallowest_first() {
    let shared = shared_ancestors(&antichain(&[
        "a/p/x", "a/p/y", "a/q/x", "a/q/y", "b/p/x", "b/p/y",
    ]));
    let paths: Vec<&str> = shared.iter().map(DepthPath::path).collect();
    assert_eq!(paths, vec!["a", "b", "a/p", "a/q", "b/p"]);
    let depths: Vec<usize> = shared.iter().map(DepthPath::depth).collect();
    assert!(depths.windows(2).all(|pair| pair[0] <= pair[1]));
}

/// Two case variations of one directory would be two ancestors naming one
/// node, and the depth holding both would add it twice. The target set they
/// are taken from settles on one, and that is what carries into here.
#[test]
fn targets_on_one_case_variation_give_ancestors_on_one() {
    assert_eq!(
        derived(&["Assets/Meshes/a", "assets/meshes/b", "ASSETS/Meshes/c"]),
        vec!["Assets", "Assets/Meshes"]
    );
}

/// The scan reads neighbours, so the shapes that matter are the ones where
/// lexicographic order puts something unrelated between two targets, or
/// where a shared string prefix stops inside a component.
#[test]
fn it_agrees_with_counting_every_ancestor() {
    for targets in [
        &[][..],
        &["a/b/c"],
        &["a/x", "a/y"],
        &["a/x", "b/y"],
        &["a/b/c/d/x", "a/b/c/d/y"],
        &["a/p/x", "a/p/y", "a/q/x", "a/q/y", "b/p/x", "b/p/y"],
        // '-' sorts below '/', so this lands between "a" and its subtree.
        &["a/x", "a-foo/y", "a/z"],
        // '0' sorts above '/', so this lands after the subtree.
        &["a/x", "a0/y", "a/z"],
        // A shared string prefix that stops inside a component.
        &["a/b/x", "a/bc/y", "a/b/z"],
        // A directory target covering the files beneath it.
        &["a/b", "a/b/x", "a/b/y", "a/c/x", "a/c/y"],
        // Three levels, and a lone target beside them.
        &["t/m/l/f", "t/m/l/g", "t/m/n/f", "t/m/n/g", "u/v/w/x"],
    ] {
        let antichain = antichain(targets);
        let derived: Vec<String> = shared_ancestors(&antichain)
            .iter()
            .map(|ancestor| ancestor.path().to_string())
            .collect();
        assert_eq!(derived, counted(&antichain), "{targets:?}");
    }
}
