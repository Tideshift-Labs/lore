// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore::interface::LoreEventCallback;
use lore_base::error::RepositoryNotFound;
use lore_revision::event::EventError;
use lore_revision::repository::RepositoryError;

pub(crate) mod test_support;

use std::sync::Mutex;

use lore::call::*;
use lore_base::error::NotFound;
use lore_error_set::Location;
use lore_error_set::prelude::*;
use lore_revision::event::LoreEvent;
use lore_revision::interface::LoreGlobalArgs;

// FORK-LOCAL (Tideshift, WP-120): the caller-supplied attempt identity tests, moved from
// `src/call.rs` with the upstream unit-test relocation.

fn globals_with_attempt(attempt: &str) -> LoreGlobalArgs {
    LoreGlobalArgs {
        attempt_id: attempt.into(),
        ..Default::default()
    }
}

/// The ordinary case, and the one every existing caller is in.
#[test]
fn no_attempt_id_supplied_is_not_an_error() {
    let parsed = dispatch_attempt(&LoreGlobalArgs::default())
        .expect("supplying nothing must not be an error");
    assert!(parsed.is_none());
}

/// The supplied identity survives parsing byte for byte. If it did not, the caller would
/// journal one id and the server would file the receipt under another.
#[test]
fn a_supplied_v7_attempt_is_preserved_exactly() {
    let uuid = uuid::Uuid::now_v7();
    let parsed = dispatch_attempt(&globals_with_attempt(&uuid.to_string()))
        .expect("a v7 uuid must be accepted")
        .expect("a supplied value must be present");

    assert_eq!(parsed.as_uuid(), uuid);
}

/// Refused rather than ignored. Ignoring it would dispatch the mutation under an identity
/// the caller never wrote down, and its later lookup would answer absent forever.
#[test]
fn a_malformed_attempt_is_refused_rather_than_dropped() {
    let error = dispatch_attempt(&globals_with_attempt("not-a-uuid"))
        .expect_err("a malformed attempt id must refuse the call");

    assert!(error.reason.contains("not a UUID"), "got: {}", error.reason);
}

/// A v4 is a well-formed UUID and still wrong: the receipt rail orders attempts by the
/// timestamp a v7 embeds, so a v4 could never have been filed as one.
#[test]
fn a_non_v7_attempt_is_refused() {
    let error = dispatch_attempt(&globals_with_attempt(&uuid::Uuid::new_v4().to_string()))
        .expect_err("a non-v7 uuid must refuse the call");

    assert!(error.reason.contains("version 4"), "got: {}", error.reason);
}

/// The property this whole change exists for: the id the caller supplied is the id the
/// dispatch sees. The transport reuses whatever is in scope and mints only when nothing is,
/// and a separate suite already proves what is in scope is what reaches the wire, so this
/// closes the chain from the caller's journal to the server's receipt.
#[tokio::test]
async fn the_supplied_attempt_is_what_the_dispatch_scope_sees() {
    let uuid = uuid::Uuid::now_v7();
    let attempt = dispatch_attempt(&globals_with_attempt(&uuid.to_string()))
        .expect("a v7 uuid must be accepted");

    let seen = in_dispatch_attempt(attempt, async {
        lore_transport::outcome::current_dispatch_attempt()
    })
    .await;

    assert_eq!(seen.map(|a| a.as_uuid()), Some(uuid));
}

/// And a caller that supplies nothing leaves the scope empty, so the transport mints its own
/// exactly as it did before this existed.
#[tokio::test]
async fn supplying_no_attempt_leaves_the_dispatch_scope_empty() {
    let seen = in_dispatch_attempt(None, async {
        lore_transport::outcome::current_dispatch_attempt()
    })
    .await;

    assert!(seen.is_none());
}

// A concrete `#[error_set]` error for the wrapper closures. Its `NotFound`
// variant wraps `lore_base::error::NotFound`, which carries error code 79, so
// the failure path has a known non-internal code to assert against.
#[error_set]
enum SampleError {
    NotFound,
}

impl EventError for SampleError {}

// The full event a callback receives, kept verbatim so a test can read the
// `Complete` detail (code, message, trace) a real consumer would see.
#[derive(Clone)]
enum CapturedEvent {
    Error,
    Complete(lore_revision::event::LoreCompleteEventData),
    Other,
}

impl CapturedEvent {
    fn from_event(event: &LoreEvent) -> Self {
        match event {
            LoreEvent::Error(_) => Self::Error,
            LoreEvent::Complete(data) => Self::Complete(data.clone()),
            _ => Self::Other,
        }
    }
}

fn make_callback(sink: Arc<Mutex<Vec<CapturedEvent>>>) -> LoreEventCallback {
    Some(Box::new(move |event: &LoreEvent| {
        sink.lock().unwrap().push(CapturedEvent::from_event(event));
    }))
}

#[tokio::test]
async fn failing_op_completes_with_error_code_and_no_error_event() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let status = no_repository_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        (),
        "failing_op",
        |()| async move { Err::<(), SampleError>(NotFound.into()) },
    )
    .await;

    let events = sink.lock().unwrap().clone();

    assert!(
        !events.iter().any(|e| matches!(e, CapturedEvent::Error)),
        "no Error event must be emitted on terminal failure"
    );

    // Exactly one `Complete` event.
    let completes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    // The status holds the error code (79 for `NotFound`) and the detail is
    // populated with that code and the error's message.
    let data = &completes[0];
    let expected_code = SampleError::from(NotFound).ffi_code();
    // The synchronous return equals the error code, matching `Complete.status`.
    assert_eq!(status, expected_code);
    assert_eq!(data.status, expected_code);
    assert_eq!(data.error.error_code, expected_code);
    assert_eq!(
        data.error.message.as_str(),
        SampleError::from(NotFound).to_string()
    );
}

#[tokio::test]
async fn succeeding_op_completes_with_status_zero_and_empty_detail() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let status = no_repository_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        (),
        "succeeding_op",
        |()| async move { Ok::<(), SampleError>(()) },
    )
    .await;

    assert_eq!(status, 0);

    let events = sink.lock().unwrap().clone();
    let completes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    let data = &completes[0];
    assert_eq!(data.status, 0);
    assert_eq!(data.error.error_code, 0);
    assert!(data.error.message.is_empty());
    assert!(data.error.trace_locations.is_empty());
}

#[tokio::test]
async fn missing_repository_completes_with_real_ffi_code() {
    // A path with no repository fails in `prepare_repository_call` before
    // any command runs. The failure must report the real
    // repository-not-found error code (45), not the old flat `1`.
    let temp = std::env::temp_dir().join(format!(
        "lore-missing-repo-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let globals = LoreGlobalArgs {
        repository_path: temp.display().to_string().into(),
        ..LoreGlobalArgs::default()
    };

    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let status = repository_call_read(
        globals,
        make_callback(sink.clone()),
        (),
        "missing_repo",
        |_repo, ()| async move { Ok::<(), SampleError>(()) },
    )
    .await;

    let events = sink.lock().unwrap().clone();
    let completes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    let expected_code = RepositoryError::from(RepositoryNotFound {
        repository: temp.display().to_string(),
    })
    .ffi_code();
    assert_ne!(expected_code, 1, "must report a real code, not the flat 1");
    assert_ne!(expected_code, 0);

    let data = &completes[0];
    // status, the synchronous return, and the detail all carry the real code.
    assert_eq!(status, expected_code);
    assert_eq!(data.status, expected_code);
    assert_eq!(data.error.error_code, expected_code);
    assert!(
        !data.error.message.is_empty(),
        "the detail must carry the error message"
    );
}

#[tokio::test]
async fn failing_op_lets_consumer_read_trace_locations() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let _status = no_repository_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        (),
        "trace_op",
        |()| async move {
            // Add a known trace entry so the consumer can read it back from
            // the `Complete` detail.
            let mut err: SampleError = NotFound.into();
            err.push_trace(Location::with_context(
                "src/trace_op.rs",
                7,
                3,
                std::sync::Arc::from("running trace op"),
            ));
            Err::<(), SampleError>(err)
        },
    )
    .await;

    let events = sink.lock().unwrap().clone();
    let data = events
        .iter()
        .find_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .expect("a Complete event must be emitted");

    // The pushed location is reconstructable from the trace; with
    // `track-locations` on, the `From` conversion prepends its own caller
    // location, so the entry we pushed is the last one.
    let locations = data.error.trace_locations.as_slice();
    assert!(
        !locations.is_empty(),
        "trace must carry at least one location"
    );
    let last = locations.last().unwrap();
    assert_eq!(last.file.as_str(), "src/trace_op.rs");
    assert_eq!(last.line, 7);
    assert_eq!(last.column, 3);
    assert_eq!(last.context.as_str(), "running trace op");
}
