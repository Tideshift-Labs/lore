// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use lore::call_delegation::*;
use lore::interface::LoreString;
use lore::remote::command::LoreCommand;
use lore_base::error::InvalidArguments;
use lore_base::error::NotFound;
use lore_base::text::ValidateText;
use lore_error_set::FfiError;
use lore_error_set::prelude::*;
use lore_revision::event::EventError;
use lore_revision::event::LoreEvent;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreGlobalArgs;

// A concrete error whose `NotFound` variant carries error code 79, so the
// async failure path has a known non-`1` code to assert against.
#[error_set]
enum SampleError {
    NotFound,
}

impl EventError for SampleError {}

// The async entry point returns `void`, so the only channel for the code is
// the callback. The callback is a real `extern "C"` function pointer (the
// FFI boundary), keyed by `user_context` to a per-test sink.
struct AsyncSink {
    status: Mutex<Option<i32>>,
    done: Mutex<Option<mpsc::Sender<()>>>,
}

fn registry() -> &'static Mutex<HashMap<u64, &'static AsyncSink>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, &'static AsyncSink>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe extern "C" fn record_event(event: &LoreEvent, user_context: u64) {
    let sink = *registry().lock().unwrap().get(&user_context).unwrap();
    match event {
        LoreEvent::Complete(data) => {
            *sink.status.lock().unwrap() = Some(data.status);
        }
        // `End` fires after `Complete`; use it to release the test.
        LoreEvent::End(_) => {
            if let Some(sender) = sink.done.lock().unwrap().take() {
                let _ = sender.send(());
            }
        }
        _ => {}
    }
}

#[test]
fn async_failure_delivers_code_only_through_complete_status() {
    let (done_tx, done_rx) = mpsc::channel();
    // Leaked so the `'static` callback can hold a stable reference for the
    // duration of the spawned task; the test process tears it down.
    let sink: &'static AsyncSink = Box::leak(Box::new(AsyncSink {
        status: Mutex::new(None),
        done: Mutex::new(Some(done_tx)),
    }));
    let context = sink as *const AsyncSink as u64;
    registry().lock().unwrap().insert(context, sink);

    let config = LoreEventCallbackConfig {
        user_context: context,
        func: Some(record_event),
    };

    let args = lore::auth::LoreAuthLocalUserInfoArgs {
        auth_endpoint: LoreString::default(),
        user_ids: lore_revision::interface::LoreArray::default(),
        with_identity_token: 0,
        with_access_token: 0,
    };

    // The async entry point returns `()`; the failing handler's code can
    // only reach the caller through the `Complete` event.
    let returned: () = run_asynchronously(
        &LoreGlobalArgs::default(),
        &args,
        config,
        |_globals, _args, callback| async move {
            // The wrappers turn a concrete error into the derived status.
            lore::call::no_repository_call(
                LoreGlobalArgs::default(),
                callback,
                (),
                "async_failure",
                |()| async move { Err::<(), SampleError>(NotFound.into()) },
            )
            .await
        },
    );
    assert_eq!(returned, ());

    // Block until the spawned task has flushed `Complete` and `End`.
    done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("async task must complete");

    let expected_code = SampleError::from(NotFound).ffi_code();
    assert_ne!(expected_code, 1, "the sample error must not collide with 1");
    assert_eq!(
        *sink.status.lock().unwrap(),
        Some(expected_code),
        "the failure code arrives through Complete.status"
    );
}

fn rejected_status() -> i32 {
    InvalidArguments {
        reason: String::new(),
    }
    .ffi_code()
}

fn invalid_utf8() -> LoreString {
    LoreString::from_bytes(&[b'a', 0xff, 0xfe])
}

fn no_callback() -> LoreEventCallbackConfig {
    LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    }
}

/// Run `args` through the synchronous entry point and report the status
/// together with whether the handler was reached.
fn dispatch<ArgsType: ValidateText + Clone + Into<LoreCommand>>(
    globals: &LoreGlobalArgs,
    args: &ArgsType,
) -> (i32, bool) {
    let reached = Arc::new(AtomicBool::new(false));
    let handler_reached = reached.clone();
    let status = run_synchronously(
        globals,
        args,
        no_callback(),
        move |_globals, _args, _callback| {
            handler_reached.store(true, Ordering::Release);
            0
        },
    );
    (status, reached.load(Ordering::Acquire))
}

/// A plain text field.
#[test]
fn a_string_argument_that_is_not_utf8_is_rejected_before_the_handler_runs() {
    let args = lore::revision_tree::resolve_path::LoreRevisionTreeResolvePathArgs {
        id: 1,
        handle: lore::revision_tree::handle::LoreRevisionTree::INVALID,
        path: invalid_utf8(),
    };

    let (status, handler_ran) = dispatch(&LoreGlobalArgs::default(), &args);

    assert_eq!(
        status,
        rejected_status(),
        "a non-UTF-8 path must be rejected"
    );
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// The same field holding valid text reaches the verb, so the check rejects
/// the encoding rather than the field.
#[test]
fn a_string_argument_that_is_utf8_reaches_the_handler() {
    let args = lore::revision_tree::resolve_path::LoreRevisionTreeResolvePathArgs {
        id: 1,
        handle: lore::revision_tree::handle::LoreRevisionTree::INVALID,
        path: LoreString::from_str("docs/readme.md"),
    };

    let (status, handler_ran) = dispatch(&LoreGlobalArgs::default(), &args);

    assert_eq!(status, 0);
    assert!(handler_ran, "valid text must reach the verb");
}

/// An element of an array of text.
#[test]
fn a_text_array_element_that_is_not_utf8_is_rejected() {
    let args = lore::file::LoreFileHashArgs {
        paths: lore_revision::interface::LoreArray::from_vec(vec![
            LoreString::from_str("first"),
            invalid_utf8(),
        ]),
    };

    let (status, handler_ran) = dispatch(&LoreGlobalArgs::default(), &args);

    assert_eq!(status, rejected_status());
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// A text field of a struct held in an array, which the check only reaches
/// by descending into the element type.
#[test]
fn a_text_field_of_an_array_element_that_is_not_utf8_is_rejected() {
    let args = lore::storage::put_file::LoreStoragePutFileArgs {
        handle: lore::storage::handle::LoreStore::INVALID,
        items: lore_revision::interface::LoreArray::from_vec(vec![
            lore::storage::put_file::LoreStoragePutFileItem {
                path: invalid_utf8(),
                ..Default::default()
            },
        ]),
    };

    let (status, handler_ran) = dispatch(&LoreGlobalArgs::default(), &args);

    assert_eq!(status, rejected_status());
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// A batch write verb's entry name. The entry type is only reached by
/// descending into it, so declaring it text-free instead of deriving the
/// check would let a name through unread.
#[test]
fn a_batch_entry_name_that_is_not_utf8_is_rejected() {
    let args = lore::revision_tree::add::LoreRevisionTreeAddArgs {
        batch_id: 1,
        handle: lore::revision_tree::handle::LoreRevisionTree::INVALID,
        entries: lore_revision::interface::LoreArray::from_vec(vec![
            lore::revision_tree::add::LoreRevisionTreeAddEntry {
                name: invalid_utf8(),
                ..Default::default()
            },
        ]),
    };

    let (status, handler_ran) = dispatch(&LoreGlobalArgs::default(), &args);

    assert_eq!(status, rejected_status());
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// A text field of a nested struct, reached by descending one field deep.
#[test]
fn a_text_field_of_a_nested_argument_struct_that_is_not_utf8_is_rejected() {
    let args = lore::storage::open::LoreStorageOpenArgs {
        remote_config: lore::storage::open::LoreStorageRemoteConfig {
            remote_url: invalid_utf8(),
        },
        ..Default::default()
    };

    let (status, handler_ran) = dispatch(&LoreGlobalArgs::default(), &args);

    assert_eq!(status, rejected_status());
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// The global arguments every operation carries are checked too, so a bad
/// repository path fails before the path is read.
#[test]
fn a_global_argument_that_is_not_utf8_is_rejected() {
    let globals = LoreGlobalArgs {
        repository_path: invalid_utf8(),
        ..LoreGlobalArgs::default()
    };
    let args = lore::revision_tree::close::LoreRevisionTreeCloseArgs::default();

    let (status, handler_ran) = dispatch(&globals, &args);

    assert_eq!(status, rejected_status());
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// The rejection names the field so a caller can tell which string to fix.
#[test]
fn the_rejection_names_the_failing_field() {
    let args = lore::storage::put_file::LoreStoragePutFileArgs {
        handle: lore::storage::handle::LoreStore::INVALID,
        items: lore_revision::interface::LoreArray::from_vec(vec![
            lore::storage::put_file::LoreStoragePutFileItem::default(),
            lore::storage::put_file::LoreStoragePutFileItem {
                path: invalid_utf8(),
                ..Default::default()
            },
        ]),
    };

    let error =
        validate_call_text(&LoreGlobalArgs::default(), &args).expect_err("the item path must fail");

    assert_eq!(
        error.to_string(),
        "invalid arguments: items[1].path is not valid UTF-8"
    );
}

/// The asynchronous entry point rejects the same calls, reporting the status
/// through `Complete` because it has no return value.
#[test]
fn the_asynchronous_entry_point_rejects_text_that_is_not_utf8() {
    let (done_tx, done_rx) = mpsc::channel();
    let sink: &'static AsyncSink = Box::leak(Box::new(AsyncSink {
        status: Mutex::new(None),
        done: Mutex::new(Some(done_tx)),
    }));
    let context = sink as *const AsyncSink as u64;
    registry().lock().unwrap().insert(context, sink);

    let config = LoreEventCallbackConfig {
        user_context: context,
        func: Some(record_event),
    };

    let args = lore::revision_tree::resolve_path::LoreRevisionTreeResolvePathArgs {
        id: 1,
        handle: lore::revision_tree::handle::LoreRevisionTree::INVALID,
        path: invalid_utf8(),
    };

    let reached = Arc::new(AtomicBool::new(false));
    let handler_reached = reached.clone();
    run_asynchronously(
        &LoreGlobalArgs::default(),
        &args,
        config,
        move |_globals, _args, _callback| {
            let reached = handler_reached.clone();
            async move {
                reached.store(true, Ordering::Release);
                0
            }
        },
    );

    done_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the rejection must complete");

    assert_eq!(*sink.status.lock().unwrap(), Some(rejected_status()));
    assert!(
        !reached.load(Ordering::Acquire),
        "the verb must not run on a rejected call"
    );
}

/// Credential arguments with no single meaning -- here an identity alongside
/// a token that already names one -- are rejected the same way malformed text
/// is, and for the same reason: the call cannot be run as asked.
#[test]
fn conflicting_identity_arguments_are_rejected_before_the_handler_runs() {
    let globals = LoreGlobalArgs {
        identity: LoreString::from_str("bob"),
        identity_token: LoreString::from_str("some-token"),
        ..LoreGlobalArgs::default()
    };
    let args = lore::revision_tree::close::LoreRevisionTreeCloseArgs::default();

    let (status, handler_ran) = dispatch(&globals, &args);

    assert_eq!(status, rejected_status());
    assert!(!handler_ran, "the verb must not run on a rejected call");
}

/// FORK-LOCAL (Tideshift, WP-120): `dispatch_command`, upstream's command relay path, refuses a
/// managed caller instead of relaying. The caller's durable context is a task-local in this
/// process, so a relayed command would run without it. Runs in a child with relaying on; the
/// repository path does not exist, so a relay or a local run that got past the check could not
/// answer with this refusal.
#[test]
fn dispatch_command_refuses_a_managed_caller_instead_of_relaying() {
    if !service_env_child(
        "call_delegation::dispatch_command_refuses_a_managed_caller_instead_of_relaying",
        &[Some("1")],
    ) {
        return;
    }
    let globals = LoreGlobalArgs {
        repository_path: LoreString::from_str("Z:/lore-dispatch-command-managed-relay-3c5d8e"),
        ..LoreGlobalArgs::default()
    };
    let command = LoreCommand::BranchPush(lore::branch::LoreBranchPushArgs {
        branch: "feature".into(),
        fast_forward_merge: 1,
    });
    let store = Arc::new(lore_transport::VolatileAttemptStore::new());
    let attempts: Arc<dyn lore_transport::AttemptStore> = store.clone();
    let callback = lore_revision::event::convert_event_callback(no_callback());

    let status = lore::runtime().block_on(lore_transport::with_managed_caller(
        uuid::Uuid::new_v4(),
        attempts,
        dispatch_command(globals, command, callback),
    ));

    assert_eq!(
        status,
        rejected_status(),
        "a managed caller must be refused before the relay"
    );
    assert!(
        lore::runtime()
            .block_on(lore_transport::AttemptStore::unresolved(store.as_ref()))
            .expect("read the store")
            .is_empty(),
        "the refused call must not touch the caller's attempt store"
    );
}

/// FORK-LOCAL (Tideshift, WP-120): runs `test_name` alone in a child process of this test binary,
/// once per `LORE_USE_SERVICE` value in `values`, and reports whether the caller is that child.
///
/// Exact child processes isolate service settings from every ordinary dispatch reader. A serial
/// group only protects its members, not the rest of the test binary. `test_name` is the full path
/// inside this binary (for example `lock::file_acquire_with_attempt_store_refuses_when_delegation_is_requested`),
/// as `--exact` matches it.
///
/// The child decides relaying from its variable through the library's own `service_in_use`: the
/// sandbox constructor in `main.rs` leaves `LORE_USE_SERVICE` as this parent set it for a child it
/// marks, and since v0.10.1 relaying needs no named service executable. The pre-merge
/// `decide_from_use_service_variable_for_test` hook in `src/` is therefore gone.
pub(crate) fn service_env_child(test_name: &str, values: &[Option<&str>]) -> bool {
    struct ReapChild(std::process::Child);
    impl Drop for ReapChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    if std::env::var(crate::SERVICE_TEST_CHILD_MARKER).as_deref() == Ok(test_name) {
        let actual = std::env::var("LORE_USE_SERVICE").ok();
        assert!(
            values.contains(&actual.as_deref()),
            "unexpected child environment: {actual:?}"
        );
        return true;
    }
    for value in values {
        let directory = std::env::temp_dir().join(format!(
            "lore-service-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).expect("create child log directory");
        let stdout = directory.join("stdout.log");
        let stderr = directory.join("stderr.log");
        let mut command =
            std::process::Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(crate::SERVICE_TEST_CHILD_MARKER, test_name)
            .stdout(std::fs::File::create(&stdout).expect("child stdout"))
            .stderr(std::fs::File::create(&stderr).expect("child stderr"));
        match value {
            Some(value) => {
                command.env("LORE_USE_SERVICE", value);
            }
            None => {
                command.env_remove("LORE_USE_SERVICE");
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = ReapChild(command.spawn().expect("spawn exact service test"));
        drop(command);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.0.try_wait().expect("poll service test") {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "{test_name} exceeded 30s; logs retained at {}",
                    directory.display()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        drop(child);
        let output = std::fs::read_to_string(&stdout).expect("read child stdout");
        let errors = std::fs::read_to_string(&stderr).expect("read child stderr");
        assert!(
            status.success() && output.contains("1 passed; 0 failed"),
            "{test_name} with {value:?}: {status}; logs {}\n{output}\n{errors}",
            directory.display()
        );
        std::fs::remove_dir_all(&directory).expect("remove successful child logs");
    }
    false
}
