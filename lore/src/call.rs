// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use lore_base::env::CallEnvironment;
use lore_base::error::InvalidArguments;
use lore_base::error::RepositoryNotFound;
use lore_base::error::ServiceUnavailable;
use lore_base::runtime::LORE_CONTEXT;
use lore_error_set::FfiError;
use lore_error_set::HasTrace;
use lore_revision::event::EventError;
use lore_revision::event::LoreErrorDetail;
use lore_revision::interface::ExecutionContext;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::lore::execution_context;
use lore_revision::lore_warn;
use lore_revision::relay::EventDispatcher;
use lore_revision::repository;
use lore_revision::repository::RepositoryAccess;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryError;
pub use lore_revision::repository::RepositoryWriteToken;
use lore_revision::repository::get_dot_lore_path;
use lore_revision::util;
use lore_transport::outcome::AttemptId;
use uuid::Uuid;

use crate::interface::LoreEventCallback;
use crate::remote::call::EXTERNAL_ROOT_MOVING;
use crate::remote::call::ServiceCallError;
use crate::util::log_command_done;
use crate::util::log_command_info;

/// Read the caller's attempt identity off the globals (WP-120).
///
/// `Ok(None)` is the ordinary case: the CLI and every embedder that does not track attempts
/// supply nothing, and nothing changes for them.
///
/// A value that is present but unreadable is an error rather than something to ignore, and the
/// asymmetry is deliberate. A caller supplies this because it keeps a durable record and means to
/// reconcile a lost response against an authoritative receipt later. Dropping the value and
/// proceeding would let the mutation dispatch under an identity the caller never wrote down, and
/// its later lookup would answer "no such receipt" forever while appearing to work perfectly.
/// Failing the call is loud, local, and costs one reissued operation; the alternative is silent
/// and permanent.
#[lore_macro::test_pub]
fn dispatch_attempt(globals: &LoreGlobalArgs) -> Result<Option<AttemptId>, InvalidArguments> {
    let Some(text) = globals.attempt_id() else {
        return Ok(None);
    };
    let uuid = Uuid::parse_str(text.trim()).map_err(|_err| InvalidArguments {
        reason: "attempt_id is not a UUID".to_owned(),
    })?;
    // v7 because the receipt rail orders and classifies attempts by a UUID's embedded timestamp.
    // A value of any other version could never have been filed as one, so quoting it later is a
    // caller error rather than a miss, and it is better found here than three layers down.
    if uuid.get_version_num() != 7 {
        return Err(InvalidArguments {
            reason: format!(
                "attempt_id is UUID version {}, not the required 7",
                uuid.get_version_num()
            ),
        });
    }
    Ok(Some(AttemptId::from_uuid(uuid)))
}

/// Run one operation inside the caller-supplied attempt scope, when there is one.
///
/// The transport's mutable dispatch reuses an attempt already in scope and mints one only when
/// none is present, so entering here is what makes the caller's own identity the one the server
/// files its receipt under. Without a supplied id this is exactly the future it was given.
///
/// It returns a future rather than being an `async fn`, which is not cosmetic. The result is
/// handed straight to `LORE_CONTEXT.scope`, whose `Send`-ness the compiler proves structurally
/// through the future it wraps; an `async fn` here erases that proof and every caller in
/// `auth.rs`, `branch.rs` and their siblings fails with "implementation of `Send` is not general
/// enough". Measured, not guessed: written as an `async fn` first, and that is the error it
/// produced.
#[lore_macro::test_pub]
fn in_dispatch_attempt<F>(
    attempt: Option<AttemptId>,
    operation: F,
) -> impl Future<Output = F::Output>
where
    F: Future,
{
    // Boxed, and this is a stack-budget fix rather than a style choice. Every one of the four
    // `repository_call_*` sites wraps its whole command future in this, so an inline async block
    // adds the command's frame to the enclosing one; the lock lane measured the desktop's deepest
    // in-process test crossing the 2 MiB test-thread limit because of it, and passing at 2.5 MiB,
    // which is an overrun rather than recursion. Boxing costs one allocation per repository call,
    // which is nothing beside the operation it wraps, and the wrapper contributes a pointer
    // instead of a frame.
    //
    // `Box::pin` of a concrete async block rather than a `Pin<Box<dyn Future>>`: the erased form
    // would drop the `Send` proof this function exists to preserve.
    Box::pin(async move {
        match attempt {
            Some(attempt) => {
                lore_transport::outcome::with_dispatch_attempt(attempt, operation).await
            }
            None => operation.await,
        }
    })
}

tokio::task_local! {
    /// The environment of the process a call running in this task was relayed from.
    static RELAYED_ENVIRONMENT: CallEnvironment;
    /// Set for a call the service socket answered with a move of the external root, which runs in
    /// this process instead.
    static EXTERNAL_ROOT_MOVE: ();
}

/// Runs `call`, handed back by the move reply, here: an open that finds no Lore directory fails
/// with the move's `ServiceUnavailable`, as the stopped service has unmounted its instances.
pub(crate) fn during_external_root_move<F: Future>(call: F) -> impl Future<Output = F::Output> {
    EXTERNAL_ROOT_MOVE.scope((), call)
}

/// Runs `call`, relayed from a process with `environment`, so that the execution context it sets
/// up reads that environment in place of this process's.
#[lore_macro::test_pub]
pub(crate) fn with_relayed_environment<F: Future>(
    environment: CallEnvironment,
    call: F,
) -> impl Future<Output = F::Output> {
    RELAYED_ENVIRONMENT.scope(environment, call)
}

/// The client execution context for a call whose events all go to `callback`.
pub fn setup_execution(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
) -> Arc<ExecutionContext> {
    setup_execution_with(globals, EventDispatcher::new(callback))
}

/// The client execution context for a call whose events go through `dispatcher`. It reads the
/// environment of the process the call was relayed from, if any, in place of this process's.
pub fn setup_execution_with(
    globals: LoreGlobalArgs,
    dispatcher: EventDispatcher,
) -> Arc<ExecutionContext> {
    let execution = ExecutionContext::new_client(globals, dispatcher);
    Arc::new(match RELAYED_ENVIRONMENT.try_with(Clone::clone) {
        Ok(environment) => execution.with_environment(environment),
        Err(_) => execution,
    })
}

/// Remote mutations such as lock operations need worktree admission but no local write token.
pub async fn repository_call_mutation_read<Arg, T, F, Fut, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    command: F,
) -> i32
where
    ErrT: EventError + FfiError + HasTrace,
    Arg: std::fmt::Debug,
    F: FnOnce(Arc<RepositoryContext>, Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let root = util::path::make_absolute_from(
        globals.repository_path.as_str(),
        globals.working_directory().map(Path::new),
    )
    .unwrap_or_else(|_| PathBuf::from(globals.repository_path.as_str()));
    let fence = match lore_revision::repository_fence::RepositoryMutationGuard::acquire(&root).await
    {
        Ok(fence) => fence,
        Err(error) => {
            let execution = setup_execution(globals, callback);
            let detail = LoreErrorDetail::from_error(&error);
            return LORE_CONTEXT
                .scope(execution, async move {
                    execution_context().dispatcher.complete(detail).await
                })
                .await;
        }
    };
    fence
        .run(repository_call_read(
            globals, callback, args, caller, command,
        ))
        .await
}

/// Read-only repository call. No `RepositoryWriteToken` is minted, so
/// closures cannot name one — write-gated leaf operations fail at compile
/// time.
///
/// ```compile_fail
/// # use std::sync::Arc;
/// # use lore::call::repository_call_read;
/// # use lore::call::RepositoryWriteToken;
/// # use lore_revision::repository::RepositoryContext;
/// # use lore_revision::interface::LoreGlobalArgs;
/// # async fn demo(globals: LoreGlobalArgs, callback: lore::interface::LoreEventCallback) {
/// repository_call_read(globals, callback, (), "demo",
///     |_repo: Arc<RepositoryContext>, _token: RepositoryWriteToken, _args: ()|
///         async move { Ok::<(), std::io::Error>(()) },
/// ).await;
/// # }
/// ```
pub async fn repository_call_read<Arg, T, F, Fut, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    command: F,
) -> i32
where
    ErrT: EventError + FfiError + HasTrace,
    Arg: std::fmt::Debug,
    F: FnOnce(Arc<RepositoryContext>, Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let (repository_path, execution, attempt) =
        match prepare_repository_call(globals, callback).await {
            Ok(v) => v,
            Err(status) => return status,
        };

    LORE_CONTEXT
        .scope(
            execution,
            in_dispatch_attempt(attempt, async move {
                log_command_info(&caller, &args);
                let time_start = Instant::now();

                let (detail, weak_repository) = 'call: {
                    let repository = match repository::load_and_connect_with_token(
                        &repository_path,
                        RepositoryAccess::ReadOnly,
                        None,
                    )
                    .await
                    {
                        Ok(repository) => repository,
                        Err(err) => break 'call (LoreErrorDetail::from_error(&err), None),
                    };
                    let detail = LoreErrorDetail::from_result(
                        &lore_transport::with_optional_caller_operation(
                            lore_transport::caller_operation_for_repository(repository.id),
                            command(repository.clone(), args),
                        )
                        .await,
                    );
                    (detail, Some(post_command_cleanup(repository)))
                };

                check_no_lingering_repository(weak_repository);

                log_command_done(&caller, time_start);
                execution_context().dispatcher.complete(detail).await
            }),
        )
        .await
}

/// Write repository call. Mints a [`RepositoryWriteToken`] for the callback
/// and shares a sibling with the [`RepositoryContext`] so opportunistic
/// leaf-fetch writes (mtime cache, status flush) still see it.
///
/// Acquiring the token serializes writes in-process on a per-path
/// `tokio::sync::Mutex`; reads skip this. Cross-process exclusion is the store
/// claims `load_and_connect` takes, and the repository `FSLock` it takes inside them.
pub async fn repository_call_write<Arg, T, F, Fut, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    command: F,
) -> i32
where
    ErrT: EventError + FfiError + HasTrace,
    Arg: std::fmt::Debug,
    F: FnOnce(Arc<RepositoryContext>, RepositoryWriteToken, Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let (repository_path, execution, attempt) =
        match prepare_repository_call(globals, callback).await {
            Ok(v) => v,
            Err(status) => return status,
        };

    let fence =
        match lore_revision::repository_fence::RepositoryMutationGuard::acquire(&repository_path)
            .await
        {
            Ok(fence) => fence,
            Err(error) => {
                let detail = LoreErrorDetail::from_error(&error);
                return LORE_CONTEXT
                    .scope(execution, async move {
                        execution_context().dispatcher.complete(detail).await
                    })
                    .await;
            }
        };

    fence
        .run(LORE_CONTEXT.scope(
            execution,
            in_dispatch_attempt(attempt, async move {
                let token = RepositoryWriteToken::acquire(&repository_path).await;
                let context_token = token.share();

                log_command_info(&caller, &args);
                let time_start = Instant::now();

                let (detail, weak_repository) = 'call: {
                    let repository = match repository::load_and_connect_with_token(
                        &repository_path,
                        RepositoryAccess::ReadWrite,
                        Some(context_token),
                    )
                    .await
                    {
                        Ok(repository) => repository,
                        Err(err) => break 'call (LoreErrorDetail::from_error(&err), None),
                    };
                    let detail = LoreErrorDetail::from_result(
                        &lore_transport::with_optional_caller_operation(
                            lore_transport::caller_operation_for_repository(repository.id),
                            command(repository.clone(), token, args),
                        )
                        .await,
                    );
                    (detail, Some(post_command_cleanup(repository)))
                };

                check_no_lingering_repository(weak_repository);

                log_command_done(&caller, time_start);
                execution_context().dispatcher.complete(detail).await
            }),
        ))
        .await
}

/// Typed write repository call for Rust callers that need the command value or
/// structured error in addition to the standard Lore event stream.
///
/// The same CLIENT write token is shared with the repository context and held
/// until command cleanup completes. The callback still receives exactly one
/// `Complete` event followed by `End`.
pub async fn repository_call_write_result<Arg, T, F, Fut, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    command: F,
) -> Result<ResT, ErrT>
where
    ErrT: EventError + FfiError + HasTrace + From<RepositoryError>,
    Arg: std::fmt::Debug,
    F: FnOnce(Arc<RepositoryContext>, RepositoryWriteToken, Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let (repository_path, execution, attempt) =
        match prepare_repository_call_result::<ErrT>(globals, callback).await {
            Ok(value) => value,
            Err(err) => return Err(err),
        };

    let fence =
        match lore_revision::repository_fence::RepositoryMutationGuard::acquire(&repository_path)
            .await
        {
            Ok(fence) => fence,
            Err(error) => {
                let err = ErrT::from(RepositoryError::from(InvalidArguments {
                    reason: error.to_string(),
                }));
                let detail = LoreErrorDetail::from_error(&err);
                LORE_CONTEXT
                    .scope(execution, async move {
                        let _ = execution_context().dispatcher.complete(detail).await;
                    })
                    .await;
                return Err(err);
            }
        };

    let token = RepositoryWriteToken::acquire(&repository_path).await;
    let context_token = token.share();

    fence
        .run(LORE_CONTEXT.scope(
            execution,
            in_dispatch_attempt(attempt, async move {
                log_command_info(&caller, &args);
                let time_start = Instant::now();

                let mut weak_repository = None;
                let result = match repository::load_and_connect_with_token(
                    &repository_path,
                    RepositoryAccess::ReadWrite,
                    Some(context_token),
                )
                .await
                {
                    Ok(repository) => {
                        let result = lore_transport::with_optional_caller_operation(
                            lore_transport::caller_operation_for_repository(repository.id),
                            command(repository.clone(), token, args),
                        )
                        .await;
                        weak_repository = Some(post_command_cleanup(repository));
                        result
                    }
                    Err(err) => Err(ErrT::from(err)),
                };

                check_no_lingering_repository(weak_repository);
                log_command_done(&caller, time_start);

                let detail = match &result {
                    Ok(_) => LoreErrorDetail::default(),
                    Err(err) => LoreErrorDetail::from_error(err),
                };
                let _ = execution_context().dispatcher.complete(detail).await;
                result
            }),
        ))
        .await
}

/// Write repository call that holds the instance's repository lock alone, in three steps.
///
/// - `plan` runs on the instance opened without stores, before the instance's repository lock
///   is taken, and keeps nothing of that opened instance. `None` ends the call there.
///   An instance whose instance file is missing is first opened with its stores, which recovers
///   its ID as a write command does. That step is boxed, as only that cold path makes it large, so
///   the call's future holds its box alone.
/// - `command` runs with the plan, holding the lock alone: it waits for the other commands of
///   this process that hold the instance's repository lock to finish and keeps them out until
///   it is done, as the lock keeps out other processes. Otherwise as [`repository_call_write`].
/// - `finish` runs with the plan after `command`, whatever it returned, and where the instance
///   could not be opened for it, without the call's hold of the lock. The flush that ends
///   `command` may still hold it. Where the call's future is dropped first, `finish` does not
///   run, so what it cleans up needs another way to be cleaned up too.
///
/// The locked steps repeat [`repository_call_write`]'s body rather than sharing a helper with it:
/// a helper holds the call's arguments a second time, which grew the future of every write
/// command by 72 to 136 bytes.
pub async fn repository_call_exclusive_planned<Arg, T, P, FutP, FutF, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    plan: impl FnOnce(Arc<RepositoryContext>, Arg) -> FutP,
    command: impl AsyncFnOnce(Arc<RepositoryContext>, RepositoryWriteToken, &P) -> Result<ResT, ErrT>,
    finish: impl FnOnce(P) -> FutF,
) -> i32
where
    ErrT: EventError + FfiError + HasTrace,
    Arg: std::fmt::Debug,
    FutP: Future<Output = Result<Option<P>, ErrT>> + 'static,
    FutF: Future<Output = ()> + 'static,
{
    let (repository_path, execution, attempt) =
        match prepare_repository_call(globals, callback).await {
            Ok(v) => v,
            Err(status) => return status,
        };

    // FORK-LOCAL (Tideshift): the fork layers of [`repository_call_write`] (mutation fence,
    // caller attempt scope, caller operation), repeated here as upstream repeats its body.
    let fence =
        match lore_revision::repository_fence::RepositoryMutationGuard::acquire(&repository_path)
            .await
        {
            Ok(fence) => fence,
            Err(error) => {
                let detail = LoreErrorDetail::from_error(&error);
                return LORE_CONTEXT
                    .scope(execution, async move {
                        execution_context().dispatcher.complete(detail).await
                    })
                    .await;
            }
        };

    fence
        .run(LORE_CONTEXT.scope(
            execution,
            in_dispatch_attempt(attempt, async move {
                log_command_info(&caller, &args);
                let time_start = Instant::now();

                let detail = 'call: {
                    if let Err(err) =
                        Box::pin(repository::recover_missing_instance_file(&repository_path)).await
                    {
                        break 'call LoreErrorDetail::from_error(&err);
                    }
                    let planned = {
                        let unlocked = match repository::load_and_connect_with_token(
                            &repository_path,
                            RepositoryAccess::NoStore,
                            None,
                        )
                        .await
                        {
                            Ok(repository) => repository,
                            Err(err) => break 'call LoreErrorDetail::from_error(&err),
                        };
                        let planned = plan(unlocked.clone(), args).await;
                        let weak = Arc::downgrade(&unlocked);
                        drop(unlocked);
                        check_no_lingering_repository(Some(weak));
                        planned
                    };
                    let plan = match planned {
                        Ok(Some(plan)) => plan,
                        Ok(None) => break 'call LoreErrorDetail::default(),
                        Err(err) => break 'call LoreErrorDetail::from_error(&err),
                    };

                    let token = RepositoryWriteToken::acquire(&repository_path).await;
                    let (detail, weak_repository) = 'locked: {
                        let context_token = token.share();
                        let repository = match repository::load_and_connect_exclusive(
                            &repository_path,
                            context_token,
                        )
                        .await
                        {
                            Ok(repository) => repository,
                            Err(err) => {
                                // Released before `finish`, as the command releases it when it ends.
                                drop(token);
                                break 'locked (LoreErrorDetail::from_error(&err), None);
                            }
                        };
                        let detail = LoreErrorDetail::from_result(
                            &lore_transport::with_optional_caller_operation(
                                lore_transport::caller_operation_for_repository(repository.id),
                                command(repository.clone(), token, &plan),
                            )
                            .await,
                        );
                        (detail, Some(post_command_cleanup(repository)))
                    };
                    check_no_lingering_repository(weak_repository);

                    finish(plan).await;
                    detail
                };

                log_command_done(&caller, time_start);
                execution_context().dispatcher.complete(detail).await
            }),
        ))
        .await
}

/// Repository call that doesn't open stores. For notification /
/// config-introspection commands that need a `RepositoryContext` but neither
/// read nor write stores; skips the `FSLock` and never mints a write token.
pub async fn repository_call_no_store<Arg, T, F, Fut, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    command: F,
) -> i32
where
    ErrT: EventError + FfiError + HasTrace,
    Arg: std::fmt::Debug,
    F: FnOnce(Arc<RepositoryContext>, Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let (repository_path, execution, attempt) =
        match prepare_repository_call(globals, callback).await {
            Ok(v) => v,
            Err(status) => return status,
        };

    LORE_CONTEXT
        .scope(
            execution,
            in_dispatch_attempt(attempt, async move {
                log_command_info(&caller, &args);
                let time_start = Instant::now();

                let (detail, weak_repository) = 'call: {
                    let repository = match repository::load_and_connect_with_token(
                        &repository_path,
                        RepositoryAccess::NoStore,
                        None,
                    )
                    .await
                    {
                        Ok(repository) => repository,
                        Err(err) => break 'call (LoreErrorDetail::from_error(&err), None),
                    };
                    let detail = LoreErrorDetail::from_result(
                        &lore_transport::with_optional_caller_operation(
                            lore_transport::caller_operation_for_repository(repository.id),
                            command(repository.clone(), args),
                        )
                        .await,
                    );
                    (detail, Some(post_command_cleanup(repository)))
                };

                check_no_lingering_repository(weak_repository);

                log_command_done(&caller, time_start);
                execution_context().dispatcher.complete(detail).await
            }),
        )
        .await
}

/// Resolves `globals.repository_path` against the call's working directory and records the result
/// in `globals`. Left as given when it cannot be resolved.
pub(crate) fn resolve_repository_path(globals: &mut LoreGlobalArgs) -> PathBuf {
    match util::path::make_absolute_from(
        globals.repository_path.as_str(),
        globals.working_directory().map(Path::new),
    ) {
        Ok(path) => {
            globals.repository_path = path.display().to_string().into();
            path
        }
        Err(_) => PathBuf::from(globals.repository_path.as_str()),
    }
}

/// On `Err`, the error has already been dispatched to the callback.
async fn prepare_repository_call(
    mut globals: LoreGlobalArgs,
    callback: LoreEventCallback,
) -> Result<(PathBuf, Arc<ExecutionContext>, Option<AttemptId>), i32> {
    let repository_path = resolve_repository_path(&mut globals);

    // Read before `globals` is moved into the execution context, and refused here rather than
    // deeper so a bad value costs nothing but this call.
    let attempt = dispatch_attempt(&globals);

    let execution = setup_execution(globals, callback);

    let attempt = match attempt {
        Ok(attempt) => attempt,
        Err(invalid) => {
            // Reported exactly as a pre-command failure is, so a caller sees the same status,
            // return value and detail shape it would for any other refusal before the command.
            let err = RepositoryError::from(invalid);
            let status = LORE_CONTEXT
                .scope(execution, async move {
                    execution_context()
                        .dispatcher
                        .complete(LoreErrorDetail::from_error(&err))
                        .await
                })
                .await;
            return Err(status);
        }
    };

    // Inside the call's scope, so the external root of a virtual instance is the one of the global
    // data directory the call carries: a service relaying calls for another global data directory
    // would otherwise look in its own.
    let found = LORE_CONTEXT
        .scope(execution.clone(), async {
            get_dot_lore_path(&repository_path)
        })
        .await;
    let failure = match found {
        Ok(dotpath) if dotpath.is_dir() => return Ok((repository_path, execution, attempt)),
        Ok(_) if EXTERNAL_ROOT_MOVE.try_with(|()| ()).is_ok() => {
            LoreErrorDetail::from_error(&ServiceCallError::from(ServiceUnavailable {
                reason: format!(
                    "{} holds no Lore directory, and {EXTERNAL_ROOT_MOVING}",
                    repository_path.display()
                ),
            }))
        }
        Ok(_) => LoreErrorDetail::from_error(&RepositoryError::from(RepositoryNotFound {
            repository: repository_path.display().to_string(),
        })),
        Err(err) => LoreErrorDetail::from_error(&err),
    };
    // A pre-command failure reports the same status, return value, and
    // detail as a command failure. Complete inside the execution scope so
    // the failure log routes to the dispatcher.
    let status = LORE_CONTEXT
        .scope(execution, async move {
            execution_context().dispatcher.complete(failure).await
        })
        .await;
    Err(status)
}

/// Typed counterpart to [`prepare_repository_call`]. On failure it dispatches
/// the normal terminal events before returning the structured repository error.
/// FORK-LOCAL (Tideshift): upstream's Lore-directory lookup answers its own one-variant set
/// (`InvalidPath`); the typed path below reports it as the `RepositoryError` it always did.
fn dot_lore_path_failure(invalid: lore_revision::repository::DotLorePathError) -> RepositoryError {
    use lore_error_set::prelude::*;
    let Err(err) = Err::<std::convert::Infallible, _>(invalid)
        .forward::<RepositoryError>("finding the Lore directory");
    err
}

async fn prepare_repository_call_result<ErrT>(
    mut globals: LoreGlobalArgs,
    callback: LoreEventCallback,
) -> Result<(PathBuf, Arc<ExecutionContext>, Option<AttemptId>), ErrT>
where
    ErrT: EventError + FfiError + HasTrace + From<RepositoryError>,
{
    let repository_path = resolve_repository_path(&mut globals);

    // Same refusal as the untyped path, reported through this one's structured error.
    let attempt = dispatch_attempt(&globals);

    let execution = setup_execution(globals, callback);

    let attempt = match attempt {
        Ok(attempt) => attempt,
        Err(invalid) => {
            let err = ErrT::from(RepositoryError::from(invalid));
            let detail = LoreErrorDetail::from_error(&err);
            LORE_CONTEXT
                .scope(execution, async move {
                    let _ = execution_context().dispatcher.complete(detail).await;
                })
                .await;
            return Err(err);
        }
    };

    // Upstream's mount-aware lookup, as the untyped path uses, inside the call's scope for the
    // same reason. Its refusal is dispatched here like every other pre-command failure on this
    // path, rather than returned bare.
    let found = LORE_CONTEXT
        .scope(execution.clone(), async {
            get_dot_lore_path(&repository_path)
        })
        .await;
    let dotpath = match found {
        Ok(dotpath) => dotpath,
        Err(invalid) => {
            let err = ErrT::from(dot_lore_path_failure(invalid));
            let detail = LoreErrorDetail::from_error(&err);
            LORE_CONTEXT
                .scope(execution, async move {
                    let _ = execution_context().dispatcher.complete(detail).await;
                })
                .await;
            return Err(err);
        }
    };
    if !dotpath.is_dir() {
        let err = ErrT::from(RepositoryError::from(RepositoryNotFound {
            repository: repository_path.display().to_string(),
        }));
        let detail = LoreErrorDetail::from_error(&err);
        LORE_CONTEXT
            .scope(execution, async move {
                let _ = execution_context().dispatcher.complete(detail).await;
            })
            .await;
        return Err(err);
    }

    Ok((repository_path, execution, attempt))
}

fn post_command_cleanup(repository: Arc<RepositoryContext>) -> std::sync::Weak<RepositoryContext> {
    repository.try_spawn_post_command_flush(execution_context().globals().flush_options());

    if let Some(duration) = execution_context().globals().store_keep_alive_duration() {
        repository.spawn_keep_alive(duration);
    }

    Arc::downgrade(&repository)
}

fn check_no_lingering_repository(weak: Option<std::sync::Weak<RepositoryContext>>) {
    if let Some(repository) = weak
        && repository.strong_count() > 0
    {
        // A stray strong reference means the command spawned a task that
        // outlives completion and is holding the repository context.
        lore_warn!("Repository has strong reference remaining after completion");
        debug_assert!(
            repository.strong_count() == 0,
            "Repository has strong reference remaining after completion"
        );
    }
}

pub async fn no_repository_call<Arg, T, F, Fut, ResT, ErrT>(
    globals: LoreGlobalArgs,
    callback: LoreEventCallback,
    args: Arg,
    caller: T,
    command: F,
) -> i32
where
    ErrT: FfiError + HasTrace + std::fmt::Display,
    Arg: std::fmt::Debug,
    F: FnOnce(Arg) -> Fut,
    Fut: Future<Output = Result<ResT, ErrT>> + 'static,
{
    let execution = setup_execution(globals, callback);

    LORE_CONTEXT
        .scope(execution, async move {
            log_command_info(&caller, &args);

            let time_start = Instant::now();

            let detail = LoreErrorDetail::from_result(&command(args).await);

            log_command_done(&caller, time_start);
            execution_context().dispatcher.complete(detail).await
        })
        .await
}
