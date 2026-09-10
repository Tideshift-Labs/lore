// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lore_base::error::InvalidArguments;
use lore_base::types::RepositoryId;
use lore_error_set::FfiError;
use lore_revision::attempt_store::RepositoryAttemptStore;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::managed_push::ManagedPushObserver;
use lore_transport::AttemptStore;
use lore_transport::CallerOperationContext;
use lore_transport::ProtocolError;
use lore_transport::VolatileAttemptStore;
use uuid::Uuid;

use super::*;
use crate::call_delegation::tests::service_env_child;
use crate::remote::command::LoreCommand;
use crate::remote::message::SerializationType;
use crate::remote::message::deserialize_message;
use crate::remote::message::serialize_message;

fn args() -> LoreBranchPushArgs {
    LoreBranchPushArgs {
        branch: "feature".into(),
        fast_forward_merge: 1,
    }
}
fn globals() -> LoreGlobalArgs {
    LoreGlobalArgs {
        repository_path: std::env::temp_dir()
            .join(format!("lore-unopened-{}", Uuid::new_v4()))
            .display()
            .to_string()
            .into(),
        ..LoreGlobalArgs::default()
    }
}
fn callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}
fn rejected() -> i32 {
    InvalidArguments {
        reason: String::new(),
    }
    .ffi_code()
}

#[test]
fn managed_service_command_roundtrips_and_old_reader_refuses_it() {
    let command = LoreCommand::ManagedBranchPush(LoreManagedBranchPushArgs { args: args() });
    let value = serde_json::to_value(&command).expect("serialize managed command");
    assert_eq!(
        value,
        serde_json::json!({"ManagedBranchPush":{"args":{"branch":"feature","fast_forward_merge":1}}})
    );
    for encoding in [SerializationType::Json, SerializationType::Bincode] {
        let bytes = serialize_message(command.clone(), encoding).expect("encode command");
        let decoded: LoreCommand = deserialize_message(&bytes, encoding).expect("decode command");
        match decoded {
            LoreCommand::ManagedBranchPush(decoded) => assert_eq!(decoded.args, args()),
            other => panic!("managed command changed kind: {other:?}"),
        }
    }
    #[derive(serde::Deserialize)]
    enum OldReader {
        BranchPush(LoreBranchPushArgs),
    }
    assert!(
        serde_json::from_value::<OldReader>(value).is_err(),
        "old readers must refuse the new command rather than accept a raw push"
    );
    let old_value =
        serde_json::to_value(LoreCommand::BranchPush(args())).expect("old command shape");
    match serde_json::from_value::<OldReader>(old_value).expect("legacy command still decodes") {
        OldReader::BranchPush(decoded) => assert_eq!(decoded, args()),
    }
}

#[test]
fn managed_push_refuses_inherited_adoption_before_repository_access() {
    if !service_env_child(
        "branch::managed_service_tests::managed_push_refuses_inherited_adoption_before_repository_access",
        &[None, Some("1")],
    ) {
        return;
    }
    crate::runtime().block_on(async {
        let store = Arc::new(VolatileAttemptStore::new());
        for pending in [true, false] {
            let globals = globals();
            let path = std::path::PathBuf::from(globals.repository_path.as_str());
            let parent = Uuid::new_v4();
            let status = if pending {
                lore_transport::with_managed_caller(
                    parent,
                    store.clone(),
                    push_managed(globals, args(), callback(), None),
                )
                .await
            } else {
                let context =
                    CallerOperationContext::new(parent, RepositoryId::from([7; 16]), store.clone());
                lore_transport::with_caller_operation(
                    context,
                    push_managed(globals, args(), callback(), None),
                )
                .await
            };
            assert_eq!(status, rejected());
            assert!(!path.exists(), "rejected adoption touched the repository");
        }
        let context =
            CallerOperationContext::new(Uuid::new_v4(), RepositoryId::from([7; 16]), store.clone());
        let status = lore_transport::with_caller_operation(
            context,
            push_managed_service_local(
                globals(),
                LoreManagedBranchPushArgs { args: args() },
                callback(),
            ),
        )
        .await;
        assert_eq!(
            status,
            rejected(),
            "service-local handler must recheck adoption"
        );
        assert!(store.unresolved().await.expect("read store").is_empty());
    });
}

struct UntouchedObserver;
impl ManagedPushObserver for UntouchedObserver {
    fn begin_stage<'a, 'b, 'f>(
        &'a self,
        _parent: Uuid,
        _repository: RepositoryId,
        _shared: Arc<RepositoryAttemptStore>,
        _label: &'b str,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn AttemptStore>, ProtocolError>> + Send + 'f>>
    where
        'a: 'f,
        'b: 'f,
        Self: 'f,
    {
        Box::pin(async { panic!("observer must not cross service boundary") })
    }
    fn complete_stage_body<'a, 'f>(
        &'a self,
        _parent: Uuid,
        _status: i32,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'f>>
    where
        'a: 'f,
        Self: 'f,
    {
        Box::pin(async { panic!("observer must remain untouched") })
    }
    fn finish_stage<'a, 'f>(
        &'a self,
        _parent: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProtocolError>> + Send + 'f>>
    where
        'a: 'f,
        Self: 'f,
    {
        Box::pin(async { panic!("observer must remain untouched") })
    }
}

#[test]
fn managed_service_push_refuses_in_process_observer() {
    if !service_env_child(
        "branch::managed_service_tests::managed_service_push_refuses_in_process_observer",
        &[Some("1")],
    ) {
        return;
    }
    let globals = globals();
    let path = std::path::PathBuf::from(globals.repository_path.as_str());
    let status = crate::runtime().block_on(push_managed(
        globals,
        args(),
        callback(),
        Some(Arc::new(UntouchedObserver)),
    ));
    assert_eq!(status, rejected());
    assert!(!path.exists());
}
