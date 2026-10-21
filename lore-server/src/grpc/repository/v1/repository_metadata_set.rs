// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_proto::lore::repository::v1::RepositoryMetadataSetRequest;
use lore_proto::lore::repository::v1::RepositoryMetadataSetResponse;
use lore_revision::metadata::Metadata;
use lore_revision::metadata::MetadataType;
use lore_revision::metadata::repository::READ_ONLY_KEYS;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_storage::hash;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::domain::DomainContext;
use crate::domain::GovernedMetadataCas;
use crate::domain::GovernedScope;
use crate::domain::MetadataCasFamily;
use crate::domain::MetadataCasOutcome;
use crate::domain::admit_at_entry;
use crate::domain_intent::CanonicalIntent;
use crate::domain_intent::canonical_intent_digest;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_authorization_optional;
use crate::grpc::get_user_id;
use crate::grpc::get_verified_token;
use crate::grpc::get_write_token;
use crate::grpc::warn_error_to_status;
use crate::util::setup_execution;

/// `lore.repository.v1.RepositoryService.RepositoryMetadataSet` handler.
///
/// Compare-and-swap update of the repository metadata pointer.
/// Validates that the proposed metadata blob (a) preserves all read-only
/// fields and (b) references only existing immutable blobs for any
/// Address-typed entries, then performs a CAS on the mutable store.
///
/// CAS hit / miss is signalled in-band by comparing
/// `response.metadata` to `request.updated`; the gRPC status is always
/// `Ok` unless an internal failure prevents the CAS from being attempted
/// at all.
#[tracing::instrument(name = "RepositoryMetadataSet::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryMetadataSetRequest>,
    authorizer: Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    domain_context: Option<&Arc<DomainContext>>,
) -> Result<Response<RepositoryMetadataSetResponse>, Status> {
    // Captured before `into_inner` consumes the request: the domain-operation
    // headers and the verified principal both live outside the message body.
    let request_metadata = request.metadata().clone();
    let request_authorization = get_authorization_optional(request.extensions());
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let (_, extensions, req) = request.into_parts();

    // CR-029 R-BLOCK-2: the one shared reader of the domain-operation headers,
    // at handler entry, before any handler logic or authorization side effect.
    let admitted = admit_at_entry(
        domain_context,
        &request_metadata,
        request_authorization.as_ref(),
        GovernedScope::TargetRepository {
            repository_id: &req.id,
        },
    )?;

    let repository_id: Context = req.id.into();
    if repository_id == Context::default() {
        return Err(Status::invalid_argument("Missing repository id"));
    }

    // Same family and same digest as v0: CR-029 freezes one canonical intent
    // per semantic operation, not one per wire shape, so v0 and v1 of the same
    // CAS must produce identical 32 bytes for identical values.
    //
    // After the empty/default check, per INTENT-02-LORE; see the v0 handler.
    let governed = match admitted {
        Some(admitted) => {
            let digest = canonical_intent_digest(&CanonicalIntent::RepositoryMetadataCas {
                repository_id: repository_id.data(),
                expected_hash: &req.expected,
                new_hash: &req.updated,
            })
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            GovernedMetadataCas::prepare(
                domain_context,
                Some(admitted),
                MetadataCasFamily::Repository,
                digest,
            )
            .await?
        }
        None => None,
    };

    let expected: Hash = req.expected.into();
    let updated: Hash = req.updated.into();

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id.into(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            // FORK-LOCAL (Tideshift): admin, not any grant; see the v0 handler.
            authorizer
                .require_action(
                    get_verified_token(&extensions).as_ref(),
                    repository_id.into(),
                    "admin",
                )
                .await?;

            let current_metadata = if !expected.is_zero() {
                Metadata::deserialize(repository.clone(), expected)
                    .await
                    .filter_slow_down()?
                    .map_err(|err| {
                        warn_error_to_status(&err, |err| {
                            Status::invalid_argument(format!(
                                "failed to deserialize current metadata: {err}"
                            ))
                        })
                    })?
            } else {
                Metadata::new()
            };

            let proposed_metadata = Metadata::deserialize(repository.clone(), updated)
                .await
                .filter_slow_down()?
                .map_err(|err| {
                    warn_error_to_status(&err, |err| {
                        Status::invalid_argument(format!(
                            "failed to deserialize proposed metadata: {err}"
                        ))
                    })
                })?;

            validate_read_only_fields(&current_metadata, &proposed_metadata)?;
            validate_binary_blobs(repository.clone(), &proposed_metadata).await?;

            let metadata_key = hash::hash_function_arg(
                repository::SALT_LORE,
                repository::METADATA,
                hex::encode(repository_id.data()).as_str(),
            );
            let previous = if let Some(governed) = &governed {
                let event = match governed.outbox_cell_id() {
                    Some(cell_id) => Some(
                        outbox_builders::repository_metadata_changed(
                            cell_id,
                            repository_id.data(),
                            expected.as_ref(),
                            updated.as_ref(),
                        )
                        .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                    ),
                    None => None,
                };
                let projection = ProjectionWrite {
                    partition: repository_id.data().to_vec(),
                    key_type: KeyType::RepositoryMetadata as i16,
                    key: metadata_key.as_ref().to_vec(),
                    value: Some(updated.as_ref().to_vec()),
                };
                match governed
                    .commit(
                        repository_id.data(),
                        None,
                        expected.as_ref(),
                        updated.as_ref(),
                        projection,
                        event,
                    )
                    .await?
                {
                    MetadataCasOutcome::Applied => expected,
                    MetadataCasOutcome::Lost(observed) => Hash::from(observed.as_slice()),
                }
            } else {
                let write_token = get_write_token();
                repository
                    .write_mutable_store(&write_token)
                    .compare_and_swap(
                        repository_id.into(),
                        metadata_key,
                        expected,
                        updated,
                        KeyType::RepositoryMetadata,
                    )
                    .await
                    .filter_slow_down()?
                    .map_err(|err| {
                        warn_error_to_status(&err, |err| {
                            Status::internal(format!("failed to update metadata: {err}"))
                        })
                    })?
            };

            let metadata = if previous == expected {
                updated
            } else {
                previous
            };
            Ok(Response::new(RepositoryMetadataSetResponse {
                metadata: metadata.into(),
            }))
        })
        .await
}

/// Reject a proposed metadata blob that mutates a read-only field.
#[lore_macro::test_pub]
fn validate_read_only_fields(current: &Metadata, proposed: &Metadata) -> Result<(), Status> {
    for key in READ_ONLY_KEYS {
        let current_value = current.get_typed(key);
        let proposed_value = proposed.get_typed(key);

        match (current_value, proposed_value) {
            (Ok((current_bytes, current_type)), Ok((proposed_bytes, proposed_type))) => {
                if current_type != proposed_type || current_bytes != proposed_bytes {
                    return Err(Status::invalid_argument(format!(
                        "cannot modify read-only key '{key}'"
                    )));
                }
            }
            (Ok(_), Err(_)) => {
                return Err(Status::invalid_argument(format!(
                    "cannot remove read-only key '{key}'"
                )));
            }
            (Err(_), Ok(_) | Err(_)) => {}
        }
    }
    Ok(())
}

/// Reject a proposed metadata blob that references an Address that is not
/// currently addressable in CAS.
async fn validate_binary_blobs(
    repo: Arc<RepositoryContext>,
    proposed: &Metadata,
) -> Result<(), Status> {
    let mut addresses = vec![];
    proposed.walk(
        |_key_slice: &[u8], value_slice: &[u8], value_type: MetadataType| {
            if value_type == MetadataType::Address
                && value_slice.len() == std::mem::size_of::<Address>()
            {
                let address: Address = value_slice.into();
                addresses.push(address);
            }
        },
    );

    for address in addresses {
        let options = lore_revision::immutable::read_options_from_repository(&repo).with_cache();
        if lore_revision::immutable::read(repo.clone(), address, None, options)
            .await
            .filter_slow_down()?
            .is_err()
        {
            return Err(Status::not_found(format!(
                "binary blob not found: {address}"
            )));
        }
    }
    Ok(())
}
