// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Offline provisioning reads. This type has no provider mutation methods and
//! must never be used as the serving fragment provider path.

use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use aws_smithy_types::retry::RetryConfig;

use super::ObjectStoreSettings;
use super::build_object_client;

/// Refusals remain distinct from provider failures; the latter retain their cause.
#[derive(Debug, thiserror::Error)]
pub enum CleanNamespaceError {
    #[error("{0}")]
    InvalidConfiguration(&'static str),
    #[error("failed to build S3 client: {0}")]
    Client(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("cannot inspect {operation}: {source}")]
    Inspection {
        operation: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error(
        "clean initialization requires versioning never enabled; Enabled, Suspended and unknown states are refused"
    )]
    VersionedNamespace,
    #[error("clean initialization refused: bucket contains objects")]
    ObjectsPresent,
    #[error("clean initialization refused: bucket contains versions or delete markers")]
    VersionsPresent,
    #[error("clean initialization refused: bucket contains incomplete multipart uploads")]
    MultipartUploadsPresent,
}

/// Stable namespace binding, without loading credentials or issuing provider I/O.
pub fn clean_namespace_identity(
    object: &ObjectStoreSettings,
) -> Result<String, CleanNamespaceError> {
    let (endpoint, region) = namespace_fields(object)?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"lore-clean-object-namespace-v1\0");
    for field in [
        endpoint,
        region,
        object.bucket.as_str(),
        if object.force_path_style {
            "true"
        } else {
            "false"
        },
    ] {
        digest.update(&(field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Ok(format!("s3-v1:{}", digest.finalize().to_hex()))
}

fn namespace_fields(object: &ObjectStoreSettings) -> Result<(&str, &str), CleanNamespaceError> {
    let endpoint = object
        .endpoint_url
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(CleanNamespaceError::InvalidConfiguration(
            "clean initialization requires an explicit object_store.endpoint_url",
        ))?;
    let region = object
        .region
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(CleanNamespaceError::InvalidConfiguration(
            "clean initialization requires an explicit object_store.region",
        ))?;
    if object.bucket.is_empty() {
        return Err(CleanNamespaceError::InvalidConfiguration(
            "clean initialization requires an object_store.bucket",
        ));
    }
    Ok((endpoint, region))
}

/// Read-only, bounded inspection of the entire configured bucket.
pub struct CleanObjectNamespaceInspector {
    client: aws_sdk_s3::Client,
    bucket: String,
    identity: String,
}

impl CleanObjectNamespaceInspector {
    /// Resolve the same endpoint, region and credential chain as the store.
    /// Explicit endpoint and region configuration is required so the attested
    /// namespace does not depend on a later environment fallback.
    pub async fn connect(object: ObjectStoreSettings) -> Result<Self, CleanNamespaceError> {
        let (endpoint, region) = namespace_fields(&object)?;
        let identity = clean_namespace_identity(&object)?;
        if object.timeout_millis == 0 {
            return Err(CleanNamespaceError::InvalidConfiguration(
                "clean initialization requires a bucket and positive object operation timeout",
            ));
        }
        let s3 = build_object_client(&object)
            .await
            .map_err(CleanNamespaceError::Client)?;
        if s3.resolved_endpoint_url().as_deref() != Some(endpoint)
            || s3
                .sdk_client()
                .config()
                .region()
                .map(|value| value.as_ref())
                != Some(region)
        {
            return Err(CleanNamespaceError::InvalidConfiguration(
                "resolved object namespace differs from its explicit configuration",
            ));
        }
        let config = s3
            .sdk_client()
            .config()
            .to_builder()
            .retry_config(RetryConfig::disabled())
            .build();
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(config),
            bucket: object.bucket,
            identity,
        })
    }

    /// Credential-free, framed digest of endpoint, region, bucket and addressing.
    pub fn namespace_identity(&self) -> &str {
        &self.identity
    }

    /// Required on initial activation and every completed rerun. Suspended is
    /// unsafe too: historical versions and delete markers can remain hidden.
    pub async fn attest_unversioned(&self) -> Result<(), CleanNamespaceError> {
        let result = self
            .client
            .get_bucket_versioning()
            .bucket(&self.bucket)
            .send()
            .await
            .map_err(|source| CleanNamespaceError::Inspection {
                operation: "bucket versioning",
                source: Box::new(source),
            })?;
        if result.status().is_some() {
            return Err(CleanNamespaceError::VersionedNamespace);
        }
        Ok(())
    }

    /// Whole-bucket probes, each limited to one result. No prefix, delimiter,
    /// pagination, object writes, deletes or multipart aborts are permitted.
    pub async fn attest_empty(&self) -> Result<(), CleanNamespaceError> {
        let objects = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .max_keys(1)
            .send()
            .await
            .map_err(|source| CleanNamespaceError::Inspection {
                operation: "bucket objects",
                source: Box::new(source),
            })?;
        if !objects.contents().is_empty()
            || objects.is_truncated() == Some(true)
            || objects.key_count().is_some_and(|count| count != 0)
        {
            return Err(CleanNamespaceError::ObjectsPresent);
        }
        match self
            .client
            .list_object_versions()
            .bucket(&self.bucket)
            .max_keys(1)
            .send()
            .await
        {
            Ok(versions) => {
                if !versions.versions().is_empty()
                    || !versions.delete_markers().is_empty()
                    || versions.is_truncated() == Some(true)
                {
                    return Err(CleanNamespaceError::VersionsPresent);
                }
            }
            // Only an explicit unsupported-operation response is exempt. Access
            // denial, network errors and generic provider failures are not proof.
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.code() == Some("NotImplemented")) => {}
            Err(error) => {
                return Err(CleanNamespaceError::Inspection {
                    operation: "bucket versions and delete markers",
                    source: Box::new(error),
                });
            }
        }
        let uploads = self
            .client
            .list_multipart_uploads()
            .bucket(&self.bucket)
            .max_uploads(1)
            .send()
            .await
            .map_err(|source| CleanNamespaceError::Inspection {
                operation: "incomplete multipart uploads",
                source: Box::new(source),
            })?;
        if !uploads.uploads().is_empty() || uploads.is_truncated() == Some(true) {
            return Err(CleanNamespaceError::MultipartUploadsPresent);
        }
        Ok(())
    }
}
