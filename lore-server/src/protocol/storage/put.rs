// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::fmt;
use std::fmt::Formatter;
use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::FragmentReference;
use lore_revision::lore::RepositoryId;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_storage::TypedBytes;
use lore_storage::validate_fragment_list;
use lore_storage::validate_fragment_metadata;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::LabelArray;
use lore_telemetry::tracing::fields::ADDRESS;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;
use smallvec::SmallVec;
use tracing::debug;
use tracing::warn;

use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::correlation::CorrelationId;
use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::attribute_map::get_user_id_from_context;
use crate::protocol::storage::messages::LoreResponse;
use crate::protocol::storage::messages::Message;
use crate::protocol::storage::messages::MessageHandleError;
use crate::protocol::storage::messages::MessageParseError;
use crate::protocol::storage::messages::Response;
use crate::util::setup_execution;

const METRICS_COMPRESSION_LABEL: &str = "fragment_compression";

#[lore_macro::test_pub]
#[derive(Clone, Debug, PartialEq)]
pub struct Put {
    address: Address,
    fragment: Fragment,
    payload: Option<Bytes>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnvalidatedPut {
    pub address: Address,
    pub fragment: Fragment,
    pub payload: Option<Bytes>,
}

impl UnvalidatedPut {
    pub fn validate(self) -> Result<Put, MessageParseError> {
        validate_fragment_metadata(&self.fragment).map_err(|err| {
            warn!(
                fragment = ?self.fragment,
                error = ?err,
                "Put rejected: invalid fragment metadata"
            );
            MessageParseError::InvalidFieldLength
        })?;

        if let Some(payload) = &self.payload
            && payload.len() != self.fragment.size_payload as usize
        {
            return Err(MessageParseError::InvalidFieldLength);
        }

        Ok(Put {
            address: self.address,
            fragment: self.fragment,
            payload: self.payload,
        })
    }
}

struct PutInstrumentProvider;

impl InstrumentProvider for PutInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.quic.message.put"
    }
}

impl PutInstrumentProvider {
    fn payload_size_histogram(&self) -> Histogram<u64> {
        self.size_histogram("payload_size")
    }

    fn content_size_histogram(&self) -> Histogram<u64> {
        self.size_histogram("content_size")
    }
}

struct PutInstrument {
    provider: &'static PutInstrumentProvider,
    payload_size_histogram: Histogram<u64>,
    content_size_histogram: Histogram<u64>,
}

impl PutInstrument {
    fn fragment_labels(&self, fragment: &Fragment) -> LabelArray {
        let mut labels = SmallVec::new();
        labels.extend(self.provider.labels().iter().cloned());

        labels.push(KeyValue::new(
            METRICS_COMPRESSION_LABEL,
            FragmentFlags::compression_label(fragment.flags),
        ));

        labels
    }

    fn payload_size(&self, size: u32, labels: &[KeyValue]) {
        self.payload_size_histogram.record(size as u64, labels);
    }

    fn content_size(&self, size: u64, labels: &[KeyValue]) {
        self.content_size_histogram.record(size, labels);
    }
}

fn instruments() -> &'static PutInstrument {
    static PROVIDER: OnceLock<PutInstrumentProvider> = OnceLock::new();
    static INSTRUMENTS: OnceLock<PutInstrument> = OnceLock::new();
    INSTRUMENTS.get_or_init(|| {
        let provider = PROVIDER.get_or_init(|| PutInstrumentProvider);
        PutInstrument {
            provider,
            payload_size_histogram: provider.payload_size_histogram(),
            content_size_histogram: provider.content_size_histogram(),
        }
    })
}

impl Put {
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Verify the caller holds the content named by the address.
    ///
    /// The payload is that proof: the hash is recomputed from it and compared to
    /// the address. A put carrying none proves nothing and is refused — skipping
    /// is not equivalent to passing. The store deduplicates on hash across
    /// partitions; sharing content across them is `Copy`'s job, which names a
    /// `source_repository` and authorizes the caller against it.
    #[lore_macro::test_pub]
    fn validate_hash(&self) -> Result<(), MessageHandleError> {
        let Some(payload) = self.payload.as_ref() else {
            warn!(
                fragment = ?self.fragment,
                {ADDRESS} = %self.address,
                "Hash validation failed, put carries no payload to prove the address"
            );
            return Err(MessageHandleError::HashFailed);
        };
        match lore_storage::hash_fragment(self.fragment, payload.as_ref()) {
            Ok(hash) => {
                if hash != self.address.hash {
                    warn!(
                        fragment = ?self.fragment,
                        {ADDRESS} = %self.address,
                        computed_hash = %hash,
                        "Hash validation failed, computed hash does not match address"
                    );
                    return Err(MessageHandleError::HashMismatch);
                }
            }
            Err(err) => {
                warn!(
                    fragment = ?self.fragment,
                    {ADDRESS} = %self.address,
                    error = ?err,
                    "Hash validation failed, unable to hash"
                );
                return Err(MessageHandleError::HashFailed);
            }
        }
        Ok(())
    }

    #[lore_macro::test_pub]
    fn validate_fragment(&self) -> Result<(), MessageHandleError> {
        // Metadata checks (size bounds, flag sanity, size_payload ≤ size_content,
        // uncompressed/unfragmented size equality, compressed+fragmented exclusion,
        // etc.) are performed at ingress in `UnvalidatedPut::validate`. Here we
        // only need the payload-dependent checks for fragment lists.
        if self.fragment.flags & FragmentFlags::PayloadFragmented != 0
            && let Some(payload) = self.payload.as_ref()
        {
            validate_fragment_list(&self.fragment, payload).map_err(|err| {
                warn!(
                    fragment = ?self.fragment,
                    {ADDRESS} = %self.address,
                    error = ?err,
                    "Fragment validation failed"
                );
                MessageHandleError::InvalidFragment
            })?;
        }
        Ok(())
    }

    /// Bind the put's structure to what its address can mean.
    ///
    /// A list's address is the hash of its reference bytes, and a plain
    /// fragment's address is the hash of its content, so the same bytes name both.
    /// The hash alone cannot tell them apart, so this checks what it can against
    /// the store:
    ///
    /// - A list must declare the content its references cover: the span from the
    ///   first to the last offset plus the last child's stored size, when the last
    ///   child is already stored.
    /// - A plain fragment whose content parses as a list, and whose last reference
    ///   names a fragment this repository holds, is refused. Honest content cannot
    ///   name a stored hash by chance, so only a forged copy of a list matches.
    ///
    /// This does not stop a plain copy uploaded before the list's children exist.
    /// The store refuses the later list as a collision, and push verification
    /// refuses a revision whose file size does not match the stored fragment.
    #[lore_macro::test_pub]
    async fn validate_structure(
        &self,
        repository: RepositoryId,
        immutable_store: &Arc<dyn ImmutableStore>,
    ) -> Result<(), MessageHandleError> {
        let Some(payload) = self.payload.as_ref() else {
            return Ok(());
        };

        if self.fragment.flags & FragmentFlags::PayloadFragmented != 0 {
            let references = payload.clone().to_aligned::<FragmentReference>();
            let references = references.as_type_slice::<FragmentReference>();
            let (Some(first), Some(last)) = (references.first(), references.last()) else {
                return Err(MessageHandleError::InvalidFragment);
            };
            let child = Address {
                context: self.address.context,
                hash: last.hash,
            };
            // A push uploads a list and its children in parallel, so the last child may not
            // have landed yet. Such a list is not compared here; push verification compares
            // every list level against the sizes the file node implies.
            let stored = match immutable_store
                .clone()
                .get_metadata(repository, child)
                .await
            {
                Ok(stored) if stored.match_made != StoreMatch::MatchNone => stored.fragment,
                Ok(_) => return Ok(()),
                Err(StoreError::SlowDown(_)) => return Err(MessageHandleError::SlowDown),
                Err(err) if err.is_address_not_found() => return Ok(()),
                Err(err) => return Err(MessageHandleError::from(err)),
            };
            let covered = (last.offset_content - first.offset_content)
                .checked_add(stored.size_content)
                .ok_or_else(|| self.refuse_structure("the covered size overflows"))?;
            if covered != self.fragment.size_content {
                return Err(self.refuse_structure("size_content does not match its children"));
            }
            return Ok(());
        }

        let reference_size = size_of::<FragmentReference>() as u64;
        let size_content = self.fragment.size_content;
        if size_content < 2 * reference_size || !size_content.is_multiple_of(reference_size) {
            return Ok(());
        }
        let content = if self.fragment.flags & FragmentFlags::PayloadCompressed != 0 {
            match lore_storage::decompress(self.fragment, payload.as_ref()) {
                Ok((_, content)) => content.freeze(),
                Err(_) => return Err(MessageHandleError::HashFailed),
            }
        } else {
            payload.clone()
        };
        let references = content.to_aligned::<FragmentReference>();
        let references = references.as_type_slice::<FragmentReference>();
        // The shape `validate_fragment_list` accepts, without a declared size:
        // at least two references at strictly increasing offsets.
        let list_shaped = references.len() >= 2
            && references
                .windows(2)
                .all(|pair| pair[0].offset_content < pair[1].offset_content);
        let (true, Some(last)) = (list_shaped, references.last()) else {
            return Ok(());
        };
        let probe = [Address {
            context: self.address.context,
            hash: last.hash,
        }];
        let mut resolved = [StoreMatchResult::default()];
        match immutable_store
            .clone()
            .query(repository, &probe, &mut resolved)
            .await
        {
            Ok(()) if resolved[0].match_made != StoreMatch::MatchNone => {
                Err(self.refuse_structure("a plain fragment encodes a list over stored fragments"))
            }
            Ok(()) => Ok(()),
            Err(StoreError::SlowDown(_)) => Err(MessageHandleError::SlowDown),
            Err(err) => Err(MessageHandleError::from(err)),
        }
    }

    fn refuse_structure(&self, reason: &str) -> MessageHandleError {
        warn!(
            fragment = ?self.fragment,
            {ADDRESS} = %self.address,
            reason,
            "Put rejected: fragment structure does not match its address"
        );
        MessageHandleError::InvalidFragment
    }

    #[cfg(feature = "test-util")]
    pub fn to_bytes(&self) -> Bytes {
        use zerocopy::IntoBytes;

        let mut bytes =
            bytes::BytesMut::with_capacity(size_of::<Address>() + size_of::<Fragment>());
        bytes.extend_from_slice(self.address.as_bytes());
        bytes.extend_from_slice(self.fragment.as_bytes());
        if let Some(payload) = self.payload.as_ref() {
            bytes.extend_from_slice(payload.as_ref());
        }
        bytes.freeze()
    }
}

impl fmt::Display for Put {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self.fragment)
    }
}

impl Put {
    pub fn parse(bytes: Bytes) -> Result<Self, MessageParseError>
    where
        Self: Sized,
    {
        if bytes.len() < size_of::<Address>() + size_of::<Fragment>() {
            return Err(MessageParseError::InvalidFieldLength);
        }

        let mut bytes = bytes;
        let address = bytes.split_to(size_of::<Address>()).into();
        let fragment: Fragment = bytes.split_to(size_of::<Fragment>()).into();

        let payload = if bytes.is_empty() { None } else { Some(bytes) };

        let unvalidated = UnvalidatedPut {
            address,
            fragment,
            payload,
        };
        unvalidated.validate()
    }
}

pub async fn handle_put(
    put: &Put,
    repository: RepositoryId,
    correlation_id: String,
    user_id: String,
    immutable_store: Arc<dyn ImmutableStore>,
) -> Result<LoreResponse, MessageHandleError> {
    let execution = setup_execution(module_path!(), correlation_id, user_id);

    debug!(
        "Handling PutFragment request for fragment with address: {} ({} bytes payload) in repository: {}",
        put.address,
        put.payload
            .as_ref()
            .map(|payload| payload.len())
            .unwrap_or_default(),
        repository
    );

    let instruments = instruments();

    let address = put.address;
    let fragment = put.fragment;
    let payload = put.payload.clone();

    LORE_CONTEXT
        .scope(execution, async move {
            put.validate_fragment()?;
            put.validate_hash()?;
            put.validate_structure(repository, &immutable_store).await?;

            let mut fragment = fragment;
            fragment.flags &= !FragmentFlags::PayloadStored;

            // Transcode incoming Oodle payloads to Zstd.
            // The hash is over uncompressed content, so the address is unchanged.
            #[cfg(feature = "oodle")]
            let (fragment, payload) = crate::protocol::oodle_ingress::convert_oodle_on_ingress(
                address, fragment, payload,
            )
            .await;

            {
                let labels = instruments.fragment_labels(&fragment);
                instruments.payload_size(put.fragment.size_payload, &labels);
                instruments.content_size(put.fragment.size_content, &labels);
            }

            match immutable_store
                .put(repository, address, fragment, payload, false)
                .await
            {
                Ok(_) => {
                    debug!("Successfully stored fragment for address: {}", address);
                    Ok(LoreResponse::Put(PutResponse::default()))
                }
                Err(StoreError::SlowDown(_)) => Err(MessageHandleError::SlowDown),
                Err(err) => {
                    warn!(error = ?err, {ADDRESS} = %address, "Failed to put fragment for address");
                    Err(MessageHandleError::from(err))
                }
            }
        })
        .await
}

#[async_trait]
impl Message for Put {
    #[tracing::instrument(name = "Put::handle", skip_all)]
    async fn handle(
        &self,
        context: Arc<AttributeMap>,
        immutable_store: Arc<dyn ImmutableStore>,
        _repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    ) -> Result<LoreResponse, MessageHandleError> {
        let repository = *context
            .get_or::<RepositoryId, MessageHandleError>(MessageHandleError::NotConnected)?;
        let user_id = get_user_id_from_context(&context);
        let correlation_id = context.get::<CorrelationId>().unwrap_or_default();
        handle_put(
            self,
            repository,
            correlation_id.to_string(),
            user_id,
            immutable_store,
        )
        .await
    }
}

impl InstrumentProvider for Put {
    fn namespace(&self) -> &'static str {
        "quic.message.put"
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct PutResponse {}

impl Response for PutResponse {
    fn data(&self) -> Vec<Bytes> {
        vec![]
    }
}
