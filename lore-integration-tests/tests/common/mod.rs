// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod net_common {
    /// Maximum candidates tried, OS-assigned and random together.
    pub(crate) const PORT_PAIR_ATTEMPTS: usize = 100;

    /// The IANA dynamic range that random fallback candidates are drawn from.
    const DYNAMIC_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;

    /// Where the leading TCP socket of one candidate binds.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Candidate {
        /// Port 0: the OS picks.
        Assigned,
        /// A random port from `DYNAMIC_PORTS`.
        At(u16),
    }

    /// A TCP listener and a UDP socket on the same port, both held exclusively.
    ///
    /// A `lore://` server serves gRPC on TCP and QUIC on UDP at one number, and no bind can reserve
    /// a number for the other protocol. So the port is not chosen and then bound twice — it is
    /// bound on TCP, matched on UDP, and handed to the servers already bound. Nothing can take
    /// either between choosing and serving, because there is no such gap.
    ///
    /// Neither socket sets a reuse option. Failed candidates stay reserved until this search ends,
    /// preventing immediate reuse. The first candidate is OS-assigned. Every later one is random:
    /// Windows excludes port ranges per protocol in blocks of 100 (Hyper-V, WSL, `WinNAT`), and
    /// the OS hands out ports sequentially, so asking it again keeps landing in the same block.
    /// A random loopback bind can succeed over another process's wildcard bind of the same port;
    /// the matching bind always had that exposure, and the OS-assigned first candidate does not.
    pub(crate) fn bind_matched_pair() -> (std::net::TcpListener, std::net::UdpSocket) {
        reserve_matched_pair(
            PORT_PAIR_ATTEMPTS,
            random_port,
            |candidate| match candidate {
                Candidate::Assigned => std::net::TcpListener::bind("127.0.0.1:0"),
                Candidate::At(port) => {
                    std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|error| {
                        std::io::Error::new(error.kind(), format!("TCP port {port}: {error}"))
                    })
                }
            },
            |tcp| {
                let port = tcp.local_addr()?.port();
                std::net::UdpSocket::bind(("127.0.0.1", port)).map_err(|error| {
                    std::io::Error::new(error.kind(), format!("UDP port {port}: {error}"))
                })
            },
        )
        .unwrap_or_else(|error| panic!("cannot reserve matched TCP/UDP sockets: {error}"))
    }

    fn random_port() -> u16 {
        rand::random_range(DYNAMIC_PORTS)
    }

    /// Bind up to `attempts` candidates until one matches. An OS-assigned bind failure is fatal,
    /// because the OS has no port to give. A random bind failure only costs that candidate.
    fn reserve_matched_pair<T, U>(
        attempts: usize,
        mut next_random: impl FnMut() -> u16,
        mut bind_leading: impl FnMut(Candidate) -> std::io::Result<T>,
        mut bind_matching: impl FnMut(&T) -> std::io::Result<U>,
    ) -> std::io::Result<(T, U)> {
        let mut rejected = Vec::new();
        let mut last_error = None;
        for attempt in 0..attempts {
            let candidate = if attempt == 0 {
                Candidate::Assigned
            } else {
                Candidate::At(next_random())
            };
            let leading = match bind_leading(candidate) {
                Ok(leading) => leading,
                Err(error) if candidate == Candidate::Assigned => return Err(error),
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            match bind_matching(&leading) {
                Ok(matching) => return Ok((leading, matching)),
                Err(error) => {
                    last_error = Some(error);
                    rejected.push(leading);
                }
            }
        }
        Err(std::io::Error::other(format!(
            "no matching socket after {attempts} candidates ({} reserved); last failure: {:?}",
            rejected.len(),
            last_error
        )))
    }

    #[cfg(test)]
    mod tests {
        use std::cell::RefCell;
        use std::collections::BTreeSet;
        use std::io;
        use std::ops::RangeInclusive;
        use std::rc::Rc;

        use super::Candidate;
        use super::DYNAMIC_PORTS;
        use super::PORT_PAIR_ATTEMPTS;
        use super::random_port;
        use super::reserve_matched_pair;

        #[derive(Debug)]
        struct Reservation(u16, Rc<RefCell<BTreeSet<u16>>>);

        impl Drop for Reservation {
            fn drop(&mut self) {
                assert!(self.1.borrow_mut().remove(&self.0));
            }
        }

        /// A model of the excluded blocks on the failing rig: TCP and UDP blocks together spanned
        /// 55333-57125. Here one protocol holds the whole span.
        const EXCLUDED: RangeInclusive<u16> = 55333..=57125;

        /// Model the OS: port 0 hands out the next number of a sequential allocator that starts
        /// inside the excluded block, a named port binds unless it is held or excluded.
        struct Model {
            held: Rc<RefCell<BTreeSet<u16>>>,
            next_assigned: u16,
            leading_excluded: bool,
        }

        impl Model {
            fn new(leading_excluded: bool) -> Self {
                Model {
                    held: Rc::new(RefCell::new(BTreeSet::new())),
                    next_assigned: *EXCLUDED.start(),
                    leading_excluded,
                }
            }

            fn bind(&mut self, candidate: Candidate) -> io::Result<Reservation> {
                let port = match candidate {
                    Candidate::Assigned => {
                        self.next_assigned += 1;
                        self.next_assigned
                    }
                    Candidate::At(port) => port,
                };
                // The OS never assigns a port excluded on its own protocol; a named port can be.
                let named = matches!(candidate, Candidate::At(_));
                if self.leading_excluded && named && EXCLUDED.contains(&port) {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                if !self.held.borrow_mut().insert(port) {
                    return Err(io::Error::from(io::ErrorKind::AddrInUse));
                }
                Ok(Reservation(port, Rc::clone(&self.held)))
            }
        }

        fn match_outside_excluded(socket: &Reservation) -> io::Result<u16> {
            if EXCLUDED.contains(&socket.0) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(socket.0)
            }
        }

        #[test]
        fn assigned_candidate_is_used_when_it_matches() {
            let mut model = Model::new(false);
            let pair = reserve_matched_pair(
                PORT_PAIR_ATTEMPTS,
                || panic!("no random candidate needed"),
                |candidate| model.bind(candidate),
                |socket| Ok(socket.0),
            )
            .unwrap();
            assert_eq!(pair.1, *EXCLUDED.start() + 1);
        }

        /// The run-6 failure: every OS-assigned port sits in a block excluded on the matching
        /// protocol. The old logic asked the OS 100 times and exhausted inside the block.
        #[test]
        fn random_fallback_escapes_a_sequential_excluded_block() {
            for leading_excluded in [false, true] {
                let mut model = Model::new(leading_excluded);
                let held = Rc::clone(&model.held);
                let mut candidates = Vec::new();
                let pair = reserve_matched_pair(
                    PORT_PAIR_ATTEMPTS,
                    random_port,
                    |candidate| {
                        candidates.push(candidate);
                        model.bind(candidate)
                    },
                    match_outside_excluded,
                )
                .unwrap();
                assert!(DYNAMIC_PORTS.contains(&pair.1) && !EXCLUDED.contains(&pair.1));
                assert_eq!(candidates[0], Candidate::Assigned);
                assert!(candidates[1..].iter().all(|candidate| {
                    matches!(candidate, Candidate::At(port) if DYNAMIC_PORTS.contains(port))
                }));
                assert_eq!(*held.borrow(), BTreeSet::from([pair.1]));
                drop(pair);
                assert!(held.borrow().is_empty());
            }
        }

        #[test]
        fn random_candidates_cover_the_dynamic_range() {
            let ports: Vec<u16> = (0..10_000).map(|_| random_port()).collect();
            assert!(ports.iter().all(|port| DYNAMIC_PORTS.contains(port)));
            assert!(ports.iter().any(|port| *port < 50_000));
            assert!(ports.iter().any(|port| *port > 64_000));
        }

        #[test]
        fn rejected_candidates_stay_reserved_until_a_pair_is_found() {
            let mut model = Model::new(false);
            let held = Rc::clone(&model.held);
            let mut randoms = [60_001, 60_002].into_iter();
            let mut visited = Vec::new();
            let pair = reserve_matched_pair(
                3,
                || randoms.next().unwrap(),
                |candidate| model.bind(candidate),
                |socket| {
                    visited.push(socket.0);
                    assert_eq!(held.borrow().len(), visited.len());
                    if socket.0 == 60_002 {
                        Ok(socket.0)
                    } else {
                        Err(io::Error::from(io::ErrorKind::AddrInUse))
                    }
                },
            )
            .unwrap();
            assert_eq!(visited, [*EXCLUDED.start() + 1, 60_001, 60_002]);
            assert_eq!(*held.borrow(), BTreeSet::from([60_002]));
            drop(pair);
            assert!(held.borrow().is_empty());
        }

        #[test]
        fn random_bind_failure_costs_only_that_candidate() {
            let mut model = Model::new(true);
            model.next_assigned = 40_000;
            let held = Rc::clone(&model.held);
            // Excluded on the leading protocol, then the held assigned port, then a free one.
            let mut randoms = [56_000, 40_001, 60_000].into_iter();
            let mut matched = Vec::new();
            let pair = reserve_matched_pair(
                4,
                || randoms.next().unwrap(),
                |candidate| model.bind(candidate),
                |socket| {
                    matched.push(socket.0);
                    if socket.0 == 40_001 {
                        Err(io::Error::from(io::ErrorKind::AddrInUse))
                    } else {
                        Ok(socket.0)
                    }
                },
            )
            .unwrap();
            assert_eq!(matched, [40_001, 60_000]);
            assert_eq!(pair.1, 60_000);
            assert_eq!(*held.borrow(), BTreeSet::from([60_000]));
            drop(pair);
            assert!(held.borrow().is_empty());
        }

        #[test]
        fn exhaustion_is_bounded_and_releases_every_candidate() {
            let mut model = Model::new(false);
            let held = Rc::clone(&model.held);
            let mut next = 60_000;
            let mut tries = 0;
            let error = reserve_matched_pair::<_, ()>(
                3,
                || {
                    next += 1;
                    next
                },
                |candidate| {
                    tries += 1;
                    model.bind(candidate)
                },
                |_| {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "UDP excluded",
                    ))
                },
            )
            .unwrap_err();
            assert_eq!(tries, 3);
            assert!(held.borrow().is_empty());
            assert!(error.to_string().contains("3 candidates (3 reserved)"));
            assert!(error.to_string().contains("UDP excluded"));
        }

        #[test]
        fn assigned_bind_failure_is_fatal() {
            let mut tries = 0;
            let error = reserve_matched_pair::<Reservation, ()>(
                3,
                || panic!("no random candidate after a fatal bind"),
                |_| {
                    tries += 1;
                    Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                },
                |_| unreachable!(),
            )
            .unwrap_err();
            assert_eq!(tries, 1);
            assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        }
    }
}

#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod aws_common {
    use std::error::Error;
    use std::sync::Arc;

    use aws_sdk_dynamodb::operation::create_table::CreateTableError;
    use aws_sdk_dynamodb::types::AttributeDefinition;
    use aws_sdk_dynamodb::types::GlobalSecondaryIndex;
    use aws_sdk_dynamodb::types::KeySchemaElement;
    use aws_sdk_dynamodb::types::KeyType;
    use aws_sdk_dynamodb::types::Projection;
    use aws_sdk_dynamodb::types::ProjectionType;
    use aws_sdk_dynamodb::types::ProvisionedThroughput;
    use aws_sdk_dynamodb::types::ScalarAttributeType;
    use aws_sdk_s3::operation::create_bucket::CreateBucketError;
    use lore_aws::clients::AwsClientBuilder;
    use lore_aws::clients::HttpClientSettings;
    use lore_aws::dynamodb::DynamoDb;
    use lore_aws::s3::S3;
    use lore_aws::store::immutable_store::FRAGMENTS_DYNAMO_PARTITION_KEY_ATTRIBUTE;
    use lore_aws::store::immutable_store::FRAGMENTS_DYNAMO_SORT_KEY_ATTRIBUTE;
    use lore_aws::store::lock_store::*;
    use lore_aws::store::mutable_store::MUTABLE_STORE_DYNAMO_PARTITION_KEY_ATTRIBUTE;
    use lore_aws::store::mutable_store::MUTABLE_STORE_DYNAMO_SORT_KEY_ATTRIBUTE;
    use tracing::info;
    use tracing::warn;

    pub const LOCKS_TABLE_NAME: &str = "locks-local";
    pub const STORE_BUCKET_NAME: &str = "lore-immutable-store-local";
    pub const MUTABLE_STORE_TABLE_NAME: &str = "lore-mutable-store-local";
    pub const FRAGMENTS_TABLE_NAME: &str = "lore-fragments-local";
    pub const FRAGMENT_STATE_TABLE_NAME: &str = "lore-fragment-state-local";
    pub const FRAGMENT_METADATA_TABLE_NAME: &str = "lore-fragment-metadata-local";

    // NOTE: these credentials are just hardcoded in lore-integration-tests/compose.yaml
    const AWS_ACCESS_KEY_ID: &str = "lorelocal";
    const AWS_SECRET_ACCESS_KEY: &str = "lorelocal";

    pub fn dynamodb_endpoint() -> String {
        std::env::var("LORE_INTEGRATION_DYNAMODB_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9090".to_string())
    }

    pub async fn setup(
        tables: Vec<&str>,
    ) -> Result<(S3, DynamoDb, DynamoDb), Box<dyn Error + 'static>> {
        let _ = tracing_subscriber::fmt::try_init();
        let s3_endpoint = std::env::var("LORE_INTEGRATION_S3_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
        let dynamodb_endpoint = dynamodb_endpoint();

        Ok((
            s3_client(s3_endpoint).await?,
            dynamodb_client(dynamodb_endpoint.clone(), tables.clone()).await?,
            dynamodb_client(dynamodb_endpoint, tables).await?,
        ))
    }

    async fn create_store_bucket(client: &aws_sdk_s3::Client) -> Result<(), Box<dyn Error>> {
        match client
            .create_bucket()
            .bucket(STORE_BUCKET_NAME)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateBucketError::BucketAlreadyOwnedByYou(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the bucket, if it turns out the bucket exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
        }
    }

    async fn s3_client(endpoint_url: String) -> Result<S3, Box<dyn Error + 'static>> {
        let http_settings = HttpClientSettings::default();

        // Set up AWS client.
        let creds = aws_sdk_s3::config::Credentials::new(
            AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY,
            None,
            None,
            "test",
        );

        let client = AwsClientBuilder::builder()
            .with_http_settings(&http_settings)
            .with_credentials_provider(creds)
            .region("us-east-1")
            .endpoint(endpoint_url)
            .build_config()
            .await
            .s3()
            .build()
            .await?;

        match client.bucket_exists(STORE_BUCKET_NAME.to_string()).await {
            Ok(exists) => {
                if !exists {
                    info!("Bucket {STORE_BUCKET_NAME} does not exist, creating...");
                    create_store_bucket(client.sdk_client()).await?;
                }

                Ok(client)
            }
            Err(e) => {
                warn!("Failed to check if bucket exists: {e:?}");
                Err(e.into())
            }
        }
    }

    async fn create_locks_table(client: &aws_sdk_dynamodb::Client) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(LOCKS_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(HASH_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(REPO_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(BRANCH_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(REPO_BRANCH_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(OWNER_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::S))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(DESC_KEY)
                    .set_attribute_type(Some(ScalarAttributeType::S))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(HASH_KEY)
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(REPO_BRANCH_KEY)
                    .set_key_type(Some(KeyType::Range))
                    .build()?,
            )
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(OWNER_REPO_BRANCH_GSI)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(OWNER_KEY)
                            .set_key_type(Some(KeyType::Hash))
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(REPO_BRANCH_KEY)
                            .set_key_type(Some(KeyType::Range))
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .provisioned_throughput(
                        ProvisionedThroughput::builder()
                            .set_read_capacity_units(Some(5000))
                            .set_write_capacity_units(Some(5000))
                            .build()?,
                    )
                    .build()?,
            )
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(REPO_BRANCH_GSI)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(REPO_KEY)
                            .set_key_type(Some(KeyType::Hash))
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(BRANCH_KEY)
                            .set_key_type(Some(KeyType::Range))
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .provisioned_throughput(
                        ProvisionedThroughput::builder()
                            .set_read_capacity_units(Some(5000))
                            .set_write_capacity_units(Some(5000))
                            .build()?,
                    )
                    .build()?,
            )
            .global_secondary_indexes(
                GlobalSecondaryIndex::builder()
                    .index_name(REPO_BRANCH_DESC_GSI)
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(REPO_BRANCH_KEY)
                            .set_key_type(Some(KeyType::Hash))
                            .build()?,
                    )
                    .key_schema(
                        KeySchemaElement::builder()
                            .attribute_name(DESC_KEY)
                            .set_key_type(Some(KeyType::Range))
                            .build()?,
                    )
                    .projection(
                        Projection::builder()
                            .projection_type(ProjectionType::All)
                            .build(),
                    )
                    .provisioned_throughput(
                        ProvisionedThroughput::builder()
                            .set_read_capacity_units(Some(5000))
                            .set_write_capacity_units(Some(5000))
                            .build()?,
                    )
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_store_table(client: &aws_sdk_dynamodb::Client) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(MUTABLE_STORE_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(MUTABLE_STORE_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Range))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_fragments_table(
        client: &aws_sdk_dynamodb::Client,
    ) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(FRAGMENTS_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_PARTITION_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(FRAGMENTS_DYNAMO_SORT_KEY_ATTRIBUTE)
                    .set_key_type(Some(KeyType::Range))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_fragment_state_table(
        client: &aws_sdk_dynamodb::Client,
    ) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(FRAGMENT_STATE_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hash")
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hash")
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    async fn create_fragment_metadata_table(
        client: &aws_sdk_dynamodb::Client,
    ) -> Result<(), Box<dyn Error>> {
        let result = client
            .create_table()
            .table_name(FRAGMENT_METADATA_TABLE_NAME)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hash")
                    .set_attribute_type(Some(ScalarAttributeType::B))
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hash")
                    .set_key_type(Some(KeyType::Hash))
                    .build()?,
            )
            .provisioned_throughput(
                ProvisionedThroughput::builder()
                    .set_read_capacity_units(Some(5000))
                    .set_write_capacity_units(Some(5000))
                    .build()?,
            )
            .send()
            .await;

        match result {
            Err(e) => {
                let err = e.as_service_error().unwrap();
                if let CreateTableError::ResourceInUseException(_) = err {
                    // Since tests run in parallel there can be a race condition trying to create
                    // the table, if it turns out the table exists, just ignore the failure.
                    return Ok(());
                }

                Err(e.into())
            }
            _ => Ok(()),
        }
    }

    pub(crate) async fn dynamodb_client(
        endpoint_url: String,
        tables: Vec<&str>,
    ) -> Result<DynamoDb, Box<dyn Error + 'static>> {
        let http_settings = HttpClientSettings::default();

        let creds = aws_sdk_dynamodb::config::Credentials::new(
            AWS_ACCESS_KEY_ID,
            AWS_SECRET_ACCESS_KEY,
            None,
            None,
            "test",
        );

        let client = AwsClientBuilder::builder()
            .with_http_settings(&http_settings)
            .with_credentials_provider(creds)
            .region("us-east-2")
            .endpoint(endpoint_url)
            .build_config()
            .await
            .dynamodb()
            .build()
            .await?;

        for table_name in tables {
            match client.table_exists(&Arc::from(table_name)).await {
                Ok(exists) => {
                    if !exists {
                        match table_name {
                            MUTABLE_STORE_TABLE_NAME => {
                                create_store_table(client.sdk_client()).await?;
                            }
                            FRAGMENTS_TABLE_NAME => {
                                create_fragments_table(client.sdk_client()).await?;
                            }
                            FRAGMENT_STATE_TABLE_NAME => {
                                create_fragment_state_table(client.sdk_client()).await?;
                            }
                            FRAGMENT_METADATA_TABLE_NAME => {
                                create_fragment_metadata_table(client.sdk_client()).await?;
                            }
                            LOCKS_TABLE_NAME => create_locks_table(client.sdk_client()).await?,
                            _ => {
                                return Err(
                                    anyhow::anyhow!("Invalid table name: {table_name}").into()
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to check if table exists: {e:?}");
                    return Err(e.into());
                }
            }
        }

        Ok(client)
    }
}
