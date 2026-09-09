// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[cfg(all(test, feature = "integration_tests"))]
pub(crate) mod net_common {
    /// Maximum simultaneously reserved candidates across both protocols.
    pub(crate) const PORT_PAIR_ATTEMPTS: usize = 100;

    /// A TCP listener and a UDP socket on the same port, both held exclusively.
    ///
    /// A `lore://` server serves gRPC on TCP and QUIC on UDP at one number, and no bind can reserve
    /// a number for the other protocol. So the port is not chosen and then bound twice — it is
    /// taken from the OS on one protocol, matched on the other, and handed to the servers already
    /// bound. Nothing can take either between choosing and serving, because there is no such gap.
    ///
    /// Neither socket sets a reuse option. Failed candidates stay reserved until this search ends,
    /// preventing immediate reuse. Alternate the leading protocol: Windows can allocate many TCP
    /// candidates inside a UDP-only excluded range (and vice versa).
    pub(crate) fn bind_matched_pair() -> (std::net::TcpListener, std::net::UdpSocket) {
        enum Socket {
            Tcp(std::net::TcpListener),
            Udp(std::net::UdpSocket),
        }
        let pair = reserve_matched_pair(
            PORT_PAIR_ATTEMPTS,
            |tcp_first| {
                if tcp_first {
                    std::net::TcpListener::bind("127.0.0.1:0").map(Socket::Tcp)
                } else {
                    std::net::UdpSocket::bind("127.0.0.1:0").map(Socket::Udp)
                }
            },
            |socket| match socket {
                Socket::Tcp(tcp) => {
                    let port = tcp.local_addr()?.port();
                    std::net::UdpSocket::bind(("127.0.0.1", port))
                        .map(Socket::Udp)
                        .map_err(|error| {
                            std::io::Error::new(error.kind(), format!("UDP port {port}: {error}"))
                        })
                }
                Socket::Udp(udp) => {
                    let port = udp.local_addr()?.port();
                    std::net::TcpListener::bind(("127.0.0.1", port))
                        .map(Socket::Tcp)
                        .map_err(|error| {
                            std::io::Error::new(error.kind(), format!("TCP port {port}: {error}"))
                        })
                }
            },
        )
        .unwrap_or_else(|error| panic!("cannot reserve matched TCP/UDP sockets: {error}"));
        match pair {
            (Socket::Tcp(tcp), Socket::Udp(udp)) | (Socket::Udp(udp), Socket::Tcp(tcp)) => {
                (tcp, udp)
            }
            _ => unreachable!("matching always binds the other protocol"),
        }
    }

    fn reserve_matched_pair<T, U>(
        attempts: usize,
        mut bind_leading: impl FnMut(bool) -> std::io::Result<T>,
        mut bind_matching: impl FnMut(&T) -> std::io::Result<U>,
    ) -> std::io::Result<(T, U)> {
        let mut rejected = Vec::new();
        let mut last_error = None;
        for attempt in 0..attempts {
            let leading = bind_leading(attempt % 2 == 0)?;
            match bind_matching(&leading) {
                Ok(matching) => return Ok((leading, matching)),
                Err(error) => {
                    last_error = Some(error);
                    rejected.push(leading);
                }
            }
        }
        Err(std::io::Error::other(format!(
            "no matching socket after {} reserved candidates; last failure: {:?}",
            rejected.len(),
            last_error
        )))
    }

    #[cfg(test)]
    mod tests {
        use std::cell::RefCell;
        use std::collections::BTreeSet;
        use std::io;
        use std::rc::Rc;

        use super::reserve_matched_pair;

        #[derive(Debug)]
        struct Reservation(u16, Rc<RefCell<BTreeSet<u16>>>);

        impl Drop for Reservation {
            fn drop(&mut self) {
                assert!(self.1.borrow_mut().remove(&self.0));
            }
        }

        // Model an allocator that immediately reuses the lowest released port. Dropping a rejected
        // reservation would select port 1 forever, even though port 3 has a matching UDP socket.
        fn lowest_free(held: &Rc<RefCell<BTreeSet<u16>>>) -> Reservation {
            let port = (1..=u16::MAX)
                .find(|port| !held.borrow().contains(port))
                .unwrap();
            assert!(held.borrow_mut().insert(port));
            Reservation(port, Rc::clone(held))
        }

        #[test]
        fn rejected_candidates_stay_reserved_until_a_pair_is_found() {
            let held = Rc::new(RefCell::new(BTreeSet::new()));
            let mut visited = Vec::new();
            let pair = reserve_matched_pair(
                3,
                |_| Ok(lowest_free(&held)),
                |tcp| {
                    visited.push(tcp.0);
                    if tcp.0 == 3 {
                        Ok(3)
                    } else {
                        Err(io::Error::from(io::ErrorKind::AddrInUse))
                    }
                },
            )
            .unwrap();
            assert_eq!(visited, [1, 2, 3]);
            assert_eq!(*held.borrow(), BTreeSet::from([3]));
            assert_eq!(pair.1, 3);
            drop(pair);
            assert!(held.borrow().is_empty());
        }

        #[test]
        fn exhaustion_is_bounded_and_releases_every_candidate() {
            let held = Rc::new(RefCell::new(BTreeSet::new()));
            let mut visited = Vec::new();
            let error = reserve_matched_pair::<_, ()>(
                3,
                |_| Ok(lowest_free(&held)),
                |tcp| {
                    visited.push(tcp.0);
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "UDP excluded",
                    ))
                },
            )
            .unwrap_err();
            assert_eq!(visited, [1, 2, 3]);
            assert!(held.borrow().is_empty());
            assert!(error.to_string().contains("3 reserved candidates"));
            assert!(error.to_string().contains("UDP excluded"));
        }

        #[test]
        fn tcp_failure_releases_previous_reservations() {
            let held = Rc::new(RefCell::new(BTreeSet::new()));
            let mut calls = 0;
            let error = reserve_matched_pair::<_, ()>(
                3,
                |_| {
                    calls += 1;
                    if calls == 2 {
                        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                    } else {
                        Ok(lowest_free(&held))
                    }
                },
                |_| Err(io::Error::from(io::ErrorKind::AddrInUse)),
            )
            .unwrap_err();
            assert_eq!(calls, 2);
            assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
            assert!(held.borrow().is_empty());
        }

        fn protocol_exclusion_model(tcp_band_excluded_on_udp: bool) {
            let held = Rc::new(RefCell::new(BTreeSet::new()));
            let mut leaders = Vec::new();
            let mut tcp_number = 0;
            let mut udp_number = 1000;
            let pair = reserve_matched_pair(
                super::PORT_PAIR_ATTEMPTS,
                |tcp_first| {
                    leaders.push(tcp_first);
                    let number = if tcp_first {
                        &mut tcp_number
                    } else {
                        &mut udp_number
                    };
                    *number += 1;
                    assert!(held.borrow_mut().insert(*number));
                    Ok(Reservation(*number, Rc::clone(&held)))
                },
                |socket| {
                    // One protocol's entire candidate band is excluded on the other protocol.
                    // The opposite allocator's first candidate also conflicts, then finds a pair.
                    let excluded = if tcp_band_excluded_on_udp {
                        socket.0 < 1000 || socket.0 == 1001
                    } else {
                        socket.0 >= 1000 || socket.0 == 1
                    };
                    if excluded {
                        Err(io::Error::from(io::ErrorKind::PermissionDenied))
                    } else {
                        Ok(socket.0)
                    }
                },
            )
            .unwrap();
            if tcp_band_excluded_on_udp {
                assert_eq!(leaders, [true, false, true, false]);
                assert_eq!(pair.1, 1002);
            } else {
                assert_eq!(leaders, [true, false, true]);
                assert_eq!(pair.1, 2);
            }
            assert_eq!(*held.borrow(), BTreeSet::from([pair.1]));
            drop(pair);
            assert!(held.borrow().is_empty());
        }

        #[test]
        fn udp_leading_escapes_a_tcp_candidate_band_excluded_on_udp() {
            protocol_exclusion_model(true);
        }

        #[test]
        fn tcp_leading_escapes_a_udp_candidate_band_excluded_on_tcp() {
            protocol_exclusion_model(false);
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
