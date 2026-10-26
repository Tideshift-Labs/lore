// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

/// The stage usage ledger must equal what the custody rows hold. Cleanup that
/// deletes or keeps a row has to move the counters by exactly that row's charge,
/// so a leak or a double refund shows up here whatever path produced it.
///
/// Reads through its own connection, straight from the tables, never through the
/// coordinator that is under test.
pub async fn assert_stage_ledger_matches_custody(url: &str) {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let task = lore_base::lore_spawn!(async move {
        connection.await.unwrap();
    });
    let row = client
        .query_one(
            "SELECT u.metadata_rows, u.metadata_bytes, u.live_files, u.live_bytes, \
                    (SELECT count(*) FROM lore_fragment_stage_custody)::bigint, \
                    (SELECT coalesce(sum(metadata_bytes),0) FROM lore_fragment_stage_custody)::bigint, \
                    (SELECT count(*) FROM lore_fragment_stage_custody WHERE state<>3)::bigint, \
                    (SELECT coalesce(sum(size_payload),0) FROM lore_fragment_stage_custody WHERE state<>3)::bigint \
             FROM lore_fragment_stage_usage u WHERE u.singleton",
            &[],
        )
        .await
        .unwrap();
    let get = |index: usize| row.get::<_, i64>(index);
    assert_eq!(
        get(0),
        get(4),
        "metadata_rows must equal the count of custody rows"
    );
    assert_eq!(
        get(1),
        get(5),
        "metadata_bytes must equal the sum of custody metadata_bytes"
    );
    assert_eq!(
        get(2),
        get(6),
        "live_files must equal the count of non-tombstone custody rows"
    );
    assert_eq!(
        get(3),
        get(7),
        "live_bytes must equal the payload bytes of non-tombstone custody rows"
    );
    drop(client);
    task.await.unwrap();
}
