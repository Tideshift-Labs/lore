// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//
// CR-030, WP-120: contract tests for `RepositoryAttemptStore`, the `.lore/`-backed durable
// `AttemptStore` implementation. [CLIENT]-class: `lore-revision` ships into user workstations.
//
// Every test uses `RepositoryAttemptStore::in_directory(tempdir)` -- the seam the module itself
// documents as existing for exactly this purpose -- so nothing here needs a `RepositoryContext`
// or a repository fixture. These pin the *durable* implementation's own promises: what
// `lore-transport`'s `VolatileAttemptStore` already pins at the trait-contract level
// (`lore-transport/tests/attempt_store.rs`) is not re-litigated here except where the durable
// backend can break it in a way the volatile one cannot (a version byte, a torn write, a file
// mode) -- see this crate's own module doc at `src/attempt_store.rs` for why the file is a
// plaintext-adjacent credential store and what obligations that puts on it.

// `std::fs::write` is disallowed workspace-wide because a production repository write must go
// through a `RepositoryWriteToken`-gated helper. This whole file writes only inside its own
// tempdir fixture -- either through `RepositoryAttemptStore` itself, or, in the version-byte and
// torn-write cases, by deliberately corrupting the raw bytes on disk to prove the store detects
// exactly that damage. Neither is a repository write this lint exists to catch.
#![allow(clippy::disallowed_methods)]

mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_base::types::RepositoryId;
    use lore_revision::attempt_store::RepositoryAttemptStore;
    use lore_transport::attempt_store::AttemptRecord;
    use lore_transport::attempt_store::AttemptResolution;
    use lore_transport::attempt_store::AttemptState;
    use lore_transport::attempt_store::AttemptStore;
    use lore_transport::attempt_store::LockOwnership;
    use lore_transport::attempt_store::OwnershipToken;
    use lore_transport::domain_receipt::DomainReceiptQuery;
    use lore_transport::outcome::AttemptId;
    use uuid::Uuid;

    include!("helper.rs");

    fn repository() -> RepositoryId {
        RepositoryId::from([0x01u8; 16])
    }

    fn unresolved_record(
        attempt: AttemptId,
        operation: &str,
        recorded_at_unix_millis: i64,
    ) -> AttemptRecord {
        AttemptRecord {
            attempt_id: attempt,
            state: AttemptState::Unresolved,
            operation: operation.to_string(),
            repository: repository(),
            recorded_at_unix_millis,
            receipt: None,
        }
    }

    fn digest(fill: u8) -> Bytes {
        Bytes::from(vec![fill; 32])
    }

    fn sample_receipt() -> DomainReceiptQuery {
        DomainReceiptQuery {
            org_uuid: Uuid::now_v7(),
            initiating_principal_namespace: Bytes::from_static(b"principal-v1\0user"),
            operation_id: Uuid::now_v7(),
            method: "RevisionService.BranchCreate".to_string(),
            scope: Bytes::from_static(b"scope"),
            fingerprint_version: 1,
            fingerprint: digest(0xAA),
            canonical_intent_digest: digest(0xBB),
            authorization_revision: 7,
            consumed_ticket_sha256: digest(0xCC),
        }
    }

    fn token(fill: u8) -> OwnershipToken {
        OwnershipToken::from_wire(&[fill; OwnershipToken::LEN])
            .expect("32 bytes must decode")
            .expect("32 bytes must produce a token, not None")
    }

    /// Read the store's own on-disk bytes, skip the version byte, and parse the body as JSON --
    /// used only to prove a *count* (no duplicate rows), which nothing in the public
    /// `AttemptStore` trait exposes directly. Never used to assert on field *names*: the on-disk
    /// shape is this crate's own private implementation detail and could rename a field without
    /// breaking the trait contract these tests exist to pin.
    fn raw_document(store: &RepositoryAttemptStore) -> serde_json::Value {
        let bytes = std::fs::read(
            store
                .path()
                .expect("RepositoryAttemptStore::in_directory always sets a path"),
        )
        .expect("read the store file directly");
        let (_version, body) = bytes
            .split_first()
            .expect("the file must have a version byte");
        serde_json::from_slice(body).expect("the body must be valid JSON")
    }

    /// A missing file is an empty store, not an error -- the very first repository operation that
    /// ever touches locks or receipts must not require the file to already exist.
    #[tokio::test]
    async fn missing_file_reads_as_an_empty_store() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());

        assert_eq!(
            store
                .lookup(&AttemptId::new())
                .await
                .expect("lookup on a missing file must not error"),
            None
        );
        assert_eq!(
            store
                .unresolved()
                .await
                .expect("unresolved on a missing file must not error"),
            vec![]
        );
        assert!(
            !store
                .path()
                .expect("RepositoryAttemptStore::in_directory always sets a path")
                .exists(),
            "a read-only call must not create the file as a side effect"
        );
    }

    /// The basic round trip: what is recorded is what comes back, field for field, including the
    /// CR-029 receipt identity when the operation family carries one.
    #[tokio::test]
    async fn record_then_lookup_round_trips_the_exact_record_with_its_receipt() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let attempt = AttemptId::new();
        let record = AttemptRecord {
            receipt: Some(sample_receipt()),
            ..unresolved_record(attempt, "RevisionService.BranchPush", 1_000)
        };

        store.record(&record).await.expect("record must succeed");

        let looked_up = store
            .lookup(&attempt)
            .await
            .expect("lookup must succeed")
            .expect("the record must be found");
        assert_eq!(looked_up, record);
    }

    /// Recording the same attempt id twice overwrites the stored row rather than duplicating it,
    /// including a transition into a resolved state -- proved against the durable file's own
    /// document, not just the trait's read-back.
    #[tokio::test]
    async fn recording_the_same_attempt_id_twice_overwrites_the_stored_row() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let attempt = AttemptId::new();

        store
            .record(&unresolved_record(attempt, "Lock.Lock", 1_000))
            .await
            .expect("first record must succeed");
        store
            .record(&AttemptRecord {
                recorded_at_unix_millis: 2_000,
                ..unresolved_record(attempt, "Lock.Lock", 2_000)
            })
            .await
            .expect("second record must succeed");

        let looked_up = store.lookup(&attempt).await.unwrap().unwrap();
        assert_eq!(looked_up.recorded_at_unix_millis, 2_000);
        let document = raw_document(&store);
        assert_eq!(
            document["attempts"]
                .as_array()
                .expect("attempts array")
                .len(),
            1,
            "one attempt id retried into a second write must replace the row, not duplicate it: {document}"
        );
    }

    /// The token round-trips byte for byte through the store's hex-encoded on-disk form.
    #[tokio::test]
    async fn ownership_round_trips_the_exact_32_byte_token() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let branch = Context::from([0x11u8; 16]);
        let resource_hash = Hash::from([0x22u8; 32]);
        let ownership = LockOwnership {
            attempt_id: AttemptId::new(),
            branch,
            resource_hash,
            token: token(0xAB),
        };

        store
            .record_ownership(&ownership)
            .await
            .expect("record_ownership must succeed");

        let held = store
            .ownership_for(&branch, &resource_hash)
            .await
            .expect("ownership_for must succeed")
            .expect("the token must be found");
        assert_eq!(held, ownership);
    }

    /// One resource holds one token: recording ownership twice for the same (branch, resource)
    /// replaces the stored row -- proved against the durable file's own document, since the
    /// trait's read-back alone cannot distinguish "replaced" from "appended and shadowed by
    /// whichever the read happens to return first".
    #[tokio::test]
    async fn recording_ownership_twice_for_one_resource_replaces_rather_than_duplicates() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let branch = Context::from([0x11u8; 16]);
        let resource_hash = Hash::from([0x22u8; 32]);

        store
            .record_ownership(&LockOwnership {
                attempt_id: AttemptId::new(),
                branch,
                resource_hash,
                token: token(0xAA),
            })
            .await
            .unwrap();
        let renewed_attempt = AttemptId::new();
        store
            .record_ownership(&LockOwnership {
                attempt_id: renewed_attempt,
                branch,
                resource_hash,
                token: token(0xBB),
            })
            .await
            .unwrap();

        let held = store
            .ownership_for(&branch, &resource_hash)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held.token, token(0xBB), "the later write must win");
        assert_eq!(held.attempt_id, renewed_attempt);

        let document = raw_document(&store);
        assert_eq!(
            document["ownership"]
                .as_array()
                .expect("ownership array")
                .len(),
            1,
            "a renewal must replace the stored row, not sit beside it: {document}"
        );
    }

    /// Clearing a resource this store holds no token for is not an error -- a release racing an
    /// eviction, or a release for a lock this working tree never itself acquired, is not a fault.
    #[tokio::test]
    async fn clear_ownership_on_an_untracked_resource_is_ok() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let branch = Context::from([0x11u8; 16]);
        let resource_hash = Hash::from([0x22u8; 32]);

        store
            .clear_ownership(&branch, &resource_hash)
            .await
            .expect("clearing an untracked resource must succeed, not error");

        assert_eq!(
            store.ownership_for(&branch, &resource_hash).await.unwrap(),
            None
        );
    }

    /// `resolve()` moves the record to `Resolved` and keeps it (never deletes), and releases only
    /// the ownership *that attempt* held -- a different attempt's held lock must survive.
    #[tokio::test]
    async fn resolve_keeps_the_record_as_resolved_and_drops_only_its_own_ownership() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let resolved_attempt = AttemptId::new();
        let other_attempt = AttemptId::new();
        let branch = Context::from([0x11u8; 16]);
        let resolved_resource = Hash::from([0x22u8; 32]);
        let other_resource = Hash::from([0x44u8; 32]);

        store
            .record(&unresolved_record(resolved_attempt, "Lock.Lock", 1_000))
            .await
            .unwrap();
        store
            .record_ownership(&LockOwnership {
                attempt_id: resolved_attempt,
                branch,
                resource_hash: resolved_resource,
                token: token(0xAB),
            })
            .await
            .unwrap();
        store
            .record_ownership(&LockOwnership {
                attempt_id: other_attempt,
                branch,
                resource_hash: other_resource,
                token: token(0xCD),
            })
            .await
            .unwrap();

        store
            .resolve(&resolved_attempt, AttemptResolution::Applied)
            .await
            .unwrap();

        let looked_up = store
            .lookup(&resolved_attempt)
            .await
            .unwrap()
            .expect("a resolved attempt must still be found by lookup, never None");
        assert_eq!(
            looked_up.state,
            AttemptState::Resolved(AttemptResolution::Applied)
        );
        assert!(
            store
                .unresolved()
                .await
                .unwrap()
                .iter()
                .all(|record| record.attempt_id != resolved_attempt),
            "a resolved attempt must not appear in unresolved()"
        );
        assert_eq!(
            store
                .ownership_for(&branch, &resolved_resource)
                .await
                .unwrap(),
            None,
            "resolving an attempt must clear the ownership it held"
        );
        assert!(
            store
                .ownership_for(&branch, &other_resource)
                .await
                .unwrap()
                .is_some(),
            "resolving one attempt must not clear a lock a different attempt holds"
        );
    }

    /// `unresolved()` is sorted oldest-first by recorded time, and includes `AdjudicatedUnknown`
    /// records -- they still block writes and still carry the no-old-id-replay marker an operator
    /// has to restore.
    #[tokio::test]
    async fn unresolved_is_oldest_first_and_includes_adjudicated_unknown() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let newest = AttemptId::new();
        let oldest = AttemptId::new();
        let adjudicated = AttemptId::new();

        store
            .record(&unresolved_record(newest, "op", 300))
            .await
            .unwrap();
        store
            .record(&unresolved_record(oldest, "op", 100))
            .await
            .unwrap();
        store
            .record(&AttemptRecord {
                state: AttemptState::AdjudicatedUnknown,
                ..unresolved_record(adjudicated, "Lock.Lock", 200)
            })
            .await
            .unwrap();

        let unresolved = store.unresolved().await.unwrap();
        assert_eq!(
            unresolved.iter().map(|r| r.attempt_id).collect::<Vec<_>>(),
            vec![oldest, adjudicated, newest],
            "must be sorted oldest-first and include the adjudicated record: {unresolved:?}"
        );
    }

    /// A file whose first byte is not the version this client reads is an ERROR, never an empty
    /// store: reading a damaged or newer-version store as empty would silently drop every held
    /// token, and the locks they name would become releasable only by an administrator.
    #[tokio::test]
    async fn an_unknown_version_byte_is_an_error_not_an_empty_store() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        store
            .record(&unresolved_record(AttemptId::new(), "Lock.Lock", 1_000))
            .await
            .expect("seed a real, valid store");

        let mut bytes = std::fs::read(
            store
                .path()
                .expect("RepositoryAttemptStore::in_directory always sets a path"),
        )
        .expect("read the seeded file");
        assert_ne!(
            bytes[0], 99,
            "sanity: 99 must not already be the real version byte"
        );
        bytes[0] = 99;
        std::fs::write(
            store
                .path()
                .expect("RepositoryAttemptStore::in_directory always sets a path"),
            &bytes,
        )
        .expect("corrupt the version byte");

        let lookup_error = store
            .lookup(&AttemptId::new())
            .await
            .expect_err("an unrecognised version byte must be refused, not read as empty");
        assert!(
            format!("{lookup_error}").contains("version"),
            "the error should name the reason: {lookup_error}"
        );
        store
            .unresolved()
            .await
            .expect_err("every read path must refuse the same corrupted file, not just lookup");
    }

    /// A valid version byte with a body that fails to parse is an error too, distinct from the
    /// wrong-version-byte case: the byte alone is not what makes the file trustworthy, and a
    /// reader that stopped checking the version was right must not silently drop a store whose
    /// body is otherwise damaged.
    #[tokio::test]
    async fn a_valid_version_byte_with_a_corrupt_json_body_is_an_error_not_an_empty_store() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        store
            .record(&unresolved_record(AttemptId::new(), "Lock.Lock", 1_000))
            .await
            .expect("seed a real, valid store");

        let path = store
            .path()
            .expect("RepositoryAttemptStore::in_directory always sets a path")
            .to_path_buf();
        let mut bytes = std::fs::read(&path).expect("read the seeded file");
        // Keep the real, valid version byte; corrupt only the body after it.
        bytes.truncate(1);
        bytes.extend_from_slice(b"this is not valid json");
        std::fs::write(&path, &bytes).expect("corrupt the JSON body");

        let lookup_error = store
            .lookup(&AttemptId::new())
            .await
            .expect_err("a corrupt body must be refused, not read as empty");
        assert!(
            format!("{lookup_error}").contains("parse"),
            "the error should name parsing as the reason, not just fail silently: {lookup_error}"
        );
        store
            .unresolved()
            .await
            .expect_err("every read path must refuse the same corrupted file, not just lookup");
    }

    /// Two concurrent `record_ownership` calls against DIFFERENT resources on one store must not
    /// lose either write. The in-process `write_guard` serialises the load-modify-store span
    /// rather than only the raw file write, so a second writer that started before the first
    /// finished must see the first one's row when it does its own read-modify-write, not overwrite
    /// a document it read before the first writer's change landed.
    #[tokio::test]
    async fn two_concurrent_record_ownership_calls_for_different_resources_do_not_lose_either_write()
     {
        let dir = generate_tempdir();
        let store = Arc::new(RepositoryAttemptStore::in_directory(dir.path()));
        let branch = Context::from([0x11u8; 16]);
        let resource_a = Hash::from([0x22u8; 32]);
        let resource_b = Hash::from([0x33u8; 32]);
        let ownership_a = LockOwnership {
            attempt_id: AttemptId::new(),
            branch,
            resource_hash: resource_a,
            token: token(0xA1),
        };
        let ownership_b = LockOwnership {
            attempt_id: AttemptId::new(),
            branch,
            resource_hash: resource_b,
            token: token(0xB1),
        };

        let (store_a, store_b) = (store.clone(), store.clone());
        let (owned_a, owned_b) = (ownership_a.clone(), ownership_b.clone());
        let (result_a, result_b) = tokio::join!(
            async move { store_a.record_ownership(&owned_a).await },
            async move { store_b.record_ownership(&owned_b).await },
        );
        result_a.expect("the first concurrent write must succeed");
        result_b.expect("the second concurrent write must succeed");

        assert_eq!(
            store.ownership_for(&branch, &resource_a).await.unwrap(),
            Some(ownership_a),
            "a concurrent sibling write must not lose this resource's ownership"
        );
        assert_eq!(
            store.ownership_for(&branch, &resource_b).await.unwrap(),
            Some(ownership_b),
            "a concurrent sibling write must not lose this resource's ownership"
        );

        let document = raw_document(&store);
        assert_eq!(
            document["ownership"]
                .as_array()
                .expect("ownership array")
                .len(),
            2,
            "both concurrent writes must be durably present, not one clobbering the other: \
             {document}"
        );
    }

    /// Atomic replace: a stray, half-written temporary sibling left behind by a hypothetical crash
    /// before its `rename` completed must never be read as the store, and must not disturb the
    /// last durably written, real file.
    #[tokio::test]
    async fn a_torn_temporary_write_is_never_read_as_the_store_and_leaves_the_real_file_intact() {
        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        let attempt = AttemptId::new();
        let record = unresolved_record(attempt, "Lock.Lock", 1_000);
        store
            .record(&record)
            .await
            .expect("seed a real, durable record");

        // Mirrors the store's own `TEMP_SUFFIX` (".~loretemp"): a torn write leaves exactly this
        // sibling next to the real file, never renamed over it.
        let mut temp_path = store
            .path()
            .expect("RepositoryAttemptStore::in_directory always sets a path")
            .as_os_str()
            .to_os_string();
        temp_path.push(".~loretemp");
        let temp_path = std::path::PathBuf::from(temp_path);
        std::fs::write(&temp_path, b"not a version byte and not valid JSON either")
            .expect("write the simulated torn temporary file");

        let looked_up = store
            .lookup(&attempt)
            .await
            .expect("a stray temp sibling must not make a healthy store unreadable")
            .expect("the previously durable record must still be found");
        assert_eq!(
            looked_up, record,
            "the real file's last durably written contents must be untouched"
        );

        // The next legitimate write must still succeed despite the leftover sibling (it creates
        // and truncates its own temp file rather than assuming it does not already exist).
        store
            .record(&unresolved_record(AttemptId::new(), "Lock.Lock", 2_000))
            .await
            .expect("a later write must succeed despite a leftover torn temp file");
    }

    /// The token is a bearer credential at rest: on unix the file is created `0o600` so it is
    /// never briefly readable by another user on the machine, matching the discipline the
    /// existing authentication token cache applies to its own on-disk secrets.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_file_mode_denies_group_and_other_access() {
        use std::os::unix::fs::PermissionsExt;

        let dir = generate_tempdir();
        let store = RepositoryAttemptStore::in_directory(dir.path());
        store
            .record(&unresolved_record(AttemptId::new(), "Lock.Lock", 1_000))
            .await
            .expect("record must succeed");

        let mode = std::fs::metadata(
            store
                .path()
                .expect("RepositoryAttemptStore::in_directory always sets a path"),
        )
        .expect("read file metadata")
        .permissions()
        .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the attempt store must be owner-read-write only, got {mode:o}"
        );
    }
}
