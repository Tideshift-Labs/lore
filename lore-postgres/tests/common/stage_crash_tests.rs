// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use super::*;

#[tokio::test]
#[ignore = "requires owned PostgreSQL, Unix and failure_generator"]
async fn actual_process_crashes_preserve_committed_stages_and_reclaim_unpublished_residue() {
    let payload = Bytes::from_static(b"actual crash boundary payload");
    let hash = blake3::hash(&payload).as_bytes().to_vec();
    if let Ok(root_path) = std::env::var("LORE_TEST_STAGE_CRASH_ROOT") {
        let url = pg_url().expect("child database");
        let domain = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
            .await
            .unwrap();
        let coordinator = domain.fragment_coordinator();
        let repository = create_repository(&domain).await;
        let root = ScratchRoot(PathBuf::from(root_path));
        let stage = open_stage(&root);
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_stage(
                &hash,
                lore_postgres::domain::fragments::StageReservationInput {
                    size_payload: payload.len() as u64,
                    original_flags: 0,
                },
            )
            .await
            .unwrap()
        else {
            panic!("fresh child stage")
        };
        stage
            .stage(&hash, intent.epoch, &intent.object_key, &payload)
            .await
            .unwrap();
        coordinator
            .commit_staged(
                &intent,
                IoObservation::Valid(FragmentManifest {
                    authority: EpochAuthority::Staged,
                    object_key: intent.object_key.clone(),
                    manifest_id: vec![0x61; 32],
                    size_payload: payload.len() as i64,
                    size_content: payload.len() as i64,
                    decoded_hash: hash.clone(),
                    payload_flags: 0,
                }),
            )
            .await
            .unwrap();
        let witness = coordinator
            .capture_current_readable_epoch_for_authority(&hash, EpochAuthority::Staged)
            .await
            .unwrap()
            .unwrap();
        coordinator
            .create_association_if_current(&witness, &repository, &[0x62; 16])
            .await
            .unwrap();
        panic!("configured crash boundary was not reached");
    }
    for (anchor, committed, associated) in [
        ("stage.temp.synced", false, false),
        ("stage.final.renamed", false, false),
        ("publication.commit.settled", true, false),
        ("association.create_guarded.settled", true, true),
    ] {
        let url = fresh_database(&pg_url().expect("owned database")).await;
        let coordinator = coordinator(&url).await;
        let root = ScratchRoot::new(anchor);
        let root_path = root.0.clone();
        let child_url = url.clone();
        let output = tokio::task::spawn_blocking(move || std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "stage_crash_tests::actual_process_crashes_preserve_committed_stages_and_reclaim_unpublished_residue", "--nocapture"])
            .env("LORE_TEST_PG_URL", child_url)
            .env("LORE_TEST_STAGE_CRASH_ROOT", root_path)
            .env("LORE_FRAGMENT_FAILPOINTS", format!("{anchor}=abort"))
            .output().unwrap()).await.unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(&format!("{anchor}: aborting this process")),
            "child must abort at the exact boundary: {:?}",
            output
        );
        let stage = open_stage(&root);
        let direct = direct_client(&url).await;
        let epoch: i64 = direct
            .query_one(
                "SELECT epoch FROM lore_fragment_stage_custody WHERE hash=$1",
                &[&hash],
            )
            .await
            .unwrap()
            .get(0);
        let key = format!("{}.s{epoch}", hex::encode(&hash));
        let witness = coordinator
            .capture_current_readable_epoch_for_authority(&hash, EpochAuthority::Staged)
            .await
            .unwrap();
        assert_eq!(witness.is_some(), committed, "{anchor}");
        let count: i64 = direct
            .query_one(
                "SELECT count(*) FROM lore_fragment_associations WHERE hash=$1",
                &[&hash],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, i64::from(associated), "{anchor}");
        if committed {
            let lore_postgres::store::write_behind::StagedRead::Found(bytes) =
                stage.read_staged(&hash, epoch, &key).await
            else {
                panic!("committed stage must be peer-readable")
            };
            assert_eq!(bytes, payload);
            assert!(
                coordinator
                    .begin_stage_cleanup(&hash, epoch)
                    .await
                    .unwrap()
                    .is_none()
            );
        } else {
            direct.execute("UPDATE lore_fragment_stage_custody SET prepare_deadline=clock_timestamp()-interval '1 second' WHERE hash=$1", &[&hash]).await.unwrap();
            let cleanup = coordinator
                .begin_stage_cleanup(&hash, epoch)
                .await
                .unwrap()
                .expect("expired unpublished custody reclaimed");
            let mut scanner =
                lore_postgres::store::write_behind::cleanup::StageFileScanner::default();
            let mut purged = false;
            for _ in 0..32 {
                for candidate in scanner.scan(&stage, 16).unwrap() {
                    if candidate.hash.as_slice() == hash.as_slice() && candidate.epoch == epoch {
                        stage.purge_candidate(&candidate, cleanup.target()).unwrap();
                        purged = true;
                    }
                }
                if purged {
                    break;
                }
            }
            assert!(
                purged,
                "crashed process must leave its identified temp or final for exact reclamation"
            );
            coordinator.commit_stage_cleanup(&cleanup).await.unwrap();
            coordinator.commit_stage_cleanup(&cleanup).await.unwrap();
            let usage = coordinator.observe_stage().await.unwrap();
            assert_eq!((usage.resident_bytes, usage.resident_files), (0, 0));
            assert!(!root.0.join("incoming").join(format!("{key}.tmp")).exists());
            assert!(matches!(
                stage.read_staged(&hash, epoch, &key).await,
                lore_postgres::store::write_behind::StagedRead::Absent
            ));
        }
    }
}
