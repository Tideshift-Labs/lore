// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `loreserver stage resolve-lost`: parse-time requirements, filter bounds,
//! refusal reporting, and the confirm token's binding and expiry. No
//! database; the live half is `lore-postgres/tests/stage_loss_rulings_live.rs`
//! and the drain half runs in `run-write-behind-linux.ps1`.

use std::time::Duration;

use clap::Parser;
use lore_postgres::domain::fragments::StagerIdentity;
use lore_postgres::domain::fragments::stage_loss::LossApplyOutcome;
use lore_postgres::domain::fragments::stage_loss::LossApplyRefusal;
use lore_postgres::domain::fragments::stage_loss::LossFilter;
use lore_postgres::domain::fragments::stage_loss::LossRulingRecord;
use lore_postgres::domain::fragments::stage_loss::LostStagedFile;
use lore_postgres::domain::fragments::stage_loss::TokenRefusal;
use lore_postgres::domain::fragments::stage_loss::check_confirm_token;
use lore_postgres::domain::fragments::stage_loss::confirm_token;
use lore_postgres::domain::fragments::stage_loss::token_issued_ms;
use lore_server::domain::stage_operator::*;

#[derive(Debug, Parser)]
struct Harness {
    #[command(subcommand)]
    command: StageCommand,
}

fn parse(args: &[&str]) -> Result<ResolveLostCommand, clap::Error> {
    let mut argv = vec!["loreserver", "resolve-lost"];
    argv.extend_from_slice(args);
    Harness::try_parse_from(argv).map(|parsed| {
        let StageCommand::ResolveLost { command } = parsed.command;
        command
    })
}

const TOKEN: &str = "v1-1-00000000000000000000000000000000";

#[test]
fn list_parses_with_the_one_hour_floor_and_the_row_maximum() {
    let ResolveLostCommand::List { selection, json } = parse(&["list"]).unwrap() else {
        panic!("list");
    };
    assert_eq!(selection.min_age_minutes, MIN_AGE_MINUTES);
    assert_eq!(MIN_AGE_MINUTES, 60);
    assert_eq!(selection.limit, MAX_ROWS);
    assert_eq!(MAX_ROWS, 1_000);
    assert!(!json);
}

#[test]
fn the_age_floor_and_the_row_bound_are_parse_errors() {
    for args in [
        ["list", "--min-age-minutes", "59"],
        ["list", "--min-age-minutes", "0"],
        ["list", "--limit", "0"],
        ["list", "--limit", "1001"],
    ] {
        assert!(parse(&args).is_err(), "{args:?} must be refused");
    }
    assert!(parse(&["list", "--min-age-minutes", "60", "--limit", "1000"]).is_ok());
}

#[test]
fn apply_requires_confirm_actor_and_reason_at_parse_time() {
    let full = [
        "apply",
        "--confirm",
        TOKEN,
        "--actor",
        "kv",
        "--reason",
        "mount checked",
    ];
    let ResolveLostCommand::Apply {
        confirm,
        actor,
        reason,
        attest_mounts_checked,
        multi_repository,
        ..
    } = parse(&full).unwrap()
    else {
        panic!("apply");
    };
    assert_eq!(
        (confirm.as_str(), actor.as_str(), reason.as_str()),
        (TOKEN, "kv", "mount checked")
    );
    assert!(
        !attest_mounts_checked && !multi_repository,
        "both recorded flags default off"
    );
    let mut multi = full.to_vec();
    multi.push("--multi-repository");
    let ResolveLostCommand::Apply {
        multi_repository, ..
    } = parse(&multi).unwrap()
    else {
        panic!("apply --multi-repository");
    };
    assert!(multi_repository);
    let mut old = full.to_vec();
    old.push("--cross-tenant");
    assert!(
        parse(&old).is_err(),
        "the old flag name is gone, not an alias"
    );
    for missing in ["--confirm", "--actor", "--reason"] {
        let at = full.iter().position(|arg| *arg == missing).unwrap();
        let args: Vec<&str> = full
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != at && *index != at + 1)
            .map(|(_, arg)| *arg)
            .collect();
        assert!(
            parse(&args).is_err(),
            "apply without {missing} must not parse"
        );
    }
}

#[test]
fn status_parses_and_bounds_its_limit() {
    let ResolveLostCommand::Status { limit, open, .. } = parse(&["status"]).unwrap() else {
        panic!("status");
    };
    assert_eq!(limit, 100);
    assert!(!open);
    assert!(parse(&["status", "--limit", "1001"]).is_err());
}

#[test]
fn hex_filters_are_checked_for_width() {
    let selection = |hash: Option<&str>, repository: Option<&str>| SelectionArgs {
        hash: hash.map(str::to_owned),
        stager: None,
        repository: repository.map(str::to_owned),
        min_age_minutes: 60,
        limit: 10,
    };
    assert!(selection(Some(&"ab".repeat(32)), None).filter().is_ok());
    assert!(selection(Some(&"ab".repeat(31)), None).filter().is_err());
    assert!(selection(Some("zz"), None).filter().is_err());
    assert!(selection(None, Some(&"cd".repeat(16))).filter().is_ok());
    assert!(selection(None, Some(&"cd".repeat(32))).filter().is_err());
    let filter = selection(None, None).filter().unwrap();
    assert_eq!(filter.min_age, Duration::from_secs(3_600));
}

#[test]
fn every_apply_refusal_fails_the_process_and_names_the_hashes() {
    let hash = vec![0xabu8; 32];
    for refusal in [
        LossApplyRefusal::Token(TokenRefusal::Expired),
        LossApplyRefusal::Token(TokenRefusal::Replayed),
        LossApplyRefusal::Empty,
        LossApplyRefusal::NeedsAttestation(vec![hash.clone()]),
        LossApplyRefusal::NeedsMultiRepository(vec![hash.clone()]),
        LossApplyRefusal::Contended,
    ] {
        let error = report_apply("cell", &LossApplyOutcome::Refused(refusal.clone()), false)
            .expect_err("a refusal exits non-zero");
        assert!(error.to_string().contains("nothing was written"), "{error}");
        if matches!(
            refusal,
            LossApplyRefusal::NeedsAttestation(_) | LossApplyRefusal::NeedsMultiRepository(_)
        ) {
            assert!(describe_refusal(&refusal).contains(&hex::encode(&hash)));
        }
    }
    assert!(
        describe_refusal(&LossApplyRefusal::NeedsAttestation(vec![hash.clone()]))
            .contains("--attest-mounts-checked")
    );
    assert!(
        describe_refusal(&LossApplyRefusal::NeedsMultiRepository(vec![hash]))
            .contains("--multi-repository")
    );
    assert!(
        report_apply(
            "cell",
            &LossApplyOutcome::Applied {
                rulings: Vec::new(),
                already_open: Vec::new()
            },
            true
        )
        .is_ok()
    );
}

/// Fix round 2 (F4): a 40001 or 40P01 during `apply` (both classify as
/// `Contention`) is a clear refusal, not a raw driver error. Every other
/// error and every outcome pass through unchanged. No retry happens here.
#[test]
fn a_contended_apply_is_a_refusal_that_says_rerun() {
    use lore_postgres::domain::DomainError;
    use lore_postgres::domain::fragments::stage_loss::refuse_contended_apply;
    for detail in [
        "stage loss ruling insert (SQLSTATE 40001: could not serialize access due to concurrent \
         update)",
        "stage loss expire before apply (SQLSTATE 40P01: deadlock detected)",
    ] {
        let mapped = refuse_contended_apply(Err(DomainError::Contention(detail.to_owned())))
            .expect("contention is a refusal, not an error");
        assert_eq!(
            mapped,
            LossApplyOutcome::Refused(LossApplyRefusal::Contended)
        );
        let message = report_apply("cell", &mapped, false)
            .expect_err("a contended apply exits non-zero")
            .to_string();
        for needle in [
            "nothing was written",
            "token is still valid",
            "run the same apply again",
        ] {
            assert!(message.contains(needle), "{message}");
        }
        assert!(!message.contains("SQLSTATE"), "{message}");
    }
    for other in [
        DomainError::Transient("pool".to_owned()),
        DomainError::OutcomeUnknown("commit ack lost".to_owned()),
        DomainError::Internal("x".to_owned()),
    ] {
        assert_eq!(refuse_contended_apply(Err(other.clone())), Err(other));
    }
    let applied = LossApplyOutcome::Applied {
        rulings: Vec::new(),
        already_open: Vec::new(),
    };
    assert_eq!(refuse_contended_apply(Ok(applied.clone())), Ok(applied));
}

fn filter() -> LossFilter {
    LossFilter {
        hash: None,
        stager: None,
        repository: None,
        min_age: Duration::from_secs(3_600),
        limit: 1_000,
    }
}

fn file(byte: u8, epoch: i64) -> LostStagedFile {
    LostStagedFile {
        hash: vec![byte; 32],
        epoch,
        manifest_id: vec![byte.wrapping_add(1); 32],
        stager: StagerIdentity::new("web-a", "inc-a"),
        age: Duration::from_secs(7_200),
        repositories: 1,
        open_ruling: None,
    }
}

#[test]
fn the_token_binds_the_exact_set_and_its_filters() {
    let issued = 1_800_000_000_000;
    let set = vec![file(1, 5), file(2, 6)];
    let token = confirm_token(issued, "cell-a", &filter(), &set);
    assert_eq!(token_issued_ms(&token), Ok(issued));
    assert_eq!(
        check_confirm_token(&token, issued + 1_000, "cell-a", &filter(), &set),
        Ok(())
    );
    // Order does not matter; content does.
    let reversed = vec![file(2, 6), file(1, 5)];
    assert_eq!(
        check_confirm_token(&token, issued, "cell-a", &filter(), &reversed),
        Ok(())
    );
    for (what, changed) in [
        ("a file left", vec![file(1, 5)]),
        ("a file joined", vec![file(1, 5), file(2, 6), file(3, 7)]),
        ("an epoch moved", vec![file(1, 5), file(2, 8)]),
        ("empty", Vec::new()),
    ] {
        assert_eq!(
            check_confirm_token(&token, issued, "cell-a", &filter(), &changed),
            Err(TokenRefusal::SetChanged),
            "{what}"
        );
    }
    let mut manifest = file(2, 6);
    manifest.manifest_id = vec![9; 32];
    assert_eq!(
        check_confirm_token(&token, issued, "cell-a", &filter(), &[file(1, 5), manifest]),
        Err(TokenRefusal::SetChanged),
        "a manifest moved"
    );
    assert_eq!(
        check_confirm_token(&token, issued, "cell-b", &filter(), &set),
        Err(TokenRefusal::SetChanged),
        "another cell"
    );
    let mut narrowed = filter();
    narrowed.stager = Some("web-a".to_owned());
    assert_eq!(
        check_confirm_token(&token, issued, "cell-a", &narrowed, &set),
        Err(TokenRefusal::SetChanged),
        "other filters"
    );
}

#[test]
fn the_token_expires_after_fifteen_minutes_and_refuses_the_future() {
    let issued = 1_800_000_000_000;
    let set = vec![file(1, 5)];
    let token = confirm_token(issued, "cell-a", &filter(), &set);
    let fifteen = 15 * 60 * 1_000;
    assert_eq!(
        check_confirm_token(&token, issued + fifteen, "cell-a", &filter(), &set),
        Ok(())
    );
    assert_eq!(
        check_confirm_token(&token, issued + fifteen + 1, "cell-a", &filter(), &set),
        Err(TokenRefusal::Expired)
    );
    assert_eq!(
        check_confirm_token(&token, issued - 60_001, "cell-a", &filter(), &set),
        Err(TokenRefusal::IssuedInFuture)
    );
}

#[test]
fn a_token_list_did_not_print_is_malformed() {
    for token in [
        "",
        "v1",
        "v1-1",
        "v2-1-00000000000000000000000000000000",
        "v1--1-00000000000000000000000000000000",
        "v1-x-00000000000000000000000000000000",
        "v1-1-0000",
        "v1-1-zz000000000000000000000000000000",
    ] {
        assert_eq!(
            token_issued_ms(token),
            Err(TokenRefusal::Malformed),
            "{token:?}"
        );
    }
}

#[test]
fn a_filter_out_of_bounds_is_refused_not_clamped() {
    let mut young = filter();
    young.min_age = Duration::from_secs(3_599);
    assert!(young.validate().is_err());
    let mut many = filter();
    many.limit = 1_001;
    assert!(many.validate().is_err());
    let mut none = filter();
    none.limit = 0;
    assert!(none.validate().is_err());
    assert!(filter().validate().is_ok());
}

fn record(outcome: Option<&str>, expired_pending: bool) -> LossRulingRecord {
    LossRulingRecord {
        ruling_id: 1,
        hash: vec![1; 32],
        epoch: 1,
        selection: "stager_not_fresh".to_owned(),
        stager: StagerIdentity::new("web-a", "inc-a"),
        actor: "kv".to_owned(),
        reason: "test".to_owned(),
        attested: false,
        multi_repository: false,
        repositories: 1,
        created_ms: 0,
        expires_ms: 1,
        outcome: outcome.map(str::to_owned),
        evidence: None,
        decided_ms: outcome.map(|_| 1),
        drain_replica_id: None,
        expired_pending,
    }
}

#[test]
fn status_names_an_undecided_ruling_past_its_expiry_and_never_calls_it_open() {
    assert_eq!(ruling_state(&record(None, false)), "open");
    assert_eq!(ruling_state(&record(None, true)), "expired (pending drain)");
    assert_eq!(ruling_state(&record(Some("found"), false)), "found");
    assert_eq!(
        TokenRefusal::Replayed.describe(),
        "an earlier apply already used this confirm token; run list again for a new one"
    );
}
