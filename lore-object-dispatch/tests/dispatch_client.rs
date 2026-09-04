// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline pins for the WP-114 CD-3 typed cell-authority client and its dispatch-runtime pool.
//!
//! Every guarantee this slice adds has a pin here, in the default `cargo test -p
//! lore-object-dispatch` tier, in addition to whatever the live tier proves. The live tier needs
//! Docker and PostgreSQL 16; this file needs neither, so a contract drift cannot pass unnoticed on
//! a rig without them. That is the INV-EU P2 follow-up applied ahead of time: CD-4's two P1 fixes
//! were pinned only by the live tier and went unguarded on a default run.
//!
//! The strongest pins here read the frozen migration artifacts and compare them against the
//! client's SQL, because artifact identity does not prove the client agrees with the procedure.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use lore_object_dispatch::DISPATCH_CONNECTION_BUDGET_STATEMENT;
use lore_object_dispatch::DISPATCH_MAINTENANCE_ROLE;
use lore_object_dispatch::DISPATCH_RUNTIME_ROLE;
use lore_object_dispatch::DISPATCHER_IDENTITY_API_REVISION_V1;
use lore_object_dispatch::DISPATCHER_REGISTRATION_API_REVISION_V1;
use lore_object_dispatch::DispatchAuthorityError;
use lore_object_dispatch::DispatchConnectionBudget;
use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchMaintenanceClient;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRecordLimits;
use lore_object_dispatch::DispatchRuntimeClient;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::EnrollParticipantOutcome;
use lore_object_dispatch::EnrollParticipantRequest;
use lore_object_dispatch::PUT_SPOOL_READY_API_REVISION_V1;
use lore_object_dispatch::PUT_UPLOAD_PROGRESS_API_REVISION_V1;
use lore_object_dispatch::PutSpoolReadyOutcome;
use lore_object_dispatch::PutSpoolReadyRequest;
use lore_object_dispatch::PutStreamIdentity;
use lore_object_dispatch::PutUploadProgressOutcome;
use lore_object_dispatch::PutUploadProgressRequest;
use lore_object_dispatch::RESERVE_PUT_API_REVISION_V1;
use lore_object_dispatch::RegisterDispatcherOutcome;
use lore_object_dispatch::RegisterDispatcherRequest;
use lore_object_dispatch::ReservePutOutcome;
use lore_object_dispatch::ReservePutQuotaScope;
use lore_object_dispatch::ReservePutRequest;
use uuid::Uuid;

const CLIENT_SOURCE: &str = include_str!("../src/dispatch_client.rs");
const POOL_SOURCE: &str = include_str!("../src/dispatch_pool.rs");

const RESERVE_PUT_MIGRATION: &str =
    include_str!("../migrations/0013_object_store_dispatch_reserve_put_mutation.sql");
const PROGRESS_MIGRATION: &str =
    include_str!("../migrations/0015_object_store_dispatch_put_upload_progress_mutation.sql");
const SPOOL_READY_MIGRATION: &str =
    include_str!("../migrations/0017_object_store_dispatch_put_spool_ready_mutation.sql");
const IDENTITY_MIGRATION: &str =
    include_str!("../migrations/0019_object_store_dispatch_dispatcher_identity_provisioning.sql");
const REGISTRATION_MIGRATION: &str =
    include_str!("../migrations/0020_object_store_dispatch_dispatcher_registration.sql");
const RETENTION_PROVISIONING_MIGRATION: &str =
    include_str!("../migrations/0003_object_store_retention_provisioning.sql");

/// One procedure the typed client calls, and where its contract is frozen.
struct Procedure {
    /// The bare procedure name inside `object_store_retention`.
    name: &'static str,
    /// The `CREATE TYPE` composite the procedure returns.
    result_type: &'static str,
    /// The migration that froze both.
    migration: &'static str,
    /// The `const` in the client that carries the call.
    statement_const: &'static str,
    /// The role the migration grants `EXECUTE` to.
    role: &'static str,
}

fn procedures() -> Vec<Procedure> {
    vec![
        Procedure {
            name: "object_store_dispatch_reserve_put_v1",
            result_type: "dispatch_reserve_put_result_v1",
            migration: RESERVE_PUT_MIGRATION,
            statement_const: "RESERVE_PUT_SQL",
            role: DISPATCH_RUNTIME_ROLE,
        },
        Procedure {
            name: "object_store_dispatch_put_upload_progress_v1",
            result_type: "dispatch_put_upload_progress_result_v1",
            migration: PROGRESS_MIGRATION,
            statement_const: "PUT_UPLOAD_PROGRESS_SQL",
            role: DISPATCH_RUNTIME_ROLE,
        },
        Procedure {
            name: "object_store_dispatch_put_spool_ready_v1",
            result_type: "dispatch_put_spool_ready_result_v1",
            migration: SPOOL_READY_MIGRATION,
            statement_const: "PUT_SPOOL_READY_SQL",
            role: DISPATCH_RUNTIME_ROLE,
        },
        Procedure {
            name: "object_store_dispatch_enroll_dispatcher_participant_v1",
            result_type: "dispatch_dispatcher_participant_enrollment_result_v1",
            migration: REGISTRATION_MIGRATION,
            statement_const: "ENROLL_PARTICIPANT_SQL",
            role: DISPATCH_MAINTENANCE_ROLE,
        },
        Procedure {
            name: "object_store_dispatch_register_dispatcher_v1",
            result_type: "dispatch_dispatcher_registration_result_v1",
            migration: REGISTRATION_MIGRATION,
            statement_const: "REGISTER_DISPATCHER_SQL",
            role: DISPATCH_RUNTIME_ROLE,
        },
        Procedure {
            name: "object_store_dispatch_dispatcher_identity_read_state_v1",
            result_type: "dispatch_dispatcher_identity_state_v1",
            migration: IDENTITY_MIGRATION,
            statement_const: "DISPATCHER_IDENTITY_READ_STATE_SQL",
            role: DISPATCH_RUNTIME_ROLE,
        },
    ]
}

/// The ordered `(name, type)` parameter list of a `CREATE FUNCTION` header in a migration.
fn migration_parameters(migration: &str, procedure: &str) -> Vec<(String, String)> {
    let marker = format!("FUNCTION object_store_retention.{procedure}(\n");
    let start = migration
        .find(&marker)
        .unwrap_or_else(|| panic!("{procedure}: no CREATE FUNCTION header in its migration"))
        + marker.len();
    let rest = &migration[start..];
    let end = rest
        .find("\n)\nRETURNS")
        .unwrap_or_else(|| panic!("{procedure}: header does not close before RETURNS"));
    parse_declaration_list(&rest[..end])
}

/// The ordered `(name, type)` column list of a `CREATE TYPE ... AS (...)` composite.
fn migration_result_columns(migration: &str, result_type: &str) -> Vec<(String, String)> {
    let marker = format!("CREATE TYPE object_store_retention.{result_type} AS (\n");
    let start = migration
        .find(&marker)
        .unwrap_or_else(|| panic!("{result_type}: no CREATE TYPE in its migration"))
        + marker.len();
    let rest = &migration[start..];
    let end = rest
        .find("\n);")
        .unwrap_or_else(|| panic!("{result_type}: composite does not close"));
    parse_declaration_list(&rest[..end])
}

fn parse_declaration_list(block: &str) -> Vec<(String, String)> {
    block
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("--"))
        .map(|line| {
            let line = line.trim_end_matches(',');
            let (name, kind) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("declaration without a type: {line}"));
            (name.to_string(), kind.trim().to_string())
        })
        .collect()
}

/// The client's SQL for one procedure, read out of the module source by its `const` name.
fn client_statement(statement_const: &str) -> String {
    let marker = format!("const {statement_const}: &str = \"");
    let start = CLIENT_SOURCE
        .find(&marker)
        .unwrap_or_else(|| panic!("{statement_const}: no such statement const in the client"))
        + marker.len();
    let rest = &CLIENT_SOURCE[start..];
    let end = rest
        .find("\";")
        .unwrap_or_else(|| panic!("{statement_const}: statement const is unterminated"));
    rest[..end].to_string()
}

/// The ordered projected columns of the client's `SELECT` list, and whether each is `::text` cast.
fn client_selected_columns(statement: &str) -> Vec<(String, bool)> {
    statement
        .lines()
        .map(str::trim)
        .take_while(|line| !line.starts_with("FROM (SELECT"))
        .filter(|line| line.contains("(r)"))
        .map(|line| {
            let line = line.trim_end_matches(',');
            let cast = line.ends_with("::text");
            let start = line
                .find("(r).")
                .unwrap_or_else(|| panic!("unparsable projection line: {line}"))
                + "(r).".len();
            let name: String = line[start..]
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            assert!(!name.is_empty(), "unparsable projection line: {line}");
            (name, cast)
        })
        .collect()
}

/// Every `$n` placeholder in the client's call, in the order they appear, with their casts.
fn client_call_placeholders(statement: &str) -> Vec<(usize, Option<String>)> {
    let start = statement
        .find("FROM (SELECT")
        .expect("statement has no call body");
    let body = &statement[start..];
    let mut found = Vec::new();
    let bytes = body.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        let number: usize = body[index + 1..cursor]
            .parse()
            .unwrap_or_else(|_| panic!("unparsable placeholder at byte {index}"));
        let tail = &body[cursor..];
        let cast = tail
            .strip_prefix("::text::object_store_retention.uint64")
            .map(|_| "uint64".to_string());
        found.push((number, cast));
        index = cursor;
    }
    found
}

// ------------------------------------------------------------------------------------------
// The client agrees with the frozen procedures
// ------------------------------------------------------------------------------------------

#[test]
fn every_call_binds_the_exact_parameter_count_and_order_the_migration_froze() {
    for procedure in procedures() {
        let declared = migration_parameters(procedure.migration, procedure.name);
        let placeholders = client_call_placeholders(&client_statement(procedure.statement_const));
        assert_eq!(
            placeholders.len(),
            declared.len(),
            "{}: client binds {} parameters, the migration declares {}",
            procedure.name,
            placeholders.len(),
            declared.len()
        );
        for (position, (number, _)) in placeholders.iter().enumerate() {
            assert_eq!(
                *number,
                position + 1,
                "{}: placeholders are not $1..$n in order",
                procedure.name
            );
        }
    }
}

#[test]
fn exactly_the_uint64_parameters_are_transferred_through_the_text_domain_cast() {
    // A signature reordering that keeps the parameter count would move a uint64 position. This is
    // the check that catches it without a database: the client's cast positions must be exactly
    // the migration's `object_store_retention.uint64` positions.
    for procedure in procedures() {
        let declared = migration_parameters(procedure.migration, procedure.name);
        let placeholders = client_call_placeholders(&client_statement(procedure.statement_const));
        for ((name, kind), (number, cast)) in declared.iter().zip(placeholders.iter()) {
            let declared_uint64 = kind == "object_store_retention.uint64";
            let cast_uint64 = cast.is_some();
            assert_eq!(
                declared_uint64, cast_uint64,
                "{}: parameter ${number} ({name}: {kind}) cast disagrees with the migration",
                procedure.name
            );
        }
        assert!(
            declared
                .iter()
                .any(|(_, kind)| kind == "object_store_retention.uint64")
                || procedure.name.contains("enroll")
                || procedure.name.contains("read_state"),
            "{}: expected at least one uint64 parameter to pin",
            procedure.name
        );
    }
}

/// The trailing path segment of each value the client binds, in bind order.
///
/// `&self.api` reads as `api`; `&self.request.identity.upload_fence` reads as `upload_fence`. The
/// one loop-driven run (0013's eighteen quota bounds) reads as a single `<quota-run>` marker.
fn client_bind_order(prepared_type: &str) -> Vec<String> {
    let impl_start = CLIENT_SOURCE
        .find(&format!("impl PreparedMutation for {prepared_type}"))
        .unwrap_or_else(|| panic!("{prepared_type}: no PreparedMutation impl"));
    let bind_start = CLIENT_SOURCE[impl_start..]
        .find("fn bind(&self)")
        .map(|offset| impl_start + offset)
        .unwrap_or_else(|| panic!("{prepared_type}: no bind()"));
    let body_end = CLIENT_SOURCE[bind_start..]
        .find("\n    fn decode(")
        .map(|offset| bind_start + offset)
        .unwrap_or_else(|| panic!("{prepared_type}: bind() is unterminated"));
    let mut names = Vec::new();
    for line in CLIENT_SOURCE[bind_start..body_end].lines().map(str::trim) {
        if line.starts_with("for value in &self.quotas") {
            names.push("<quota-run>".to_string());
            continue;
        }
        let expression = line
            .trim_end_matches(',')
            .trim_end_matches(");")
            .trim_end_matches(',');
        let expression = expression
            .strip_prefix("params.push(")
            .unwrap_or(expression)
            .trim_end_matches(')');
        let Some(path) = expression.strip_prefix("&self.") else {
            continue;
        };
        let Some(last) = path.rsplit('.').next() else {
            continue;
        };
        if last.is_empty() || last.contains(' ') {
            continue;
        }
        names.push(last.to_string());
    }
    names
}

#[test]
fn every_bound_value_sits_at_the_position_the_migration_declares_for_its_name() {
    // The SQL-text pins above prove the client's *statement* matches the migration. This one
    // proves the Rust `bind()` vector agrees with that statement: swapping two same-typed values
    // in `bind()` leaves the SQL untouched and the cast positions intact, and was previously
    // caught only by the live tier.
    //
    // The eighteen 0013 quota bounds are pushed by a loop, so they are checked as a run: the
    // migration's parameters at those positions must be exactly the three scopes' six bounds, in
    // scope-then-bound order, which is the order `PreparedReservePut::new` fills the array in.
    const QUOTA_RUN: [&str; 18] = [
        "global_max_bytes",
        "global_max_rows",
        "global_max_concurrency",
        "global_low_water_bytes",
        "global_low_water_rows",
        "global_low_water_concurrency",
        "cell_max_bytes",
        "cell_max_rows",
        "cell_max_concurrency",
        "cell_low_water_bytes",
        "cell_low_water_rows",
        "cell_low_water_concurrency",
        "tenant_max_bytes",
        "tenant_max_rows",
        "tenant_max_concurrency",
        "tenant_low_water_bytes",
        "tenant_low_water_rows",
        "tenant_low_water_concurrency",
    ];
    // The quota array's initializers must name the scope and bound each position stands for. Bind
    // order alone cannot see a scope swap inside the array, because every slot has the same type.
    let array = section(
        CLIENT_SOURCE,
        "let quotas: [String; 18] = [",
        "\n        ];",
    );
    let initializers: Vec<String> = array
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("request.")?
                .strip_suffix(".to_string(),")
                .map(str::to_string)
        })
        .collect();
    let expected: Vec<String> = QUOTA_RUN
        .iter()
        .map(|name| {
            let (scope, bound) = name
                .split_once('_')
                .unwrap_or_else(|| panic!("unparsable quota parameter {name}"));
            format!("{scope}_quota.{bound}")
        })
        .collect();
    assert_eq!(
        initializers, expected,
        "the quota array is filled from the wrong scope for at least one position"
    );

    for (prepared_type, procedure_name, migration) in [
        (
            "PreparedReservePut<'_>",
            "object_store_dispatch_reserve_put_v1",
            RESERVE_PUT_MIGRATION,
        ),
        (
            "PreparedPutUploadProgress<'_>",
            "object_store_dispatch_put_upload_progress_v1",
            PROGRESS_MIGRATION,
        ),
        (
            "PreparedPutSpoolReady<'_>",
            "object_store_dispatch_put_spool_ready_v1",
            SPOOL_READY_MIGRATION,
        ),
        (
            "PreparedEnrollParticipant<'_>",
            "object_store_dispatch_enroll_dispatcher_participant_v1",
            REGISTRATION_MIGRATION,
        ),
        (
            "PreparedRegisterDispatcher<'_>",
            "object_store_dispatch_register_dispatcher_v1",
            REGISTRATION_MIGRATION,
        ),
    ] {
        let declared: Vec<String> = migration_parameters(migration, procedure_name)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        let mut bound = Vec::new();
        for name in client_bind_order(prepared_type) {
            if name == "<quota-run>" {
                bound.extend(QUOTA_RUN.iter().map(|value| (*value).to_string()));
            } else if name == "api" {
                // The one alias: the client's field is `api`, the parameter is `api_revision`.
                bound.push("api_revision".to_string());
            } else {
                bound.push(name);
            }
        }
        assert_eq!(
            bound, declared,
            "{procedure_name}: bind() order does not match the migration's parameter order"
        );
    }
}

#[test]
fn every_projection_selects_the_result_columns_in_the_frozen_composite_order() {
    for procedure in procedures() {
        let declared = migration_result_columns(procedure.migration, procedure.result_type);
        let selected = client_selected_columns(&client_statement(procedure.statement_const));
        assert_eq!(
            selected.len(),
            declared.len(),
            "{}: client selects {} columns, the composite declares {}",
            procedure.name,
            selected.len(),
            declared.len()
        );
        for ((declared_name, declared_kind), (selected_name, cast)) in
            declared.iter().zip(selected.iter())
        {
            assert_eq!(
                declared_name, selected_name,
                "{}: projection order does not match the composite",
                procedure.name
            );
            assert_eq!(
                declared_kind == "object_store_retention.uint64",
                *cast,
                "{}: column {declared_name} cast disagrees with the composite",
                procedure.name
            );
        }
    }
}

#[test]
fn every_call_is_granted_to_the_role_its_pool_connects_as() {
    // The runtime pool must never carry the maintenance-only enrollment, and the maintenance pool
    // must never carry a runtime mutation. The migration's own GRANT is the authority for which.
    // 0019 grants its readback to all three roles and 0020 later revokes two of them, so the
    // effective grant is whatever survives the whole install set in order, not the first one seen.
    for procedure in procedures() {
        let qualified = format!("object_store_retention.{}(", procedure.name);
        let mut effective: Vec<String> = Vec::new();
        let mut grants_seen = 0usize;
        for migration in install_set_migrations() {
            for statement in grant_statements(migration) {
                // A blanket schema-wide revoke clears the roles it names; 0011 issues one, which is
                // why 0019 deliberately does not.
                let blanket = statement.contains("ON ALL FUNCTIONS IN SCHEMA");
                if !blanket && !statement.contains(&qualified) {
                    continue;
                }
                let is_grant = statement.starts_with("GRANT ");
                let separator = if is_grant { ") TO " } else { " FROM " };
                let Some((_, roles)) = statement.rsplit_once(separator) else {
                    continue;
                };
                let roles: Vec<String> = roles
                    .split(',')
                    .map(|role| role.trim().to_string())
                    .filter(|role| role.starts_with("object_dispatch_"))
                    .collect();
                if is_grant {
                    if blanket {
                        continue;
                    }
                    grants_seen += 1;
                    for role in roles {
                        if !effective.contains(&role) {
                            effective.push(role);
                        }
                    }
                } else {
                    effective.retain(|role| !roles.contains(role));
                }
            }
        }
        assert!(
            grants_seen > 0,
            "{}: no EXECUTE grant found in the install set",
            procedure.name
        );
        assert_eq!(
            effective,
            vec![procedure.role.to_string()],
            "{}: effective EXECUTE roles and the client's pool identity disagree",
            procedure.name
        );
    }
}

#[test]
fn every_api_revision_constant_is_the_one_its_migration_asserts() {
    for (constant, migration) in [
        (RESERVE_PUT_API_REVISION_V1, RESERVE_PUT_MIGRATION),
        (PUT_UPLOAD_PROGRESS_API_REVISION_V1, PROGRESS_MIGRATION),
        (PUT_SPOOL_READY_API_REVISION_V1, SPOOL_READY_MIGRATION),
        (
            DISPATCHER_REGISTRATION_API_REVISION_V1,
            REGISTRATION_MIGRATION,
        ),
        (DISPATCHER_IDENTITY_API_REVISION_V1, IDENTITY_MIGRATION),
    ] {
        // 0019 wraps its literal onto a second line, so compare on collapsed whitespace.
        let collapsed = migration.split_whitespace().collect::<Vec<_>>().join(" ");
        let assertion = format!("api_revision IS DISTINCT FROM '{constant}'");
        assert!(
            collapsed.contains(&assertion),
            "no migration asserts the API revision {constant}"
        );
    }
}

// ------------------------------------------------------------------------------------------
// Closed decoding
// ------------------------------------------------------------------------------------------

#[test]
fn the_closed_result_code_sets_are_exactly_what_the_migrations_project() {
    // Four of the five mutations validate their own projection against an accepted set before
    // returning it. Pin that set literally: a procedure that grew a third code would make the
    // client's closed decoding refuse a legitimate result, and this is where that surfaces.
    for (migration, guard) in [
        (
            RESERVE_PUT_MIGRATION,
            "result_code NOT IN ('CREATED', 'REPLAY')",
        ),
        (
            PROGRESS_MIGRATION,
            "result_code NOT IN ('APPLIED', 'REPLAY')",
        ),
        (
            SPOOL_READY_MIGRATION,
            "result_code NOT IN ('APPLIED', 'REPLAY')",
        ),
        (
            REGISTRATION_MIGRATION,
            "result_code NOT IN ('CREATED', 'REPLAY')",
        ),
    ] {
        assert!(
            migration.contains(guard),
            "a projection's accepted result-code set drifted from `{guard}`"
        );
    }
    // 0020's enrollment returns its two codes inline rather than through a projection guard.
    let enrollment = section(
        REGISTRATION_MIGRATION,
        "CREATE FUNCTION object_store_retention.object_store_dispatch_enroll_dispatcher_participant_v1(",
        "\n$$;",
    );
    // Derived from the artifact, not from a hand-listed candidate set: every single-quoted
    // SCREAMING_CASE literal in the first position of a returned ROW is a result code.
    let enrollment_codes: Vec<String> = enrollment
        .match_indices("RETURN ROW(")
        .filter_map(|(index, _)| {
            let tail = &enrollment[index + "RETURN ROW(".len()..];
            let start = tail.find(char::is_alphanumeric)?;
            let quoted = tail[..start].contains('\'');
            let end = tail[start..].find(|c: char| !c.is_ascii_uppercase() && c != '_')?;
            let literal = tail[start..start + end].to_string();
            (quoted && !literal.is_empty()).then_some(literal)
        })
        .collect();
    assert_eq!(
        enrollment_codes,
        vec!["CREATED".to_string(), "REPLAY".to_string()],
        "enrollment's returned result codes drifted from the client's closed set"
    );
    // The readback returns exactly one code, and the client accepts only that one.
    assert!(IDENTITY_MIGRATION.contains("project_dispatch_dispatcher_identity_state_v1('READ')"));
    assert!(CLIENT_SOURCE.contains("const READ_ONLY_RESULT_CODE: &str = \"READ\";"));

    // The client's two closed sets are exactly those pairs, and anything else is a refusal.
    assert!(
        CLIENT_SOURCE.contains("const CREATED_OR_REPLAY: [&str; 2] = [\"CREATED\", \"REPLAY\"];")
    );
    assert!(
        CLIENT_SOURCE.contains("const APPLIED_OR_REPLAY: [&str; 2] = [\"APPLIED\", \"REPLAY\"];")
    );
    let decoder = section(CLIENT_SOURCE, "fn disposition_of(", "fn text(");
    assert!(
        decoder.contains("Err(DispatchAuthorityError::UnrecognizedResultCode)"),
        "an unrecognized result code must be a refusal, never a default"
    );
}

/// Every `GRANT`/`REVOKE` statement in one migration, in order, with whitespace collapsed so the
/// one-line and wrapped spellings of the same statement parse identically.
fn grant_statements(migration: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let padded = format!("\n{migration}");
    let mut cursor = 0usize;
    while cursor < padded.len() {
        let grant = padded[cursor..]
            .find("\nGRANT ")
            .map(|o| (cursor + o, 1usize));
        let revoke = padded[cursor..]
            .find("\nREVOKE ")
            .map(|o| (cursor + o, 1usize));
        let next = match (grant, revoke) {
            (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
            (Some(left), None) => Some(left),
            (None, Some(right)) => Some(right),
            (None, None) => None,
        };
        let Some((start, skip)) = next else {
            break;
        };
        let body_start = start + skip;
        let end = padded[body_start..]
            .find(';')
            .map_or(padded.len(), |offset| body_start + offset);
        statements.push(
            padded[body_start..end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        );
        cursor = end;
    }
    statements
}

/// Every function body in the cell install set, latest definition winning.
fn function_bodies() -> Vec<(String, String)> {
    let mut bodies: Vec<(String, String)> = Vec::new();
    for migration in install_set_migrations() {
        let mut cursor = 0usize;
        while let Some(offset) = migration[cursor..].find("FUNCTION object_store_retention.") {
            let start = cursor + offset + "FUNCTION object_store_retention.".len();
            cursor = start;
            let name: String = migration[start..]
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            let tail = &migration[start..];
            let Some(body_start) = tail.find("\nAS $$") else {
                continue;
            };
            // A GRANT or REVOKE naming this function has no body before the next definition.
            if tail[..body_start].contains("CREATE ") && !tail[..body_start].contains("RETURNS") {
                continue;
            }
            let Some(body_end) = tail[body_start..].find("\n$$;") else {
                continue;
            };
            let body = tail[body_start..body_start + body_end].to_string();
            if let Some(existing) = bodies.iter_mut().find(|(existing, _)| existing == &name) {
                existing.1 = body;
            } else {
                bodies.push((name, body));
            }
        }
    }
    bodies
}

fn install_set_migrations() -> Vec<&'static str> {
    vec![
        include_str!("../migrations/0002_object_store_retention_authority.sql"),
        RETENTION_PROVISIONING_MIGRATION,
        include_str!("../migrations/0007_object_store_dispatch_authority_core.sql"),
        include_str!("../migrations/0008_object_store_dispatch_authority_provisioning.sql"),
        include_str!("../migrations/0009_object_store_dispatch_authority_canonical_codec.sql"),
        include_str!("../migrations/0010_object_store_dispatch_put_reservation_schema.sql"),
        include_str!("../migrations/0011_object_store_dispatch_put_reservation_provisioning.sql"),
        include_str!("../migrations/0012_object_store_dispatch_put_reservation_record_codec.sql"),
        RESERVE_PUT_MIGRATION,
        include_str!("../migrations/0014_object_store_dispatch_put_upload_progress_codec.sql"),
        PROGRESS_MIGRATION,
        include_str!("../migrations/0016_object_store_dispatch_put_spool_ready_codec.sql"),
        SPOOL_READY_MIGRATION,
        include_str!("../migrations/0018_object_store_dispatch_dispatcher_identity_schema.sql"),
        IDENTITY_MIGRATION,
        REGISTRATION_MIGRATION,
    ]
}

#[test]
fn every_condition_reachable_from_a_called_procedure_has_a_named_refusal() {
    // Walk the call graph from the six procedures the client calls, following every
    // `object_store_retention.<fn>(` reference, and collect the conditions those bodies raise.
    // Sweeping whole migration files instead would drag in migrator-only install paths the client
    // can never reach; this set is exactly what a runtime or maintenance caller can be told.
    //
    // The two 40001 CONFLICT conditions are deliberately absent from the client's condition table:
    // the procedures raise them *as* serialization failures, so the retry classification claims
    // them first. Every other reachable condition must map, or a real refusal would arrive as the
    // generic AuthorityUnavailable.
    const RETRY_CLASSIFIED: [&str; 2] = [
        "DISPATCH_PUT_UPLOAD_PROGRESS_CONFLICT",
        "DISPATCH_PUT_SPOOL_READY_CONFLICT",
    ];
    let bodies = function_bodies();
    let mut reachable: Vec<String> = procedures()
        .iter()
        .map(|procedure| procedure.name.to_string())
        .collect();
    let mut cursor = 0usize;
    while cursor < reachable.len() {
        let current = reachable[cursor].clone();
        cursor += 1;
        let Some((_, body)) = bodies.iter().find(|(name, _)| name == &current) else {
            continue;
        };
        for (index, _) in body.match_indices("object_store_retention.") {
            let callee: String = body[index + "object_store_retention.".len()..]
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect();
            if bodies.iter().any(|(name, _)| name == &callee) && !reachable.contains(&callee) {
                reachable.push(callee);
            }
        }
    }
    assert!(
        reachable.len() > 10,
        "call-graph walk found only {} functions",
        reachable.len()
    );

    let mut conditions: Vec<String> = Vec::new();
    for name in &reachable {
        let Some((_, body)) = bodies.iter().find(|(existing, _)| existing == name) else {
            continue;
        };
        for (index, _) in body.match_indices("RAISE EXCEPTION '") {
            let tail = &body[index + "RAISE EXCEPTION '".len()..];
            let Some(end) = tail.find('\'') else { continue };
            let condition = tail[..end].to_string();
            // Digits are part of a condition name (LOCAL_CANONICAL_U32_INVALID, INVALID_UUIDV7).
            // An earlier charset here excluded them, and six reachable conditions escaped both
            // this sweep and the client table because of it.
            if !condition.is_empty()
                && condition.chars().all(|character| {
                    character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
                })
                && !conditions.contains(&condition)
            {
                conditions.push(condition);
            }
        }
    }
    // A floor near the real count, so a parse that silently stops matching fails here rather than
    // passing vacuously. The walk finds 69 with digits counted; an earlier charset that dropped
    // digit-bearing names found 63 and still cleared a floor of 25.
    assert!(
        conditions.len() >= 65,
        "expected the reachable condition set, found {}: {conditions:?}",
        conditions.len()
    );

    let table = section(
        CLIENT_SOURCE,
        "fn refusal_for_condition(",
        "/// The fallback for a SQLSTATE",
    );
    let mut unmapped: Vec<&String> = Vec::new();
    for condition in &conditions {
        let quoted = format!("\"{condition}\"");
        if RETRY_CLASSIFIED.contains(&condition.as_str()) {
            assert!(
                !table.contains(&quoted),
                "{condition} is raised as 40001 and must be left to the retry classification"
            );
            continue;
        }
        if !table.contains(&quoted) {
            unmapped.push(condition);
        }
    }
    assert!(
        unmapped.is_empty(),
        "conditions reachable from a called procedure with no named refusal: {unmapped:?}"
    );
}

#[test]
fn the_serializable_requirement_is_asserted_and_the_client_opens_serializable_mutations() {
    assert!(
        RETENTION_PROVISIONING_MIGRATION
            .contains("RAISE EXCEPTION 'SERIALIZABLE_READ_WRITE_TRANSACTION_REQUIRED'")
    );
    for migration in [
        RESERVE_PUT_MIGRATION,
        PROGRESS_MIGRATION,
        SPOOL_READY_MIGRATION,
        REGISTRATION_MIGRATION,
    ] {
        assert!(
            migration.contains("assert_serializable_write_v1()"),
            "a called mutation does not assert serializable write"
        );
    }
    assert!(
        CLIENT_SOURCE.contains(".isolation_level(tokio_postgres::IsolationLevel::Serializable)"),
        "mutations must open serializable transactions"
    );
    assert!(
        CLIENT_SOURCE.contains(".read_only(false)"),
        "mutations must open read-write transactions"
    );
}

// ------------------------------------------------------------------------------------------
// The bounded-execution envelope
// ------------------------------------------------------------------------------------------

#[test]
fn every_transaction_sets_both_local_timeouts() {
    assert!(POOL_SOURCE.contains("SET LOCAL statement_timeout = '{}ms'; SET LOCAL lock_timeout"));
    // Both the mutation path and the read path apply the preamble, and neither opens a
    // transaction without it.
    let preamble_uses = CLIENT_SOURCE
        .matches("bounded_execution_preamble()")
        .count();
    assert_eq!(
        preamble_uses, 2,
        "expected exactly the mutation and read paths to apply the envelope preamble"
    );
    let mutation = section(
        CLIENT_SOURCE,
        "async fn mutate_on_lease",
        "/// One read-only transaction",
    );
    assert!(mutation.contains("batch_execute(&preamble)"));
    let read = section(CLIENT_SOURCE, "async fn read_on_lease", "// ------");
    assert!(read.contains("batch_execute(preamble)"));
}

#[test]
fn the_read_path_is_read_only_and_carries_no_retry() {
    let read = section(CLIENT_SOURCE, "async fn read_on_lease", "// ------");
    assert!(read.contains(".read_only(true)"));
    assert!(
        !read.contains("MUTATION_RETRY_SCHEDULE") && !read.contains("sleep"),
        "a read-only transaction must never be retried"
    );
    let read_entry = section(
        CLIENT_SOURCE,
        "pub async fn read_dispatcher_identity_state",
        "/// The maintenance-identity client",
    );
    assert!(
        !read_entry.contains("for "),
        "the read entry point must not loop"
    );
    assert!(read_entry.contains("read_once("));
}

#[test]
fn the_mutation_loop_releases_the_session_before_it_sleeps() {
    // CR-033 D1 requires the pooled session to be back before the backoff. `mutate_once` owns the
    // lease for exactly one attempt and always releases or poisons it before returning, so the
    // sleep in `run_mutation` provably holds nothing.
    let attempt = section(
        CLIENT_SOURCE,
        "async fn mutate_once",
        "async fn mutate_on_lease",
    );
    assert!(attempt.contains("lease.poison();"));
    assert!(attempt.contains("lease.release().await;"));
    let loop_body = section(
        CLIENT_SOURCE,
        "async fn run_mutation",
        "/// One serializable attempt",
    );
    assert!(loop_body.contains("tokio::time::sleep(delay).await"));
    assert!(
        !loop_body.contains("acquire()"),
        "the retry loop must not hold a lease across a sleep"
    );
}

#[test]
fn only_a_commit_with_no_sqlstate_is_ambiguous_and_it_is_resolved_not_reported() {
    let commit = section(CLIENT_SOURCE, "fn classify_commit<T>", "fn refusal_of(");
    assert!(commit.contains("if error.code().is_none()"));
    assert!(commit.contains("AttemptOutcome::AmbiguousCommit"));
    assert!(
        commit.contains("classify_precommit(error)"),
        "a SQLSTATE at COMMIT is a proved abort and must not be folded into the ambiguous arm"
    );
    let loop_body = section(
        CLIENT_SOURCE,
        "async fn run_mutation",
        "/// One serializable attempt",
    );
    assert!(
        loop_body.contains("ambiguity_seen = true;"),
        "an ambiguous commit must be resolved by the next attempt, not returned"
    );
}

/// The `pub` field names of a struct declared in the client, in declaration order.
fn struct_fields(type_name: &str) -> Vec<String> {
    let body = section(
        CLIENT_SOURCE,
        &format!("pub struct {type_name} {{"),
        "\n}\n",
    );
    body.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("pub "))
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.trim().to_string())
        .collect()
}
/// How one decoder must account for every field its outcome type returns.
///
/// The three classes are exhaustive by assertion, so a field added to an outcome cannot land
/// unclassified: it is either name-matched against something the call submitted, bound under a
/// different name (recorded in `renamed`), or produced by the authority (recorded in `minted`).
struct BindingContract {
    request_type: &'static str,
    outcome_type: &'static str,
    /// `(outcome field, request field, comparison operator)` for bindings whose two sides are
    /// spelled differently. Name intersection cannot see these, and all four were deletable on a
    /// full green run before this map existed - including the durable-body binding whose own
    /// comment says a later reader trusts it.
    renamed: &'static [(&'static str, &'static str, &'static str)],
    /// Fields the authority produces. The call supplies nothing to compare them to, so they are
    /// legitimately unbound - but they are listed, not inferred, so suppressing a real binding
    /// means editing this list where a reader can see it.
    ///
    /// **The anti-suppression assert below covers the name-matched half only.** `required` is the
    /// name intersection, so a *renamed* field is never in it: moving an entry out of `renamed`
    /// into `minted` and deleting its source binding leaves the suite green. No text-level
    /// assertion can close that, because once the binding is deleted there is no string left for a
    /// test to look for. Machine-checked: a field the call submits under its own name cannot be
    /// listed here. Review-checked: a field listed here that is really bound under another name.
    /// Moving anything into this list is a claim that the authority alone produces it, and that
    /// claim is only ever as good as the diff it lands in.
    minted: &'static [&'static str],
}

const BINDING_CONTRACTS: [BindingContract; 5] = [
    BindingContract {
        request_type: "ReservePutRequest",
        outcome_type: "ReservePutOutcome",
        renamed: &[],
        minted: &[
            "admission_clock_unix_ms",
            "expires_at_unix_ms",
            "reserve_put_ack_canonical_bytes",
            "reserve_put_ack_blake3",
        ],
    },
    BindingContract {
        request_type: "PutUploadProgressRequest",
        outcome_type: "PutUploadProgressOutcome",
        // An inequality, not an equality: the authority may have committed a longer prefix than
        // this call supplied, but never a shorter one.
        renamed: &[("committed_prefix_bytes", "fsynced_prefix_bytes", ">=")],
        minted: &[
            "spool_object_id",
            "committed_prefix_chunks",
            "spool_revision",
            "record_blake3",
        ],
    },
    BindingContract {
        request_type: "PutSpoolReadyRequest",
        outcome_type: "PutSpoolReadyOutcome",
        renamed: &[
            ("committed_size", "fsynced_body_size", "=="),
            ("committed_blake3", "fsynced_body_blake3", "=="),
        ],
        minted: &[
            "spool_object_id",
            "ready_at_unix_ms",
            "reserve_put_ack_canonical_bytes",
            "reserve_put_ack_blake3",
            "spool_revision",
            "record_blake3",
        ],
    },
    BindingContract {
        request_type: "EnrollParticipantRequest",
        outcome_type: "EnrollParticipantOutcome",
        renamed: &[],
        minted: &[],
    },
    BindingContract {
        request_type: "RegisterDispatcherRequest",
        outcome_type: "RegisterDispatcherOutcome",
        renamed: &[("lease_generation", "next_generation", "==")],
        // 0020 mints both identity columns from the enrolled participant row.
        minted: &[
            "dispatcher_id",
            "provider_boundary_id",
            "state",
            "record_blake3",
        ],
    },
];

#[test]
fn every_decoder_accounts_for_every_field_its_projection_returns() {
    // A replay returns the authority's stored projection. If a decoder accepts one without
    // checking it names what this call submitted, an ambiguity resolution can adopt another
    // writer's record as its own result.
    //
    // Two earlier versions of this test were too weak. The first asserted only that each decode
    // body contained `require(` and `self.request`. The second derived the required set by
    // intersecting field *names*, which left every binding whose two sides are spelled differently
    // outside it - four of them, all deletable on a full green run. This version keeps the
    // derivation, adds the renamed bindings explicitly, and asserts the three classes cover the
    // outcome type exactly, so the residual is additive and visible rather than silent.
    const SIGNATURE: &str = "fn decode(&self, row: &Row) -> Result<DispatchAccepted<Self::Outcome>, DispatchAuthorityError> {";
    let decoders: Vec<&str> = CLIENT_SOURCE
        .match_indices(SIGNATURE)
        .map(|(index, _)| {
            let tail = &CLIENT_SOURCE[index..];
            let end = tail
                .find("\n    }\n")
                .unwrap_or_else(|| panic!("a decode body is unterminated"));
            &tail[..end]
        })
        .collect();
    assert_eq!(
        decoders.len(),
        BINDING_CONTRACTS.len(),
        "expected one decoder per binding contract"
    );

    let identity_fields = struct_fields("PutStreamIdentity");
    assert!(
        identity_fields.contains(&"attempt_id".to_string()),
        "PutStreamIdentity parse found no attempt_id: {identity_fields:?}"
    );

    for (decoder, contract) in decoders.iter().zip(BINDING_CONTRACTS.iter()) {
        // The pairing above is positional. Each decoder names the type it builds, so check it
        // rather than trusting source order: reordering the table would otherwise surface as
        // "fields returned but neither bound..." and send a reader looking at the wrong thing.
        assert!(
            decoder.contains(&format!("let value = {} {{", contract.outcome_type)),
            "binding contract order does not match decoder order: expected the decoder that \
             builds {}, but this one builds something else",
            contract.outcome_type
        );

        let request_fields = struct_fields(contract.request_type);
        let outcome_fields = struct_fields(contract.outcome_type);
        assert!(
            !outcome_fields.is_empty(),
            "{}: parsed no outcome fields",
            contract.outcome_type
        );

        // Only a request that actually embeds a `PutStreamIdentity` contributes its fields.
        // Applying them to every pair is what previously let `RegisterDispatcherOutcome` look
        // correct: `provider_boundary_id` entered the submitted set through an identity the
        // request does not have, and the `minted` entry then suppressed it again. Two errors
        // cancelling. Derived here so the first one cannot come back.
        let embeds_identity = request_fields.iter().any(|field| field == "identity");
        let mut submitted = request_fields.clone();
        if embeds_identity {
            submitted.extend(identity_fields.iter().cloned());
        }

        let required: Vec<String> = outcome_fields
            .iter()
            .filter(|field| submitted.contains(field))
            .cloned()
            .collect();
        let renamed_fields: Vec<String> = contract
            .renamed
            .iter()
            .map(|(outcome_field, _, _)| (*outcome_field).to_string())
            .collect();
        let minted_fields: Vec<String> = contract.minted.iter().map(|f| (*f).to_string()).collect();

        // A field the call *does* supply must never be listed as minted. This is the assertion
        // that catches the cancelling pair above: give `RegisterDispatcherRequest` a real
        // `provider_boundary_id` and the standing `minted` entry stops being harmless.
        for field in &minted_fields {
            assert!(
                !required.contains(field),
                "{}: `{field}` is listed as minted but the call submits it, so its binding is \
                 being suppressed rather than being genuinely unavailable",
                contract.outcome_type
            );
            assert!(
                outcome_fields.contains(field),
                "{}: `{field}` is listed as minted but the outcome does not return it",
                contract.outcome_type
            );
        }
        for (outcome_field, request_field, _) in contract.renamed {
            assert!(
                outcome_fields.contains(&(*outcome_field).to_string()),
                "{}: renamed entry `{outcome_field}` is not a field of the outcome",
                contract.outcome_type
            );
            assert!(
                request_fields.contains(&(*request_field).to_string()),
                "{}: renamed entry points at `{request_field}`, which the request does not carry",
                contract.request_type
            );
            assert!(
                !required.contains(&(*outcome_field).to_string()),
                "{}: `{outcome_field}` is name-matched already and needs no renamed entry",
                contract.outcome_type
            );
        }

        // Exhaustiveness: every field the projection returns is accounted for by one of the three
        // classes, so a new outcome field cannot land unclassified.
        let mut accounted: Vec<String> = required.clone();
        accounted.extend(renamed_fields.iter().cloned());
        accounted.extend(minted_fields.iter().cloned());
        let unaccounted: Vec<&String> = outcome_fields
            .iter()
            .filter(|field| !accounted.contains(field))
            .collect();
        assert!(
            unaccounted.is_empty(),
            "{}: fields returned but neither bound, renamed, nor recorded as minted: \
             {unaccounted:?}",
            contract.outcome_type
        );
        assert!(
            !required.is_empty() || !renamed_fields.is_empty(),
            "{}: nothing is bound at all",
            contract.outcome_type
        );

        // The bindings themselves.
        for field in &required {
            let direct = format!("value.{field} == self.request.{field}");
            let through_identity = format!("value.{field} == self.request.identity.{field}");
            assert!(
                decoder.contains(&direct) || decoder.contains(&through_identity),
                "{}: `{field}` is returned and was submitted, but the decoder does not bind it",
                contract.outcome_type
            );
        }
        for (outcome_field, request_field, operator) in contract.renamed {
            let comparison =
                format!("value.{outcome_field} {operator} self.request.{request_field}");
            assert!(
                decoder.contains(&comparison),
                "{}: the decoder does not carry `{comparison}`",
                contract.outcome_type
            );
        }
    }
}

#[test]
fn the_retryable_classification_names_exactly_two_sqlstates() {
    // CR-033 D1: retry only 40001 and 40P01. A third retryable class would silently repeat a
    // mutation the database never said was safe to repeat.
    let classify = section(
        CLIENT_SOURCE,
        "fn classify(error: &tokio_postgres::Error)",
        "/// The closed set of conditions",
    );
    let retryable = section(classify, "if code ==", "return Classification::Retryable;");
    assert!(retryable.contains("SqlState::T_R_SERIALIZATION_FAILURE"));
    assert!(retryable.contains("SqlState::T_R_DEADLOCK_DETECTED"));
    assert_eq!(
        retryable.matches("SqlState::").count(),
        2,
        "the retryable branch names a SQLSTATE beyond 40001 and 40P01: {retryable}"
    );
    assert_eq!(
        classify.matches("Classification::Retryable").count(),
        1,
        "there is more than one path into the retryable classification"
    );
}

#[test]
fn a_wall_clock_timeout_before_commit_is_sent_is_a_refusal_not_an_ambiguity() {
    // The envelope's wall-clock bound can fire at any point in the transaction. Only a firing with
    // COMMIT already on the wire is ambiguous; before that the client can prove it never asked the
    // database to commit, so that case keeps its own arm. Folding both into ambiguity would report
    // an unresolvable outcome for a provable one.
    let attempt = section(
        CLIENT_SOURCE,
        "async fn mutate_once",
        "async fn mutate_on_lease",
    );
    assert!(attempt.contains("commit_sent.load(Ordering::SeqCst)"));
    assert!(attempt.contains("AttemptOutcome::Refused(DispatchAuthorityError::OperationTimeout)"));
    assert!(
        attempt.contains("AttemptOutcome::AmbiguousCommit"),
        "the with-COMMIT-in-flight case must still be ambiguous"
    );
    // Either way the abandoned session is closed rather than returned to the pool.
    assert_eq!(attempt.matches("lease.poison();").count(), 2);

    // The flag is written in exactly one place, and that place is immediately before COMMIT.
    assert_eq!(CLIENT_SOURCE.matches("commit_sent.store(").count(), 1);
    let body = section(
        CLIENT_SOURCE,
        "async fn mutate_on_lease",
        "/// One read-only transaction",
    );
    let store = body
        .find("commit_sent.store(true, Ordering::SeqCst);")
        .expect("the commit-sent flag is never set");
    let commit = body
        .find("transaction.commit().await")
        .expect("mutate_on_lease never commits");
    assert!(
        store < commit,
        "the commit-sent flag must be set before COMMIT is written to the wire"
    );
}

#[test]
fn the_retry_budget_is_three_attempts_in_total_including_any_ambiguity_resolution() {
    // CR-033 D1's envelope says mutations run at exactly three attempts. The resolution step it
    // also requires - reconnect plus the operation-specific authoritative read - is the next
    // attempt in this same loop, not a second budget. Giving resolution its own three attempts
    // would let one logical mutation reach six and silently double the wall clock a caller sizes
    // a deadline from, which is an amendment to a frozen contract, not a fix.
    let loop_body = section(
        CLIENT_SOURCE,
        "async fn run_mutation",
        "/// One serializable attempt",
    );
    assert_eq!(
        loop_body.matches("mutate_once(pool, prepared)").count(),
        1,
        "there is more than one place attempts are issued from"
    );
    assert_eq!(
        loop_body
            .matches("for retry_delay in MUTATION_RETRY_SCHEDULE")
            .count(),
        1,
        "there is more than one retry budget"
    );
    // Its declaration plus exactly one consumer, counted over non-test code only.
    let production = CLIENT_SOURCE
        .split("#[cfg(test)]")
        .next()
        .expect("client source is empty");
    assert_eq!(
        production.matches("MUTATION_RETRY_SCHEDULE").count(),
        2,
        "the retry schedule is consumed somewhere other than the one mutation loop"
    );

    // Once ambiguity is seen, no later attempt may report a definite refusal for this call: it
    // could be refusing precisely because the earlier attempt committed.
    assert!(loop_body.contains("AttemptOutcome::Refused(_) if ambiguity_seen"));
    assert!(
        loop_body.contains(
            "None if ambiguity_seen => return Err(DispatchAuthorityError::AmbiguousCommit)"
        )
    );
    assert!(
        loop_body.contains("accepted.disposition.after_ambiguity()"),
        "a commit after an unresolved one must carry an AfterAmbiguousCommit disposition"
    );
}

// ------------------------------------------------------------------------------------------
// Redaction
// ------------------------------------------------------------------------------------------

fn identity() -> PutStreamIdentity {
    PutStreamIdentity {
        provider_boundary_id: "boundary-secret".into(),
        authenticated_cell_id: "cell-secret".into(),
        authenticated_tenant_id: "tenant-secret".into(),
        logical_request_id: Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
        attempt_id: Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000),
        upload_id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
        upload_fence: 987_654_321,
    }
}

fn limits() -> DispatchRecordLimits {
    DispatchRecordLimits {
        maximum_identity_bytes: 256,
        maximum_boundary_token_bytes: 256,
        maximum_record_bytes: 16_384,
    }
}

fn quota() -> ReservePutQuotaScope {
    ReservePutQuotaScope {
        max_bytes: 10,
        max_rows: 10,
        max_concurrency: 10,
        low_water_bytes: 0,
        low_water_rows: 0,
        low_water_concurrency: 0,
    }
}

/// Fields that are not identifiers or boundary ids and may therefore be rendered.
///
/// Everything else must render as `[REDACTED]`. Checking the *set of rendered fields* rather than a
/// list of known-secret substrings is deliberate: a substring list only catches the values the test
/// author thought to plant, and an earlier version of this test missed a mutation that swapped a
/// redacted field for an unredacted one because the newly disclosed value was not on the list.
const RENDERABLE_KEYS: [&str; 29] = [
    // Pool configuration. None of these name a subject; the URL and the CA bundle, which do, are
    // redacted by their own `Debug` impls and are checked by this same allowlist.
    "role",
    "pool_max",
    "connect_timeout",
    "acquire_timeout",
    "statement_timeout",
    "lock_timeout",
    "tls",
    "budget",
    "immutable_pool_max",
    "mutable_pool_max",
    "lock_pool_max",
    "domain_pool_max",
    "dispatch_pool_max",
    "statement_timeout_ms",
    "lock_timeout_ms",
    "operation_timeout",
    "connections_per_replica",
    // Bounds and limits, which describe the schema rather than the subject.
    "limits",
    "maximum_identity_bytes",
    "maximum_boundary_token_bytes",
    "maximum_record_bytes",
    "maximum_durable_handle_bytes",
    // Database clock readings and deadlines. Not identifying, and load-bearing in diagnostics.
    "admission_clock_unix_ms",
    "expires_at_unix_ms",
    "ready_at_unix_ms",
    "granted_at_database_unix_ms",
    // Closed enum discriminants with a fixed, small domain.
    "state",
    "install_revision",
    "installed_at_unix_ms",
];

/// Assert a pretty-printed `Debug` renders nothing but `[REDACTED]`, nested-struct headers, and
/// the explicitly renderable keys above.
fn assert_redacted(label: &str, rendered: &str) {
    let mut redactions = 0usize;
    for line in rendered.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if trimmed.is_empty() {
            continue;
        }
        // Openers and closers carry no value: `Name {`, `Name(`, `}`, `)`, `],`.
        // `..` is `finish_non_exhaustive`'s marker for the fields deliberately not rendered.
        if matches!(trimmed, "}" | ")" | "]" | "..")
            || (trimmed.ends_with('{') || trimmed.ends_with('(') || trimmed.ends_with('['))
                && !trimmed.contains(": ")
        {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(": ") else {
            // A bare value line: a tuple-variant payload, or a sequence element. An earlier
            // version skipped these, so a derived `Debug` on a tuple variant rendered its payload
            // on its own line and passed - the allowlisted key licensed the `Variant(` header and
            // the payload line had no `": "` to match. Only the weaker substring test caught that,
            // which is exactly backwards. Nothing here legitimately renders a bare value.
            assert!(
                trimmed == "\"[REDACTED]\"",
                "{label}: bare value `{trimmed}` is rendered outside any named field\n\
                 full render:\n{rendered}"
            );
            redactions += 1;
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if value == "\"[REDACTED]\"" {
            redactions += 1;
            continue;
        }
        // A header for a nested struct, tuple variant, or sequence. Skipping it is safe *because*
        // its contents are checked line by line by the branches above - which is what the bare
        // value rule added. Previously a tuple header on an allowlisted key was skipped and its
        // payload line was skipped too, so nothing checked the payload at all.
        if value.ends_with('{') || value.ends_with('(') || value.ends_with('[') {
            continue;
        }
        assert!(
            RENDERABLE_KEYS.contains(&key),
            "{label}: field `{key}` is rendered as {value}\nfull render:\n{rendered}"
        );
    }
    assert!(
        redactions > 0,
        "{label} rendered without any redaction marker:\n{rendered}"
    );
}

#[test]
fn no_request_type_discloses_an_identifier_or_a_boundary_id_through_debug() {
    let reserve = ReservePutRequest {
        protocol_revision: "protocol-1".into(),
        policy_revision: "policy-1".into(),
        identity: identity(),
        spool_object_id: Uuid::from_u128(7),
        boundary_blake3: [1; 32],
        boundary_token: "boundary-secret".into(),
        observation_binding_blake3: [2; 32],
        expected_size: 987_654_321,
        expected_blake3: [3; 32],
        put_reservation_fingerprint: [4; 32],
        allocation_revision: "allocation-1".into(),
        allocation_fence: 987_654_321,
        reservation_deadline_unix_ms: 3_000,
        allocation_hard_expiry_unix_ms: 4_000,
        prepared_ttl_ms: 1_000,
        max_chunk_bytes: 16,
        quota_revision: 1,
        global_quota: quota(),
        cell_quota: quota(),
        tenant_quota: quota(),
        limits: limits(),
    };
    assert_redacted("ReservePutRequest", &format!("{reserve:#?}"));
    assert_redacted("PutStreamIdentity", &format!("{:#?}", identity()));

    let progress = PutUploadProgressRequest {
        protocol_revision: "protocol-1".into(),
        identity: identity(),
        chunk_index: 987_654_321,
        fsynced_prefix_bytes: 987_654_321,
        limits: limits(),
    };
    assert_redacted("PutUploadProgressRequest", &format!("{progress:#?}"));

    let ready = PutSpoolReadyRequest {
        protocol_revision: "protocol-1".into(),
        identity: identity(),
        final_chunk_index: 987_654_321,
        fsynced_body_size: 987_654_321,
        fsynced_body_blake3: [5; 32],
        durable_handle: "handle-secret".into(),
        maximum_identity_bytes: 256,
        maximum_boundary_token_bytes: 256,
        maximum_durable_handle_bytes: 256,
        maximum_record_bytes: 16_384,
    };
    assert_redacted("PutSpoolReadyRequest", &format!("{ready:#?}"));

    let enroll = EnrollParticipantRequest {
        provider_boundary_id: "boundary-secret".into(),
        dispatcher_id: "instance-secret".into(),
        participant_key_blake3: [6; 32],
    };
    assert_redacted("EnrollParticipantRequest", &format!("{enroll:#?}"));

    let register = RegisterDispatcherRequest {
        participant_key: [7; 32],
        next_generation: 987_654_321,
        service_instance_id: "instance-secret".into(),
        dispatcher_fence: 987_654_321,
        authority_revision: 1,
        allocation_revision: "allocation-1".into(),
        allocation_fence: 987_654_321,
        provider_credential_revision: "credential-secret".into(),
        acquired_at_unix_ms: 1,
        renewed_at_unix_ms: 2,
        expires_at_unix_ms: 3,
        state_changed_at_unix_ms: 4,
    };
    assert_redacted("RegisterDispatcherRequest", &format!("{register:#?}"));
}

#[test]
fn no_outcome_type_discloses_an_identifier_through_debug() {
    // Constructed values, checked by the same structural rule the request types get. The previous
    // version grepped each `Debug` impl for seven hard-coded field names, which is the same "list
    // of what the author thought to plant" that the request-side test already failed at, moved
    // from values to field names: rendering `upload_fence` and the ACK bytes raw survived a full
    // green run. Every outcome field is `pub`, so nothing here depends on the decoder.
    assert_redacted(
        "ReservePutOutcome",
        &format!(
            "{:#?}",
            ReservePutOutcome {
                spool_object_id: Uuid::from_u128(0x7777_8888_9999_aaaa_bbbb_cccc_dddd_eeee),
                logical_request_id: Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
                attempt_id: Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000),
                upload_id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
                upload_fence: 987_654_321,
                admission_clock_unix_ms: 2000,
                expires_at_unix_ms: 3000,
                reserve_put_ack_canonical_bytes: b"boundary-secret".to_vec(),
                reserve_put_ack_blake3: [7; 32],
            }
        ),
    );
    assert_redacted(
        "PutUploadProgressOutcome",
        &format!(
            "{:#?}",
            PutUploadProgressOutcome {
                spool_object_id: Uuid::from_u128(0x7777_8888_9999_aaaa_bbbb_cccc_dddd_eeee),
                logical_request_id: Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
                attempt_id: Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000),
                upload_id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
                upload_fence: 987_654_321,
                committed_prefix_bytes: 987_654_321,
                committed_prefix_chunks: 987_654_321,
                spool_revision: 987_654_321,
                record_blake3: [7; 32],
            }
        ),
    );
    assert_redacted(
        "PutSpoolReadyOutcome",
        &format!(
            "{:#?}",
            PutSpoolReadyOutcome {
                spool_object_id: Uuid::from_u128(0x7777_8888_9999_aaaa_bbbb_cccc_dddd_eeee),
                logical_request_id: Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
                attempt_id: Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000),
                upload_id: Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
                upload_fence: 987_654_321,
                durable_handle: "handle-secret".into(),
                committed_size: 987_654_321,
                committed_blake3: [7; 32],
                ready_at_unix_ms: 2000,
                reserve_put_ack_canonical_bytes: b"boundary-secret".to_vec(),
                reserve_put_ack_blake3: [7; 32],
                spool_revision: 987_654_321,
                record_blake3: [7; 32],
            }
        ),
    );
    assert_redacted(
        "EnrollParticipantOutcome",
        &format!(
            "{:#?}",
            EnrollParticipantOutcome {
                provider_boundary_id: "boundary-secret".into(),
                dispatcher_id: "instance-secret".into(),
            }
        ),
    );
    assert_redacted(
        "RegisterDispatcherOutcome",
        &format!(
            "{:#?}",
            RegisterDispatcherOutcome {
                dispatcher_id: "instance-secret".into(),
                lease_generation: 987_654_321,
                provider_boundary_id: "boundary-secret".into(),
                service_instance_id: "instance-secret".into(),
                dispatcher_fence: 987_654_321,
                state: 1,
                record_blake3: [7; 32],
            }
        ),
    );
}

#[test]
fn no_pool_type_discloses_its_url_or_tls_material_through_debug() {
    // Same structural rule again. The pool's own unit tests substring-check for the planted host
    // and password, which is the weaker form; this checks the set of rendered fields.
    let mut config = pool_config(DispatchPoolRole::Runtime);
    config.postgres_url = format!(
        "postgresql://{DISPATCH_RUNTIME_ROLE}:boundary-secret@handle-secret:5432/cell?sslmode=require"
    );
    config.tls = DispatchTlsMode::PinnedRootCa("instance-secret".into());
    assert_redacted("DispatchPoolConfig", &format!("{config:#?}"));

    let mut plaintext = pool_config(DispatchPoolRole::Runtime);
    plaintext.postgres_url = format!(
        "postgresql://{DISPATCH_RUNTIME_ROLE}:boundary-secret@handle-secret:5432/cell?sslmode=disable"
    );
    let pool = DispatchRuntimePool::new(plaintext).expect("pool");
    assert_redacted("DispatchRuntimePool", &format!("{pool:#?}"));
}

#[test]
fn no_error_variant_carries_a_value_that_display_could_leak() {
    // No error variant carries a value at all, so no `Display` can leak one.
    let enum_body = section(
        CLIENT_SOURCE,
        "pub enum DispatchAuthorityError {",
        "impl DispatchAuthorityError {",
    );
    for line in enum_body.lines().map(str::trim) {
        if line.starts_with("#[error(") {
            assert!(
                !line.contains("{0}") || line.contains("is not usable: {0}"),
                "an error variant interpolates a value: {line}"
            );
        }
    }
}

#[test]
fn neither_module_logs_a_parameter_a_diagnostic_or_an_identifier() {
    for (label, source) in [
        ("dispatch_client", CLIENT_SOURCE),
        ("dispatch_pool", POOL_SOURCE),
    ] {
        // Every tracing call must be a single string literal with no interpolation and no
        // arguments. An earlier version of this check exempted any call mentioning "connection
        // ended", which would have let that one call grow an interpolated value unnoticed.
        for (index, _) in source.match_indices("tracing::") {
            let tail = &source[index..];
            let end = tail.find(");").map_or(tail.len(), |offset| offset + 2);
            let call = &tail[..end];
            let arguments = call
                .split_once('(')
                .map(|(_, rest)| rest.trim_end_matches(");").trim())
                .unwrap_or_default();
            assert!(
                arguments.starts_with('"') && arguments.ends_with('"'),
                "{label}: a tracing call takes something other than one string literal: {call}"
            );
            assert!(
                !arguments.contains('{') && !arguments.contains(','),
                "{label}: a tracing call interpolates or carries a field: {call}"
            );
        }
    }
}

#[test]
fn neither_module_uses_unwrap_or_expect_outside_tests() {
    for (label, source) in [
        ("dispatch_client", CLIENT_SOURCE),
        ("dispatch_pool", POOL_SOURCE),
    ] {
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("module source is empty");
        for forbidden in [".unwrap()", ".expect("] {
            assert!(
                !production.contains(forbidden),
                "{label}: non-test code uses {forbidden}"
            );
        }
    }
}

#[test]
fn both_new_files_carry_the_spdx_header() {
    for source in [CLIENT_SOURCE, POOL_SOURCE] {
        assert!(source.starts_with("// SPDX-FileCopyrightText: 2026 Tideshift Labs\n"));
        assert!(source.contains("// SPDX-License-Identifier: MIT\n"));
    }
}

// ------------------------------------------------------------------------------------------
// The pool and its connection budget
// ------------------------------------------------------------------------------------------

#[test]
fn the_connection_budget_statement_is_present_and_arithmetically_true() {
    let exact_limit = DispatchConnectionBudget::new(2, 3, 4, 5, 6).expect("exact limit");
    assert_eq!(exact_limit.connections_per_replica(), 20);
    for fragment in [
        "immutable, mutable, lock, and domain pools plus",
        "five independently configured maxima",
        "sum above 20 PostgreSQL connections",
        "do-managed-pg-connection-budget.md",
    ] {
        assert!(
            DISPATCH_CONNECTION_BUDGET_STATEMENT.contains(fragment),
            "the budget statement omits {fragment}"
        );
    }
}

#[test]
fn a_pool_may_not_be_configured_beyond_the_budget_it_declares() {
    let mut config = pool_config(DispatchPoolRole::Runtime);
    config.pool_max = 6;
    assert!(DispatchRuntimePool::new(config).is_err());
}

#[test]
fn a_client_refuses_a_pool_that_connects_as_the_other_role() {
    let runtime_pool =
        DispatchRuntimePool::new(pool_config(DispatchPoolRole::Runtime)).expect("runtime pool");
    assert_eq!(
        DispatchMaintenanceClient::new(runtime_pool).err(),
        Some(DispatchAuthorityError::WrongPoolRole)
    );
    let maintenance_pool = DispatchRuntimePool::new(pool_config(DispatchPoolRole::Maintenance))
        .expect("maintenance pool");
    assert_eq!(
        DispatchRuntimeClient::new(Arc::new(maintenance_pool)).err(),
        Some(DispatchAuthorityError::WrongPoolRole)
    );
}

#[test]
fn a_pool_url_naming_a_role_other_than_its_own_is_refused() {
    let mut config = pool_config(DispatchPoolRole::Runtime);
    config.postgres_url = format!(
        "postgres://{DISPATCH_MAINTENANCE_ROLE}:secret@cell.invalid:5432/lorecell?sslmode=disable"
    );
    assert!(DispatchRuntimePool::new(config).is_err());
}

fn pool_config(role: DispatchPoolRole) -> DispatchPoolConfig {
    DispatchPoolConfig {
        postgres_url: format!(
            "postgres://{}:secret@cell.invalid:5432/lorecell?sslmode=disable",
            role.role_name()
        ),
        role,
        expected_database_identity: DispatchDatabaseIdentity::new(1, 1)
            .expect("test physical database identity"),
        pool_max: 5,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_millis(2_000),
        lock_timeout: Duration::from_millis(1_000),
        tls: DispatchTlsMode::Disabled,
        budget: test_budget(5),
    }
}

fn test_budget(dispatch_pool_max: u32) -> DispatchConnectionBudget {
    DispatchConnectionBudget::new(1, 1, 1, 1, dispatch_pool_max).expect("test process budget")
}

// ------------------------------------------------------------------------------------------
// Source-dark boundary
// ------------------------------------------------------------------------------------------

#[test]
fn no_other_crate_source_file_calls_the_typed_clients_or_builds_another_pool() {
    // Phase 5 composes CD-4 charging over CD-3's one shared runtime pool. WP-114 CD-8's
    // cell-scale retention joined it as a second legitimate consumer, on the same rule: it also
    // takes the process's already-built pool rather than constructing its own (checked below by
    // the same `DispatchRuntimePool::new(` scan). No OTHER sibling may call a typed client or
    // retain the pool.
    let mut sources = Vec::new();
    collect_rust_sources(&crate_root().join("src"), &mut sources);
    assert!(sources.len() > 20, "source walk found too few files");
    let mut pool_consumers = Vec::new();
    for path in sources {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default();
        if matches!(name, "dispatch_client.rs" | "dispatch_pool.rs" | "lib.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read crate source");
        for symbol in ["DispatchRuntimeClient", "DispatchMaintenanceClient"] {
            assert!(
                !source.contains(symbol),
                "{}: composes the dark typed client via {symbol}",
                path.display()
            );
        }
        if source.contains("DispatchRuntimePool") {
            pool_consumers.push(name.to_string());
            assert!(
                !source.contains("DispatchRuntimePool::new("),
                "{}: constructs a second dispatch pool",
                path.display()
            );
        }
    }
    assert_eq!(
        pool_consumers,
        vec!["cell_retention.rs", "provider_charge.rs"],
        "only the charge authority and cell-scale retention (WP-114 CD-8) may consume the shared \
         runtime pool"
    );
}

fn collect_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|value| value == "rs") {
            sources.push(path);
        }
    }
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The slice of `source` from `start_marker` up to the next `end_marker`.
///
/// **Both markers must be found.** An earlier version fell back to the end of the file when the end
/// marker was missing, so a marker left stale by a refactor silently widened the "function body" to
/// the whole file tail - including `#[cfg(test)]` - and the assertions over it kept passing for the
/// wrong reason. A silent degrade in a source-text tier is how two unfalsifiable guarantees got
/// through review, so this fails loudly instead.
fn section<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .find(start_marker)
        .unwrap_or_else(|| panic!("missing section start: {start_marker}"));
    let rest = &source[start..];
    let end = rest.find(end_marker).unwrap_or_else(|| {
        panic!("missing section end `{end_marker}` after start `{start_marker}`")
    });
    &rest[..end]
}
