// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Shared fixture: the SQL `cell-schema-install` runs for a frozen cell migration on the connected
//! server's major.
//!
//! Frozen 0008 and 0011 embed a `PostgreSQL` 16 manifest digest in their own catalog asserts, so a
//! live test that installs their raw bytes and then calls an install procedure is refused on
//! `PostgreSQL` 18. The installer instead runs `cell_migration_sql`'s rendering there. Tests use the
//! same rendering, so both majors install exactly what a real cell installs. Every other artifact,
//! and every artifact on `PostgreSQL` 16, is returned unchanged.

use std::borrow::Cow;

use lore_object_dispatch::cell_schema_install::CELL_INSTALL_SET;
use lore_object_dispatch::cell_schema_install::cell_migration_sql;
use lore_object_dispatch::cell_schema_install::read_server_major;
use tokio_postgres::Client;

/// Returns the SQL to install `frozen` on `client`'s server major.
///
/// # Panics
///
/// When the server major is unsupported, or a rendering does not match its pinned digest.
pub async fn cell_install_sql(client: &Client, frozen: &'static str) -> Cow<'static, str> {
    let Some(migration) = CELL_INSTALL_SET
        .iter()
        .find(|migration| migration.sql == frozen)
    else {
        return Cow::Borrowed(frozen);
    };
    let major = read_server_major(client)
        .await
        .expect("read a supported PostgreSQL major");
    cell_migration_sql(major, migration).expect("render the cell migration for this major")
}
