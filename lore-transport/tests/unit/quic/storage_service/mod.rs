// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT

mod client;
// FORK-LOCAL (Tideshift, merge D-QS1): the fork keeps CR-026 session-layer rebinding instead of
// upstream 5c88e6e7's transport-level re-issue, so `reconnect` drives its commands through a
// `StorageSession`; see that module's doc.
mod reconnect;
pub(crate) mod test_server;
