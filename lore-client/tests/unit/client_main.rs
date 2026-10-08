// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use clap::Parser;
use lore_client::cli::LoreCli;
use lore_client::cli::LoreCommands;
use lore_client::client_main::runs_the_service;

fn command_of(args: &[&str]) -> LoreCommands {
    LoreCli::try_parse_from(args)
        .expect("the arguments must parse")
        .command
        .expect("the arguments must name a command")
}

/// `service run` is the service. Sizing it for relaying would leave the
/// process that does all the work with the pools of one that does none.
#[test]
fn the_command_that_runs_the_service_is_not_sized_for_relaying() {
    assert!(runs_the_service(&command_of(&["lore", "service", "run"])));
}

/// Every other `service` command is a client of the service, including the
/// two that ask for one to start and stop.
#[test]
fn the_commands_that_act_on_the_service_are_sized_for_relaying() {
    for args in [
        vec!["lore", "service", "start"],
        vec!["lore", "service", "stop"],
        vec!["lore", "service", "set-executable", "/opt/lore/bin/lore"],
        vec!["lore", "service", "set-use-automatically", "true"],
        vec!["lore", "status"],
    ] {
        assert!(
            !runs_the_service(&command_of(&args)),
            "{} is a client of the service",
            args.join(" ")
        );
    }
}
