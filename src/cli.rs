use crate::cli_commands;

use clap::Command;

pub fn build_cli() -> Command {
    Command::new("cryptpw")
        .author("Talleux Raphael")
        .about("A command-line password manager that securely stores and retrieves encrypted passwords.")

        .subcommand(cli_commands::add::cmd())
        .subcommand(cli_commands::remove::cmd())

    //view, remove, update, search
}
