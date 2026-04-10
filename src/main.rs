mod app_context;
mod cli;
mod cli_commands;
mod database;
mod encrypt;
mod utils;

use app_context::AppContext;
use clap::ArgMatches;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut ctx = AppContext::default();

    let user_command: ArgMatches = cli::build_cli().get_matches();

    // For now, there is just a default profile
    let profile: &str = "default";
    ctx.settings.user_profile = Some(String::from(profile));
    ctx.settings.profile_id = Some(1);

    // Init database, and check profile validity
    database::init(&mut ctx)?;

    // Apply user command
    match user_command.subcommand() {
        Some(("add", args)) => {
            cli_commands::add::exec(&mut ctx, args)?;
        }
        Some(("list", _)) => {
            cli_commands::list::exec(&mut ctx);
        }
        _ => {
            println!("Use --help to see available commands.");
        }
    }

    Ok(())
}
