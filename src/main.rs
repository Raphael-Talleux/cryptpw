mod app_context;
mod cli;
mod cli_commands;
mod database;
mod encryption;
mod model;
mod utils;

use app_context::AppContext;
use clap::ArgMatches;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut ctx = AppContext::default();

    let user_command: ArgMatches = cli::build_cli().get_matches();

    // Init database, ensure data integrity
    database::init()?;

    // For now, there is just a default profile
    let profile: &str = "default";
    ctx.settings.user_profile = Some(String::from(profile));
    ctx.settings.profile_id = Some(1);

    database::load_profile(&mut ctx)?;

    // Apply user command
    match user_command.subcommand() {
        Some(("add", args)) => {
            cli_commands::add::exec(&ctx, args)?;
        }
        Some(("list", _)) => {
            cli_commands::list::exec(&ctx)?;
        }
        _ => {
            println!("Use --help to see available commands.");
        }
    }

    Ok(())
}
