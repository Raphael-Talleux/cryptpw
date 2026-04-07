mod app_context;
mod cli;
mod cli_commands;
mod database;
mod encrypt;

use app_context::AppContext;
use clap::ArgMatches;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut ctx = AppContext::default();

    let user_command: ArgMatches = cli::build_cli().get_matches();

    // For now, there is just a default profile
    let profile: &str = "default";
    ctx.settings.user_profile = Some(String::from(profile));

    // Init database, and check profile validity
    database::init(&ctx)?;

    Ok(())
}
