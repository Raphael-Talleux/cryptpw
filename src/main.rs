mod cli;
mod cli_commands;
mod database;
mod encrypt;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    cli::build_cli().get_matches();

    database::init()?;

    Ok(())
}
