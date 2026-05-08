use clap::{Arg, Command};

use crate::{
    app_context::AppContext,
    database,
    model::{self},
};

pub fn cmd() -> Command {
    Command::new("show")
        .about("Display the password for a stored entry found by ID search (fuzzy).")
        .arg(
            Arg::new("source")
                .required(true)
                .help("ID (or partial/fuzzy ID) of the entry to display"),
        )
}

#[allow(unreachable_code)]
pub fn exec(_ctx: &AppContext, _args: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("Implement SHOW exec command");

    // Request database for the list of secrets for the current profile
    let _secrets: Vec<model::Secret> =
        database::list_all_secret_for_profile(_ctx.settings.profile_id.unwrap())?;

    // TEMP DECRYPT SOURCES

    // TODO: filter secrets using fuzzy search on the provided source argument

    // TODO: decrypt the matched secret's passwords

    // TODO: display the resulting password to the user

    Ok(())
}

fn _fuzzy_filter(_all_secret: Vec<model::Secret>) -> Vec<model::Secret> {
    //let mut result: Vec<model::Secret> = all_secret.into_iter().filter();
    let result: Vec<model::Secret> = vec![];
    result
}
