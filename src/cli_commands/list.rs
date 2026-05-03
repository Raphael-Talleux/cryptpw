use clap::Command;

use crate::{app_context::AppContext, database, model, utils};

pub fn cmd() -> Command {
    Command::new("list").about("Lists the sources registered for the profile")
}

pub fn exec(ctx: &mut AppContext) -> Result<(), Box<dyn std::error::Error>> {
    // Load profile with user credentials
    utils::request_user_login(ctx)?;

    // Request database to obtain secrets list
    let secrets: Vec<model::Secret> =
        database::list_all_secret_for_profile(ctx.settings.profile_id.unwrap())?;

    // Print list to user
    println!("🔐 Secrets list:");
    for (i, secret) in secrets.iter().enumerate() {
        println!(
            "{} - {}",
            i + 1,
            secret.as_source_plaintext(&ctx.encryption_key.clone().unwrap().as_ref())
        )
    }

    Ok(())
}
