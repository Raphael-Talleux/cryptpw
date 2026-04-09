use crate::{app_context::AppContext, database, encrypt, utils::request_profile_password};
use clap::{Arg, Command};

pub fn cmd() -> Command {
    Command::new("add").about("Save a password").arg(
        Arg::new("source")
            .required(true)
            .help("The key used to retrieve the stored password"),
    )
}

/// Executes the command by validating the user's profile password
/// and storing it as the encryption key in the application context.
///
/// This function prompts the user to enter their profile password,
/// verifies it against the stored password hash, and repeats the
/// process until a valid password is provided.
///
/// # Arguments
/// * `ctx` - Mutable reference to the application context, which will
///   be updated with the encryption key upon successful authentication.
/// * `args` - Command-line arguments parsed by `clap`, expected to contain
///   a `"source"` parameter.
///
/// # Returns
/// * `Ok(())` if the password is successfully validated and stored.
/// * `Err(...)` if an error occurs while retrieving the password hash
///   or verifying it.
///
/// # Errors
/// This function will return an error if:
/// - Retrieving the stored password hash from the database fails.
/// - The password hash verification process fails.
///
/// # Panics
/// This function will panic if the `"source"` argument is missing or invalid,
/// due to the use of `expect("Arg invalid")`.
///
/// # Behavior
/// - Continuously prompts the user for their profile password.
/// - Compares the entered password with the stored hash.
/// - On success, sets `ctx.encryption_key` and exits the loop.
/// - On failure, displays an error message and retries.
pub fn exec(
    ctx: &mut AppContext,
    args: &clap::ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let source: &str = args.get_one::<String>("source").expect("Arg invalid");

    // Prompt the user for the encryption key
    while ctx.encryption_key.is_none() {
        if let Some(password) = request_profile_password(ctx) {
            if let Some(hash) =
                database::get_profile_password_hash(ctx.settings.user_profile.as_ref().unwrap())?
            {
                // Verify that the profile password is correct
                if encrypt::check_password_hash(&password, &hash)? {
                    ctx.encryption_key = Some(password);
                    break;
                }
            }
        }

        println!("Incorrect profile password. Please try again.");
    }

    // Request a new secret for registration
    let new_secret: &str = "my_secret";
    println!("TODO REQUEST NEW USER SECRET");

    // TODO Source encryption
    // TODO Secret encryption

    // Write user secret into db
    if let Some(profile_id) = ctx.settings.profile_id {
        database::create_new_secret(profile_id, source, new_secret)?;
    }

    Ok(())
}
