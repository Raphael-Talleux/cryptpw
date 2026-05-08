use crate::{
    app_context::AppContext,
    database,
    encryption::{self},
    utils::{self},
};
use clap::{Arg, Command};

pub fn cmd() -> Command {
    Command::new("add").about("Save a password").arg(
        Arg::new("source")
            .required(true)
            .help("The key used to retrieve the stored password"),
    )
}

/// Executes the command by authenticating the user, then encrypting and storing
/// a SOURCE and SECRET in the database.
///
/// The function prompts the user to input a new secret.
///
/// Both the provided `source` and the user-entered `secret` are encrypted using
/// AES before being stored in the database. The same salt is reused for both
/// values to allow consistent encryption linkage.
///
/// # Arguments
/// * `ctx` - Application context
/// * `args` - Parsed CLI arguments, must contain a `"source"` parameter.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(...)` if authentication, encryption, or database operations fail.
///
/// # Errors
/// Returns an error if:
/// - Database insertion fails.
///
/// # Panics
/// Panics if:
/// - The `"source"` argument is missing (`expect("Arg invalid")`).
/// - The user cancels secret input (`unwrap()` on `request_new_secret`).
/// - Encryption fails (`unwrap()`).
///
/// # Behavior
/// - Prompts the user to input a new secret.
/// - Encrypts `source` with a randomly generated salt.
/// - Encrypts `secret` using the same salt as `source`.
/// - Persists encrypted values in the database.
pub fn exec(ctx: &AppContext, args: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let source: &str = args.get_one::<String>("source").expect("Arg invalid");

    // Request a new secret for registration
    let new_secret: &str = &utils::request_new_secret().unwrap();

    if let Some(key) = &ctx.encryption_key {
        let profile_id = ctx.settings.profile_id.unwrap();

        // Apply encryption to SOURCE and SECRET
        let source_ciphertext = encryption::encrypt_data(&key, source, None, None).unwrap();
        let secret_ciphertext = encryption::encrypt_data(
            &key,
            new_secret,
            Some(source_ciphertext.2.clone()),
            Some(source_ciphertext.1.clone()),
        )
        .unwrap();

        // Write result in database
        database::create_new_secret(
            profile_id,
            &source_ciphertext.0,
            &secret_ciphertext.0,
            &secret_ciphertext.1,
            &secret_ciphertext.2,
        )?;
    }

    Ok(())
}
