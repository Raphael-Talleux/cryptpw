use crate::{
    app_context::AppContext,
    database,
    encrypt::{self},
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
/// The function first ensures the user is authenticated by requesting their
/// profile password via `request_user_login`. Once authenticated, it prompts
/// the user to input a new secret.
///
/// Both the provided `source` and the user-entered `secret` are encrypted using
/// AES before being stored in the database. The same salt is reused for both
/// values to allow consistent encryption linkage.
///
/// # Arguments
/// * `ctx` - Mutable application context; updated with the encryption key after authentication.
/// * `args` - Parsed CLI arguments, must contain a `"source"` parameter.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(...)` if authentication, encryption, or database operations fail.
///
/// # Errors
/// Returns an error if:
/// - User authentication fails (via `request_user_login`).
/// - Database insertion fails.
///
/// # Panics
/// Panics if:
/// - The `"source"` argument is missing (`expect("Arg invalid")`).
/// - The user cancels secret input (`unwrap()` on `request_new_secret`).
/// - Encryption fails (`unwrap()`).
///
/// # Behavior
/// - Authenticates the user and stores the encryption key in `ctx.encryption_key`.
/// - Prompts the user to input a new secret.
/// - Encrypts `source` with a randomly generated salt.
/// - Encrypts `secret` using the same salt as `source`.
/// - Persists encrypted values in the database.
pub fn exec(
    ctx: &mut AppContext,
    args: &clap::ArgMatches,
) -> Result<(), Box<dyn std::error::Error>> {
    let source: &str = args.get_one::<String>("source").expect("Arg invalid");

    // Load profile with user credentials
    utils::request_user_login(ctx)?;

    // Request a new secret for registration
    let new_secret: &str = &utils::request_new_secret().unwrap();

    if let Some(key) = &ctx.encryption_key {
        let profile_id = ctx.settings.profile_id.unwrap();

        // Apply encryption to SOURCE and SECRET
        let source_ciphertext = encrypt::encrypt_data(&key, source, None, None).unwrap();
        let secret_ciphertext = encrypt::encrypt_data(
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
