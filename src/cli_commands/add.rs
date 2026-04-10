use crate::{
    app_context::AppContext,
    database, encrypt,
    utils::{self, request_profile_password},
};
use clap::{Arg, Command};

pub fn cmd() -> Command {
    Command::new("add").about("Save a password").arg(
        Arg::new("source")
            .required(true)
            .help("The key used to retrieve the stored password"),
    )
}

/// Executes the command by validating the user's profile password,
/// then encrypts and stores a SOURCE and SECRET in the database.
///
/// The function prompts the user for their profile password until it is valid.
/// Once authenticated, it encrypts:
/// - the provided `source`
/// - a newly generated secret
/// using AES encryption, then saves the results.
///
/// # Arguments
/// * `ctx` - Mutable application context; updated with the encryption key after authentication.
/// * `args` - Parsed CLI arguments, must contain a `"source"` parameter.
///
/// # Returns
/// * `Ok(())` on success.
/// * `Err(...)` if password retrieval, verification, or database operations fail.
///
/// # Errors
/// Returns an error if:
/// - Fetching the stored password hash fails.
/// - Password verification fails.
/// - Database insertion fails.
///
/// # Panics
/// Panics if the `"source"` argument is missing (`expect("Arg invalid")`)
/// or if encryption fails (due to `unwrap()`).
///
/// # Behavior
/// - Repeatedly prompts for the profile password until valid.
/// - Stores the password in `ctx.encryption_key`.
/// - Encrypts `source` with a random salt.
/// - Encrypts `secret` using the same salt as `source`.
/// - Persists encrypted values in the database.
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
    let new_secret: &str = &utils::request_new_secret().unwrap();

    if let Some(key) = &ctx.encryption_key {
        let profile_id = ctx.settings.profile_id.unwrap();

        // Apply encryption to SOURCE and SECRET
        let source_ciphertext = encrypt::encrypt_data(&key, source, None).unwrap();
        let secret_ciphertext = encrypt::encrypt_data(
            &key,
            new_secret,
            Some(encrypt::decode_salt(&source_ciphertext.2)),
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
