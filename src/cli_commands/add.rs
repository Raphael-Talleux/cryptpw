use crate::{
    app_context::AppContext,
    database,
    encryption::{self},
    model::Encryptable,
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

/// Prompts the user for a secret, encrypts that secret with the application's
/// encryption key, and stores a new record in the database alongside the
/// provided source.
///
/// The function requests a new secret from the user, encrypts only the secret
/// (AES) producing ciphertext, nonce and salt, and persists the encrypted
/// secret together with the (currently plaintext) source. A salt/nonce pair
/// is generated for the secret, the code currently reuses that salt/nonce when
/// writing the database record.
///
/// # Arguments
/// * ctx - Application context.
/// * args - Parsed CLI arguments.
///
/// # Returns
/// * Ok(()) on success.
/// * Err(...) if encryption or database operations fail.
///
/// # Errors
/// Returns an error if:
/// - Database insertion fails.
///
/// # Panics
/// Panics if:
/// - The "source" argument is missing.
/// - The user cancels secret input.
/// - Encryption fails.
pub fn exec(ctx: &AppContext, args: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    let source: &str = args.get_one::<String>("source").expect("Arg invalid");

    // Request a new secret for registration
    let new_secret: &str = &utils::request_new_secret().unwrap();

    if let Some(key) = &ctx.encryption_key {
        let profile_id = ctx.settings.profile_id.unwrap();

        // ############################################################################################
        // TODO: UGLY SALT/NONCE HANDLING, NEED REFACTOR (REPLACE TUPLES, REFACTOR ENCRYPTION FONCTION)
        // ############################################################################################

        // By default, source is plaintext
        let source = Encryptable::Plain(source.to_string());

        // Apply encryption to password
        let (password_ciphertext, nonce, salt) =
            encryption::encrypt_data(&key, new_secret, None, None).unwrap();
        let password = Encryptable::Encrypted(password_ciphertext);

        // Write result in database
        database::create_new_secret(profile_id, &source, &password, &nonce, &salt)?;
    }

    Ok(())
}
