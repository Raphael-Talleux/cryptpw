use crate::{app_context::AppContext, database, encrypt};
use dialoguer::Password;

/// Prompts the user to log in by entering their profile password.
///
/// This function repeatedly asks the user for their profile password until a
/// valid one is provided. The entered password is verified against the stored
/// password hash associated with the current user profile.
///
/// If the password is correct, it is stored in the application context as the
/// encryption key (`ctx.encryption_key`).
///
/// # Errors
/// Returns an error if retrieving the stored password hash or verifying the
/// password fails.
///
/// # Behavior
/// - Loops until a valid password is entered.
/// - Prints an error message on each failed attempt.
/// - Updates `ctx.encryption_key` upon successful authentication.
pub fn request_user_login(ctx: &mut AppContext) -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}

/// Prompts the user to enter the password for the current profile.
///
/// This function builds a prompt message using the profile name stored
/// in the application context, then securely asks the user to input
/// their password via the terminal.
///
/// # Arguments
/// * `ctx` - Reference to the application context containing the
///   current profile information.
///
/// # Returns
/// * `Some(String)` containing the password entered by the user.
/// * `None` if the input operation fails or is interrupted.
///
/// # Behavior
/// - Displays a prompt in the form: `"Password for '<profile>' profile"`.
/// - Reads the password securely (input is hidden).
/// - Returns the entered password if successful.
fn request_profile_password(ctx: &AppContext) -> Option<String> {
    let prompt = String::from("Password for '")
        + ctx.settings.user_profile.as_ref().unwrap()
        + &String::from("' profile");

    let password: Result<String, dialoguer::Error> = Password::new().with_prompt(prompt).interact();

    if let Ok(password) = password {
        Some(password)
    } else {
        None
    }
}

/// Prompts the user to securely input a new secret value via the terminal.
///
/// This function uses a hidden password prompt with confirmation to ensure
/// the user enters the intended secret correctly. If the input and its
/// confirmation match, the secret is returned as a `String`.
///
/// # Returns
/// - `Some(String)` containing the validated secret if the input succeeds.
/// - `None` if the user cancels the prompt or an input error occurs.
pub fn request_new_secret() -> Option<String> {
    let secret: Result<String, dialoguer::Error> = Password::new()
        .with_prompt("Add new secret (hidden)")
        .with_confirmation("Confirm secret", "Secrets mismatching")
        .interact();

    if let Ok(secret) = secret {
        Some(secret)
    } else {
        None
    }
}
