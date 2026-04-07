use crate::app_context::AppContext;
use dialoguer::Password;

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
pub fn request_profile_password(ctx: &AppContext) -> Option<String> {
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
