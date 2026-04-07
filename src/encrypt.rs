use argon2::{
    self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};

/// Generates a secure password hash using Argon2
///
/// ## Arguments
///
/// * `plain_password` - The plaintext password to hash
///
/// ## Returns
///
/// * `Ok(String)` containing the password hash on success
/// * `Err` if an error occurs during hashing
pub fn generate_password_hash(plain_password: &str) -> Result<String, Box<dyn std::error::Error>> {
    let password = plain_password.as_bytes();
    let salt = SaltString::generate(&mut OsRng);

    Ok(Argon2::default()
        .hash_password(password, &salt)?
        .to_string())
}

/// Checks if a plaintext password matches a given Argon2 hash
///
/// ## Arguments
///
/// * `password` - The plaintext password to verify
/// * `password_hash` - The Argon2 hash to compare against
/// ## Returns
///
/// * `Ok(true)` if the password matches the hash
/// * `Ok(false)` if the password does not match
/// * `Err` if the provided hash is invalid
pub fn check_password_hash(
    password: &String,
    password_hash: &String,
) -> Result<bool, Box<dyn std::error::Error>> {
    let parsed_hash = PasswordHash::new(&password_hash)?;

    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}
