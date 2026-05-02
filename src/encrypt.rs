use aes_gcm::{
    AeadCore, Aes256Gcm, Error, Key, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray},
};
use argon2::{
    self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose};
use rand::Rng;

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

/// Encrypts plaintext using AES-256-GCM with a password, generating a random nonce
/// and optionally using a provided salt and/or nonce (or generating them if not supplied).
///
/// # Arguments
///
/// * `key` - The password or passphrase used to derive the AES key.
/// * `plaintext` - The text data to encrypt.
/// * `optionnal_salt` - An optional 16-byte salt encoded in Base64. If `None`, a random salt is generated.
///   Providing a salt allows deterministic key derivation.
/// * `optionnal_nonce` - An optional 12-byte nonce encoded in Base64. If `None`, a random nonce is generated.
///
/// # Returns
///
/// A `Result` containing a tuple of three Base64-encoded strings:
/// 1. `ciphertext_b64` - the encrypted data
/// 2. `nonce_b64` - the nonce used for encryption (provided or randomly generated)
/// 3. `salt_b64` - the salt used to derive the key (provided or randomly generated)
///
/// # Errors
///
/// Returns an error if encryption fails.
///
/// # Example
///
/// ```
/// // With random salt and nonce
/// let (ciphertext_b64, nonce_b64, salt_b64) =
///     encrypt_data("password123", "Hello world", None, None)?;
///
/// // With provided salt and nonce
/// let salt = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
/// let nonce = base64::engine::general_purpose::STANDARD.encode([0u8; 12]);
///
/// let (ciphertext_b64, nonce_b64, salt_b64) =
///     encrypt_data("password123", "Hello world", Some(salt), Some(nonce))?;
/// ```
pub fn encrypt_data(
    key: &str,
    plaintext: &str,
    optionnal_salt: Option<String>,
    optionnal_nonce: Option<String>,
) -> Result<(String, String, String), Error> {
    // Generate salt (16 bytes)
    let (salt_bytes, salt_b64) = if let Some(salt_b64) = optionnal_salt {
        let salt: [u8; 16] = general_purpose::STANDARD
            .decode(&salt_b64)
            .unwrap()
            .try_into()
            .unwrap();

        (salt, salt_b64)
    } else {
        let salt = generate_salt();
        let salt_b64 = general_purpose::STANDARD.encode(&salt);
        (salt, salt_b64)
    };

    // Generate random nonce (12 bytes)
    let (nonce_bytes, nonce_b64) = if let Some(nonce_b64) = optionnal_nonce {
        let decoded = general_purpose::STANDARD.decode(&nonce_b64).unwrap();
        let nonce = GenericArray::from_exact_iter(decoded)
            .ok_or("invalid nonce size")
            .unwrap();
        (nonce, nonce_b64)
    } else {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_b64 = general_purpose::STANDARD.encode(&nonce);
        (nonce, nonce_b64)
    };

    // Derive 32-byte AES key from password + salt
    let key = generate_key(key, &salt_bytes);
    let key_32bytes = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(key_32bytes);

    // Encrypt plaintext data
    let ciphertext = cipher.encrypt(&nonce_bytes, plaintext.as_bytes())?;
    let ciphertext_b64 = general_purpose::STANDARD.encode(&ciphertext);

    Ok((ciphertext_b64, nonce_b64, salt_b64))
}

/// Decrypts a Base64-encoded ciphertext using AES-256-GCM and a password.
///
/// # Arguments
///
/// * `key` - The password or passphrase to derive the AES key.
/// * `ciphertext_b64` - Base64-encoded ciphertext to decrypt.
/// * `nonce_b64` - Base64-encoded nonce used during encryption (must match the encryption nonce).
/// * `salt_b64` - Base64-encoded salt used to derive the key (must match the encryption salt).
///
/// # Returns
///
/// `Result<String, Error>` containing the decrypted plaintext as UTF-8 string.
///
/// # Errors
///
/// Returns an error if:
/// - Base64 decoding fails for salt, nonce, or ciphertext
/// - The derived key does not match the encryption key
/// - Decryption fails (wrong key/nonce/ciphertext)
/// - The decrypted data is not valid UTF-8
///
/// # Example
///
/// ```
/// let plaintext = decrypt_data(password, ciphertext_b64, nonce_b64, salt_b64)?;
/// ```
pub fn decrypt_data(
    key: &str,
    ciphertext_b64: &str,
    nonce_b64: &str,
    salt_b64: &str,
) -> Result<String, Error> {
    // Decode salt
    let salt = decode_salt(salt_b64);

    // Decode nonce
    let decoded_nonce = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let nonce = Nonce::from_slice(&decoded_nonce);

    // Derive AES key
    let binding = generate_key(key, &salt);
    let key_32bytes = Key::<Aes256Gcm>::from_slice(&binding);
    let cipher = Aes256Gcm::new(key_32bytes);

    // Decode ciphertext and decrypt data
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).unwrap();
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_slice()).unwrap();

    if let Ok(plaintext) = String::from_utf8(plaintext) {
        return Ok(plaintext);
    }

    Ok(String::from("ERROR"))
}

/// Derives a 32-byte encryption key from a password and a salt using Argon2.
///
/// # Arguments
///
/// * `initial_key` - The password or passphrase to derive the key from.
/// * `salt` - A 16-byte salt used to make the key derivation unique and secure.
///
/// # Returns
///
/// A `[u8; 32]` array containing the derived key suitable for AES-256 encryption.
///
/// # Panics
///
/// Panics if the Argon2 key derivation fails
fn generate_key(initial_key: &str, salt: &[u8; 16]) -> [u8; 32] {
    // Generate 32 bytes key
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(initial_key.as_bytes(), salt, &mut key)
        .unwrap();

    key
}

/// Generates a random 16-byte salt for cryptographic operations.
///
/// # Returns
///
/// A `[u8; 16]` array containing the randomly generated salt.
fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);

    salt
}

/// Decodes a Base64-encoded salt into a 16-byte array.
///
/// # Panics
///
/// Panics if the input is not valid Base64 or not 16 bytes long.
pub fn decode_salt(salt_b64: &str) -> [u8; 16] {
    let decoded_salt = general_purpose::STANDARD.decode(&salt_b64).unwrap();
    decoded_salt.try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::encrypt::{self, decrypt_data};

    #[test]
    fn test_encryption() {
        let initial_plaintext = "my super plaintext";
        let key = "test key for encryption";

        let cyphertext = encrypt::encrypt_data(&key, &initial_plaintext, None, None).unwrap();
        let plaintext = decrypt_data(&key, &cyphertext.0, &cyphertext.1, &cyphertext.2).unwrap();

        assert!(initial_plaintext == plaintext);
    }
}
