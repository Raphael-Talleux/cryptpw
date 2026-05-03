//! This module handles SQLite database initialization
//! and user profile creation/loading, including encrypted passwords.
//!
//! Main pub functions:
//! - `init()` : initializes the database and the default profile

use crate::{
    app_context::AppContext,
    encryption,
    model::{self},
};
use dialoguer::Password;
use rusqlite::{Connection, Result, params};

/// Opens a connection to the SQLite database.
fn open_connection() -> Result<Connection> {
    Connection::open(".data/data.db")
}

/// Initializes the database and ensures a default profile exists.
///
/// - Checks if the "profiles" table exists, and creates it if not.
/// - Attempts to load the "default" profile, or generates a new one.
pub fn init(ctx: &mut AppContext) -> Result<(), Box<dyn std::error::Error>> {
    let db: Connection = open_connection()?;

    // Check "profiles" table
    if !is_table_exist(&db, "profiles")? {
        generate_profile_table(&db)?;
    }

    // Check "secrets" table
    if !is_table_exist(&db, "secrets")? {
        generate_secrets_table(&db)?;
    }

    if let Some(profile) = ctx.settings.user_profile.clone().as_deref() {
        // Try to load user profile
        if is_valid_profile(&db, profile)? {
            println!("Profile loaded : {}", profile);
        } else {
            generate_new_profile(&db, ctx, profile)?;
        }
    }

    Ok(())
}

/// Checks if a table exists in the database.
fn is_table_exist(db: &Connection, table_name: &str) -> Result<bool> {
    let mut stmt = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?1")?;

    let mut rows = stmt.query([table_name])?;

    Ok(rows.next()?.is_some())
}

/// Checks if a profile exists in the database.
fn is_valid_profile(db: &Connection, profile_name: &str) -> Result<bool> {
    let exists: i64 = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM profiles WHERE name=?1)",
        [&profile_name],
        |row| row.get(0),
    )?;

    Ok(exists != 0)
}

/// Creates the "profiles" table.
fn generate_profile_table(db: &Connection) -> Result<()> {
    println!("Creating default resources : 'profiles' table.");

    db.execute(
        "CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                pass_hash TEXT NOT NULL)",
        [],
    )?;

    Ok(())
}

/// Creates the "secrets" table.
fn generate_secrets_table(db: &Connection) -> Result<()> {
    println!("Creating default resources : 'secrets' table.");

    db.execute(
        "CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY,
                profile_id INTEGER NOT NULL,
                ciphertext_source TEXT NOT NULL,
                ciphertext_password TEXT NOT NULL,
                nonce TEXT NOT NULL,
                salt TEXT NOT NULL)
                ",
        [],
    )?;

    Ok(())
}

/// Generates a new profile by asking the user for a master password.
///
/// ## Notes
/// - The password input is hidden (no echo in terminal).
/// - The user is asked to confirm the password before saving.
fn generate_new_profile(
    db: &Connection,
    ctx: &mut AppContext,
    profile_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "No data found for '{}'. A new profile will be generated.",
        profile_name
    );

    loop {
        let password = Password::new()
            .with_prompt("Please enter your master password")
            .with_confirmation("Confirm password", "Passwords mismatching")
            .interact();

        if let Ok(password) = password {
            ctx.encryption_key = Some(password.clone());

            let password_hash = encryption::generate_password_hash(&password)?;

            db.execute(
                "INSERT INTO profiles (name, pass_hash) VALUES (?1, ?2)",
                [profile_name, &password_hash],
            )?;

            break;
        }
    }

    println!("Profile created successfully !");
    Ok(())
}

/// Retrieves the password hash associated with a given profile name.
///
/// This function queries the database for the `pass_hash` field
/// in the `profiles` table using the provided profile name.
///
/// # Arguments
/// * `profile` - The name of the profile to look up.
///
/// # Returns
/// * `Ok(String)` containing the password hash if the profile exists.
/// * `Ok(None)` if no matching profile is found.
/// * `Err(...)` if a database error occurs.
///
/// # Errors
/// This function will return an error if:
/// - The database connection cannot be established.
/// - The SQL statement fails to prepare or execute.
/// - The row data cannot be retrieved.
pub fn get_profile_password_hash(
    profile: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let db: Connection = open_connection()?;

    let mut stmt = db.prepare("SELECT pass_hash FROM profiles WHERE name= ?1")?;
    let mut rows = stmt.query([profile])?;

    if let Some(row) = rows.next()? {
        Ok(row.get(0)?)
    } else {
        Ok(None)
    }
}

pub fn create_new_secret(
    profile_id: u32,
    ciphertext_source: &str,
    ciphertext_password: &str,
    nonce: &str,
    salt: &str,
) -> Result<()> {
    // Check inputs to avoid DB corruption
    if profile_id <= 0 || ciphertext_password.is_empty() || ciphertext_source.is_empty() {
        println!("Error : Can't create secret entry :");
        dbg!((
            profile_id,
            ciphertext_password,
            ciphertext_source,
            nonce,
            salt
        ));
    }

    // Write secret into db
    let db = open_connection()?;

    if is_table_exist(&db, "secrets")? {
        db.execute(
            "INSERT INTO secrets (profile_id, ciphertext_source, ciphertext_password, nonce, salt) 
                VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                profile_id,
                ciphertext_source,
                ciphertext_password,
                nonce,
                salt
            ],
        )?;

        println!("User secret created successfully !");
    }

    // TODO handle error
    Ok(())
}

pub fn list_all_secret_for_profile(
    profile_id: u32,
) -> Result<Vec<model::Secret>, Box<dyn std::error::Error>> {
    let db = open_connection()?;

    let mut stmt = db.prepare(
        "
        SELECT ciphertext_source, ciphertext_password, nonce, salt
        FROM secrets
        INNER JOIN profiles
        ON secrets.profile_id = profiles.id
        WHERE profile_id = ?1
        ",
    )?;

    let rows = stmt.query_map([profile_id], |row| {
        Ok(model::Secret {
            source: row.get(0)?,
            _password: row.get(1)?,
            nonce: row.get(2)?,
            salt: row.get(3)?,
        })
    })?;

    Ok(rows.collect::<Result<_, _>>()?)
}
