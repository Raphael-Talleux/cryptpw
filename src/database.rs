//! This module handles SQLite database initialization
//! and user profile creation/loading, including encrypted passwords.
//!
//! Main pub functions:
//! - `init()` : initializes the database and the default profile

use crate::{app_context::AppContext, encrypt};
use dialoguer::Password;
use rusqlite::{Connection, Result};

/// Opens a connection to the SQLite database.
fn open_connection() -> Result<Connection> {
    Connection::open(".data/data.db")
}

/// Initializes the database and ensures a default profile exists.
///
/// - Checks if the "profiles" table exists, and creates it if not.
/// - Attempts to load the "default" profile, or generates a new one.
pub fn init(ctx: &AppContext) -> Result<(), Box<dyn std::error::Error>> {
    let db: Connection = open_connection()?;

    let profile = ctx.settings.user_profile.as_deref().unwrap();

    // Check "profiles" table
    if !is_table_exist(&db, "profiles")? {
        generate_profile_table(&db)?;
    }

    // Try to load user profile
    if is_valid_profile(&db, profile)? {
        println!("Profile loaded : {}", profile);
    } else {
        generate_new_profile(&db, profile)?;
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
    println!("Database is empty. Creating default resources.");

    db.execute(
        "CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                pass_hash TEXT NOT NULL)",
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
            let password = encrypt::generate_password_hash(&password)?;

            db.execute(
                "INSERT INTO profiles (name, pass_hash) VALUES (?1, ?2)",
                [profile_name, &password],
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
