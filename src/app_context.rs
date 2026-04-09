/// Global application context.
///
/// This struct is intended to group all shared state and resources
/// used throughout the application (settings, database connections, etc.).
#[derive(Debug)]
pub struct AppContext {
    pub settings: Settings,

    pub encryption_key: Option<String>,
}

impl Default for AppContext {
    fn default() -> Self {
        AppContext {
            settings: Settings::default(),
            encryption_key: None,
        }
    }
}

/// Application settings shared across the program.
///
/// This struct holds user-specific configuration that can be
/// accessed and modified during runtime.
#[derive(Debug)]
pub struct Settings {
    pub user_profile: Option<String>,
    pub profile_id: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            user_profile: None,
            profile_id: None,
        }
    }
}
