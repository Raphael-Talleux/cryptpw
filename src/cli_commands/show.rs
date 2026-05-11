use clap::{Arg, Command};
use jaro_winkler::jaro_winkler;

use crate::{
    app_context::AppContext,
    database,
    model::{self, Secret},
};

pub fn cmd() -> Command {
    Command::new("show")
        .about("Display the password for a stored entry found by ID search (fuzzy).")
        .arg(
            Arg::new("source")
                .required(true)
                .help("ID (or partial/fuzzy ID) of the entry to display"),
        )
}

#[allow(unreachable_code)]
pub fn exec(_ctx: &AppContext, _args: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
    unimplemented!("Implement SHOW exec command");

    // Request database for the list of secrets for the current profile
    let _secrets: Vec<model::Secret> =
        database::list_all_secret_for_profile(_ctx.settings.profile_id.unwrap())?;

    // TEMP DECRYPT SOURCES

    // TODO: filter secrets using fuzzy search on the provided source argument

    // TODO: decrypt the matched secret's passwords

    // TODO: display the resulting password to the user

    Ok(())
}

fn fuzzy_filter(secret_list: Vec<model::Secret>, query: &str) -> Vec<model::Secret> {
    let query = query.trim().to_lowercase();

    // TODO check if secret.source is encrypted

    // Calculate fuzzy score for each secret
    const FUZZY_SCORE_THRESHOLD: f32 = 0.6;

    let mut results: Vec<(f32, Secret)> = secret_list
        .into_iter()
        .filter_map(|secret| {
            let source = secret.as_source_plaintext("").trim().to_lowercase();
            let score = jaro_winkler(source.as_str(), &query);
            (score >= FUZZY_SCORE_THRESHOLD).then_some((score, secret))
        })
        .collect();

    // Return sorted result
    results.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    results.into_iter().map(|(_, secret)| secret).collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        cli_commands::show::fuzzy_filter,
        model::{self, Encryptable, Secret},
    };

    #[test]
    fn test_fuzzy() {
        let secret_1 = Secret {
            source: Encryptable::Plain(String::from("proton")),
            _password: Encryptable::Plain(String::new()),
            nonce: String::new(),
            salt: String::new(),
        };

        let secret_2 = Secret {
            source: Encryptable::Plain(String::from("gamil")),
            _password: Encryptable::Plain(String::new()),
            nonce: String::new(),
            salt: String::new(),
        };

        let secret_3 = Secret {
            source: Encryptable::Plain(String::from("gmail")),
            _password: Encryptable::Plain(String::new()),
            nonce: String::new(),
            salt: String::new(),
        };

        let secrets: Vec<model::Secret> =
            vec![secret_1.clone(), secret_2.clone(), secret_3.clone()];

        let fuzzy = fuzzy_filter(secrets, "gmai");

        assert_eq!(fuzzy.len(), 2);
        assert_eq!(fuzzy[0], secret_3);
        assert_eq!(fuzzy[1], secret_2);
    }
}
