use clap::{Arg, Command};

pub fn cmd() -> Command {
    Command::new("show")
        .about("Display the password for a stored entry found by ID search (fuzzy).")
        .arg(
            Arg::new("source")
                .required(true)
                .help("ID (or partial/fuzzy ID) of the entry to display"),
        )
}
