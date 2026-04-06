use clap::{Arg, Command};

pub fn cmd() -> Command {
    Command::new("remove").about("Delete a saved password").arg(
        Arg::new("password-id")
            .required(true)
            .help("The key used to retrieve the password"),
    )
}
