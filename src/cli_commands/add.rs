use clap::{Arg, Command};


pub fn cmd() -> Command {
    Command::new("add")
        .about("Save a password")
        .arg(Arg::new("password-id").required(true).help("The key used to retrieve the password"))
}