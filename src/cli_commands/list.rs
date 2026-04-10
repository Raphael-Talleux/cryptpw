use clap::Command;

use crate::app_context::AppContext;

pub fn cmd() -> Command {
    Command::new("list").about("Lists the sources registered for the profile")
}

pub fn exec(_ctx: &mut AppContext) {
    println!("LIST");
}
