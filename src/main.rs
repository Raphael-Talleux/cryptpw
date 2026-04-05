mod cli;
mod cli_commands;

fn main() {
    cli::build_cli().get_matches();
}
