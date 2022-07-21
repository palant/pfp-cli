/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::args::{Args, Commands};
use clap::{CommandFactory, FromArgMatches};
use pfp::passwords::Passwords;
use pfp::storage_io;
use rustyline::error::ReadlineError;
use std::io::Write;

fn get_default_history_path() -> std::path::PathBuf {
    let app_info = app_dirs2::AppInfo {
        name: "PfP",
        author: "Wladimir Palant",
    };
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("history.txt");
    path
}

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    storage_path: &std::path::PathBuf,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    let history_path = match &args.command {
        Commands::Shell {
            history: Some(value),
        } => value.clone(),
        _ => get_default_history_path(),
    };

    let mut editor = rustyline::Editor::<()>::new();
    if let Err(error) = editor.load_history(&history_path) {
        eprintln!(
            "Did not load previous command history from {} ({}).",
            history_path.display(),
            error
        );
    }

    println!("Enter a command or type 'help' for a list of commands. Enter 'help <command>' for detailed information on a command.");
    std::io::stdout().flush().unwrap();
    loop {
        match editor.readline("pfp> ") {
            Ok(line) => {
                macro_rules! print_errors {
                    ($expr:expr) => {
                        match $expr {
                            Ok(value) => value,
                            Err(error) => {
                                eprintln!("{}", error);
                                continue;
                            }
                        }
                    };
                }

                editor.add_history_entry(line.clone());

                let words = print_errors!(shellwords::split(&line));

                let mut command = Args::command()
                    .bin_name("")
                    .disable_help_flag(true)
                    .disable_version_flag(true)
                    .no_binary_name(true)
                    .subcommand(clap::Command::new("exit")
                        .about("Exits the shell"))
                    .subcommand(clap::Command::new("lock")
                        .about("Locks passwords, so that the next operation will ask for the primary password again"))
                    .mut_subcommand("shell", |subcmd| subcmd.hide(true))
                    .mut_subcommand("set-primary", |subcmd| subcmd.hide(true))
                    .help_template("COMMANDS:\n{subcommands}");
                for subcommand in command.get_subcommands_mut() {
                    *subcommand = subcommand
                        .clone()
                        .help_template("{about}\n\nUSAGE:\n   {usage}\n\n{all-args}");
                }

                let matches = print_errors!(command.try_get_matches_from(words));
                if let Some(("exit", _)) = matches.subcommand() {
                    break;
                }
                if let Some(("lock", _)) = matches.subcommand() {
                    passwords.lock();
                    println!("Passwords locked.");
                    continue;
                }
                if let Some(("shell", _)) = matches.subcommand() {
                    eprintln!("You cannot run a shell from a shell.");
                    continue;
                }
                if let Some(("set-primary", _)) = matches.subcommand() {
                    eprintln!("You cannot change primary password from a shell.");
                    continue;
                }

                let mut new_args = print_errors!(Args::from_arg_matches(&matches));
                new_args.stdin_passwords = args.stdin_passwords;

                print_errors!(super::process_command(new_args, storage_path, passwords));
                std::io::stdout().flush().unwrap();
            }
            Err(ReadlineError::Interrupted) => {}
            Err(ReadlineError::Eof) => {
                break;
            }
            Err(error) => {
                eprintln!("Error: {:?}", error);
            }
        }
    }

    if let Err(error) = editor.save_history(&history_path) {
        eprintln!(
            "Failed saving history to {} ({}).",
            history_path.display(),
            error
        );
    }

    Ok(())
}
