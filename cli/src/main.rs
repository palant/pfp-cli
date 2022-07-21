/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod args;
mod processor;

#[cfg(leaking_alloc)]
mod leaking_allocator;

#[cfg(logging_alloc)]
mod logging_allocator;

#[cfg(logging_alloc)]
use logging_allocator::{init_allocator, shutdown_allocator};

#[cfg(not(logging_alloc))]
fn init_allocator() {}

#[cfg(not(logging_alloc))]
fn shutdown_allocator() {}

use args::{Args, Commands};
use io_streams::StreamWriter;
use pfp::passwords::Passwords;
use pfp::storage_io::FileIO;
use processor::utils::ConvertError;
use std::io::Write;

struct Shutdown {
    wait: bool,
}

impl Shutdown {
    pub fn new(wait: bool) -> Self {
        Self { wait }
    }
}

impl Drop for Shutdown {
    fn drop(&mut self) {
        if self.wait {
            std::io::stdout().flush().unwrap();
            StreamWriter::stdout()
                .unwrap()
                .write_all(b"\nWaiting...\n")
                .unwrap();

            let mut _input = String::new();
            std::io::stdin().read_line(&mut _input).unwrap();
        }
        shutdown_allocator();
    }
}

fn get_default_storage_path() -> std::path::PathBuf {
    let app_info = app_dirs2::AppInfo {
        name: "PfP",
        author: "Wladimir Palant",
    };
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("storage.json");
    path
}

fn main_inner(args: Args) -> Result<(), String> {
    let storage_path = match &args.storage {
        Some(value) => value.clone(),
        None => get_default_storage_path(),
    };

    let io = if let Commands::SetPrimary { assume_yes } = &args.command {
        match FileIO::load(&storage_path) {
            Ok(io) => {
                if !assume_yes {
                    let allow = question::Question::new(
                        "Changing primary password will remove all existing data. Continue?",
                    )
                    .default(question::Answer::NO)
                    .show_defaults()
                    .confirm();
                    if allow == question::Answer::NO {
                        return Ok(());
                    }
                }
                io
            }
            Err(_) => FileIO::new(&storage_path),
        }
    } else {
        FileIO::load(&storage_path).convert_error()?
    };

    let mut passwords = Passwords::new(io);
    processor::process_command(args, &storage_path, &mut passwords)
}

fn main() -> std::process::ExitCode {
    init_allocator();

    let args = <Args as clap::Parser>::parse();
    let _shutdown = Shutdown::new(args.wait);
    if let Err(error) = main_inner(args) {
        eprintln!("{}", error);
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
