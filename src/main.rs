/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod crypto;
mod master_password;
mod storage;

use app_dirs2;
use clap::{Parser, Subcommand};
use question;
use rpassword;
use std::path;
use std::process;

/// PfP: Pain-free Passwords, command line edition
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args
{
    /// Data storage file path
    #[clap(parse(from_os_str), short = 'c', long)]
    storage: Option<path::PathBuf>,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands
{
    /// Set a new master password
    SetMaster
    {
        /// Do not prompt before overwriting data
        #[clap(short = 'y', long)]
        assume_yes: bool
    },
    /// Generate a password
    Generate
    {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
        /// Password length
        #[clap(short = 'l', long, default_value_t = 16, parse(try_from_str = parse_length))]
        length: u8,
        /// Do not include lower-case letters
        #[clap(short = 'w', long)]
        no_lower: bool,
        /// Do not include upper-case letters
        #[clap(short = 'u', long)]
        no_upper: bool,
        /// Do not include digits
        #[clap(short = 'd', long)]
        no_digit: bool,
        /// Do not include symbols
        #[clap(short = 's', long)]
        no_symbol: bool,
    }
}

fn get_default_storage_path() -> path::PathBuf
{
    let app_info = app_dirs2::AppInfo {name: "PfP", author: "Wladimir Palant"};
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("storage.json");
    return path;
}

fn parse_length(arg: &str) -> Result<u8, String>
{
    let length = match arg.parse::<u8>()
    {
        Ok(length) => length,
        Err(error) => match error.kind() {
            std::num::IntErrorKind::InvalidDigit => return Err("invalid digit found in string".to_string()),
            std::num::IntErrorKind::PosOverflow => return Err("number too large".to_string()),
            _other_error => return Err(format!("Could not parse: {:?}", error)),
        }
    };
    if length >= 4u8 && length <= 24u8
    {
        return Ok(length);
    }
    return Err("Password length should be between 4 and 24 characters.".to_string());
}

fn main()
{
    let args = Args::parse();
    let storage_path = if args.storage.is_some() { args.storage.unwrap() } else { get_default_storage_path() };

    match &args.command
    {
        Commands::SetMaster {assume_yes} =>
        {
            if !assume_yes && storage_path.exists()
            {
                let allow = question::Question::new("Changing master password will remove all existing data. Continue?")
                        .default(question::Answer::NO)
                        .confirm();
                if allow == question::Answer::NO
                {
                    process::exit(0);
                }
            }

            let master_password = rpassword::prompt_password("New master password: ").unwrap();
            if master_password.len() < 6
            {
                eprintln!("Master password length should be at least 6 characters.");
                process::exit(1);
            }

            let master_password2 = rpassword::prompt_password("Repeat master password: ").unwrap();
            if master_password != master_password2
            {
                eprintln!("Master passwords don't match.");
                process::exit(1);
            }

            master_password::change_password(&storage_path, &master_password);
            eprintln!("New master password set for {}.", storage_path.to_string_lossy());
        }

        Commands::Generate {domain, name, revision, length, no_lower, no_upper, no_digit, no_symbol} =>
        {
            let mut charset = crypto::new_charset();
            if !no_lower
            {
                charset.insert(crypto::CharacterType::LOWER);
            }
            if !no_upper
            {
                charset.insert(crypto::CharacterType::UPPER);
            }
            if !no_digit
            {
                charset.insert(crypto::CharacterType::DIGIT);
            }
            if !no_symbol
            {
                charset.insert(crypto::CharacterType::SYMBOL);
            }
            if charset.len() == 0
            {
                eprintln!("You need to allow at least one character set.");
                process::exit(1);
            }

            let master_password = rpassword::prompt_password("Your master password: ").unwrap();
            let password = crypto::derive_password(&master_password, &domain, &name, &revision, usize::from(*length), charset);
            println!("Password generated");
            println!("{}", password);
        }
    }
}
