/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod crypto;
mod storage;
mod passwords;

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
    /// Adds a generated password to the storage
    AddGenerated
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
        length: usize,
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
        /// Overwrite existing passwords if present
        #[clap(short = 'f', long)]
        force: bool,
    },
    /// Stores a verbatim password in the storage
    AddStored
    {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
        /// Overwrite existing passwords if present
        #[clap(short = 'f', long)]
        force: bool,
    },
    /// Retrieves a password
    Password
    {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
    },
    /// Lists passwords for a site
    List
    {
        /// Website name to list passwords for
        domain: String,
        /// User name wildcard
        #[clap(default_value = "*")]
        name: String,
    },
}

fn get_default_storage_path() -> path::PathBuf
{
    let app_info = app_dirs2::AppInfo {name: "PfP", author: "Wladimir Palant"};
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("storage.json");
    return path;
}

fn ensure_unlocked_passwords(passwords: &mut passwords::Passwords)
{
    if passwords.initialized().is_none()
    {
        eprintln!("Failed reading storage data from {}. Maybe use set-master subcommand first?", passwords.get_storage_path().to_string_lossy());
        process::exit(1);
    }

    while passwords.unlocked().is_none()
    {
        let master_password = rpassword::prompt_password("Your master password: ").unwrap();
        if master_password.len() < 6
        {
            eprintln!("Master password length should be at least 6 characters.");
        }
        else if passwords.unlock(&master_password).is_none()
        {
            eprintln!("This does not seem to be the correct master password.");
        }
    }
}

fn parse_length(arg: &str) -> Result<usize, String>
{
    let length = match arg.parse::<usize>()
    {
        Ok(length) => length,
        Err(error) => match error.kind() {
            std::num::IntErrorKind::InvalidDigit => return Err("invalid digit found in string".to_string()),
            std::num::IntErrorKind::PosOverflow => return Err("number too large".to_string()),
            _other_error => return Err(format!("Could not parse: {:?}", error)),
        }
    };
    if length >= 4 && length <= 24
    {
        return Ok(length);
    }
    return Err("Password length should be between 4 and 24 characters.".to_string());
}

fn main()
{
    let args = Args::parse();
    let storage_path = if args.storage.is_some() { args.storage.unwrap() } else { get_default_storage_path() };
    let mut passwords = passwords::Passwords::new(storage::Storage::new(&storage_path));

    match &args.command
    {
        Commands::SetMaster {assume_yes} =>
        {
            if !assume_yes && passwords.initialized().is_some()
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

            passwords.reset(&master_password);
            eprintln!("New master password set for {}.", storage_path.to_string_lossy());
        }

        Commands::AddGenerated {domain, name, revision, length, no_lower, no_upper, no_digit, no_symbol, force} =>
        {
            ensure_unlocked_passwords(&mut passwords);

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

            if !force && passwords.has(domain, name, revision).unwrap_or(false)
            {
                eprintln!("A password with this domain/name/revision combination already exists. Specify a different revision or use --force flag to overwrite.");
                process::exit(1);
            }

            passwords.set_generated(domain, name, revision, *length, charset);
            println!("Password added");
        }

        Commands::AddStored {domain, name, revision, force} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            if !force && passwords.has(domain, name, revision).unwrap_or(false)
            {
                eprintln!("A password with this domain/name/revision combination already exists. Specify a different revision or use --force flag to overwrite.");
                process::exit(1);
            }

            let password = rpassword::prompt_password("Password to be stored: ").unwrap();
            passwords.set_stored(domain, name, revision, &password);
            println!("Password added");
        }

        Commands::Password {domain, name, revision} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            let password = passwords.get(domain, name, revision);
            if password.is_none()
            {
                eprintln!("No password with the given domain/name/revision combination.");
                process::exit(1);
            }
            println!("Password retrieved");
            println!("{}", password.unwrap());
        }

        Commands::List {domain, name} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            for password in passwords.list(domain, name)
            {
                let name;
                let revision;
                let password_type;
                match password
                {
                    storage::Password::Generated { password } =>
                    {
                        name = password.id().name().to_owned();
                        revision = password.id().revision().to_owned();
                        password_type = "generated";
                    }
                    storage::Password::Stored { password } =>
                    {
                        name = password.id().name().to_owned();
                        revision = password.id().revision().to_owned();
                        password_type = "stored";
                    }
                }
                if revision != ""
                {
                    println!("{} #{} ({})", name, revision, password_type);
                }
                else
                {
                    println!("{} ({})", name, password_type);
                }
            }
        }
    }
}
