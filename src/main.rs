/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod crypto;
mod error;
mod passwords;
mod storage;
mod storage_io;
mod storage_types;

use app_dirs2;
use clap::{Parser, Subcommand};
use question;
use rpassword;
use std::fmt;
use std::path;
use std::process;
use storage_types::{Password};
use error::Error;

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
    Add
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
    /// Removes a password from the storage
    Remove
    {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
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
    /// Lists passwords for a website
    List
    {
        /// Website name to list passwords for (can be a wildcard pattern)
        #[clap(default_value = "*")]
        domain: String,
        /// User name wildcard pattern
        #[clap(default_value = "*")]
        name: String,
    },
    /// Sets an alias for a website
    SetAlias
    {
        /// Website name to become an alias
        domain: String,
        /// Website name the domain should be equivalent to
        alias: String,
    },
    /// Makes a website no longer be an alias
    RemoveAlias
    {
        /// Website name that is an alias
        domain: String,
    },
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Error::CreateDirFailure { error } => write!(f, "Failed creating directory for storage ({}).", *error),
            Error::FileReadFailure { error } => write!(f, "Failed reading storage file ({}). Maybe use set-master subcommand first?", *error),
            Error::FileWriteFailure { error } => write!(f, "Failed writing storage file ({}).", *error),
            Error::StorageNotInitialized => write!(f, "Unexpected: Storage is being accessed before initialization."),
            Error::UnexpectedStorageFormat => write!(f, "Unexpected storage file format."),
            Error::PasswordsLocked => write!(f, "Passwords are locked."),
            Error::KeyMissing => write!(f, "No such value in storage."),
            Error::UnexpectedData => write!(f, "Unexpected JSON data in storage."),
            Error::InvalidCiphertext => write!(f, "Corrupt ciphertext data in storage."),
            Error::InvalidBase64 { error } => write!(f, "Corrupt Base64 data in storage ({}).", error),
            Error::InvalidJson { error } => write!(f, "Corrupt JSON data in storage ({}).", error),
            Error::InvalidUtf8 { error } => write!(f, "Corrupt UTF-8 data in storage ({}).", error),
            Error::DecryptionFailure => write!(f, "Decryption failure, wrong master password?"),
            Error::PasswordMissingType => write!(f, "Corrupt data, missing password type."),
            Error::PasswordUnknownType => write!(f, "Unknown password type."),
            Error::PasswordMissingSite => write!(f, "Corrupt data, missing password site."),
            Error::PasswordMissingName => write!(f, "Corrupt data, missing password name."),
            Error::PasswordMissingRevision => write!(f, "Corrupt data, missing password revision."),
            Error::PasswordMissingLength => write!(f, "Corrupt data, missing password length."),
            Error::PasswordMissingValue => write!(f, "Corrupt data, missing password value."),
            Error::SiteMissingName => write!(f, "Corrupt data, missing site name."),
            Error::NoSuchAlias => write!(f, "Site is not an alias."),
            Error::AliasToSelf => write!(f, "Cannot make a site an alias for itself."),
            Error::SiteHasPasswords => write!(f, "Site has passwords, remove before making it an alias."),
        }
    }
}

trait HandleError<T>
{
    fn handle_error(self) -> T;
}

impl<T> HandleError<T> for Result<T, Error>
{
    fn handle_error(self) -> T
    {
        match self
        {
            Ok(value) => return value,
            Err(error) =>
            {
                eprintln!("{}", error);
                process::exit(1);
            }
        };
    }
}

impl<T> HandleError<T> for Result<T, &Error>
{
    fn handle_error(self) -> T
    {
        match self
        {
            Ok(value) => return value,
            Err(error) =>
            {
                eprintln!("{}", *error);
                process::exit(1);
            }
        };
    }
}

fn get_default_storage_path() -> path::PathBuf
{
    let app_info = app_dirs2::AppInfo {name: "PfP", author: "Wladimir Palant"};
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("storage.json");
    return path;
}

fn ensure_unlocked_passwords<IO: storage_io::StorageIO>(passwords: &mut passwords::Passwords<IO>)
{
    passwords.initialized().handle_error();

    while passwords.unlocked().is_err()
    {
        let master_password = rpassword::prompt_password("Your master password: ").unwrap();
        if master_password.len() < 6
        {
            eprintln!("Master password length should be at least 6 characters.");
        }
        else
        {
            passwords.unlock(&master_password).unwrap_or_else(|error| eprintln!("{}", error));
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
    let storage_path = match args.storage {
        Some(value) => value,
        None => get_default_storage_path(),
    };
    let storage = storage::Storage::new(storage_io::FileIO::new(&storage_path));
    let mut passwords = passwords::Passwords::new(storage);

    match &args.command
    {
        Commands::SetMaster {assume_yes} =>
        {
            if !assume_yes && passwords.initialized().is_ok()
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

            passwords.reset(&master_password).handle_error();
            println!("New master password set for {}.", storage_path.to_string_lossy());
        }

        Commands::Add {domain, name, revision, length, no_lower, no_upper, no_digit, no_symbol, force} =>
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

            passwords.set_generated(domain, name, revision, *length, charset).handle_error();
            println!("Password added.");
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
            passwords.set_stored(domain, name, revision, &password).handle_error();
            println!("Password added.");
        }

        Commands::Remove {domain, name, revision} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            passwords.remove(domain, name, revision).handle_error();
            println!("Password removed.");
        }

        Commands::Password {domain, name, revision} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            let password = passwords.get(domain, name, revision).handle_error();
            println!("Password retrieved.");
            println!("{}", password);
        }

        Commands::List {domain, name} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            let mut empty_sites = Vec::new();

            let mut found = false;
            for site in passwords.list_sites(domain)
            {
                let mut empty = true;
                for password in passwords.list(&site, name)
                {
                    if empty
                    {
                        empty = false;
                        println!("Passwords for {}:", site);
                    }

                    let name;
                    let revision;
                    let password_type;
                    match password
                    {
                        Password::Generated { password } =>
                        {
                            name = password.id().name().to_owned();
                            revision = password.id().revision().to_owned();
                            password_type = "generated";
                        }
                        Password::Stored { password } =>
                        {
                            name = password.id().name().to_owned();
                            revision = password.id().revision().to_owned();
                            password_type = "stored";
                        }
                    }
                    if revision != ""
                    {
                        println!("    {} #{} ({})", name, revision, password_type);
                    }
                    else
                    {
                        println!("    {} ({})", name, password_type);
                    }
                }

                if empty
                {
                    empty_sites.push(site);
                }
                else
                {
                    found = true;
                }
            }

            passwords.remove_sites(&empty_sites).handle_error();

            if !found
            {
                println!("No matching passwords found.");
            }
        }

        Commands::SetAlias {domain, alias} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            passwords.set_alias(&domain, &alias).handle_error();
            println!("Alias added.");
        }

        Commands::RemoveAlias {domain} =>
        {
            ensure_unlocked_passwords(&mut passwords);

            passwords.remove_alias(&domain).handle_error();
            println!("Alias removed.");
        }
    }
}
