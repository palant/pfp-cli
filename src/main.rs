/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use clap::{Parser, Subcommand};
use pfp::{passwords, storage_io};
use pfp::error::Error;
use pfp::recovery_codes;
use pfp::storage_types::{Password, Site, CharacterType, CharacterSet};
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
    /// Integration tests only: read passwords from stdin
    #[clap(long, hide = true)]
    stdin_passwords: bool,
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
        #[clap(short = 'l', long, default_value_t = 16, validator = validate_length)]
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
        /// Do not prompt before overwriting existing passwords
        #[clap(short = 'y', long)]
        assume_yes: bool
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
        /// Use a recovery code
        #[clap(short = 'c', long)]
        recovery: bool,
        /// Do not prompt before overwriting existing passwords
        #[clap(short = 'y', long)]
        assume_yes: bool
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
    /// Retrieves a password and displays it
    Show
    {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
        /// Output the password as a QR code
        #[clap(short = 'q', long)]
        qrcode: bool,
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
        /// Show password values (can be slow)
        #[clap(short = 's', long)]
        show: bool,
        /// Show recovery codes for stored passwords
        #[clap(short = 'r', long)]
        recovery: bool,
        /// Show site aliases and password generation parameters
        #[clap(short = 'v', long)]
        verbose: bool,
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

fn prompt_password(prompt: &str, stdin_passwords: bool) -> String
{
    if stdin_passwords
    {
        use std::io::Write;
        let mut input = String::new();
        std::io::stdout().write_all(prompt.as_bytes()).unwrap();
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut input).unwrap();
        input.trim().to_string()
    }
    else
    {
        rpassword::prompt_password(prompt).unwrap()
    }
}

fn format_error(error: &Error) -> String
{
    match error
    {
        Error::CreateDirFailure { error } => format!("Failed creating directory for storage ({}).", *error),
        Error::FileReadFailure { error } => format!("Failed reading storage file ({}). Maybe use set-master subcommand first?", *error),
        Error::FileWriteFailure { error } => format!("Failed writing storage file ({}).", *error),
        Error::StorageNotInitialized => "Unexpected: Storage is being accessed before initialization.".to_string(),
        Error::UnexpectedStorageFormat => "Unexpected storage file format.".to_string(),
        Error::PasswordsLocked => "Passwords are locked.".to_string(),
        Error::KeyMissing => "No such value in storage.".to_string(),
        Error::UnexpectedData => "Unexpected JSON data in storage.".to_string(),
        Error::InvalidCiphertext => "Corrupt ciphertext data in storage.".to_string(),
        Error::InvalidBase64 { error } => format!("Corrupt Base64 data in storage ({}).", error),
        Error::InvalidJson { error } => format!("Corrupt JSON data in storage ({}).", error),
        Error::InvalidUtf8 { error } => format!("Corrupt UTF-8 data in storage ({}).", error),
        Error::DecryptionFailure => "Decryption failure, wrong master password?".to_string(),
        Error::PasswordMissingType => "Corrupt data, missing password type.".to_string(),
        Error::PasswordUnknownType => "Unknown password type.".to_string(),
        Error::PasswordMissingSite => "Corrupt data, missing password site.".to_string(),
        Error::PasswordMissingName => "Corrupt data, missing password name.".to_string(),
        Error::PasswordMissingRevision => "Corrupt data, missing password revision.".to_string(),
        Error::PasswordMissingLength => "Corrupt data, missing password length.".to_string(),
        Error::PasswordMissingValue => "Corrupt data, missing password value.".to_string(),
        Error::SiteMissingName => "Corrupt data, missing site name.".to_string(),
        Error::NoSuchAlias => "Site is not an alias.".to_string(),
        Error::AliasToSelf => "Cannot make a site an alias for itself.".to_string(),
        Error::SiteHasPasswords => "Site has passwords, remove before making it an alias.".to_string(),
        Error::RecoveryCodeExtraData { line } => format!("Error in recovery code, extra data starting with line {}.", line),
        Error::RecoveryCodeChecksumMismatch { line } => format!("Error in recovery code, checksum mismatch in line {}.", line),
        Error::RecoveryCodeIncomplete => "Error in recovery code, code is incomplete.".to_string(),
        Error::RecoveryCodeWrongVersion => "Wrong recovery code version, generated by a newer application version?".to_string(),
        Error::RecoveryCodeInsufficientData => "Not enough data in the recovery code.".to_string(),
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
            Ok(value) => value,
            Err(error) =>
            {
                eprintln!("{}", format_error(&error));
                process::exit(1);
            }
        }
    }
}

fn get_default_storage_path() -> path::PathBuf
{
    let app_info = app_dirs2::AppInfo {name: "PfP", author: "Wladimir Palant"};
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("storage.json");
    path
}

fn ensure_unlocked_passwords<IO: storage_io::StorageIO>(passwords: &mut passwords::Passwords<IO>, stdin_passwords: bool)
{
    while !passwords.unlocked()
    {
        let master_password = prompt_password("Your master password: ", stdin_passwords);
        if master_password.len() < 6
        {
            eprintln!("Master password length should be at least 6 characters.");
        }
        else
        {
            passwords.unlock(&master_password).unwrap_or_else(|error| eprintln!("{}", format_error(&error)));
        }
    }
}

fn validate_length(arg: &str) -> Result<(), String>
{
    if let Ok(length) = arg.parse::<usize>()
    {
        if !(4..=24).contains(&length)
        {
            return Err("Password length should be between 4 and 24 characters.".to_string());
        }
    };
    Ok(())
}

fn prompt_recovery_code<IO: storage_io::StorageIO>(passwords: &passwords::Passwords<IO>) -> String
{
    let mut accepted = String::new();
    loop
    {
        if let Some(question::Answer::RESPONSE(line)) = question::Question::new("Next line of your recovery code (empty line to abort):").ask()
        {
            if line.is_empty()
            {
                process::exit(0);
            }

            let code = String::from(&accepted) + &line;
            let formatted = recovery_codes::format_code(code.as_bytes(), true);
            match passwords.decode_recovery_code(&code)
            {
                Ok(value) => return value,
                Err(error) =>
                {
                    match error
                    {
                        Error::RecoveryCodeExtraData { line } =>
                        {
                            accepted = formatted.split('\n').collect::<Vec<&str>>()[..line].join("\n");

                            let query = format!("The following seems to be a valid recovery code:\n{}\nYou entered some additional data however. Ignore the extra data and decode the recovery code?", &accepted);
                            let accept = question::Question::new(&query)
                                    .default(question::Answer::YES)
                                    .show_defaults()
                                    .confirm();
                            if accept == question::Answer::YES
                            {
                                return passwords.decode_recovery_code(&accepted).handle_error();
                            }
                            else
                            {
                                process::exit(0);
                            }
                        },
                        Error::RecoveryCodeChecksumMismatch { line } =>
                        {
                            accepted = formatted.split('\n').collect::<Vec<&str>>()[..line].join("\n");
                            if accepted.is_empty()
                            {
                                eprintln!("The data you entered doesn't seem valid, please try again.\n");
                            }
                            else
                            {
                                eprintln!("The following lines were accepted:\n{}\nThe line after that doesn't seem valid, a typo maybe?\n", &accepted);
                            }
                        },
                        Error::RecoveryCodeIncomplete =>
                        {
                            accepted = formatted;
                            eprintln!("Line accepted. The recovery code is still incomplete, please enter more data.\n");
                        },
                        unknown_error =>
                        {
                            eprintln!("{}", format_error(&unknown_error));
                            process::exit(1);
                        }
                    }
                }
            }
        }
    }
}

fn main()
{
    let args = Args::parse();
    let storage_path = match args.storage {
        Some(value) => value,
        None => get_default_storage_path(),
    };
    let mut passwords = if let Commands::SetMaster { assume_yes } = &args.command
    {
        match passwords::Passwords::new(storage_io::FileIO::new(&storage_path))
        {
            Ok(passwords) =>
            {
                if !assume_yes
                {
                    let allow = question::Question::new("Changing master password will remove all existing data. Continue?")
                            .default(question::Answer::NO)
                            .show_defaults()
                            .confirm();
                    if allow == question::Answer::NO
                    {
                        process::exit(0);
                    }
                }
                passwords
            },
            Err(_) => passwords::Passwords::uninitialized(storage_io::FileIO::new(&storage_path)),
        }
    }
    else
    {
        passwords::Passwords::new(storage_io::FileIO::new(&storage_path)).handle_error()
    };

    match &args.command
    {
        Commands::SetMaster {..} =>
        {
            let master_password = prompt_password("New master password: ", args.stdin_passwords);
            if master_password.len() < 6
            {
                eprintln!("Master password length should be at least 6 characters.");
                process::exit(1);
            }

            let master_password2 = prompt_password("Repeat master password: ", args.stdin_passwords);
            if master_password != master_password2
            {
                eprintln!("Master passwords don't match.");
                process::exit(1);
            }

            passwords.reset(&master_password).handle_error();
            println!("New master password set for {}.", storage_path.to_string_lossy());
        }

        Commands::Add {domain, name, revision, length, no_lower, no_upper, no_digit, no_symbol, assume_yes} =>
        {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            let mut charset = CharacterSet::empty();
            if !no_lower
            {
                charset.insert(CharacterType::Lower);
            }
            if !no_upper
            {
                charset.insert(CharacterType::Upper);
            }
            if !no_digit
            {
                charset.insert(CharacterType::Digit);
            }
            if !no_symbol
            {
                charset.insert(CharacterType::Symbol);
            }
            if charset.is_empty()
            {
                eprintln!("You need to allow at least one character set.");
                process::exit(1);
            }

            if !assume_yes && passwords.has(domain, name, revision).unwrap_or(false)
            {
                let allow = question::Question::new("A password with this domain/name/revision combination already exists. Overwrite?")
                        .default(question::Answer::NO)
                        .show_defaults()
                        .confirm();
                if allow == question::Answer::NO
                {
                    process::exit(0);
                }
            }

            passwords.set_generated(domain, name, revision, *length, charset).handle_error();
            println!("Password added.");
        }

        Commands::AddStored {domain, name, revision, recovery, assume_yes} =>
        {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            if !assume_yes && passwords.has(domain, name, revision).unwrap_or(false)
            {
                let allow = question::Question::new("A password with this domain/name/revision combination already exists. Overwrite?")
                        .default(question::Answer::NO)
                        .show_defaults()
                        .confirm();
                if allow == question::Answer::NO
                {
                    process::exit(0);
                }
            }

            let password = if *recovery
            {
                prompt_recovery_code(&passwords)
            }
            else
            {
                prompt_password("Password to be stored: ", args.stdin_passwords)
            };
            passwords.set_stored(domain, name, revision, &password).handle_error();
            println!("Password added.");
        }

        Commands::Remove {domain, name, revision} =>
        {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            passwords.remove(domain, name, revision).handle_error();
            println!("Password removed.");
        }

        Commands::Show {domain, name, revision, qrcode} =>
        {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            let password = passwords.get(domain, name, revision).handle_error();
            println!("Password retrieved.");
            if *qrcode
            {
                const BLOCKS: [char; 4] = [' ', '\u{2580}', '\u{2584}', '\u{2588}'];

                match qrcodegen::QrCode::encode_text(&password, qrcodegen::QrCodeEcc::Low)
                {
                    Ok(qr) =>
                    {
                        for y in (0 .. qr.size()).step_by(2)
                        {
                            for x in 0 .. qr.size()
                            {
                                let index = if qr.get_module(x, y) { 1 } else { 0 } | if qr.get_module(x, y + 1) { 2 } else { 0 };
                                print!("{}", BLOCKS[index]);
                            }
                            println!();
                        }
                    },
                    Err(error) =>
                    {
                        eprintln!("Error generating QR code: {}", error);
                        process::exit(1);
                    }
                }
            }
            else
            {
                println!("{}", password);
            }
        }

        Commands::List {domain, name, show, recovery, verbose} =>
        {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            let mut empty_sites = Vec::new();

            let mut sites = passwords.list_sites(domain).collect::<Vec<Site>>();
            let mut additions = Vec::new();
            for site in sites.iter()
            {
                if let Some(alias) = site.alias()
                {
                    additions.push(Site::new(alias, None));
                }
            }
            sites.append(&mut additions);
            sites.sort_by_key(|site| site.name().to_owned());
            sites.dedup_by_key(|site| site.name().to_owned());

            let mut aliases = std::collections::HashMap::new();
            sites.retain(|site|
            {
                match site.alias()
                {
                    Some(alias) =>
                    {
                        if !aliases.contains_key(alias)
                        {
                            aliases.insert(alias.to_owned(), Vec::new());
                        }
                        aliases.get_mut(alias).unwrap().push(site.name().to_string());
                        false
                    },
                    None => true,
                }
            });

            let mut found = false;
            for site in sites
            {
                let mut list = passwords.list(site.name(), name).collect::<Vec<Password>>();
                if list.is_empty()
                {
                    if name == "*"
                    {
                        empty_sites.push(site.name().to_string());
                    }
                    continue;
                }

                found = true;
                println!("Passwords for {}:", site.name());
                if *verbose
                {
                    if let Some(aliased) = aliases.get(site.name())
                    {
                        println!("    Aliases: {}", aliased.join(",\n             "));
                    }
                }

                list.sort_by_key(|password| password.id().name().to_string() + " " + password.id().revision());
                for password in list
                {
                    let name = password.id().name().to_owned();
                    let revision = password.id().revision().to_owned();
                    let password_type;
                    match &password
                    {
                        Password::Generated { .. } =>
                        {
                            password_type = "generated";
                        }
                        Password::Stored { .. } =>
                        {
                            password_type = "stored";
                        }
                    }
                    if !revision.is_empty()
                    {
                        println!("    {} ({}, revision: {})", name, password_type, revision);
                    }
                    else
                    {
                        println!("    {} ({})", name, password_type);
                    }

                    if *show
                    {
                        println!("        {}", passwords.get(site.name(), &name, &revision).handle_error());
                    }

                    if *recovery
                    {
                        if let Password::Stored { password } = &password
                        {
                            println!("        Recovery code:");
                            for line in passwords.get_recovery_code(password).handle_error().split('\n')
                            {
                                println!("        {}", line);
                            }
                        }
                    }

                    if *verbose
                    {
                        if let Password::Generated { password } = &password
                        {
                            println!("        Length: {}", password.length());

                            let mut chars = Vec::new();
                            if password.charset().contains(CharacterType::Lower)
                            {
                                chars.push("abc");
                            }
                            if password.charset().contains(CharacterType::Upper)
                            {
                                chars.push("ABC");
                            }
                            if password.charset().contains(CharacterType::Digit)
                            {
                                chars.push("789");
                            }
                            if password.charset().contains(CharacterType::Symbol)
                            {
                                chars.push("+^;");
                            }
                            println!("        Allowed characters: {}", chars.join(" "));
                        }
                    }
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
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            passwords.set_alias(domain, alias).handle_error();
            println!("Alias added.");
        }

        Commands::RemoveAlias {domain} =>
        {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords);

            passwords.remove_alias(domain).handle_error();
            println!("Alias removed.");
        }
    }
}
