/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use clap::{Parser, Subcommand};
use pfp::error::Error;
use pfp::recovery_codes;
use pfp::storage_types::{CharacterSet, CharacterType, Password, Site};
use pfp::{passwords, storage_io};
use std::path;

use io_streams::{StreamReader, StreamWriter};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::io::{Read, Write};

/// PfP: Pain-free Passwords, command line edition
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Data storage file path
    #[clap(parse(from_os_str), short = 'c', long)]
    storage: Option<path::PathBuf>,
    /// Integration tests only: read passwords from stdin
    #[clap(long, hide = true)]
    stdin_passwords: bool,
    /// Integration tests only: lock passwords and wait when done
    #[clap(long, hide = true)]
    wait: bool,
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set a new master password
    SetMaster {
        /// Do not prompt before overwriting data
        #[clap(short = 'y', long)]
        assume_yes: bool,
    },
    /// Adds a generated password to the storage
    Add {
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
        assume_yes: bool,
    },
    /// Stores a verbatim password in the storage
    AddStored {
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
        assume_yes: bool,
    },
    /// Removes a password from the storage
    Remove {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
    },
    /// Retrieves a password and displays it
    Show {
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
    /// Shows or sets the notes for a password
    Notes {
        /// Website name to generate password for
        domain: String,
        /// User name associated with the account
        name: String,
        /// Password revision
        #[clap(short = 'r', long, default_value = "1")]
        revision: String,
        /// Set notes for this password
        #[clap(short = 's', long)]
        set: bool,
    },
    /// Lists passwords for a website
    List {
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
    SetAlias {
        /// Website name to become an alias
        domain: String,
        /// Website name the domain should be equivalent to
        alias: String,
    },
    /// Makes a website no longer be an alias
    RemoveAlias {
        /// Website name that is an alias
        domain: String,
    },
}

fn prompt_password(prompt: &str, stdin_passwords: bool) -> SecretString {
    let secret = if stdin_passwords {
        StreamWriter::stdout()
            .unwrap()
            .write_all(prompt.as_bytes())
            .unwrap();

        let mut byte_buffer = [0];
        let mut buffer = Vec::with_capacity(1024);
        let mut stdin = StreamReader::stdin().unwrap();
        while let Ok(1) = stdin.read(&mut byte_buffer) {
            if byte_buffer[0] == b'\n' {
                break;
            }
            buffer.push(byte_buffer[0]);
        }

        let input = SecretVec::new(buffer);
        SecretString::new(
            std::str::from_utf8(input.expose_secret().as_slice())
                .unwrap()
                .to_owned(),
        )
    } else {
        SecretString::new(rpassword::prompt_password(prompt).unwrap())
    };
    SecretString::new(secret.expose_secret().trim().to_owned())
}

fn format_error(error: &Error) -> String {
    match error {
        Error::CreateDirFailure { error } => {
            format!("Failed creating directory for storage ({}).", error)
        }
        Error::FileReadFailure { error } => format!(
            "Failed reading storage file ({}). Maybe use set-master subcommand first?",
            error
        ),
        Error::FileWriteFailure { error } => format!("Failed writing storage file ({}).", error),
        Error::StorageNotInitialized => {
            "Storage is missing data. Maybe use set-master subcommand first?".to_string()
        }
        Error::UnexpectedStorageFormat => "Unexpected storage file format.".to_string(),
        Error::PasswordsLocked => "Passwords are locked.".to_string(),
        Error::KeyMissing => "No such value in storage.".to_string(),
        Error::UnexpectedData => "Unexpected JSON data in storage.".to_string(),
        Error::InvalidCiphertext => "Corrupt ciphertext data in storage.".to_string(),
        Error::InvalidBase64 { error } => format!("Corrupt Base64 data in storage ({}).", error),
        Error::InvalidJson { error } => format!("Corrupt JSON data in storage ({}).", error),
        Error::InvalidUtf8 { error } => format!("Corrupt UTF-8 data in storage ({}).", error),
        Error::DecryptionFailure => "Decryption failure, wrong master password?".to_string(),
        Error::NoSuchAlias => "Site is not an alias.".to_string(),
        Error::AliasToSelf => "Cannot make a site an alias for itself.".to_string(),
        Error::SiteHasPasswords => {
            "Site has passwords, remove before making it an alias.".to_string()
        }
        Error::RecoveryCodeExtraData { line } => format!(
            "Error in recovery code, extra data starting with line {}.",
            line
        ),
        Error::RecoveryCodeChecksumMismatch { line } => format!(
            "Error in recovery code, checksum mismatch in line {}.",
            line
        ),
        Error::RecoveryCodeIncomplete => "Error in recovery code, code is incomplete.".to_string(),
        Error::RecoveryCodeWrongVersion => {
            "Wrong recovery code version, generated by a newer application version?".to_string()
        }
        Error::RecoveryCodeInsufficientData => "Not enough data in the recovery code.".to_string(),
    }
}

trait ConvertError<T> {
    fn convert_error(self) -> Result<T, String>;
}

impl<T> ConvertError<T> for Result<T, Error> {
    fn convert_error(self) -> Result<T, String> {
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err(format_error(&error)),
        }
    }
}

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
    }
}

fn get_default_storage_path() -> path::PathBuf {
    let app_info = app_dirs2::AppInfo {
        name: "PfP",
        author: "Wladimir Palant",
    };
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("storage.json");
    path
}

fn ensure_unlocked_passwords<IO: storage_io::StorageIO>(
    passwords: &mut passwords::Passwords<IO>,
    stdin_passwords: bool,
) -> Result<(), String> {
    if !passwords.initialized() {
        return Err(format_error(&Error::StorageNotInitialized));
    }

    while !passwords.unlocked() {
        let master_password = prompt_password("Your master password: ", stdin_passwords);
        if master_password.expose_secret().len() < 6 {
            eprintln!("Master password length should be at least 6 characters.");
        } else {
            passwords
                .unlock(master_password)
                .unwrap_or_else(|error| eprintln!("{}", format_error(&error)));
        }
    }
    Ok(())
}

fn validate_length(arg: &str) -> Result<(), String> {
    if let Ok(length) = arg.parse::<usize>() {
        if !(4..=24).contains(&length) {
            return Err("Password length should be between 4 and 24 characters.".to_string());
        }
    };
    Ok(())
}

fn prompt_recovery_code<IO: storage_io::StorageIO>(
    passwords: &passwords::Passwords<IO>,
) -> Result<SecretString, String> {
    let mut accepted = String::new();
    loop {
        if let Some(question::Answer::RESPONSE(line)) =
            question::Question::new("Next line of your recovery code (empty line to abort):").ask()
        {
            if line.is_empty() {
                return Err(String::new());
            }

            let code = String::from(&accepted) + &line;
            let formatted = recovery_codes::format_code(code.as_bytes(), true);
            match passwords.decode_recovery_code(&code) {
                Ok(value) => return Ok(value),
                Err(error) => match error {
                    Error::RecoveryCodeExtraData { line } => {
                        accepted = formatted.split('\n').collect::<Vec<&str>>()[..line].join("\n");

                        let query = format!("The following seems to be a valid recovery code:\n{}\nYou entered some additional data however. Ignore the extra data and decode the recovery code?", &accepted);
                        let accept = question::Question::new(&query)
                            .default(question::Answer::YES)
                            .show_defaults()
                            .confirm();
                        if accept == question::Answer::YES {
                            return passwords.decode_recovery_code(&accepted).convert_error();
                        } else {
                            return Err(String::new());
                        }
                    }
                    Error::RecoveryCodeChecksumMismatch { line } => {
                        accepted = formatted.split('\n').collect::<Vec<&str>>()[..line].join("\n");
                        if accepted.is_empty() {
                            eprintln!(
                                "The data you entered doesn't seem valid, please try again.\n"
                            );
                        } else {
                            eprintln!("The following lines were accepted:\n{}\nThe line after that doesn't seem valid, a typo maybe?\n", &accepted);
                        }
                    }
                    Error::RecoveryCodeIncomplete => {
                        accepted = formatted;
                        eprintln!("Line accepted. The recovery code is still incomplete, please enter more data.\n");
                    }
                    unknown_error => {
                        return Err(format_error(&unknown_error));
                    }
                },
            }
        }
    }
}

fn main_inner(args: Args) -> Result<(), String> {
    let storage_path = match args.storage {
        Some(value) => value,
        None => get_default_storage_path(),
    };

    let io = if let Commands::SetMaster { assume_yes } = &args.command {
        match storage_io::FileIO::load(&storage_path) {
            Ok(io) => {
                if !assume_yes {
                    let allow = question::Question::new(
                        "Changing master password will remove all existing data. Continue?",
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
            Err(_) => storage_io::FileIO::new(&storage_path),
        }
    } else {
        storage_io::FileIO::load(&storage_path).convert_error()?
    };
    let mut passwords = passwords::Passwords::new(io);

    match &args.command {
        Commands::SetMaster { .. } => {
            let master_password = prompt_password("New master password: ", args.stdin_passwords);
            if master_password.expose_secret().len() < 6 {
                return Err("Master password length should be at least 6 characters.".to_owned());
            }

            let master_password2 =
                prompt_password("Repeat master password: ", args.stdin_passwords);
            if master_password.expose_secret() != master_password2.expose_secret() {
                return Err("Master passwords don't match.".to_owned());
            }

            passwords.reset(master_password).convert_error()?;
            println!(
                "New master password set for {}.",
                storage_path.to_string_lossy()
            );
        }

        Commands::Add {
            domain,
            name,
            revision,
            length,
            no_lower,
            no_upper,
            no_digit,
            no_symbol,
            assume_yes,
        } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            let mut charset = CharacterSet::empty();
            if !no_lower {
                charset.insert(CharacterType::Lower);
            }
            if !no_upper {
                charset.insert(CharacterType::Upper);
            }
            if !no_digit {
                charset.insert(CharacterType::Digit);
            }
            if !no_symbol {
                charset.insert(CharacterType::Symbol);
            }
            if charset.is_empty() {
                return Err("You need to allow at least one character set.".to_owned());
            }

            if !assume_yes && passwords.has(domain, name, revision).unwrap_or(false) {
                let allow = question::Question::new("A password with this domain/name/revision combination already exists. Overwrite?")
                        .default(question::Answer::NO)
                        .show_defaults()
                        .confirm();
                if allow == question::Answer::NO {
                    return Ok(());
                }
            }

            passwords
                .set_generated(domain, name, revision, *length, charset)
                .convert_error()?;
            println!("Password added.");
        }

        Commands::AddStored {
            domain,
            name,
            revision,
            recovery,
            assume_yes,
        } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            if !assume_yes && passwords.has(domain, name, revision).unwrap_or(false) {
                let allow = question::Question::new("A password with this domain/name/revision combination already exists. Overwrite?")
                        .default(question::Answer::NO)
                        .show_defaults()
                        .confirm();
                if allow == question::Answer::NO {
                    return Ok(());
                }
            }

            let password = if *recovery {
                prompt_recovery_code(&passwords)?
            } else {
                prompt_password("Password to be stored: ", args.stdin_passwords)
            };
            passwords
                .set_stored(domain, name, revision, password)
                .convert_error()?;
            println!("Password added.");
        }

        Commands::Remove {
            domain,
            name,
            revision,
        } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            passwords.remove(domain, name, revision).convert_error()?;
            println!("Password removed.");
        }

        Commands::Show {
            domain,
            name,
            revision,
            qrcode,
        } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            let password = passwords.get(domain, name, revision).convert_error()?;
            let mut stdout = StreamWriter::stdout().unwrap();
            stdout.write_all(b"Password retrieved.").unwrap();
            if *qrcode {
                const BLOCKS: [&str; 4] = [" ", "\u{2580}", "\u{2584}", "\u{2588}"];

                match qrcodegen::QrCode::encode_text(
                    password.expose_secret(),
                    qrcodegen::QrCodeEcc::Low,
                ) {
                    Ok(qr) => {
                        for y in (0..qr.size()).step_by(2) {
                            for x in 0..qr.size() {
                                let index = if qr.get_module(x, y) { 1 } else { 0 }
                                    | if qr.get_module(x, y + 1) { 2 } else { 0 };
                                stdout.write_all(BLOCKS[index].as_bytes()).unwrap();
                            }
                            stdout.write_all(b"\n").unwrap();
                        }
                    }
                    Err(error) => {
                        return Err(format!("Error generating QR code: {}", error));
                    }
                }
            } else {
                stdout.write_all(password.expose_secret().as_bytes()).unwrap();
                stdout.write_all(b"\n").unwrap();
            }
        }

        Commands::Notes {
            domain,
            name,
            revision,
            set,
        } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            let notes = passwords
                .get_notes(domain, name, revision)
                .convert_error()?;
            if notes.expose_secret().is_empty() {
                println!("Currently no notes are stored for this password.");
            } else {
                let mut stdout = StreamWriter::stdout().unwrap();
                stdout.write_all(b"Notes for this password: ").unwrap();
                stdout.write_all(notes.expose_secret().as_bytes()).unwrap();
                stdout.write_all(b"\n").unwrap();
            }

            if *set {
                if let Some(question::Answer::RESPONSE(notes)) =
                    question::Question::new("Please enter new notes to be stored:").ask()
                {
                    let removing = notes.is_empty();
                    passwords
                        .set_notes(domain, name, revision, SecretString::new(notes))
                        .convert_error()?;
                    if removing {
                        println!("Notes removed.");
                    } else {
                        println!("Notes stored.");
                    }
                }
            }
        }

        Commands::List {
            domain,
            name,
            show,
            recovery,
            verbose,
        } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            let mut empty_sites = Vec::new();

            let mut sites = passwords.list_sites(domain).collect::<Vec<Site>>();
            let mut additions = Vec::new();
            for site in sites.iter() {
                if let Some(alias) = site.alias() {
                    additions.push(Site::new(alias, None));
                }
            }
            sites.append(&mut additions);
            sites.sort_by_key(|site| site.name().to_owned());
            sites.dedup_by_key(|site| site.name().to_owned());

            let mut aliases = std::collections::HashMap::new();
            sites.retain(|site| match site.alias() {
                Some(alias) => {
                    if !aliases.contains_key(alias) {
                        aliases.insert(alias.to_owned(), Vec::new());
                    }
                    aliases
                        .get_mut(alias)
                        .unwrap()
                        .push(site.name().to_string());
                    false
                }
                None => true,
            });

            let mut found = false;
            for site in sites {
                let mut list = passwords.list(site.name(), name).collect::<Vec<Password>>();
                if list.is_empty() {
                    if name == "*" {
                        empty_sites.push(site.name().to_string());
                    }
                    continue;
                }

                found = true;
                println!("Passwords for {}:", site.name());
                if *verbose {
                    if let Some(aliased) = aliases.get(site.name()) {
                        println!("    Aliases: {}", aliased.join(",\n             "));
                    }
                }

                list.sort_by_key(|password| {
                    password.id().name().to_string() + " " + password.id().revision()
                });
                for password in list {
                    let name = password.id().name().to_owned();
                    let revision = password.id().revision().to_owned();
                    let password_type = match &password {
                        Password::Generated(_) => "generated",
                        Password::Stored(_) => "stored",
                    };
                    if !revision.is_empty() {
                        println!("    {} ({}, revision: {})", name, password_type, revision);
                    } else {
                        println!("    {} ({})", name, password_type);
                    }

                    if *show {
                        print!("        ");
                        std::io::stdout().flush().unwrap();
                        StreamWriter::stdout()
                            .unwrap()
                            .write_all(
                                passwords
                                    .get(site.name(), &name, &revision)
                                    .convert_error()?
                                    .expose_secret()
                                    .as_bytes(),
                            )
                            .unwrap();
                        println!();
                    }

                    if *recovery {
                        if let Password::Stored(password) = &password {
                            println!("        Recovery code:");
                            for line in passwords
                                .get_recovery_code(password)
                                .convert_error()?
                                .split('\n')
                            {
                                println!("        {}", line);
                            }
                        }
                    }

                    if *verbose {
                        let notes = password.notes();
                        if !notes.expose_secret().is_empty() {
                            print!("        Notes: ");
                            std::io::stdout().flush().unwrap();
                            StreamWriter::stdout()
                                .unwrap()
                                .write_all(notes.expose_secret().as_bytes())
                                .unwrap();
                            println!();
                        }

                        if let Password::Generated(password) = &password {
                            println!("        Length: {}", password.length());

                            let mut chars = Vec::new();
                            if password.charset().contains(CharacterType::Lower) {
                                chars.push("abc");
                            }
                            if password.charset().contains(CharacterType::Upper) {
                                chars.push("ABC");
                            }
                            if password.charset().contains(CharacterType::Digit) {
                                chars.push("789");
                            }
                            if password.charset().contains(CharacterType::Symbol) {
                                chars.push("+^;");
                            }
                            println!("        Allowed characters: {}", chars.join(" "));
                        }
                    }
                }
            }

            passwords.remove_sites(&empty_sites).convert_error()?;

            if !found {
                println!("No matching passwords found.");
            }
        }

        Commands::SetAlias { domain, alias } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            passwords.set_alias(domain, alias).convert_error()?;
            println!("Alias added.");
        }

        Commands::RemoveAlias { domain } => {
            ensure_unlocked_passwords(&mut passwords, args.stdin_passwords)?;

            passwords.remove_alias(domain).convert_error()?;
            println!("Alias removed.");
        }
    }
    Ok(())
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let _shutdown = Shutdown::new(args.wait);
    if let Err(error) = main_inner(args) {
        eprintln!("{}", error);
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}
