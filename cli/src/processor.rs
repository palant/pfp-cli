/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::args::{Args, Commands};
use io_streams::{StreamReader, StreamWriter};
use pfp::error::Error;
use pfp::passwords::Passwords;
use pfp::recovery_codes;
use pfp::storage_io;
use pfp::storage_types::{CharacterSet, CharacterType, Password, Site};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::io::{Read, Write};

fn format_error(error: &Error) -> String {
    match error {
        Error::CreateDirFailure { error } => {
            format!("Failed creating directory for storage ({}).", error)
        }
        Error::FileReadFailure { error } => format!(
            "Failed reading storage file ({}). Maybe use set-primary subcommand first?",
            error
        ),
        Error::FileWriteFailure { error } => format!("Failed writing storage file ({}).", error),
        Error::StorageNotInitialized => {
            "Storage is missing data. Maybe use set-primary subcommand first?".to_string()
        }
        Error::UnexpectedStorageFormat => "Unexpected storage file format.".to_string(),
        Error::PasswordsLocked => "Passwords are locked.".to_string(),
        Error::KeyMissing => "No such value in storage.".to_string(),
        Error::UnexpectedData => "Unexpected JSON data in storage.".to_string(),
        Error::InvalidCiphertext => "Corrupt ciphertext data in storage.".to_string(),
        Error::InvalidBase64 { error } => format!("Corrupt Base64 data in storage ({}).", error),
        Error::InvalidJson { error } => format!("Corrupt JSON data in storage ({}).", error),
        Error::InvalidUtf8 { error } => format!("Corrupt UTF-8 data in storage ({}).", error),
        Error::DecryptionFailure => "Decryption failure, wrong primary password?".to_string(),
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

pub trait ConvertError<T> {
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

fn prompt_secret_text(prompt: &str) -> SecretString {
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
}

fn prompt_password(prompt: &str, stdin_passwords: bool) -> SecretString {
    let secret = if stdin_passwords {
        prompt_secret_text(prompt)
    } else {
        SecretString::new(rpassword::prompt_password(prompt).unwrap())
    };
    SecretString::new(secret.expose_secret().trim().to_owned())
}

fn get_default_history_path() -> std::path::PathBuf {
    let app_info = app_dirs2::AppInfo {
        name: "PfP",
        author: "Wladimir Palant",
    };
    let mut path = app_dirs2::get_app_root(app_dirs2::AppDataType::UserConfig, &app_info).unwrap();
    path.push("history.txt");
    path
}

fn ensure_unlocked_passwords<IO: storage_io::StorageIO>(
    passwords: &mut Passwords<IO>,
    stdin_passwords: bool,
) -> Result<(), String> {
    if !passwords.initialized() {
        return Err(format_error(&Error::StorageNotInitialized));
    }

    while !passwords.unlocked() {
        let primary_password = prompt_password("Your primary password: ", stdin_passwords);
        if primary_password.expose_secret().len() < 6 {
            eprintln!("Primary password length should be at least 6 characters.");
        } else {
            passwords
                .unlock(primary_password)
                .unwrap_or_else(|error| eprintln!("{}", format_error(&error)));
        }
    }
    Ok(())
}

fn prompt_recovery_code<IO: storage_io::StorageIO>(
    passwords: &Passwords<IO>,
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

pub fn process_command<IO: storage_io::StorageIO>(
    args: Args,
    storage_path: &std::path::PathBuf,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    match &args.command {
        Commands::SetPrimary { .. } => {
            let primary_password = prompt_password("New primary password: ", args.stdin_passwords);
            if primary_password.expose_secret().len() < 6 {
                return Err("Primary password length should be at least 6 characters.".to_owned());
            }

            let primary_password2 =
                prompt_password("Repeat primary password: ", args.stdin_passwords);
            if primary_password.expose_secret() != primary_password2.expose_secret() {
                return Err("Primary passwords don't match.".to_owned());
            }

            passwords.reset(primary_password).convert_error()?;
            println!(
                "New primary password set for {}.",
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
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

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
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

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
                prompt_recovery_code(passwords)?
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
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

            passwords.remove(domain, name, revision).convert_error()?;
            println!("Password removed.");
        }

        Commands::Show {
            domain,
            name,
            revision,
            qrcode,
        } => {
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

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
                stdout
                    .write_all(password.expose_secret().as_bytes())
                    .unwrap();
                stdout.write_all(b"\n").unwrap();
            }
        }

        Commands::Notes {
            domain,
            name,
            revision,
            set,
        } => {
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

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
                let notes = prompt_secret_text("Please enter new notes to be stored:");
                let removing = notes.expose_secret().is_empty();
                passwords
                    .set_notes(domain, name, revision, notes)
                    .convert_error()?;
                if removing {
                    println!("Notes removed.");
                } else {
                    println!("Notes stored.");
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
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

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
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

            passwords.set_alias(domain, alias).convert_error()?;
            println!("Alias added.");
        }

        Commands::RemoveAlias { domain } => {
            ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

            passwords.remove_alias(domain).convert_error()?;
            println!("Alias removed.");
        }

        Commands::Shell { history } => {
            let history_path = match history {
                Some(value) => value.clone(),
                None => get_default_history_path(),
            };

            use clap::{CommandFactory, FromArgMatches};
            use rustyline::error::ReadlineError;

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

                        print_errors!(process_command(new_args, storage_path, passwords));
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
        }
    }
    Ok(())
}