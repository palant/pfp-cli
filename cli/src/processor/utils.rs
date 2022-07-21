/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use io_streams::{StreamReader, StreamWriter};
use pfp::error::Error;
use pfp::passwords::Passwords;
use pfp::recovery_codes;
use pfp::storage_io;
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

pub fn prompt_secret_text(prompt: &str) -> SecretString {
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

pub fn prompt_password(prompt: &str, stdin_passwords: bool) -> SecretString {
    let secret = if stdin_passwords {
        prompt_secret_text(prompt)
    } else {
        SecretString::new(rpassword::prompt_password(prompt).unwrap())
    };
    SecretString::new(secret.expose_secret().trim().to_owned())
}

pub fn ensure_unlocked_passwords<IO: storage_io::StorageIO>(
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

pub fn prompt_recovery_code<IO: storage_io::StorageIO>(
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
