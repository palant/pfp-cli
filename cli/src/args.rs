/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use clap::{Parser, Subcommand};

/// PfP: Pain-free Passwords, command line edition
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Data storage file path
    #[clap(parse(from_os_str), short = 'c', long)]
    pub storage: Option<std::path::PathBuf>,
    /// Integration tests only: read passwords from stdin
    #[clap(long, hide = true)]
    pub stdin_passwords: bool,
    /// Integration tests only: lock passwords and wait when done
    #[clap(long, hide = true)]
    pub wait: bool,
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Set a new primary password
    SetPrimary {
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
    /// Open an interactive shell
    Shell {
        /// Command history file path
        #[clap(parse(from_os_str), short = 's', long)]
        history: Option<std::path::PathBuf>,
    },
}

fn validate_length(arg: &str) -> Result<(), String> {
    if let Ok(length) = arg.parse::<usize>() {
        if !(4..=24).contains(&length) {
            return Err("Password length should be between 4 and 24 characters.".to_string());
        }
    };
    Ok(())
}
