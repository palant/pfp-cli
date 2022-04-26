/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

mod crypto;

use clap::Parser;
use rpassword;
use std::process;

/// PfP: Pain-free Passwords, command line edition
#[derive(clap::Parser)]
#[clap(author, version, about, long_about = None)]
struct Args
{
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands
{
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
    match &args.command
    {
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
            let password = crypto::derive_password(&master_password, &domain, &name, &revision, *length, charset);
            println!("Password generated");
            println!("{}", password);
        }
    }
}
