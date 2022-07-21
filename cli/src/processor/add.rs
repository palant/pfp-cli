/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{ensure_unlocked_passwords, ConvertError};
use crate::args::{Args, Commands};
use pfp::passwords::Passwords;
use pfp::storage_io;
use pfp::storage_types::{CharacterSet, CharacterType};

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::Add {
        domain,
        name,
        revision,
        length,
        no_lower,
        no_upper,
        no_digit,
        no_symbol,
        assume_yes,
    } = &args.command
    {
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
            let allow = question::Question::new(
                "A password with this domain/name/revision combination already exists. Overwrite?",
            )
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

    Ok(())
}
