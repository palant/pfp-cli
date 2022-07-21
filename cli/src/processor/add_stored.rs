/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{
    ensure_unlocked_passwords, prompt_password, prompt_recovery_code, ConvertError,
};
use crate::args::{Args, Commands};
use pfp::passwords::Passwords;
use pfp::storage_io;

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::AddStored {
        domain,
        name,
        revision,
        recovery,
        assume_yes,
    } = &args.command
    {
        ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

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

    Ok(())
}
