/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{ensure_unlocked_passwords, ConvertError};
use crate::args::{Args, Commands};
use pfp::passwords::Passwords;
use pfp::storage_io;

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::Alias {
        domain,
        alias_target,
        remove,
    } = &args.command
    {
        ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

        if let Some(target) = alias_target {
            passwords.set_alias(domain, target).convert_error()?;
            println!("Alias added.");
        } else if *remove {
            passwords.remove_alias(domain).convert_error()?;
            println!("Alias removed.");
        } else {
            println!(
                "'{}' is an alias for '{}'.",
                domain,
                passwords.get_alias(domain).convert_error()?
            );
        }
    }

    Ok(())
}
