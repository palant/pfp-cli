/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{ensure_unlocked_passwords, ConvertError};
use crate::args::{Args, Commands};
use pfp::passwords::Passwords;
use pfp::storage_io;

pub fn processor_set<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::SetAlias { domain, alias } = &args.command {
        ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

        passwords.set_alias(domain, alias).convert_error()?;
        println!("Alias added.");
    }

    Ok(())
}

pub fn processor_remove<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::RemoveAlias { domain } = &args.command {
        ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

        passwords.remove_alias(domain).convert_error()?;
        println!("Alias removed.");
    }

    Ok(())
}
