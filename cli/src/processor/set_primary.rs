/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{prompt_password, ConvertError};
use crate::args::Args;
use pfp::passwords::Passwords;
use pfp::storage_io;
use secrecy::ExposeSecret;

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    storage_path: &std::path::Path,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    let primary_password = prompt_password("New primary password: ", args.stdin_passwords);
    if primary_password.expose_secret().len() < 6 {
        return Err("Primary password length should be at least 6 characters.".to_owned());
    }

    let primary_password2 = prompt_password("Repeat primary password: ", args.stdin_passwords);
    if primary_password.expose_secret() != primary_password2.expose_secret() {
        return Err("Primary passwords don't match.".to_owned());
    }

    passwords.reset(primary_password).convert_error()?;
    println!(
        "New primary password set for {}.",
        storage_path.to_string_lossy()
    );

    Ok(())
}
