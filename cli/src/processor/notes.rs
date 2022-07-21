/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{ensure_unlocked_passwords, prompt_secret_text, ConvertError};
use crate::args::{Args, Commands};
use io_streams::StreamWriter;
use pfp::passwords::Passwords;
use pfp::storage_io;
use secrecy::ExposeSecret;
use std::io::Write;

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::Notes {
        domain,
        name,
        revision,
        set,
    } = &args.command
    {
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

    Ok(())
}
