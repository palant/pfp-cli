/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::utils::{ensure_unlocked_passwords, ConvertError};
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
    if let Commands::Show {
        domain,
        name,
        revision,
        qrcode,
    } = &args.command
    {
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

    Ok(())
}
