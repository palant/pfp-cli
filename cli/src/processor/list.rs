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
use pfp::storage_types::{CharacterType, Password, Site};
use secrecy::ExposeSecret;
use std::io::Write;

pub fn processor<IO: storage_io::StorageIO>(
    args: &Args,
    passwords: &mut Passwords<IO>,
) -> Result<(), String> {
    if let Commands::List {
        domain,
        name,
        show,
        recovery,
        verbose,
    } = &args.command
    {
        ensure_unlocked_passwords(passwords, args.stdin_passwords)?;

        let mut empty_sites = Vec::new();

        let mut sites = passwords.list_sites(domain).collect::<Vec<Site>>();
        let mut additions = Vec::new();
        for site in sites.iter() {
            if let Some(alias) = site.alias() {
                additions.push(Site::new(alias, None));
            }
        }
        sites.append(&mut additions);
        sites.sort_by_key(|site| site.name().to_owned());
        sites.dedup_by_key(|site| site.name().to_owned());

        let mut aliases = std::collections::HashMap::new();
        sites.retain(|site| match site.alias() {
            Some(alias) => {
                if !aliases.contains_key(alias) {
                    aliases.insert(alias.to_owned(), Vec::new());
                }
                aliases
                    .get_mut(alias)
                    .unwrap()
                    .push(site.name().to_string());
                false
            }
            None => true,
        });

        let mut found = false;
        for site in sites {
            let mut list = passwords.list(site.name(), name).collect::<Vec<Password>>();
            if list.is_empty() {
                if name == "*" {
                    empty_sites.push(site.name().to_string());
                }
                continue;
            }

            found = true;
            println!("Passwords for {}:", site.name());
            if *verbose {
                if let Some(aliased) = aliases.get(site.name()) {
                    println!("    Aliases: {}", aliased.join(",\n             "));
                }
            }

            list.sort_by_key(|password| {
                password.id().name().to_string() + " " + password.id().revision()
            });
            for password in list {
                let name = password.id().name().to_owned();
                let revision = password.id().revision().to_owned();
                let password_type = match &password {
                    Password::Generated(_) => "generated",
                    Password::Stored(_) => "stored",
                };
                if !revision.is_empty() {
                    println!("    {} ({}, revision: {})", name, password_type, revision);
                } else {
                    println!("    {} ({})", name, password_type);
                }

                if *show {
                    print!("        ");
                    std::io::stdout().flush().unwrap();
                    StreamWriter::stdout()
                        .unwrap()
                        .write_all(
                            passwords
                                .get(site.name(), &name, &revision)
                                .convert_error()?
                                .expose_secret()
                                .as_bytes(),
                        )
                        .unwrap();
                    println!();
                }

                if *recovery {
                    if let Password::Stored(password) = &password {
                        println!("        Recovery code:");
                        for line in passwords
                            .get_recovery_code(password)
                            .convert_error()?
                            .split('\n')
                        {
                            println!("        {}", line);
                        }
                    }
                }

                if *verbose {
                    let notes = password.notes();
                    if !notes.expose_secret().is_empty() {
                        print!("        Notes: ");
                        std::io::stdout().flush().unwrap();
                        StreamWriter::stdout()
                            .unwrap()
                            .write_all(notes.expose_secret().as_bytes())
                            .unwrap();
                        println!();
                    }

                    if let Password::Generated(password) = &password {
                        println!("        Length: {}", password.length());

                        let mut chars = Vec::new();
                        if password.charset().contains(CharacterType::Lower) {
                            chars.push("abc");
                        }
                        if password.charset().contains(CharacterType::Upper) {
                            chars.push("ABC");
                        }
                        if password.charset().contains(CharacterType::Digit) {
                            chars.push("789");
                        }
                        if password.charset().contains(CharacterType::Symbol) {
                            chars.push("+^;");
                        }
                        println!("        Allowed characters: {}", chars.join(" "));
                    }
                }
            }
        }

        passwords.remove_sites(&empty_sites).convert_error()?;

        if !found {
            println!("No matching passwords found.");
        }
    }

    Ok(())
}
