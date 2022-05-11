/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const MASTER_PASSWORD: &str = "foobar";
const ANOTHER_MASTER_PASSWORD: &str = "asdfyxcv";

#[test]
fn short_password()
{
    let setup = Setup::new();
    let mut session = setup.run(&["set-master"], None);

    session.expect("New master password").expect("App should request master password");
    session.send_line("asdf").unwrap();
    session.expect("at least 6 characters").expect("App should reject master password");
}

#[test]
fn mismatch()
{
    let setup = Setup::new();
    let mut session = setup.run(&["set-master"], None);

    session.expect("New master password").expect("App should request master password");
    session.send_line(MASTER_PASSWORD).unwrap();
    session.expect("Repeat master password").expect("App should request master password to be repeated");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("don't match").expect("App should reject repeated master password");
}

#[test]
fn success()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["list"], Some(ANOTHER_MASTER_PASSWORD));
    session.expect("Decryption failure").expect("App should reject wrong master password");
    session.expect("Your master password").expect("App should request master password again");
    session.send_line(MASTER_PASSWORD).unwrap();
    session.expect("No matching passwords").expect("App should accept correct master password");
}

#[test]
fn reinitialization_aborted()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["set-master"], None);
    session.expect("remove all existing data").expect("App should warn about removing existing data");
    session.send_line("n").unwrap();
    session.expect(expectrl::Eof).expect("App show terminate");
}

#[test]
fn reinitialization_accepted()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["set-master"], None);
    session.expect("remove all existing data").expect("App should warn about removing existing data");
    session.send_line("y").unwrap();

    session.expect("New master password").expect("App should request master password");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("Repeat master password").expect("App should request master password to be repeated");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("master password set").expect("App should accept master password");

    session = setup.run(&["list"], Some(MASTER_PASSWORD));
    session.expect("Decryption failure").expect("App should reject wrong master password");
    session.expect("Your master password").expect("App should request master password again");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("No matching passwords").expect("App should accept correct master password");
}

#[test]
fn reinitialization_noninteractive()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["set-master", "-y"], None);
    session.expect("New master password").expect("App should request master password");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("Repeat master password").expect("App should request master password to be repeated");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("master password set").expect("App should accept master password");

    session = setup.run(&["list"], Some(MASTER_PASSWORD));
    session.expect("Decryption failure").expect("App should reject wrong master password");
    session.expect("Your master password").expect("App should request master password again");
    session.send_line(ANOTHER_MASTER_PASSWORD).unwrap();
    session.expect("No matching passwords").expect("App should accept correct master password");
}
