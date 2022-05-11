/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::{Setup, read_to_eof};

const MASTER_PASSWORD: &str = "foobar";
const STORED_PASSWORD: &str = "asdf";
const ANOTHER_STORED_PASSWORD: &str = "yxcv";

#[test]
fn uninitialized()
{
    let setup = Setup::new();
    let mut session = setup.run(&["add", "example.com", "blubber"], None);
    session.expect("Failed reading storage file").expect("App should error out on missing file");

    session = setup.run(&["add-stored", "example.com", "blubber"], None);
    session.expect("Failed reading storage file").expect("App should error out on missing file");

    session = setup.run(&["show", "example.com", "blubber"], None);
    session.expect("Failed reading storage file").expect("App should error out on missing file");
}

#[test]
fn add()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "example.com", "blubber", "-r", "2", "--no-lower", "--no-digit", "--length", "5"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "example.com", "blubber", "-r", "8", "--no-upper", "--no-symbol", "--length", "20"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "example.com", "blabber", "-r", "another"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(ANOTHER_STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    blabber (stored)\r
    blabber (stored, revision: another)\r
    blubber (generated)\r
        Length: 16\r
        Allowed characters: abc ABC 789 +^;\r
    blubber (generated, revision: 2)\r
        Length: 5\r
        Allowed characters: ABC +^;\r
    blubber (generated, revision: 8)\r
        Length: 20\r
        Allowed characters: abc 789
".trim());

    session = setup.run(&["show", "example.com", "blubber", "--revision", "1"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), "SUDJjn&%:nBe}cr8");

    session = setup.run(&["show", "example.com", "blubber", "-r", "2"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), "&>?DR");

    session = setup.run(&["show", "example.com", "blubber", "-r", "8"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), "8svhxq86pwfc87qwvx9g");

    session = setup.run(&["show", "-r", "1", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), STORED_PASSWORD);

    session = setup.run(&["show", "-r", "another", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), ANOTHER_STORED_PASSWORD);
}

#[test]
fn overwrite_aborted()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "example.com", "blubber", "--length", "8", "--no-lower"], Some(MASTER_PASSWORD));
    session.expect("already exists").expect("App should warn before overwriting password");
    session.send_line("n").unwrap();
    session.expect(expectrl::Eof).expect("App should terminate");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    blubber (generated)\r
        Length: 16\r
        Allowed characters: abc ABC 789 +^;\r
".trim());
}

#[test]
fn overwrite_aborted_stored()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("already exists").expect("App should warn before overwriting password");
    session.send_line("n").unwrap();
    session.expect(expectrl::Eof).expect("App should terminate");

    session = setup.run(&["show", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), STORED_PASSWORD);
}

#[test]
fn overwrite_accepted()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "example.com", "blubber", "--length", "8", "--no-lower"], Some(MASTER_PASSWORD));
    session.expect("already exists").expect("App should warn before overwriting password");
    session.send_line("y").unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    blubber (generated)\r
        Length: 8\r
        Allowed characters: ABC 789 +^;\r
".trim());
}

#[test]
fn overwrite_accepted_stored()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("already exists").expect("App should warn before overwriting password");
    session.send_line("y").unwrap();
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(ANOTHER_STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["show", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), ANOTHER_STORED_PASSWORD);
}

#[test]
fn overwrite_noninteractive()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "-y", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "-y", "example.com", "blubber", "--length", "8", "--no-lower"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    blubber (generated)\r
        Length: 8\r
        Allowed characters: ABC 789 +^;\r
".trim());
}

#[test]
fn overwrite_noninteractive_stored()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "-y", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "-y", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(ANOTHER_STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["show", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), ANOTHER_STORED_PASSWORD);
}

#[test]
fn remove()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber", "-r", "5"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["remove", "example.com", "blubber", "-r", "5"], Some(MASTER_PASSWORD));
    session.expect("Password removed").expect("Call should succeed");

    session = setup.run(&["remove", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password removed").expect("Call should succeed");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    session.expect("No matching passwords").expect("Call should succeed");
}

#[test]
fn recovery_codes()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["list", "-r"], Some(MASTER_PASSWORD));
    session.expect("Recovery code:").expect("Call should succeed");
    let recovery_code = read_to_eof(&mut session);

    session = setup.run(&["add-stored", "-c", "example.net", "test"], Some(MASTER_PASSWORD));
    session.expect("line of your recovery code").expect("App should request recovery code");
    session.send_line("").unwrap();
    session.expect(expectrl::Eof).expect("App should terminate");

    session = setup.run(&["add-stored", "-c", "example.net", "test"], Some(MASTER_PASSWORD));
    for line in recovery_code.trim().split("\r\n")
    {
        session.expect("line of your recovery code").expect("App should request recovery code");
        session.send_line(line).unwrap();
    }
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["show", "example.net", "test"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), STORED_PASSWORD);
}

#[test]
fn show_qrcode()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["show", "-q", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved.").expect("Call should succeed");
    assert_eq!(read_to_eof(&mut session).trim(), "
█▀▀▀▀▀█ █  ▄  █▀▀▀▀▀█\r
█ ███ █ ▀▄▄▀▀ █ ███ █\r
█ ▀▀▀ █ ▄▀█ █ █ ▀▀▀ █\r
▀▀▀▀▀▀▀ █▄█ █ ▀▀▀▀▀▀▀\r
  ███▄▀ ▀ ▄ ████  ███\r
 ▄▀▄ ▄▀▀▀▀▀▀▄▄ ▄██▄█ \r
▀   ▀ ▀▀█ ▄ ▀▄▀ ▀▄▄ ▄\r
█▀▀▀▀▀█   ▀▀▀ █▀ ▄█▀ \r
█ ███ █ ███▄  ▀█ ▄▄▀ \r
█ ▀▀▀ █ ▀▀▄ █▄█▄█ ▄  \r
▀▀▀▀▀▀▀     ▀ ▀ ▀ ▀▀ \r
".trim());
}
