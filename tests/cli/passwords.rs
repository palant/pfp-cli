/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const MASTER_PASSWORD: &str = "foobar";
const STORED_PASSWORD: &str = "asdf";
const ANOTHER_STORED_PASSWORD: &str = "yxcv";

#[test]
fn uninitialized()
{
    let setup = Setup::new();
    let mut session = setup.run(&["add", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");
    session.read_to_eof();

    session = setup.run(&["add-stored", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");
    session.read_to_eof();

    session = setup.run(&["show", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");
    session.read_to_eof();
}

#[test]
fn add()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "example.com", "blubber", "-r", "2", "--no-lower", "--no-digit", "--length", "5"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "example.com", "blubber", "-r", "8", "--no-upper", "--no-symbol", "--length", "20"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "example.com", "blabber", "-r", "another"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(ANOTHER_STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    blabber (stored)
    blabber (stored, revision: another)
    blubber (generated)
        Length: 16
        Allowed characters: abc ABC 789 +^;
    blubber (generated, revision: 2)
        Length: 5
        Allowed characters: ABC +^;
    blubber (generated, revision: 8)
        Length: 20
        Allowed characters: abc 789
".trim());

    session = setup.run(&["show", "example.com", "blubber", "--revision", "1"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), "SUDJjn&%:nBe}cr8");

    session = setup.run(&["show", "example.com", "blubber", "-r", "2"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), "&>?DR");

    session = setup.run(&["show", "example.com", "blubber", "-r", "8"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), "8svhxq86pwfc87qwvx9g");

    session = setup.run(&["show", "-r", "1", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), STORED_PASSWORD);

    session = setup.run(&["show", "-r", "another", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), ANOTHER_STORED_PASSWORD);
}

#[test]
fn overwrite_aborted()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "example.com", "blubber", "--length", "8", "--no-lower"], Some(MASTER_PASSWORD));
    session.expect_str("already exists");
    session.send_line("n");
    session.read_to_eof();

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    blubber (generated)
        Length: 16
        Allowed characters: abc ABC 789 +^;
".trim());
}

#[test]
fn overwrite_aborted_stored()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("already exists");
    session.send_line("n");
    session.read_to_eof();

    session = setup.run(&["show", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), STORED_PASSWORD);
}

#[test]
fn overwrite_accepted()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "example.com", "blubber", "--length", "8", "--no-lower"], Some(MASTER_PASSWORD));
    session.expect_str("already exists");
    session.send_line("y");
    session.expect_str("Password added");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    blubber (generated)
        Length: 8
        Allowed characters: ABC 789 +^;
".trim());
}

#[test]
fn overwrite_accepted_stored()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("already exists");
    session.send_line("y");
    session.expect_str("Password to be stored");
    session.send_line(ANOTHER_STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["show", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), ANOTHER_STORED_PASSWORD);
}

#[test]
fn overwrite_noninteractive()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "-y", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "-y", "example.com", "blubber", "--length", "8", "--no-lower"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    blubber (generated)
        Length: 8
        Allowed characters: ABC 789 +^;
".trim());
}

#[test]
fn overwrite_noninteractive_stored()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "-y", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "-y", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(ANOTHER_STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["show", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), ANOTHER_STORED_PASSWORD);
}

#[test]
fn remove()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber", "-r", "5"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["remove", "example.com", "blubber", "-r", "5"], Some(MASTER_PASSWORD));
    session.expect_str("Password removed");

    session = setup.run(&["remove", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password removed");

    session = setup.run(&["list", "-v"], Some(MASTER_PASSWORD));
    session.expect_str("No matching passwords");
}

#[test]
fn recovery_codes()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["list", "-r"], Some(MASTER_PASSWORD));
    session.expect_str("Recovery code:");
    let recovery_code = session.read_to_eof();

    session = setup.run(&["add-stored", "-c", "example.net", "test"], Some(MASTER_PASSWORD));
    session.expect_str("line of your recovery code");
    session.send_line("");
    session.read_to_eof();

    session = setup.run(&["add-stored", "-c", "example.net", "test"], Some(MASTER_PASSWORD));
    for line in recovery_code.trim().split('\n')
    {
        session.expect_str("line of your recovery code");
        session.send_line(line);
    }
    session.expect_str("Password added");

    session = setup.run(&["show", "example.net", "test"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), STORED_PASSWORD);
}

#[test]
fn show_qrcode()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add-stored", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["show", "-q", "example.com", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved.");
    assert_eq!(session.read_to_eof().trim(), "
█▀▀▀▀▀█ █  ▄  █▀▀▀▀▀█\n
█ ███ █ ▀▄▄▀▀ █ ███ █\n
█ ▀▀▀ █ ▄▀█ █ █ ▀▀▀ █\n
▀▀▀▀▀▀▀ █▄█ █ ▀▀▀▀▀▀▀\n
  ███▄▀ ▀ ▄ ████  ███\n
 ▄▀▄ ▄▀▀▀▀▀▀▄▄ ▄██▄█ \n
▀   ▀ ▀▀█ ▄ ▀▄▀ ▀▄▄ ▄\n
█▀▀▀▀▀█   ▀▀▀ █▀ ▄█▀ \n
█ ███ █ ███▄  ▀█ ▄▄▀ \n
█ ▀▀▀ █ ▀▀▄ █▄█▄█ ▄  \n
▀▀▀▀▀▀▀     ▀ ▀ ▀ ▀▀ \n
".replace("\n\n", "\n").trim());
}
