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
    let mut session = setup.run(&["list"], None);
    session.expect_str("Failed reading storage file");
    session.read_to_eof();
}

#[test]
fn list()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "example.com", "blubber", "-r", "2", "--no-lower", "--no-digit", "--length", "5"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add", "example.com", "blubber", "-r", "8", "--no-upper", "--no-symbol", "--length", "20"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "example.net", "blabber"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["add-stored", "example.com", "blabber", "-r", "another"], Some(MASTER_PASSWORD));
    session.expect_str("Password to be stored");
    session.send_line(ANOTHER_STORED_PASSWORD);
    session.expect_str("Password added");

    session = setup.run(&["set-alias", "example.info", "example.com"], Some(MASTER_PASSWORD));
    session.expect_str("Alias added");

    session = setup.run(&["set-alias", "example.org", "example.com"], Some(MASTER_PASSWORD));
    session.expect_str("Alias added");

    session = setup.run(&["list", "-v", "foo.example.com"], Some(MASTER_PASSWORD));
    session.expect_str("No matching passwords");

    session = setup.run(&["list", "-v", "example.com", "x*"], Some(MASTER_PASSWORD));
    session.expect_str("No matching passwords");

    session = setup.run(&["list", "-v", "-s"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), ("
Passwords for example.com:
    Aliases: example.info,
             example.org
    blabber (stored, revision: another)
        ".to_string() + ANOTHER_STORED_PASSWORD + "
    blubber (generated)
        SUDJjn&%:nBe}cr8
        Length: 16
        Allowed characters: abc ABC 789 +^;
    blubber (generated, revision: 2)
        &>?DR
        Length: 5
        Allowed characters: ABC +^;
    blubber (generated, revision: 8)
        8svhxq86pwfc87qwvx9g
        Length: 20
        Allowed characters: abc 789
Passwords for example.net:
    blabber (stored)
        " + STORED_PASSWORD + "
").trim());

    session = setup.run(&["list", "-v", "*.net"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.net:
    blabber (stored)
".trim());

    session = setup.run(&["list", "-v", "example.com", "*ub*"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    Aliases: example.info,
             example.org
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

    // Note: example.org alias isn't listed because our wildcard only catches example.info
    session = setup.run(&["list", "-v", "example.info", "blabber"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    Aliases: example.info
    blabber (stored, revision: another)
".trim());

    session = setup.run(&["list", "-v", "*", "blabber"], Some(MASTER_PASSWORD));
    assert_eq!(session.read_to_eof().trim(), "
Passwords for example.com:
    Aliases: example.info,
             example.org
    blabber (stored, revision: another)
Passwords for example.net:
    blabber (stored)
".trim());
}
