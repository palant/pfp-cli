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
    let mut session = setup.run(&["list"], None);
    session.expect("Failed reading storage file").expect("App should error out on missing file");
    read_to_eof(&mut session);
}

#[test]
fn list()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "example.com", "blubber", "-r", "2", "--no-lower", "--no-digit", "--length", "5"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add", "example.com", "blubber", "-r", "8", "--no-upper", "--no-symbol", "--length", "20"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "example.net", "blabber"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["add-stored", "example.com", "blabber", "-r", "another"], Some(MASTER_PASSWORD));
    session.expect("Password to be stored").expect("App should request password");
    session.send_line(ANOTHER_STORED_PASSWORD).unwrap();
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["set-alias", "example.info", "example.com"], Some(MASTER_PASSWORD));
    session.expect("Alias added").expect("Call should succeed");

    session = setup.run(&["set-alias", "example.org", "example.com"], Some(MASTER_PASSWORD));
    session.expect("Alias added").expect("Call should succeed");

    session = setup.run(&["list", "-v", "foo.example.com"], Some(MASTER_PASSWORD));
    session.expect("No matching passwords").expect("Call should fail");

    session = setup.run(&["list", "-v", "example.com", "x*"], Some(MASTER_PASSWORD));
    session.expect("No matching passwords").expect("Call should fail");

    session = setup.run(&["list", "-v", "-s"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), ("
Passwords for example.com:\r
    Aliases: example.info,\r
             example.org\r
    blabber (stored, revision: another)\r
        ".to_string() + ANOTHER_STORED_PASSWORD + "\r
    blubber (generated)\r
        SUDJjn&%:nBe}cr8\r
        Length: 16\r
        Allowed characters: abc ABC 789 +^;\r
    blubber (generated, revision: 2)\r
        &>?DR\r
        Length: 5\r
        Allowed characters: ABC +^;\r
    blubber (generated, revision: 8)\r
        8svhxq86pwfc87qwvx9g\r
        Length: 20\r
        Allowed characters: abc 789\r
Passwords for example.net:\r
    blabber (stored)\r
        " + STORED_PASSWORD + "\r
").trim());

    session = setup.run(&["list", "-v", "*.net"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.net:\r
    blabber (stored)\r
".trim());

    session = setup.run(&["list", "-v", "example.com", "*ub*"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    Aliases: example.info,\r
             example.org\r
    blubber (generated)\r
        Length: 16\r
        Allowed characters: abc ABC 789 +^;\r
    blubber (generated, revision: 2)\r
        Length: 5\r
        Allowed characters: ABC +^;\r
    blubber (generated, revision: 8)\r
        Length: 20\r
        Allowed characters: abc 789\r
".trim());

    // Note: example.org alias isn't listed because our wildcard only catches example.info
    session = setup.run(&["list", "-v", "example.info", "blabber"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    Aliases: example.info\r
    blabber (stored, revision: another)\r
".trim());

    session = setup.run(&["list", "-v", "*", "blabber"], Some(MASTER_PASSWORD));
    assert_eq!(read_to_eof(&mut session).trim(), "
Passwords for example.com:\r
    Aliases: example.info,\r
             example.org\r
    blabber (stored, revision: another)\r
Passwords for example.net:\r
    blabber (stored)\r
".trim());
}
