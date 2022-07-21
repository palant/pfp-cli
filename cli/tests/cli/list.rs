/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const PRIMARY_PASSWORD: &str = "foobar";
const STORED_PASSWORD: &str = "asdf";
const ANOTHER_STORED_PASSWORD: &str = "yxcv";
const SECRETS: &[&[u8]] = &[
    PRIMARY_PASSWORD.as_bytes(),
    ANOTHER_STORED_PASSWORD.as_bytes(),
    STORED_PASSWORD.as_bytes(),
    b"SUDJjn&%:nBe}cr8",
    b"&>?DR",
    b"8svhxq86pwfc87qwvx9g",
    b"Now some notes stored here",
];

#[test]
fn uninitialized() {
    let setup = Setup::new();
    let mut session = setup.run(&["list"], None);
    session.expect_str("Failed reading storage file");
}

#[test]
fn list() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(&["add", "example.com", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password added");

        session = setup.run(
            &[
                "add",
                "example.com",
                "blubber",
                "-r",
                "2",
                "--no-lower",
                "--no-digit",
                "--length",
                "5",
            ],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &[
                "add",
                "example.com",
                "blubber",
                "-r",
                "8",
                "--no-upper",
                "--no-symbol",
                "--length",
                "20",
            ],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["add-stored", "example.net", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber", "-r", "another"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(ANOTHER_STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["alias", "example.info", "example.com"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Alias added");
    }

    {
        let mut session = setup.run(
            &["alias", "example.org", "example.com"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Alias added");
    }

    {
        let mut session = setup.run(
            &["notes", "www.example.com", "blubber", "-r", "8", "-s"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("no notes are stored");
        session.expect_str("enter new notes");
        session.send_line("Now some notes stored here");
        session.expect_str("Notes stored");
    }

    {
        let mut session = setup.run(&["list", "-v", "foo.example.com"], Some(PRIMARY_PASSWORD));
        session.expect_str("No matching passwords");
    }

    {
        let mut session = setup.run(&["list", "-v", "example.com", "x*"], Some(PRIMARY_PASSWORD));
        session.expect_str("No matching passwords");
    }

    {
        let mut session = setup.run(&["list", "-v", "-s"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            ("
Passwords for example.com:
    Aliases: example.info,
             example.org
    blabber (stored, revision: another)
        "
            .to_string()
                + ANOTHER_STORED_PASSWORD
                + "
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
        Notes: Now some notes stored here
        Length: 20
        Allowed characters: abc 789
Passwords for example.net:
    blabber (stored)
        " + STORED_PASSWORD
                + "
")
            .trim()
        );
    }

    {
        let mut session = setup.run(&["list", "-v", "*.net"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
Passwords for example.net:
    blabber (stored)
"
            .trim()
        );
    }

    {
        let mut session = setup.run(
            &["list", "-v", "example.com", "*ub*"],
            Some(PRIMARY_PASSWORD),
        );
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
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
        Notes: Now some notes stored here
        Length: 20
        Allowed characters: abc 789
"
            .trim()
        );
    }

    {
        // Note: example.org alias isn't listed because our wildcard only catches example.info
        let mut session = setup.run(
            &["list", "-v", "example.info", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
Passwords for example.com:
    Aliases: example.info
    blabber (stored, revision: another)
"
            .trim()
        );
    }

    {
        let mut session = setup.run(&["list", "-v", "*", "blabber"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
Passwords for example.com:
    Aliases: example.info,
             example.org
    blabber (stored, revision: another)
Passwords for example.net:
    blabber (stored)
"
            .trim()
        );
    }
}
