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
    b"hi there!",
];

#[test]
fn uninitialized() {
    let setup = Setup::new();
    let mut session = setup.run(&["add", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");

    session = setup.run(&["add-stored", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");

    session = setup.run(&["show", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");

    session = setup.run(&["notes", "example.com", "blubber"], None);
    session.expect_str("Failed reading storage file");
}

#[test]
fn add() {
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
            &["add-stored", "example.com", "blabber"],
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
        let mut session = setup.run(&["list", "-v"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
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
"
            .trim()
        );
    }

    {
        let mut session = setup.run(
            &["show", "example.com", "blubber", "--revision", "1"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), "SUDJjn&%:nBe}cr8");
    }

    {
        let mut session = setup.run(
            &["show", "example.com", "blubber", "-r", "2"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), "&>?DR");
    }

    {
        let mut session = setup.run(
            &["show", "example.com", "blubber", "-r", "8"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), "8svhxq86pwfc87qwvx9g");
    }

    {
        let mut session = setup.run(
            &["show", "-r", "1", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), STORED_PASSWORD);
    }

    {
        let mut session = setup.run(
            &["show", "-r", "another", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), ANOTHER_STORED_PASSWORD);
    }
}

#[test]
fn overwrite_aborted() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(&["add", "example.com", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &[
                "add",
                "example.com",
                "blubber",
                "--length",
                "8",
                "--no-lower",
            ],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("already exists");
        session.send_line("n");
    }

    {
        let mut session = setup.run(&["list", "-v"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
Passwords for example.com:
    blubber (generated)
        Length: 16
        Allowed characters: abc ABC 789 +^;
"
            .trim()
        );
    }
}

#[test]
fn overwrite_aborted_stored() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("already exists");
        session.send_line("n");
    }

    {
        let mut session = setup.run(&["show", "example.com", "blabber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), STORED_PASSWORD);
    }
}

#[test]
fn overwrite_accepted() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(&["add", "example.com", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &[
                "add",
                "example.com",
                "blubber",
                "--length",
                "8",
                "--no-lower",
            ],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("already exists");
        session.send_line("y");
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["list", "-v"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
Passwords for example.com:
    blubber (generated)
        Length: 8
        Allowed characters: ABC 789 +^;
"
            .trim()
        );
    }
}

#[test]
fn overwrite_accepted_stored() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("already exists");
        session.send_line("y");
        session.expect_str("Password to be stored");
        session.send_line(ANOTHER_STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["show", "example.com", "blabber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), ANOTHER_STORED_PASSWORD);
    }
}

#[test]
fn overwrite_noninteractive() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add", "-y", "example.com", "blubber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &[
                "add",
                "-y",
                "example.com",
                "blubber",
                "--length",
                "8",
                "--no-lower",
            ],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["list", "-v"], Some(PRIMARY_PASSWORD));
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
Passwords for example.com:
    blubber (generated)
        Length: 8
        Allowed characters: ABC 789 +^;
"
            .trim()
        );
    }
}

#[test]
fn overwrite_noninteractive_stored() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add-stored", "-y", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["add-stored", "-y", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(ANOTHER_STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["show", "example.com", "blabber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), ANOTHER_STORED_PASSWORD);
    }
}

#[test]
fn remove() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add", "example.com", "blubber", "-r", "5"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["remove", "example.com", "blubber", "-r", "5"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password removed");
    }

    {
        let mut session = setup.run(
            &["remove", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password removed");
    }

    {
        let mut session = setup.run(&["list", "-v"], Some(PRIMARY_PASSWORD));
        session.expect_str("No matching passwords");
    }
}

#[test]
fn recovery_codes() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    let recovery_code = {
        let mut session = setup.run(&["list", "-r"], Some(PRIMARY_PASSWORD));
        session.expect_str("Recovery code:");
        session.read_to_empty_line()
    };

    {
        let mut session = setup.run(
            &["add-stored", "-c", "example.net", "test"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("line of your recovery code");
        session.send_line("");
    }

    {
        let mut session = setup.run(
            &["add-stored", "-c", "example.net", "test"],
            Some(PRIMARY_PASSWORD),
        );
        for line in recovery_code.trim().split('\n') {
            session.expect_str("line of your recovery code");
            session.send_line(line);
        }
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["show", "example.net", "test"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password retrieved.");
        assert_eq!(session.read_to_empty_line().trim(), STORED_PASSWORD);
    }
}

#[test]
fn show_qrcode() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
            &["add-stored", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password to be stored");
        session.send_line(STORED_PASSWORD);
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(
            &["show", "-q", "example.com", "blabber"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Password retrieved.");
        assert_eq!(
            session.read_to_empty_line().trim(),
            "
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
"
            .replace("\n\n", "\n")
            .trim()
        );
    }
}

#[test]
fn notes() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(
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
            &["notes", "example.com", "blubber", "-r", "2"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("no notes are stored");
    }

    {
        let mut session = setup.run(
            &["notes", "example.com", "blubber", "-r", "2", "-s"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("no notes are stored");
        session.expect_str("enter new notes");
        session.send_line("hi there!");
        session.expect_str("Notes stored");
    }

    {
        let mut session = setup.run(
            &["notes", "example.com", "blubber", "-r", "2"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Notes for this password: hi there!");
    }

    {
        let mut session = setup.run(
            &["notes", "example.com", "blubber", "-r", "2", "-s"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Notes for this password: hi there!");
        session.expect_str("enter new notes");
        session.send_line("");
        session.expect_str("Notes removed");
    }

    {
        let mut session = setup.run(
            &["notes", "example.com", "blubber", "-r", "2"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("no notes are stored");
    }
}
