/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const PRIMARY_PASSWORD: &str = "foobar";
const STORED_PASSWORD: &str = "asdf";
const PASSWORD_NOTES: &str = "hi there!";
const SECRETS: &[&[u8]] = &[
    PRIMARY_PASSWORD.as_bytes(),
    STORED_PASSWORD.as_bytes(),
    PASSWORD_NOTES.as_bytes(),
];

#[test]
fn shell() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    let mut session = setup.run(&["shell"], None);
    session.expect_str("Enter a command");

    session.send_line("help");
    session.expect_str("add");
    session.expect_str("generated password");
    session.expect_str("add-stored");
    session.expect_str("verbatim password");
    session.expect_str("list");
    session.expect_str("Lists passwords");
    session.expect_str("set-alias");
    session.expect_str("alias for a website");

    session.send_line("help add");
    session.expect_str("generated password");
    session.expect_str("USAGE");
    session.expect_str("<DOMAIN>");
    session.expect_str("<NAME>");
    session.expect_str("--no-digit");

    session.send_line("add example.com blubber");
    session.expect_str("Your primary password:");
    session.send_line(PRIMARY_PASSWORD);
    session.expect_str("Password added");

    session.send_line("add-stored example.com 'blabber whatever'");
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session.send_line("add-stored -r 2 example.com 'blabber whatever'");
    session.expect_str("Password to be stored");
    session.send_line(STORED_PASSWORD);
    session.expect_str("Password added");

    session.send_line("remove example.com 'blabber whatever'");
    session.expect_str("Password removed");

    session.send_line("set-alias example.info example.com");
    session.expect_str("Alias added");

    session.send_line("set-alias example.org example.com");
    session.expect_str("Alias added");

    session.send_line("notes -s example.com blubber");
    session.expect_str("no notes are stored");
    session.expect_str("enter new notes");
    session.send_line(PASSWORD_NOTES);
    session.expect_str("Notes stored");

    session.send_line("notes example.com blubber");
    session.expect_str(PASSWORD_NOTES);

    session.send_line("lock");
    session.expect_str("Passwords locked");

    session.send_line("remove-alias example.info");
    session.expect_str("Your primary password:");
    session.send_line(PRIMARY_PASSWORD);
    session.expect_str("Alias removed");

    session.send_line("show --revision 2 example.com \"blabber whatever\"");
    session.expect_str("Password retrieved");
    session.expect_str(STORED_PASSWORD);

    session.send_line("list -v");
    assert_eq!(
        session.read_to("+^;").trim(),
        ("
Passwords for example.com:
    Aliases: example.org
    blabber whatever (stored, revision: 2)
    blubber (generated)
        Notes: "
            .to_string()
            + PASSWORD_NOTES
            + "
        Length: 16
        Allowed characters: abc ABC 789 +^;
")
        .trim(),
    );

    session.send_line("set-primary");
    session.expect_str("cannot change primary password");

    session.send_line("shell");
    session.expect_str("cannot run a shell");
}
