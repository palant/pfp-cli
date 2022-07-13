/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const PRIMARY_PASSWORD: &str = "foobar";
const ANOTHER_PRIMARY_PASSWORD: &str = "asdfyxcv";
const SECRETS: &[&[u8]] = &[
    PRIMARY_PASSWORD.as_bytes(),
    ANOTHER_PRIMARY_PASSWORD.as_bytes(),
];

#[test]
fn short_password() {
    let setup = Setup::new();
    let mut session = setup.run(&["set-primary"], None);

    session.expect_str("New primary password");
    session.send_line("asdf");
    session.expect_str("at least 6 characters");
}

#[test]
fn mismatch() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    let mut session = setup.run(&["set-primary"], None);

    session.expect_str("New primary password");
    session.send_line(PRIMARY_PASSWORD);
    session.expect_str("Repeat primary password");
    session.send_line(ANOTHER_PRIMARY_PASSWORD);
    session.expect_str("don't match");
}

#[test]
fn success() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    let mut session = setup.run(&["list"], Some(ANOTHER_PRIMARY_PASSWORD));
    session.expect_str("Decryption failure");
    session.expect_str("Your primary password");
    session.send_line(PRIMARY_PASSWORD);
    session.expect_str("No matching passwords");
}

#[test]
fn reinitialization_aborted() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    let mut session = setup.run(&["set-primary"], None);
    session.expect_str("remove all existing data");
    session.send_line("n");
}

#[test]
fn reinitialization_accepted() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(&["set-primary"], None);
        session.expect_str("remove all existing data");
        session.send_line("y");

        session.expect_str("New primary password");
        session.send_line(ANOTHER_PRIMARY_PASSWORD);
        session.expect_str("Repeat primary password");
        session.send_line(ANOTHER_PRIMARY_PASSWORD);
        session.expect_str("primary password set");
    }

    {
        let mut session = setup.run(&["list"], Some(PRIMARY_PASSWORD));
        session.expect_str("Decryption failure");
        session.expect_str("Your primary password");
        session.send_line(ANOTHER_PRIMARY_PASSWORD);
        session.expect_str("No matching passwords");
    }
}

#[test]
fn reinitialization_noninteractive() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(&["set-primary", "-y"], None);
        session.expect_str("New primary password");
        session.send_line(ANOTHER_PRIMARY_PASSWORD);
        session.expect_str("Repeat primary password");
        session.send_line(ANOTHER_PRIMARY_PASSWORD);
        session.expect_str("primary password set");
    }

    {
        let mut session = setup.run(&["list"], Some(PRIMARY_PASSWORD));
        session.expect_str("Decryption failure");
        session.expect_str("Your primary password");
        session.send_line(ANOTHER_PRIMARY_PASSWORD);
        session.expect_str("No matching passwords");
    }
}
