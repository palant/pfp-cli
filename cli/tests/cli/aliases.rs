/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const MASTER_PASSWORD: &str = "foobar";
const SECRETS: &[&[u8]] = &[MASTER_PASSWORD.as_bytes()];

#[test]
fn uninitialized() {
    let setup = Setup::new();
    let mut session = setup.run(&["set-alias", "example.info", "example.com"], None);
    session.expect_str("Failed reading storage file");

    session = setup.run(&["remove-alias", "example.info"], None);
    session.expect_str("Failed reading storage file");
}

#[test]
fn add_remove() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(MASTER_PASSWORD);

    {
        let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
        session.expect_str("No such value");
    }

    {
        let mut session = setup.run(
            &["set-alias", "example.info", "example.com"],
            Some(MASTER_PASSWORD),
        );
        session.expect_str("Alias added");
    }

    {
        let mut session = setup.run(
            &["set-alias", "example.net", "example.com"],
            Some(MASTER_PASSWORD),
        );
        session.expect_str("Alias added");
    }

    {
        let mut session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
        session.expect_str("Password retrieved");
    }

    {
        let mut session = setup.run(&["remove-alias", "example.info"], Some(MASTER_PASSWORD));
        session.expect_str("Alias removed");
    }

    {
        let mut session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
        session.expect_str("No such value");
    }

    {
        let mut session = setup.run(&["show", "example.net", "blubber"], Some(MASTER_PASSWORD));
        session.expect_str("Password retrieved");
    }
}
