/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const PRIMARY_PASSWORD: &str = "foobar";
const SECRETS: &[&[u8]] = &[PRIMARY_PASSWORD.as_bytes()];

#[test]
fn uninitialized() {
    let setup = Setup::new();

    {
        let mut session = setup.run(&["alias", "example.info"], None);
        session.expect_str("Failed reading storage file");
    }

    {
        let mut session = setup.run(&["alias", "example.info", "example.com"], None);
        session.expect_str("Failed reading storage file");
    }

    {
        let mut session = setup.run(&["alias", "-r", "example.info"], None);
        session.expect_str("Failed reading storage file");
    }
}

#[test]
fn add_remove() {
    let mut setup = Setup::new();
    setup.set_secrets(SECRETS);
    setup.initialize(PRIMARY_PASSWORD);

    {
        let mut session = setup.run(&["add", "example.com", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password added");
    }

    {
        let mut session = setup.run(&["show", "example.info", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("No such value");
    }

    {
        let mut session = setup.run(&["alias", "example.info"], Some(PRIMARY_PASSWORD));
        session.expect_str("is not an alias");
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
            &["alias", "example.net", "example.com"],
            Some(PRIMARY_PASSWORD),
        );
        session.expect_str("Alias added");
    }

    {
        let mut session = setup.run(&["alias", "example.info"], Some(PRIMARY_PASSWORD));
        session.expect_str("'example.info' is an alias for 'example.com'");
    }

    {
        let mut session = setup.run(&["alias", "example.net"], Some(PRIMARY_PASSWORD));
        session.expect_str("'example.net' is an alias for 'example.com'");
    }

    {
        let mut session = setup.run(&["alias", "example.com"], Some(PRIMARY_PASSWORD));
        session.expect_str("is not an alias");
    }

    {
        let mut session = setup.run(&["show", "example.info", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password retrieved");
    }

    {
        let mut session = setup.run(&["alias", "-r", "example.info"], Some(PRIMARY_PASSWORD));
        session.expect_str("Alias removed");
    }

    {
        let mut session = setup.run(&["show", "example.info", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("No such value");
    }

    {
        let mut session = setup.run(&["show", "example.net", "blubber"], Some(PRIMARY_PASSWORD));
        session.expect_str("Password retrieved");
    }
}
