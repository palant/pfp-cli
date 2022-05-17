/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const MASTER_PASSWORD: &str = "foobar";

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
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password added");

    session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("No such value");

    session = setup.run(
        &["set-alias", "example.info", "example.com"],
        Some(MASTER_PASSWORD),
    );
    session.expect_str("Alias added");

    session = setup.run(
        &["set-alias", "example.net", "example.com"],
        Some(MASTER_PASSWORD),
    );
    session.expect_str("Alias added");

    session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved");

    session = setup.run(&["remove-alias", "example.info"], Some(MASTER_PASSWORD));
    session.expect_str("Alias removed");

    session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("No such value");

    session = setup.run(&["show", "example.net", "blubber"], Some(MASTER_PASSWORD));
    session.expect_str("Password retrieved");
}
