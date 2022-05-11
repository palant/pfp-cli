/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

const MASTER_PASSWORD: &str = "foobar";

#[test]
fn uninitialized()
{
    let setup = Setup::new();
    let mut session = setup.run(&["set-alias", "example.info", "example.com"], None);
    session.expect("Failed reading storage file").expect("App should error out on missing file");

    session = setup.run(&["remove-alias", "example.info"], None);
    let output = crate::common::read_to_eof(&mut session);
    eprintln!("{}", output);
    assert!(output.contains("Failed reading storage file"));
    //session.expect("Failed reading storage file").expect("App should error out on missing file");
}

#[test]
fn add_remove()
{
    let setup = Setup::new();
    setup.initialize(MASTER_PASSWORD);

    let mut session = setup.run(&["add", "example.com", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password added").expect("Call should succeed");

    session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
    session.expect("No such value").expect("Password retrieval should fail");

    session = setup.run(&["set-alias", "example.info", "example.com"], Some(MASTER_PASSWORD));
    session.expect("Alias added").expect("Call should succeed");

    session = setup.run(&["set-alias", "example.net", "example.com"], Some(MASTER_PASSWORD));
    session.expect("Alias added").expect("Call should succeed");

    session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved").expect("Password retrieval should succeed");

    session = setup.run(&["remove-alias", "example.info"], Some(MASTER_PASSWORD));
    session.expect("Alias removed").expect("Call should succeed");

    session = setup.run(&["show", "example.info", "blubber"], Some(MASTER_PASSWORD));
    session.expect("No such value").expect("Password retrieval should fail");

    session = setup.run(&["show", "example.net", "blubber"], Some(MASTER_PASSWORD));
    session.expect("Password retrieved").expect("Password retrieval should succeed");
}
