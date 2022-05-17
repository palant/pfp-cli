/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::common::Setup;

#[test]
fn empty_file() {
    let setup = Setup::new();
    setup.set_file_data("");
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("EOF");
}

#[test]
fn wrong_type() {
    let setup = Setup::new();
    setup.set_file_data("42");
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("invalid type");
}

#[test]
fn empty_object() {
    let setup = Setup::new();
    setup.set_file_data("{}");
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("missing field");
}

#[test]
fn wrong_application() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"easypasswords"}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("unknown variant");
    session.expect_str("pfp");
}

#[test]
fn wrong_format() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":8}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("Unexpected format");
    session.expect_str("expected 3");
}

#[test]
fn wrong_format_type() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":"3"}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("invalid type");
}

#[test]
fn missing_data() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":3}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("missing field");
}

#[test]
fn null_data() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":3,"data":null}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("invalid type");
}

#[test]
fn empty_data() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":3,"data":{}}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("missing field");
}

#[test]
fn missing_salt() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":3,"data":{"hmac_secret":"abc"}}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("missing field");
    session.expect_str("salt");
}

#[test]
fn missing_hmac_secret() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":3,"data":{"salt":"cba"}}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("missing field");
    session.expect_str("hmac-secret");
}

#[test]
fn missing_bracket() {
    let setup = Setup::new();
    setup.set_file_data(
        r#"{"application":"pfp","format":3,"data":{"salt":"cba","hmac-secret":"abc"}"#,
    );
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("EOF");
}

#[test]
fn extra_field() {
    let setup = Setup::new();
    setup.set_file_data(r#"{"application":"pfp","format":3,"data":{"salt":"cba","hmac-secret":"abc"},"something":2}"#);
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("unknown field");
}

#[test]
fn extra_data() {
    let setup = Setup::new();
    setup.set_file_data(
        r#"{"application":"pfp","format":3,"data":{"salt":"cba","hmac-secret":"abc"}}5"#,
    );
    let mut session = setup.run(&["list"], None);

    session.expect_str("Corrupt JSON data");
    session.expect_str("trailing characters");
}

#[test]
fn complete_data() {
    let setup = Setup::new();
    setup.set_file_data(
        r#"{"application":"pfp","format":3,"data":{"salt":"cba","hmac-secret":"abc"}}"#,
    );
    setup.run(&["list"], Some("asdf")).kill();
}
