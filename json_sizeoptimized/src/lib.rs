/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

pub use json_sizeoptimized_derive::{Deserialize, Serialize};
pub use serde_json::{json, Error, Map, Value};

mod api;
pub use api::*;

mod macros;
pub use macros::*;

mod types;
pub mod secret_serialization;

pub fn deserialize<'de, T: Deserializable<'de>>(value: &Value) -> Result<T, Error> {
    T::deserialize(value)
}

#[cold]
pub fn invalid_type(value: &Value, expected: &str) -> Error {
    serde::de::Error::custom(format!(
        "invalid type: got {}, expected {}",
        serde_json::to_string(value).unwrap(),
        expected
    ))
}

#[cold]
pub fn key_missing(key: &str) -> Error {
    serde::de::Error::custom(format!("missing field: {}", key))
}

#[cold]
pub fn invalid_value(value: &Value, expected: &str) -> Error {
    serde::de::Error::custom(format!(
        "Unexpected value: got {}, expected {}",
        serde_json::to_string(value).unwrap(),
        expected
    ))
}
