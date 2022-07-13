/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::{
    api::{Deserializable, Serializable},
    Error, Value,
};
use secrecy::{ExposeSecret, SecretString};

pub fn serialize(value: &SecretString) -> Result<Value, Error> {
    value.expose_secret().serialize()
}

pub fn deserialize(value: &Value) -> Result<SecretString, Error> {
    Ok(SecretString::new(String::deserialize(value)?))
}

pub fn default() -> SecretString {
    SecretString::new(String::new())
}
