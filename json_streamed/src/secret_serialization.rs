/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

pub fn serialize<S>(value: &SecretString, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    value.expose_secret().serialize(s)
}

pub fn deserialize<'de, D>(d: D) -> Result<SecretString, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    Ok(SecretString::new(String::deserialize(d)?))
}

pub fn default() -> SecretString {
    SecretString::new(String::new())
}
