/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationName
{
    Pfp,
}

#[derive(Copy, Clone, Debug)]
pub enum Format
{
    Current = 3,
}

impl serde::ser::Serialize for Format
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
        where S: serde::ser::Serializer,
    {
        s.serialize_u64(*self as u64)
    }
}

impl<'de> serde::de::Deserialize<'de> for Format
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: serde::de::Deserializer<'de>
    {
        let result = u64::deserialize(deserializer)?;
        if result == Self::Current as u64
        {
            Ok(Self::Current)
        }
        else
        {
            Err(serde::de::Error::invalid_value(serde::de::Unexpected::Unsigned(result), &(Self::Current as u64).to_string().as_str()))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Metadata
{
    pub application: ApplicationName,
    pub format: Format,
    pub data: HashMap<String, String>,
}

impl Metadata
{
    pub fn new(data: HashMap<String, String>) -> Self
    {
        Self {
            application: ApplicationName::Pfp,
            format: Format::Current,
            data,
        }
    }
}
