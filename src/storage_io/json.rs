/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use serde::ser::{Serialize, SerializeMap};
use serde::de::{Visitor, Deserialize, MapAccess, Unexpected};
use std::collections::HashMap;

const APPLICATION_KEY: &str = "application";
const APPLICATION_VALUE: &str = "pfp";
const FORMAT_KEY: &str = "format";
const CURRENT_FORMAT: u64 = 3;
const DATA_KEY: &str = "data";

pub(crate) struct Serializer<'ser>
{
    io: &'ser super::FileIO,
}

impl<'ser> Serializer<'ser>
{
    pub fn new(io: &'ser super::FileIO) -> Self
    {
        Self {
            io,
        }
    }
}

impl<'ser> Serialize for Serializer<'ser>
{
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(APPLICATION_KEY, APPLICATION_VALUE)?;
        map.serialize_entry(FORMAT_KEY, &CURRENT_FORMAT)?;
        map.serialize_entry(DATA_KEY, self.io.data())?;
        map.end()
    }
}

pub(crate) struct Deserializer
{
    data: Option<HashMap<String, String>>,
}

impl Deserializer
{
    pub fn new() -> Self
    {
        Self {
            data: None,
        }
    }

    pub fn data(self) -> Option<HashMap<String, String>>
    {
        self.data
    }
}

impl<'de> Deserialize<'de> for Deserializer
{
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    {
        deserializer.deserialize_map(Self::new())
    }
}

impl<'de> Visitor<'de> for Deserializer
{
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        formatter.write_str("valid PfP backup data")
    }

    type Value = Self;

    fn visit_map<A: MapAccess<'de>>(mut self, mut map: A) -> Result<Self::Value, A::Error>
    {
        let mut seen_application = false;
        let mut seen_format = false;

        loop
        {
            match map.next_key::<&str>()?
            {
                None => break,
                Some(APPLICATION_KEY) =>
                {
                    if seen_application
                    {
                        return Err(serde::de::Error::duplicate_field(APPLICATION_KEY));
                    }

                    let value = map.next_value::<String>()?;
                    if value != APPLICATION_VALUE
                    {
                        return Err(serde::de::Error::invalid_value(Unexpected::Str(&value), &APPLICATION_VALUE));
                    }
                    seen_application = true;
                },
                Some(FORMAT_KEY) =>
                {
                    if seen_format
                    {
                        return Err(serde::de::Error::duplicate_field(FORMAT_KEY));
                    }

                    let value = map.next_value::<u64>()?;
                    if value != CURRENT_FORMAT
                    {
                        return Err(serde::de::Error::invalid_value(Unexpected::Unsigned(value), &CURRENT_FORMAT.to_string().as_str()));
                    }
                    seen_format = true;
                },
                Some(DATA_KEY) =>
                {
                    if self.data.is_some()
                    {
                        return Err(serde::de::Error::duplicate_field(DATA_KEY));
                    }

                    self.data = Some(map.next_value()?);
                },
                Some(key) =>
                {
                    return Err(serde::de::Error::unknown_field(key, &[APPLICATION_KEY, FORMAT_KEY, DATA_KEY]));
                },
            }
        }

        if !seen_application
        {
            Err(serde::de::Error::missing_field(APPLICATION_KEY))
        }
        else if !seen_format
        {
            Err(serde::de::Error::missing_field(FORMAT_KEY))
        }
        else if self.data.is_none()
        {
            Err(serde::de::Error::missing_field(DATA_KEY))
        }
        else
        {
            Ok(self)
        }
    }
}
