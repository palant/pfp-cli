/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
enum ApplicationName
{
    Pfp,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(try_from="u8", into="u8")]
enum Format
{
    Current = 3,
}

impl From<Format> for u8
{
    fn from(value: Format) -> u8
    {
        value as u8
    }
}

impl TryFrom<u8> for Format
{
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error>
    {
        if value == Self::Current as u8
        {
            Ok(Self::Current)
        }
        else
        {
            Err(format!("Unexpected format {}, expected {}", value, Self::Current as u8))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Metadata
{
    application: ApplicationName,
    format: Format,
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

    pub fn data(&self) -> &HashMap<String, String>
    {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut HashMap<String, String>
    {
        &mut self.data
    }
}
