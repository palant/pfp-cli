/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use serde::{Serialize, Deserialize};
use serde_repr::{Serialize_repr, Deserialize_repr};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum FieldName
{
    Application,
    Format,
    Data,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ApplicationName
{
    Pfp,
}

#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u32)]
enum Format
{
    Current = 3,
}

#[derive(Serialize)]
pub struct Serializer<'ser>
{
    application: ApplicationName,
    format: Format,
    data: &'ser HashMap<String, String>,
}

impl<'ser> Serializer<'ser>
{
    pub fn new(data: &'ser HashMap<String, String>) -> Self
    {
        Self {
            application: ApplicationName::Pfp,
            format: Format::Current,
            data,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deserializer
{
    #[allow(dead_code)]
    application: ApplicationName,
    #[allow(dead_code)]
    format: Format,
    data: HashMap<String, String>,
}

impl Deserializer
{
    pub fn data(self) -> HashMap<String, String>
    {
        self.data
    }
}
