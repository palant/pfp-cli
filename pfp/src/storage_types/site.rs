/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::json::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
/// A website entry in storage.
pub struct Site {
    #[serde(rename = "site")]
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    alias: Option<String>,
}

impl Site {
    /// Creates a new website entry from name and optionally name of the site it is aliased to.
    pub fn new(name: &str, alias: Option<&str>) -> Site {
        Site {
            name: name.to_string(),
            alias: alias.map(|alias| alias.to_string()),
        }
    }

    /// Retrieves the website's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieves the name of the website this site is aliased to if any.
    pub fn alias(&self) -> Option<&str> {
        match &self.alias {
            Some(value) => Some(value),
            None => None,
        }
    }
}
