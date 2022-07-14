/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::json::{Deserialize, Serialize};
use super::CharacterSet;
use secrecy::{ExposeSecret, SecretString};

fn empty_secret(str: &SecretString) -> bool {
    str.expose_secret().is_empty()
}

#[derive(Serialize, Deserialize, Debug)]
/// A password identifier, no two passwords with identical identifiers are allowed in storage.
pub struct PasswordId {
    site: String,
    name: String,
    revision: String,
}

impl PasswordId {
    /// Creates a new password identifier from site name, password name and password revision.
    ///
    /// Password revision is usually numerical but does not have to be. Revision `"1"` is treated
    /// like an empty string (no revision).
    pub fn new(site: &str, name: &str, revision: &str) -> PasswordId {
        PasswordId {
            site: site.to_string(),
            name: name.to_string(),
            revision: if revision != "1" {
                revision.to_string()
            } else {
                "".to_string()
            },
        }
    }

    /// Retrieves the site name associated with the password identifier.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Retrieves the password name associated with the password identifier.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Retrieves the password revision associated with the password identifier.
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

#[derive(Serialize, Deserialize, Debug)]
/// A generated password, generated from primary password and various password parameters when
/// needed.
pub struct GeneratedPassword {
    #[serde(flatten)]
    id: PasswordId,
    length: usize,
    #[serde(with = "super::character_set", flatten)]
    charset: CharacterSet,
    #[serde(
        skip_serializing_if = "empty_secret",
        default = "crate::json::secret_serialization::default",
        with = "crate::json::secret_serialization"
    )]
    notes: SecretString,
}

impl GeneratedPassword {
    /// Creates a password with given password generation parameters: site name, password name,
    /// password revision, password length and character types to be used.
    pub fn new(
        site: &str,
        name: &str,
        revision: &str,
        length: usize,
        charset: CharacterSet,
    ) -> GeneratedPassword {
        GeneratedPassword {
            id: PasswordId::new(site, name, revision),
            length,
            charset,
            notes: SecretString::new(String::new()),
        }
    }

    /// Retrieves the password's identifier.
    pub fn id(&self) -> &PasswordId {
        &self.id
    }

    /// Retrieves the password's length.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Retrieves the character types used when generating password.
    pub fn charset(&self) -> CharacterSet {
        self.charset
    }

    /// Retrieves the password-specific salt used when deriving data from the primary password for
    /// password generation.
    pub fn salt(&self) -> String {
        let mut salt = self.id.site().to_string();
        salt.push('\0');
        salt.push_str(self.id.name());
        if !self.id.revision().is_empty() {
            salt.push('\0');
            salt.push_str(self.id.revision());
        }
        salt
    }

    /// Retrieves the notes stored with the password if any.
    pub fn notes(&self) -> &SecretString {
        &self.notes
    }

    /// Sets the notes for the password.
    pub fn set_notes(&mut self, notes: SecretString) {
        self.notes = notes;
    }
}

#[derive(Serialize, Deserialize, Debug)]
/// A stored password, with the password value stored verbatim in storage.
pub struct StoredPassword {
    #[serde(flatten)]
    id: PasswordId,
    #[serde(with = "crate::json::secret_serialization")]
    password: SecretString,
    #[serde(
        skip_serializing_if = "empty_secret",
        default = "crate::json::secret_serialization::default",
        with = "crate::json::secret_serialization"
    )]
    notes: SecretString,
}

impl StoredPassword {
    /// Creates a password with given site name, password name, password revision and actual
    /// password value.
    pub fn new(site: &str, name: &str, revision: &str, password: SecretString) -> StoredPassword {
        StoredPassword {
            id: PasswordId::new(site, name, revision),
            password,
            notes: SecretString::new(String::new()),
        }
    }

    /// Retrieves the password's identifier.
    pub fn id(&self) -> &PasswordId {
        &self.id
    }

    /// Retrieves the password's value.
    pub fn password(&self) -> &SecretString {
        &self.password
    }

    /// Retrieves the notes stored with the password if any.
    pub fn notes(&self) -> &SecretString {
        &self.notes
    }

    /// Sets the notes for the password.
    pub fn set_notes(&mut self, notes: SecretString) {
        self.notes = notes;
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
/// The type used by functions that can handle both generated and stored passwords.
pub enum Password {
    #[serde(rename = "generated2")]
    /// Contains a generated password
    Generated(GeneratedPassword),
    /// Contains a stored password
    #[serde(rename = "stored")]
    Stored(StoredPassword),
}

impl Password {
    /// Retrieves the password's identifier.
    pub fn id(&self) -> &PasswordId {
        match self {
            Self::Generated(password) => password.id(),
            Self::Stored(password) => password.id(),
        }
    }

    /// Retrieves the notes stored with the password if any.
    pub fn notes(&self) -> &SecretString {
        match self {
            Self::Generated(password) => password.notes(),
            Self::Stored(password) => password.notes(),
        }
    }

    /// Sets the notes for the password.
    pub fn set_notes(&mut self, notes: SecretString) {
        match self {
            Self::Generated(password) => password.set_notes(notes),
            Self::Stored(password) => password.set_notes(notes),
        }
    }
}
