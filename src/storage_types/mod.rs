/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Various types processed by storage functions.

mod json;

#[derive(enumset::EnumSetType, Debug)]
/// Possible character types that a password is generated from.
pub enum CharacterType
{
    Lower,
    Upper,
    Digit,
    Symbol,
}

/// A set of character types to generate a password from.
pub type CharacterSet = enumset::EnumSet<CharacterType>;

#[derive(Debug)]
/// A password identifier, no two passwords with identical identifiers are allowed in storage.
pub struct PasswordId
{
    site: String,
    name: String,
    revision: String,
}

impl PasswordId
{
    /// Creates a new password identifier from site name, password name and password revision.
    ///
    /// Password revision is usually numerical but does not have to be. Revision `"1"` is treated
    /// like an empty string (no revision).
    pub fn new(site: &str, name: &str, revision: &str) -> PasswordId
    {
        PasswordId {
            site: site.to_string(),
            name: name.to_string(),
            revision: if revision != "1" { revision.to_string() } else { "".to_string() },
        }
    }

    /// Retrieves the site name associated with the password identifier.
    pub fn site(&self) -> &str
    {
        &self.site
    }

    /// Retrieves the password name associated with the password identifier.
    pub fn name(&self) -> &str
    {
        &self.name
    }

    /// Retrieves the password revision associated with the password identifier.
    pub fn revision(&self) -> &str
    {
        &self.revision
    }
}

#[derive(Debug)]
/// A generated password, generated from master password and various password parameters when
/// needed.
pub struct GeneratedPassword
{
    id: PasswordId,
    length: usize,
    charset: CharacterSet,
    notes: String,
}

impl GeneratedPassword
{
    /// Creates a password with given password generation parameters: site name, password name,
    /// password revision, password length and character types to be used.
    pub fn new(site: &str, name: &str, revision: &str, length: usize, charset: CharacterSet) -> GeneratedPassword
    {
        GeneratedPassword {
            id: PasswordId::new(site, name, revision),
            length,
            charset,
            notes: String::new(),
        }
    }

    /// Retrieves the password's identifier.
    pub fn id(&self) -> &PasswordId
    {
        &self.id
    }

    /// Retrieves the password's length.
    pub fn length(&self) -> usize
    {
        self.length
    }

    /// Retrieves the character types used when generating password.
    pub fn charset(&self) -> CharacterSet
    {
        self.charset
    }

    /// Retrieves the password-specific salt used when deriving data from the master password for
    /// password generation.
    pub fn salt(&self) -> String
    {
        let mut salt = self.id.site().to_string();
        salt.push('\0');
        salt.push_str(self.id.name());
        if !self.id.revision().is_empty()
        {
            salt.push('\0');
            salt.push_str(self.id.revision());
        }
        salt
    }

    /// Retrieves the notes stored with the password if any.
    pub fn notes(&self) -> &str
    {
        &self.notes
    }

    /// Sets the notes for the password.
    pub fn set_notes(&mut self, notes: &str)
    {
        self.notes = notes.to_string();
    }
}

#[derive(Debug)]
/// A stored password, with the password value stored verbatim in storage.
pub struct StoredPassword
{
    id: PasswordId,
    password: String,
    notes: String,
}

impl StoredPassword
{
    /// Creates a password with given site name, password name, password revision and actual
    /// password value.
    pub fn new(site: &str, name: &str, revision: &str, password: &str) -> StoredPassword
    {
        StoredPassword {
            id: PasswordId::new(site, name, revision),
            password: password.to_string(),
            notes: String::new(),
        }
    }

    /// Retrieves the password's identifier.
    pub fn id(&self) -> &PasswordId
    {
        &self.id
    }

    /// Retrieves the password's value.
    pub fn password(&self) -> &str
    {
        &self.password
    }

    /// Retrieves the notes stored with the password if any.
    pub fn notes(&self) -> &str
    {
        &self.notes
    }

    /// Sets the notes for the password.
    pub fn set_notes(&mut self, notes: &str)
    {
        self.notes = notes.to_string();
    }
}

#[derive(Debug)]
/// The type used by functions that can handle both generated and stored passwords.
pub enum Password
{
    Generated
    {
        password: GeneratedPassword,
    },
    Stored
    {
        password: StoredPassword,
    },
}

impl Password
{
    /// Retrieves the password's identifier.
    pub fn id(&self) -> &PasswordId
    {
        match self
        {
            Self::Generated { password } => password.id(),
            Self::Stored { password } => password.id(),
        }
    }

    /// Retrieves the notes stored with the password if any.
    pub fn notes(&self) -> &str
    {
        match self
        {
            Self::Generated { password } => password.notes(),
            Self::Stored { password } => password.notes(),
        }
    }

    /// Sets the notes for the password.
    pub fn set_notes(&mut self, notes: &str)
    {
        match self
        {
            Self::Generated { password } => password.set_notes(notes),
            Self::Stored { password } => password.set_notes(notes),
        }
    }
}

#[derive(Debug)]
/// A website entry in storage.
pub struct Site
{
    name: String,
    alias: Option<String>,
}

impl Site
{
    /// Creates a new website entry from name and optionally name of the site it is aliased to.
    pub fn new(name: &str, alias: Option<&str>) -> Site
    {
        Site
        {
            name: name.to_string(),
            alias: alias.map(|alias| alias.to_string()),
        }
    }

    /// Retrieves the website's name.
    pub fn name(&self) -> &str
    {
        &self.name
    }

    /// Retrieves the name of the website this site is aliased to if any.
    pub fn alias(&self) -> Option<&str>
    {
        match &self.alias
        {
            Some(value) => Some(value),
            None => None,
        }
    }
}
