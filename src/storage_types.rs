/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Various types processed by storage functions.

use crate::error::Error;

pub(crate) trait FromJson
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error> where Self: Sized;
}

pub(crate) trait ToJson
{
    fn to_json(&self) -> json::object::Object;
}

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

impl FromJson for PasswordId
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error>
    {
        return Ok(PasswordId::new(
            value["site"].as_str().ok_or(Error::PasswordMissingSite)?,
            value["name"].as_str().ok_or(Error::PasswordMissingName)?,
            value["revision"].as_str().ok_or(Error::PasswordMissingRevision)?,
        ));
    }
}

impl ToJson for PasswordId
{
    fn to_json(&self) -> json::object::Object
    {
        let mut obj = json::object::Object::new();
        obj.insert("site", self.site().into());
        obj.insert("name", self.name().into());
        obj.insert("revision", self.revision().into());
        obj
    }
}

#[derive(Debug)]
/// A generated password, generated from master password and various password parameters when
/// needed.
pub struct GeneratedPassword
{
    id: PasswordId,
    length: usize,
    charset: CharacterSet
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
}

impl FromJson for GeneratedPassword
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error>
    {
        let id = PasswordId::from_json(value)?;

        let mut charset = CharacterSet::empty();
        if value["lower"].as_bool().unwrap_or(false)
        {
            charset.insert(CharacterType::Lower);
        }
        if value["upper"].as_bool().unwrap_or(false)
        {
            charset.insert(CharacterType::Upper);
        }
        if value["number"].as_bool().unwrap_or(false)
        {
            charset.insert(CharacterType::Digit);
        }
        if value["symbol"].as_bool().unwrap_or(false)
        {
            charset.insert(CharacterType::Symbol);
        }

        Ok(GeneratedPassword {
            id,
            length: value["length"].as_usize().ok_or(Error::PasswordMissingLength)?,
            charset,
        })
    }
}

impl ToJson for GeneratedPassword
{
    fn to_json(&self) -> json::object::Object
    {
        let mut obj = self.id.to_json();
        obj.insert("length", self.length().into());
        obj.insert("lower", self.charset().contains(CharacterType::Lower).into());
        obj.insert("upper", self.charset().contains(CharacterType::Upper).into());
        obj.insert("number", self.charset().contains(CharacterType::Digit).into());
        obj.insert("symbol", self.charset().contains(CharacterType::Symbol).into());
        obj
    }
}

#[derive(Debug)]
/// A stored password, with the password value stored verbatim in storage.
pub struct StoredPassword
{
    id: PasswordId,
    password: String,
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
}

impl FromJson for StoredPassword
{
    fn from_json(value: &json::object::Object) -> Result<StoredPassword, Error>
    {
        let id = PasswordId::from_json(value)?;
        let password = value["password"].as_str().ok_or(Error::PasswordMissingValue)?;
        Ok(StoredPassword {
            id,
            password: password.to_string(),
        })
    }
}

impl ToJson for StoredPassword
{
    fn to_json(&self) -> json::object::Object
    {
        let mut obj = self.id.to_json();
        obj.insert("password", self.password().into());
        obj
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
        return match self
        {
            Self::Generated { password } => password.id(),
            Self::Stored { password } => password.id(),
        };
    }
}

impl FromJson for Password
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error>
    {
        let password_type = value["type"].as_str().ok_or(Error::PasswordMissingType)?;
        if password_type == "generated2"
        {
            Ok(Password::Generated { password: GeneratedPassword::from_json(value)? })
        }
        else if password_type == "stored"
        {
            Ok(Password::Stored { password: StoredPassword::from_json(value)? })
        }
        else
        {
            Err(Error::PasswordUnknownType)
        }
    }
}

impl ToJson for Password
{
    fn to_json(&self) -> json::object::Object
    {
        match self
        {
            Password::Generated {password} =>
            {
                let mut value = password.to_json();
                value.insert("type", "generated2".into());
                value
            },
            Password::Stored {password} =>
            {
                let mut value = password.to_json();
                value.insert("type", "stored".into());
                value
            }
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

impl FromJson for Site
{
    fn from_json(value: &json::object::Object) -> Result<Site, Error>
    {
        return Ok(Site::new(
            value["site"].as_str().ok_or(Error::SiteMissingName)?,
            value["alias"].as_str(),
        ));
    }
}

impl ToJson for Site
{
    fn to_json(&self) -> json::object::Object
    {
        let mut obj = json::object::Object::new();
        obj.insert("site", self.name().into());
        if let Some(value) = self.alias()
        {
            obj.insert("alias", value.into());
        }
        obj
    }
}
