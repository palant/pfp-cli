/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

//! Various types processed by storage functions.

use serde::ser::{Serializer, Serialize, SerializeMap};
use serde::de::{Deserializer, Visitor, Deserialize, MapAccess, Unexpected, Error};

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

impl Serialize for Password
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        let mut map = serializer.serialize_map(None)?;
        match self
        {
            Password::Generated {password} =>
            {
                map.serialize_entry("type", "generated2")?;
                map.serialize_entry("site", password.id().site())?;
                map.serialize_entry("name", password.id().name())?;
                map.serialize_entry("revision", password.id().revision())?;
                map.serialize_entry("length", &password.length())?;
                map.serialize_entry("lower", &password.charset().contains(CharacterType::Lower))?;
                map.serialize_entry("upper", &password.charset().contains(CharacterType::Upper))?;
                map.serialize_entry("number", &password.charset().contains(CharacterType::Digit))?;
                map.serialize_entry("symbol", &password.charset().contains(CharacterType::Symbol))?;
                if !password.notes().is_empty()
                {
                    map.serialize_entry("notes", password.notes())?;
                }
            },
            Password::Stored {password} =>
            {
                map.serialize_entry("type", "stored")?;
                map.serialize_entry("site", password.id().site())?;
                map.serialize_entry("name", password.id().name())?;
                map.serialize_entry("revision", password.id().revision())?;
                map.serialize_entry("password", password.password())?;
                if !password.notes().is_empty()
                {
                    map.serialize_entry("notes", password.notes())?;
                }
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Password
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    {
        deserializer.deserialize_map(PasswordVisitor {})
    }
}

struct PasswordVisitor;

impl<'de> Visitor<'de> for PasswordVisitor
{
    type Value = Password;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        formatter.write_str("PfP password data")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error>
    {
        let mut pwdtype = 0;
        let mut site = None;
        let mut name = None;
        let mut revision = None;
        let mut length = None;
        let mut charset = CharacterSet::empty();
        let mut password = None;
        let mut notes = None;

        loop
        {
            match map.next_key::<&str>()?
            {
                None => break,
                Some("type") =>
                {
                    if pwdtype != 0
                    {
                        return Err(Error::duplicate_field("type"));
                    }

                    let value = map.next_value::<String>()?;
                    if value == "generated2"
                    {
                        pwdtype = 1;
                    }
                    else if value == "stored"
                    {
                        pwdtype = 2;
                    }
                    else
                    {
                        return Err(Error::invalid_value(Unexpected::Str(&value), &"generated2 or stored"));
                    }
                },
                Some("site") =>
                {
                    if site.is_some()
                    {
                        return Err(Error::duplicate_field("site"));
                    }

                    site = Some(map.next_value::<String>()?);
                },
                Some("name") =>
                {
                    if name.is_some()
                    {
                        return Err(Error::duplicate_field("name"));
                    }

                    name = Some(map.next_value::<String>()?);
                },
                Some("revision") =>
                {
                    if revision.is_some()
                    {
                        return Err(Error::duplicate_field("revision"));
                    }

                    revision = Some(map.next_value::<String>()?);
                },
                Some("length") =>
                {
                    if length.is_some()
                    {
                        return Err(Error::duplicate_field("length"));
                    }

                    length = Some(map.next_value::<usize>()?);
                },
                Some("lower") =>
                {
                    if map.next_value::<bool>()?
                    {
                        charset.insert(CharacterType::Lower);
                    }
                },
                Some("upper") =>
                {
                    if map.next_value::<bool>()?
                    {
                        charset.insert(CharacterType::Upper);
                    }
                },
                Some("number") =>
                {
                    if map.next_value::<bool>()?
                    {
                        charset.insert(CharacterType::Digit);
                    }
                },
                Some("symbol") =>
                {
                    if map.next_value::<bool>()?
                    {
                        charset.insert(CharacterType::Symbol);
                    }
                },
                Some("password") =>
                {
                    if password.is_some()
                    {
                        return Err(Error::duplicate_field("password"));
                    }

                    password = Some(map.next_value::<String>()?);
                },
                Some("notes") =>
                {
                    if notes.is_some()
                    {
                        return Err(Error::duplicate_field("notes"));
                    }

                    notes = Some(map.next_value::<String>()?);
                },
                Some(key) =>
                {
                    return Err(Error::unknown_field(key, &[]));
                },
            }
        }

        if pwdtype == 1
        {
            if password.is_some()
            {
                return Err(Error::unknown_field("password", &[]));
            }
            if charset.is_empty()
            {
                return Err(Error::missing_field("lower/upper/number/symbol"));
            }
            let mut result = GeneratedPassword::new(
                &site.ok_or_else(|| Error::missing_field("site"))?,
                &name.ok_or_else(|| Error::missing_field("name"))?,
                &revision.ok_or_else(|| Error::missing_field("revision"))?,
                length.ok_or_else(|| Error::missing_field("length"))?,
                charset,
            );
            if let Some(value) = notes
            {
                result.set_notes(&value);
            }
            Ok(Password::Generated { password: result })
        }
        else if pwdtype == 2
        {
            if length.is_some()
            {
                return Err(Error::unknown_field("length", &[]));
            }
            if !charset.is_empty()
            {
                return Err(Error::unknown_field("lower/upper/number/symbol", &[]));
            }
            let mut result = StoredPassword::new(
                &site.ok_or_else(|| Error::missing_field("site"))?,
                &name.ok_or_else(|| Error::missing_field("name"))?,
                &revision.ok_or_else(|| Error::missing_field("revision"))?,
                &password.ok_or_else(|| Error::missing_field("password"))?,
            );
            if let Some(value) = notes
            {
                result.set_notes(&value);
            }
            Ok(Password::Stored { password: result })
        }
        else
        {
            Err(Error::missing_field("type"))
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

impl Serialize for Site
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("site", self.name())?;
        if let Some(value) = self.alias()
        {
            map.serialize_entry("alias", value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Site
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    {
        deserializer.deserialize_map(SiteVisitor {})
    }
}

struct SiteVisitor;

impl<'de> Visitor<'de> for SiteVisitor
{
    type Value = Site;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result
    {
        formatter.write_str("PfP site data")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error>
    {
        let mut site = None;
        let mut alias = None;

        loop
        {
            match map.next_key::<&str>()?
            {
                None => break,
                Some("site") =>
                {
                    if site.is_some()
                    {
                        return Err(Error::duplicate_field("site"));
                    }

                    site = Some(map.next_value::<String>()?);
                },
                Some("alias") =>
                {
                    if alias.is_some()
                    {
                        return Err(Error::duplicate_field("alias"));
                    }

                    alias = Some(map.next_value::<String>()?);
                },
                Some(key) =>
                {
                    return Err(Error::unknown_field(key, &["site", "alias"]));
                },
            }
        }

        Ok(Site::new(
            &site.ok_or_else(|| Error::missing_field("site"))?,
            alias.as_deref(),
        ))
    }
}
