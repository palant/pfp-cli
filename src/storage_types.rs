/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::crypto;
use super::error::Error;

pub trait FromJson
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error> where Self: Sized;
}

pub trait ToJson
{
    fn to_json(&self) -> json::object::Object;
}

#[derive(Debug)]
pub struct PasswordId
{
    site: String,
    name: String,
    revision: String,
}

impl PasswordId
{
    pub fn new(site: &str, name: &str, revision: &str) -> PasswordId
    {
        return PasswordId
        {
            site: site.to_string(),
            name: name.to_string(),
            revision: if revision != "1" { revision.to_string() } else { "".to_string() },
        };
    }

    pub fn site(&self) -> &str
    {
        return &self.site;
    }

    pub fn name(&self) -> &str
    {
        return &self.name;
    }

    pub fn revision(&self) -> &str
    {
        return &self.revision;
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
        return obj;
    }
}

#[derive(Debug)]
pub struct GeneratedPassword
{
    id: PasswordId,
    length: usize,
    charset: enumset::EnumSet<crypto::CharacterType>
}

impl GeneratedPassword
{
    pub fn new(site: &str, name: &str, revision: &str, length: usize, charset: enumset::EnumSet<crypto::CharacterType>) -> GeneratedPassword
    {
        return GeneratedPassword
        {
            id: PasswordId::new(site, name, revision),
            length: length,
            charset: charset,
        };
    }

    pub fn id(&self) -> &PasswordId
    {
        return &self.id;
    }

    pub fn length(&self) -> usize
    {
        return self.length;
    }

    pub fn charset(&self) -> enumset::EnumSet<crypto::CharacterType>
    {
        return self.charset;
    }

    pub fn salt(&self) -> String
    {
        let mut salt = self.id.site().to_string();
        salt.push_str("\0");
        salt.push_str(&self.id.name());
        if self.id.revision() != ""
        {
            salt.push_str("\0");
            salt.push_str(&self.id.revision());
        }
        return salt;
    }
}

impl FromJson for GeneratedPassword
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error>
    {
        let id = PasswordId::from_json(value)?;

        let mut charset = crypto::new_charset();
        if value["lower"].as_bool().unwrap_or(false)
        {
            charset.insert(crypto::CharacterType::LOWER);
        }
        if value["upper"].as_bool().unwrap_or(false)
        {
            charset.insert(crypto::CharacterType::UPPER);
        }
        if value["number"].as_bool().unwrap_or(false)
        {
            charset.insert(crypto::CharacterType::DIGIT);
        }
        if value["symbol"].as_bool().unwrap_or(false)
        {
            charset.insert(crypto::CharacterType::SYMBOL);
        }

        return Ok(GeneratedPassword {
            id: id,
            length: value["length"].as_usize().ok_or(Error::PasswordMissingLength)?,
            charset: charset,
        });
    }
}

impl ToJson for GeneratedPassword
{
    fn to_json(&self) -> json::object::Object
    {
        let mut obj = self.id.to_json();
        obj.insert("length", self.length().into());
        obj.insert("lower", self.charset().contains(crypto::CharacterType::LOWER).into());
        obj.insert("upper", self.charset().contains(crypto::CharacterType::UPPER).into());
        obj.insert("number", self.charset().contains(crypto::CharacterType::DIGIT).into());
        obj.insert("symbol", self.charset().contains(crypto::CharacterType::SYMBOL).into());
        return obj;
    }
}

#[derive(Debug)]
pub struct StoredPassword
{
    id: PasswordId,
    password: String,
}

impl StoredPassword
{
    pub fn new(site: &str, name: &str, revision: &str, password: &str) -> StoredPassword
    {
        return StoredPassword
        {
            id: PasswordId::new(site, name, revision),
            password: password.to_string(),
        };
    }

    pub fn id(&self) -> &PasswordId
    {
        return &self.id;
    }

    pub fn password(&self) -> &str
    {
        return &self.password;
    }
}

impl FromJson for StoredPassword
{
    fn from_json(value: &json::object::Object) -> Result<StoredPassword, Error>
    {
        let id = PasswordId::from_json(value)?;
        let password = value["password"].as_str().ok_or(Error::PasswordMissingValue)?;
        return Ok(StoredPassword {
            id: id,
            password: password.to_string(),
        });
    }
}

impl ToJson for StoredPassword
{
    fn to_json(&self) -> json::object::Object
    {
        let mut obj = self.id.to_json();
        obj.insert("password", self.password().into());
        return obj;
    }
}

#[derive(Debug)]
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

impl FromJson for Password
{
    fn from_json(value: &json::object::Object) -> Result<Self, Error>
    {
        let password_type = value["type"].as_str().ok_or(Error::PasswordMissingType)?;
        if password_type == "generated2"
        {
            return Ok(Password::Generated { password: GeneratedPassword::from_json(value)? });
        }
        else if password_type == "stored"
        {
            return Ok(Password::Stored { password: StoredPassword::from_json(value)? });
        }
        return Err(Error::PasswordUnknownType);
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
                return value;
            },
            Password::Stored {password} =>
            {
                let mut value = password.to_json();
                value.insert("type", "stored".into());
                return value;
            }
        };
    }
}

#[derive(Debug)]
pub struct Site
{
    name: String,
    alias: Option<String>,
}

impl Site
{
    pub fn new(name: &str, alias: Option<&str>) -> Site
    {
        return Site
        {
            name: name.to_string(),
            alias: match alias
            {
                Some(value) => Some(value.to_string()),
                None => None,
            },
        };
    }

    pub fn name(&self) -> &str
    {
        return &self.name;
    }

    pub fn alias(&self) -> Option<&str>
    {
        return match &self.alias
        {
            Some(value) => Some(value),
            None => None,
        };
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
        match self.alias()
        {
            Some(value) => obj.insert("alias", value.into()),
            None => {},
        }
        return obj;
    }
}
