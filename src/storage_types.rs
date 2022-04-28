/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use json::object;
use super::crypto;
use super::error::Error;

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

impl TryFrom<&json::JsonValue> for PasswordId
{
    type Error = Error;
    fn try_from(value: &json::JsonValue) -> Result<PasswordId, Self::Error>
    {
        return Ok(PasswordId::new(
            value["site"].as_str().ok_or(Error::PasswordMissingSite)?,
            value["name"].as_str().ok_or(Error::PasswordMissingName)?,
            value["revision"].as_str().ok_or(Error::PasswordMissingRevision)?,
        ));
    }
}

impl From<&PasswordId> for json::JsonValue
{
    fn from(value: &PasswordId) -> json::JsonValue
    {
        return object!{
            site: value.site(),
            name: value.name(),
            revision: value.revision(),
        };
    }
}

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

impl TryFrom<&json::JsonValue> for GeneratedPassword
{
    type Error = Error;
    fn try_from(value: &json::JsonValue) -> Result<GeneratedPassword, Self::Error>
    {
        let id = PasswordId::try_from(value)?;

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

impl From<&GeneratedPassword> for json::JsonValue
{
    fn from(value: &GeneratedPassword) -> json::JsonValue
    {
        let mut obj = json::JsonValue::from(&value.id);
        obj.insert("length", value.length()).unwrap();
        obj.insert("lower", value.charset().contains(crypto::CharacterType::LOWER)).unwrap();
        obj.insert("upper", value.charset().contains(crypto::CharacterType::UPPER)).unwrap();
        obj.insert("number", value.charset().contains(crypto::CharacterType::DIGIT)).unwrap();
        obj.insert("symbol", value.charset().contains(crypto::CharacterType::SYMBOL)).unwrap();
        return obj;
    }
}

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

impl TryFrom<&json::JsonValue> for StoredPassword
{
    type Error = Error;
    fn try_from(value: &json::JsonValue) -> Result<StoredPassword, Self::Error>
    {
        let id = PasswordId::try_from(value)?;
        let password = value["password"].as_str().ok_or(Error::PasswordMissingValue)?;
        return Ok(StoredPassword {
            id: id,
            password: password.to_string(),
        });
    }
}

impl From<&StoredPassword> for json::JsonValue
{
    fn from(value: &StoredPassword) -> json::JsonValue
    {
        let mut obj = json::JsonValue::from(&value.id);
        obj.insert("password", value.password()).unwrap();
        return obj;
    }
}

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

impl TryFrom<json::JsonValue> for Password
{
    type Error = Error;
    fn try_from(value: json::JsonValue) -> Result<Password, Self::Error>
    {
        let password_type = value["type"].as_str().ok_or(Error::PasswordMissingType)?;
        if password_type == "generated2"
        {
            return Ok(Password::Generated { password: GeneratedPassword::try_from(&value)? });
        }
        else if password_type == "stored"
        {
            return Ok(Password::Stored { password: StoredPassword::try_from(&value)? });
        }
        return Err(Error::PasswordUnknownType);
    }
}

impl From<&Password> for json::JsonValue
{
    fn from(value: &Password) -> json::JsonValue
    {
        match value
        {
            Password::Generated {password} =>
            {
                let mut value = json::JsonValue::from(password);
                value.insert("type", "generated2").unwrap();
                return value;
            },
            Password::Stored {password} =>
            {
                let mut value = json::JsonValue::from(password);
                value.insert("type", "stored").unwrap();
                return value;
            }
        };
    }
}

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

impl TryFrom<json::JsonValue> for Site
{
    type Error = Error;
    fn try_from(value: json::JsonValue) -> Result<Site, Self::Error>
    {
        return Ok(Site::new(
            value["site"].as_str().ok_or(Error::SiteMissingName)?,
            value["alias"].as_str(),
        ));
    }
}

impl From<&Site> for json::JsonValue
{
    fn from(value: &Site) -> json::JsonValue
    {
        let mut obj = object!{
            site: value.name(),
        };
        match value.alias()
        {
            Some(value) => obj.insert("alias", value).unwrap(),
            None => {},
        }
        return obj;
    }
}
