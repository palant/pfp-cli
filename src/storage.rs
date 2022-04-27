/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::crypto;
use json::object;
use std::fs;
use std::io;
use std::path;

const APPLICATION_KEY: &str = "application";
const APPLICATION_VALUE: &str = "pfp";
const FORMAT_KEY: &str = "format";
const CURRENT_FORMAT: u32 = 3;
const DATA_KEY: &str = "data";
const SALT_KEY: &str = "salt";
const HMAC_SECRET_KEY: &str = "hmac-secret";
const STORAGE_PREFIX: &str = "site:";

fn insert_encrypted(obj: &mut json::JsonValue, key: &String, value: &json::JsonValue, encryption_key: &[u8]) -> Option<()>
{
    return obj.insert(key, crypto::encrypt_data(value.dump().as_bytes(), encryption_key)).ok();
}

fn decrypt(value: &json::JsonValue, encryption_key: &[u8]) -> Option<json::JsonValue>
{
    let value = value.as_str()?;
    let decrypted = crypto::decrypt_data(&value.to_string(), encryption_key)?;
    return json::parse(&decrypted).ok();
}

fn get_decrypted(obj: &json::JsonValue, key: &String, encryption_key: &[u8]) -> Option<json::JsonValue>
{
    return decrypt(&obj[key], encryption_key);
}

fn parse_storage(path: &path::PathBuf) -> Result<json::JsonValue, io::Error>
{
    let contents = fs::read_to_string(path)?;
    let mut root = match json::parse(&contents)
    {
        Ok(node) => node,
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
    };
    if !root.is_object()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "storage root is not an object"));
    }

    if root[APPLICATION_KEY] != APPLICATION_VALUE || root[FORMAT_KEY] != CURRENT_FORMAT
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown format"));
    }

    let data = root.remove(DATA_KEY);
    if !data.is_object()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "storage data isn't an object"));
    }

    if !data[SALT_KEY].is_string() || !data[HMAC_SECRET_KEY].is_string()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing password salt or HMAC secret"));
    }

    return Ok(data)
}

fn to_password(value: &json::JsonValue) -> Option<Password>
{
    if !value.is_object()
    {
        return None;
    }

    let password_type = value["type"].as_str()?;
    if password_type == "generated2"
    {
        let mut charset = crypto::new_charset();
        if value["lower"].as_bool()?
        {
            charset.insert(crypto::CharacterType::LOWER);
        }
        if value["upper"].as_bool()?
        {
            charset.insert(crypto::CharacterType::UPPER);
        }
        if value["number"].as_bool()?
        {
            charset.insert(crypto::CharacterType::DIGIT);
        }
        if value["symbol"].as_bool()?
        {
            charset.insert(crypto::CharacterType::SYMBOL);
        }
        return Some(Password::Generated {
            password: GeneratedPassword::new(
                value["site"].as_str()?.to_string(),
                value["name"].as_str()?.to_string(),
                value["revision"].as_str()?.to_string(),
                value["length"].as_usize()?,
                charset
            )
        });
    }
    else if password_type == "stored"
    {
        return Some(Password::Stored {
            password: StoredPassword::new(
                value["site"].as_str()?.to_string(),
                value["name"].as_str()?.to_string(),
                value["revision"].as_str()?.to_string(),
                value["password"].as_str()?.to_string(),
            )
        });
    }
    return None;
}

pub struct PasswordId
{
    site: String,
    name: String,
    revision: String,
}

impl PasswordId
{
    pub fn new(site: String, name: String, revision: String) -> PasswordId
    {
        return PasswordId
        {
            site: site,
            name: name,
            revision: if revision != "1" { revision } else { "".to_string() },
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

pub struct GeneratedPassword
{
    id: PasswordId,
    length: usize,
    charset: enumset::EnumSet<crypto::CharacterType>
}

impl GeneratedPassword
{
    pub fn new(site: String, name: String, revision: String, length: usize, charset: enumset::EnumSet<crypto::CharacterType>) -> GeneratedPassword
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

pub struct StoredPassword
{
    id: PasswordId,
    password: String,
}

impl StoredPassword
{
    pub fn new(site: String, name: String, revision: String, password: String) -> StoredPassword
    {
        return StoredPassword
        {
            id: PasswordId::new(site, name, revision),
            password: password,
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

pub struct Storage
{
    path: path::PathBuf,
    data: Option<json::JsonValue>,
}

impl Storage
{
    pub fn new(path: &path::PathBuf) -> Storage
    {
        return Storage {
            path: path.clone(),
            data: match parse_storage(path)
            {
                Ok(data) => Some(data),
                Err(_error) => None,
            }
        };
    }

    pub fn clear(&mut self)
    {
        self.data = Some(object!{});
    }

    pub fn flush(&self) -> Option<()>
    {
        let mut root = object!{};
        root.insert(APPLICATION_KEY, APPLICATION_VALUE).ok()?;
        root.insert(FORMAT_KEY, CURRENT_FORMAT).ok()?;
        root.insert(DATA_KEY, self.data.clone()).ok()?;

        let parent = self.path.parent();
        if parent.is_some()
        {
            fs::create_dir_all(parent?).ok()?;
        }
        fs::write(&self.path, json::stringify(root)).ok()?;
        return Some(());
    }

    pub fn initialized(&self) -> Option<()>
    {
        self.data.as_ref()?;
        return Some(());
    }

    pub fn get_path(&self) -> &path::PathBuf
    {
        return &self.path;
    }

    pub fn get_salt(&self) -> Option<Vec<u8>>
    {
        self.initialized()?;

        let salt = self.data.as_ref()?[SALT_KEY].as_str()?;
        return base64::decode(salt).ok();
    }

    pub fn set_salt(&mut self, salt: &[u8]) -> Option<()>
    {
        self.initialized()?;

        return self.data.as_mut()?.insert(SALT_KEY, base64::encode(salt)).ok();
    }

    pub fn get_hmac_secret(&self, encryption_key: &Vec<u8>) -> Option<Vec<u8>>
    {
        self.initialized()?;

        let hmac_secret_value = get_decrypted(self.data.as_ref()?, &HMAC_SECRET_KEY.to_string(), encryption_key)?;
        let hmac_secret = hmac_secret_value.as_str()?;
        return base64::decode(hmac_secret).ok();
    }

    pub fn set_hmac_secret(&mut self, hmac_secret: &[u8], encryption_key: &Vec<u8>) -> Option<()>
    {
        self.initialized()?;

        return insert_encrypted(self.data.as_mut()?, &HMAC_SECRET_KEY.to_string(), &base64::encode(hmac_secret).into(), encryption_key);
    }

    fn get_site_key(&self, site: &String, hmac_secret: &[u8]) -> String
    {
        let mut result = String::new();
        result.push_str(STORAGE_PREFIX);
        result.push_str(&crypto::get_digest(hmac_secret, site));
        return result;
    }

    fn get_site_prefix(&self, site: &String, hmac_secret: &[u8]) -> String
    {
        let mut result = self.get_site_key(site, hmac_secret);
        result.push_str(":");
        return result;
    }

    fn get_password_key(&self, id: &PasswordId, hmac_secret: &[u8]) -> String
    {
        let mut input = String::new();
        input.push_str(id.site());
        input.push_str("\0");
        input.push_str(id.name());
        input.push_str("\0");
        input.push_str(id.revision());

        let mut result = self.get_site_prefix(&id.site().to_string(), hmac_secret);
        result.push_str(&crypto::get_digest(hmac_secret, &input));
        return result;
    }

    pub fn get_alias(&self, site: &String, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<String>
    {
        let key = self.get_site_key(site, hmac_secret);
        let data = get_decrypted(self.data.as_ref()?, &key, encryption_key)?;
        return if data.is_object() { Some(data["alias"].as_str()?.to_string()) } else { None };
    }

    pub fn resolve_site(&self, site: &String, hmac_secret: &[u8], encryption_key: &[u8]) -> String
    {
        let stripped = site.strip_prefix("www.").unwrap_or(site).to_string();
        return self.get_alias(&stripped, hmac_secret, encryption_key).unwrap_or(stripped);
    }

    pub fn ensure_site_data(&mut self, site: &String, hmac_secret: &[u8], encryption_key: &[u8])
    {
        assert!(self.initialized().is_some());

        let key = self.get_site_key(site, hmac_secret);
        let data = get_decrypted(self.data.as_ref().unwrap(), &key, encryption_key);
        if !data.is_some() || !data.unwrap().is_object()
        {
            insert_encrypted(self.data.as_mut().unwrap(), &key, &object!{
                site: site.as_str()
            }, encryption_key);
        }
    }

    pub fn has_password(&self, id: &PasswordId, hmac_secret: &[u8]) -> Option<bool>
    {
        let key = self.get_password_key(id, hmac_secret);
        return Some(self.data.as_ref()?.has_key(&key));
    }

    pub fn set_generated(&mut self, password: &GeneratedPassword, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<()>
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        let value = object!{
            type: "generated2",
            site: password.id().site(),
            name: password.id().name(),
            revision: password.id().revision(),
            length: password.length(),
            lower: password.charset().contains(crypto::CharacterType::LOWER),
            upper: password.charset().contains(crypto::CharacterType::UPPER),
            number: password.charset().contains(crypto::CharacterType::DIGIT),
            symbol: password.charset().contains(crypto::CharacterType::SYMBOL),
        };
        return insert_encrypted(self.data.as_mut()?, &key, &value, encryption_key);
    }

    pub fn set_stored(&mut self, password: &StoredPassword, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<()>
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        let value = object!{
            type: "stored",
            site: password.id().site(),
            name: password.id().name(),
            revision: password.id().revision(),
            password: password.password(),
        };
        return insert_encrypted(self.data.as_mut()?, &key, &value, encryption_key);
    }

    pub fn get_password(&self, id: &PasswordId, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<Password>
    {
        let key = self.get_password_key(id, hmac_secret);
        let value = get_decrypted(self.data.as_ref()?, &key, encryption_key)?;
        return to_password(&value);
    }

    pub fn list_passwords(&self, site: &String, hmac_secret: &[u8], encryption_key: &[u8]) -> impl Iterator<Item = Password> + '_
    {
        assert!(self.initialized().is_some());

        let data = self.data.as_ref().unwrap();
        let prefix = self.get_site_prefix(site, hmac_secret);
        let encryption_key_vec = encryption_key.to_owned();
        return data.entries().filter_map(move |(key, value)| if key.starts_with(&prefix)
        {
            to_password(&decrypt(value, encryption_key_vec.as_slice()).unwrap())
        } else { None });
    }

    pub fn list_sites(&self, encryption_key: &[u8]) -> impl Iterator<Item = String> + '_
    {
        assert!(self.initialized().is_some());

        let data = self.data.as_ref().unwrap();
        let encryption_key_vec = encryption_key.to_owned();
        return data.entries().filter_map(move |(key, value)| if key.strip_prefix(STORAGE_PREFIX).unwrap_or(":").find(":").is_none()
        {
            Some(decrypt(value, encryption_key_vec.as_slice()).unwrap()["site"].as_str().unwrap().to_string())
        } else { None })
    }
}
