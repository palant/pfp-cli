/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::crypto;
use super::storage_types::{PasswordId, GeneratedPassword, StoredPassword, Password, Site};
use json::object;
use std::collections::HashMap;
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

fn parse_storage(path: &path::PathBuf) -> Result<(String, String, HashMap<String, String>), io::Error>
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

    let data_obj = root.remove(DATA_KEY);
    if !data_obj.is_object()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "storage data isn't an object"));
    }

    if !data_obj[SALT_KEY].is_string() || !data_obj[HMAC_SECRET_KEY].is_string()
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing password salt or HMAC secret"));
    }

    let salt = data_obj[SALT_KEY].as_str().unwrap().to_string();
    let hmac = data_obj[HMAC_SECRET_KEY].as_str().unwrap().to_string();

    let mut data = HashMap::new();
    for (key, value) in data_obj.entries()
    {
        if key.starts_with(STORAGE_PREFIX) && value.is_string()
        {
            data.insert(key.to_string(), value.as_str().unwrap().to_string());
        }
    }

    return Ok((salt, hmac, data));
}

pub struct Storage
{
    path: path::PathBuf,
    salt: Option<String>,
    hmac_secret: Option<String>,
    data: Option<HashMap<String, String>>,
}

impl Storage
{
    pub fn new(path: &path::PathBuf) -> Storage
    {
        return match parse_storage(path)
        {
            Ok((salt, hmac_secret, data)) => Storage
            {
                path: path.clone(),
                salt: Some(salt),
                hmac_secret: Some(hmac_secret),
                data: Some(data),
            },
            Err(_error) => Storage
            {
                path: path.clone(),
                salt: None,
                hmac_secret: None,
                data: None,
            },
        };
    }

    pub fn clear(&mut self, salt: &[u8], hmac_secret: &[u8], encryption_key: &Vec<u8>)
    {
        self.data = Some(HashMap::new());
        self.set_salt(salt);
        self.set_hmac_secret(hmac_secret, encryption_key);
    }

    pub fn flush(&self) -> Option<()>
    {
        self.initialized()?;

        let mut root = object!{
            [APPLICATION_KEY]: APPLICATION_VALUE,
            [FORMAT_KEY]: CURRENT_FORMAT,
        };

        let mut data = object!{
            [SALT_KEY]: self.salt.as_ref()?.clone(),
            [HMAC_SECRET_KEY]: self.hmac_secret.as_ref()?.clone(),
        };
        for (key, val) in self.data.as_ref()?.iter()
        {
            let mut storage_key = String::from(STORAGE_PREFIX);
            storage_key.push_str(key);
            data.insert(&storage_key, val.clone()).ok()?;
        }
        root.insert(DATA_KEY, data).ok()?;

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

    pub fn contains(&self, key: &str) -> Option<bool>
    {
        self.initialized()?;

        let data = self.data.as_ref()?;
        return Some(data.contains_key(key));
    }

    pub fn get<T>(&self, key: &str, encryption_key: &[u8]) -> Option<T>
        where T: TryFrom<json::JsonValue>
    {
        self.initialized()?;

        let data = self.data.as_ref()?;
        let decrypted = crypto::decrypt_data(data.get(key)?, encryption_key)?;
        return T::try_from(json::parse(&decrypted).ok()?).ok();
    }

    pub fn set<'a, T>(&'a mut self, key: &'a str, value: &'a T, encryption_key: &'a [u8]) -> Option<()>
        where json::JsonValue: From<&'a T>
    {
        self.initialized()?;

        let data = self.data.as_mut()?;
        let value = json::JsonValue::from(value);
        data.insert(key.to_string(), crypto::encrypt_data(value.dump().as_bytes(), encryption_key))?;
        return Some(());
    }

    pub fn get_salt(&self) -> Option<Vec<u8>>
    {
        self.initialized()?;

        return base64::decode(self.salt.as_ref()?.as_bytes()).ok();
    }

    fn set_salt(&mut self, salt: &[u8])
    {
        self.salt = Some(base64::encode(salt));
    }

    pub fn get_hmac_secret(&self, encryption_key: &Vec<u8>) -> Option<Vec<u8>>
    {
        self.initialized()?;

        let decrypted = crypto::decrypt_data(self.hmac_secret.as_ref()?, encryption_key)?;
        let parsed = json::parse(&decrypted).ok()?;
        let hmac_secret = parsed.as_str()?;
        return base64::decode(hmac_secret).ok();
    }

    fn set_hmac_secret(&mut self, hmac_secret: &[u8], encryption_key: &Vec<u8>)
    {
        let stringified = json::JsonValue::from(base64::encode(hmac_secret)).dump();
        let encrypted = crypto::encrypt_data(stringified.as_bytes(), encryption_key);
        self.hmac_secret = Some(encrypted);
    }

    fn get_site_key(&self, site: &str, hmac_secret: &[u8]) -> String
    {
        return crypto::get_digest(hmac_secret, site);
    }

    fn get_site_prefix(&self, site: &str, hmac_secret: &[u8]) -> String
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

    pub fn get_alias(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<String>
    {
        let key = self.get_site_key(site, hmac_secret);
        let site: Site = self.get(&key, encryption_key)?;
        return match site.alias()
        {
            Some(value) => Some(value.to_string()),
            None => None,
        };
    }

    pub fn resolve_site(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> String
    {
        let stripped = site.strip_prefix("www.").unwrap_or(site).to_string();
        return self.get_alias(&stripped, hmac_secret, encryption_key).unwrap_or(stripped);
    }

    pub fn ensure_site_data(&mut self, site: &str, hmac_secret: &[u8], encryption_key: &[u8])
    {
        assert!(self.initialized().is_some());

        let key = self.get_site_key(site, hmac_secret);
        let existing: Option<Site> = self.get(&key, encryption_key);
        if existing.is_none()
        {
            self.set(&key, &Site::new(site, None), encryption_key);
        }
    }

    pub fn has_password(&self, id: &PasswordId, hmac_secret: &[u8]) -> Option<bool>
    {
        let key = self.get_password_key(id, hmac_secret);
        return self.contains(&key);
    }

    pub fn set_generated(&mut self, password: GeneratedPassword, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<()>
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        return self.set(&key, &Password::Generated { password }, encryption_key);
    }

    pub fn set_stored(&mut self, password: StoredPassword, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<()>
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        return self.set(&key, &Password::Stored { password }, encryption_key);
    }

    pub fn get_password(&self, id: &PasswordId, hmac_secret: &[u8], encryption_key: &[u8]) -> Option<Password>
    {
        let key = self.get_password_key(id, hmac_secret);
        return self.get(&key, encryption_key);
    }

    pub fn list_passwords<'a>(&'a self, site: &str, hmac_secret: &[u8], encryption_key: &'a [u8]) -> impl Iterator<Item = Password> + 'a
    {
        assert!(self.initialized().is_some());

        let data = self.data.as_ref().unwrap();
        let prefix = self.get_site_prefix(site, hmac_secret);
        return data.keys().filter_map(move |key| if key.starts_with(&prefix)
        {
            self.get(key, encryption_key)
        } else { None });
    }

    pub fn list_sites<'a>(&'a self, encryption_key: &'a [u8]) -> impl Iterator<Item = String> + 'a
    {
        assert!(self.initialized().is_some());

        let data = self.data.as_ref().unwrap();
        return data.keys().filter_map(move |key| if key.find(":").is_none()
        {
            let site: Site = self.get(key, encryption_key)?;
            Some(site.name().to_string())
        } else { None })
    }
}
