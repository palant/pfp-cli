/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use json::object;
use std::collections::HashMap;
use std::fs;
use std::path;
use super::crypto;
use super::error::Error;
use super::storage_types::{PasswordId, GeneratedPassword, StoredPassword, Password, Site};

const APPLICATION_KEY: &str = "application";
const APPLICATION_VALUE: &str = "pfp";
const FORMAT_KEY: &str = "format";
const CURRENT_FORMAT: u32 = 3;
const DATA_KEY: &str = "data";
const SALT_KEY: &str = "salt";
const HMAC_SECRET_KEY: &str = "hmac-secret";
const STORAGE_PREFIX: &str = "site:";

fn parse_json_object(input: &str) -> Result<json::object::Object, Error>
{
    let parsed = json::parse(input).or(Err(Error::InvalidJson))?;
    return match parsed
    {
        json::JsonValue::Object(object) => Ok(object),
        _unexpected => Err(Error::InvalidJson),
    };
}

fn get_json_object(obj: &mut json::object::Object, key: &str) -> Result<json::object::Object, Error>
{
    return match obj.remove(key).ok_or(Error::KeyMissing)?
    {
        json::JsonValue::Object(obj) => Ok(obj),
        _unexpected => Err(Error::UnexpectedData),
    }
}

fn get_json_string(obj: &json::object::Object, key: &str) -> Result<String, Error>
{
    return Ok(obj[key].as_str().ok_or(Error::UnexpectedData)?.to_string());
}

fn get_json_u32(obj: &json::object::Object, key: &str) -> Result<u32, Error>
{
    return obj[key].as_u32().ok_or(Error::UnexpectedData);
}

fn parse_storage(path: &path::PathBuf) -> Result<(String, String, HashMap<String, String>), Error>
{
    let contents = fs::read_to_string(path).or(Err(Error::FileReadFailure))?;
    let mut root = parse_json_object(&contents)?;

    if get_json_string(&root, APPLICATION_KEY)? != APPLICATION_VALUE || get_json_u32(&root, FORMAT_KEY)? != CURRENT_FORMAT
    {
        return Err(Error::UnexpectedStorageFormat);
    }

    let data_obj = get_json_object(&mut root, DATA_KEY)?;
    let salt = get_json_string(&data_obj, SALT_KEY)?;
    let hmac = get_json_string(&data_obj, HMAC_SECRET_KEY)?;

    let mut data = HashMap::new();
    for (key, value) in data_obj.iter()
    {
        if !value.is_string()
        {
            continue;
        }
        match key.strip_prefix(STORAGE_PREFIX)
        {
            Some(key) => { data.insert(key.to_string(), value.as_str().unwrap().to_string()); },
            None => {},
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

    pub fn flush(&self) -> Result<(), Error>
    {
        let mut root = object!{
            [APPLICATION_KEY]: APPLICATION_VALUE,
            [FORMAT_KEY]: CURRENT_FORMAT,
        };

        let mut data = object!{
            [SALT_KEY]: self.salt.as_ref().ok_or(Error::StorageNotInitialized)?.clone(),
            [HMAC_SECRET_KEY]: self.hmac_secret.as_ref().ok_or(Error::StorageNotInitialized)?.clone(),
        };
        for (key, val) in self.data.as_ref().ok_or(Error::StorageNotInitialized)?.iter()
        {
            let mut storage_key = String::from(STORAGE_PREFIX);
            storage_key.push_str(key);
            data.insert(&storage_key, val.clone()).unwrap();
        }
        root.insert(DATA_KEY, data).unwrap();

        let parent = self.path.parent();
        match parent
        {
            Some(parent) => fs::create_dir_all(parent).or(Err(Error::CreateDirFailure))?,
            None => {},
        }
        fs::write(&self.path, json::stringify(root)).or(Err(Error::FileWriteFailure))?;
        return Ok(());
    }

    pub fn initialized(&self) -> Result<(), Error>
    {
        return match self.data.as_ref()
        {
            Some(_) => Ok(()),
            None => Err(Error::StorageNotInitialized),
        };
    }

    pub fn contains(&self, key: &str) -> Result<bool, Error>
    {
        let data = self.data.as_ref().ok_or(Error::StorageNotInitialized)?;
        return Ok(data.contains_key(key));
    }

    pub fn get<T>(&self, key: &str, encryption_key: &[u8]) -> Result<T, Error>
        where T: TryFrom<json::object::Object, Error = Error>
    {
        let data = self.data.as_ref().ok_or(Error::StorageNotInitialized)?;
        let value = data.get(key).ok_or(Error::KeyMissing)?;
        let decrypted = crypto::decrypt_data(value, encryption_key)?;
        let parsed = parse_json_object(&decrypted)?;
        return T::try_from(parsed);
    }

    pub fn set<'a, T>(&'a mut self, key: &'a str, value: &'a T, encryption_key: &'a [u8]) -> Result<(), Error>
        where json::object::Object: From<&'a T>
    {
        self.initialized()?;

        let data = self.data.as_mut().ok_or(Error::StorageNotInitialized)?;
        let value = json::object::Object::from(value);
        data.insert(key.to_string(), crypto::encrypt_data(value.dump().as_bytes(), encryption_key));
        return Ok(());
    }

    pub fn get_salt(&self) -> Result<Vec<u8>, Error>
    {
        let encoded = self.salt.as_ref().ok_or(Error::StorageNotInitialized)?;
        return base64::decode(encoded.as_bytes()).or(Err(Error::InvalidBase64));
    }

    fn set_salt(&mut self, salt: &[u8])
    {
        self.salt = Some(base64::encode(salt));
    }

    pub fn get_hmac_secret(&self, encryption_key: &Vec<u8>) -> Result<Vec<u8>, Error>
    {
        let ciphertext = self.hmac_secret.as_ref().ok_or(Error::StorageNotInitialized)?;
        let decrypted = crypto::decrypt_data(ciphertext, encryption_key)?;
        let parsed = json::parse(&decrypted).or(Err(Error::InvalidJson))?;
        let hmac_secret = parsed.as_str().ok_or(Error::UnexpectedData)?;
        return base64::decode(hmac_secret).or(Err(Error::InvalidBase64));
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

    pub fn get_alias(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<String, Error>
    {
        let key = self.get_site_key(site, hmac_secret);
        let site: Site = self.get(&key, encryption_key)?;
        return match site.alias()
        {
            Some(value) => Ok(value.to_string()),
            None => Err(Error::NoSuchAlias),
        };
    }

    pub fn resolve_site(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> String
    {
        let stripped = site.strip_prefix("www.").unwrap_or(site).to_string();
        return self.get_alias(&stripped, hmac_secret, encryption_key).unwrap_or(stripped);
    }

    pub fn ensure_site_data(&mut self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<(), Error>
    {
        assert!(self.initialized().is_ok());

        let key = self.get_site_key(site, hmac_secret);
        let existing: Result<Site, Error> = self.get(&key, encryption_key);
        if existing.is_err()
        {
            return self.set(&key, &Site::new(site, None), encryption_key);
        }
        return Ok(());
    }

    pub fn has_password(&self, id: &PasswordId, hmac_secret: &[u8]) -> Result<bool, Error>
    {
        let key = self.get_password_key(id, hmac_secret);
        return self.contains(&key);
    }

    pub fn set_generated(&mut self, password: GeneratedPassword, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<(), Error>
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        return self.set(&key, &Password::Generated { password }, encryption_key);
    }

    pub fn set_stored(&mut self, password: StoredPassword, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<(), Error>
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        return self.set(&key, &Password::Stored { password }, encryption_key);
    }

    pub fn get_password(&self, id: &PasswordId, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<Password, Error>
    {
        let key = self.get_password_key(id, hmac_secret);
        return self.get(&key, encryption_key);
    }

    pub fn list_passwords<'a>(&'a self, site: &str, hmac_secret: &[u8], encryption_key: &'a [u8]) -> impl Iterator<Item = Password> + 'a
    {
        let data = self.data.as_ref().unwrap();
        let prefix = self.get_site_prefix(site, hmac_secret);
        return data.keys().filter_map(move |key| if key.starts_with(&prefix)
        {
            self.get(key, encryption_key).ok()
        } else { None });
    }

    pub fn list_sites<'a>(&'a self, encryption_key: &'a [u8]) -> impl Iterator<Item = String> + 'a
    {
        let data = self.data.as_ref().unwrap();
        return data.keys().filter_map(move |key| if key.find(":").is_none()
        {
            let site: Site = self.get(key, encryption_key).ok()?;
            Some(site.name().to_string())
        } else { None })
    }
}
