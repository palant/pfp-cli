/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use std::collections::HashMap;
use super::crypto;
use super::error::Error;
use super::storage_io;
use super::storage_types::{FromJson, ToJson, PasswordId, GeneratedPassword, StoredPassword, Password, Site};

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
    let parsed = json::parse(input).or_else(|error| Err(Error::InvalidJson { error }))?;
    return match parsed
    {
        json::JsonValue::Object(object) => Ok(object),
        _unexpected => Err(Error::UnexpectedData),
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

fn parse_storage(io: &impl storage_io::StorageIO) -> Result<(String, String, HashMap<String, String>), Error>
{
    let contents = io.load()?;
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
        match value.as_str()
        {
            Some(str) =>
            {
                match key.strip_prefix(STORAGE_PREFIX)
                {
                    Some(key) => { data.insert(key.to_string(), str.to_string()); },
                    None => {},
                }
            },
            None => {},
        }
    }

    return Ok((salt, hmac, data));
}

pub struct Storage<IO>
{
    error: Option<Error>,
    io: IO,
    salt: Option<String>,
    hmac_secret: Option<String>,
    data: Option<HashMap<String, String>>,
}

impl<IO: storage_io::StorageIO> Storage<IO>
{
    pub fn new(io: IO) -> Self
    {
        return match parse_storage(&io)
        {
            Ok((salt, hmac_secret, data)) => Self
            {
                error: None,
                io: io,
                salt: Some(salt),
                hmac_secret: Some(hmac_secret),
                data: Some(data),
            },
            Err(error) => Self
            {
                error: Some(error),
                io: io,
                salt: None,
                hmac_secret: None,
                data: None,
            },
        };
    }

    pub fn clear(&mut self, salt: &[u8], hmac_secret: &[u8], encryption_key: &[u8])
    {
        self.error = None;
        self.data = Some(HashMap::new());
        self.set_salt(salt);
        self.set_hmac_secret(hmac_secret, encryption_key);
    }

    pub fn flush(&self) -> Result<(), Error>
    {
        let mut root = json::object::Object::new();
        root.insert(APPLICATION_KEY, APPLICATION_VALUE.into());
        root.insert(FORMAT_KEY, CURRENT_FORMAT.into());

        let mut data = json::object::Object::new();
        data.insert(SALT_KEY, self.salt.as_ref().ok_or(Error::StorageNotInitialized)?.clone().into());
        data.insert(HMAC_SECRET_KEY,  self.hmac_secret.as_ref().ok_or(Error::StorageNotInitialized)?.clone().into());
        for (key, val) in self.data.as_ref().ok_or(Error::StorageNotInitialized)?.iter()
        {
            let mut storage_key = String::from(STORAGE_PREFIX);
            storage_key.push_str(key);
            data.insert(&storage_key, val.clone().into());
        }
        root.insert(DATA_KEY, data.into());
        return self.io.save(&json::stringify(root));
    }

    pub fn initialized(&self) -> Result<(), &Error>
    {
        return match &self.error
        {
            Some(error) => Err(error),
            None => Ok(()),
        };
    }

    pub fn contains(&self, key: &str) -> Result<bool, Error>
    {
        let data = self.data.as_ref().ok_or(Error::StorageNotInitialized)?;
        return Ok(data.contains_key(key));
    }

    pub fn get<T>(&self, key: &str, encryption_key: &[u8]) -> Result<T, Error>
        where T: FromJson
    {
        let data = self.data.as_ref().ok_or(Error::StorageNotInitialized)?;
        let value = data.get(key).ok_or(Error::KeyMissing)?;
        let decrypted = crypto::decrypt_data(value, encryption_key)?;
        let parsed = parse_json_object(&decrypted)?;
        return T::from_json(&parsed);
    }

    pub fn set<T>(&mut self, key: &str, value: &T, encryption_key: &[u8]) -> Result<(), Error>
        where T: ToJson
    {
        let data = self.data.as_mut().ok_or(Error::StorageNotInitialized)?;
        let obj = value.to_json();
        data.insert(key.to_string(), crypto::encrypt_data(obj.dump().as_bytes(), encryption_key));
        return Ok(());
    }

    pub fn get_salt(&self) -> Result<Vec<u8>, Error>
    {
        let encoded = self.salt.as_ref().ok_or(Error::StorageNotInitialized)?;
        return base64::decode(encoded.as_bytes()).or_else(|error| Err(Error::InvalidBase64 { error }));
    }

    fn set_salt(&mut self, salt: &[u8])
    {
        self.salt = Some(base64::encode(salt));
    }

    pub fn get_hmac_secret(&self, encryption_key: &[u8]) -> Result<Vec<u8>, Error>
    {
        let ciphertext = self.hmac_secret.as_ref().ok_or(Error::StorageNotInitialized)?;
        let decrypted = crypto::decrypt_data(ciphertext, encryption_key)?;
        let parsed = json::parse(&decrypted).or_else(|error| Err(Error::InvalidJson { error }))?;
        let hmac_secret = parsed.as_str().ok_or(Error::UnexpectedData)?;
        return base64::decode(hmac_secret).or_else(|error| Err(Error::InvalidBase64 { error }));
    }

    fn set_hmac_secret(&mut self, hmac_secret: &[u8], encryption_key: &[u8])
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

#[cfg(test)]
mod tests
{
    use json::object;
    use storage_io::{MemoryIO, StorageIO};
    use super::*;

    fn default_data() -> String
    {
        return json::stringify(object!{
            "application": "pfp",
            "format": 3,
            "data": {
                // cba as base64
                "salt": "Y2Jh",
                // abc encrypted (nonce abcdefghijkl, encryption key abcdefghijklmnopqrstuvwxyz123456)
                "hmac-secret": "YWJjZGVmZ2hpamts_IjTSu0kFnBz6wSrzs73IKmBRi8zn9w==",
                // example.com (hmac-sha256)
                "site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=":
                    // {"site":"example.com"} encrypted
                    "YWJjZGVmZ2hpamts_e0/2mFdCrXFftagc/uRqX1zVWlVX2CndVHow98vMbf1CEoCMinc=",
                // example.com\x00blubber\x00 (hmac-sha256)
                "site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:/uudghlPp4TDZPtfZFPj6nJs/zMDAE2AqVfz6Hu8N9I=":
                    // {"type":"generated2","site":"example.com","name":"blubber","revision":"","length":16,"lower":true,"upper":true,"number":true,"symbol":true} encrypted
                    "YWJjZGVmZ2hpamts_e0/xiFNCrXFft7UT9uZnThfSBxpZh7InA7TxwRchhB8xNUCP8AQBt60o0dplkj0d85WabgV46VFsKYTYFREBpwu0V2UXOYtfLQs57L0+RhGX8DLb6mfNMvwdeQ6tYPZdSNhdrqVOBlYbdeOA1HTq+OcNoPb4MDZ+TJeVX2kK+88Hj0mn4QSrloOrHS7WRBuHsAJM4DOPrxOLF00=",
                // example.com\x00blabber\x002 (hmac-sha256)
                "site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:h2pnx6RFyNbAUBLcuQYz9w79/vnf4fgJlY/c+EP44d8=":
                    // {"type":"stored","site":"example.com","name":"blabber","revision":"2","password":"asdf"} encrypted
                    "YWJjZGVmZ2hpamts_e0/xiFNCrXFfo6QS4fFiGF6URlEBwON0VbSrmlg0kBtyJkOH/EtMtO5plpY+3TpTqNWaZwI4pxZsbt6TFB0YoFrnGjkXL4sNYFom/rwrVluP6GKeoiODIKEGZcC+lKGefkKz97EFdEM=",
                // example.info (hmac-sha256)
                "site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=":
                    // {"site":"example.info"} encrypted
                    "YWJjZGVmZ2hpamts_e0/2mFdCrXFftagc/uRqX1zfW14ah7y+PC4vvSZR2oUnodSsOmi/",
                // example.info\x00test\x00yet another (hmac-sha256)
                "site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=:BSjLwWY3MLEPQdG1f/jwKOtJRKCxwXpRH5qkMrUnVsI=":
                    // {"type":"generated2","site":"example.info","name":"test","revision":"yet another","length":8,"lower":true,"upper":false,"number":true,"symbol":false} encrypted
                    "YWJjZGVmZ2hpamts_e0/xiFNCrXFft7UT9uZnThfSBxpZh7InA7TxwRchhB8xNUCP8A4AvOAm35ZqnjVa643adhVp/xYyKdqfER0EpxezGjEXeswJIUg75qcxVwuX5iGBoyvGKeNaMRS7NuhHWpEN+e9KEVFcY7WH0WGjqKtCq/XxMXFoGouVVydN+pRQmVS+phL9l4+jAu/UlX6+yWgvwdxujw6gg3PFRIUACUVMB+vd",
            },
        });
    }

    mod initialization
    {
        use super::*;

        #[test]
        fn read_empty_file()
        {
            let io = MemoryIO::new("");
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::InvalidJson { .. }));
        }

        #[test]
        fn read_literal()
        {
            let io = MemoryIO::new("42");
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"),  Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_empty_object()
        {
            let io = MemoryIO::new(&json::stringify(object!{}));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_wrong_application()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "easypasswords",
                "format": 3,
            }));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedStorageFormat { .. }));
        }

        #[test]
        fn read_wrong_format_version()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "pfp",
                "format": 8,
            }));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedStorageFormat { .. }));
        }

        #[test]
        fn read_missing_data()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "pfp",
                "format": 3,
                "data": null,
            }));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_empty_data()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "pfp",
                "format": 3,
                "data": {},
            }));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_missing_hmac()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "pfp",
                "format": 3,
                "data": {
                    "salt": "asdf",
                },
            }));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_missing_salt()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "pfp",
                "format": 3,
                "data": {
                    "hmac-secret": "fdsa",
                },
            }));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
            assert!(matches!(storage.get_salt().expect_err("Storage should be uninitialized"), Error::StorageNotInitialized { ..}));
            assert!(matches!(storage.get_hmac_secret(b"").expect_err("Storage should be uninitialized"), Error::StorageNotInitialized { ..}));
        }

        #[test]
        fn read_success()
        {
            let io = MemoryIO::new(&default_data());
            let storage = Storage::new(io);
            storage.initialized().expect("Storage should be initialized");
            assert_eq!(storage.get_salt().expect("Storage should be initialized"), b"cba");
            assert_eq!(storage.get_hmac_secret(b"abcdefghijklmnopqrstuvwxyz123456").expect("Storage should be initialized"), b"abc");
        }
    }

    mod clear
    {
        use super::*;

        #[test]
        fn flush()
        {
            let io = MemoryIO::new("dummy");
            let mut storage = Storage::new(io);

            storage.clear(b"cba", b"abc", b"abcdefghijklmnopqrstuvwxyz123456");
            storage.initialized().expect("Storage should be initialized");

            storage.flush().expect("Flush should succeed");

            assert_eq!(json::parse(&storage.io.load().unwrap()).expect("Should be valid JSON"), object!{
                "application": "pfp",
                "format": 3,
                "data": {
                    "salt": "Y2Jh",
                    "hmac-secret": "YWJjZGVmZ2hpamts_IjTSu0kFnBz6wSrzs73IKmBRi8zn9w==",
                },
            });
        }
    }

    mod retrieval
    {
        use super::*;

        fn list_sites(storage: &Storage<MemoryIO>) -> Vec<String>
        {
            let mut vec = storage.list_sites(b"abcdefghijklmnopqrstuvwxyz123456").collect::<Vec<String>>();
            vec.sort();
            return vec;
        }

        fn list_passwords(storage: &Storage<MemoryIO>, site: &str) -> Vec<json::JsonValue>
        {
            let mut vec = storage.list_passwords(site, b"abc", b"abcdefghijklmnopqrstuvwxyz123456").map(|password| json::JsonValue::from(password.to_json())).collect::<Vec<json::JsonValue>>();
            vec.sort_by_key(|password| password["name"].as_str().unwrap().to_owned());
            return vec;
        }

        #[test]
        fn list_empty()
        {
            let io = MemoryIO::new(&json::stringify(object!{
                "application": "pfp",
                "format": 3,
                "data": {
                    "salt": "Y2Jh",
                    "hmac-secret": "YWJjZGVmZ2hpamts_IjTSu0kFnBz6wSrzs73IKmBRi8zn9w==",
                },
            }));

            let storage = Storage::new(io);
            assert_eq!(list_sites(&storage).len(), 0);
            assert_eq!(list_passwords(&storage, "example.com").len(), 0);
        }

        #[test]
        fn list_non_empty()
        {
            let io = MemoryIO::new(&default_data());

            let storage = Storage::new(io);
            assert_eq!(list_sites(&storage), vec!["example.com", "example.info"]);

            let password1 = object!{
                "type": "stored",
                "site": "example.com",
                "name": "blabber",
                "revision": "2",
                "password": "asdf"
            };
            let password2 = object!{
                "type": "generated2",
                "site": "example.com",
                "name": "blubber",
                "revision": "",
                "length": 16,
                "lower": true,
                "upper": true,
                "number": true,
                "symbol": true,
            };
            let password3 = object!{
                "type": "generated2",
                "site": "example.info",
                "name": "test",
                "revision": "yet another",
                "length": 8,
                "lower": true,
                "upper": false,
                "number": true,
                "symbol": false,
            };
            assert_eq!(list_passwords(&storage, "example.com"), vec![password1, password2]);
            assert_eq!(list_passwords(&storage, "example.info"), vec![password3]);
            assert_eq!(list_passwords(&storage, "example.net").len(), 0);
        }

        #[test]
        fn get_password()
        {
            let io = MemoryIO::new(&default_data());

            let storage = Storage::new(io);

            assert!(storage.has_password(&PasswordId::new("example.com", "blabber", "2"), b"abc").expect("Storage should be initialized"));
            let password1 = storage.get_password(&PasswordId::new("example.com", "blabber", "2"), b"abc", b"abcdefghijklmnopqrstuvwxyz123456").expect("Password should be present");
            assert_eq!(password1.to_json(), object!{
                "type": "stored",
                "site": "example.com",
                "name": "blabber",
                "revision": "2",
                "password": "asdf"
            });

            assert!(storage.has_password(&PasswordId::new("example.com", "blubber", ""), b"abc").expect("Storage should be initialized"));
            let password2 = storage.get_password(&PasswordId::new("example.com", "blubber", ""), b"abc", b"abcdefghijklmnopqrstuvwxyz123456").expect("Password should be present");
            assert_eq!(password2.to_json(), object!{
                "type": "generated2",
                "site": "example.com",
                "name": "blubber",
                "revision": "",
                "length": 16,
                "lower": true,
                "upper": true,
                "number": true,
                "symbol": true,
            });

            assert!(storage.has_password(&PasswordId::new("example.info", "test", "yet another"), b"abc").expect("Storage should be initialized"));
            let password3 = storage.get_password(&PasswordId::new("example.info", "test", "yet another"), b"abc", b"abcdefghijklmnopqrstuvwxyz123456").expect("Password should be present");
            assert_eq!(password3.to_json(), object!{
                "type": "generated2",
                "site": "example.info",
                "name": "test",
                "revision": "yet another",
                "length": 8,
                "lower": true,
                "upper": false,
                "number": true,
                "symbol": false,
            });

            assert!(!storage.has_password(&PasswordId::new("example.net", "blubber", ""), b"abc").expect("Storage should be initialized"));
            assert!(matches!(storage.get_password(&PasswordId::new("example.net", "blubber", ""), b"abc", b"abcdefghijklmnopqrstuvwxyz123456").expect_err("Password should be missing"), Error::KeyMissing { .. }));
        }
    }
}
