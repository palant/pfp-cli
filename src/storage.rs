/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use super::crypto;
use super::error::Error;
use super::storage_io;
use super::storage_types::{FromJson, ToJson, PasswordId, GeneratedPassword, StoredPassword, Password, Site};

const SALT_KEY: &str = "salt";
const HMAC_SECRET_KEY: &str = "hmac-secret";
const STORAGE_PREFIX: &str = "site:";

fn parse_json_object(input: &str) -> Result<json::object::Object, Error>
{
    let parsed = json::parse(input).map_err(|error| Error::InvalidJson { error })?;
    match parsed
    {
        json::JsonValue::Object(object) => Ok(object),
        _unexpected => Err(Error::UnexpectedData),
    }
}

pub struct Storage<IO>
{
    error: Option<Error>,
    io: IO,
}

impl<IO: storage_io::StorageIO> Storage<IO>
{
    fn load_storage(io: &mut impl storage_io::StorageIO) -> Result<(), Error>
    {
        io.load()?;
        if io.contains_key(SALT_KEY) && io.contains_key(HMAC_SECRET_KEY)
        {
            Ok(())
        }
        else
        {
            Err(Error::UnexpectedData)
        }
    }

    pub fn new(mut io: IO) -> Self
    {
        match Self::load_storage(&mut io)
        {
            Ok(()) => Self {
                error: None,
                io,
            },
            Err(error) => Self {
                error: Some(error),
                io,
            },
        }
    }

    pub fn clear(&mut self, salt: &[u8], hmac_secret: &[u8], encryption_key: &[u8])
    {
        self.error = None;
        self.io.clear();
        self.set_salt(salt);
        self.set_hmac_secret(hmac_secret, encryption_key);
    }

    pub fn flush(&mut self) -> Result<(), Error>
    {
        self.io.flush()
    }

    pub fn initialized(&self) -> Result<(), &Error>
    {
        match &self.error
        {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn contains(&self, key: &str) -> bool
    {
        self.io.contains_key(key)
    }

    fn get<T>(&self, key: &str, encryption_key: &[u8]) -> Result<T, Error>
        where T: FromJson
    {
        let value = self.io.get(key)?;
        let decrypted = crypto::decrypt_data(value, encryption_key)?;
        let parsed = parse_json_object(&decrypted)?;
        T::from_json(&parsed)
    }

    fn set<T>(&mut self, key: &str, value: &T, encryption_key: &[u8])
        where T: ToJson
    {
        let obj = value.to_json();
        self.io.set(key.to_string(), crypto::encrypt_data(obj.dump().as_bytes(), encryption_key));
    }

    fn remove(&mut self, key: &str) -> Result<(), Error>
    {
        self.io.remove(key)
    }

    pub fn get_salt(&self) -> Result<Vec<u8>, Error>
    {
        let encoded = self.io.get(SALT_KEY).map_err(|_| Error::StorageNotInitialized)?;
        base64::decode(encoded.as_bytes()).map_err(|error| Error::InvalidBase64 { error })
    }

    fn set_salt(&mut self, salt: &[u8])
    {
        self.io.set(SALT_KEY.to_string(), base64::encode(salt));
    }

    pub fn get_hmac_secret(&self, encryption_key: &[u8]) -> Result<Vec<u8>, Error>
    {
        let ciphertext = self.io.get(HMAC_SECRET_KEY).map_err(|_| Error::StorageNotInitialized)?;
        let decrypted = crypto::decrypt_data(ciphertext, encryption_key)?;
        let parsed = json::parse(&decrypted).map_err(|error| Error::InvalidJson { error })?;
        let hmac_secret = parsed.as_str().ok_or(Error::UnexpectedData)?;
        base64::decode(hmac_secret).map_err(|error| Error::InvalidBase64 { error })
    }

    fn set_hmac_secret(&mut self, hmac_secret: &[u8], encryption_key: &[u8])
    {
        let stringified = json::JsonValue::from(base64::encode(hmac_secret)).dump();
        let encrypted = crypto::encrypt_data(stringified.as_bytes(), encryption_key);
        self.io.set(HMAC_SECRET_KEY.to_string(), encrypted);
    }

    fn get_site_key(&self, site: &str, hmac_secret: &[u8]) -> String
    {
        let mut result = String::from(STORAGE_PREFIX);
        result.push_str(&crypto::get_digest(hmac_secret, site));
        result
    }

    fn get_site_prefix(&self, site: &str, hmac_secret: &[u8]) -> String
    {
        let mut result = self.get_site_key(site, hmac_secret);
        result.push(':');
        result
    }

    fn get_password_key(&self, id: &PasswordId, hmac_secret: &[u8]) -> String
    {
        let mut input = String::new();
        input.push_str(id.site());
        input.push('\0');
        input.push_str(id.name());
        input.push('\0');
        input.push_str(id.revision());

        let mut result = self.get_site_prefix(&id.site().to_string(), hmac_secret);
        result.push_str(&crypto::get_digest(hmac_secret, &input));
        result
    }

    pub fn get_alias(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<String, Error>
    {
        let site = self.get_site(site, hmac_secret, encryption_key)?;
        site.alias().map(|value| value.to_string()).ok_or(Error::NoSuchAlias)
    }

    pub fn normalize_site(&self, site: &str) -> String
    {
        site.strip_prefix("www.").unwrap_or(site).to_string()
    }

    pub fn resolve_site(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> String
    {
        let normalized = self.normalize_site(site);
        self.get_alias(&normalized, hmac_secret, encryption_key).unwrap_or(normalized)
    }

    pub fn ensure_site_data(&mut self, site: &str, hmac_secret: &[u8], encryption_key: &[u8])
    {
        let key = self.get_site_key(site, hmac_secret);
        if self.get::<Site>(&key, encryption_key).is_err()
        {
            self.set(&key, &Site::new(site, None), encryption_key)
        }
    }

    pub fn set_alias(&mut self, site: &str, alias: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<(), Error>
    {
        if site == alias
        {
            return Err(Error::AliasToSelf);
        }
        let key = self.get_site_key(site, hmac_secret);
        let site = Site::new(site, Some(alias));
        self.set(&key, &site, encryption_key);
        Ok(())
    }

    pub fn get_site(&self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<Site, Error>
    {
        let key = self.get_site_key(site, hmac_secret);
        self.get(&key, encryption_key)
    }

    pub fn remove_alias(&mut self, site: &str, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<(), Error>
    {
        let key = self.get_site_key(site, hmac_secret);
        let site: Site = self.get(&key, encryption_key).or(Err(Error::NoSuchAlias))?;
        if site.alias().is_none()
        {
            Err(Error::NoSuchAlias)
        }
        else
        {
            self.remove(&key)
        }
    }

    pub fn remove_site(&mut self, site: &str, hmac_secret: &[u8]) -> Result<(), Error>
    {
        let key = self.get_site_key(site, hmac_secret);
        self.remove(&key)
    }

    pub fn has_password(&self, id: &PasswordId, hmac_secret: &[u8]) -> bool
    {
        let key = self.get_password_key(id, hmac_secret);
        self.contains(&key)
    }

    pub fn set_generated(&mut self, password: GeneratedPassword, hmac_secret: &[u8], encryption_key: &[u8])
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        self.set(&key, &Password::Generated { password }, encryption_key);
    }

    pub fn set_stored(&mut self, password: StoredPassword, hmac_secret: &[u8], encryption_key: &[u8])
    {
        let key = self.get_password_key(password.id(), hmac_secret);
        self.set(&key, &Password::Stored { password }, encryption_key);
    }

    pub fn get_password(&self, id: &PasswordId, hmac_secret: &[u8], encryption_key: &[u8]) -> Result<Password, Error>
    {
        let key = self.get_password_key(id, hmac_secret);
        self.get(&key, encryption_key)
    }

    pub fn remove_password(&mut self, id: &PasswordId, hmac_secret: &[u8]) -> Result<(), Error>
    {
        let key = self.get_password_key(id, hmac_secret);
        self.remove(&key)
    }

    pub fn list_passwords<'a>(&'a self, site: &str, hmac_secret: &[u8], encryption_key: &'a [u8]) -> impl Iterator<Item = Password> + 'a
    {
        let prefix = self.get_site_prefix(site, hmac_secret);
        self.io.keys().filter_map(move |key| if key.starts_with(&prefix)
        {
            self.get(key, encryption_key).ok()
        } else { None })
    }

    pub fn list_sites<'a>(&'a self, encryption_key: &'a [u8]) -> impl Iterator<Item = Site> + 'a
    {
        self.io.keys().filter_map(move |key| if key.starts_with(STORAGE_PREFIX) && key[STORAGE_PREFIX.len()..].find(':').is_none()
        {
            self.get(key, encryption_key).ok()
        } else { None })
    }
}

#[cfg(test)]
mod tests
{
    use std::collections::HashMap;
    use storage_io::MemoryIO;
    use super::*;

    const HMAC_SECRET: &[u8] = b"abc";
    const ENCRYPTION_KEY: &[u8] = b"abcdefghijklmnopqrstuvwxyz123456";

    fn empty_data() -> HashMap<String, String>
    {
        return HashMap::from([
            ("salt", "Y2Jh"),
            ("hmac-secret", "YWJjZGVmZ2hpamts_IjTSu0kFnBz6wSrzs73IKmBRi8zn9w=="),
        ]).iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    fn default_data() -> HashMap<String, String>
    {
        return HashMap::from([
            // cba as base64
            ("salt", "Y2Jh"),
            // abc encrypted (nonce abcdefghijkl, encryption key abcdefghijklmnopqrstuvwxyz123456)
            ("hmac-secret", "YWJjZGVmZ2hpamts_IjTSu0kFnBz6wSrzs73IKmBRi8zn9w=="),
            // example.com (hmac-sha256)
            ("site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=",
                // {"site":"example.com"} encrypted
                "YWJjZGVmZ2hpamts_e0/2mFdCrXFftagc/uRqX1zVWlVX2CndVHow98vMbf1CEoCMinc="),
            // example.com\x00blubber\x00 (hmac-sha256)
            ("site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:/uudghlPp4TDZPtfZFPj6nJs/zMDAE2AqVfz6Hu8N9I=",
                // {"type":"generated2","site":"example.com","name":"blubber","revision":"","length":16,"lower":true,"upper":true,"number":true,"symbol":true} encrypted
                "YWJjZGVmZ2hpamts_e0/xiFNCrXFft7UT9uZnThfSBxpZh7InA7TxwRchhB8xNUCP8AQBt60o0dplkj0d85WabgV46VFsKYTYFREBpwu0V2UXOYtfLQs57L0+RhGX8DLb6mfNMvwdeQ6tYPZdSNhdrqVOBlYbdeOA1HTq+OcNoPb4MDZ+TJeVX2kK+88Hj0mn4QSrloOrHS7WRBuHsAJM4DOPrxOLF00="),
            // example.com\x00blabber\x002 (hmac-sha256)
            ("site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:h2pnx6RFyNbAUBLcuQYz9w79/vnf4fgJlY/c+EP44d8=",
                // {"type":"stored","site":"example.com","name":"blabber","revision":"2","password":"asdf"} encrypted
                "YWJjZGVmZ2hpamts_e0/xiFNCrXFfo6QS4fFiGF6URlEBwON0VbSrmlg0kBtyJkOH/EtMtO5plpY+3TpTqNWaZwI4pxZsbt6TFB0YoFrnGjkXL4sNYFom/rwrVluP6GKeoiODIKEGZcC+lKGefkKz97EFdEM="),
            // example.info (hmac-sha256)
            ("site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=",
                // {"site":"example.info"} encrypted
                "YWJjZGVmZ2hpamts_e0/2mFdCrXFftagc/uRqX1zfW14ah7y+PC4vvSZR2oUnodSsOmi/"),
            // example.info\x00test\x00yet another (hmac-sha256)
            ("site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=:BSjLwWY3MLEPQdG1f/jwKOtJRKCxwXpRH5qkMrUnVsI=",
                // {"type":"generated2","site":"example.info","name":"test","revision":"yet another","length":8,"lower":true,"upper":false,"number":true,"symbol":false} encrypted
                "YWJjZGVmZ2hpamts_e0/xiFNCrXFft7UT9uZnThfSBxpZh7InA7TxwRchhB8xNUCP8A4AvOAm35ZqnjVa643adhVp/xYyKdqfER0EpxezGjEXeswJIUg75qcxVwuX5iGBoyvGKeNaMRS7NuhHWpEN+e9KEVFcY7WH0WGjqKtCq/XxMXFoGouVVydN+pRQmVS+phL9l4+jAu/UlX6+yWgvwdxujw6gg3PFRIUACUVMB+vd"),
            // example.org (hmac-sha256)
            ("site:5IS/IdH3aaMwyzRv0fwy+2oh5OsXZ2emV8991dFWrko=",
                // {"site":"example.org","alias":"example.com"} encrypted
                "YWJjZGVmZ2hpamts_e0/2mFdCrXFftagc/uRqX1zZR19XieMvG7iyiBd+3hskJEGasgJAueBp0cngww8j0ruPmOiqFSkDcdc0"),
        ]).iter().map(|(key, value)| (key.to_string(), value.to_string())).collect()
    }

    fn decrypt_entries(data: &HashMap<String, String>) -> HashMap<String, json::JsonValue>
    {
        let mut decrypted = HashMap::new();
        for (key, value) in data.iter()
        {
            if key.starts_with("site:")
            {
                let entry = crypto::decrypt_data(value, ENCRYPTION_KEY).expect("Value should be decryptable");
                decrypted.insert(key.to_owned(), json::parse(&entry).expect("Should be valid JSON"));
            }
        }
        return decrypted;
    }

    fn compare_storage_data(data1: &HashMap<String, String>, data2: &HashMap<String, String>)
    {
        assert_eq!(decrypt_entries(data1), decrypt_entries(data2));
    }

    mod initialization
    {
        use super::*;

        #[test]
        fn read_empty_data()
        {
            let io = MemoryIO::new(HashMap::new());
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_missing_hmac()
        {
            let io = MemoryIO::new(HashMap::from([
                ("salt".to_string(), "asdf".to_string()),
            ]));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
        }

        #[test]
        fn read_missing_salt()
        {
            let io = MemoryIO::new(HashMap::from([
                ("hmac-secret".to_string(), "fdsa".to_string()),
            ]));
            let storage = Storage::new(io);
            assert!(matches!(storage.initialized().expect_err("Storage should be uninitialized"), Error::UnexpectedData { .. }));
            assert!(matches!(storage.get_salt().expect_err("Storage should be uninitialized"), Error::StorageNotInitialized { ..}));
            assert!(matches!(storage.get_hmac_secret(ENCRYPTION_KEY).expect_err("Decrypting HMAC secret should fail"), Error::InvalidCiphertext { ..}));
        }

        #[test]
        fn read_success()
        {
            let io = MemoryIO::new(default_data());
            let storage = Storage::new(io);
            storage.initialized().expect("Storage should be initialized");
            assert_eq!(storage.get_salt().expect("Storage should be initialized"), b"cba");
            assert_eq!(storage.get_hmac_secret(ENCRYPTION_KEY).expect("Storage should be initialized"), HMAC_SECRET);
        }
    }

    mod clear
    {
        use super::*;

        #[test]
        fn clear_uninitialized()
        {
            let io = MemoryIO::new(HashMap::new());
            let mut storage = Storage::new(io);

            storage.clear(b"cba", HMAC_SECRET, ENCRYPTION_KEY);
            storage.initialized().expect("Storage should be initialized");
            assert_eq!(storage.list_sites(ENCRYPTION_KEY).count(), 0);

            storage.flush().expect("Flush should succeed");

            assert_eq!(storage.io.data(), &empty_data());
        }

        #[test]
        fn clear_initialized()
        {
            let io = MemoryIO::new(default_data());
            let mut storage = Storage::new(io);

            storage.clear(b"cba", HMAC_SECRET, ENCRYPTION_KEY);
            storage.initialized().expect("Storage should be initialized");
            assert_eq!(storage.list_sites(ENCRYPTION_KEY).count(), 0);

            storage.flush().expect("Flush should succeed");

            assert_eq!(storage.io.data(), &empty_data());
        }
    }

    mod retrieval
    {
        use super::*;
        use json::object;

        fn list_sites(storage: &Storage<MemoryIO>) -> Vec<String>
        {
            let mut vec = storage.list_sites(ENCRYPTION_KEY).map(|site| site.name().to_string()).collect::<Vec<String>>();
            vec.sort();
            return vec;
        }

        fn list_passwords(storage: &Storage<MemoryIO>, site: &str) -> Vec<json::JsonValue>
        {
            let mut vec = storage.list_passwords(site, HMAC_SECRET, ENCRYPTION_KEY).map(|password| json::JsonValue::from(password.to_json())).collect::<Vec<json::JsonValue>>();
            vec.sort_by_key(|password| password["name"].as_str().unwrap().to_owned());
            return vec;
        }

        #[test]
        fn list_empty()
        {
            let io = MemoryIO::new(empty_data());
            let storage = Storage::new(io);

            assert_eq!(list_sites(&storage).len(), 0);
            assert_eq!(list_passwords(&storage, "example.com").len(), 0);
        }

        #[test]
        fn list_non_empty()
        {
            let io = MemoryIO::new(default_data());
            let storage = Storage::new(io);
            assert_eq!(list_sites(&storage), vec!["example.com", "example.info", "example.org"]);

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
            assert_eq!(list_passwords(&storage, "example.org").len(), 0);
            assert_eq!(list_passwords(&storage, "example.net").len(), 0);
        }

        #[test]
        fn get_password()
        {
            let io = MemoryIO::new(default_data());
            let storage = Storage::new(io);

            let site1 = storage.get_site("example.com", HMAC_SECRET, ENCRYPTION_KEY).expect("Site should be present");
            assert_eq!(site1.to_json(), object!{
                "site": "example.com",
            });
            let site2 = storage.get_site("example.info", HMAC_SECRET, ENCRYPTION_KEY).expect("Site should be present");
            assert_eq!(site2.to_json(), object!{
                "site": "example.info",
            });
            let site3 = storage.get_site("example.org", HMAC_SECRET, ENCRYPTION_KEY).expect("Site should be present");
            assert_eq!(site3.to_json(), object!{
                "site": "example.org",
                "alias": "example.com",
            });
            assert!(matches!(storage.get_site("example.net", HMAC_SECRET, ENCRYPTION_KEY).expect_err("Site should be missing"), Error::KeyMissing { .. }));

            assert!(storage.has_password(&PasswordId::new("example.com", "blabber", "2"), HMAC_SECRET));
            let password1 = storage.get_password(&PasswordId::new("example.com", "blabber", "2"), HMAC_SECRET, ENCRYPTION_KEY).expect("Password should be present");
            assert_eq!(password1.to_json(), object!{
                "type": "stored",
                "site": "example.com",
                "name": "blabber",
                "revision": "2",
                "password": "asdf"
            });

            assert!(storage.has_password(&PasswordId::new("example.com", "blubber", ""), HMAC_SECRET));
            let password2 = storage.get_password(&PasswordId::new("example.com", "blubber", ""), HMAC_SECRET, ENCRYPTION_KEY).expect("Password should be present");
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

            assert!(storage.has_password(&PasswordId::new("example.info", "test", "yet another"), HMAC_SECRET));
            let password3 = storage.get_password(&PasswordId::new("example.info", "test", "yet another"), HMAC_SECRET, ENCRYPTION_KEY).expect("Password should be present");
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

            assert!(!storage.has_password(&PasswordId::new("example.org", "blubber", ""), HMAC_SECRET));
            assert!(matches!(storage.get_password(&PasswordId::new("example.org", "blubber", ""), HMAC_SECRET, ENCRYPTION_KEY).expect_err("Password should be missing"), Error::KeyMissing { .. }));
        }

        #[test]
        fn get_alias()
        {
            let io = MemoryIO::new(default_data());
            let storage = Storage::new(io);

            assert!(matches!(storage.get_alias("example.com", HMAC_SECRET, ENCRYPTION_KEY).expect_err("Alias shouldn't be present"), Error::NoSuchAlias { .. }));
            assert_eq!(storage.get_alias("example.org", HMAC_SECRET, ENCRYPTION_KEY).expect("Alias should be present"), "example.com");
        }

        #[test]
        fn resolve_site()
        {
            let io = MemoryIO::new(default_data());
            let storage = Storage::new(io);

            assert_eq!(storage.normalize_site("example.com"), "example.com");
            assert_eq!(storage.resolve_site("example.com", HMAC_SECRET, ENCRYPTION_KEY), "example.com");

            assert_eq!(storage.normalize_site("www.example.com"), "example.com");
            assert_eq!(storage.resolve_site("www.example.com", HMAC_SECRET, ENCRYPTION_KEY), "example.com");

            assert_eq!(storage.normalize_site("www2.example.com"), "www2.example.com");
            assert_eq!(storage.resolve_site("www2.example.com", HMAC_SECRET, ENCRYPTION_KEY), "www2.example.com");

            assert_eq!(storage.normalize_site("www.example.net"), "example.net");
            assert_eq!(storage.resolve_site("www.example.net", HMAC_SECRET, ENCRYPTION_KEY), "example.net");

            assert_eq!(storage.normalize_site("example.org"), "example.org");
            assert_eq!(storage.resolve_site("example.org", HMAC_SECRET, ENCRYPTION_KEY), "example.com");

            assert_eq!(storage.normalize_site("www.example.org"), "example.org");
            assert_eq!(storage.resolve_site("www.example.org", HMAC_SECRET, ENCRYPTION_KEY), "example.com");
        }
    }

    mod addition
    {
        use super::*;

        #[test]
        fn add_passwords()
        {
            let io = MemoryIO::new(empty_data());
            let mut storage = Storage::new(io);

            storage.ensure_site_data("example.com", HMAC_SECRET, ENCRYPTION_KEY);
            storage.ensure_site_data("example.com", HMAC_SECRET, ENCRYPTION_KEY);

            storage.set_generated(GeneratedPassword::from_json(&parse_json_object(r#"{
                "site": "example.com",
                "name": "blubber",
                "revision": "",
                "length": 16,
                "lower": true,
                "upper": true,
                "number": true,
                "symbol": true
            }"#).unwrap()).unwrap(), HMAC_SECRET, ENCRYPTION_KEY);

            storage.set_stored(StoredPassword::from_json(&parse_json_object(r#"{
                "site": "example.com",
                "name": "blabber",
                "revision": "2",
                "password": "asdf"
            }"#).unwrap()).unwrap(), HMAC_SECRET, ENCRYPTION_KEY);

            storage.ensure_site_data("example.info", HMAC_SECRET, ENCRYPTION_KEY);
            storage.ensure_site_data("example.info", HMAC_SECRET, ENCRYPTION_KEY);

            storage.set_generated(GeneratedPassword::from_json(&parse_json_object(r#"{
                "site": "example.info",
                "name": "test",
                "revision": "yet another",
                "length": 8,
                "lower": true,
                "upper": false,
                "number": true,
                "symbol": false
            }"#).unwrap()).unwrap(), HMAC_SECRET, ENCRYPTION_KEY);

            let result = storage.set_alias("example.com", "example.com", HMAC_SECRET, ENCRYPTION_KEY);
            assert!(matches!(result.expect_err("Setting an alias to itself should fail"), Error::AliasToSelf { .. }));

            storage.set_alias("example.org", "example.com", HMAC_SECRET, ENCRYPTION_KEY).expect("Setting alias should succeed");
            storage.ensure_site_data("example.org", HMAC_SECRET, ENCRYPTION_KEY);

            storage.flush().expect("Flush should succeed");

            compare_storage_data(storage.io.data(), &default_data());
        }
    }

    mod removal
    {
        use super::*;

        #[test]
        fn remove_passwords()
        {
            let io = MemoryIO::new(default_data());
            let mut storage = Storage::new(io);

            assert!(matches!(storage.remove_alias("example.com", HMAC_SECRET, ENCRYPTION_KEY).expect_err("Removing alias should fail"), Error::NoSuchAlias { .. }));
            assert!(matches!(storage.remove_alias("example.net", HMAC_SECRET, ENCRYPTION_KEY).expect_err("Removing alias should fail"), Error::NoSuchAlias { .. }));
            assert!(matches!(storage.remove_password(&PasswordId::new("example.info", "blubber", ""), HMAC_SECRET).expect_err("Removing password should fail"), Error::KeyMissing { .. }));

            storage.remove_password(&PasswordId::new("example.com", "blubber", ""), HMAC_SECRET).expect("Removing password should succeed");
            storage.remove_password(&PasswordId::new("example.com", "blabber", "2"), HMAC_SECRET).expect("Removing password should succeed");
            storage.remove_password(&PasswordId::new("example.info", "test", "yet another"), HMAC_SECRET).expect("Removing password should succeed");
            storage.remove_alias("example.org", HMAC_SECRET, ENCRYPTION_KEY).expect("Removing alias should succeed");

            storage.remove_site("example.com", HMAC_SECRET).expect("Removing site should succeed");
            storage.remove_site("example.info", HMAC_SECRET).expect("Removing site should succeed");

            storage.flush().expect("Flush should succeed");

            compare_storage_data(storage.io.data(), &empty_data());
        }
    }
}
