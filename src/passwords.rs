/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use rand::Rng;
use super::crypto;
use super::error::Error;
use super::storage;
use super::storage_io;
use super::storage_types::{PasswordId, GeneratedPassword, StoredPassword, Password};

fn get_encryption_key(master_password: &str, salt: &[u8]) -> Vec<u8>
{
    // Replicate salt being converted to UTF-8 as done by JS code
    let salt_str = String::from_iter(salt.iter().map(|byte| *byte as char));
    return crypto::derive_key(master_password, salt_str.as_bytes());
}

pub struct Passwords<IO>
{
    storage: storage::Storage<IO>,
    key: Option<Vec<u8>>,
    hmac_secret: Option<Vec<u8>>,
    master_password: Option<String>,
}

impl<IO: storage_io::StorageIO> Passwords<IO>
{
    pub fn new(storage: storage::Storage<IO>) -> Self
    {
        return Self
        {
            storage: storage,
            key: None,
            hmac_secret: None,
            master_password: None,
        }
    }

    pub fn initialized(&self) -> Result<(), &Error>
    {
        return self.storage.initialized();
    }

    pub fn unlocked(&self) -> Result<(), Error>
    {
        return match self.key.as_ref()
        {
            Some(_) => Ok(()),
            None => Err(Error::PasswordsLocked),
        };
    }

    pub fn reset(&mut self, master_password: &str) -> Result<(), Error>
    {
        let salt = rand::thread_rng().gen::<[u8; 16]>();
        let key = get_encryption_key(master_password, &salt);
        let hmac_secret = rand::thread_rng().gen::<[u8; 32]>();

        self.storage.clear(&salt, &hmac_secret, &key);
        self.storage.flush()?;

        self.key = Some(key);
        self.hmac_secret = Some(hmac_secret.to_vec());
        return Ok(());
    }

    pub fn unlock(&mut self, master_password: &str) -> Result<(), Error>
    {
        let salt = self.storage.get_salt()?;
        let key = get_encryption_key(master_password, &salt);

        let hmac_secret = self.storage.get_hmac_secret(&key)?;
        self.key = Some(key);
        self.hmac_secret = Some(hmac_secret);
        self.master_password = Some(master_password.to_string());
        return Ok(());
    }

    pub fn set_alias(&mut self, site: &str, alias: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?;
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_normalized = self.storage.normalize_site(site);
        let alias_resolved = self.storage.resolve_site(alias, hmac_secret, key);
        if self.storage.list_passwords(&site_normalized, hmac_secret, key).next().is_some()
        {
            return Err(Error::SiteHasPasswords);
        }

        self.storage.set_alias(&site_normalized, &alias_resolved, hmac_secret, key)?;
        return self.storage.flush();
    }

    pub fn set_generated(&mut self, site: &str, name: &str, revision: &str, length: usize, charset: enumset::EnumSet<crypto::CharacterType>) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        self.storage.ensure_site_data(&site_resolved, hmac_secret, key)?;

        self.storage.set_generated(
            GeneratedPassword::new(&site_resolved, name, revision, length, charset),
            hmac_secret, key
        )?;
        return self.storage.flush();
    }

    pub fn set_stored(&mut self, site: &str, name: &str, revision: &str, password: &str) -> Result<(), Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        self.storage.ensure_site_data(&site_resolved, hmac_secret, key)?;

        self.storage.set_stored(
            StoredPassword::new(&site_resolved, name, revision, password),
            hmac_secret, key
        )?;
        return self.storage.flush();
    }

    pub fn has(&self, site: &str, name: &str, revision: &str) -> Result<bool, Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        return self.storage.has_password(
            &PasswordId::new(&site_resolved, name, revision),
            hmac_secret
        );
    }

    pub fn get(&self, site: &str, name: &str, revision: &str) -> Result<String, Error>
    {
        let hmac_secret = self.hmac_secret.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();
        let key = self.key.as_ref().ok_or(Error::PasswordsLocked)?.as_slice();
        let master_password = self.master_password.as_ref().ok_or(Error::PasswordsLocked)?;

        let site_resolved = self.storage.resolve_site(site, hmac_secret, key);
        let password = self.storage.get_password(
            &PasswordId::new(&site_resolved, name, revision),
            hmac_secret, key
        )?;

        match password
        {
            Password::Generated {password} =>
            {
                return Ok(crypto::derive_password(master_password, &password.salt(), password.length(), password.charset()));
            }
            Password::Stored {password} =>
            {
                return Ok(password.password().to_string());
            }
        }
    }

    pub fn list(&self, site: &str, name: &str) -> impl Iterator<Item = Password> + '_
    {
        assert!(self.unlocked().is_ok());

        let site_resolved = self.storage.resolve_site(site, self.hmac_secret.as_ref().unwrap().as_slice(), self.key.as_ref().unwrap().as_slice());
        let matcher = wildmatch::WildMatch::new(name);
        return self.storage.list_passwords(&site_resolved, self.hmac_secret.as_ref().unwrap().as_slice(), self.key.as_ref().unwrap().as_slice()).filter(move |password|
        {
            let name =  match password
            {
                Password::Generated {password} => password.id().name(),
                Password::Stored {password} => password.id().name(),
            };
            return matcher.matches(name);
        });
    }

    pub fn list_sites(&self, site: &str) -> impl Iterator<Item = String> + '_
    {
        assert!(self.unlocked().is_ok());

        let matcher = wildmatch::WildMatch::new(site);
        return self.storage.list_sites(self.key.as_ref().unwrap().as_slice()).filter(move |site| matcher.matches(&site));
    }
}

#[cfg(test)]
mod tests
{
    use json::object;
    use storage::Storage;
    use storage_io::MemoryIO;
    use super::*;

    fn empty_data() -> String
    {
        return json::stringify(object!{
            "application": "pfp",
            "format": 3,
            "data": {
                "salt": "Y2Jh",
                "hmac-secret": "YWJjZGVmZ2hpamts_Nosk0g9vPYtLPn9QzyFXLQ/1ZuAHVw==",
            },
        });
    }

    fn default_data() -> String
    {
        // Master password is foobar
        return json::stringify(object!{
            "application": "pfp",
            "format": 3,
            "data": {
                // cba as base64
                "salt": "Y2Jh",
                // abc encrypted (nonce abcdefghijkl, encryption key \x9b\x4f\x2d\x17\x37\xb6\xc2\x57\xf7\x50\x49\x51\x8c\x84\x49\x87\xb5\xde\x40\x1b\x3a\x87\x04\x8b\x26\x2d\x9b\x40\xae\xf8\xb0\xe2)
                "hmac-secret": "YWJjZGVmZ2hpamts_Nosk0g9vPYtLPn9QzyFXLQ/1ZuAHVw==",
                // example.com (hmac-sha256)
                "site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=":
                    // {"site":"example.com"} encrypted
                    "YWJjZGVmZ2hpamts_b/AA8REorsFjuwlGDYB+KVw/fqoHPv2Ehc7sBIYqhR+ygcsd/t4=",
                // example.com\x00blubber\x00 (hmac-sha256)
                "site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:/uudghlPp4TDZPtfZFPj6nJs/zMDAE2AqVfz6Hu8N9I=":
                    // {"type":"generated2","site":"example.com","name":"blubber","revision":"","length":16,"lower":true,"upper":true,"number":true,"symbol":true} encrypted
                    "YWJjZGVmZ2hpamts_b/AH4RUorsFjuRRJBYJzOBc4I+UJYXWhqhFXbEC9Aw5pRRO/Q31d6d/+RQhdj8wH0SWpEXk/ZkVXSAjSqpbqKsEek2JzzOetQNutMR4tblZGzTsPxWZogaKazYGFvg+J43L9ugBf7PjDfk+Rx3QbGdWaScEdCdciXlv6z/drMjyK0b8+kKgrdjdaIT7NuJwpEiZxzMngRiqPqZI=",
                // example.com\x00blabber\x002 (hmac-sha256)
                "site:fRTOldDD+lTwIBS8G+eUkrIzvNsfdGRSWQXrXqszDHM=:h2pnx6RFyNbAUBLcuQYz9w79/vnf4fgJlY/c+EP44d8=":
                    // {"type":"stored","site":"example.com","name":"blabber","revision":"2","password":"asdf"} encrypted
                    "YWJjZGVmZ2hpamts_b/AH4RUorsFjrQVIEpV2bl5+Yq5RJiTy/BENNw+oFwoqVhC3TzIQ6py/AkQGwMtJimWpGH5/KAJXD1KZq5rzLZBN3j5z2uf/DYqyIx84fhxe1WtKjSImk92FeghEDLDNbwijfAnncDw=",
                // example.info (hmac-sha256)
                "site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=":
                    // {"site":"example.info"} encrypted
                    "YWJjZGVmZ2hpamts_b/AA8REorsFjuwlGDYB+KVw1f6FKYXsPR37ZtYXddpCecTwncBIM",
                // example.info\x00test\x00yet another (hmac-sha256)
                "site:Gd2Cx/SbNs6BWf2KlmHZrOY7SNi5GnjBLG58eJdgqdc=:BSjLwWY3MLEPQdG1f/jwKOtJRKCxwXpRH5qkMrUnVsI=":
                    // {"type":"generated2","site":"example.info","name":"test","revision":"yet another","length":8,"lower":true,"upper":false,"number":true,"symbol":false} encrypted
                    "YWJjZGVmZ2hpamts_b/AH4RUorsFjuRRJBYJzOBc4I+UJYXWhqhFXbEC9Aw5pRRO/Q3dc4pLwS0RSg8RAyT3pCWkucAIJSFaVrprvKt0Z3jZzj6D7TJivOwQif0xG2yhVjCpjmr3dhZuT6BGT8Tut7Upb+/+EaBmWwmFSSZnVQsIUCJA0CEf6x7ksM2fdx6In1759dztSPv4LAx+oMQrVGzjFO4a3iuk8bTSFjmb4jtH+",
                // example.org (hmac-sha256)
                "site:5IS/IdH3aaMwyzRv0fwy+2oh5OsXZ2emV8991dFWrko=":
                    // {"site":"example.org","alias":"example.com"} encrypted
                    "YWJjZGVmZ2hpamts_b/AA8REorsFjuwlGDYB+KVwzY6AHbySpsh0UJUDiWQp8VBKqAXsc55K/RRsY3NAIQzDdtK+4TrjLOu3X",
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
            let passwords = Passwords::new(Storage::new(io));

            assert!(matches!(passwords.initialized().expect_err("Passwords should be uninitialized"), Error::InvalidJson { .. }));
            assert!(matches!(passwords.unlocked().expect_err("Passwords should locked"), Error::PasswordsLocked { .. }));
        }

        #[test]
        fn read_success()
        {
            let io = MemoryIO::new(&empty_data());
            let passwords = Passwords::new(Storage::new(io));

            passwords.initialized().expect("Passwords should be initialized");
            assert!(matches!(passwords.unlocked().expect_err("Passwords should locked"), Error::PasswordsLocked { .. }));
        }

        #[test]
        fn unlock()
        {
            let io = MemoryIO::new(&default_data());
            let mut passwords = Passwords::new(Storage::new(io));

            assert!(matches!(passwords.unlock("asdfyxcv").expect_err("Passwords shouldn't unlock"), Error::DecryptionFailure { .. }));
            passwords.unlock("foobar").expect("Passwords should unlock");
        }
    }

    mod retrieval
    {
        use super::*;

        fn list_sites(passwords: &Passwords<MemoryIO>, site: &str) -> Vec<String>
        {
            let mut vec = passwords.list_sites(site).collect::<Vec<String>>();
            vec.sort();
            return vec;
        }

        fn list_passwords(passwords: &Passwords<MemoryIO>, site: &str, name: &str) -> Vec<String>
        {
            let mut vec = passwords.list(site, name).map(|password| match password
            {
                Password::Generated {password} => password.id().name().to_string(),
                Password::Stored {password} => password.id().name().to_string(),
            }).collect::<Vec<String>>();
            vec.sort();
            return vec;
        }

        #[test]
        fn list_sites_wildcards()
        {
            let io = MemoryIO::new(&default_data());
            let mut passwords = Passwords::new(Storage::new(io));
            passwords.unlock("foobar").expect("Passwords should unlock");

            assert_eq!(list_sites(&passwords, "*"), vec!["example.com", "example.info"]);
            assert_eq!(list_sites(&passwords, "ex*"), vec!["example.com", "example.info"]);
            assert_eq!(list_sites(&passwords, "*.com"), vec!["example.com"]);
            assert_eq!(list_sites(&passwords, "*am*i*"), vec!["example.info"]);
            assert_eq!(list_sites(&passwords, "blub*").len(), 0);
        }

        #[test]
        fn list_passwords_wildcards()
        {
            let io = MemoryIO::new(&default_data());
            let mut passwords = Passwords::new(Storage::new(io));
            passwords.unlock("foobar").expect("Passwords should unlock");

            assert_eq!(list_passwords(&passwords, "example.com", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "*"), vec!["test"]);
            assert_eq!(list_passwords(&passwords, "www.example.info", "*"), vec!["test"]);

            assert_eq!(list_passwords(&passwords, "example.com", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "b*"), vec!["blabber", "blubber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "b*").len(), 0);
            assert_eq!(list_passwords(&passwords, "www.example.info", "b*").len(), 0);

            assert_eq!(list_passwords(&passwords, "example.com", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "blu*"), vec!["blubber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "blu*").len(), 0);
            assert_eq!(list_passwords(&passwords, "www.example.info", "blu*").len(), 0);

            assert_eq!(list_passwords(&passwords, "example.com", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "www.example.com", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "example.org", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "www.example.org", "*a*"), vec!["blabber"]);
            assert_eq!(list_passwords(&passwords, "example.info", "t*t"), vec!["test"]);
            assert_eq!(list_passwords(&passwords, "www.example.info", "t*t"), vec!["test"]);
        }
    }
}
