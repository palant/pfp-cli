/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use rand::Rng;
use super::crypto;
use super::error::Error;
use super::storage;
use super::storage_types::{PasswordId, GeneratedPassword, StoredPassword, Password};

fn get_encryption_key(master_password: &str, salt: &[u8]) -> Vec<u8>
{
    // Replicate salt being converted to UTF-8 as done by JS code
    let mut salt_str = String::new();
    for byte in salt
    {
        salt_str.push(*byte as char);
    }
    return crypto::derive_key(master_password, salt_str.as_bytes());
}

pub struct Passwords
{
    storage: storage::Storage,
    key: Option<Vec<u8>>,
    hmac_secret: Option<Vec<u8>>,
    master_password: Option<String>,
}

impl Passwords
{
    pub fn new(storage: storage::Storage) -> Passwords
    {
        return Passwords
        {
            storage: storage,
            key: None,
            hmac_secret: None,
            master_password: None,
        }
    }

    pub fn initialized(&self) -> Result<(), Error>
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
