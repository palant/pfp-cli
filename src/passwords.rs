/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use crate::crypto;
use crate::storage;
use rand::Rng;
use std::path;

fn get_encryption_key(master_password: &String, salt: &[u8]) -> Vec<u8>
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
        }
    }

    pub fn initialized(&self) -> Option<()>
    {
        return self.storage.initialized();
    }

    pub fn unlocked(&self) -> Option<()>
    {
        self.key.as_ref()?;
        return Some(());
    }

    pub fn get_storage_path(&self) -> &path::PathBuf
    {
        return self.storage.get_path();
    }

    pub fn reset(&mut self, master_password: &String) -> Option<()>
    {
        let salt = rand::thread_rng().gen::<[u8; 16]>();
        let key = get_encryption_key(master_password, &salt);
        let hmac_secret = rand::thread_rng().gen::<[u8; 32]>();

        self.storage.clear();
        self.storage.set_salt(&salt)?;
        self.storage.set_hmac_secret(&hmac_secret, &key)?;
        self.storage.flush()?;

        self.key = Some(key);
        self.hmac_secret = Some(hmac_secret.to_vec());
        return Some(());
    }

    pub fn unlock(&mut self, master_password: &String) -> Option<()>
    {
        self.initialized()?;

        let salt = self.storage.get_salt()?;
        let key = get_encryption_key(master_password, &salt);

        let hmac_secret = self.storage.get_hmac_secret(&key)?;
        self.key = Some(key);
        self.hmac_secret = Some(hmac_secret);
        return Some(());
    }

    pub fn add_generated(&mut self, site: &String, name: &String, revision: &String, length: usize, charset: enumset::EnumSet<crypto::CharacterType>) -> Option<()>
    {
        self.unlocked()?;

        let site_resolved = self.storage.resolve_site(site, self.hmac_secret.as_ref()?.as_slice(), self.key.as_ref()?.as_slice());
        self.storage.ensure_site_data(&site_resolved, self.hmac_secret.as_ref()?.as_slice(), self.key.as_ref()?.as_slice());

        self.storage.set_generated(
            &storage::GeneratedPassword::new(site_resolved, name.clone(), revision.clone(), length, charset),
            self.hmac_secret.as_ref()?.as_slice(), self.key.as_ref()?.as_slice()
        );
        return self.storage.flush();
    }
}
